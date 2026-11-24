"""CISA's SSVC rating of each matched CVE, from the CVE Services record, for the urgency model (cve/priority.py).

CISA's Vulnrichment program adds an "ADP" container (`providerMetadata.shortName` "CISA-ADP") to CVE records. It carries the SSVC
decision points Exploitation, Automatable and Technical Impact for "new and recent CVEs", and CVSS and CWE for some
(https://github.com/cisagov/vulnrichment). Automatable and Technical Impact are two of the four variables of CISA BOD 26-04.

Where the data comes from, read on 2026-11-24:

    GET https://cveawg.mitre.org/api/cve/<CVE-ID>

The CVE Services API's OpenAPI document (https://cveawg.mitre.org/api-docs/openapi.json, operation `cveGetSingle`, "Returns a CVE
Record by CVE ID (accessible to all users)") says "Endpoint is accessible to all": no key. Its answers carry `RateLimit-Limit`,
`RateLimit-Policy`, `RateLimit-Remaining` and `RateLimit-Reset` headers ("Clients MUST NOT assume that a positive remaining value is
a guarantee that further requests will be served. When the value of the remaining keyword is low, it indicates that the server may
soon throttle the client"), and the operation documents a 429. The policy seen was `25000;w=60`. The program's terms of use are at
https://www.cve.org/Legal/TermsOfUse. The record is JSON 5.x: `containers.adp[]` with `providerMetadata.shortName == "CISA-ADP"`
has `metrics[]` with `other: {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}, {"Automatable": "yes"},
{"Technical Impact": "total"}], "timestamp": ...}}`, and the CNA's (or the ADP's) CVSS is in `metrics[]` under `cvssV4_0`,
`cvssV3_1`, `cvssV3_0` or `cvssV2_0` with `baseScore` and `vectorString`. The alternatives were rejected for size: the cvelistV5
daily bundle is 641 MB and the Vulnrichment repository 416 MB, for the few thousand CVEs a hub matches.

The hub asks only for CVEs it has matched, one request at a time, and keeps the answer in `cve_record` (store.py). A kept record is
asked for again after `REFETCH_DAYS` while the CVE is still matched, and at once when its KEV status has changed since it was read.
The first fill is spread over passes (`PER_PASS`, `PASS_SECONDS`). The `RateLimit-*` headers are obeyed: the pass stops when the
quota left is low or the service answers 429 or 5xx, and no request is made before the time the service named. Everything here is
data from a download: HTTPS only, the answer must come from `cveawg.mitre.org`, no redirect is followed, a body over 1 MB is
refused, and only a few short fields are kept. The request carries only the generic User-Agent "DaemonSight/<version>".
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import time

import httpx

from .. import __version__

USER_AGENT = f"DaemonSight/{__version__}"
HOST = "cveawg.mitre.org"
URL = f"https://{HOST}/api/cve/{{id}}"
DOCS = "https://cveawg.mitre.org/api-docs/openapi.json"
TERMS = "https://www.cve.org/Legal/TermsOfUse"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
MAX_BYTES = 1 << 20             # one record; the real ones are 15 to 60 KB
PER_PASS = 100                  # at most this many records asked for in one pass
PASS_SECONDS = 20.0             # and no more than this long in one pass
REFETCH_DAYS = 7                # a kept record is asked for again after this long while its CVE is matched
ERROR_RETRY_HOURS = 1
ABSENT_RETRY_DAYS = 1           # the service had no record (404): it may be published later
RESERVE = 100                   # stop when the quota left is this low
WAIT_MIN, WAIT_MAX = 30.0, 3600.0
UNTIL_KEY = "cve_services_until"   # meta: do not ask before this time (epoch)
SOURCE_STATES = ("fix", "esm", "nofix")   # the matches that show a CVE

SSVC_VALUES = {"Exploitation": ("none", "poc", "active"), "Automatable": ("yes", "no"), "Technical Impact": ("partial", "total")}
CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


class FetchError(Exception):
    pass


# --- parsing ------------------------------------------------------------------------------------------------------------

def _short(text, limit: int) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= limit else t[:limit - 1].rstrip() + "…"


def _ssvc(adp: dict) -> dict | None:
    for m in adp.get("metrics") or []:
        other = m.get("other") if isinstance(m, dict) else None
        if not isinstance(other, dict) or str(other.get("type") or "").lower() != "ssvc":
            continue
        content = other.get("content")
        if not isinstance(content, dict):
            continue
        got: dict[str, str] = {}
        for opt in content.get("options") or []:
            if isinstance(opt, dict):
                for k, v in opt.items():
                    if k in SSVC_VALUES and isinstance(v, str) and v.strip().lower() in SSVC_VALUES[k]:
                        got[k] = v.strip().lower()
        if got:
            return {"exploitation": got.get("Exploitation"), "automatable": got.get("Automatable"),
                    "impact": got.get("Technical Impact"), "at": _short(content.get("timestamp"), 40) or None}
    return None


def _cvss(container: dict) -> tuple[float, str] | None:
    """(score, vector) of the container's best CVSS metric: the newest version it carries."""
    metrics = [m for m in container.get("metrics") or [] if isinstance(m, dict)]
    for key in CVSS_KEYS:
        for m in metrics:
            c = m.get(key)
            if not isinstance(c, dict):
                continue
            score, vec = c.get("baseScore"), c.get("vectorString")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10 and isinstance(vec, str):
                return float(score), _short(vec, 120)
    return None


def parse(cve: str, doc) -> dict:
    """What is kept of one CVE Services record: {"exploitation", "automatable", "impact", "ssvc_at", "cvss_score", "cvss_vector",
    "cvss_source"}, every value None that the record does not have. Raises FetchError when the document is not that CVE's record."""
    if not isinstance(doc, dict) or not isinstance(doc.get("cveMetadata"), dict) \
            or str(doc["cveMetadata"].get("cveId", "")).upper() != cve.upper():
        raise FetchError("the answer is not that CVE's record")
    cont = doc.get("containers") if isinstance(doc.get("containers"), dict) else {}
    out = {"exploitation": None, "automatable": None, "impact": None, "ssvc_at": None,
           "cvss_score": None, "cvss_vector": None, "cvss_source": None}
    adps = [a for a in cont.get("adp") or [] if isinstance(a, dict)]
    for a in adps:
        if (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP":
            s = _ssvc(a)
            if s:
                out.update(exploitation=s["exploitation"], automatable=s["automatable"], impact=s["impact"], ssvc_at=s["at"])
            break
    sources = [("CNA", cont.get("cna") if isinstance(cont.get("cna"), dict) else {})]
    sources += [("CISA-ADP", a) for a in adps if (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"]
    for name, c in sources:
        got = _cvss(c)
        if got:
            out.update(cvss_score=got[0], cvss_vector=got[1], cvss_source=name)
            break
    return out


# --- the cache ------------------------------------------------------------------------------------------------------------

def cached(conn, cves=None) -> dict[str, dict]:
    """{cve: row} of `cve_record`. A database from before the table existed gives {}."""
    try:
        rows = conn.execute("SELECT * FROM cve_record").fetchall()
    except sqlite3.OperationalError:
        return {}
    return {r["cve"]: dict(r) for r in rows if cves is None or r["cve"] in cves}


def wanted(conn) -> list[dict]:
    """Every CVE the hub has matched and shows, with its record row (None), KEV status now and EPSS: [{"cve", "row", "kev",
    "epss"}], most important first (KEV, then EPSS), for `due`."""
    marks = ",".join("?" for _ in SOURCE_STATES)
    rows = conn.execute(
        "SELECT m.cve AS cve, k.cve IS NOT NULL AS kev, e.score AS epss FROM (SELECT DISTINCT cve FROM match "
        f"WHERE state IN ({marks})) m LEFT JOIN kev k ON k.cve = m.cve LEFT JOIN epss e ON e.cve = m.cve", SOURCE_STATES).fetchall()
    have = cached(conn)
    out = [{"cve": r["cve"], "row": have.get(r["cve"]), "kev": bool(r["kev"]), "epss": r["epss"] or 0.0}
           for r in rows if CVE_RE.match(r["cve"])]
    out.sort(key=lambda w: (not w["kev"], -w["epss"], w["cve"]))
    return out


def is_due(w: dict, now: float) -> bool:
    r = w["row"]
    if r is None:
        return True
    tried = r["tried_at"] or 0
    if r["status"] == "error":
        return now - tried >= ERROR_RETRY_HOURS * 3600
    if r["status"] == "absent":
        return now - tried >= ABSENT_RETRY_DAYS * 86400
    if bool(r["kev"]) != w["kev"]:
        return True
    return now - (r["fetched_at"] or 0) >= REFETCH_DAYS * 86400


def due(conn, now: float) -> list[str]:
    """The CVEs to ask for now, most important first: no row yet, a failure older than an hour, a 404 older than a day, a record
    older than `REFETCH_DAYS`, or one read when its KEV status was different."""
    return [w["cve"] for w in wanted(conn) if is_due(w, now)]


def _store_ok(conn, cve: str, got: dict, kev: bool, now: float) -> None:
    conn.execute("INSERT OR REPLACE INTO cve_record (cve, status, fetched_at, tried_at, kev, exploitation, automatable, impact, "
                 "ssvc_at, cvss_score, cvss_vector, cvss_source, detail) VALUES (?, 'ok', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                 (cve, now, now, int(kev), got["exploitation"], got["automatable"], got["impact"], got["ssvc_at"],
                  got["cvss_score"], got["cvss_vector"], got["cvss_source"]))


def _store_status(conn, cve: str, status: str, why: str, now: float) -> None:
    # A kept record stays when a later ask fails; only `tried_at` moves, which the retry is counted from.
    conn.execute("INSERT INTO cve_record (cve, status, tried_at, detail) VALUES (?, ?, ?, ?) "
                 "ON CONFLICT (cve) DO UPDATE SET tried_at = excluded.tried_at, "
                 "status = CASE WHEN cve_record.status = 'ok' THEN 'ok' ELSE excluded.status END, "
                 "detail = CASE WHEN cve_record.status = 'ok' THEN cve_record.detail ELSE excluded.detail END",
                 (cve, status, now, _short(why, 120)))


def generation(conn) -> str:
    """Changes whenever a record is read, so the findings are worked out again."""
    try:
        n, last = conn.execute("SELECT COUNT(*), COALESCE(MAX(fetched_at), 0) FROM cve_record WHERE status = 'ok'").fetchone()
    except sqlite3.OperationalError:
        return "rec:0:0"
    return f"rec:{n}:{last:.0f}"


# --- asking ---------------------------------------------------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, url: str):
    """(status, headers, body) of one GET. HTTPS only, the answer must come from `HOST`, a redirect is not followed (a 3xx is
    returned as it is), and the body is read only up to `MAX_BYTES`."""
    try:
        async with client.stream("GET", url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                                 follow_redirects=False) as r:
            u = r.request.url
            if u.scheme != "https" or u.host != HOST:
                raise FetchError(f"answered by {u.host}, which is not the source")
            if 300 <= r.status_code < 400:
                return r.status_code, r.headers, b""
            body = bytearray()
            async for chunk in r.aiter_bytes(1 << 14):
                body += chunk
                if len(body) > MAX_BYTES:
                    raise FetchError("the answer is larger than the limit")
            return r.status_code, r.headers, bytes(body)
    except httpx.HTTPError as exc:
        raise FetchError(f"{type(exc).__name__}"[:60]) from None


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def wait_until(headers, now: float) -> float:
    """When the service may be asked again after a 429, a 5xx or a quota nearly used: `Retry-After` seconds if the answer has
    them, else `RateLimit-Reset` (seconds until the quota resets), else a minute. Between `WAIT_MIN` and `WAIT_MAX` seconds."""
    wait = None
    for name in ("retry-after", "ratelimit-reset"):
        n = _int(headers.get(name))
        if n is not None and n >= 0:
            wait = float(n)
            break
    if wait is None:
        wait = 60.0
    return now + min(max(wait, WAIT_MIN), WAIT_MAX)


async def resolve(conn, now: float, client: httpx.AsyncClient | None = None, per_pass: int = PER_PASS,
                  seconds: float = PASS_SECONDS, clock=time.monotonic) -> dict:
    """Ask for the records that are due, one at a time, at most `per_pass` and `seconds` in one pass, and keep what comes. Returns
    {"asked", "read", "absent", "failed", "waiting"}: `waiting` is the number still due when the pass ended (over the cap, or the
    service asked for a pause). Never raises for an answer: a failure is stored on the CVE's row. `conn` is the chore's cve.db
    connection."""
    from . import store
    out = {"asked": 0, "read": 0, "absent": 0, "failed": 0, "waiting": 0}
    todo = due(conn, now)
    if not todo:
        return out
    try:
        until = float(store.get_meta(conn, UNTIL_KEY, "0") or 0)
    except ValueError:
        until = 0.0
    if now < until:
        out["waiting"] = len(todo)
        return out
    kev = {w["cve"]: w["kev"] for w in wanted(conn)}
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=False, headers={"User-Agent": USER_AGENT})
    started = clock()
    stopped = False
    try:
        for i, cve in enumerate(todo):
            if stopped or out["asked"] >= per_pass or clock() - started >= seconds:
                out["waiting"] = len(todo) - i
                break
            out["asked"] += 1
            try:
                status, hdrs, body = await _get(client, URL.format(id=cve))
            except FetchError as exc:
                _store_status(conn, cve, "error", str(exc), now)
                out["failed"] += 1
                continue
            if status == 429 or status >= 500:
                # The service asks for a pause (or is down): stop, keep nothing against the CVE, ask again after the wait.
                store.set_meta(conn, UNTIL_KEY, str(wait_until(hdrs, now)))
                out["asked"] -= 1
                out["waiting"] = len(todo) - i
                stopped = True
                break
            try:
                if status == 404:
                    _store_status(conn, cve, "absent", "the service has no record", now)
                    out["absent"] += 1
                elif status != 200:
                    raise FetchError(f"HTTP {status}")
                else:
                    try:
                        got = parse(cve, json.loads(body.decode("utf-8", "replace")))
                    except ValueError:
                        raise FetchError("the answer is not JSON") from None
                    _store_ok(conn, cve, got, kev.get(cve, False), now)
                    out["read"] += 1
            except FetchError as exc:
                _store_status(conn, cve, "error", str(exc), now)
                out["failed"] += 1
            remaining = _int(hdrs.get("ratelimit-remaining"))
            if remaining is not None and remaining <= RESERVE:
                store.set_meta(conn, UNTIL_KEY, str(wait_until(hdrs, now)))
                out["waiting"] = len(todo) - i - 1
                stopped = True
    finally:
        if own:
            await client.aclose()
    return out
