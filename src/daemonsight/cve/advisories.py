"""CVE ids of the security advisories an OPNsense changelog names, for a release's CVE set.

The changelog (cve/opnsense.py) names many fixes only by an advisory: `FREEBSD-SA:26:74.ktls` (a FreeBSD security advisory
for the base system) or `GHSA:GHSA-f35q-c34m-pfw3` (a GitHub security advisory OPNsense published for its own code). Neither
footnote carries a CVE id. This module asks the advisory's own publisher once and keeps the answer. Read on 2026-11-24:

FreeBSD (https://www.freebsd.org/security/advisories/FreeBSD-SA-<year>:<n>.<module>.asc)
    A plain-text, PGP-signed advisory. `https://security.freebsd.org/advisories/<same file>` answers 301 to this address, so
    the address after the redirect is used and no redirect is followed. Its header block has a `CVE Name:` line with one or
    more ids separated by commas (`CVE-2026-127752, CVE-2026-127753, CVE-2026-127754`); all 21 advisories of OPNsense 26.7.10
    (SA-26:74 to 26:94) have one, and older ones read (19:08, 23:06, 24:04, 25:08) have the same shape. An advisory with no such
    line is kept as having no CVE. The index (https://www.freebsd.org/security/advisories/) and the RSS feed list names only,
    not CVE ids, so one file cannot cover many advisories. FreeBSD's VuXML (vuxml.freebsd.org/freebsd/vuln.xml.bz2, 1.4 MB,
    10.5 MB decoded) names CVEs next to `<freebsdsa>` for only 474 advisories out of 6,880 entries and was not used. The
    advisory's PGP signature is not checked. Errata notices (`FREEBSD-EN:`) are not security advisories, have no `CVE Name:`
    field (FreeBSD-EN-26:32.zfs has no "CVE" in it) and are never read: the changelog parser does not keep them.

GitHub (https://api.github.com/repos/opnsense/core/security-advisories/<GHSA id>)
    `GET /advisories/<id>` (the global database) answers 404 for these: an advisory published on the repository itself is
    not in it. `GET /repos/opnsense/core/security-advisories/<id>` answers 200 with no token ("Anyone can access any
    published security advisory on a public repository", docs.github.com/en/rest/security-advisories/repository-advisories).
    The fields used: `ghsa_id`, `state` ("published"), `cve_id` (a CVE id or null; both of 26.7.10's were null, GHSA-2v2x-m4j7-76pv
    has CVE-2026-63442), `severity` ("low", "medium", "high", "critical" or null) and `cvss.score`. The limit for a request with
    no token is 60 an hour per address (docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api); the answer
    says so in `x-ratelimit-limit`, `-remaining` and `-reset` (epoch seconds). A request over the limit is answered 403 or
    429; the page says not to retry before `x-ratelimit-reset`, or before `retry-after` seconds when that header is present.

An advisory is immutable once published, so an answer is kept for good in `opn_adv`; only a failed answer is asked again,
after `[cve] refresh_hours`. (A GitHub advisory published without a CVE id could be given one later; that is not looked for.)
Everything here is data from a download: size-capped, HTTPS only, no redirect followed, parsed with the standard library, and
stored as ids, a rating and one short line.
"""

from __future__ import annotations

import asyncio
import json
import re

import httpx

from .. import __version__

USER_AGENT = f"DaemonSight/{__version__}"
SA_HOST = "www.freebsd.org"
GH_HOST = "api.github.com"
SA_URL = f"https://{SA_HOST}/security/advisories/FreeBSD-SA-{{id}}.asc"
GH_URL = f"https://{GH_HOST}/repos/opnsense/core/security-advisories/{{id}}"
SA_DOCS = "https://www.freebsd.org/security/advisories/"
GH_DOCS = "https://docs.github.com/en/rest/security-advisories/repository-advisories#get-a-repository-security-advisory"

SA_REF = re.compile(r"^FREEBSD-SA:(\d{2}:\d{1,3}\.[A-Za-z0-9_-]{1,30})$")
GH_REF = re.compile(r"^GHSA:(GHSA(?:-[a-z0-9]{4}){3})$")
CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,10}")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
SEVERITIES = ("low", "medium", "high", "critical")

SA_MAX_BYTES = 128 << 10          # the real ones are 5 to 9 KB
GH_MAX_BYTES = 512 << 10          # the real ones are 17 to 20 KB (the description is long)
HEADER_BYTES = 6000               # the header block (Topic, Category, CVE Name) is in the first lines
MAX_CVES = 40                     # per advisory; the real maximum seen is 3
SPACING = {SA_HOST: 0.5, GH_HOST: 1.0}   # seconds between two requests to the same host in one pass
PER_PASS = 40                     # at most this many advisories asked for in one pass (the rest wait for the next)
GH_UNTIL_KEY = "opn_gh_until"     # meta: do not ask GitHub before this time (epoch)
GH_WAIT_MAX = 6 * 3600            # a header that asks for longer is not believed
GH_WAIT_DEFAULT = 3600            # a 403 or 429 that says nothing about when


class FetchError(Exception):
    pass


def label(ref: str) -> str:
    """The advisory's own name: `FreeBSD-SA-26:74.ktls` or `GHSA-f35q-c34m-pfw3`."""
    m = SA_REF.match(ref)
    if m:
        return "FreeBSD-SA-" + m.group(1)
    m = GH_REF.match(ref)
    return m.group(1) if m else ref


def kind(ref: str) -> str | None:
    return "sa" if SA_REF.match(ref) else "gh" if GH_REF.match(ref) else None


def host_of(ref: str) -> str | None:
    return {"sa": SA_HOST, "gh": GH_HOST}.get(kind(ref) or "")


def api_url(ref: str) -> str | None:
    """The address asked for one advisory, or None for a reference this does not resolve."""
    m = SA_REF.match(ref)
    if m:
        return SA_URL.format(id=m.group(1))
    m = GH_REF.match(ref)
    return GH_URL.format(id=m.group(1)) if m else None


def _short(text, limit: int) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= limit else t[:limit - 1].rstrip() + "…"


# --- parsing ----------------------------------------------------------------------------------------------------------------

def parse_sa(ref: str, text: str) -> dict:
    """{"cves": [...], "title": str} from a FreeBSD advisory's text. Raises FetchError when the text is not that advisory (an
    error page served with a 200). Only the header block is read: the `CVE Name:` line and the indented lines after it. An
    advisory with no such line, or one with no id in it ("N/A"), has no CVE."""
    m = SA_REF.match(ref)
    if not m:
        raise FetchError("not a FreeBSD advisory reference")
    head = text[:HEADER_BYTES]
    if f"FreeBSD-SA-{m.group(1)}" not in head:
        raise FetchError("the answer is not that advisory")
    end = re.search(r"^(?:For general information|I\.\s)", head, re.M)      # the header block ends where the sections begin
    lines = (head[:end.start()] if end else head).splitlines()
    cves: list[str] = []
    title = ""
    for i, ln in enumerate(lines):
        if ln.startswith("Topic:") and not title:
            title = _short(ln.split(":", 1)[1], 160)
        if ln.startswith("CVE Name:"):
            chunk = [ln.split(":", 1)[1]]
            for nxt in lines[i + 1:]:
                if not nxt.strip() or nxt[:1] not in (" ", "\t"):
                    break
                chunk.append(nxt)
            cves = list(dict.fromkeys(CVE_FIND.findall(" ".join(chunk))))[:MAX_CVES]
            break
    return {"cves": cves, "title": title, "severity": None, "score": None}


def parse_ghsa(ref: str, doc) -> dict:
    """{"cves": [...], "severity", "score", "title"} from a repository advisory's JSON. Raises FetchError when the document is
    not that published advisory. The description is never read: it names CVEs of earlier fixes ("incomplete fix of CVE-...")."""
    m = GH_REF.match(ref)
    if not m:
        raise FetchError("not a GitHub advisory reference")
    if not isinstance(doc, dict) or str(doc.get("ghsa_id", "")).lower() != m.group(1).lower():
        raise FetchError("the answer is not that advisory")
    if doc.get("state") != "published":
        raise FetchError(f"the advisory is {_short(doc.get('state'), 20) or 'not published'}")
    cve = doc.get("cve_id")
    cves = [cve] if isinstance(cve, str) and CVE_RE.match(cve) else []
    sev = doc.get("severity")
    sev = sev if isinstance(sev, str) and sev in SEVERITIES else None
    score = None
    cvss = doc.get("cvss")
    if isinstance(cvss, dict) and isinstance(cvss.get("score"), (int, float)) and not isinstance(cvss.get("score"), bool):
        score = float(cvss["score"]) if 0 <= cvss["score"] <= 10 else None
    return {"cves": cves, "title": _short(doc.get("summary"), 160), "severity": sev, "score": score}


# --- the cache --------------------------------------------------------------------------------------------------------------

def cached(conn, refs=None) -> dict[str, dict]:
    """{ref: row} of `opn_adv` (`cves` is a list). A database from before the table existed gives {}."""
    import sqlite3
    try:
        rows = conn.execute("SELECT ref, status, cves, severity, score, title, fetched_at, tried_at, detail FROM opn_adv").fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for r in rows:
        if refs is not None and r["ref"] not in refs:
            continue
        d = dict(r)
        try:
            d["cves"] = [c for c in json.loads(d["cves"] or "[]") if isinstance(c, str) and CVE_RE.match(c)]
        except ValueError:
            d["cves"] = []
        out[d["ref"]] = d
    return out


def generation(conn) -> str:
    """Changes whenever an advisory is resolved, so a firewall's matches are made again."""
    import sqlite3
    try:
        n, last = conn.execute("SELECT COUNT(*), COALESCE(MAX(fetched_at), 0) FROM opn_adv WHERE status = 'ok'").fetchone()
    except sqlite3.OperationalError:
        return "adv:0:0"
    return f"adv:{n}:{last:.0f}"


def _store_ok(conn, ref: str, got: dict, now: float) -> None:
    conn.execute("INSERT OR REPLACE INTO opn_adv (ref, status, cves, severity, score, title, fetched_at, tried_at, detail) "
                 "VALUES (?, 'ok', ?, ?, ?, ?, ?, ?, NULL)",
                 (ref, json.dumps(got["cves"]), got["severity"], got["score"], got["title"], now, now))


def _store_error(conn, ref: str, why: str, now: float) -> None:
    conn.execute("INSERT INTO opn_adv (ref, status, cves, tried_at, detail) VALUES (?, 'error', '[]', ?, ?) "
                 "ON CONFLICT (ref) DO UPDATE SET status = 'error', tried_at = excluded.tried_at, detail = excluded.detail "
                 "WHERE opn_adv.status != 'ok'", (ref, now, _short(why, 120)))


def due(rows: dict[str, dict], refs, now: float, refresh_hours: float) -> list[str]:
    """The references to ask for: no row yet, or a failure older than `refresh_hours`. A kept answer is never asked again."""
    out = []
    for ref in sorted(set(refs)):
        if kind(ref) is None:
            continue
        r = rows.get(ref)
        if r is None or (r["status"] != "ok" and (r["tried_at"] is None or now - r["tried_at"] >= refresh_hours * 3600)):
            out.append(ref)
    return out


# --- asking -----------------------------------------------------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, url: str, host: str, limit: int, headers: dict):
    """(status, headers, body) of one GET. HTTPS only, the answer must come from `host`, a redirect is not followed (a 3xx is
    returned as it is), and the body is read only up to `limit`."""
    try:
        async with client.stream("GET", url, headers=headers, follow_redirects=False) as r:
            u = r.request.url
            if u.scheme != "https" or u.host != host:
                raise FetchError(f"answered by {u.host}, which is not the source")
            if 300 <= r.status_code < 400:
                return r.status_code, r.headers, b""
            body = bytearray()
            async for chunk in r.aiter_bytes(1 << 14):
                body += chunk
                if len(body) > limit:
                    raise FetchError("the answer is larger than the limit")
            return r.status_code, r.headers, bytes(body)
    except httpx.HTTPError as exc:
        raise FetchError(f"{type(exc).__name__}"[:60]) from None


def gh_wait_until(headers, now: float) -> float:
    """When GitHub may be asked again after a 403, a 429 or a last allowed request: `retry-after` seconds if the answer has
    it, else `x-ratelimit-reset` when the remaining count is 0, else an hour. At least a minute, at most `GH_WAIT_MAX`."""
    wait = float(GH_WAIT_DEFAULT)
    try:
        if headers.get("retry-after"):
            wait = float(headers["retry-after"])
        elif headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset"):
            wait = float(headers["x-ratelimit-reset"]) - now
    except ValueError:
        pass
    return now + min(max(wait, 60.0), GH_WAIT_MAX)


async def resolve(conn, refs, now: float, refresh_hours: float, client: httpx.AsyncClient | None = None, sleep=None) -> dict:
    """Ask for each reference in `refs` that has no kept answer (and no failure younger than `refresh_hours`), one request at
    a time with `SPACING` between two to the same host, and keep what comes. Returns {"asked", "resolved", "failed",
    "waiting"} (`waiting`: references left for a later pass: over `PER_PASS`, or GitHub is rate limited until its reset).
    Never raises for an answer: a failure is stored on the advisory's row. `conn` is the chore's cve.db connection."""
    from . import store
    sleep = sleep or asyncio.sleep
    out = {"asked": 0, "resolved": 0, "failed": 0, "waiting": 0}
    todo = due(cached(conn, refs), refs, now, refresh_hours)
    if not todo:
        return out
    try:
        until = float(store.get_meta(conn, GH_UNTIL_KEY, "0") or 0)
    except ValueError:
        until = 0.0
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=False, headers={"User-Agent": USER_AGENT})
    asked_hosts: set[str] = set()
    blocked: set[str] = set()
    try:
        for ref in todo:
            host = host_of(ref)
            if out["asked"] >= PER_PASS or host in blocked or (host == GH_HOST and now < until):
                out["waiting"] += 1
                continue
            if host in asked_hosts:
                await sleep(SPACING[host])
            asked_hosts.add(host)
            out["asked"] += 1
            headers = {"User-Agent": USER_AGENT}
            if host == GH_HOST:
                headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
            try:
                status, hdrs, body = await _get(client, api_url(ref), host, GH_MAX_BYTES if host == GH_HOST else SA_MAX_BYTES, headers)
            except FetchError as exc:
                _store_error(conn, ref, str(exc), now)
                out["failed"] += 1
                continue
            limited = status == 429 or (status == 403 and (hdrs.get("retry-after") or hdrs.get("x-ratelimit-remaining") == "0"))
            if host == GH_HOST and limited:
                # Over the limit: stop, keep nothing against the advisory, and ask again only after the reset. (A plain 403 is
                # a refusal of that advisory, a failure like any other: it must not hold the others back.)
                until = gh_wait_until(hdrs, now)
                store.set_meta(conn, GH_UNTIL_KEY, str(until))
                blocked.add(host)
                out["waiting"] += 1
                continue
            if status == 429 or status == 503:
                blocked.add(host)
            try:
                if status != 200:
                    raise FetchError(f"HTTP {status}")
                if host == GH_HOST:
                    try:
                        got = parse_ghsa(ref, json.loads(body.decode("utf-8", "replace")))
                    except ValueError:
                        raise FetchError("the answer is not JSON") from None
                else:
                    got = parse_sa(ref, body.decode("utf-8", "replace"))
            except FetchError as exc:
                _store_error(conn, ref, str(exc), now)
                out["failed"] += 1
                continue
            _store_ok(conn, ref, got, now)
            out["resolved"] += 1
            if host == GH_HOST and hdrs.get("x-ratelimit-remaining") == "0":
                until = gh_wait_until(hdrs, now)        # the last request the window allows: wait for the reset
                store.set_meta(conn, GH_UNTIL_KEY, str(until))
                blocked.add(host)
    finally:
        if own:
            await client.aclose()
    return out
