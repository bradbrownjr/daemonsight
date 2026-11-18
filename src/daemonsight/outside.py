"""The outside view: what Shodan's InternetDB says the internet sees of each
host's public addresses, compared with what DaemonSight knows from inside.

InternetDB (https://internetdb.shodan.io/) answers `GET /<ip>` with
{ip, ports, cpes, hostnames, tags, vulns}, or HTTP 404 and
{"detail": "No information available"} when it has nothing on the address.
It needs no key, updates weekly, returns no banners, and is "free for
non-commercial use" ("If you're using the InternetDB API to make money then
you need an enterprise license"). So it is off by default ([outside] enabled).
Its rate limit is documented as bursts of up to 10,000 requests a second
(book.shodan.io, "InternetDB"); this module makes one request per address per
refresh, a second apart, and stops for the pass on HTTP 429.

The other source is Shodan's own REST API with the owner's key ([outside]
source = "shodan"; shodan.py holds the key file and its redaction). It is the
route for use InternetDB's terms do not cover: Shodan's pricing page lists
"Commercial Use" on its Freelancer, Small Business and Corporate API plans. A
host lookup, `GET https://api.shodan.io/shodan/host/<ip>?key=...`, uses no
query credits ("IP lookups don't consume query credits", book.shodan.io,
"Shodan API"), is limited to one request a second on every plan (pricing page),
and gives each port's transport, product, version and the time Shodan last saw
it. It is fetched in full: with `minify` the answer has "no banners", so no
per-port transport or time. One request per address per refresh, 1.2 s apart.
The key is sent only to api.shodan.io, only as the `key` query parameter (the
only way the documentation shows), and is redacted from every error and log
line. A refused key (HTTP 401/403) or no credits is reported as an
`outside.key` finding at once, and nothing falls back to InternetDB.

Only the IP address is sent, with the User-Agent "DaemonSight/<version>".
Private, loopback and link-local addresses are never sent. The answer is
untrusted text: it is size-capped, every field is checked and trimmed, it is
stored as data and escaped when shown.

The hub chore (`loop`) never blocks a page request: it runs on the event loop,
fetching with async HTTP, and everything else it does is a few small queries.
It keeps each host's `outside.*` findings current, as the CVE chore does for
`cve.*` (db.reconcile_findings with only_prefix).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from . import __version__, db, settings, shodan
from .config import Config
from .findings import Finding, anchor, digest, firewall_state, public_listeners

log = logging.getLogger("daemonsight.outside")

URL = "https://internetdb.shodan.io/"
DOCS = "https://internetdb.shodan.io/"
USER_AGENT = f"DaemonSight/{__version__}"
TERMS = ("Free for non-commercial use. \"If you're using the InternetDB API to make money then you need an "
         "enterprise license.\" (https://internetdb.shodan.io/)")
SHODAN_TERMS = ("Data from Shodan (https://www.shodan.io/). Shodan's pricing page says the API may be used in products "
                "\"as long as the data is attributed to Shodan\", and lists Commercial Use on its Freelancer, Small "
                "Business and Corporate plans (https://developer.shodan.io/pricing).")


def source_of(cfg: Config) -> str:
    """"shodan" when the Shodan API is chosen, else "internetdb"."""
    return "shodan" if cfg.outside.source == "shodan" else "internetdb"
MAX_BYTES = 1 << 20          # largest answer accepted
SHODAN_MAX_BYTES = 4 << 20   # a full host answer holds every banner (HTTP pages included)
GAP_SECONDS = 1.0            # between two requests in one pass
SOURCES = ("internetdb", "shodan")
SOURCE_NAMES = {"internetdb": "InternetDB", "shodan": "the Shodan API"}
RETRY_AFTER_ERROR = 3600     # seconds before asking again after a failure
STALE_FLOOR_HOURS = 72       # an answer older than max(this, 3 refreshes) is called stale

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,39}$")

# Tags that make `outside.tagged` critical. All four are in the Tag list of
# Shodan's own banner schema (https://datapedia.shodan.io/banner.schema.json,
# definitions.Tag.enum): "compromised" (a NoSQL database compromised for
# ransomware), "malware" (a verified command-and-control server, from Malware
# Hunter), "c2" (a command-and-control server), "doublepulsar" (an SMB banner
# answering the DoublePulsar backdoor handshake).
CRITICAL_TAGS = ("compromised", "malware", "c2", "doublepulsar")
TAG_NOTES = {
    "compromised": "Shodan thinks a service here was breached (it applies this to NoSQL databases held for ransom).",
    "malware": "Shodan thinks a service here is a malware command-and-control server.",
    "c2": "Shodan thinks a service here is a command-and-control server.",
    "doublepulsar": "An SMB service here answered the DoublePulsar backdoor handshake.",
}

# Addresses that are never sent to anyone: not reachable from the internet.
_NEVER = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fc00::/7", "fe80::/10")]


def sendable(value: str) -> str | None:
    """The canonical text of an address that may be sent to InternetDB, or None.
    Documentation ranges pass (a collector's scope check keeps real hosts from
    reporting them); anything private, local or special does not."""
    try:
        addr = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified
            or any(addr in n for n in _NEVER)):
        return None
    return str(addr)


def port_expected(expected, port: int) -> bool:
    """Whether exposure.expected_public lists this port number, on any protocol
    (InternetDB gives port numbers only)."""
    return any(str(e).partition("/")[0] == str(port) for e in expected)


# ---- which addresses -----------------------------------------------------------

def public_addresses(ports: dict | None) -> list[str]:
    """A host's own addresses with scope "public" in its ports snapshot (the
    snapshot is a collector's upload: untrusted, so each is checked again)."""
    out = []
    for a in (ports or {}).get("addresses", []):
        if isinstance(a, dict) and a.get("scope") == "public" and isinstance(a.get("ip"), str):
            ip = sendable(a["ip"])
            if ip and ip not in out:
                out.append(ip)
    return out


def config_addresses(cfg: Config) -> list[tuple[str, str | None]]:
    """[outside] addresses as (ip, host or None). Entries that are not an
    address a public check can use are logged and left out."""
    out = []
    for entry in cfg.outside.addresses:
        ip_text, _, host = str(entry).partition("=")
        ip = sendable(ip_text.strip())
        if ip is None:
            log.warning("[outside] addresses: %r is not a public IP address; skipped", ip_text.strip())
            continue
        out.append((ip, host.strip() or None))
    return out


def host_addresses(host: str, ports: dict | None, cfg: Config) -> list[str]:
    """Every address to check for one host: its own public ones, then the
    config's extras for it ("ip=host", or a plain ip it reports itself)."""
    out = public_addresses(ports)
    for ip, to in config_addresses(cfg):
        if to == host and ip not in out:
            out.append(ip)
    return out


def targets(conn, cfg: Config) -> dict[str, set[str]]:
    """address -> the hosts it belongs to, for every host the hub knows."""
    out: dict[str, set[str]] = {}
    hosts = [r["id"] for r in conn.execute("SELECT id FROM hosts ORDER BY id")]
    for host in hosts:
        snap = db.get_snapshot(conn, host, "ports")
        data = snap.data if snap and snap.data and snap.data.get("available") is not False else None
        for ip in host_addresses(host, data, cfg):
            out.setdefault(ip, set()).add(host)
    for ip, to in config_addresses(cfg):
        if to is None and ip not in out:
            log.warning("[outside] address %s is not reported by any host; write it as \"%s=<host id>\" to attach it",
                        ip, ip)
    return out


# ---- the answer ------------------------------------------------------------------

def _text(value, limit: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    return value


def clean(payload) -> dict | None:
    """The answer reduced to what DaemonSight uses, or None when it isn't the
    documented shape. Every field is optional, trimmed, and checked."""
    if not isinstance(payload, dict):
        return None

    def items(key, keep, cap):
        raw = payload.get(key)
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError(key)
        out = []
        for x in raw[:cap * 2]:
            y = keep(x)
            if y is not None and y not in out:
                out.append(y)
        return out[:cap]

    try:
        ports = items("ports", lambda p: p if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536 else None, 1000)
        return {
            "ports": sorted(ports),
            "cpes": items("cpes", lambda x: _text(x, 200), 100),
            "hostnames": items("hostnames", lambda x: _text(x, 253), 50),
            "tags": items("tags", lambda x: x if isinstance(x, str) and TAG_RE.match(x) else None, 50),
            "vulns": sorted(items("vulns", lambda x: x if isinstance(x, str) and CVE_RE.match(x) else None, 2000)),
        }
    except ValueError:
        return None


@dataclass
class Result:
    status: str                      # "ok", "none" or "error"
    data: dict | None = None
    error: str | None = None
    retry_after: float | None = None  # the whole pass should stop for this long (HTTP 429)
    stop: bool = False                # the key was refused, or Shodan has no credits: asking again now is pointless


async def fetch(client: httpx.AsyncClient, ip: str) -> Result:
    """Ask InternetDB about one address. Never raises."""
    try:
        async with client.stream("GET", URL + ip, headers={"User-Agent": USER_AGENT}) as r:
            code = r.status_code
            if code == 404:
                return Result("none")
            if code == 429:
                try:
                    wait = min(float(r.headers.get("retry-after", "")), 86400)
                except ValueError:
                    wait = 3600
                return Result("error", error="HTTP 429: InternetDB says slow down", retry_after=wait)
            if code != 200:
                return Result("error", error=f"HTTP {code}")
            body = b""
            async for chunk in r.aiter_bytes(1 << 14):
                body += chunk
                if len(body) > MAX_BYTES:
                    return Result("error", error="answer is larger than the limit")
    except httpx.HTTPError as exc:
        return Result("error", error=f"{type(exc).__name__}: {exc}"[:200])
    try:
        data = clean(json.loads(body))
    except (ValueError, RecursionError):
        data = None
    if data is None:
        return Result("error", error="the answer is not the documented shape")
    return Result("ok", data)


def _port(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536 else None


def _when(value) -> float | None:
    """Shodan's banner time, "2021-01-22T08:49:35.190817" (UTC, no zone), as epoch seconds."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


TRANSPORT_RE = re.compile(r"^[a-z]{2,10}$")


def empty_shodan() -> dict:
    return {"source": "shodan", "ports": [], "services": [], "cpes": [], "hostnames": [], "tags": [], "vulns": [],
            "last_update": None}


def clean_host(payload) -> dict | None:
    """A Shodan host lookup reduced to what DaemonSight uses, in the shape `clean` gives plus `services` (one per
    port and transport: product, version, the time Shodan last saw it) and `source`; None when it isn't the
    documented shape. The documented fields (https://developer.shodan.io/api, GET /shodan/host/{ip}, and the banner
    schema at https://datapedia.shodan.io/): ports, hostnames, tags, last_update, and data[] banners with port,
    transport, timestamp, optional product, version, cpe23 and vulns."""
    if not isinstance(payload, dict):
        return None
    try:
        banners = payload.get("data")
        if banners is None:
            banners = []
        if not isinstance(banners, list):
            raise ValueError("data")
        services: dict[tuple[int, str], dict] = {}
        cpes: list[str] = []
        vulns: set[str] = set()
        for b in banners[:2000]:
            if not isinstance(b, dict):
                continue
            port, transport = _port(b.get("port")), b.get("transport")
            if port is None or not isinstance(transport, str) or not TRANSPORT_RE.match(transport):
                continue
            svc = {"port": port, "transport": transport, "product": _text(b.get("product"), 100),
                   "version": _text(b.get("version"), 60), "seen": _when(b.get("timestamp"))}
            old = services.get((port, transport))
            if old is None or (svc["seen"] or 0) >= (old["seen"] or 0):
                services[(port, transport)] = svc
            listed = b.get("cpe23") if isinstance(b.get("cpe23"), list) else b.get("cpe")
            for c in listed if isinstance(listed, list) else []:
                c = _text(c, 200)
                if c and c not in cpes and len(cpes) < 100:
                    cpes.append(c)
            bv = b.get("vulns")
            if isinstance(bv, dict):
                vulns.update(k for k in list(bv)[:2000] if isinstance(k, str) and CVE_RE.match(k))

        def items(key, keep, cap):
            raw = payload.get(key)
            if raw is None:
                return []
            if not isinstance(raw, list):
                raise ValueError(key)
            out = []
            for x in raw[:cap * 2]:
                y = keep(x)
                if y is not None and y not in out:
                    out.append(y)
            return out[:cap]

        ports = items("ports", _port, 1000) if payload.get("ports") is not None else sorted({k[0] for k in services})
        top_vulns = payload.get("vulns")
        if isinstance(top_vulns, dict):
            top_vulns = list(top_vulns)
        if isinstance(top_vulns, list):
            vulns.update(v for v in top_vulns[:4000] if isinstance(v, str) and CVE_RE.match(v))
        return {
            "source": "shodan",
            "ports": sorted(ports),
            "services": [services[k] for k in sorted(services)][:1000],
            "cpes": cpes,
            "hostnames": items("hostnames", lambda x: _text(x, 253), 50),
            "tags": items("tags", lambda x: x if isinstance(x, str) and TAG_RE.match(x) else None, 50),
            "vulns": sorted(vulns)[:2000],
            "last_update": _when(payload.get("last_update")),
        }
    except ValueError:
        return None


async def _read(r: httpx.Response, limit: int) -> bytes | None:
    body = b""
    async for chunk in r.aiter_bytes(1 << 14):
        body += chunk
        if len(body) > limit:
            return None
    return body


async def fetch_shodan(client: httpx.AsyncClient, ip: str, key: str) -> Result:
    """Ask the Shodan API about one address (a full host lookup, one address per request). Never raises. Every
    error text is redacted: the key is a query parameter and must not leave this function in any message."""
    try:
        async with client.stream("GET", shodan.HOST_URL + ip, params={"key": key},
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json"}) as r:
            code = r.status_code
            if code == 429:
                try:
                    wait = min(float(r.headers.get("retry-after", "")), 86400)
                except ValueError:
                    wait = 3600
                return Result("error", error="HTTP 429: Shodan says slow down (its limit is 1 request a second)",
                              retry_after=wait)
            body = await _read(r, SHODAN_MAX_BYTES if code == 200 else 1 << 16)
    except httpx.HTTPError as exc:
        return Result("error", error=shodan.redact(f"{type(exc).__name__}: {exc}", key)[:200])
    if body is None:
        return Result("error", error="answer is larger than the limit")
    if code == 404:
        return Result("none", empty_shodan())
    if code != 200:
        text = shodan.error_text(code, body, key)
        return Result("error", error=text[:400], stop=text.startswith((shodan.KEY_REFUSED, shodan.NO_CREDITS)))
    try:
        data = clean_host(json.loads(body))
    except (ValueError, RecursionError):
        data = None
    if data is None:
        return Result("error", error="the answer is not the documented shape")
    return Result("ok", data)


# ---- storage ---------------------------------------------------------------------

def get_rows(conn) -> dict[str, dict]:
    """ip -> row (data decoded). Empty when the table isn't there yet (a hub
    that has not migrated: the web process only reads)."""
    try:
        rows = conn.execute("SELECT * FROM outside").fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for r in rows:
        d = dict(r)
        try:
            d["data"] = json.loads(r["data"]) if r["data"] else None
        except ValueError:
            d["data"] = None
        out[d["ip"]] = d
    return out


def store_result(conn, ip: str, res: Result, now: float) -> None:
    if res.status == "error":
        conn.execute(
            "INSERT INTO outside (ip, first_try, checked_at, status, error) VALUES (?, ?, ?, 'error', ?) "
            "ON CONFLICT (ip) DO UPDATE SET checked_at=excluded.checked_at, error=excluded.error",
            (ip, now, now, res.error))
        return
    conn.execute(
        "INSERT INTO outside (ip, first_try, checked_at, fetched_at, status, data, error) VALUES (?, ?, ?, ?, ?, ?, NULL) "
        "ON CONFLICT (ip) DO UPDATE SET checked_at=excluded.checked_at, fetched_at=excluded.fetched_at, "
        "status=excluded.status, data=excluded.data, error=NULL",
        (ip, now, now, now, res.status, json.dumps(res.data) if res.data is not None else None))


def row_source(row: dict) -> str:
    """Which source a stored answer came from. An InternetDB answer carries no mark; a Shodan one says "shodan"."""
    data = row.get("data")
    return "shodan" if isinstance(data, dict) and data.get("source") == "shodan" else "internetdb"


def is_due(row: dict | None, now: float, refresh_hours: float, source: str = "internetdb") -> bool:
    if row is None:
        return True
    if row["fetched_at"] is not None and row_source(row) != source:
        return True      # the source was changed: ask the new one now, whatever the old answer's age
    wait = refresh_hours * 3600
    if row["error"]:
        wait = min(wait, RETRY_AFTER_ERROR)
    return now - row["checked_at"] >= wait


def stale_after(refresh_hours: float) -> float:
    return max(STALE_FLOOR_HOURS, 3 * refresh_hours) * 3600


def is_stale(row: dict, now: float, refresh_hours: float) -> bool:
    """No good answer within three refreshes (at least 72 hours; InternetDB itself updates weekly)."""
    since = row["fetched_at"] if row["fetched_at"] is not None else row["first_try"]
    return now - since > stale_after(refresh_hours)


# ---- what DaemonSight knows about a port --------------------------------------------

def _data(snaps: dict, source: str) -> dict | None:
    snap = snaps.get(source)
    if snap is None or not snap.data or snap.data.get("available") is False:
        return None
    return snap.data


TUNNEL_NICS = ("wg", "tun", "tap", "tailscale", "ppp", "zt", "ts")


def _target_ip(to: str) -> str | None:
    """The address in a DNAT target: 10.99.0.2, 10.99.0.2:8080, [fd00::2]:80."""
    t = str(to or "").strip()
    m = re.match(r"^\[([^\]]+)\](?::[\d-]+)?$", t)
    if m:
        t = m.group(1)
    elif t.count(":") == 1:
        t = t.split(":")[0]
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def nic_for(to: str, ports: dict | None) -> str | None:
    """The host's interface whose subnet (/24, or /64 for IPv6) holds a forward's
    target, or None. The ports snapshot has addresses without prefix lengths, so
    this is a guess from the neighbour address, and is worded as one."""
    ip = _target_ip(to)
    if ip is None:
        return None
    want = ipaddress.ip_address(ip)
    for a in (ports or {}).get("addresses", []):
        try:
            mine = ipaddress.ip_address(str(a.get("ip", "")).split("%", 1)[0])
        except ValueError:
            continue
        if mine.version != want.version or not a.get("nic"):
            continue
        net = ipaddress.ip_network(f"{mine}/{24 if mine.version == 4 else 64}", strict=False)
        if want in net and mine != want:
            return str(a["nic"])
    return None


def explain_port(snaps: dict, port: int) -> list[str]:
    """Plain sentences about one port number on a host, from its own readings:
    what listens on it, what forwards it, what Docker publishes. The last
    sentence says so when there is nothing."""
    lines = []
    ports = _data(snaps, "ports") or {}
    names = {c["id"]: c["name"] for c in (_data(snaps, "docker") or {}).get("containers", []) if isinstance(c, dict)}
    for r in ports.get("listeners", []):
        if r.get("port") != port:
            continue
        owner = r.get("owner") or {}
        parts = [r.get("process") or "an unknown process"]
        if owner.get("kind") == "unit":
            parts.append(f"unit {owner['id']}")
        elif owner.get("kind") == "container":
            parts.append(f"container {names.get(owner['id'], str(owner['id'])[:12])}")
        who = parts[0] + (f" ({', '.join(parts[1:])})" if len(parts) > 1 else "")
        where = ", ".join(r.get("addresses", []))
        local = " It is bound to loopback only, so it is not what answers from outside." if r.get("scope") == "loopback" else ""
        lines.append(f"A listener on this host: {who} on {r['proto']} port {port}, bound to {where}.{local}")
    for c in (_data(snaps, "docker") or {}).get("containers", []):
        for p in c.get("ports", []) if isinstance(c, dict) else []:
            if p.get("host_port") == port and c.get("status") == "running":
                lines.append(f"Container {c['name']} publishes {p.get('host_ip') or '*'}:{port} to its port "
                             f"{p.get('container_port')}/{p.get('proto')}.")
    by_target: dict[str, list[dict]] = {}
    for f in (_data(snaps, "firewall") or {}).get("forwards", []):
        if any(lo <= port <= hi for lo, hi in f["ranges"]):
            by_target.setdefault(f["to"], []).append(f)
    for to, fwds in by_target.items():
        nic = nic_for(to, ports)
        via = ""
        if nic:
            via = f" over the {nic} tunnel" if nic.startswith(TUNNEL_NICS) else f" through {nic}"
        covered = []
        for f in fwds:
            proto = {"all": "TCP and UDP"}.get(f["proto"], f["proto"].upper())
            when = f", arriving {', '.join(f['conditions'])}" if f["conditions"] else ""
            covered.append(f"{proto} ports {f['ports']}{when}")
        lines.append(f"A port forward sends it to {to}{via}: the rules cover {'; '.join(covered)}. "
                     f"Whatever listens on {to} answers.")
    if not lines:
        lines.append("Nothing on this host listens on it, and no port forward covers it.")
    return lines


def _serves(listener: dict, ip: str) -> bool:
    """Whether a listener can answer on this address: bound to the address, to 0.0.0.0
    (IPv4 only), or to :: (taken to serve both families, the Linux default)."""
    want = ipaddress.ip_address(ip)
    for a in listener.get("addresses", []):
        if a == "::":
            return True
        if a == "0.0.0.0":
            if want.version == 4:
                return True
            continue
        try:
            if ipaddress.ip_address(a.split("%", 1)[0]) == want:
                return True
        except ValueError:
            continue
    return False


def expected_ports_here(snaps: dict, cfg_expected, upstream, ip: str, eph) -> dict[int, str]:
    """Ports DaemonSight judges reachable from the internet on this address and
    listed in expected_public: port -> who listens. Not judged: a port the
    firewall blocks or forwards away, or one the provider firewall keeps out."""
    out: dict[int, str] = {}

    def allowed(proto: str, port: int) -> bool:
        return not upstream or f"{port}/{proto}" in upstream

    for r in public_listeners(snaps, {"eph": eph}):
        if not port_expected(cfg_expected, r["port"]) or not _serves(r, ip):
            continue
        if not allowed(r["proto"], r["port"]):
            continue
        if firewall_state(snaps, r["proto"], r["port"], r["addresses"])["state"] in ("forwarded", "blocked", "restricted"):
            continue
        out.setdefault(r["port"], r.get("process") or "an unknown process")
    for c in (_data(snaps, "docker") or {}).get("containers", []):
        for p in c.get("ports", []) if isinstance(c, dict) else []:
            if (c.get("status") == "running" and p.get("host_ip") in ("0.0.0.0", "::", "")
                    and isinstance(p.get("host_port"), int) and port_expected(cfg_expected, p["host_port"])
                    and allowed(p["proto"], p["host_port"])):
                out.setdefault(p["host_port"], f"container {c['name']}")
    return out


def eph_of(snaps: dict) -> tuple[int, int]:
    snap = snaps.get("settings")
    e = (snap.data or {}).get("eph") if snap and snap.data else None
    return (int(e[0]), int(e[1])) if isinstance(e, list) and len(e) == 2 else (32768, 60999)


# ---- the rules -------------------------------------------------------------------

def service_label(svc: dict) -> str:
    """"nginx 1.24.0", "nginx", or "" when Shodan named no software."""
    return " ".join(x for x in (svc.get("product"), svc.get("version")) if x)


def seen_on(svcs: list[dict]) -> str:
    """One sentence about what Shodan saw on a port, from its services (one per transport). No dates in the
    basis: this is detail only."""
    parts = []
    for svc in svcs:
        what = service_label(svc) or "a service it could not name"
        when = (f", last seen {time.strftime('%Y-%m-%d', time.gmtime(svc['seen']))}" if svc.get("seen") else "")
        parts.append(f"{what} over {svc['transport'].upper()}{when}")
    return "Shodan saw " + "; ".join(parts) + "."


def _ids(items: list[str], limit: int = 8) -> str:
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def key_finding(problem: str, error: str | None) -> Finding:
    """The Shodan key is the reason this host's addresses can't be refreshed: said once for the host, at once,
    with the fix. Basis is the kind of problem only, so it does not reopen when the text changes."""
    title, how = {
        "refused": ("Shodan refused the API key",
                    "Open Settings, Outside view, and press Test key to see Shodan's answer.\n"
                    "Copy the key again from https://account.shodan.io/ and replace the saved one.\n"
                    "Looking up IPs through the Shodan API needs at least a Membership; a free account's key is refused.\n"
                    "To stop asking Shodan, set Source back to InternetDB (free for non-commercial use only) or turn the Outside view off."),
        "missing": ("The Shodan API is selected but no key is saved",
                    "Open Settings, Outside view, paste your Shodan API key and save it.\n"
                    "Or set Source back to InternetDB (free for non-commercial use only)."),
        "credits": ("Shodan has no query credits left",
                    "Open Settings, Outside view, and press Test key to see the credits Shodan reports.\n"
                    "Query credits renew at the start of each month (https://help.shodan.io/the-basics/credit-types-explained).\n"
                    "Host lookups are documented as using none, so look at the plan too (https://account.shodan.io/)."),
    }[problem]
    return Finding("outside.key", "shodan", "medium", title,
                   f"{error or title}. Nothing is being refreshed for this host's public addresses, and DaemonSight "
                   "does not fall back to InternetDB on its own: the findings from Shodan come from the last good "
                   "answer, if any.",
                   "/settings#outside", basis=problem, howto=how)


def host_findings(host: str, rows: dict[str, dict], snaps: dict, exposure, now: float, refresh_hours: float,
                  cve_matches: dict[str, str] | None = None, source: str = "internetdb") -> list[Finding]:
    """The `outside.*` findings for one host. `rows` are the stored answers for
    its addresses (ip -> row), `exposure` its ExposureConfig, `cve_matches`
    DaemonSight's own CVE matches for it (cve id -> state), or None when that
    data does not exist."""
    out: list[Finding] = []
    expected = exposure.expected_public
    eph = eph_of(snaps)
    name = SOURCE_NAMES.get(source, "InternetDB")
    for ip, row in sorted(rows.items()):
        link = f"/exposure#{anchor('outside', ip)}"
        problem = next((k for p, k in shodan.KEY_PROBLEMS.items() if (row["error"] or "").startswith(p)), None) \
            if source == "shodan" else None
        if problem and not any(f.rule == "outside.key" for f in out):
            out.append(key_finding(problem, row["error"]))
        if is_stale(row, now, refresh_hours):
            since = row["fetched_at"]
            when = (f"The last good answer is {int((now - since) // 86400)} days old." if since is not None
                    else "It has never answered.")
            how = ("Check that the hub can reach https://api.shodan.io/ and that the key still works (Settings, Outside view, Test key).\n"
                   "Shodan's limit is 1 request a second on every plan. If the error says HTTP 429, raise refresh_hours under [outside]."
                   if source == "shodan" else
                   "Check that the hub can reach https://internetdb.shodan.io/ (see the source panel for a curl command).\n"
                   "If the error says HTTP 429, raise refresh_hours under [outside].")
            out.append(Finding(
                "outside.stale", ip, "low", f"Shodan's view of {ip} could not be refreshed",
                f"{name[0].upper() + name[1:]} has not given a good answer for {ip} for a while. {when} The last error was: "
                f"{row['error'] or 'none recorded'}. The outside findings for this address come from the last good answer.",
                link, basis=ip, howto=how))
        if row["status"] not in ("ok", "none") or row["fetched_at"] is None:
            continue
        data = row["data"] or {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
        via_api = data.get("source") == "shodan"
        by_port: dict[int, list[dict]] = {}
        for svc in data.get("services", []):
            by_port.setdefault(svc["port"], []).append(svc)
        seen = set(data["ports"])
        for p in data["ports"]:
            if port_expected(expected, p):
                continue
            lines = explain_port(snaps, p)
            if via_api:
                lag = (seen_on(by_port[p]) + " Shodan's data can lag behind a change." if p in by_port else
                       "Shodan listed the port with no banner, so it does not say whether it is TCP or UDP. "
                       "Its data can lag behind a change.")
            else:
                lag = "Shodan's data is up to a week old, and it does not say whether the port is TCP or UDP."
            out.append(Finding(
                "outside.unexpected_port", f"{ip} {p}", "high", f"Shodan sees port {p} open on {ip}",
                f"Port {p} is not in exposure.expected_public. " + " ".join(lines) + " " + lag,
                f"/exposure#{anchor('outside', ip, p)}", basis=f"{ip}|{p}|{digest(lines)}",
                howto=f"Find what answers on port {p}: the source panel on the port's row says what DaemonSight knows.\n"
                      f"If it is meant to be public, add \"{p}/tcp\" (or udp) to exposure.expected_public in the host's config.\n"
                      "If it is not, stop the service or bind it to 127.0.0.1, or close the forward or the provider firewall rule that lets it in.\n"
                      "Once it is closed this clears at the next refresh. Shodan rescans about weekly, so its own data may lag."))
        if row["status"] == "none" and ipaddress.ip_address(ip).version == 6:
            pass  # a missing IPv6 address says little; not judged
        else:
            for p, who in sorted(expected_ports_here(snaps, expected, exposure.upstream_allow, ip, eph).items()):
                if p in seen:
                    continue
                why = ("Shodan has no record of this address at all." if row["status"] == "none"
                       else "Shodan lists other ports on this address, but not this one.")
                out.append(Finding(
                    "outside.not_seen", f"{ip} {p}", "low", f"Shodan does not list port {p} on {ip}",
                    f"DaemonSight expects port {p} to be public on this host ({who} listens on it, and it is in "
                    f"exposure.expected_public). {why} That may be fine: Shodan may not have scanned it yet "
                    + ("(Shodan crawls the internet at least once a week)" if via_api else "(InternetDB updates once a week)")
                    + ", or a provider firewall may keep Shodan's scanners out.",
                    f"/exposure#{anchor('outside', ip)}", basis=f"{ip}|{p}",
                    howto=f"Test it yourself from a machine outside your network, for example: curl -sv --connect-timeout 5 http://{ip}:{p}/ "
                          "(use the right protocol for the service).\n"
                          "If it answers, there is nothing to fix; accept this finding with a note, or wait for Shodan's next scan.\n"
                          "If it does not answer, the service is not reachable from outside: check the host firewall and the provider firewall."))
        crit = [t for t in data["tags"] if t in CRITICAL_TAGS]
        if crit:
            notes = " ".join(TAG_NOTES[t] for t in crit)
            out.append(Finding(
                "outside.tagged", ip, "critical", f"Shodan tags {ip} as {', '.join(crit)}",
                f"{notes} These tags are Shodan's own classification, made by scanning from outside; DaemonSight "
                "cannot confirm them from inside. Treat it as a possible compromise until you have checked.",
                link, basis=f"{ip}|{','.join(sorted(crit))}",
                howto="Check what listens on this address and who started it: the Exposure page lists every listener and forward.\n"
                      "Look through the host's logs and its process list for anything you did not install.\n"
                      "If the host is compromised, isolate it, rotate the credentials it holds, and rebuild it from a known-good image.\n"
                      "If you find nothing, the tag may be a false positive: accept this finding with a note saying what you checked."))
        vulns = data["vulns"]
        if vulns:
            if cve_matches is None:
                cross = "DaemonSight's own CVE matching has no data for this host to compare with."
            else:
                both = [v for v in vulns if v in cve_matches]
                cross = (f"{len(both)} of them are also in DaemonSight's own package matches for this host: {_ids(both)}."
                         if both else
                         "None of them is in DaemonSight's own package matches for this host. That is common: a banner "
                         "shows the upstream version, and distributions fix bugs without changing it.")
            out.append(Finding(
                "outside.vulns", ip, "medium", f"Shodan lists {len(vulns)} CVE{'s' if len(vulns) != 1 else ''} for {ip}",
                f"{_ids(vulns)}. These are guesses: "
                + ("Shodan matches the software version a service shows in its banner against known CVEs, and some "
                   "of them are marked unverified. " if via_api else
                   "InternetDB matches the software version a service shows in its banner against known CVEs, and "
                   "returns no banners to check. ") + cross,
                link, basis=f"{ip}|{digest(vulns)}",
                howto="Open the Seen from outside section on the Exposure page for the full list and the services behind it.\n"
                      "For each, check the version the service really runs, and whether your distribution backported the fix (the Vulnerabilities page does this for installed packages).\n"
                      "Update or close what is really affected. If the list is a false alarm, accept this finding with a note."))
    return out


# ---- the chore ---------------------------------------------------------------------

def _hosts_with_outside_findings(conn) -> set[str]:
    return {r["host"] for r in conn.execute(
        "SELECT DISTINCT host FROM findings WHERE rule LIKE 'outside.%' AND resolved_at IS NULL")}


def _set_findings(conn, host: str, now: float, current: list[Finding]) -> None:
    changes = db.reconcile_findings(conn, host, now, current, only_prefix="outside.")
    for change, f in changes:
        if change == "opened":
            db.add_event(conn, host, now, "finding_opened", f.title, severity=f.severity, detail=f.detail, link=f.link)
        else:
            db.add_event(conn, host, now, "finding_resolved", f"Resolved: {f['title']}", link=f["link"])


def clear_findings(conn, now: float) -> None:
    """With [outside] off, close any outside.* finding left from when it was on."""
    for host in _hosts_with_outside_findings(conn):
        db.reconcile_findings(conn, host, now, [], only_prefix="outside.")


def _cve_matches(cfg: Config, host: str) -> dict[str, str] | None:
    """DaemonSight's own CVE matches for a host (cve id -> state), or None when [cve] has no data."""
    if not cfg.cve.enabled:
        return None
    from .cve import match, store
    cdb = store.connect_reader(cfg.cve_db_path)
    if cdb is None:
        return None
    try:
        return {c["cve"]: c["state"] for c in match.host_cves(cdb, host)}
    except sqlite3.Error:
        return None
    finally:
        cdb.close()


class Chore:
    def __init__(self, cfg: Config, state_conn, client: httpx.AsyncClient | None = None, gap: float | None = None):
        self.base = cfg            # the config file's values; self.cfg adds the Settings page's, each pass
        self.cfg = cfg
        self.state = state_conn
        self.client = client       # an httpx client for tests
        self.gap = gap             # seconds between requests; None: the source's own (a test passes 0)
        self.paused_until = 0.0    # after an HTTP 429
        self.mark: tuple | None = None   # (source, a digest of the key): when it changes, key errors are retried at once

    def _gap(self, source: str) -> float:
        if self.gap is not None:
            return self.gap
        return shodan.RATE_LIMIT_GAP if source == "shodan" else GAP_SECONDS

    async def run_once(self, now: float | None = None) -> int:
        """One pass: fetch what is due, then bring the findings up to date.
        Returns the number of requests made. Does nothing when disabled."""
        now = time.time() if now is None else now
        # Read the settings afresh: a change on the Settings page applies on this pass.
        self.cfg = settings.effective(self.base, self.state)
        if not self.cfg.outside.enabled:
            clear_findings(self.state, now)
            return 0
        source = source_of(self.cfg)
        key = shodan.read_key(self.cfg) if source == "shodan" else None
        mark = (source, hashlib.sha256(key.encode()).hexdigest() if key else None)
        retry_key_errors, self.mark = mark != self.mark, mark
        tg = targets(self.state, self.cfg)
        rows = get_rows(self.state)
        hours = self.cfg.outside.refresh_hours
        due = sorted(ip for ip in tg if is_due(rows.get(ip), now, hours, source)
                     or (retry_key_errors and (rows[ip]["error"] or "").startswith(tuple(shodan.KEY_PROBLEMS))))
        sent = 0
        if due and source == "shodan" and key is None:
            for ip in due:
                store_result(self.state, ip, Result("error", error=(
                    f"{shodan.KEY_MISSING}. Save one on the Settings page, or set Source back to InternetDB.")), now)
        elif due and now >= self.paused_until:
            own = self.client is None
            client = self.client or httpx.AsyncClient(timeout=httpx.Timeout(20.0), follow_redirects=False)
            gap = self._gap(source)
            try:
                for i, ip in enumerate(due):
                    if i and gap:
                        await asyncio.sleep(gap)
                    res = await (fetch_shodan(client, ip, key) if source == "shodan" else fetch(client, ip))
                    sent += 1
                    store_result(self.state, ip, res, now)
                    if res.stop:
                        # The key is refused, or Shodan has no credits: every other address would get the same
                        # answer, so say so for each without asking again.
                        for rest in due[i + 1:]:
                            store_result(self.state, rest, Result("error", error=res.error), now)
                        log.warning("Shodan API: %s", shodan.redact(res.error, key))
                        break
                    if res.retry_after:
                        self.paused_until = now + res.retry_after
                        log.warning("%s asked us to wait; pausing outside checks for %.0f s",
                                    "Shodan" if source == "shodan" else "InternetDB", res.retry_after)
                        break
            finally:
                if own:
                    await client.aclose()
        # Forget an address that nothing has asked for in a month (a host's address changed).
        for ip, row in rows.items():
            if ip not in tg and now - row["checked_at"] > 30 * 86400:
                self.state.execute("DELETE FROM outside WHERE ip = ?", (ip,))
        self.rebuild(tg, now)
        return sent

    def rebuild(self, tg: dict[str, set[str]], now: float) -> None:
        from .web import views
        rows = get_rows(self.state)
        by_host: dict[str, dict[str, dict]] = {}
        for ip, hosts in tg.items():
            for h in hosts:
                if ip in rows:
                    by_host.setdefault(h, {})[ip] = rows[ip]
        for host in sorted(set(by_host) | _hosts_with_outside_findings(self.state)):
            hcfg = views.host_config(self.state, self.cfg, host)
            snaps = db.get_snapshots(self.state, host)
            current = host_findings(host, by_host.get(host, {}), snaps, hcfg.exposure, now,
                                    self.cfg.outside.refresh_hours, _cve_matches(self.cfg, host),
                                    source_of(self.cfg)) \
                if host in by_host else []
            _set_findings(self.state, host, now, current)


async def loop(cfg: Config, state_conn, client: httpx.AsyncClient | None = None) -> None:
    chore = Chore(cfg, state_conn, client)
    await asyncio.sleep(10)   # let the web server and the first uploads settle
    while True:
        try:
            await chore.run_once()
        except Exception:
            log.exception("Outside check failed")
        await asyncio.sleep(60)
