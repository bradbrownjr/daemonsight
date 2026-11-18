"""The outside view: what Shodan's InternetDB says the internet sees of each
host's public addresses, compared with what DaemonSight knows from inside.

InternetDB (https://internetdb.shodan.io/) answers `GET /<ip>` with
{ip, ports, cpes, hostnames, tags, vulns}, or HTTP 404 and
{"detail": "No information available"} when it has nothing on the address.
It needs no key, updates weekly, returns no banners, and is "free for
non-commercial use" ("If you're using the InternetDB API to make money then
you need an enterprise license"). So it is off by default ([outside] enabled).
Its rate limits are not documented; this module makes one request per address
per refresh, a second apart, and stops for the pass on HTTP 429.

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
import ipaddress
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass

import httpx

from . import __version__, db
from .config import Config
from .findings import Finding, anchor, digest, firewall_state, public_listeners

log = logging.getLogger("daemonsight.outside")

URL = "https://internetdb.shodan.io/"
DOCS = "https://internetdb.shodan.io/"
USER_AGENT = f"DaemonSight/{__version__}"
TERMS = ("Free for non-commercial use. \"If you're using the InternetDB API to make money then you need an "
         "enterprise license.\" (https://internetdb.shodan.io/)")
MAX_BYTES = 1 << 20          # largest answer accepted
GAP_SECONDS = 1.0            # between two requests in one pass
RETRY_AFTER_ERROR = 3600     # seconds before asking again after a failure
STALE_FLOOR_HOURS = 72       # an answer older than max(this, 3 refreshes) is called stale

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,39}$")

# Tags that make `outside.tagged` critical. From Shodan's tag filter as listed
# by a third-party client library (github.com/denisgubin/shodan, models/tags),
# since Shodan's own help pages list no values: "compromised" (a NoSQL database
# compromised for ransomware), "malware" (a verified command-and-control
# server, from Malware Hunter), "doublepulsar" (an SMB banner answering the
# DoublePulsar backdoor handshake). "c2" is on the owner's list and in
# Shodan's top tags; it is unverified in any official text.
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


def is_due(row: dict | None, now: float, refresh_hours: float) -> bool:
    if row is None:
        return True
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

def _ids(items: list[str], limit: int = 8) -> str:
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def host_findings(host: str, rows: dict[str, dict], snaps: dict, exposure, now: float, refresh_hours: float,
                  cve_matches: dict[str, str] | None = None) -> list[Finding]:
    """The `outside.*` findings for one host. `rows` are the stored answers for
    its addresses (ip -> row), `exposure` its ExposureConfig, `cve_matches`
    DaemonSight's own CVE matches for it (cve id -> state), or None when that
    data does not exist."""
    out: list[Finding] = []
    expected = exposure.expected_public
    eph = eph_of(snaps)
    for ip, row in sorted(rows.items()):
        link = f"/exposure#{anchor('outside', ip)}"
        if is_stale(row, now, refresh_hours):
            since = row["fetched_at"]
            when = (f"The last good answer is {int((now - since) // 86400)} days old." if since is not None
                    else "It has never answered.")
            out.append(Finding(
                "outside.stale", ip, "low", f"Shodan's view of {ip} could not be refreshed",
                f"InternetDB has not given a good answer for {ip} for a while. {when} The last error was: "
                f"{row['error'] or 'none recorded'}. The outside findings for this address come from the last good answer.",
                link, basis=ip,
                howto="Check that the hub can reach https://internetdb.shodan.io/ (see the source panel for a curl command).\n"
                      "Rate limits are not documented. If the error says HTTP 429, raise refresh_hours under [outside]."))
        if row["status"] not in ("ok", "none") or row["fetched_at"] is None:
            continue
        data = row["data"] or {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
        seen = set(data["ports"])
        for p in data["ports"]:
            if port_expected(expected, p):
                continue
            lines = explain_port(snaps, p)
            out.append(Finding(
                "outside.unexpected_port", f"{ip} {p}", "high", f"Shodan sees port {p} open on {ip}",
                f"Port {p} is not in exposure.expected_public. " + " ".join(lines)
                + " Shodan's data is up to a week old, and it does not say whether the port is TCP or UDP.",
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
                    "(InternetDB updates once a week), or a provider firewall may keep Shodan's scanners out.",
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
                f"{_ids(vulns)}. These are guesses: InternetDB matches the software version a service shows in its "
                f"banner against known CVEs, and returns no banners to check. {cross}",
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
    def __init__(self, cfg: Config, state_conn, client: httpx.AsyncClient | None = None, gap: float = GAP_SECONDS):
        self.cfg = cfg
        self.state = state_conn
        self.client = client       # an httpx client for tests
        self.gap = gap
        self.paused_until = 0.0    # after an HTTP 429

    async def run_once(self, now: float | None = None) -> int:
        """One pass: fetch what is due, then bring the findings up to date.
        Returns the number of requests made. Does nothing when disabled."""
        now = time.time() if now is None else now
        if not self.cfg.outside.enabled:
            return 0
        tg = targets(self.state, self.cfg)
        rows = get_rows(self.state)
        due = sorted(ip for ip in tg if is_due(rows.get(ip), now, self.cfg.outside.refresh_hours))
        sent = 0
        if due and now >= self.paused_until:
            own = self.client is None
            client = self.client or httpx.AsyncClient(timeout=httpx.Timeout(20.0), follow_redirects=False)
            try:
                for i, ip in enumerate(due):
                    if i and self.gap:
                        await asyncio.sleep(self.gap)
                    res = await fetch(client, ip)
                    sent += 1
                    store_result(self.state, ip, res, now)
                    if res.retry_after:
                        self.paused_until = now + res.retry_after
                        log.warning("InternetDB asked us to wait; pausing outside checks for %.0f s", res.retry_after)
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
                                    self.cfg.outside.refresh_hours, _cve_matches(self.cfg, host)) \
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
