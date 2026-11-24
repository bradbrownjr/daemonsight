"""The UniFi Network Integration API: which endpoints the hub reads, what is kept from each reply, and the connection test.

Everything here is a GET. The endpoints and field names come from Ubiquiti's published OpenAPI document for UniFi Network
11.0.97 (https://developer.ui.com/network/v11.0.97/openapi.json, read 2026-11-24; the list of operations is also in
https://developer.ui.com/network/v11.0.97/llms.txt). Auth is the `X-API-KEY` header (same llms.txt: "All APIs use API Key
authentication via the `X-API-KEY` header"). The document declares no security scheme, so it says nothing about what a key
may do. The base for a local console is `https://<console>/proxy/network/integration` (the document's second server).

What the API cannot say, and what this module does about it (docs/DESIGN.md, "UniFi Network"):

* A key's role. The document has no "who am I" operation: the only call that is not about a site, a device or a client is
  `GET /v1/info` (`applicationVersion`). So the hub cannot check that the key is read-only. It never tries a write; the
  admin's View Only role is what limits the key, and the form says so.
* Which firmware version an update brings. `firmwareUpdatable` is a flag; there is no target version. The hub therefore
  cannot match a pending update to a security advisory (see the card on the Overview page).
* The newest Network application version. `/v1/info` has only the installed one, so there is no "controller is out of
  date" finding.
* Port forwards. The document has no NAT operation. The gateway rule reads firewall policies instead.

Secrets in replies. The Wi-Fi list (`GET /v1/sites/{siteId}/wifi/broadcasts`) carries only the security type of each
network; the detail operation for one network (`.../wifi/broadcasts/{wifiBroadcastId}`) carries `passphrase` and
`presharedKeys` (schemas `IntegrationWifiWpa2PersonalSecurityConfigurationDetailDto` and the other `...DetailDto`s). The
whitelist below never allows a detail path, and the parsers copy named fields only, so a `passphrase` that did arrive is
dropped. Client lists would carry names, MACs and addresses of people's devices: only their count is read (`limit=0`).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from .client import Net, RemoteError, Rest, scrub
from .unraid import epoch, num, text

PREFIX = "/proxy/network/integration"
HEADER = "X-API-KEY"
NOUN = "controller"
PAGE = 200                  # the largest page the API allows (`limit` maximum 200)
PAGES_MAX = 5               # pages read per list: 1000 rows
SITES_MAX = 10

_UUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_PAGE = r"\?offset=\d{1,5}&limit=\d{1,3}"
_P = re.escape(PREFIX)

# Every path the hub may request, as whole-path patterns. Detail, action, voucher and client-identity paths are not here.
TEMPLATES = {
    "info": rf"{_P}/v1/info",
    "sites": rf"{_P}/v1/sites{_PAGE}",
    "pending": rf"{_P}/v1/pending-devices{_PAGE}",
    "devices": rf"{_P}/v1/sites/{_UUID}/devices{_PAGE}",
    "stats": rf"{_P}/v1/sites/{_UUID}/devices/{_UUID}/statistics/latest",
    "clients": rf"{_P}/v1/sites/{_UUID}/clients\?offset=0&limit=0",
    "wifi": rf"{_P}/v1/sites/{_UUID}/wifi/broadcasts{_PAGE}",
    "zones": rf"{_P}/v1/sites/{_UUID}/firewall/zones{_PAGE}",
    "policies": rf"{_P}/v1/sites/{_UUID}/firewall/policies{_PAGE}",
}
PATTERNS = tuple(re.compile(p) for p in TEMPLATES.values())
# The same, written the way the docs and the source panels show them.
SHOWN = {
    "info": "/v1/info", "sites": "/v1/sites", "pending": "/v1/pending-devices", "devices": "/v1/sites/{siteId}/devices",
    "stats": "/v1/sites/{siteId}/devices/{deviceId}/statistics/latest", "clients": "/v1/sites/{siteId}/clients (count only: limit=0)",
    "wifi": "/v1/sites/{siteId}/wifi/broadcasts", "zones": "/v1/sites/{siteId}/firewall/zones",
    "policies": "/v1/sites/{siteId}/firewall/policies",
}
RELEASES_URL = "https://community.ui.com/releases"
API_DOCS_URL = "https://developer.ui.com/network/v11.0.97/gettingstarted"
SPEC_URL = "https://developer.ui.com/network/v11.0.97/openapi.json"

FAST, SLOW = "fast", "slow"
SLOW_SECONDS = 300
ROWS_MAX = PAGE * PAGES_MAX
STATS_MAX = 20              # heartbeat reads per poll, for devices that are not online

DOWN_STATES = frozenset({"OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED"})
STATE_LABEL = {"ONLINE": "Online", "OFFLINE": "Offline", "PENDING_ADOPTION": "Pending adoption", "UPDATING": "Updating",
               "GETTING_READY": "Getting ready", "ADOPTING": "Adopting", "DELETING": "Deleting",
               "CONNECTION_INTERRUPTED": "Connection interrupted", "ISOLATED": "Isolated",
               "U5G_INCORRECT_TOPOLOGY": "Incorrect topology"}
SECURITY_LABEL = {"OPEN": "Open", "WPA2_PERSONAL": "WPA2 personal", "WPA3_PERSONAL": "WPA3 personal",
                  "WPA2_WPA3_PERSONAL": "WPA2/WPA3 personal", "WPA2_ENTERPRISE": "WPA2 enterprise",
                  "WPA3_ENTERPRISE": "WPA3 enterprise", "WPA2_WPA3_ENTERPRISE": "WPA2/WPA3 enterprise"}
# The API's list has no WPA or WEP value (v11.0.97). If a later version adds one, these names stand for it.
LEGACY_SECURITY = re.compile(r"^(WEP|WPA)(_|$)(?!2|3)")


@dataclass(frozen=True)
class Source:
    name: str                  # the snapshot name
    title: str
    tier: str
    menu: str                  # where the owner finds the same thing in the UniFi web UI
    paths: tuple[str, ...]     # keys of SHOWN
    optional: bool = False


SOURCES: dict[str, Source] = {s.name: s for s in (
    Source("unifi_info", "Controller", FAST, "UniFi Network, the version is under Settings, System", ("info", "sites", "clients")),
    Source("unifi_devices", "Devices", FAST, "UniFi Network, Devices", ("devices", "pending", "stats")),
    Source("unifi_wifi", "Wi-Fi networks", SLOW, "UniFi Network, Settings, WiFi", ("wifi",)),
    Source("unifi_gateway", "Gateway firewall", SLOW, "UniFi Network, Settings, Policy Table (zone-based firewall)",
           ("zones", "policies"), optional=True),
)}
SNAPSHOT_PREFIX = "unifi_"


def due(now: float, taken_at: float | None, tier: str, interval: int) -> bool:
    gap = interval if tier == FAST else max(SLOW_SECONDS, interval)
    return taken_at is None or now - taken_at >= gap - 1


# --- paths -------------------------------------------------------------------------------------------------------

def _id(value: str) -> str:
    if not re.fullmatch(_UUID, value or ""):
        raise ValueError("not an id")
    return value


def p_info() -> str:
    return f"{PREFIX}/v1/info"


def p_sites(offset: int = 0) -> str:
    return f"{PREFIX}/v1/sites?offset={int(offset)}&limit={PAGE}"


def p_pending(offset: int = 0) -> str:
    return f"{PREFIX}/v1/pending-devices?offset={int(offset)}&limit={PAGE}"


def p_site(site: str, what: str, offset: int = 0) -> str:
    """`what` is devices, wifi (broadcasts), zones or policies."""
    tail = {"devices": "devices", "wifi": "wifi/broadcasts", "zones": "firewall/zones", "policies": "firewall/policies"}[what]
    return f"{PREFIX}/v1/sites/{_id(site)}/{tail}?offset={int(offset)}&limit={PAGE}"


def p_clients(site: str) -> str:
    return f"{PREFIX}/v1/sites/{_id(site)}/clients?offset=0&limit=0"


def p_stats(site: str, device: str) -> str:
    return f"{PREFIX}/v1/sites/{_id(site)}/devices/{_id(device)}/statistics/latest"


# --- helpers -----------------------------------------------------------------------------------------------------

def _dicts(x) -> list[dict]:
    return [r for r in x if isinstance(r, dict)] if isinstance(x, list) else []


def _strs(x, n: int = 40) -> list[str]:
    return [text(v, 40) for v in x][:n] if isinstance(x, list) else []


async def _pages(rest: Rest, path_for) -> list[dict]:
    """Every row of a paginated list (`offset` and `limit`), up to ROWS_MAX. A reply that is not a list page is an error."""
    rows: list[dict] = []
    offset = 0
    for _ in range(PAGES_MAX):
        d = await rest.get(path_for(offset))
        if not isinstance(d, dict) or not isinstance(d.get("data"), list):
            raise ValueError("not a page")
        got = _dicts(d["data"])
        rows += got
        total = num(d.get("totalCount"))
        offset += PAGE
        if not got or total is None or offset >= total:
            break
    return rows[:ROWS_MAX]


# --- parsers -----------------------------------------------------------------------------------------------------

def parse_info(d: dict) -> str:
    return text(d.get("applicationVersion"), 40)


def parse_sites(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        sid = str(r.get("id") or "")
        if re.fullmatch(_UUID, sid):
            out.append({"id": sid, "name": text(r.get("name"), 80) or "Site", "ref": text(r.get("internalReference"), 60)})
    return out[:SITES_MAX]


def parse_device(r: dict, site: str = "") -> dict:
    """One adopted device. Named fields only; the site's name is added by the caller."""
    state = text(r.get("state"), 30).upper()
    return {"id": text(r.get("id"), 40), "site": site, "name": text(r.get("name"), 80) or text(r.get("model"), 40) or "device",
            "model": text(r.get("model"), 40), "mac": text(r.get("macAddress"), 20).lower(), "ip": text(r.get("ipAddress"), 60),
            "state": state, "firmware": text(r.get("firmwareVersion"), 40), "updatable": r.get("firmwareUpdatable") is True,
            "supported": r.get("supported") is not False, "features": _strs(r.get("features"), 6),
            "heartbeat": None, "down_since": None, "update_since": None}


def parse_pending(r: dict) -> dict:
    return {"mac": text(r.get("macAddress"), 20).lower(), "ip": text(r.get("ipAddress"), 60), "model": text(r.get("model"), 40),
            "state": text(r.get("state"), 30).upper(), "firmware": text(r.get("firmwareVersion"), 40),
            "supported": r.get("supported") is not False}


def parse_wifi(r: dict, site: str = "") -> dict:
    """One Wi-Fi network from the list. The list's security object holds the type (and, for WPA2 personal, the ids of
    networks that share a key); nothing but the type is kept. Whatever else arrives, a `passphrase` included, is dropped."""
    sec = r.get("securityConfiguration") if isinstance(r.get("securityConfiguration"), dict) else {}
    stype = text(sec.get("type"), 40).upper()
    hot = r.get("hotspotConfiguration") if isinstance(r.get("hotspotConfiguration"), dict) else {}
    bands = r.get("broadcastingFrequenciesGHz")
    return {"id": text(r.get("id"), 40), "site": site, "name": text(r.get("name"), 80) or "(no name)", "enabled": r.get("enabled") is True,
            "security": stype, "security_label": SECURITY_LABEL.get(stype) or stype.replace("_", " ").title() or "Unknown",
            "bands": sorted({float(b) for b in bands if isinstance(b, (int, float)) and not isinstance(b, bool)})[:6]
            if isinstance(bands, list) else [],
            "hotspot": text(hot.get("type"), 30).upper(), "type": text(r.get("type"), 30).upper()}


def parse_zones(rows: list[dict]) -> list[dict]:
    meta = lambda r: r.get("metadata") if isinstance(r.get("metadata"), dict) else {}  # noqa: E731
    return [{"id": text(r.get("id"), 40), "name": text(r.get("name"), 60), "origin": text(meta(r).get("origin"), 20).upper()}
            for r in rows][:60]


def parse_policies(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        act = r.get("action") if isinstance(r.get("action"), dict) else {}
        src = r.get("source") if isinstance(r.get("source"), dict) else {}
        dst = r.get("destination") if isinstance(r.get("destination"), dict) else {}
        meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
        dtf = dst.get("trafficFilter") if isinstance(dst.get("trafficFilter"), dict) else {}
        out.append({"id": text(r.get("id"), 40), "name": text(r.get("name"), 120), "description": text(r.get("description"), 200),
                    "enabled": r.get("enabled") is True, "action": text(act.get("type"), 10).upper(),
                    "source_zone": text(src.get("zoneId"), 40), "dest_zone": text(dst.get("zoneId"), 40),
                    "origin": text(meta.get("origin"), 20).upper(), "index": num(r.get("index")),
                    "dest_filter": text(dtf.get("type"), 30).upper(), "dest_ports": isinstance(dtf.get("portFilter"), dict)})
    return out[:ROWS_MAX]


def has_gateway(devices: dict | None) -> bool:
    return any("gateway" in d.get("features", []) for d in (devices or {}).get("devices", []))


# --- reading -----------------------------------------------------------------------------------------------------

async def read_sites(rest: Rest) -> list[dict]:
    return parse_sites(await _pages(rest, p_sites))


async def read_info(rest: Rest, sites: list[dict]) -> dict:
    version = parse_info(await rest.get(p_info()))
    counts: dict[str, int | None] = {}
    for s in sites:
        try:
            d = await rest.get(p_clients(s["id"]))
            counts[s["id"]] = num(d.get("totalCount")) if isinstance(d, dict) else None
        except RemoteError as exc:
            if exc.kind in ("auth", "tls"):
                raise
            counts[s["id"]] = None
    return {"version": version, "sites": sites, "clients": counts}


def track(devices: list[dict], prev: dict | None, now: float) -> None:
    """Time two things the API does not: how long a device has been down and how long its update has been waiting. Both
    count from the hub's first sight, unless the device's own last heartbeat says it went quiet earlier."""
    before = {d["id"]: d for d in (prev or {}).get("devices", []) if d.get("id")}
    for d in devices:
        old = before.get(d["id"], {})
        if d["state"] in DOWN_STATES:
            since = old.get("down_since") if old.get("state") in DOWN_STATES else None
            d["down_since"] = since or now
            if d["heartbeat"] and d["heartbeat"] < d["down_since"]:
                d["down_since"] = d["heartbeat"]
        if d["updatable"]:
            d["update_since"] = old.get("update_since") if old.get("updatable") else None
            d["update_since"] = d["update_since"] or now


async def read_devices(rest: Rest, sites: list[dict], prev: dict | None, now: float) -> dict:
    devices: list[dict] = []
    for s in sites:
        for r in await _pages(rest, lambda off, sid=s["id"]: p_site(sid, "devices", off)):
            devices.append(parse_device(r, s["id"]))
    pending = [parse_pending(r) for r in await _pages(rest, p_pending)]
    # Best effort: a device that is down reports when it last sent a heartbeat, which dates its outage better than the
    # hub's own first sight. Failing to read it is not a problem.
    for d in [x for x in devices if x["state"] in DOWN_STATES][:STATS_MAX]:
        try:
            st = await rest.get(p_stats(d["site"], d["id"]))
            d["heartbeat"] = epoch(st.get("lastHeartbeatAt")) if isinstance(st, dict) else None
        except (RemoteError, ValueError) as exc:
            if isinstance(exc, RemoteError) and exc.kind in ("auth", "tls"):
                raise
    track(devices, prev, now)
    return {"devices": devices[:ROWS_MAX], "pending": pending[:200], "sites": {s["id"]: s["name"] for s in sites}}


async def read_wifi(rest: Rest, sites: list[dict]) -> dict:
    nets: list[dict] = []
    for s in sites:
        for r in await _pages(rest, lambda off, sid=s["id"]: p_site(sid, "wifi", off)):
            nets.append(parse_wifi(r, s["id"]))
    return {"networks": nets[:ROWS_MAX], "sites": {s["id"]: s["name"] for s in sites}}


async def read_gateway(rest: Rest, sites: list[dict], devices: dict | None) -> dict:
    """Zones and policies of the sites that have a gateway. A site without one is not asked: the zone-based firewall is the
    gateway's."""
    gw_sites = {d["site"] for d in (devices or {}).get("devices", []) if "gateway" in d.get("features", [])}
    if not gw_sites:
        return {"present": False, "zones": [], "policies": []}
    zones: list[dict] = []
    policies: list[dict] = []
    for s in sites:
        if s["id"] not in gw_sites:
            continue
        z = parse_zones(await _pages(rest, lambda off, sid=s["id"]: p_site(sid, "zones", off)))
        pol = parse_policies(await _pages(rest, lambda off, sid=s["id"]: p_site(sid, "policies", off)))
        zones += [{**x, "site": s["id"]} for x in z]
        policies += [{**x, "site": s["id"]} for x in pol]
    return {"present": True, "zones": zones, "policies": policies, "sites": {s["id"]: s["name"] for s in sites}}


def forbidden_data(src: Source) -> dict:
    return {"available": False, "reason": f"The admin this key belongs to may not read {src.title.lower()} (HTTP 403)."}


async def read_all(rest: Rest, snaps: dict, now: float, interval: int) -> dict[str, tuple[bool, str | None, dict | None]]:
    """The sources that are due, as {snapshot name: (ok, error, data)}. The site list is read every time (it is one small
    call and every other source needs it). A refused key, a certificate that fails or a controller that can't be reached
    ends the poll (RemoteError); any other failure belongs to one source and the rest carry on."""
    sites = await read_sites(rest)
    results: dict[str, tuple[bool, str | None, dict | None]] = {}

    def prev(name: str):
        s = snaps.get(name)
        return s if s and s.data and s.data.get("available") is not False else None

    async def run(name: str, coro_fn):
        s = snaps.get(name)
        if not due(now, s.taken_at if s else None, SOURCES[name].tier, interval):
            return
        try:
            results[name] = (True, None, await coro_fn())
        except RemoteError as exc:
            if exc.kind in ("auth", "tls") or (exc.kind == "unreachable" and not any(r[0] for r in results.values())):
                raise
            if exc.kind == "forbidden":
                results[name] = (False, forbidden_data(SOURCES[name])["reason"], forbidden_data(SOURCES[name]))
            else:
                results[name] = (False, error_text(exc), None)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            results[name] = (False, f"Unexpected reply: {type(exc).__name__}", None)

    await run("unifi_info", lambda: read_info(rest, sites))
    old_dev = prev("unifi_devices")
    await run("unifi_devices", lambda: read_devices(rest, sites, old_dev.data if old_dev else None, now))
    await run("unifi_wifi", lambda: read_wifi(rest, sites))
    fresh = results.get("unifi_devices")
    dev_data = fresh[2] if fresh and fresh[0] else (old_dev.data if old_dev else None)
    await run("unifi_gateway", lambda: read_gateway(rest, sites, dev_data))
    return results


def error_text(exc: Exception, *secrets: str | None) -> str:
    msg = exc.message if isinstance(exc, RemoteError) else f"{type(exc).__name__}: {exc}"
    return scrub(msg, *secrets)[:300] if secrets else msg[:300]


def make_rest(url: str, key: str, http) -> Rest:
    """The GET-only client for a controller: the key in X-API-KEY, only the paths in TEMPLATES."""
    return Rest(url, key, None, http, frozenset(), header=HEADER, noun=NOUN, patterns=PATTERNS)


# --- test connection ---------------------------------------------------------------------------------------------

KEY_NOTE = ("The UniFi Network API has no call that says what a key may do, so DaemonSight cannot check that this key is "
            "read-only, and it never tries a write to find out. What limits the key is the role of the admin who made it: "
            "use a local admin with the View Only role.")


@dataclass
class Probe:
    """What a test found. `problem` is set when the system can't be used. `note` is always shown: what could not be checked."""
    problem: str | None = None
    facts: list[tuple[str, str]] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)
    note: str = KEY_NOTE

    @property
    def ok(self) -> bool:
        return self.problem is None


async def probe(net: Net, url: str, key: str, tls: str = "verify", pem: str | None = None) -> Probe:
    """Read the version, the sites, the devices and the Wi-Fi list once, all GET. Raises RemoteError when the controller
    can't be reached or refuses the key. Nothing is written, and nothing is tried that could be."""
    rest = make_rest(url, key, net.http(tls, pem))
    out = Probe()
    try:
        try:
            version = parse_info(await rest.get(p_info()))
            sites = await read_sites(rest)
        except RemoteError as exc:
            if exc.kind == "forbidden":
                out.problem = ("The key is accepted, but the admin it belongs to may not read this controller's sites. "
                               "Make the key as a local admin with the View Only role, in the Network application.")
                return out
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            out.problem = f"The address answered, but not like a UniFi Network API ({type(exc).__name__}). Check the address and port."
            return out
        if not sites:
            out.problem = "The controller lists no sites for this key."
            return out
        found: dict[str, dict] = {}
        for name, fn in (("unifi_devices", lambda: read_devices(rest, sites, None, 0.0)), ("unifi_wifi", lambda: read_wifi(rest, sites))):
            src = SOURCES[name]
            entry = {"title": src.title, "menu": src.menu}
            try:
                found[name] = await fn()
                entry["state"], entry["note"] = "ok", ""
            except RemoteError as exc:
                if exc.kind in ("auth", "tls", "unreachable"):
                    raise
                entry["state"] = "forbidden" if exc.kind == "forbidden" else "error"
                entry["note"] = "this admin may not read it" if exc.kind == "forbidden" else error_text(exc, key)
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                entry["state"], entry["note"] = "error", f"Unexpected reply: {type(exc).__name__}"
            out.sources.append(entry)
    finally:
        await rest.aclose()
    devices, wifi = found.get("unifi_devices"), found.get("unifi_wifi")
    out.facts.append(("Version", f"UniFi Network {version}" if version else "UniFi Network"))
    out.facts.append(("Sites", ", ".join(s["name"] for s in sites[:5]) + (f" and {len(sites) - 5} more" if len(sites) > 5 else "")))
    if devices:
        d = devices["devices"]
        out.facts.append(("Devices", f"{len(d)} adopted" + (f", {len(devices['pending'])} waiting for adoption" if devices["pending"] else "")))
        out.facts.append(("Gateway", "Yes: its firewall policies are read" if has_gateway(devices) else "None: no firewall policies to read"))
    if wifi:
        out.facts.append(("Wi-Fi networks", str(len(wifi["networks"]))))
    if all(s["state"] == "forbidden" for s in out.sources):
        out.problem = "The key is accepted, but its admin may not read devices or Wi-Fi networks. Use a local admin with the View Only role."
    return out


# --- shared with the pages and rules -----------------------------------------------------------------------------

def is_guest(net: dict) -> bool:
    """A network behind a hotspot portal (captive portal or Passpoint) is the guest network. The Integration API has no other
    "guest" flag on a Wi-Fi network (v11.0.97)."""
    return bool(net.get("hotspot"))


def kind_of(device: dict) -> str:
    f = device.get("features") or []
    return "gateway" if "gateway" in f else "access point" if "accessPoint" in f else "switch" if "switching" in f else "device"
