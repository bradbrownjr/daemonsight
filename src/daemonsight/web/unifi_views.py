"""What the pages show for a UniFi Network controller the hub reads over its Integration API. Same shapes as
opnsense_views.py (tables with data-label cells, row anchors that findings link to, source panels naming the GET request),
built from the `unifi_*` snapshots the poller (remote/poll.py) stores.

Every table row that a finding is about carries the finding's label (Unexpected, Accepted, Changed) and a panel with Accept.
Text from the controller (names, models) is untrusted: cut to a length, stripped of control characters by the parsers, and
escaped by the templates. No client is named anywhere: only counts are read."""

from __future__ import annotations

import time

from .. import db, findings as rules
from ..config import Config
from ..remote import store, unifi, unifi_rules
from . import provenance as prov
from . import views
from .views import fmt_ago, fmt_duration, status_of

PAGES = ("overview", "devices", "wifi")

STATE_BADGE = {"ONLINE": "bg-green-lt", "UPDATING": "bg-blue-lt", "GETTING_READY": "bg-blue-lt", "ADOPTING": "bg-blue-lt",
               "PENDING_ADOPTION": "bg-yellow-lt"}


def _data(snaps: dict, source: str) -> dict | None:
    s = snaps.get(source)
    return s.data if s and s.data and s.data.get("available") is not False else None


def _short(snaps: dict) -> dict[str, dict | None]:
    return {n.removeprefix(unifi.SNAPSHOT_PREFIX): _data(snaps, n) for n in unifi.SOURCES}


def _panels(conn, cfg: Config) -> tuple[str | None, int]:
    r = store.get(conn, cfg.host_id)
    return (r["url"], r["interval"]) if r else (None, 60)


def _by_key(conn, host: str, prefix: str = "unifi.") -> dict[tuple[str, str], dict]:
    active, held = views.findings_lists(conn, host)
    return {(f["rule"], f["key"]): f for f in active + held if f["rule"].startswith(prefix)}


def _status(finding: dict | None) -> dict | None:
    return status_of(False, finding) if finding else None


def _src(base: dict, finding: dict | None, anchor: str) -> dict:
    return {**base, "finding": finding, "anchor": anchor}


def _ago(ts) -> str:
    return fmt_ago(ts) if ts else "never"


def _when(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts else "never"


def _states(snaps: dict) -> dict:
    return {src.title: views._source_state(snaps, name) for name, src in unifi.SOURCES.items()}


def _site(d: dict | None, sid: str) -> str:
    return ((d or {}).get("sites") or {}).get(sid) or ""


# --- Overview --------------------------------------------------------------------------------------------------

def overview(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    info, dev, wifi, gw = d["info"], d["devices"], d["wifi"], d["gateway"]
    now = time.time()
    devices = (dev or {}).get("devices", [])

    glance = []
    if info:
        glance.append({"id": "controller", "title": "UniFi Network", "value": info.get("version") or "?",
                       "note": f"{len(info.get('sites', []))} site{'s' if len(info.get('sites', [])) != 1 else ''}"})
        counts = [c for c in (info.get("clients") or {}).values() if isinstance(c, int)]
        if counts:
            glance.append({"title": "Connected clients", "value": str(sum(counts)), "note": "a count only; no client is read by name"})
    if dev is not None:
        down = [x for x in devices if x["state"] in unifi.DOWN_STATES]
        up = sum(1 for x in devices if x["state"] == "ONLINE")
        glance.append({"title": "Devices", "value": f"{up} of {len(devices)} online", "alert": f"{len(down)} offline" if down else None,
                       "link": "/devices#devices"})
        if dev.get("pending"):
            glance.append({"title": "Waiting for adoption", "value": str(len(dev["pending"])), "alert": "check them", "link": "/devices#pending"})
        n_up = sum(1 for x in devices if x["updatable"])
        glance.append({"title": "Firmware updates", "value": f"{n_up} waiting" if n_up else "None waiting", "link": "/#updates"})
    if wifi:
        nets = wifi["networks"]
        open_ = [n for n in nets if n["enabled"] and n["security"] == "OPEN" and not unifi.is_guest(n)]
        glance.append({"title": "Wi-Fi networks", "value": f"{sum(1 for n in nets if n['enabled'])} on, {len(nets)} in all",
                       "alert": f"{len(open_)} open" if open_ else None, "link": "/wifi#networks"})
    if gw and gw.get("present"):
        glance.append({"title": "Gateway policies", "value": f"{len(gw['policies'])} listed", "link": "/devices#gateway"})
    r = store.get(conn, host)
    if r:
        glance.append({"title": "Last read", "value": _ago(r["last_poll"]) if r["last_poll"] else "never",
                       "alert": (r["last_error"] or "")[:120] if r["fails"] else None})

    waiting = sorted((x for x in devices if x["updatable"]), key=lambda x: (x["name"].casefold(), x["id"]))
    updates = {"count": len(waiting), "state": views._source_state(snaps, "unifi_devices"),
               "rows": [{"anchor": unifi_rules.dev_anchor(x), "name": x["name"], "model": x["model"] or "—", "kind": unifi.kind_of(x),
                         "firmware": x["firmware"] or "—", "since": _ago(x["update_since"]) if x.get("update_since") else "just now"}
                        for x in waiting][:100],
               "short": "No CVE list: Ubiquiti publishes no feed of security advisories, and the API does not say which version an update brings.",
               "releases": unifi.RELEASES_URL,
               "src": prov.unifi_updates(), }
    return {
        "host": views._host(cfg, snaps), "tiles": None, **views.findings_overview(conn, host),
        "events": views.events_list(conn, host), "glance": glance,
        "sources": {k: v for k, v in _states(snaps).items() if v["state"] != "ok"},
        "top": None, "firmware": None, "resources": None, "unifi": updates,
        "src": {"findings": prov.section("findings", cfg), "events": prov.section("events", cfg),
                "updates": prov.unifi_updates()},
    }


# --- Devices ---------------------------------------------------------------------------------------------------

def devices(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    findings = _by_key(conn, host)
    now = time.time()
    dev, info, gw = d["devices"], d["info"], d["gateway"]
    fw_find = findings.get(("unifi.fw_update", "firmware"))

    rows = []
    for x in (dev or {}).get("devices", []):
        f = findings.get(("unifi.device_offline", x["id"]))
        status = f or (fw_find if x["updatable"] else None)
        anchor = unifi_rules.dev_anchor(x)
        down = x["state"] in unifi.DOWN_STATES
        rows.append({
            "anchor": anchor, "name": x["name"], "kind": unifi.kind_of(x), "model": x["model"] or "—", "ip": x["ip"] or "—",
            "site": _site(dev, x["site"]), "state": unifi.STATE_LABEL.get(x["state"], x["state"].title() or "Unknown"),
            "state_badge": "bg-red-lt" if down else STATE_BADGE.get(x["state"], "bg-secondary-lt"),
            "firmware": x["firmware"] or "—", "update": x["updatable"], "supported": x["supported"],
            "down": (fmt_duration(now - x["down_since"]) + f" (since {_when(x['down_since'])})") if down and x.get("down_since") else "—",
            "down_v": views._sortval(now - x["down_since"] if down and x.get("down_since") else None),
            "status": _status(status),
            "src": _src(prov.unifi_row(f"Device {x['name']}", "unifi_devices", url), status, anchor)})

    pend = []
    for p in (dev or {}).get("pending", []):
        key = p["mac"] or p["ip"]
        f = findings.get(("unifi.pending_adoption", key))
        anchor = rules.anchor("pend", key)
        pend.append({"anchor": anchor, "model": p["model"] or "—", "ip": p["ip"] or "—", "mac": p["mac"] or "—",
                     "firmware": p["firmware"] or "—", "status": _status(f),
                     "src": _src(prov.unifi_row(f"Pending device {p['model'] or key}", "unifi_devices", url), f, anchor)})

    sites = []
    if info:
        for s in info.get("sites", []):
            c = (info.get("clients") or {}).get(s["id"])
            sites.append({"name": s["name"], "clients": c if isinstance(c, int) else None})
    controller = {"version": (info or {}).get("version") or "", "sites": sites}

    gwv = None
    if gw is not None:
        zones = {z["id"]: z["name"] for z in gw.get("zones", [])}
        pol = []
        for p in sorted(gw.get("policies", []), key=lambda p: (p["index"] if isinstance(p["index"], (int, float)) else 1 << 30, p["name"])):
            f = findings.get(("unifi.gateway_forward", p["id"]))
            anchor = rules.anchor("pol", p["id"][:12])
            pol.append({"anchor": anchor, "name": p["name"] or p["id"][:8], "from": zones.get(p["source_zone"]) or "?",
                        "to": zones.get(p["dest_zone"]) or "?", "action": p["action"].title() or "?", "enabled": p["enabled"],
                        "origin": {"SYSTEM_DEFINED": "UniFi", "USER_DEFINED": "You", "DERIVED": "Derived"}.get(p["origin"], p["origin"].title() or "?"),
                        "status": _status(f),
                        "src": _src(prov.unifi_row(f"Policy {p['name'] or p['id'][:8]}", "unifi_gateway", url), f, anchor)})
        gwv = {"present": gw.get("present", False), "policies": pol}
    return {
        "host": views._host(cfg, snaps), "controller": controller, "devices": rows, "pending": pend, "gateway": gwv,
        "dev_state": views._source_state(snaps, "unifi_devices"), "info_state": views._source_state(snaps, "unifi_info"),
        "gw_state": views._source_state(snaps, "unifi_gateway"), "updates": prov.unifi_updates(),
        "src": {"info": prov.unifi_section("unifi_info", url, interval), "devices": prov.unifi_section("unifi_devices", url, interval),
                "gateway": prov.unifi_section("unifi_gateway", url, interval), "updates": prov.unifi_updates()},
    }


# --- Wi-Fi -----------------------------------------------------------------------------------------------------

def wifi(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    findings = _by_key(conn, host)
    rows = []
    for n in (d["wifi"] or {}).get("networks", []):
        f = findings.get(("unifi.wifi_open", n["id"])) or findings.get(("unifi.wifi_legacy", n["id"]))
        anchor = unifi_rules.wifi_anchor(n)
        weak = n["security"] == "OPEN" or bool(unifi.LEGACY_SECURITY.match(n["security"]))
        rows.append({"anchor": anchor, "name": n["name"], "site": _site(d["wifi"], n["site"]), "enabled": n["enabled"],
                     "security": n["security_label"], "weak": weak,
                     "bands": ", ".join(f"{b:g}" for b in n["bands"]) + " GHz" if n["bands"] else "—",
                     "guest": {"CAPTIVE_PORTAL": "Hotspot portal", "PASSPOINT": "Passpoint"}.get(n["hotspot"], "No"),
                     "status": _status(f),
                     "src": _src(prov.unifi_row(f"Wi-Fi network {n['name']}", "unifi_wifi", url), f, anchor)})
    return {"host": views._host(cfg, snaps), "networks": rows, "wifi_state": views._source_state(snaps, "unifi_wifi"),
            "src": {"wifi": prov.unifi_section("unifi_wifi", url, interval)}}


PAGE_FUNCS = {"overview": overview, "devices": devices, "wifi": wifi}
