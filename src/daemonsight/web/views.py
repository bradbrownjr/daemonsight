"""Turn database rows into what the templates show."""

from __future__ import annotations

import json
import re
import time
from urllib.parse import quote, urlsplit
from dataclasses import replace

from .. import db, distro, findings as rules, hub, outside as outside_mod, shodan as shodan_mod
from ..collector.sources.caddy import is_local
from .. import cve as _cve  # noqa: F401 (package)
from ..cve import feeds as cve_feeds, match as cve_match, store as cve_store
from . import provenance as prov
from ..config import Config, ExposureConfig

SEVERITY_BADGE = {
    "critical": ("Critical", "bg-red text-red-fg"),
    "high": ("High", "bg-orange text-orange-fg"),
    "medium": ("Medium", "bg-yellow text-yellow-fg"),
    "low": ("Low", "bg-azure-lt"),
    "info": ("Info", "bg-secondary-lt"),
}


# The status label every list carries. Only "unexpected" and "changed" need
# attention; "accepted" and "expected" are shown, never hidden, and not counted.
STATUS = {
    "unexpected": ("Unexpected", "bg-red-lt"),
    "accepted": ("Accepted", "bg-green-lt"),
    "changed": ("Changed", "bg-orange-lt"),
    "expected": ("Expected", "bg-azure-lt"),
}
NEEDS_ATTENTION = ("unexpected", "changed")


def status_info(key: str, acc: dict | None = None) -> dict:
    """A status label for templates: {"key", "label", "badge", "note", "attention"}.
    `acc` is a finding_item's "accepted" entry; its note shows on hover and in the row."""
    label, badge = STATUS[key]
    note = None
    if acc and key in ("accepted", "changed"):
        note = f"{acc['note']} ({acc['by']}, {acc['when']})"
    return {"key": key, "label": label, "badge": badge, "note": note, "attention": key in NEEDS_ATTENTION}


def status_of(expected: bool, finding: dict | None) -> dict:
    """The status of something that is internet-reachable. An acceptance of
    its finding wins (Accepted, or Changed when its basis moved), then the
    config's expected list, else it is Unexpected."""
    acc = finding["accepted"] if finding else None
    if acc:
        return status_info("changed" if acc["changed"] else "accepted", acc)
    return status_info("expected" if expected else "unexpected")


# --- formatting -------------------------------------------------------------

def fmt_bytes(n) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit in ("B", "KiB") or n >= 100 else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def fmt_bits(bps) -> str:
    if bps is None:
        return "—"
    for unit, div in (("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{bps:.0f} bit/s"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "—"
    s = int(max(seconds, 0))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h} h {m} min" if m and h < 6 else f"{h} h"
    return f"{s // 86400} d"


def fmt_ago(ts, now: float | None = None) -> str:
    if not ts:
        return "never"
    delta = (now or time.time()) - ts
    return "just now" if delta < 5 else f"{fmt_duration(delta)} ago"


def _sortval(value) -> str:
    """Raw value for a table cell's data-v attribute; empty sorts last."""
    return "" if value is None else str(value)


def pct_class(value) -> str:
    """CSS class for a width percentage (the CSP forbids inline styles)."""
    if value is None:
        return "pct-0"
    return f"pct-{max(0, min(100, round(value)))}"


def level_class(value, warn=75, crit=90) -> str:
    if value is None:
        return "bg-secondary"
    return "bg-red" if value >= crit else "bg-yellow" if value >= warn else "bg-primary"


def sparkline(points: list[tuple[float, float]], width: int = 200, height: int = 40, floor: float | None = 0) -> str:
    """SVG polyline points for a small chart, scaled to the box."""
    if len(points) < 2:
        return ""
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    x0, x1 = min(xs), max(xs)
    lo = min(ys) if floor is None else min(floor, min(ys))
    hi = max(ys)
    if hi - lo < 1e-9:
        hi = lo + 1
    span = x1 - x0 or 1
    pad = 2
    return " ".join(
        f"{(x - x0) / span * width:.1f},{height - pad - (y - lo) / (hi - lo) * (height - 2 * pad):.1f}"
        for x, y in points
    )


# --- view models -----------------------------------------------------------

def _support(data: dict | None) -> dict:
    """The OS support status for templates; "label" is empty when unknown."""
    sup = rules.system_support(data)
    return {"status": sup.status, "label": sup.label, "plain": sup.plain,
            "badge": distro.STATUS_BADGE.get(sup.status, "bg-secondary-lt")}


def _unraid_host(cfg: Config, snaps: dict) -> dict:
    """The header facts for a system the hub reads over its API (Unraid)."""
    snap = snaps.get("unraid_system")
    data = snap.data if snap and snap.data else {}
    now = time.time()
    age = now - snap.taken_at if snap else None
    fresh = age is not None and age < cfg.collector.interval_system * 4
    ago = fmt_ago(snap.taken_at) if snap else "never"
    return {
        "id": cfg.host_id, "kind": cfg.kind, "kind_label": "Unraid",
        "os": f"Unraid {data['version']}" if data.get("version") else "Unraid",
        "kernel": data.get("kernel") or None, "virt": None,
        "support": {"status": "supported", "label": "", "plain": True, "badge": "bg-secondary-lt"},
        "uptime": fmt_duration(now - data["boot_time"]) if data.get("boot_time") else None,
        "collected_ago": ago, "fresh": fresh,
        "status_text": f"Read {ago}" if fresh else f"Not reachable \u00b7 last read {ago}",
    }


def _opnsense_host(cfg: Config, snaps: dict) -> dict:
    """The header facts for an OPNsense firewall the hub reads over its API."""
    fw = snaps.get("opnsense_firmware")
    fwd = fw.data if fw and fw.data and fw.data.get("available") is not False else {}
    seen = snaps.get("opnsense_interfaces") or snaps.get("opnsense_gateways") or fw
    now = time.time()
    fresh = seen is not None and now - seen.taken_at < cfg.collector.interval_system * 4
    ago = fmt_ago(seen.taken_at) if seen else "never"
    return {
        "id": cfg.host_id, "kind": cfg.kind, "kind_label": "OPNsense",
        "os": f"OPNsense {fwd['version']}" if fwd.get("version") else "OPNsense",
        "kernel": fwd.get("os") or None, "virt": None,
        "support": {"status": "supported", "label": "", "plain": True, "badge": "bg-secondary-lt"},
        "uptime": None, "collected_ago": ago, "fresh": fresh,
        "status_text": f"Read {ago}" if fresh else f"Not reachable \u00b7 last read {ago}",
    }


def _host(cfg: Config, snaps: dict) -> dict:
    if cfg.kind == "unraid":
        return _unraid_host(cfg, snaps)
    if cfg.kind == "opnsense":
        return _opnsense_host(cfg, snaps)
    system = snaps.get("system")
    data = system.data if system and system.data else {}
    age = time.time() - system.taken_at if system else None
    stale_after = cfg.collector.interval_system * 4
    return {
        "id": cfg.host_id,
        "os": data.get("os"),
        "kernel": data.get("kernel"),
        "virt": data.get("virt"),
        "support": _support(data),
        "uptime": fmt_duration(time.time() - data["boot_time"]) if data.get("boot_time") else None,
        "collected_ago": fmt_ago(system.taken_at) if system else "never",
        "fresh": age is not None and age < stale_after,
        "kind": None, "kind_label": None,
        "status_text": (f"Collected {fmt_ago(system.taken_at) if system else 'never'}" if age is not None and age < stale_after
                       else f"Collector not reporting \u00b7 last {fmt_ago(system.taken_at) if system else 'never'}"),
    }


def _source_state(snaps: dict, name: str) -> dict:
    snap = snaps.get(name)
    if snap is None:
        return {"state": "waiting", "reason": "No data yet."}
    if snap.data and snap.data.get("available") is False:
        return {"state": "unavailable", "reason": snap.data.get("reason")}
    if not snap.ok:
        return {"state": "error", "reason": snap.error}
    return {"state": "ok", "reason": None}


def fmt_when(ts: float) -> str:
    """An absolute UTC time, for what must still read right when printed or exported."""
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def finding_item(r: dict) -> dict:
    """One finding (a dict from db.findings_state) as the templates and the
    report show it."""
    label, cls = SEVERITY_BADGE.get(r["severity"], (r["severity"], "bg-secondary-lt"))
    acc = r["accepted"]
    item = {"id": rules.anchor("finding", r["rule"], r["key"]), "rule": r["rule"], "key": r["key"],
            "severity": r["severity"], "title": r["title"], "detail": r["detail"], "link": r["link"],
            "fix": r["fix"], "howto": [ln.strip() for ln in (r.get("howto") or "").split("\n") if ln.strip()],
            "step": rules.step_of(r["rule"], r["key"]) if r["fix"] else None,
            "label": label, "badge": cls, "since": fmt_ago(r["first_seen"]),
            "src": prov.finding(r["rule"], r["link"]), "accepted": None, "changed_note": None,
            "status": status_info("unexpected")}
    if acc:
        item["accepted"] = {"note": acc["note"], "by": acc["accepted_by"], "ago": fmt_ago(acc["accepted_at"]),
                            "when": fmt_when(acc["accepted_at"]), "changed": acc["changed"]}
        item["status"] = status_info("changed" if acc["changed"] else "accepted", item["accepted"])
        if acc["changed"]:
            item["changed_note"] = (f"Accepted on {fmt_when(acc['accepted_at'])[:10]} ({acc['note']}) "
                                    "\u2014 this has changed since")
    return item


def findings_lists(conn, host: str) -> tuple[list[dict], list[dict]]:
    """(open, accepted) findings for display. A finding whose acceptance no
    longer applies is in the open list, with a note saying so."""
    active, held = db.findings_state(conn, host)
    return [finding_item(r) for r in active], [finding_item(r) for r in held]


def findings_overview(conn, host: str) -> dict:
    """What the Overview findings list shows: every open finding in severity
    order, accepted ones in place with their status. `attention` counts the
    Unexpected and Changed ones, which is what the Hosts page and the
    report's steps count too."""
    active, held = db.findings_state(conn, host)
    rows = sorted(active + held, key=lambda r: (db.SEVERITY_ORDER.get(r["severity"], 9), r["first_seen"]))
    return {"findings": [finding_item(r) for r in rows], "attention": len(active), "held": len(held)}


def findings_list(conn, host: str) -> list[dict]:
    return findings_lists(conn, host)[0]


def events_list(conn, host: str, limit: int = 8) -> list[dict]:
    return [{"title": r["title"], "detail": r["detail"], "link": r["link"], "ago": fmt_ago(r["ts"]),
             "severity": r["severity"]} for r in db.recent_events(conn, host, limit)]


def overview(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    hour_ago = time.time() - 3600
    sysd = snaps["system"].data if "system" in snaps and snaps["system"].data else None

    tiles = None
    if sysd:
        root = next((d for d in sysd["disks"] if d["mount"] == "/"), sysd["disks"][0] if sysd["disks"] else None)
        nic = max(sysd["net"].items(), key=lambda kv: kv[1]["rx_bps"] + kv[1]["tx_bps"], default=(None, None))
        mem = sysd["memory"]
        tiles = {
            "cpu": {"percent": sysd["cpu"]["percent"], "count": sysd["cpu"]["count"],
                    "load": " ".join(f"{v:.2f}" for v in sysd["cpu"]["load"]),
                    "spark": sparkline(db.metric_series(conn, host, "cpu.percent", hour_ago))},
            "mem": {"percent": mem["percent"], "used": fmt_bytes(mem["total"] - mem["available"]),
                    "total": fmt_bytes(mem["total"]), "pct": pct_class(mem["percent"]),
                    "level": level_class(mem["percent"])},
            "disk": None if not root else {
                "mount": root["mount"], "percent": root["percent"], "used": fmt_bytes(root["used"]),
                "total": fmt_bytes(root["total"]), "pct": pct_class(root["percent"]),
                "level": level_class(root["percent"], 80, cfg.thresholds.disk_percent),
                "others": len(sysd["disks"]) - 1},
            "net": None if not nic[0] else {
                "nic": nic[0], "rx": fmt_bits(nic[1]["rx_bps"]), "tx": fmt_bits(nic[1]["tx_bps"]),
                "spark": sparkline(db.metric_series(conn, host, f"net.{nic[0]}.rx_bps", hour_ago))},
        }

    glance = []
    if cfg.role == "workstation":
        glance.append({"id": "role", "title": "Role", "value": "Workstation",
                       "note": "Often off or asleep; Offline, not Not reporting, when it stops uploading"})
    if sysd and sysd.get("os"):
        sup = _support(sysd)
        shown = sup["label"] and not sup["plain"]
        # Red only once the release gets no free security updates; LTS/ESM is a note.
        red = shown and sup["status"] in ("ended", "eol")
        note = " · ".join(x for x in (f"Kernel {sysd['kernel']}" if sysd.get("kernel") else "",
                                       sup["label"] if sup["label"] and not red else "") if x)
        glance.append({"id": "os", "title": "Operating system", "value": sysd["os"],
                       "alert": sup["label"] if red else None, "note": note or None})
    sd = snaps.get("systemd")
    if sd and sd.data and sd.data.get("units") is not None:
        counts = sd.data["counts"]
        glance.append({"title": "systemd services", "value": f"{counts.get('active', 0)} active",
                       "alert": f"{counts['failed']} failed" if counts.get("failed") else None})
    dk = snaps.get("docker")
    if dk and dk.data:
        if dk.data.get("available") is False:
            glance.append({"title": "Containers", "value": "Docker not found", "alert": None})
        else:
            cs = dk.data["containers"]
            running = sum(1 for c in cs if c["status"] == "running")
            down = sum(1 for c in cs if c["status"] != "running" and (c["exit_code"] or c["oom_killed"]))
            glance.append({"title": "Containers", "value": f"{running} running",
                           "alert": f"{down} down" if down else None})
    cd = _snap_data(snaps, "caddy")
    if cd is not None:
        glance.append({"title": "Caddy sites", "value": f"{len(cd.get('sites', []))} sites",
                       "alert": None, "note": f"admin API on {cd.get('admin', {}).get('listen')}"})
    fb = _snap_data(snaps, "fail2ban")
    if fb is not None:
        js = fb.get("jails", [])
        banned = sum(j["banned_now"] or 0 for j in js if isinstance(j.get("banned_now"), int))
        glance.append({"title": "fail2ban", "value": f"{len(js)} jail{'' if len(js) == 1 else 's'}", "alert": None,
                       "note": f"{banned} {'address' if banned == 1 else 'addresses'} banned"})
    fw = _snap_data(snaps, "firewall")
    if fw is not None:
        glance.append({"title": "Firewall", "value": "Filtering inbound" if fw.get("filtering") else "No inbound filtering",
                       "alert": None if fw.get("filtering") else "accepts everything", "note": None})
    pk = _snap_data(snaps, "packages")
    if pk is not None:
        n_sec = pk.get("security_count") or 0
        n_all = len(pk.get("updates", []))
        glance.append({"title": "Updates", "value": f"{n_all} waiting",
                       "alert": f"{n_sec} security" if n_sec else None,
                       "note": "Reboot needed" if rules.reboot_reasons(pk) else None,
                       "link": "/packages"})
    pt = snaps.get("ports")
    if pt and pt.data:
        ls = pt.data["listeners"]
        wide = sum(1 for r in ls if r["scope"] in ("all", "public"))
        glance.append({"title": "Listening sockets", "value": f"{len(ls)} total",
                       "alert": None, "note": f"{wide} on all or public addresses"})

    return {
        "host": _host(cfg, snaps),
        "tiles": tiles,
        **findings_overview(conn, host),
        "events": events_list(conn, host),
        "glance": glance,
        "sources": {name: _source_state(snaps, name)
                    for name in ("system", "systemd", "ports", "docker", "caddy", "fail2ban", "firewall", "packages")},
        "src": {name: prov.section(name, cfg) for name in ("system", "findings", "events")},
    }


UNIT_FILTERS = ("active", "failed", "all")


def services(conn, cfg: Config, unit_filter: str = "active") -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    now = time.time()

    containers = []
    dk = snaps.get("docker")
    docker_state = _source_state(snaps, "docker")
    if dk and dk.data and dk.data.get("available") is not False:
        for c in dk.data["containers"]:
            running = c["status"] == "running"
            bad = (not running and (c["exit_code"] or c["oom_killed"])) or c["health"] == "unhealthy"
            containers.append({
                "name": c["name"], "image": c["image"], "status": c["status"], "src": prov.container(c),
                "status_badge": "bg-green-lt" if running else ("bg-red text-red-fg" if bad else "bg-secondary-lt"),
                "exit": f" ({c['exit_code']})" if not running and c["exit_code"] is not None else "",
                "oom": c["oom_killed"],
                "health": "no check" if c["health"] == "none" else c["health"],
                "health_bad": c["health"] == "unhealthy",
                "restarts": c["restart_count"], "policy": c["restart_policy"],
                "cpu": f"{c['cpu_percent']:.1f}%" if c["cpu_percent"] is not None else "—",
                "mem": fmt_bytes(c["memory"]),
                "cpu_v": _sortval(c["cpu_percent"]), "mem_v": _sortval(c["memory"]),
                "ports": [{"text": f"{p['host_ip']}:{p['host_port']}→{p['container_port']}/{p['proto']}",
                           "wide": p["host_ip"] in ("0.0.0.0", "::", "")} for p in c["ports"]],
            })

    units = []
    sd = snaps.get("systemd")
    counts = {}
    if sd and sd.data and sd.data.get("units") is not None:
        counts = sd.data["counts"]
        for u in sd.data["units"]:
            if unit_filter == "failed" and u["active"] != "failed":
                continue
            if unit_filter == "active" and u["active"] == "inactive":
                continue
            badge = {"active": "bg-green-lt", "failed": "bg-red text-red-fg"}.get(u["active"], "bg-secondary-lt")
            units.append({
                "name": u["name"], "description": u["description"], "active": u["active"], "sub": u["sub"],
                "src": prov.unit(u),
                "badge": badge, "since": fmt_duration(now - u["since"]) if u.get("since") else "—",
                "restarts": u.get("restarts"), "memory": fmt_bytes(u.get("memory")),
                "cpu": fmt_duration((u["cpu_ns"] or 0) / 1e9) if u.get("cpu_ns") is not None else "—",
                "result": u.get("result"),
                "since_v": _sortval(now - u["since"] if u.get("since") else None),
                "memory_v": _sortval(u.get("memory")), "cpu_v": _sortval(u.get("cpu_ns")),
                "restarts_v": _sortval(u.get("restarts")),
            })

    listeners = []
    pt = snaps.get("ports")
    owners_known = True
    if pt and pt.data:
        owners_known = pt.data.get("owners_known", True)
        names = {c["id"]: c["name"] for c in (dk.data.get("containers", []) if dk and dk.data else [])}
        for r in pt.data["listeners"]:
            owner = r["owner"]
            if owner["kind"] == "unit":
                who = owner["id"]
            elif owner["kind"] == "container":
                who = f"container {names.get(owner['id'], owner['id'][:12])}"
            else:
                who = None
            listeners.append({
                "port": f"{r['port']}/{r['proto']}", "port_v": r["port"], "addresses": ", ".join(r["addresses"]),
                "scope": {"all": "All interfaces", "public": "Public", "private": "Private",
                          "loopback": "Loopback", "unknown": "Unknown"}[r["scope"]],
                "scope_badge": {"all": "bg-orange-lt", "public": "bg-red-lt"}.get(r["scope"], "bg-secondary-lt"),
                "process": r.get("process") or "—", "owner": who or "—",
                "src": prov.listener(r, names, _snap_data(snaps, "caddy")),
            })

    return {
        "host": _host(cfg, snaps),
        "containers": containers, "docker_state": docker_state,
        "units": units, "unit_counts": counts, "unit_filter": unit_filter,
        "systemd_state": _source_state(snaps, "systemd"),
        "listeners": listeners, "owners_known": owners_known,
        "ports_state": _source_state(snaps, "ports"),
        "src": {name: prov.section(name, cfg) for name in ("docker", "systemd", "ports")},
    }


def container_logs(conn, cfg: Config, name: str) -> dict | None:
    snap = db.get_snapshot(conn, cfg.host_id, "docker")
    if not snap or not snap.data or snap.data.get("available") is False:
        return None
    for c in snap.data["containers"]:
        if c["name"] == name:
            return {"name": name, "lines": c["logs"], "collected": fmt_ago(snap.taken_at)}
    return None


# --- phase 2 pages ---------------------------------------------------------

FW_BADGE = {"open": "bg-red-lt", "unfiltered": "bg-orange-lt", "restricted": "bg-yellow-lt",
            "blocked": "bg-green-lt", "unknown": "bg-secondary-lt", "forwarded": "bg-purple-lt"}
FW_LABEL = {"open": "Allowed", "unfiltered": "No filtering", "restricted": "Restricted",
            "blocked": "Blocked", "unknown": "Unknown", "forwarded": "Forwarded away"}


def _snap_data(snaps: dict, name: str) -> dict | None:
    s = snaps.get(name)
    if s is None or not s.data or s.data.get("available") is False:
        return None
    return s.data


def _secs(v) -> str:
    if not isinstance(v, (int, float)):
        return "—"
    if v < 0:
        return "permanent"
    return fmt_duration(v)


def _port_ranges(opened: list[dict]) -> list[str]:
    out = []
    for o in opened:
        port = str(o["from"]) if o["from"] == o["to"] else f"{o['from']}-{o['to']}"
        proto = "tcp+udp" if o["proto"] == "th" else o["proto"]
        cond = f" ({', '.join(o['conditions'])})" if o["conditions"] else ""
        out.append(f"{port}/{proto}{cond}")
    return out


def _jail_for(jails: list[dict], unit, process, extra) -> str | None:
    for j in jails:
        if rules.jail_covers(j, unit, process, extra):
            return j["name"]
    return None


FORWARD_PORTS_CHECKED = 1000


def forward_status(f: dict, host_public: bool, cfg: Config, finding: dict | None) -> dict | None:
    """The status of a port forward: None when it can't be reached from the
    internet (the host has no public address, or the provider firewall lets
    none of its ports in). Expected only when every port it forwards is in
    exposure.expected_public; a wide forward never is."""
    if not host_public:
        return None
    protos = ("tcp", "udp") if f["proto"] == "all" else (f["proto"],)
    count = sum(hi - lo + 1 for lo, hi in f["ranges"])
    if cfg.exposure.upstream_allow:
        allowed = [p for p in cfg.exposure.upstream_allow
                   if p.partition("/")[0].isdigit() and p.partition("/")[2] in protos
                   and any(lo <= int(p.partition("/")[0]) <= hi for lo, hi in f["ranges"])]
        if not allowed:
            return None
    expected = set(cfg.exposure.expected_public)
    covered = count <= FORWARD_PORTS_CHECKED and all(
        f"{port}/{proto}" in expected for proto in protos for lo, hi in f["ranges"] for port in range(lo, hi + 1))
    return status_of(covered, finding)


def exposure(conn, cfg: Config) -> dict:
    snaps = db.get_snapshots(conn, cfg.host_id)
    ports = _snap_data(snaps, "ports") or {}
    pub = rules.host_is_public(ports)
    f2b = _snap_data(snaps, "fail2ban")
    jails = (f2b or {}).get("jails", [])
    expected = set(cfg.exposure.expected_public)
    # The port's exposure finding, open or accepted, so its panel can accept it.
    active, held = findings_lists(conn, cfg.host_id)
    port_findings = {f["key"]: f for f in active + held if f["rule"] in ("expose.unexpected", "expose.docker_bypass")}
    forward_findings = {f["key"]: f for f in active + held if f["rule"] == "expose.forward_all"}
    lo, hi = _eph(snaps)
    from ..remote import opnsense as opn_mod
    own_ips = {a["ip"] for a in ports.get("addresses", []) if isinstance(a, dict) and a.get("ip")}
    through = opn_mod.reach_by_listener(conn, own_ips) if own_ips else {}
    public_keys = {(r["proto"], r["port"]) for r in rules.public_listeners(snaps, {"eph": _eph(snaps)})}
    ctr_names = {c["id"]: c["name"] for c in (_snap_data(snaps, "docker") or {}).get("containers", [])}
    rows = []
    for r in ports.get("listeners", []):
        if r["scope"] == "loopback":
            continue
        where = rules.reach(r, pub)
        fw = rules.firewall_state(snaps, r["proto"], r["port"], r["addresses"])
        if where == "internet" and not rules.upstream_allows(cfg, r["proto"], r["port"]):
            fw = {"state": "blocked", "why": "Not in the provider firewall's allow list (exposure.upstream_allow)"}
        owner = r.get("owner") or {}
        unit = owner.get("id") if owner.get("kind") == "unit" else None
        internet = (r["proto"], r["port"]) in public_keys
        key = f"{r['port']}/{r['proto']}"
        # Reachable from the internet: public by address, past the provider firewall, not forwarded
        # away, and not an unconnected UDP client socket. Docker's published ports count too.
        reachable = (where == "internet" and rules.upstream_allows(cfg, r["proto"], r["port"])
                     and fw["state"] != "forwarded" and not (r["proto"] == "udp" and lo <= r["port"] <= hi))
        status = status_of(key in expected, port_findings.get(key)) if reachable else None
        jail = _jail_for(jails, unit, r.get("process"), cfg.exposure.jail_covers) if internet else None
        via = through.get((r["proto"], r["port"]), [])
        panel = prov.listener(r, ctr_names, _snap_data(snaps, "caddy"))
        for v_ in via[:6]:
            panel["entries"].append({"kind": "hublink", "label": "Reached from the internet through",
                                     "href": f"/h/{v_['fw']}/firewall#{v_['anchor']}",
                                     "text": (f"OPNsense port forward {v_['name']}" if v_["how"] == "forward" else f"Caddy site {v_['name']}") + f" on {v_['fw']}"})
        rows.append({
            "port": key, "port_v": r["port"], "addresses": ", ".join(r["addresses"]),
            "reach": {"internet": "Internet", "lan": "LAN"}.get(where, where),
            "reach_badge": "bg-red-lt" if where == "internet" else "bg-secondary-lt",
            "process": r.get("process") or "—", "owner": unit or "—",
            "fw": FW_LABEL[fw["state"]], "fw_badge": FW_BADGE[fw["state"]], "fw_why": fw["why"],
            "status": status,
            "jail": (jail or "None") if internet else "—", "jail_bad": internet and not jail,
            "anchor": rules.anchor("port", r["port"], r["proto"]),
            "via": [{"text": ("Reached from the internet through OPNsense port forward " + v_["name"] if v_["how"] == "forward"
                              else "Reached from the internet through Caddy site " + v_["name"]) + f" on {v_['fw']}",
                     "href": f"/h/{v_['fw']}/firewall#{v_['anchor']}"} for v_ in via[:3]],
            "src": {**panel, "finding": port_findings.get(key),
                    "anchor": rules.anchor("port", r["port"], r["proto"])},
        })
    docker = []
    for c in (_snap_data(snaps, "docker") or {}).get("containers", []):
        for p in c.get("ports", []):
            wide = p["host_ip"] in ("0.0.0.0", "::", "")
            docker.append({"container": c["name"], "status": c["status"], "src": prov.container(c),
                           "published": f"{p['host_ip'] or '*'}:{p['host_port']}",
                           "target": f"{p['container_port']}/{p['proto']}", "wide": wide})
    fwdata = _snap_data(snaps, "firewall")
    forwards = []
    for f in (fwdata or {}).get("forwards", []):
        fkey = f"{f['family']} {f['proto']} {f['to']}"
        forwards.append({
            "proto": f["proto"], "ports": f["ports"], "to": f["to"],
            "anchor": rules.anchor("fwd", f["family"], f["proto"], f["to"]),
            "family": "IPv6" if f["family"] == "ip6" else "IPv4",
            "conditions": ", ".join(f["conditions"]), "copies": f["copies"],
            "wide": sum(hi_ - lo_ + 1 for lo_, hi_ in f["ranges"]) > 1000,
            "status": forward_status(f, pub, cfg, forward_findings.get(fkey)),
            "src": {**prov.forward({**f, "family_raw": f["family"]}), "finding": forward_findings.get(fkey),
                    "anchor": rules.anchor("fwd", f["family"], f["proto"], f["to"])}})
    chains = [{"name": f"{c['family']} {c['table']} {c['chain']}", "policy": c["policy"],
               "default": c["default"], "accept_all": c["accept_all"], "open": _port_ranges(c["open"]),
               "src": prov.chain(c)}
              for c in (fwdata or {}).get("input", [])]
    return {
        "host": _host(cfg, snaps),
        "public": pub,
        "public_ips": [a["ip"] for a in ports.get("addresses", []) if a.get("scope") == "public"],
        "listeners": rows, "docker": docker,
        "firewall": {"chains": chains, "docker_nat": (fwdata or {}).get("docker_nat", False),
                     "tables": (fwdata or {}).get("tables", []), "backend": (fwdata or {}).get("backend"),
                     "duplicates": (fwdata or {}).get("duplicates", 0),
                     "forwards": forwards},
        "firewall_state": _source_state(snaps, "firewall"),
        "ports_state": _source_state(snaps, "ports"),
        "outside": outside_section(conn, cfg, snaps, ports, expected, active + held),
        "expected": sorted(expected),
        "upstream": cfg.exposure.upstream_allow,
        "src": {name: prov.section(name, cfg) for name in ("ports", "firewall", "docker")},
    }


NVD = "https://nvd.nist.gov/vuln/detail/"


def outside_section(conn, cfg: Config, snaps: dict, ports: dict, expected: set, found: list[dict]) -> dict:
    """"Seen from outside": what Shodan (InternetDB, or the Shodan API with the owner's key) lists for this
    host's public addresses, each port with a status and what DaemonSight knows about it. With the API, each
    port also has its transport, the software Shodan named and when it last saw it."""
    source = outside_mod.source_of(cfg)
    out = {"state": "ok", "message": None, "addresses": [], "refresh_hours": cfg.outside.refresh_hours,
           "terms": outside_mod.SHODAN_TERMS if source == "shodan" else outside_mod.TERMS,
           "url": outside_mod.URL, "enabled": cfg.outside.enabled, "source": source,
           "source_name": "Shodan API" if source == "shodan" else "Shodan InternetDB", "rich": False,
           "key_saved": shodan_mod.key_saved(cfg) if source == "shodan" else None}
    if not cfg.hub.enabled:
        out.update(state="off", message="Outside checks run on a hub, which asks Shodan about each host's public "
                                        "addresses. This host has no hub.")
        return out
    if not cfg.outside.enabled:
        out.update(state="off", message="Outside checks are off. To see what Shodan lists for this host's public "
                                        "addresses, turn on Outside view on the Settings page (or set "
                                        "enabled = true under [outside] in the hub's config; docs/INSTALL.md, "
                                        "\"Outside checks\"). InternetDB is free for non-commercial "
                                        "use only; for commercial use choose the Shodan API there and add your "
                                        "own key. Read the terms on that page first.")
        return out
    ips = outside_mod.host_addresses(cfg.host_id, ports, cfg)
    if not ips:
        out.update(state="empty", message="This host reports no public address, so there is nothing to check. To check "
                                          "one anyway, add \"<ip>=<this host's id>\" to addresses under [outside].")
        return out
    rows = outside_mod.get_rows(conn)
    now = time.time()
    by_key = {(f["rule"], f["key"]): f for f in found if f["rule"].startswith("outside.")}
    eph = outside_mod.eph_of(snaps)
    cve_matches = None
    for ip in ips:
        row = rows.get(ip)
        a = {"ip": ip, "anchor": rules.anchor("outside", ip), "state": "waiting", "fetched": "never", "stale": False,
             "error": (row or {}).get("error"), "ports": [], "missing": [], "hostnames": [], "cpes": [], "tags": [],
             "vulns": [], "src": prov.outside_address(ip, row, source),
             "stale_finding": by_key.get(("outside.stale", ip)), "key_finding": by_key.get(("outside.key", "shodan"))}
        out["addresses"].append(a)
        if row is None:
            continue
        a["stale"] = outside_mod.is_stale(row, now, cfg.outside.refresh_hours)
        if row["fetched_at"] is None:
            a["state"] = "error"
            continue
        a["state"] = row["status"]
        a["fetched"] = fmt_ago(row["fetched_at"], now)
        data = row["data"] or {}
        seen = set(data.get("ports", []))
        by_port: dict[int, list[dict]] = {}
        for svc in data.get("services", []):
            by_port.setdefault(svc["port"], []).append(svc)
        via_api = data.get("source") == "shodan"
        out["rich"] = out["rich"] or via_api
        a["rich"] = via_api
        for p in sorted(seen):
            finding = by_key.get(("outside.unexpected_port", f"{ip} {p}"))
            known = outside_mod.explain_port(snaps, p)
            anchor_id = rules.anchor("outside", ip, p)
            svcs = by_port.get(p, [])
            names = []
            for svc in svcs:
                label = outside_mod.service_label(svc)
                if label and label not in names:
                    names.append(label)
            newest = max((svc["seen"] for svc in svcs if svc.get("seen")), default=None)
            a["ports"].append({
                "port": p, "anchor": anchor_id, "known": known,
                "status": status_of(outside_mod.port_expected(expected, p), finding),
                "transport": ", ".join(sorted({svc["transport"] for svc in svcs})) or "not given",
                "service": ", ".join(names) or ("not named" if svcs else "no banner"),
                "seen": fmt_ago(newest, now) if newest else "not given", "seen_v": newest or "",
                "seen_abs": fmt_when(newest) if newest else "",
                "src": {**prov.outside_port(ip, p, known, source), "finding": finding, "anchor": anchor_id}})
        if not (row["status"] == "none" and ":" in ip):
            a["missing"] = [{"port": p, "who": who} for p, who in sorted(
                outside_mod.expected_ports_here(snaps, expected, cfg.exposure.upstream_allow, ip, eph).items())
                if p not in seen]
        a["hostnames"] = data.get("hostnames", [])
        a["cpes"] = data.get("cpes", [])
        a["tags"] = [{"name": t, "critical": t in outside_mod.CRITICAL_TAGS} for t in data.get("tags", [])]
        vulns = data.get("vulns", [])
        if vulns:
            if cve_matches is None:
                cve_matches = outside_mod._cve_matches(cfg, cfg.host_id) or {}
            a["vulns"] = [{"id": v, "url": NVD + v, "also": v in cve_matches} for v in vulns[:200]]
            a["vulns_more"] = max(len(vulns) - 200, 0)
    return out


def _eph(snaps: dict) -> tuple[int, int]:
    """The host's ephemeral port range: from its settings on a hub, else
    this machine's."""
    settings = snaps.get("settings")
    if settings and settings.data and len(settings.data.get("eph") or []) == 2:
        return int(settings.data["eph"][0]), int(settings.data["eph"][1])
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as fh:
            lo, hi = fh.read().split()
            return int(lo), int(hi)
    except (OSError, ValueError):
        return 32768, 60999


def routes(conn, cfg: Config) -> dict:
    import os
    snaps = db.get_snapshots(conn, cfg.host_id)
    caddy = _snap_data(snaps, "caddy")
    ports = _snap_data(snaps, "ports") or {}
    own = {a["ip"] for a in ports.get("addresses", [])}
    listening = {(r["proto"], r["port"]) for r in ports.get("listeners", [])}
    fails = {u["address"]: u for u in (caddy or {}).get("upstream_status", [])}
    sites = []
    for s in (caddy or {}).get("sites", []):
        handlers = []
        worst = "ok"
        for h in s["handlers"]:
            path = ", ".join(h["paths"]) if h["paths"] else ""
            if h.get("when"):
                path += (" " if path else "") + "(only requests matching " + ", ".join(h["when"]) + ")"
            if h["kind"] == "proxy":
                ups = []
                for u in h["upstreams"]:
                    state, note = "remote", "another host"
                    if u["network"] == "unix" and u.get("path"):
                        state, note = ("ok", "socket exists") if os.path.exists(u["path"]) else ("down", "no socket")
                    elif u["network"] == "placeholder":
                        state, note = "remote", "set per request"
                    elif u["port"] and is_local(u["host"], own):
                        state, note = (("ok", "listening") if ("tcp", u["port"]) in listening
                                       else ("down", "nothing listening"))
                    f = fails.get(u["text"])
                    if f and (f.get("fails") or 0) > 0:
                        state, note = "failing", f"{f['fails']} recent failures"
                    if state in ("down", "failing"):
                        worst = "down"
                    ups.append({"text": u["text"], "state": state, "note": note})
                if h.get("dynamic"):
                    ups.append({"text": "dynamic upstreams", "state": "remote", "note": "resolved at runtime"})
                handlers.append({"kind": "Proxy", "path": path, "upstreams": ups})
            elif h["kind"] == "files":
                handlers.append({"kind": "Files", "path": path, "detail": h.get("root") or "site root"})
            elif h["kind"] == "redirect":
                handlers.append({"kind": "Redirect", "path": path, "detail": h.get("target") or ""})
            else:
                handlers.append({"kind": "Respond", "path": path, "detail": str(h.get("status") or 200)})
        sites.append({
            "anchor": rules.anchor("site", s["host"]),
            "host": s["host"], "listen": ", ".join(s["listen"]),
            "access": ("Only " + ", ".join(s["allow"])) if s["allow"] else "Anyone",
            "access_badge": "bg-green-lt" if s["allow"] else "bg-secondary-lt",
            "handlers": handlers, "state": worst,
            "src": prov.caddy_site(s, (caddy or {}).get("admin_address")),
        })
    admin = (caddy or {}).get("admin") or {}
    return {
        "host": _host(cfg, snaps),
        "sites": sites,
        "servers": (caddy or {}).get("servers", []),
        "admin": {"listen": admin.get("listen"), "unix": str(admin.get("listen", "")).startswith("unix/"),
                  "read_from": (caddy or {}).get("admin_address")},
        "caddy_state": _source_state(snaps, "caddy"),
        "down": sum(1 for s in sites if s["state"] != "ok"),
        "src": {"caddy": prov.section("caddy", cfg, {"admin": (caddy or {}).get("admin_address")})},
    }


def jails(conn, cfg: Config) -> dict:
    snaps = db.get_snapshots(conn, cfg.host_id)
    f2b = _snap_data(snaps, "fail2ban")
    rows, bans = [], []
    for j in (f2b or {}).get("jails", []):
        if j["backend"] == "systemd":
            watching = [{"text": m, "missing": False} for m in j["journalmatch"]] or [{"text": "journal", "missing": False}]
        else:
            watching = [{"text": lp["path"], "missing": not lp["exists"]} for lp in j["logpaths"]]
        rows.append({
            "anchor": rules.anchor("jail", j["name"]),
            "name": j["name"], "backend": "journal" if j["backend"] == "systemd" else "files",
            "watching": watching,
            "failed_now": j["failed_now"], "failed_total": j["failed_total"],
            "banned_now": j["banned_now"], "banned_total": j["banned_total"],
            "bantime": _secs(j["bantime"]), "bantime_v": j["bantime"] if isinstance(j["bantime"], int) else "",
            "findtime": _secs(j["findtime"]), "maxretry": j["maxretry"] if j["maxretry"] is not None else "—",
            "actions": ", ".join(j["actions"]) or "—", "ignoreip": ", ".join(j["ignoreip"]),
            "src": prov.jail(j),
        })
        for b in j["bans"]:
            bans.append({"jail": j["name"], **b})
    coverage = []
    jl = (f2b or {}).get("jails", [])
    seen = set()
    for r in rules.public_listeners(snaps, {"eph": _eph(snaps)}):
        owner = r.get("owner") or {}
        unit = owner.get("id") if owner.get("kind") == "unit" else None
        name = unit or r.get("process") or f"port {r['port']}"
        if name in seen:
            continue
        seen.add(name)
        jail = _jail_for(jl, unit, r.get("process"), cfg.exposure.jail_covers)
        coverage.append({"service": name, "port": f"{r['port']}/{r['proto']}", "jail": jail,
                         "src": prov.listener(r)})
    return {
        "host": _host(cfg, snaps),
        "version": (f2b or {}).get("version"),
        "jails": rows, "bans": bans, "coverage": coverage,
        "f2b_state": _source_state(snaps, "fail2ban"),
        "public_host": rules.host_is_public(_snap_data(snaps, "ports")),
        "src": {"fail2ban": prov.section("fail2ban", cfg), "ports": prov.section("ports", cfg)},
    }


def _auto_updates(auto: dict | None, data: dict, cfg: Config) -> dict:
    """The "Automatic updates" card: a one-line state and the fix, if any."""
    if not auto or not auto.get("known"):
        return {"known": False}
    workstation = cfg.role == "workstation"
    tool = "dnf5 automatic" if auto.get("tool") == "dnf5-automatic" else "unattended-upgrades"
    if auto.get("on"):
        state, cls = "On", "text-green"
    elif workstation:
        state, cls = "Off", "text-secondary"
    else:
        state, cls = "Off", "text-orange"
    notes = []
    if auto.get("tool") == "dnf5-automatic":
        notes.append("Installed" if auto.get("installed") else "dnf5-plugin-automatic isn't installed")
        if auto.get("installed"):
            notes.append(f"dnf5-automatic.timer is {auto.get('timer') or 'not enabled'}")
            notes.append("applies updates" if auto.get("apply") else "only downloads updates (apply_updates is off)")
            if auto.get("apply"):
                notes.append(f"upgrade_type is {auto.get('upgrade_type')}")
    else:
        notes.append("Installed" if auto.get("installed") else "unattended-upgrades isn't installed")
        notes.append(f"Unattended-Upgrade is {auto.get('unattended') or 'unset'}")
        notes.append(f"Update-Package-Lists is {auto.get('lists') or 'unset'}")
        if auto.get("timer"):
            notes.append(f"apt-daily-upgrade.timer is {auto['timer']}")
    return {"known": True, "on": bool(auto.get("on")), "state": state, "cls": cls, "tool": tool,
            "notes": notes, "workstation": workstation,
            "howto": "" if auto.get("on") else rules.auto_updates_howto(data)[0],
            "howto_fix": None if auto.get("on") else rules.auto_updates_howto(data)[1]}


def packages(conn, cfg: Config) -> dict:
    snaps = db.get_snapshots(conn, cfg.host_id)
    data = _snap_data(snaps, "packages")
    snap = snaps.get("packages")
    now = time.time()

    def row(u):
        return {"anchor": rules.anchor("pkg", u["name"]), "name": u["name"],
                "current": u.get("current") or "new", "candidate": u.get("candidate") or "—",
                "origin": u.get("origin") or "—"}

    ups = (data or {}).get("updates", [])
    kernel = (data or {}).get("kernel") or {}
    nr = (data or {}).get("needrestart") or {}
    reboot = (data or {}).get("reboot") or {}
    age = (data or {}).get("lists_age")
    reasons = rules.reboot_reasons(data)
    backend = (data or {}).get("backend") or "apt"
    return {
        "host": _host(cfg, snaps),
        "auto": _auto_updates((data or {}).get("auto_updates"), data or {}, cfg),
        "state": _source_state(snaps, "packages"),
        "checked": fmt_ago(snap.taken_at) if snap else "never",
        "security": [row(u) for u in ups if u.get("security")],
        "other": [row(u) for u in ups if not u.get("security")],
        "kept_back": (data or {}).get("kept_back", []),
        "removals": (data or {}).get("removals", 0),
        "held": (data or {}).get("held", []),
        "reboot_needed": bool(reasons),
        "reboot_reasons": reasons,
        "reboot_pkgs": reboot.get("pkgs", []),
        "kernel": kernel,
        "needrestart": nr,
        "lists_age": fmt_ago(age, now) if age else None,
        "lists_stale": bool(age) and now - age > rules.STALE_LISTS_DAYS * 86400,
        "timer": (data or {}).get("daily_timer"),
        "errors": (data or {}).get("errors", {}),
        "backend": backend,
        "tool": "dnf" if backend == "dnf" else "apt",
        "src": {part: prov.packages(part, backend) for part in prov.PACKAGES_PARTS},
    }


# --- vulnerabilities -----------------------------------------------------------

TRACKER = "https://security-tracker.debian.org/tracker/"
STATE_LABEL = {"fix": ("Fix available", "bg-orange-lt"), "nofix": ("No fix yet", "bg-secondary-lt"),
               "minor": ("Won't fix or minor", "bg-secondary-lt"), "undetermined": ("Being assessed", "bg-secondary-lt")}
CVES_SHOWN = 30      # CVEs listed per package; the tracker link has the rest
BINARIES_SHOWN = 6
FEED_STALE_DAYS = 3


def _epss_text(score) -> str:
    if score is None:
        return "—"
    return f"{score * 100:.0f}%" if score >= 0.01 else "<1%"


def _cve_row(c: dict, backend: str) -> dict:
    label, badge = STATE_LABEL[c["state"]]
    if backend == "dnf":
        url = f"https://bodhi.fedoraproject.org/updates/{c['fixed']}" if c.get("fixed") else None
        fix_url = url
        cve_url = f"https://nvd.nist.gov/vuln/detail/{c['cve']}"
    else:
        cve_url = TRACKER + c["cve"]
        fix_url = None
    return {"cve": c["cve"], "url": cve_url, "state": c["state"], "label": label, "badge": badge,
            "kev": c["kev"], "kev_name": c.get("kev_name") or "", "ransomware": c.get("ransomware") == "Known",
            "epss": c["epss"], "epss_text": _epss_text(c["epss"]),
            "urgency": c.get("urgency") if c.get("urgency") and c["urgency"] != "not yet assigned" else "",
            "fixed": c.get("fixed") if backend != "dnf" else "", "advisory": c.get("fixed") if backend == "dnf" else "",
            "advisory_url": fix_url, "descr": c.get("descr") or ""}


def _feed_rows(cdb, now: float, refresh_hours: float) -> list[dict]:
    have = {r["name"]: r for r in cdb.execute("SELECT * FROM feed")} if cdb is not None else {}
    out = []
    # Alpine's secdb files are listed after the three fixed feeds, one per release an image runs and per file.
    alpine = {}
    for name in sorted(have):
        m = re.match(r"^" + cve_feeds.ALPINE_PREFIX + r"(v[0-9.]+)-(main|community)$", name)
        if m:
            alpine[name] = cve_feeds.alpine_feed(m.group(1), m.group(2))
    for name, feed in [*cve_feeds.FEEDS.items(), *alpine.items()]:
        r = have.get(name)
        ok_at = r["ok_at"] if r else None
        stale = bool(r) and (now - (ok_at if ok_at is not None else (r["first_try"] or now))) > FEED_STALE_DAYS * 86400
        if r is None or r["checked_at"] is None:
            state, cls = "Not fetched yet", "text-secondary"
        elif r["status"] == "absent":
            state, cls = "Not in Alpine's security database", "text-secondary"
        elif r["status"] == "error":
            state, cls = "Last try failed", "text-red"
        else:
            state, cls = "Up to date" if not stale else "Old", "text-green" if not stale else "text-orange"
        out.append({
            "name": name, "alpine": name in alpine, "title": feed.title, "url": feed.url, "terms": feed.terms, "state": state, "cls": cls,
            "checked": fmt_ago(r["checked_at"]) if r and r["checked_at"] else "never",
            "ok": fmt_ago(ok_at) if ok_at else "never",
            "changed": fmt_ago(r["changed_at"]) if r and r["changed_at"] else "never",
            "detail": (r["detail"] or "") if r else "", "note": (r["note"] or "") if r else "",
            "rows": r["rows"] if r else None, "size": fmt_bytes(r["size"]) if r and r["size"] else "—",
            "stale": stale, "src": prov.cve_feed(feed, r),
        })
    return out


def vulnerabilities(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    now = time.time()
    inv_snap = snaps.get("inventory")
    inv = inv_snap.data if inv_snap and inv_snap.data else None
    out = {"host": _host(cfg, snaps), "hub": cfg.hub.enabled, "enabled": cfg.cve.enabled, "inv": None,
           "message": None, "packages": [], "totals": None, "feeds": [], "epss_high": cfg.cve.epss_high,
           "refresh_hours": cfg.cve.refresh_hours,
           "src": {"packages": prov.cve_packages(), "inventory": prov.cve_inventory()}, "backend": "apt"}
    if not cfg.hub.enabled:
        out["message"] = "CVE matching runs on a hub, which downloads the vulnerability data. This host has no hub."
        return out
    if not cfg.cve.enabled:
        out["message"] = "CVE matching is turned off on this hub (Settings page, CVE checks; or [cve] enabled = false in the config)."
        return out
    cdb = cve_store.connect_reader(cfg.cve_db_path)
    try:
        out["feeds"] = _feed_rows(cdb, now, cfg.cve.refresh_hours)
        if inv is None:
            out["message"] = ("This host hasn't sent its package list. The collector needs to be updated to a "
                              "version that sends it.")
            return out
        backend = inv.get("backend") or "apt"
        out["backend"] = backend
        release = cve_match.release_of(inv)
        ident = " ".join(x for x in (inv.get("os_id"), inv.get("version_id"), f"({inv['codename']})" if inv.get("codename") else "") if x)
        out["inv"] = {"ago": fmt_ago(inv_snap.taken_at), "count": len(inv.get("sources", [])) or len(inv.get("advisories", [])),
                      "release": ident or "unknown", "backend": backend}
        if backend == "apt" and release is None:
            out["message"] = ("This host's release isn't matched yet. CVE matching covers Debian and Raspberry Pi OS; "
                              "Ubuntu is planned (Ubuntu's own CVE data is the source to use).")
            return out
        if cdb is None:
            out["message"] = "No vulnerability data has been downloaded yet. The hub fetches it shortly after it starts."
            return out
        m = cdb.execute("SELECT * FROM matched WHERE host = ?", (host,)).fetchone()
        if m is None or m["inv_at"] != inv_snap.taken_at:
            out["message"] = "This host's package list hasn't been matched yet. Check back in a minute."
            if m is None:
                return out
        out["matched_ago"] = fmt_ago(m["matched_at"]) if m else None
        out["match_note"] = (m["note"] or "") if m else ""
        cves = cve_match.host_cves(cdb, host)
    finally:
        if cdb is not None:
            cdb.close()
    bins = {s: b for s, _v, b in inv.get("sources", [])}
    by_pkg: dict[str, list[dict]] = {}
    for c in cves:
        by_pkg.setdefault(c["source"], []).append(c)
    rows = []
    totals = {"packages": 0, "fix": 0, "nofix": 0, "minor": 0, "undetermined": 0, "kev": 0}
    for src, items in by_pkg.items():
        items.sort(key=cve_match.rank_key)
        counts = {k: sum(1 for c in items if c["state"] == k) for k in cve_match.STATES}
        actionable = [c for c in items if c["state"] in ("fix", "nofix")]
        top = (actionable or items)[0]
        kev_n = sum(1 for c in items if c["kev"] and c["state"] in ("fix", "nofix"))
        fixed_v = cve_match._fixed_version([c for c in items if c["state"] == "fix"]) if backend == "apt" else None
        names = bins.get(src, [])
        top_row = _cve_row(top, backend)
        epss_max = max((c["epss"] or 0 for c in actionable), default=0)
        rows.append({
            "anchor": rules.anchor("cve", src), "name": src,
            "binaries": names[:BINARIES_SHOWN], "more_binaries": max(len(names) - BINARIES_SHOWN, 0),
            "installed": items[0]["installed"] or "—", "fixed": fixed_v or "—", "counts": counts,
            "total": len(items), "kev": kev_n, "top": top_row, "epss_max": epss_max,
            "high": bool(kev_n or any(c["state"] == "fix" and (c["epss"] or 0) >= cfg.cve.epss_high for c in items)),
            "cves": [_cve_row(c, backend) for c in items[:CVES_SHOWN]], "more": max(len(items) - CVES_SHOWN, 0),
            "tracker": (TRACKER + "source-package/" + quote(src, safe="")) if backend == "apt" else None,
            "sort": (-kev_n, -(counts["fix"] > 0), -epss_max, -counts["fix"], -counts["nofix"], src),
        })
        totals["packages"] += 1
        for k in cve_match.STATES:
            totals[k] += counts[k]
        totals["kev"] += kev_n
    rows.sort(key=lambda r: r["sort"])
    out["packages"] = rows
    out["totals"] = totals
    return out


# --- hub -------------------------------------------------------------------

def host_config(conn, cfg: Config, host: str) -> Config:
    """The hub's config, with the host's own settings from its last upload:
    which ports it expects to be public, its jail links, web UI links and
    how often it reads system health."""
    snap = db.get_snapshot(conn, host, "settings")
    data = snap.data if snap and snap.data else {}
    exp = data.get("exposure") or {}
    exposure = ExposureConfig(
        expected_public=list(exp.get("expected_public") or []),
        upstream_allow=list(exp.get("upstream_allow") or []),
        jail_covers={k: list(v) for k, v in (exp.get("jail_covers") or {}).items()},
    )
    collector = replace(cfg.collector, interval_system=int(data.get("interval_system") or cfg.collector.interval_system))
    role = "workstation" if data.get("role") == "workstation" else "server"
    kind = ""
    row = conn.execute("SELECT kind FROM hosts WHERE id = ?", (host,)).fetchone()
    if row and row["kind"]:
        kind = row["kind"]
        rem = conn.execute("SELECT interval FROM remotes WHERE id = ?", (host,)).fetchone()
        # A remote system counts as stale after four missed polls (a collector: four of its own reads).
        collector = replace(cfg.collector, interval_system=int(rem["interval"]) if rem else 60)
    return replace(cfg, host_id=host, role=role, kind=kind, exposure=exposure, links=dict(data.get("links") or {}),
                   collector=collector)


def hosts_list(conn, cfg: Config) -> dict:
    now = time.time()
    # Accepted findings are left out of the counts and the reboot badge. The
    # "Not reporting" state still follows host.silent: it says what the host is doing.
    counts: dict[str, dict[str, int]] = {}
    reboot = set()
    for host_id, items in db.active_findings_by_host(conn).items():
        for d in items:
            counts.setdefault(host_id, {}).setdefault(d["severity"], 0)
            counts[host_id][d["severity"]] += 1
            if d["rule"] == "pkg.reboot":
                reboot.add(host_id)
    silent = {r["host"]: r["title"] for r in conn.execute(
        "SELECT host, title FROM findings WHERE rule = 'host.silent' AND resolved_at IS NULL")}
    target = hub.hub_revision()
    rows = []
    remotes = {r["id"]: r for r in conn.execute("SELECT * FROM remotes")}
    for h in conn.execute("SELECT * FROM hosts ORDER BY id"):
        c = counts.get(h["id"], {})
        findings = [(SEVERITY_BADGE[sev][0], SEVERITY_BADGE[sev][1], c[sev])
                    for sev in ("critical", "high", "medium", "low") if c.get(sev)]
        findings_v = sum(c.get(sev, 0) * w for sev, w in (("critical", 1000), ("high", 100), ("medium", 10), ("low", 1)))
        if h["kind"] and h["id"] in remotes:
            rows.append(_remote_row(conn, h, remotes[h["id"]], now, findings, findings_v))
            continue
        system = db.get_snapshot(conn, h["id"], "system")
        data = system.data if system and system.data else {}
        role = hub.host_role(conn, h["id"])
        if h["last_seen"] is None:
            state, badge = "Never reported", "bg-secondary-lt"
        elif h["id"] in silent:
            if role == "workstation" and silent[h["id"]].startswith("Offline since"):
                state, badge = "Offline", "bg-secondary-lt"
            else:
                state, badge = "Not reporting", "bg-red-lt"
        else:
            state, badge = "Reporting", "bg-green-lt"
        rows.append({
            "id": h["id"], "kind": None, "state": state, "state_badge": badge, "role": role,
            "seen": fmt_ago(h["last_seen"]) if h["last_seen"] else "never",
            "seen_v": h["last_seen"] or 0,
            "os": data.get("os") or "",
            "kernel": data.get("kernel") or "",
            "support": _support(data),
            "reboot": h["id"] in reboot,
            "uptime": fmt_duration(now - data["boot_time"]) if data.get("boot_time") else "",
            "version": h["version"] or "",
            "address": h["address"] or "",
            **_update_state(h, target, now),
            "findings": findings, "findings_v": findings_v,
        })
    return {"hosts": rows, "reporting": sum(1 for r in rows if r["state"] in ("Reporting", "Reachable")),
            "hub_rev": target, "behind": sum(1 for r in rows if r["can_update"]),
            # Changes that belong to no host: a setting changed on the Settings page.
            "events": events_list(conn, db.HUB_HOST)}


def hosts_menu(conn) -> list[dict]:
    """The hosts for the nav's Hosts menu, A to Z: a light read, none of hosts_list's findings or snapshots.
    "fresh" follows the Hosts page's state: Reporting or Reachable."""
    silent = {r["host"] for r in conn.execute(
        "SELECT host FROM findings WHERE rule = 'host.silent' AND resolved_at IS NULL")}
    remotes = {r["id"]: r for r in conn.execute("SELECT id, kind, enabled, fails, last_ok, last_error FROM remotes")}
    out = []
    for h in conn.execute("SELECT id, kind, last_seen FROM hosts"):
        r = remotes.get(h["id"]) if h["kind"] else None
        if r is not None:
            fresh = bool(r["enabled"]) and not r["fails"] and (r["last_ok"] is not None or bool(r["last_error"]))
        else:
            fresh = h["last_seen"] is not None and h["id"] not in silent
        out.append({"id": h["id"], "fresh": fresh})
    return sorted(out, key=lambda x: (x["id"].casefold(), x["id"]))


def _remote_row(conn, h, r, now: float, findings, findings_v) -> dict:
    """A Hosts page row for a system the hub reads over its API."""
    opn = r["kind"] == "opnsense"
    snap = db.get_snapshot(conn, h["id"], "opnsense_firmware" if opn else "unraid_system")
    data = snap.data if snap and snap.data and snap.data.get("available") is not False else {}
    if not r["enabled"]:
        state, badge = "Disabled", "bg-secondary-lt"
    elif r["last_ok"] is None and not r["last_error"]:
        state, badge = "Not read yet", "bg-secondary-lt"
    elif r["fails"]:
        state, badge = "Unreachable", "bg-red-lt"
    else:
        state, badge = "Reachable", "bg-green-lt"
    host = urlsplit(r["url"]).netloc
    from ..remote import release
    ver = data.get("version")
    latest = release.stored(conn) if not opn else None
    label = "OPNsense" if opn else "Unraid"
    return {
        "id": h["id"], "kind": r["kind"], "kind_label": f"{label} {ver} \u00b7 API" if ver else f"{label} \u00b7 API",
        "os_update": (data.get("new_version") or "") if opn and data.get("count") else (latest["version"] if release.newer(latest, ver) else ""),
        "state": state, "state_badge": badge,
        "role": "server", "seen": fmt_ago(r["last_poll"]) if r["last_poll"] else "never", "seen_v": r["last_poll"] or 0,
        "error": (r["last_error"] or "")[:200] if r["fails"] else "",
        "os": f"{label} {data['version']}" if data.get("version") else label,
        "kernel": ("" if opn else data.get("kernel")) or "", "support": _support({}), "reboot": bool(opn and data.get("needs_reboot")),
        "uptime": fmt_duration(now - data["boot_time"]) if data.get("boot_time") else "",
        "version": "", "address": host, "rev": None, "can_update": False, "updating": "", "update_note": "",
        "findings": findings, "findings_v": findings_v,
    }


UPDATE_WORDS = {"failed": "failed", "refused": "refused", "rolled_back": "failed, rolled back"}


def _update_state(h, target: str | None, now: float) -> dict:
    """What the Version column says about updates from the hub."""
    out = {"rev": hub.revision(h["version"]), "can_update": False, "updating": "", "update_note": ""}
    if h["update_to"]:
        asked = fmt_ago(h["update_asked"]) if h["update_asked"] else ""
        out["updating"] = f"Updating to {h['update_to'][:7]}" + (f", asked {asked}" if asked else "")
        return out
    if h["remote_update"] == 0:
        out["update_note"] = "Updates from the hub are off on this host"
        return out
    out["can_update"] = hub.behind(h, target)
    try:
        last = json.loads(h["update_state"]) if h["update_state"] else None
    except ValueError:
        last = None
    if last and last.get("status") in UPDATE_WORDS and not hub.same_rev(out["rev"], last.get("ref")):
        out["update_note"] = (f"Update to {str(last.get('ref'))[:7]} {UPDATE_WORDS[last['status']]} "
                              f"{fmt_ago(last.get('at') or now)}"
                              + (f": {last['detail']}" if last.get("detail") else ""))
    return out
