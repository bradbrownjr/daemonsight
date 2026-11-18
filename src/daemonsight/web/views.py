"""Turn database rows into what the templates show."""

from __future__ import annotations

import json
import time
from dataclasses import replace

from .. import db, findings as rules, hub
from ..collector.sources.caddy import is_local
from . import provenance as prov
from ..config import Config, ExposureConfig

SEVERITY_BADGE = {
    "critical": ("Critical", "bg-red text-red-fg"),
    "high": ("High", "bg-orange text-orange-fg"),
    "medium": ("Medium", "bg-yellow text-yellow-fg"),
    "low": ("Low", "bg-azure-lt"),
    "info": ("Info", "bg-secondary-lt"),
}


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

def _host(cfg: Config, snaps: dict) -> dict:
    system = snaps.get("system")
    data = system.data if system and system.data else {}
    age = time.time() - system.taken_at if system else None
    stale_after = cfg.collector.interval_system * 4
    return {
        "id": cfg.host_id,
        "os": data.get("os"),
        "kernel": data.get("kernel"),
        "virt": data.get("virt"),
        "uptime": fmt_duration(time.time() - data["boot_time"]) if data.get("boot_time") else None,
        "collected_ago": fmt_ago(system.taken_at) if system else "never",
        "fresh": age is not None and age < stale_after,
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


def findings_list(conn, host: str) -> list[dict]:
    out = []
    for r in db.open_findings(conn, host):
        label, cls = SEVERITY_BADGE.get(r["severity"], (r["severity"], "bg-secondary-lt"))
        out.append({"title": r["title"], "detail": r["detail"], "link": r["link"], "label": label,
                    "badge": cls, "since": fmt_ago(r["first_seen"]), "src": prov.finding(r["rule"], r["link"])})
    return out


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
        glance.append({"title": "fail2ban", "value": f"{len(js)} jails", "alert": None,
                       "note": f"{banned} {'address' if banned == 1 else 'addresses'} banned"})
    fw = _snap_data(snaps, "firewall")
    if fw is not None:
        glance.append({"title": "Firewall", "value": "Filtering inbound" if fw.get("filtering") else "No inbound filtering",
                       "alert": None if fw.get("filtering") else "accepts everything", "note": None})
    pt = snaps.get("ports")
    if pt and pt.data:
        ls = pt.data["listeners"]
        wide = sum(1 for r in ls if r["scope"] in ("all", "public"))
        glance.append({"title": "Listening sockets", "value": f"{len(ls)} total",
                       "alert": None, "note": f"{wide} on all or public addresses"})

    return {
        "host": _host(cfg, snaps),
        "tiles": tiles,
        "findings": findings_list(conn, host),
        "events": events_list(conn, host),
        "glance": glance,
        "sources": {name: _source_state(snaps, name)
                    for name in ("system", "systemd", "ports", "docker", "caddy", "fail2ban", "firewall")},
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


def exposure(conn, cfg: Config) -> dict:
    snaps = db.get_snapshots(conn, cfg.host_id)
    ports = _snap_data(snaps, "ports") or {}
    pub = rules.host_is_public(ports)
    f2b = _snap_data(snaps, "fail2ban")
    jails = (f2b or {}).get("jails", [])
    expected = set(cfg.exposure.expected_public)
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
        jail = _jail_for(jails, unit, r.get("process"), cfg.exposure.jail_covers) if internet else None
        rows.append({
            "port": key, "port_v": r["port"], "addresses": ", ".join(r["addresses"]),
            "reach": {"internet": "Internet", "lan": "LAN"}.get(where, where),
            "reach_badge": "bg-red-lt" if where == "internet" else "bg-secondary-lt",
            "process": r.get("process") or "—", "owner": unit or "—",
            "fw": FW_LABEL[fw["state"]], "fw_badge": FW_BADGE[fw["state"]], "fw_why": fw["why"],
            "expected": ("Yes" if key in expected else "No") if internet else "—",
            "jail": (jail or "None") if internet else "—", "jail_bad": internet and not jail,
            "anchor": rules.anchor("port", r["port"], r["proto"]), "src": prov.listener(r, ctr_names, _snap_data(snaps, "caddy")),
        })
    docker = []
    for c in (_snap_data(snaps, "docker") or {}).get("containers", []):
        for p in c.get("ports", []):
            wide = p["host_ip"] in ("0.0.0.0", "::", "")
            docker.append({"container": c["name"], "status": c["status"], "src": prov.container(c),
                           "published": f"{p['host_ip'] or '*'}:{p['host_port']}",
                           "target": f"{p['container_port']}/{p['proto']}", "wide": wide})
    fwdata = _snap_data(snaps, "firewall")
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
                     "forwards": [{"proto": f["proto"], "ports": f["ports"], "to": f["to"],
                                   "anchor": rules.anchor("fwd", f["family"], f["proto"], f["to"]),
                                   "family": "IPv6" if f["family"] == "ip6" else "IPv4",
                                   "conditions": ", ".join(f["conditions"]), "copies": f["copies"],
                                   "wide": sum(hi - lo + 1 for lo, hi in f["ranges"]) > 1000,
                                   "src": prov.forward({**f, "family_raw": f["family"]})}
                                  for f in (fwdata or {}).get("forwards", [])]},
        "firewall_state": _source_state(snaps, "firewall"),
        "ports_state": _source_state(snaps, "ports"),
        "expected": sorted(expected),
        "upstream": cfg.exposure.upstream_allow,
        "src": {name: prov.section(name, cfg) for name in ("ports", "firewall", "docker")},
    }


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
    return replace(cfg, host_id=host, exposure=exposure, links=dict(data.get("links") or {}), collector=collector)


def hosts_list(conn, cfg: Config) -> dict:
    now = time.time()
    counts: dict[str, dict[str, int]] = {}
    for r in conn.execute("SELECT host, severity, COUNT(*) AS n FROM findings WHERE resolved_at IS NULL "
                          "GROUP BY host, severity"):
        counts.setdefault(r["host"], {})[r["severity"]] = r["n"]
    silent = {r["host"] for r in conn.execute(
        "SELECT host FROM findings WHERE rule = 'host.silent' AND resolved_at IS NULL")}
    target = hub.hub_revision()
    rows = []
    for h in conn.execute("SELECT * FROM hosts ORDER BY id"):
        system = db.get_snapshot(conn, h["id"], "system")
        data = system.data if system and system.data else {}
        if h["last_seen"] is None:
            state, badge = "Never reported", "bg-secondary-lt"
        elif h["id"] in silent:
            state, badge = "Not reporting", "bg-red-lt"
        else:
            state, badge = "Reporting", "bg-green-lt"
        c = counts.get(h["id"], {})
        rows.append({
            "id": h["id"], "state": state, "state_badge": badge,
            "seen": fmt_ago(h["last_seen"]) if h["last_seen"] else "never",
            "seen_v": h["last_seen"] or 0,
            "os": data.get("os") or "",
            "uptime": fmt_duration(now - data["boot_time"]) if data.get("boot_time") else "",
            "version": h["version"] or "",
            "address": h["address"] or "",
            **_update_state(h, target, now),
            "findings": [(SEVERITY_BADGE[sev][0], SEVERITY_BADGE[sev][1], c[sev])
                         for sev in ("critical", "high", "medium", "low") if c.get(sev)],
            "findings_v": sum(c.get(sev, 0) * w for sev, w in (("critical", 1000), ("high", 100),
                                                                ("medium", 10), ("low", 1))),
        })
    return {"hosts": rows, "reporting": sum(1 for r in rows if r["state"] == "Reporting"),
            "hub_rev": target, "behind": sum(1 for r in rows if r["can_update"])}


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
