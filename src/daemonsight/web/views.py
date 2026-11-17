"""Turn database rows into what the templates show."""

from __future__ import annotations

import time

from .. import db
from ..config import Config

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
                    "badge": cls, "since": fmt_ago(r["first_seen"])})
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
        "sources": {name: _source_state(snaps, name) for name in ("system", "systemd", "ports", "docker")},
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
                "name": c["name"], "image": c["image"], "status": c["status"],
                "status_badge": "bg-green-lt" if running else ("bg-red text-red-fg" if bad else "bg-secondary-lt"),
                "exit": f" ({c['exit_code']})" if not running and c["exit_code"] is not None else "",
                "oom": c["oom_killed"],
                "health": "no check" if c["health"] == "none" else c["health"],
                "health_bad": c["health"] == "unhealthy",
                "restarts": c["restart_count"], "policy": c["restart_policy"],
                "cpu": f"{c['cpu_percent']:.1f}%" if c["cpu_percent"] is not None else "—",
                "mem": fmt_bytes(c["memory"]),
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
                "badge": badge, "since": fmt_duration(now - u["since"]) if u.get("since") else "—",
                "restarts": u.get("restarts"), "memory": fmt_bytes(u.get("memory")),
                "cpu": fmt_duration((u["cpu_ns"] or 0) / 1e9) if u.get("cpu_ns") is not None else "—",
                "result": u.get("result"),
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
                "port": f"{r['port']}/{r['proto']}", "addresses": ", ".join(r["addresses"]),
                "scope": {"all": "All interfaces", "public": "Public", "private": "Private",
                          "loopback": "Loopback", "unknown": "Unknown"}[r["scope"]],
                "scope_badge": {"all": "bg-orange-lt", "public": "bg-red-lt"}.get(r["scope"], "bg-secondary-lt"),
                "process": r.get("process") or "—", "owner": who or "—",
            })

    return {
        "host": _host(cfg, snaps),
        "containers": containers, "docker_state": docker_state,
        "units": units, "unit_counts": counts, "unit_filter": unit_filter,
        "systemd_state": _source_state(snaps, "systemd"),
        "listeners": listeners, "owners_known": owners_known,
        "ports_state": _source_state(snaps, "ports"),
    }


def container_logs(conn, cfg: Config, name: str) -> dict | None:
    snap = db.get_snapshot(conn, cfg.host_id, "docker")
    if not snap or not snap.data or snap.data.get("available") is False:
        return None
    for c in snap.data["containers"]:
        if c["name"] == name:
            return {"name": name, "lines": c["logs"], "collected": fmt_ago(snap.taken_at)}
    return None
