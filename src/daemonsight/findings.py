"""Rules that turn snapshots into findings.

Each rule reads the latest snapshot data and returns the findings that hold
right now. The collector stores them; a finding missing from the next run is
marked resolved. Phase 1 rules cover services, containers, Docker port
exposure, disk, memory and failing sources.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config


@dataclass(frozen=True)
class Finding:
    rule: str
    key: str
    severity: str  # critical, high, medium, low
    title: str
    detail: str
    link: str | None = None


def _data(snaps: dict, source: str) -> dict | None:
    """Latest data for a source. When the last read failed, the collector keeps
    the previous data, so findings don't flap on a transient error."""
    snap = snaps.get(source)
    if snap is None or not snap.data or snap.data.get("available") is False:
        return None
    return snap.data


def svc_failed(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "systemd")
    if not data:
        return []
    out = []
    for u in data["units"]:
        if u["active"] != "failed":
            continue
        result = u.get("result")
        detail = f"Result: {result}." if result and result != "success" else "The unit is in the failed state."
        out.append(Finding("svc.failed", u["name"], "high", f"{u['name']} failed",
                           f"{detail} Check: journalctl -u {u['name']}", f"/services#unit-{u['name']}"))
    return out


def ctr_down(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "docker")
    if not data:
        return []
    out = []
    for c in data["containers"]:
        name = c["name"]
        link = f"/services#ctr-{name}"
        if c["status"] == "exited" and (c["exit_code"] or c["oom_killed"]):
            why = "was killed for running out of memory" if c["oom_killed"] else f"exited with code {c['exit_code']}"
            policy = "" if c["restart_policy"] != "no" else " It has no restart policy."
            out.append(Finding("ctr.down", name, "high", f"Container {name} is down",
                               f"It {why}.{policy}", link))
        elif c["status"] == "restarting":
            out.append(Finding("ctr.down", name, "high", f"Container {name} keeps restarting",
                               f"Restart count is {c['restart_count']}.", link))
        elif c["health"] == "unhealthy":
            out.append(Finding("ctr.down", name, "high", f"Container {name} is unhealthy",
                               "Its health check is failing.", link))
    return out


def expose_docker_bypass(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "docker")
    if not data:
        return []
    out = []
    for c in data["containers"]:
        if c["status"] != "running":
            continue
        for p in c["ports"]:
            if p["host_ip"] not in ("0.0.0.0", "::", ""):
                continue
            key = f"{p['host_port']}/{p['proto']}"
            out.append(Finding(
                "expose.docker_bypass", key, "critical",
                f"Port {key} is published on all interfaces",
                f"Container {c['name']} publishes {p['host_ip']}:{p['host_port']}. Docker routes published "
                f"ports in the nat table, before host firewall rules apply, so the firewall does not block it. "
                f"If only local services need it, publish it as 127.0.0.1:{p['host_port']}:{p['container_port']}.",
                f"/services#ctr-{c['name']}",
            ))
    return out


def sys_disk(snaps, cfg: Config, ctx) -> list[Finding]:
    data = _data(snaps, "system")
    if not data:
        return []
    limit = cfg.thresholds.disk_percent
    out = []
    for d in data["disks"]:
        if d["percent"] >= limit:
            sev = "high" if d["percent"] >= max(limit, 95) else "medium"
            out.append(Finding("sys.disk", d["mount"], sev, f"Disk {d['mount']} is {d['percent']:.0f}% full",
                               f"Threshold is {limit:.0f}%.", "/#system"))
    return out


def sys_memory(snaps, cfg: Config, ctx) -> list[Finding]:
    avg = ctx.get("mem_avg")
    if avg is None:
        return []
    limit = cfg.thresholds.memory_percent
    if avg < limit:
        return []
    mins = cfg.thresholds.memory_minutes
    return [Finding("sys.memory", "mem", "medium", f"Memory has averaged {avg:.0f}% for {mins} minutes",
                    f"Threshold is {limit:.0f}%.", "/#system")]


def source_errors(snaps, cfg, ctx) -> list[Finding]:
    out = []
    for name, snap in snaps.items():
        if not snap.ok:
            out.append(Finding("collector.source", name, "low", f"Collector cannot read {name}",
                               snap.error or "Unknown error.", None))
    return out


RULES = [svc_failed, ctr_down, expose_docker_bypass, sys_disk, sys_memory, source_errors]


def evaluate(snaps: dict, cfg: Config, ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    out: dict[tuple[str, str], Finding] = {}
    for rule in RULES:
        for f in rule(snaps, cfg, ctx):
            # One finding per (rule, key); an IPv4 and IPv6 binding of the same port is one problem.
            out.setdefault((f.rule, f.key), f)
    return list(out.values())
