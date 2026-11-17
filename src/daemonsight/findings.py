"""Rules that turn snapshots into findings.

Each rule reads the latest snapshot data and returns the findings that hold
right now. The collector stores them; a finding missing from the next run is
marked resolved. Rule names and severities follow docs/DESIGN.md.
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


# ---- Phase 2: exposure, routes, jails -------------------------------------

def host_is_public(ports: dict | None) -> bool:
    """Whether this host has an internet-routable address of its own."""
    return any(a.get("scope") == "public" for a in (ports or {}).get("addresses", []))


def reach(listener: dict, host_public: bool) -> str:
    """"internet", "lan" or "local" for a listener row."""
    scope = listener["scope"]
    if scope == "public" or (scope == "all" and host_public):
        return "internet"
    if scope == "loopback":
        return "local"
    return "lan"


def _docker_published(snaps) -> set[tuple[str, int]]:
    data = _data(snaps, "docker")
    out = set()
    for c in (data or {}).get("containers", []):
        for p in c.get("ports", []):
            if isinstance(p.get("host_port"), int):
                out.add((p["proto"], p["host_port"]))
    return out


def public_listeners(snaps, ctx) -> list[dict]:
    """Listeners reachable from the internet, without Docker's own (another
    rule covers those) or unconnected UDP client sockets."""
    ports = _data(snaps, "ports")
    if not ports:
        return []
    pub = host_is_public(ports)
    lo, hi = ctx.get("eph", (32768, 60999))
    docker = _docker_published(snaps)
    out = []
    for r in ports["listeners"]:
        if reach(r, pub) != "internet":
            continue
        if r["proto"] == "udp" and lo <= r["port"] <= hi:
            continue
        if (r["proto"], r["port"]) in docker:
            continue
        out.append(r)
    return out


OPENNESS = {"open": 4, "unfiltered": 4, "unknown": 3, "restricted": 2, "blocked": 1, "forwarded": 0}


def firewall_state(snaps, proto: str, port: int, addresses: list[str] | None = None) -> dict:
    """The firewall's verdict for a listener, checking IPv6 too when the
    listener binds an IPv6 address; the more open family wins."""
    from .collector.sources.firewall import port_verdict
    snap = snaps.get("firewall")
    if snap is None or not snap.data:
        return {"state": "unknown", "why": "Firewall not read yet"}
    if snap.data.get("available") is False:
        return {"state": "unfiltered", "why": snap.data.get("reason") or "No firewall tools"}
    families = ["ip"]
    if any(":" in a for a in addresses or []):
        families = ["ip6"] if all(":" in a for a in addresses) else ["ip", "ip6"]
    verdicts = [port_verdict(snap.data, proto, port, f) for f in families]
    return max(verdicts, key=lambda v: OPENNESS.get(v["state"], 0))


def expose_unexpected(snaps, cfg: Config, ctx) -> list[Finding]:
    expected = set(cfg.exposure.expected_public)
    out = []
    for r in public_listeners(snaps, ctx):
        key = f"{r['port']}/{r['proto']}"
        if key in expected:
            continue
        fw = firewall_state(snaps, r["proto"], r["port"], r["addresses"])
        who = r.get("process") or "an unknown process"
        if fw["state"] == "forwarded":
            continue  # traffic to that port goes to another host; see expose.forward_all
        if fw["state"] in ("open", "unfiltered"):
            sev, verdict = "critical", "and the firewall lets it through"
        elif fw["state"] == "unknown":
            sev, verdict = "high", "and the firewall state is unknown"
        else:
            sev, verdict = "medium", "but the firewall blocks it"
        out.append(Finding(
            "expose.unexpected", key, sev, f"Port {key} is reachable from the internet",
            f"{who} listens on {', '.join(r['addresses'])} {verdict} ({fw['why']}). It is not in "
            f"exposure.expected_public. Bind it to 127.0.0.1, or add it to the list if it is meant to be public.",
            "/exposure#listeners"))
    return out


def expose_forward_all(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "firewall")
    out = []
    for f in (data or {}).get("forwards", []):
        count = sum(hi - lo + 1 for lo, hi in f["ranges"])
        if count <= 1000:
            continue
        proto = f["proto"].upper() if f["proto"] != "all" else "TCP and UDP"
        where = f" arriving {', '.join(f['conditions'])}" if f["conditions"] else ""
        out.append(Finding(
            "expose.forward_all", f"{f['family']} {f['proto']} {f['to']}", "high",
            (f"All {proto} ports except {f['ports'][len('all except '):]} are forwarded to {f['to']}"
             if f["ports"].startswith("all except ") else f"{proto} ports {f['ports']} are forwarded to {f['to']}"),
            f"Every {proto} port{where} except the ones listed goes to {f['to']} ({count} ports). Anything "
            f"that host listens on, now or later, is reachable from the internet through this one. "
            f"Forward only the ports it needs.", "/exposure#forwards"))
    return out


def firewall_default_accept(snaps, cfg, ctx) -> list[Finding]:
    data, ports = _data(snaps, "firewall"), _data(snaps, "ports")
    if not data or not ports:
        return []
    out = []
    for family, label in (("ip", "IPv4"), ("ip6", "IPv6")):
        has_public = any(a.get("scope") == "public" and (":" in a["ip"]) == (family == "ip6")
                         for a in ports.get("addresses", []))
        chains = [c for c in data.get("input", []) if c["family"] in (family, "inet")]
        if not has_public or not chains or any(c["default"] == "drop" for c in chains):
            continue
        accepts = sorted({f"{o['from']}" for c in chains for o in c["open"]}, key=int)
        note = (f" The ACCEPT rules for {', '.join(accepts)} change nothing while the default is accept."
                if accepts else "")
        out.append(Finding(
            "firewall.default_accept", family, "medium", f"{label} input accepts all traffic by default",
            f"This host has a public {label} address and no input chain drops by default, so every port "
            f"listening on it is reachable.{note} Set the policy to drop after accepting the ports you need.",
            "/exposure#firewall"))
    return out


def firewall_duplicates(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "firewall")
    if not data or not data.get("duplicates"):
        return []
    odd = data.get("odd_names") or []
    extra = (f" Some rules name the interface {', '.join(odd)} literally, which looks like a shell "
             f"variable that was never filled in.") if odd else ""
    return [Finding("firewall.duplicate_rules", "dups", "low",
                    f"{data['duplicates']} firewall rules are duplicates",
                    "The same rule appears more than once, usually because a script (a WireGuard PostUp, "
                    "say) adds rules each time it runs without removing them." + extra, "/exposure#firewall")]


def _local_listener(ports: dict, proto: str, port: int) -> bool:
    for r in ports.get("listeners", []):
        if r["proto"] == proto and r["port"] == port:
            return True
    return False


def route_upstream_down(snaps, cfg, ctx) -> list[Finding]:
    import os
    from .collector.sources.caddy import is_local
    caddy, ports = _data(snaps, "caddy"), _data(snaps, "ports")
    if not caddy or not ports:
        return []
    own = {a["ip"] for a in ports.get("addresses", [])}
    out = []
    for site in caddy.get("sites", []):
        for h in site["handlers"]:
            for u in h.get("upstreams", []):
                missing = False
                if u["network"] == "unix" and u.get("path"):
                    missing = not os.path.exists(u["path"])
                elif u["network"] in ("tcp", "tcp4", "tcp6") and u["port"] and is_local(u["host"], own):
                    missing = not _local_listener(ports, "tcp", u["port"])
                if missing:
                    out.append(Finding(
                        "route.upstream_down", f"{site['host']} {u['text']}", "medium",
                        f"{site['host']}: nothing listens on {u['text']}",
                        "Caddy proxies this site to an address on this host where no service is listening, "
                        "so visitors get a 502.", "/routes"))
    return out


def route_upstream_failing(snaps, cfg, ctx) -> list[Finding]:
    caddy = _data(snaps, "caddy")
    out = []
    for u in (caddy or {}).get("upstream_status", []):
        if (u.get("fails") or 0) > 0:
            out.append(Finding(
                "route.upstream_failing", u["address"], "medium", f"Upstream {u['address']} is failing",
                f"Caddy has counted {u['fails']} recent failed requests to it (passive health checks).",
                "/routes"))
    return out


def _stem(name: str) -> str:
    base = name.split("@", 1)[0].rsplit(".", 1)[0].lower()
    return base[:-1] if base.endswith("d") and len(base) > 3 else base


def jail_covers(jail: dict, unit: str | None, process: str | None, extra: dict) -> bool:
    if unit and unit in extra.get(jail["name"], []):
        return True
    if unit and unit in jail.get("units", []):
        return True
    stems = {_stem(x) for x in (unit, process) if x}
    if _stem(jail["name"]) in stems or any(_stem(jail["name"]).startswith(s + "-") for s in stems):
        return True
    for lp in jail.get("logpaths", []):
        if any(s and s in lp["path"].lower() for s in stems):
            return True
    return False


def jail_uncovered(snaps, cfg: Config, ctx) -> list[Finding]:
    f2b = snaps.get("fail2ban")
    if f2b is None or f2b.data is None:
        return []
    running = f2b.data.get("available") is not False
    jails = f2b.data.get("jails", []) if running else []
    extra = cfg.exposure.jail_covers
    out, seen = [], set()
    for r in public_listeners(snaps, ctx):
        owner = r.get("owner") or {}
        unit = owner.get("id") if owner.get("kind") == "unit" else None
        name = unit or r.get("process")
        if not name or name in seen:
            continue
        seen.add(name)
        if any(jail_covers(j, unit, r.get("process"), extra) for j in jails):
            continue
        why = "fail2ban is not running on this host." if not running else \
            "No jail reads its journal or log files. Add a jail, or link an existing one in exposure.jail_covers."
        out.append(Finding("jail.uncovered", name, "high", f"{name} is public with no fail2ban jail",
                           f"It listens on {r['port']}/{r['proto']} from the internet. {why}", "/fail2ban"))
    return out


def jail_log_missing(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "fail2ban")
    out = []
    for j in (data or {}).get("jails", []):
        for lp in j.get("logpaths", []):
            if not lp["exists"]:
                out.append(Finding("jail.log_missing", f"{j['name']} {lp['path']}", "medium",
                                   f"Jail {j['name']} watches a missing file",
                                   f"{lp['path']} does not exist, so the jail sees nothing there.", "/fail2ban"))
    return out


def caddy_admin_tcp(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "caddy")
    if not data:
        return []
    listen = (data.get("admin") or {}).get("listen", "")
    if listen.startswith("unix/"):
        return []
    return [Finding("caddy.admin_tcp", "admin", "low", "Caddy's admin API listens on TCP",
                    f"It is on {listen}. Any local user or process can change Caddy's config through it. "
                    "Caddy recommends a Unix socket with file permissions: admin unix//run/caddy/admin.sock.",
                    "/routes")]


RULES = [svc_failed, ctr_down, expose_docker_bypass, sys_disk, sys_memory, source_errors,
         expose_unexpected, expose_forward_all, firewall_default_accept, firewall_duplicates,
         route_upstream_down, route_upstream_failing, jail_uncovered,
         jail_log_missing, caddy_admin_tcp]


def evaluate(snaps: dict, cfg: Config, ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    out: dict[tuple[str, str], Finding] = {}
    for rule in RULES:
        for f in rule(snaps, cfg, ctx):
            # One finding per (rule, key); an IPv4 and IPv6 binding of the same port is one problem.
            out.setdefault((f.rule, f.key), f)
    return list(out.values())
