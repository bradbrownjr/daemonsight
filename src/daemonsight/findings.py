"""Rules that turn snapshots into findings.

Each rule reads the latest snapshot data and returns the findings that hold
right now. The collector stores them; a finding missing from the next run is
marked resolved. Rule names and severities follow docs/DESIGN.md.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from datetime import date
from dataclasses import dataclass

from . import distro
from .config import Config


def anchor(kind: str, *parts) -> str:
    """The id of a table row a finding links to, e.g. port-2083-tcp. The
    pages build their row ids with this too, so the two always match."""
    return f"{kind}-" + re.sub(r"[^A-Za-z0-9_.-]+", "_", "-".join(str(p) for p in parts)).strip("_")


@dataclass(frozen=True)
class Finding:
    """One thing a rule found.

    `fix` is the exact command or commands that resolve it, one per line, or
    None when no single command does (an exposed port: the fix is a decision).
    `basis` is what the finding is about, apart from numbers that drift (ages,
    counts): an accepted finding comes back when its basis changes. None means
    the title.
    `howto` is plain-language steps, one per line, shown as "What to do". Only
    the hub's own rules (unraid.*, remote.*) set it; collectors don't upload it.
    """
    rule: str
    key: str
    severity: str  # critical, high, medium, low
    title: str
    detail: str
    link: str | None = None
    fix: str | None = None
    basis: str | None = None
    howto: str | None = None


def held(prior: dict | None, rule: str, key: str) -> Finding | None:
    """The open finding (rule, key) as it stands, to be emitted again unchanged. A rule uses it when it cannot tell whether the
    finding still holds (data not read yet, a match not made yet): a finding the rule does not emit is resolved by the
    reconcile step, so "unknown" must emit the last finding rather than nothing. `prior` maps (rule, key) to the open rows."""
    row = (prior or {}).get((rule, key))
    if row is None:
        return None
    return Finding(rule, key, row["severity"], row["title"], row["detail"], row["link"], row["fix"], row["basis"], row["howto"])


# Where a fix sits in the report's steps, by rule. Steps run in this order;
# a finding with a fix and no step gets a card of its own after "auto-updates",
# and "os-upgrade" (planning) comes last. A finding with no fix is a decision
# whatever its step.
STEP_ORDER = ("upgrade", "restart", "reboot", "auto-updates", "os-upgrade")
STEP_TITLES = {
    "upgrade": "Install updates",
    "restart": "Restart services",
    "reboot": "Reboot",
    "auto-updates": "Turn on automatic updates",
    "os-upgrade": "Upgrade the operating system",
}
STEP_OF = {
    "pkg.lists_stale": "upgrade", "pkg.updates": "upgrade", "pkg.security_updates": "upgrade",
    "cve.package": "upgrade",
    "pkg.restart": "restart",
    "pkg.reboot": "reboot",
    "pkg.auto_updates_off": "auto-updates",
    "os.lts": "os-upgrade", "os.eol_soon": "os-upgrade", "os.eol": "os-upgrade",
}


def step_of(rule: str, key: str | None = None) -> str | None:
    # A kernel fix only applies after a reboot, so kernel CVEs join that step.
    if rule == "cve.package" and key == "linux":
        return "reboot"
    return STEP_OF.get(rule)


def digest(items) -> str:
    """A short, stable hash of a collection, for a basis too long to store whole."""
    return hashlib.sha256("\n".join(sorted(map(str, items))).encode()).hexdigest()[:16]


def fingerprint(rule: str, key: str, basis: str | None, title: str) -> str:
    """What an acceptance is tied to. It changes when the finding's basis
    does, and the finding shows as open again."""
    raw = f"{rule}\0{key}\0{basis if basis is not None else title}"
    return hashlib.sha256(raw.encode()).hexdigest()


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
                f"/services#ctr-{c['name']}", basis=f"{key}|{c['name']}",
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
                               f"Threshold is {limit:.0f}%.", "/#system", basis=f"{d['mount']}|{sev}"))
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
                    f"Threshold is {limit:.0f}%.", "/#system", basis="mem")]


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


def upstream_allows(cfg: Config, proto: str, port: int) -> bool:
    allow = cfg.exposure.upstream_allow
    return not allow or f"{port}/{proto}" in allow


def expose_unexpected(snaps, cfg: Config, ctx) -> list[Finding]:
    expected = set(cfg.exposure.expected_public)
    out = []
    for r in public_listeners(snaps, ctx):
        key = f"{r['port']}/{r['proto']}"
        if key in expected or not upstream_allows(cfg, r["proto"], r["port"]):
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
            f"/exposure#{anchor('port', r['port'], r['proto'])}",
            basis=f"{key}|{r.get('process') or ''}|{sev}"))
    return out


def expose_forward_all(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "firewall")
    out = []
    allow = cfg.exposure.upstream_allow
    for f in (data or {}).get("forwards", []):
        count = sum(hi - lo + 1 for lo, hi in f["ranges"])
        if count <= 1000:
            continue
        proto = f["proto"].upper() if f["proto"] != "all" else "TCP and UDP"
        where = f" arriving {', '.join(f['conditions'])}" if f["conditions"] else ""
        if allow:
            # The provider firewall decides what actually arrives.
            reach = sorted(int(p.split("/")[0]) for p in allow if "/" in p
                           and p.split("/")[1] in (f["proto"], "tcp", "udp")
                           and (f["proto"] == "all" or p.split("/")[1] == f["proto"])
                           and any(lo <= int(p.split("/")[0]) <= hi for lo, hi in f["ranges"]))
            out.append(Finding(
                "expose.forward_all", f"{f['family']} {f['proto']} {f['to']}", "low",
                f"{proto} forward to {f['to']} relies on the provider firewall",
                f"The rule forwards {f['ports']}{where}. The provider firewall lets in "
                f"{', '.join(map(str, reach)) or 'none of them'}. A port added to the provider policy later "
                f"goes to {f['to']} as well. Listing the ports in the rule removes that dependence.",
                f"/exposure#{anchor('fwd', f['family'], f['proto'], f['to'])}",
                basis=f"{f['family']} {f['proto']} {f['to']}|{f['ports']}|{','.join(map(str, reach))}"))
            continue
        out.append(Finding(
            "expose.forward_all", f"{f['family']} {f['proto']} {f['to']}", "high",
            (f"All {proto} ports except {f['ports'][len('all except '):]} are forwarded to {f['to']}"
             if f["ports"].startswith("all except ") else f"{proto} ports {f['ports']} are forwarded to {f['to']}"),
            f"Every {proto} port{where} except the ones listed goes to {f['to']} ({count} ports). Anything "
            f"that host listens on, now or later, is reachable from the internet through this one. "
            f"Forward only the ports it needs.", f"/exposure#{anchor('fwd', f['family'], f['proto'], f['to'])}",
            basis=f"{f['family']} {f['proto']} {f['to']}|{f['ports']}|"))
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
        if cfg.exposure.upstream_allow:
            note += (" The provider firewall in front of the host lets in "
                     f"{', '.join(cfg.exposure.upstream_allow)}. If that policy changes, nothing on the host "
                     "backs it up.")
        out.append(Finding(
            "firewall.default_accept", family, "low" if cfg.exposure.upstream_allow else "medium",
            f"{label} input accepts all traffic by default",
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
                    "The same rule appears more than once. A script that adds rules each time it runs and "
                    "never removes them, such as a WireGuard PostUp, leaves this behind." + extra, "/exposure#firewall",
                    basis="dups")]


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
                        f"Caddy proxies this site to {u['text']}, and nothing on this host listens there. "
                        "Visitors get a 502 error.", f"/routes#{anchor('site', site['host'])}"))
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
                           f"It listens on {r['port']}/{r['proto']} from the internet. {why}",
                           f"/exposure#{anchor('port', r['port'], r['proto'])}",
                           basis=f"{name}|{r['port']}/{r['proto']}"))
    return out


def jail_log_missing(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "fail2ban")
    out = []
    for j in (data or {}).get("jails", []):
        for lp in j.get("logpaths", []):
            if not lp["exists"]:
                out.append(Finding("jail.log_missing", f"{j['name']} {lp['path']}", "medium",
                                   f"Jail {j['name']} watches a missing file",
                                   f"{lp['path']} does not exist.", f"/fail2ban#{anchor('jail', j['name'])}"))
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
                    "/routes", basis=f"admin|{listen}")]


# ---- Phase 3a: packages ----------------------------------------------------

STALE_LISTS_DAYS = 3


def upgrade_cmd(data: dict | None) -> str:
    """The command that installs pending updates on this host's package system."""
    return "sudo dnf upgrade --refresh" if (data or {}).get("backend") == "dnf" else "sudo apt upgrade"


def reboot_reasons(data: dict | None) -> list[str]:
    """Why the host wants a reboot; empty when it doesn't."""
    data = data or {}
    out = []
    reboot = data.get("reboot") or {}
    if reboot.get("required"):
        pkgs = reboot.get("pkgs") or []
        if pkgs:
            out.append("Updated packages ask for it: " + ", ".join(pkgs[:5]) + ".")
        elif data.get("backend") == "dnf":
            out.append("dnf needs-restarting asks for it.")
        else:
            out.append("The system asks for it (/var/run/reboot-required).")
    kernel = data.get("kernel") or {}
    if kernel.get("managed") and kernel.get("newer_installed"):
        out.append(f"Kernel {kernel['newer_installed']} is installed, {kernel['running']} is running.")
    return out


def _names(items: list[str], limit: int = 5) -> str:
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def pkg_security_updates(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "packages")
    sec = [u["name"] for u in (data or {}).get("updates", []) if u.get("security")]
    if not sec:
        return []
    n = len(sec)
    age = data.get("lists_age")
    fresh = age is not None and snaps["packages"].taken_at - age < STALE_LISTS_DAYS * 86400
    todo = "Install them."
    if data.get("unattended_upgrades"):
        todo = "unattended-upgrades is installed but is not applying them. Check it, or install them yourself."
    return [Finding("pkg.security_updates", "security", "high" if fresh else "medium",
                    f"{n} security update{'s' if n > 1 else ''} waiting",
                    f"{_names(sec)}. {todo}", "/packages#security",
                    fix=upgrade_cmd(data), basis=f"security:{digest(sec)}")]


def pkg_updates(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "packages")
    ups = (data or {}).get("updates", [])
    other = [u["name"] for u in ups if not u.get("security")]
    if not other or len(other) != len(ups):
        return []
    n = len(other)
    # Basis: not the package names. Accepting this says regular updates may wait
    # on this host, and a new batch of them is not a change to that decision.
    return [Finding("pkg.updates", "updates", "low", f"{n} update{'s' if n > 1 else ''} waiting",
                    f"{_names(other)}. Install them.", "/packages#other",
                    fix=upgrade_cmd(data), basis="updates")]


def pkg_reboot(snaps, cfg, ctx) -> list[Finding]:
    reasons = reboot_reasons(_data(snaps, "packages"))
    if not reasons:
        return []
    # A newer kernel installed since the acceptance is a new reason to reboot.
    kernel = (_data(snaps, "packages") or {}).get("kernel") or {}
    return [Finding("pkg.reboot", "reboot", "medium", "Reboot needed", " ".join(reasons), "/packages#reboot",
                    fix="sudo reboot", basis=f"reboot:{kernel.get('newer_installed') or ''}")]


def pkg_restart(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "packages")
    svcs = ((data or {}).get("needrestart") or {}).get("services") or []
    if not svcs:
        return []
    n = len(svcs)
    if (data or {}).get("backend") == "dnf":
        fix = "sudo systemctl restart " + " ".join(shlex.quote(s) for s in svcs)
    else:
        fix = "sudo needrestart -r a"
    return [Finding("pkg.restart", "restart", "low",
                    f"{n} service{'s use' if n > 1 else ' uses'} old libraries",
                    f"{_names(svcs)}. Restart them.", "/packages#reboot",
                    fix=fix if len(fix) <= 1900 else None, basis=f"restart:{digest(svcs)}")]


def auto_updates_off(data: dict | None, cfg: Config) -> bool:
    """Whether to say this host doesn't install updates on its own. Unknown
    (the collector couldn't read it) counts as not off, and a workstation is
    never flagged: desktops usually update through the software centre
    (KDE Discover, GNOME Software)."""
    if cfg.role == "workstation":
        return False
    auto = (data or {}).get("auto_updates") or {}
    return bool(auto.get("known")) and not auto.get("on")


def auto_updates_howto(data: dict) -> tuple[str, str | None]:
    """What to do about it for this host's package system: the advice in
    words, and the commands that carry it out (None when it's an edit to a
    file, which no command does)."""
    auto = data.get("auto_updates") or {}
    if data.get("backend") == "dnf":
        if not auto.get("installed"):
            return ("Install the dnf5 automatic plugin. In /etc/dnf/automatic.conf, under [commands], set "
                    "apply_updates = yes and, to install only security updates, upgrade_type = security. "
                    "Then enable the dnf5-automatic timer.",
                    "sudo dnf install dnf5-plugin-automatic\n"
                    "# In /etc/dnf/automatic.conf, under [commands], set apply_updates = yes "
                    "(and upgrade_type = security to install only security updates)\n"
                    "sudo systemctl enable --now dnf5-automatic.timer")
        if auto.get("timer") != "enabled":
            return "Enable the dnf5-automatic timer.", "sudo systemctl enable --now dnf5-automatic.timer"
        return ("In /etc/dnf/automatic.conf, under [commands], set apply_updates = yes. Today it only "
                "downloads updates.", None)
    if not auto.get("installed"):
        return "Install unattended-upgrades.", "sudo apt install unattended-upgrades"
    if (auto.get("unattended") or "") in ("", "0"):
        return ("Turn it on by reconfiguring the package, and answer Yes.",
                "sudo dpkg-reconfigure -plow unattended-upgrades")
    return "Enable the apt-daily-upgrade timer.", "sudo systemctl enable --now apt-daily-upgrade.timer"


def pkg_auto_updates_off(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "packages")
    if not auto_updates_off(data, cfg):
        return []
    tool = "dnf5 automatic" if data.get("backend") == "dnf" else "unattended-upgrades"
    how, fix = auto_updates_howto(data)
    return [Finding("pkg.auto_updates_off", "auto", "low", "Security updates aren't installed automatically",
                    f"Nothing on this host installs updates by itself ({tool} is not on), so a security fix "
                    f"waits until someone installs it. {how}",
                    "/packages#auto", fix=fix)]


def pkg_lists_stale(snaps, cfg, ctx) -> list[Finding]:
    data = _data(snaps, "packages")
    age = (data or {}).get("lists_age")
    if age is None:
        return []
    days = int((snaps["packages"].taken_at - age) // 86400)
    if days < STALE_LISTS_DAYS:
        return []
    fix = None
    if (data or {}).get("backend") == "dnf":
        why = "dnf's makecache timer may be off (systemctl list-timers 'dnf5-makecache*')."
    elif data.get("periodic_update") is False:
        why = "apt's daily timer runs but doesn't refresh the lists: APT::Periodic::Update-Package-Lists isn't set."
        if auto_updates_off(data, cfg):
            why += " The automatic updates finding has the fix, since unattended-upgrades sets it."
        else:
            why += " Refresh them with apt update, or install unattended-upgrades, which sets it."
            fix = "sudo apt update"
    else:
        why = "apt's daily timer may be off (systemctl list-timers 'apt-daily*')."
    return [Finding("pkg.lists_stale", "lists", "low", f"Package lists are {days} days old",
                    f"{why} Updates listed here may be missing newer ones.", "/packages#lists",
                    fix=fix, basis="lists")]


# ---- OS support -------------------------------------------------------------

SOON_DAYS = 180


def system_support(data: dict | None, today: date | None = None) -> distro.Support:
    return distro.evaluate(data or {}, today)


def _upgrade(sup: distro.Support) -> str:
    if not sup.current_version or sup.current_version == sup.version:
        return ""
    return f" Upgrading to {sup.current}, the current release, gets full support."


def os_lts(snaps, cfg, ctx) -> list[Finding]:
    sup = system_support(_data(snaps, "system"), ctx.get("today"))
    if sup.status != "extended" or not sup.until:
        return []
    today = ctx.get("today") or date.today()
    soon = (sup.until - today).days <= SOON_DAYS
    if sup.distro == "debian":
        what, label = "LTS", "LTS"
        detail = (f"Regular security support ended {sup.eol.isoformat()}. LTS covers fewer packages; "
                  f"see {distro.LTS_URL}.")
    else:
        what, label = "ESM", "ESM"
        detail = (f"Standard support ended {sup.eol.isoformat()}. Security updates now come only through "
                  f"ESM, part of Ubuntu Pro.")
    return [Finding("os.lts", "os", "medium" if soon else "low",
                    f"{sup.name} is on {label} until {sup.until.isoformat()}",
                    detail + _upgrade(sup), "/#os")]


def os_eol_soon(snaps, cfg, ctx) -> list[Finding]:
    """Fedora has no LTS: warn for the last 60 days before a release ends."""
    sup = system_support(_data(snaps, "system"), ctx.get("today"))
    if sup.distro != "fedora" or sup.status != "supported" or not sup.eol:
        return []
    today = ctx.get("today") or date.today()
    if (sup.eol - today).days > distro.EOL_SOON_DAYS:
        return []
    cur = sup.current_version
    detail = f"Fedora stops security updates for {sup.name} on {sup.eol.isoformat()}."
    fix = None
    if cur and cur != sup.version:
        detail += (f" Upgrade to Fedora {cur}, the current release: install pending updates, download the "
                   f"new release, then reboot into the upgrade.")
        fix = (f"sudo dnf upgrade --refresh\nsudo dnf system-upgrade download --releasever={cur}\n"
               f"sudo dnf system-upgrade reboot")
    return [Finding("os.eol_soon", "os", "low", f"{sup.name} support ends on {sup.eol.isoformat()}",
                    detail, "/#os", fix=fix)]


def os_eol(snaps, cfg, ctx) -> list[Finding]:
    sup = system_support(_data(snaps, "system"), ctx.get("today"))
    if sup.status not in ("ended", "eol"):
        return []
    if sup.status == "ended":
        detail = (f"Free security support ended {sup.until.isoformat()}. Only paid ELTS covers "
                  f"{sup.name} now.")
    else:
        detail = f"Security support for {sup.name} has ended."
    return [Finding("os.eol", "os", "high", f"{sup.name} no longer gets security updates",
                    detail + _upgrade(sup), "/#os")]


RULES = [svc_failed, ctr_down, expose_docker_bypass, sys_disk, sys_memory, source_errors,
         expose_unexpected, expose_forward_all, firewall_default_accept, firewall_duplicates,
         route_upstream_down, route_upstream_failing, jail_uncovered,
         jail_log_missing, caddy_admin_tcp, pkg_security_updates, pkg_updates, pkg_reboot,
         pkg_restart, pkg_lists_stale, pkg_auto_updates_off, os_lts, os_eol_soon, os_eol]


def evaluate(snaps: dict, cfg: Config, ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    out: dict[tuple[str, str], Finding] = {}
    for rule in RULES:
        for f in rule(snaps, cfg, ctx):
            # One finding per (rule, key); an IPv4 and IPv6 binding of the same port is one problem.
            out.setdefault((f.rule, f.key), f)
    return list(out.values())
