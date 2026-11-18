"""The Unraid GraphQL API: the queries, what is stored from each, and the
check that a key may only read.

Every query is written from Unraid's published schema, `api/generated-schema.graphql`
in https://github.com/unraid/api (type names are given beside each query),
and was run against a real Unraid 7.3.2 server (read-only) to confirm its
shape. Introspection is not used.

Auth: the key goes in an `x-api-key` header; the endpoint is `/graphql`
(https://docs.unraid.net/API/how-to-use-the-api/). The server's own
`me` query returns the key's roles and explicit permissions
(`api/src/unraid-api/graph/user/user.resolver.ts`; `auth.service.ts`
`validateApiKeyCasbin` builds that user from the stored key), so the hub can
check, before it saves a key and on every poll, that the key is Viewer-only.

Unraid says what a poll costs in time (measured on a 6-disk server with 800
stored notifications): `disks` runs smartctl on each disk (2.4 s) and
`notifications` reads the notification files (1.1 s), so those two are read
every five minutes. Everything else is under 0.7 s and is read every
`interval` (60 s by default).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from math import isfinite

from .client import Graph, Net, RemoteError, scrub

# --- the queries ---------------------------------------------------------------
# Query.me: UserAccount { name roles permissions { resource actions } }
Q_ME = "{ me { name roles permissions { resource actions } } }"

# Query.vars: Vars { name version }. Query.info: Info { os, versions, cpu }.
# Query.metrics: Metrics { cpu: CpuUtilization, memory: MemoryUtilization }.
Q_SYSTEM = ("{ vars { name version } "
            "info { os { hostname release kernel uptime } versions { core { unraid api } } cpu { brand cores threads } } "
            "metrics { cpu { percentTotal } memory { total available percentTotal swapTotal swapUsed } } }")

# Query.array: UnraidArray { state capacity parityCheckStatus parities disks caches boot }, each disk an ArrayDisk.
# Query.display: InfoDisplay { hot max warning critical } (Unraid's disk temperature and usage thresholds).
# Query.parityHistory: [ParityCheck].
_ARRAY_DISK = ("idx name device size status rotational temp numReads numWrites numErrors "
               "fsSize fsFree fsUsed type fsType transport isSpinning warning critical")
Q_ARRAY = ("{ array { state capacity { kilobytes { free used total } disks { used total } } "
           "parityCheckStatus { date duration speed status errors progress correcting paused running } "
           "parities { ...D } disks { ...D } caches { ...D } boot { ...D } } "
           "display { hot max warning critical } parityHistory { date duration speed status errors } } "
           f"fragment D on ArrayDisk {{ {_ARRAY_DISK} }}")

# Query.docker: Docker { containers: [DockerContainer] }
Q_DOCKER = ("{ docker { containers { names image state status autoStart isUpdateAvailable isOrphaned "
            "ports { ip privatePort publicPort type } } } }")

# Query.vms: Vms { domains: [VmDomain { name state }] }. Null when the VM manager is off.
Q_VMS = "{ vms { domains { name state } } }"

# Query.notifications: Notifications { overview.unread, warningsAndAlerts: [Notification] } (unread only)
Q_NOTIFICATIONS = ("{ notifications { overview { unread { info warning alert total } } "
                   "warningsAndAlerts { id title subject importance timestamp } } }")

# Query.upsDevices: [UPSDevice { status battery power }]
Q_UPS = ("{ upsDevices { id name model status battery { chargeLevel estimatedRuntime health } "
         "power { loadPercentage } } }")

# Query.disks: [Disk { smartStatus temperature interfaceType ... }] (runs smartctl)
Q_DISKS = "{ disks { device type name vendor size interfaceType smartStatus temperature isSpinning } }"

# What "Test connection" counts.
Q_PROBE = ("{ vars { name version } "
           "array { state parities { name } disks { name } caches { name } } docker { containers { names } } }")

# source name -> (query, root fields that must come back, how often)
FAST, SLOW = "fast", "slow"
SOURCES: dict[str, tuple[str, tuple[str, ...], str]] = {
    "unraid_system": (Q_SYSTEM, ("vars", "info", "metrics"), FAST),
    "unraid_array": (Q_ARRAY, ("array", "display", "parityHistory"), FAST),
    "unraid_docker": (Q_DOCKER, ("docker",), FAST),
    "unraid_vms": (Q_VMS, (), FAST),
    "unraid_ups": (Q_UPS, ("upsDevices",), FAST),
    "unraid_disks": (Q_DISKS, ("disks",), SLOW),
    "unraid_notifications": (Q_NOTIFICATIONS, ("notifications",), SLOW),
}
SLOW_SECONDS = 300
ALL_QUERIES = [Q_ME, Q_PROBE] + [q for q, _r, _t in SOURCES.values()]

# What each stored source was read with, as shown in its panel.
QUERY_OF = {src: q for src, (q, _r, _t) in SOURCES.items()}


# --- the key may only read ------------------------------------------------------

READ_ACTIONS = {"READ_ANY", "READ_OWN"}
HOW_TO_VIEWER = ("In Unraid, open Settings \u2192 Management Access \u2192 API Keys, add a key, give it the Viewer role only "
                 "(no other role, no extra permissions) and use that key here.")


def key_problem(me: dict) -> str | None:
    """Why this key may not be used, or None when it can only read. A Viewer
    key has the role VIEWER and nothing that creates, updates or deletes."""
    roles = sorted({str(r) for r in (me.get("roles") or [])})
    writes = sorted({str(p.get("resource")) for p in (me.get("permissions") or []) if isinstance(p, dict)
                     and any(a not in READ_ACTIONS for a in (p.get("actions") or []))})
    extra = [r for r in roles if r != "VIEWER"]
    if not extra and not writes:
        return None
    parts = []
    if extra:
        parts.append(f"the {', '.join(extra)} role" + ("s" if len(extra) > 1 else ""))
    if writes:
        parts.append("permission to change " + ", ".join(w.lower() for w in writes[:6]) + (" and more" if len(writes) > 6 else ""))
    return (f"This key has {' and '.join(parts)}. DaemonSight only reads, and refuses a key that could change "
            f"anything. {HOW_TO_VIEWER}")


# --- small helpers -------------------------------------------------------------

def num(v):
    """A number from a JSON number or a numeric string (Unraid's BigInt), else None."""
    if v is None or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if not isfinite(f):
        return None
    return int(f) if f.is_integer() else f


def text(v, n: int = 200) -> str:
    """Printable text from the server, cut to n characters. It is shown only through escaped templates."""
    return "".join(c for c in str(v if v is not None else "")[:n] if c.isprintable()).strip()


def epoch(v) -> float | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _upper(v) -> str:
    return text(v, 40).upper()


# --- turning replies into what is stored ---------------------------------------

def parse_system(d: dict) -> dict:
    vars_, info, m = d["vars"], d["info"], d["metrics"]
    core = (info.get("versions") or {}).get("core") or {}
    os_ = info.get("os") or {}
    cpu = info.get("cpu") or {}
    mem = m.get("memory") or {}
    total, avail = num(mem.get("total")), num(mem.get("available"))
    return {
        "name": text(vars_.get("name"), 80),
        "version": text(vars_.get("version") or core.get("unraid"), 40),
        "api_version": text(core.get("api"), 40),
        "hostname": text(os_.get("hostname"), 80),
        "release": text(os_.get("release"), 60),
        "kernel": text(os_.get("kernel"), 60),
        "boot_time": epoch(os_.get("uptime")),
        "cpu": {"brand": text(cpu.get("brand"), 80), "cores": num(cpu.get("cores")),
                "threads": num(cpu.get("threads")), "percent": num((m.get("cpu") or {}).get("percentTotal"))},
        "memory": {"total": total, "available": avail,
                   "percent": num(mem.get("percentTotal")),
                   "swap_total": num(mem.get("swapTotal")), "swap_used": num(mem.get("swapUsed"))},
    }


def _percent(used, size) -> float | None:
    return round(used / size * 100, 1) if used is not None and size else None


def _disk(d: dict) -> dict:
    size, used, free = num(d.get("fsSize")), num(d.get("fsUsed")), num(d.get("fsFree"))
    if used is None and size and free is not None:
        used = size - free
    return {
        "slot": num(d.get("idx")), "name": text(d.get("name"), 40), "device": text(d.get("device"), 40),
        "kind": text(d.get("type"), 12).lower(), "status": _upper(d.get("status")),
        "size_kb": num(d.get("size")), "rotational": d.get("rotational") if isinstance(d.get("rotational"), bool) else None,
        "temp": num(d.get("temp")), "reads": num(d.get("numReads")), "writes": num(d.get("numWrites")),
        "errors": num(d.get("numErrors")),
        "fs_type": text(d.get("fsType"), 12), "fs_size_kb": size, "fs_used_kb": used, "fs_free_kb": free,
        "percent": _percent(used, size), "spinning": d.get("isSpinning") if isinstance(d.get("isSpinning"), bool) else None,
        "transport": text(d.get("transport"), 12),
    }


def _check(c: dict | None) -> dict:
    c = c or {}
    return {"status": _upper(c.get("status")), "date": epoch(c.get("date")), "duration": num(c.get("duration")),
            "speed": text(c.get("speed"), 30), "errors": num(c.get("errors")), "progress": num(c.get("progress")),
            "running": bool(c.get("running")), "paused": bool(c.get("paused")), "correcting": bool(c.get("correcting"))}


def parse_array(d: dict) -> dict:
    a = d["array"]
    cap = a.get("capacity") or {}
    kb = cap.get("kilobytes") or {}
    nd = cap.get("disks") or {}
    disks = []
    for key in ("parities", "disks", "caches"):
        disks += [_disk(x) for x in (a.get(key) or []) if isinstance(x, dict)][:60]
    if isinstance(a.get("boot"), dict):
        disks.append(_disk(a["boot"]))
    total, used = num(kb.get("total")), num(kb.get("used"))
    disp = d.get("display") or {}
    hist = [_check(h) for h in (d.get("parityHistory") or []) if isinstance(h, dict)]
    hist.sort(key=lambda h: h["date"] or 0, reverse=True)
    return {
        "state": _upper(a.get("state")),
        "capacity": {"total_kb": total, "used_kb": used, "free_kb": num(kb.get("free")),
                     "percent": _percent(used, total), "disks_used": num(nd.get("used")), "disks_total": num(nd.get("total"))},
        "parity_check": _check(a.get("parityCheckStatus")),
        "parity_history": hist[:30],
        "thresholds": {"hot": num(disp.get("hot")), "max": num(disp.get("max")),
                       "warning": num(disp.get("warning")), "critical": num(disp.get("critical"))},
        "disks": disks,
    }


def parse_docker(d: dict) -> dict:
    out = []
    for c in (d["docker"].get("containers") or [])[:500]:
        if not isinstance(c, dict):
            continue
        names = c.get("names") or []
        out.append({
            "name": text(names[0] if names else "", 80).lstrip("/"), "image": text(c.get("image"), 200),
            "state": _upper(c.get("state")), "status": text(c.get("status"), 80),
            "auto_start": bool(c.get("autoStart")),
            "update": c.get("isUpdateAvailable") if isinstance(c.get("isUpdateAvailable"), bool) else None,
            "orphaned": bool(c.get("isOrphaned")),
            "ports": [{"ip": text(p.get("ip"), 45), "private": num(p.get("privatePort")), "public": num(p.get("publicPort")),
                       "type": _upper(p.get("type"))} for p in (c.get("ports") or [])[:20] if isinstance(p, dict)],
        })
    out.sort(key=lambda c: c["name"].lower())
    return {"containers": out}


def parse_vms(d: dict, warnings: list[str] | None = None) -> dict:
    vms = d.get("vms")
    if not isinstance(vms, dict):
        return {"available": False, "reason": (warnings or ["The VM manager is not running."])[0]}
    out = [{"name": text(v.get("name"), 80), "state": _upper(v.get("state"))}
           for v in (vms.get("domains") or [])[:200] if isinstance(v, dict)]
    out.sort(key=lambda v: v["name"].lower())
    return {"vms": out}


def parse_notifications(d: dict) -> dict:
    n = d["notifications"]
    unread = (n.get("overview") or {}).get("unread") or {}
    items = []
    for x in (n.get("warningsAndAlerts") or [])[:50]:
        if not isinstance(x, dict):
            continue
        nid = text(x.get("id"), 300)
        items.append({"id": nid.split(":", 1)[-1], "title": text(x.get("title"), 120), "subject": text(x.get("subject"), 200),
                      "importance": _upper(x.get("importance")), "time": epoch(x.get("timestamp"))})
    return {"unread": {k: num(unread.get(k)) or 0 for k in ("info", "warning", "alert", "total")}, "items": items}


def parse_ups(d: dict) -> dict:
    out = []
    for u in (d["upsDevices"] or [])[:10]:
        if not isinstance(u, dict):
            continue
        b, p = u.get("battery") or {}, u.get("power") or {}
        out.append({"id": text(u.get("id"), 60), "name": text(u.get("name"), 60), "model": text(u.get("model"), 80),
                    "status": text(u.get("status"), 40), "charge": num(b.get("chargeLevel")),
                    "runtime": num(b.get("estimatedRuntime")), "health": text(b.get("health"), 20),
                    "load": num(p.get("loadPercentage"))})
    return {"devices": out}


def parse_disks(d: dict) -> dict:
    out = []
    for x in (d["disks"] or [])[:100]:
        if not isinstance(x, dict):
            continue
        dev = text(x.get("device"), 40)
        out.append({"device": dev.removeprefix("/dev/"), "model": text(x.get("name"), 80), "vendor": text(x.get("vendor"), 40),
                    "type": text(x.get("type"), 12), "size": num(x.get("size")), "interface": _upper(x.get("interfaceType")),
                    "smart": _upper(x.get("smartStatus")), "temp": num(x.get("temperature")),
                    "spinning": x.get("isSpinning") if isinstance(x.get("isSpinning"), bool) else None})
    return {"disks": out}


PARSERS = {"unraid_system": parse_system, "unraid_array": parse_array, "unraid_docker": parse_docker,
           "unraid_vms": parse_vms, "unraid_ups": parse_ups, "unraid_disks": parse_disks,
           "unraid_notifications": parse_notifications}


def parse(source: str, data: dict, warnings: list[str]) -> dict:
    if source == "unraid_vms":
        return parse_vms(data, warnings)
    return PARSERS[source](data)


# --- test connection -------------------------------------------------------------

@dataclass
class Probe:
    """What a test found. `problem` is set when the key may not be used."""
    roles: list[str] = field(default_factory=list)
    key_name: str = ""
    problem: str | None = None
    name: str = ""
    version: str = ""
    array_state: str = ""
    disks: int | None = None
    containers: int | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.problem is None


async def probe(net: Net, url: str, key: str, tls: str = "verify", pem: str | None = None) -> Probe:
    """Ask the server who this key is and, if it is a Viewer key, what is
    there. Raises RemoteError when the server can't be read at all."""
    graph = Graph(url, key, net.http(tls, pem))
    try:
        me = (await graph.query(Q_ME, ("me",))).data["me"]
        out = Probe(roles=sorted({text(r, 20) for r in (me.get("roles") or [])}), key_name=text(me.get("name"), 60))
        out.problem = key_problem(me)
        if out.problem:
            return out
        reply = await graph.query(Q_PROBE, ("vars", "array"))
        d = reply.data
        out.warnings = reply.warnings
        out.name, out.version = text(d["vars"].get("name"), 80), text(d["vars"].get("version"), 40)
        a = d["array"]
        out.array_state = _upper(a.get("state"))
        out.disks = sum(len(a.get(k) or []) for k in ("parities", "disks", "caches"))
        out.containers = len(((d.get("docker") or {}).get("containers")) or [])
        return out
    finally:
        await graph.aclose()


def error_text(exc: Exception, key: str | None) -> str:
    return scrub(exc.message if isinstance(exc, RemoteError) else f"{type(exc).__name__}: {exc}", key)[:300]


def due(row_now: float, taken_at: float | None, tier: str, interval: int) -> bool:
    gap = interval if tier == FAST else max(SLOW_SECONDS, interval)
    return taken_at is None or row_now - taken_at >= gap - 1
