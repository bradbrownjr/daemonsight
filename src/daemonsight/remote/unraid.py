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
`notifications` reads the notification files (1.1 s per list; the two lists
of alerts and of warnings took 2.1 s together), so those two are read
every five minutes. Everything else is under 0.7 s and is read every
`interval` (60 s by default).

The one thing that is not a query is the container CPU and memory (`unraid_stats`): Unraid has them only as a
subscription. The hub samples it for a few seconds each `interval` through `Graph.sample`, the only place a
subscription is sent (client.py); the protocol, the id format and the permission are in docs/DESIGN.md, Unraid.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from math import isfinite

from .client import STATS_SUBSCRIPTION, Graph, Net, RemoteError, Sample, scrub

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

# Query.docker: Docker { containers: [DockerContainer] }. `id` is a PrefixedID, "<server id>:<64 hex digits>"; the
# statistics subscription reports containers by the same id (see parse_stats).
Q_DOCKER = ("{ docker { containers { id names image state status autoStart isUpdateAvailable isOrphaned "
            "ports { ip privatePort publicPort type } } } }")

# Query.docker.organizer: ResolvedOrganizerV1 { version views: [ResolvedOrganizerView { id name rootId flatEntries
# prefs }] }. FlatOrganizerEntry { id type name parentId depth position path hasChildren childrenIds meta: DockerContainer }
# is one row of the folder tree, depth first in the owner's order: `type` is "folder" or "container", `position` is the
# place under its parent, `path` the names from the root, and for a container `meta.names` is the Docker name. The
# same Docker tab folders the owner arranged. Read on its own, so a version without it (or a failure) leaves the
# container list working, just flat.
Q_FOLDERS = ("{ docker { organizer { version views { id name rootId flatEntries { id type name parentId depth position "
             "path hasChildren childrenIds meta { names } } } } } }")

# Query.vms: Vms { domains: [VmDomain { name state }] }. Null when the VM manager is off.
Q_VMS = "{ vms { domains { name state } } }"

# Query.notifications: Notifications { overview.unread, list(filter): [Notification] } (unread only).
# Notification { id title subject description importance link timestamp } is the schema's type; `description`
# and `link` are String!/String. Why `list` and not `warningsAndAlerts`: that field drops repeats (it keeps one
# notification per importance, title, subject, description and link) and stops at 50, so thirteen "Unclean
# shutdown detected" alerts come back as one. `list` returns each file. Its `limit` counts the newest
# notification FILES, of any importance, before the importance filter is applied
# (notifications.service.ts: loadNotificationsFromPaths slices the files, then filters), so the limit has to
# cover the whole inbox (2000 here; `truncated` says when it does not).
NOTIFICATIONS_SCAN = 2000
_NOTIFICATION = "id title subject description importance link timestamp"
Q_NOTIFICATIONS = ("{ notifications { overview { unread { info warning alert total } } "
                   f"alerts: list(filter: {{type: UNREAD, importance: ALERT, offset: 0, limit: {NOTIFICATIONS_SCAN}}}) {{ {_NOTIFICATION} }} "
                   f"warnings: list(filter: {{type: UNREAD, importance: WARNING, offset: 0, limit: {NOTIFICATIONS_SCAN}}}) {{ {_NOTIFICATION} }} }} }}")
NOTIFICATIONS_KEPT = 400        # warnings and alerts stored, alerts first and newest first

# Query.upsDevices: [UPSDevice { status battery power }]
Q_UPS = ("{ upsDevices { id name model status battery { chargeLevel estimatedRuntime health } "
         "power { loadPercentage } } }")

# Query.disks: [Disk { smartStatus temperature interfaceType ... }] (runs smartctl)
Q_DISKS = "{ disks { device type name vendor size interfaceType smartStatus temperature isSpinning } }"

# Subscription.dockerContainerStats: DockerContainerStats! { id: PrefixedID!, cpuPercent: Float!, memUsage: String!,
# memPercent: Float! } (also netIO and blockIO, which are not asked for). Unraid has container CPU and memory only as
# this subscription: there is no query and no field on DockerContainer. It is `docker stats` run on the server
# (api/src/unraid-api/graph/resolvers/docker/docker-stats.service.ts), one message per container about every half
# second while someone is subscribed, and the stream stops when the last subscriber leaves. The hub subscribes for
# a few seconds each poll (`Graph.sample` in client.py, the only place a subscription is sent).
STATS = "unraid_stats"
Q_STATS = STATS_SUBSCRIPTION
STATS_TIER = "fast"

# What "Test connection" counts.
Q_PROBE = ("{ vars { name version } "
           "array { state parities { name } disks { name } caches { name } } docker { containers { names } } }")

# source name -> (query, root fields that must come back, how often)
FAST, SLOW = "fast", "slow"
SOURCES: dict[str, tuple[str, tuple[str, ...], str]] = {
    "unraid_system": (Q_SYSTEM, ("vars", "info", "metrics"), FAST),
    "unraid_array": (Q_ARRAY, ("array", "display", "parityHistory"), FAST),
    "unraid_docker": (Q_DOCKER, ("docker",), FAST),
    "unraid_folders": (Q_FOLDERS, ("docker",), SLOW),
    "unraid_vms": (Q_VMS, (), FAST),
    "unraid_ups": (Q_UPS, ("upsDevices",), FAST),
    "unraid_disks": (Q_DISKS, ("disks",), SLOW),
    "unraid_notifications": (Q_NOTIFICATIONS, ("notifications",), SLOW),
}
SLOW_SECONDS = 300
# Sources whose failure is not a problem with the system: the Docker folders (an older Unraid has none).
OPTIONAL = frozenset({"unraid_folders"})
# The statistics are sampled with a subscription, not a query, so they are not in SOURCES; the poller handles them
# beside it. A failed sample is not a problem with the system (the other sources say that), so it is optional too.
OPTIONAL = OPTIONAL | {STATS}
ALL_QUERIES = [Q_ME, Q_PROBE] + [q for q, _r, _t in SOURCES.values()]

# What each stored source was read with, as shown in its panel.
QUERY_OF = {src: q for src, (q, _r, _t) in SOURCES.items()} | {STATS: Q_STATS}


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
            "id": container_id(c.get("id")),
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


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_DOCKER_ID = re.compile(r"([0-9a-f]{64})$")


def container_id(v) -> str | None:
    """The 64 hex digits of a Docker container id from Unraid's PrefixedID ("<server id>:<id>"), or None."""
    m = _DOCKER_ID.search(_ANSI.sub("", str(v or "")))
    return m.group(1) if m else None


_SIZE_UNITS = {"B": 1, "KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40, "PIB": 1 << 50,
               "KB": 10 ** 3, "MB": 10 ** 6, "GB": 10 ** 9, "TB": 10 ** 12}
_SIZE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*$")


def _size(v: str) -> int | None:
    m = _SIZE.match(v)
    mult = _SIZE_UNITS.get(m.group(2).upper()) if m else None
    return round(float(m.group(1)) * mult) if m and mult else None


def parse_mem_usage(v) -> tuple[int | None, int | None]:
    """(used, limit) in bytes from `memUsage`, Docker's own "970MiB / 94.28GiB" (docker/cli
    cli/command/container/formatter_stats.go: `units.BytesSize(used) + " / " + units.BytesSize(limit)`, binary units
    with four significant digits; "-- / --" while a container is stopping). With no memory limit set, Docker reports
    the host's memory as the limit."""
    parts = str(v if v is not None else "").split("/")
    if len(parts) != 2:
        return None, None
    return _size(parts[0]), _size(parts[1])


def parse_stats(sample: Sample, names: dict[str, str], now: float) -> dict:
    """What a sample stores, by container name: {"containers": {name: {cpu, mem_percent, mem_used, mem_limit,
    sampled_at}}, "sampled_at", "reported", "seconds"}. `names` maps a Docker id to the name from the docker
    source, so a report for a container the list does not have is dropped. cpuPercent is Docker's figure for the
    last second and can be above 100 (one core is 100)."""
    out: dict[str, dict] = {}
    for cid, r in sample.items.items():
        name = names.get(cid)
        cpu, mem_pct = num(r.get("cpu")), num(r.get("mem_percent"))
        if not name or cpu is None or mem_pct is None or cpu < 0 or mem_pct < 0:
            continue
        used, limit = parse_mem_usage(r.get("mem_usage"))
        out[name] = {"cpu": round(float(cpu), 2), "mem_percent": round(float(mem_pct), 2), "mem_used": used,
                     "mem_limit": limit, "sampled_at": now}
    return {"containers": out, "sampled_at": now, "reported": len(out), "seconds": sample.seconds}


FOLDERS_MAX = 200


def parse_folders(d: dict) -> dict:
    """The Docker tab's folders, in the owner's order: {"folders": [{"name", "path", "containers": [Docker names]}]}.
    The entries come depth first, as Unraid lists them (checked live), so a folder's place in the list is its
    place on the Docker tab; a nested folder carries its path. Containers directly under the root belong to no
    folder (the page shows them as Ungrouped, in their order under the root). The view "default" is used when there is one, else the first."""
    org = ((d.get("docker") or {}).get("organizer")) or {}
    views = [v for v in (org.get("views") or []) if isinstance(v, dict)]
    view = next((v for v in views if v.get("id") == "default"), views[0] if views else None)
    if view is None:
        return {"available": False, "reason": "Unraid has no Docker folder view."}
    entries = [e for e in (view.get("flatEntries") or []) if isinstance(e, dict)]
    root = text(view.get("rootId"), 80)
    folders: dict[str, dict] = {}
    for e in entries:
        fid = text(e.get("id"), 80)
        if e.get("type") == "folder" and fid != root and len(folders) < FOLDERS_MAX:
            path = [text(p, 60) for p in (e.get("path") or [])][1:]
            folders[fid] = {"name": text(e.get("name"), 60) or fid, "path": path or [text(e.get("name"), 60) or fid],
                            "containers": []}
    loose: list[str] = []
    for e in sorted((e for e in entries if e.get("type") == "container"), key=lambda e: num(e.get("position")) or 0):
        meta = e.get("meta") if isinstance(e.get("meta"), dict) else {}
        names = meta.get("names") or []
        name = text(names[0] if names else e.get("name"), 80).lstrip("/")
        parent = text(e.get("parentId"), 80)
        if parent in folders and name and len(folders[parent]["containers"]) < 500:
            folders[parent]["containers"].append(name)
        elif parent == root and name and len(loose) < 500:
            loose.append(name)
    return {"folders": list(folders.values()), "ungrouped": loose}


def parse_vms(d: dict, warnings: list[str] | None = None) -> dict:
    vms = d.get("vms")
    if not isinstance(vms, dict):
        return {"available": False, "reason": (warnings or ["The VM manager is not running."])[0]}
    out = [{"name": text(v.get("name"), 80), "state": _upper(v.get("state"))}
           for v in (vms.get("domains") or [])[:200] if isinstance(v, dict)]
    out.sort(key=lambda v: v["name"].lower())
    return {"vms": out}


_TAG = re.compile(r"<[^>]*>")


def plain(v, n: int) -> str:
    """Text for a notification: Unraid's own notices put <br> and other markup in descriptions."""
    s = _TAG.sub(" ", re.sub(r"(?i)<br\s*/?>", " ", str(v if v is not None else "")))
    return text(" ".join(s.split()), n)


def parse_notifications(d: dict) -> dict:
    n = d["notifications"]
    unread = (n.get("overview") or {}).get("unread") or {}
    items, returned = [], {}
    for name, importance in (("alerts", "ALERT"), ("warnings", "WARNING")):
        got = [x for x in (n.get(name) or []) if isinstance(x, dict)]
        returned[importance.lower()] = len(got)
        for x in got:
            items.append({"id": text(x.get("id"), 300).split(":", 1)[-1], "title": text(x.get("title"), 120),
                          "subject": text(x.get("subject"), 200), "description": plain(x.get("description"), 300),
                          "link": text(x.get("link"), 100), "importance": _upper(x.get("importance")) or importance,
                          "time": epoch(x.get("timestamp"))})
    items.sort(key=lambda i: (i["importance"] != "ALERT", -(i["time"] or 0)))
    counts = {k: num(unread.get(k)) or 0 for k in ("info", "warning", "alert", "total")}
    return {"unread": counts, "items": items[:NOTIFICATIONS_KEPT], "returned": returned,
            "truncated": counts["total"] > NOTIFICATIONS_SCAN}


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
           "unraid_folders": parse_folders,
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
