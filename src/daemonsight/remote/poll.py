"""The hub's remote chore: read each enabled system every `interval` seconds
and keep its rows current. It runs on the hub's event loop like the CVE
chore; the network reads are async, the database writes are short and
synchronous (no await inside one), so a page request never waits for it.

Per system, one poll:
  1. `me`: the key's roles. A key with more than the Viewer role stops the
     poll (nothing else is asked) and shows as the error.
  2. The sources that are due (see unraid.SOURCES; SMART and notifications
     every five minutes, the rest every `interval`). Each is its own query,
     so one that fails (VMs switched off, say) doesn't stop the others; it
     keeps its last data and shows its error.
     The container statistics (`unraid_stats`) are the one source that is not
     a query: Unraid offers them only as a subscription, so once the container
     list is read a task subscribes for up to SAMPLE_SECONDS (it stops at once
     when every running container has reported, about two seconds on 69
     running ones) while the remaining queries run. A failed sample keeps the
     last data, and shows its age and error on the page; it never ends the poll.
  3. Rules (unraid_rules.py) make the open `unraid.*` findings match.

Unreachable: a poll that can't read the server leaves every stored reading as
it was and records `last_error`. After three intervals (and at least three
minutes) without a good poll the hub opens `remote.unreachable` (High).
`host.silent` isn't reused: its text blames a collector, and its checks
(`[upload]`, tokens) don't apply to a system the hub reads itself.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import time

from .. import db, settings
from ..config import Config
from ..findings import Finding
from . import release, store, unraid
from .client import Graph, Net, RemoteError

log = logging.getLogger("daemonsight.remote")
UNREACHABLE_AFTER_INTERVALS = 3
UNREACHABLE_MIN_SECONDS = 180
MAX_PARALLEL = 4
RULE_PREFIX = "unraid."


HOWTO_UNREACHABLE = "\n".join((
    "Check that the system is on and on the network: ping its address from the machine the hub runs on",
    "Open Hosts and Edit this system: check its address and that the API key is still right",
    "In Unraid, Settings \u2192 Management Access \u2192 API Keys shows whether the key still exists; it must have the Viewer role only",
    "If you pinned its certificate and Unraid's certificate changed, pin the new one in the same form",
    "The finding goes away at the next good read"))


def _put_source(conn, host: str, source: str, now: float, ok: bool, error: str | None, data: dict | None) -> None:
    """Store one source. A failed read keeps the previous data, as the collector does, so findings don't flap."""
    if data is None:
        old = db.get_snapshot(conn, host, source)
        data = old.data if old else None
    db.put_snapshot(conn, host, source, now, ok, error, data)


def _rule_inputs(conn, host: str) -> dict[str, dict | None]:
    snaps = db.get_snapshots(conn, host)
    out: dict[str, dict | None] = {}
    for src in unraid.SOURCES:
        s = snaps.get(src)
        out[src.removeprefix("unraid_")] = s.data if s and s.data and s.data.get("available") is not False else None
    out["release"] = release.stored(conn)
    return out


def _event(conn, host: str, now: float, kind: str, title: str, severity: str | None = None, detail: str | None = None) -> None:
    db.add_event(conn, host, now, kind, title, severity=severity, detail=detail, link=None)


def _set_unreachable(conn, row, now: float, error: str | None) -> None:
    """Open, update or resolve remote.unreachable for a system."""
    host = row["id"]
    f = None
    if error is not None:
        base = row["last_ok"] or row["created_at"]
        if now - base > max(UNREACHABLE_AFTER_INTERVALS * row["interval"], UNREACHABLE_MIN_SECONDS):
            since = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(row["last_ok"])) if row["last_ok"] else "never"
            f = Finding("remote.unreachable", "unreachable", "high", "Can't read this system",
                        f"The hub has not read this system for {int(now - base)} seconds (last good read: {since}). "
                        f"Last error: {error} Check that it is on, that its address and key are right "
                        "(Hosts, Edit) and, for a pinned certificate, that it hasn't changed.", "/", None, None,
                        HOWTO_UNREACHABLE)
    change = db.set_finding(conn, host, now, f, rule="remote.unreachable", key="unreachable")
    if change == "opened":
        db.add_event(conn, host, now, "remote_unreachable", f.title, severity="high", detail=error, link="/")
    elif change == "resolved":
        db.add_event(conn, host, now, "remote_back", "Reading this system again", link="/")


def _record_failure(conn, row, now: float, error: str) -> None:
    fails = (row["fails"] or 0) + 1
    conn.execute("UPDATE remotes SET last_poll=?, last_error=?, fails=? WHERE id=?", (now, error, fails, row["id"]))
    if fails == 1:
        _event(conn, row["id"], now, "remote_error", "Could not read this system", "low", error)
    _set_unreachable(conn, store.get(conn, row["id"]), now, error)


def _record_success(conn, row, now: float, system: dict | None) -> None:
    host = row["id"]
    was_down = (row["fails"] or 0) > 0
    conn.execute("UPDATE remotes SET last_poll=?, last_ok=?, last_error=?, fails=0 WHERE id=?", (now, now, None, host))
    version = (system or {}).get("version")
    conn.execute("UPDATE hosts SET last_seen=?, version=COALESCE(?, version) WHERE id=?",
                 (now, f"Unraid {version}" if version else None, host))
    if was_down:
        _event(conn, host, now, "remote_back", "Reading this system again")
    _set_unreachable(conn, store.get(conn, host), now, None)
    current = unraid_rules_evaluate(conn, host, now)
    for change, f in db.reconcile_findings(conn, host, now, current, only_prefix=RULE_PREFIX):
        if change == "opened":
            db.add_event(conn, host, now, "finding_opened", f.title, severity=f.severity, detail=f.detail, link=f.link)
        else:
            db.add_event(conn, host, now, "finding_resolved", f"Resolved: {f['title']}", link=f["link"])


def unraid_rules_evaluate(conn, host: str, now: float) -> list[Finding]:
    from . import unraid_rules
    return unraid_rules.evaluate(_rule_inputs(conn, host), now)


async def _sample_stats(graph: Graph, docker: dict | None, key: str, now: float) -> tuple[bool, str | None, dict | None]:
    """The container statistics, as (ok, error, data) like any other source. Never raises. `docker` is the parsed
    container list: it says which containers are running (so the sample can stop when all have reported) and what
    each Docker id is called."""
    if docker is None:
        return False, "The container list is not available yet.", None
    containers = [c for c in docker.get("containers", []) if c.get("id")]
    expected = {c["id"] for c in containers if c.get("state") == "RUNNING"}
    if not expected:
        return True, None, {"containers": {}, "sampled_at": now, "reported": 0, "seconds": 0}
    try:
        sample = await graph.sample(expected=expected)
        if not sample.items:
            raise RemoteError("graphql", "The server sent no container statistics.")
        return True, None, unraid.parse_stats(sample, {c["id"]: c["name"] for c in containers}, now)
    except RemoteError as exc:
        return False, unraid.error_text(exc, key), None
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return False, f"Unexpected reply: {type(exc).__name__}", None


async def poll_one(conn, cfg: Config, row, net: Net, now: float | None = None) -> None:
    """One poll of one system. Never raises."""
    now = time.time() if now is None else now
    host = row["id"]
    key = store.read_key(cfg.data_dir, host)
    if key is None:
        if store.get(conn, host) is not None:
            _record_failure(conn, row, now, "The API key file is missing or unreadable. Edit the system and enter the key again.")
        return
    results: dict[str, tuple[bool, str | None, dict | None]] = {}
    try:
        graph = Graph(row["url"], key, net.http(row["tls"], row["tls_cert"]),
                      ws=functools.partial(net.websocket, tls=row["tls"], pem=row["tls_cert"]))
    except RemoteError as exc:
        _record_failure(conn, row, now, unraid.error_text(exc, key))
        return
    stats_task: asyncio.Task | None = None
    try:
        try:
            me = (await graph.query(unraid.Q_ME, ("me",))).data["me"]
            problem = unraid.key_problem(me)
            if problem:
                raise RemoteError("key", problem)
            snaps = db.get_snapshots(conn, host)
            prev_stats = snaps.get(unraid.STATS)
            stats_due = unraid.due(now, prev_stats.taken_at if prev_stats else None, unraid.STATS_TIER, row["interval"])
            for source, (doc, require, tier) in unraid.SOURCES.items():
                prev = snaps.get(source)
                if not unraid.due(now, prev.taken_at if prev else None, tier, row["interval"]):
                    continue
                try:
                    reply = await graph.query(doc, require)
                    results[source] = (True, None, unraid.parse(source, reply.data, reply.warnings))
                except RemoteError as exc:
                    if exc.kind in ("auth", "tls", "key"):
                        raise
                    results[source] = (False, unraid.error_text(exc, key), None)
                except (KeyError, TypeError, ValueError, AttributeError) as exc:
                    results[source] = (False, f"Unexpected reply: {type(exc).__name__}", None)
                if source == "unraid_docker" and stats_due:
                    # With the list just read (or the last good one), sample in the background while the rest is read.
                    fresh = results.get(source)
                    old = snaps.get(source)
                    docker = fresh[2] if fresh and fresh[0] else (old.data if old and old.data else None)
                    stats_task = asyncio.create_task(_sample_stats(graph, docker, key, now))
            if stats_due and stats_task is None:      # the container list was not due: use the last one
                old = snaps.get("unraid_docker")
                stats_task = asyncio.create_task(_sample_stats(graph, old.data if old and old.data else None, key, now))
            if stats_task is not None:
                results[unraid.STATS] = await stats_task
        finally:
            if stats_task is not None and not stats_task.done():
                stats_task.cancel()
            await graph.aclose()
    except RemoteError as exc:
        current = store.get(conn, host)
        if current is not None and current["enabled"]:
            _record_failure(conn, current, now, unraid.error_text(exc, key))
        return
    except Exception as exc:  # a bug here must not stop the other systems
        log.exception("Reading %s failed", host)
        current = store.get(conn, host)
        if current is not None:
            _record_failure(conn, current, now, f"Unexpected error: {type(exc).__name__}")
        return
    current = store.get(conn, host)
    if current is None or not current["enabled"]:   # removed or disabled while we waited
        return
    for source, (ok, error, data) in results.items():
        _put_source(conn, host, source, now, ok, error, data)
    fresh = results.get("unraid_system")
    if fresh and fresh[0]:
        system = fresh[2]
        db.add_metrics(conn, host, now, {"cpu.percent": system["cpu"].get("percent"),
                                         "mem.percent": system["memory"].get("percent")})
    else:
        old = db.get_snapshot(conn, host, "unraid_system")
        system = old.data if old else None
    _record_success(conn, current, now, system)


async def run_once(conn, cfg: Config, net: Net, now: float | None = None) -> int:
    """Poll every enabled system that is due. Returns how many were polled."""
    now = time.time() if now is None else now
    todo = [r for r in store.all_rows(conn)
            if r["enabled"] and (r["last_poll"] is None or now - r["last_poll"] >= r["interval"] - 1)]
    sem = asyncio.Semaphore(MAX_PARALLEL)

    async def one(row):
        async with sem:
            await poll_one(conn, cfg, row, net, now)

    await asyncio.gather(*(one(r) for r in todo))
    return len(todo)


async def loop(cfg: Config, conn, net: Net | None = None) -> None:
    net = net or Net()
    await asyncio.sleep(3)     # let the web server finish starting
    while True:
        try:
            # Read the settings afresh: switching reading on or off applies on this pass.
            if settings.effective(cfg, conn).remote.enabled:
                await release.refresh(conn, net)       # once a day, public page, nothing about the server is sent
                await run_once(conn, cfg, net)
        except Exception:
            log.exception("Remote chore failed")
        await asyncio.sleep(5)
