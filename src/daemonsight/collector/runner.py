"""The collector loop: run each source on its interval, store snapshots and
metrics, record changes as events, and keep findings current."""

from __future__ import annotations

import asyncio
import logging
import signal
import time

from .. import db, findings
from ..config import Config
from .sources import Source, SourceUnavailable
from .sources.caddy import CaddySource
from .sources.docker import DockerSource
from .sources.fail2ban import Fail2banSource
from .sources.firewall import FirewallSource
from .sources.ports import PortsSource
from .sources.system import SystemSource
from .sources.systemd import SystemdSource
from .upload import Uploader

log = logging.getLogger("daemonsight.collector")


def build_sources(cfg: Config) -> list[Source]:
    c = cfg.collector
    return [
        SystemSource(c.interval_system),
        SystemdSource(c.interval_systemd, c.service_patterns),
        PortsSource(c.interval_ports),
        DockerSource(c.interval_docker, c.docker_socket, c.log_tail_lines),
        CaddySource(c.interval_caddy, c.caddy_admin),
        Fail2banSource(c.interval_fail2ban, c.fail2ban_socket),
        FirewallSource(c.interval_firewall, c.nft),
    ]


def ephemeral_range() -> tuple[int, int]:
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as fh:
            lo, hi = fh.read().split()
            return int(lo), int(hi)
    except (OSError, ValueError):
        return 32768, 60999


async def collect_once(source: Source, timeout: float) -> tuple[bool, str | None, dict | None]:
    try:
        data = await asyncio.wait_for(source.collect(), timeout=timeout)
        return True, None, data
    except SourceUnavailable as exc:
        return True, None, {"available": False, "reason": str(exc)}
    except Exception as exc:  # a source must never take the collector down
        log.warning("source %s failed: %s", source.name, exc, exc_info=log.isEnabledFor(logging.DEBUG))
        return False, f"{type(exc).__name__}: {exc}", None


def diff_events(source: str, prev: dict | None, cur: dict | None, eph: tuple[int, int]) -> list[dict]:
    """Changes between two snapshots worth showing under "Recent changes"."""
    if not prev or not cur or prev.get("available") is False or cur.get("available") is False:
        return []
    events = []
    if source == "ports":
        def keyset(data):
            out = {}
            for r in data["listeners"]:
                if r["scope"] == "loopback":
                    continue
                if r["proto"] == "udp" and eph[0] <= r["port"] <= eph[1]:
                    continue  # unconnected UDP client sockets come and go
                out[(r["proto"], r["port"])] = r
            return out
        before, after = keyset(prev), keyset(cur)
        for k in sorted(after.keys() - before.keys()):
            r = after[k]
            who = r.get("process") or "unknown process"
            events.append({"kind": "port_new", "severity": "medium",
                           "title": f"New listener {k[1]}/{k[0]}",
                           "detail": f"{who} on {', '.join(r['addresses'])}", "link": "/services#ports"})
        for k in sorted(before.keys() - after.keys()):
            events.append({"kind": "port_gone", "severity": None,
                           "title": f"Listener {k[1]}/{k[0]} closed", "detail": None, "link": "/services#ports"})
    elif source == "systemd":
        before = {u["name"]: u for u in prev["units"]}
        for u in cur["units"]:
            old = before.get(u["name"])
            if old and u.get("restarts") is not None and old.get("restarts") is not None \
                    and u["restarts"] > old["restarts"]:
                events.append({"kind": "svc_restart", "severity": "medium",
                               "title": f"{u['name']} restarted",
                               "detail": f"Restart count {old['restarts']} → {u['restarts']}",
                               "link": f"/services#unit-{u['name']}"})
    elif source == "docker":
        before = {c["name"]: c for c in prev["containers"]}
        for c in cur["containers"]:
            old = before.get(c["name"])
            if old and c["restart_count"] > old["restart_count"]:
                events.append({"kind": "ctr_restart", "severity": "medium",
                               "title": f"Container {c['name']} restarted",
                               "detail": f"Restart count {old['restart_count']} → {c['restart_count']}",
                               "link": f"/services#ctr-{c['name']}"})
            elif old and old["status"] == "running" and c["status"] != "running":
                why = " (out of memory)" if c["oom_killed"] else ""
                events.append({"kind": "ctr_stopped", "severity": "high",
                               "title": f"Container {c['name']} {c['status']}{why}",
                               "detail": f"Exit code {c['exit_code']}", "link": f"/services#ctr-{c['name']}"})
    elif source == "caddy":
        before = {x["host"] for x in prev.get("sites", [])}
        after = {x["host"] for x in cur.get("sites", [])}
        for h in sorted(after - before):
            events.append({"kind": "route_new", "severity": "medium", "title": f"New Caddy site {h}",
                           "detail": None, "link": "/routes"})
        for h in sorted(before - after):
            events.append({"kind": "route_gone", "severity": None, "title": f"Caddy site {h} removed",
                           "detail": None, "link": "/routes"})
    elif source == "fail2ban":
        before = {j["name"]: j for j in prev.get("jails", [])}
        for j in cur.get("jails", []):
            old = before.get(j["name"])
            if old is None:
                events.append({"kind": "jail_new", "severity": None, "title": f"Jail {j['name']} started",
                               "detail": None, "link": "/fail2ban"})
                continue
            if isinstance(j.get("banned_total"), int) and isinstance(old.get("banned_total"), int) \
                    and j["banned_total"] > old["banned_total"]:
                n = j["banned_total"] - old["banned_total"]
                events.append({"kind": "ban", "severity": None,
                               "title": f"{j['name']} banned {n} address{'es' if n > 1 else ''}",
                               "detail": None, "link": "/fail2ban"})
        for name in sorted(before.keys() - {j["name"] for j in cur.get("jails", [])}):
            events.append({"kind": "jail_gone", "severity": "high", "title": f"Jail {name} stopped",
                           "detail": None, "link": "/fail2ban"})
    elif source == "firewall":
        def shape(d):
            return [(c["family"], c["table"], c["chain"], c["default"], c["accept_all"],
                     sorted((o["proto"], o["from"], o["to"], tuple(o["conditions"])) for o in c["open"]))
                    for c in d.get("input", [])]
        if shape(prev) != shape(cur) or prev.get("forwards") != cur.get("forwards"):
            events.append({"kind": "firewall_changed", "severity": "medium",
                           "title": "Firewall rules changed", "detail": None, "link": "/exposure"})
    return events


class Collector:
    def __init__(self, cfg: Config, sources: list[Source] | None = None):
        self.cfg = cfg
        self.host = cfg.host_id
        self.conn = db.connect_writer(cfg.db_path)
        self.sources = sources if sources is not None else build_sources(cfg)
        self.eph = ephemeral_range()
        self._lock = asyncio.Lock()
        self._last_prune = 0.0

    async def step(self, source: Source) -> None:
        ts = time.time()
        ok, error, data = await collect_once(source, timeout=max(source.interval, 15))
        async with self._lock:
            prev = db.get_snapshot(self.conn, self.host, source.name)
            if not ok and prev is not None:
                data = prev.data  # keep showing the last good data, flagged with the error
            db.put_snapshot(self.conn, self.host, source.name, ts, ok, error, data)
            if ok and data and data.get("available") is not False:
                db.add_metrics(self.conn, self.host, ts, source.metrics(data))
                if prev is not None and prev.ok:
                    for e in diff_events(source.name, prev.data, data, self.eph):
                        db.add_event(self.conn, self.host, ts, e["kind"], e["title"], severity=e["severity"],
                                     detail=e["detail"], link=e["link"])
            self._evaluate(ts)
            if ts - self._last_prune > 3600:
                db.prune_metrics(self.conn, self.host, ts - self.cfg.collector.metrics_retention_hours * 3600)
                self._last_prune = ts

    def _evaluate(self, ts: float) -> None:
        snaps = db.get_snapshots(self.conn, self.host)
        t = self.cfg.thresholds
        avg, n = db.metric_average(self.conn, self.host, "mem.percent", ts - t.memory_minutes * 60)
        expected = t.memory_minutes * 60 / max(self.cfg.collector.interval_system, 1)
        ctx = {"mem_avg": avg if n >= expected * 0.8 else None, "eph": self.eph}
        current = findings.evaluate(snaps, self.cfg, ctx)
        for change, f in db.reconcile_findings(self.conn, self.host, ts, current):
            if change == "opened":
                db.add_event(self.conn, self.host, ts, "finding_opened", f.title,
                             severity=f.severity, detail=f.detail, link=f.link)
            else:
                db.add_event(self.conn, self.host, ts, "finding_resolved", f"Resolved: {f['title']}",
                             link=f["link"])

    async def _loop(self, source: Source) -> None:
        while True:
            started = time.monotonic()
            try:
                await self.step(source)
            except Exception:
                log.exception("collector step for %s failed", source.name)
            await asyncio.sleep(max(source.interval - (time.monotonic() - started), 1))

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        tasks = [asyncio.create_task(self._loop(s), name=f"source-{s.name}") for s in self.sources]
        log.info("collector started for host %s with %d sources", self.host, len(tasks))
        if self.cfg.upload.url:
            longest = max((s.interval for s in self.sources), default=60)
            uploader = Uploader(self.cfg, self.conn, self._lock, self.eph, longest)
            tasks.append(asyncio.create_task(uploader.run(stop), name="upload"))
        await stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for s in self.sources:
            await s.close()
        self.conn.close()
        log.info("collector stopped")
