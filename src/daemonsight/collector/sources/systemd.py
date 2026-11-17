"""systemd units over D-Bus.

API: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
ListUnitsByPatterns returns a(ssssssouso): name, description, load state,
active state, sub state, followed, object path, job id, job type, job path.
Read calls need no privilege ("Read access is generally granted to all clients").
"""

from __future__ import annotations

import asyncio
import logging

from dbus_fast import BusType, Message, MessageType
from dbus_fast.aio import MessageBus

from . import Source, SourceUnavailable

log = logging.getLogger("daemonsight.systemd")

DEST = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
MANAGER_IFACE = "org.freedesktop.systemd1.Manager"
UINT64_MAX = 2**64 - 1  # systemd's "not set" for counters such as MemoryCurrent
# The system bus rejects more than 128 pending replies per connection with
# org.freedesktop.DBus.Error.LimitsExceeded (max_replies_per_connection in
# /usr/share/dbus-1/system.conf), so property reads are capped well below that.
MAX_IN_FLIGHT = 32


def _num(value) -> int | None:
    if value is None or value == UINT64_MAX:
        return None
    return int(value)


def parse_unit_row(row) -> dict:
    name, description, load, active, sub, _followed, path, *_ = row
    return {"name": name, "description": description, "load": load, "active": active, "sub": sub, "path": path}


def merge_props(unit: dict, unit_props: dict, service_props: dict) -> dict:
    since_us = _num(unit_props.get("ActiveEnterTimestamp"))
    if unit["active"] in ("failed", "inactive"):
        since_us = _num(unit_props.get("InactiveEnterTimestamp")) or since_us
    unit.update({
        "since": since_us / 1_000_000 if since_us else None,
        "restarts": _num(service_props.get("NRestarts")),
        "memory": _num(service_props.get("MemoryCurrent")),
        "cpu_ns": _num(service_props.get("CPUUsageNSec")),
        "main_pid": _num(service_props.get("MainPID")) or None,
        "result": service_props.get("Result"),
        "cgroup": service_props.get("ControlGroup") or None,
        # Where the unit is defined (org.freedesktop.systemd1(5), Unit interface).
        "fragment": unit_props.get("FragmentPath") or None,
        "dropins": list(unit_props.get("DropInPaths") or []),
    })
    return unit


class SystemdSource(Source):
    name = "systemd"

    def __init__(self, interval: int = 30, patterns: list[str] | None = None):
        self.interval = interval
        self.patterns = patterns or ["*.service"]
        self._bus: MessageBus | None = None
        self._sem = asyncio.Semaphore(MAX_IN_FLIGHT)

    async def _connect(self) -> MessageBus:
        if self._bus is None or not self._bus.connected:
            try:
                self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            except (FileNotFoundError, ConnectionRefusedError) as exc:
                raise SourceUnavailable(f"system D-Bus not reachable: {exc}") from exc
        return self._bus

    async def _call(self, bus, path, interface, member, signature="", body=None):
        reply = await bus.call(Message(destination=DEST, path=path, interface=interface,
                                       member=member, signature=signature, body=body or []))
        if reply.message_type == MessageType.ERROR:
            raise RuntimeError(f"{member}: {reply.error_name}: {reply.body}")
        return reply.body

    async def _props(self, bus, path, interface) -> dict:
        async with self._sem:
            try:
                body = await self._call(bus, path, "org.freedesktop.DBus.Properties", "GetAll", "s", [interface])
            except RuntimeError as exc:
                log.debug("GetAll %s on %s failed: %s", interface, path, exc)
                return {}
        return {k: v.value for k, v in body[0].items()}

    async def collect(self) -> dict:
        bus = await self._connect()
        listed = await self._call(bus, MANAGER_PATH, MANAGER_IFACE, "ListUnitsByPatterns", "asas", [[], self.patterns])
        failed = await self._call(bus, MANAGER_PATH, MANAGER_IFACE, "ListUnitsByPatterns", "asas", [["failed"], []])
        units = {u["name"]: u for u in map(parse_unit_row, listed[0]) if u["load"] == "loaded"}
        for row in failed[0]:
            u = parse_unit_row(row)
            units.setdefault(u["name"], u)

        async def enrich(u: dict) -> dict:
            unit_props, service_props = await asyncio.gather(
                self._props(bus, u["path"], "org.freedesktop.systemd1.Unit"),
                self._props(bus, u["path"], "org.freedesktop.systemd1.Service")
                if u["name"].endswith(".service") else asyncio.sleep(0, {}),
            )
            return merge_props(u, unit_props, service_props)

        enriched = await asyncio.gather(*(enrich(u) for u in units.values()))
        enriched.sort(key=lambda u: (u["active"] != "failed", u["name"]))
        counts: dict[str, int] = {}
        for u in enriched:
            counts[u["active"]] = counts.get(u["active"], 0) + 1
        return {"units": enriched, "counts": counts}

    async def close(self) -> None:
        if self._bus is not None:
            self._bus.disconnect()
            self._bus = None
