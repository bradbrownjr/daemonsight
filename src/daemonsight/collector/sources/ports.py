"""Listening sockets from psutil.net_connections().

Without root, psutil returns pid=None for sockets owned by other users
(checked on Debian 13 with psutil 7.2.2), so owners are only known when the
collector runs as root.

The owner of a PID is read from /proc/<pid>/cgroup. On cgroup v2 hosts the
line is "0::/system.slice/<unit>" for a systemd service and
"0::/system.slice/docker-<id>.scope" (systemd cgroup driver) or
"0::/docker/<id>" (cgroupfs driver) for a container.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket

import psutil

from . import Source

DOCKER_SCOPE = re.compile(r"/docker-([0-9a-f]{64})\.scope$")
DOCKER_CGROUPFS = re.compile(r"/docker/([0-9a-f]{64})$")
SYSTEMD_UNIT = re.compile(r"/([^/]+\.(?:service|scope))$")


def owner_from_cgroup(text: str) -> dict:
    """Parse /proc/<pid>/cgroup content into {"kind": ..., "id": ...}."""
    path = None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            path = parts[2]
            break
    if path is None and text.strip():
        path = text.strip().splitlines()[0].split(":", 2)[-1]
    if not path:
        return {"kind": "unknown", "id": None}
    for pattern in (DOCKER_SCOPE, DOCKER_CGROUPFS):
        m = pattern.search(path)
        if m:
            return {"kind": "container", "id": m.group(1)}
    m = SYSTEMD_UNIT.search(path)
    if m:
        unit = m.group(1)
        if unit.startswith("session-") or unit == "init.scope":
            return {"kind": "session" if unit.startswith("session-") else "init", "id": unit}
        return {"kind": "unit", "id": unit}
    return {"kind": "unknown", "id": path}


def classify(ip: str) -> str:
    """Where a bind address can be reached from."""
    if ip in ("0.0.0.0", "::", ""):
        return "all"
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_global:
        return "public"
    return "private"


SCOPE_RANK = {"all": 0, "public": 1, "private": 2, "unknown": 3, "loopback": 4}


def _proc_info(pid: int) -> dict:
    info = {"pid": pid, "process": None, "owner": {"kind": "unknown", "id": None}}
    try:
        p = psutil.Process(pid)
        info["process"] = p.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return info
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            info["owner"] = owner_from_cgroup(fh.read())
    except OSError:
        pass
    return info


def group_listeners(conns, proc_lookup=_proc_info) -> list[dict]:
    """Collapse sockets into one row per (protocol, port, pid)."""
    rows: dict[tuple, dict] = {}
    cache: dict[int, dict] = {}
    for c in conns:
        if c.type == socket.SOCK_STREAM and c.status != psutil.CONN_LISTEN:
            continue
        if c.type == socket.SOCK_DGRAM and c.raddr:
            continue
        if c.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM) or not c.laddr:
            continue
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        key = (proto, c.laddr.port, c.pid)
        row = rows.get(key)
        if row is None:
            info = cache.setdefault(c.pid, proc_lookup(c.pid)) if c.pid else {
                "pid": None, "process": None, "owner": {"kind": "unknown", "id": None}}
            row = rows[key] = {"proto": proto, "port": c.laddr.port, "addresses": [], **info}
        if c.laddr.ip not in row["addresses"]:
            row["addresses"].append(c.laddr.ip)
    for row in rows.values():
        row["addresses"].sort()
        row["scope"] = min((classify(a) for a in row["addresses"]), key=lambda s: SCOPE_RANK[s])
    return sorted(rows.values(), key=lambda r: (SCOPE_RANK[r["scope"]], r["port"], r["proto"]))


class PortsSource(Source):
    name = "ports"

    def __init__(self, interval: int = 60):
        self.interval = interval

    async def collect(self) -> dict:
        listeners = group_listeners(psutil.net_connections("inet"))
        # Without root only our own sockets have PIDs (see module docstring).
        return {"listeners": listeners, "owners_known": os.geteuid() == 0}
