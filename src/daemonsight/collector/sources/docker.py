"""Docker containers through the Engine API on the local Unix socket.

Reference: Docker Engine API v1.47 OpenAPI spec
https://docs.docker.com/reference/api/engine/version/v1.47.yaml

- GET /containers/json?all=1, GET /containers/{id}/json, GET /containers/{id}/logs,
  GET /containers/{id}/stats?stream=false, GET /version.
- Health.Status is one of none, starting, healthy, unhealthy.
- Logs from a container without a TTY are multiplexed: each frame starts with
  an 8-byte header [STREAM_TYPE, 0, 0, 0, SIZE1..SIZE4] with a big-endian
  uint32 size (1 = stdout, 2 = stderr).
- CPU % = (cpu_delta / system_cpu_delta) * number_cpus * 100, which needs the
  two-sample read, so stats are fetched with stream=false and without one-shot.

Only GET requests are ever sent.
"""

from __future__ import annotations

import asyncio
import os
import re
import struct

import httpx

from . import Source, SourceUnavailable

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)(\S+)"),
    re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)"),
]


def mask_secrets(line: str) -> str:
    line = SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}***", line)
    line = SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}***", line)
    line = SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}***{m.group(3)}", line)
    return line


def demux(raw: bytes) -> list[str]:
    """Split a multiplexed log stream into text lines."""
    out = bytearray()
    i = 0
    while i + 8 <= len(raw):
        stream_type = raw[i]
        if stream_type not in (0, 1, 2) or raw[i + 1:i + 4] != b"\x00\x00\x00":
            # Not a multiplexed stream after all; treat the rest as raw text.
            out += raw[i:]
            break
        (size,) = struct.unpack(">I", raw[i + 4:i + 8])
        out += raw[i + 8:i + 8 + size]
        i += 8 + size
    else:
        out += raw[i:]
    return out.decode("utf-8", "replace").splitlines()


def cpu_percent(stats: dict) -> float | None:
    try:
        cpu, pre = stats["cpu_stats"], stats["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu["system_cpu_usage"] - pre["system_cpu_usage"]
        ncpu = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or []) or 1
    except (KeyError, TypeError):
        return None
    if sys_delta <= 0 or cpu_delta < 0:
        return None
    return round(cpu_delta / sys_delta * ncpu * 100.0, 2)


def memory_used(stats: dict) -> int | None:
    mem = stats.get("memory_stats") or {}
    usage = mem.get("usage")
    if usage is None:
        return None
    detail = mem.get("stats") or {}
    if "inactive_file" in detail:  # cgroup v2
        return usage - detail["inactive_file"]
    if "cache" in detail:  # cgroup v1
        return usage - detail["cache"]
    return usage


def published_ports(inspect: dict) -> list[dict]:
    """Host bindings from NetworkSettings.Ports: {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}."""
    out = []
    for key, bindings in ((inspect.get("NetworkSettings") or {}).get("Ports") or {}).items():
        if not bindings:
            continue
        port, _, proto = key.partition("/")
        for b in bindings:
            out.append({"host_ip": b.get("HostIp") or "0.0.0.0", "host_port": int(b.get("HostPort") or 0),
                        "container_port": int(port), "proto": proto or "tcp"})
    seen, unique = set(), []
    for p in out:
        k = (p["host_ip"], p["host_port"], p["proto"])
        if k not in seen:
            seen.add(k)
            unique.append(p)
    return unique


def summarize(inspect: dict, stats: dict | None, logs: list[str]) -> dict:
    state = inspect.get("State") or {}
    health = (state.get("Health") or {}).get("Status") or "none"
    config = inspect.get("Config") or {}
    labels = config.get("Labels") or {}
    return {
        "id": inspect["Id"],
        "name": inspect.get("Name", "").lstrip("/"),
        "image": config.get("Image"),
        "project": labels.get("com.docker.compose.project"),
        "status": state.get("Status"),
        "exit_code": state.get("ExitCode"),
        "oom_killed": bool(state.get("OOMKilled")),
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "health": health,
        "restart_count": inspect.get("RestartCount", 0),
        "restart_policy": ((inspect.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name") or "no",
        "ports": published_ports(inspect),
        "cpu_percent": cpu_percent(stats) if stats else None,
        "memory": memory_used(stats) if stats else None,
        "logs": [mask_secrets(line) for line in logs],
    }


class DockerSource(Source):
    name = "docker"

    def __init__(self, interval: int = 30, socket_path: str = "/var/run/docker.sock", tail: int = 100):
        self.interval = interval
        self.socket_path = socket_path
        self.tail = tail
        self._client: httpx.AsyncClient | None = None
        self._prefix = ""

    async def _get(self, path: str, **params):
        resp = await self._client.get(self._prefix + path, params=params)
        resp.raise_for_status()
        return resp

    async def collect(self) -> dict:
        if not os.path.exists(self.socket_path):
            raise SourceUnavailable(f"no Docker socket at {self.socket_path}")
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(uds=self.socket_path),
                base_url="http://docker", timeout=10.0,
            )
            version = (await self._get("/version")).json()
            self._prefix = f"/v{version['ApiVersion']}"
            self._version = {"engine": version.get("Version"), "api": version.get("ApiVersion")}

        listing = (await self._get("/containers/json", all="1")).json()

        async def one(c: dict) -> dict:
            cid = c["Id"]
            inspect = (await self._get(f"/containers/{cid}/json")).json()
            stats = None
            if (inspect.get("State") or {}).get("Running"):
                try:
                    stats = (await self._get(f"/containers/{cid}/stats", stream="false")).json()
                except httpx.HTTPError:
                    stats = None
            try:
                raw = (await self._get(f"/containers/{cid}/logs", stdout="1", stderr="1",
                                       timestamps="1", tail=str(self.tail))).content
                tty = bool((inspect.get("Config") or {}).get("Tty"))
                logs = raw.decode("utf-8", "replace").splitlines() if tty else demux(raw)
            except httpx.HTTPError:
                logs = []
            return summarize(inspect, stats, logs)

        containers = await asyncio.gather(*(one(c) for c in listing))
        containers.sort(key=lambda c: (c["status"] == "running", c["name"]))
        return {"version": self._version, "containers": containers}

    def metrics(self, data: dict) -> dict[str, float]:
        out = {}
        for c in data.get("containers", []):
            if c["cpu_percent"] is not None:
                out[f"ctr.{c['name']}.cpu"] = c["cpu_percent"]
            if c["memory"] is not None:
                out[f"ctr.{c['name']}.mem"] = c["memory"]
        return out

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
