"""CPU, memory, disk and network from psutil (https://psutil.io/)."""

from __future__ import annotations

import asyncio
import os
import platform
import time

import psutil

from . import Source

# Filesystems that hold real data. Everything else (tmpfs, overlay, squashfs
# snaps, container layers) is skipped.
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "vfat", "exfat", "ntfs", "fuseblk"}
SKIP_NICS_PREFIX = ("lo", "veth", "docker", "br-", "virbr")


def os_name() -> str:
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


async def detect_virt() -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemd-detect-virt", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await proc.communicate()
    except FileNotFoundError:
        return None
    value = out.decode().strip()
    return None if value in ("", "none") else value


class SystemSource(Source):
    name = "system"

    def __init__(self, interval: int = 15):
        self.interval = interval
        self._virt: str | None | bool = False
        self._last_net: tuple[float, dict] | None = None
        psutil.cpu_percent(interval=None)  # first call primes the counter and returns 0.0

    async def collect(self) -> dict:
        if self._virt is False:
            self._virt = await detect_virt()
        now = time.time()
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        disks = []
        seen_devices = set()
        for part in psutil.disk_partitions(all=False):
            if part.fstype not in REAL_FS or part.device in seen_devices:
                continue
            seen_devices.add(part.device)
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            disks.append({
                "mount": part.mountpoint, "device": part.device, "fstype": part.fstype,
                "total": usage.total, "used": usage.used, "percent": usage.percent,
            })
        if not any(d["mount"] == "/" for d in disks):
            # Containers often mount / from an overlay or zfs dataset psutil filters out.
            try:
                usage = psutil.disk_usage("/")
                disks.insert(0, {"mount": "/", "device": None, "fstype": None,
                                 "total": usage.total, "used": usage.used, "percent": usage.percent})
            except OSError:
                pass

        counters = psutil.net_io_counters(pernic=True)
        nics = {}
        if self._last_net:
            last_ts, last = self._last_net
            span = max(now - last_ts, 0.001)
            for nic, c in counters.items():
                if nic.startswith(SKIP_NICS_PREFIX) or nic not in last:
                    continue
                rx = max(c.bytes_recv - last[nic].bytes_recv, 0) * 8 / span
                tx = max(c.bytes_sent - last[nic].bytes_sent, 0) * 8 / span
                nics[nic] = {"rx_bps": rx, "tx_bps": tx}
        self._last_net = (now, counters)

        load = os.getloadavg()
        return {
            "os": os_name(),
            "kernel": platform.release(),
            "virt": self._virt,
            "boot_time": psutil.boot_time(),
            "cpu": {"percent": psutil.cpu_percent(interval=None), "count": psutil.cpu_count(), "load": load},
            "memory": {"total": vm.total, "available": vm.available, "percent": vm.percent,
                       "swap_total": swap.total, "swap_used": swap.used},
            "disks": disks,
            "net": nics,
        }

    def metrics(self, data: dict) -> dict[str, float]:
        out = {"cpu.percent": data["cpu"]["percent"], "mem.percent": data["memory"]["percent"]}
        for d in data["disks"]:
            out[f"disk.{d['mount']}.percent"] = d["percent"]
        for nic, rates in data["net"].items():
            out[f"net.{nic}.rx_bps"] = rates["rx_bps"]
            out[f"net.{nic}.tx_bps"] = rates["tx_bps"]
        return out
