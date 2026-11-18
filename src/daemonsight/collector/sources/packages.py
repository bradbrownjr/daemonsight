"""Pending package updates, reboots and services on old libraries (Debian and
Ubuntu: dpkg and apt).

Everything here only reads:

* `apt-get -s -o Debug::NoLocking=1 dist-upgrade` simulates an upgrade. Lines
  look like `Inst libssl3t64 [3.5.1-1] (3.5.4-1~deb13u1 Debian-Security:13/stable-security [amd64])`;
  a package with no `[old]` part is new on the host. It needs no root and
  changes nothing. The collector never runs `apt update`; the host's own apt
  timers do, and the age of the package lists is reported instead.
* `apt-mark showhold`, `dpkg-query` and `dpkg --compare-versions`.
* `needrestart -b -r l`, if installed. `-b` is batch mode (nothing is
  restarted, output is machine-readable) and `-r l` is "list only"
  (needrestart(1) and README.batch.md in https://github.com/liske/needrestart).
  Batch output is NEEDRESTART-KCUR / KEXP / KSTA / SVC lines. It needs root,
  like the collector.

Each part fails on its own: the reason goes in `errors[part]`.
"""

from __future__ import annotations

import asyncio
import glob
import os
import platform
import re
import shutil
import subprocess

from . import Source, SourceUnavailable

TIMEOUT = 120
ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}
LISTS_GLOB = "/var/lib/apt/lists/*InRelease"
LISTS_GLOB_OLD = "/var/lib/apt/lists/*Release"
REBOOT_FILE = "/var/run/reboot-required"
MAX_ITEMS = 500

INST = re.compile(r"^Inst (\S+)(?: \[(\S+)\])? \((\S+) (.+?)(?: \[([^\]]+)\])?\)\s*$")


def run(argv: list[str]) -> tuple[int, str]:
    """(exit code, stdout). Raises on a missing program or a timeout."""
    proc = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=TIMEOUT,
                          env=ENV, stdin=subprocess.DEVNULL)
    return proc.returncode, proc.stdout


def is_security(origin: str | None) -> bool:
    """Debian: "Debian-Security:13/stable-security". Ubuntu:
    "Ubuntu:24.04/noble-security". With several origins any one counts."""
    return "-security" in (origin or "").lower()


def parse_dist_upgrade(text: str) -> dict:
    """Packages an upgrade would install, plus what it keeps back or removes."""
    updates, kept, removals = [], [], 0
    in_kept = False
    for line in text.splitlines():
        if line.startswith("Inst "):
            m = INST.match(line.strip())
            if m:
                name, current, candidate, origin, arch = m.groups()
                updates.append({"name": name, "current": current, "candidate": candidate,
                                "origin": origin, "arch": arch, "security": is_security(origin)})
            in_kept = False
        elif line.startswith("Remv "):
            removals += 1
            in_kept = False
        elif line.startswith("The following packages have been kept back"):
            in_kept = True
        elif in_kept and line.startswith(" "):
            kept += line.split()
        else:
            in_kept = False
    return {"updates": updates[:MAX_ITEMS], "kept_back": sorted(set(kept))[:MAX_ITEMS], "removals": removals}


def parse_kernel_packages(text: str) -> list[tuple[str, str]]:
    """(package, version) of installed linux-image packages, from
    dpkg-query -W -f='${Package}\\t${Version}\\t${db:Status-Abbrev}\\n'."""
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip().startswith("ii"):
            out.append((parts[0], parts[1]))
    return out


def kernel_release(package: str) -> str | None:
    """"6.12.48+deb13-amd64" for linux-image-6.12.48+deb13-amd64. Metapackages
    (linux-image-amd64) and variants without a release number give None."""
    m = re.match(r"^linux-image-(?:unsigned-)?(\d.*)$", package)
    return m.group(1) if m else None


def version_gt(a: str, b: str) -> bool:
    return subprocess.run(["dpkg", "--compare-versions", a, "gt", b], timeout=TIMEOUT,
                          env=ENV, stdin=subprocess.DEVNULL).returncode == 0


def kernel_state(running: str, packages: list[tuple[str, str]], gt=version_gt) -> dict:
    """Whether the running kernel is one this host's packages manage, and
    whether a newer one is installed. In a container, or with a custom
    kernel, no installed package matches the running release: not managed."""
    installed = [(kernel_release(p), v) for p, v in packages if kernel_release(p)]
    if not any(rel == running for rel, _ in installed):
        return {"managed": False, "running": running}
    newest_rel, newest_ver = installed[0]
    for rel, ver in installed[1:]:
        if gt(ver, newest_ver):
            newest_rel, newest_ver = rel, ver
    return {"managed": True, "running": running,
            "newer_installed": newest_rel if newest_rel != running else None}


def parse_needrestart(text: str) -> dict:
    """Batch output: NEEDRESTART-VER, -KCUR, -KEXP, -KSTA, -UCSTA, -SVC, -CONT, -SESS.
    KSTA: 0 unknown, 1 no pending upgrade, 2 ABI-compatible upgrade pending,
    3 version upgrade pending."""
    out = {"installed": True, "services": [], "ksta": None, "kcur": None, "kexp": None}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep or not key.startswith("NEEDRESTART-"):
            continue
        value = value.strip()
        key = key[len("NEEDRESTART-"):]
        if key == "SVC" and value and len(out["services"]) < MAX_ITEMS:
            out["services"].append(value)
        elif key == "KSTA" and value.isdigit():
            out["ksta"] = int(value)
        elif key == "KCUR":
            out["kcur"] = value
        elif key == "KEXP":
            out["kexp"] = value
    return out


def newest_lists_mtime() -> float | None:
    files = glob.glob(LISTS_GLOB) or glob.glob(LISTS_GLOB_OLD)
    times = []
    for f in files:
        try:
            times.append(os.stat(f).st_mtime)
        except OSError:
            pass
    return max(times) if times else None


def read_reboot() -> dict:
    pkgs: list[str] = []
    try:
        with open(REBOOT_FILE + ".pkgs") as fh:
            pkgs = [l.strip() for l in fh if l.strip()][:MAX_ITEMS]
    except OSError:
        pass
    return {"required": os.path.exists(REBOOT_FILE), "pkgs": sorted(set(pkgs))}


def collect_sync() -> dict:
    if not (shutil.which("dpkg") and shutil.which("apt-get")):
        raise SourceUnavailable("This host does not use apt and dpkg")
    data: dict = {"available": True, "updates": [], "security_count": 0, "kept_back": [], "removals": 0,
                  "held": [], "lists_age": None, "daily_timer": None,
                  "reboot": {"required": False, "pkgs": []}, "kernel": {"managed": False},
                  "needrestart": {"installed": False},
                  "unattended_upgrades": os.path.exists("/usr/bin/unattended-upgrade"), "errors": {}}
    errors = data["errors"]

    def part(name, fn):
        try:
            fn()
        except Exception as exc:  # each part fails on its own
            errors[name] = f"{type(exc).__name__}: {exc}"

    def updates():
        code, out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"])
        if code != 0:
            raise RuntimeError(f"apt-get exited {code}")
        data.update(parse_dist_upgrade(out))
        data["security_count"] = sum(1 for u in data["updates"] if u["security"])

    def held():
        code, out = run(["apt-mark", "showhold"])
        if code != 0:
            raise RuntimeError(f"apt-mark exited {code}")
        data["held"] = sorted(l.strip() for l in out.splitlines() if l.strip())[:MAX_ITEMS]

    def lists():
        data["lists_age"] = newest_lists_mtime()
        if shutil.which("systemctl"):
            try:
                _, out = run(["systemctl", "is-enabled", "apt-daily.timer"])
                data["daily_timer"] = out.strip() or None
            except (OSError, subprocess.SubprocessError):
                pass  # optional detail

    def reboot():
        data["reboot"] = read_reboot()

    def kernel():
        code, out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n", "linux-image-*"])
        if code != 0 and out.strip() == "":
            out = ""  # dpkg-query exits 1 when nothing matches
        elif code != 0:
            raise RuntimeError(f"dpkg-query exited {code}")
        data["kernel"] = kernel_state(platform.release(), parse_kernel_packages(out))

    def needrestart():
        path = shutil.which("needrestart")
        if not path:
            data["needrestart"] = {"installed": False}
            return
        code, out = run([path, "-b", "-r", "l"])
        if code != 0 and "NEEDRESTART-" not in out:
            raise RuntimeError(f"needrestart exited {code}")
        data["needrestart"] = parse_needrestart(out)

    for name, fn in (("updates", updates), ("held", held), ("lists", lists), ("reboot", reboot),
                     ("kernel", kernel), ("needrestart", needrestart)):
        part(name, fn)
    return data


class PackagesSource(Source):
    name = "packages"

    def __init__(self, interval: int = 3600):
        self.interval = interval

    async def collect(self) -> dict:
        return await asyncio.to_thread(collect_sync)

    def metrics(self, data: dict) -> dict[str, float]:
        return {"pkg.updates": float(len(data.get("updates", []))),
                "pkg.security": float(data.get("security_count", 0))}
