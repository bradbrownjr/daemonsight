"""Pending package updates, reboots and services on old libraries. Two
backends, picked by what is on PATH: apt and dpkg (Debian, Ubuntu), or dnf5
and rpm (Fedora). Both produce the same data shape; `backend` says which.

Automatic updates are read with `apt-config shell L APT::Periodic::Update-Package-Lists
U APT::Periodic::Unattended-Upgrade` (apt.conf(5)), `systemctl is-enabled
apt-daily-upgrade.timer`, and a check for /usr/bin/unattended-upgrade; on dnf
with `rpm -q dnf5-plugin-automatic`, `systemctl is-enabled dnf5-automatic.timer` and
the `[commands]` section of dnf5-automatic's config files
(https://dnf5.readthedocs.io/en/latest/dnf5_plugins/automatic.8.html).

The dnf backend is further down (collect_dnf). Everything in both only reads.

apt:

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

dnf (dnf5, https://dnf5.readthedocs.io/): see the comment above collect_dnf.

Each part fails on its own: the reason goes in `errors[part]`.
"""

from __future__ import annotations

import asyncio
import glob
import json
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
UU_BINARY = "/usr/bin/unattended-upgrade"
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


def parse_apt_config_shell(text: str) -> dict[str, str]:
    """`apt-config shell L APT::X U APT::Y` prints shell assignments, `L='1'`
    (apt-config(8)); an unset option prints nothing."""
    return {m.group(1): m.group(2) for m in re.finditer(r"^([A-Za-z_]\w*)='?([^'\n]*)'?$", text, re.M)}


def apt_auto_on(auto: dict) -> bool:
    """Whether this host installs updates on its own: unattended-upgrades is
    installed, APT::Periodic::Unattended-Upgrade is set to something other than
    0, and apt-daily-upgrade.timer (which runs it) isn't off. The timer is
    unknown on a host without systemd; that doesn't count against it."""
    return (bool(auto.get("installed")) and (auto.get("unattended") or "") not in ("", "0")
            and auto.get("timer") not in ("disabled", "masked", "masked-runtime", "static-masked"))


def collect_apt() -> dict:
    data: dict = {"available": True, "backend": "apt", "updates": [], "security_count": 0, "kept_back": [], "removals": 0,
                  "held": [], "lists_age": None, "daily_timer": None,
                  "reboot": {"required": False, "pkgs": []}, "kernel": {"managed": False},
                  "needrestart": {"installed": False},
                  "unattended_upgrades": os.path.exists(UU_BINARY), "errors": {}}
    data["auto_updates"] = {"tool": "unattended-upgrades", "installed": data["unattended_upgrades"],
                            "lists": None, "unattended": None, "timer": None, "on": False,
                            "known": False}
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

    def timer_state(unit: str) -> str | None:
        if not shutil.which("systemctl"):
            return None
        try:
            _, out = run(["systemctl", "is-enabled", unit])
        except (OSError, subprocess.SubprocessError):
            return None  # optional detail
        return out.strip() or None

    def lists():
        data["lists_age"] = newest_lists_mtime()
        auto = data["auto_updates"]
        # apt-daily.timer only refreshes the lists when Update-Package-Lists is
        # set (normally by the unattended-upgrades package); with it unset the
        # timer does nothing. apt-daily-upgrade.timer runs unattended-upgrades
        # when Unattended-Upgrade is set. Both come from apt-config(8).
        try:
            _, out = run(["apt-config", "shell", "L", "APT::Periodic::Update-Package-Lists",
                          "U", "APT::Periodic::Unattended-Upgrade"])
            values = parse_apt_config_shell(out)
            data["periodic_update"] = values.get("L", "") not in ("", "0")
            auto["lists"], auto["unattended"] = values.get("L", ""), values.get("U", "")
            auto["known"] = True
        except (OSError, subprocess.SubprocessError):
            pass  # optional detail; auto["known"] stays False
        data["daily_timer"] = timer_state("apt-daily.timer")
        auto["timer"] = timer_state("apt-daily-upgrade.timer")
        auto["on"] = apt_auto_on(auto)

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


# ---- dnf (Fedora) -------------------------------------------------------------
#
# Commands, all read-only and cache-only (-C, --cacheonly: "Use only cached data
# for working with packages and repository metadata", dnf5(8)); the collector
# never touches the network. Metadata comes from the host's own makecache timer
# (dnf5-makecache.timer) or its last dnf run. dnf5 docs: https://dnf5.readthedocs.io/
#
# * `dnf --version`: first line "dnf5 version 5.x". dnf4 is not supported.
# * `dnf check-upgrade -C --json` (commands/check-upgrade.8): exit 100 when
#   updates are available, 0 when none. With no cached metadata it exits 1 and
#   prints `Cache-only enabled but no cache for repository "fedora"`.
#   JSON: {"upgrades": [{"name", "arch", "evr", "repository"}]}.
# * `dnf check-upgrade -C --security --json`: the same, limited to packages
#   covered by a security advisory. Those are the "security" updates.
# * `rpm -q --qf '%{NAME}\t%{ARCH}\t%{EVR}\n' <names>`: installed versions.
# * `dnf versionlock list` (commands/versionlock.8, in dnf5-plugins): "Package
#   name: <name>" lines, read from /etc/dnf/versionlock.toml.
# * `dnf needs-restarting -C --json` (dnf5_plugins/needs_restarting.8): exit 1
#   means a reboot is recommended. JSON: [{"type": "reboot", "reboot_required":
#   true, "packages": [...]}]. Needs filelists metadata; a cache without it
#   gives the "Cache-only enabled" message, and then only /run/reboot-required
#   (which dnf5 writes when it last ran as root) is used.
# * `dnf needs-restarting -C -s`: systemd services started before a library
#   they use was updated. Output format not captured (no D-Bus in the test
#   container): lines naming *.service are taken as services.
# * `rpm -q kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n'`: installed
#   kernels, in the same form as `uname -r` on Fedora.
# * Metadata age: newest mtime of /var/cache/libdnf5/*/repodata/repomd.xml.
# * Automatic updates: package dnf5-plugin-automatic (`rpm -q`), its
#   `dnf5-automatic.timer` (`systemctl is-enabled`), and the settings in its
#   config files. dnf5-automatic(8) lists them in this order, later files
#   overriding earlier ones: /usr/share/dnf5/dnf5-plugins/automatic.conf, its
#   automatic.conf.d/*.conf, /etc/dnf/dnf5-plugins/automatic.conf (deprecated),
#   /etc/dnf/automatic.conf, /etc/dnf/automatic.conf.d/*.conf. In [commands],
#   `apply_updates` (default no: updates are only downloaded) and
#   `upgrade_type` (default, security or distro-sync). Updates are installed
#   on their own only when the timer is enabled and apply_updates is on.
#   https://dnf5.readthedocs.io/en/latest/dnf5_plugins/automatic.8.html

DNF_CACHE_GLOB = "/var/cache/libdnf5/*/repodata/repomd.xml"
DNF_REBOOT_FILE = "/run/reboot-required"
DNF_TIMER = "dnf5-makecache.timer"
DNF_AUTO_PACKAGE = "dnf5-plugin-automatic"
DNF_AUTO_TIMER = "dnf5-automatic.timer"
DNF_AUTO_CONF = ["/usr/share/dnf5/dnf5-plugins/automatic.conf",
                 "/usr/share/dnf5/dnf5-plugins/automatic.conf.d/*.conf",
                 "/etc/dnf/dnf5-plugins/automatic.conf",
                 "/etc/dnf/automatic.conf",
                 "/etc/dnf/automatic.conf.d/*.conf"]
NO_CACHE = "Cache-only enabled"


def _rpm_segments(v: str):
    return re.findall(r"~|\^|[0-9]+|[A-Za-z]+", v)


def rpmvercmp(a: str, b: str) -> int:
    """rpm's version comparison (rpmvercmp): numbers beat letters, `~` sorts
    before everything, `^` just after the end."""
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    for x, y in zip(sa, sb):
        if x == y:
            continue
        if x == "~" or y == "~":
            return -1 if x == "~" else 1
        if x == "^" or y == "^":
            return -1 if x == "^" else 1
        xn, yn = x.isdigit(), y.isdigit()
        if xn != yn:
            return 1 if xn else -1
        if xn:
            return 1 if int(x) > int(y) else -1
        return 1 if x > y else -1
    if len(sa) == len(sb):
        return 0
    rest, sign = (sa[len(sb):], 1) if len(sa) > len(sb) else (sb[len(sa):], -1)
    return -sign if rest[0] == "~" else sign


def rpm_evr_gt(a: str, b: str) -> bool:
    """a > b for epoch:version-release strings (no epoch means 0)."""
    def split(v):
        epoch, sep, rest = v.partition(":")
        return (epoch, rest) if sep and epoch.isdigit() else ("0", v)
    ea, ra = split(a)
    eb, rb = split(b)
    if ea != eb:
        return int(ea) > int(eb)
    return rpmvercmp(ra, rb) > 0


def parse_auto_conf(texts: list[str]) -> dict:
    """[commands] apply_updates and upgrade_type from dnf5-automatic's config
    files, given in the order they are read (later ones win). Booleans are
    written yes/no in the shipped file; libdnf5 also takes true/false, 1/0."""
    import configparser
    values: dict[str, str] = {}
    for text in texts:
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            cp.read_string(text)
        except configparser.Error:
            continue
        for key in ("apply_updates", "upgrade_type"):
            if cp.has_option("commands", key):
                values[key] = cp.get("commands", key).strip().strip("\"'").lower()
    return {"apply": values.get("apply_updates", "no") in ("yes", "true", "1", "on", "enabled"),
            "upgrade_type": values.get("upgrade_type", "default")}


def dnf_auto_state(installed: bool, timer: str | None, conf: dict) -> dict:
    """Whether this host installs updates on its own."""
    return {"tool": "dnf5-automatic", "installed": installed, "timer": timer, "apply": conf["apply"],
            "upgrade_type": conf["upgrade_type"], "known": True,
            "on": installed and timer == "enabled" and conf["apply"]}


def is_dnf5(version_output: str) -> bool:
    return version_output.lstrip().startswith("dnf5 version")


def parse_upgrades(text: str) -> list[dict]:
    """The "upgrades" of `check-upgrade --json`. No output means none."""
    if not text.strip():
        return []
    obj = json.loads(text)
    items = obj.get("upgrades", []) if isinstance(obj, dict) else obj
    return [u for u in items if isinstance(u, dict) and u.get("name")]


def parse_rpm_evr(text: str) -> dict[tuple[str, str], list[str]]:
    """(name, arch) -> installed versions, from the rpm -q --qf lines. rpm's
    "package x is not installed" lines have no tabs and are skipped."""
    out: dict[tuple[str, str], list[str]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and all(parts):
            out.setdefault((parts[0], parts[1]), []).append(parts[2])
    return out


def newest_evr(versions: list[str]) -> str | None:
    best = None
    for v in versions:
        if best is None or rpm_evr_gt(v, best):
            best = v
    return best


def build_dnf_updates(upgrades: list[dict], security: list[dict], installed: dict) -> list[dict]:
    sec = {(u["name"], u.get("arch")) for u in security}
    out = []
    for u in upgrades:
        key = (u["name"], u.get("arch"))
        out.append({"name": u["name"], "current": newest_evr(installed.get(key, [])),
                    "candidate": u.get("evr"), "origin": u.get("repository"), "arch": u.get("arch"),
                    "security": key in sec})
    return out[:MAX_ITEMS]


def parse_versionlock(text: str) -> list[str]:
    return sorted({l.split(":", 1)[1].strip() for l in text.splitlines()
                   if l.startswith("Package name:") and l.split(":", 1)[1].strip()})[:MAX_ITEMS]


def parse_rpm_kernels(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and " " not in l.strip()]


def kernel_state_rpm(running: str, releases: list[str]) -> dict:
    """Like kernel_state, for `VERSION-RELEASE.ARCH` strings from rpm."""
    if running not in releases:
        return {"managed": False, "running": running}
    newest = releases[0]
    for r in releases[1:]:
        if rpm_evr_gt(r, newest):
            newest = r
    return {"managed": True, "running": running, "newer_installed": newest if newest != running else None}


def parse_needs_restarting_json(text: str) -> dict | None:
    """{"required": bool, "pkgs": [...]}, or None when the text is not the JSON."""
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    for item in obj if isinstance(obj, list) else []:
        if isinstance(item, dict) and item.get("type") == "reboot":
            return {"required": bool(item.get("reboot_required")),
                    "pkgs": sorted({str(p) for p in item.get("packages") or []})[:MAX_ITEMS]}
    return {"required": False, "pkgs": []}


def parse_needs_restarting_services(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*(?:[*-]\s+)?(\S+\.service)\s*$", line)
        if m and len(out) < MAX_ITEMS:
            out.append(m.group(1))
    return sorted(set(out))


def newest_cache_mtime() -> float | None:
    times = []
    for f in glob.glob(DNF_CACHE_GLOB):
        try:
            times.append(os.stat(f).st_mtime)
        except OSError:
            pass
    return max(times) if times else None


def collect_dnf() -> dict:
    code, out = run(["dnf", "--version"])
    if code != 0 or not is_dnf5(out):
        raise SourceUnavailable("This host's dnf is not dnf5 (Fedora 41 and newer)")
    data: dict = {"available": True, "backend": "dnf", "updates": [], "security_count": 0, "kept_back": [],
                  "removals": 0, "held": [], "lists_age": None, "daily_timer": None,
                  "reboot": {"required": False, "pkgs": []}, "kernel": {"managed": False},
                  "needrestart": {"installed": False}, "unattended_upgrades": False,
                  "auto_updates": {"tool": "dnf5-automatic", "installed": False, "timer": None, "apply": False,
                                   "upgrade_type": "default", "on": False, "known": False}, "errors": {}}
    errors = data["errors"]

    def part(name, fn):
        try:
            fn()
        except Exception as exc:  # each part fails on its own
            errors[name] = f"{type(exc).__name__}: {exc}"

    def auto():
        code, _ = run(["rpm", "-q", DNF_AUTO_PACKAGE])
        timer = None
        if shutil.which("systemctl"):
            _, out = run(["systemctl", "is-enabled", DNF_AUTO_TIMER])
            timer = out.strip() or None
        texts = []
        for pattern in DNF_AUTO_CONF:
            for path in sorted(glob.glob(pattern)):
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        texts.append(fh.read(200_000))
                except OSError:
                    pass
        data["auto_updates"] = dnf_auto_state(code == 0, timer, parse_auto_conf(texts))

    def check(extra: list[str]) -> list[dict]:
        code, out = run(["dnf", "check-upgrade", "-C", "--json", *extra])
        if code == 1 and NO_CACHE in out:
            raise RuntimeError("no dnf metadata cache yet; run: sudo dnf makecache")
        if code not in (0, 100):
            raise RuntimeError(f"dnf exited {code}")
        return parse_upgrades(out)

    def updates():
        ups = check([])
        sec = check(["--security"]) if ups else []
        installed: dict = {}
        names = sorted({u["name"] for u in ups})
        if names:
            _, out = run(["rpm", "-q", "--qf", "%{NAME}\t%{ARCH}\t%{EVR}\n", *names])  # exit 1 if any missing
            installed = parse_rpm_evr(out)
        data["updates"] = build_dnf_updates(ups, sec, installed)
        data["security_count"] = sum(1 for u in data["updates"] if u["security"])

    def held():
        code, out = run(["dnf", "versionlock", "list"])
        data["held"] = parse_versionlock(out) if code == 0 else []  # no plugin: nothing is locked

    def lists():
        data["lists_age"] = newest_cache_mtime()
        if shutil.which("systemctl"):
            try:
                _, out = run(["systemctl", "is-enabled", DNF_TIMER])
                data["daily_timer"] = out.strip() or None
            except (OSError, subprocess.SubprocessError):
                pass  # optional detail

    def reboot():
        code, out = run(["dnf", "needs-restarting", "-C", "--json"])
        parsed = parse_needs_restarting_json(out)
        if parsed is None:
            # No filelists in the cache (or no plugin): fall back to the flag dnf5 leaves.
            parsed = {"required": os.path.exists(DNF_REBOOT_FILE), "pkgs": [], "checked": False}
        data["reboot"] = parsed

    def kernel():
        _, out = run(["rpm", "-q", "kernel-core", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}\n"])
        data["kernel"] = kernel_state_rpm(platform.release(), parse_rpm_kernels(out))

    def needrestart():
        code, out = run(["dnf", "needs-restarting", "-C", "-s"])
        if NO_CACHE in out or code not in (0, 1):
            data["needrestart"] = {"installed": False, "tool": "dnf"}
            return
        data["needrestart"] = {"installed": True, "tool": "dnf", "services": parse_needs_restarting_services(out)}

    for name, fn in (("updates", updates), ("held", held), ("lists", lists), ("reboot", reboot),
                     ("kernel", kernel), ("needrestart", needrestart), ("auto", auto)):
        part(name, fn)
    return data


def collect_sync() -> dict:
    if shutil.which("dpkg") and shutil.which("apt-get"):
        return collect_apt()
    if shutil.which("dnf") and shutil.which("rpm"):
        return collect_dnf()
    raise SourceUnavailable("This host uses neither apt and dpkg nor dnf and rpm")


class PackagesSource(Source):
    name = "packages"

    def __init__(self, interval: int = 3600):
        self.interval = interval

    async def collect(self) -> dict:
        return await asyncio.to_thread(collect_sync)

    def metrics(self, data: dict) -> dict[str, float]:
        return {"pkg.updates": float(len(data.get("updates", []))),
                "pkg.security": float(data.get("security_count", 0))}
