"""Installed packages, for the hub's CVE matching. The collector only lists
what is installed; it downloads no vulnerability data and runs no scanner.
The hub does the matching (see cve/ and docs/DESIGN.md "CVE matching").

apt hosts: `dpkg-query -W -f '${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\t${Package}\\t${Version}\\n'`.
dpkg-query(1) documents all four fields: `source:Package` and `source:Version`
"since dpkg 1.16.2", `db:Status-Abbrev` is the three-letter state such as
"ii " (https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html). The
Debian security tracker is keyed by source package, and a binNMU rebuild
changes `Version` ("2.3.2-2+b1") but not `source:Version` ("2.3.2-2"), so the
source name and version are what gets matched.

dnf hosts (Fedora): the pending security advisories, from
`dnf advisory list --updates --security --json -C` (one row per installed
package an advisory updates: `name`, `nevra`, `severity`) and
`dnf advisory info --updates --security --json -C` (`Name`, `Description`,
`references`). `-C` reads only the cache. Fedora's references are of type
`bugzilla`, and `--with-cve` and `--cves=` matched nothing on fedora:44, so the
CVE ids are found in the description and the reference titles. See
https://dnf5.readthedocs.io/en/latest/commands/advisory.8.html. Unlike apt, a
host sends no package list, only what is pending; Fedora's unfixed CVEs are
not available this way.

The inventory goes to the hub in its own top-level `inventory` field, not
as a snapshot: an older hub ignores unknown top-level fields, while it
refuses a snapshot from a source it doesn't know (the whole upload gets a
422). See collector/upload.py and hub.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import re
import shutil
import subprocess

from ... import distro
from . import Source, SourceUnavailable
from .packages import ENV, TIMEOUT
from .system import read_os_release

FORMAT = "${db:Status-Abbrev}\t${source:Package}\t${source:Version}\t${Package}\t${Version}\n"
MAX_BINARIES = 30
MAX_SOURCES = 20_000


def parse_dpkg_query(text: str, running_kernel: str | None = None) -> list[list]:
    """[source, source version, [binary packages]] for every installed package,
    one row per distinct source and version, sorted. A binary list that is
    only the source's own name is left empty to keep the upload small. Lines
    for packages that are removed but not purged ("rc") are skipped.

    Debian's kernel images come from linux-signed-<arch>, whose version
    ("6.1.164+1") isn't the kernel's, and the tracker lists kernel CVEs under
    `linux` only. The running kernel's image (linux-image-<uname -r>) carries
    the `linux` version as its own ("6.1.164-1"), so it is listed under
    `linux` with that version. Other installed kernels aren't running and are
    left out."""
    groups: dict[tuple[str, str], set[str]] = {}
    image = f"linux-image-{running_kernel}" if running_kernel else None
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or len(parts[0]) < 2 or parts[0][1] != "i":
            continue
        _, src, src_ver, binary, bin_ver = parts
        if not src or not src_ver or not binary:
            continue
        if src.startswith("linux-signed"):
            if binary != image or not bin_ver:
                continue
            src, src_ver = "linux", bin_ver
        groups.setdefault((src, src_ver), set()).add(binary)
    rows = []
    for (src, ver), bins in sorted(groups.items()):
        listed = sorted(bins - {src})[:MAX_BINARIES]
        rows.append([src, ver, listed])
    return rows[:MAX_SOURCES]


def fingerprint(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def inventory_apt(dpkg_text: str, osr: dict[str, str], running_kernel: str | None = None) -> dict:
    ident = distro.os_ident(osr)
    rows = parse_dpkg_query(dpkg_text, running_kernel)
    return {"available": True, "backend": "apt", "os_id": ident["os_id"], "version_id": ident["version_id"],
            "codename": ident["version_codename"], "sources": rows, "count": len(rows),
            "hash": fingerprint(ident, rows)}


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DNF_ADVISORY = ["dnf", "advisory", "{sub}", "--updates", "--security", "--json", "-C"]
MAX_ADVISORIES = 2_000


def rpm_name(nevra: str) -> str:
    """Name from a NEVRA such as "pcre2-syntax-10.49-1.fc44.noarch"."""
    stem = nevra.rsplit(".", 1)[0]
    parts = stem.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else stem


def parse_dnf_advisories(list_text: str, info_text: str) -> list[dict]:
    """[{id, severity, cves, packages}] for each pending security advisory that
    names at least one CVE. Packages come from the list (installed ones only;
    the info's package collection spans every architecture and subpackage)."""
    rows = json.loads(list_text) if list_text.strip() else []
    infos = json.loads(info_text) if info_text.strip() else []
    if not isinstance(rows, list) or not isinstance(infos, list):
        raise ValueError("dnf advisory output is not a list")
    packages: dict[str, set[str]] = {}
    for r in rows:
        if isinstance(r, dict) and r.get("name") and r.get("nevra"):
            packages.setdefault(str(r["name"]), set()).add(rpm_name(str(r["nevra"])))
    out = []
    for a in infos:
        if not isinstance(a, dict) or str(a.get("Name")) not in packages:
            continue
        text = [str(a.get("Description") or "")] + [str(x.get("Title") or "") for x in a.get("references") or []
                                                      if isinstance(x, dict)]
        cves = sorted(set(CVE_RE.findall("\n".join(text))))[:200]
        if cves:
            out.append({"id": str(a["Name"]), "severity": str(a.get("Severity") or "").lower()[:20],
                        "cves": cves, "packages": sorted(packages[str(a["Name"])])[:100]})
    return out[:MAX_ADVISORIES]


def inventory_dnf(list_text: str, info_text: str, osr: dict[str, str]) -> dict:
    ident = distro.os_ident(osr)
    adv = parse_dnf_advisories(list_text, info_text)
    return {"available": True, "backend": "dnf", "os_id": ident["os_id"], "version_id": ident["version_id"],
            "codename": ident["version_codename"], "advisories": adv, "count": len(adv),
            "hash": fingerprint(ident, adv)}


def collect_sync() -> dict:
    if shutil.which("dnf") and not shutil.which("dpkg-query"):
        outs = []
        for sub in ("list", "info"):
            proc = subprocess.run([a.format(sub=sub) for a in DNF_ADVISORY], capture_output=True, text=True,
                                  errors="replace", timeout=TIMEOUT, env=ENV, stdin=subprocess.DEVNULL)
            if proc.returncode != 0:
                raise RuntimeError(f"dnf advisory {sub} exited {proc.returncode}")
            outs.append(proc.stdout)
        return inventory_dnf(outs[0], outs[1], read_os_release())
    if shutil.which("dpkg-query"):
        proc = subprocess.run(["dpkg-query", "-W", "-f", FORMAT], capture_output=True, text=True,
                              errors="replace", timeout=TIMEOUT, env=ENV, stdin=subprocess.DEVNULL)
        if proc.returncode != 0:
            raise RuntimeError(f"dpkg-query exited {proc.returncode}")
        return inventory_apt(proc.stdout, read_os_release(), platform.release())
    raise SourceUnavailable("CVE matching needs apt and dpkg, or dnf5")


class InventorySource(Source):
    name = "inventory"

    def __init__(self, interval: int = 3600):
        self.interval = interval

    async def collect(self) -> dict:
        return await asyncio.to_thread(collect_sync)
