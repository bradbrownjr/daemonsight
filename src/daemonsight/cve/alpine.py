"""Match Alpine container images against Alpine's security database (secdb).

https://secdb.alpinelinux.org/ has a directory per release (`v3.23/`, and `edge/`), each with `main.json` and
`community.json` (and the same as YAML). What was read, on 2026-11-24, from the files themselves:

    {"apkurl": "...", "archs": [...], "reponame": "main", "urlprefix": "https://dl-cdn.alpinelinux.org/alpine",
     "distroversion": "v3.23",
     "packages": [{"pkg": {"name": "openssl", "secfixes": {
         "0": ["CVE-2022-1292", ...],
         "3.5.4-r0": ["CVE-2025-9230", ...]}}}, ...]}

* `name` is the origin (source) package: `openssl`, never `libcrypto3` or `libssl3` (checked: neither is a name in
  v3.23's main.json, and `openssl` is). The installed database's `o:` line gives each installed package's origin
  (docker_packages.parse_apk_installed), so a package is looked up by its origin.
* `secfixes` maps a version to the CVEs that version fixed, so a CVE is open for an installed version lower than the one
  that fixed it.
* The key `"0"` is not a version. Alpine's maintainers write the CVEs that never affected Alpine's package under it. This
  convention is informal: the Alpine apk-tools list says "it has become somewhat a norm to mark them as 0"
  (https://lists.alpinelinux.org/~alpine/apk-tools/%3C20241116073528.75a751c2%40gmacedo.com%3E, 2024-11-16), and the
  APKBUILD manual does not mention it. Those entries are ignored, never matched.
* An entry is a string that can carry text after the CVE id: `"CVE-2021-27219 GHSL-2021-045"`, `"CVE-2020-11501
  GNUTLS-SA-2020-03-31"`. The first word is the id. Entries whose first word is not a CVE id (`ALPINE-13661`,
  `ZDI-CAN-22300`, `GHSA-...`, `RUSTSEC-...`) cannot be ranked by KEV or EPSS and are dropped.
* The same CVE can be listed under more than one version of one package (intel-ucode, cacti): a partial fix, then the
  rest. The highest version is the one that finishes the fix, so that is the one an installed version is compared with.
* There is no list of CVEs without a fix. secdb only records fixes, so an Alpine image has fixable CVEs and no "no fix
  yet" count.

Versions are compared with apkver.py. Everything here is data from a download, so it is checked before it is kept: a
name, a CVE id or a version that does not match its pattern is skipped.
"""

from __future__ import annotations

import re
import time

from . import apkver

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$")
RELEASE_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})(?:\.\d{1,4})*$")
MAX_ROWS = 400_000


class SecdbError(ValueError):
    pass


def release_of(version_id: str | None) -> str | None:
    """"v3.23" for an os-release VERSION_ID of 3.23.2 (or 3.23), the directory name in secdb. None for anything that is
    not a plain release number: an `edge` image has 3.24.0_alpha20260101 and is not mapped (secdb has an `edge`
    directory; matching it is left out because how an edge image names its snapshot was not checked)."""
    m = RELEASE_RE.match((version_id or "").strip())
    return f"v{m.group(1)}.{m.group(2)}" if m else None


def display(release: str | None) -> str:
    """"Alpine 3.23" for "v3.23"."""
    return f"Alpine {release[1:]}" if release else "Alpine"


def parse_secdb(doc) -> list[tuple[str, str, str]]:
    """(origin, cve, fixed version) for every fixed CVE in one secdb file's JSON document. Raises SecdbError for a document
    that is not secdb's shape. Skips what does not look right, and the `"0"` key."""
    pkgs = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(pkgs, list):
        raise SecdbError("no packages list in the secdb file")
    out: dict[tuple[str, str, str], None] = {}
    for item in pkgs:
        pkg = item.get("pkg") if isinstance(item, dict) else None
        if not isinstance(pkg, dict):
            continue
        name, fixes = pkg.get("name"), pkg.get("secfixes")
        if not isinstance(name, str) or not NAME_RE.match(name) or not isinstance(fixes, dict):
            continue
        for version, cves in fixes.items():
            if version == "0" or not isinstance(version, str) or not isinstance(cves, list) or not apkver.valid(version):
                continue
            for entry in cves:
                words = entry.split() if isinstance(entry, str) else []
                if words and CVE_RE.match(words[0]):
                    out[(name, words[0], version)] = None
                    if len(out) > MAX_ROWS:
                        raise SecdbError("the secdb file has more entries than expected")
    return list(out)


def newest_fix(fixed: list[str]) -> str:
    """The highest of several fixed versions of one CVE."""
    best = fixed[0]
    for v in fixed[1:]:
        if apkver.compare(v, best) > 0:
            best = v
    return best


def is_fixable(installed: str, fixed: list[str]) -> str | None:
    """The version that fixes a CVE for this installed one: the highest fixed version when the installed one is below it,
    else None (already fixed, or a version apk does not parse)."""
    if not fixed or not apkver.valid(installed):
        return None
    top = newest_fix(fixed)
    return top if apkver.compare(installed, top) < 0 else None


def match_host(conn, host: str, inv: dict, gen: str) -> dict:
    """Replace the image's rows in `match` (cve/match.py's table; `source` is the origin package, `state` is `fix`).
    `inv` is the pseudo inventory of remote/docker_images.py: {"release", "sources": [[origin, version, [binaries]]]}.
    Returns {"packages", "cves", "note"}."""
    release = inv.get("release")
    rows: list[tuple] = []
    for origin, version, _bins in inv.get("sources", []):
        by_cve: dict[str, list[str]] = {}
        for r in conn.execute("SELECT cve, fixed FROM apk WHERE release = ? AND origin = ?", (release, origin)):
            by_cve.setdefault(r["cve"], []).append(r["fixed"])
        for cve, fixed in by_cve.items():
            top = is_fixable(version, fixed)
            if top:
                rows.append((host, origin, cve, "fix", version, top, None))
    note = inv.get("note") or ""
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM match WHERE host = ?", (host,))
        conn.executemany("INSERT OR REPLACE INTO match VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("INSERT OR REPLACE INTO matched VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (host, inv.get("hash"), inv.get("taken_at"), gen, time.time(), len(inv.get("sources", [])), note))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return {"packages": len(inv.get("sources", [])), "cves": len(rows), "note": note}
