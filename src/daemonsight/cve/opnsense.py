"""CVEs fixed by an OPNsense release, from the project's own changelog.

Source: https://github.com/opnsense/changelog (BSD 2-Clause), the repository the firewall's own System, Firmware, Changelog
tab is built from (docs.opnsense.org/releases/CE_<series>.html is the same text rendered; its CVE set for 26.1 equals the
repository's, checked 2026-11-24). What was read, on 2026-11-24, from the repository's README and 357 files under `community/`:

Layout
    community/<series>/<release>   one plain-text file per release, no extension. <series> is YY.1 or YY.7 (24 of them, 15.1
    to 26.7); <release> is `26.1` (the major release), `26.1.11`, a few four-part ones (`15.1.6.1`), and `26.1.r1`,
    `26.1.r2` or `25.1.b` for release candidates and betas, which are skipped. `business/<series>/` (YY.4, YY.10) is the
    Business Edition and is not read. There is no `_N` file: a hotfix such as `26.1.11_3` is a section inside its release's
    file (see below). The README says only "File name is the release name" and describes the markup.

File format (README, and every file read)
    `@ July 21, 2026` first, then prose, then `o ` bullet lines (a continuation line is indented), then `Stay safe,`, then a
    `--` line and numbered footnotes. A footnote is `[n] KIND:ID`, and the bullet refers to it as `[n]`. The kinds that name
    a security issue are `CVE:CVE-2026-57154`, `GHSA:GHSA-xxxx-xxxx-xxxx` (a GitHub advisory of OPNsense's own code, no CVE
    id) and `FREEBSD-SA:26:74.ktls` (a FreeBSD advisory, no CVE id in the file). The repository's `Links/` directory turns
    each into a URL; `Links/CVE` is https://www.cve.org/cverecord?id=%s. Old files (15.1 to 20.x) also have a CVE id typed in
    the bullet, or a cve.mitre.org URL as the footnote.
    Hotfix sections: a line `A hotfix release was issued as 26.1.11_3:` (126 files; also `Another hotfix release was issued
    as ...` and `Here are the hotfixes issued with ...`) starts a block of bullets for that hotfix version. A line such as
    `Out of band hotfix for PHP CVE-2026-109618 and CVE-2026-109619:` names the CVEs for the bullet that follows it.

What counts as a fix here (conservative; a miss is better than a false "fixed")
    * a bullet that has a CVE id in its own text, or one of its footnotes is a `CVE:` (or cve.mitre.org) reference;
    * the CVE ids in a lead line that ends in `:` apply to the bullets under it (the out-of-band PHP hotfix);
    * a bullet with a `GHSA:` or `FREEBSD-SA:` footnote and no CVE id is counted as an advisory without a CVE id: it is
      not matched against KEV or EPSS, only counted and listed.
    * CVE ids that appear only in the prose before the patch notes are NOT counted. Some say a CVE is not fixed ("resurfacing
    CVE-2024-6640" in 24.7.3, "does not affect" CVE-2020-15078 in 21.1.6, "We are aware of ... CVE-2023-5678" in 23.7.8);
    others list fixes (21.7.2's "Today the following CVEs are being addressed"). Telling them apart needs reading
    sentences; this does not try.
    Some security fixes are not in the file at all, or only as a FreeBSD advisory number. Treat the count as a floor.

What was not checked: that every release since 15.1 follows this layout (357 files were parsed without an error, and the
tests keep a sample), and that the changelog is complete for fixes that were not announced.

The matching: an update from version A to version B brings every changelog section whose version V has A < V <= B
(opnver.py gives the order). A section's version is its release, or its hotfix version when it sits under a hotfix line, so
an update from 26.1.11 to 26.1.11_10 brings the hotfix sections only. A CVE named in several sections of the range is
reported at the highest one (the same rule as Alpine's secdb: the last mention finishes the fix).

Everything here is data from a download, so it is checked before it is kept: a file name, a version, a CVE id or a
footnote that does not match its pattern is skipped, and sizes and counts are capped.
"""

from __future__ import annotations

import json
import re
import tarfile
import time
import zlib
from datetime import datetime

from . import opnver

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,10}")
FILE_RE = re.compile(r"^[^/]+/community/(\d{2}\.\d{1,2})/(\d{2}\.\d{1,2}(?:\.\d{1,5}){0,2})$")
DATE_RE = re.compile(r"^@\s+([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})\s*$")
BULLET_RE = re.compile(r"^o\s+(\S.*)$")
FOOT_RE = re.compile(r"^\[(\d{1,3})\]\s+(\S.*?)\s*$")
REF_RE = re.compile(r"\[(\d{1,3})\]")
HOTFIX_RE = re.compile(r"hotfix\w*\b.*\bissued (?:as|with) (\S+?):?\s*$", re.I)
CVE_FOOT = re.compile(r"^CVE:(CVE-\d{4}-\d{4,10})$")
GHSA_FOOT = re.compile(r"^(GHSA:GHSA(?:-[a-z0-9]{4}){3})$")
SA_FOOT = re.compile(r"^(FREEBSD-SA:\d{2}:\d{2}\.[A-Za-z0-9_-]{1,30})$")

MAX_FILE_BYTES = 256 << 10        # the largest real file is 17 KB
MAX_TOTAL_BYTES = 400 << 20       # everything the tar says it holds, read or skipped
MAX_MEMBERS = 20_000              # the real repository has about 1,000 entries
MAX_BULLETS = 2000
MAX_ROWS = 40_000
LINE_MAX = 220

SOURCE = "opnsense"               # `match.source` of a row, and the product
PSEUDO = "opnsense:"              # pseudo-host prefix: opnsense:<system id>
UNSEEN_PSEUDO = "opnsense-unseen:"  # the newest release the firewall has not seen: a separate match from the pending update
URL = "https://codeload.github.com/opnsense/changelog/tar.gz/refs/heads/master"
REPO = "https://github.com/opnsense/changelog"
DOCS_URL = "https://docs.opnsense.org/CE_releases.html"
CORE_PACKAGES = ("opnsense", "opnsense-devel", "opnsense-business")


class ChangelogError(ValueError):
    pass


def pseudo_host(system: str) -> str:
    """The `match.host` of a firewall's CVEs. A real host id has no colon, so this cannot clash with one."""
    return PSEUDO + system


def changelog_url(release: str) -> str:
    """The release's file in the repository, which is what the firewall's Changelog tab shows. A hotfix version shares its
    release's file."""
    base = release.split("_")[0]
    series = opnver.series_of(base) or ""
    return f"{REPO}/blob/master/community/{series}/{base}"


def _short(text: str, limit: int = LINE_MAX) -> str:
    t = " ".join(text.split())
    return t if len(t) <= limit else t[:limit - 1].rstrip() + "…"


# --- parsing one file -----------------------------------------------------------------------------------------------------------

def _date(line: str) -> str | None:
    m = DATE_RE.match(line.strip())
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3)}", "%B %d %Y").date().isoformat()
    except ValueError:
        return None


def _footnote(value: str) -> tuple[str, str] | None:
    """(kind, ref) a footnote names, or None for any other kind of footnote (PLUGINS:, CURL:, a plain URL ...)."""
    v = value.strip()
    m = CVE_FOOT.match(v)
    if m:
        return "cve", m.group(1)
    m = GHSA_FOOT.match(v)
    if m:
        return "adv", m.group(1)
    m = SA_FOOT.match(v)
    if m:
        return "adv", m.group(1)
    if v.startswith("https://") and "cve" in v.lower():     # the old files: https://cve.mitre.org/...?name=CVE-2015-1283
        ids = CVE_FIND.findall(v)
        if len(ids) == 1:
            return "cve", ids[0]
    return None


def parse_release(release: str, text: str) -> dict:
    """{"date": ISO or None, "fixes": [{"version", "kind", "ref", "line"}]} for one release's file. `kind` is "cve" or
    "adv" (an advisory without a CVE id). A row is made once per (version, kind, ref); the first bullet's text is kept.
    "versions" lists the release and every hotfix version a section header names, whether or not it fixes a CVE."""
    lines = text.splitlines()
    foot: dict[str, str] = {}
    for ln in lines:
        m = FOOT_RE.match(ln)
        if m:
            foot[m.group(1)] = m.group(2)
    date = _date(lines[0]) if lines else None
    version = release
    versions = [release]
    lead_text, lead_ids = "", []
    started = False
    bullets: list[tuple[str, str, str, list[str]]] = []      # (section version, text, lead text, lead ids)
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip():
            continue
        m = BULLET_RE.match(raw)
        if m:
            started = True
            parts = [m.group(1).strip()]
            while i < len(lines) and lines[i][:1] in (" ", "\t") and lines[i].strip():
                parts.append(lines[i].strip())
                i += 1
            if len(bullets) >= MAX_BULLETS:
                raise ChangelogError(f"{release}: more bullets than expected")
            bullets.append((version, " ".join(parts), lead_text, lead_ids))
            continue
        if not started or FOOT_RE.match(raw):
            continue
        line = raw.strip()
        hm = HOTFIX_RE.search(line)
        lead_text, lead_ids = "", []
        if hm and opnver.valid(hm.group(1)) and opnver.series_of(hm.group(1)) == opnver.series_of(release):
            version = hm.group(1)
            if version not in versions:
                versions.append(version)
        elif line.endswith(":") and CVE_FIND.search(line):
            lead_text, lead_ids = line.rstrip(":").strip(), list(dict.fromkeys(CVE_FIND.findall(line)))
    out: dict[tuple[str, str, str], str] = {}
    for sect, body, lead, lids in bullets:
        refs: list[tuple[str, str]] = [("cve", c) for c in CVE_FIND.findall(body)]
        for n in REF_RE.findall(body):
            f = _footnote(foot[n]) if n in foot else None
            if f:
                refs.append(f)
        refs += [("cve", c) for c in lids]
        shown = _short(REF_RE.sub("", body))
        if lids:
            shown = _short(f"{REF_RE.sub('', body)} ({lead})")
        have_cve = any(k == "cve" for k, _r in refs)
        for kind, ref in dict.fromkeys(refs):
            if kind == "adv" and have_cve:
                continue                     # one bullet, one issue: the advisory's CVE id is the better name
            if kind == "cve" and not CVE_RE.match(ref):
                continue
            out.setdefault((sect, kind, ref), shown)
    return {"date": date, "versions": versions, "fixes": [{"version": v, "kind": k, "ref": r, "line": ln} for (v, k, r), ln in out.items()]}


# --- the repository's tarball ----------------------------------------------------------------------------------------------------

def read_tarball(path, series: set[str]) -> dict[str, tuple[str, str]]:
    """{release: (series, text)} for every release file of the wanted series in a saved codeload tarball. Nothing is
    extracted: the tar is streamed and only regular files whose name is exactly community/<series>/<release> are read, each
    capped. Raises ChangelogError when the file is not a tarball, is bigger than it should be, or holds no release file at
    all (a changed layout), so the last good rows stay."""
    out: dict[str, tuple[str, str]] = {}
    seen_any = False
    total = members = 0
    try:
        with tarfile.open(path, mode="r|gz") as tar:
            for m in tar:
                members += 1
                total += max(m.size, 0)
                if members > MAX_MEMBERS or total > MAX_TOTAL_BYTES:
                    raise ChangelogError("the changelog archive is bigger than expected")
                if not m.isfile():
                    continue
                f = FILE_RE.match(m.name)
                if not f or f.group(1) != opnver.series_of(f.group(2)):
                    continue
                seen_any = True
                if f.group(1) not in series:
                    continue
                if m.size > MAX_FILE_BYTES:
                    raise ChangelogError(f"{f.group(2)} is larger than the limit")
                fh = tar.extractfile(m)
                out[f.group(2)] = (f.group(1), (fh.read(MAX_FILE_BYTES + 1) if fh else b"").decode("utf-8", "replace"))
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise ChangelogError(f"not a readable changelog archive: {type(exc).__name__}") from None
    if not seen_any:
        raise ChangelogError("no community/<series>/<release> files in the archive")
    return out


def load(conn, path, series: set[str]) -> tuple[int, str]:
    """Replace the `opn_release` and `opn_fix` rows with what the saved tarball holds for these series. The old rows stay when
    the file does not parse. Returns (rows kept, note)."""
    files = read_tarball(path, series)
    releases, fixes, versions = [], [], set()
    for release, (ser, text) in sorted(files.items()):
        parsed = parse_release(release, text)
        versions.update(parsed["versions"])
        releases.append((release, ser, parsed["date"]))
        fixes += [(f["version"], release, f["kind"], f["ref"], f["line"]) for f in parsed["fixes"]]
        if len(fixes) > MAX_ROWS:
            raise ChangelogError("the changelog has more entries than expected")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM opn_fix")
        conn.execute("DELETE FROM opn_release")
        conn.executemany("INSERT OR REPLACE INTO opn_release VALUES (?, ?, ?)", releases)
        conn.executemany("INSERT OR IGNORE INTO opn_fix VALUES (?, ?, ?, ?, ?)", fixes)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    from . import store
    store.set_meta(conn, "opn_versions", json.dumps(sorted(versions)))
    cves = len({f[3] for f in fixes if f[2] == "cve"})
    return len(fixes), f"series {', '.join(sorted(series))}: {len(releases)} releases, {cves} CVEs"


# --- what a pending update brings -----------------------------------------------------------------------------------------------

def plan(fw: dict | None) -> dict:
    """What the firewall's firmware status (remote/opnsense.py `parse_firmware`) says is coming, as {"ok": True,
    "installed", "offered", "series": [...]} or {"ok": False, "why": ...}. `offered` is the new version of the OPNsense
    package itself when the pending list has it (a hotfix shows as `26.1.11_10`), else the release the status names (a major
    upgrade lists sets, not packages). Updates to other packages alone have no release, so they have no changelog."""
    if not fw or fw.get("available") is False or not (fw.get("count") or 0):
        return {"ok": False, "why": "nothing"}
    core = next((p for p in (fw.get("packages") or []) + (fw.get("sets") or []) if p.get("name") in CORE_PACKAGES and p.get("new")), None)
    installed = fw.get("version") or (core or {}).get("old") or ""
    offered = (core or {}).get("new") or fw.get("new_version") or ""
    if not offered:
        return {"ok": False, "why": "no_release"}
    if not (opnver.valid(installed) and opnver.valid(offered)):
        return {"ok": False, "why": "version", "installed": installed, "offered": offered}
    if opnver.compare(offered, installed) <= 0:
        return {"ok": False, "why": "no_release"}
    series = opnver.series_between(installed, offered)
    if series is None:
        return {"ok": False, "why": "series", "installed": installed, "offered": offered}
    return {"ok": True, "installed": installed, "offered": offered, "series": series}


def plan_hash(p: dict) -> str:
    return f"{p['installed']}>{p['offered']}"


def fixes_between(conn, installed: str, offered: str, kind: str | None = None) -> list[dict]:
    """The changelog rows with installed < version <= offered, oldest first."""
    sql = "SELECT version, release, kind, ref, line FROM opn_fix"
    rows = conn.execute(sql + (" WHERE kind = ?" if kind else ""), (kind,) if kind else ()).fetchall()
    keep = [dict(r) for r in rows if opnver.valid(r["version"])
            and opnver.compare(r["version"], installed) > 0 and opnver.compare(r["version"], offered) <= 0]
    keep.sort(key=lambda r: (opnver.key(r["version"]), r["kind"], r["ref"]))
    return keep


def releases_between(conn, installed: str, offered: str) -> list[dict]:
    """The release files whose own version is inside the range (a release with no CVE in it is still one the update brings),
    with their dates, oldest first. A hotfix has no file of its own, so an update that only adds a hotfix lists none."""
    out = []
    for r in conn.execute("SELECT version, series, date FROM opn_release"):
        if opnver.valid(r["version"]) and opnver.compare(r["version"], installed) > 0 and opnver.compare(r["version"], offered) <= 0:
            out.append(dict(r))
    out.sort(key=lambda r: opnver.key(r["version"]))
    return out


def match_host(conn, host: str, p: dict, gen: str) -> dict:
    """Replace the firewall's rows in `match` (cve/match.py's table: `source` is `opnsense`, `state` is `fix`, `installed` is
    the running version and `fixed` the highest section of the range that names the CVE) and its `matched` row. `p` is a
    `plan`. Returns {"releases", "cves", "note"}."""
    by_cve: dict[str, str] = {}
    for r in fixes_between(conn, p["installed"], p["offered"], "cve"):
        by_cve[r["ref"]] = r["version"]          # oldest first, so the last one written is the highest
    rels = releases_between(conn, p["installed"], p["offered"])
    base = p["offered"].split("_")[0]
    note = ""
    if conn.execute("SELECT 1 FROM opn_release WHERE version = ?", (base,)).fetchone() is None:
        note = f"The changelog has no entry for {base} yet; CVEs it fixes are not listed."
    rows = [(host, SOURCE, cve, "fix", p["installed"], v, None) for cve, v in sorted(by_cve.items())]
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM match WHERE host = ?", (host,))
        conn.executemany("INSERT OR REPLACE INTO match VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("INSERT OR REPLACE INTO matched VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (host, plan_hash(p), 0.0, gen, time.time(), len(rels), note))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return {"releases": len(rels), "cves": len(rows), "note": note}


def loaded_series(conn) -> set[str]:
    """The series the stored changelog rows were loaded for."""
    from . import store
    try:
        return set(json.loads(store.get_meta(conn, "opn_series", "[]") or "[]"))
    except ValueError:
        return set()


def versions_missing(conn) -> bool:
    """The stored rows were loaded by a version that did not keep the list of release and hotfix versions."""
    from . import store
    return store.get_meta(conn, "opn_versions") is None


# --- a release the firewall has not been offered ---------------------------------------------------------------------------------

def watch_series(fw: dict | None) -> list[str]:
    """The series to keep for a firewall that may have no update pending: the one it runs and the two after it (a newer
    series is a major upgrade, which only gets a line on the card). [] when the version is not a community release."""
    if not fw or fw.get("available") is False:
        return []
    ser = opnver.series_of(fw.get("version"))
    return [ser, *opnver.next_series(ser)] if ser and opnver.is_community_series(ser) else []


def _seen(fw: dict) -> str:
    """The highest version in the installed series that the firewall's own status names: what it runs, what it calls the
    latest, the new version, and the OPNsense package of a pending update (a hotfix appears there). A version from another
    series (a major upgrade on offer) says nothing about this series."""
    ser = opnver.series_of(fw["version"])
    best = fw["version"]
    cands = [fw.get("latest"), fw.get("new_version")]
    cands += [p.get("new") for p in (fw.get("packages") or []) + (fw.get("sets") or []) if p.get("name") in CORE_PACKAGES]
    for v in cands:
        if opnver.valid(v) and opnver.series_of(v) == ser and opnver.compare(v, best) > 0:
            best = v
    return best


def _ser_key(s: str) -> tuple[int, int]:
    a, b = s.split(".")
    return int(a), int(b)


def known_versions(conn) -> set[str]:
    """Every release and hotfix version the stored changelog names (hotfixes with no CVE included)."""
    from . import store
    out: set[str] = set()
    try:
        out.update(json.loads(store.get_meta(conn, "opn_versions", "[]") or "[]"))
    except ValueError:
        pass
    out.update(r[0] for r in conn.execute("SELECT version FROM opn_release"))
    out.update(r[0] for r in conn.execute("SELECT version FROM opn_fix"))
    return {v for v in out if opnver.valid(v)}


def unseen_host(system: str) -> str:
    return UNSEEN_PSEUDO + system


def unseen_plan(conn, fw: dict | None) -> dict:
    """The newest changelog version in the firewall's own series that is above both what it runs and what its last firmware
    check showed (`_seen`), as {"ok": True, "installed", "seen", "offered", "newer_series"} (`offered` is the newest, so the
    plan is matched like a pending update's). Else {"ok": False, "why", "newer_series"}: `newer_series` is the newest later
    series the changelog has ("27.1"), which the firewall would offer as a major upgrade, or ""."""
    out = {"ok": False, "why": "version", "newer_series": ""}
    if not fw or fw.get("available") is False or not opnver.valid(fw.get("version")):
        return out
    ser = opnver.series_of(fw["version"])
    if not opnver.is_community_series(ser):
        return out
    seen = _seen(fw)
    known = known_versions(conn)
    newer = sorted({x for v in known if (x := opnver.series_of(v)) and opnver.is_community_series(x) and _ser_key(x) > _ser_key(ser)},
                   key=_ser_key)
    out["newer_series"] = newer[-1] if newer else ""
    above = [v for v in known if opnver.series_of(v) == ser and opnver.compare(v, seen) > 0]
    if not above:
        out["why"] = "none"
        return out
    return {"ok": True, "why": "", "installed": fw["version"], "seen": seen, "offered": max(above, key=opnver.key),
            "newer_series": out["newer_series"]}
