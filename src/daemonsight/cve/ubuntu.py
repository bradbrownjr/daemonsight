"""Match Ubuntu hosts and Ubuntu container images against Canonical's OVAL data.

Source: the "CVE" OVAL file of each release, https://security-metadata.canonical.com/oval/com.ubuntu.<codename>.cve.oval.xml.bz2
(one bz2 file per release; Creative Commons Attribution-ShareAlike 4.0 per the directory's LICENSE; `ETag` and `Last-Modified`,
so a conditional GET answers 304; an unknown release answers 404). What was read in the noble file on 2026-11-24 (11.9 MB
download, 284 MB of XML, 37,611 `vulnerability` definitions, one per CVE):

* A definition has `metadata/reference[@source='CVE']/@ref_id`, a `description` that ends with Canonical's "Update
  Instructions" text (cut here), and `advisory/cve/@priority` (Ubuntu's own priority: negligible, low, medium, high,
  critical).
* Its `criteria` is a list of one `criterion` per affected source package. The test and state elements further down the file
  work on binary package names (variables) and are not needed: the criterion's `comment` names the source package, the
  archive pocket and the status, and holds the fixed version:

      libxmltok source package in esm-apps/noble, is affected and has been fixed (note: '1.2-4.1ubuntu2.24.0.4.1+esm3').
      cadaver source package in noble, might be affected and may need fixing.

  The pocket is the release name for the standard archives, `esm-apps/<release>` or `esm-infra/<release>` for the
  Ubuntu Pro (ESM) archives. A fixed version is a source version in dpkg order, with `ubuntu`, `build` and `+esm` parts.
* A kernel is not a package check: the definition holds, per kernel flavor, an AND of "Is kernel 'linux-aws' running?" and
  "'linux-aws' kernel in noble was vulnerable but has been fixed (note: '6.8.0-1009.9')." (fixed), or the running check alone
  (no fix yet). The flavor is the kernel's source package (`linux`, `linux-aws`, `linux-hwe-6.8`).
* "might be affected and may need fixing" is the only unfixed status. Canonical's generator turns the tracker's `needed`,
  `needs-triage`, `pending` and `deferred` (and `ignored`) all into a package that "might be affected" (oval_lib.py in
  git.launchpad.net/ubuntu-cve-tracker maps every one of them to the internal status `vulnerable`), so the file does
  not say which one it was. Only the priority tells a negligible issue from a real one.
* There is no "not affected" row: a package the tracker calls `not-affected` or `DNE` is absent from the definition.

A host or image is matched by source package name and source version (the dpkg status `Source:` field and its
version, as for Debian), compared in dpkg order (debver.py). Everything here is data from a download: names, versions,
CVE ids and pockets are checked before they are kept.
"""

from __future__ import annotations

import bz2
import re
import time
import xml.etree.ElementTree as ET

from . import debver

NS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
SRC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$")
CODENAME_RE = re.compile(r"^[a-z]{3,20}$")
CRITERION_SRC = re.compile(r"^(\S+) source package in (?:(esm-[a-z]+)/)?([a-z]+), (.+)$")
CRITERION_FIXED = re.compile(r"^is affected and has been fixed \(note: '([^']+)'\)\.$")
CRITERION_OPEN = "might be affected and may need fixing."
KERNEL_RUNNING = re.compile(r"^Is kernel '([^']+)' running\?$")
KERNEL_FIXED = re.compile(r"^'([^']+)' kernel in ([a-z]+) was vulnerable but has been fixed \(note: '([^']+)'\)\.$")
PRIORITIES = ("negligible", "low", "medium", "high", "critical")
ESM_POCKETS = ("esm-infra", "esm-apps")
MAX_BYTES = 1500 << 20           # decoded size cap (the real noble file is 284 MB)
MAX_ROWS = 3_000_000
DESCR_MAX = 200
UPDATE_TEXT = "Update Instructions:"

OVAL_HOST = "security-metadata.canonical.com"
OVAL_URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{release}.cve.oval.xml.bz2"
OVAL_DOCS = "https://ubuntu.com/security/oval"
TRACKER_URL = "https://ubuntu.com/security/"
LICENCE_URL = "https://security-metadata.canonical.com/oval/LICENSE"


class OvalError(ValueError):
    pass


def display(release: str | None, version_id: str | None = None) -> str:
    """"Ubuntu 24.04" for noble, from the bundled release data; "Ubuntu noble" when it does not list the name."""
    if not release:
        return "Ubuntu"
    from .. import distro
    try:
        row = next((r for r in distro.load_rows("ubuntu", version_id, release) if (r.get("series") or "").lower() == release), None)
    except Exception:
        row = None
    version = (row or {}).get("version") or version_id or ""
    version = version.replace(" LTS", "")
    return f"Ubuntu {version}" if version else f"Ubuntu {release}"


def release_of(inv: dict) -> str | None:
    """The Ubuntu release (codename) an inventory is from. Only Ubuntu itself: a derivative with its own os-release `ID`
    (Linux Mint, Pop!_OS) is not matched."""
    if inv.get("backend") == "apt" and inv.get("os_id") == "ubuntu" and CODENAME_RE.match(inv.get("codename") or ""):
        return inv["codename"]
    return None


def is_esm_pocket(pocket: str) -> bool:
    return pocket in ESM_POCKETS or pocket.startswith("esm-")


def _short(text: str) -> str:
    t = text.split(UPDATE_TEXT, 1)[0]
    t = " ".join(t.split())
    return t if len(t) <= DESCR_MAX else t[:DESCR_MAX - 1].rstrip() + "…"


def _criteria(el, out: dict, release: str) -> None:
    """Walk one definition's criteria. `out` maps (source, pocket, kernel) -> ("fixed", version) or ("open", None)."""
    for child in el:
        if child.tag == NS + "criterion":
            comment = child.get("comment") or ""
            m = CRITERION_SRC.match(comment)
            if m:
                src, esm, rel, what = m.groups()
                pocket = esm or ""
                if rel != release or not SRC_RE.match(src):
                    continue
                f = CRITERION_FIXED.match(what)
                if f:
                    out[(src, pocket, 0)] = ("fixed", f.group(1))
                elif what == CRITERION_OPEN:
                    out.setdefault((src, pocket, 0), ("open", None))
                continue
            k = KERNEL_RUNNING.match(comment)
            if k and SRC_RE.match(k.group(1)):
                out.setdefault((k.group(1), "", 1), ("open", None))
        elif child.tag == NS + "criteria":
            if child.get("operator") == "AND":
                fixed = None
                for c in child.iter(NS + "criterion"):
                    f = KERNEL_FIXED.match(c.get("comment") or "")
                    if f and f.group(2) == release and SRC_RE.match(f.group(1)):
                        fixed = f
                if fixed:
                    out[(fixed.group(1), "", 1)] = ("fixed", fixed.group(3))
                    continue
            _criteria(child, out, release)


class _Capped:
    """A binary stream that refuses to give out more than `limit` bytes: a bz2 file that expands without bound is
    refused instead of filling the disk or memory."""

    def __init__(self, fh, limit: int):
        self.fh, self.left = fh, limit

    def read(self, n: int = -1) -> bytes:
        data = self.fh.read(n if n and n > 0 else 1 << 16)
        self.left -= len(data)
        if self.left < 0:
            raise OvalError("the file decodes to more than the size limit")
        return data


def parse_oval(fh, release: str):
    """Yield (cve, priority, description, rows) for every vulnerability definition of one release's CVE OVAL file, from a
    binary stream of the decoded XML. `rows` is a list of (source, pocket, kernel, state, fixed): state "fixed" (with the
    fixed source version) or "open". Definitions without a usable CVE id or without rows are skipped. Raises OvalError for
    a document that is not Canonical's OVAL shape."""
    seen_root = False
    try:
        for event, el in ET.iterparse(_Capped(fh, MAX_BYTES), events=("start", "end")):
            if event == "start":
                if not seen_root:
                    if el.tag != NS + "oval_definitions":
                        raise OvalError("not an OVAL definitions file")
                    seen_root = True
                continue
            if el.tag == NS + "definition":
                if el.get("class") == "vulnerability":
                    got = _definition(el, release)
                    if got:
                        yield got
                el.clear()
            elif el.tag == NS + "definitions":
                return                      # tests, objects, states and variables follow and are not used
    except ET.ParseError as e:
        raise OvalError(f"not readable XML: {e}") from None
    if not seen_root:
        raise OvalError("empty OVAL file")


def _definition(el, release: str):
    meta = el.find(NS + "metadata")
    if meta is None:
        return None
    cve = next((r.get("ref_id") for r in meta.findall(NS + "reference") if r.get("source") == "CVE"), None)
    if not cve or not CVE_RE.match(cve):
        return None
    prio = None
    adv = meta.find(NS + "advisory")
    if adv is not None:
        tag = adv.find(NS + "cve")
        prio = (tag.get("priority") or "").lower() if tag is not None else None
    if prio not in PRIORITIES:
        prio = ""
    found: dict = {}
    crit = el.find(NS + "criteria")
    if crit is not None:
        _criteria(crit, found, release)
    rows = []
    for (src, pocket, kernel), (state, fixed) in found.items():
        if pocket and not is_esm_pocket(pocket):
            continue
        if state == "fixed":
            try:
                debver.parse(fixed)
            except ValueError:
                continue
        rows.append((src, pocket, kernel, state, fixed))
    if not rows:
        return None
    d = meta.find(NS + "description")
    return cve, prio, _short(d.text or "") if d is not None else "", rows


def load_file(path, release: str):
    """parse_oval over a saved .bz2 file."""
    if not CODENAME_RE.match(release):
        raise OvalError("not a release name")
    with bz2.open(path, "rb") as fh:
        yield from parse_oval(fh, release)


# ---- matching ---------------------------------------------------------------

def classify(rows: list[tuple], installed: str, esm: frozenset[str] | set[str] | None, priority: str) -> tuple[str, str | None] | None:
    """The state and fixed version of one CVE for one source package, from every row the file has for it (one per pocket).

    * A row with a fixed version older than or equal to the installed one does not apply (fixed already).
    * Of the fixed versions above the installed one, the highest decides. A fix in an ESM pocket is "esm" (an update exists
      but only through Ubuntu Pro) unless the host has that Pro service on (`esm` holds "esm-infra" and "esm-apps" for the
      services it has), then it is "fix" like any other.
    * With no applicable fix and an open row: "nofix".
    * A negligible priority does not change the state: it is a vendor rating that cve/priority.py applies (low, only when the
      system is not exposed and the CVE is not in the KEV catalog).
    Returns None when nothing applies."""
    best = None
    open_row = False
    for pocket, state, fixed in rows:
        if state == "open":
            open_row = True
            continue
        try:
            if debver.compare(installed, fixed) >= 0:
                continue
            if best is None or debver.compare(fixed, best[1]) > 0:
                best = (pocket, fixed)
        except ValueError:
            continue
    if best:
        pocket, fixed = best
        esm_only = is_esm_pocket(pocket) or "+esm" in fixed
        state = "esm" if esm_only and not (esm and pocket in esm) else "fix"
        out = (state, fixed)
    elif open_row:
        out = ("nofix", None)
    else:
        return None
    return out


def match_host(conn, host: str, inv: dict, gen: str) -> dict:
    """Replace the host's (or image's) rows in `match` (cve/match.py's table: `source` is the source package, `state` is
    fix, esm, nofix or minor, `urgency` is Ubuntu's priority). `inv` is a host inventory, or the pseudo inventory of
    remote/docker_images.py. Returns {"packages", "cves", "note"}."""
    release = release_of(inv)
    sources = inv.get("sources", [])
    rows: list[tuple] = []
    notes: list[str] = []
    esm = inv.get("esm")
    services = frozenset(f"esm-{s}" if not str(s).startswith("esm-") else str(s) for s in esm) if isinstance(esm, list) else None
    if release is None:
        notes.append("This host's Ubuntu release has no name to look up" if inv.get("os_id") == "ubuntu"
                     else "CVE matching covers Debian, Raspberry Pi OS and Ubuntu hosts so far")
    elif not conn.execute("SELECT 1 FROM ubu WHERE release = ? LIMIT 1", (release,)).fetchone():
        notes.append(f"{display(release, inv.get('version_id'))}: no CVE data downloaded for this release")
    else:
        kernels = {r[0] for r in conn.execute("SELECT DISTINCT source FROM ubu WHERE release = ? AND kernel = 1", (release,))}
        prio = {}
        for src, ver, bins in sources:
            # A kernel's CVEs are the running kernel's: only a source with a kernel image counts (a container's
            # linux-libc-dev, from the same source, does not run one).
            if src in kernels and not any(isinstance(b, str) and b.startswith("linux-image-") for b in (bins or [])):
                continue
            by_cve: dict[str, list[tuple]] = {}
            for r in conn.execute("SELECT cve, pocket, state, fixed, priority FROM ubu WHERE release = ? AND source = ?", (release, src)):
                by_cve.setdefault(r["cve"], []).append((r["pocket"], r["state"], r["fixed"]))
                prio[r["cve"]] = r["priority"]
            for cve, crows in by_cve.items():
                got = classify(crows, ver, services, prio[cve])
                if got:
                    state, fixed = got
                    rows.append((host, src, cve, state, ver, fixed, prio[cve] or None))
        if esm is None and any(r[3] == "esm" for r in rows):
            notes.append("Whether this host has Ubuntu Pro is not known (the collector did not report it), so fixes that exist only in Ubuntu Pro's ESM archives are not counted as available")
    note = "; ".join(notes)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM match WHERE host = ?", (host,))
        conn.executemany("INSERT OR REPLACE INTO match VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("INSERT OR REPLACE INTO matched VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (host, inv.get("hash"), inv.get("taken_at"), gen, time.time(), len(sources), note))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return {"packages": len(sources), "cves": len(rows), "note": note}
