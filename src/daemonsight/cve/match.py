"""Match a host's installed packages against the Debian security tracker, and
turn the result into findings.

For one installed source package at version V on release R, each tracker row
(R, source, CVE) gives a state:

* `resolved` with fixed version F: V older than F (Debian version order,
  debver.py) means the CVE still applies and a fix exists: "fix". V at or
  after F: fixed already, not stored. F of "0" means the release was never
  affected: not stored at all (feeds.load_debian).
* `open`: no fix yet: "nofix".
* `undetermined`: Debian hasn't decided: "undetermined".
* A row Debian marked `nodsa` (no advisory will be issued: minor issue,
  ignored, postponed), or with urgency `unimportant` or `end-of-life`, is
  "minor", whether or not a fix exists. These are listed on the page and
  never raise a finding.

This follows Issue.get_status in the maintainers' own reader,
bin/tracker_data.py in https://salsa.debian.org/security-tracker-team/security-tracker.
"""

from __future__ import annotations

import time

from ..findings import Finding, anchor, digest, upgrade_cmd
from . import debver

STATES = ("fix", "nofix", "minor", "undetermined")
MINOR_URGENCY = ("unimportant", "end-of-life")
TRACKER_URL = "https://security-tracker.debian.org/tracker/"
MAX_FINDINGS = 100
TOP_CVES = 4


# Bump when matching changes what a host matches, so the hub matches every
# host again without waiting for a new package list or tracker download.
MATCH_VERSION = 2


def release_of(inv: dict) -> str | None:
    """The Debian release an inventory is from. Raspberry Pi OS (raspbian) is
    Debian under its own name, looked up by codename as distro.py does.
    Ubuntu and other derivatives are not matched yet."""
    if inv.get("backend") == "apt" and inv.get("os_id") in ("debian", "raspbian") and inv.get("codename"):
        return inv["codename"]
    return None


def classify(status: str, fixed: str | None, urgency: str | None, nodsa: str | None,
             installed: str) -> str | None:
    """The state for one tracker row against an installed version, or None
    when the CVE no longer applies."""
    if status == "resolved":
        if not fixed:
            return None
        try:
            if debver.compare(installed, fixed) >= 0:
                return None
        except ValueError:
            return None
        return "minor" if nodsa is not None or urgency in MINOR_URGENCY else "fix"
    if status == "open":
        return "minor" if nodsa is not None or urgency in MINOR_URGENCY else "nofix"
    if status == "undetermined":
        return "undetermined"
    return None


def _kernel_installed(src: str, bins) -> bool:
    """Kernel CVEs apply only where a Debian kernel image is installed. A
    container or a host on another kernel can still have linux-libc-dev (the
    headers for compiling) or tools built from the same source; those don't
    run the kernel, so its CVEs aren't theirs. Other sources always match."""
    if src != "linux" and not src.startswith("linux-signed"):
        return True
    return any(isinstance(b, str) and b.startswith("linux-image-") for b in (bins or []))


def match_host(conn, host: str, inv: dict, gen: str) -> dict:
    """Replace the host's rows in `match`. Returns {"packages", "cves", "note"}."""
    release = release_of(inv)
    rows: list[tuple] = []
    note = ""
    if release is None:
        note = ("CVE matching covers Debian and Raspberry Pi OS hosts so far" if inv.get("backend") == "apt"
                else "This host's package system isn't matched here")
    else:
        for src, ver, bins in inv.get("sources", []):
            if not _kernel_installed(src, bins):
                continue
            for r in conn.execute("SELECT cve, status, fixed, urgency, nodsa FROM deb WHERE release = ? AND source = ?",
                                  (release, src)):
                state = classify(r["status"], r["fixed"], r["urgency"], r["nodsa"], ver)
                if state:
                    rows.append((host, src, r["cve"], state, ver, r["fixed"], r["urgency"]))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM match WHERE host = ?", (host,))
        conn.executemany("INSERT OR REPLACE INTO match VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("INSERT OR REPLACE INTO matched VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (host, inv.get("hash"), inv.get("taken_at"), gen, time.time(),
                      len(inv.get("sources", [])), note))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return {"packages": len(inv.get("sources", [])), "cves": len(rows), "note": note}


def set_advisories(conn, host: str, inv: dict, gen: str) -> dict:
    """Fedora: every CVE named by a pending security advisory is a "fix"."""
    rows = []
    for a in inv.get("advisories", []):
        for cve in a.get("cves", []):
            for pkg in a.get("packages", []) or [""]:
                rows.append((host, pkg or a["id"], cve, "fix", None, a["id"], (a.get("severity") or "").lower()))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM match WHERE host = ?", (host,))
        conn.executemany("INSERT OR REPLACE INTO match VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("INSERT OR REPLACE INTO matched VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (host, inv.get("hash"), inv.get("taken_at"), gen, time.time(),
                      len({r[1] for r in rows}), ""))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return {"packages": len({r[1] for r in rows}), "cves": len(rows), "note": ""}


# ---- ranking ----------------------------------------------------------------

def pct(score: float | None) -> str:
    if score is None:
        return "no EPSS score"
    p = score * 100
    return f"EPSS {p:.0f}%" if p >= 1 or score == 0 else "EPSS under 1%"


def rank_key(c: dict):
    """Worst first: on the KEV list, then the higher EPSS score, then a fix
    over none, then the CVE id."""
    return (not c["kev"], -(c["epss"] or 0), c["state"] != "fix", c["cve"])


def host_cves(conn, host: str, states: tuple[str, ...] = STATES) -> list[dict]:
    """Every stored match for a host, with EPSS score, KEV flag and description."""
    marks = ",".join("?" for _ in states)
    out = []
    for r in conn.execute(
            "SELECT m.source, m.cve, m.state, m.installed, m.fixed, m.urgency, e.score AS epss, e.pct AS pctile, "
            "k.cve IS NOT NULL AS kev, k.name AS kev_name, k.ransomware AS ransomware, c.descr AS descr "
            "FROM match m LEFT JOIN epss e ON e.cve = m.cve LEFT JOIN kev k ON k.cve = m.cve "
            f"LEFT JOIN cve c ON c.id = m.cve WHERE m.host = ? AND m.state IN ({marks})", (host, *states)):
        d = dict(r)
        d["kev"] = bool(d["kev"])
        out.append(d)
    return out


def _fixed_version(cves: list[dict]) -> str | None:
    best = None
    for c in cves:
        if c["state"] == "fix" and c["fixed"]:
            try:
                if best is None or debver.compare(c["fixed"], best) > 0:
                    best = c["fixed"]
            except ValueError:
                pass
    return best


def _describe(c: dict) -> str:
    bits = []
    if c["kev"]:
        bits.append("exploited, CISA KEV")
    bits.append(pct(c["epss"]))
    if c.get("urgency") and c["urgency"] != "not yet assigned":
        bits.append(f"Debian urgency {c['urgency']}")
    if c["state"] == "nofix":
        bits.append("no fix yet")
    return f"{c['cve']} ({', '.join(bits)})"


def package_findings(cves: list[dict], binaries: dict[str, list[str]], pending: set[str],
                     epss_high: float, backend: str = "apt", reboot_pending: bool = False) -> list[Finding]:
    """One finding per source package: High if any open or fixable CVE is on
    CISA's KEV list or has an EPSS score at or above `epss_high`, Medium if a
    fix is available, otherwise none."""
    by_pkg: dict[str, list[dict]] = {}
    for c in cves:
        if c["state"] in ("fix", "nofix"):
            by_pkg.setdefault(c["source"], []).append(c)
    out = []
    for src, items in by_pkg.items():
        items.sort(key=rank_key)
        kev = [c for c in items if c["kev"]]
        hot = [c for c in items if not c["kev"] and c["state"] == "fix" and (c["epss"] or 0) >= epss_high]
        fixes = [c for c in items if c["state"] == "fix"]
        if kev:
            sev = "high"
            title = (f"{src}: {kev[0]['cve']} is being exploited (CISA KEV)" if len(kev) == 1
                     else f"{src}: {len(kev)} CVEs are being exploited (CISA KEV)")
        elif hot:
            sev = "high"
            title = (f"{src}: {hot[0]['cve']} has a high exploit score ({pct(hot[0]['epss'])})" if len(hot) == 1
                     else f"{src}: {len(hot)} CVEs have a high exploit score (EPSS {epss_high * 100:.0f}% or more)")
        elif fixes:
            sev = "medium"
            title = (f"{src}: {fixes[0]['cve']} is fixed in an update" if len(fixes) == 1
                     else f"{src}: {len(fixes)} CVEs fixed in an update")
        else:
            continue
        parts = []
        fix = None
        installed = items[0]["installed"]
        if fixes:
            fv = _fixed_version(fixes)
            names = binaries.get(src, [])
            if backend == "dnf":
                parts.append("Fedora has security advisories for it. Install the update.")
                fix = upgrade_cmd({"backend": "dnf"})
            elif src == "linux" and reboot_pending:
                # The inventory lists the running kernel, and a newer one is
                # installed (pkg.reboot is open): the reboot is what applies it.
                parts.append(f"Running kernel {installed}; fixed in {fv}. A newer kernel is installed: reboot "
                             "to run it. If this stays after the reboot, that kernel doesn't have the fix yet; "
                             "install the update.")
                fix = "sudo reboot"
            else:
                kernel = src == "linux"
                parts.append(f"{'Running kernel' if kernel else 'Installed'} {installed}; fixed in {fv}. "
                             f"Install the update{', then reboot to run it' if kernel else ''}.")
                fix = upgrade_cmd(None)
                if names or src:
                    listed = pending & ({src} | set(names))
                    parts.append("apt lists this update on the Packages page." if listed else
                                 "apt isn't offering it yet: refresh the package lists with apt update, and "
                                 "check the host's apt sources include the security archive.")
                    if not listed:
                        fix = "sudo apt update\n" + fix
                if src == "linux":
                    fix += "\nsudo reboot"
        unfixed = [c for c in items if c["state"] == "nofix"]
        top = ", ".join(_describe(c) for c in items[:TOP_CVES])
        parts.append(f"Top CVEs: {top}" + (f" and {len(items) - TOP_CVES} more." if len(items) > TOP_CVES else "."))
        if unfixed and kev and not fixes:
            parts.append(f"Debian has no fix yet. See {TRACKER_URL}{kev[0]['cve']} for mitigations.")
        elif unfixed:
            parts.append(f"{len(unfixed)} more in this package have no fix yet.")
        # Basis: the CVE ids, so a new CVE in the package brings an accepted finding back.
        out.append(Finding("cve.package", src, sev, title[:300], " ".join(parts)[:3900],
                           f"/vulnerabilities#{anchor('cve', src)}", fix=fix,
                           basis=f"cves:{digest(c['cve'] for c in items)}"))
    out.sort(key=lambda f: (f.severity != "high", f.title))
    return out[:MAX_FINDINGS]


def stale_finding(stale: list[tuple[str, float | None]], titles: dict[str, str]) -> Finding | None:
    """cve.feed_stale (Low): a feed has had no successful fetch for over 3 days."""
    if not stale:
        return None
    parts = []
    days = 0
    for name, age in stale:
        d = int(age // 86400) if age is not None else None
        days = max(days, d or 0)
        parts.append(f"{titles.get(name, name)} ({'never fetched' if d is None else f'{d} days'})")
    return Finding("cve.feed_stale", "feeds", "low", "CVE data is out of date",
                   "The hub hasn't fetched: " + ", ".join(parts) + ". Matches and scores here may be old. Check the "
                   "hub's outbound HTTPS to these sites, and the feed status on the Vulnerabilities page.",
                   "/vulnerabilities#feeds")
