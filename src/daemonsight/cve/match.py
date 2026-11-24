"""Match a host's installed packages against the Debian security tracker, and
turn the result into findings. (Ubuntu is matched in ubuntu.py, into the same
`match` table, with the extra state `esm`: a fix that exists only in Ubuntu
Pro's ESM archives and is not available to a host without Pro.)

For one installed source package at version V on release R, each tracker row
(R, source, CVE) gives a state:

* `resolved` with fixed version F: V older than F (Debian version order,
  debver.py) means the CVE still applies and a fix exists: "fix". V at or
  after F: fixed already, not stored. F of "0" means the release was never
  affected: not stored at all (feeds.load_debian).
* `open`: no fix yet: "nofix".
* `undetermined`: Debian hasn't decided: "undetermined".
* A row Debian marked `nodsa` (no advisory will be issued: minor issue,
  ignored, postponed), or with urgency `end-of-life`, is "minor", whether or
  not a fix exists. These are listed on the page and never raise a finding.
  Urgency `unimportant` is not minor here: it is a vendor rating that
  cve/priority.py applies (low, only when the host is not exposed and the CVE is
  not in the KEV catalog), so it has to reach the prioritiser.

This follows Issue.get_status in the maintainers' own reader,
bin/tracker_data.py in https://salsa.debian.org/security-tracker-team/security-tracker.
"""

from __future__ import annotations

import sqlite3
import time

from ..findings import Finding, anchor, digest, upgrade_cmd
from . import debver, priority

STATES = ("fix", "esm", "nofix", "minor", "undetermined")
MINOR_URGENCY = ("end-of-life",)
TRACKER_URL = "https://security-tracker.debian.org/tracker/"
MAX_FINDINGS = 100
TOP_CVES = 4


# Bump when matching changes what a host matches, so the hub matches every
# host again without waiting for a new package list or tracker download.
MATCH_VERSION = 3


def release_of(inv: dict) -> str | None:
    """The Debian release an inventory is from. Raspberry Pi OS (raspbian) is
    Debian under its own name, looked up by codename as distro.py does.
    Ubuntu is matched by cve/ubuntu.py (its own data); other derivatives are not matched."""
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

def pct(score: float | None, pctile: float | None = None) -> str:
    """"15.3% (92nd)": the EPSS probability, with its percentile when known (FIRST: use the probability, show both)."""
    return priority.epss_text(score, pctile)


RECORD_COLS = ("r.automatable AS automatable, r.impact AS impact, r.exploitation AS exploitation, "
               "r.cvss_score AS cvss_score, r.cvss_vector AS cvss_vector, r.cvss_source AS cvss_source")
NO_RECORD_COLS = ("NULL AS automatable, NULL AS impact, NULL AS exploitation, NULL AS cvss_score, NULL AS cvss_vector, "
                  "NULL AS cvss_source")


def host_cves(conn, host: str, states: tuple[str, ...] = STATES) -> list[dict]:
    """Every stored match for a host, with EPSS probability and percentile, KEV flag, description and CISA's SSVC rating
    (`automatable`, `impact`: None where CISA has not rated the CVE or its record has not been read yet)."""
    marks = ",".join("?" for _ in states)
    rows = None
    # Ubuntu's CVE text is in its own table (the Debian tracker's is replaced whole on each load), and the CVE Services records
    # in another. A reader that meets a cve.db from before a table existed (the chore has not migrated it yet) goes without it.
    for descr, records in (("COALESCE(c.descr, u.descr)", True), ("c.descr", True), ("COALESCE(c.descr, u.descr)", False), ("c.descr", False)):
        join = "LEFT JOIN ubu_cve u ON u.cve = m.cve " if "u." in descr else ""
        rec = "LEFT JOIN cve_record r ON r.cve = m.cve " if records else ""
        cols = RECORD_COLS if records else NO_RECORD_COLS
        try:
            rows = conn.execute(
                "SELECT m.source, m.cve, m.state, m.installed, m.fixed, m.urgency, e.score AS epss, e.pct AS pctile, "
                f"k.cve IS NOT NULL AS kev, k.name AS kev_name, k.ransomware AS ransomware, {descr} AS descr, {cols} "
                "FROM match m LEFT JOIN epss e ON e.cve = m.cve LEFT JOIN kev k ON k.cve = m.cve "
                f"LEFT JOIN cve c ON c.id = m.cve {join}{rec}WHERE m.host = ? AND m.state IN ({marks})", (host, *states)).fetchall()
            break
        except sqlite3.OperationalError:
            if (descr, records) == ("c.descr", False):
                raise
    out = []
    for r in rows:
        d = dict(r)
        d["kev"] = bool(d["kev"])
        out.append(d)
    return out


def _fixed_version(cves: list[dict], state: str = "fix") -> str | None:
    best = None
    for c in cves:
        if c["state"] == state and c["fixed"]:
            try:
                if best is None or debver.compare(c["fixed"], best) > 0:
                    best = c["fixed"]
            except ValueError:
                pass
    return best


def counted(items: list[dict]) -> list[dict]:
    """The CVEs of one package that raise its finding: a fix (or an ESM fix) for a CVE, or a known-exploited CVE that nothing
    fixes yet. An unfixed CVE that is not in the KEV catalog is listed, never raised."""
    return [c for c in items if (c["state"] in ("fix", "esm") or (c["state"] == "nofix" and c["kev"]))]


def _lower_first(text: str) -> str:
    return text[:1].lower() + text[1:]


def _describe(c: dict, label: str = "Debian urgency") -> str:
    bits = []
    if c["kev"]:
        bits.append("exploited, CISA KEV")
    bits.append("EPSS " + pct(c["epss"], c.get("pctile")) if c["epss"] is not None else pct(None))
    if c.get("urgency") and c["urgency"] != "not yet assigned":
        bits.append(f"{label} {c['urgency']}")
    if c.get("rating") is not None:
        bits.append(_lower_first(c["rating"].deadline.split(" (")[0]))
    if c["state"] == "nofix":
        bits.append("no fix yet")
    elif c["state"] == "esm":
        bits.append("fix only with Ubuntu Pro")
    return f"{c['cve']} ({', '.join(bits)})"


def finding_text(worst: dict, why: str | None, extra: list[str] | None = None) -> tuple[str, list[str]]:
    """(the sentence a finding's detail starts with, the "What to do" lines that explain it) for the worst CVE of an update:
    its deadline and Table 1 row, the four inputs with their values (an estimate is marked), the CVSS score for information, and
    for a row that asks for forensic triage the short check-for-compromise steps. `why` is the exposure evidence."""
    r = worst["rating"]
    lead = f"{r.deadline}, set by {worst['cve']} ({priority.basis_text(r)})."
    lines = [f"{r.deadline}. It is set by {worst['cve']}, the most urgent CVE here: {priority.basis_text(r)}",
             *priority.inputs_text(r, why)]
    if worst.get("cvss_score") is not None:
        lines.append(f"CVSS base score {worst['cvss_score']:g} ({worst.get('cvss_source') or 'CVE record'}), for information only: "
                     "it measures severity, not risk, and does not set the deadline")
    if r.vendor_lowered:
        lines.append("The vendor rates this CVE as not important, the system is not exposed and the CVE is not in the KEV catalog, "
                     "so it waits for the next upgrade")
    if r.triage:
        lines.append("This row also asks for forensic triage. Check for signs of compromise (CISA's recommended best practice):")
        lines += priority.TRIAGE_STEPS
    if r.estimated:
        lines.append(f"Values marked \"{priority.EST}\" are not CISA's: CISA has not rated this CVE yet, so DaemonSight estimates them "
                     "(Automatable from the EPSS probability, Technical impact as partial)")
    lines += extra or []
    return lead, lines


UBUNTU_CVE_URL = "https://ubuntu.com/security/"
ESM_FIX = "pro security-status\nsudo pro enable esm-infra esm-apps\nsudo apt update\nsudo apt upgrade"


def is_kernel_source(src: str, names: list[str]) -> bool:
    """The running kernel's source: `linux`, or an Ubuntu flavor (`linux-aws`, `linux-hwe-6.8`) whose binaries include the
    running kernel image (the collector lists only that one)."""
    return src == "linux" or (src.startswith("linux-") and any(isinstance(b, str) and b.startswith("linux-image-") for b in names))


def package_findings(cves: list[dict], binaries: dict[str, list[str]], pending: set[str],
                     exposure, epss_automatable: float, backend: str = "apt", reboot_pending: bool = False,
                     distro: str = "debian") -> list[Finding]:
    """One finding per source package that has a CVE an update fixes (on Ubuntu, one fixed only in Ubuntu Pro's ESM archives
    counts as a fix, and the finding says plainly that apt will not install it), or a CVE on CISA's KEV list that has no fix
    yet. Its severity and deadline come from the worst of those CVEs by CISA BOD 26-04's Table 1 (cve/priority.py).
    `exposure` is the host's (cve/exposure.Exposure); `epss_automatable` is the EPSS probability that stands in for CISA's
    Automatable rating where CISA has not rated a CVE."""
    ubuntu = distro == "ubuntu"
    label = "Ubuntu priority" if ubuntu else "Debian urgency"
    by_pkg: dict[str, list[dict]] = {}
    for c in cves:
        if c["state"] in ("fix", "esm", "nofix"):
            by_pkg.setdefault(c["source"], []).append(c)
    out = []
    for src, items in by_pkg.items():
        priority.attach(items, exposure.exposed, epss_automatable)
        fixes = [c for c in items if c["state"] == "fix"]
        esms = [c for c in items if c["state"] == "esm"]
        # What raises the finding: a fix (or an ESM fix) for a CVE, or a known-exploited CVE that nothing fixes yet.
        raised = counted(items)
        if not raised:
            continue
        top = priority.worst(c["rating"] for c in raised)
        worst = next(c for c in raised if c["rating"] is top)
        kev = [c for c in raised if c["kev"]]
        if kev:
            base = (f"{src}: {kev[0]['cve']} is being exploited (CISA KEV)" if len(kev) == 1
                    else f"{src}: {len(kev)} CVEs are being exploited (CISA KEV)")
        elif fixes:
            base = (f"{src}: {fixes[0]['cve']} is fixed in an update" if len(fixes) == 1
                    else f"{src}: {len(fixes)} CVEs fixed in an update")
        else:
            base = (f"{src}: {esms[0]['cve']} is fixed only in Ubuntu Pro (ESM)" if len(esms) == 1
                    else f"{src}: {len(esms)} CVEs fixed only in Ubuntu Pro (ESM)")
        title = f"{base}; {_lower_first(top.deadline.split(' (')[0])}"
        lead, howto = finding_text(worst, exposure.why)
        parts = [lead]
        fix = None
        installed = items[0]["installed"]
        if fixes:
            fv = _fixed_version(fixes)
            names = binaries.get(src, [])
            if backend == "dnf":
                parts.append("Fedora has security advisories for it. Install the update.")
                fix = upgrade_cmd({"backend": "dnf"})
            elif is_kernel_source(src, names) and reboot_pending:
                # The inventory lists the running kernel, and a newer one is
                # installed (pkg.reboot is open): the reboot is what applies it.
                parts.append(f"Running kernel {installed}; fixed in {fv}. A newer kernel is installed: reboot "
                             "to run it. If this stays after the reboot, that kernel doesn't have the fix yet; "
                             "install the update.")
                fix = "sudo reboot"
            else:
                kernel = is_kernel_source(src, names)
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
                if kernel:
                    fix += "\nsudo reboot"
        if esms:
            ev = _fixed_version(esms, "esm")
            parts.append(f"{len(esms)} of its CVEs {'is' if len(esms) == 1 else 'are'} fixed in {ev}, which is only in Ubuntu Pro's ESM "
                         "archives. apt does not install it unless this host has the matching Pro service on "
                         "(`pro status` shows which are on)." + ("" if fixes else " Enabling it makes the fix an ordinary update."))
            if not fixes:
                fix = ESM_FIX
        unfixed = [c for c in items if c["state"] == "nofix"]
        shown = ", ".join(_describe(c, label) for c in items[:TOP_CVES])
        parts.append(f"Top CVEs: {shown}" + (f" and {len(items) - TOP_CVES} more." if len(items) > TOP_CVES else "."))
        if unfixed and kev and not fixes and not esms:
            parts.append(f"{'Ubuntu' if ubuntu else 'Debian'} has no fix yet. See "
                         f"{(UBUNTU_CVE_URL if ubuntu else TRACKER_URL)}{kev[0]['cve']} for mitigations.")
        elif unfixed:
            parts.append(f"{len(unfixed)} more in this package have no fix yet.")
        # Basis: the CVE ids, so a new CVE in the package brings an accepted finding back. Never the severity or the deadline:
        # a change of exposure or of CISA's rating must not reopen a finding someone accepted.
        out.append(Finding("cve.package", src, top.severity, title[:300], " ".join(parts)[:3900],
                           f"/vulnerabilities#{anchor('cve', src)}", fix=fix,
                           basis=f"cves:{digest(c['cve'] for c in items)}", howto="\n".join(howto)[:3900]))
    out.sort(key=lambda f: (priority.SEV_ORDER.index(f.severity), f.title))
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
                   "/vulnerabilities#feeds", None, None,
                   "Open the Vulnerabilities page and read the feed status for the feed that failed\n"
                   "Check that the machine the hub runs on can reach that site over HTTPS (DNS, firewall, proxy)\n"
                   "The finding goes away after the next successful fetch")
