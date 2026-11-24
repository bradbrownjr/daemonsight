"""The CVEs a firewall's pending update fixes, for its finding and its updates card.

The hub's CVE chore (cve/run.py) matches each OPNsense system whose last firmware check shows a new release against the
project's changelog (cve/opnsense.py), under the pseudo-host `opnsense:<system id>`, the way container images are matched
under `docker:<host>:<image id>`. This module reads those matches back: `load` for one firewall's stored firmware status,
`summary` for the ranking and the severity. Both the finding (opnsense_rules.firmware_rules) and the page use them, so
they always agree.

Severity follows the Debian host rule (cve/match.py `package_findings`) and the image rule (docker_images.cve_summary): a
fixable CVE on CISA's KEV list, or one with an EPSS score at or above `[cve] epss_high`, is High; any other fixable CVE is
Medium. Every CVE found here is fixable, because it is listed as fixed by the update the firewall offers.
"""

from __future__ import annotations

from .. import settings
from ..cve import match, opnsense, store

SHOWN = 4                  # CVEs named in a finding's text
LIST_MAX = 60              # rows on the page


def cve_url(cve: str) -> str:
    return f"https://www.cve.org/cverecord?id={cve}"          # the changelog repository's Links/CVE


def advisory_url(ref: str) -> str | None:
    """The URL the changelog repository's Links/ files give an advisory (Links/GHSA and Links/FREEBSD-SA)."""
    kind, _, rest = ref.partition(":")
    if kind == "GHSA":
        return f"https://github.com/opnsense/core/security/advisories/{rest}"
    if kind == "FREEBSD-SA":
        return f"https://www.freebsd.org/security/advisories/FreeBSD-SA-{rest}.asc"
    return None


def _feed_state(cdb) -> dict:
    r = cdb.execute("SELECT status, ok_at, detail FROM feed WHERE name = 'opnsense-changelog'").fetchone()
    if r is None:
        return {"ok_at": None, "error": None, "tried": False}
    return {"ok_at": r["ok_at"], "error": r["detail"] if r["status"] == "error" else None, "tried": True}


def load(cfg, state_conn, host: str, fw: dict | None) -> dict:
    """What the chore found for this firewall's pending update:
    {"state": "none" | "off" | "unmapped" | "pending" | "ok", "plan", "feed", "epss_high", ...}.
    `none`: nothing is pending. `off`: CVE matching is switched off. `unmapped`: the pending update has no OPNsense release in
    it, or a version this cannot place (`plan["why"]`). `pending`: the changelog has not been read for it yet. `ok` adds
    "cves" (every match, with its changelog section and line), "advisories" (issues named without a CVE id), "releases"
    (the release files in the range) and "note"."""
    p = opnsense.plan(fw)
    out: dict = {"state": "none", "plan": p, "feed": {"ok_at": None, "error": None, "tried": False}, "epss_high": 0.10,
                 "cves": [], "advisories": [], "releases": [], "note": ""}
    if not p["ok"]:
        out["state"] = "none" if p["why"] == "nothing" else "unmapped"
        return out
    eff = settings.effective(cfg, state_conn)
    out["epss_high"] = eff.cve.epss_high
    if not eff.cve.enabled:
        out["state"] = "off"
        return out
    out["state"] = "pending"
    cdb = store.connect_reader(cfg.cve_db_path)
    if cdb is None:
        return out
    try:
        out["feed"] = _feed_state(cdb)
        ph = opnsense.pseudo_host(host)
        row = cdb.execute("SELECT inv_hash, note FROM matched WHERE host = ?", (ph,)).fetchone()
        if row is None or row["inv_hash"] != opnsense.plan_hash(p):
            return out
        lines = {(r["version"], r["ref"]): r["line"] for r in opnsense.fixes_between(cdb, p["installed"], p["offered"], "cve")}
        dates = {r["version"]: r["date"] for r in cdb.execute("SELECT version, date FROM opn_release")}
        cves = match.host_cves(cdb, ph, ("fix",))
        for c in cves:
            c["release"] = c["fixed"]
            c["line"] = lines.get((c["fixed"], c["cve"]), "")
            c["date"] = dates.get(c["fixed"].split("_")[0])
            c["url"] = cve_url(c["cve"])
            c["changelog"] = opnsense.changelog_url(c["fixed"])
        seen, adv = set(), []
        for r in opnsense.fixes_between(cdb, p["installed"], p["offered"], "adv"):
            if r["ref"] not in seen:
                seen.add(r["ref"])
                adv.append({"ref": r["ref"], "version": r["version"], "line": r["line"], "url": advisory_url(r["ref"])})
        out.update({"state": "ok", "cves": cves, "advisories": adv, "note": row["note"] or "",
                    "releases": opnsense.releases_between(cdb, p["installed"], p["offered"])})
    finally:
        cdb.close()
    return out


def summary(cves: list[dict], epss_high: float) -> dict:
    """Counts and the worst CVEs, ranked as a host's are (KEV, then EPSS). Every one is fixable by the update."""
    ranked = sorted(cves, key=match.rank_key)
    kev = [c for c in ranked if c["kev"]]
    hot = [c for c in ranked if not c["kev"] and (c["epss"] or 0) >= epss_high]
    return {"fixable": ranked, "kev": kev, "hot": hot, "severity": "high" if kev or hot else "medium" if ranked else None}


def headline(n: int, kev: int, lower: bool = False) -> str:
    """"Fixes 5 CVEs (2 known exploited)": the card's line, and (lower-case, `lower`) part of the finding's title."""
    text = f"Fixes {n} {'CVE' if n == 1 else 'CVEs'}" + (f" ({kev} known exploited)" if kev else "")
    return text[0].lower() + text[1:] if lower else text


def describe(c: dict) -> str:
    bits = []
    if c["kev"]:
        bits.append("exploited, CISA KEV")
    bits.append(match.pct(c["epss"]))
    bits.append(f"fixed in {c['release']}")
    return f"{c['cve']} ({', '.join(bits)})"
