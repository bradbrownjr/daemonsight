"""The CVEs a firewall's pending update fixes, for its finding and its updates card.

The hub's CVE chore (cve/run.py) matches each OPNsense system whose last firmware check shows a new release against the
project's changelog (cve/opnsense.py), under the pseudo-host `opnsense:<system id>`, the way container images are matched
under `docker:<host>:<image id>`. This module reads those matches back: `load` for one firewall's stored firmware status,
`summary` for the ranking and the severity. Both the finding (opnsense_rules.firmware_rules) and the page use them, so
they always agree.

Severity follows the host and image rule (cve/priority.py, CISA BOD 26-04): the update takes the worst of the CVEs it fixes,
rated for a firewall, which is always publicly exposed (cve/exposure.py `FIREWALL`: a network device, which CISA's guidance
treats as public). Every CVE found here is fixable, because it is listed as fixed by the update the firewall offers.

The changelog also names security advisories (FreeBSD and GitHub) with no CVE id. The hub resolves them to CVE ids where the
advisory's publisher names any (cve/advisories.py); those CVEs are in the list above, with the advisory as the evidence ("via
FreeBSD-SA-26:74.ktls"). An advisory that names none, or has not been resolved yet, stays in the advisories list, and
`summary` rates it with an interim floor that is outside the BOD 26-04 table: Medium at least (own choice: a security fix that
cannot be ranked is not routine; the guidance says "longer timelines are acceptable" for what has no CVE id), and High when
GitHub rates it High or Critical (GitHub's own rating of OPNsense's advisory). Errata notices and plugin notes are not counted.
"""

from __future__ import annotations

from .. import settings
from ..cve import advisories, exposure, match, opnsense, priority, store

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


def _matches(cdb, ph: str, p: dict, row) -> dict:
    """The matched CVEs, advisories and releases of a plan the chore has stored under pseudo-host `ph`."""
    lines = {(r["version"], r["ref"]): r["line"] for r in opnsense.fixes_between(cdb, p["installed"], p["offered"], "cve")}
    dates = {r["version"]: r["date"] for r in cdb.execute("SELECT version, date FROM opn_release")}
    cves = match.host_cves(cdb, ph, ("fix",))
    for c in cves:
        c["release"] = c["fixed"]
        c["line"] = lines.get((c["fixed"], c["cve"]), "")
        c["date"] = dates.get(c["fixed"].split("_")[0])
        c["url"] = cve_url(c["cve"])
        c["changelog"] = opnsense.changelog_url(c["fixed"])
    adv = []
    via: dict[str, list[dict]] = {}
    for a in opnsense.advisories_between(cdb, p["installed"], p["offered"]):
        a["url"] = advisory_url(a["ref"])
        a["label"] = advisories.label(a["ref"])
        adv.append(a)
        for cve in a["cves"]:
            via.setdefault(cve, []).append(a)
    for c in cves:
        c["direct"] = bool(c["line"])
        c["via"] = [{"label": a["label"], "url": a["url"]} for a in via.get(c["cve"], [])]
        if not c["line"] and via.get(c["cve"]):
            c["line"] = via[c["cve"]][-1]["line"]          # named by an advisory only: its changelog bullet is the line
    return {"state": "ok", "cves": cves, "advisories": adv, "note": row["note"] or "",
            "releases": opnsense.releases_between(cdb, p["installed"], p["offered"])}


def load(cfg, state_conn, host: str, fw: dict | None) -> dict:
    """What the chore found for this firewall's pending update:
    {"state": "none" | "off" | "unmapped" | "pending" | "ok", "plan", "feed", "epss_automatable", "unseen", ...}.
    `none`: nothing is pending. `off`: CVE matching is switched off. `unmapped`: the pending update has no OPNsense release in
    it, or a version this cannot place (`plan["why"]`). `pending`: the changelog has not been read for it yet. `ok` adds
    "cves" (every match, with its changelog section and line), "advisories" (issues named without a CVE id), "releases"
    (the release files in the range) and "note".
    `unseen` is None, or what the changelog holds above what the firewall has seen (`opnsense.unseen_plan`): {"state": "none" |
    "pending" | "ok", "plan", "newer_series"} and, for `ok`, the same "cves", "advisories", "releases" and "note" for the range
    from the installed version to the newest one. The caller decides whether the firewall's last check is old enough
    (`unseen_state`)."""
    p = opnsense.plan(fw)
    out: dict = {"state": "none", "plan": p, "feed": {"ok_at": None, "error": None, "tried": False}, "epss_automatable": 0.04,
                 "cves": [], "advisories": [], "releases": [], "note": "", "unseen": None}
    if not p["ok"]:
        out["state"] = "none" if p["why"] == "nothing" else "unmapped"
    eff = settings.effective(cfg, state_conn)
    out["epss_automatable"] = eff.cve.epss_automatable
    priority.use(eff.data_dir)
    if not eff.cve.enabled:
        if p["ok"]:
            out["state"] = "off"
        return out
    if p["ok"]:
        out["state"] = "pending"
    cdb = store.connect_reader(cfg.cve_db_path)
    if cdb is None:
        return out
    try:
        out["feed"] = _feed_state(cdb)
        if p["ok"]:
            row = cdb.execute("SELECT inv_hash, note FROM matched WHERE host = ?", (opnsense.pseudo_host(host),)).fetchone()
            if row is not None and row["inv_hash"] == opnsense.plan_hash(p):
                out.update(_matches(cdb, opnsense.pseudo_host(host), p, row))
        u = opnsense.unseen_plan(cdb, fw)
        if u["ok"] or u["newer_series"]:
            un = {"state": "pending" if u["ok"] else "none", "plan": u, "newer_series": u["newer_series"], "cves": [],
                  "advisories": [], "releases": [], "note": ""}
            if u["ok"]:
                row = cdb.execute("SELECT inv_hash, note FROM matched WHERE host = ?", (opnsense.unseen_host(host),)).fetchone()
                if row is not None and row["inv_hash"] == opnsense.plan_hash(u):
                    un.update(_matches(cdb, opnsense.unseen_host(host), u, row))
            out["unseen"] = un
    finally:
        cdb.close()
    return out


# --- a release the firewall has not been offered ----------------------------------------------------------------------------------

STALE_DAYS = 2        # DaemonSight's choice (the owner's): a firewall that has not checked for two days may have missed a release


def unseen_state(fw: dict | None, cves: dict | None, now: float) -> dict | None:
    """The `opnsense.unseen_release` condition, shared by the finding and the card: a newer release exists in the firewall's
    series than it runs and than its last check showed, AND that check is `STALE_DAYS` or more old, missing or unreadable.
    Returns {"version", "plan", "cves", "advisories", "epss_automatable", "checked" (Unix time or None), "last_check", "newer_series"}
    (`version` is "" when only a newer series exists, which is a line on the card and no finding), or None when the check is
    recent or nothing newer is known. A finding needs `version` and the matched CVEs (`ready`)."""
    from .opnsense import last_check_ts
    un = (cves or {}).get("unseen")
    if not un or not fw:
        return None
    ts = last_check_ts(fw.get("last_check"))
    if ts is not None and now - ts < STALE_DAYS * 86400:
        return None
    ok = un["plan"].get("ok")
    return {"version": un["plan"]["offered"] if ok else "", "plan": un["plan"], "cves": un["cves"], "advisories": un["advisories"],
            "epss_automatable": cves["epss_automatable"], "checked": ts, "last_check": fw.get("last_check") or "", "newer_series": un["newer_series"],
            "ready": ok and un["state"] == "ok", "note": un.get("note") or ""}


def fixes_phrase(n: int, adv: int) -> str:
    """"27 CVEs and 2 other security advisories", "2 security advisories" (no CVE) or "3 CVEs": what an update fixes. `adv` is
    the number of security advisories that name no CVE."""
    cves = f"{n} {'CVE' if n == 1 else 'CVEs'}"
    if not adv:
        return cves
    word = "security advisory" if adv == 1 else "security advisories"
    return f"{cves} and {adv} other {word}" if n else f"{adv} {word}"


def unseen_title(st: dict, now: float | None = None) -> str:
    """"26.7.10 is out (fixes 3 CVEs and 2 other security advisories); the firewall hasn't checked since Nov 18" (the finding's
    title and the card's line)."""
    import time
    s = summary(st["cves"], st["epss_automatable"], st.get("advisories"))
    n, k = len(s["fixable"]), len(s["unresolved"])
    head = f"{st['version']} is out" + (f" (fixes {fixes_phrase(n, k)})" if n or k else "")
    if st["checked"] is None:
        return head + "; the firewall's last check time is unknown"
    t = time.gmtime(st["checked"])
    year = time.gmtime(now if now is not None else time.time()).tm_year
    return head + "; the firewall hasn't checked since " + time.strftime("%b %-d", t) + ("" if t.tm_year == year else f" {t.tm_year}")


def summary(cves: list[dict], epss_automatable: float, advisories: list[dict] | None = None) -> dict:
    """Counts and the worst CVEs, most urgent first (CISA BOD 26-04 timeline, then EPSS: cve/priority.py), each CVE gaining its
    "rating". A firewall is always publicly exposed. Every CVE is fixable by the update, so the update's severity is the worst
    CVE's. `advisories` are the security advisories of the range (`opnsense.advisories_between`, as `load` returns them). Those
    that name no CVE (`unresolved`: not asked about yet, failed, or naming none) are outside the table, so an interim floor
    applies: the severity is at least Medium, and High when GitHub rates one High or Critical. A CVE that ranks higher is not
    lowered by any of this. Returns {"fixable", "kev", "unresolved", "severity", "worst" (the most urgent CVE or None),
    "exposure"}."""
    ranked = priority.attach(list(cves), True, epss_automatable)
    kev = [c for c in ranked if c["kev"]]
    unresolved = [a for a in (advisories or []) if not a.get("cves")]
    sev = ranked[0]["rating"].severity if ranked else None
    if unresolved:
        sev = priority.worse_severity(sev, "high" if any(a.get("severity") in ("high", "critical") for a in unresolved) else "medium")
    return {"fixable": ranked, "kev": kev, "unresolved": unresolved, "severity": sev,
            "worst": ranked[0] if ranked else None, "exposure": exposure.FIREWALL}


def headline(n: int, kev: int, lower: bool = False, adv: int = 0) -> str:
    """"Fixes 5 CVEs (2 known exploited) and 2 other security advisories": the card's line, and (lower-case, `lower`) part of
    the finding's title. `adv` counts the advisories with no CVE; with no CVE at all: "Fixes 2 security advisories"."""
    if n:
        text = "Fixes " + fixes_phrase(n, 0) + (f" ({kev} known exploited)" if kev else "")
        if adv:
            text += f" and {adv} other security {'advisory' if adv == 1 else 'advisories'}"
    else:
        text = "Fixes " + fixes_phrase(0, adv)
    return text[0].lower() + text[1:] if lower else text


def describe(c: dict) -> str:
    bits = []
    if c["kev"]:
        bits.append("exploited, CISA KEV")
    bits.append("EPSS " + match.pct(c["epss"], c.get("pctile")) if c["epss"] is not None else match.pct(None))
    if c.get("rating") is not None:
        bits.append(c["rating"].deadline.split(" (")[0][0].lower() + c["rating"].deadline.split(" (")[0][1:])
    bits.append(f"fixed in {c['release']}")
    if c.get("via") and not c.get("direct"):
        bits.append("via " + ", ".join(v["label"] for v in c["via"][:2]))
    return f"{c['cve']} ({', '.join(bits)})"
