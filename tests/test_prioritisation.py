"""Prioritisation across the finding types: an update takes the worst CVE it fixes (host package, container image, firewall update),
an accepted finding stays accepted when its severity changes, and the pages show the deadline."""

import time

import pytest

from daemonsight import db
from daemonsight.cve import exposure, match, priority
from daemonsight.remote import docker_images as di, opnsense_cves

from .test_cve import cvedb, epss_gz, findings_for, inventory, kev_gz, rate_ssvc, tracker_gz  # noqa: F401 (fixtures)
from .test_docker_images import DEB12, BOOKWORM_PACKAGES, IDS, entry, matched  # noqa: F401
from .test_docker_images import cvedb as image_cvedb  # noqa: F401 (fixture: the bookworm one)


def test_a_host_package_takes_the_worst_cve_it_fixes(cvedb):
    # c-ares: CVE-2016-5180 (EPSS 8.7%), CVE-2017-1000381 (3.3%), CVE-2023-31124 (0.9%, Debian: unimportant). Give each a rating.
    rate_ssvc(cvedb, "CVE-2017-1000381", "poc", "yes", "total")          # not exposed: N/N/Y/total, row 13, 60 days
    rate_ssvc(cvedb, "CVE-2016-5180", "none", "no", "partial")           # N/N/N/partial, row 16, next upgrade
    rate_ssvc(cvedb, "CVE-2023-31124", "none", "yes", "total")           # would be row 13, but the vendor rating lowers it
    src = [["c-ares", "1.10.0-1", []]]
    f = findings_for(cvedb, src)["c-ares"]
    assert f.severity == "medium" and f.detail.startswith("Fix within 60 days (CISA BOD 26-04 timeline), set by CVE-2017-1000381")
    # Exposed, the unimportant one is no longer lowered: Y/N/Y/total, row 5, 3 days. The worst is now it.
    e = findings_for(cvedb, src, exposed=True)["c-ares"]
    assert e.severity == "critical" and "set by CVE-2017-1000381" in e.detail and "row 5" in e.detail


def test_accepted_findings_stay_accepted_when_the_severity_changes(cvedb, tmp_path):
    rate_ssvc(cvedb, "CVE-2026-111497", "active", "no", "total")
    src = [["brotli", "1.0.9-2", ["libbrotli1"]]]
    conn = db.connect_writer(tmp_path / "state.db")
    conn.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('web1', 'x', 0)")
    now = time.time()

    def reconcile(exposed):
        f = findings_for(cvedb, src, exposed=exposed)["brotli"]
        db.reconcile_findings(conn, "web1", now, [f], only_prefix="cve.package")
        return f

    first = reconcile(False)
    assert first.severity == "high"
    assert db.accept_finding(conn, "web1", "cve.package", "brotli", "patched on the 3rd", "admin", now)
    active, held = db.findings_state(conn, "web1")
    assert not active and [h["key"] for h in held] == ["brotli"]
    # The host becomes exposed: the same CVE is critical now, with a new deadline, and the finding stays accepted.
    second = reconcile(True)
    assert second.severity == "critical" and second.title != first.title and second.basis == first.basis
    active, held = db.findings_state(conn, "web1")
    assert not active and held[0]["severity"] == "critical" and held[0]["accepted"]["changed"] is False
    # CISA's rating changes too: still accepted. A new CVE in the package brings it back.
    rate_ssvc(cvedb, "CVE-2026-111497", "active", "yes", "total")
    reconcile(True)
    assert not db.findings_state(conn, "web1")[0]
    cvedb.execute("INSERT OR REPLACE INTO match (host, source, cve, state) VALUES ('h', 'brotli', 'CVE-2026-9999', 'fix')")
    changed = match.package_findings(match.host_cves(cvedb, "h", ("fix", "nofix")), {}, set(), exposure.Exposure(False, "t"), 0.04)[0]
    assert changed.basis != first.basis
    conn.close()


def test_an_image_and_a_firewall_take_the_worst_cve_too(image_cvedb):
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES)
    cves = matched(image_cvedb, [e])
    cvedb_cves = cves["images"][e["image_id"]]["cves"]
    by = {c["cve"]: c for c in cvedb_cves if c["state"] == "fix"}
    assert len(by) == 3
    s = di.cve_summary(cvedb_cves, 0.04, exposure.Exposure(False, "test"))
    assert s["worst"]["cve"] == "CVE-2026-111497" and s["severity"] == s["worst"]["rating"].severity == "high"
    assert s["fixable"] == sorted(s["fixable"], key=priority.sort_key)
    # The same CVEs on a firewall (always exposed): the image's worst is its first, and the summary's severity is that CVE's.
    fw = opnsense_cves.summary([{**c, "release": "26.1.4", "line": "", "via": []} for c in by.values()], 0.04)
    assert fw["worst"] is fw["fixable"][0] and fw["severity"] == fw["worst"]["rating"].severity
    assert fw["exposure"].exposed and all(c["rating"].exposed for c in fw["fixable"])
    # An advisory with no CVE is outside the table: an interim floor, medium, or high when GitHub rates it high or critical.
    quiet = opnsense_cves.summary([], 0.04, [{"ref": "GHSA:x", "cves": [], "severity": "low"}])
    assert quiet["severity"] == "medium" and quiet["worst"] is None
    loud = opnsense_cves.summary([], 0.04, [{"ref": "GHSA:x", "cves": [], "severity": "critical"}])
    assert loud["severity"] == "high"
    # A CVE that ranks higher is not lowered by the floor.
    top = opnsense_cves.summary([{**by["CVE-2026-111497"], "release": "r", "line": "", "via": []}], 0.04, [{"ref": "GHSA:x", "cves": [], "severity": "low"}])
    assert top["severity"] == "critical"          # a KEV CVE on a firewall (exposed, EPSS 83% so estimated automatable): row 2, 3 days


@pytest.mark.parametrize("auto", [0.04, 0.9])
def test_the_estimate_is_labelled_in_every_finding_text(cvedb, auto):
    f = findings_for(cvedb, [["c-ares", "1.10.0-1", []]], auto=auto)["c-ares"]
    assert "estimated by DaemonSight" in f.howto
    assert 'Values marked "estimated by DaemonSight" are not CISA\'s' in f.howto
