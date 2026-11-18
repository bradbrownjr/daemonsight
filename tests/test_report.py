"""Fixes and bases on findings, accepting findings with a note, and the per-host report."""

import re
import sqlite3
import time
from datetime import date

import pytest
from fastapi.testclient import TestClient

from daemonsight import db, findings, hub
from daemonsight.config import Config
from daemonsight.cve import match
from daemonsight.db import Snapshot
from daemonsight.findings import Finding
from daemonsight.web import report, views
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_collector import WIDE, container
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)
from .test_packages import auto_rules, apt_auto, data as pkg_data, rules as pkg_rules, upd
from .test_phase2 import listener, ports_data
from .test_web import seeded  # noqa: F401 (fixture)


def snap(source, d):
    return Snapshot(source, time.time(), True, None, d)


# ---- fix, step and basis on the rules ---------------------------------------

def test_package_rules_carry_their_commands_and_bases():
    sec = pkg_rules(pkg_data(updates=[upd("a", True), upd("b", True)], security_count=2))["pkg.security_updates"]
    assert sec.fix == "sudo apt upgrade" and findings.step_of(sec.rule) == "upgrade"
    # The title's count drifts; the basis is the set of packages.
    more = pkg_rules(pkg_data(updates=[upd("a", True), upd("b", True), upd("c", True)],
                              security_count=3))["pkg.security_updates"]
    assert more.title != sec.title and more.basis != sec.basis
    same = pkg_rules(pkg_data(updates=[upd("b", True), upd("a", True)], security_count=2))["pkg.security_updates"]
    assert same.basis == sec.basis

    # Regular updates: the basis ignores which packages are waiting.
    a = pkg_rules(pkg_data(updates=[upd("x")]))["pkg.updates"]
    b = pkg_rules(pkg_data(updates=[upd("x"), upd("y")]))["pkg.updates"]
    assert a.fix == "sudo apt upgrade" and a.basis == b.basis and a.title != b.title

    dnf = pkg_rules(pkg_data(backend="dnf", updates=[upd("x", True)], security_count=1))
    assert dnf["pkg.security_updates"].fix == "sudo dnf upgrade --refresh"

    kernel = {"managed": True, "running": "6.1", "newer_installed": "6.2"}
    r = pkg_rules(pkg_data(reboot={"required": True, "pkgs": []}, kernel=kernel))["pkg.reboot"]
    r2 = pkg_rules(pkg_data(reboot={"required": True, "pkgs": []},
                            kernel={**kernel, "newer_installed": "6.3"}))["pkg.reboot"]
    assert r.fix == "sudo reboot" and findings.step_of(r.rule) == "reboot" and r.basis != r2.basis

    svc = pkg_rules(pkg_data(needrestart={"installed": True, "services": ["a.service"]}))["pkg.restart"]
    assert svc.fix == "sudo needrestart -r a" and findings.step_of(svc.rule) == "restart"

    old = time.time() - 5 * 86400
    l1 = pkg_rules(pkg_data(lists_age=old, periodic_update=False))["pkg.lists_stale"]
    l2 = pkg_rules(pkg_data(lists_age=time.time() - 9 * 86400, periodic_update=False))["pkg.lists_stale"]
    assert l1.title != l2.title and l1.basis == l2.basis == "lists"
    off = auto_rules(pkg_data(auto_updates=apt_auto()))["pkg.auto_updates_off"]
    assert off.fix == "sudo apt install unattended-upgrades" and findings.step_of(off.rule) == "auto-updates"


def test_rules_with_no_single_command_have_no_fix(cfg):
    snaps = {
        "docker": snap("docker", {"containers": [container("db", ports=WIDE), container("gone", "exited", 1)]}),
        "ports": snap("ports", ports_data([listener(8000, process="python3")])),
    }
    got = {(f.rule, f.key): f for f in findings.evaluate(snaps, cfg)}
    bypass = got[("expose.docker_bypass", "5432/tcp")]
    assert bypass.fix is None and bypass.basis == "5432/tcp|db"
    assert got[("ctr.down", "gone")].fix is None and got[("ctr.down", "gone")].basis is None
    port = got[("expose.unexpected", "8000/tcp")]
    assert port.fix is None and port.basis.startswith("8000/tcp|python3|")
    other = findings.evaluate({"ports": snap("ports", ports_data([listener(8000, process="node")]))}, cfg)
    assert other[0].basis != port.basis  # a different process on the port is a different finding


def test_disk_basis_ignores_the_percentage(cfg):
    def run(pct):
        d = {"disks": [{"mount": "/", "device": "x", "fstype": "ext4", "total": 1, "used": 1, "percent": pct}]}
        return findings.sys_disk({"system": snap("system", {**d, "cpu": {}, "memory": {}})}, cfg, {})[0]
    a, b, c = run(91.0), run(93.0), run(97.0)
    assert a.title != b.title and a.basis == b.basis == "/|medium"
    assert c.basis == "/|high"  # crossing into High is a change


def test_fedora_upgrade_has_the_three_commands():
    from .test_fedora import F43
    cfg = Config()
    ctx = {"today": date(2026, 10, 3)}
    f = findings.os_eol_soon({"system": snap("system", F43)}, cfg, ctx)[0]
    assert f.fix.split("\n")[-1] == "sudo dnf system-upgrade reboot"
    assert findings.step_of("os.eol_soon") == "os-upgrade"


def cve_row(cve, state="fix", source="openssl", kev=False):
    return {"source": source, "cve": cve, "state": state, "installed": "1.0", "fixed": "1.1", "urgency": "medium",
            "epss": 0.0, "pctile": 0.0, "kev": kev, "kev_name": None, "ransomware": None, "descr": ""}


def test_kernel_cves_join_the_reboot_step():
    k = [cve_row("CVE-2026-0009", source="linux")]
    bins = {"linux": ["linux-image-6.1.0-53-cloud-amd64"]}
    waiting = match.package_findings(k, bins, set(), 0.5, reboot_pending=True)[0]
    assert waiting.fix == "sudo reboot" and "Running kernel" in waiting.detail
    assert findings.step_of(waiting.rule, waiting.key) == "reboot"
    behind = match.package_findings(k, bins, {"linux-image-6.1.0-53-cloud-amd64"}, 0.5)[0]
    assert behind.fix == "sudo apt upgrade\nsudo reboot"
    assert findings.step_of("cve.package", "openssl") == "upgrade"


def test_cve_package_fix_and_basis():
    one = match.package_findings([cve_row("CVE-2026-0001")], {"openssl": ["libssl3"]}, {"libssl3"}, 0.5)[0]
    two = match.package_findings([cve_row("CVE-2026-0001"), cve_row("CVE-2026-0002")],
                                 {"openssl": ["libssl3"]}, {"libssl3"}, 0.5)[0]
    assert one.fix == "sudo apt upgrade" and findings.step_of(one.rule) == "upgrade"
    assert one.basis != two.basis  # a new CVE brings an accepted finding back
    nofix = match.package_findings([cve_row("CVE-2026-0003", "nofix", kev=True)], {}, set(), 0.5)[0]
    assert nofix.fix is None  # no fix exists yet
    dnf = match.package_findings([cve_row("CVE-2026-0001")], {}, set(), 0.5, "dnf")[0]
    assert dnf.fix == "sudo dnf upgrade --refresh"


def test_fingerprint_follows_the_basis_not_the_title():
    a = Finding("sys.disk", "/", "medium", "Disk / is 86% full", "d", basis="/|medium")
    b = Finding("sys.disk", "/", "medium", "Disk / is 88% full", "d", basis="/|medium")
    assert findings.fingerprint(a.rule, a.key, a.basis, a.title) == findings.fingerprint(b.rule, b.key, b.basis, b.title)
    c = Finding("x.y", "k", "low", "t1", "d")
    d = Finding("x.y", "k", "low", "t2", "d")
    assert findings.fingerprint(c.rule, c.key, c.basis, c.title) != findings.fingerprint(d.rule, d.key, d.basis, d.title)


# ---- storage ----------------------------------------------------------------

V3_SCHEMA = """
CREATE TABLE findings (id INTEGER PRIMARY KEY, host TEXT NOT NULL, rule TEXT NOT NULL, key TEXT NOT NULL,
    severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, link TEXT, first_seen REAL NOT NULL,
    last_seen REAL NOT NULL, resolved_at REAL);
CREATE UNIQUE INDEX findings_open ON findings (host, rule, key) WHERE resolved_at IS NULL;
INSERT INTO findings (host, rule, key, severity, title, detail, link, first_seen, last_seen)
    VALUES ('h', 'pkg.updates', 'updates', 'low', '2 updates waiting', 'a, b. Run: sudo apt upgrade', NULL, 1, 2);
PRAGMA user_version=3;
"""


def test_migration_from_schema_3(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript(V3_SCHEMA)
    raw.close()
    conn = db.connect_writer(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION == 7
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    assert {"fix", "basis", "howto"} <= cols       # schema 6 added howto
    # Schema 7: Shodan's view of each public address.
    assert {"ip", "first_try", "checked_at", "fetched_at", "status", "data", "error"} == \
        {r[1] for r in conn.execute("PRAGMA table_info(outside)")}
    # Schema 5: remote systems.
    assert "kind" in {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
    assert {"id", "kind", "url", "enabled", "tls", "tls_pin", "interval", "last_ok", "last_error", "fails"} <= \
        {r[1] for r in conn.execute("PRAGMA table_info(remotes)")}
    assert {r[1] for r in conn.execute("PRAGMA table_info(accepted)")} == {
        "host", "rule", "key", "fingerprint", "note", "accepted_at", "accepted_by"}
    row = conn.execute("SELECT * FROM findings").fetchone()
    assert row["fix"] is None and row["basis"] is None and row["howto"] is None  # old rows get NULL
    # The next run rewrites the row with the new fields.
    db.reconcile_findings(conn, "h", 3, [Finding("pkg.updates", "updates", "low", "2 updates waiting", "d",
                                                 None, "sudo apt upgrade", "updates")])
    assert conn.execute("SELECT fix, basis FROM findings").fetchone()["fix"] == "sudo apt upgrade"
    db.migrate(conn)  # twice is fine


def test_reader_copes_with_an_unmigrated_database(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript(V3_SCHEMA)
    raw.close()
    conn = db.connect_reader(path)
    active, held = db.findings_state(conn, "h")
    assert [d["rule"] for d in active] == ["pkg.updates"] and active[0]["fix"] is None and held == []
    assert active[0]["howto"] is None           # a reader that finds no howto column still works


V5_SCHEMA = """
CREATE TABLE findings (id INTEGER PRIMARY KEY, host TEXT NOT NULL, rule TEXT NOT NULL, key TEXT NOT NULL,
    severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, link TEXT, first_seen REAL NOT NULL,
    last_seen REAL NOT NULL, resolved_at REAL, fix TEXT, basis TEXT);
INSERT INTO findings (host, rule, key, severity, title, detail, first_seen, last_seen)
    VALUES ('h', 'unraid.disk_full', 'disk1', 'high', 'disk1 is 96% full', 'd', 1, 2);
PRAGMA user_version=5;
"""


def test_migration_from_schema_5_adds_howto(tmp_path):
    path = tmp_path / "v5.db"
    raw = sqlite3.connect(path)
    raw.executescript(V5_SCHEMA)
    raw.close()
    conn = db.connect_writer(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert "outside" in {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "howto" in {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    assert conn.execute("SELECT howto FROM findings").fetchone()["howto"] is None
    db.reconcile_findings(conn, "h", 3, [Finding("unraid.disk_full", "disk1", "high", "disk1 is 96% full", "d",
                                                 None, None, "disk1:high", "one\ntwo")])
    assert conn.execute("SELECT howto FROM findings").fetchone()["howto"] == "one\ntwo"
    db.migrate(conn)


# ---- accepting findings on a hub --------------------------------------------

DISK = dict(rule="sys.disk", key="/", severity="medium", link="/#system")


def disk(pct, basis="/|medium", **kw):
    return Finding(DISK["rule"], DISK["key"], kw.get("severity", "medium"), f"Disk / is {pct}% full",
                   "Threshold is 85%.", "/#system", basis=basis)


UPDATES = Finding("pkg.updates", "updates", "low", "2 updates waiting", "a, b. Install them.", "/packages#other",
                  fix="sudo apt upgrade", basis="updates")
REBOOT = Finding("pkg.reboot", "reboot", "medium", "Reboot needed", "libc6", "/packages#reboot", fix="sudo reboot",
                 basis="reboot:")
PORT = Finding("expose.unexpected", "8000/tcp", "critical", "Port 8000/tcp is reachable from the internet",
               "python3 listens. <b>x</b>", "/exposure#port-8000-tcp", basis="8000/tcp|python3|critical")


@pytest.fixture
def hubapp(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    now = time.time()
    db.put_snapshot(conn, "testhost", "system", now, True, None, {
        "os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-18-amd64", "virt": None,
        "boot_time": now - 86400 * 3, "cpu": {"percent": 1.0, "count": 1, "load": [0, 0, 0]},
        "memory": {"total": 1, "available": 1, "percent": 1.0}, "disks": [], "net": {}})
    db.reconcile_findings(conn, "testhost", now, [disk(86), UPDATES, REBOOT, PORT])
    conn.execute("UPDATE hosts SET last_seen = ?, version = ? WHERE id = 'testhost'", (now, "0.1.0 (abc1234)"))
    app = create_app(hub_cfg)
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    yield c, conn, hub_cfg
    conn.close()


def accept(c, rule, key, note="known and fine", next_="/h/testhost/#finding-x", **headers):
    return c.post("/h/testhost/findings/accept", data={"rule": rule, "key": key, "note": note, "next": next_},
                  headers=headers)


def counts_text(c):
    return c.get("/").text


def test_accept_needs_login_and_refuses_cross_site(hubapp, hub_cfg):
    c, conn, _ = hubapp
    anon = TestClient(create_app(hub_cfg), follow_redirects=False)
    r = accept(anon, "pkg.updates", "updates")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0

    r = accept(c, "pkg.updates", "updates", **{"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    r = c.post("/h/testhost/findings/unaccept", data={"rule": "pkg.updates", "key": "updates"},
               headers={"Sec-Fetch-Site": "same-site"})
    assert r.status_code == 403
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0
    # A browser's own same-origin post and one without the header (curl) pass.
    assert accept(c, "pkg.updates", "updates", **{"Sec-Fetch-Site": "same-origin"}).status_code == 303
    assert accept(c, "pkg.reboot", "reboot").status_code == 303


def test_accept_checks_host_and_finding(hubapp):
    c, conn, _ = hubapp
    assert c.post("/h/nobody/findings/accept", data={"rule": "a.b", "key": "k", "note": "x"}).status_code == 404
    assert c.post("/h/..%2Fx/findings/accept", data={"rule": "a.b", "key": "k", "note": "x"}).status_code == 404
    r = accept(c, "pkg.updates", "nope")
    assert r.status_code == 303
    assert "no longer open" in c.get("/h/testhost/").text
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0


@pytest.mark.parametrize("note", ["", "   ", "x" * 501, "bad\x1bescape", "rtl‮text"])
def test_note_is_validated(hubapp, note):
    c, conn, _ = hubapp
    r = accept(c, "pkg.updates", "updates", note=note)
    assert r.status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0
    assert "note of 1 to 500 characters" in c.get(r.headers["location"]).text


def test_note_limits_are_inclusive(hubapp):
    c, conn, _ = hubapp
    assert accept(c, "pkg.updates", "updates", note="x").status_code == 303
    assert accept(c, "pkg.reboot", "reboot", note="y" * 500).status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 2


def test_accept_and_unaccept_flow(hubapp):
    c, conn, cfg = hubapp
    r = accept(c, "expose.unexpected", "8000/tcp", note="Public on purpose; fronted by the proxy",
               next_="/h/testhost/#finding-expose.unexpected-8000_tcp")
    assert r.status_code == 303
    assert r.headers["location"] == "/h/testhost/#finding-expose.unexpected-8000_tcp"  # back to the anchor
    row = conn.execute("SELECT * FROM accepted").fetchone()
    assert (row["host"], row["rule"], row["key"], row["accepted_by"]) == ("testhost", "expose.unexpected",
                                                                         "8000/tcp", "admin")
    assert row["note"] == "Public on purpose; fronted by the proxy"
    assert row["fingerprint"] == findings.fingerprint(PORT.rule, PORT.key, PORT.basis, PORT.title)

    page = c.get("/h/testhost/").text  # the flash shows once
    assert "Accepted: Port 8000/tcp is reachable from the internet" in page
    assert "Accepted: Port 8000/tcp" not in c.get("/h/testhost/").text.split("Recent changes")[0]
    # It stays in the Findings list, in place, labelled Accepted, with its note.
    row = c.get("/h/testhost/").text.split('id="finding-expose.unexpected-8000_tcp"')[1].split("data-row")[0]
    assert 'data-status-label="accepted"' in row and "Public on purpose; fronted by the proxy" in row
    assert "Accepted by admin" in row and 'id="accepted"' not in page
    ev = [e for e in db.recent_events(conn, "testhost", 10) if e["kind"] == "finding_accepted"]
    assert ev[0]["title"] == "Accepted: Port 8000/tcp is reachable from the internet"
    assert ev[0]["detail"] == "Public on purpose; fronted by the proxy"
    # It's still an open finding in the database.
    assert any(r["rule"] == "expose.unexpected" for r in db.open_findings(conn, "testhost"))

    r = c.post("/h/testhost/findings/unaccept", data={"rule": "expose.unexpected", "key": "8000/tcp",
                                                      "next": "/h/testhost/"})
    assert r.status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0
    ev = [e for e in db.recent_events(conn, "testhost", 10) if e["kind"] == "finding_unaccepted"]
    assert ev[0]["title"].startswith("Un-accepted: Port 8000/tcp") and "fronted by the proxy" in ev[0]["detail"]
    back = c.get("/h/testhost/").text.split('id="finding-expose.unexpected-8000_tcp"')[1].split("data-row")[0]
    assert 'data-status-label="unexpected"' in back and "Public on purpose" not in back
    # Un-accepting what isn't accepted says so.
    c.post("/h/testhost/findings/unaccept", data={"rule": "expose.unexpected", "key": "8000/tcp"})
    assert "was not accepted" in c.get("/h/testhost/").text


def test_port_panel_accepts_its_finding(hubapp):
    c, conn, _ = hubapp
    db.put_snapshot(conn, "testhost", "ports", time.time(), True, None, {
        "listeners": [{"proto": "tcp", "port": 8000, "addresses": ["0.0.0.0"], "scope": "all", "pid": 1,
                       "process": "python3", "owner": {"kind": "unknown", "id": None}}],
        "owners_known": True, "addresses": [{"nic": "eth0", "ip": "203.0.113.10", "scope": "public"}]})
    page = c.get("/h/testhost/exposure").text
    panel = page.split('id="port-8000-tcp"')[1]
    assert "Accept risk" in panel and "Cancel" in panel and 'value="/h/testhost/exposure#port-8000-tcp"' in panel
    r = accept(c, "expose.unexpected", "8000/tcp", note="On purpose", next_="/h/testhost/exposure#port-8000-tcp")
    assert r.headers["location"] == "/h/testhost/exposure#port-8000-tcp"
    panel = c.get("/h/testhost/exposure").text.split('id="port-8000-tcp"')[1]
    assert "Un-accept" in panel and "On purpose" in panel and "Accept risk" not in panel.split("</tr>")[0]


def test_next_must_be_a_local_path(hubapp):
    c, _, _ = hubapp
    assert accept(c, "pkg.updates", "updates", next_="//evil.example/").headers["location"] == "/"
    assert accept(c, "pkg.reboot", "reboot", next_="").headers["location"] == "/h/testhost/"


def test_accepted_findings_leave_every_summary(hubapp):
    c, conn, cfg = hubapp

    def hosts_cell():
        row = re.search(r'data-label="Findings">(.*?)</td>', c.get("/").text, re.S).group(1)
        return re.sub(r"<[^>]+>", " ", row).split()

    assert hosts_cell() == ["1", "critical", "2", "medium", "1", "low"]
    assert "Reboot needed" in c.get("/").text  # the badge on the Hosts page
    overview = c.get("/h/testhost/").text
    assert "4 need attention" in overview and 'class="badge ds-sev bg-red text-red-fg"' in overview
    assert 'data-status-label="accepted"' not in overview and "Needs attention" not in overview
    accept(c, "expose.unexpected", "8000/tcp")
    accept(c, "pkg.reboot", "reboot")
    accept(c, "pkg.updates", "updates")
    assert hosts_cell() == ["1", "medium"]
    assert "Reboot needed" not in c.get("/").text
    page = c.get("/h/testhost/").text
    assert "1 needs attention · 3 accepted" in page
    # All four are in the one list. Three carry an Accepted label and don't count; the fourth is Unexpected.
    findings_card = page.split('id="findings-title"')[1].split("At a glance")[0]
    assert 'id="accepted"' not in page and "Port 8000/tcp" in findings_card and "Disk / is 86% full" in findings_card
    assert findings_card.count('data-status-label="accepted"') == 3
    assert findings_card.count('data-status-label="unexpected"') == 1
    assert 'data-status="accepted"' in findings_card and "Needs attention" in findings_card  # the filter
    rep = c.get("/h/testhost/report").text
    assert "Nothing to report" not in rep and "Disk / is 86% full" in rep
    # Helper used by the Hosts page.
    active = db.active_findings_by_host(conn)
    assert [d["rule"] for d in active["testhost"]] == ["sys.disk"]
    # The Hosts page still says what the host is doing: a silent host is still not reporting.
    assert views.hosts_list(conn, cfg)["hosts"][0]["state"] == "Reporting"


def test_a_change_to_the_basis_brings_it_back(hubapp):
    c, conn, cfg = hubapp
    now = time.time()
    accept(c, "sys.disk", "/", note="Backups land here")
    assert "3 need attention · 1 accepted" in c.get("/h/testhost/").text
    # The title drifts (86% to 91%) but the basis doesn't: still accepted.
    db.reconcile_findings(conn, "testhost", now + 60, [disk(91), UPDATES, REBOOT, PORT])
    page = c.get("/h/testhost/").text
    assert "4 need attention" not in page and 'data-status-label="accepted"' in page and "Backups land here" in page
    # It crosses into High: the basis changes, so it is open again with a note.
    db.reconcile_findings(conn, "testhost", now + 120,
                          [disk(97, basis="/|high", severity="high"), UPDATES, REBOOT, PORT])
    page = c.get("/h/testhost/").text
    assert "4 need attention" in page and 'data-status-label="accepted"' not in page
    assert 'data-status-label="changed"' in page  # one Changed label, counted as needing attention
    assert re.search(r"Accepted on \d{4}-\d\d-\d\d \(Backups land here\) — this has changed since", page)
    assert views.findings_list(conn, "testhost")[1]["changed_note"]
    # The report flags it too, and the Hosts page counts it again.
    rep = c.get("/h/testhost/report").text
    assert "this has changed since" in rep
    assert "this has changed since" in c.get("/h/testhost/report.md").text
    hosts = views.hosts_list(conn, cfg)["hosts"][0]["findings"]
    assert dict((label, n) for label, _c, n in hosts)["High"] == 1
    # Accepting again takes the new basis.
    accept(c, "sys.disk", "/", note="Still backups")
    assert "4 need attention" not in c.get("/h/testhost/").text


def test_acceptance_is_deleted_when_the_finding_resolves(hubapp):
    c, conn, _ = hubapp
    now = time.time()
    accept(c, "pkg.updates", "updates")
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 1
    db.reconcile_findings(conn, "testhost", now + 30, [disk(86), REBOOT, PORT])  # updates installed
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0
    # It comes back later as a new finding, not accepted.
    db.reconcile_findings(conn, "testhost", now + 60, [disk(86), UPDATES, REBOOT, PORT])
    assert [d["rule"] for d in db.findings_state(conn, "testhost")[0]].count("pkg.updates") == 1
    # set_finding resolves the same way.
    stale = Finding("cve.feed_stale", "feeds", "low", "CVE data is out of date", "d")
    db.set_finding(conn, "testhost", now, stale, rule="cve.feed_stale", key="feeds")
    accept(c, "cve.feed_stale", "feeds")
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 1
    db.set_finding(conn, "testhost", now + 1, None, rule="cve.feed_stale", key="feeds")
    assert conn.execute("SELECT COUNT(*) FROM accepted").fetchone()[0] == 0


def test_hub_findings_upload_carries_fix_and_basis(hub_cfg, token):  # noqa: F811
    c = TestClient(create_app(hub_cfg))
    f = {"rule": "pkg.updates", "key": "updates", "severity": "low", "title": "2 updates waiting",
         "detail": "a, b.", "link": "/packages#other", "fix": "sudo apt upgrade", "basis": "updates"}
    assert post(c, body(findings=[f]), token).status_code == 200
    conn = db.connect_writer(hub_cfg.db_path)
    row = conn.execute("SELECT fix, basis FROM findings").fetchone()
    assert (row["fix"], row["basis"]) == ("sudo apt upgrade", "updates")
    # A collector from before fix and basis existed sends neither.
    old = {k: v for k, v in f.items() if k not in ("fix", "basis")}
    assert post(c, body(seq=10**13, findings=[old]), token).status_code == 200
    row = conn.execute("SELECT fix, basis FROM findings WHERE resolved_at IS NULL").fetchone()
    assert (row["fix"], row["basis"]) == (None, None)
    # The fix is plain text: no escape sequences or direction overrides. A bad
    # one is dropped; the rest of the upload is kept.
    for n, bad in enumerate(("sudo apt upgrade\x1b[2J", "ls ‮", "x" * 2001)):
        r = post(c, body(seq=10**13 + 1 + n, findings=[{**f, "fix": bad}]), token)
        assert r.status_code == 200, bad
        assert conn.execute("SELECT fix FROM findings WHERE resolved_at IS NULL").fetchone()["fix"] is None
    seq = 10**13 + 10
    assert post(c, body(seq=seq, findings=[{**f, "fix": "a\nb"}]), token).status_code == 200


def test_collector_upload_sends_fix_only_when_set(cfg, tmp_path):
    from daemonsight.collector import upload
    conn = db.connect_writer(cfg.db_path)
    db.reconcile_findings(conn, "testhost", 1.0, [UPDATES, Finding("a.b", "k", "low", "t", "d")])
    payload, _, _ = upload.build(conn, cfg, (1, 2), 60)
    by = {f["rule"]: f for f in payload["findings"]}
    assert by["pkg.updates"]["fix"] == "sudo apt upgrade" and by["pkg.updates"]["basis"] == "updates"
    assert "fix" not in by["a.b"] and "basis" not in by["a.b"]


def test_standalone_has_no_accept_routes(seeded):
    c = TestClient(create_app(seeded), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    assert c.post("/h/testhost/findings/accept", data={"rule": "a.b", "key": "k", "note": "x"}).status_code == 404
    html = c.get("/").text
    assert "Accept" not in html.replace("Accepted", "")  # the web process is read-only there
    assert 'href="/report"' in html


# ---- steps ------------------------------------------------------------------

def item(rule, key, fix, severity="low", title=None):
    return {"id": f"finding-{rule}-{key}", "rule": rule, "key": key, "severity": severity, "title": title or rule,
            "detail": "d", "link": None, "fix": fix, "step": findings.step_of(rule) if fix else None,
            "label": severity.title(), "badge": "x", "since": "now", "accepted": None, "changed_note": None}


def test_steps_merge_and_order():
    items = [
        item("pkg.auto_updates_off", "auto", "sudo apt install unattended-upgrades"),
        item("os.eol_soon", "os", "sudo dnf upgrade --refresh\nsudo dnf system-upgrade reboot"),
        item("pkg.reboot", "reboot", "sudo reboot"),
        item("pkg.restart", "restart", "sudo needrestart -r a"),
        item("pkg.updates", "updates", "sudo apt upgrade"),
        item("cve.package", "openssl", "sudo apt update\nsudo apt upgrade", severity="high"),
        item("pkg.lists_stale", "lists", "sudo apt update"),
        item("custom.thing", "x", "run-this --now", title="Custom"),
        item("expose.unexpected", "8000/tcp", None, severity="critical"),
        item("os.lts", "os", None),
    ]
    cards, decide = report.steps(items)
    assert [c["key"] for c in cards] == ["upgrade", "restart", "reboot", "auto-updates",
                                         "finding-custom.thing-x", "os-upgrade"]
    assert [c["title"] for c in cards] == ["Install updates", "Restart services", "Reboot",
                                           "Turn on automatic updates", "Custom", "Upgrade the operating system"]
    up = cards[0]
    # The list refresh comes first, each command once.
    assert up["commands"] == "sudo apt update\nsudo apt upgrade"
    assert [f["rule"] for f in up["findings"]] == ["pkg.updates", "cve.package", "pkg.lists_stale"]
    assert [d["rule"] for d in decide] == ["expose.unexpected", "os.lts"]
    assert cards[-1]["commands"] == "sudo dnf upgrade --refresh\nsudo dnf system-upgrade reboot"


def test_kernel_cve_notes_the_reboot_only_when_one_is_open():
    kernel = item("cve.package", "linux", "sudo apt upgrade", severity="high")
    cards, _ = report.steps([kernel])
    assert cards[0]["note"] is None
    cards, _ = report.steps([kernel, item("pkg.reboot", "reboot", "sudo reboot")])
    assert "Reboot afterwards" in cards[0]["note"]
    cards, _ = report.steps([item("cve.package", "openssl", "sudo apt upgrade"), item("pkg.reboot", "reboot", "sudo reboot")])
    assert cards[0]["note"] is None


# ---- the report page and Markdown -------------------------------------------

def test_report_page_on_a_hub(hubapp):
    c, conn, _ = hubapp
    accept(c, "sys.disk", "/", note="Backups <land> here")
    r = c.get("/h/testhost/report")
    assert r.status_code == 200
    html = r.text
    assert "Report" in html and "Debian GNU/Linux 12 (bookworm)" in html and "6.1.0-18-amd64" in html
    assert "0.1.0 (abc1234)" in html and "Last upload" in html and "Generated" in html and "Server" in html
    # Steps: one card per step, merged commands, each finding linked to its evidence row.
    assert "1. Install updates" in html and "2. Reboot" in html
    assert 'href="/h/testhost/packages#other"' in html and 'href="/h/testhost/packages#reboot"' in html
    assert 'class="ds-copy-text">sudo apt upgrade</code>' in html
    # Decide: the exposed port has no fix.
    decide = html.split('id="decide"')[1].split('id="all"')[0]
    assert "Port 8000/tcp is reachable" in decide and "sudo reboot" not in decide
    assert 'href="/h/testhost/exposure#port-8000-tcp"' in decide
    # All findings by severity.
    assert "Do now" in html and "Do soon" in html and "When convenient" in html
    # Accepted with its note, escaped.
    acc = html.split('id="accepted"')[1]
    assert "Backups &lt;land&gt; here" in acc and "admin" in acc and "Un-accept" in acc
    # Escaping of host-controlled text.
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html
    # Copy and print affordances.
    assert 'data-copy-from="report-text"' in html and 'id="report-text"' in html
    assert 'href="/h/testhost/report.md"' in html and "Download Markdown" in html
    assert "ds-noprint" in html and "style=" not in html and "<script" not in html.replace("<script src", "")
    assert 'data-label="Severity"' in html and 'data-label="Note"' in html
    assert 'href="/h/testhost/report"' in html  # the nav link on the phone menu


def test_report_links_from_hosts_overview_and_menu(hubapp):
    c, _, _ = hubapp
    assert 'href="/h/testhost/report"' in c.get("/").text
    overview = c.get("/h/testhost/").text
    assert 'href="/h/testhost/report"' in overview
    assert re.search(r'id="ds-menu".*?href="/h/testhost/report".*?</nav>', overview, re.S)


def test_report_page_standalone(seeded):
    c = TestClient(create_app(seeded), follow_redirects=False)
    assert c.get("/report").status_code == 303
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    r = c.get("/report")
    assert r.status_code == 200
    assert "Port 5432/tcp is published on all interfaces" in r.text and "Last collected" in r.text
    assert 'href="/report.md"' in r.text and "Debian GNU/Linux 12 (bookworm)" in r.text
    assert "findings/accept" not in r.text  # read-only on a single host
    md = c.get("/report.md")
    assert md.status_code == 200 and "Port 5432/tcp is published on all interfaces" in md.text
    assert c.get("/h/testhost/report").status_code == 404


def test_markdown_export(hubapp):
    c, conn, _ = hubapp
    accept(c, "sys.disk", "/", note="Backups land here")
    anon = TestClient(create_app(hubapp[2]), follow_redirects=False)
    r = anon.get("/h/testhost/report.md")
    assert r.status_code == 303  # login required
    r = c.get("/h/testhost/report.md")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/markdown; charset=utf-8"
    day = time.strftime("%Y-%m-%d", time.gmtime())
    assert r.headers["content-disposition"] == f"attachment; filename=testhost-report-{day}.md"
    md = r.text
    assert md.startswith("# Report for testhost\n")
    assert "- Operating system: Debian GNU/Linux 12 \\(bookworm\\)" in md
    assert "## Steps" in md and "### 1. Install updates" in md and "### 2. Reboot" in md
    assert "```sh\nsudo apt upgrade\n```" in md and "```sh\nsudo reboot\n```" in md
    assert md.index("Install updates") < md.index("### 2. Reboot")
    assert "## Decide" in md and "Port 8000/tcp is reachable from the internet" in md
    assert "### Do now" in md and "### Do soon" in md and "### When convenient" in md
    assert "## Accepted" in md and "Note: Backups land here (admin, " in md
    # The page's "Copy as text" holds the same Markdown.
    page = c.get("/h/testhost/report").text
    area = re.search(r'<textarea id="report-text"[^>]*>(.*?)</textarea>', page, re.S).group(1)
    import html as htmllib
    assert htmllib.unescape(area).replace("Generated: ", "G").split("Generated")[0] == \
        md.replace("Generated: ", "G").split("Generated")[0]


def test_markdown_escapes_host_text():
    assert report.md_text("a *b* _c_ [d](e) <i>f</i> `g` # h | i") == \
        "a \\*b\\* \\_c\\_ \\[d\\]\\(e\\) \\<i\\>f\\</i\\> \\`g\\` \\# h \\| i"
    assert report.md_text("line one\n# not a heading") == "line one \\# not a heading"
    assert report.md_text("- item") == "\\- item" and report.md_text("1. item") == "\\1. item"
    assert report.md_text("&lt;") == "\\&lt;"
    block = report.md_code("echo ```\n````")
    assert block.startswith("`````sh\n") and block.endswith("\n`````")  # longer than any run inside
    assert report.filename("we/ird host", 0) == "we_ird_host-report-1970-01-01.md"
    it = item("a.b", "k", None, title="# Evil [x](javascript:alert(1))")
    it.update(href=None, step_title=None)
    out = "\n".join(report._finding_md(it, fix=False))
    assert "\\# Evil \\[x\\]\\(javascript:alert\\(1\\)\\)" in out and "](javascript" not in out
