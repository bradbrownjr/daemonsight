"""The status label on every list: Unexpected, Accepted, Changed, Expected.

Accepted and expected items are never hidden; only Unexpected and Changed
count as needing attention. Checked on the Overview findings list (with its
filter) and on the Exposure page's listener and forward rows.
"""

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daemonsight import db, findings
from daemonsight.hub import HUB_RULES
from daemonsight.web import views
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)
from .test_outside import PUBLIC, seed
from .test_phase2 import listener

STATIC = Path(__file__).parent.parent / "src" / "daemonsight" / "web" / "static"


def reevaluate(conn, cfg, process="python3", extra=()):
    """Run the rules on the host's snapshots, as its collector would, and store the findings."""
    ports = db.get_snapshot(conn, "testhost", "ports")
    data = dict(ports.data)
    data["listeners"] = [*data["listeners"], listener(2083, process=process), *extra]
    db.put_snapshot(conn, "testhost", "ports", time.time(), True, None, data)
    hcfg = views.host_config(conn, cfg, "testhost")
    found = findings.evaluate(db.get_snapshots(conn, "testhost"), hcfg, {"eph": (32768, 60999)})
    db.reconcile_findings(conn, "testhost", time.time(), found, keep_prefix=HUB_RULES)
    return found


@pytest.fixture
def web(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    reevaluate(conn, hub_cfg)
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    yield c, conn, hub_cfg
    conn.close()


def accept(c, rule, key, note="known and fine"):
    return c.post("/h/testhost/findings/accept", data={"rule": rule, "key": key, "note": note, "next": "/h/testhost/"})


def rows(html):
    """Exposure table rows by id."""
    return {m.group(1): m.group(0) for m in re.finditer(r'<tr data-row id="([^"]+)">.*?</tr>', html, re.S)}


def label(row_html):
    cell = re.search(r'data-label="Status"[^>]*>(.*?)</td>', row_html, re.S).group(1)
    m = re.search(r'data-status-label="(\w+)"', cell)
    return m.group(1) if m else re.sub(r"<[^>]+>", "", cell).strip()


def exposure(c):
    return c.get("/h/testhost/exposure").text


# ---- the Exposure page ---------------------------------------------------------------------

def test_listener_and_forward_rows_carry_a_status(web):
    c, conn, cfg = web
    r = rows(exposure(c))
    assert [label(r[f"port-{p}-tcp"]) for p in (22, 80, 443)] == ["expected"] * 3
    assert label(r["port-443-udp"]) == "expected"
    assert label(r["port-2083-tcp"]) == "unexpected"
    assert "port-8001-tcp" not in r                       # loopback is not on this page
    fwds = {k: v for k, v in r.items() if k.startswith("fwd-")}
    assert len(fwds) == 2 and {label(v) for v in fwds.values()} == {"unexpected"}   # the two wide forwards


def test_accepting_a_row_changes_its_label_and_shows_the_note(web):
    c, conn, cfg = web
    assert accept(c, "expose.unexpected", "2083/tcp", note="Internal dashboard, proxied").status_code == 303
    r = rows(exposure(c))
    assert label(r["port-2083-tcp"]) == "accepted"
    assert "Internal dashboard, proxied" in r["port-2083-tcp"]            # the note, in the row
    assert 'title="Internal dashboard, proxied (admin' in r["port-2083-tcp"]  # and on hover
    assert label(r["port-22-tcp"]) == "expected"                            # others untouched
    # The row is still there and still sorted with the rest.
    assert 'id="port-2083-tcp"' in exposure(c)
    # Accept a forward too.
    fkey = next(f["key"] for f in db.open_findings(conn, "testhost") if f["rule"] == "expose.forward_all")
    assert accept(c, "expose.forward_all", fkey, note="Tunnel to the home server").status_code == 303
    fwds = [v for k, v in rows(exposure(c)).items() if k.startswith("fwd-")]
    assert sorted(label(v) for v in fwds) == ["accepted", "unexpected"]


def test_a_changed_basis_shows_changed_and_counts_again(web):
    c, conn, cfg = web
    accept(c, "expose.unexpected", "2083/tcp", note="Internal dashboard")
    before = c.get("/h/testhost/").text
    # A different program now listens on the port: the basis includes the process.
    ports = db.get_snapshot(conn, "testhost", "ports").data
    ports["listeners"] = [x for x in ports["listeners"] if x["port"] != 2083]
    db.put_snapshot(conn, "testhost", "ports", time.time(), True, None, ports)
    reevaluate(conn, cfg, process="node")
    r = rows(exposure(c))
    assert label(r["port-2083-tcp"]) == "changed"
    assert "Internal dashboard" in r["port-2083-tcp"]
    after = c.get("/h/testhost/").text
    assert 'data-status-label="changed"' in after and 'data-status-label="changed"' not in before


def test_expected_wins_over_nothing_but_not_over_an_acceptance(hub_cfg, token):  # noqa: F811
    """A docker-published port listed in expected_public is Expected; accepting its finding changes the label."""
    from .test_collector import container
    wide = [{"host_ip": "0.0.0.0", "host_port": 2083, "container_port": 80, "proto": "tcp"}]
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    db.put_snapshot(conn, "testhost", "docker", time.time(), True, None,
                    {"version": {}, "containers": [container("web", ports=wide)]})
    snaps = db.get_snapshots(conn, "testhost")
    ports = snaps["ports"].data
    ports["listeners"].append(listener(2083, unit=None, process="docker-proxy"))
    db.put_snapshot(conn, "testhost", "ports", time.time(), True, None, ports)
    hcfg = views.host_config(conn, hub_cfg, "testhost")
    hcfg.exposure.expected_public.append("2083/tcp")
    # The docker_bypass finding is open whatever the config says; the row's label follows the list.
    db.reconcile_findings(conn, "testhost", time.time(), findings.evaluate(
        db.get_snapshots(conn, "testhost"), hcfg, {"eph": (32768, 60999)}), keep_prefix=HUB_RULES)
    db.put_snapshot(conn, "testhost", "settings", time.time(), True, None, {
        "exposure": {"expected_public": hcfg.exposure.expected_public, "upstream_allow": [], "jail_covers": {}},
        "links": {}, "eph": [32768, 60999], "interval_system": 10, "role": "server"})
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    assert label(rows(exposure(c))["port-2083-tcp"]) == "expected"
    assert accept(c, "expose.docker_bypass", "2083/tcp", note="Bound by design").status_code == 303
    assert label(rows(exposure(c))["port-2083-tcp"]) == "accepted"


def test_a_row_that_is_not_reachable_from_the_internet_has_no_status(web):
    c, conn, cfg = web
    # The provider firewall lets in only SSH: the other listeners can't be reached.
    settings = db.get_snapshot(conn, "testhost", "settings").data
    settings["exposure"]["upstream_allow"] = ["22/tcp"]
    db.put_snapshot(conn, "testhost", "settings", time.time(), True, None, settings)
    r = rows(exposure(c))
    assert label(r["port-22-tcp"]) == "expected" and label(r["port-2083-tcp"]) == "—"
    assert label(r["port-80-tcp"]) == "—"
    # Every forward is out of reach too: none of its ports is in the provider policy but 22 (which it leaves out).
    assert {label(v) for k, v in r.items() if k.startswith("fwd-")} == {"—"}
    # A host with no public address: nothing is internet-reachable.
    ports = db.get_snapshot(conn, "testhost", "ports").data
    ports["addresses"] = [a for a in ports["addresses"] if a["scope"] != "public"]
    db.put_snapshot(conn, "testhost", "ports", time.time(), True, None, ports)
    settings["exposure"]["upstream_allow"] = []
    db.put_snapshot(conn, "testhost", "settings", time.time(), True, None, settings)
    r = rows(exposure(c))
    assert {label(v) for v in r.values()} == {"—"}


def test_a_narrow_forward_is_expected_only_when_every_port_is_listed(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    narrow = {"family": "ip", "proto": "tcp", "ranges": [[443, 443]], "to": "10.99.0.2", "conditions": [],
              "ports": "443", "copies": 1}
    fw = db.get_snapshot(conn, "testhost", "firewall").data
    fw["forwards"] = [narrow, {**narrow, "ranges": [[9443, 9443]], "ports": "9443", "to": "10.99.0.3"}]
    db.put_snapshot(conn, "testhost", "firewall", time.time(), True, None, fw)
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    r = {k: v for k, v in rows(exposure(c)).items() if k.startswith("fwd-")}
    assert sorted(label(v) for v in r.values()) == ["expected", "unexpected"]


# ---- the Overview list ---------------------------------------------------------------------------

def list_card(html):
    return html.split('id="findings-title"')[1].split("At a glance")[0]


def row_html(html, finding_id):
    return list_card(html).split(f'id="{finding_id}"')[1].split("data-row")[0]


def test_overview_lists_every_finding_in_place_with_a_status(web):
    c, conn, cfg = web
    html = c.get("/h/testhost/").text
    card = list_card(html)
    n = len(db.open_findings(conn, "testhost"))
    assert n >= 3 and card.count("data-row data-status=") == n
    assert card.count('data-status-label="unexpected"') == n
    assert 'id="accepted"' not in html and "Needs attention" not in card   # no accepted, so no filter needed
    assert f"{n} need attention" in card
    port_id = "finding-expose.unexpected-2083_tcp"
    accept(c, "expose.unexpected", "2083/tcp", note="Internal dashboard, proxied")
    html = c.get("/h/testhost/").text
    card = list_card(html)
    # It stays where it was: same position in the list, now labelled Accepted, with its note and an Un-accept.
    ids = re.findall(r'id="(finding-[^"]+)"', card)
    assert port_id in ids and len(ids) >= n
    row = row_html(html, port_id)
    assert 'data-status-label="accepted"' in row and "Internal dashboard, proxied" in row
    assert 'title="Internal dashboard, proxied (admin' in row and "Un-accept" in row
    assert re.search(r'data-status="accepted" id="' + re.escape(port_id), card)
    # The card's count is "needs attention": the accepted one is out of it, and the list says how many are accepted.
    assert f"{n - 1} need" in card and "1 accepted" in card
    # The filter: All and Needs attention, hidden without scripts (ds-js-only), nothing saved server-side.
    assert 'data-status-mode="all"' in card and 'data-status-mode="attention"' in card and "ds-js-only" in card
    assert "Nothing needs attention" in card   # the message shown when the filter leaves nothing
    # Order is by severity, accepted or not: the critical accepted port stays above the lower ones.
    order = [m for m in re.findall(r'class="badge ds-sev [^"]*">(\w+)</span>', card)]
    sev = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    assert [sev[s] for s in order] == sorted(sev[s] for s in order)


def test_the_overview_count_follows_changed_and_accepted(web):
    c, conn, cfg = web
    n = len(db.open_findings(conn, "testhost"))
    accept(c, "expose.unexpected", "2083/tcp")
    assert f"{n - 1} need" in list_card(c.get("/h/testhost/").text)
    ports = db.get_snapshot(conn, "testhost", "ports").data
    ports["listeners"] = [x for x in ports["listeners"] if x["port"] != 2083]
    db.put_snapshot(conn, "testhost", "ports", time.time(), True, None, ports)
    reevaluate(conn, cfg, process="node")
    page = c.get("/h/testhost/").text
    assert f"{n} need" in list_card(page) and " accepted" not in list_card(page).split("attention")[1][:40]
    assert 'data-status-label="changed"' in row_html(page, "finding-expose.unexpected-2083_tcp")
    assert "this has changed since" in row_html(page, "finding-expose.unexpected-2083_tcp")
    # The Hosts page counts the same set: a Changed finding counts, an Accepted one does not.
    ov = views.findings_overview(conn, "testhost")
    assert ov["attention"] == n and ov["held"] == 0 and len(ov["findings"]) == n


def test_the_report_keeps_its_accepted_section(web):
    c, conn, cfg = web
    accept(c, "expose.unexpected", "2083/tcp", note="Internal dashboard, proxied")
    rep = c.get("/h/testhost/report").text
    assert 'id="accepted"' in rep and "Internal dashboard, proxied" in rep
    assert "## Accepted" in c.get("/h/testhost/report.md").text


# ---- the filter's script and style ------------------------------------------------------------------

def test_the_filter_remembers_its_choice_in_a_guarded_local_storage():
    js = (STATIC / "app.js").read_text()
    # Every localStorage read and write sits in the try/catch of the store helpers; the filter uses them.
    assert js.count("window.localStorage") == 2
    for call in ("getItem", "setItem"):
        i = js.index(f"window.localStorage.{call}")
        assert "try {" in js[max(0, i - 120):i] and "catch" in js[i:i + 200]
    assert 'store.get("findingsFilter")' in js and 'store.set("findingsFilter"' in js
    assert "data-status-mode" in js and "ds-status-hidden" in js
    css = (STATIC / "app.css").read_text()
    assert ".ds-status-hidden" in css and "data-status-empty" in css
