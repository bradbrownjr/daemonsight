"""Managing collector hosts in the web UI: the Manage column, the manage page, adding a Linux host, and each
action (update, replace token, revoke, remove)."""

import logging
import re
import time

import pytest
from fastapi.testclient import TestClient

from daemonsight import db, hub
from daemonsight.cve import store as cve_store
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post  # noqa: F401 (fixtures)

HUB_REV = "abcdef1"
OLD = "0.1.0 (1234567)"
CROSS = {"Sec-Fetch-Site": "cross-site"}


@pytest.fixture(autouse=True)
def hub_version(monkeypatch):
    monkeypatch.setattr(hub, "full_version", lambda: f"0.1.0 ({HUB_REV})")


@pytest.fixture
def conn(hub_cfg):
    c = db.connect_writer(hub_cfg.db_path)
    yield c
    c.close()


@pytest.fixture
def c(hub_cfg, conn):
    app = create_app(hub_cfg)
    client = TestClient(app, follow_redirects=False)
    assert client.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    return client


def titles(conn):
    return [e["title"] for e in db.recent_events(conn, db.HUB_HOST, 20)]


def seed(conn, cve_path, host):
    """One row of everything a host can have, in every table removal clears."""
    conn.execute("INSERT INTO snapshots (host, source, taken_at, ok, data) VALUES (?, 'system', 1, 1, '{}')", (host,))
    conn.execute("INSERT INTO metrics (host, ts, name, value) VALUES (?, 1, 'cpu.percent', 3)", (host,))
    conn.execute("INSERT INTO findings (host, rule, key, severity, title, detail, first_seen, last_seen) "
                 "VALUES (?, 'r', 'k', 'low', 't', 'd', 1, 1)", (host,))
    conn.execute("INSERT INTO events (host, ts, kind, title) VALUES (?, 1, 'x', 'e')", (host,))
    conn.execute("INSERT INTO accepted (host, rule, key, fingerprint, note, accepted_at, accepted_by) "
                 "VALUES (?, 'r', 'k', 'f', 'n', 1, 'admin')", (host,))
    cve = cve_store.connect(cve_path)
    cve.execute("INSERT INTO match (host, source, cve, state) VALUES (?, 'deb', 'CVE-2026-0001', 'fix')", (host,))
    cve.execute("INSERT INTO matched (host) VALUES (?)", (host,))
    cve.close()


def rows(conn, cve_path, host):
    out = {t: conn.execute(f"SELECT COUNT(*) FROM {t} WHERE host = ?", (host,)).fetchone()[0] for t in hub.PURGE_TABLES}
    cve = cve_store.connect(cve_path)
    out["match"] = cve.execute("SELECT COUNT(*) FROM match WHERE host = ?", (host,)).fetchone()[0]
    out["matched"] = cve.execute("SELECT COUNT(*) FROM matched WHERE host = ?", (host,)).fetchone()[0]
    cve.close()
    return out


def add(conn, name, version=OLD, seen=True):
    token = hub.add_host(conn, name)
    if seen:
        conn.execute("UPDATE hosts SET last_seen=?, version=?, address='192.0.2.9' WHERE id=?", (time.time(), version, name))
    return token


# --- the Hosts table -------------------------------------------------------------

def test_manage_column_for_both_kinds(c, conn):
    add(conn, "web1")
    conn.execute("INSERT INTO hosts (id, token_hash, created_at, kind) VALUES ('tower', 'x', 1, 'unraid')")
    conn.execute("INSERT INTO remotes (id, kind, url, created_at) VALUES ('tower', 'unraid', 'https://t.test', 1)")
    html = c.get("/").text
    assert "<th>Manage</th>" in html
    assert html.index("<th>Report</th>") < html.index("<th>Manage</th>")
    assert 'href="/hosts/web1/manage"' in html and 'href="/remotes/tower/edit"' in html
    assert html.count('data-label="Manage"') == 2
    assert 'class="small">Edit</a>' not in html  # the old link under the name is gone
    assert 'href="/hosts/new"' in html and 'href="/remotes/new"' in html
    # the manage page of an API system is its edit page
    r = c.get("/hosts/tower/manage")
    assert r.status_code == 303 and r.headers["location"] == "/remotes/tower/edit"


# --- add a Linux host ------------------------------------------------------------

def test_add_host_shows_token_once(c, conn, caplog):
    assert "Add a Linux host" in c.get("/hosts/new").text
    with caplog.at_level(logging.DEBUG):
        r = c.post("/hosts/new", data={"name": "vps"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    token = re.search(r'<code class="ds-copy-text">([A-Za-z0-9_-]{40,})</code>', r.text).group(1)
    assert hub.host_for_token(conn, token)["id"] == "vps"
    assert f"sudo daemonsight set-upload-token --url http://testserver/api/v1/ingest" in r.text
    assert "host_id" in r.text and "systemctl restart daemonsight-collector" in r.text
    assert token not in caplog.text and token not in "".join(titles(conn))
    assert "Host added: vps" in titles(conn)
    # not shown again: no page of the hub carries it
    for path in ("/", "/hosts/vps/manage", "/hosts/new"):
        assert token not in c.get(path).text
    assert hub.hash_token(token) not in c.get("/").text


@pytest.mark.parametrize("name,word", [("", "type a name"), ("a b", "no spaces"), ("-x", "starting with"),
                                       ("../etc", "starting with"), ("x" * 64, "63 at most")])
def test_add_host_validation(c, conn, name, word):
    r = c.post("/hosts/new", data={"name": name})
    assert r.status_code == 400 and word in r.text and "ds-copy-text" not in r.text
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0


def test_add_host_duplicate_and_csrf(c, conn):
    add(conn, "vps")
    r = c.post("/hosts/new", data={"name": "vps"})
    assert r.status_code == 400 and "already exists" in r.text
    assert c.post("/hosts/new", data={"name": "other"}, headers=CROSS).status_code == 403
    assert conn.execute("SELECT 1 FROM hosts WHERE id = 'other'").fetchone() is None
    anon = TestClient(c.app, follow_redirects=False)
    assert anon.post("/hosts/new", data={"name": "other"}).status_code == 303
    assert conn.execute("SELECT 1 FROM hosts WHERE id = 'other'").fetchone() is None


# --- version ---------------------------------------------------------------------

def test_update_now(c, conn):
    add(conn, "web1")
    html = c.get("/hosts/web1/manage").text
    assert OLD in html and HUB_REV in html and "Update now" in html and "disabled" not in html
    assert c.post("/hosts/web1/update", headers=CROSS).status_code == 403
    assert conn.execute("SELECT update_to FROM hosts").fetchone()[0] is None
    r = c.post("/hosts/web1/update")
    assert r.status_code == 303 and r.headers["location"] == "/hosts/web1/manage"
    assert conn.execute("SELECT update_to FROM hosts").fetchone()[0] == HUB_REV
    assert f"Update requested: web1" in titles(conn)
    html = c.get("/hosts/web1/manage").text
    assert "Asked web1 to update" in html and "disabled" in html and "Cancel the update" in html
    c.post("/hosts/web1/update", data={"action": "cancel"})
    assert conn.execute("SELECT update_to FROM hosts").fetchone()[0] is None
    assert "Update cancelled: web1" in titles(conn)


def test_update_disabled_with_a_reason(c, conn):
    add(conn, "cur", version=f"0.1.0 ({HUB_REV})")
    add(conn, "new", seen=False)
    add(conn, "off")
    conn.execute("UPDATE hosts SET remote_update = 0 WHERE id = 'off'")
    for host, reason in (("cur", "runs the hub"), ("new", "has not reported yet"),
                         ("off", "turned off")):
        html = c.get(f"/hosts/{host}/manage").text
        assert reason in html and "disabled" in html
        c.post(f"/hosts/{host}/update")  # a forced post does nothing either
        assert conn.execute("SELECT update_to FROM hosts WHERE id = ?", (host,)).fetchone()[0] is None
    assert "Update requested: cur" not in titles(conn)


# --- replace token ---------------------------------------------------------------

def test_replace_token(c, conn, hub_cfg, caplog):
    old = add(conn, "web1")
    other = add(conn, "web2")
    page = c.get("/hosts/web1/manage/token")
    assert page.status_code == 200 and "stops working" in page.text
    assert c.post("/hosts/web1/token", headers=CROSS).status_code == 403
    assert hub.host_for_token(conn, old)["id"] == "web1"
    with caplog.at_level(logging.DEBUG):
        r = c.post("/hosts/web1/token")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    new = re.search(r'<code class="ds-copy-text">([A-Za-z0-9_-]{40,})</code>', r.text).group(1)
    assert new != old and hub.host_for_token(conn, new)["id"] == "web1"
    assert hub.host_for_token(conn, old) is None and hub.host_for_token(conn, other)["id"] == "web2"
    assert new not in caplog.text and "Upload token replaced: web1" in titles(conn)
    assert new not in c.get("/hosts/web1/manage").text
    # the old token no longer uploads, the new one does
    up = TestClient(c.app)
    assert post(up, body(host="web1", seq=1), old).status_code == 401
    assert post(up, body(host="web1", seq=2), new).status_code == 200


# --- revoke ----------------------------------------------------------------------

def test_revoke_keeps_history(c, conn, hub_cfg):
    token = add(conn, "web1")
    seed(conn, hub_cfg.cve_db_path, "web1")
    assert "history stays" in c.get("/hosts/web1/manage/revoke").text
    assert c.post("/hosts/web1/revoke", headers=CROSS).status_code == 403
    assert hub.host_for_token(conn, token) is not None
    r = c.post("/hosts/web1/revoke")
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert hub.host_for_token(conn, token) is None
    assert all(n == 1 for n in rows(conn, hub_cfg.cve_db_path, "web1").values())
    assert "Host revoked: web1" in titles(conn)
    assert c.get("/hosts/web1/manage").status_code == 404
    # allowing it again is adding the name again; the history is still there
    again = c.post("/hosts/new", data={"name": "web1"})
    assert again.status_code == 200 and "ds-copy-text" in again.text


# --- remove ----------------------------------------------------------------------

def test_remove_deletes_exactly_what_is_listed(c, conn, hub_cfg):
    path = hub_cfg.cve_db_path
    add(conn, "web1")
    add(conn, "web2")
    seed(conn, path, "web1")
    seed(conn, path, "web2")
    page = c.get("/hosts/web1/manage/remove").text
    for label in ("Snapshots", "Metric points", "Findings", "Events", "Accepted findings", "CVE matches", "Upload token"):
        assert label in page
    before_other = rows(conn, path, "web2")
    assert c.post("/hosts/web1/remove", data={"confirm": "web1"}, headers=CROSS).status_code == 403
    # a wrong or missing name deletes nothing
    for typed in ("", "web2", "WEB1"):
        r = c.post("/hosts/web1/remove", data={"confirm": typed})
        assert r.status_code == 303 and r.headers["location"] == "/hosts/web1/manage/remove"
    assert all(n == 1 for n in rows(conn, path, "web1").values())
    r = c.post("/hosts/web1/remove", data={"confirm": "web1"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert all(n == 0 for n in rows(conn, path, "web1").values())
    assert conn.execute("SELECT 1 FROM hosts WHERE id = 'web1'").fetchone() is None
    assert rows(conn, path, "web2") == before_other and conn.execute("SELECT 1 FROM hosts WHERE id = 'web2'").fetchone()
    assert "Host removed: web1" in titles(conn)
    # the tables it clears are the ones the page lists, plus the CVE matches
    assert [l for l, _ in hub.data_counts(conn, "web2", path)] == [
        "Snapshots", "Metric points", "Findings", "Events", "Accepted findings", "CVE matches"]


def test_remove_without_a_cve_db(c, conn, hub_cfg):
    add(conn, "web1")
    assert not hub_cfg.cve_db_path.exists()
    assert c.post("/hosts/web1/remove", data={"confirm": "web1"}).status_code == 303
    assert not hub_cfg.cve_db_path.exists()  # removing a host doesn't create it


# --- unknown hosts and the login ---------------------------------------------------

@pytest.mark.parametrize("path", ["/hosts/nope/manage", "/hosts/nope/manage/token", "/hosts/nope/manage/revoke",
                                  "/hosts/nope/manage/remove", "/hosts/..%2Fx/manage"])
def test_unknown_host_get(c, path):
    assert c.get(path).status_code == 404


@pytest.mark.parametrize("path,data", [("/hosts/nope/update", {}), ("/hosts/nope/token", {}),
                                       ("/hosts/nope/revoke", {}), ("/hosts/nope/remove", {"confirm": "nope"})])
def test_unknown_host_post(c, path, data):
    assert c.post(path, data=data).status_code == 404


def test_unknown_action_and_api_system(c, conn):
    add(conn, "web1")
    assert c.get("/hosts/web1/manage/nuke").status_code == 404
    conn.execute("INSERT INTO hosts (id, token_hash, created_at, kind) VALUES ('tower', 'x', 1, 'unraid')")
    conn.execute("INSERT INTO remotes (id, kind, url, created_at) VALUES ('tower', 'unraid', 'https://t.test', 1)")
    # these routes never touch an API system, whose removal has its own page
    for path in ("/hosts/tower/revoke", "/hosts/tower/token", "/hosts/tower/remove"):
        assert c.post(path, data={"confirm": "tower"}).status_code == 404
    assert conn.execute("SELECT 1 FROM remotes WHERE id = 'tower'").fetchone()


def test_login_required(hub_cfg, conn):
    add(conn, "web1")
    anon = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert anon.get("/hosts/web1/manage").status_code == 303 and anon.get("/hosts/new").status_code == 303
    for path in ("update", "token", "revoke", "remove"):
        assert anon.post(f"/hosts/web1/{path}", data={"confirm": "web1"}).status_code == 303
    assert conn.execute("SELECT 1 FROM hosts WHERE id = 'web1'").fetchone()
    assert conn.execute("SELECT update_to FROM hosts").fetchone()[0] is None
