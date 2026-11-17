"""Updates the hub asks hosts to install."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from daemonsight import db, hub
from daemonsight.collector import remote_update
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)

HUB_REV = "abcdef1"
OLD = "0.1.0 (1234567)"


@pytest.fixture(autouse=True)
def hub_version(monkeypatch):
    monkeypatch.setattr(hub, "full_version", lambda: f"0.1.0 ({HUB_REV})")


def logged_in(app):
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    return c


def test_versions():
    assert hub.revision("0.1.0 (b41c588)") == "b41c588"
    assert hub.revision("0.1.0 (b41c588-modified)") is None and hub.revision("0.1.0") is None
    assert hub.same_rev("b41c588", "b41c5889f00") and not hub.same_rev("b41c588", None)


def test_request_reply_and_done(hub_cfg, token):  # noqa: F811
    c = TestClient(create_app(hub_cfg))
    assert "update_to" not in post(c, body(version=OLD, seq=1), token).json()
    conn = db.connect_writer(hub_cfg.db_path)
    assert hub.request_update(conn, "testhost", HUB_REV, time.time())
    assert post(c, body(version=OLD, seq=2), token).json()["update_to"] == HUB_REV
    # The host turned updates off: the hub stops asking.
    assert "update_to" not in post(c, body(version=OLD, seq=3, remote_update=False), token).json()
    # Installed: the request clears and an event says so.
    assert "update_to" not in post(c, body(version=f"0.1.0 ({HUB_REV})", seq=4), token).json()
    assert conn.execute("SELECT update_to FROM hosts").fetchone()[0] is None
    assert db.recent_events(conn, "testhost")[0]["title"] == f"Updated to {HUB_REV}"


def test_failed_update_clears_the_request(hub_cfg, token):  # noqa: F811
    c = TestClient(create_app(hub_cfg))
    conn = db.connect_writer(hub_cfg.db_path)
    post(c, body(version=OLD, seq=1), token)
    asked = time.time()
    hub.request_update(conn, "testhost", HUB_REV, asked)
    stale = {"ref": HUB_REV, "status": "failed", "at": asked - 60, "detail": "older attempt"}
    assert post(c, body(version=OLD, seq=2, update=stale), token).json()["update_to"] == HUB_REV
    failed = {"ref": HUB_REV, "status": "rolled_back", "at": asked + 60,
              "detail": "the collector didn't stay running; went back to 1234567"}
    assert "update_to" not in post(c, body(version=OLD, seq=3, update=failed), token).json()
    e = db.recent_events(conn, "testhost")[0]
    assert e["title"] == f"Update to {HUB_REV} failed and was rolled back" and e["severity"] == "medium"
    bad = {"ref": "zzz", "status": "done", "at": 1}
    assert post(c, body(version=OLD, seq=4, update=bad), token).status_code == 422
    # A newer collector's unknown top-level field doesn't break an older hub.
    assert post(c, body(version=OLD, seq=5, something_new=1), token).status_code == 200


def test_hosts_page_buttons(hub_cfg, token):  # noqa: F811
    app = create_app(hub_cfg)
    post(TestClient(app), body(version=OLD, seq=1), token)
    c = logged_in(app)
    html = c.get("/").text
    assert f"Update 1 host to {HUB_REV}" in html and f"Update to {HUB_REV}" in html
    r = c.post("/hosts/update", data={"host": "testhost"}, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert c.post("/hosts/update", data={"host": "testhost"}).status_code == 303
    html = c.get("/").text
    assert f"Updating to {HUB_REV}" in html and "Cancel" in html
    c.post("/hosts/update", data={"host": "testhost", "action": "cancel"})
    assert f"Update to {HUB_REV}" in c.get("/").text
    assert TestClient(app, follow_redirects=False).post("/hosts/update", data={"host": "*"}).status_code == 303
    conn = db.connect_writer(hub_cfg.db_path)
    assert conn.execute("SELECT update_to FROM hosts").fetchone()[0] is None  # not logged in: nothing asked


def test_collector_writes_one_request(cfg, monkeypatch):
    monkeypatch.setattr(remote_update, "full_version", lambda: OLD)
    cfg.db_path.parent.mkdir(parents=True)
    assert remote_update.handle(cfg, "not-a-commit") == "invalid"
    assert remote_update.handle(cfg, "1234567") == "current"
    assert remote_update.handle(cfg, HUB_REV) == "requested"
    request = cfg.db_path.parent / remote_update.REQUEST
    assert request.read_text().strip() == HUB_REV and oct(request.stat().st_mode & 0o777) == "0o600"
    assert remote_update.handle(cfg, HUB_REV) == "waiting"  # not picked up yet
    request.unlink()
    result = cfg.db_path.parent / remote_update.RESULT
    now = time.time()
    result.write_text(json.dumps({"ref": HUB_REV, "status": "failed", "at": now - 60, "detail": "x\u0007y"}))
    assert remote_update.read_result(cfg.data_dir)["detail"] == "xy"
    assert remote_update.handle(cfg, HUB_REV, now) == "waiting"  # tried within the hour
    assert remote_update.handle(cfg, HUB_REV, now + 3600) == "requested"
    request.unlink()
    cfg.upload.remote_update = False
    assert remote_update.handle(cfg, HUB_REV) == "off" and not request.exists()
    result.write_text('{"ref": "../x", "status": "done", "at": 1}')
    assert remote_update.read_result(cfg.data_dir) is None
