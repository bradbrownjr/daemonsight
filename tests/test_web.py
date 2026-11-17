import logging

import pytest
from fastapi.testclient import TestClient

from daemonsight import db
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_collector import WIDE, container


@pytest.fixture
def seeded(cfg):
    conn = db.connect_writer(cfg.db_path)
    ts = db.now()
    c = container("status", "exited", 137, oom=True)
    c["logs"] = ["2026-11-15T03:59:40Z db password=***", "plain"]
    db.put_snapshot(conn, "testhost", "docker", ts, True, None,
                    {"version": {}, "containers": [container("db", ports=WIDE), c]})
    db.put_snapshot(conn, "testhost", "systemd", ts, True, None, {"units": [{
        "name": "backup.service", "description": "Nightly backup", "load": "loaded", "active": "failed",
        "sub": "failed", "path": "/", "since": ts - 3600, "restarts": 0, "memory": None, "cpu_ns": 12_000_000_000,
        "main_pid": None, "result": "exit-code", "cgroup": None}], "counts": {"failed": 1}})
    db.put_snapshot(conn, "testhost", "system", ts, True, None, {
        "os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0", "virt": None, "boot_time": ts - 86400 * 41,
        "cpu": {"percent": 23.0, "count": 2, "load": [0.4, 0.3, 0.3]},
        "memory": {"total": 4 * 2**30, "available": 1 * 2**30, "percent": 75.0, "swap_total": 0, "swap_used": 0},
        "disks": [{"mount": "/", "device": "/dev/vda1", "fstype": "ext4", "total": 58e9, "used": 31e9, "percent": 54.0}],
        "net": {"eth0": {"rx_bps": 1.8e6, "tx_bps": 6e5}}})
    from daemonsight.findings import Finding
    db.reconcile_findings(conn, "testhost", ts, [
        Finding("expose.docker_bypass", "5432/tcp", "critical", "Port 5432/tcp is published on all interfaces",
                "detail <b>escaped</b>", "/services#ctr-db")])
    yield cfg
    conn.close()


def client(cfg):
    return TestClient(create_app(cfg), follow_redirects=False)


def login(c):
    r = c.post("/login", data={"password": PASSWORD, "next": "/"})
    assert r.status_code == 303
    return c


def test_requires_login(seeded):
    c = client(seeded)
    r = c.get("/")
    assert r.status_code == 303
    assert r.headers["location"] == "/login?next=/"
    r = c.get("/partials/overview", headers={"HX-Request": "true"})
    assert r.headers["HX-Redirect"] == "/login"


def test_wrong_password_is_logged_and_rate_limited(seeded, caplog):
    c = client(seeded)
    with caplog.at_level(logging.WARNING, logger="daemonsight.auth"):
        for _ in range(5):
            assert c.post("/login", data={"password": "nope"}).status_code == 401
        assert c.post("/login", data={"password": PASSWORD}).status_code == 429
    assert "Failed login from testclient" in caplog.text


def test_open_redirect_blocked(seeded):
    c = client(seeded)
    r = c.post("/login", data={"password": PASSWORD, "next": "//evil.example/"})
    assert r.headers["location"] == "/"


def test_overview(seeded):
    c = login(client(seeded))
    r = c.get("/")
    assert r.status_code == 200
    assert "Port 5432/tcp is published on all interfaces" in r.text
    assert "detail &lt;b&gt;escaped&lt;/b&gt;" in r.text
    assert "Debian GNU/Linux 12 (bookworm)" in r.text
    assert "pct-75" in r.text
    assert "style=" not in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_services_and_logs(seeded):
    c = login(client(seeded))
    r = c.get("/services")
    assert r.status_code == 200
    assert "backup.service" in r.text
    assert "0.0.0.0:5432→5432/tcp" in r.text
    assert "OOM" in r.text
    r = c.get("/services?units=failed")
    assert "backup.service" in r.text
    r = c.get("/partials/logs/status")
    assert "password=***" in r.text
    r = c.get("/partials/logs/nope")
    assert "No logs for nope" in r.text


def test_no_database_yet(cfg):
    c = login(client(cfg))
    r = c.get("/")
    assert r.status_code == 200
    assert "No data yet" in r.text


def test_theme_toggle(seeded):
    c = login(client(seeded))
    r = c.post("/theme", data={"next": "/services"})
    assert r.headers["location"] == "/services"
    assert "theme=light" in r.headers["set-cookie"]


def test_healthz_is_public(cfg):
    assert client(cfg).get("/healthz").text == "ok"
