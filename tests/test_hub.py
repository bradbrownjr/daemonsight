"""The hub: tokens, the upload route, storing uploads, and the hub's pages."""

import asyncio
import gzip
import json
import os
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import db, hub
from daemonsight.collector import upload
from daemonsight.config import Config
from daemonsight.findings import Finding
from daemonsight.web.app import create_app
from daemonsight.web.auth import hash_password

from .conftest import PASSWORD
from .test_provenance import check_panels
from .test_web import seeded  # noqa: F401 (fixture: a collector's database for "testhost")


@pytest.fixture
def hub_cfg(tmp_path):
    c = Config(host_id="hub", data_dir=str(tmp_path / "hubdata"))
    c.hub.enabled = True
    c.web.password_file = str(tmp_path / "hubpassword")
    c.web.secret_file = str(tmp_path / "hubsecret")
    (tmp_path / "hubpassword").write_text(hash_password(PASSWORD))
    (tmp_path / "hubsecret").write_text("y" * 64)
    return c


@pytest.fixture
def token(hub_cfg):
    conn = db.connect_writer(hub_cfg.db_path)
    t = hub.add_host(conn, "testhost")
    conn.close()
    return t


def body(host="testhost", seq=None, **extra):
    payload = {"v": 1, "host": host, "seq": seq or int(time.time() * 1000), "sent_at": time.time(),
               "version": "test", "max_interval": 60, **extra}
    return gzip.compress(json.dumps(payload).encode())


def post(c, data, token=None, **headers):
    h = {"Content-Type": "application/json", "Content-Encoding": "gzip", **headers}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return c.post("/api/v1/ingest", content=data, headers=h)


# --- tokens -----------------------------------------------------------------

def test_tokens_are_stored_hashed(hub_cfg, token):
    conn = db.connect_writer(hub_cfg.db_path)
    row = conn.execute("SELECT token_hash FROM hosts WHERE id = 'testhost'").fetchone()
    assert row["token_hash"] == hub.hash_token(token) and token not in row["token_hash"]
    assert hub.host_for_token(conn, token)["id"] == "testhost"
    assert hub.host_for_token(conn, token + "x") is None
    with pytest.raises(ValueError):
        hub.add_host(conn, "testhost")
    for bad in ("../etc", "a b", "-x", "", "x" * 64):
        with pytest.raises(ValueError):
            hub.add_host(conn, bad)
    assert hub.revoke_host(conn, "testhost") and hub.host_for_token(conn, token) is None


# --- the upload route -------------------------------------------------------

def test_refusals(hub_cfg, token, caplog):
    hub_cfg.hub.max_upload_mb = 1
    hub_cfg.hub.max_unpacked_mb = 2
    c = TestClient(create_app(hub_cfg))
    assert post(c, body()).status_code == 401
    assert post(c, body(), "wrong").status_code == 401
    assert "Refused upload from testclient: unknown token" in caplog.text
    assert post(c, body(host="other"), token).status_code == 403
    assert post(c, body(), token, **{"Content-Type": "text/plain"}).status_code == 415
    assert post(c, body(), token, **{"Content-Encoding": "br"}).status_code == 415
    assert post(c, b"x" * (2 * 2**20), token).status_code == 413
    bomb = gzip.compress(b" " * (8 * 2**20))  # about 8 KB that unpacks to 8 MB
    assert len(bomb) < 2**20 and post(c, bomb, token).status_code == 413
    assert post(c, gzip.compress(b"{not json"), token).status_code == 400
    assert post(c, body(events=[{"id": 1, "ts": 1, "kind": "x", "title": "t",
                                 "link": "javascript:alert(1)"}]), token).status_code == 422
    assert post(c, body(findings=[{"rule": "host.silent", "key": "k", "severity": "low", "title": "t",
                                   "detail": "d"}]), token).status_code == 422
    assert post(c, body(snapshots=[{"source": "ports", "taken_at": 1, "ok": True,
                                    "data": {"listeners": "x"}}]), token).status_code == 422


def test_bad_tokens_are_rate_limited(hub_cfg, token):
    c = TestClient(create_app(hub_cfg))
    for _ in range(10):
        assert post(c, body(), "wrong").status_code == 401
    assert post(c, body(), token).status_code == 429  # the address is blocked, even with a good token


def test_sequence_numbers(hub_cfg, token):
    c = TestClient(create_app(hub_cfg))
    assert post(c, body(seq=100), token).json() == {"last_seq": 100}
    r = post(c, body(seq=100), token)
    assert r.status_code == 409 and r.json() == {"last_seq": 100}
    assert post(c, body(seq=101), token).status_code == 200


# --- collector to hub -------------------------------------------------------

def uploader_for(cfg, hub_app, conn):
    cfg.upload.url = "https://hub.test/api/v1/ingest"
    up = upload.Uploader(cfg, conn, asyncio.Lock(), (32768, 60999), 60)
    up.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=hub_app), base_url="https://hub.test")
    return up


def test_upload_end_to_end(seeded, hub_cfg, token, tmp_path):  # noqa: F811
    seeded.upload.token_file = str(tmp_path / "hub.token")
    (tmp_path / "hub.token").write_text(token + "\n")
    seeded.exposure.expected_public = ["22/tcp", "5432/tcp"]
    conn = db.connect_writer(seeded.db_path)
    ts = db.now()
    db.add_metrics(conn, "testhost", ts, {"cpu.percent": 12.5, "mem.percent": 40.0})
    db.add_event(conn, "testhost", ts, "port_new", "New listener 22/tcp", link="/services#ports")
    hub_app = create_app(hub_cfg)
    up = uploader_for(seeded, hub_app, conn)

    assert asyncio.run(up.upload_once()) is False
    h = db.connect_writer(hub_cfg.db_path)
    assert set(db.get_snapshots(h, "testhost")) == {"docker", "systemd", "system", "settings"}
    assert db.metric_series(h, "testhost", "cpu.percent", 0) == [(ts, 12.5)]
    assert [e["title"] for e in db.recent_events(h, "testhost")] == ["New listener 22/tcp"]
    assert [f["rule"] for f in db.open_findings(h, "testhost")] == ["expose.docker_bypass"]
    assert db.get_snapshot(h, "testhost", "settings").data["exposure"]["expected_public"] == ["22/tcp", "5432/tcp"]
    row = h.execute("SELECT * FROM hosts WHERE id = 'testhost'").fetchone()
    assert row["last_seen"] and row["version"]

    # Nothing new: the next upload carries no snapshots, metrics or events.
    payload, _, more = upload.build(conn, seeded, (32768, 60999), 60)
    assert payload["snapshots"] == [] and payload["metrics"] == [] and payload["events"] == [] and not more

    # A reply lost after the hub stored the upload: the collector sends the
    # same data again, and the hub adds nothing twice.
    db.set_meta(conn, {"upload.event_id": 0, "upload.metric_row": 0})
    assert asyncio.run(up.upload_once()) is False
    assert len(db.recent_events(h, "testhost")) == 1
    assert len(db.metric_series(h, "testhost", "cpu.percent", 0)) == 1

    # A slow source writes an older timestamp after a newer one was sent.
    db.put_snapshot(conn, "testhost", "caddy", ts - 30, True, None, {"sites": [], "servers": [], "admin": {}})
    assert [s["source"] for s in upload.build(conn, seeded, (32768, 60999), 60)[0]["snapshots"]] == ["caddy"]

    # The finding resolves on the host, so it resolves on the hub.
    db.reconcile_findings(conn, "testhost", db.now(), [])
    asyncio.run(up.upload_once())
    assert db.open_findings(h, "testhost") == []


def test_upload_needs_https():
    for url in ("http://hub.example.com/api/v1/ingest", "ftp://x", "hub.example.com"):
        with pytest.raises(upload.UploadError):
            upload.check_url(url)
    upload.check_url("https://hub.example.com/api/v1/ingest")
    upload.check_url("http://127.0.0.1:8466/api/v1/ingest")


# --- the hub's own findings -------------------------------------------------

def test_silent_hosts_and_clock_skew(hub_cfg, token):
    conn = db.connect_writer(hub_cfg.db_path)
    now = time.time()
    hub.check_silent(conn, now)
    assert db.open_findings(conn, "testhost") == []  # just added
    hub.check_silent(conn, now + 700)
    assert [f["title"] for f in db.open_findings(conn, "testhost")] == ["Never reported"]

    row = hub.host_for_token(conn, token)
    up = hub.Upload.model_validate(json.loads(gzip.decompress(body(seq=5))))
    later = now + 800
    up.sent_at = later - 900  # clock 15 minutes behind
    hub.store(conn, row, up, later, "203.0.113.9")
    assert [f["rule"] for f in db.open_findings(conn, "testhost")] == ["host.clock_skew"]
    assert db.recent_events(conn, "testhost")[0]["title"] == "Reporting again"

    # An upload's findings never close the hub's own.
    db.reconcile_findings(conn, "testhost", later, [], keep_prefix=hub.HUB_RULES)
    assert len(db.open_findings(conn, "testhost")) == 1

    hub.check_silent(conn, later + 3 * 60 + 1)
    assert {f["rule"] for f in db.open_findings(conn, "testhost")} == {"host.clock_skew", "host.silent"}


# --- pages ------------------------------------------------------------------

def test_hub_pages(seeded, hub_cfg, token, tmp_path):  # noqa: F811
    seeded.upload.token_file = str(tmp_path / "hub.token")
    (tmp_path / "hub.token").write_text(token)
    conn = db.connect_writer(seeded.db_path)
    hub_app = create_app(hub_cfg)
    asyncio.run(uploader_for(seeded, hub_app, conn).upload_once())

    c = TestClient(hub_app, follow_redirects=False)
    assert c.get("/").status_code == 303  # login first
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    html = c.get("/").text
    assert 'href="/h/testhost/"' in html and "Reporting" in html and "1 critical" in html

    html = c.get("/h/testhost/").text
    assert 'href="/h/testhost/exposure"' in html and 'hx-get="/h/testhost/partials/overview"' in html
    assert 'href="/h/testhost/services#ctr-db"' in html  # the finding's link, on this host
    assert check_panels(html) > 0
    for page in ("exposure", "routes", "services", "fail2ban"):
        r = c.get(f"/h/testhost/{page}")
        assert r.status_code == 200, page
        check_panels(r.text)
    assert c.get("/h/testhost/partials/services?units=failed").status_code == 200
    assert c.get("/h/nobody/").status_code == 404
    assert c.get("/h/..%2Fetc/").status_code == 404
    assert c.get("/exposure").status_code == 404  # no single-host pages on a hub


def test_hub_prunes_old_metrics(hub_cfg):
    conn = db.connect_writer(hub_cfg.db_path)
    now = time.time()
    db.add_metrics(conn, "a", now - 49 * 3600, {"cpu.percent": 1})
    db.add_metrics(conn, "b", now - 3600, {"cpu.percent": 2})
    db.add_event(conn, "a", now - 40 * 86400, "port_new", "old")
    db.add_event(conn, "a", now - 86400, "port_new", "new")
    db.prune(conn, now, 48, 30, 0)
    assert [r[0] for r in conn.execute("SELECT host FROM metrics")] == ["b"]
    assert [r["title"] for r in db.recent_events(conn, "a")] == ["new"]
    db.prune(conn, now, 0, 0, 0)  # 0 keeps everything
    assert conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0] == 1


# --- enrolling a host ---------------------------------------------------------

def test_set_upload_url_keeps_the_file(tmp_path):
    from daemonsight import config
    p = tmp_path / "config.toml"
    p.write_text('host_id = "web1"  # keep me\n\n[upload]\n# url = ""\ninterval = 30\n\n[web]\nport = 8466\n')
    os.chmod(p, 0o640)
    config.set_upload_url(p, "https://hub.example.com/api/v1/ingest")
    text = p.read_text()
    assert "# keep me" in text and 'url = "https://hub.example.com/api/v1/ingest"\ninterval = 30' in text
    assert oct(p.stat().st_mode & 0o777) == "0o640"
    c = config.load(p)
    assert c.upload.url == "https://hub.example.com/api/v1/ingest" and c.web.port == 8466

    q = tmp_path / "old.toml"
    q.write_text('host_id = "web2"\n')
    config.set_upload_url(q, "https://hub.example.com/api/v1/ingest")
    assert config.load(q).upload.url.endswith("/ingest")
    config.set_upload_url(q, "https://other.example.com/api/v1/ingest")  # replaces, no second line
    assert q.read_text().count("url =") == 1
    for bad in ('https://x/"; evil = 1', "https://x/ y"):
        with pytest.raises(ValueError):
            config.set_upload_url(q, bad)


def test_enroll_by_pipe(hub_cfg, tmp_path, monkeypatch, capsys):
    import io as _io
    import sys as _sys
    from daemonsight import cli
    hub_toml = tmp_path / "hub.toml"
    hub_toml.write_text(f'host_id = "hub"\ndata_dir = "{hub_cfg.data_dir}"\n[hub]\nenabled = true\n')
    assert cli.main(["--config", str(hub_toml), "hub", "add-host", "web1", "--quiet"]) == 0
    token = capsys.readouterr().out.strip()
    assert len(token) >= 32 and "\n" not in token

    host_toml = tmp_path / "host.toml"
    host_toml.write_text(f'host_id = "web1"\ndata_dir = "{tmp_path / "hostdata"}"\n'
                         f'[upload]\ntoken_file = "{tmp_path / "hub.token"}"\n')
    monkeypatch.setattr(_sys, "stdin", _io.StringIO(token + "\n"))
    assert cli.main(["--config", str(host_toml), "set-upload-token",
                     "--url", "https://hub.example.com/api/v1/ingest"]) == 0
    assert (tmp_path / "hub.token").read_text().strip() == token
    assert token not in capsys.readouterr().out
    monkeypatch.setattr(_sys, "stdin", _io.StringIO(token))
    assert cli.main(["--config", str(host_toml), "set-upload-token", "--url", "http://hub.example.com/x"]) == 1
