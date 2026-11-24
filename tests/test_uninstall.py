"""Remove from hub, with "Uninstall the collector first": the hub's pending state and reply, the collector's rules for
acting on it, `daemonsight uninstall`, and what a host shows when the hub refuses its token."""

import asyncio
import gzip
import json
import os
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import cli, db, hub, uninstall
from daemonsight.collector import remote_uninstall, upload
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post  # noqa: F401 (fixtures)
from .test_host_manage import CROSS, add, titles

URL = "https://hub.test/api/v1/ingest"


@pytest.fixture
def conn(hub_cfg):
    c = db.connect_writer(hub_cfg.db_path)
    yield c
    c.close()


@pytest.fixture
def web(hub_cfg):
    app = create_app(hub_cfg)
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    return c


def confirm_remove(c, host, **form):
    return c.post(f"/hosts/{host}/remove", data={"confirm": host, **form})


def state(conn, host):
    return conn.execute("SELECT uninstall_state, uninstall_detail FROM hosts WHERE id = ?", (host,)).fetchone()


# --- the hub -----------------------------------------------------------------

def test_only_the_pending_host_is_told_to_uninstall(hub_cfg, conn):
    t1, t2 = add(conn, "alpha"), add(conn, "beta")
    c = TestClient(create_app(hub_cfg))
    assert "uninstall" not in post(c, body("alpha", seq=1), t1).json()
    hub.request_uninstall(conn, "alpha", time.time())
    assert post(c, body("alpha", seq=2), t1).json() == {"last_seq": 2, "uninstall": True}
    assert "uninstall" not in post(c, body("beta", seq=1), t2).json()   # another host is not asked
    hub.cancel_uninstall(conn, "alpha")
    assert "uninstall" not in post(c, body("alpha", seq=3), t1).json()


def test_pending_survives_a_restart(hub_cfg, conn, web):
    token = add(conn, "alpha", seen=False)
    conn.execute("UPDATE hosts SET last_seen=? WHERE id='alpha'", (time.time(),))
    assert confirm_remove(web, "alpha", uninstall="1").status_code == 303
    assert state(conn, "alpha")["uninstall_state"] == "pending"
    assert hub.host_for_token(conn, token) is not None            # not revoked yet
    assert "Uninstall requested: alpha" in titles(conn)
    # A new app and a new connection: the hub restarted.
    fresh = TestClient(create_app(hub_cfg))
    assert post(fresh, body("alpha", seq=5), token).json()["uninstall"] is True


def test_remove_without_the_box_or_for_a_silent_host_removes_now(hub_cfg, conn, web):
    add(conn, "alpha")
    assert confirm_remove(web, "alpha").status_code == 303        # box not ticked
    assert conn.execute("SELECT 1 FROM hosts WHERE id='alpha'").fetchone() is None
    add(conn, "never", seen=False)
    assert confirm_remove(web, "never", uninstall="1").status_code == 303   # never reported: nothing to ask
    assert conn.execute("SELECT 1 FROM hosts WHERE id='never'").fetchone() is None


def test_confirm_page_box_is_ticked_only_for_a_reporting_host(conn, web):
    add(conn, "alpha")
    add(conn, "never", seen=False)
    on = web.get("/hosts/alpha/manage/remove").text
    assert 'name="uninstall"' in on and "Uninstall the collector first" in on and " checked" in on.split('name="uninstall"')[1][:60]
    off = web.get("/hosts/never/manage/remove").text
    assert " disabled" in off.split('name="uninstall"')[1][:60] and "not reporting" in off


def test_manage_page_shows_the_wait_with_the_upload_interval(hub_cfg, conn, web):
    token = add(conn, "alpha")
    hub.request_uninstall(conn, "alpha", time.time())
    html = web.get("/hosts/alpha/manage").text
    assert "Waiting for alpha to check in (its next upload)" in html
    c = TestClient(create_app(hub_cfg))
    post(c, body("alpha", seq=1, upload_interval=30), token)
    assert "Waiting for alpha to check in (its next upload, about every 30 seconds)" in web.get("/hosts/alpha/manage").text
    conn.execute("UPDATE hosts SET upload_interval=300 WHERE id='alpha'")
    assert "about every 5 minutes" in web.get("/hosts/alpha/manage").text
    assert "Cancel uninstall" in html and "Remove anyway" in html


def test_cancel(conn, web):
    token = add(conn, "alpha")
    hub.request_uninstall(conn, "alpha", time.time())
    assert web.post("/hosts/alpha/uninstall", data={"action": "cancel"}).status_code == 303
    assert state(conn, "alpha")["uninstall_state"] is None
    assert hub.host_for_token(conn, token) is not None
    assert "Uninstall cancelled: alpha" in titles(conn)
    assert "Cancel uninstall" not in web.get("/hosts/alpha/manage").text


def test_remove_anyway_revokes_and_purges_and_links_the_manual_steps(hub_cfg, conn, web):
    token = add(conn, "alpha")
    conn.execute("INSERT INTO events (host, ts, kind, title) VALUES ('alpha', 1, 'x', 'e')")
    hub.request_uninstall(conn, "alpha", time.time())
    r = web.post("/hosts/alpha/uninstall", data={"action": "now"})
    assert r.status_code == 200 and "docs/INSTALL.md#remove" in r.text and "sudo daemonsight uninstall --yes" in r.text
    assert hub.host_for_token(conn, token) is None
    assert conn.execute("SELECT COUNT(*) FROM events WHERE host='alpha'").fetchone()[0] == 0
    assert any(t.startswith("Host removed: alpha") for t in titles(conn))


def test_uninstall_actions_refuse_cross_site_and_idle_hosts(conn, web):
    add(conn, "alpha")
    hub.request_uninstall(conn, "alpha", time.time())
    assert web.post("/hosts/alpha/uninstall", data={"action": "now"}, headers=CROSS).status_code == 403
    assert state(conn, "alpha")["uninstall_state"] == "pending"
    hub.cancel_uninstall(conn, "alpha")
    web.post("/hosts/alpha/uninstall", data={"action": "now"})   # nothing waiting: nothing happens
    assert conn.execute("SELECT 1 FROM hosts WHERE id='alpha'").fetchone() is not None


def test_ack_started_revokes_and_purges_and_records_an_event(hub_cfg, conn):
    token = add(conn, "alpha")
    other = add(conn, "beta")
    conn.execute("INSERT INTO events (host, ts, kind, title) VALUES ('alpha', 1, 'x', 'e')")
    hub.request_uninstall(conn, "alpha", time.time())
    c = TestClient(create_app(hub_cfg))
    r = post(c, body("alpha", seq=9, uninstall="started"), token)
    assert r.status_code == 200 and "uninstall" not in r.json()
    assert hub.host_for_token(conn, token) is None and hub.host_for_token(conn, other) is not None
    assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE host='alpha'").fetchone()[0] == 0
    assert "Host uninstalled and removed: alpha" in titles(conn)
    assert post(c, body("alpha", seq=10), token).status_code == 401


def test_an_ack_from_a_host_that_is_not_pending_does_nothing(hub_cfg, conn):
    token = add(conn, "alpha")
    c = TestClient(create_app(hub_cfg))
    assert post(c, body("alpha", seq=1, uninstall="started"), token).status_code == 200
    assert hub.host_for_token(conn, token) is not None


def test_ack_refused_stops_the_asking_and_shows_why(hub_cfg, conn, web):
    token = add(conn, "alpha")
    hub.request_uninstall(conn, "alpha", time.time())
    c = TestClient(create_app(hub_cfg))
    r = post(c, body("alpha", seq=1, uninstall="refused", uninstall_detail=remote_uninstall.OFF), token)
    assert "uninstall" not in r.json()
    assert tuple(state(conn, "alpha")) == ("refused", remote_uninstall.OFF)
    assert hub.host_for_token(conn, token) is not None
    html = web.get("/hosts/alpha/manage").text
    assert "alpha refused to uninstall: allow_remote_uninstall is off on this host" in html and "Remove anyway" in html
    assert "Uninstall refused by alpha" in titles(conn)
    assert "uninstall" not in post(c, body("alpha", seq=2), token).json()


def test_cli_asks_and_cancels(hub_cfg, conn, capsys, tmp_path):
    add(conn, "alpha")
    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(f'data_dir = "{hub_cfg.data_dir}"\n[hub]\nenabled = true\n')
    assert cli.main(["-c", str(cfgfile), "hub", "uninstall", "alpha"]) == 0
    assert state(conn, "alpha")["uninstall_state"] == "pending"
    assert cli.main(["-c", str(cfgfile), "hub", "uninstall", "alpha", "--cancel"]) == 0
    assert state(conn, "alpha")["uninstall_state"] is None
    assert cli.main(["-c", str(cfgfile), "hub", "uninstall", "nobody"]) == 1


def test_older_database_gets_the_columns(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    c = db.connect_writer(path)
    for col in ("upload_interval", "uninstall_state", "uninstall_asked", "uninstall_detail"):
        c.execute(f"ALTER TABLE hosts DROP COLUMN {col}")
    c.execute("PRAGMA user_version=10")
    c.close()
    c = db.connect_writer(path)
    assert {"upload_interval", "uninstall_state", "uninstall_asked", "uninstall_detail"} <= \
        {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(hosts)")}
    c.close()


# --- the collector -----------------------------------------------------------

@pytest.fixture
def unit(tmp_path, monkeypatch):
    """The path unit install.sh installs, in a temp folder."""
    p = tmp_path / "daemonsight-uninstall.path"
    p.write_text("[Path]\n")
    monkeypatch.setattr(remote_uninstall, "UNIT", p)
    return p


class Hub:
    """A fake hub for the collector: answers each upload from `script`, records what it was sent."""

    def __init__(self, script):
        self.script = script
        self.sent = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(gzip.decompress(request.content))
        self.sent.append((request, payload))
        step = self.script[min(len(self.sent), len(self.script)) - 1]
        if isinstance(step, Exception):
            raise step
        status, extra = step
        extra = dict(extra)
        data = {"last_seq": payload["seq"], **extra} if status == 200 else extra
        return httpx.Response(status, json=data)


def uploader(cfg, hub_double, tmp_path):
    cfg.upload.url = URL
    cfg.upload.token_file = str(tmp_path / "hub.token")
    (tmp_path / "hub.token").write_text("t" * 40 + "\n")
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    conn = db.connect_writer(cfg.db_path)
    up = upload.Uploader(cfg, conn, asyncio.Lock(), (32768, 60999), 60)
    up.client = httpx.AsyncClient(transport=httpx.MockTransport(hub_double), follow_redirects=False)
    return up, conn


def request_file(cfg):
    return Path(cfg.data_dir) / remote_uninstall.REQUEST


def test_collector_acknowledges_then_hands_the_uninstall_to_systemd(cfg, tmp_path, unit, caplog):
    h = Hub([(200, {"uninstall": True}), (200, {})])
    up, _ = uploader(cfg, h, tmp_path)
    asyncio.run(up.upload_once())
    assert len(h.sent) == 2 and "uninstall" not in h.sent[0][1]
    assert h.sent[1][1]["uninstall"] == "started"          # the final upload, before anything is removed
    assert h.sent[1][0].headers["Authorization"] == "Bearer " + "t" * 40
    f = request_file(cfg)
    assert f.exists() and oct(f.stat().st_mode & 0o777) == "0o600"
    assert "uninstall" in caplog.text.lower()
    asyncio.run(up.upload_once())                          # nothing sends a second request or loops
    assert len(h.sent) == 3


def test_collector_still_uninstalls_when_the_final_upload_fails(cfg, tmp_path, unit):
    h = Hub([(200, {"uninstall": True}), httpx.ConnectError("down")])
    up, _ = uploader(cfg, h, tmp_path)
    asyncio.run(up.upload_once())
    assert request_file(cfg).exists()


@pytest.mark.parametrize("step", [
    (401, {"uninstall": True}), (403, {"uninstall": True}), (404, {"uninstall": True}),
    (500, {"uninstall": True}), (302, {"uninstall": True}), (409, {"uninstall": True, "last_seq": 1}),
    httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"),
    httpx.ConnectTimeout("hub unreachable"),
])
def test_collector_never_uninstalls_on_an_error(cfg, tmp_path, unit, step):
    h = Hub([step])
    up, _ = uploader(cfg, h, tmp_path)
    with pytest.raises(upload.UploadError):
        asyncio.run(up.upload_once())
    assert not request_file(cfg).exists() and len(h.sent) == 1


@pytest.mark.parametrize("reply", [{"uninstall": "true"}, {"uninstall": 1}, {"uninstall": False}, {}])
def test_collector_acts_only_on_a_real_true(cfg, tmp_path, unit, reply):
    h = Hub([(200, reply)])
    up, _ = uploader(cfg, h, tmp_path)
    asyncio.run(up.upload_once())
    assert not request_file(cfg).exists() and len(h.sent) == 1


def test_collector_ignores_a_reply_for_another_upload(cfg, tmp_path, unit):
    h = Hub([(200, {"uninstall": True, "last_seq": 1})])   # not the sequence number it sent
    up, _ = uploader(cfg, h, tmp_path)
    asyncio.run(up.upload_once())
    assert not request_file(cfg).exists()


def test_collector_ignores_a_plain_http_hub(cfg, tmp_path, unit):
    h = Hub([(200, {"uninstall": True})])
    up, _ = uploader(cfg, h, tmp_path)
    cfg.upload.url = "http://hub.example.com/api/v1/ingest"
    up.client = httpx.AsyncClient(transport=httpx.MockTransport(h), follow_redirects=False)
    asyncio.run(up.upload_once())
    assert not request_file(cfg).exists()


def test_the_lock_switch_refuses_and_the_hub_is_told(cfg, tmp_path, unit):
    cfg.collector.allow_remote_uninstall = False
    h = Hub([(200, {"uninstall": True}), (200, {"uninstall": True}), (200, {})])
    up, _ = uploader(cfg, h, tmp_path)
    asyncio.run(up.upload_once())
    assert not request_file(cfg).exists() and len(h.sent) == 1
    asyncio.run(up.upload_once())                          # the next upload carries the answer
    assert h.sent[1][1]["uninstall"] == "refused" and h.sent[1][1]["uninstall_detail"] == remote_uninstall.OFF
    asyncio.run(up.upload_once())                          # still asked, so still answering
    assert h.sent[2][1]["uninstall"] == "refused"
    asyncio.run(up.upload_once())                          # the hub stopped asking: the answer stops too
    assert "uninstall" not in h.sent[3][1] and not request_file(cfg).exists()


def test_a_host_without_the_path_unit_refuses(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(remote_uninstall, "UNIT", tmp_path / "missing.path")
    h = Hub([(200, {"uninstall": True}), (200, {})])
    up, _ = uploader(cfg, h, tmp_path)
    asyncio.run(up.upload_once())
    asyncio.run(up.upload_once())
    assert h.sent[1][1]["uninstall"] == "refused" and "update it first" in h.sent[1][1]["uninstall_detail"]
    assert not request_file(cfg).exists()


def test_collector_and_hub_together(hub_cfg, cfg, conn, tmp_path, unit):
    token = hub.add_host(conn, "testhost")
    conn.execute("UPDATE hosts SET last_seen=? WHERE id='testhost'", (time.time(),))
    hub.request_uninstall(conn, "testhost", time.time())
    up, _ = uploader(cfg, lambda r: None, tmp_path)
    (tmp_path / "hub.token").write_text(token)
    up.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(hub_cfg)), base_url="https://hub.test",
                                  follow_redirects=False)
    asyncio.run(up.upload_once())
    assert request_file(cfg).exists()
    assert hub.host_for_token(conn, token) is None         # revoked and purged on the final upload
    assert "Host uninstalled and removed: testhost" in titles(conn)


# --- a refused token ----------------------------------------------------------

def test_a_refused_token_backs_off_an_hour_and_is_shown(cfg, tmp_path, monkeypatch, capsys):
    h = Hub([(401, {})])
    up, conn = uploader(cfg, h, tmp_path)
    delays = []
    stop = asyncio.Event()

    async def fake_wait_for(coro, timeout):
        delays.append(timeout)
        coro.close()
        stop.set()

    monkeypatch.setattr(upload.asyncio, "wait_for", fake_wait_for)
    asyncio.run(up.run(stop))
    assert delays == [upload.REJECTED_RETRY] == [3600]
    bad = upload.rejection(conn)
    assert bad["status"] == 401

    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(f'host_id = "testhost"\ndata_dir = "{cfg.data_dir}"\n[upload]\nurl = "{URL}"\n')
    capsys.readouterr()
    assert cli.main(["-c", str(cfgfile), "status"]) == 0
    out = capsys.readouterr().out
    assert "the hub rejected this host's upload token (HTTP 401" in out and "Last upload: never accepted" in out

    # The local web page says it too.
    c = TestClient(create_app(cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    import html
    assert "the hub rejected this host's upload token (HTTP 401" in html.unescape(c.get("/").text)

    # Accepted again: the mark clears.
    h.script = [(200, {})]
    up.client = httpx.AsyncClient(transport=httpx.MockTransport(h), follow_redirects=False)
    asyncio.run(up.upload_once())
    assert upload.rejection(conn) is None
    capsys.readouterr()
    assert cli.main(["-c", str(cfgfile), "status"]) == 0
    assert "rejected" not in capsys.readouterr().out


def test_other_failures_keep_the_short_backoff(cfg, tmp_path, monkeypatch):
    h = Hub([(500, {})])
    up, conn = uploader(cfg, h, tmp_path)
    delays = []
    stop = asyncio.Event()

    async def fake_wait_for(coro, timeout):
        delays.append(timeout)
        coro.close()
        stop.set()

    monkeypatch.setattr(upload.asyncio, "wait_for", fake_wait_for)
    asyncio.run(up.run(stop))
    assert delays == [cfg.upload.interval] and upload.rejection(conn) is None


# --- daemonsight uninstall ----------------------------------------------------

def make_install(root: Path, web=True, jail=True, sudoers=True) -> list[Path]:
    """Lay down what install.sh lays down (and the optional extras), under a temp root."""
    made = []

    def f(path, text="x"):
        p = root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        made.append(p)

    for u in ("collector.service", "update.service", "update.path", "uninstall.service", "uninstall.path"):
        f(f"/etc/systemd/system/daemonsight-{u}")
    if web:
        f("/etc/systemd/system/daemonsight-web.service")
    f("/opt/daemonsight/venv/bin/python")
    f("/opt/daemonsight/REVISION", "abc1234")
    f("/opt/daemonsight/src/install.sh")
    for name in ("config.toml", "hub.token", "install.options", "password", "secret"):
        f(f"/etc/daemonsight/{name}")
    for name in ("state.db", "update.request", "uninstall.request"):
        f(f"/var/lib/daemonsight/{name}")
    f("/var/lib/daemonsight/backups/b.tar")
    f("/usr/local/sbin/daemonsight-update")
    link = root / "usr/local/bin/daemonsight"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to("/opt/daemonsight/venv/bin/daemonsight")
    made.append(link)
    if jail:
        f("/etc/fail2ban/filter.d/daemonsight.conf")
        f("/etc/fail2ban/jail.d/daemonsight.conf")
    if sudoers:
        f("/etc/sudoers.d/daemonsight-update")
    return made


class Pw:
    pw_dir = "/var/lib/daemonsight"
    pw_shell = "/usr/sbin/nologin"


class Recorder:
    def __init__(self):
        self.cmds = []

    def __call__(self, cmd):
        self.cmds.append(cmd)
        return 0


def lookup_ours(name):
    return Pw()


def lookup_none(name):
    raise KeyError(name)


def test_uninstall_removes_exactly_what_install_sh_installed(tmp_path):
    root = tmp_path / "root"
    made = make_install(root)
    bystanders = []
    for path in ("/etc/systemd/system/other.service", "/etc/fail2ban/jail.d/sshd.conf", "/usr/local/bin/other",
                 "/opt/other/x", "/etc/daemonsight-extra/x", "/var/lib/daemonsightx/x", "/home/u/.bashrc"):
        p = root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("keep")
        bystanders.append(p)
    rec, lines = Recorder(), []
    assert uninstall.run(root, rec, lookup_ours, lines.append) == 0
    assert not any(p.exists() or p.is_symlink() for p in made)
    for d in ("opt/daemonsight", "etc/daemonsight", "var/lib/daemonsight"):
        assert not (root / d).exists()
    assert all(p.read_text() == "keep" for p in bystanders)                 # nothing else was touched
    cmds = [" ".join(c) for c in rec.cmds]
    for unit in ("daemonsight-collector.service", "daemonsight-web.service", "daemonsight-update.path",
                 "daemonsight-uninstall.path"):
        assert f"systemctl disable --now {unit}" in cmds
    assert not any(c.startswith("systemctl disable") and c.endswith(".service") and "collector" not in c
                   and "web" not in c for c in cmds)                        # never the service that runs this
    assert "systemctl daemon-reload" in cmds and "systemctl reload fail2ban" in cmds and "userdel daemonsight" in cmds


def test_uninstall_is_idempotent(tmp_path):
    root = tmp_path / "root"
    make_install(root)
    assert uninstall.run(root, Recorder(), lookup_ours, lambda _l: None) == 0
    rec, lines = Recorder(), []
    assert uninstall.run(root, rec, lookup_none, lines.append) == 0       # the user is gone too
    assert rec.cmds == [] and lines == ["Nothing to remove: DaemonSight is not installed here."]


def test_uninstall_of_a_collector_only_install_without_extras(tmp_path):
    root = tmp_path / "root"
    made = make_install(root, web=False, jail=False, sudoers=False)
    rec = Recorder()
    assert uninstall.run(root, rec, lookup_none, lambda _l: None) == 0
    assert not any(p.exists() or p.is_symlink() for p in made)
    cmds = [" ".join(c) for c in rec.cmds]
    assert "systemctl disable --now daemonsight-web.service" not in cmds and "systemctl reload fail2ban" not in cmds
    assert "userdel daemonsight" not in cmds


def test_an_account_that_is_not_the_one_install_sh_made_is_kept(tmp_path):
    class Other:
        pw_dir = "/home/daemonsight"
        pw_shell = "/bin/bash"
    root = tmp_path / "root"
    make_install(root)
    rec = Recorder()
    uninstall.run(root, rec, lambda n: Other(), lambda _l: None)
    assert ["userdel", "daemonsight"] not in rec.cmds


def test_without_yes_it_only_lists(tmp_path, capsys):
    root = tmp_path / "root"
    made = make_install(root)
    assert uninstall.main(False, root=root) == 0
    out = capsys.readouterr().out
    assert "/opt/daemonsight" in out and "Run it again with --yes" in out
    assert all(p.exists() or p.is_symlink() for p in made)


def test_main_with_yes_prints_and_removes(tmp_path, capsys):
    root = tmp_path / "root"
    made = make_install(root)
    assert uninstall.main(True, root=root, runner=Recorder()) == 0
    out = capsys.readouterr().out
    assert "Removing:" in out and "Removed /opt/daemonsight" in out
    assert not any(p.exists() or p.is_symlink() for p in made)


def test_hub_request_needs_the_request_file_and_the_hosts_own_switch(tmp_path):
    root = tmp_path / "root"
    made = make_install(root)
    request = root / "var/lib/daemonsight/uninstall.request"
    request.unlink()
    assert uninstall.main(False, hub_request=True, allowed=True, root=root, runner=Recorder()) == 0
    assert all(p.exists() or p.is_symlink() for p in made if p != request)   # no request file: nothing happens
    request.write_text("uninstall\n")
    assert uninstall.main(False, hub_request=True, allowed=False, root=root, runner=Recorder()) == 0
    assert (root / "opt/daemonsight").exists() and not request.exists()      # switch off: refused, request dropped
    request.write_text("uninstall\n")
    assert uninstall.main(False, hub_request=True, allowed=True, root=root, runner=Recorder()) == 0
    assert not (root / "opt/daemonsight").exists()


def test_the_cli_command_wires_the_switch(tmp_path, monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(uninstall, "main", lambda yes, hub_request=False, allowed=False, **kw: seen.update(
        yes=yes, hub=hub_request, allowed=allowed) or 0)
    off = tmp_path / "off.toml"
    off.write_text("[collector]\nallow_remote_uninstall = false\n")
    assert cli.main(["-c", str(off), "uninstall", "--hub-request"]) == 0
    assert seen == {"yes": False, "hub": True, "allowed": False}
    on = tmp_path / "on.toml"
    on.write_text("")
    assert cli.main(["-c", str(on), "uninstall", "--yes", "--hub-request"]) == 0
    assert seen == {"yes": True, "hub": True, "allowed": True}
    broken = tmp_path / "broken.toml"
    broken.write_text("this is = = not toml")
    assert cli.main(["-c", str(broken), "uninstall", "--yes"]) == 0      # a host whose config is broken can still go
    assert seen["allowed"] is False


def test_the_removal_list_matches_install_sh_and_the_units_exist():
    """Every path install.sh writes is on the list, and every unit it installs is in packaging/systemd."""
    import re
    repo = Path(__file__).resolve().parent.parent
    text = (repo / "install.sh").read_text()
    units = set(re.findall(r"packaging/systemd/(daemonsight-[a-z-]+\.(?:service|path))", text))
    assert units and {Path(u).name for u in uninstall.UNIT_FILES} == units
    for u in units:
        assert (repo / "packaging" / "systemd" / u).exists()
    assert "/usr/local/sbin/daemonsight-update" in uninstall.COMMANDS and "/usr/local/bin/daemonsight" in uninstall.COMMANDS
    for var in ("PREFIX=/opt/daemonsight", "ETC=/etc/daemonsight", "DATA=/var/lib/daemonsight",
                "USER_NAME=daemonsight"):
        assert var in text
    assert set(uninstall.TREES) == {"/opt/daemonsight", "/etc/daemonsight", "/var/lib/daemonsight"}
    for f in uninstall.FAIL2BAN:
        assert Path(f).name in text
    path_unit = (repo / "packaging/systemd/daemonsight-uninstall.path").read_text()
    assert f"PathExists={uninstall.DATA}/{uninstall.REQUEST}" in path_unit
    assert uninstall.REQUEST == remote_uninstall.REQUEST
    assert "daemonsight uninstall --hub-request" in (repo / "packaging/systemd/daemonsight-uninstall.service").read_text()


def test_the_upload_client_checks_certificates_and_follows_no_redirects(cfg, tmp_path):
    import ssl
    up, _ = uploader(cfg, lambda r: None, tmp_path)
    real = upload.Uploader(cfg, up.conn, asyncio.Lock(), (32768, 60999), 60)   # the client as built, not the test double
    ctx = real.client._transport._pool._ssl_context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert real.client.follow_redirects is False
