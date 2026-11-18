"""The pages: add, test, edit, disable and remove a system; what its pages show; and that the API key
never shows up anywhere."""

import logging
import re
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import backup, db, hub
from daemonsight.remote import poll, store, unraid
from daemonsight.remote.client import fingerprint, fmt_fingerprint
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .fake_unraid import KEY, FakeUnraid, load, make_cert
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

URL = "https://tower.test:4443"
CROSS = {"Sec-Fetch-Site": "cross-site"}


@pytest.fixture
def fake():
    return FakeUnraid()


@pytest.fixture
def app_client(hub_cfg, fake):
    def make(f=None):
        app = create_app(hub_cfg, remote_net=(f or fake).net())
        return TestClient(app, follow_redirects=False)
    return make


@pytest.fixture
def c(app_client):
    client = app_client()
    assert client.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    return client


def form(**kw):
    return {"kind": "unraid", "name": "tower", "url": URL, "key": KEY, "tls": "verify", "interval": "60", **kw}


def save(c, **kw):
    return c.post("/remotes/new", data=form(action="save", **kw))


def edit(c, **kw):
    """The edit form with its "Read this system" box ticked, as a browser sends it."""
    return c.post("/remotes/tower/edit", data=form(action="save", enabled="1", **kw))


def conn_of(hub_cfg):
    return db.connect_writer(hub_cfg.db_path)


def pending_of(html):
    return re.search(r'name="pending" value="([^"]*)"', html).group(1)


def poll_now(hub_cfg, fake, at=None):
    conn = conn_of(hub_cfg)
    try:
        import asyncio
        asyncio.run(poll.run_once(conn, hub_cfg, fake.net(), at or time.time()))
    finally:
        conn.close()


# --- access --------------------------------------------------------------------------------

def test_every_remote_page_needs_the_login(app_client, hub_cfg, fake):
    c = app_client()
    for path in ("/remotes/new", "/remotes/tower/edit"):
        r = c.get(path)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
    for path in ("/remotes/new", "/remotes/tower/edit", "/remotes/tower/toggle", "/remotes/tower/remove"):
        r = c.post(path, data=form(action="save"))
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), path
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()
    assert fake.requests == []


def test_cross_site_posts_are_refused_and_change_nothing(c, hub_cfg, fake):
    assert c.post("/remotes/new", data=form(action="save"), headers=CROSS).status_code == 403
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone() and fake.requests == []
    assert save(c).status_code == 303
    for path, data in (("/remotes/tower/edit", form(action="save", enabled="1", interval="90")),
                       ("/remotes/tower/toggle", {"enable": ""}), ("/remotes/tower/remove", {"confirm": "tower"})):
        assert c.post(path, data=data, headers=CROSS).status_code == 403, path
    row = conn_of(hub_cfg).execute("SELECT * FROM remotes WHERE id='tower'").fetchone()
    assert row["enabled"] == 1 and row["interval"] == 60 and store.key_path(hub_cfg.data_dir, "tower").exists()
    # Same-origin and "none" (a typed address) are fine.
    assert c.post("/remotes/tower/toggle", data={"enable": ""}, headers={"Sec-Fetch-Site": "same-origin"}).status_code == 303


def test_the_form_and_its_links(c):
    html = c.get("/remotes/new").text
    assert 'type="password" class="form-control" id="key" name="key"' in html and "Unraid · GraphQL API" in html
    assert 'href="/remotes/new?kind=opnsense"' in html and "OPNsense · REST API" in html
    assert "Viewer" in html and "Settings → Management Access → API Keys" in html
    # How to make the key, with the vendor's docs, opened outside the app.
    assert "Making an Unraid key" in html
    assert ('href="https://docs.unraid.net/API/programmatic-api-key-management/" target="_blank" '
            'rel="noopener noreferrer"') in html
    for page in ("/", "/partials/hosts"):
        h = c.get(page).text
        assert 'href="/remotes/new"' in h
    # The menu (which becomes the phone menu panel) links to it from every hub page.
    nav = re.compile(r'class="nav-link ds-nav-add"\s+href="/remotes/new" title="Add a system" aria-label="Add a system">')
    assert nav.search(c.get("/").text)
    # A divider between the hub's items and a host's sections, only on host pages.
    assert 'class="ds-nav-sep"' not in c.get("/").text
    assert re.search(r'aria-current="page"\s+href="/remotes/new"', html)


# --- test connection ----------------------------------------------------------------------------

def test_test_connection_shows_what_it_found_and_saves_nothing(c, hub_cfg, fake):
    r = c.post("/remotes/new", data=form(action="test"))
    assert r.status_code == 200
    html = r.text
    for expect in ("Connected.", "VIEWER", "tower-test", "7.3.2", "Started", ">6<", ">12<"):
        assert expect in html, expect
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()
    assert not store.key_dir(hub_cfg.data_dir).exists() or not list(store.key_dir(hub_cfg.data_dir).iterdir())
    assert KEY not in html and 'value="' + KEY not in html
    assert pending_of(html)        # the key waits in memory, so Save needs no retyping


def test_save_after_test_does_not_need_the_key_again(c, hub_cfg):
    token = pending_of(c.post("/remotes/new", data=form(action="test")).text)
    r = c.post("/remotes/new", data=form(action="save", key="", pending=token))
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert store.read_key(hub_cfg.data_dir, "tower") == KEY
    # The token works once; saved means forgotten.
    again = c.post("/remotes/new", data=form(action="save", key="", pending=token, name="tower2"))
    assert again.status_code == 400 and "enter the key" in again.text


def test_a_key_with_more_than_viewer_is_refused_with_the_way_to_make_one(c, hub_cfg, fake):
    fake.replies[unraid.Q_ME] = load("me_admin")
    for action in ("test", "save"):
        r = c.post("/remotes/new", data=form(action=action))
        assert r.status_code == 200
        assert "Not saved." in r.text and "ADMIN" in r.text
        assert "Settings → Management Access → API Keys" in r.text and "Viewer role only" in r.text
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()
    assert not store.key_path(hub_cfg.data_dir, "tower").exists()
    assert fake.queries() == [unraid.Q_ME, unraid.Q_ME]     # nothing but the role check was asked
    fake.replies[unraid.Q_ME] = load("me_viewer_with_write")
    r = c.post("/remotes/new", data=form(action="save"))
    assert "permission to change docker" in r.text and not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()


def test_bad_input_is_explained(c, hub_cfg):
    cases = [({"url": "http://tower.lan"}, "plain text"), ({"name": "../x"}, "Name:"), ({"interval": "5"}, "Interval:"),
             ({"interval": "abc"}, "Interval:"), ({"key": "short"}, "API key"), ({"url": ""}, "Address:"),
             ({"kind": "opnsense"}, "secret")]
    for change, expect in cases:
        r = c.post("/remotes/new", data=form(action="test", **change))
        assert r.status_code == 400 and expect in r.text, (change, r.text[:200])
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()


def test_a_wrong_key_or_dead_server_says_so(c, hub_cfg, fake):
    r = c.post("/remotes/new", data=form(action="test", key="not-the-key-not-the-key"))
    assert r.status_code == 400 and "refused the key" in r.text
    fake.fail = httpx.ConnectTimeout("t")
    assert "did not answer" in c.post("/remotes/new", data=form(action="test")).text


def test_a_name_in_use_is_refused(c, hub_cfg):
    conn = conn_of(hub_cfg)
    hub.add_host(conn, "web1")
    r = c.post("/remotes/new", data=form(action="save", name="web1"))
    assert r.status_code == 400 and "already exists" in r.text


# --- save, and the Hosts page ---------------------------------------------------------------------

def test_saving_adds_the_system_the_key_file_and_a_flash(c, hub_cfg, fake):
    r = save(c)
    assert r.status_code == 303 and r.headers["location"] == "/"
    home = c.get("/")
    assert "Added tower." in home.text
    path = store.key_path(hub_cfg.data_dir, "tower")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_text().strip() == KEY
    conn = conn_of(hub_cfg)
    row = conn.execute("SELECT * FROM remotes WHERE id='tower'").fetchone()
    assert (row["kind"], row["url"], row["enabled"], row["tls"], row["interval"]) == ("unraid", URL, 1, "verify", 60)
    assert conn.execute("SELECT kind, token_hash FROM hosts WHERE id='tower'").fetchone()["kind"] == "unraid"
    h = home.text
    assert "Unraid · API" in h and "Not read yet" in h and "tower.test:4443" in h and 'href="/remotes/tower/edit"' in h
    assert "Update to" not in h        # a remote is never offered a collector update
    assert KEY not in h


def test_hosts_page_after_polls(c, hub_cfg, fake):
    save(c)
    poll_now(hub_cfg, fake, time.time())
    h = c.get("/partials/hosts").text
    assert "Reachable" in h and "Unraid 7.3.2" in h and 'data-label="Last poll"' in h and "1 reporting" in h
    assert re.search(r'<span class="badge [^"]+">\d+ (high|medium|low)</span>', h)
    fake.fail = httpx.ConnectTimeout("t")
    poll_now(hub_cfg, fake, time.time() + 61)
    h = c.get("/partials/hosts").text
    assert "Unreachable" in h and "did not answer in time" in h and "0 reporting" in h
    assert KEY not in h


# --- self-signed certificates: pin after confirming the fingerprint ---------------------------------------

def test_a_self_signed_server_is_pinned_only_after_the_fingerprint_is_confirmed(c, hub_cfg, fake, tmp_path):
    pem, _, _ = make_cert(tmp_path, "tower.test")
    fp = fmt_fingerprint(fingerprint(pem))
    fake.server_cert = pem
    r = c.post("/remotes/new", data=form(action="test"))
    assert r.status_code == 200 and fp in r.text and "self-signed" in r.text
    assert 'name="trust" value="' + fp + '"' in r.text and 'value="pin" checked' in r.text
    assert fake.requests == []       # the key was not sent to a server we hadn't confirmed
    # Saving without confirming does nothing.
    assert save(c, tls="pin").status_code == 200
    assert save(c, tls="pin", pin_confirm="00" * 32).status_code == 200
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone() and fake.requests == []
    # Confirm with the button (it carries the fingerprint that was shown), then it connects.
    ok = c.post("/remotes/new", data=form(action="test", tls="pin", trust=fp))
    assert "Connected." in ok.text and "you pinned" in ok.text
    assert save(c, tls="pin", pin_confirm=fp).status_code == 303
    row = conn_of(hub_cfg).execute("SELECT * FROM remotes WHERE id='tower'").fetchone()
    assert row["tls"] == "pin" and row["tls_pin"] == fingerprint(pem) and row["tls_cert"] == pem
    assert KEY in [r.get("x-api-key") for r in fake.headers]      # the key only went once the pin was confirmed
    assert 'value="pin" checked' in c.get("/remotes/tower/edit").text and fp in c.get("/remotes/tower/edit").text


def test_a_changed_certificate_is_refused_by_the_poll_and_by_a_test(c, hub_cfg, fake, tmp_path):
    pem, _, _ = make_cert(tmp_path / "a", "tower.test")
    fp = fmt_fingerprint(fingerprint(pem))
    fake.server_cert = pem
    assert save(c, tls="pin", pin_confirm=fp).status_code == 303
    poll_now(hub_cfg, fake, time.time())
    assert store.get(conn_of(hub_cfg), "tower")["last_error"] is None
    # The server gets a new certificate.
    other, _, _ = make_cert(tmp_path / "b", "tower.test")
    fake.server_cert = other
    fake.requests.clear(); fake.headers.clear()
    poll_now(hub_cfg, fake, time.time() + 61)
    err = store.get(conn_of(hub_cfg), "tower")["last_error"]
    assert "certificate was not accepted" in err and KEY not in err and fake.requests == []
    r = c.post("/remotes/tower/edit", data=form(action="test", tls="pin", pin_confirm=fp, key=""))
    assert "not the one you pinned" in r.text and fmt_fingerprint(fingerprint(other)) in r.text and fake.requests == []


# --- edit, disable, remove ------------------------------------------------------------------------------

def test_edit_keeps_the_key_unless_a_new_one_is_given(c, hub_cfg, fake):
    save(c)
    key_file = store.key_path(hub_cfg.data_dir, "tower")
    r = edit(c, url="https://tower.test:5443", interval="120", key="")
    assert r.status_code == 303
    row = conn_of(hub_cfg).execute("SELECT * FROM remotes WHERE id='tower'").fetchone()
    assert row["url"] == "https://tower.test:5443" and row["interval"] == 120 and key_file.read_text().strip() == KEY
    newkey = "n" * 48
    fake.key = newkey
    assert edit(c, key=newkey).status_code == 303
    assert key_file.read_text().strip() == newkey and stat.S_IMODE(key_file.stat().st_mode) == 0o600
    # A replacement key with too much power is refused and the saved one stays.
    fake.replies[unraid.Q_ME] = load("me_admin")
    fake.key = "m" * 48              # the server accepts this key, but it is an Admin key
    r = edit(c, key="m" * 48)
    assert r.status_code == 200 and "Not saved." in r.text and key_file.read_text().strip() == newkey
    assert "m" * 48 not in r.text
    # Even when the box is unticked, a new key is checked before it is kept.
    r = c.post("/remotes/tower/edit", data=form(action="save", key="m" * 48))
    assert r.status_code == 200 and key_file.read_text().strip() == newkey


def test_the_edit_page_never_shows_the_key(c, hub_cfg):
    save(c)
    html = c.get("/remotes/tower/edit").text
    assert KEY not in html and "Leave empty to keep the saved key" in html and 'name="key"' in html
    assert 'id="name" value="tower" disabled' in html


def test_disable_and_enable(c, hub_cfg, fake):
    save(c)
    poll_now(hub_cfg, fake, time.time())
    r = c.post("/remotes/tower/toggle", data={"enable": ""})
    assert r.status_code == 303 and store.get(conn_of(hub_cfg), "tower")["enabled"] == 0
    assert "Disabled" in c.get("/partials/hosts").text
    fake.requests.clear()
    poll_now(hub_cfg, fake, time.time() + 600)
    assert fake.requests == []
    c.post("/remotes/tower/toggle", data={"enable": "1"})
    poll_now(hub_cfg, fake, time.time() + 1200)
    assert fake.requests and "Reachable" in c.get("/partials/hosts").text
    # Disabling through the edit page works without a connection test.
    fake.fail = httpx.ConnectTimeout("x")
    r = c.post("/remotes/tower/edit", data=form(action="save", key="", url=URL))
    assert r.status_code in (200, 303)


def test_disable_from_the_edit_form_does_not_need_the_server(c, hub_cfg, fake):
    save(c)
    fake.fail = httpx.ConnectTimeout("down")
    form_data = form(action="save", key="")
    form_data.pop("enabled", None)        # an unticked box sends nothing
    r = c.post("/remotes/tower/edit", data=form_data)
    assert r.status_code == 303 and store.get(conn_of(hub_cfg), "tower")["enabled"] == 0


def test_remove_needs_the_name_and_deletes_everything(c, hub_cfg, fake):
    save(c)
    poll_now(hub_cfg, fake, time.time())
    path = store.key_path(hub_cfg.data_dir, "tower")
    r = c.post("/remotes/tower/remove", data={"confirm": "nope"})
    assert r.status_code == 303 and r.headers["location"] == "/remotes/tower/edit" and path.exists()
    assert "type its name" in c.get("/remotes/tower/edit").text
    r = c.post("/remotes/tower/remove", data={"confirm": "tower"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert not path.exists()
    conn = conn_of(hub_cfg)
    for table, col in (("remotes", "id"), ("hosts", "id"), ("snapshots", "host"), ("findings", "host"),
                       ("events", "host"), ("metrics", "host")):
        assert not conn.execute(f"SELECT 1 FROM {table} WHERE {col}='tower'").fetchone(), table
    assert "Removed tower" in c.get("/").text
    assert c.get("/h/tower/").status_code == 404 and c.get("/remotes/tower/edit").status_code == 404


def test_unknown_and_collector_hosts_have_no_edit_page(c, hub_cfg):
    conn = conn_of(hub_cfg)
    hub.add_host(conn, "web1")
    for path in ("/remotes/nope/edit", "/remotes/web1/edit", "/remotes/..%2Fx/edit"):
        assert c.get(path).status_code == 404
    assert c.post("/remotes/web1/remove", data={"confirm": "web1"}).status_code == 404
    assert conn.execute("SELECT 1 FROM hosts WHERE id='web1'").fetchone()


# --- the pages for an Unraid host ---------------------------------------------------------------------------

@pytest.fixture
def polled(c, hub_cfg, fake):
    save(c)
    poll_now(hub_cfg, fake, time.time())
    return c


def test_overview(polled):
    html = polled.get("/h/tower/").text
    assert "At a glance" in html and "7.3.2" in html and "Started" in html and "of 12 running" in html
    assert "Parity check" in html and "UPS" in html and "ONLINE" in html and "Unread notifications" in html
    assert "full" in html and "ds-tiles" in html and "threads" in html
    assert "Findings" in html and 'id="finding-unraid.disk_full-disk1"' in html
    assert check_panels(html) >= 3
    partial = polled.get("/h/tower/partials/overview", headers={"HX-Request": "true"})
    assert partial.status_code == 200 and "At a glance" in partial.text
    # The header says where the data came from, in plain words.
    assert re.search(r"Read (just now|\d+ s ago)", html) and "tower" in html


def test_container_update_column_says_what_it_is(polled):
    html = polled.get("/h/tower/containers").text
    assert "built-in method" not in html and "object at 0x" not in html
    assert re.search(r'data-label="Update"><span class="badge [^"]+">(Available|Current|Unknown)</span>', html)


def test_what_to_do_shows_on_the_overview_the_report_and_the_markdown(polled):
    html = polled.get("/h/tower/").text
    fid = 'id="finding-unraid.container_updates-all"'
    assert fid in html and "What to do" in html
    block = html[html.index(fid):]
    block = block[:block.index("data-row", 10)]
    assert "<ol" in block and "<li>In the Unraid web UI, open the Docker tab and press Check for Updates</li>" in block
    assert "<li>Update the containers you want one at a time, or press Update All</li>" in block
    # The report page: findings with steps and no command stay under "Decide", with their steps.
    rep = polled.get("/h/tower/report").text
    decide = rep[rep.index('id="decide"'):rep.index('id="all"')]
    assert "disk1 is 95% full" in decide and "What to do" in decide and "Allocation method" in decide
    assert "<ol" in rep[rep.index('id="all"'):]
    md = polled.get("/h/tower/report.md").text
    assert "  What to do:" in md and "  1. In the Unraid web UI, open the Docker tab and press Check for Updates" in md
    assert "  2. Update the containers you want one at a time, or press Update All" in md
    decide_md = md[md.index("## Decide"):md.index("## All findings")]
    assert "What to do:" in decide_md and "1. " in decide_md


def test_what_to_do_is_escaped_like_the_rest(polled, hub_cfg):
    conn = conn_of(hub_cfg)
    conn.execute("UPDATE findings SET howto=? WHERE rule='unraid.container_updates'", ("<b>bold</b> step\n1. second *step*",))
    html = polled.get("/h/tower/").text
    assert "<b>bold</b>" not in html and "&lt;b&gt;bold&lt;/b&gt; step" in html
    md = polled.get("/h/tower/report.md").text
    assert r"1. \<b\>bold\</b\> step" in md and r"2. \1. second \*step\*" in md


def test_collector_uploads_carry_no_howto(hub_cfg):
    from daemonsight.collector import upload
    assert "howto" not in hub.FindingIn.model_fields
    row = {"rule": "pkg.updates", "key": "u", "severity": "low", "title": "t", "detail": "d", "link": None,
           "fix": "sudo apt upgrade", "basis": "b", "howto": "steps"}
    assert "howto" not in upload._finding_payload(row)
    with pytest.raises(Exception):
        hub.FindingIn(rule="pkg.updates", key="u", severity="low", title="t", detail="d", howto="steps")


def test_the_notifications_page_lists_every_unread_alert_with_what_becomes_of_it(polled):
    html = polled.get("/h/tower/notifications").text
    assert "Date (UTC)" in html and "2026-10-01" in html and "System crashed" in html       # date, description
    assert "Investigate at Settings / User Utilities / Fix Common Problems" in html
    assert "Covered by a live check" in html and "unraid.disk_full" in html and "unraid.disk_temp" in html
    assert "Finding" in html and "56 listed" in html and "49 alerts, 186 warnings" in html
    assert "more unread than this list holds" in html          # the fixture holds 56 of 235
    cells = re.findall(r"<td[^>]*>", html)
    assert cells and all("data-label=" in t for t in cells)
    ids = re.findall(r'<tr id="(notif-[^"]*)"', html)
    assert len(ids) == 56 and len(set(ids)) == 56


def test_the_old_per_container_findings_resolve(hub_cfg, fake, c):
    save(c)
    conn = conn_of(hub_cfg)
    conn.execute("INSERT INTO findings (host, rule, key, severity, title, detail, first_seen, last_seen) "
                 "VALUES ('tower', 'unraid.container_update', 'app-1', 'low', 'An update is available for app-1', 'd', 1, 2)")
    poll_now(hub_cfg, fake, time.time())
    rules = {f["rule"] for f in db.open_findings(conn, "tower")}
    assert "unraid.container_update" not in rules and "unraid.container_updates" in rules


def test_pages_have_labelled_cells_row_anchors_and_source_panels(polled):
    for path, anchors, query in (
            ("/h/tower/disks", ("array", "parity", "disk-parity", "disk-disk1", "disk-flash"), "array { state"),
            ("/h/tower/containers", ("ctr-app-1",), "docker { containers"),
            ("/h/tower/vms", ("vm-vm-1",), "vms { domains"),
            ("/h/tower/notifications", (), "importance: ALERT")):
        r = polled.get(path)
        assert r.status_code == 200, path
        html = r.text
        for a in anchors:
            assert f'id="{a}"' in html, (path, a)
        cells = re.findall(r"<td[^>]*>", html)
        assert cells and all("data-label=" in t for t in cells), path
        assert check_panels(html) >= 1
        assert query in html and "never a mutation" in html           # the panel names the query
        assert 'hx-get="/h/tower/partials/' in html
        assert polled.get(path.replace("/h/tower/", "/h/tower/partials/")).status_code == 200
        assert KEY not in html


def test_disk_rows_show_what_is_wrong(polled):
    html = polled.get("/h/tower/disks").text
    row = re.search(r'<tr id="disk-disk2".*?</tr>', html, re.S).group(0)
    assert "disk2" in row and "97%" in row and "sdd" in row and 'badge bg-green-lt">ok' in row
    assert "smartctl -a" in html and "Unraid web UI" in html
    assert "Parity check" in html and "COMPLETED".lower() in html


def test_every_finding_link_points_at_a_row_that_exists(polled, hub_cfg):
    conn = conn_of(hub_cfg)
    links = {f["link"] for f in db.open_findings(conn, "tower") if f["link"]}
    assert links
    pages = {}
    for link in links:
        path, _, frag = link.partition("#")
        path = path or "/"
        page = pages.setdefault(path, polled.get("/h/tower" + path).text)
        if frag:
            assert f'id="{frag}"' in page, link


def test_other_hosts_pages_do_not_exist_for_unraid_and_vice_versa(polled, hub_cfg):
    for page in ("exposure", "routes", "services", "packages", "fail2ban", "vulnerabilities"):
        assert polled.get(f"/h/tower/{page}").status_code == 404, page
    assert polled.get("/h/tower/partials/logs/x").status_code == 404
    hub.add_host(conn_of(hub_cfg), "web1")
    for page in ("disks", "containers", "vms", "notifications"):
        assert polled.get(f"/h/web1/{page}").status_code == 404
    nav = polled.get("/h/tower/").text
    assert "Array &amp; disks" in nav or "Array & disks" in nav
    assert 'href="/h/tower/exposure"' not in nav and 'href="/h/tower/disks"' in nav


def test_report_and_accept_work_unchanged(polled, hub_cfg):
    html = polled.get("/h/tower/report").text
    assert "Last read" in html and "Do now" in html and "disk1" in html
    md = polled.get("/h/tower/report.md")
    assert md.status_code == 200 and "# Report for tower" in md.text and "Last read:" in md.text and "DaemonSight:" not in md.text
    before = polled.get("/partials/hosts").text
    r = polled.post("/h/tower/findings/accept", data={"rule": "unraid.disk_full", "key": "disk1", "note": "known, archive disk",
                                                       "next": "/h/tower/"})
    assert r.status_code == 303
    page = polled.get("/h/tower/").text
    assert "Accepted" in page and "known, archive disk" in page
    # The next poll keeps it accepted (the basis, disk1:high, hasn't changed).
    conn = conn_of(hub_cfg)
    acc = conn.execute("SELECT * FROM accepted WHERE host='tower'").fetchall()
    assert len(acc) == 1 and acc[0]["key"] == "disk1"
    assert polled.get("/partials/hosts").text != before    # its count dropped


def test_untrusted_text_from_the_server_is_escaped(polled, hub_cfg, fake):
    evil = "<script>alert(1)</script>"
    fake.set(unraid.Q_NOTIFICATIONS, lambda d: d["notifications"]["alerts"][0].update(title=evil, subject=evil, description=evil))
    fake.set(unraid.Q_DOCKER, lambda d: d["docker"]["containers"][0].update(names=["/" + evil], image=evil))
    poll_now(hub_cfg, fake, time.time() + 400)
    for path in ("/h/tower/notifications", "/h/tower/containers", "/h/tower/", "/h/tower/report"):
        html = polled.get(path).text
        assert "<script>alert(1)" not in html, path
    assert "&lt;script&gt;" in polled.get("/h/tower/notifications").text


def test_events_show_the_remote_outage(c, hub_cfg, fake):
    save(c)
    base = time.time() - 3600
    poll_now(hub_cfg, fake, base)
    fake.fail = httpx.ConnectError("refused")
    for i in range(1, 5):
        poll_now(hub_cfg, fake, base + 61 * i)
    html = c.get("/h/tower/").text
    assert "Could not read this system" in html and "Can&#39;t read this system" in html
    assert "Not reachable" in html       # the header: the last good read is an hour old


# --- the key stays secret -----------------------------------------------------------------------------------------

def test_the_key_appears_in_no_page_log_or_event(app_client, hub_cfg, fake, caplog):
    caplog.set_level(logging.DEBUG)
    c = app_client()
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    seen = []
    seen.append(c.get("/remotes/new").text)
    seen.append(c.post("/remotes/new", data=form(action="test")).text)
    fake.replies[unraid.Q_ME] = load("me_admin")
    seen.append(c.post("/remotes/new", data=form(action="test")).text)
    seen.append(c.post("/remotes/new", data=form(action="test", key="x" * 20 + KEY[:8])).text)
    fake.replies[unraid.Q_ME] = load("me_viewer")
    seen.append(save(c).text)
    fake.fail = httpx.ConnectError(f"boom {KEY}")
    for i in range(5):
        poll_now(hub_cfg, fake, time.time() + 61 * i)
    for path in ("/", "/partials/hosts", "/remotes/tower/edit", "/h/tower/", "/h/tower/report", "/h/tower/report.md",
                 "/h/tower/disks", "/h/tower/containers", "/h/tower/notifications"):
        seen.append(c.get(path).text)
    assert KEY not in "\n".join(seen)
    assert KEY not in caplog.text
    conn = conn_of(hub_cfg)
    dump = "\n".join(str(tuple(r)) for t in ("events", "findings", "remotes", "snapshots") for r in conn.execute(f"SELECT * FROM {t}"))
    assert KEY not in dump
    assert "boom" in dump or "Could not connect" in dump      # the failure was recorded, without the key


# --- the hub around it ------------------------------------------------------------------------------------------------

def test_backups_hold_the_key_files_and_a_restore_brings_them_back(c, hub_cfg, tmp_path):
    save(c)
    conn = conn_of(hub_cfg)
    conn.execute("PRAGMA wal_checkpoint(FULL)")
    conf = tmp_path / "config.toml"
    conf.write_text("")
    path = backup.create(hub_cfg, conf)
    assert "remotes/tower.key" in backup.inspect(path)["files"]
    store.key_path(hub_cfg.data_dir, "tower").unlink()
    conn.close()
    backup.restore(hub_cfg, path, conf)
    key = store.key_path(hub_cfg.data_dir, "tower")
    assert key.read_text().strip() == KEY and stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700


def test_a_backup_cannot_smuggle_files_in_through_the_key_folder(tmp_path, hub_cfg):
    import io, tarfile
    p = tmp_path / "daemonsight-evil.tar.gz"
    with tarfile.open(p, "w:gz") as tar:
        for name in ("state.db", "manifest.json", "remotes/../evil.key", "remotes/a/b.key", "remotes/x.txt"):
            info = tarfile.TarInfo(name)
            info.size = 2
            tar.addfile(info, io.BytesIO(b"{}"))
    with pytest.raises(backup.BackupError, match="unexpected entry"):
        backup.inspect(p)


def test_retention_prunes_a_remotes_history_with_everyone_elses(polled, hub_cfg):
    conn = conn_of(hub_cfg)
    old = time.time() - 10 * 86400
    db.add_metrics(conn, "tower", old, {"cpu.percent": 5.0})
    db.add_event(conn, "tower", old, "x", "old event")
    db.prune(conn, time.time(), metrics_hours=48, events_days=7, resolved_findings_days=0)
    assert not conn.execute("SELECT 1 FROM metrics WHERE host='tower' AND ts < ?", (time.time() - 86400,)).fetchone()
    assert not conn.execute("SELECT 1 FROM events WHERE title='old event'").fetchone()


def test_the_poller_starts_with_the_hub_and_can_be_switched_off(hub_cfg, fake):
    app = create_app(hub_cfg, remote_net=fake.net())
    with TestClient(app) as client:          # runs the lifespan: starts the chores, then cancels them
        assert client.get("/healthz").text == "ok"
    hub_cfg.remote.enabled = False
    with TestClient(create_app(hub_cfg, remote_net=fake.net())) as client:
        assert client.get("/healthz").text == "ok"
