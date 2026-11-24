"""The Settings page's notification channels: add, edit, Send test and remove, with the login and the cross-site check, and that a
secret is never shown back."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daemonsight import db
from daemonsight.notify import channels
from daemonsight.remote.client import Net
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .fake_notify import DISCORD_URL, NTFY_TOKEN, SLACK_URL, Fake
from .test_hub import hub_cfg  # noqa: F401 (fixture)

CROSS = {"Sec-Fetch-Site": "cross-site"}
SAME = {"Sec-Fetch-Site": "same-origin"}


@pytest.fixture(autouse=True)
def _tz(monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")


@pytest.fixture
def hub(hub_cfg):  # noqa: F811
    fake = Fake()
    c = TestClient(create_app(hub_cfg, remote_net=Net(transport=fake.transport())), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    conn = db.connect_writer(hub_cfg.db_path)
    yield c, conn, hub_cfg, fake
    conn.close()


def post(c, path, data, headers=SAME):
    return c.post(path, data=data, headers=headers)


def slack_form(**over):
    d = {"kind": "slack", "name": "Ops", "secret": SLACK_URL, "severity": ["critical", "high"], "mode": "immediate",
         "deadline_reminders": "on", "skip_empty": "on", "digest_freq": "daily", "digest_time": "08:00"}
    d.update(over)
    return d


def add(c, **over):
    return post(c, "/settings/notify/new", slack_form(**over))


def hub_events(conn):
    return [dict(r) for r in conn.execute("SELECT title, detail FROM events WHERE host='' ORDER BY id")]


def test_the_page_has_a_notifications_section_with_the_hub_address_and_no_channels(hub):
    c, _conn, _cfg, _fake = hub
    html = c.get("/settings").text
    assert 'id="notify"' in html and "Hub address for links" in html and 'id="notify-channels"' in html
    assert "No channels yet" in html and 'href="/settings/notify/new"' in html
    assert "America/New_York" in html and "TZ environment variable" in html


def test_adding_a_channel_stores_it_with_its_secret_in_a_file_and_logs_it_without_the_secret(hub):
    c, conn, cfg, _fake = hub
    r = add(c)
    assert r.status_code == 303 and r.headers["location"] == "/settings#notify-channels"
    (row,) = channels.all_channels(conn)
    assert row["name"] == "Ops" and row["kind"] == "slack" and row["severities"] == ["critical", "high"]
    assert channels.read_secret(cfg.data_dir, row["id"]) == SLACK_URL
    assert "abcdefghijklmnopqrstuvwx" not in "".join(conn.iterdump())
    titles = [e["title"] for e in hub_events(conn)]
    assert "Notification channel added: Ops (Slack)" in titles
    assert SLACK_URL not in json.dumps(hub_events(conn)) and "abcdefghijklmnopqrstuvwx" not in json.dumps(hub_events(conn))
    page = c.get("/settings").text
    assert "Ops" in page and "Slack" in page and f"/settings/notify/{row['id']}" in page and "Manage" in page
    assert SLACK_URL not in page and "abcdefghijklmnopqrstuvwx" not in page
    assert "Notification channel added: Ops (Slack)" in page                         # under Recent hub changes


def test_the_hub_address_defaults_to_the_address_the_admin_used(hub):
    c, conn, cfg, _fake = hub
    add(c)
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key='notify.hub_url'").fetchone()[0]) == "http://testserver"
    assert any("Notifications, hub url" in e["title"] for e in hub_events(conn))
    # a value someone set is never overwritten by the next save
    post(c, "/settings", {"notify.hub_url": "https://daemonsight.example.com", "group": "notify"})
    add(c, name="Second")
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key='notify.hub_url'").fetchone()[0]) == "https://daemonsight.example.com"


def test_the_hub_address_setting_is_checked(hub):
    c, conn, cfg, _fake = hub
    for bad in ("ftp://hub.example.com", "https://u:p@hub.example.com", "https://hub.example.com/?x=1", "not a url"):
        r = post(c, "/settings", {"notify.hub_url": bad, "group": "notify"})
        assert r.status_code == 400, bad
    assert not conn.execute("SELECT 1 FROM settings WHERE key='notify.hub_url'").fetchone()
    assert post(c, "/settings", {"notify.hub_url": "daemonsight.example.com/", "group": "notify"}).status_code == 303
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key='notify.hub_url'").fetchone()[0]) == "https://daemonsight.example.com"
    html = c.get("/settings").text
    assert 'value="https://daemonsight.example.com"' in html


@pytest.mark.parametrize("over, field", [
    ({"name": ""}, "name"), ({"name": "-bad"}, "name"), ({"secret": "https://evil.example/hook"}, "secret"),
    ({"secret": ""}, "secret"), ({"severity": []}, "severity"), ({"mode": "sometimes"}, "mode"),
    ({"mode": "digest", "digest_time": "7pm"}, "digest_time"), ({"mode": "digest", "digest_freq": "monthly", "digest_day": "31"}, "digest_day"),
])
def test_a_bad_form_is_shown_again_with_the_reason_and_nothing_saved(hub, over, field):
    c, conn, cfg, _fake = hub
    r = add(c, **over)
    assert r.status_code == 400 and f'id="{field}-err"' in r.text
    assert channels.all_channels(conn) == []
    assert not list((Path(cfg.data_dir) / "notify").glob("*"))                  # no secret file was left behind
    assert SLACK_URL not in r.text                                          # a typed secret is never put back in the page


def test_each_kind_can_be_added(hub):
    c, conn, cfg, _fake = hub
    assert add(c, name="S").status_code == 303
    assert post(c, "/settings/notify/new", {"kind": "discord", "name": "D", "secret": DISCORD_URL, "severity": ["critical"],
                                            "mode": "digest", "digest_freq": "weekly", "digest_time": "07:30", "digest_weekday": "4"}).status_code == 303
    assert post(c, "/settings/notify/new", {"kind": "ntfy", "name": "N", "ntfy_server": "https://ntfy.example.org", "ntfy_topic": "ds-1",
                                            "ntfy_auth": "token", "secret": NTFY_TOKEN, "severity": ["critical", "high", "medium"],
                                            "mode": "both", "digest_freq": "monthly", "digest_time": "09:00", "digest_day": "5"}).status_code == 303
    assert post(c, "/settings/notify/new", {"kind": "email", "name": "E", "email_host": "smtp.example.com", "email_security": "starttls",
                                            "email_user": "bot", "secret": "app-password", "email_from": "ds@example.com",
                                            "email_to": "a@example.com, b@example.com", "severity": ["critical"], "mode": "immediate"}).status_code == 303
    rows = {r["name"]: r for r in channels.all_channels(conn)}
    assert set(rows) == {"S", "D", "N", "E"}
    assert rows["D"]["digest_freq"] == "weekly" and rows["D"]["digest_weekday"] == 4 and rows["D"]["next_digest_at"]
    assert rows["N"]["config"] == {"server": "https://ntfy.example.org", "topic": "ds-1", "auth": "token"} and rows["N"]["mode"] == "both"
    assert rows["E"]["config"]["port"] == 587 and rows["E"]["config"]["to"] == ["a@example.com", "b@example.com"]
    assert rows["S"]["next_digest_at"] is None and rows["S"]["deadline_reminders"] and not rows["S"]["send_resolved"]
    assert channels.read_secret(cfg.data_dir, rows["E"]["id"]) == "app-password"
    page = c.get("/settings").text
    for secret in (SLACK_URL, DISCORD_URL, NTFY_TOKEN, "app-password"):
        assert secret not in page
    assert "weekly on friday at 07:30" in page.lower() and "next digest" in page.lower()


def test_duplicate_names_are_refused(hub):
    c, conn, cfg, _fake = hub
    add(c)
    assert add(c, name="ops").status_code == 400
    assert len(channels.all_channels(conn)) == 1


def test_the_edit_page_says_a_secret_is_saved_and_never_shows_it(hub):
    c, conn, cfg, _fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    html = c.get(f"/settings/notify/{cid}").text
    assert "A webhook URL is saved" in html and SLACK_URL not in html and "abcdefghijklmnopqrstuvwx" not in html
    assert 'type="password"' in html
    assert re.search(r'name="secret"[^>]*value=', html) is None                 # the box has no value


def test_editing_keeps_the_secret_unless_a_new_one_is_typed(hub):
    c, conn, cfg, _fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    r = post(c, f"/settings/notify/{cid}", slack_form(name="Ops renamed", secret="", severity=["critical"], send_resolved="on"))
    assert r.status_code == 303
    row = channels.get(conn, cid)
    assert row["name"] == "Ops renamed" and row["severities"] == ["critical"] and row["send_resolved"]
    assert channels.read_secret(cfg.data_dir, cid) == SLACK_URL
    new = SLACK_URL.replace("abcdefghijklmnopqrstuvwx", "zzzzzzzzzzzzzzzzzzzzzzzz")
    assert post(c, f"/settings/notify/{cid}", slack_form(name="Ops renamed", secret=new, severity=["critical"], send_resolved="on")).status_code == 303
    assert channels.read_secret(cfg.data_dir, cid) == new
    ev = json.dumps(hub_events(conn))
    assert "Notification channel changed: Ops renamed" in ev and "webhook URL" in ev
    assert "zzzzzzzz" not in ev and "abcdefgh" not in ev
    # a form that changes nothing says so
    assert post(c, f"/settings/notify/{cid}", slack_form(name="Ops renamed", secret="", severity=["critical"], send_resolved="on")).status_code == 303
    assert len([e for e in hub_events(conn) if e["title"].startswith("Notification channel changed")]) == 2     # the third save changed nothing and logged nothing


def test_editing_cannot_change_the_type_or_use_a_wrong_secret(hub):
    c, conn, cfg, _fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    r = post(c, f"/settings/notify/{cid}", {**slack_form(), "kind": "discord", "secret": DISCORD_URL})
    assert r.status_code == 400 and channels.get(conn, cid)["kind"] == "slack"
    assert channels.read_secret(cfg.data_dir, cid) == SLACK_URL


def test_an_ntfy_channel_that_stops_using_a_login_forgets_the_secret(hub):
    c, conn, cfg, _fake = hub
    post(c, "/settings/notify/new", {"kind": "ntfy", "name": "N", "ntfy_server": "https://ntfy.example.org", "ntfy_topic": "t",
                                     "ntfy_auth": "token", "secret": NTFY_TOKEN, "severity": ["critical"], "mode": "immediate"})
    cid = channels.all_channels(conn)[0]["id"]
    assert channels.secret_saved(cfg.data_dir, cid)
    post(c, f"/settings/notify/{cid}", {"name": "N", "ntfy_server": "https://ntfy.example.org", "ntfy_topic": "t", "ntfy_auth": "none",
                                        "severity": ["critical"], "mode": "immediate"})
    assert not channels.secret_saved(cfg.data_dir, cid)
    # switching from a token to a password needs the new secret
    r = post(c, f"/settings/notify/{cid}", {"name": "N", "ntfy_server": "https://ntfy.example.org", "ntfy_topic": "t", "ntfy_auth": "basic",
                                            "ntfy_user": "alice", "severity": ["critical"], "mode": "immediate"})
    assert r.status_code == 400


def test_send_test_posts_the_form_as_typed_and_shows_the_result(hub):
    c, conn, cfg, fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    r = post(c, "/settings/notify-test", {**slack_form(secret=""), "id": str(cid)})
    assert r.status_code == 200 and "The test message was sent" in r.text
    assert len(fake.requests) == 1 and fake.requests[0]["url"] == SLACK_URL                 # the saved secret was used
    body = fake.json()
    assert "test message" in body["text"].lower() and "If you can read it" in json.dumps(body)
    assert "DaemonSight" in body["blocks"][-1]["elements"][0]["text"] and "http://testserver" in body["blocks"][-1]["elements"][0]["text"]
    assert SLACK_URL not in r.text
    assert channels.get(conn, cid)["severities"] == ["critical", "high"]                    # a test saves nothing


def test_send_test_with_a_newly_typed_secret_uses_it_and_does_not_save_it(hub):
    c, conn, cfg, fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    other = SLACK_URL.replace("abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx")       # same path: the fake accepts it
    fake.script = [(404, {}, b"no_service")]
    r = post(c, "/settings/notify-test", {**slack_form(secret=other), "id": str(cid)})
    assert "The test failed" in r.text and "no_service" in r.text and "HTTP 404" in r.text
    assert SLACK_URL not in r.text and "abcdefghijklmnopqrstuvwx" not in r.text
    assert channels.read_secret(cfg.data_dir, cid) == SLACK_URL


def test_send_test_with_a_bad_form_asks_for_the_fix_and_sends_nothing(hub):
    c, conn, cfg, fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    r = post(c, "/settings/notify-test", {**slack_form(secret="", severity=[]), "id": str(cid)})
    assert r.status_code == 400 and "Fix the marked fields" in r.text and not fake.requests


def test_the_edit_page_has_send_test_and_remove_and_the_list_has_one_manage_button(hub):
    c, conn, cfg, _fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    edit = c.get(f"/settings/notify/{cid}").text
    assert 'formaction="/settings/notify-test"' in edit and f'href="/settings/notify/{cid}/remove"' in edit
    lst = c.get("/settings").text
    assert lst.count(f'href="/settings/notify/{cid}"') == 1 and "Send test" not in lst.split('id="notify-channels"')[1].split("</section>")[0]


def test_removing_needs_the_name_and_deletes_everything(hub):
    c, conn, cfg, _fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    conn.execute("INSERT INTO notify_seen (channel_id, host, rule, key, first_seen, severity, title) VALUES (?, 'h', 'r', 'k', 1, 'high', 't')", (cid,))
    page = c.get(f"/settings/notify/{cid}/remove").text
    assert "Type the name to confirm" in page and "The channel and its settings" in page and SLACK_URL not in page
    assert post(c, f"/settings/notify/{cid}/remove", {"confirm": "wrong"}).status_code == 400
    assert channels.get(conn, cid) is not None
    r = post(c, f"/settings/notify/{cid}/remove", {"confirm": "Ops"})
    assert r.status_code == 303
    assert channels.get(conn, cid) is None and not channels.secret_saved(cfg.data_dir, cid)
    assert conn.execute("SELECT COUNT(*) FROM notify_seen").fetchone()[0] == 0
    assert "Notification channel removed: Ops (Slack)" in [e["title"] for e in hub_events(conn)]
    assert "No channels yet" in c.get("/settings").text


def test_every_post_refuses_a_cross_site_request_and_changes_nothing(hub):
    c, conn, cfg, fake = hub
    add(c)
    cid = channels.all_channels(conn)[0]["id"]
    for path, data in (("/settings/notify/new", slack_form(name="Evil")), (f"/settings/notify/{cid}", slack_form(name="Evil")),
                       ("/settings/notify-test", {**slack_form(), "id": str(cid)}), (f"/settings/notify/{cid}/remove", {"confirm": "Ops"})):
        assert post(c, path, data, CROSS).status_code == 403, path
        assert post(c, path, data, {"Sec-Fetch-Site": "same-site"}).status_code == 403, path
    assert [r["name"] for r in channels.all_channels(conn)] == ["Ops"] and channels.secret_saved(cfg.data_dir, cid)
    assert not fake.requests


def test_nothing_is_reachable_without_the_login(hub_cfg):  # noqa: F811
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    for method, path in (("get", "/settings/notify/new"), ("get", "/settings/notify/1"), ("get", "/settings/notify/1/remove"),
                         ("post", "/settings/notify/new"), ("post", "/settings/notify/1"), ("post", "/settings/notify-test"),
                         ("post", "/settings/notify/1/remove")):
        r = getattr(c, method)(path, **({"data": {}, "headers": SAME} if method == "post" else {}))
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), (method, path)


def test_an_unknown_channel_is_a_404(hub):
    c, _conn, _cfg, _fake = hub
    assert c.get("/settings/notify/999").status_code == 404
    assert post(c, "/settings/notify/999", slack_form()).status_code == 404
    assert c.get("/settings/notify/999/remove").status_code == 404


def test_the_new_form_shows_only_its_own_kind_s_fields(hub):
    c, _conn, _cfg, _fake = hub
    slack, ntfy, email = (c.get(f"/settings/notify/new?kind={k}").text for k in ("slack", "discord", "email"))
    assert 'name="secret"' in slack and 'name="ntfy_topic"' not in slack and "Webhook URL" in slack
    assert 'name="email_host"' in email and "Implicit TLS" in email and "STARTTLS" in email and 'value="none"' not in email
    assert 'data-ds-when="f-mode=digest|both"' in slack and "Skip empty digests" in slack
    assert "Save the channel first" in slack


def test_a_collector_install_has_no_channel_pages(hub_cfg, tmp_path):  # noqa: F811
    hub_cfg.hub.enabled = False
    from daemonsight.config import Config
    cfg = Config(host_id="solo", data_dir=str(tmp_path / "solo"))
    cfg.web.password_file, cfg.web.secret_file = hub_cfg.web.password_file, hub_cfg.web.secret_file
    db.connect_writer(cfg.db_path).close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    assert c.get("/settings/notify/new").status_code == 404
    assert "notify-channels" not in c.get("/settings").text
