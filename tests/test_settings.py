"""The account menu, the Settings page, and how GUI settings combine with the config file."""

import asyncio
import sqlite3
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daemonsight import config, db, settings
from daemonsight.config import Config
from daemonsight.cve import run as cve_run
from daemonsight.web.app import _hub_chores, create_app

from .conftest import PASSWORD
from .test_cve import put_inventory, serve
from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)
from .test_outside import FakeShodan, chore, open_outside, seed
from .test_web import seeded  # noqa: F401 (fixture: a collector's database for "testhost")

CROSS = {"Sec-Fetch-Site": "cross-site"}


def login(c):
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    return c


@pytest.fixture
def hub(hub_cfg, token):  # noqa: F811
    """A logged-in client on a hub, with its own writer connection for checking what was stored."""
    c = login(TestClient(create_app(hub_cfg), follow_redirects=False))
    conn = db.connect_writer(hub_cfg.db_path)
    yield c, conn, hub_cfg
    conn.close()


def stored(conn):
    return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}


def hub_events(conn):
    return [r["title"] for r in conn.execute("SELECT title FROM events WHERE host = '' ORDER BY id")]


class Tree(HTMLParser):
    """Enough of a DOM to ask what sits inside the element with an id or class."""

    def __init__(self, html):
        super().__init__()
        self.stack, self.nodes = [], []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        node = {"tag": tag, "attrs": a, "path": [n["attrs"].get("id") or n["attrs"].get("class") or n["tag"]
                                                  for n in self.stack], "ids": [n["attrs"].get("id") for n in self.stack],
                "classes": [(n["attrs"].get("class") or "").split() for n in self.stack]}
        self.nodes.append(node)
        if tag not in ("input", "img", "meta", "link", "br", "source", "hr"):
            self.stack.append(node)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                break

    def inside(self, ident):
        return [n for n in self.nodes if ident in n["ids"]]


# --- the account menu --------------------------------------------------------------------------

@pytest.mark.parametrize("which", ["single", "hub"])
def test_account_menu_markup(which, seeded, hub, request):  # noqa: F811
    c = login(TestClient(create_app(seeded), follow_redirects=False)) if which == "single" else hub[0]
    html = c.get("/exposure" if which == "single" else "/").text
    tree = Tree(html)
    (button,) = [n for n in tree.nodes if n["attrs"].get("id") == "ds-acct-btn"]
    assert button["tag"] == "button" and button["attrs"]["aria-label"] == "Account and settings"
    assert button["attrs"]["popovertarget"] == "ds-acct-pop" and button["attrs"]["type"] == "button"
    assert "<svg" in html.split('id="ds-acct-btn"')[1].split("</button>")[0]
    (panel,) = [n for n in tree.nodes if n["attrs"].get("id") == "ds-acct-pop"]
    assert "popover" in panel["attrs"] and panel["attrs"]["aria-label"] == "Account and settings"
    items = tree.inside("ds-acct-pop")
    assert [n["attrs"]["href"] for n in items if n["tag"] == "a"] == ["/settings"]
    themes = [n for n in items if n["tag"] == "button" and n["attrs"].get("name") == "theme"]
    assert [n["attrs"]["value"] for n in themes] == ["light", "dark", "auto"]
    assert [n["attrs"]["aria-pressed"] for n in themes] == ["false", "true", "false"]   # dark until chosen
    assert any(n["attrs"].get("id") == "ds-hide-empty" and n["attrs"].get("type") == "checkbox" for n in items)
    forms = [n["attrs"]["action"] for n in items if n["tag"] == "form"]
    assert forms == ["/theme", "/logout"]
    assert "Log out</button>" in html.split('action="/logout"')[1].split("</form>")[0]
    # The header's old separate controls are gone from the header proper.
    outside_panel = html.replace(html[html.index('id="ds-acct-pop"'):html.index("</form>", html.index('action="/logout"'))], "")
    assert "Hide empty sections" not in outside_panel and "Log out" not in outside_panel
    assert " mode</button>" not in html
    # The row filter stays in the header.
    assert 'id="ds-filter"' in html


def test_phone_menu_holds_the_same_items_inline(seeded):  # noqa: F811
    c = login(TestClient(create_app(seeded), follow_redirects=False))
    html = c.get("/exposure").text
    tree = Tree(html)
    # The panel sits inside the hamburger menu's collapsible region, so a phone shows it there, not as a popover.
    (panel,) = [n for n in tree.nodes if n["attrs"].get("id") == "ds-acct-pop"]
    assert any("ds-collapsible" in cl and "ds-account" in cl for cl in panel["classes"])
    css = c.get("/static/app.css").text
    phone = css[css.index("/* Account menu"):]
    phone = phone[phone.index("@media (max-width: 767.98px)"):phone.index("/* Settings page")]
    assert ".ds-acct-btn { display: none; }" in phone            # the hamburger is the button
    assert ".ds-acct-pop:not(:popover-open), .ds-acct-pop { display: flex; position: static;" in phone
    assert ".ds-no-popover .ds-acct-btn { display: none; }" in css
    js = c.get("/static/app.js").text
    assert 'getElementById("ds-hide-empty")' in js and "initAccount" in js


def test_menu_is_keyboard_reachable_and_closes_on_escape(seeded):  # noqa: F811
    c = login(TestClient(create_app(seeded), follow_redirects=False))
    css = c.get("/static/app.css").text
    # Visible focus styles on the button and every item.
    assert ".ds-acct-btn:focus-visible" in css and ".ds-acct-pop a:focus-visible" in css
    html = c.get("/").text
    # A native popover closes on Escape and on a click outside, and returns focus to its button: no script needed.
    assert "popover" in html and "popovertarget=\"ds-acct-pop\"" in html
    # No inline script or style anywhere (the CSP is script-src 'self'; style-src 'self').
    assert "<script>" not in html and ' style="' not in html and "onclick" not in html
    assert "script-src 'self'" in c.get("/").headers["content-security-policy"]


def test_theme_choice_and_auto(seeded):  # noqa: F811
    c = login(TestClient(create_app(seeded), follow_redirects=False))
    r = c.post("/theme", data={"next": "/settings", "theme": "auto"})
    assert r.headers["location"] == "/settings" and "theme=auto" in r.headers["set-cookie"]
    html = c.get("/").text
    assert 'data-theme-pref="auto"' in html and 'data-bs-theme="dark"' in html
    assert "prefers-color-scheme: dark" in html and '<script src="/static/theme.js"></script>' in html
    assert 'aria-pressed="true"' in html.split('value="auto"')[1].split(">")[0]
    assert "matchMedia" in c.get("/static/theme.js").text
    r = c.post("/theme", data={"next": "/", "theme": "light"})
    assert "theme=light" in r.headers["set-cookie"]
    assert 'data-bs-theme="light"' in c.get("/").text
    # No choice posted: the old toggle between light and dark still works.
    assert "theme=dark" in c.post("/theme", data={"next": "/"}).headers["set-cookie"]
    assert "theme=nonsense" not in c.post("/theme", data={"next": "/", "theme": "nonsense"}).headers["set-cookie"]


# --- precedence --------------------------------------------------------------------------------

def test_precedence_default_file_override(tmp_path, hub_cfg):  # noqa: F811
    f = tmp_path / "config.toml"
    f.write_text("[outside]\nenabled = true\n[retention]\nmetrics_hours = 48\n")   # 48 is the default, still "file"
    base = config.load(f)
    conn = db.connect_writer(tmp_path / "s.db")
    found = settings.overrides(conn)
    assert found == {}
    by = {x["key"]: x for g in settings.describe(base, conn, True) for x in g["fields"]}
    assert (by["outside.enabled"]["source"], by["outside.enabled"]["value"]) == (settings.FILE, True)
    assert by["retention.metrics_hours"]["source"] == settings.FILE          # set in the file, equal to the default
    assert (by["cve.refresh_hours"]["source"], by["cve.refresh_hours"]["value"]) == (settings.DEFAULT, 24)
    assert settings.effective(base, conn) is base
    settings.save(conn, base, {"outside.enabled": False, "cve.refresh_hours": 12.0}, "admin")
    eff = settings.effective(base, conn)
    assert eff.outside.enabled is False and eff.cve.refresh_hours == 12.0
    assert base.outside.enabled is True and base.cve.refresh_hours == 24      # the file's config is untouched
    by = {x["key"]: x for g in settings.describe(base, conn, True) for x in g["fields"]}
    assert by["outside.enabled"]["source"] == settings.HERE and by["outside.enabled"]["file"] == "on"
    assert by["cve.refresh_hours"]["source"] == settings.HERE and by["cve.refresh_hours"]["default"] == "24"
    assert f.read_text().startswith("[outside]\nenabled = true")              # the file is never rewritten
    # Reset goes back to the file's value, or the default.
    assert settings.reset(conn, base, "outside.enabled", "admin") and settings.reset(conn, base, "cve.refresh_hours", "admin")
    assert settings.effective(base, conn) is base
    assert not settings.reset(conn, base, "outside.enabled", "admin")
    conn.close()


def test_old_metrics_name_loses_to_a_setting_made_here(tmp_path):
    f = tmp_path / "config.toml"
    f.write_text("[collector]\nmetrics_retention_hours = 10\n")
    base = config.load(f)
    conn = db.connect_writer(tmp_path / "s.db")
    assert base.metrics_hours == 10 and "retention.metrics_hours" in base.file_keys
    settings.save(conn, base, {"retention.metrics_hours": 72}, "admin")
    assert settings.effective(base, conn).metrics_hours == 72
    conn.close()


def test_a_bad_row_in_the_database_is_ignored(tmp_path, caplog):
    conn = db.connect_writer(tmp_path / "s.db")
    conn.executemany("INSERT INTO settings VALUES (?, ?, 0, 'x')", [
        ("cve.epss_automatable", "5"), ("web.port", "1"), ("outside.enabled", '"yes"'), ("cve.refresh_hours", "not json"),
        ("backup.keep", "9")])
    assert settings.overrides(conn) == {"backup.keep": 9}
    assert settings.effective(Config(), conn).backup.keep == 9
    conn.close()


# --- validation ----------------------------------------------------------------------------------

@pytest.mark.parametrize("key,raw,value", [
    ("outside.enabled", "on", True), ("outside.enabled", "off", False),
    ("outside.refresh_hours", "6", 6.0), ("cve.epss_automatable", "0.25", 0.25),
    ("retention.events_days", "0", 0), ("backup.interval_hours", "", None), ("backup.interval_hours", "12", 12),
    ("outside.addresses", "203.0.113.9\n198.51.100.4=vps-1\n\n203.0.113.9", ["203.0.113.9", "198.51.100.4=vps-1"]),
])
def test_valid_values(key, raw, value):
    assert settings.parse(settings.BY_KEY[key], raw) == value


@pytest.mark.parametrize("key,raw", [
    ("outside.enabled", "maybe"), ("outside.refresh_hours", "0"), ("outside.refresh_hours", "100000"),
    ("outside.refresh_hours", "nan"), ("outside.refresh_hours", "abc"), ("cve.epss_automatable", "0"), ("cve.epss_automatable", "1.5"),
    ("retention.metrics_hours", "4.5"), ("retention.events_days", "-1"), ("backup.keep", "0"),
    ("backup.keep", ""), ("backup.interval_hours", "-3"),
    ("outside.addresses", "10.0.0.5"), ("outside.addresses", "not-an-ip"), ("outside.addresses", "203.0.113.9=bad host"),
    ("outside.addresses", "127.0.0.1"), ("outside.addresses", "\n".join(f"198.51.100.{i % 250}=h{i}" for i in range(101))),
])
def test_invalid_values(key, raw):
    with pytest.raises(settings.Invalid):
        settings.parse(settings.BY_KEY[key], raw)


def all_tabs(c) -> str:
    """Every tab of the Settings page, one after another."""
    return "\n".join(c.get(f"/settings/{t}").text for t in settings.TAB_IDS)


# --- saving on the hub --------------------------------------------------------------------------

def test_the_page_lists_each_field_with_its_source_and_the_licence(hub):
    c, conn, cfg = hub
    html = all_tabs(c)
    for label in ("Outside view", "CVE checks", "Retention", "Backups", "Remote systems", "Config file only"):
        assert label in html
    assert "free for non-commercial use only" in html and "enterprise license" in html
    for key in settings.BY_KEY:
        assert f'name="{key}"' in html
    assert html.count("Default</span>") >= 10 and "Set here</span>" not in html
    assert "Default: off" in html and "Allowed: 1 to 720" in html
    assert "Edit <code>" in html and "config.toml" in html
    assert "Account and settings" in html and 'aria-current="page"' in html


def test_saving_stores_an_override_flashes_and_logs_an_event(hub):
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "outside", "outside.enabled": "on", "outside.refresh_hours": "6",
                                  "outside.addresses": "203.0.113.9\n198.51.100.4=vps"})
    assert r.status_code == 303 and r.headers["location"] == "/settings/security#outside"
    import json
    assert json.loads(stored(conn)["outside.enabled"]) is True
    assert json.loads(stored(conn)["outside.refresh_hours"]) == 6
    assert json.loads(stored(conn)["outside.addresses"]) == ["203.0.113.9", "198.51.100.4=vps"]
    row = conn.execute("SELECT changed_by, changed_at FROM settings WHERE key = 'outside.enabled'").fetchone()
    assert row["changed_by"] == "admin" and abs(row["changed_at"] - time.time()) < 60
    assert cfg.outside.enabled is False                                    # the file-level config object is untouched
    html = c.get("/settings/security").text
    assert "Saved: Outside view, enabled" in html and 'role="status"' in html
    assert "Set here</span>" in html and 'name="reset" value="outside.enabled"' in html
    assert "Reset to default" in html
    titles = hub_events(conn)
    assert "Setting changed: Outside view, enabled: off → on" in titles
    assert "Setting changed: Outside view, refresh hours: 24 → 6" in titles
    assert "Setting changed: Outside view, addresses: none → 203.0.113.9, 198.51.100.4=vps" in titles
    # Hub-wide events: on the Settings page and the Hosts page, and under no host's Recent changes.
    assert "Setting changed: Outside view, enabled: off" in c.get("/settings/changes").text
    hosts = c.get("/").text
    assert "Recent hub changes" in hosts and "Setting changed: Outside view, enabled: off" in hosts
    assert not db.recent_events(conn, "testhost", 10)
    # Saving the same values again changes nothing and says so.
    n = len(hub_events(conn))
    c.post("/settings", data={"group": "outside", "outside.enabled": "on"})
    assert len(hub_events(conn)) == n and "No changes" in c.get("/settings/changes").text


def test_a_setting_applies_to_the_pages_at_once(hub, seeded):  # noqa: F811
    c, conn, cfg = hub
    c.post("/settings", data={"group": "cve", "cve.enabled": "off"})
    conn.execute("INSERT OR IGNORE INTO hosts (id, token_hash, created_at) VALUES ('h1', 'x', 0)")
    assert "turned off on this hub" in c.get("/h/h1/vulnerabilities").text
    assert "Open the Settings page" in c.get("/h/h1/exposure").text


def test_errors_rerender_with_messages_and_save_nothing(hub):
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "cve", "cve.enabled": "on", "cve.refresh_hours": "0", "cve.epss_automatable": "2"})
    assert r.status_code == 400
    assert r.text.count("Enter a number from 1 to 720") == 1 and "Enter a number from 0.001 to 1" in r.text
    assert "Nothing was saved" in r.text and 'value="0"' in r.text           # what was typed is kept
    assert stored(conn) == {} and hub_events(conn) == []
    r = c.post("/settings", data={"group": "outside", "outside.addresses": "10.1.2.3\nnope"})
    assert r.status_code == 400 and "not a public IP address" in r.text and stored(conn) == {}


def test_reset_deletes_the_override_and_logs_it(hub):
    c, conn, cfg = hub
    c.post("/settings", data={"group": "retention", "retention.events_days": "30", "retention.metrics_hours": "24"})
    assert set(stored(conn)) == {"retention.events_days", "retention.metrics_hours"}
    r = c.post("/settings", data={"reset": "retention.events_days"})
    assert r.status_code == 303
    assert set(stored(conn)) == {"retention.metrics_hours"}
    assert "Setting reset: Retention, events days: 30 → 0 (default)" in hub_events(conn)
    r = c.post("/settings", data={"reset": "retention.events_days"})        # nothing left to reset
    assert r.status_code == 303 and "nothing to reset" in c.get("/settings/changes").text
    assert c.post("/settings", data={"reset": "web.port"}).status_code == 400


def test_reset_names_the_config_file_when_it_sets_the_value(tmp_path, hub_cfg, token):  # noqa: F811
    f = tmp_path / "config.toml"
    f.write_text("[backup]\nkeep = 3\n")
    hub_cfg.backup.keep = 3
    hub_cfg.file_keys = frozenset({"backup.keep"})
    c = login(TestClient(create_app(hub_cfg, config_file=f), follow_redirects=False))
    c.post("/settings", data={"group": "backup", "backup.keep": "20"})
    html = c.get("/settings/general").text
    assert "Reset to config file" in html and "Config file: 3" in html and str(f) in html
    c.post("/settings", data={"reset": "backup.keep"})
    conn = db.connect_writer(hub_cfg.db_path)
    assert "Setting reset: Backups, keep: 20 → 3 (config file)" in hub_events(conn)
    conn.close()


@pytest.mark.parametrize("key,value", [
    ("web.port", "9000"), ("web.listen", "0.0.0.0"), ("web.password_file", "/tmp/x"), ("web.secret_file", "/tmp/y"),
    ("web.secure_cookies", "false"), ("hub.enabled", "false"), ("data_dir", "/tmp"), ("backup.dir", "/tmp/b"),
    ("upload.url", "https://example.net/"), ("log_file", "/tmp/l"), ("host_id", "x")])
def test_read_only_settings_are_refused_even_if_posted(hub, key, value):
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "cve", "cve.enabled": "off", key: value})
    assert r.status_code == 400
    assert "be changed on this page" in r.text or "is not a setting" in r.text
    assert stored(conn) == {} and hub_events(conn) == []                 # nothing else in the request was saved either
    r = c.post("/settings", data={"reset": key})
    assert r.status_code == 400 and stored(conn) == {}


def test_read_only_values_are_listed_with_the_reason(hub):
    c, conn, cfg = hub
    html = c.get("/settings/general").text
    section = html.split('id="config-file-only"')[1]
    for label in ("Web listen address", "Web port", "Data folder", "Database", "Backup folder", "Password file",
                  "Session secret file", "Hub enabled", "Upload address"):
        assert label in section
    assert "127.0.0.1" in section and "8466" in section
    assert "lock you out" in section
    assert 'name="web.port"' not in html and 'name="hub.enabled"' not in html


def test_cross_site_and_logged_out_posts_are_refused(hub, hub_cfg):  # noqa: F811
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "cve", "cve.enabled": "off"}, headers=CROSS)
    assert r.status_code == 403 and stored(conn) == {}
    assert c.post("/settings", data={"reset": "cve.enabled"}, headers=CROSS).status_code == 403
    r = c.post("/settings", data={"group": "cve", "cve.enabled": "on"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    anon = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert anon.get("/settings").headers["location"].startswith("/login")
    r = anon.post("/settings", data={"group": "cve", "cve.enabled": "off"})
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert json_value(conn, "cve.enabled") is True


def json_value(conn, key):
    import json
    return json.loads(stored(conn)[key])


# --- single-host installs --------------------------------------------------------------------------

def test_a_single_host_shows_effective_values_read_only(seeded, monkeypatch):  # noqa: F811
    seeded.retention.events_days = 14
    app = create_app(seeded, config_file=Path("/etc/daemonsight/config.toml"))
    c = login(TestClient(app, follow_redirects=False))
    html = all_tabs(c)
    assert "<form method=\"post\" action=\"/settings\"" not in html
    assert 'name="retention.events_days"' not in html and "<select" not in html
    assert "Edit <code>/etc/daemonsight/config.toml</code>" in html and "restart" in html
    assert "opens the database read-only" in html
    assert "<strong>14</strong>" in html and "Config file</span>" in html and "Hub only: not used on this install" in html
    assert "Reset to" not in html and "Recent hub changes" not in html
    assert c.post("/settings", data={"group": "retention", "retention.events_days": "1"}).status_code == 405
    # Settings stored in a database never apply on a host.
    conn = db.connect_writer(seeded.db_path)
    conn.execute("INSERT INTO settings VALUES ('retention.events_days', '99', 0, 'x')")
    conn.close()
    assert "<strong>14</strong>" in c.get("/settings/general").text
    # Without a path from the command line, the page names the real one: $DAEMONSIGHT_CONFIG, else the default.
    monkeypatch.setenv("DAEMONSIGHT_CONFIG", "/srv/ds/custom.toml")
    c2 = login(TestClient(create_app(seeded), follow_redirects=False))
    assert "<code>/srv/ds/custom.toml</code>" in c2.get("/settings/general").text
    monkeypatch.delenv("DAEMONSIGHT_CONFIG")
    c3 = login(TestClient(create_app(seeded), follow_redirects=False))
    assert "<code>/etc/daemonsight/config.toml</code>" in c3.get("/settings/general").text


def test_settings_needs_a_login(seeded):  # noqa: F811
    assert TestClient(create_app(seeded), follow_redirects=False).get("/settings").status_code == 303


def test_a_single_host_with_no_database_still_shows_the_page(cfg):
    c = login(TestClient(create_app(cfg), follow_redirects=False))
    r = c.get("/settings")
    assert r.status_code == 200 and "Config file only" in r.text


# --- the chores read the settings on every pass ------------------------------------------------------

def test_outside_chore_follows_the_setting_without_a_restart(hub):
    c, conn, cfg = hub
    seed(conn)
    fake = FakeShodan()
    ch = chore(cfg, conn, fake)
    assert cfg.outside.enabled is False
    assert asyncio.run(ch.run_once()) == 0 and fake.calls == []
    c.post("/settings", data={"group": "outside", "outside.enabled": "on", "outside.refresh_hours": "1"})
    assert asyncio.run(ch.run_once()) > 0 and fake.calls and open_outside(conn)
    # The address list is read again too.
    c.post("/settings", data={"group": "outside", "outside.addresses": "198.51.100.77=testhost"})
    asyncio.run(ch.run_once(time.time() + 3 * 3600))
    assert "198.51.100.77" in {r.url.path.lstrip("/") for r in fake.calls}
    # Off again: no more requests, and the leftover findings close at that pass, not at a restart.
    c.post("/settings", data={"group": "outside", "outside.enabled": "off"})
    n = len(fake.calls)
    assert asyncio.run(ch.run_once(time.time() + 10 * 3600)) == 0 and len(fake.calls) == n
    assert not open_outside(conn)
    # Reset brings back the file's value (off): still none.
    c.post("/settings", data={"reset": "outside.enabled"})
    assert asyncio.run(ch.run_once(time.time() + 20 * 3600)) == 0


def test_cve_chore_follows_the_setting_without_a_restart(tmp_path, hub_cfg):  # noqa: F811
    hub_cfg.cve.enabled = True
    state = db.connect_writer(hub_cfg.db_path)
    state.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('web1', 'x', 0)")
    put_inventory(state, "web1", [["brotli", "1.0.9-2", ["libbrotli1"]]])
    calls = []
    now = time.time()

    async def go():
        ch = cve_run.Chore(hub_cfg, state, serve(tmp_path, calls))
        await ch.run_once(now)
        assert ("cve.package", "brotli") in {(r["rule"], r["key"]) for r in db.open_findings(state, "web1")} and calls
        settings.save(state, hub_cfg, {"cve.enabled": False}, "admin")
        n = len(calls)
        await ch.run_once(now + 2 * 86400)
        assert len(calls) == n and not [r for r in db.open_findings(state, "web1") if r["rule"].startswith("cve.")]
        settings.save(state, hub_cfg, {"cve.enabled": True}, "admin")
        await ch.run_once(now + 4 * 86400)
        assert len(calls) > n and [r for r in db.open_findings(state, "web1") if r["rule"] == "cve.package"]
        # refresh_hours is read each pass: a long interval means nothing is due a day later.
        settings.save(state, hub_cfg, {"cve.refresh_hours": 720.0}, "admin")
        n = len(calls)
        await ch.run_once(now + 6 * 86400)
        assert len(calls) == n
    asyncio.run(go())
    state.close()


def test_retention_is_read_again_on_each_housekeeping_pass(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    old = time.time() - 40 * 86400
    db.add_event(conn, "testhost", old, "x", "ancient")
    assert hub_cfg.retention.events_days == 0
    settings.save(conn, hub_cfg, {"retention.events_days": 30}, "admin")

    async def one_pass():
        task = asyncio.create_task(_hub_chores(conn, hub_cfg, None))
        await asyncio.sleep(0.5)
        task.cancel()
    asyncio.run(one_pass())
    assert not db.recent_events(conn, "testhost", 10)
    conn.close()


def test_remote_polling_flag_is_effective_per_pass(hub_cfg):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    assert settings.effective(hub_cfg, conn).remote.enabled is True
    settings.save(conn, hub_cfg, {"remote.enabled": False}, "admin")
    assert settings.effective(hub_cfg, conn).remote.enabled is False
    conn.close()


def test_every_chore_is_started_and_decides_each_pass(hub_cfg, token):  # noqa: F811
    """Chores no longer start only when enabled in the file: all run, and each checks its setting every pass."""
    app = create_app(hub_cfg)
    hub_cfg.cve.enabled = False
    with TestClient(app) as c:                       # runs the lifespan: starts the chores
        assert c.get("/healthz").text == "ok"


# --- the schema --------------------------------------------------------------------------------------

def test_migration_adds_the_settings_table(tmp_path):
    path = tmp_path / "old.db"
    conn = db.connect_writer(path)
    conn.execute("DROP TABLE settings")
    conn.execute("PRAGMA user_version=7")
    conn.close()
    assert "settings" not in {r[0] for r in sqlite3.connect(path).execute("SELECT name FROM sqlite_master")}
    conn = db.connect_writer(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert [r[1] for r in conn.execute("PRAGMA table_info(settings)")] == ["key", "value", "changed_at", "changed_by"]
    conn.close()


def test_a_database_without_the_table_reads_as_no_overrides(tmp_path):
    raw = sqlite3.connect(tmp_path / "x.db")
    raw.row_factory = sqlite3.Row
    assert settings.overrides(raw) == {} and settings.effective(Config(), raw).outside.enabled is False
    raw.close()


def test_the_old_epss_high_setting_is_read_as_epss_automatable(tmp_path):
    """[cve] epss_high became epss_automatable: a value saved on the Settings page under the old name applies to the new one until
    the new one is saved (which removes the old row), and a reset removes both."""
    conn = db.connect_writer(tmp_path / "s.db")
    conn.execute("INSERT INTO settings VALUES ('cve.epss_high', '0.2', 0, 'x')")
    assert settings.overrides(conn) == {"cve.epss_automatable": 0.2}
    assert settings.effective(Config(), conn).cve.epss_automatable == 0.2
    conn.execute("INSERT INTO settings VALUES ('cve.epss_high', '9', 0, 'x') ON CONFLICT (key) DO UPDATE SET value = '9'")
    assert settings.overrides(conn) == {}                               # an old value that is not valid for the new field is ignored
    conn.execute("UPDATE settings SET value = '0.2' WHERE key = 'cve.epss_high'")
    settings.save(conn, Config(), {"cve.epss_automatable": 0.07}, "admin")
    assert {r["key"] for r in conn.execute("SELECT key FROM settings")} == {"cve.epss_automatable"}
    assert settings.effective(Config(), conn).cve.epss_automatable == 0.07
    conn.execute("INSERT INTO settings VALUES ('cve.epss_high', '0.3', 0, 'x')")
    assert settings.overrides(conn) == {"cve.epss_automatable": 0.07}   # the saved new name wins over a stale old row
    assert settings.reset(conn, Config(), "cve.epss_automatable", "admin")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0
    conn.close()


def test_the_old_epss_high_name_in_a_config_file_still_loads(tmp_path, caplog):
    from daemonsight import config
    p = tmp_path / "c.toml"
    p.write_text("[cve]\nepss_high = 0.25\nrefresh_hours = 12\n")
    c = config.load(p)
    assert c.cve.epss_automatable == 0.25 and c.cve.refresh_hours == 12 and "cve.epss_automatable" in c.file_keys
    assert "epss_high is renamed epss_automatable" in caplog.text
    p.write_text("[cve]\nepss_high = 0.25\nepss_automatable = 0.5\n")      # the new name wins when both are there
    assert config.load(p).cve.epss_automatable == 0.5
    p.write_text("[cve]\nepss_automatable = 0.02\n")
    assert config.load(p).cve.epss_automatable == 0.02 and config.Config().cve.epss_automatable == 0.04


# --- tabs ----------------------------------------------------------------------------------------------

SECTIONS_OF = {"general": ("retention", "backup", "config-file-only"), "security": ("cve", "outside"),
               "systems": ("remote",), "notifications": ("notify", "notify-channels"), "changes": ("settings-events",)}


def test_every_group_is_on_exactly_one_tab():
    placed = [g for _, _, groups in settings.TABS for g in groups]
    assert sorted(placed) == sorted(settings.GROUPS) and len(placed) == len(set(placed))
    assert settings.TAB_IDS[0] == "general"


@pytest.mark.parametrize("tab", settings.TAB_IDS)
def test_each_tab_renders_its_sections_and_no_others(hub, tab):
    c, conn, cfg = hub
    html = c.get(f"/settings/{tab}").text
    mine = SECTIONS_OF[tab]
    for sid in sum(SECTIONS_OF.values(), ()):
        assert (f'id="{sid}"' in html) == (sid in mine), sid
    assert f'href="/settings/{tab}" aria-current="page"' in html
    assert html.count('class="ds-tab"') == len(settings.TAB_IDS)


def test_a_bare_settings_opens_the_first_tab(hub):
    c, conn, cfg = hub
    html = c.get("/settings").text
    assert 'id="retention"' in html and 'id="cve"' not in html and 'href="/settings/general" aria-current="page"' in html


def test_an_unknown_tab_is_a_404(hub):
    c, conn, cfg = hub
    assert c.get("/settings/nope").status_code == 404
    assert c.get("/settings/notify").status_code == 404


def test_a_single_host_has_no_changes_tab(seeded):  # noqa: F811
    c = login(TestClient(create_app(seeded), follow_redirects=False))
    assert c.get("/settings/changes").status_code == 404
    assert 'href="/settings/changes"' not in c.get("/settings").text


def test_saving_returns_to_the_tab_the_group_is_on(hub):
    c, conn, cfg = hub
    for group, key, value, tab in (("retention", "retention.events_days", "30", "general"),
                                   ("cve", "cve.enabled", "on", "security"),
                                   ("remote", "remote.enabled", "off", "systems"),
                                   ("notify", "notify.hub_url", "https://ds.example.com", "notifications")):
        r = c.post("/settings", data={"group": group, key: value, "tab": tab})
        assert r.status_code == 303 and r.headers["location"] == f"/settings/{tab}#{group}"
        assert "Saved:" in c.get(r.headers["location"].split("#")[0]).text
    r = c.post("/settings", data={"reset": "cve.enabled"})
    assert r.headers["location"] == "/settings/security#cve"


def test_a_bad_value_opens_the_tab_with_the_field(hub):
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "cve", "cve.enabled": "on", "cve.refresh_hours": "0", "tab": "general"})
    assert r.status_code == 400
    assert 'id="cve"' in r.text and 'id="retention"' not in r.text
    assert 'href="/settings/security" aria-current="page"' in r.text and "Nothing was saved" in r.text
    r = c.post("/settings", data={"group": "backup", "backup.keep": "0", "tab": "security"})
    assert r.status_code == 400 and 'id="backup"' in r.text and 'href="/settings/general" aria-current="page"' in r.text


def test_a_refused_key_stays_on_the_posting_tab(hub):
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "cve", "web.port": "1", "tab": "security"})
    assert r.status_code == 400 and 'href="/settings/security" aria-current="page"' in r.text


def test_links_to_a_setting_land_on_its_tab(hub):
    c, conn, cfg = hub
    assert 'href="/settings/changes"' in c.get("/").text
    for link in ("/settings/security#cve", "/settings/security#outside", "/settings/notifications#notify-channels"):
        page, anchor = link.split("#")
        assert f'id="{anchor}"' in c.get(page).text
    assert settings.tab_of("remote") == "systems" and settings.tab_of("unknown") == "general"


def test_tab_forms_keep_their_csrf_check(hub):
    c, conn, cfg = hub
    r = c.post("/settings", data={"group": "cve", "cve.enabled": "off", "tab": "security"}, headers=CROSS)
    assert r.status_code == 403 and stored(conn) == {}
