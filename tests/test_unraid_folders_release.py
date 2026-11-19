"""Unraid's Docker folders on the Containers page, and the newest stable release (the os_update rule)."""

import asyncio
import json
import re
import time

import httpx
import pytest

from daemonsight import db
from daemonsight.remote import poll, release, store, unraid, unraid_rules
from daemonsight.remote.client import Net

from .fake_unraid import KEY, FakeUnraid, load
from .test_remote import NOW, add, all_data, by_rule, conn, cfg, fake, parsed, rules_for  # noqa: F401 (fixtures)
from .test_remote_web import app_client, c, conn_of, poll_now, save  # noqa: F401 (fixtures)
from .test_hub import hub_cfg  # noqa: F401 (fixture)


def run(coro):
    return asyncio.run(coro)


# --- the folders ----------------------------------------------------------------------------------------------------

def test_the_organizer_query_is_a_read_of_the_schemas_fields():
    q = unraid.Q_FOLDERS
    assert q.startswith("{ docker { organizer { version views { id name rootId flatEntries {")
    for field in ("id", "type", "name", "parentId", "depth", "position", "path", "hasChildren", "childrenIds", "meta { names }"):
        assert field in q
    assert "mutation" not in q and unraid.Q_FOLDERS in [q for q, _r, _t in unraid.SOURCES.values()]


def test_folders_come_out_in_the_owners_order_with_nested_paths():
    f = parsed("unraid_folders", "folders")["folders"]
    assert [x["path"] for x in f] == [["Folder One"], ["Folder Two"], ["Folder Two", "Sub folder"]]
    assert f[0]["containers"] == ["app-3", "app-1", "app-4"]            # by position, names without the slash
    assert f[1]["containers"] == ["app-5", "app-2", "gone-1"] and f[2]["containers"] == ["app-6"]
    assert parsed("unraid_folders", "folders")["ungrouped"] == [f"app-{i}" for i in (7, 8, 9, 10, 11, 12)]


def test_no_view_is_unavailable_not_an_error():
    assert unraid.parse("unraid_folders", {"docker": {"organizer": {"version": 1, "views": []}}}, [])["available"] is False


def groups_of(html):
    """[(heading text, [row anchors])] from the containers page, in page order."""
    out = []
    for body in re.findall(r"<tbody.*?</tbody>", html, re.S):
        head = re.search(r'<th scope="colgroup"[^>]*>(.*?)</th>', body, re.S)
        rows = re.findall(r'<tr id="(ctr-[^"]+)" data-row', body)
        out.append((re.sub(r"<[^>]+>", "", head.group(1)).split() if head else None, rows))
    return out


@pytest.fixture
def polled(c, hub_cfg, fake):
    save(c)
    poll_now(hub_cfg, fake, time.time())
    return c


def test_containers_are_grouped_by_folder_in_order_with_counts_and_an_ungrouped_group(polled):
    html = polled.get("/h/tower/containers").text
    g = groups_of(html)
    assert [h and " ".join(h) for h, _r in g] == ["Folder One 3", "Folder Two 2", "Folder Two / Sub folder 1", "Ungrouped 6"]
    assert g[0][1] == ["ctr-app-3", "ctr-app-1", "ctr-app-4"]
    assert g[1][1] == ["ctr-app-5", "ctr-app-2"]                          # the stale entry (gone-1) is not a row
    assert g[3][1] == [f"ctr-app-{i}" for i in range(7, 13)]
    # Nothing is hidden: every container is on the page exactly once.
    ids = [r for _h, rows in g for r in rows]
    assert sorted(ids) == sorted(f"ctr-app-{i}" for i in range(1, 13)) and len(set(ids)) == 12
    assert "12 total" in html and "4 groups" in html
    # data-label cells and one heading per folder, for the phone layout.
    cells = re.findall(r"<td[^>]*>", html)
    assert cells and all("data-label=" in t for t in cells)
    assert html.count('<th scope="colgroup"') == 4 and html.count("data-group") == 4
    assert 'id="ctr-app-2"' in html and ">Available<" in html
    assert "Docker folders could not be read" not in html


def test_without_the_organizer_the_list_is_flat(c, hub_cfg, fake):
    fake.replies[unraid.Q_FOLDERS] = {"data": {"docker": None}, "errors": [{"message": "Cannot query field \"organizer\""}]}
    save(c)
    poll_now(hub_cfg, fake, time.time())
    html = c.get("/h/tower/containers").text
    g = groups_of(html)
    assert len(g) == 1 and g[0][0] is None and len(g[0][1]) == 12
    assert "Docker folders could not be read" in html and "colgroup" not in html
    assert "unraid_folders" not in c.get("/h/tower/").text              # an older Unraid is not a source problem
    assert store.get(conn_of(hub_cfg), "tower")["fails"] == 0


def test_a_container_with_no_folder_entry_is_ungrouped(polled, hub_cfg):
    conn = conn_of(hub_cfg)
    snap = db.get_snapshot(conn, "tower", "unraid_folders")
    data = snap.data
    data["folders"][0]["containers"].remove("app-3")
    db.put_snapshot(conn, "tower", "unraid_folders", snap.taken_at, True, None, data)
    g = groups_of(polled.get("/h/tower/containers").text)
    assert "ctr-app-3" in g[-1][1] and g[0][1] == ["ctr-app-1", "ctr-app-4"]


def test_folder_names_from_the_server_are_escaped(polled, hub_cfg):
    conn = conn_of(hub_cfg)
    snap = db.get_snapshot(conn, "tower", "unraid_folders")
    data = snap.data
    data["folders"][0]["name"], data["folders"][0]["path"] = "<script>alert(1)</script>", ["<script>alert(1)</script>"]
    db.put_snapshot(conn, "tower", "unraid_folders", snap.taken_at, True, None, data)
    html = polled.get("/h/tower/containers").text
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


# --- the newest release ---------------------------------------------------------------------------------------------

def test_versions_and_the_page_reply():
    assert release.parse_version("7.3.2") == (7, 3, 2, 1) and release.parse_version("7.4.0-rc.1") == (7, 4, 0, 0)
    assert release.parse_version("seven") is None and release.parse_version(None) is None
    ok = release.valid(load("release"))
    assert ok == {"version": "7.4.0", "date": "2026-11-09", "notes": "https://docs.unraid.net/unraid-os/release-notes/7.4.0/"}
    assert release.valid({**load("release"), "version": "7.5.0-rc.1"}) is None          # stable only
    assert release.valid({"error": "Unable to fetch release information"}) is None and release.valid([]) is None
    # A notes link that is not on Unraid's own sites is replaced by the docs address for that version.
    bad = release.valid({**load("release"), "changelogPretty": "https://evil.example/x"})
    assert bad["notes"] == "https://docs.unraid.net/unraid-os/release-notes/7.4.0/"
    assert release.newer({"version": "7.4.0"}, "7.3.2") and not release.newer({"version": "7.3.2"}, "7.3.2")
    assert not release.newer({"version": "7.3.2"}, "7.4.0") and release.newer({"version": "7.4.0"}, "7.4.0-rc.2")
    assert not release.newer(None, "7.3.2") and not release.newer({"version": "7.4.0"}, None)


def test_the_hub_asks_once_a_day_and_sends_nothing_about_the_server(conn, cfg, fake):
    add(conn, cfg)
    net = fake.net()
    assert run(release.refresh(conn, net, NOW)) is True
    req = fake.release_requests[0]
    assert str(req.url) == "https://releases.unraid.net/os?branch=stable" and req.method == "GET"
    ua = req.headers["user-agent"]
    assert re.fullmatch(r"DaemonSight/\S+", ua)
    sent = str(req.url) + json.dumps(dict(req.headers))
    for secret in (KEY, "tower", "4443", "Tower", "x-api-key"):
        assert secret not in sent, secret
    assert release.stored(conn) == {"version": "7.4.0", "date": "2026-11-09",
                                    "notes": "https://docs.unraid.net/unraid-os/release-notes/7.4.0/"}
    assert run(release.refresh(conn, net, NOW + 3600)) is False and run(release.refresh(conn, net, NOW + 86399)) is False
    assert len(fake.release_requests) == 1
    assert run(release.refresh(conn, net, NOW + 86400)) is True and len(fake.release_requests) == 2


def test_a_failed_fetch_keeps_the_old_release_and_retries_in_six_hours(conn, cfg, fake):
    add(conn, cfg)
    net = fake.net()
    run(release.refresh(conn, net, NOW))
    fake.release_status = 503
    run(release.refresh(conn, net, NOW + 86400))
    assert release.stored(conn)["version"] == "7.4.0"
    assert run(release.refresh(conn, net, NOW + 86400 + 3600)) is False
    fake.release_status = 200
    fake.release = {**load("release"), "version": "7.4.1"}
    assert run(release.refresh(conn, net, NOW + 86400 + 6 * 3600)) is True and release.stored(conn)["version"] == "7.4.1"
    fake.fail = httpx.ConnectError("down")
    assert run(release.refresh(conn, net, NOW + 4 * 86400)) is True        # never raises
    assert release.stored(conn)["version"] == "7.4.1"


def test_no_request_without_an_enabled_unraid_system(conn, cfg, fake):
    assert run(release.refresh(conn, fake.net(), NOW)) is False and fake.release_requests == []
    add(conn, cfg)
    conn.execute("UPDATE remotes SET enabled=0")
    assert run(release.refresh(conn, fake.net(), NOW)) is False and fake.release_requests == []


def with_release(version="7.4.0"):
    data = all_data()
    data["release"] = {"version": version, "date": "2026-11-09", "notes": f"https://docs.unraid.net/unraid-os/release-notes/{version}/"}
    return unraid_rules.evaluate(data, NOW)


def test_os_update_is_low_names_both_versions_and_says_what_to_do():
    f = by_rule(with_release(), "unraid.os_update")
    assert len(f) == 1
    x = f[0]
    assert x.severity == "low" and x.title == "Unraid 7.4.0 is available (running 7.3.2)" and x.fix is None
    assert x.basis == "7.4.0" and x.link == "/#os"
    assert "https://docs.unraid.net/unraid-os/release-notes/7.4.0/" in x.detail and "2026-11-09" in x.detail
    steps = x.howto.split("\n")
    assert steps[0].startswith("Read the release notes first: https://docs.unraid.net/unraid-os/release-notes/7.4.0/")
    assert "Boot Device Backup" in steps[1] and "Tools → Update OS" in steps[2]
    assert by_rule(with_release("7.4.1"), "unraid.os_update")[0].basis == "7.4.1"        # a newer one brings an acceptance back
    assert not by_rule(with_release("7.3.2"), "unraid.os_update") and not by_rule(with_release("7.3.1"), "unraid.os_update")
    assert not by_rule(rules_for(), "unraid.os_update")                                   # no release read yet


def test_the_version_shows_on_the_overview_and_the_hosts_page(polled, hub_cfg):
    conn = conn_of(hub_cfg)
    html = polled.get("/h/tower/").text
    assert "7.3.2" in html and "available" not in html.split("id=\"glance-title\">At a glance")[1].split("Last read")[0]
    run(release.refresh(conn, FakeUnraid().net(), time.time()))
    poll_now(hub_cfg, FakeUnraid(), time.time() + 100)
    html = polled.get("/h/tower/").text
    glance = html.split("id=\"glance-title\">At a glance")[1]
    assert "7.4.0 available" in glance and 'id="os"' in html
    assert "Unraid 7.4.0 is available (running 7.3.2)" in html and "Tools → Update OS" in html
    hosts = polled.get("/partials/hosts").text
    assert "Unraid 7.3.2 · API" in hosts and "7.4.0 available" in hosts
    # The finding's link goes to a row that exists, and its panel cites the page it comes from.
    assert "curl -s &#39;https://releases.unraid.net/os?branch=stable&#39;" in html or "curl -s https://releases.unraid.net/os?branch=stable" in html
    # Accepted, it stays visible, and counts only if it changes.
    r = polled.post("/h/tower/findings/accept", data={"rule": "unraid.os_update", "key": "os", "note": "after the audit",
                                                       "next": "/h/tower/"})
    assert r.status_code == 303
    page = polled.get("/h/tower/").text
    # Accepted findings stay in the list, in place, with an Accepted label and their note.
    row = page.split('id="finding-unraid.os_update-os"')[1].split('data-row')[0]
    assert "after the audit" in row and "Unraid 7.4.0 is available" in row and 'data-status-label="accepted"' in row
