"""The hub's side of the Docker reader: the client, what is stored, the origin hints, the findings, the poll, the form
that attaches a reader and the Docker storage page."""

import asyncio
import copy
import logging
import re
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import backup, db
from daemonsight.remote import docker_storage as ds
from daemonsight.remote import poll, store
from daemonsight.remote.client import RemoteError
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .fake_docker import ANON_A, ANON_B, IDS, FakeReader, standard_summary
from .fake_unraid import KEY, FakeUnraid
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

TOKEN = "r" * 24 + "0123456789abcdef"
READER = "http://daemonsight-docker-reader:8467"
NOW = 1_800_000_100.0


def containers(*apps):
    """A container list as the Unraid API gave it: (name, image, managed) tuples."""
    return {"containers": [{"name": n, "image": i, "orphaned": not managed, "state": "RUNNING"} for n, i, managed in apps]}


def stored(summary=None, prev=None, unraid=None, now=NOW):
    return ds.parse_summary(summary or standard_summary(), prev, unraid, now)


def by_name(analysis):
    return {i["name"]: i for i in analysis["unused_images"]}


# --- the address ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw, out", [(READER, READER), ("daemonsight-docker-reader:8467", READER), (" http://10.0.0.5:8467/ ", "http://10.0.0.5:8467"),
                                      ("https://reader.example.lan", "https://reader.example.lan"), ("http://[::1]:8467", "http://[::1]:8467")])
def test_the_reader_address_is_normalized(raw, out):
    assert ds.normalize_url(raw) == out


@pytest.mark.parametrize("raw", ["", "ftp://x", "http://", "http://u:p@host:8467", "http://host:8467/v1/summary", "http://host?x=1",
                                 "http://host#x", "http://host:99999", "http://ho st", "x" * 400, "http://ho\nst"])
def test_a_bad_reader_address_is_refused(raw):
    with pytest.raises(ValueError):
        ds.normalize_url(raw)


# --- the client ---------------------------------------------------------------------------------------------------------

async def reader_for(fake: FakeReader, url=READER) -> ds.Reader:
    return ds.Reader(url, TOKEN, fake.client())


async def test_the_client_sends_a_get_with_the_token_to_two_paths_only():
    fake = FakeReader(TOKEN)
    r = await reader_for(fake)
    assert (await r.get("/v1/summary"))["v"] == 1 and (await r.get("/v1/health"))["ok"] is True
    assert [q.method for q in fake.requests] == ["GET", "GET"] and fake.paths() == ["/v1/summary", "/v1/health"]
    assert all(q.headers["authorization"] == f"Bearer {TOKEN}" and not q.content for q in fake.requests)
    for bad in ("/v1/summary?x=1", "/v1/summary/", "/containers/json", "/v1/containers", "/", "", "v1/summary", "/v1/../containers/json"):
        with pytest.raises(ValueError):
            await r.get(bad)
    assert len(fake.requests) == 2
    assert not any(hasattr(r, n) for n in ("post", "put", "delete", "request", "send"))
    await r.aclose()


async def test_client_errors_are_sorted_and_never_hold_the_token():
    fake = FakeReader(TOKEN)
    cases = [(lambda f: setattr(f, "fail", httpx.ConnectError(f"refused {TOKEN}")), "unreachable"),
             (lambda f: setattr(f, "fail", httpx.ReadTimeout("slow")), "unreachable"),
             (lambda f: setattr(f, "status", 502), "http")]
    for stage, kind in cases:
        f = FakeReader(TOKEN)
        stage(f)
        with pytest.raises(RemoteError) as exc:
            await (await reader_for(f)).get("/v1/summary")
        assert exc.value.kind == kind and TOKEN not in exc.value.message
    r = ds.Reader(READER, "wrong-token-wrong-token-wrong-token", fake.client())
    with pytest.raises(RemoteError) as exc:
        await r.get("/v1/summary")
    assert exc.value.kind == "auth" and "wrong-token" not in exc.value.message


async def test_the_client_does_not_follow_redirects_or_accept_junk():
    def handler(request):
        if request.url.path == "/v1/summary":
            return httpx.Response(302, headers={"Location": "http://evil.example/steal"})
        return httpx.Response(200, text="not json")
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    r = ds.Reader(READER, TOKEN, http)
    with pytest.raises(RemoteError, match="Redirects are not followed"):
        await r.get("/v1/summary")
    with pytest.raises(RemoteError, match="not JSON"):
        await r.get("/v1/health")


async def test_probe_checks_health_and_fetch_gets_the_summary():
    fake = FakeReader(TOKEN)

    class N:
        def reader(self):
            return fake.client()
    p = await ds.probe(N(), READER, TOKEN)
    assert (p.docker, p.api) == ("29.0.0", "1.54")
    assert (await ds.fetch(N(), READER, TOKEN))["v"] == 1
    assert fake.paths() == ["/v1/health", "/v1/summary"]
    fake.token = "other"
    with pytest.raises(RemoteError):
        await ds.probe(N(), READER, TOKEN)


# --- what is stored -----------------------------------------------------------------------------------------------------

def test_the_stored_summary_is_checked_again_and_cut_down():
    raw = standard_summary()
    raw["images"] += [{"id": "not-sha"}, "junk", {"id": "sha256:" + "a" * 64, "tags": "no", "digests": [1, "x" * 900], "created": -5,
                                                  "size": "big", "labels": {"org.opencontainers.image.source": "s" * 999, "evil": "x", 5: 1},
                                                  "in_use": "yes", "Env": ["PASSWORD=x"]}]
    raw["Env"] = ["secret"]
    raw["volumes"] += [{"name": "v" * 300, "refs": 0, "size": None, "anonymous": 1, "labels": {"com.docker.compose.project": "p", "secret": "s"}}]
    out = stored(raw)
    dumped = str(out)
    assert "PASSWORD" not in dumped and "secret" not in dumped and "not-sha" not in dumped
    junk = next(i for i in out["images"] if i["id"] == "sha256:" + "a" * 64)
    assert junk["tags"] == [] and len(junk["digests"][0]) == 200 and junk["created"] is None and junk["size"] is None
    assert junk["in_use"] is False and junk["labels"] == {"org.opencontainers.image.source": "s" * 200}
    vols = out["volumes"]
    assert vols["total"] == 6 and vols["in_use"] == 2 and vols["unknown"] == 0
    assert len(vols["unused"]) == 4 and all(len(v["name"]) <= 100 for v in vols["unused"])
    assert all(set(v["labels"]) <= {"com.docker.compose.project", "com.docker.compose.volume"} for v in vols["unused"])
    # Only the unused volumes are kept in full.
    assert {v["name"] for v in vols["unused"]} >= {ANON_A, ANON_B, "shop_db"}


def test_a_summary_without_df_has_volumes_of_unknown_size_but_known_use():
    raw = standard_summary()
    raw["df_at"], raw["build_cache"], raw["images_reclaimable"], raw["df_running"] = None, None, None, True
    for v in raw["volumes"]:
        v["size"] = None
    out = stored(raw)
    a = ds.analyze(out)
    assert out["df_running"] is True and a["build_cache"] is None and len(a["unused_volumes"]) == 3
    assert all(v["size"] is None for v in a["unused_volumes"])
    assert ds.evaluate(out)       # the volume finding still holds, with "?" for its size


# --- origin hints, one test per rule ------------------------------------------------------------------------------------------

def test_repo_of():
    for ref, repo in [("nginx", "nginx"), ("nginx:1.27", "nginx"), ("docker.io/library/nginx:1", "nginx"), ("library/nginx", "nginx"),
                      ("Ghcr.IO/Acme/Widget:Latest", "ghcr.io/acme/widget"), ("localhost:5000/team/app:2", "localhost:5000/team/app"),
                      ("localhost:5000/app", "localhost:5000/app"), ("acme/widget@sha256:" + "a" * 64, "acme/widget"),
                      ("acme/widget:1@sha256:" + "a" * 64, "acme/widget"), ("sha256:" + "a" * 64, ""), ("", ""), ("<none>", "<none>")]:
        assert ds.repo_of(ref) == repo, ref


def test_rule_1_superseded_needs_no_tag_and_a_newer_image_in_use():
    a = ds.analyze(stored(unraid=containers(("widget", "ghcr.io/acme/widget:latest", True))))
    old = by_name(a)["ghcr.io/acme/widget (untagged)"]
    assert old["hint"] == {"key": "superseded", "text": "old version of ghcr.io/acme/widget left by an update; safe to remove"}
    assert old["superseded"] and [i["name"] for i in a["superseded"]] == [old["name"]]
    # A tagged unused image of the same repository is not "superseded" (it has a tag someone chose).
    raw = standard_summary()
    for i in raw["images"]:
        if i["id"] == IDS["widget-old"]:
            i["tags"] = ["ghcr.io/acme/widget:1.0"]
    assert ds.analyze(stored(raw))["unused_images"][0]["hint"]["key"] != "superseded"
    assert not any(i["superseded"] for i in ds.analyze(stored(raw))["unused_images"])
    # Older than the image in use is required: when the untagged one is the newer, it is not "left by an update".
    raw = standard_summary()
    for i in raw["images"]:
        if i["id"] == IDS["widget-old"]:
            i["created"] += 10 ** 9
    assert "ghcr.io/acme/widget (untagged)" in by_name(ds.analyze(stored(raw)))
    assert not by_name(ds.analyze(stored(raw)))["ghcr.io/acme/widget (untagged)"]["superseded"]


def test_rule_1_also_matches_by_the_source_label_when_the_digest_names_differ():
    raw = standard_summary()
    for i in raw["images"]:
        if i["id"] == IDS["widget-old"]:
            i["digests"] = []
    a = ds.analyze(stored(raw))
    old = next(i for i in a["unused_images"] if i["id"] == IDS["widget-old"])
    assert old["hint"]["key"] == "superseded" and "https://github.com/acme/widget" in old["hint"]["text"]
    assert old["name"] == IDS["widget-old"].removeprefix("sha256:")[:12] + " (untagged)"


def test_rule_2_removed_app_needs_an_app_the_hub_saw_and_nothing_using_it_now():
    gone = {"acme/oldapp": {"name": "oldapp", "seen": 1_790_000_000}}
    a = ds.analyze(stored(prev={"apps_seen": gone}))
    assert by_name(a)["acme/oldapp:latest"]["hint"] == {
        "key": "removed_app", "text": "app oldapp was removed from Unraid; its template may still be there"}
    # A container (or another image in use) of the same repository means the app is still installed.
    a = ds.analyze(stored(prev={"apps_seen": gone}), containers(("oldapp2", "acme/oldapp:2", True)))
    assert by_name(a)["acme/oldapp:latest"]["hint"]["key"] == "none"
    # Never seen: no claim that it was removed.
    assert by_name(ds.analyze(stored()))["acme/oldapp:latest"]["hint"]["key"] == "none"
    # It beats the source label (rule 3).
    a = ds.analyze(stored(prev={"apps_seen": {"acme/gadget": {"name": "gadget", "seen": 1}}}))
    assert by_name(a)["acme/gadget:2"]["hint"]["key"] == "removed_app"


def test_apps_are_remembered_only_for_containers_with_a_template():
    apps = ds.remember_apps(None, containers(("a", "nginx:1", True), ("b", "acme/b:2", False), ("c", "", True)), 50.0)
    assert apps == {"nginx": {"name": "a", "seen": 50}}
    apps = ds.remember_apps(apps, containers(("a2", "acme/new:1", True)), 90.0)
    assert apps["nginx"] == {"name": "a", "seen": 50} and apps["acme/new"]["name"] == "a2"
    many = {f"r{i}": {"name": "x", "seen": i} for i in range(ds.APPS_KEPT + 20)}
    kept = ds.remember_apps(many, None, 1.0)
    assert len(kept) == ds.APPS_KEPT and "r0" not in kept and f"r{ds.APPS_KEPT + 19}" in kept
    assert ds.remember_apps("junk", containers(), 1.0) == {}


def test_rule_3_source_label():
    h = by_name(ds.analyze(stored()))["acme/gadget:2"]["hint"]
    assert h == {"key": "source", "text": "from https://example.test/acme/gadget"}


def test_rule_4_bare_base_image_only_without_a_template():
    assert by_name(ds.analyze(stored()))["debian:12"]["hint"] == {"key": "base", "text": "base image, probably pulled for a build or a test"}
    a = ds.analyze(stored(prev={"apps_seen": {"debian": {"name": "mydeb", "seen": 1}}}))
    assert by_name(a)["debian:12"]["hint"]["key"] == "removed_app"          # a remembered app: not "bare"
    for ref in ("python:3.13", "node:22", "alpine:3", "ubuntu:24.04", "fedora:44", "docker.io/library/debian:13"):
        img = {"id": "sha256:" + "b" * 64, "tags": [ref], "digests": [], "labels": {}}
        assert ds.hint(img, [], set(), {})["key"] == "base", ref
    img = {"id": "sha256:" + "b" * 64, "tags": ["acme/python-tool:1"], "digests": [], "labels": {}}
    assert ds.hint(img, [], set(), {})["key"] == "none"


def test_rule_5_no_hint():
    h = by_name(ds.analyze(stored()))["someone/mystery:1"]["hint"]
    assert h == {"key": "none", "text": "no hint"}


def test_every_hint_comes_with_when_the_image_arrived():
    a = by_name(ds.analyze(stored()))
    assert (a["debian:12"]["arrived"], a["debian:12"]["arrived_how"]) == (1748779200, "tagged")     # LastTagTime
    assert (a["acme/oldapp:latest"]["arrived"], a["acme/oldapp:latest"]["arrived_how"]) == (1730000000, "built")   # else Created
    assert all(i["arrived"] for i in a.values())
    assert ds.arrived({"last_tag": None, "created": None}) == (None, "built")


def test_volumes_say_in_use_or_not_anonymous_or_named_and_the_compose_project():
    a = ds.analyze(stored())
    by = {v["name"]: v for v in a["unused_volumes"]}
    assert set(by) == {ANON_A, ANON_B, "shop_db"} and a["volumes_total"] == 5 and a["volumes_in_use"] == 2
    assert by[ANON_A]["anonymous"] and by[ANON_A]["hint"] == "left by a container that was removed"
    assert not by["shop_db"]["anonymous"] and by["shop_db"]["project"] == "shop" and by["shop_db"]["hint"] == "from compose project shop"
    assert [v["name"] for v in a["unused_volumes"]][0] == "shop_db"           # largest first
    raw = standard_summary()
    for v in raw["volumes"]:
        if v["name"] == "shop_db":
            v["labels"] = {}
    assert {v["name"]: v for v in ds.analyze(stored(raw))["unused_volumes"]}["shop_db"]["hint"] == "named volume; no container uses it"


# --- findings -------------------------------------------------------------------------------------------------------------------

def finds(data=None, unraid=None):
    return {f.rule: f for f in ds.evaluate(data or stored(), unraid)}


def test_the_superseded_finding():
    f = finds()["docker.superseded_images"]
    assert (f.severity, f.key, f.fix) == ("low", "all", "docker image prune")
    assert f.title == "1 old image version left by updates, 290.0 MB"
    assert f.link == "/docker#images" and "docker image prune" in f.howto and "Remove all dangling images" in f.howto
    assert "-a" not in f.fix


def test_the_unused_images_finding_has_a_fix_line_per_image_and_leaves_the_superseded_ones_to_the_other():
    f = finds()["docker.unused_images"]
    assert f.severity == "info" and f.title == "5 images no container uses, 1.4 GB"
    lines = f.fix.splitlines()
    assert len(lines) == 5 and all(ln.startswith("docker image rm ") for ln in lines)
    assert "docker image rm acme/tool:1 acme/tool:stable" in lines                  # several tags: by name, not by id
    assert IDS["widget-old"].removeprefix("sha256:")[:12] not in f.fix            # that one is in the superseded finding
    assert "image prune -a" not in f.fix and "prune" not in f.fix
    assert "prune -a" in f.howto and "do not" in f.howto.lower()


def test_the_unused_volumes_finding_warns_about_data_and_never_offers_a_prune_all():
    f = finds()["docker.unused_volumes"]
    assert f.severity == "info" and f.title == "3 volumes no container uses, 934.0 MB" and f.link == "/docker#volumes"
    assert f.fix is None                                                          # a decision, one volume at a time
    first = f.howto.splitlines()[0]
    assert first.startswith("WARNING") and "only copy of data" in first
    assert "docker volume rm" in f.howto and "Never run docker volume prune" in f.howto
    assert "docker volume prune" not in (f.fix or "") and "system prune" not in (f.fix or "")


def test_the_build_cache_finding_is_over_5_gb_only():
    f = finds()["docker.build_cache"]
    assert (f.severity, f.fix, f.title) == ("info", "docker builder prune", "Docker build cache is 6.1 GB")
    assert "Remove build cache" in f.howto and "--filter until" in f.howto
    for size, expect in ((ds.CACHE_FINDING_MIN, False), (ds.CACHE_FINDING_MIN + 1, True), (0, False), (None, False)):
        raw = standard_summary()
        raw["build_cache"] = {"count": 1, "size": size}
        assert ("docker.build_cache" in finds(stored(raw))) is expect, size
    raw = standard_summary()
    raw["build_cache"] = None
    assert "docker.build_cache" not in finds(stored(raw))


def test_basis_has_no_sizes_or_dates_so_an_accept_stays_put_and_a_new_item_brings_it_back():
    base = {r: f.basis for r, f in finds().items()}
    raw = standard_summary()
    for i in raw["images"]:
        i["size"] = (i["size"] or 0) + 12345
        i["created"] = (i["created"] or 0) + 99
    for v in raw["volumes"]:
        v["size"] = (v["size"] or 0) + 7_000_000
    raw["build_cache"] = {"count": 99, "size": 9_999_999_999}
    raw["generated"] += 5000
    again = finds(stored(raw))
    assert {r: f.basis for r, f in again.items()} == base
    # Titles do move with the sizes, which is why the basis is not the title.
    assert again["docker.unused_volumes"].title != finds()["docker.unused_volumes"].title
    raw = standard_summary()
    raw["volumes"].append({"name": "newvol", "created": "", "driver": "local", "labels": {}, "anonymous": False, "size": 1, "refs": 0})
    changed = finds(stored(raw))
    assert changed["docker.unused_volumes"].basis != base["docker.unused_volumes"]
    assert changed["docker.unused_images"].basis == base["docker.unused_images"]


def test_a_long_list_keeps_the_fix_short_enough_to_store():
    raw = standard_summary()
    for n in range(300):
        raw["images"].append({"id": "sha256:" + f"{n:064x}", "tags": [f"acme/app{n}:1"], "digests": [], "created": 1, "size": 1,
                              "last_tag": None, "labels": {}, "in_use": False})
    f = finds(stored(raw))["docker.unused_images"]
    assert len(f.fix) <= 2000 and f.fix.splitlines()[-1].startswith("# ") and "more" in f.fix.splitlines()[-1]
    assert f.title.startswith("305 images")


def test_nothing_to_report_when_nothing_is_unused():
    raw = standard_summary()
    for i in raw["images"]:
        i["in_use"] = True
    for v in raw["volumes"]:
        v["refs"] = 1
    raw["build_cache"] = {"count": 1, "size": 1}
    assert ds.evaluate(stored(raw)) == [] and ds.evaluate(None) == []


# --- the poll --------------------------------------------------------------------------------------------------------------------

def conn_of(cfg):
    return db.connect_writer(cfg.db_path)


class World:
    """A fake Unraid and a fake reader behind one Net."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.unraid = FakeUnraid()
        self.reader = FakeReader(TOKEN)
        self.net = self.unraid.net()
        self.net.reader = self.reader.client

    def poll(self, at=None):
        conn = conn_of(self.cfg)
        try:
            asyncio.run(poll.run_once(conn, self.cfg, self.net, at or time.time()))
        finally:
            conn.close()


@pytest.fixture
def world(hub_cfg):
    return World(hub_cfg)


def add_system(world, reader=True):
    conn = conn_of(world.cfg)
    store.add(conn, world.cfg.data_dir, "tower", "unraid", "https://tower.test:4443", KEY, reader_url=READER if reader else None,
              reader_token=TOKEN if reader else None, interval=30)
    conn.close()


def snap(world, source=ds.SNAPSHOT):
    conn = conn_of(world.cfg)
    try:
        return db.get_snapshot(conn, "tower", source)
    finally:
        conn.close()


def open_rules(world):
    conn = conn_of(world.cfg)
    try:
        return {r["rule"]: r for r in db.open_findings(conn, "tower") if r["rule"].startswith("docker.")}
    finally:
        conn.close()


def test_a_poll_stores_the_summary_opens_the_findings_and_remembers_apps(world):
    add_system(world)
    t = time.time()
    world.poll(t)
    s = snap(world)
    assert s.ok and s.error is None and len(s.data["images"]) == 10
    assert set(open_rules(world)) == {"docker.superseded_images", "docker.unused_images", "docker.unused_volumes", "docker.build_cache"}
    assert world.reader.paths() == ["/v1/summary"]
    assert set(s.data["apps_seen"]) == {"registry.example/app-1"} or s.data["apps_seen"]       # from the fixture's managed containers
    assert all(r.method == "GET" and r.headers["authorization"] == f"Bearer {TOKEN}" for r in world.reader.requests)


def test_the_reader_is_read_at_most_every_ten_minutes(world):
    add_system(world)
    t = time.time()
    world.poll(t)
    world.poll(t + 60)
    world.poll(t + 540)
    assert world.reader.paths() == ["/v1/summary"]
    world.poll(t + 601)
    assert world.reader.paths() == ["/v1/summary"] * 2
    assert snap(world).taken_at == t + 601


def test_without_a_reader_nothing_is_asked_and_nothing_stored(world):
    add_system(world, reader=False)
    world.poll()
    assert world.reader.requests == [] and snap(world) is None and open_rules(world) == {}


def test_a_failing_reader_keeps_the_last_data_and_never_fails_the_poll(world):
    add_system(world)
    t = time.time()
    world.poll(t)
    first = snap(world).data
    world.reader.fail = httpx.ConnectError(f"no route {TOKEN}")
    world.poll(t + 700)
    s = snap(world)
    assert not s.ok and "Could not connect" in s.error and TOKEN not in s.error and s.data == first
    assert len(open_rules(world)) == 4                                   # the findings hold on the last good data
    conn = conn_of(world.cfg)
    row = store.get(conn, "tower")
    assert row["fails"] == 0 and row["last_error"] is None               # Unraid itself was read fine
    conn.close()
    world.reader.fail = None
    world.poll(t + 1400)
    assert snap(world).ok


def test_a_wrong_token_is_an_auth_error_on_the_page_not_a_crash(world):
    add_system(world)
    world.reader.token = "someone-elses-token-someone-elses-token"
    world.poll()
    s = snap(world)
    assert not s.ok and "refused the token" in s.error and TOKEN not in s.error


def test_a_missing_token_file_says_so(world):
    add_system(world)
    store.reader_token_path(world.cfg.data_dir, "tower").unlink()
    world.poll()
    assert "token file is missing" in snap(world).error and world.reader.requests == []


def test_findings_resolve_when_the_unused_things_go_away(world):
    add_system(world)
    t = time.time()
    world.poll(t)
    raw = standard_summary()
    for i in raw["images"]:
        i["in_use"] = True
    for v in raw["volumes"]:
        v["refs"] = 1
    raw["build_cache"] = {"count": 1, "size": 5}
    world.reader.summary = raw
    world.poll(t + 700)
    assert open_rules(world) == {}


def test_a_removed_app_is_noticed_across_polls(world):
    """The first poll sees a managed container running an app; once it is gone the app's image is "removed app"."""
    add_system(world)
    t = time.time()
    raw = standard_summary()
    raw["images"].append({"id": IDS["tool"], "tags": ["registry.example/app-1:latest"], "digests": [], "created": 5, "size": 5, "last_tag": None,
                          "labels": {}, "in_use": False})
    world.reader.summary = raw
    world.poll(t)
    conn = conn_of(world.cfg)
    d = db.get_snapshot(conn, "tower", "unraid_docker").data
    assert any(c["image"].startswith("registry.example/app-1") and not c["orphaned"] for c in d["containers"])
    # app-1 disappears from the Unraid list; its image is still on the server, unused.
    world.unraid.replies = copy.deepcopy(world.unraid.replies)
    from daemonsight.remote import unraid
    world.unraid.replies[unraid.Q_DOCKER]["data"]["docker"]["containers"] = [
        c for c in world.unraid.replies[unraid.Q_DOCKER]["data"]["docker"]["containers"] if not c["image"].startswith("registry.example/app-1")]
    world.poll(t + 700)
    a = ds.analyze(db.get_snapshot(conn, "tower", ds.SNAPSHOT).data, db.get_snapshot(conn, "tower", "unraid_docker").data)
    assert by_name(a)["registry.example/app-1:latest"]["hint"]["key"] == "removed_app"
    conn.close()


# --- the schema --------------------------------------------------------------------------------------------------------------

def test_migration_adds_reader_url_to_a_version_8_database(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    conn = db.connect_writer(path)
    conn.execute("ALTER TABLE remotes DROP COLUMN reader_url")
    conn.execute("PRAGMA user_version=8")
    conn.close()
    assert "reader_url" not in {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(remotes)")}
    conn = db.connect_writer(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert "reader_url" in {r[1] for r in conn.execute("PRAGMA table_info(remotes)")}
    conn.close()


# --- the token file and backups ---------------------------------------------------------------------------------------------------

def test_the_reader_token_is_a_private_file_never_in_the_database(world):
    add_system(world)
    path = store.reader_token_path(world.cfg.data_dir, "tower")
    assert path.read_text().strip() == TOKEN and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    conn = conn_of(world.cfg)
    dump = "\n".join(str(tuple(r)) for t in ("remotes", "hosts", "snapshots", "events", "findings") for r in conn.execute(f"SELECT * FROM {t}"))
    assert TOKEN not in dump
    assert store.remove(conn, world.cfg.data_dir, "tower")
    assert not path.exists()
    conn.close()
    for bad in ("short", "a b" * 20, "x" * 300, ""):
        with pytest.raises(ValueError):
            store.clean_reader_token(bad)


def test_a_backup_holds_the_reader_token_and_a_restore_brings_it_back(world, tmp_path):
    add_system(world)
    conn = conn_of(world.cfg)
    conn.execute("PRAGMA wal_checkpoint(FULL)")
    conn.close()
    conf = tmp_path / "config.toml"
    conf.write_text("")
    arch = backup.create(world.cfg, conf, tmp_path / "bk")
    import tarfile
    with tarfile.open(arch) as tar:
        assert "remotes/tower.reader-token" in tar.getnames() and "remotes/tower.key" in tar.getnames()
    store.reader_token_path(world.cfg.data_dir, "tower").unlink()
    backup.restore(world.cfg, arch, conf)
    path = store.reader_token_path(world.cfg.data_dir, "tower")
    assert path.read_text().strip() == TOKEN and stat.S_IMODE(path.stat().st_mode) == 0o600


# --- the form and the page ----------------------------------------------------------------------------------------------------------

@pytest.fixture
def web(hub_cfg):
    w = World(hub_cfg)
    app = create_app(hub_cfg, remote_net=w.net)
    client = TestClient(app, follow_redirects=False)
    assert client.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    w.client = client
    return w


def form(**kw):
    return {"kind": "unraid", "name": "tower", "url": "https://tower.test:4443", "key": KEY, "tls": "verify", "interval": "60", **kw}


def test_the_reader_option_is_a_dependent_option_under_its_checkbox(web):
    html = web.client.get("/remotes/new").text
    assert re.search(r'<input class="form-check-input" type="checkbox" id="reader-on" name="reader_on" value="1">', html)
    assert 'class="ds-subpanel mt-2" id="docker-reader" data-ds-when="reader-on=on"' in html
    assert "Read images and volumes" in html
    sub = html.split('id="docker-reader"')[1].split("</form>")[0]
    for needle in ('name="reader_url"', 'name="reader_token"', 'type="password"', 'value="test-reader"', 'for="reader_url"', 'for="reader_token"'):
        assert needle in sub, needle
    # One form, one Save: the subpanel is inside the system's own form, with no form of its own.
    form_html = html.split('<form method="post" action="/remotes/new#result"')[1].split("</form>")[0]
    assert 'id="docker-reader"' in form_html and form_html.count("<form") == 0
    assert 'formaction="/remotes/new#docker-reader"' in html
    # An OPNsense form has no reader option.
    assert "reader-on" not in web.client.get("/remotes/new?kind=opnsense").text
    js = open("src/daemonsight/web/static/app.js").read()
    assert 'select.type === "checkbox"' in js


def test_saving_with_the_reader_stores_the_address_and_the_token_file(web, hub_cfg):
    r = web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url="daemonsight-docker-reader:8467", reader_token=TOKEN))
    assert r.status_code == 303
    conn = conn_of(hub_cfg)
    assert store.get(conn, "tower")["reader_url"] == READER
    conn.close()
    path = store.reader_token_path(hub_cfg.data_dir, "tower")
    assert path.read_text().strip() == TOKEN and stat.S_IMODE(path.stat().st_mode) == 0o600
    edit = web.client.get("/remotes/tower/edit").text
    assert TOKEN not in edit and "A token is saved" in edit and f'value="{READER}"' in edit
    assert 'id="reader-on" name="reader_on" value="1" checked' in edit


def test_the_reader_needs_an_address_and_a_token_and_nothing_is_saved_without_them(web, hub_cfg):
    for kw, msg in (({"reader_url": "", "reader_token": TOKEN}, "Docker reader address"),
                    ({"reader_url": READER, "reader_token": ""}, "Docker reader token: enter the token"),
                    ({"reader_url": READER, "reader_token": "short"}, "Docker reader token: The reader token must be"),
                    ({"reader_url": "ftp://x", "reader_token": TOKEN}, "Docker reader address")):
        r = web.client.post("/remotes/new", data=form(action="save", reader_on="1", **kw))
        assert r.status_code == 400 and msg in r.text, msg
        assert TOKEN not in r.text
    conn = conn_of(hub_cfg)
    assert conn.execute("SELECT 1 FROM remotes").fetchone() is None
    conn.close()
    assert not store.reader_token_path(hub_cfg.data_dir, "tower").exists()


def test_test_reader_checks_the_reader_and_shows_what_it_found(web):
    r = web.client.post("/remotes/new", data=form(action="test-reader", reader_on="1", reader_url=READER, reader_token=TOKEN, key=""))
    assert r.status_code == 200 and "Connected to the reader. Docker 29.0.0, API 1.54." in r.text and TOKEN not in r.text
    assert web.reader.paths() == ["/v1/health"] and web.unraid.requests == []          # Unraid was not touched
    # The typed token is held for Save, so it need not be typed again.
    pending = re.search(r'name="pending_reader" value="([^"]+)"', r.text).group(1)
    assert pending and TOKEN not in r.text
    ok = web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url=READER, pending_reader=pending))
    assert ok.status_code == 303
    web.reader.token = "other-other-other-other-other-other"
    bad = web.client.post("/remotes/new", data=form(action="test-reader", reader_on="1", reader_url=READER, reader_token="z" * 40, key=""))
    assert bad.status_code == 400 and "Docker reader: The reader refused the token" in bad.text and "z" * 40 not in bad.text
    unticked = web.client.post("/remotes/new", data=form(action="test-reader", reader_url=READER, reader_token=TOKEN, key=""))
    assert "Tick Read images and volumes first" in unticked.text


def test_editing_keeps_the_saved_token_changes_it_or_turns_the_reader_off(web, hub_cfg):
    web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url=READER, reader_token=TOKEN))
    path = store.reader_token_path(hub_cfg.data_dir, "tower")
    base = form(action="save", enabled="1", key="", reader_on="1")
    assert web.client.post("/remotes/tower/edit", data={**base, "reader_url": "http://other-reader:9000"}).status_code == 303
    conn = conn_of(hub_cfg)
    assert store.get(conn, "tower")["reader_url"] == "http://other-reader:9000" and path.read_text().strip() == TOKEN
    conn.close()
    new = "n" * 40
    assert web.client.post("/remotes/tower/edit", data={**base, "reader_url": READER, "reader_token": new}).status_code == 303
    assert path.read_text().strip() == new
    # Seed a snapshot, then untick: the reader, its token and its data go.
    conn = conn_of(hub_cfg)
    db.put_snapshot(conn, "tower", ds.SNAPSHOT, time.time(), True, None, {"images": []})
    conn.close()
    off = form(action="save", enabled="1", key="")
    assert web.client.post("/remotes/tower/edit", data=off).status_code == 303
    conn = conn_of(hub_cfg)
    assert store.get(conn, "tower")["reader_url"] is None and db.get_snapshot(conn, "tower", ds.SNAPSHOT) is None
    conn.close()
    assert not path.exists()
    assert 'id="reader-on" name="reader_on" value="1" checked' not in web.client.get("/remotes/tower/edit").text


def test_an_old_system_without_a_reader_is_unchanged_by_saving_the_form(web, hub_cfg):
    web.client.post("/remotes/new", data=form(action="save"))
    assert web.client.post("/remotes/tower/edit", data=form(action="save", enabled="1", key="")).status_code == 303
    conn = conn_of(hub_cfg)
    assert store.get(conn, "tower")["reader_url"] is None
    conn.close()


@pytest.fixture
def page(web, hub_cfg):
    web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url=READER, reader_token=TOKEN))
    web.poll(time.time())
    return web


def test_the_page_lists_unused_images_volumes_and_the_build_cache(page):
    html = page.client.get("/h/tower/docker").text
    assert "Docker storage" in html and 'id="images"' in html and 'id="volumes"' in html and 'id="cache"' in html
    imgs = html.split('id="images"')[1].split('id="volumes"')[0]
    assert "acme/oldapp:latest" in imgs and "ghcr.io/acme/widget (untagged)" in imgs and "acme/gadget:2" in imgs
    assert "old version of ghcr.io/acme/widget left by an update; safe to remove" in imgs
    assert "from https://example.test/acme/gadget" in imgs and "base image, probably pulled for a build or a test" in imgs
    assert "no hint" in imgs and "1760000000" not in imgs                     # sort values are in data-v, the text is a date
    assert re.search(r'data-label="Arrived">2025-06-01<div class="text-secondary small">tagged</div>', imgs)
    assert re.search(r'data-label="Arrived">\d{4}-\d\d-\d\d<div class="text-secondary small">built</div>', imgs)
    assert "Docker does not record who pulled an image" in html            # in the (i) panels
    assert 'nginx:1.27' not in imgs                                        # in use: not listed
    vols = html.split('id="volumes"')[1].split('id="cache"')[0]
    assert "shop_db" in vols and "from compose project shop" in vols and "left by a container that was removed" in vols
    assert ANON_A[:12] + "…" in vols and "anonymous" in vols and "webdata" not in vols
    assert "docker volume rm shop_db" in vols and "docker run --rm -v shop_db:/v:ro alpine ls -la /v" in vols
    cache = html.split('id="cache"')[1]
    assert "6.1 GB" in cache and "12 records" in cache and "docker builder prune" in cache
    # Every cell has its label for the phone layout; each row has a status word and a source panel.
    for table in re.findall(r'<table[^>]*data-table="docker-(?:images|volumes)".*?</table>', html, re.S):
        for row in re.findall(r"<tr id=.*?</tr>", table, re.S):
            assert row.count("data-label=") == 5 and "ds-status" in row and "popover" in row
    assert check_panels(html) >= 6


def test_the_panels_say_where_the_data_came_from_and_the_cli_that_matches(page):
    html = page.client.get("/h/tower/docker").text
    assert f"GET {READER}/v1/summary" in html and "docker image ls --no-trunc" in html and "docker volume ls" in html and "docker system df -v" in html
    assert "/images/&lt;id&gt;/json" in html and "/system/df?verbose=1" in html
    assert "docker image rm" in html and "Inspect it" in html
    assert "Authorization: Bearer $TOKEN" in html and TOKEN not in html


def test_rows_carry_a_status_and_can_be_accepted_from_their_panel(page, hub_cfg):
    html = page.client.get("/h/tower/docker").text
    row = re.search(r'<tr id="(img-[^"]+)" data-row>.*?data-status-label="unexpected"', html, re.S)
    assert row and "Accept risk" in html
    r = page.client.post("/h/tower/findings/accept", data={"rule": "docker.unused_volumes", "key": "all", "note": "kept on purpose",
                                                           "next": "/h/tower/docker#volumes"})
    assert r.status_code == 303 and r.headers["location"] == "/h/tower/docker#volumes"
    html = page.client.get("/h/tower/docker").text
    vols = html.split('id="volumes"')[1].split('id="cache"')[0]
    assert 'data-status-label="accepted"' in vols and "kept on purpose" in vols and 'data-status-label="unexpected"' not in vols
    # The accepted rows stay on the page, and the images are unaffected.
    assert "shop_db" in vols and 'data-status-label="unexpected"' in html.split('id="images"')[1].split('id="volumes"')[0]
    # A new unused volume changes the basis: the acceptance comes back as Changed.
    raw = standard_summary()
    raw["volumes"].append({"name": "extra", "created": "", "driver": "local", "labels": {}, "anonymous": False, "size": 1, "refs": 0})
    page.reader.summary = raw
    page.poll(time.time() + 700)
    html = page.client.get("/h/tower/docker").text
    assert 'data-status-label="changed"' in html.split('id="volumes"')[1].split('id="cache"')[0]


def test_the_findings_show_on_the_overview_and_the_report(page):
    ov = page.client.get("/h/tower/").text
    assert "1 old image version left by updates, 290.0 MB" in ov and "3 volumes no container uses, 934.0 MB" in ov
    assert "Docker build cache is 6.1 GB" in ov and "docker image prune" in ov and "WARNING" in ov
    assert 'href="/h/tower/docker#volumes"' in ov and "Docker storage" in ov and "6 unused images, 3 unused volumes" in ov
    rep = page.client.get("/h/tower/report.md").text
    assert "docker builder prune" in rep and "docker image prune" in rep
    assert "docker volume prune" not in rep.replace("Never run docker volume prune", "").replace("docker volume prune or", "")


def test_the_page_before_a_reader_is_set_up_and_when_it_fails(web, hub_cfg):
    web.client.post("/remotes/new", data=form(action="save"))
    web.poll()
    html = web.client.get("/h/tower/docker").text
    assert 'id="images"' in html and "Docker storage is not set up for this system" in html and 'href="/remotes/tower/edit#docker-reader"' in html
    # Attach one that fails: the error is shown, with no token.
    web.client.post("/remotes/tower/edit", data=form(action="save", enabled="1", key="", reader_on="1", reader_url=READER, reader_token=TOKEN))
    web.reader.fail = httpx.ConnectError(f"nope {TOKEN}")
    web.poll(time.time() + 100)
    html = web.client.get("/h/tower/docker").text
    assert "The reader could not be read: Could not connect to the reader" in html and TOKEN not in html


def test_the_token_is_on_no_page_event_log_or_stored_row(web, hub_cfg, caplog):
    caplog.set_level(logging.DEBUG)
    seen = [web.client.get("/remotes/new").text,
            web.client.post("/remotes/new", data=form(action="test-reader", reader_on="1", reader_url=READER, reader_token=TOKEN, key="")).text,
            web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url=READER, reader_token=TOKEN)).text]
    web.reader.fail = httpx.ConnectError(f"boom {TOKEN}")
    for i in range(4):
        web.poll(time.time() + 700 * i)
    web.reader.fail = None
    web.reader.token = "x" * 30
    web.poll(time.time() + 9000)
    for path in ("/", "/partials/hosts", "/remotes/tower/edit", "/h/tower/", "/h/tower/docker", "/h/tower/partials/docker", "/h/tower/report",
                 "/h/tower/report.md", "/h/tower/containers", "/h/tower/disks"):
        seen.append(web.client.get(path).text)
    assert TOKEN not in "\n".join(seen) and TOKEN not in caplog.text
    conn = conn_of(hub_cfg)
    dump = "\n".join(str(tuple(r)) for t in ("events", "findings", "remotes", "snapshots", "hosts") for r in conn.execute(f"SELECT * FROM {t}"))
    assert TOKEN not in dump
    conn.close()


def test_untrusted_text_from_the_reader_is_escaped(page):
    raw = standard_summary()
    raw["images"][-1].update({"in_use": False, "tags": ["<script>alert(1)</script>:1"], "labels": {"org.opencontainers.image.source": "<img src=x onerror=alert(2)>"}})
    raw["volumes"][0]["name"] = "<b>vol</b>"
    page.reader.summary = raw
    page.poll(time.time() + 700)
    html = page.client.get("/h/tower/docker").text
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html
    assert "<img src=x" not in html and "&lt;b&gt;vol" in html


def test_a_large_volume_list_is_cut_to_keep_the_page_light(page):
    raw = standard_summary()
    for n in range(400):
        raw["volumes"].append({"name": f"{n:064x}", "created": "", "driver": "local", "labels": {}, "anonymous": True, "size": 100 + n, "refs": 0})
    page.reader.summary = raw
    page.poll(time.time() + 700)
    html = page.client.get("/h/tower/docker").text
    assert html.count('data-table="docker-volumes"') == 1
    assert len(re.findall(r'<tr id="vol-', html)) == 100 and "303 more are not shown" in html
    assert "403 volumes no container uses" in page.client.get("/h/tower/").text or "403 volumes" in page.client.get("/h/tower/report").text


def test_every_section_anchor_exists_with_and_without_a_reader(page, web):
    from .test_sections import check_registry
    check_registry(page.client, "/h/tower", "unraid")
