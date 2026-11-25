"""Container image CVEs on a host with a collector (docs/DESIGN.md, "Collector hosts: image CVEs"): the collector reads each running
container image's OS and packages through the Docker socket (GET only, four fixed paths), sends a list only when the hub does not
have it, and the hub matches it under pseudo-host ids and raises `docker.image_cves` like it does for an Unraid system. Everything
is synthetic; the Docker engine is the fake on a unix socket (tests/fake_docker.py)."""

import gzip
import hashlib
import json
import re
import time

import pytest

from daemonsight import db, docker_packages as pk, hub
from daemonsight.collector import upload
from daemonsight.collector.runner import build_sources
from daemonsight.collector.sources import SourceUnavailable
from daemonsight.collector.sources.docker_images import DockerImagesSource
from daemonsight.config import Config
from daemonsight.cve import exposure
from daemonsight.remote import docker_images as di
from daemonsight.web import views

from .fake_docker import IDS, SECRET, FakeEngine, serve_files
from .test_cve import page_client
from .test_docker_images import (BOOKWORM_PACKAGES, DEB12, TODAY, UBU24, UBUNTU_PACKAGES, bundled_only, cve_on, entry, os_,  # noqa: F401 (fixtures)
                                 run_chore)
from .test_docker_reader import APK, DEBIAN12_OS, DPKG, many_images, world_replies  # noqa: F401 (fixture)
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)
from .test_opnsense import _added, app_client, c, conn_of, fake  # noqa: F401 (fixtures)
from .test_web import client, login, seeded  # noqa: F401 (fixture)

FW_IP = "10.20.0.8"        # the address the fixture firewall's port forward on 8080 leads to, as port 80 (tests/fixtures/opnsense/nat.json)


@pytest.fixture
def sock(tmp_path):
    return tmp_path / "d.sock"     # AF_UNIX paths are short: directly under tmp_path


def archive_reads(eng) -> list[str]:
    return [t for t in eng.targets() if "/archive?" in t]


def two_images():
    """A server with a Debian 12 image (web, with a second container web2 on it), an Alpine one (db), and a stopped one (off)."""
    replies = world_replies([("web", "nginx", "running"), ("web2", "nginx", "running"), ("db", "postgres", "running"), ("off", "debian", "exited")])
    serve_files(replies, "web", {"/usr/lib/os-release": DEBIAN12_OS, "/var/lib/dpkg/status": DPKG})
    serve_files(replies, "db", {"/etc/os-release": b"ID=alpine\nVERSION_ID=3.19.1\n", "/lib/apk/db/installed": APK})
    return replies


# --- the collector's source ---------------------------------------------------------------------------------------------------------

async def test_the_source_sends_only_get_and_only_the_four_paths_and_reads_each_image_id_once(sock):
    async with FakeEngine(sock, two_images()) as eng:
        now = [1_000.0]
        src = DockerImagesSource(300, eng.path, clock=lambda: now[0])
        first = await src.collect()
        by = {e["image_id"]: e for e in first["image_packages"]}
        n = by[IDS["nginx"]]
        assert n["container"] == "web" and n["manager"] == "dpkg" and n["count"] == 3 and n["error"] is None and n["read_at"] == 1000
        assert n["os"]["codename"] == "bookworm" and n["packages"][0] == ["libbrotli1", "brotli", "1.0.9-2+b6", "1.0.9-2"]
        assert re.fullmatch(r"[0-9a-f]{32}", n["hash"]) and n["hash"] == pk.fingerprint(n)
        assert by[IDS["postgres"]]["manager"] == "apk" and by[IDS["postgres"]]["os"]["id"] == "alpine"
        assert by[IDS["debian"]]["error"] == "not read: stopped" and by[IDS["debian"]]["packages"] == [] and "hash" not in by[IDS["debian"]]
        # Every request: GET; the lists are two reads of a list; each archive read is one of the four paths of a container's 64-digit id.
        assert {m for m, _t in eng.requests} == {"GET"}
        others = {FakeEngine.strip(t) for t in eng.targets() if "/archive?" not in t}
        assert others == {"/version", "/containers/json?all=1", "/images/json?all=0&digests=1"}
        reads = archive_reads(eng)
        assert reads and all(pk.ARCHIVE_TARGET.fullmatch(FakeEngine.strip(t)) for t in reads)
        assert not any(hashlib.sha256(x).hexdigest() in t for t in reads for x in (b"web2", b"off"))      # one container per image; none stopped
        # A second look at the same server asks only for the lists: nothing is read again.
        before = len(reads)
        now[0] += 3600 * 5
        again = await src.collect()
        assert len(archive_reads(eng)) == before and again["image_packages"] == first["image_packages"]
        # An update changes the image id: the new one is read, the old one goes.
        newid = "sha256:" + "ab" * 32
        for c in eng.replies["/containers/json?all=1"][:2]:
            c["ImageID"] = newid
        changed = await src.collect()
        ids = {e["image_id"] for e in changed["image_packages"]}
        assert newid in ids and IDS["nginx"] not in ids and len(archive_reads(eng)) > before
        await src.close()
    assert {m for m, _t in eng.requests} == {"GET"}


async def test_a_restart_reads_nothing_again_and_an_error_is_tried_again_only_after_thirty_minutes(sock):
    replies = two_images()
    del replies[next(k for k in replies if k.endswith("%2Fvar%2Flib%2Fdpkg%2Fstatus"))]            # web's dpkg database is not there
    async with FakeEngine(sock, replies) as eng:
        now = [1_000.0]
        src = DockerImagesSource(300, eng.path, clock=lambda: now[0])
        data = await src.collect()
        web = next(e for e in data["image_packages"] if e["image_id"] == IDS["nginx"])
        assert web["manager"] is None and "no dpkg or apk package database" in web["error"]
        n = len(archive_reads(eng))
        now[0] += 600
        await src.collect()
        assert len(archive_reads(eng)) == n                                    # too soon
        now[0] += 1300
        await src.collect()
        assert len(archive_reads(eng)) > n                                     # 30 minutes on: the failed image only
        assert not any(hashlib.sha256(b"db").hexdigest() in t for t in archive_reads(eng)[n:])
        # A new source takes the good reads from the stored snapshot: nothing but the failed one is read.
        again = DockerImagesSource(300, eng.path, clock=lambda: now[0])
        again.restore(data)
        n = len(archive_reads(eng))
        out = await again.collect()
        assert {e["image_id"]: e["manager"] for e in out["image_packages"]}[IDS["postgres"]] == "apk"
        assert not any(hashlib.sha256(b"db").hexdigest() in t for t in archive_reads(eng)[n:])
        await src.close()
        await again.close()


async def test_a_restored_source_with_all_reads_makes_no_archive_request(sock):
    async with FakeEngine(sock, two_images()) as eng:
        first = DockerImagesSource(300, eng.path)
        data = await first.collect()
        await first.close()
        n = len(archive_reads(eng))
        src = DockerImagesSource(300, eng.path)
        src.restore(json.loads(json.dumps(data)))
        out = await src.collect()
        assert len(archive_reads(eng)) == n and out["image_packages"] == data["image_packages"]
        src.restore({"image_packages": [{"image_id": "x"}, "junk", {"image_id": "sha256:" + "0" * 64, "manager": "dpkg"}]})       # junk is ignored
        await src.close()


async def test_at_most_ten_images_are_read_per_look(sock, many_images):
    from .fake_docker import container
    replies = world_replies([(f"c{n}", n, "running") for n in many_images[:25]])
    for n in many_images[:25]:
        serve_files(replies, f"c{n}", {"/usr/lib/os-release": DEBIAN12_OS, "/var/lib/dpkg/status": DPKG})
    async with FakeEngine(sock, replies) as eng:
        src = DockerImagesSource(300, eng.path)
        counts = []
        for _ in range(3):
            data = await src.collect()
            counts.append(sum(1 for e in data["image_packages"] if e["manager"]))
        assert counts == [10, 20, 25]
        await src.close()


async def test_the_source_is_off_when_asked_or_without_docker_and_nothing_secret_is_kept(sock, tmp_path):
    off = DockerImagesSource(300, str(sock), enabled=False)
    with pytest.raises(SourceUnavailable) as exc:
        await off.collect()
    assert "docker_read_packages = false" in str(exc.value)
    with pytest.raises(SourceUnavailable, match="no Docker socket"):
        await DockerImagesSource(300, str(tmp_path / "none.sock")).collect()
    async with FakeEngine(sock, two_images()) as eng:
        src = DockerImagesSource(300, eng.path)
        data = await src.collect()
        assert SECRET not in json.dumps(data) and set(data) == {"v", "engine", "containers", "images", "image_packages"}
        assert set(data["containers"][0]) == {"name", "image", "image_id", "state"}
        await src.close()


def test_the_source_is_built_only_for_a_host_that_uploads_and_follows_the_toggle():
    cfg = Config()
    assert not [s for s in build_sources(cfg) if s.name == "docker_images"]
    cfg.upload.url = "https://hub.example.test/api/v1/ingest"
    [src] = [s for s in build_sources(cfg) if s.name == "docker_images"]
    assert src.enabled and src.interval == 300 and src.socket_path == "/var/run/docker.sock"
    cfg.collector.docker_read_packages = False
    assert [s for s in build_sources(cfg) if s.name == "docker_images"][0].enabled is False


# --- what the collector uploads ---------------------------------------------------------------------------------------------------

def wire(e: dict) -> dict:
    d = dict(e)
    if d["manager"]:
        d["hash"] = pk.fingerprint(d)
    return d


def snapshot_of(entries, containers=None):
    return {"v": 1, "engine": {"version": "29.0.0", "api": "1.54"},
            "containers": containers if containers is not None else [{"name": "web", "image": "nginx:1.27", "image_id": IDS["nginx"], "state": "running"}],
            "images": [], "image_packages": [wire(e) for e in entries]}


@pytest.fixture
def host(tmp_path):
    cfg = Config(host_id="vps", data_dir=str(tmp_path / "cdata"))
    conn = db.connect_writer(cfg.db_path)
    yield cfg, conn
    conn.close()


def put(conn, data, ts=None, host="vps"):
    db.put_snapshot(conn, host, "docker_images", ts or time.time(), True, None, data)


def build(cfg, conn, resend=frozenset()):
    payload, cursors, _more = upload.build(conn, cfg, (32768, 60999), 60, resend)
    return payload, cursors


def accept(conn, cursors):
    db.set_meta(conn, cursors)


def lists(payload):
    return {e["image_id"]: bool(e["packages"]) for e in payload["docker_images"]["image_packages"]}


def test_a_package_list_is_sent_when_new_or_changed_and_only_its_hash_otherwise(host):
    cfg, conn = host
    a = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web")
    b = entry(IDS["postgres"], os_("alpine", "3.19.1"), [("musl", "", "1.2.4", "")], manager="apk", container="db")
    off = entry(IDS["debian"], None, None, error="not read: stopped", container=None, read_at=None)
    put(conn, snapshot_of([a, b, off]))
    payload, cursors = build(cfg, conn)
    assert lists(payload) == {IDS["nginx"]: True, IDS["postgres"]: True, IDS["debian"]: False}          # all new: in full
    assert "docker_images" not in [s["source"] for s in payload["snapshots"]]                           # not a snapshot, a field of its own
    accept(conn, cursors)
    # Nothing changed: the field is not in the upload at all.
    put(conn, snapshot_of([a, b, off]))
    assert "docker_images" not in build(cfg, conn)[0]
    # One image changed: the field is there, and only the changed image carries its list.
    a2 = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES + [("curl", "", "7.88", "")], container="web")
    put(conn, snapshot_of([a2, b, off]))
    payload, cursors = build(cfg, conn)
    assert lists(payload) == {IDS["nginx"]: True, IDS["postgres"]: False, IDS["debian"]: False}
    kept = next(e for e in payload["docker_images"]["image_packages"] if e["image_id"] == IDS["postgres"])
    assert kept["packages"] == [] and kept["count"] == 1 and re.fullmatch(r"[0-9a-f]{32}", kept["hash"]) and kept["manager"] == "apk"
    # An upload the hub did not accept moves nothing: the next build still carries the list.
    again, _ = build(cfg, conn)
    assert lists(again)[IDS["nginx"]] is True
    accept(conn, cursors)
    put(conn, snapshot_of([a2, b, off]))
    assert "docker_images" not in build(cfg, conn)[0]
    # The hub asks for a list again (its reply): that one goes in full.
    payload, _ = build(cfg, conn, frozenset({IDS["postgres"]}))
    assert lists(payload) == {IDS["nginx"]: False, IDS["postgres"]: True, IDS["debian"]: False}


def test_every_list_is_sent_again_after_a_day(host, monkeypatch):
    cfg, conn = host
    a = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web")
    put(conn, snapshot_of([a]))
    payload, cursors = build(cfg, conn)
    accept(conn, cursors)
    put(conn, snapshot_of([a]))
    assert "docker_images" not in build(cfg, conn)[0]
    later = time.time() + upload.DOCKER_IMAGES_RESEND + 5
    monkeypatch.setattr(upload.time, "time", lambda: later)
    payload, _ = build(cfg, conn)
    assert lists(payload) == {IDS["nginx"]: True}


def test_a_host_with_no_docker_or_the_toggle_off_says_so_once(host):
    cfg, conn = host
    put(conn, {"available": False, "reason": "reading image packages is turned off ([collector] docker_read_packages = false)"})
    payload, cursors = build(cfg, conn)
    assert payload["docker_images"]["available"] is False and "docker_read_packages = false" in payload["docker_images"]["reason"]
    accept(conn, cursors)
    put(conn, {"available": False, "reason": "reading image packages is turned off ([collector] docker_read_packages = false)"})
    assert "docker_images" not in build(cfg, conn)[0]


def test_the_uploader_notes_the_lists_the_hub_asks_for_and_not_more_often_than_every_ten_minutes(host):
    import httpx
    cfg, conn = host
    cfg.upload.url, cfg.upload.token_file = "https://hub.example.test/api/v1/ingest", "/nonexistent"
    up = upload.Uploader(cfg, conn, __import__("asyncio").Lock(), (32768, 60999), 60)
    ask = httpx.Response(200, json={"last_seq": 1, "docker_images_resend": [IDS["nginx"], "junk", 5, "sha256:" + "0" * 63]})
    up._hub_wants_lists(ask)
    assert up._resend == frozenset({IDS["nginx"]})
    up._hub_wants_lists(ask)                                  # asked again at once: not honoured
    assert up._resend == frozenset()
    up._hub_wants_lists(httpx.Response(200, text="not json"))
    assert up._resend == frozenset()


def synthetic_entries(images: int, packages: int) -> list[dict]:
    out = []
    for i in range(images):
        iid = "sha256:" + hashlib.sha256(f"img{i}".encode()).hexdigest()
        pk_list = [(f"libexample{n}-dev", f"example{n}" if n % 2 else "", f"1.{n}.{i}-2+deb12u1", "") for n in range(packages)]
        out.append(entry(iid, DEB12, pk_list, container=f"app{i}"))
    return out


def test_thirty_images_stay_far_under_the_hubs_upload_cap(host):
    """30 images of 300 packages each (a heavy image has 100 to 250): the first upload in full, then the hash-only one."""
    cfg, conn = host
    entries = synthetic_entries(30, 300)
    containers = [{"name": e["container"], "image": f"app/{e['container']}:1", "image_id": e["image_id"], "state": "running"} for e in entries]
    put(conn, snapshot_of(entries, containers))
    payload, cursors = build(cfg, conn)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    full_gz = len(gzip.compress(raw, 6))
    accept(conn, cursors)
    # one image changed: the field with 29 hashes and one list
    entries[0] = entry(entries[0]["image_id"], DEB12, [*entries[0]["packages"], ("curl", "", "7.88.1-10", "")], container="app0")
    put(conn, snapshot_of(entries, containers))
    one, _ = build(cfg, conn)
    one_gz = len(gzip.compress(json.dumps(one, separators=(",", ":")).encode(), 6))
    caps = Config().hub
    assert len(raw) < 1_000_000 and full_gz < 150_000                       # 9,000 packages: under 1 MB unpacked and 150 kB gzipped
    assert full_gz < caps.max_upload_mb * 2**20 / 50 and len(raw) < caps.max_unpacked_mb * 2**20 / 40
    assert one_gz < 25_000 and one_gz < full_gz / 5
    print(f"30 images x 300 packages: {len(raw)} bytes unpacked, {full_gz} gzipped; one changed: {one_gz} gzipped")


# --- the hub: checking, storing and carrying the lists forward -------------------------------------------------------------------

def field(entries, containers=None, taken_at=None, **kw):
    f = snapshot_of(entries, containers)
    f["taken_at"] = taken_at or time.time()
    f.update(kw)
    return f


def stored(hub_cfg, host="testhost"):
    conn = db.connect_writer(hub_cfg.db_path)
    try:
        snap = db.get_snapshot(conn, host, "docker_images")
        return snap.data if snap else None
    finally:
        conn.close()


def test_the_lists_are_stored_carried_forward_by_hash_and_asked_for_when_the_hub_has_none(hub_cfg, token):
    from fastapi.testclient import TestClient
    from daemonsight.web.app import create_app
    c = TestClient(create_app(hub_cfg))
    a = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web")
    r = post(c, body(docker_images=field([a])), token)
    assert r.status_code == 200 and "docker_images_resend" not in r.json()
    st = stored(hub_cfg)
    e = st["image_packages"][0]
    assert st["source"] == "collector" and e["manager"] == "dpkg" and len(e["packages"]) == len(BOOKWORM_PACKAGES) and e["os"]["codename"] == "bookworm"
    assert st["containers"][0]["name"] == "web" and st["docker"]["api"] == "1.54"
    # The hash only: the list the hub holds for that image id and hash is kept.
    hash_only = {**wire(a), "packages": []}
    r = post(c, body(docker_images={**field([a]), "image_packages": [hash_only]}), token)
    assert r.status_code == 200 and "docker_images_resend" not in r.json()
    e2 = stored(hub_cfg)["image_packages"][0]
    assert e2["packages"] == e["packages"] and e2["manager"] == "dpkg" and not e2.get("need_list")
    # A hash the hub has no list for (it was never sent, or the hub lost it): shown as not read yet, and the reply asks for it.
    other = {**hash_only, "hash": "f" * 32}
    r = post(c, body(docker_images={**field([a]), "image_packages": [other]}), token)
    assert r.json()["docker_images_resend"] == [IDS["nginx"]]
    e3 = stored(hub_cfg)["image_packages"][0]
    assert e3["manager"] is None and e3["error"] == "not read yet" and e3["need_list"] and e3["packages"] == []
    # It is sent in full: stored, no longer asked for.
    b = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES + [("curl", "", "7.88", "")], container="web")
    r = post(c, body(docker_images=field([b])), token)
    assert "docker_images_resend" not in r.json() and len(stored(hub_cfg)["image_packages"][0]["packages"]) == len(BOOKWORM_PACKAGES) + 1
    # A collector that restarted says "not read yet" or "stopped": the last good read of that image id stands, marked carried.
    blank = entry(IDS["nginx"], None, None, error="not read yet", container=None, read_at=None)
    post(c, body(docker_images=field([blank])), token)
    e4 = stored(hub_cfg)["image_packages"][0]
    assert e4["carried"] is True and e4["manager"] == "dpkg" and len(e4["packages"]) == len(BOOKWORM_PACKAGES) + 1
    stopped = entry(IDS["nginx"], None, None, error="not read: stopped", container=None, read_at=None)
    post(c, body(docker_images=field([stopped])), token)
    assert stored(hub_cfg)["image_packages"][0]["carried"] is True
    # A failed read is never carried over a good one's place... it is stored as the failure it is.
    failed = entry(IDS["nginx"], None, None, error="packages not read: docker said no", container=None, read_at=None)
    post(c, body(docker_images=field([failed])), token)
    assert stored(hub_cfg)["image_packages"][0]["manager"] is None
    # No Docker (or switched off): nothing is kept.
    post(c, body(docker_images={"v": 1, "taken_at": time.time(), "available": False, "reason": "no Docker socket at /var/run/docker.sock"}), token)
    gone = stored(hub_cfg)
    assert gone["available"] is False and gone["image_packages"] == [] and "no Docker socket" in gone["reason"]


def test_the_fields_are_checked_as_strictly_as_the_rest_of_the_upload(hub_cfg, token, caplog):
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from daemonsight.web.app import create_app
    good = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web")

    def bad(**changes):
        e = {**wire(good), **changes}
        return {**field([good]), "image_packages": [e]}

    pkg = ["name", "", "1.0", ""]
    cases = {
        "an image id that is not a sha256": bad(image_id="nginx"),
        "a package name over 100 characters": bad(packages=[["x" * 101, "", "1", ""]]),
        "a control character in a version": bad(packages=[["a", "", "1\x00", ""]]),
        "a package with three fields": bad(packages=[["a", "", "1"]]),
        "a package with no name": bad(packages=[["", "", "1", ""]]),
        "a package that is not a list": bad(packages=["a"]),
        "more than 4000 packages for one image": bad(packages=[pkg] * 4001),
        "a package manager that is neither dpkg nor apk": bad(manager="rpm"),
        "a hash that is not hex": bad(hash="XYZ"),
        "a negative count": bad(count=-1),
        "an unreadable os": bad(os={"id": "x" * 41}),
        "a container name over 80 characters": {**field([good]), "containers": [{"name": "n" * 81, "image": "a", "image_id": "b", "state": "running"}]},
        "an image sent twice": {**field([good]), "image_packages": [wire(good), wire(good)]},
        "more packages than one host may send": {**field([good]), "image_packages": [
            {**wire(entry(f"sha256:{i:064x}", DEB12, [("a", "", "1", "")], container="c")), "packages": [pkg] * 4000} for i in range(11)]},
        "a version that is not 1": {**field([good]), "v": 2},
        "NaN": {**field([good]), "taken_at": float("nan")},
    }
    for why, payload in cases.items():
        with pytest.raises(ValidationError):
            hub.DockerImagesIn.model_validate(json.loads(json.dumps(payload, allow_nan=True)) if why != "NaN" else payload)
        # Inside an upload the lists are dropped with a warning and the rest of the upload is still stored.
        up = hub.Upload.model_validate({"v": 1, "host": "testhost", "seq": 1, "sent_at": time.time(), "version": "t", "max_interval": 60,
                                        "docker_images": payload})
        assert up.docker_images is None, why
    assert "Ignoring unreadable image package lists" in caplog.text
    c = TestClient(create_app(hub_cfg))
    r = post(c, body(docker_images=cases["a package name over 100 characters"], settings={"role": "server"}), token)
    assert r.status_code == 200 and stored(hub_cfg) is None
    # The same field can not come in as a snapshot, and a collector can not send findings of the hub's docker.* rules.
    assert post(c, body(snapshots=[{"source": "docker_images", "taken_at": 1, "ok": True, "data": {}}]), token).status_code == 422
    assert post(c, body(findings=[{"rule": "docker.image_cves", "key": "k", "severity": "low", "title": "t", "detail": "d"}]), token).status_code == 422
    # A newer collector's extra fields are ignored, and the hub's own size limits hold.
    ok = hub.DockerImagesIn.model_validate({**field([good]), "future": 1, "image_packages": [{**wire(good), "future": 1}]})
    assert ok.image_packages[0].count == len(BOOKWORM_PACKAGES)
    assert hub.MAX_IMAGE_PACKAGES == pk.MAX_PACKAGES and hub.MAX_IMAGE_PACKAGES_TOTAL == 40_000


# --- the chore: matching and the findings --------------------------------------------------------------------------------------------

PUBLIC_IP = "203.0.113.9"


def ports_snap(listeners=(), ip=PUBLIC_IP, scope="public"):
    return {"source": "ports", "taken_at": time.time(), "ok": True,
            "data": {"listeners": list(listeners), "owners_known": True, "addresses": [{"nic": "eth0", "ip": ip, "scope": scope}]}}


def docker_snap(containers):
    return {"source": "docker", "taken_at": time.time(), "ok": True, "data": {"containers": containers}}


def ctr(name, ports=(), image="nginx:1.27", status="running", project=None):
    return {"id": hashlib.sha256(name.encode()).hexdigest(), "name": name, "image": image, "status": status, "project": project,
            "exit_code": 0, "oom_killed": False, "health": "none", "restart_count": 0, "restart_policy": "no", "cpu_percent": None,
            "memory": None, "started_at": None, "finished_at": None, "compose_dir": None, "compose_files": [], "logs": [],
            "ports": [{"host_ip": ip, "host_port": p, "container_port": p, "proto": "tcp"} for ip, p in ports]}


def caddy_snap(sites=None, available=True):
    if not available:
        return {"source": "caddy", "taken_at": time.time(), "ok": True, "data": {"available": False, "reason": "no Caddy admin API"}}
    return {"source": "caddy", "taken_at": time.time(), "ok": True, "data": {"admin": {}, "servers": [], "sites": sites or []}}


def site(host, upstream, listen=(":443",), allow=()):
    host_part, _, port = upstream.rpartition(":")
    return {"host": host, "server": "srv0", "listen": list(listen), "allow": list(allow),
            "handlers": [{"paths": [], "kind": "proxy", "dynamic": False, "when": [], "allow": [], "root": None, "target": None, "status": None,
                          "upstreams": [{"network": "tcp", "host": host_part, "port": int(port), "text": upstream}]}]}


def web_images():
    """The images the hub is told of: nginx (Debian 12, a fixable KEV CVE) used by the container `web`."""
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web")
    return field([e], [{"name": "web", "image": "nginx:1.27", "image_id": IDS["nginx"], "state": "running"}])


def send(c, token, snapshots, images=None, host="testhost"):
    r = post(c, body(host=host, snapshots=snapshots, docker_images=images if images is not None else web_images()), token)
    assert r.status_code == 200, r.text
    return r


def findings(hub_cfg, host="testhost", prefix="docker."):
    conn = db.connect_writer(hub_cfg.db_path)
    try:
        return {(r["rule"], r["key"]): dict(r) for r in db.open_findings(conn, host) if r["rule"].startswith(prefix)}
    finally:
        conn.close()


def test_the_chore_matches_the_images_under_pseudo_host_ids_and_raises_the_finding_for_the_collector_host(hub_cfg, token, tmp_path):
    c = page_client(hub_cfg, token)
    send(c, token, [ports_snap([]), docker_snap([ctr("web", [("127.0.0.1", 8080)])]), caddy_snap(available=False)])
    run_chore(hub_cfg, tmp_path, time.time())
    from daemonsight.cve import store as cvestore
    cdb = cvestore.connect_reader(hub_cfg.cve_db_path)
    assert {r["host"] for r in cdb.execute("SELECT host FROM matched")} == {di.pseudo_host("testhost", IDS["nginx"])}
    cdb.close()
    f = findings(hub_cfg)
    assert set(f) == {("docker.image_cves", "nginx:1.27")}
    row = f[("docker.image_cves", "nginx:1.27")]
    # The same wording and rating as an Unraid image: the worst fixable CVE, rated for the image's exposure (here: loopback only).
    assert row["title"] == "nginx:1.27 (Debian 12): 3 fixable CVEs, 1 known exploited; fix within 14 days" and row["severity"] == "high"
    assert row["link"] == f"/images#ci-{IDS['nginx'].removeprefix('sha256:')[:12]}" and row["deadline_days"] == 14
    assert "Publicly exposed: no: it publishes 127.0.0.1:8080/tcp" in row["howto"] and "no Caddy" in row["howto"]
    # The steps are for a host with Docker Compose, not for Unraid's Docker tab.
    assert "docker compose pull" in row["howto"] and "Docker tab" not in row["howto"] and "Check for Updates" not in row["howto"]
    conn = db.connect_writer(hub_cfg.db_path)
    assert not [r for r in db.open_findings(conn, "testhost") if r["rule"].startswith("cve.")]
    assert not conn.execute("SELECT 1 FROM hosts WHERE id LIKE 'docker:%'").fetchone()
    assert conn.execute("SELECT 1 FROM events WHERE kind = 'finding_opened' AND title LIKE 'nginx:1.27%'").fetchone()
    conn.close()


def test_a_published_port_on_a_public_host_makes_it_exposed_and_the_deadline_shorter(hub_cfg, token, tmp_path):
    c = page_client(hub_cfg, token)
    send(c, token, [ports_snap([]), docker_snap([ctr("web", [("0.0.0.0", 8080)])]), caddy_snap(available=False)])
    run_chore(hub_cfg, tmp_path, time.time())
    row = findings(hub_cfg)[("docker.image_cves", "nginx:1.27")]
    assert row["severity"] == "critical" and row["title"].endswith("fix within 3 days") and row["deadline_days"] == 3
    assert "Publicly exposed: yes: port 8080/tcp of container web is published on all interfaces of a host with a public address" in row["howto"]


def test_findings_do_not_flap_over_a_hub_restart_a_collector_restart_or_missing_matches(hub_cfg, token, tmp_path):
    from daemonsight.cve import run, store as cvestore
    c = page_client(hub_cfg, token)
    send(c, token, [ports_snap([]), docker_snap([ctr("web", [("0.0.0.0", 8080)])]), caddy_snap(available=False)])
    t = time.time()
    run_chore(hub_cfg, tmp_path, t)
    before = findings(hub_cfg)
    assert len(before) == 1

    def same():
        after = findings(hub_cfg)
        assert after.keys() == before.keys()
        k = ("docker.image_cves", "nginx:1.27")
        assert all(after[k][x] == before[k][x] for x in ("id", "basis", "title", "detail", "severity", "howto", "first_seen"))
        conn = db.connect_writer(hub_cfg.db_path)
        assert not conn.execute("SELECT 1 FROM events WHERE kind = 'finding_resolved'").fetchone()
        conn.close()

    run_chore(hub_cfg, tmp_path, t + 100)                  # a hub restart: a new Chore with nothing in memory
    same()
    # The matches are gone (the CVE database was replaced, or not made yet): the finding stays as it was.
    wdb = cvestore.connect(hub_cfg.cve_db_path)
    wdb.execute("DELETE FROM match WHERE host LIKE 'docker:%'")
    wdb.execute("DELETE FROM matched WHERE host LIKE 'docker:%'")
    wdb.close()
    conn = conn_of(hub_cfg)
    import asyncio
    chore = run.Chore(hub_cfg, conn, None)
    asyncio.run(chore._docker_findings(t + 110))
    conn.close()
    same()
    # The collector restarts and has read nothing yet: the last good read of the image id is carried.
    blank = entry(IDS["nginx"], None, None, error="not read yet", container=None, read_at=None)
    send(c, token, [], field([blank], [{"name": "web", "image": "nginx:1.27", "image_id": IDS["nginx"], "state": "running"}]))
    run_chore(hub_cfg, tmp_path, t + 200)
    same()
    # Even a hash-only entry the hub cannot match to a list (so it knows nothing about the image) leaves the finding open.
    unknown = {**wire(entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES + [("x", "", "1", "")], container="web")), "packages": []}
    send(c, token, [], {**web_images(), "image_packages": [unknown]})
    run_chore(hub_cfg, tmp_path, t + 300)
    same()
    # The image is updated past the fixed versions: only now it resolves.
    fixed = entry(IDS["nginx"], DEB12, [("libbrotli1", "brotli", "1.0.9-2+deb12u1", ""), ("libc-ares2", "c-ares", "1.19.0-1", "")], container="web")
    send(c, token, [], field([fixed], [{"name": "web", "image": "nginx:1.27", "image_id": IDS["nginx"], "state": "running"}]))
    run_chore(hub_cfg, tmp_path, t + 400)
    assert findings(hub_cfg) == {}
    conn = db.connect_writer(hub_cfg.db_path)
    assert conn.execute("SELECT 1 FROM events WHERE kind = 'finding_resolved' AND title LIKE 'Resolved: nginx:1.27%'").fetchone()
    conn.close()


def test_switching_cve_matching_off_clears_the_hosts_image_findings(hub_cfg, token, tmp_path):
    c = page_client(hub_cfg, token)
    send(c, token, [ports_snap([]), docker_snap([ctr("web", [("0.0.0.0", 8080)])]), caddy_snap(available=False)])
    run_chore(hub_cfg, tmp_path, time.time())
    assert findings(hub_cfg)
    hub_cfg.cve.enabled = False
    run_chore(hub_cfg, tmp_path, time.time() + 10)
    assert findings(hub_cfg) == {}


def test_an_old_collector_that_sends_no_lists_has_its_images_shown_as_not_read_and_no_finding(hub_cfg, token, tmp_path):
    c = page_client(hub_cfg, token)
    r = post(c, body(snapshots=[docker_snap([ctr("web", [("0.0.0.0", 8080)]), ctr("db", [], image="postgres:17")])]), token)
    assert r.status_code == 200
    run_chore(hub_cfg, tmp_path, time.time())
    assert findings(hub_cfg) == {}
    html = c.get("/h/testhost/images").text
    assert "has not sent image package lists" in html and "not the same as having no CVEs" in html
    assert "nginx:1.27" in html and "postgres:17" in html and html.count("Not read") >= 2 and html.count("Not checked") >= 2
    assert "None fixable" not in html and "0 fixable" not in html


# --- exposure, from what the hub knows about the host ----------------------------------------------------------------------------------

def decide(hub_cfg, conn, host="web", images=None):
    data = {"image_packages": [{"image_id": IDS["nginx"]}], "containers": [
        {"name": n, "image": "nginx:1.27", "image_id": IDS["nginx"], "state": "running"} for n in (images or ["web"])]}
    return exposure.collector_image_exposures(conn, views.host_config(conn, hub_cfg, host), host, data)[IDS["nginx"]]


def add(c, hub_cfg, name, snapshots, address=None):
    conn = conn_of(hub_cfg)
    token = hub.add_host(conn, name)
    assert post(c, body(host=name, snapshots=snapshots), token).status_code == 200
    if address:
        conn.execute("UPDATE hosts SET address = ? WHERE id = ?", (address, name))
    return conn


def listener(port, addrs=("0.0.0.0",), scope="all", owner=None, process="docker-proxy"):
    return {"proto": "tcp", "port": port, "addresses": list(addrs), "scope": scope, "pid": 1, "process": process,
            "owner": owner or {"kind": "unknown", "id": None}}


def test_a_port_published_on_all_interfaces_of_a_public_host_is_exposed_and_loopback_is_not(c, hub_cfg, fake):
    conn = add(c, hub_cfg, "web", [ports_snap([listener(8080)]), docker_snap([ctr("web", [("0.0.0.0", 8080)])]), caddy_snap(available=False)])
    e = decide(hub_cfg, conn)
    assert e.exposed and e.data and "port 8080/tcp of container web is published on all interfaces of a host with a public address" in e.why
    conn = add(c, hub_cfg, "lo", [ports_snap([listener(8080, ["127.0.0.1"], "loopback")]), docker_snap([ctr("web", [("127.0.0.1", 8080)])]),
                                   caddy_snap(available=False)])
    e = decide(hub_cfg, conn, "lo")
    assert not e.exposed and e.data and "it publishes 127.0.0.1:8080/tcp, which the internet cannot reach" in e.why and "the host has no Caddy" in e.why
    # A specific public address is exposed too; the provider's allow list can rule a port out.
    conn = add(c, hub_cfg, "spec", [ports_snap([]), docker_snap([ctr("web", [(PUBLIC_IP, 9000)])]), caddy_snap(available=False)])
    assert "published on the public address 203.0.113.9" in decide(hub_cfg, conn, "spec").why
    cfg = views.host_config(conn, hub_cfg, "spec")
    cfg.exposure.upstream_allow = ["22/tcp"]
    data = {"image_packages": [{"image_id": IDS["nginx"]}], "containers": [{"name": "web", "image": "x", "image_id": IDS["nginx"], "state": "running"}]}
    assert not exposure.collector_image_exposures(conn, cfg, "spec", data)[IDS["nginx"]].exposed


def test_a_container_on_a_host_without_a_public_address_is_internal_unless_a_forward_leads_to_it(c, hub_cfg, fake):
    snaps = [ports_snap([listener(80, [FW_IP])], ip=FW_IP, scope="private"), docker_snap([ctr("web", [("0.0.0.0", 80)])]), caddy_snap(available=False)]
    conn = add(c, hub_cfg, "lan", snaps)
    e = decide(hub_cfg, conn, "lan")
    assert not e.exposed and e.data and "which the internet cannot reach" in e.why
    _added(c, hub_cfg, fake)                                      # the hub now reads the firewall: its forward 8080 -> 10.20.0.8:80
    e = decide(hub_cfg, conn, "lan")
    assert e.exposed and e.data and "port 80/tcp of container web is reached from the internet through forward 'Web server' on fw1" in e.why
    # Bound to loopback, the same forward does not reach it.
    conn = add(c, hub_cfg, "lan2", [ports_snap([], ip=FW_IP, scope="private"), docker_snap([ctr("web", [("127.0.0.1", 80)])]), caddy_snap(available=False)])
    assert not decide(hub_cfg, conn, "lan2").exposed


def test_a_container_bound_to_loopback_behind_an_internet_facing_caddy_site_is_exposed(c, hub_cfg, fake):
    caddy = caddy_snap([site("app.example.test", "127.0.0.1:8080")])
    conn = add(c, hub_cfg, "vps", [ports_snap([listener(443, ["0.0.0.0", "::"], "all", process="caddy")]),
                                   docker_snap([ctr("web", [("127.0.0.1", 8080)])]), caddy])
    e = decide(hub_cfg, conn, "vps")
    assert e.exposed and e.data and "Caddy site app.example.test proxies to container web (127.0.0.1:8080) and Caddy listens on port 443/tcp" in e.why
    # localhost and the host's own address are this machine too; another host's address is not.
    for dial, expect in (("localhost:8080", True), (f"{PUBLIC_IP}:8080", True), ("192.0.2.77:8080", False), ("127.0.0.1:9999", False)):
        name = "v" + re.sub(r"\W", "", dial)
        conn = add(c, hub_cfg, name, [ports_snap([listener(443, ["0.0.0.0"], "all", process="caddy")]),
                                      docker_snap([ctr("web", [("127.0.0.1", 8080)])]), caddy_snap([site("a.example.test", dial)])])
        assert decide(hub_cfg, conn, name).exposed is expect, dial
    # The site is behind an access list of private ranges only: the internet cannot use it. An access list that names a public range still can.
    for allow, expect in ((["10.0.0.0/8", "192.168.0.0/16"], False), (["10.0.0.0/8", "8.8.8.0/24"], True)):
        name = "a" + str(len(allow)) + str(expect)
        conn = add(c, hub_cfg, name, [ports_snap([listener(443, ["0.0.0.0"], "all", process="caddy")]),
                                      docker_snap([ctr("web", [("127.0.0.1", 8080)])]), caddy_snap([site("a.example.test", "127.0.0.1:8080", allow=allow)])])
        e = decide(hub_cfg, conn, name)
        assert e.exposed is expect and e.data, allow
        if not expect:
            assert "it publishes 127.0.0.1:8080/tcp" in e.why and "no internet-facing Caddy site" in e.why
    # Caddy only listens on loopback, or the provider's allow list does not pass 443: a site in front of it does not make it reachable.
    conn = add(c, hub_cfg, "loopcaddy", [ports_snap([listener(443, ["127.0.0.1"], "loopback", process="caddy")]),
                                         docker_snap([ctr("web", [("127.0.0.1", 8080)])]),
                                         caddy_snap([site("a.example.test", "127.0.0.1:8080", listen=("127.0.0.1:443",))])])
    e = decide(hub_cfg, conn, "loopcaddy")
    assert not e.exposed and "a Caddy site proxies to it, but the internet cannot reach Caddy" in e.why


def test_caddy_in_a_container_names_the_container_or_its_compose_service(c, hub_cfg, fake):
    """On a Compose network Caddy dials `app:8080`, the service name; the container is "<project>-app-1"."""
    web = ctr("shop-app-1", [], project="shop")
    caddy_ctr = ctr("shop-caddy-1", [("0.0.0.0", 443)], image="caddy:2", project="shop")
    for dial, expect in (("app:8080", True), ("shop-app-1:8080", True), ("other:8080", False)):
        name = "c" + re.sub(r"\W", "", dial)
        conn = add(c, hub_cfg, name, [ports_snap([listener(443)]), docker_snap([web, caddy_ctr]), caddy_snap([site("shop.example.test", dial)])])
        e = decide(hub_cfg, conn, name, images=["shop-app-1"])
        assert e.exposed is expect, dial
        if expect:
            assert "Caddy site shop.example.test proxies to container shop-app-1" in e.why and "Caddy is published on port 443/tcp" in e.why


def test_a_container_on_the_host_network_is_judged_by_its_listeners(c, hub_cfg, fake):
    web = ctr("web", [])
    owner = {"kind": "container", "id": web["id"]}
    conn = add(c, hub_cfg, "hostnet", [ports_snap([listener(3000, ["0.0.0.0"], "all", owner=owner, process="node")]), docker_snap([web]),
                                       caddy_snap(available=False)])
    e = decide(hub_cfg, conn, "hostnet")
    assert e.exposed and "port 3000/tcp of container web is published on all interfaces" in e.why
    conn = add(c, hub_cfg, "hostnet2", [ports_snap([listener(3000, ["127.0.0.1"], "loopback", owner=owner, process="node")]), docker_snap([web]),
                                        caddy_snap(available=False)])
    assert not decide(hub_cfg, conn, "hostnet2").exposed


def test_when_unsure_the_guidance_decides_by_the_hosts_address(c, hub_cfg, fake):
    # No Docker or ports data at all: the best-effort rule (a publicly routable address is public).
    conn = add(c, hub_cfg, "blind", [], address="203.0.113.50")
    e = decide(hub_cfg, conn, "blind")
    assert e.exposed and not e.data and "publicly routable (exposure data is missing)" in e.why
    conn = add(c, hub_cfg, "blind2", [], address="10.1.2.3")
    e = decide(hub_cfg, conn, "blind2")
    assert not e.exposed and not e.data
    # A container that publishes nothing, on a host whose Caddy was never read, is unknown too (it may sit behind a proxy we cannot see).
    conn = add(c, hub_cfg, "nocaddy", [ports_snap([]), docker_snap([ctr("web", [])])])
    e = decide(hub_cfg, conn, "nocaddy")
    assert e.exposed and not e.data
    # An image no running container uses is not exposed.
    data = {"image_packages": [{"image_id": IDS["nginx"]}], "containers": [{"name": "web", "image": "x", "image_id": IDS["nginx"], "state": "exited"}]}
    assert not exposure.collector_image_exposures(conn, views.host_config(conn, hub_cfg, "nocaddy"), "nocaddy", data)[IDS["nginx"]].exposed


def test_the_caddy_site_and_the_provider_allow_list_rules_read_listen_addresses_as_caddy_writes_them():
    assert exposure._listen_port(":443") == ("", 443) and exposure._listen_port("0.0.0.0:80") == ("0.0.0.0", 80)
    assert exposure._listen_port("[::1]:8080") == ("::1", 8080) and exposure._listen_port("tcp/:443") == ("", 443)
    assert exposure._listen_port("unix//run/caddy.sock") is None and exposure._listen_port("junk") is None
    assert exposure._service_name({"project": "shop", "name": "shop-app-1"}) == "app" and exposure._service_name({"project": None, "name": "x"}) is None
    assert exposure._service_name({"project": "shop", "name": "shop-db-cache-2"}) == "db-cache"
    assert exposure._site_audience({"allow": []}) == "internet" and exposure._site_audience({"allow": ["10.0.0.0/8", "fd00::/8"]}) == "lan"
    assert exposure._site_audience({"allow": ["not a range"]}) == "internet"


# --- the page ---------------------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def page(hub_cfg, token, tmp_path):
    c = page_client(hub_cfg, token)
    eol = entry(IDS["postgres"], os_("debian", "10", "buster"), [("libfoo", "", "1.0", "")], container="db")
    alpine = entry(IDS["widget-new"], os_("alpine", "3.17.2"), [("musl", "", "1.2.4", "")], manager="apk", container="widget")
    stopped = entry(IDS["debian"], DEB12, None, error="not read: stopped", container=None, read_at=None)
    web = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web")
    images = field([web, eol, alpine, stopped], [
        {"name": "web", "image": "nginx:1.27", "image_id": IDS["nginx"], "state": "running"},
        {"name": "db", "image": "postgres:17", "image_id": IDS["postgres"], "state": "running"},
        {"name": "widget", "image": "ghcr.io/acme/widget:latest", "image_id": IDS["widget-new"], "state": "running"},
        {"name": "off", "image": "debian:12", "image_id": IDS["debian"], "state": "exited"}])
    send(c, token, [ports_snap([]), docker_snap([ctr("web", [("0.0.0.0", 8080)]), ctr("db", [], image="postgres:17"),
                                                  ctr("widget", [], image="ghcr.io/acme/widget:latest"), ctr("off", [], image="debian:12", status="exited")]),
                    caddy_snap(available=False)], images)
    run_chore(hub_cfg, tmp_path, time.time())
    return c


def test_the_images_page_of_a_collector_host_shows_each_image_like_an_unraid_systems(page):
    html = page.get("/h/testhost/images").text
    assert "Container images" in html and 'id="image-list"' in html and 'id="image-coverage"' in html
    assert "package lists the collector reads from running containers" in html and 'href="/h/testhost/images"' in html
    table = html.split('data-table="container-images"')[1].split("</table>")[0]
    rows = {m.group(1): m.group(0) for m in re.finditer(r'<tr id="(ci-[^"]+)" data-row>.*?</tr>', table, re.S)}
    assert len(rows) == 4
    web = rows["ci-" + IDS["nginx"].removeprefix("sha256:")[:12]]
    assert "nginx:1.27" in web and "Debian 12" in web and "bookworm" in web and "3 fixable" in web and "1 exploited (KEV)" in web
    assert "3 days" in web and "public: port 8080/tcp of container web is published on all interfaces" in web and 'data-status-label="unexpected"' in web
    assert "Not read: stopped" in rows["ci-" + IDS["debian"].removeprefix("sha256:")[:12]]
    assert "paid ELTS only" in rows["ci-" + IDS["postgres"].removeprefix("sha256:")[:12]]
    for row in rows.values():
        assert row.count("data-label=") == 7 and "popover" in row
    assert "docker cp -L web:/var/lib/dpkg/status - | tar -xO" in html and "The collector on this host" in html and "Reader endpoint" not in html
    assert "docker compose pull" in html and "Check for Updates" not in html
    cov = html.split('id="image-coverage"')[1]
    assert "3 of 4 images have a package list" in cov and "Debian: 2 images matched" in cov
    # The jump menu lists both sections, and the nav has the tab for a collector host.
    from daemonsight.web import sections
    assert sections.SECTIONS[""]["images"] == [("image-list", "Images"), ("image-coverage", "What is checked")]
    assert 'href="/h/testhost/images#image-list"' in html and 'id="ds-sec-images"' in html


def test_the_finding_is_on_the_host_overview_and_the_report(page):
    overview = page.get("/h/testhost/").text
    assert "nginx:1.27 (Debian 12): 3 fixable CVEs" in overview and "container image" in overview.lower() or "nginx:1.27" in overview
    report = page.get("/h/testhost/report").text
    assert "nginx:1.27" in report


def test_the_images_tab_is_only_in_hub_mode(seeded):
    c = login(client(seeded))
    assert c.get("/images").status_code == 404
    assert "/images" not in c.get("/").text
