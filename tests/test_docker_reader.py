"""The Docker reader: it reads Docker through a fixed list of GETs, trims what it keeps, and answers only the hub, with a
token. The engine is a fake one on a unix socket in tmp_path (tests/fake_docker.py)."""

import asyncio
import json
import logging
import os

import httpx
import pytest

from daemonsight import cli, docker_reader as dr

from .fake_docker import ANON_A, ANON_B, ANON_USED, IDS, SECRET, FakeEngine, standard_replies

TOKEN = "t" * 20 + "0123456789abcdef" + "ZZ"


@pytest.fixture
def sock(tmp_path):
    # AF_UNIX paths are short: keep it directly under tmp_path
    return tmp_path / "d.sock"


async def summary_of(engine: FakeEngine, **kw) -> dict:
    docker = dr.Docker.over_socket(engine.path)
    kw.setdefault("read_packages", False)
    s = dr.Summarizer(docker, **kw)
    try:
        first = await s.get()
        if s.df_task is not None:
            await s.df_task
            s._built = 0           # let the next get() rebuild with the df result in place
        return await s.get() if kw.get("clock") is None else first
    finally:
        await docker.aclose()


# --- what the reader asks Docker ----------------------------------------------------------------------------------------

async def test_only_the_listed_gets_are_sent_with_the_versioned_path(sock):
    async with FakeEngine(sock) as eng:
        await summary_of(eng)
    methods = {m for m, _t in eng.requests}
    assert methods == {"GET"}
    targets = eng.targets()
    assert targets[0] == "/version" and "/_ping" not in targets
    for t in targets[1:]:
        assert t.startswith("/v1.54/"), t
        bare = eng.strip(t)
        assert bare in dr.VERSIONED or dr._INSPECT.match(bare), t
    # Every endpoint of the list was used (the helper builds twice, so the list ones come twice; df only once), and
    # inspect only for the images no container uses.
    bare = [eng.strip(t) for t in targets]
    for t in dr.VERSIONED:
        assert bare.count(t) == (1 if "system/df" in t else 2), t
    inspected = {t for t in bare if t.startswith("/images/") and t != "/images/json?all=0&digests=1"}
    assert inspected == {f"/images/{IDS[n]}/json" for n in ("widget-old", "debian", "gadget", "oldapp", "mystery", "tool")}
    # Never a container inspect: that is where Env lives.
    assert not any(t.startswith("/containers/") and t != "/containers/json?all=1" for t in bare)


def test_the_docker_client_has_no_way_to_send_anything_but_get():
    d = dr.Docker(httpx.AsyncClient())
    public = {n for n in dir(d) if not n.startswith("_")}
    assert public == {"api", "aclose", "archive", "check_allowed", "get", "negotiate", "over_socket"}
    for ok in ("/_ping", "/version", "/containers/json?all=1", "/images/json?all=0&digests=1", "/volumes",
               "/system/df?verbose=1", f"/images/{IDS['debian']}/json"):
        d.check_allowed(ok)
    for bad in ("/containers/abc/json", f"/containers/{'a' * 64}/json", "/containers/json?all=0", "/containers/json",
                "/images/json?all=1", "/images/json", "/images/debian/json", "/images/sha256:abc/json",
                f"/images/{IDS['debian']}/json?x=1", f"/images/{IDS['debian']}/history", "/images/../containers/x/json",
                "/exec/create", "/containers/x/exec", "/volumes/x", "/volumes?filters=1", "/system/df", "/v1.54/volumes",
                "/info", "/events", "/containers/json?all=1&size=1", ""):
        with pytest.raises(ValueError):
            d.check_allowed(bad)


async def test_a_forbidden_target_is_refused_before_anything_is_sent(sock):
    async with FakeEngine(sock) as eng:
        docker = dr.Docker.over_socket(eng.path)
        await docker.negotiate()
        with pytest.raises(ValueError):
            await docker.get(f"/containers/{'a' * 64}/json")
        await docker.aclose()
    assert eng.targets() == ["/version"]


@pytest.mark.parametrize("daemon, minimum, expected", [("1.60", "1.24", "/v1.54/"), ("1.45", "1.24", "/v1.45/"),
                                                       ("1.54", "1.24", "/v1.54/"), ("1.60", "1.58", "/v1.60/")])
async def test_the_api_version_is_the_lower_of_the_daemons_and_the_one_read(sock, daemon, minimum, expected):
    replies = standard_replies()
    replies["/version"] = {"ApiVersion": daemon, "MinAPIVersion": minimum, "Version": "x"}
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        await docker.negotiate()
        await docker.get("/volumes")
        await docker.aclose()
    assert eng.targets()[1].startswith(expected)


async def test_docker_errors_become_short_messages_without_docker_text(sock):
    replies = standard_replies()
    replies["/volumes"] = (500, {"message": f"boom {SECRET}"})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        s = dr.Summarizer(docker, read_packages=False)
        with pytest.raises(dr.DockerError) as exc:
            await s.get()
        await docker.aclose()
    assert "HTTP 500" in str(exc.value) and SECRET not in str(exc.value)


async def test_an_unreachable_socket_is_an_error_not_a_crash(tmp_path):
    docker = dr.Docker.over_socket(str(tmp_path / "none.sock"))
    with pytest.raises(dr.DockerError, match="Could not reach"):
        await docker.negotiate()
    await docker.aclose()


# --- trimming -----------------------------------------------------------------------------------------------------------

async def test_nothing_secret_comes_out_even_if_docker_returns_it(sock):
    async with FakeEngine(sock) as eng:
        out = await summary_of(eng)
    dumped = json.dumps(out)
    for needle in (SECRET, '"Env"', '"Cmd"', '"Entrypoint"', "PASSWORD", "/entry.sh", "Mountpoint", "/var/lib/docker", "/mnt/user/appdata", "com.example.secret",
                   "secret.label", "other.label", "evil"):
        assert needle not in dumped, needle
    for c in out["containers"]:
        assert set(c) == {"name", "image", "image_id", "state"}      # no container id: the reader keeps it to read packages
    for i in out["images"]:
        assert set(i) == {"id", "tags", "digests", "created", "size", "last_tag", "labels", "in_use"}
        assert all(k.startswith(("org.opencontainers.image.", "net.unraid.")) for k in i["labels"])
        assert all(len(v) <= 200 for v in i["labels"].values())
    for v in out["volumes"]:
        assert set(v) == {"name", "created", "driver", "labels", "anonymous", "size", "refs"}
        assert all(k.startswith("com.docker.compose.") for k in v["labels"])


async def test_what_is_kept(sock):
    async with FakeEngine(sock) as eng:
        out = await summary_of(eng)
    by = {i["id"]: i for i in out["images"]}
    old = by[IDS["widget-old"]]
    assert old["tags"] == [] and old["digests"] == ["ghcr.io/acme/widget@sha256:" + "4" * 64] and not old["in_use"]
    assert old["labels"]["org.opencontainers.image.source"] == "https://github.com/acme/widget"
    assert len(old["labels"]["org.opencontainers.image.description"]) == 200          # cut to 200
    assert "evil" not in old["labels"]
    assert old["last_tag"] is None                                                    # the zero time is "never tagged"
    assert by[IDS["debian"]]["last_tag"] == 1748779200                                # 2025-06-01T12:00:00Z
    assert by[IDS["nginx"]]["in_use"] and by[IDS["nginx"]]["labels"] == {"org.opencontainers.image.title": "nginx"}
    assert by[IDS["nginx"]]["last_tag"] is None                                       # not inspected: only unused images are
    assert by[IDS["tool"]]["tags"] == ["acme/tool:1", "acme/tool:stable"]
    # A container that exited still counts as using its image.
    assert by[IDS["inuse2"]]["in_use"]
    vols = {v["name"]: v for v in out["volumes"]}
    assert vols["shop_db"]["labels"] == {"com.docker.compose.project": "shop", "com.docker.compose.volume": "db"}
    assert vols[ANON_A]["anonymous"] and not vols["shop_db"]["anonymous"]
    assert (vols[ANON_B]["size"], vols[ANON_B]["refs"]) == (30_000_000, 0) and vols["webdata"]["refs"] == 1
    assert out["build_cache"] == {"count": 12, "size": 6_100_000_000}
    assert out["docker"] == {"version": "29.0.0", "api": "1.54"}


async def test_the_old_shape_of_system_df_is_read_too(sock):
    async with FakeEngine(sock, standard_replies("old")) as eng:
        out = await summary_of(eng)
    assert out["build_cache"] == {"count": 12, "size": 6_000_000_000}
    assert {v["name"]: v["size"] for v in out["volumes"]}["shop_db"] == 900_000_000


def test_parse_df_survives_junk():
    assert dr.parse_df(None) == {"volumes": {}, "build_cache": None, "images_reclaimable": None}
    out = dr.parse_df({"VolumeUsage": {"Items": ["x", {"Name": "a", "UsageData": {"Size": -1, "RefCount": -1}}]}, "BuildCacheUsage": []})
    assert out["volumes"] == {"a": {"size": None, "refs": None}}


def test_keep_labels_and_epoch():
    assert dr.keep_labels(None, dr.LABEL_PREFIXES) == {}
    assert dr.keep_labels({"org.opencontainers.image.x": "a\x00b" + "c" * 300, "other": "no", 5: "x"}, dr.LABEL_PREFIXES) == {
        "org.opencontainers.image.x": "ab" + "c" * 197}
    assert dr.epoch("0001-01-01T00:00:00Z") is None and dr.epoch("") is None and dr.epoch("garbage") is None
    assert dr.epoch("2025-06-01T12:00:00+00:00") == 1748779200 == dr.epoch("2025-06-01T12:00:00.123456789Z")


# --- timing and caching ---------------------------------------------------------------------------------------------------

async def test_the_summary_is_cached_and_df_runs_in_the_background_every_30_minutes(sock):
    now = [1_000.0]
    async with FakeEngine(sock) as eng:
        eng.delay["/system/df?verbose=1"] = 1.0          # a slow df must not hold up the summary
        docker = dr.Docker.over_socket(eng.path)
        s = dr.Summarizer(docker, clock=lambda: now[0], read_packages=False)
        first = await s.get()
        assert not s.df_task.done()                       # the summary came back while df was still running
        assert first["df_at"] is None and first["df_running"] is True and first["build_cache"] is None
        # Volumes are known to be unused without df: the containers' mounts say so.
        refs = {v["name"]: v["refs"] for v in first["volumes"]}
        assert refs == {ANON_A: 0, ANON_B: 0, "shop_db": 0, "webdata": 1, ANON_USED: 1}
        await s.df_task
        again = await s.get()                             # within SUMMARY_SECONDS: cached, with the df result merged in
        assert again["df_at"] == 1_000 and again["df_running"] is False and again["build_cache"]["count"] == 12
        n = len(eng.requests)
        now[0] += 30
        await s.get()
        assert len(eng.requests) == n                     # still cached
        now[0] += dr.SUMMARY_SECONDS + 1
        await s.get()                                     # rebuilt: lists again, df not yet due
        assert sum(1 for t in eng.targets() if "system/df" in t) == 1
        assert sum(1 for t in eng.targets() if t.endswith("/containers/json?all=1")) == 2
        inspects = sum(1 for t in eng.targets() if t.endswith("/json") and "/images/sha256" in t)
        assert inspects == 6                              # the inspect results were reused
        now[0] += dr.DF_SECONDS
        await s.get()
        await s.df_task
        assert sum(1 for t in eng.targets() if "system/df" in t) == 2
        await docker.aclose()


async def test_a_failed_df_keeps_the_last_good_one_and_says_so(sock):
    now = [1_000.0]
    async with FakeEngine(sock) as eng:
        docker = dr.Docker.over_socket(eng.path)
        s = dr.Summarizer(docker, clock=lambda: now[0], read_packages=False)
        await s.get()
        await s.df_task
        eng.replies["/system/df?verbose=1"] = (500, {"message": "x"})
        now[0] += dr.DF_SECONDS + dr.SUMMARY_SECONDS
        await s.get()
        await s.df_task
        out = await s.get()
        assert out["df_at"] == 1_000 and "HTTP 500" in out["df_error"] and out["build_cache"]["count"] == 12
        await docker.aclose()


# --- the token ----------------------------------------------------------------------------------------------------------------

def write_token(path, text=TOKEN, mode=0o600):
    path.write_text(text + "\n")
    os.chmod(path, mode)
    return str(path)


def test_the_token_file_must_be_private_and_long_enough(tmp_path):
    assert dr.read_token_file(write_token(tmp_path / "t")) == TOKEN
    for mode in (0o644, 0o640, 0o604, 0o660):
        with pytest.raises(dr.TokenError, match="0600") as exc:
            dr.read_token_file(write_token(tmp_path / f"m{mode}", mode=mode))
        assert TOKEN not in str(exc.value)
    with pytest.raises(dr.TokenError, match="at least 32") as exc:
        dr.read_token_file(write_token(tmp_path / "short", "short-secret"))
    assert "short-secret" not in str(exc.value)
    with pytest.raises(dr.TokenError):
        dr.read_token_file(write_token(tmp_path / "spaced", "a" * 20 + " " + "b" * 20))
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "t")
    with pytest.raises(dr.TokenError):                                # a symlink is not followed
        dr.read_token_file(str(link))
    with pytest.raises(dr.TokenError):
        dr.read_token_file(str(tmp_path))                             # a directory
    with pytest.raises(dr.TokenError, match="Can't open"):
        dr.read_token_file(str(tmp_path / "none"))


def test_token_matches_is_exact_and_only_for_bearer():
    assert dr.token_matches(TOKEN, f"Bearer {TOKEN}") and dr.token_matches(TOKEN, f"bearer {TOKEN}")
    for bad in (None, "", TOKEN, f"Basic {TOKEN}", f"Bearer {TOKEN}x", f"Bearer {TOKEN[:-1]}", "Bearer ", "Bearer", f"Bearer  {TOKEN.upper()}",
                f"Token {TOKEN}"):
        assert not dr.token_matches(TOKEN, bad), bad


def test_the_comparison_is_constant_time_by_construction():
    import inspect
    src = inspect.getsource(dr.token_matches)
    assert "compare_digest" in src and "==" not in src.replace("scheme.lower() ==", "")


async def served(sock, token=TOKEN):
    """An ASGI client for the reader's app, over a fake engine."""
    eng = FakeEngine(sock)
    await eng.__aenter__()
    docker = dr.Docker.over_socket(eng.path)
    app = dr.create_app(token, docker)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://reader")
    return eng, docker, client


async def test_the_app_needs_the_token_on_both_routes(sock, caplog):
    caplog.set_level(logging.DEBUG)
    eng, docker, c = await served(sock)
    try:
        for path in ("/v1/summary", "/v1/health"):
            assert (await c.get(path)).status_code == 401
            assert (await c.get(path, headers={"Authorization": "Bearer wrong"})).status_code == 401
            assert (await c.get(path, headers={"Authorization": f"Basic {TOKEN}"})).status_code == 401
            r = await c.get(path, headers={"Authorization": "Bearer wrong"})
            assert r.headers["www-authenticate"] == "Bearer" and TOKEN not in r.text
        assert eng.requests == []                                    # a refused request never reaches Docker
        good = {"Authorization": f"Bearer {TOKEN}"}
        h = await c.get("/v1/health", headers=good)
        assert h.status_code == 200 and h.json() == {"ok": True, "version": "29.0.0", "api": "1.54"}
        r = await c.get("/v1/summary", headers=good)
        assert r.status_code == 200 and r.json()["v"] == 1 and SECRET not in r.text and TOKEN not in r.text
    finally:
        await c.aclose()
        await docker.aclose()
        await eng.__aexit__(None, None, None)
    # The token is in no log line, whatever the level.
    assert TOKEN not in caplog.text and "Bearer" not in caplog.text


async def test_the_app_is_not_a_proxy(sock):
    eng, docker, c = await served(sock)
    good = {"Authorization": f"Bearer {TOKEN}"}
    try:
        for path in ("/", "/docs", "/redoc", "/openapi.json", "/v1", "/v1/", "/v1/summary/", "/v1/containers", "/v1/images/json",
                     "/v1.54/containers/json", "/containers/json", "/_ping", "/version", "/v1/../containers/json",
                     "/v1/summary/containers/abc/json", "/%2e%2e/containers", "/v1/health/../summary"):
            r = await c.get(path, headers=good)
            assert r.status_code in (404, 307, 308) or r.status_code == 200 and path == "/v1/health/../summary", (path, r.status_code)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            for path in ("/v1/summary", "/v1/health", "/containers/create"):
                assert (await c.request(method, path, headers=good, content=b"{}")).status_code in (404, 405)
        # A query string or body is ignored: it never turns into a Docker request.
        await c.get("/v1/summary?all=1&filters=%7B%7D&path=/containers/x/json", headers=good)
    finally:
        await c.aclose()
        await docker.aclose()
        await eng.__aexit__(None, None, None)
    assert {m for m, _ in eng.requests} == {"GET"}
    for t in eng.targets():
        bare = eng.strip(t)
        assert bare in dr.VERSIONED | dr.UNVERSIONED or dr._INSPECT.match(bare) or dr.pk.ARCHIVE_TARGET.match(bare), t


async def test_docker_down_is_a_502_with_a_short_message(tmp_path):
    docker = dr.Docker.over_socket(str(tmp_path / "gone.sock"))
    app = dr.create_app(TOKEN, docker)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://reader") as c:
        for path in ("/v1/summary", "/v1/health"):
            r = await c.get(path, headers={"Authorization": f"Bearer {TOKEN}"})
            assert r.status_code == 502 and "Could not reach Docker" in r.json()["error"]
    await docker.aclose()


# --- the command ----------------------------------------------------------------------------------------------------------

def test_the_command_refuses_a_loose_token_file_and_a_missing_socket(tmp_path, capsys):
    conf = tmp_path / "c.toml"
    conf.write_text("")
    loose = write_token(tmp_path / "loose", mode=0o644)
    assert cli.main(["-c", str(conf), "docker-reader", "--token-file", loose, "--socket", str(tmp_path / "s")]) == 1
    err = capsys.readouterr().err
    assert "0600" in err and TOKEN not in err
    ok = write_token(tmp_path / "ok")
    assert cli.main(["-c", str(conf), "docker-reader", "--token-file", ok, "--socket", str(tmp_path / "missing.sock")]) == 1
    assert "No Docker socket" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["-c", str(conf), "docker-reader"])                                   # --token-file is required: no token on the command line


def test_the_token_is_not_an_environment_variable_or_an_argument():
    import inspect
    src = inspect.getsource(dr) + inspect.getsource(cli.cmd_docker_reader)
    assert "environ" not in src and "getenv" not in src
    assert "--token " not in src and '"--token"' not in src


def test_the_entrypoint_skips_the_hubs_setup_for_the_reader():
    text = open("packaging/docker/entrypoint.sh").read()
    head = text.split("daemonsight init")[0]
    assert 'docker-reader' in head and "exec daemonsight" in head


# --- package lists: the archive endpoint, the tar stream, the parsers, the cache and the rate -------------------------------

import gzip
import hashlib
import tarfile

from daemonsight import docker_packages as pk

from .fake_docker import archive_key, serve_files, tar_of

CID = hashlib.sha256(b"web").hexdigest()
DEBIAN12_OS = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nVERSION_CODENAME=bookworm\nID=debian\n'
DPKG = (b"Package: libbrotli1\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0.9-2+b6\nSource: brotli (1.0.9-2)\nDescription: library\n continued line\n\n"
        b"Package: nginx\nStatus: install ok installed\nVersion: 1.27.0-1\nArchitecture: amd64\n\n"
        b"Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\nArchitecture: amd64\n\n"
        b"Package: half\nStatus: install ok half-configured\nVersion: 1.0\nArchitecture: amd64\n\n"
        b"Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\nSource: glibc\nArchitecture: amd64\n\n"
        b"Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\nSource: glibc\nArchitecture: i386\n")
APK = b"C:Q1abc\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\nT:the musl c library\n\nP:libcrypto3\nV:3.1.4-r5\no:openssl\n\nP:broken\n"
ARCHIVE_URLS = [f"/containers/{CID}/archive?path=%2Fusr%2Flib%2Fos-release", f"/containers/{CID}/archive?path=%2Fetc%2Fos-release",
                f"/containers/{CID}/archive?path=%2Fvar%2Flib%2Fdpkg%2Fstatus", f"/containers/{CID}/archive?path=%2Flib%2Fapk%2Fdb%2Finstalled"]


def test_the_archive_get_is_allowed_for_the_four_paths_only():
    d = dr.Docker(httpx.AsyncClient())
    for ok in ARCHIVE_URLS:
        d.check_allowed(ok)
        d.check_allowed(ok, "GET")
    assert [pk.archive_target(CID, p) for p in pk.ARCHIVE_PATHS] == ARCHIVE_URLS
    base = f"/containers/{CID}/archive?path="
    for bad in (base + "%2Fetc%2Fshadow", base + "%2Fetc%2Fpasswd", base + "%2Fproc%2Fself%2Fenviron", base + "%2F", base,
                base + "%2Fusr%2Flib%2Fos-release%2F..%2F..%2Fshadow", base + "%2Fusr%2Flib%2F..%2Flib%2Fos-release",
                base + "..%2F..%2Fetc%2Fshadow", base + "%2Fetc%2Fos-release%00", base + "%2Fetc%2Fos-release%0A",
                base + "/etc/os-release", base + "%2fetc%2fos-release", base + "%252Fetc%252Fos-release",
                base + "%2Fetc%2Fos-release&path=%2Fetc%2Fshadow", base + "%2Fetc%2Fos-release&x=1", base + "%2Fetc%2Fos-release\n",
                base + "%2Fvar%2Flib%2Fdpkg%2Fstatus.d", base + "%2Fvar%2Flib%2Fdpkg%2Fstatus%2F",
                f"/containers/{CID[:63]}/archive?path=%2Fetc%2Fos-release", f"/containers/{CID.upper()}/archive?path=%2Fetc%2Fos-release",
                "/containers/web/archive?path=%2Fetc%2Fos-release", f"/containers/{CID}/archive/?path=%2Fetc%2Fos-release",
                f"/containers/{CID}/archive", f"/containers/{CID}/json", f"/containers/{CID}/export",
                f"/containers/../containers/{CID}/archive?path=%2Fetc%2Fos-release", f"/v1.54/containers/{CID}/archive?path=%2Fetc%2Fos-release",
                f"/containers/{CID}/archive?path=%2Fetc%2Fos-release#x"):
        with pytest.raises(ValueError):
            d.check_allowed(bad)
    for method in ("PUT", "HEAD", "POST", "DELETE", "get"):
        with pytest.raises(ValueError):
            d.check_allowed(ARCHIVE_URLS[0], method)
    for bad_id, bad_path in (("web", "/etc/os-release"), (CID, "/etc/shadow"), (CID, "/etc/../etc/os-release"), (CID + "0", "/etc/os-release")):
        with pytest.raises(ValueError):
            pk.archive_target(bad_id, bad_path)


async def test_archive_sends_one_get_and_refuses_the_rest_before_sending(sock):
    replies = standard_replies()
    serve_files(replies, "web", {"/usr/lib/os-release": DEBIAN12_OS})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        await docker.negotiate()
        assert await docker.archive(CID, "/usr/lib/os-release") == DEBIAN12_OS
        assert await docker.archive(CID, "/etc/os-release") is None               # a 404 is "no such file"
        for bad in ("/etc/shadow", "/etc/../usr/lib/os-release", "/usr/lib/os-release/"):
            with pytest.raises(ValueError):
                await docker.archive(CID, bad)
        with pytest.raises(ValueError):
            await docker.get(ARCHIVE_URLS[0])                                    # an archive is not JSON: not through get
        await docker.aclose()
    assert [m for m, _t in eng.requests] == ["GET", "GET", "GET"]
    assert eng.targets()[1] == "/v1.54" + ARCHIVE_URLS[0] and eng.targets()[2] == "/v1.54" + ARCHIVE_URLS[1]


def test_the_tar_stream_is_one_regular_file_within_the_cap():
    assert pk.read_single_file(tar_of("os-release", b"ID=debian\n"), 100) == b"ID=debian\n"
    assert pk.read_single_file(tar_of("x", b""), 100) == b""
    # a link is not followed: /etc/os-release is normally one
    with pytest.raises(pk.ArchiveSymlink):
        pk.read_single_file(tar_of("os-release", kind=tarfile.SYMTYPE, link="../usr/lib/os-release"), 100)
    with pytest.raises(pk.ArchiveSymlink):
        pk.read_single_file(tar_of("os-release", kind=tarfile.LNKTYPE, link="other"), 100)
    for kind in (tarfile.DIRTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
        with pytest.raises(pk.ArchiveError, match="not a regular file"):
            pk.read_single_file(tar_of("d", kind=kind), 100)
    with pytest.raises(pk.ArchiveError, match="larger than the limit"):
        pk.read_single_file(tar_of("big", b"x" * 101), 100)
    with pytest.raises(pk.ArchiveError, match="more than one member"):
        pk.read_single_file(tar_of("a", b"1", extra=(("b", b"2"),)), 100)
    with pytest.raises(pk.ArchiveError, match="empty"):
        pk.read_single_file(b"\0" * 1024, 100)
    whole = tar_of("a", b"y" * 600)
    with pytest.raises(pk.ArchiveError):
        pk.read_single_file(whole[:700], 1000)                                   # cut inside the file
    for junk in (b"", b"not a tar at all" * 100, gzip.compress(tar_of("a", b"1"))):
        with pytest.raises(pk.ArchiveError):                                     # a gzip stream is not unpacked
            pk.read_single_file(junk, 100)


async def test_a_reply_over_the_cap_is_refused_while_it_streams(sock):
    big = tar_of("status", b"x" * (pk.CAPS["/etc/os-release"] + pk.TAR_OVERHEAD))
    replies = standard_replies()
    replies[archive_key("web", "/etc/os-release")] = big
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        await docker.negotiate()
        with pytest.raises(dr.DockerError, match="too large"):
            await docker.archive(CID, "/etc/os-release")
        await docker.aclose()
    assert pk.CAPS == {"/usr/lib/os-release": 65536, "/etc/os-release": 65536, "/var/lib/dpkg/status": 16 << 20, "/lib/apk/db/installed": 4 << 20}


def test_os_release_dpkg_and_apk_parsers():
    os = pk.parse_os_release(DEBIAN12_OS.decode())
    assert os == {"id": "debian", "like": [], "version_id": "12", "codename": "bookworm", "pretty": "Debian GNU/Linux 12 (bookworm)"}
    pi = pk.parse_os_release('ID=raspbian\nID_LIKE=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
    assert pi["like"] == ["debian"] and pk.os_kind(pi) == "dpkg"
    assert pk.os_kind(os) == "dpkg" and pk.os_kind({"id": "alpine", "like": []}) == "apk" and pk.os_kind({"id": "ubuntu", "like": ["debian"]}) == "dpkg"
    assert pk.os_kind({"id": "centos", "like": ["rhel", "fedora"]}) == "other" and pk.os_kind(None) == "unknown" and pk.os_kind({"id": ""}) == "unknown"
    pkgs, count = pk.parse_dpkg_status(DPKG.decode())
    assert count == 3 and pkgs == [["libbrotli1", "brotli", "1.0.9-2+b6", "1.0.9-2"], ["nginx", "", "1.27.0-1", ""], ["libc6", "glibc", "2.36-9", ""]]
    assert pk.parse_dpkg_status("Package: a\nStatus: install ok installed\nVersion: 1\nSource: b\n") == ([["a", "b", "1", ""]], 1)
    assert pk.parse_dpkg_status("") == ([], 0) and pk.parse_dpkg_status("garbage\n\n\n:::\n") == ([], 0)
    apk, n = pk.parse_apk_installed(APK.decode())
    assert n == 2 and apk == [["musl", "", "1.2.4-r2", ""], ["libcrypto3", "openssl", "3.1.4-r5", ""]]


def test_a_huge_package_list_is_counted_but_cut():
    text = "".join(f"Package: p{i}\nStatus: install ok installed\nVersion: 1\n\n" for i in range(pk.MAX_PACKAGES + 50))
    pkgs, count = pk.parse_dpkg_status(text)
    assert len(pkgs) == pk.MAX_PACKAGES and count == pk.MAX_PACKAGES + 50


def world_replies(containers: list[tuple[str, str, str]]):
    """A server whose containers are (name, image name, state): every image id is made up from its name."""
    from .fake_docker import container
    replies = standard_replies()
    replies["/containers/json?all=1"] = [container(n, i, i + ":1", state=s) for n, i, s in containers]
    replies["/images/json?all=0&digests=1"] = []
    return replies


@pytest.fixture
def many_images():
    """Twenty-five images, each used by one running container, plus one used only by a stopped container."""
    from . import fake_docker as fd
    names = [f"img{i:02d}" for i in range(25)] + ["stopped-img"]
    for n in names:
        fd.IDS.setdefault(n, fd.hid(n))
    yield names
    for n in names:
        fd.IDS.pop(n, None)


async def test_one_container_per_image_is_read_once_and_cached_by_image_id(sock):
    from .fake_docker import IDS
    replies = world_replies([("web", "nginx", "running"), ("web2", "nginx", "running"), ("db", "postgres", "running"), ("off", "debian", "exited")])
    serve_files(replies, "web", {"/usr/lib/os-release": DEBIAN12_OS, "/var/lib/dpkg/status": DPKG})
    serve_files(replies, "db", {"/etc/os-release": b"ID=alpine\nVERSION_ID=3.19.1\n", "/lib/apk/db/installed": APK})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        now = [1_000.0]
        s = dr.Summarizer(docker, clock=lambda: now[0], pace=0)
        first = await s.get()
        await s.pk_task
        out = await s.get()
        by = {e["image_id"]: e for e in out["image_packages"]}
        n = by[IDS["nginx"]]
        assert n["container"] == "web" and n["manager"] == "dpkg" and n["count"] == 3 and n["error"] is None and n["read_at"] == 1000
        assert n["os"]["id"] == "debian" and n["os"]["codename"] == "bookworm" and n["packages"][0] == ["libbrotli1", "brotli", "1.0.9-2+b6", "1.0.9-2"]
        a = by[IDS["postgres"]]
        assert a["manager"] == "apk" and a["count"] == 2 and a["os"]["id"] == "alpine"
        assert by[IDS["debian"]]["error"] == "not read: stopped" and by[IDS["debian"]]["packages"] == [] and by[IDS["debian"]]["read_at"] is None
        assert {e["image_id"] for e in first["image_packages"]} == set(by)           # the first reply listed them too, as not read yet
        assert all(e["error"] == "not read yet" for e in first["image_packages"] if e["image_id"] != IDS["debian"])
        archive_reads = [t for t in eng.targets() if "/archive?" in t]
        assert sum(1 for t in archive_reads if CID in t) == 2                       # os-release, dpkg status; web2 never read
        assert not any(hashlib.sha256(b"web2").hexdigest() in t for t in archive_reads)
        assert not any(hashlib.sha256(b"off").hexdigest() in t for t in archive_reads)          # a stopped container is skipped
        before = len(archive_reads)
        now[0] += dr.SUMMARY_SECONDS + 1
        await s.get()
        now[0] += 3600
        await s.get()
        if s.pk_task:
            await s.pk_task
        assert len([t for t in eng.targets() if "/archive?" in t]) == before        # cached: the image id did not change
        # An update changes the image id: the new image is read, the old entry goes.
        newid = "sha256:" + "ab" * 32
        replies2 = eng.replies["/containers/json?all=1"]
        replies2[0]["ImageID"] = replies2[1]["ImageID"] = newid
        now[0] += dr.SUMMARY_SECONDS + 1
        await s.get()
        await s.pk_task
        out = await s.get()
        ids = {e["image_id"] for e in out["image_packages"]}
        assert newid in ids and IDS["nginx"] not in ids
        assert len([t for t in eng.targets() if "/archive?" in t]) > before
        await docker.aclose()
    assert {m for m, _t in eng.requests} == {"GET"}


async def test_the_rate_limit_reads_ten_images_per_cycle_and_the_rest_later(sock, many_images):
    replies = world_replies([(f"c{n}", n, "running") for n in many_images[:25]] + [("cs", "stopped-img", "exited")])
    for n in many_images[:25]:
        serve_files(replies, f"c{n}", {"/usr/lib/os-release": DEBIAN12_OS, "/var/lib/dpkg/status": DPKG})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        s = dr.Summarizer(docker, pace=3600)                 # the background task would wait an hour: drive the batches by hand
        await s.docker.negotiate()
        await s._build(1000.0)
        assert dr.ARCHIVE_IMAGES_PER_CYCLE == 10 and s.max_reads == 10
        assert await s.read_batch() == 10 and len(s._pk) == 10
        assert await s.read_batch() == 10 and len(s._pk) == 20
        assert await s.read_batch() == 5 and len(s._pk) == 25
        assert await s.read_batch() == 0
        entries = s._pk_entries()
        assert len(entries) == 26 and sum(1 for e in entries if e["manager"] == "dpkg") == 25
        assert [e["error"] for e in entries if e["container"] is None] == ["not read: stopped"]
        # Each batch is images, not requests: two reads (os-release, dpkg status) each, in name order
        assert sum(1 for t in eng.targets() if "/archive?" in t) == 50
        await docker.aclose()


async def test_the_background_pass_spreads_the_first_read_over_cycles(sock, many_images):
    replies = world_replies([(f"c{n}", n, "running") for n in many_images[:12]])
    for n in many_images[:12]:
        serve_files(replies, f"c{n}", {"/usr/lib/os-release": DEBIAN12_OS, "/var/lib/dpkg/status": DPKG})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        s = dr.Summarizer(docker, pace=1.5)
        await s.get()
        for _ in range(100):
            if len(s._pk) >= 10:
                break
            await asyncio.sleep(0.05)
        assert len(s._pk) == 10                               # one cycle's worth, then it waits for the pace
        await s.pk_task
        assert len(s._pk) == 12
        await docker.aclose()


async def test_other_oses_distroless_and_failures_say_why_and_are_retried_only_when_they_may_pass(sock):
    replies = world_replies([("web", "nginx", "running"), ("db", "postgres", "running"), ("tool", "tool", "running"), ("gadget", "gadget", "running")])
    serve_files(replies, "web", {"/usr/lib/os-release": b'ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="8"\nPRETTY_NAME="CentOS Linux 8"\n'})
    serve_files(replies, "db", {"/usr/lib/os-release": DEBIAN12_OS})                          # debian with no dpkg status: distroless
    serve_files(replies, "tool", {"/etc/os-release": ("tar", tar_of("os-release", kind=tarfile.SYMTYPE, link="../usr/lib/os-release"))})
    replies[archive_key("gadget", "/usr/lib/os-release")] = (500, {"message": "boom"})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        now = [1_000.0]
        s = dr.Summarizer(docker, clock=lambda: now[0], pace=0)
        await s.get()
        await s.pk_task
        by = {e["container"]: e for e in (await s.get())["image_packages"]}
        assert by["web"]["error"] == "packages not read: CentOS Linux 8 does not use dpkg or apk" and by["web"]["os"]["id"] == "centos"
        assert by["db"]["error"].startswith("packages not read: no dpkg or apk package database") and by["db"]["os"]["id"] == "debian"
        assert by["tool"]["error"].startswith("packages not read: no dpkg or apk package database") and by["tool"]["os"] is None
        assert by["gadget"]["error"] == "packages not read: Docker answered HTTP 500."
        assert all(e["packages"] == [] and e["manager"] is None for e in by.values())
        reads = sum(1 for t in eng.targets() if "/archive?" in t)
        now[0] += dr.SUMMARY_SECONDS + 1
        await s.get()
        if s.pk_task:
            await s.pk_task
        # The centos answer is final; the other three may pass, so they wait PACKAGES_RETRY_SECONDS.
        assert sum(1 for t in eng.targets() if "/archive?" in t) == reads
        now[0] += dr.PACKAGES_RETRY_SECONDS
        await s.get()
        await s.pk_task
        again = sum(1 for t in eng.targets() if "/archive?" in t) - reads
        assert again > 0 and not any(hashlib.sha256(b"web").hexdigest() in t for t in eng.targets()[-again:])
        await docker.aclose()


async def test_the_summary_carries_package_lists_and_nothing_else_from_inside_a_container(sock):
    replies = world_replies([("web", "nginx", "running")])
    serve_files(replies, "web", {"/usr/lib/os-release": DEBIAN12_OS + b"SECRET_TOKEN=hunter2\nHOME_URL=https://x.test\n",
                                 "/var/lib/dpkg/status": DPKG + b"\nPackage: leak\nStatus: install ok installed\nVersion: 1\nConffiles: /etc/x hunter2\n"})
    async with FakeEngine(sock, replies) as eng:
        docker = dr.Docker.over_socket(eng.path)
        s = dr.Summarizer(docker, pace=0)
        await s.get()
        await s.pk_task
        out = await s.get()
        await docker.aclose()
    dumped = json.dumps(out["image_packages"])
    assert "hunter2" not in dumped and "SECRET_TOKEN" not in dumped and "HOME_URL" not in dumped
    e = out["image_packages"][0]
    assert set(e) == {"image_id", "container", "read_at", "os", "manager", "count", "packages", "error"}
    assert set(e["os"]) == {"id", "like", "version_id", "codename", "pretty"}
    for c in out["containers"]:
        assert set(c) == {"name", "image", "image_id", "state"}
