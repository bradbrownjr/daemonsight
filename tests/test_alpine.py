"""Alpine's security database (secdb): the parser, the release mapping, the download, the loader and the matching of one
image's packages. The files are synthetic (tests/fixtures/cve/alpine-*.json): public package names, made-up versions and
CVE ids from the other fixtures. See cve/alpine.py for what the real files were read to look like."""

import asyncio
import gzip
import json
import re
import time
from pathlib import Path

import httpx
import pytest

from daemonsight.config import Config
from daemonsight.cve import alpine, feeds, run, store

from .test_cve import FIX, DAY, serve

OK = '"v1"'


def secdb_gz(tmp_path: Path, release: str, repo: str) -> Path:
    p = tmp_path / f"alpine-{release}-{repo}.json.gz"
    p.write_bytes(gzip.compress((FIX / f"alpine-{repo}.json").read_text().replace("RELEASE", release).encode()))
    return p


def loaded(tmp_path: Path, release: str = "v3.23"):
    """A cve.db with both of a release's files loaded."""
    conn = store.connect(tmp_path / "cve.db")
    for feed in feeds.alpine_feeds(release):
        feeds.load_alpine(conn, secdb_gz(tmp_path, release, feed.repo), feed)
    return conn


# --- the release mapping --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("version_id, release", [
    ("3.23.2", "v3.23"), ("3.23", "v3.23"), ("3.17.2", "v3.17"), ("3.9.6", "v3.9"), (" 3.20.1 ", "v3.20"), ("3.2.3", "v3.2"),
    ("3.24.0_alpha20260101", None), ("edge", None), ("", None), (None, None), ("3", None), ("v3.23", None), ("3.23.x", None),
    ("3.23.2; rm -rf /", None), ("../3.23", None)])
def test_an_os_release_version_maps_to_the_directory_in_secdb(version_id, release):
    assert alpine.release_of(version_id) == release


def test_the_display_name_of_a_release():
    assert alpine.display("v3.23") == "Alpine 3.23" and alpine.display(None) == "Alpine"


# --- parsing --------------------------------------------------------------------------------------------------------------------

DOC = {"reponame": "main", "distroversion": "v3.23", "packages": [
    {"pkg": {"name": "openssl", "secfixes": {
        "0": ["CVE-2022-1292", "CVE-2022-2068"],                       # never affected Alpine's package: not a vulnerability
        "3.5.4-r0": ["CVE-2025-9230", "CVE-2021-27219 GHSL-2021-045"],  # a CVE id with text after it
        "3.5.5-r0": ["CVE-2025-9230"]}}},                               # the same CVE fixed again later
    {"pkg": {"name": "zlib", "secfixes": {"1.3.1-r0": ["ALPINE-13661", "ZDI-CAN-22300", "GHSA-1234", "RUSTSEC-2020-0146", "cve-2020-1234"]}}},
    {"pkg": {"name": "bad name", "secfixes": {"1.0-r0": ["CVE-2026-1111"]}}},
    {"pkg": {"name": "x", "secfixes": {"1.0bc": ["CVE-2026-2222"], "2.0-r0": "CVE-2026-3333", "": ["CVE-2026-4444"]}}},
    {"pkg": {"name": "empty", "secfixes": {}}}, {"pkg": {"name": "nofixes"}}, {"nopkg": 1}, "junk", None]}


def test_the_zero_key_is_dropped_trailing_text_is_cut_and_non_cve_ids_are_skipped():
    rows = alpine.parse_secdb(DOC)
    assert sorted(rows) == [("openssl", "CVE-2021-27219", "3.5.4-r0"), ("openssl", "CVE-2025-9230", "3.5.4-r0"),
                            ("openssl", "CVE-2025-9230", "3.5.5-r0")]
    assert not any(c in ("CVE-2022-1292", "CVE-2022-2068") for _o, c, _v in rows)           # under "0"
    assert not any(o in ("zlib", "x", "bad name") for o, _c, _v in rows)                      # ALPINE-/ZDI-/GHSA-/RUSTSEC- ids; bad versions; bad names


def test_the_name_is_the_origin_so_a_subpackage_is_found_through_its_origin(tmp_path):
    """secdb lists `openssl`, not `libcrypto3`; the installed database's o: line says libcrypto3 comes from openssl."""
    from daemonsight.docker_packages import parse_apk_installed
    pk, _n = parse_apk_installed("P:libcrypto3\nV:3.1.4-r0\no:openssl\n\nP:openssl\nV:3.1.4-r0\no:openssl\n\nP:musl\nV:1.2.4_git20230717-r4\no:musl\n")
    assert [p[:3] for p in pk] == [["libcrypto3", "openssl", "3.1.4-r0"], ["openssl", "", "3.1.4-r0"], ["musl", "", "1.2.4_git20230717-r4"]]
    conn = loaded(tmp_path)
    assert conn.execute("SELECT COUNT(*) FROM apk WHERE origin IN ('libcrypto3', 'libssl3', 'brotli-libs')").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM apk WHERE origin = 'openssl'").fetchone()[0] > 0


@pytest.mark.parametrize("doc", [[], {}, {"packages": {}}, {"packages": "x"}, "text", None, 5])
def test_a_document_that_is_not_secdb_is_refused(doc):
    with pytest.raises(alpine.SecdbError):
        alpine.parse_secdb(doc)


def test_loading_keeps_the_rows_of_the_fixture_and_replaces_one_file_at_a_time(tmp_path):
    conn = loaded(tmp_path)
    got = {(r["repo"], r["origin"], r["cve"], r["fixed"]) for r in conn.execute("SELECT * FROM apk WHERE release = 'v3.23'")}
    assert ("main", "brotli", "CVE-2026-111497", "1.1.0-r1") in got                      # the text after the id is gone
    assert ("main", "openssl", "CVE-2026-11979", "3.1.4-r2") in got and ("community", "c-ares", "CVE-2008-4409", "1.28.1-r0") in got
    assert not [g for g in got if g[1] in ("busybox", "broken", "not a valid name!", "nothing")]       # only non-CVE ids, bad versions, bad names
    assert not [g for g in got if g[2] in ("CVE-2016-5180", "CVE-2026-6653") and g[1] != "widget-server"]    # under "0" in main
    # Reloading main with other contents changes main's rows and leaves community's.
    main = feeds.alpine_feed("v3.23", "main")
    other = tmp_path / "other.json.gz"
    other.write_bytes(gzip.compress(json.dumps({"distroversion": "v3.23", "packages": [
        {"pkg": {"name": "only", "secfixes": {"1.0-r0": ["CVE-2026-9999"]}}}]}).encode()))
    feeds.load_alpine(conn, other, main)
    assert conn.execute("SELECT origin FROM apk WHERE repo = 'main'").fetchall()[0][0] == "only"
    assert conn.execute("SELECT COUNT(*) FROM apk WHERE repo = 'community'").fetchone()[0] == 2
    # A file that does not parse keeps what was there.
    bad = tmp_path / "bad.json.gz"
    bad.write_bytes(gzip.compress(b'{"packages": [1, 2'))
    with pytest.raises(ValueError):
        feeds.load_alpine(conn, bad, main)
    wrong = tmp_path / "wrong.json.gz"
    wrong.write_bytes(gzip.compress(json.dumps({"distroversion": "v3.99", "packages": []}).encode()))
    with pytest.raises(alpine.SecdbError):
        feeds.load_alpine(conn, wrong, main)
    assert conn.execute("SELECT origin FROM apk WHERE repo = 'main'").fetchall()[0][0] == "only"


# --- what counts as fixable -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("installed, fixed, result", [
    ("3.1.4-r0", ["3.1.4-r1"], "3.1.4-r1"), ("3.1.4-r1", ["3.1.4-r1"], None), ("3.1.4-r2", ["3.1.4-r1"], None),
    ("3.1.4-r0", ["3.1.4-r1", "3.1.4-r2"], "3.1.4-r2"),                   # fixed again later: the highest finishes the fix
    ("3.1.4-r1", ["3.1.4-r1", "3.1.4-r2"], "3.1.4-r2"), ("3.1.4-r2", ["3.1.4-r1", "3.1.4-r2"], None),
    ("1.2.4", ["1.2.4_git20230717-r5"], "1.2.4_git20230717-r5"), ("1.2.4_git20230717-r4", ["1.2.4_git20230717-r5"], "1.2.4_git20230717-r5"),
    ("1.2.4_rc1-r0", ["1.2.4-r0"], "1.2.4-r0"), ("1.10.0-r0", ["1.9.9-r0"], None), ("1.9.0-r0", ["1.10.0-r0"], "1.10.0-r0"),
    ("not a version", ["1.0-r0"], None), ("1.0-r0", [], None)])
def test_is_fixable_compares_with_apks_rules(installed, fixed, result):
    assert alpine.is_fixable(installed, fixed) == result


def inv(sources, release="v3.23", h="a1"):
    return {"backend": "apk", "os_id": "alpine", "release": release, "sources": sources, "taken_at": 1.0, "hash": h, "note": ""}


def test_matching_one_image_by_origin_and_version(tmp_path):
    conn = loaded(tmp_path)
    alpine.match_host(conn, "docker:tower:aaaa", inv([
        ["openssl", "3.1.4-r0", ["libcrypto3", "libssl3"]], ["brotli", "1.1.0-r0", ["brotli-libs"]], ["musl", "1.2.4_git20230717-r4", []],
        ["busybox", "1.36.1-r5", []], ["zlib", "1.3.1-r1", []], ["c-ares", "1.28.1-r0", []]]), "g")
    rows = {(r["source"], r["cve"]): (r["state"], r["installed"], r["fixed"]) for r in conn.execute("SELECT * FROM match WHERE host = 'docker:tower:aaaa'")}
    assert rows == {
        ("openssl", "CVE-2023-31124"): ("fix", "3.1.4-r0", "3.1.4-r2"),            # fixed in r1 and again in r2: the highest
        ("openssl", "CVE-2026-11979"): ("fix", "3.1.4-r0", "3.1.4-r2"),
        ("brotli", "CVE-2026-111497"): ("fix", "1.1.0-r0", "1.1.0-r1"),
        ("musl", "CVE-2026-74860"): ("fix", "1.2.4_git20230717-r4", "1.2.4_git20230717-r5")}
    # Not there: CVE-2016-5180 ("0"), CVE-2008-4409 (3.0.0-r0 is below the installed version), busybox's non-CVE ids, zlib and c-ares (already fixed).
    m = conn.execute("SELECT packages, note FROM matched WHERE host = 'docker:tower:aaaa'").fetchone()
    assert m["packages"] == 6
    # Another release has no rows, so nothing matches; and the rows are replaced, not added to.
    alpine.match_host(conn, "docker:tower:aaaa", inv([["openssl", "3.1.4-r0", []]], release="v3.99"), "g2")
    assert conn.execute("SELECT COUNT(*) FROM match WHERE host = 'docker:tower:aaaa'").fetchone()[0] == 0


# --- the download -----------------------------------------------------------------------------------------------------------------

def chore(tmp_path, client):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    return cfg, run.Chore(cfg, None, client)


def feed_rows(cfg):
    conn = store.connect(cfg.cve_db_path)
    try:
        return {r["name"]: dict(r) for r in conn.execute("SELECT * FROM feed WHERE name LIKE 'alpine-%'")}
    finally:
        conn.close()


def apk_count(cfg, release="v3.23"):
    conn = store.connect(cfg.cve_db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM apk WHERE release = ?", (release,)).fetchone()[0]
    finally:
        conn.close()


def refresh(c, releases, now):
    async def go():
        conn = c.factory()
        try:
            return await c._refresh_alpine(conn, releases, now)
        finally:
            conn.close()
    return asyncio.run(go())


def test_each_release_asks_main_and_community_once_a_day_with_a_conditional_get(tmp_path):
    calls = []
    cfg, c = chore(tmp_path, serve(tmp_path, calls))
    now = 1_800_000_000.0
    assert refresh(c, {"v3.23"}, now) is True
    secdb = [(h, d) for h, d in calls if h == feeds.ALPINE_HOST]
    assert len(secdb) == 2 and all("if-none-match" not in d for _h, d in secdb)
    assert apk_count(cfg) > 5
    rows = feed_rows(cfg)
    assert set(rows) == {"alpine-v3.23-main", "alpine-v3.23-community"}
    main = rows["alpine-v3.23-main"]
    assert main["status"] == "ok" and main["etag"] == OK and main["last_modified"] and main["rows"] > 0 and "packages" in main["note"]
    assert main["url"] == "https://secdb.alpinelinux.org/v3.23/main.json"
    assert (Path(cfg.data_dir) / "cve" / "alpine-v3.23-main.json.gz").exists()
    # An hour later nothing is asked; a day later each file is asked with its validators and answers 304.
    assert refresh(c, {"v3.23"}, now + 3600) is False and len(calls) == 2
    assert refresh(c, {"v3.23"}, now + DAY + 5) is False
    again = calls[2:]
    assert len(again) == 2 and all(d["if-none-match"] == OK and d["if-modified-since"].startswith("Tue, 24 Nov") for _h, d in again)
    assert feed_rows(cfg)["alpine-v3.23-main"]["status"] == "not modified" and apk_count(cfg) > 5
    # The requests carry the generic User-Agent only (serve asserts it) and nothing else of ours.
    assert all(set(d) <= {"host", "accept", "accept-encoding", "connection", "user-agent", "if-none-match", "if-modified-since"} for _h, d in calls)


def test_a_failed_download_keeps_the_last_good_copy_and_says_so(tmp_path):
    cfg, c = chore(tmp_path, serve(tmp_path))
    now = 1_800_000_000.0
    refresh(c, {"v3.23"}, now)
    before = apk_count(cfg)
    c.client = serve(tmp_path, override={feeds.ALPINE_HOST: lambda r: httpx.Response(503)})
    assert refresh(c, {"v3.23"}, now + DAY + 5) is False
    row = feed_rows(cfg)["alpine-v3.23-main"]
    assert row["status"] == "error" and row["detail"] == "HTTP 503" and row["ok_at"] == now                 # the last success is still the first
    assert apk_count(cfg) == before                                                                          # the rows from the good copy stay
    # An error is tried again after an hour, not a day.
    calls = []
    c.client = serve(tmp_path, calls, override={feeds.ALPINE_HOST: lambda r: httpx.Response(503)})
    refresh(c, {"v3.23"}, now + DAY + 5 + 1800)
    assert calls == []
    refresh(c, {"v3.23"}, now + DAY + 5 + 3600)
    assert len(calls) == 2
    # A file that downloads but is not secdb also keeps the rows.
    c.client = serve(tmp_path, override={feeds.ALPINE_HOST: lambda r: httpx.Response(200, content=b'{"packages": 5}', headers={"etag": '"v2"'})})
    refresh(c, {"v3.23"}, now + 3 * DAY)
    row = feed_rows(cfg)["alpine-v3.23-main"]
    assert row["status"] == "error" and "SecdbError" in row["detail"] and row["etag"] is None and apk_count(cfg) == before
    # Back to normal: loaded again.
    c.client = serve(tmp_path)
    refresh(c, {"v3.23"}, now + 4 * DAY)
    assert feed_rows(cfg)["alpine-v3.23-main"]["status"] == "ok" and apk_count(cfg) == before


def test_a_release_secdb_does_not_have_is_an_answer_not_an_error(tmp_path):
    cfg, c = chore(tmp_path, serve(tmp_path))
    now = 1_800_000_000.0
    assert refresh(c, {"v3.23", "v3.9"}, now) is True
    rows = feed_rows(cfg)
    assert rows["alpine-v3.9-main"]["status"] == "absent" and rows["alpine-v3.9-community"]["status"] == "absent"
    assert rows["alpine-v3.9-main"]["ok_at"] == now and rows["alpine-v3.9-main"]["detail"] is None and rows["alpine-v3.9-main"]["rows"] == 0
    assert apk_count(cfg, "v3.9") == 0 and not (Path(cfg.data_dir) / "cve" / "alpine-v3.9-main.json.gz").exists()
    # Asked again a day later (no validators, a plain request), and still absent: no change reported.
    calls = []
    c.client = serve(tmp_path, calls)
    assert refresh(c, {"v3.23", "v3.9"}, now + DAY + 5) is False
    assert len(calls) == 4 and sum("if-none-match" in d for _h, d in calls) == 2        # v3.23's two files are validated, v3.9's two have nothing to
    assert feed_rows(cfg)["alpine-v3.9-main"]["status"] == "absent"
    # Not a feed that counts as stale: it answered.
    conn = store.connect(cfg.cve_db_path)
    assert feeds.stale_feeds(conn, now + 2 * DAY) == []
    conn.close()


def test_a_release_no_image_runs_any_more_is_forgotten(tmp_path):
    cfg, c = chore(tmp_path, serve(tmp_path))
    now = 1_800_000_000.0
    refresh(c, {"v3.23", "v3.17"}, now)
    assert apk_count(cfg, "v3.17") > 0 and (Path(cfg.data_dir) / "cve" / "alpine-v3.17-main.json.gz").exists()
    assert refresh(c, {"v3.23"}, now + 60) is True
    assert apk_count(cfg, "v3.17") == 0 and apk_count(cfg) > 0
    assert set(feed_rows(cfg)) == {"alpine-v3.23-main", "alpine-v3.23-community"}
    assert not (Path(cfg.data_dir) / "cve" / "alpine-v3.17-main.json.gz").exists()
    assert refresh(c, set(), now + 120) is True and feed_rows(cfg) == {} and apk_count(cfg) == 0


def test_a_redirect_off_secdbs_host_and_a_huge_file_are_refused(tmp_path):
    async def go():
        conn = store.connect(tmp_path / "c.db")
        f = feeds.alpine_feed("v3.23", "main")
        row = feeds.feed_row(conn, f)

        def hop(request):
            if request.url.host == feeds.ALPINE_HOST:
                return httpx.Response(302, headers={"location": "https://evil.example/main.json"})
            return httpx.Response(200, content=b"{}")
        with pytest.raises(feeds.FetchError, match="not a source"):
            await feeds.download(f, row, tmp_path / "a.gz", httpx.AsyncClient(transport=httpx.MockTransport(hop), follow_redirects=True))
        big = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"0" * (feeds.ALPINE_MAX_BYTES + 1))))
        with pytest.raises(feeds.FetchError, match="larger"):
            await feeds.download(f, row, tmp_path / "b.gz", big)
        assert not (tmp_path / "a.gz").exists() and not (tmp_path / "b.gz").exists()
        assert f.hosts == (feeds.ALPINE_HOST,) and f.url == "https://secdb.alpinelinux.org/v3.23/main.json"
    asyncio.run(go())


def test_the_feed_for_a_release_has_its_terms_and_a_title():
    f = feeds.alpine_feed("v3.23", "community")
    assert f.name == "alpine-v3.23-community" and "Attribution-ShareAlike 4.0" in f.terms
    assert feeds.alpine_title(f.name) == f.title == "Alpine security database v3.23 community" and feeds.alpine_title("kev") == "kev"
    assert re.fullmatch(r"alpine-v[0-9.]+-(main|community)", f.name)
    assert [x.repo for x in feeds.alpine_feeds("v3.23")] == ["main", "community"]
