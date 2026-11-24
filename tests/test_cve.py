"""CVE matching on the hub: the tracker reader, feeds, matching states,
findings, the chore, the upload shape and the Vulnerabilities page."""

import asyncio
import bz2
import gzip
import json
import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import db, hub
from daemonsight.collector import upload
from daemonsight.collector.sources import inventory as inv
from daemonsight.config import Config
from daemonsight.cve import exposure, feeds, match, priority, run, store, tracker
from daemonsight.web.app import create_app

from . import fake_advisories, fake_changelog, fake_cve_services
from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)
from .test_web import seeded  # noqa: F401 (fixture)

FIX = Path(__file__).parent / "fixtures" / "cve"
DAY = 86400


def tracker_gz(tmp_path) -> Path:
    p = tmp_path / "tracker.json.gz"
    p.write_bytes(gzip.compress((FIX / "tracker-sample.json").read_bytes()))
    return p


def epss_gz(tmp_path) -> Path:
    p = tmp_path / "epss.csv.gz"
    p.write_bytes(gzip.compress((FIX / "epss-sample.csv").read_bytes()))
    return p


def kev_gz(tmp_path) -> Path:
    p = tmp_path / "kev.json.gz"
    p.write_bytes(gzip.compress((FIX / "kev-sample.json").read_bytes()))
    return p


@pytest.fixture
def cvedb(tmp_path):
    conn = store.connect(tmp_path / "cve.db")
    feeds.load_debian(conn, tracker_gz(tmp_path), {"trixie"})
    feeds.load_epss(conn, epss_gz(tmp_path))
    feeds.load_kev(conn, kev_gz(tmp_path))
    yield conn
    conn.close()


def inventory(sources, codename="trixie", os_id="debian", taken_at=None, h="a1"):
    return {"v": 1, "taken_at": taken_at or time.time(), "backend": "apt", "os_id": os_id, "version_id": "13",
            "codename": codename, "hash": h, "sources": sources}


# ---- the tracker reader ----------------------------------------------------------

def test_stream_reader_equals_json_load(monkeypatch):
    """Read with a tiny buffer, so every value is split across refills."""
    monkeypatch.setattr(tracker, "CHUNK", 37)
    expected = json.loads((FIX / "tracker-sample.json").read_text())
    got: dict = {}
    with open(FIX / "tracker-sample.json", encoding="utf-8") as fh:
        for pkg, cve, entry in tracker.iter_entries(fh):
            got.setdefault(pkg, {})[cve] = entry
    assert got == expected


@pytest.mark.parametrize("text", ['{"a": {"CVE-1": {"x": 1}', '[1, 2]', '{"a": {"b" 1}}', '{"a": 5}'])
def test_stream_reader_refuses_broken_feeds(text):
    import io
    with pytest.raises(tracker.FeedFormatError):
        list(tracker.iter_entries(io.StringIO(text)))


def test_stream_reader_has_a_size_limit():
    import io
    with pytest.raises(tracker.FeedFormatError):
        list(tracker.iter_entries(io.StringIO('{"a": {"CVE-1": {"x": "' + "y" * 5000 + '"}}}'), limit=1000))


def test_load_debian_keeps_only_asked_releases_and_drops_not_affected(tmp_path):
    conn = store.connect(tmp_path / "c.db")
    n = feeds.load_debian(conn, tracker_gz(tmp_path), {"trixie"})
    assert n == 11  # 12 trixie rows; libxml2 CVE-2008-4409 is fixed_version 0: not affected
    assert conn.execute("SELECT COUNT(*) FROM deb WHERE release != 'trixie'").fetchone()[0] == 0
    assert conn.execute("SELECT 1 FROM deb WHERE cve = 'CVE-2008-4409'").fetchone() is None
    assert conn.execute("SELECT descr FROM cve WHERE id = 'CVE-2016-5180'").fetchone()
    feeds.load_debian(conn, tracker_gz(tmp_path), {"bookworm"})  # replaces, not adds
    assert conn.execute("SELECT COUNT(*) FROM deb WHERE release = 'trixie'").fetchone()[0] == 0


def test_load_epss_and_kev(cvedb):
    row = cvedb.execute("SELECT score, pct FROM epss WHERE cve = 'CVE-2026-111497'").fetchone()
    assert (row["score"], row["pct"]) == (0.82641, 0.99673)
    k = cvedb.execute("SELECT * FROM kev WHERE cve = 'CVE-2026-111497'").fetchone()
    assert k["vendor"] == "Google" and k["added"]


def test_epss_loader_skips_junk(tmp_path):
    p = tmp_path / "e.csv.gz"
    p.write_bytes(gzip.compress(b"#model_version:v1,score_date:2026-01-01\ncve,epss,percentile\n"
                                b"CVE-2020-0001,0.5,0.9\nnot-a-cve,0.5,0.9\nCVE-2020-0002,7,0.9\nCVE-2020-0003,x,y\n"))
    conn = store.connect(tmp_path / "c.db")
    assert feeds.load_epss(conn, p) == (1, "model_version:v1,score_date:2026-01-01")


# ---- states ------------------------------------------------------------------------

@pytest.mark.parametrize("status,fixed,urgency,nodsa,installed,state", [
    ("resolved", "1.2-1", "medium", None, "1.1-1", "fix"),
    ("resolved", "1.2-1", "medium", None, "1.2-1", None),          # already fixed
    ("resolved", "1.2-1", "medium", None, "1.2-1+b1", None),
    ("resolved", "1.2-1", "unimportant", None, "1.1-1", "fix"),     # a vendor rating, applied by cve/priority.py, not a state
    ("resolved", "1.2-1", "not yet assigned", "Minor issue", "1.1-1", "minor"),
    ("resolved", "0", "unimportant", None, "1.1-1", None),
    ("resolved", "1.0-", "low", None, "1.1-1", None),               # malformed version: skipped
    ("open", None, "not yet assigned", None, "1.1-1", "nofix"),
    ("open", None, "unimportant", None, "1.1-1", "nofix"),
    ("open", None, "end-of-life", None, "1.1-1", "minor"),
    ("open", None, "not yet assigned", "ignored", "1.1-1", "minor"),
    ("undetermined", None, "not yet assigned", None, "1.1-1", "undetermined"),
])
def test_classify(status, fixed, urgency, nodsa, installed, state):
    assert match.classify(status, fixed, urgency, nodsa, installed) == state


def test_release_of():
    assert match.release_of(inventory([])) == "trixie"
    assert match.release_of(inventory([], os_id="raspbian")) == "trixie"
    assert match.release_of(inventory([], os_id="ubuntu", codename="noble")) is None      # Ubuntu has its own matcher (cve/ubuntu.py)
    assert match.release_of({**inventory([]), "backend": "dnf"}) is None


def states(conn, host, src):
    return {r["cve"]: r["state"] for r in conn.execute("SELECT * FROM match WHERE host = ? AND source = ?", (host, src))}


def test_match_host_states(cvedb):
    i = inventory([["brotli", "1.0.9-2", []], ["c-ares", "1.10.0-1", ["libc-ares2"]], ["libxml2", "2.12.0", []],
                   ["nodejs", "26.13.0-1", []]])
    r = match.match_host(cvedb, "h", i, "g")
    assert r["packages"] == 4
    assert states(cvedb, "h", "brotli") == {"CVE-2026-111497": "fix"}
    assert states(cvedb, "h", "c-ares") == {"CVE-2016-5180": "fix", "CVE-2017-1000381": "fix", "CVE-2023-31124": "fix"}
    # Debian's urgency "unimportant" is kept as the vendor's rating (the prioritiser lowers it); nodsa stays "minor".
    assert states(cvedb, "h", "libxml2") == {"CVE-2026-11979": "nofix", "CVE-2026-6653": "minor", "CVE-2026-74860": "nofix"}
    assert states(cvedb, "h", "nodejs") == {"CVE-2026-111497": "nofix"}


def test_running_kernel_is_listed_under_linux():
    text = "".join(f"ii \t{s}\t{sv}\t{b}\t{bv}\n" for s, sv, b, bv in [
        ("linux-signed-amd64", "6.1.158+1", "linux-image-6.1.0-41-cloud-amd64", "6.1.158-1"),
        ("linux-signed-amd64", "6.1.164+1", "linux-image-6.1.0-44-cloud-amd64", "6.1.164-1"),
        ("linux", "6.1.164-1", "linux-libc-dev", "6.1.164-1"),
        ("c-ares", "1.18.1-3", "libc-ares2", "1.18.1-3")])
    rows = inv.parse_dpkg_query(text, "6.1.0-41-cloud-amd64")
    assert ["linux", "6.1.158-1", ["linux-image-6.1.0-41-cloud-amd64"]] in rows
    assert ["linux", "6.1.164-1", ["linux-libc-dev"]] in rows
    assert not any(r[0].startswith("linux-signed") for r in rows)
    # Another kernel running (a container on its host's kernel): no image listed.
    assert not any("linux-image" in b for r in inv.parse_dpkg_query(text, "6.18.38-Unraid") for b in r[2])


def test_kernel_sources_need_a_kernel_image():
    # A container on another kernel can have the headers without the kernel.
    assert not match._kernel_installed("linux", ["linux-libc-dev"])
    assert match._kernel_installed("linux", ["linux-image-6.12.115-amd64", "linux-libc-dev"])
    assert match._kernel_installed("linux-signed-amd64", ["linux-image-6.1.0-56-cloud-amd64"])
    assert not match._kernel_installed("linux-signed-amd64", [])
    assert match._kernel_installed("c-ares", [])


def test_match_is_replaced_not_added(cvedb):
    match.match_host(cvedb, "h", inventory([["c-ares", "1.10.0-1", []]]), "g")
    match.match_host(cvedb, "h", inventory([["c-ares", "1.19.1-2", []]]), "g")  # now fixed everywhere
    assert states(cvedb, "h", "c-ares") == {}


def test_unmatched_release_says_why(cvedb):
    r = match.match_host(cvedb, "h", inventory([["c-ares", "1.0", []]], os_id="ubuntu", codename="noble"), "g")
    assert r["cves"] == 0 and "Debian" in r["note"]


# ---- findings ------------------------------------------------------------------------

def findings_for(conn, sources, auto=0.04, pending=frozenset(), exposed=False):
    match.match_host(conn, "h", inventory(sources), "g")
    bins = {s: b for s, _v, b in sources}
    return {f.key: f for f in match.package_findings(match.host_cves(conn, "h", ("fix", "nofix")), bins, set(pending),
                                                     exposure.Exposure(exposed, "test exposure"), auto)}


def rate_ssvc(conn, cve, exploitation, automatable, impact):
    conn.execute("INSERT OR REPLACE INTO cve_record (cve, status, fetched_at, tried_at, kev, exploitation, automatable, impact) "
                 "VALUES (?, 'ok', 1, 1, 0, ?, ?, ?)", (cve, exploitation, automatable, impact))


def test_kev_without_a_cisa_rating_is_estimated_and_labelled(cvedb):
    # KEV, EPSS 83% (so Automatable is estimated "yes"), Technical impact assumed partial: row 10 for a host that is not exposed.
    f = findings_for(cvedb, [["brotli", "1.0.9-2", ["libbrotli1"]]])["brotli"]
    assert f.severity == "high"
    assert f.title == "brotli: CVE-2026-111497 is being exploited (CISA KEV); fix within 14 days"
    assert "Fix within 14 days (CISA BOD 26-04 timeline)" in f.detail and "CISA BOD 26-04 Table 1 row 10: 14 days" in f.detail
    assert "1.1.0-2+deb13u1" in f.detail and "EPSS 82.6% (100th)" in f.detail
    howto = f.howto.split("\n")
    assert "Publicly exposed: no: test exposure" in howto and "In CISA's KEV catalog: yes" in howto
    assert any("Automatable by an adversary: yes (estimated by DaemonSight, from the EPSS probability)" in x for x in howto)
    assert any("Technical impact: partial (estimated by DaemonSight" in x for x in howto)
    assert f.fix == "sudo apt update\nsudo apt upgrade"   # not offered yet: refresh first
    assert f.link == "/vulnerabilities#cve-brotli"
    assert "apt isn't offering it yet" in f.detail            # not among the pending updates
    f2 = findings_for(cvedb, [["brotli", "1.0.9-2", ["libbrotli1"]]], pending={"libbrotli1"})["brotli"]
    assert "apt lists this update" in f2.detail and f2.fix == "sudo apt upgrade"


def test_cisa_rating_replaces_the_estimate_and_exposure_moves_the_row(cvedb):
    rate_ssvc(cvedb, "CVE-2026-111497", "active", "no", "total")
    src = [["brotli", "1.0.9-2", ["libbrotli1"]]]
    f = findings_for(cvedb, src)["brotli"]                    # not exposed, KEV, not automatable, total: row 11
    assert (f.severity, "row 11: 14 days" in f.detail) == ("high", True)
    assert not any("estimated" in x for x in f.howto.split("\n"))
    assert "Automatable by an adversary: no (CISA)" in f.howto and "Technical impact: total (CISA)" in f.howto
    e = findings_for(cvedb, src, exposed=True)["brotli"]      # exposed, KEV, not automatable, total: row 3, 3 days and triage
    assert e.severity == "critical" and "row 3: 3 days and forensic triage" in e.detail
    assert e.title.endswith("fix within 3 days")
    assert "This row also asks for forensic triage" in e.howto and "Preserve evidence before patching" in e.howto
    assert "forensic triage" not in f.howto
    # The basis does not carry the severity: an accepted finding stays accepted when the exposure changes.
    assert e.basis == f.basis


def test_a_fix_is_low_medium_or_high_by_the_table_not_by_cvss(cvedb):
    src = [["c-ares", "1.10.0-1", []]]
    # CVE-2016-5180 has EPSS 8.7%. At the default 0.04 it is estimated automatable: N/N/Y/partial, row 14, 60 days.
    f = findings_for(cvedb, src)["c-ares"]
    assert (f.severity, f.title) == ("medium", "c-ares: 3 CVEs fixed in an update; fix within 60 days")
    assert "CVE-2016-5180" in f.detail and "fixed in 1.19.1-2" in f.detail  # the newest fixed version
    # Raise the estimate threshold above it: N/N/N, "fix on system upgrade", low.
    f = findings_for(cvedb, src, auto=0.1)["c-ares"]
    assert f.severity == "low" and f.title.endswith("fix at the next upgrade") and f.detail.startswith("Fix at the next upgrade, set by")
    # Exposed: Y/N/N/partial is row 8, 60 days.
    assert findings_for(cvedb, src, auto=0.1, exposed=True)["c-ares"].severity == "medium"


def test_the_vendor_rating_lowers_only_an_unexposed_cve_that_is_not_in_the_kev(cvedb):
    match.match_host(cvedb, "h", inventory([["c-ares", "1.10.0-1", []], ["nodejs", "26.13.0-1", []]]), "g")
    cves = {c["cve"] + c["source"]: c for c in match.host_cves(cvedb, "h", ("fix", "nofix"))}
    unimportant = cves["CVE-2023-31124c-ares"]
    assert unimportant["urgency"] == "unimportant" and not unimportant["kev"]
    r = priority.rate(unimportant, False, 0.04)
    assert (r.vendor_lowered, r.days, r.severity) == (True, None, "low")
    assert priority.rate(unimportant, True, 0.04).vendor_lowered is False      # exposed: the table decides
    kev = cves["CVE-2026-111497nodejs"]
    assert kev["urgency"] == "unimportant" and kev["kev"]
    assert priority.rate(kev, False, 0.04).vendor_lowered is False             # in the KEV: the table decides
    assert priority.rate({**unimportant, "urgency": "low"}, False, 0.04).vendor_lowered is False   # another rating
    assert priority.rate({**unimportant, "urgency": "negligible"}, False, 0.04).vendor_lowered is True   # Ubuntu's word


def test_unfixed_and_minor_raise_nothing_unless_exploited(cvedb):
    got = findings_for(cvedb, [["libxml2", "2.12.0", []], ["nodejs", "26.13.0-1", []], ["openssh", "10.0", []]])
    # libxml2: no fix yet, or minor (nodsa): nothing. nodejs and openssh are in the KEV with no fix: the owner may mitigate.
    assert set(got) == {"nodejs", "openssh"}
    assert got["openssh"].title == "openssh: CVE-2026-123158 is being exploited (CISA KEV); fix within 14 days"
    assert "Debian has no fix yet" in got["openssh"].detail


def test_up_to_date_package_has_nothing(cvedb):
    assert findings_for(cvedb, [["c-ares", "1.19.1-2", []], ["brotli", "1.1.0-2+deb13u1", []]]) == {}


def test_stale_finding():
    assert match.stale_finding([], {}) is None
    f = match.stale_finding([("epss", 4 * DAY + 5), ("kev", None)], {"epss": "EPSS", "kev": "KEV"})
    assert (f.rule, f.severity, f.link) == ("cve.feed_stale", "low", "/vulnerabilities#feeds")
    assert "EPSS (4 days)" in f.detail and "KEV (never fetched)" in f.detail


def test_stale_feeds_use_last_success(tmp_path):
    conn = store.connect(tmp_path / "c.db")
    now = 100 * DAY
    for name, first, ok in (("a", now - 10 * DAY, now - 4 * DAY), ("b", now - 10 * DAY, now - DAY),
                            ("c", now - 5 * DAY, None), ("d", now - DAY, None)):
        conn.execute("INSERT INTO feed (name, url, first_try, ok_at) VALUES (?, 'u', ?, ?)", (name, first, ok))
    assert [n for n, _ in feeds.stale_feeds(conn, now)] == ["a", "c"]


def test_feed_is_due(tmp_path):
    conn = store.connect(tmp_path / "c.db")
    row = lambda **kw: {"checked_at": 1000.0, "status": "ok", **kw}
    assert feeds.is_due({"checked_at": None, "status": None}, 0, 24)
    assert not feeds.is_due(row(), 1000 + 23 * 3600, 24)
    assert feeds.is_due(row(), 1000 + 24 * 3600, 24)
    assert feeds.is_due(row(status="error"), 1000 + 3600, 24)      # retry an hour after an error
    assert not feeds.is_due(row(status="error"), 1000 + 1800, 24)


# ---- download ---------------------------------------------------------------------------

def serve(tmp_path, calls=None, etag='"v1"', override=None):
    """A fake of the three feeds, of the OPNsense changelog tarball (the repository's archive), of Alpine's secdb (main.json and community.json for v3.17 and v3.23 only; any other
    release is a 404, as secdb answers for a release it has no directory for) and of Canonical's OVAL (the noble and focal
    files only: trimmed copies; any other release is a 404). Conditional requests get 304 when the etag matches."""
    files = {"security-tracker.debian.org": (tracker_gz(tmp_path), True), "epss.empiricalsecurity.com": (epss_gz(tmp_path), False),
             "www.cisa.gov": (kev_gz(tmp_path), True)}

    def handler(request: httpx.Request) -> httpx.Response:
        records = fake_cve_services.handler(request)    # CISA's SSVC ratings: not one of the feeds `calls` counts
        if records is not None:
            return records
        if calls is not None:
            calls.append((request.url.host, dict(request.headers)))
        assert request.headers["user-agent"] == feeds.USER_AGENT and request.headers["user-agent"].startswith("DaemonSight/")
        if request.url.host in (override or {}):
            return override[request.url.host](request)
        adv = fake_advisories.handler(request)         # FreeBSD's advisory files and GitHub's repository advisory API
        if adv is not None:
            return adv
        if request.url.host == feeds.ALPINE_HOST:
            m = re.fullmatch(r"/(v3\.(?:17|23))/(main|community)\.json", request.url.path)
            if not m:
                return httpx.Response(404)
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304)
            body = (FIX / f"alpine-{m.group(2)}.json").read_text().replace("RELEASE", m.group(1))
            return httpx.Response(200, content=body.encode(), headers={"etag": etag, "last-modified": "Tue, 24 Nov 2026 01:45:59 GMT"})
        if request.url.host == feeds.ubuntu.OVAL_HOST:      # Canonical's OVAL: one bz2 file per release
            m = re.fullmatch(r"/oval/com\.ubuntu\.(noble|focal)\.cve\.oval\.xml\.bz2", request.url.path)
            if not m:
                return httpx.Response(404)
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304)
            return httpx.Response(200, content=bz2.compress((FIX / f"ubuntu-{m.group(1)}.oval.xml").read_bytes()),
                                  headers={"etag": etag, "last-modified": "Thu, 19 Nov 2026 19:37:14 GMT"})
        if request.url.host == feeds.OPNSENSE_HOST:     # the OPNsense changelog repository's tarball
            if request.url.path != fake_changelog.PATH:
                return httpx.Response(404)
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304)
            return httpx.Response(200, content=fake_changelog.tarball_bytes(),
                                  headers={"etag": etag, "last-modified": "Tue, 24 Nov 2026 10:56:27 GMT"})
        if request.headers.get("if-none-match") == etag:
            return httpx.Response(304)
        path, decode = files[request.url.host]
        data = path.read_bytes()
        headers = {"etag": etag, "last-modified": "Tue, 17 Nov 2026 13:30:41 GMT"}
        if decode:  # served as gzip content-encoding: httpx hands back the decoded JSON
            return httpx.Response(200, content=data, headers={**headers, "content-encoding": "gzip"})
        return httpx.Response(200, content=data, headers=headers)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_download_is_conditional(tmp_path):
    async def go():
        calls = []
        client = serve(tmp_path, calls)
        conn = store.connect(tmp_path / "c.db")
        f = feeds.FEEDS["kev"]
        row = feeds.feed_row(conn, f)
        dest = tmp_path / "out" / "kev.json.gz"
        info = await feeds.download(f, row, dest, client)
        assert info["etag"] == '"v1"' and dest.exists() and "if-none-match" not in calls[0][1]
        assert json.loads(gzip.decompress(dest.read_bytes()))["count"] == 2
        feeds._record(conn, f, **{k: info[k] for k in ("etag", "last_modified")})
        again = await feeds.download(f, feeds.feed_row(conn, f), dest, client)
        assert again is None  # 304
        assert calls[1][1]["if-none-match"] == '"v1"' and calls[1][1]["if-modified-since"].startswith("Tue, 17 Nov")
    asyncio.run(go())


def test_download_refuses_redirect_to_another_host_and_big_files(tmp_path):
    async def go():
        conn = store.connect(tmp_path / "c.db")
        f = feeds.FEEDS["epss"]
        row = feeds.feed_row(conn, f)
        bad = serve(tmp_path, override={"epss.empiricalsecurity.com": lambda r: httpx.Response(
            302, headers={"location": "https://evil.example/x.csv.gz"}) if r.url.host == "epss.empiricalsecurity.com" else None})

        def hop(request):
            if request.url.host == "epss.empiricalsecurity.com":
                return httpx.Response(302, headers={"location": "https://evil.example/x.csv.gz"})
            return httpx.Response(200, content=b"x")
        client = httpx.AsyncClient(transport=httpx.MockTransport(hop), follow_redirects=True)
        with pytest.raises(feeds.FetchError, match="not a source"):
            await feeds.download(f, row, tmp_path / "e.gz", client)
        assert not (tmp_path / "e.gz").exists()
        big = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"\x1f\x8b" + b"0" * 5000)))
        small = feeds.Feed("t", "t", "https://www.cisa.gov/x", ("www.cisa.gov",), 1000, True, "", "")
        with pytest.raises(feeds.FetchError, match="larger"):
            await feeds.download(small, row, tmp_path / "t.gz", big)
        with pytest.raises(feeds.FetchError, match="HTTP 500"):
            await feeds.download(f, row, tmp_path / "e.gz", httpx.AsyncClient(
                transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    asyncio.run(go())


# ---- the chore ------------------------------------------------------------------------------

def put_inventory(conn, host, sources, taken_at=None, **kw):
    data = {k: v for k, v in inventory(sources, **kw).items() if k != "taken_at"}
    db.put_snapshot(conn, host, "inventory", taken_at or time.time(), True, None, data)


def test_chore_end_to_end(tmp_path):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    state = db.connect_writer(cfg.db_path)
    state.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('web1', 'x', 0)")
    put_inventory(state, "web1", [["brotli", "1.0.9-2", ["libbrotli1"]], ["c-ares", "1.19.1-2", []]])
    calls = []
    fake_cve_services.CALLS.clear()

    async def go():
        chore = run.Chore(cfg, state, serve(tmp_path, calls))
        now = time.time()
        await chore.run_once(now)
        open_ = {(r["rule"], r["key"]): r for r in db.open_findings(state, "web1")}
        assert ("cve.package", "brotli") in open_
        assert open_[("cve.package", "brotli")]["severity"] == "high"
        assert not any(k[0] == "cve.feed_stale" for k in open_)
        assert len(calls) == 3
        assert "CVE-2026-111497" in fake_cve_services.CALLS         # CISA's rating of the matched CVE was asked for
        events = [r["title"] for r in db.recent_events(state, "web1", 10)]
        assert any("brotli" in t for t in events)
        # An hour later nothing is due; nothing is asked again.
        await chore.run_once(now + 3600)
        assert len(calls) == 3
        # A day later each feed gets a conditional request and answers 304.
        await chore.run_once(now + DAY + 10)
        assert len(calls) == 6 and all("if-none-match" in h for _, h in calls[3:])
        assert ("cve.package", "brotli") in {(r["rule"], r["key"]) for r in db.open_findings(state, "web1")}
        # The host upgrades the package: the finding resolves.
        put_inventory(state, "web1", [["brotli", "1.1.0-2+deb13u1", ["libbrotli1"]]], taken_at=now + 2 * DAY)
        await chore.run_once(now + DAY + 20)
        assert not [r for r in db.open_findings(state, "web1") if r["rule"] == "cve.package"]
        # Feeds unreachable for over 3 days: a low cve.feed_stale finding, on top of the data it still has.
        down = serve(tmp_path, override={h: (lambda r: httpx.Response(503)) for h in
                                         ("security-tracker.debian.org", "epss.empiricalsecurity.com", "www.cisa.gov")})
        chore.client = down
        await chore.run_once(now + 5 * DAY)
        stale = [r for r in db.open_findings(state, "web1") if r["rule"] == "cve.feed_stale"]
        assert len(stale) == 1 and stale[0]["severity"] == "low"
        # Back again: it clears.
        chore.client = serve(tmp_path)
        await chore.run_once(now + 7 * DAY)
        assert not [r for r in db.open_findings(state, "web1") if r["rule"] == "cve.feed_stale"]
    asyncio.run(go())
    state.close()


def test_a_host_finding_stays_open_while_its_matches_are_not_made(tmp_path):
    """A hub restart can leave a host with no `matched` row for a pass: that is not "no CVEs", so its findings stay as they are."""
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    state = db.connect_writer(cfg.db_path)
    state.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('web1', 'x', 0)")
    put_inventory(state, "web1", [["brotli", "1.0.9-2", ["libbrotli1"]]])

    async def go():
        chore = run.Chore(cfg, state, serve(tmp_path))
        now = time.time()
        await chore.run_once(now)
        before = {(r["rule"], r["key"]): dict(r) for r in db.open_findings(state, "web1") if r["rule"] == "cve.package"}
        assert ("cve.package", "brotli") in before
        conn = store.connect(cfg.cve_db_path)
        conn.execute("DELETE FROM match")
        conn.execute("DELETE FROM matched")
        conn.close()
        chore.dirty = True
        await chore._findings({"web1": _inventories_of(state)["web1"]}, now + 5)
        after = {(r["rule"], r["key"]): dict(r) for r in db.open_findings(state, "web1") if r["rule"] == "cve.package"}
        assert after.keys() == before.keys() and after[("cve.package", "brotli")]["basis"] == before[("cve.package", "brotli")]["basis"]
        # the next pass matches again and the finding is still there
        await chore.run_once(now + 10)
        assert ("cve.package", "brotli") in {(r["rule"], r["key"]) for r in db.open_findings(state, "web1")}
        # a host that was matched and has nothing fixable resolves
        put_inventory(state, "web1", [["brotli", "1.1.0-2+deb13u1", ["libbrotli1"]]], taken_at=now + 2 * DAY)
        await chore.run_once(now + 20)
        assert not [r for r in db.open_findings(state, "web1") if r["rule"] == "cve.package"]
    asyncio.run(go())
    state.close()


def _inventories_of(state):
    return run._inventories(state)


def test_a_host_on_a_new_release_reparses_the_saved_file(tmp_path):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    state = db.connect_writer(cfg.db_path)
    put_inventory(state, "a", [["c-ares", "1.10.0-1", []]])

    async def go():
        chore = run.Chore(cfg, state, serve(tmp_path))
        await chore.run_once(1000.0)
        conn = store.connect(cfg.cve_db_path)
        assert conn.execute("SELECT COUNT(*) FROM deb WHERE release = 'bookworm'").fetchone()[0] == 0
        put_inventory(state, "b", [["c-ares", "1.10.0-1", []]], codename="bookworm")
        await chore.run_once(1100.0)  # nothing downloaded again, the saved file is read again
        assert conn.execute("SELECT COUNT(*) FROM deb WHERE release = 'bookworm'").fetchone()[0] > 0
        conn.close()
    asyncio.run(go())
    state.close()


def test_turning_cve_off_closes_its_findings(tmp_path):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    state = db.connect_writer(cfg.db_path)
    state.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('h', 'x', 0)")
    from daemonsight.findings import Finding
    db.set_finding(state, "h", 1.0, Finding("cve.package", "x", "medium", "t", "d", "/vulnerabilities"), rule="cve.package", key="x")
    db.set_finding(state, "h", 1.0, Finding("pkg.updates", "updates", "low", "t", "d", "/"), rule="pkg.updates", key="updates")
    run.clear_findings(state, 2.0)
    assert [r["rule"] for r in db.open_findings(state, "h")] == ["pkg.updates"]


# ---- upload shape ------------------------------------------------------------------------------

def test_collector_sends_inventory_as_its_own_field(tmp_path):
    cfg = Config(host_id="h", data_dir=str(tmp_path))
    conn = db.connect_writer(cfg.db_path)
    data = inv.inventory_apt("ii \tbrotli\t1.0.9-2\tlibbrotli1\t1.0.9-2+b1\n", {"ID": "debian", "VERSION_CODENAME": "trixie", "VERSION_ID": "13"})
    db.put_snapshot(conn, "h", "inventory", 5.0, True, None, data)
    db.put_snapshot(conn, "h", "system", 5.0, True, None, {"cpu": {}, "memory": {}})
    payload, cursors, _ = upload.build(conn, cfg, (1, 2), 30)
    assert [s["source"] for s in payload["snapshots"]] == ["system"]  # an old hub would refuse an unknown source
    assert payload["inventory"]["sources"] == [["brotli", "1.0.9-2", ["libbrotli1"]]]
    assert payload["inventory"]["codename"] == "trixie" and payload["inventory"]["v"] == 1
    db.set_meta(conn, cursors)
    again, _, _ = upload.build(conn, cfg, (1, 2), 30)
    assert "inventory" not in again                              # unchanged: not sent again
    db.set_meta(conn, {"upload.inv_at": time.time() - 2 * DAY})
    assert "inventory" in upload.build(conn, cfg, (1, 2), 30)[0]  # but once a day


def test_parse_dpkg_query():
    text = ("ii \topenssl\t3.5.7-1\tlibssl3t64\t3.5.7-1+b1\nii \topenssl\t3.5.7-1\topenssl\t3.5.7-1+b1\n"
            "rc \told\t1.0\told\t1.0\nii \tacl\t2.3.2-2\tacl\t2.3.2-2+b1\nii \tacl\t2.3.2-2\tlibacl1\t2.3.2-2+b1\n"
            "hi \theld\t2.0\theld\t2.0\njunk line\n")
    # One row per source and version; the binary list leaves out the source's own name.
    assert inv.parse_dpkg_query(text) == [["acl", "2.3.2-2", ["libacl1"]], ["held", "2.0", []],
                                          ["openssl", "3.5.7-1", ["libssl3t64"]]]


DNF = Path(__file__).parent / "fixtures" / "dnf"


def dnf_inventory():
    return inv.inventory_dnf((DNF / "advisory-list.json").read_text(), (DNF / "advisory-info.json").read_text(),
                             {"ID": "fedora", "VERSION_ID": "44"})


def test_parse_fedora_advisories_from_real_dnf_output():
    i = dnf_inventory()
    # CVE ids come from the description and the reference titles, since the references are
    # bugzilla ones. Package names come from the list (installed ones), not from the info's
    # per-architecture collections.
    assert i["backend"] == "dnf" and i["os_id"] == "fedora" and i["count"] == 4
    by_id = {a["id"]: a for a in i["advisories"]}
    assert by_id["FEDORA-2026-d657495ea3"] == {
        "id": "FEDORA-2026-d657495ea3", "severity": "moderate",
        "cves": ["CVE-2026-92822", "CVE-2026-92823", "CVE-2026-92824"], "packages": ["libmodulemd"]}
    assert by_id["FEDORA-2026-450395b11f"]["packages"] == ["pcre2", "pcre2-syntax"]
    assert len(by_id["FEDORA-2026-450395b11f"]["cves"]) == 8
    assert by_id["FEDORA-2026-e7379f9f3f"]["packages"] == ["dnf5", "dnf5-plugins", "libdnf5", "libdnf5-cli"]
    assert i["hash"] == dnf_inventory()["hash"]
    assert inv.parse_dnf_advisories("", "") == []
    with pytest.raises(ValueError):
        inv.parse_dnf_advisories('{"a": 1}', "[]")
    assert inv.rpm_name("pcre2-syntax-10.49-1.fc44.noarch") == "pcre2-syntax"
    assert inv.rpm_name("libdnf5-cli-5.4.8.0-2.fc44.x86_64") == "libdnf5-cli"


def test_fedora_advisories_become_fixes_ranked_with_epss_and_kev(cvedb):
    i = {k: v for k, v in dnf_inventory().items() if k not in ("available", "count")}
    i["taken_at"] = time.time()
    r = match.set_advisories(cvedb, "fed", i, "g")
    # 3 CVEs x 1 package, 8 x 2, 1 x 1 (tpm2-tss), 1 x 4
    assert r["cves"] == 3 + 16 + 1 + 4
    rows = match.host_cves(cvedb, "fed", ("fix", "nofix"))
    assert {c["state"] for c in rows} == {"fix"}
    assert {"CVE-2026-92822", "CVE-2026-123177", "CVE-2026-86145"} <= {c["cve"] for c in rows}
    fs = {f.key: f for f in match.package_findings(rows, {}, set(), exposure.Exposure(False, "test"), 0.04, "dnf")}
    f = fs["libmodulemd"]
    assert (f.rule, f.severity) == ("cve.package", "low") and "libmodulemd" == f.key   # not exposed, not in KEV: fix at the next upgrade
    assert f.fix == "sudo dnf upgrade --refresh" and "apt" not in f.detail and "apt" not in f.fix
    assert {"pcre2", "pcre2-syntax", "dnf5", "libdnf5"} <= set(fs)


def test_hub_accepts_a_fedora_inventory(hub_cfg, token):
    i = {k: v for k, v in dnf_inventory().items() if k not in ("available", "count")}
    i.update(v=1, taken_at=time.time())
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert post(c, body(inventory=i), token).status_code == 200
    conn = db.connect_writer(hub_cfg.db_path)
    snap = db.get_snapshots(conn, "testhost")["inventory"]
    assert {a["id"] for a in snap.data["advisories"]} >= {"FEDORA-2026-d657495ea3", "FEDORA-2026-efb1f85550"}


def test_new_hub_stores_inventory_and_survives_a_bad_one(hub_cfg, token):
    c = TestClient(create_app(hub_cfg))
    good = {"v": 1, "taken_at": 5.0, "backend": "apt", "hash": "ab", "os_id": "debian", "codename": "trixie",
            "sources": [["brotli", "1.0.9-2", ["libbrotli1"]]], "future_field": [1, 2]}
    assert post(c, body(inventory=good), token).status_code == 200
    conn = db.connect_writer(hub_cfg.db_path)
    snap = db.get_snapshot(conn, "testhost", "inventory")
    assert snap.data["sources"] == [["brotli", "1.0.9-2", ["libbrotli1"]]] and "future_field" not in snap.data
    # An inventory the hub can't read is dropped; the rest of the upload is accepted.
    for bad in ({**good, "v": 2}, {**good, "sources": [["x" * 500, "1", []]]}, "text", {**good, "backend": "pacman"},
                {**good, "codename": "../etc"}):
        r = post(c, body(inventory=bad, snapshots=[{"source": "system", "taken_at": 1.0, "ok": True,
                                                    "data": {"cpu": {}, "memory": {}}}]), token)
        assert r.status_code == 200, bad
    assert db.get_snapshot(conn, "testhost", "inventory").taken_at == 5.0  # still the good one


def test_old_hub_shape_ignores_the_new_field():
    """An older hub's Upload has extra="ignore" at the top level, which is what made the
    inventory field safe; this pins that setting, and that an unknown source would not be."""
    assert hub.Upload.model_config["extra"] == "ignore"
    assert "inventory" not in hub.SOURCES
    with pytest.raises(Exception):
        hub.SnapshotIn(source="inventory", taken_at=1.0, ok=True)  # the 422 the packages source once caused


def test_old_collector_upload_is_still_accepted(hub_cfg, token):
    c = TestClient(create_app(hub_cfg))
    assert post(c, body(), token).status_code == 200  # no inventory field at all


def test_collectors_cannot_send_cve_findings(hub_cfg, token):
    c = TestClient(create_app(hub_cfg))
    f = {"rule": "cve.package", "key": "x", "severity": "high", "title": "t", "detail": "d"}
    assert post(c, body(findings=[f]), token).status_code == 422


def test_an_upload_does_not_close_the_hubs_cve_findings(hub_cfg, token):
    from daemonsight.findings import Finding
    c = TestClient(create_app(hub_cfg))
    assert post(c, body(seq=1), token).status_code == 200
    conn = db.connect_writer(hub_cfg.db_path)
    db.set_finding(conn, "testhost", 1.0, Finding("cve.package", "x", "medium", "t", "d", "/"), rule="cve.package", key="x")
    assert post(c, body(seq=2), token).status_code == 200
    assert [r["rule"] for r in db.open_findings(conn, "testhost")] == ["cve.package"]


# ---- the page ------------------------------------------------------------------------------------

def page_client(hub_cfg, token, enabled=True):
    hub_cfg.cve.enabled = enabled  # the app is not started with its lifespan here, so nothing is downloaded
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD}).status_code == 303
    return c


def seed_hub(hub_cfg, token, tmp_path, hostile=False):
    c = page_client(hub_cfg, token)
    sources = [["brotli", "1.0.9-2", ["libbrotli1"]], ["c-ares", "1.10.0-1", ["libc-ares2"]], ["libxml2", "2.12.0", []],
               ["nodejs", "26.13.0-1", []]]
    good = inventory(sources, h="ab")
    assert post(c, body(inventory=good), token).status_code == 200
    cdb = store.connect(hub_cfg.cve_db_path)
    src = tracker_gz(tmp_path)
    if hostile:
        d = json.loads((FIX / "tracker-sample.json").read_text())
        d["brotli"]["CVE-2026-111497"]["description"] = '<script>alert(1)</script> & "quotes"'
        src = tmp_path / "hostile.json.gz"
        src.write_bytes(gzip.compress(json.dumps(d).encode()))
    feeds.load_debian(cdb, src, {"trixie"})
    feeds.load_epss(cdb, epss_gz(tmp_path))
    feeds.load_kev(cdb, kev_gz(tmp_path))
    for name, f in feeds.FEEDS.items():
        feeds.feed_row(cdb, f)
        feeds._record(cdb, f, checked_at=time.time(), ok_at=time.time(), changed_at=time.time(), status="ok", rows=3,
                      size=1000, note="model v1")
    conn = db.connect_writer(hub_cfg.db_path)
    snap = db.get_snapshot(conn, "testhost", "inventory")
    match.match_host(cdb, "testhost", {**snap.data, "taken_at": snap.taken_at}, "g")
    cdb.close()
    return c


def test_vulnerabilities_page(hub_cfg, token, tmp_path):
    c = seed_hub(hub_cfg, token, tmp_path)
    r = c.get("/h/testhost/vulnerabilities")
    assert r.status_code == 200
    html = r.text
    assert "Vulnerabilities" in html and 'href="/h/testhost/vulnerabilities"' in html
    assert 'id="cve-brotli"' in html and 'id="cve-c-ares"' in html
    assert "https://security-tracker.debian.org/tracker/CVE-2026-111497" in html
    assert ">KEV<" in html and "82.6% (100th)" in html
    # The deadline: a column, the table's name and the host's exposure, with CVSS only as information.
    assert "<th data-sort=\"num\">Fix within</th>" in html and "14 days" in html and "CISA BOD 26-04" in html
    assert "This host counts as" in html and "sets nothing" in html
    assert 'id="feeds"' in html and "EPSS scores (FIRST)" in html and "CC0 1.0" in html
    # Every table cell carries a label for the phone card layout.
    rows = re.findall(r"<tr data-row.*?</tr>", html, re.S)
    assert rows
    for row in rows:
        assert row.count("<td") == row.count("<td") and all("data-label=" in t for t in re.findall(r"<td[^>]*>", row))
    # The page's own links resolve: the finding link lands on a row id.
    assert re.search(r'<tr data-row id="cve-brotli">', html)
    assert c.get("/h/testhost/partials/vulnerabilities").status_code == 200


def test_the_data_feeds_card_lists_alpine_secdb_files_only_when_images_need_them(hub_cfg, token, tmp_path):
    c = seed_hub(hub_cfg, token, tmp_path)
    assert "Alpine security database" not in c.get("/h/testhost/vulnerabilities").text
    cdb = store.connect(hub_cfg.cve_db_path)
    for name, status in (("v3.23", "ok"), ("v3.9", "absent")):
        for f in feeds.alpine_feeds(name):
            feeds.feed_row(cdb, f)
            feeds._record(cdb, f, checked_at=time.time(), ok_at=time.time(), changed_at=time.time(), status=status, rows=3, size=1000)
    cdb.close()
    html = c.get("/h/testhost/vulnerabilities").text
    assert "Alpine security database v3.23 main" in html and "Alpine security database v3.9 community" in html
    assert "Not in Alpine&#39;s security database" in html and "https://secdb.alpinelinux.org/v3.23/main.json" in html
    assert "downloaded only for the Alpine releases that container images run" in html and "Attribution-ShareAlike 4.0" in html


def test_page_escapes_hostile_feed_text(hub_cfg, token, tmp_path):
    c = seed_hub(hub_cfg, token, tmp_path, hostile=True)
    html = c.get("/h/testhost/vulnerabilities").text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_page_without_inventory_or_data(hub_cfg, token, tmp_path):
    c = page_client(hub_cfg, token)
    assert post(c, body(), token).status_code == 200
    html = c.get("/h/testhost/vulnerabilities").text
    assert "sent its package list" in html
    # Nothing downloaded yet: the page still renders.
    post(c, body(inventory=inventory([["c-ares", "1.0", []]], h="ab12")), token)
    assert "No vulnerability data has been downloaded yet" in c.get("/h/testhost/vulnerabilities").text


def test_page_for_an_unmatched_release_and_a_standalone_host(hub_cfg, token, tmp_path, seeded):
    c = page_client(hub_cfg, token)
    post(c, body(inventory=inventory([["c-ares", "1.0", []]], os_id="ubuntu", codename="noble")), token)
    store.connect(hub_cfg.cve_db_path).close()
    # An Ubuntu host with no codename in the inventory, and a derivative with its own id, are not matched.
    post(c, body(inventory=inventory([["c-ares", "1.0", []]], os_id="linuxmint", codename="wilma")), token)
    assert "derivative with its own name" in c.get("/h/testhost/vulnerabilities").text
    # A host with no hub: the page explains, and the nav has no such item.
    solo = TestClient(create_app(seeded), follow_redirects=False)
    solo.post("/login", data={"password": PASSWORD})
    page = solo.get("/vulnerabilities")
    assert page.status_code == 200 and "runs on a hub" in page.text
    assert 'href="/vulnerabilities"' not in page.text


def test_page_says_when_cve_matching_is_off(hub_cfg, token):
    c = page_client(hub_cfg, token, enabled=False)
    assert "turned off" in c.get("/h/testhost/vulnerabilities").text


def test_config_section(tmp_path):
    from daemonsight import config
    p = tmp_path / "c.toml"
    p.write_text("[cve]\nenabled = false\nrefresh_hours = 12\nepss_automatable = 0.25\n")
    c = config.load(p)
    assert (c.cve.enabled, c.cve.refresh_hours, c.cve.epss_automatable) == (False, 12, 0.25)
    assert config.Config().cve.epss_automatable == 0.04
    assert config.Config().cve.enabled is True and config.Config().cve.refresh_hours == 24
