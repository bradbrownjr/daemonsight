"""The CVEs an OPNsense firewall's pending update fixes: OPNsense's version order, the changelog parser on real files, the
tarball reader, the range an update brings, the download, the chore's matching, the updates finding and the card.
The changelog files in tests/fixtures/opnsense/changelog/ are real ones from the project's repository (see the README
there); the firewall's replies are the synthetic ones in tests/fixtures/opnsense/."""

import asyncio
import copy
import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import db
from daemonsight.config import Config
from daemonsight.cve import feeds, opnsense as chg, opnver, run, store
from daemonsight.remote import opnsense, opnsense_cves, opnsense_rules as rules, poll, store as remotes
from daemonsight.web.app import create_app

from . import fake_advisories, fake_changelog
from .conftest import PASSWORD
from .fake_opnsense import FakeOpnsense, KEY, SECRET, load
from .test_cve import DAY, serve
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

NOW = 1_795_000_000.0
URL = "https://fw.test:8443"
CHANGELOG = Path(__file__).parent / "fixtures" / "opnsense" / "changelog" / "community"


def text_of(series: str, release: str) -> str:
    return (CHANGELOG / series / release).read_text(encoding="utf-8")


def parsed(series: str, release: str) -> dict:
    return chg.parse_release(release, text_of(series, release))


def rows(series: str, release: str, kind: str = "cve") -> dict[tuple[str, str], str]:
    return {(f["version"], f["ref"]): f["line"] for f in parsed(series, release)["fixes"] if f["kind"] == kind}


# --- OPNsense's version order -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, order", [
    ("26.1.2", "26.1.2_3", -1),                 # a hotfix is above its release (pkg: the revision is compared last)
    ("26.1.11", "26.1.11_3", -1), ("26.1.11_3", "26.1.11_10", -1), ("26.1.11_6", "26.1.11_10", -1),   # _10 is above _6: numbers
    ("26.1.11_10", "26.1.12", -1), ("26.1.2_3", "26.1.3", -1), ("26.1.2_3", "26.1.2_3", 0),
    ("26.7.9", "26.7.10", -1), ("26.7.10", "26.7.9", 1),                                                 # not a string comparison
    ("26.7", "26.7.0", 0), ("26.7", "26.7.1", -1), ("26.1.11_10", "26.7", -1), ("26.7", "26.1.11_10", 1),
    ("25.7.7", "26.1", -1), ("15.1.6", "15.1.6.1", -1), ("15.1.6.1", "15.1.7", -1), ("9.9", "10.1", -1)])
def test_versions_are_ordered_as_pkg_orders_them(a, b, order):
    assert opnver.compare(a, b) == order and opnver.compare(b, a) == -order


@pytest.mark.parametrize("v", [None, "", " ", "26", "26.7.r1", "26.1.b", "26.1.r2_2", "26.1.2_x", "26.1.2_", "26.1.2,1", "v26.1", "26.1.2-p1",
                               "26.1.2; rm -rf /", "26.1.2_3_4", "1.2.3.4.5", "../26.1"])
def test_anything_else_is_not_a_version(v):
    assert opnver.parse(v) is None and not opnver.valid(v)
    with pytest.raises(ValueError):
        opnver.compare(v or "x", "26.1")


@pytest.mark.parametrize("v, series", [("26.1.11_3", "26.1"), ("26.7", "26.7"), ("15.1.6.1", "15.1"), ("26.10", "26.10"), ("26.7.r1", None), (None, None)])
def test_the_series_is_the_first_two_parts(v, series):
    assert opnver.series_of(v) == series


@pytest.mark.parametrize("a, b, series", [
    ("26.1.2_3", "26.1.5", ["26.1"]), ("26.1.11_10", "26.7", ["26.1", "26.7"]), ("25.7.7", "26.7", ["25.7", "26.1", "26.7"]),
    ("26.7.1", "26.1", ["26.7"]),                       # not newer: only the series the firewall is on
    ("25.10.2", "26.1", None), ("26.4.1", "26.4.2", None),    # Business Edition series (YY.4, YY.10) are not read
    ("junk", "26.1", None), ("26.1", None, None), ("14.1", "26.7", None)])
def test_the_series_an_update_crosses(a, b, series):
    assert opnver.series_between(a, b) == series


# --- the parser, on real files ---------------------------------------------------------------------------------------------------

def test_a_cve_in_a_footnote_is_found_with_its_bullet():
    got = rows("26.1", "26.1.4")
    assert list(got) == [("26.1.4", "CVE-2026-30868")]
    assert got[("26.1.4", "CVE-2026-30868")] == "mvc: fix CSRF vulnerability in multiple API endpoints by enforcing POST-only requests (contributed by Oliver Jueguen)"
    assert rows("25.7", "25.7.7") == {("25.7.7", "CVE-2025-13698"): "system: simplify RRD backup code and remove exec() usage (reported by Alex Williams from Pellera Technologies working with Trend Zero Day Initiative)"}
    assert parsed("26.1", "26.1.4")["date"] == "2026-03-11"


def test_a_release_with_no_cve_has_no_rows_and_a_release_candidate_is_not_a_release():
    assert parsed("26.1", "26.1.5")["fixes"] == [] and parsed("26.7", "26.7")["fixes"] == []
    assert not chg.FILE_RE.match("changelog-master/community/26.1/26.1.r1")


def test_a_cve_typed_in_the_bullet_and_several_in_one_bullet():
    assert set(rows("18.7", "18.7.7")) == {("18.7.7", "CVE-2018-18958")}
    old = rows("15.1", "15.1.6.1")                         # a four-part version; "bind 9.9.6-P2[2] (CVE-2015-1349), php 5.6.6[3] (CVE-2015-0273)"
    assert set(old) == {("15.1.6.1", "CVE-2015-1349"), ("15.1.6.1", "CVE-2015-0273")}


def test_a_cve_named_only_in_the_prose_is_not_counted():
    """24.7.3 says CVE-2024-6640 "resurfaces" (not fixed); 21.7.2 lists four CVEs in its introduction. Neither is a bullet."""
    assert "CVE-2024-6640" in text_of("24.7", "24.7.3") and rows("24.7", "24.7.3") == {}
    assert "CVE-2021-3711" in text_of("21.7", "21.7.2") and rows("21.7", "21.7.2") == {}


def test_hotfix_sections_have_their_own_version_and_the_out_of_band_lead_line_names_its_cves():
    got = rows("26.1", "26.1.11")
    assert {v for v, _ in got} == {"26.1.11", "26.1.11_10"}
    assert {c for v, c in got if v == "26.1.11"} == {"CVE-2026-57154", "CVE-2026-57155", "CVE-2026-58390", "CVE-2026-58392",
                                                      "CVE-2026-58393", "CVE-2026-58394", "CVE-2026-58395"}
    line = got[("26.1.11_10", "CVE-2026-109618")]
    assert line.startswith("ports: php 8.3.36") and "Out of band hotfix for PHP CVE-2026-109618 and CVE-2026-109619" in line
    assert ("26.1.11_10", "CVE-2026-109619") in got
    # The hotfix sections that name an advisory but no CVE: 26.1.11_3 has a GitHub advisory and no CVE id.
    assert ("26.1.11_3", "GHSA:GHSA-p9pr-782r-w2xw") in rows("26.1", "26.1.11", "adv")
    assert {c for v, c in rows("26.7", "26.7.7")} == {"CVE-2026-109618", "CVE-2026-109619"}


def test_an_advisory_without_a_cve_id_is_kept_apart_and_a_bullet_with_a_cve_does_not_count_twice():
    adv = rows("26.7", "26.7.1", "adv")
    assert set(adv) == {("26.7.1", f"GHSA:{g}") for g in ("GHSA-h4qj-j2x9-q553", "GHSA-rw63-4hw9-p4v7", "GHSA-vw8q-pqq7-2q7v", "GHSA-jm2f-ch62-rpxr")}
    assert not rows("26.7", "26.7.1", "cve")
    sa = rows("26.7", "26.7.10", "adv")
    assert ("26.7.10", "FREEBSD-SA:26:74.ktls") in sa and ("26.7.10", "GHSA:GHSA-89wp-xvvm-9pp4") in sa
    # 26.1.11's bullet 2 has CVE-2026-58394 and bullet 4 the same CVE: one row.
    cve = [f for f in parsed("26.1", "26.1.11")["fixes"] if f["ref"] == "CVE-2026-58394"]
    assert len(cve) == 1 and all(r["kind"] == "cve" for r in cve)


def test_a_release_that_does_not_look_like_a_changelog_gives_what_it_can_and_never_a_wrong_id():
    t = ("@ not a date\n\nIntro with CVE-2026-0001 in the prose.\n\nHere are the full patch notes:\n\n"
         "o system: fixes CVE-2026-1[1]\n"
         "o system: fixes CVE-2026-12345[9] and CVE-2026-22222[1]\n"
         "o firewall: long line that\n  continues here[2]\n\n"
         "A hotfix release was issued as 25.1.9_1:\n\n"
         "o system: another series, so the heading is ignored CVE-2026-33333\n"
         "A hotfix release was issued as 26.1.9_2:\n\n"
         "o ports: the real hotfix CVE-2026-44444\n\n--\n[1] CVE:CVE-2026-55555\n[2] CVE:cve-2026-6\n[3] https://example.com/cve-2026-77777\n")
    r = chg.parse_release("26.1.9", t)
    assert r["date"] is None
    got = {(f["version"], f["ref"]) for f in r["fixes"]}
    assert got == {("26.1.9", "CVE-2026-12345"), ("26.1.9", "CVE-2026-22222"), ("26.1.9", "CVE-2026-55555"), ("26.1.9", "CVE-2026-33333"),
                   ("26.1.9_2", "CVE-2026-44444")}
    assert chg.parse_release("26.1.9", "")["fixes"] == []
    with pytest.raises(chg.ChangelogError):
        chg.parse_release("26.1.9", "\n".join("o x" for _ in range(chg.MAX_BULLETS + 1)))


def test_a_hotfix_is_compared_as_the_package_version_it_names():
    assert [f["version"] for f in parsed("26.1", "26.1.11")["fixes"] if f["version"] != "26.1.11"][0] in ("26.1.11_3", "26.1.11_10")
    assert all(opnver.valid(f["version"]) for r in ("26.1.11", "26.1.9") for f in parsed("26.1", r)["fixes"])


# --- the tarball ------------------------------------------------------------------------------------------------------------------

def test_the_tarball_reader_takes_only_release_files_of_the_wanted_series(tmp_path):
    p = fake_changelog.write_tarball(tmp_path / "a.tar.gz", extra={
        "community/26.1/26.1.99": b"@ July 21, 2026\no x\n",
        "business/26.4/26.4": b"@ April 15, 2026\n", "work/notes": b"x",
        "community/26.1/../../etc/passwd": b"x", "community/26.1/26.1.7.sh": b"x", "community/26.1/link": None,
        "community/26.7/26.1.1": b"x"})                            # a file whose name is not of its directory's series
    got = chg.read_tarball(p, {"26.1"})
    assert set(got) == {"26.1.4", "26.1.5", "26.1.7", "26.1.9", "26.1.10", "26.1.11", "26.1.99"}
    assert all(s == "26.1" for s, _t in got.values())
    assert set(chg.read_tarball(p, {"26.7"})) == {"26.7", "26.7.1", "26.7.7", "26.7.10"} and chg.read_tarball(p, {"99.1"}) == {}


@pytest.mark.parametrize("make", ["junk", "empty tar", "no community", "huge member", "too many"])
def test_a_file_that_is_not_the_changelog_is_refused(tmp_path, monkeypatch, make):
    if make == "junk":
        data = fake_changelog.not_a_tarball()
    elif make == "empty tar":
        data = fake_changelog.tarball_bytes(skip=tuple(str(f.relative_to(fake_changelog.FIX)) for f in fake_changelog.FIX.rglob("*") if f.is_file()))
    elif make == "no community":
        data = fake_changelog.tarball_bytes(root="x", skip=tuple(str(f.relative_to(fake_changelog.FIX)) for f in fake_changelog.FIX.rglob("*")
                                                                  if f.is_file() and "community" in str(f)))
    else:
        data = fake_changelog.tarball_bytes()
        monkeypatch.setattr(chg, "MAX_FILE_BYTES" if make == "huge member" else "MAX_MEMBERS", 1000 if make == "huge member" else 3)
    p = tmp_path / "x.tar.gz"
    p.write_bytes(data)
    with pytest.raises(chg.ChangelogError):
        chg.read_tarball(p, {"26.1", "26.7", "25.7", "21.7", "24.7", "18.7", "15.1"})


def loaded_db(tmp_path, series=("26.1", "26.7")):
    conn = store.connect(tmp_path / "cve.db")
    chg.load(conn, fake_changelog.write_tarball(tmp_path / "t.tar.gz"), set(series))
    return conn


def test_loading_replaces_the_rows_and_a_bad_file_keeps_them(tmp_path):
    conn = loaded_db(tmp_path, ("26.1",))
    assert conn.execute("SELECT COUNT(*) FROM opn_release WHERE series = '26.7'").fetchone()[0] == 0
    n = conn.execute("SELECT COUNT(*) FROM opn_fix").fetchone()[0]
    assert n > 30 and {r["version"] for r in conn.execute("SELECT version FROM opn_release")} >= {"26.1.4", "26.1.11"}
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(fake_changelog.not_a_tarball())
    with pytest.raises(chg.ChangelogError):
        chg.load(conn, bad, {"26.1"})
    assert conn.execute("SELECT COUNT(*) FROM opn_fix").fetchone()[0] == n
    chg.load(conn, fake_changelog.write_tarball(tmp_path / "t.tar.gz"), {"26.7"})                 # another set of series replaces it all
    assert {r["series"] for r in conn.execute("SELECT series FROM opn_release")} == {"26.7"}


# --- which fixes an update brings -----------------------------------------------------------------------------------------------

def cves_between(conn, a, b):
    return {(r["version"], r["ref"]) for r in chg.fixes_between(conn, a, b, "cve")}


def test_an_update_brings_every_section_above_the_installed_version_up_to_the_offered_one(tmp_path):
    conn = loaded_db(tmp_path)
    # 26.1.2_3 to 26.1.5: 26.1.4 only (26.1.5 has none; the fixtures have no 26.1.3).
    assert cves_between(conn, "26.1.2_3", "26.1.5") == {("26.1.4", "CVE-2026-30868")}
    assert cves_between(conn, "26.1.4", "26.1.5") == set()                       # installed is the release that has it: already fixed
    assert cves_between(conn, "26.1.3", "26.1.4") == {("26.1.4", "CVE-2026-30868")}                    # offered is the release that has it
    assert cves_between(conn, "26.1.7", "26.1.9") == {("26.1.9", "CVE-2026-49131"), ("26.1.9", "CVE-2026-49132")}
    assert len(cves_between(conn, "26.1.2_3", "26.1.11")) == 13
    # A hotfix of 26.1.11: only its own sections, and the installed hotfix's are already in.
    assert cves_between(conn, "26.1.11", "26.1.11_10") == {("26.1.11_10", "CVE-2026-109618"), ("26.1.11_10", "CVE-2026-109619")}
    assert cves_between(conn, "26.1.11_3", "26.1.11_10") == cves_between(conn, "26.1.11", "26.1.11_10")
    assert cves_between(conn, "26.1.11_10", "26.7") == set()
    assert cves_between(conn, "26.1.11_3", "26.1.11_6") == set()
    # Nothing newer than what is installed.
    assert cves_between(conn, "26.7.10", "26.7.10") == set() and cves_between(conn, "26.7.7", "26.7.5") == set()
    # Across a major upgrade the two series' sections are all in range; the last one that names a CVE is its release.
    both = cves_between(conn, "26.1.10", "26.7.7")
    assert ("26.1.11", "CVE-2026-57154") in both and ("26.7.7", "CVE-2026-109618") in both and ("26.1.11_10", "CVE-2026-109618") in both
    chg.match_host(conn, "opnsense:fw1", {"installed": "26.1.10", "offered": "26.7.7"}, "g")
    m = {r["cve"]: r for r in conn.execute("SELECT * FROM match WHERE host = 'opnsense:fw1'")}
    assert m["CVE-2026-109618"]["fixed"] == "26.7.7" and m["CVE-2026-57154"]["fixed"] == "26.1.11"
    assert {r["state"] for r in m.values()} == {"fix"} and {r["source"] for r in m.values()} == {"opnsense"}
    assert {r["installed"] for r in m.values()} == {"26.1.10"} and len(m) == 9


def test_matching_stores_the_plan_so_a_change_of_the_offered_version_is_seen(tmp_path):
    conn = loaded_db(tmp_path)
    p = {"installed": "26.1.2_3", "offered": "26.1.5"}
    r = chg.match_host(conn, "opnsense:fw1", p, "g1")
    assert r["cves"] == 1 and r["note"] == ""
    row = conn.execute("SELECT * FROM matched WHERE host = 'opnsense:fw1'").fetchone()
    assert row["inv_hash"] == chg.plan_hash(p) == "26.1.2_3>26.1.5" and row["gen"] == "g1" and row["packages"] == 2    # 26.1.4 and 26.1.5 files
    # An offered release the changelog does not have yet is said, and nothing is invented for it.
    r = chg.match_host(conn, "opnsense:fw1", {"installed": "26.1.2_3", "offered": "26.1.12"}, "g2")
    assert "no entry for 26.1.12 yet" in r["note"] and r["cves"] > 1
    assert "no entry" not in chg.match_host(conn, "opnsense:fw1", {"installed": "26.1.2_3", "offered": "26.1.11_10"}, "g3")["note"]


# --- the plan, from the firewall's firmware status ------------------------------------------------------------------------------

def firmware(to="26.1.5", frm=None, **kw):
    raw = load("firmware")
    raw["product"]["product_latest"] = to
    raw["all_packages"]["opnsense"]["new"] = to
    if frm:
        raw["product"]["product_version"] = raw["product_version"] = frm
        raw["all_packages"]["opnsense"]["old"] = frm
    raw.update(kw)
    return opnsense.parse_firmware(raw)


def test_the_plan_names_the_installed_and_the_offered_version():
    assert chg.plan(firmware()) == {"ok": True, "installed": "26.1.2_3", "offered": "26.1.5", "series": ["26.1"]}
    assert chg.plan(firmware(to="26.1.11_10", frm="26.1.11"))["series"] == ["26.1"]
    # A hotfix: the package's new version has the revision, the release status does not.
    raw = load("firmware")
    raw["product"]["product_version"] = raw["product_version"] = "26.1.11"
    raw["product"]["product_latest"] = "26.1.11"
    raw["all_packages"]["opnsense"].update(old="26.1.11", new="26.1.11_10")
    assert chg.plan(opnsense.parse_firmware(raw))["offered"] == "26.1.11_10"
    # A major upgrade lists sets, not packages: the release is the upgrade's version.
    raw = load("firmware")
    raw.update(status="upgrade", all_packages={}, upgrade_major_version="26.7",
               all_sets={"base": {"name": "base", "old": "26.1.2_3", "new": "26.7", "reason": "upgrade"}})
    raw["product"]["product_latest"] = "26.1.2"
    p = chg.plan(opnsense.parse_firmware(raw))
    assert p["ok"] and p["offered"] == "26.7" and p["series"] == ["26.1", "26.7"]


def test_a_plan_is_refused_for_what_has_no_release_or_cannot_be_ordered():
    fw = firmware()
    assert chg.plan(None) == chg.plan({}) == {"ok": False, "why": "nothing"}
    assert chg.plan({**fw, "count": 0})["why"] == "nothing" and chg.plan({"available": False})["why"] == "nothing"
    only_plugin = {**fw, "packages": [p for p in fw["packages"] if p["name"] != "opnsense"], "new_version": ""}
    assert chg.plan(only_plugin) == {"ok": False, "why": "no_release"}                       # package updates are not releases
    assert chg.plan({**fw, "version": "26.1.2_3", "packages": [{"name": "opnsense", "old": "26.1.2_3", "new": "26.1.2_3"}]})["why"] == "no_release"
    odd = chg.plan({**fw, "version": "26.1.r1"})
    assert odd["why"] == "version" and odd["installed"] == "26.1.r1"
    bus = chg.plan({**fw, "version": "25.10.1", "packages": [{"name": "opnsense-business", "old": "25.10.1", "new": "25.10.2"}]})
    assert bus["ok"] is False and bus["why"] == "series"


# --- the download -----------------------------------------------------------------------------------------------------------------

def put_firmware(conn, fw, host="fw1", ok=True):
    db.put_snapshot(conn, host, "opnsense_firmware", NOW, ok, None, fw)


def make(tmp_path, fw=None, client=None, calls=None, name="fw1"):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    conn = db.connect_writer(cfg.db_path)
    remotes.add(conn, cfg.data_dir, name, "opnsense", URL, KEY, secret=SECRET, interval=60, now=NOW - 1000)
    put_firmware(conn, fw or firmware(), name)
    return cfg, conn, run.Chore(cfg, conn, client or serve(tmp_path, calls))


def cve_rows(cfg, table="opn_fix"):
    conn = store.connect(cfg.cve_db_path)
    try:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]
    finally:
        conn.close()


def feed_row(cfg):
    conn = store.connect(cfg.cve_db_path)
    try:
        r = conn.execute("SELECT * FROM feed WHERE name = 'opnsense-changelog'").fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def opn_calls(calls):
    return [(h, d) for h, d in calls if h == feeds.OPNSENSE_HOST]


def test_the_changelog_is_fetched_once_a_day_with_a_conditional_get_and_only_while_a_firewall_is_enabled(tmp_path):
    calls = []
    cfg, conn, c = make(tmp_path, calls=calls)
    asyncio.run(c.run_once(NOW))
    got = opn_calls(calls)
    assert len(got) == 1 and "if-none-match" not in got[0][1]
    row = feed_row(cfg)
    assert row["status"] == "ok" and row["etag"] == '"v1"' and row["url"] == chg.URL and "series 26.1" in row["note"] and row["rows"] > 0
    # the firewall's series and the later ones the changelog has (a major upgrade is only a line on the card)
    assert {r["series"] for r in cve_rows(cfg, "opn_release")} == {"26.1", "26.7"}
    assert (Path(cfg.data_dir) / "cve" / "opnsense-changelog.tar.gz").exists()
    m = store.connect(cfg.cve_db_path)
    assert m.execute("SELECT cve, fixed FROM match WHERE host = 'opnsense:fw1'").fetchall()[0][:] == ("CVE-2026-30868", "26.1.4")
    m.close()
    # An hour later nothing is asked; a day later it is asked with its validators and answers 304, and the rows stay.
    asyncio.run(c.run_once(NOW + 3600))
    assert len(opn_calls(calls)) == 1
    asyncio.run(c.run_once(NOW + DAY + 5))
    again = opn_calls(calls)[1]
    assert again[1]["if-none-match"] == '"v1"' and again[1]["if-modified-since"].startswith("Tue, 24 Nov")
    assert feed_row(cfg)["status"] == "not modified" and cve_rows(cfg)
    assert all(set(d) <= {"host", "accept", "accept-encoding", "connection", "user-agent", "if-none-match", "if-modified-since"} for _h, d in opn_calls(calls))
    # An update no longer pending changes nothing: the changelog is kept for a release the firewall may not have seen.
    put_firmware(conn, {**firmware(), "count": 0, "packages": []})
    asyncio.run(c.run_once(NOW + 2 * DAY - 10))
    assert feed_row(cfg) is not None and cve_rows(cfg)
    # No enabled firewall is left: the file, the rows and the feed row go, and nothing is asked.
    conn.execute("UPDATE remotes SET enabled = 0 WHERE id = 'fw1'")
    asyncio.run(c.run_once(NOW + 2 * DAY + 10))
    assert len(opn_calls(calls)) == 2 and feed_row(cfg) is None and cve_rows(cfg) == []
    assert not (Path(cfg.data_dir) / "cve" / "opnsense-changelog.tar.gz").exists()
    s = store.connect(cfg.cve_db_path)
    assert s.execute("SELECT COUNT(*) FROM match WHERE host LIKE 'opnsense:%'").fetchone()[0] == 0 and s.execute("SELECT COUNT(*) FROM matched WHERE host LIKE 'opnsense:%'").fetchone()[0] == 0
    s.close()


def test_a_disabled_firewall_asks_for_nothing_and_package_updates_alone_still_need_the_changelog(tmp_path):
    calls = []
    only_plugin = firmware()
    only_plugin["packages"] = [p for p in only_plugin["packages"] if p["name"] != "opnsense"]
    only_plugin.update(new_version="", count=1)
    cfg, conn, c = make(tmp_path, only_plugin, calls=calls)
    conn.execute("UPDATE remotes SET enabled = 0 WHERE id = 'fw1'")
    asyncio.run(c.run_once(NOW))
    assert opn_calls(calls) == [] and feed_row(cfg) is None
    put_firmware(conn, firmware())
    conn.execute("UPDATE remotes SET enabled = 0 WHERE id = 'fw1'")
    asyncio.run(c.run_once(NOW + 10))
    assert opn_calls(calls) == []
    conn.execute("UPDATE remotes SET enabled = 1 WHERE id = 'fw1'")
    asyncio.run(c.run_once(NOW + 20))
    assert len(opn_calls(calls)) == 1


def test_a_failed_download_keeps_the_last_good_copy_and_says_so(tmp_path):
    cfg, conn, c = make(tmp_path)
    asyncio.run(c.run_once(NOW))
    before = cve_rows(cfg)
    assert before
    c.client = serve(tmp_path, override={feeds.OPNSENSE_HOST: lambda r: httpx.Response(503)})
    asyncio.run(c.run_once(NOW + DAY + 5))
    row = feed_row(cfg)
    assert row["status"] == "error" and row["detail"] == "HTTP 503" and row["ok_at"] == NOW and cve_rows(cfg) == before
    # The finding's data still comes from the last copy, with the error to show.
    got = opnsense_cves.load(cfg, conn, "fw1", firmware())
    assert got["state"] == "ok" and got["feed"]["error"] == "HTTP 503" and got["feed"]["ok_at"] == NOW and len(got["cves"]) == 1
    # An error is tried again after an hour, not a day.
    calls = []
    c.client = serve(tmp_path, calls, override={feeds.OPNSENSE_HOST: lambda r: httpx.Response(503)})
    asyncio.run(c.run_once(NOW + DAY + 5 + 1800))
    assert opn_calls(calls) == []
    asyncio.run(c.run_once(NOW + DAY + 5 + 3600))
    assert len(opn_calls(calls)) == 1
    # A file that downloads but is not the changelog keeps the rows too.
    c.client = serve(tmp_path, override={feeds.OPNSENSE_HOST: lambda r: httpx.Response(200, content=fake_changelog.not_a_tarball(), headers={"etag": '"v2"'})})
    asyncio.run(c.run_once(NOW + 3 * DAY))
    row = feed_row(cfg)
    assert row["status"] == "error" and "ChangelogError" in row["detail"] and row["etag"] is None and cve_rows(cfg) == before
    # Back to normal: loaded again.
    c.client = serve(tmp_path)
    asyncio.run(c.run_once(NOW + 4 * DAY))
    assert feed_row(cfg)["status"] == "ok" and cve_rows(cfg) == before


def test_a_first_download_that_fails_leaves_the_finding_without_cves_and_is_not_an_outage(tmp_path):
    cfg, conn, c = make(tmp_path, client=serve(tmp_path, override={feeds.OPNSENSE_HOST: lambda r: httpx.Response(503)}))
    asyncio.run(c.run_once(NOW))
    got = opnsense_cves.load(cfg, conn, "fw1", firmware())
    assert got["state"] == "pending" and got["feed"]["error"] == "HTTP 503" and got["feed"]["ok_at"] is None
    assert [f for f in rules.firmware_rules(firmware(), NOW, got) if f.rule == "opnsense.updates"][0].title.endswith("(to 26.1.5)")


def test_a_pending_update_that_reaches_another_series_reads_the_saved_file_without_downloading_again(tmp_path):
    calls = []
    cfg, conn, c = make(tmp_path, firmware(to="26.7.7", frm="26.7.1"), calls=calls)
    asyncio.run(c.run_once(NOW))
    assert {r["series"] for r in cve_rows(cfg, "opn_release")} == {"26.7"} and len(opn_calls(calls)) == 1
    crossing = firmware(to="26.7.7", frm="26.1.10")
    put_firmware(conn, crossing)
    asyncio.run(c.run_once(NOW + 120))
    assert len(opn_calls(calls)) == 1                                                            # not asked again
    assert {r["series"] for r in cve_rows(cfg, "opn_release")} == {"26.1", "26.7"}
    assert "26.1, 26.7" in feed_row(cfg)["note"]
    got = opnsense_cves.load(cfg, conn, "fw1", crossing)
    assert got["state"] == "ok" and len(got["cves"]) == 10               # 9 in the changelog lines, 1 through GHSA-2v2x-m4j7-76pv
    by = {c["cve"]: c["release"] for c in got["cves"]}
    assert by["CVE-2026-109618"] == "26.7.7" and by["CVE-2026-57154"] == "26.1.11"           # named in 26.1.11_10 and in 26.7.7: the later one
    # The firewall is back to a single series: only that one is kept.
    put_firmware(conn, firmware(to="26.7.7", frm="26.7.1"))
    asyncio.run(c.run_once(NOW + 240))
    assert {r["series"] for r in cve_rows(cfg, "opn_release")} == {"26.7"} and len(opn_calls(calls)) == 1


def test_a_redirect_off_the_repository_host_and_a_huge_file_are_refused(tmp_path):
    async def go():
        conn = store.connect(tmp_path / "c.db")
        f = feeds.OPNSENSE_FEED
        row = feeds.feed_row(conn, f)

        def hop(request):
            if request.url.host == feeds.OPNSENSE_HOST:
                return httpx.Response(302, headers={"location": "https://evil.example/c.tar.gz"})
            return httpx.Response(200, content=fake_changelog.tarball_bytes())
        with pytest.raises(feeds.FetchError, match="not a source"):
            await feeds.download(f, row, tmp_path / "a.tar.gz", httpx.AsyncClient(transport=httpx.MockTransport(hop), follow_redirects=True))
        big = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"\x1f\x8b" + b"0" * (feeds.OPNSENSE_MAX_BYTES + 1))))
        with pytest.raises(feeds.FetchError, match="larger"):
            await feeds.download(f, row, tmp_path / "b.tar.gz", big)
        plain = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"<html>not gzip</html>")))
        with pytest.raises(feeds.FetchError, match="gzip"):
            await feeds.download(f, row, tmp_path / "c.tar.gz", plain)
        assert not list(tmp_path.glob("*.tar.gz*"))
        assert f.hosts == ("codeload.github.com",) and f.url == chg.URL and "BSD 2-Clause" in f.terms
    asyncio.run(go())


# --- the finding ------------------------------------------------------------------------------------------------------------------

def chored(tmp_path, fw=None, now=NOW):
    cfg, conn, c = make(tmp_path, fw)
    asyncio.run(c.run_once(now))
    return cfg, conn, c


def updates(fw, cves, now=NOW):
    got = [f for f in rules.firmware_rules(fw, now, cves) if f.rule == "opnsense.updates"]
    return got[0] if got else None


def set_kev(cfg, cve):
    s = store.connect(cfg.cve_db_path)
    s.execute("INSERT OR REPLACE INTO kev VALUES (?, 'OPNsense', 'OPNsense', 'Synthetic KEV entry', '2026-11-01', 'Unknown')", (cve,))
    s.close()


def set_epss(cfg, cve, score):
    s = store.connect(cfg.cve_db_path)
    s.execute("INSERT OR REPLACE INTO epss VALUES (?, ?, 0.5)", (cve, score))
    s.close()


def test_the_updates_finding_gains_the_cve_count_and_the_worst_ones(tmp_path):
    fw = firmware(to="26.1.11")
    cfg, conn, _c = chored(tmp_path, fw)
    cves = opnsense_cves.load(cfg, conn, "fw1", fw)
    assert cves["state"] == "ok" and len(cves["cves"]) == 14 and cves["releases"] and cves["plan"]["offered"] == "26.1.11"
    f = updates(fw, cves)
    assert f.severity == "medium" and "fixes 14 CVEs and 38 other security advisories" in f.title and "known exploited" not in f.title
    assert "Updating to 26.1.11 fixes 14 CVEs named in OPNsense's changelog or in the FreeBSD and GitHub advisories it lists" in f.detail
    assert "Top CVEs:" in f.detail and "and 10 more" in f.detail
    assert "38 security advisories (FreeBSD and GitHub) name no CVE yet" in f.detail
    assert f.link == "/#firmware" and f.basis and "26.1.11" in f.basis
    # The how-to names System, Firmware, Updates and the changelog of the offered version.
    assert "System, Firmware, Updates" in f.howto and chg.changelog_url("26.1.11") in f.howto
    assert chg.changelog_url("26.1.11") == "https://github.com/opnsense/changelog/blob/master/community/26.1/26.1.11"
    assert chg.changelog_url("26.1.11_3") == chg.changelog_url("26.1.11")
    # The finding from before the CVE data is the same finding with less in it.
    plain = updates(fw, None)
    assert plain.severity == "low" and "CVE" not in plain.title and plain.howto == rules.HOWTO_UPDATES and f.severity != plain.severity


def test_a_cve_on_the_kev_list_makes_the_finding_high_as_for_a_debian_host(tmp_path):
    fw = firmware()
    cfg, conn, _c = chored(tmp_path, fw)
    base = updates(fw, opnsense_cves.load(cfg, conn, "fw1", fw))
    assert base.severity == "medium" and base.title.endswith("fixes 1 CVE")
    set_kev(cfg, "CVE-2026-30868")
    cves = opnsense_cves.load(cfg, conn, "fw1", fw)
    f = updates(fw, cves)
    assert f.severity == "high" and "fixes 1 CVE (1 known exploited)" in f.title and "on CISA's list of exploited vulnerabilities (KEV)" in f.detail
    assert "exploited, CISA KEV" in f.detail and f.basis == base.basis       # the basis is the CVE ids, as for a Debian host
    # A high EPSS probability makes the CVE automatable (estimated), which moves a firewall's CVE to 14 days; a low one does not.
    set_epss(cfg, "CVE-2026-30868", 0.02)
    s = store.connect(cfg.cve_db_path)
    s.execute("DELETE FROM kev")
    s.close()
    assert updates(fw, opnsense_cves.load(cfg, conn, "fw1", fw)).severity == "medium"
    set_epss(cfg, "CVE-2026-30868", 0.5)
    hot = updates(fw, opnsense_cves.load(cfg, conn, "fw1", fw))
    assert hot.severity == "high" and "Fix within 14 days (CISA BOD 26-04 timeline)" in hot.detail and "EPSS 50.0% (50th)" in hot.detail
    assert "Publicly exposed: yes: a firewall is a network device" in hot.howto
    # The CVE never lowers what the packages already make High.
    many = copy.deepcopy(fw)
    many["count"] = many["count_packages"] = 25
    assert updates(many, opnsense_cves.load(cfg, conn, "fw1", many)).severity == "high"
    s = store.connect(cfg.cve_db_path)
    s.execute("DELETE FROM epss")
    s.close()
    assert updates(many, opnsense_cves.load(cfg, conn, "fw1", many)).severity == "high"


def test_the_basis_changes_when_the_offered_version_or_a_cve_changes_and_not_with_ages(tmp_path):
    fw5 = firmware()
    cfg, conn, c = chored(tmp_path, fw5)
    b5 = updates(fw5, opnsense_cves.load(cfg, conn, "fw1", fw5)).basis
    older = {**fw5, "pending_since": NOW - 5 * 86400}
    assert updates(older, opnsense_cves.load(cfg, conn, "fw1", older)).basis == b5
    fw7 = firmware(to="26.1.7")
    put_firmware(conn, fw7)
    asyncio.run(c.run_once(NOW + 120))
    cves7 = opnsense_cves.load(cfg, conn, "fw1", fw7)
    assert cves7["state"] == "ok" and len(cves7["cves"]) == 3
    b7 = updates(fw7, cves7).basis
    assert b7 != b5 and "26.1.7" in b7
    # The same offered version with a different CVE set (the changelog was corrected) is another basis.
    s = store.connect(cfg.cve_db_path)
    s.execute("DELETE FROM opn_fix WHERE ref = 'CVE-2026-44195'")
    s.execute("DELETE FROM match WHERE cve = 'CVE-2026-44195'")
    s.close()
    assert updates(fw7, opnsense_cves.load(cfg, conn, "fw1", fw7)).basis != b7


def test_the_finding_fires_and_clears(tmp_path):
    fw = firmware()
    cfg, conn, c = chored(tmp_path, fw)
    cves = opnsense_cves.load(cfg, conn, "fw1", fw)
    assert updates(fw, cves) is not None
    gone = {**fw, "count": 0, "count_packages": 0, "packages": []}
    assert updates(gone, opnsense_cves.load(cfg, conn, "fw1", gone)) is None
    assert opnsense_cves.load(cfg, conn, "fw1", gone)["state"] == "none"
    # Old matches of an earlier plan are not used for another one: the plan's hash must agree.
    fw7 = firmware(to="26.1.7")
    assert opnsense_cves.load(cfg, conn, "fw1", fw7)["state"] == "pending"
    # CVE matching switched off: no CVEs in the finding, and a state the card can say.
    cfg.cve.enabled = False
    off = opnsense_cves.load(cfg, conn, "fw1", fw)
    assert off["state"] == "off" and "CVE" not in updates(fw, off).title
    # Package updates alone have no release to read.
    only = {**fw, "packages": [p for p in fw["packages"] if p["name"] != "opnsense"], "new_version": ""}
    assert opnsense_cves.load(cfg, conn, "fw1", only)["state"] == "unmapped"


def test_a_whole_poll_puts_the_cves_in_the_stored_finding(tmp_path):
    fake = FakeOpnsense()
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    conn = db.connect_writer(cfg.db_path)
    remotes.add(conn, cfg.data_dir, "fw1", "opnsense", URL, KEY, secret=SECRET, interval=60, now=NOW - 1000)
    asyncio.run(poll.run_once(conn, cfg, fake.net(), NOW))
    first = conn.execute("SELECT title FROM findings WHERE host='fw1' AND rule='opnsense.updates' AND resolved_at IS NULL").fetchone()
    assert first and "CVE" not in first["title"]                          # the changelog is not read yet
    asyncio.run(run.Chore(cfg, conn, serve(tmp_path)).run_once(NOW + 30))
    asyncio.run(poll.run_once(conn, cfg, fake.net(), NOW + 400))
    row = conn.execute("SELECT * FROM findings WHERE host='fw1' AND rule='opnsense.updates' AND resolved_at IS NULL").fetchone()
    assert row["title"].endswith("fixes 1 CVE") and "CVE-2026-30868" in row["detail"] and row["severity"] == "medium"
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE host='fw1' AND rule='opnsense.updates'").fetchone()[0] == 1       # the same finding
    # It clears when the firewall's next check shows nothing pending.
    fake.edit("firmware", lambda d: d.update(status="none", all_packages={}, upgrade_packages=[]))
    asyncio.run(poll.run_once(conn, cfg, fake.net(), NOW + 800))
    assert not conn.execute("SELECT 1 FROM findings WHERE host='fw1' AND rule='opnsense.updates' AND resolved_at IS NULL").fetchone()


# --- the card ---------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def page(hub_cfg, tmp_path):
    hub_cfg.cve.enabled = True
    fake = FakeOpnsense()
    client = TestClient(create_app(hub_cfg, remote_net=fake.net()), follow_redirects=False)
    assert client.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    assert client.post("/remotes/new", data={"kind": "opnsense", "name": "fw1", "url": URL, "key": KEY, "secret": SECRET,
                                            "tls": "verify", "interval": "60", "action": "save"}).status_code == 303
    conn = db.connect_writer(hub_cfg.db_path)
    asyncio.run(poll.run_once(conn, hub_cfg, fake.net(), time.time()))
    yield client, hub_cfg, conn, fake
    conn.close()


def read_cves(cfg, conn, serve_client=None, now=None):
    asyncio.run(run.Chore(cfg, conn, serve_client or serve(Path(cfg.data_dir).parent)).run_once(now or time.time()))


def test_the_card_before_the_changelog_is_read_says_so(page):
    client, cfg, conn, _fake = page
    html = client.get("/h/fw1/").text
    assert 'id="firmware-cves"' in html and "Looking up the CVEs fixed between 26.1.2_3 and 26.1.5" in html
    assert "Fixes " not in html.split('id="firmware-cves"')[1].split("</section>")[0]
    check_panels(html)


def test_the_card_lists_the_cves_the_update_fixes_with_their_rank_and_the_panel(page):
    client, cfg, conn, fake = page
    read_cves(cfg, conn)
    asyncio.run(poll.run_once(conn, cfg, fake.net(), time.time() + 400))              # the next poll puts the CVEs in the finding
    set_kev(cfg, "CVE-2026-30868")
    set_epss(cfg, "CVE-2026-30868", 0.8123)
    html = client.get("/h/fw1/").text
    card = html.split('id="firmware-cves"')[1].split("</section>")[0]
    assert "Fixes 1 CVE (1 known exploited)" in card
    assert 'data-table="opn-firmware-cves"' in card and "https://www.cve.org/cverecord?id=CVE-2026-30868" in card
    assert "81.2%" in card and ">KEV<" in card and "<th data-sort=\"num\">Fix within</th>" in card and "3 days" in card
    assert "Fix within 3 days (CISA BOD 26-04 timeline)" in card and "26.1.4" in card and "2026-03-11" in card
    assert "mvc: fix CSRF vulnerability in multiple API endpoints" in card
    assert "https://github.com/opnsense/changelog/blob/master/community/26.1/26.1.4" in card
    # The panel: sources, terms, and the same check in OPNsense.
    assert 'id="src-fw-cves"' in html and "CVEs this update fixes" in html
    assert chg.URL in html and chg.REPO in html and "docs.opnsense.org/CE_releases.html" in html
    assert "System, Firmware, Changelog" in html and "Run an audit, Security" in html and "BSD 2-Clause" in html
    # The package table is still there, and the finding on the page carries the same count.
    assert 'data-table="opn-firmware"' in card and "os-example-devel" in card
    assert "fixes 1 CVE" in html
    check_panels(html)
    for row in re.findall(r"<tr data-row.*?</tr>", card, re.S):
        assert all("data-label=" in t for t in re.findall(r"<td[^>]*>", row))


def test_the_card_says_what_it_cannot_list(page):
    client, cfg, conn, _fake = page
    cfg.cve.enabled = False
    html = client.get("/h/fw1/").text
    assert "CVE matching is off in Settings" in html
    cfg.cve.enabled = True
    snap = db.get_snapshot(conn, "fw1", "opnsense_firmware")
    data = copy.deepcopy(snap.data)
    data["packages"] = [p for p in data["packages"] if p["name"] != "opnsense"]
    data["new_version"] = ""
    db.put_snapshot(conn, "fw1", "opnsense_firmware", time.time(), True, None, data)
    assert "no new OPNsense release" in client.get("/h/fw1/").text


def test_a_failed_read_shows_an_error_line_with_the_age_of_the_copy(page):
    client, cfg, conn, _fake = page
    read_cves(cfg, conn, now=time.time() - 2 * DAY)
    read_cves(cfg, conn, serve(Path(cfg.data_dir).parent, override={feeds.OPNSENSE_HOST: lambda r: httpx.Response(503)}), now=time.time())
    html = client.get("/h/fw1/").text
    assert "The last try to read OPNsense&#39;s changelog failed: HTTP 503" in html and "last good copy, 2 d ago" in html
    assert "Fixes 1 CVE" in html


def test_the_vulnerabilities_feed_list_names_the_changelog_while_it_is_needed(page):
    client, cfg, conn, _fake = page
    read_cves(cfg, conn)
    cdb = store.connect(cfg.cve_db_path)
    rows = {r["name"]: r for r in cdb.execute("SELECT * FROM feed")}
    cdb.close()
    assert "opnsense-changelog" in rows
    from daemonsight.web import views
    cdb = store.connect_reader(cfg.cve_db_path)
    feeds_listed = views._feed_rows(cdb, time.time(), 24)
    cdb.close()
    mine = [f for f in feeds_listed if f["name"] == "opnsense-changelog"]
    assert len(mine) == 1 and mine[0]["title"] == "OPNsense changelog" and mine[0]["state"] == "Up to date" and mine[0]["url"] == chg.URL


# --- a release the firewall has not been offered (opnsense.unseen_release) -----------------------------------------------------

LC = "Wed Nov 18 08:45:50 EST 2026"            # the shape `date` prints (core scripts/firmware/check.sh)
LC_TS = opnsense.last_check_ts(LC)


def idle(version, latest=None, last_check=LC, **kw):
    """A firmware status with nothing pending: what the live firewall showed (version 26.7.9_3, latest 26.7.9, status none)."""
    base = latest or version.split("_")[0]
    return {"version": version, "latest": base, "new_version": "", "status": "none", "message": "There are no updates available on the selected mirror.",
            "packages": [], "sets": [], "count": 0, "count_packages": 0, "count_sets": 0, "needs_reboot": False,
            "last_check": last_check, "major": "", "name": "OPNsense", "series": version[:4], "pending_since": None, **kw}


def unseen_world(tmp_path, fw, extra=None, override=None):
    override = {**(override or {}), **({feeds.OPNSENSE_HOST: lambda r: httpx.Response(200, content=fake_changelog.tarball_bytes(extra=extra))} if extra else {})} or None
    cfg, conn, c = make(tmp_path, fw, serve(tmp_path, override=override))
    asyncio.run(c.run_once(NOW))
    return cfg, conn, c


def unseen_findings(cfg, conn, fw, now):
    cves = opnsense_cves.load(cfg, conn, "fw1", fw)
    return [f for f in rules.firmware_rules(fw, now, cves) if f.rule == "opnsense.unseen_release"], cves


def both(cfg, conn, fw, now):
    cves = opnsense_cves.load(cfg, conn, "fw1", fw)
    return sorted(f.rule for f in rules.firmware_rules(fw, now, cves) if f.rule in ("opnsense.unseen_release", "opnsense.updates"))


@pytest.mark.parametrize("text, want", [
    ("Wed Nov 18 08:45:50 EST 2026", LC_TS), ("Wed Nov 18 13:45:50 UTC 2026", LC_TS), ("Wed Nov 18 09:45:50 EDT 2026", LC_TS),
    ("Wed Nov 18 16:45:50 +03 2026", LC_TS), ("Wed Nov 18 13:45:50 XYZ 2026", LC_TS),     # an unknown abbreviation is read as UTC
    ("Sun Nov  8 08:45:50 EST 2026", LC_TS - 10 * 86400),                                  # a day under 10 is space-padded
    ("unknown", None), ("", None), (None, None), ("Wed Nov 18 08:45:50 2026", None), ("Wed Foo 18 08:45:50 EST 2026", None),
    ("Wed Feb 31 08:45:50 EST 2026", None)])
def test_last_check_is_read_the_way_date_prints_it(text, want):
    assert opnsense.last_check_ts(text) == want


def test_a_newer_release_and_an_old_check_raise_the_finding_and_the_updates_finding_stays_away(tmp_path):
    fw = idle("26.7.1", latest="26.7.1")
    cfg, conn, _c = unseen_world(tmp_path, fw)
    now = LC_TS + 3 * DAY
    got, cves = unseen_findings(cfg, conn, fw, now)
    assert len(got) == 1 and cves["unseen"]["state"] == "ok"
    f = got[0]
    assert f.title == "26.7.10 is out (fixes 27 CVEs and 2 other security advisories); the firewall hasn't checked since Nov 18"
    assert f.basis == "26.7.10" and f.link == "/#firmware"
    assert "Updating to 26.7.10 fixes 27 CVEs" in f.detail and "CVE-2026-101312" in f.detail and "last firmware check (Wed Nov 18" in f.detail
    assert "via FreeBSD-SA-26:81.vfs" in f.detail and "2 security advisories (FreeBSD and GitHub) name no CVE yet" in f.detail
    assert "GitHub rates 2 of them High or Critical" in f.detail and f.severity == "high"
    assert "nothing above 26.7.1" in f.detail
    assert "System, Firmware, Status, Check for updates" in f.howto and "'Firmware update check'" in f.howto and "System, Settings, Cron" in f.howto
    assert chg.changelog_url("26.7.10") in f.howto
    assert both(cfg, conn, fw, now) == ["opnsense.unseen_release"]


def test_a_recent_check_does_not_raise_it(tmp_path):
    fw = idle("26.7.1", latest="26.7.1")
    cfg, conn, _c = unseen_world(tmp_path, fw)
    assert unseen_findings(cfg, conn, fw, LC_TS + 2 * DAY - 60)[0] == []
    assert len(unseen_findings(cfg, conn, fw, LC_TS + 2 * DAY)[0]) == 1                    # 2 days or more


def test_no_newer_release_and_an_old_check_raise_nothing(tmp_path):
    fw = idle("26.7.10", latest="26.7.10")
    cfg, conn, _c = unseen_world(tmp_path, fw)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 30 * DAY)
    assert got == [] and cves["unseen"] is None


def test_it_clears_when_the_firewall_catches_up_and_the_updates_finding_takes_over(tmp_path):
    fw = idle("26.7.1", latest="26.7.1")
    cfg, conn, c = unseen_world(tmp_path, fw)
    now = LC_TS + 3 * DAY
    assert both(cfg, conn, fw, now) == ["opnsense.unseen_release"]
    caught = idle("26.7.1", latest="26.7.10")                                        # the check ran: it knows 26.7.10, nothing to install yet
    assert both(cfg, conn, caught, now) == []
    pending = firmware(to="26.7.10", frm="26.7.1", last_check=LC)                  # and when it offers the update
    put_firmware(conn, pending)
    asyncio.run(c.run_once(NOW + 10))
    assert both(cfg, conn, pending, now) == ["opnsense.updates"]


def test_a_hotfix_only_newer_version_counts(tmp_path):
    fw = idle("26.1.11_3", latest="26.1.11")
    cfg, conn, _c = unseen_world(tmp_path, fw)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    assert len(got) == 1 and got[0].title.startswith("26.1.11_10 is out (fixes 2 CVEs); ") and got[0].basis == "26.1.11_10"
    assert cves["unseen"]["plan"]["seen"] == "26.1.11_3"
    # A hotfix with no CVE in it is known too, from its section header.
    conn2 = loaded_db(tmp_path / "x")
    assert "26.7.1_1" in chg.known_versions(conn2) and not conn2.execute("SELECT 1 FROM opn_fix WHERE version = '26.7.1_1'").fetchall()


def test_an_unreadable_last_check_counts_as_unknown_age(tmp_path):
    for i, bad in enumerate(("unknown", "", "yesterday-ish")):
        fw = idle("26.7.1", latest="26.7.1", last_check=bad)
        (tmp_path / str(i)).mkdir()
        cfg, conn, _c = unseen_world(tmp_path / str(i), fw)
        got, _ = unseen_findings(cfg, conn, fw, NOW)
        assert len(got) == 1 and got[0].title == "26.7.10 is out (fixes 27 CVEs and 2 other security advisories); the firewall's last check time is unknown"


NEW_SERIES = {"community/27.1/27.1": b"@ November 24, 2026\n\nHello!\n\no system: something\n\nStay safe,\n"}


def test_a_newer_series_alone_raises_no_finding_and_is_one_line_on_the_card(tmp_path):
    fw = idle("26.7.10", latest="26.7.10")
    cfg, conn, _c = unseen_world(tmp_path, fw, extra=NEW_SERIES)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    assert got == [] and cves["unseen"]["newer_series"] == "27.1" and not cves["unseen"]["plan"]["ok"]
    st = opnsense_cves.unseen_state(fw, cves, LC_TS + 3 * DAY)
    assert st and st["version"] == "" and st["newer_series"] == "27.1"
    from daemonsight.web import opnsense_views
    v = opnsense_views._unseen_view(fw, cves, LC_TS + 3 * DAY)
    assert v["title"] is None and "27.1 is also out" in v["newer"]
    assert opnsense_cves.unseen_state(fw, cves, LC_TS + DAY) is None                   # a recent check: nothing at all


def test_a_release_in_the_series_wins_over_a_newer_series_for_the_finding(tmp_path):
    fw = idle("26.7.1", latest="26.7.1")
    cfg, conn, _c = unseen_world(tmp_path, fw, extra=NEW_SERIES)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    assert len(got) == 1 and got[0].basis == "26.7.10" and cves["unseen"]["newer_series"] == "27.1"


def test_with_no_cve_the_title_counts_the_security_advisories_and_severity_is_medium(tmp_path):
    """Nothing resolves (both sites answer 503): 26.7.10 names no CVE id in a line, so 23 security advisories are all there is."""
    down = {fake_advisories.SA_HOST: lambda r: httpx.Response(503), fake_advisories.GH_HOST: lambda r: httpx.Response(503)}
    fw = idle("26.7.7", latest="26.7.7")
    cfg, conn, _c = unseen_world(tmp_path, fw, override=down)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    assert got[0].title == "26.7.10 is out (fixes 23 security advisories); the firewall hasn't checked since Nov 18"
    assert got[0].severity == "medium" and not cves["unseen"]["cves"] and len(cves["unseen"]["advisories"]) == 23


def test_severity_comes_from_the_same_summary_call_as_the_updates_finding(tmp_path):
    """The two rules rank the same CVE set the same way, with no mapping of their own: a change to the shared scale moves both."""
    pend = firmware(to="26.7.10", frm="26.7.1", last_check=LC)
    idle_fw = idle("26.7.1", latest="26.7.1")
    unrated = {fake_advisories.GH_HOST: lambda r: httpx.Response(404)}        # GitHub's High rating would make every case High
    cfg, conn, c = unseen_world(tmp_path, pend, override=unrated)
    now = LC_TS + 3 * DAY
    for mark in (None, "kev", "epss"):
        if mark == "kev":
            set_kev(cfg, "CVE-2026-109618")
        if mark == "epss":
            s = store.connect(cfg.cve_db_path)
            s.execute("DELETE FROM kev")
            s.close()
            set_epss(cfg, "CVE-2026-109619", 0.9)
        put_firmware(conn, pend)
        asyncio.run(c.run_once(NOW + 20))
        up = updates(pend, opnsense_cves.load(cfg, conn, "fw1", pend))
        put_firmware(conn, idle_fw)
        asyncio.run(c.run_once(NOW + 30))
        cves = opnsense_cves.load(cfg, conn, "fw1", idle_fw)
        un = unseen_findings(cfg, conn, idle_fw, now)[0][0]
        want = opnsense_cves.summary(cves["unseen"]["cves"], cves["epss_automatable"], cves["unseen"]["advisories"])["severity"]
        assert un.severity == want == up.severity == ("medium" if mark is None else "high")


def test_the_card_has_the_same_sentence_and_the_cve_table_and_labels_the_release_as_not_offered(page):
    client, cfg, conn, _fake = page
    put_firmware(conn, idle("26.7.1", latest="26.7.1"))
    read_cves(cfg, conn, now=time.time())
    html = client.get("/h/fw1/").text
    card = html.split('id="firmware-unseen"')[1].split("</section>")[0]
    assert "26.7.10 is out (fixes 27 CVEs and 2 other security advisories); the firewall hasn&#39;t checked since Nov 18" in card
    assert "The firewall has not been offered 26.7.10 yet" in card and "nothing above 26.7.1" in card
    assert 'data-table="opn-firmware-unseen-cves"' in card and "CVE-2026-101313" in card
    assert "Firmware release not yet seen" in html and "Pending firmware updates" not in html
    assert 'id="src-fw-unseen"' in html and "CVEs the newest release fixes" in html
    check_panels(html)
    # A recent check: no card.
    put_firmware(conn, idle("26.7.1", latest="26.7.1", last_check=time.strftime("%a %b %e %H:%M:%S UTC %Y", time.gmtime())))
    assert 'id="firmware-unseen"' not in client.get("/h/fw1/").text
