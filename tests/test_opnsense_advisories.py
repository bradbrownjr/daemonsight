"""The CVE ids of the security advisories an OPNsense changelog names (cve/advisories.py): the FreeBSD and GitHub answers as the
real sites gave them on 2026-11-24 (tests/fixtures/opnsense/advisories/), the one-time cache and the retry, GitHub's rate limit,
the size and redirect limits, and what the ids do to the finding: matching, de-duplication, severity and the title."""

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest

from daemonsight.cve import advisories as adv, opnsense as chg, store
from daemonsight.remote import opnsense_cves, opnsense_rules as rules

from . import fake_advisories as fake
from .test_cve import DAY, serve
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_opnsense_cves import (LC, LC_TS, NOW, firmware, idle, make, page, put_firmware, read_cves, set_epss,  # noqa: F401 (page: fixture)
                                 set_kev, unseen_findings, unseen_world)

FIX = fake.FIX
SA_74 = "FREEBSD-SA:26:74.ktls"
GH_1, GH_2, GH_CVE = "GHSA:GHSA-f35q-c34m-pfw3", "GHSA:GHSA-89wp-xvvm-9pp4", "GHSA:GHSA-2v2x-m4j7-76pv"
HOURS = 24


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def resolve(conn, refs, now=NOW, handler=fake.handler, sleep=None):
    async def nap(_s):
        return None
    return asyncio.run(adv.resolve(conn, refs, now, HOURS, client(handler), sleep or nap))


@pytest.fixture
def cdb(tmp_path):
    conn = store.connect(tmp_path / "cve.db")
    yield conn
    conn.close()


# --- what the two sites return, parsed ----------------------------------------------------------------------------------------

def test_a_freebsd_advisory_gives_the_cve_name_line():
    one = adv.parse_sa(SA_74, (FIX / "FreeBSD-SA-26_74.ktls.asc").read_text())
    assert one == {"cves": ["CVE-2026-101313"], "title": "Kernel memory disclosure via KTLS control messages", "severity": None, "score": None}
    two = adv.parse_sa("FREEBSD-SA:26:85.kqueue", (FIX / "FreeBSD-SA-26_85.kqueue.asc").read_text())
    assert two["cves"] == ["CVE-2026-101320", "CVE-2026-127750"]
    # All 21 FreeBSD advisories of 26.7.10 have the line: 25 CVE ids between them, at most 3 in one.
    assert fake.SA_CVE_COUNT == 25 and len(fake.SA) == 21 and max(len(v) for v in fake.SA_CVES.values()) == 3


def test_a_cve_name_line_may_wrap_and_an_advisory_may_have_none():
    wrapped = fake.sa_text("26:76.ocs_fc", "CVE-2026-1, CVE-2026-127752,\n                CVE-2026-127753\n                and CVE-2026-127754")
    assert adv.parse_sa("FREEBSD-SA:26:76.ocs_fc", wrapped)["cves"] == ["CVE-2026-127752", "CVE-2026-127753", "CVE-2026-127754"]
    assert adv.parse_sa("FREEBSD-SA:26:76.ocs_fc", fake.sa_text("26:76.ocs_fc", ""))["cves"] == []
    assert adv.parse_sa("FREEBSD-SA:26:76.ocs_fc", fake.sa_text("26:76.ocs_fc", "N/A"))["cves"] == []
    # The line is read from the header block only: a CVE in the text below is not the advisory's.
    body = fake.sa_text("26:76.ocs_fc", "") + "\nSee also CVE-2026-999999.\nCVE Name: CVE-2026-888888\n"
    assert adv.parse_sa("FREEBSD-SA:26:76.ocs_fc", body)["cves"] == []


@pytest.mark.parametrize("text", ["", "<html>404</html>", "FreeBSD-SA-26:75.linux  Security Advisory\nCVE Name: CVE-2026-101314\n"])
def test_an_answer_that_is_not_the_advisory_asked_for_is_refused(text):
    with pytest.raises(adv.FetchError):
        adv.parse_sa("FREEBSD-SA:26:76.ocs_fc", text)


def test_the_two_github_advisories_of_26_7_10_name_no_cve_and_are_rated_high():
    for ref in (GH_1, GH_2):
        got = adv.parse_ghsa(ref, json.loads((FIX / (ref.split(":")[1] + ".json")).read_text()))
        assert got["cves"] == [] and got["severity"] == "high" and got["score"] == 7.2 and got["title"]
    assert "incomplete fix of CVE-2026-57154" in adv.parse_ghsa(GH_1, json.loads((FIX / "GHSA-f35q-c34m-pfw3.json").read_text()))["title"]
    # One that has a CVE id: only its cve_id counts, never a CVE mentioned in a summary.
    got = adv.parse_ghsa(GH_CVE, json.loads((FIX / "GHSA-2v2x-m4j7-76pv.json").read_text()))
    assert got["cves"] == ["CVE-2026-63442"] and got["severity"] == "high" and got["score"] == 8.1


def test_a_github_answer_that_is_wrong_in_any_way_is_refused_and_odd_values_are_dropped():
    doc = json.loads((FIX / "GHSA-f35q-c34m-pfw3.json").read_text())
    for bad in (None, [], {}, {**doc, "ghsa_id": "GHSA-aaaa-bbbb-cccc"}, {**doc, "state": "draft"}, {**doc, "state": None}):
        with pytest.raises(adv.FetchError):
            adv.parse_ghsa(GH_1, bad)
    got = adv.parse_ghsa(GH_1, {**doc, "cve_id": "CVE-26-1", "severity": "catastrophic", "cvss": {"score": 99}})
    assert got["cves"] == [] and got["severity"] is None and got["score"] is None
    assert adv.parse_ghsa(GH_1, {**doc, "cve_id": "CVE-2026-1234", "severity": "critical"})["cves"] == ["CVE-2026-1234"]


def test_only_security_advisories_are_resolved_errata_and_plugin_notes_are_not():
    assert adv.kind(SA_74) == "sa" and adv.kind(GH_1) == "gh"
    for ref in ("FREEBSD-EN:26:32.zfs", "PLUGINS:26.7/www/caddy", "PHP8:8.5.13", "GHSA:ghsa-x", "FREEBSD-SA:26:74", "CVE:CVE-2026-1"):
        assert adv.kind(ref) is None and adv.api_url(ref) is None
    assert adv.api_url(SA_74) == "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:74.ktls.asc"
    assert adv.api_url(GH_1) == "https://api.github.com/repos/opnsense/core/security-advisories/GHSA-f35q-c34m-pfw3"
    assert adv.label(SA_74) == "FreeBSD-SA-26:74.ktls" and adv.label(GH_1) == "GHSA-f35q-c34m-pfw3"
    # The parser keeps the errata of 26.7.10 out of the advisories altogether.
    refs = {f["ref"] for f in chg.parse_release("26.7.10", (CHANGELOG / "26.7" / "26.7.10").read_text())["fixes"]}
    assert not [r for r in refs if "FREEBSD-EN" in r or "PLUGINS" in r] and len([r for r in refs if r.startswith("FREEBSD-SA")]) == 21


# --- asked once, kept for good, asked again after a failure -----------------------------------------------------------------

def test_an_answer_is_kept_for_good_and_never_asked_for_again(cdb):
    calls = []

    def h(request):
        calls.append(request.url.path)
        return fake.handler(request)
    got = resolve(cdb, [SA_74, GH_1, GH_CVE], handler=h)
    assert got == {"asked": 3, "resolved": 3, "failed": 0, "waiting": 0} and len(calls) == 3
    rows = adv.cached(cdb)
    assert rows[SA_74]["cves"] == ["CVE-2026-101313"] and rows[GH_1]["severity"] == "high" and rows[GH_CVE]["cves"] == ["CVE-2026-63442"]
    assert resolve(cdb, [SA_74, GH_1, GH_CVE], now=NOW + 1000 * DAY, handler=h)["asked"] == 0 and len(calls) == 3


def test_a_failure_is_asked_again_only_after_refresh_hours_and_a_kept_answer_is_not_replaced(cdb):
    calls = []
    state = {"up": False}

    def h(request):
        calls.append(request.url.path)
        return fake.handler(request) if state["up"] else httpx.Response(503, text="busy")
    assert resolve(cdb, [SA_74], handler=h) == {"asked": 1, "resolved": 0, "failed": 1, "waiting": 0}
    row = adv.cached(cdb)[SA_74]
    assert row["status"] == "error" and row["detail"] == "HTTP 503" and row["cves"] == [] and row["tried_at"] == NOW
    assert resolve(cdb, [SA_74], now=NOW + HOURS * 3600 - 1, handler=h)["asked"] == 0 and len(calls) == 1
    state["up"] = True
    assert resolve(cdb, [SA_74], now=NOW + HOURS * 3600, handler=h)["resolved"] == 1 and len(calls) == 2
    assert adv.cached(cdb)[SA_74]["status"] == "ok" and adv.cached(cdb)[SA_74]["cves"] == ["CVE-2026-101313"]
    # A late failure for an advisory that was answered (a second hub pass racing the first) does not overwrite it.
    adv._store_error(cdb, SA_74, "HTTP 500", NOW + 5 * DAY)
    assert adv.cached(cdb)[SA_74]["status"] == "ok"
    # A 404 is a failure too (the file may not be published yet) and is asked again after the same wait.
    assert resolve(cdb, ["FREEBSD-SA:26:99.nothing"], now=NOW + DAY, handler=h)["failed"] == 1
    assert adv.cached(cdb)["FREEBSD-SA:26:99.nothing"]["detail"] == "HTTP 404"


def test_the_generation_changes_when_an_advisory_is_resolved_and_not_on_a_failure(cdb):
    g0 = adv.generation(cdb)
    resolve(cdb, [SA_74], handler=lambda r: httpx.Response(503))
    assert adv.generation(cdb) == g0
    resolve(cdb, [SA_74], now=NOW + 2 * DAY)
    assert adv.generation(cdb) != g0


def test_requests_are_spaced_per_host_and_follow_the_rate_limit_headers(cdb, monkeypatch):
    monkeypatch.setattr(adv, "SPACING", {adv.SA_HOST: 0.5, adv.GH_HOST: 1.0})
    naps = []

    async def nap(s):
        naps.append(s)
    refs = [SA_74, "FREEBSD-SA:26:75.linux", GH_1, GH_2]
    resolve(cdb, refs, sleep=nap)
    assert sorted(naps) == [0.5, 1.0]            # one wait between the two FreeBSD requests, one between the two GitHub ones


def test_github_over_the_limit_stops_the_pass_and_waits_for_the_reset(cdb):
    calls = []
    reset = NOW + 1800

    def limited(request):
        calls.append(request.url.path)
        if request.url.host == adv.GH_HOST:
            return httpx.Response(403, json={"message": "API rate limit exceeded"}, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(reset))})
        return fake.handler(request)
    refs = [GH_1, GH_2, GH_CVE, SA_74]
    got = resolve(cdb, refs, handler=limited)
    # The first GitHub request is refused; the other two are not tried; FreeBSD is a different host and is asked.
    assert got == {"asked": 2, "resolved": 1, "failed": 0, "waiting": 3}
    assert len([c for c in calls if "security-advisories" in c]) == 1 and adv.cached(cdb).keys() == {SA_74}
    assert float(store.get_meta(cdb, adv.GH_UNTIL_KEY)) == reset
    # Nothing is held against the advisory: no failure row. Until the reset GitHub is not asked; after it, it is.
    n = len(calls)
    assert resolve(cdb, refs, now=NOW + 1799, handler=limited)["asked"] == 0 and len(calls) == n
    ok = resolve(cdb, refs, now=reset + 1, handler=fake.handler)
    assert ok["resolved"] == 3 and set(adv.cached(cdb)) == set(refs)


def test_a_plain_403_is_that_advisory_failing_and_does_not_hold_the_others_back(cdb):
    def refuse_one(request):
        if "f35q" in request.url.path:
            return httpx.Response(403, json={"message": "Forbidden"})
        return fake.handler(request)
    got = resolve(cdb, [GH_1, GH_2, GH_CVE], handler=refuse_one)
    assert got == {"asked": 3, "resolved": 2, "failed": 1, "waiting": 0}
    assert adv.cached(cdb)[GH_1]["detail"] == "HTTP 403" and store.get_meta(cdb, adv.GH_UNTIL_KEY) is None


def test_a_429_with_retry_after_and_a_last_allowed_request_both_hold_github_back(cdb):
    def slow(request):
        return httpx.Response(429, headers={"retry-after": "600"})
    resolve(cdb, [GH_1, GH_2], handler=slow)
    assert float(store.get_meta(cdb, adv.GH_UNTIL_KEY)) == NOW + 600 and not adv.cached(cdb)
    # An answer that says no requests are left is used, and the next one waits for the reset.
    store.set_meta(cdb, adv.GH_UNTIL_KEY, "0")
    calls = []

    def last(request):
        calls.append(request.url.path)
        r = fake.handler(request)
        r.headers["x-ratelimit-remaining"] = "0"
        r.headers["x-ratelimit-reset"] = str(int(NOW + 900))
        return r
    got = resolve(cdb, [GH_1, GH_2], now=NOW + 5000, handler=last)
    assert got["resolved"] == 1 and got["waiting"] == 1 and len(calls) == 1
    assert float(store.get_meta(cdb, adv.GH_UNTIL_KEY)) == NOW + 5000 + 60          # a reset in the past: at least a minute
    # A header that asks for more than six hours is not believed, and one that says nothing waits an hour.
    assert adv.gh_wait_until({"retry-after": "999999"}, NOW) == NOW + adv.GH_WAIT_MAX
    assert adv.gh_wait_until({}, NOW) == NOW + adv.GH_WAIT_DEFAULT
    assert adv.gh_wait_until({"retry-after": "soon"}, NOW) == NOW + adv.GH_WAIT_DEFAULT


def test_size_caps_redirects_and_odd_answers_are_failures_and_nothing_is_followed(cdb):
    seen = []

    def h(request):
        seen.append(str(request.url))
        if request.url.host == adv.SA_HOST:
            if "74" in request.url.path:
                return httpx.Response(301, headers={"location": "https://evil.example/x.asc"})
            if "75" in request.url.path:
                return httpx.Response(200, content=b"x" * (adv.SA_MAX_BYTES + 1))
            return httpx.Response(200, text="<html>an error page served with 200</html>")
        if "f35q" in request.url.path:
            return httpx.Response(200, content=b"{" + b" " * (adv.GH_MAX_BYTES + 1))
        if "89wp" in request.url.path:
            return httpx.Response(200, text="not json")
        return httpx.Response(200, json={"ghsa_id": "GHSA-aaaa-bbbb-cccc"})
    refs = [SA_74, "FREEBSD-SA:26:75.linux", "FREEBSD-SA:26:76.ocs_fc", GH_1, GH_2, GH_CVE]
    got = resolve(cdb, refs, handler=h)
    assert got["failed"] == 6 and got["resolved"] == 0
    rows = adv.cached(cdb)
    assert rows[SA_74]["detail"] == "HTTP 301" and "larger" in rows["FREEBSD-SA:26:75.linux"]["detail"]
    assert "not that advisory" in rows["FREEBSD-SA:26:76.ocs_fc"]["detail"] and "larger" in rows[GH_1]["detail"]
    assert rows[GH_2]["detail"] == "the answer is not JSON" and "not that advisory" in rows[GH_CVE]["detail"]
    assert not any("evil.example" in u for u in seen) and all(u.startswith("https://") for u in seen)
    assert adv.SA_HOST == "www.freebsd.org" and adv.GH_HOST == "api.github.com"


def test_one_pass_asks_for_at_most_per_pass_advisories_and_the_rest_wait(cdb, monkeypatch):
    monkeypatch.setattr(adv, "PER_PASS", 3)
    refs = [f"FREEBSD-SA:26:{n}.{m}" for n, m in [(74, "ktls"), (75, "linux"), (76, "ocs_fc"), (77, "netlink"), (78, "gssd")]]
    assert resolve(cdb, refs) == {"asked": 3, "resolved": 3, "failed": 0, "waiting": 2}
    assert resolve(cdb, refs, now=NOW + 60) == {"asked": 2, "resolved": 2, "failed": 0, "waiting": 0}


def test_a_database_from_before_the_table_gives_nothing_and_an_older_one_gains_it(tmp_path):
    path = tmp_path / "old.db"
    conn = store.connect(path)
    conn.execute("DROP TABLE opn_adv")
    conn.execute("PRAGMA user_version=4")
    conn.close()
    r = store.connect_reader(path)
    assert adv.cached(r) == {} and adv.generation(r) == "adv:0:0"
    r.close()
    conn = store.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION == 5
    assert conn.execute("SELECT COUNT(*) FROM opn_adv").fetchone()[0] == 0
    conn.close()


# --- what the ids do: matching, evidence, de-duplication -----------------------------------------------------------------------

CHANGELOG = Path(__file__).parent / "fixtures" / "opnsense" / "changelog" / "community"


def release_file(date, bullets, foots):
    body = "\n".join(f"o {b}" for b in bullets)
    return (f"@ {date}\n\nHello!\n\nHere are the full patch notes:\n\n{body}\n\nStay safe,\nYour OPNsense team\n\n--\n"
            + "\n".join(f"[{i}] {f}" for i, f in enumerate(foots, 1)) + "\n").encode()


def new_release(version, bullets, foots):
    return {f"community/{version[:4]}/{version}": release_file("November 25, 2026", bullets, foots)}


def world(tmp_path, fw, extra=None, **kw):
    return unseen_world(tmp_path, fw, extra=extra, **kw)


def test_the_cves_of_the_advisories_join_the_set_with_the_advisory_as_evidence(tmp_path):
    fw = idle("26.7.9_3", latest="26.7.9")
    cfg, conn, _c = world(tmp_path, fw)
    whole = opnsense_cves.load(cfg, conn, "fw1", fw)
    got = whole["unseen"]
    assert got["state"] == "ok" and len(got["cves"]) == 25 and got["plan"]["offered"] == "26.7.10"
    by = {c["cve"]: c for c in got["cves"]}
    assert by["CVE-2026-101313"]["via"] == [{"label": "FreeBSD-SA-26:74.ktls", "url": "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:74.ktls.asc"}]
    assert by["CVE-2026-101313"]["release"] == "26.7.10" and "ktls: check the record type message holds its byte" in by["CVE-2026-101313"]["line"]
    assert [v["label"] for v in by["CVE-2026-127753"]["via"]] == ["FreeBSD-SA-26:76.ocs_fc"]
    # The two GitHub advisories name no CVE: they stay advisories, rated high by GitHub.
    advs = {a["ref"]: a for a in got["advisories"]}
    assert len(advs) == 23 and advs[GH_1]["cves"] == [] and advs[GH_1]["severity"] == "high" and advs[GH_1]["state"] == "ok"
    assert advs[SA_74]["cves"] == ["CVE-2026-101313"] and advs[SA_74]["url"] == "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:74.ktls.asc"
    assert advs[GH_2]["url"] == "https://github.com/opnsense/core/security/advisories/GHSA-89wp-xvvm-9pp4"
    s = opnsense_cves.summary(got["cves"], whole["epss_high"], got["advisories"])
    assert len(s["fixable"]) == 25 and {a["ref"] for a in s["unresolved"]} == {GH_1, GH_2}


def test_ranking_applies_to_the_resolved_cves(tmp_path):
    fw = idle("26.7.9_3", latest="26.7.9")
    cfg, conn, _c = world(tmp_path, fw)
    set_kev(cfg, "CVE-2026-101313")
    set_epss(cfg, "CVE-2026-127750", 0.9)
    whole = opnsense_cves.load(cfg, conn, "fw1", fw)
    got = whole["unseen"]
    s = opnsense_cves.summary(got["cves"], whole["epss_high"], got["advisories"])
    assert [c["cve"] for c in s["kev"]] == ["CVE-2026-101313"] and [c["cve"] for c in s["hot"]] == ["CVE-2026-127750"]
    assert s["severity"] == "high" and s["fixable"][0]["cve"] == "CVE-2026-101313" and s["fixable"][1]["cve"] == "CVE-2026-127750"
    assert "via FreeBSD-SA-26:74.ktls" in opnsense_cves.describe(s["fixable"][0])


def test_a_cve_named_by_a_line_and_by_an_advisory_is_one_cve_at_the_highest_section(tmp_path):
    # 26.7.11 names CVE-2026-101313 in a line (above 26.7.10, which names it through FreeBSD-SA-26:74.ktls); 26.7.12 names the
    # same advisory again and a CVE of 26.7.10's GHSA-2v2x-m4j7-76pv in a footnote.
    extra = {**new_release("26.7.11", ["src: ktls: the same bug, written as a CVE[1]"], ["CVE:CVE-2026-101313"]),
             **new_release("26.7.12", ["src: ktls: advisory again[1]", "interfaces: another one[2]", "interfaces: and a CVE[3]"],
                           [SA_74, GH_CVE, "CVE:CVE-2026-63442"])}
    fw = idle("26.7.9_3", latest="26.7.9")
    cfg, conn, _c = world(tmp_path, fw, extra)
    got = opnsense_cves.load(cfg, conn, "fw1", fw)["unseen"]
    by = {c["cve"]: c for c in got["cves"]}
    assert len(got["cves"]) == len(by) == 25 + 1                               # 25 from 26.7.10's FreeBSD advisories, plus CVE-2026-63442
    # The highest section that names it is 26.7.12, and there it is the advisory that names it.
    assert by["CVE-2026-101313"]["release"] == "26.7.12" and by["CVE-2026-101313"]["direct"] is False
    assert [v["label"] for v in by["CVE-2026-101313"]["via"]] == ["FreeBSD-SA-26:74.ktls"]
    # CVE-2026-63442 has a footnote in the same release as its advisory: its own line is the evidence, and the advisory bullet
    # is still listed with that CVE.
    assert by["CVE-2026-63442"]["release"] == "26.7.12" and by["CVE-2026-63442"]["direct"] is True
    advs = {a["ref"]: a for a in got["advisories"]}
    assert advs[SA_74]["version"] == "26.7.12" and advs[GH_CVE]["cves"] == ["CVE-2026-63442"]
    assert len([r for r in cdb_rows(cfg, "match", "opnsense-unseen:fw1") if r["cve"] == "CVE-2026-101313"]) == 1


def cdb_rows(cfg, table, host=None):
    c = store.connect(cfg.cve_db_path)
    try:
        q = f"SELECT * FROM {table}" + (" WHERE host = ?" if host else "")
        return [dict(r) for r in c.execute(q, (host,) if host else ())]
    finally:
        c.close()


def test_only_the_advisories_of_the_range_a_firewall_needs_are_asked_for_and_each_once(tmp_path):
    calls = []

    def rec(request):
        calls.append(request.url.path)
        return fake.handler(request)
    hosts = {fake.SA_HOST: rec, fake.GH_HOST: rec}
    # A firewall on 26.7.10 needs nothing above it: the 23 advisories of 26.7.10 are in the changelog and are not asked for.
    fw = idle("26.7.10", latest="26.7.10")
    cfg, conn, c = make(tmp_path, fw, serve(tmp_path, override=hosts))
    asyncio.run(c.run_once(NOW))
    assert calls == [] and cdb_rows(cfg, "opn_fix") and cdb_rows(cfg, "opn_adv") == []
    # One that has not been offered 26.7.10 needs them: the 21 FreeBSD and 2 GitHub advisories, once each.
    put_firmware(conn, idle("26.7.9_3", latest="26.7.9"))
    asyncio.run(c.run_once(NOW + 10))
    assert len(calls) == 23 and len(set(calls)) == 23 and sum("security-advisories" in p for p in calls) == 2
    assert {adv.api_url(r["ref"]).split(".org")[-1].split(".com")[-1] for r in cdb_rows(cfg, "opn_adv")} == set(calls)
    asyncio.run(c.run_once(NOW + 20))
    asyncio.run(c.run_once(NOW + 3 * DAY))
    assert len(calls) == 23
    assert {r["ref"] for r in cdb_rows(cfg, "opn_adv")} >= {SA_74, GH_1, GH_2}
    # A pending update to 26.7.10 needs the same ones, and they are already known.
    put_firmware(conn, firmware(to="26.7.10", frm="26.7.9_3", last_check=LC))
    asyncio.run(c.run_once(NOW + 4 * DAY))
    assert len(calls) == 23


def test_a_failed_lookup_leaves_the_advisory_and_the_chore_tries_again_after_refresh_hours(tmp_path):
    calls = []
    state = {"up": False}

    def sometimes(request):
        calls.append(request.url.path)
        return fake.handler(request) if state["up"] else httpx.Response(500)
    fw = idle("26.7.9_3", latest="26.7.9")
    cfg, conn, c = world(tmp_path, fw, override={fake.SA_HOST: sometimes, fake.GH_HOST: sometimes})
    first = len(calls)
    assert first == 23 and not opnsense_cves.load(cfg, conn, "fw1", fw)["unseen"]["cves"]
    assert {r["detail"] for r in cdb_rows(cfg, "opn_adv")} == {"HTTP 500"}
    asyncio.run(c.run_once(NOW + 3600))
    assert len(calls) == first                                                 # not before refresh_hours
    state["up"] = True
    asyncio.run(c.run_once(NOW + 25 * 3600))
    assert len(calls) == first * 2
    un = opnsense_cves.load(cfg, conn, "fw1", fw)["unseen"]
    assert len(un["cves"]) == 25                                               # the matches were made again with the new answers
    asyncio.run(c.run_once(NOW + 3 * DAY))
    assert len(calls) == first * 2


def test_a_busy_site_is_asked_one_advisory_a_pass_not_all_of_them(tmp_path):
    """A 503 or 429 says the site is busy: the pass stops asking that host, and the next pass tries the next advisory."""
    calls = []

    def busy(request):
        calls.append(request.url.host)
        return httpx.Response(503)
    fw = idle("26.7.9_3", latest="26.7.9")
    cfg, conn, c = world(tmp_path, fw, override={fake.SA_HOST: busy, fake.GH_HOST: busy})
    assert sorted(calls) == [fake.GH_HOST, fake.SA_HOST]
    assert len(cdb_rows(cfg, "opn_adv")) == 2
    asyncio.run(c.run_once(NOW + 60))
    assert len(calls) == 4 and len(cdb_rows(cfg, "opn_adv")) == 4


# --- severity and the title -------------------------------------------------------------------------------------------------

def cve(name, kev=False, epss=None):
    return {"cve": name, "kev": kev, "epss": epss, "state": "fix", "release": "26.7.10"}


def advisory(ref, cves=(), severity=None, state="ok"):
    return {"ref": ref, "cves": list(cves), "severity": severity, "state": state}


def test_an_advisory_with_no_cve_makes_the_severity_medium_and_a_high_github_rating_high():
    s = opnsense_cves.summary
    assert s([], 0.1)["severity"] is None and s([], 0.1, [])["severity"] is None
    # Not resolved yet (or failed, or naming none): at least medium.
    assert s([], 0.1, [advisory(SA_74, state="pending")])["severity"] == "medium"
    assert s([], 0.1, [advisory(SA_74, state="error")])["severity"] == "medium"
    assert s([], 0.1, [advisory(SA_74)])["severity"] == "medium"
    assert s([], 0.1, [advisory(GH_1, severity="low")])["severity"] == "medium"
    assert s([], 0.1, [advisory(GH_1, severity="medium")])["severity"] == "medium"
    # GitHub's high and critical.
    assert s([], 0.1, [advisory(GH_1, severity="high")])["severity"] == "high"
    assert s([], 0.1, [advisory(GH_2, severity="critical")])["severity"] == "high"
    assert s([cve("CVE-2026-1")], 0.1, [advisory(GH_1, severity="high")])["severity"] == "high"
    # A CVE that ranks higher is not lowered; a resolved advisory (one that names a CVE) adds nothing of its own.
    assert s([cve("CVE-2026-1", kev=True)], 0.1, [advisory(GH_1, severity="low")])["severity"] == "high"
    assert s([cve("CVE-2026-1", epss=0.5)], 0.1, [advisory(GH_1)])["severity"] == "high"
    assert s([cve("CVE-2026-1")], 0.1, [advisory(SA_74, cves=["CVE-2026-1"]), advisory(GH_CVE, cves=["CVE-2026-2"], severity="critical")])["severity"] == "medium"
    assert s([], 0.1, [advisory(SA_74, cves=["CVE-2026-1"])])["unresolved"] == []


def test_titles_say_how_many_cves_and_how_many_other_advisories():
    f = opnsense_cves.fixes_phrase
    assert [f(0, 0), f(1, 0), f(3, 0), f(27, 2), f(3, 1), f(0, 1), f(0, 11)] == [
        "0 CVEs", "1 CVE", "3 CVEs", "27 CVEs and 2 other security advisories", "3 CVEs and 1 other security advisory",
        "1 security advisory", "11 security advisories"]
    h = opnsense_cves.headline
    assert h(5, 2, adv=3) == "Fixes 5 CVEs (2 known exploited) and 3 other security advisories"
    assert h(5, 0) == "Fixes 5 CVEs" and h(0, 0, adv=2) == "Fixes 2 security advisories"
    assert h(1, 1, lower=True, adv=1) == "fixes 1 CVE (1 known exploited) and 1 other security advisory"


# 26.7.10's FreeBSD advisories 74 to 82 and its two GitHub advisories: 11 advisories, and no CVE id anywhere in the file.
SA_NAMES = [r for r in fake.SA if r.startswith("26:") and 74 <= int(r[3:5]) <= 82]


def eleven():
    refs = [f"FREEBSD-SA:{r}" for r in SA_NAMES] + [GH_1, GH_2]
    bullets = [f"src: advisory number {i}[{i}]" for i in range(1, 10)] + ["interfaces: PPP[10]", "firmware: flavour[11]"]
    return new_release("26.7.11", bullets, refs), refs


def test_a_26_7_10_style_release_with_no_cve_id_and_11_advisories_reads_as_a_security_release(tmp_path):
    extra, refs = eleven()
    assert len(refs) == 11 and len(SA_NAMES) == 9
    fw = idle("26.7.10", latest="26.7.10")
    # Neither site answers: all 11 are advisories with no CVE, GitHub's rating is not known: Medium.
    down = {fake.SA_HOST: lambda r: httpx.Response(503), fake.GH_HOST: lambda r: httpx.Response(503)}
    cfg, conn, c = world(tmp_path, fw, extra, override=down)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    assert cves["unseen"]["plan"]["offered"] == "26.7.11" and not cves["unseen"]["cves"] and len(cves["unseen"]["advisories"]) == 11
    f = got[0]
    assert f.title == "26.7.11 is out (fixes 11 security advisories); the firewall hasn't checked since Nov 18"
    assert f.severity == "medium"
    assert "fixes security advisories named in OPNsense's changelog" in f.detail and "11 security advisories (FreeBSD and GitHub) name no CVE yet" in f.detail
    assert "Updating to 26.7.11 fixes 0" not in f.detail and f.basis == "26.7.11"


def test_the_same_release_with_the_sites_answering_names_the_cves_and_keeps_the_two_github_advisories(tmp_path):
    extra, _refs = eleven()
    fw = idle("26.7.10", latest="26.7.10")
    cfg, conn, _c = world(tmp_path, fw, extra)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    n = sum(len(fake.SA_CVES[r]) for r in SA_NAMES)
    assert n == 11 and len(cves["unseen"]["cves"]) == n
    f = got[0]
    assert f.title == f"26.7.11 is out (fixes {n} CVEs and 2 other security advisories); the firewall hasn't checked since Nov 18"
    assert f.severity == "high" and "GitHub rates 2 of them High or Critical" in f.detail      # GitHub: High, no CVE id
    # GitHub says Medium for them and the CVEs rank no higher: Medium.
    weak = {fake.GH_HOST: lambda r: httpx.Response(200, json={**json.loads((FIX / ("GHSA-" + r.url.path.split("GHSA-")[1] + ".json")).read_text()), "severity": "medium"})}
    (tmp_path / "w").mkdir()
    cfg2, conn2, _c2 = world(tmp_path / "w", fw, extra, override=weak)
    got2, _ = unseen_findings(cfg2, conn2, fw, LC_TS + 3 * DAY)
    assert got2[0].severity == "medium"


def test_the_updates_finding_and_the_unseen_finding_use_the_same_summary_with_advisories(tmp_path):
    pend = firmware(to="26.7.10", frm="26.7.9_3", last_check=LC)
    cfg, conn, c = make(tmp_path, pend, serve(tmp_path))
    asyncio.run(c.run_once(NOW))
    cves = opnsense_cves.load(cfg, conn, "fw1", pend)
    assert cves["state"] == "ok" and len(cves["cves"]) == 25 and len(cves["advisories"]) == 23
    f = [x for x in rules.firmware_rules(pend, NOW, cves) if x.rule == "opnsense.updates"][0]
    assert f.severity == "high" and f.title.endswith("fixes 25 CVEs and 2 other security advisories")
    assert "Updating to 26.7.10 fixes 25 CVEs" in f.detail and "2 security advisories (FreeBSD and GitHub) name no CVE yet" in f.detail
    # The basis carries the advisories that name no CVE: one that gets a CVE changes it (a new finding for an accepted one).
    s = store.connect(cfg.cve_db_path)
    s.execute("UPDATE opn_adv SET cves = '[\"CVE-2026-777777\"]' WHERE ref = ?", (GH_1,))
    s.close()
    again = opnsense_cves.load(cfg, conn, "fw1", pend)
    f2 = [x for x in rules.firmware_rules(pend, NOW, again) if x.rule == "opnsense.updates"][0]
    assert f2.basis != f.basis and "1 other security advisory" in f2.title


def test_errata_and_plugin_notes_alone_do_not_make_a_security_release(tmp_path):
    extra = new_release("26.7.11", ["src: tzdata: import tzdata 2026f[1]", "plugins: os-caddy 2.2.4[2]", "ports: php 8.5.13[3]"],
                        ["FREEBSD-EN:26:29.tzdata", "PLUGINS:26.7/www/caddy", "PHP8:8.5.13"])
    fw = idle("26.7.10", latest="26.7.10")
    cfg, conn, _c = world(tmp_path, fw, extra)
    got, cves = unseen_findings(cfg, conn, fw, LC_TS + 3 * DAY)
    assert got[0].title == "26.7.11 is out; the firewall hasn't checked since Nov 18" and got[0].severity == "low"
    assert cves["unseen"]["advisories"] == [] and cves["unseen"]["cves"] == []


# --- the card -----------------------------------------------------------------------------------------------------------------

def test_the_card_lists_each_advisory_with_its_cves_or_no_cve_published_and_links_it(page):
    client, cfg, conn, _fake = page
    put_firmware(conn, idle("26.7.9_3", latest="26.7.9"))
    read_cves(cfg, conn, now=time.time())
    html = client.get("/h/fw1/").text
    card = html.split('id="firmware-unseen"')[1].split("</section>")[0]
    assert "26.7.10 is out (fixes 25 CVEs and 2 other security advisories)" in card
    assert "23 security advisories in the changelog; 2 with no CVE yet, not ranked." in card
    assert 'href="https://www.freebsd.org/security/advisories/FreeBSD-SA-26:74.ktls.asc"' in card and ">FreeBSD-SA-26:74.ktls</a>, in 26.7.10:" in card
    assert 'href="https://www.cve.org/cverecord?id=CVE-2026-101313"' in card
    assert 'href="https://github.com/opnsense/core/security/advisories/GHSA-f35q-c34m-pfw3"' in card and "no CVE published" in card
    assert "GitHub rates it high, CVSS 7.2" in card
    # The CVE table names the advisory a CVE came through.
    assert "via <a" in card and ">FreeBSD-SA-26:76.ocs_fc</a>" in card
    assert 'id="src-fw-unseen"' in html and "FreeBSD advisories" in html and "GitHub advisories" in html
    from .test_provenance import check_panels
    check_panels(html)


def test_the_card_says_a_lookup_is_pending_or_failed(page):
    client, cfg, conn, _fake = page
    put_firmware(conn, idle("26.7.9_3", latest="26.7.9"))
    down = serve(Path(cfg.data_dir).parent, override={fake.SA_HOST: lambda r: httpx.Response(500), fake.GH_HOST: lambda r: httpx.Response(500)})
    read_cves(cfg, conn, down, now=time.time())
    card = client.get("/h/fw1/").text.split('id="firmware-unseen"')[1].split("</section>")[0]
    assert "26.7.10 is out (fixes 23 security advisories)" in card and "23 security advisories in the changelog; 23 with no CVE yet" in card
    assert card.count("CVE lookup failed, tried again later") == 23
    # A row that was never asked (the chore has not reached it) says pending.
    s = store.connect(cfg.cve_db_path)
    s.execute("DELETE FROM opn_adv WHERE ref = ?", (SA_74,))
    s.close()
    card = client.get("/h/fw1/").text.split('id="firmware-unseen"')[1].split("</section>")[0]
    assert "CVE lookup pending" in card


def test_the_changelog_dropped_with_the_last_firewall_keeps_the_answers_it_was_given(tmp_path):
    fw = idle("26.7.9_3", latest="26.7.9")
    cfg, conn, c = world(tmp_path, fw)
    assert len(cdb_rows(cfg, "opn_adv")) == 23
    conn.execute("UPDATE remotes SET enabled = 0 WHERE id = 'fw1'")
    asyncio.run(c.run_once(NOW + 10))
    assert cdb_rows(cfg, "opn_fix") == [] and len(cdb_rows(cfg, "opn_adv")) == 23        # immutable, tiny: never asked for twice
