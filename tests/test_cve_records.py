"""CISA's SSVC ratings from the CVE Services record of each matched CVE (cve/records.py): the shape it reads, what it asks for, the
cache and its refetch rules, the rate limit, the size cap and a record that has no CISA-ADP container."""

import asyncio
import json

import httpx
import pytest

from daemonsight.cve import match, records, store

from . import fake_cve_services as fake

DAY = 86400
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def reset_fake():
    fake.CALLS.clear()
    fake.OVERRIDE.clear()
    saved = (dict(fake.RATINGS), dict(fake.CVSS))
    yield
    fake.RATINGS.clear(); fake.RATINGS.update(saved[0])
    fake.CVSS.clear(); fake.CVSS.update(saved[1])


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "cve.db")
    yield c
    c.close()


def matched(conn, *cves, state="fix", host="h"):
    for cve in cves:
        conn.execute("INSERT OR REPLACE INTO match (host, source, cve, state) VALUES (?, 'pkg', ?, ?)", (host, cve, state))


def client(seen=None):
    def handler(request):
        if seen is not None:
            seen.append(request)
        return fake.handler(request) or httpx.Response(500)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(conn, now=NOW, cl=None, **kw):
    return asyncio.run(records.resolve(conn, now, cl or client(), **kw))


def row(conn, cve):
    r = conn.execute("SELECT * FROM cve_record WHERE cve = ?", (cve,)).fetchone()
    return dict(r) if r else None


# --- the record ------------------------------------------------------------------------------------------------------------------

def test_the_ssvc_rating_and_cvss_are_read_from_the_cisa_adp_container():
    got = records.parse("CVE-2026-111497", fake.record("CVE-2026-111497", ("active", "no", "total"), fake.CVSS["CVE-2026-111497"]))
    assert got == {"exploitation": "active", "automatable": "no", "impact": "total", "ssvc_at": "2026-11-20T12:00:00.000000Z",
                   "cvss_score": 9.3, "cvss_vector": fake.CVSS["CVE-2026-111497"][2], "cvss_source": "CNA"}


def test_a_record_without_a_cisa_adp_container_keeps_no_rating():
    got = records.parse("CVE-2026-5005", fake.record("CVE-2026-5005", None, ("cvssV3_1", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")))
    assert (got["automatable"], got["impact"], got["exploitation"]) == (None, None, None) and got["cvss_score"] == 7.5
    other = records.parse("CVE-2026-5005", fake.record("CVE-2026-5005", ("active", "yes", "total"), adp_name="Some-Other-ADP"))
    assert other["automatable"] is None                 # only CISA's container counts
    cna_less = fake.record("CVE-2026-5005", ("none", "yes", "partial"))
    del cna_less["containers"]["cna"]
    assert records.parse("CVE-2026-5005", cna_less)["impact"] == "partial"


def test_the_cvss_comes_from_the_cna_first_then_cisa_and_the_newest_version():
    d = fake.record("CVE-2026-5005", ("none", "no", "partial"))
    d["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": 5.0, "vectorString": "v31"}}, {"cvssV4_0": {"baseScore": 6.0, "vectorString": "v4"}}]
    d["containers"]["adp"][0]["metrics"].append({"cvssV3_1": {"baseScore": 9.8, "vectorString": "adp"}})
    assert records.parse("CVE-2026-5005", d)["cvss_score"] == 6.0 and records.parse("CVE-2026-5005", d)["cvss_source"] == "CNA"
    del d["containers"]["cna"]["metrics"]
    got = records.parse("CVE-2026-5005", d)
    assert (got["cvss_score"], got["cvss_source"]) == (9.8, "CISA-ADP")


@pytest.mark.parametrize("doc", [[], {}, {"cveMetadata": {"cveId": "CVE-2026-9"}}, {"cveMetadata": []}])
def test_a_document_that_is_not_that_cves_record_is_refused(doc):
    with pytest.raises(records.FetchError):
        records.parse("CVE-2026-5005", doc)


def test_junk_values_are_dropped_not_kept():
    d = fake.record("CVE-2026-5005", ("active", "maybe", "huge"))
    got = records.parse("CVE-2026-5005", d)
    assert (got["exploitation"], got["automatable"], got["impact"]) == ("active", None, None)
    d["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": 99, "vectorString": "x"}}]
    assert records.parse("CVE-2026-5005", d)["cvss_score"] is None


# --- asking ---------------------------------------------------------------------------------------------------------------------

def test_only_matched_cves_are_asked_for_and_the_answer_is_kept(conn):
    matched(conn, "CVE-2026-111497")
    matched(conn, "CVE-2020-0001", state="minor")           # not shown, so not asked
    seen = []
    got = run(conn, cl=client(seen))
    assert got == {"asked": 1, "read": 1, "absent": 0, "failed": 0, "waiting": 0}
    assert [str(r.url) for r in seen] == ["https://cveawg.mitre.org/api/cve/CVE-2026-111497"]
    assert seen[0].headers["user-agent"].startswith("DaemonSight/") and seen[0].method == "GET"
    r = row(conn, "CVE-2026-111497")
    assert (r["status"], r["automatable"], r["impact"], r["exploitation"], r["cvss_score"], r["fetched_at"]) == ("ok", "no", "total", "active", 9.3, NOW)
    assert r["kev"] == 0
    # The host_cves join carries the rating to the matcher.
    c = next(x for x in match.host_cves(conn, "h") if x["cve"] == "CVE-2026-111497")
    assert (c["automatable"], c["impact"], c["cvss_score"], c["cvss_source"]) == ("no", "total", 9.3, "CNA")


def test_a_cached_record_is_not_asked_for_again_until_seven_days_pass(conn):
    matched(conn, "CVE-2026-111497")
    run(conn)
    assert run(conn, NOW + 3600)["asked"] == 0 and run(conn, NOW + 7 * DAY - 10)["asked"] == 0
    assert fake.CALLS == ["CVE-2026-111497"]
    assert run(conn, NOW + 7 * DAY + 10)["read"] == 1 and len(fake.CALLS) == 2
    assert row(conn, "CVE-2026-111497")["fetched_at"] == NOW + 7 * DAY + 10
    # A CVE no host matches any more is left alone, however old.
    conn.execute("DELETE FROM match")
    assert run(conn, NOW + 30 * DAY)["asked"] == 0


def test_a_change_of_kev_status_asks_again_at_once(conn):
    matched(conn, "CVE-2026-111497")
    run(conn)
    conn.execute("INSERT INTO kev (cve, vendor, product, name, added, ransomware) VALUES ('CVE-2026-111497', 'g', 'p', 'n', '2026-11-20', 'Unknown')")
    assert run(conn, NOW + 60)["read"] == 1 and row(conn, "CVE-2026-111497")["kev"] == 1
    assert run(conn, NOW + 120)["asked"] == 0                       # now it matches what was read
    conn.execute("DELETE FROM kev")
    assert run(conn, NOW + 180)["read"] == 1 and row(conn, "CVE-2026-111497")["kev"] == 0


def test_a_cve_with_no_record_is_remembered_and_asked_again_after_a_day(conn):
    matched(conn, "CVE-2026-7770")
    assert run(conn)["absent"] == 1 and row(conn, "CVE-2026-7770")["status"] == "absent"
    assert run(conn, NOW + DAY - 10)["asked"] == 0
    fake.RATINGS["CVE-2026-7770"] = ("none", "yes", "total")           # the service has it now
    assert run(conn, NOW + DAY + 10)["read"] == 1
    assert (row(conn, "CVE-2026-7770")["status"], row(conn, "CVE-2026-7770")["automatable"]) == ("ok", "yes")


def test_a_record_with_no_cisa_container_is_kept_as_read_without_a_rating(conn):
    matched(conn, "CVE-2026-8880")
    fake.CVSS["CVE-2026-8880"] = ("cvssV3_1", 5.5, "v")
    run(conn)
    r = row(conn, "CVE-2026-8880")
    assert (r["status"], r["automatable"], r["impact"], r["cvss_score"]) == ("ok", None, None, 5.5)
    assert run(conn, NOW + 3600)["asked"] == 0                         # not asked every pass because CISA has not rated it


def test_a_failed_ask_is_tried_again_after_an_hour_and_never_loses_a_kept_record(conn):
    matched(conn, "CVE-2026-111497")
    fake.OVERRIDE["CVE-2026-111497"] = httpx.Response(200, content=b"not json")
    assert run(conn)["failed"] == 1 and row(conn, "CVE-2026-111497")["status"] == "error"
    assert run(conn, NOW + 1800)["asked"] == 0
    fake.OVERRIDE.clear()
    assert run(conn, NOW + 3601)["read"] == 1 and row(conn, "CVE-2026-111497")["status"] == "ok"
    # A failed refresh of a kept record keeps what it knew.
    fake.OVERRIDE["CVE-2026-111497"] = httpx.Response(200, content=b"{}")
    got = run(conn, NOW + 3601 + 8 * DAY)
    assert got["failed"] == 1
    r = row(conn, "CVE-2026-111497")
    assert (r["status"], r["automatable"]) == ("ok", "no") and r["tried_at"] == NOW + 3601 + 8 * DAY


def test_the_first_fill_is_spread_over_passes_and_the_most_important_come_first(conn):
    cves = [f"CVE-2026-{n}" for n in range(1000, 1010)]
    matched(conn, *cves)
    conn.execute("INSERT INTO kev (cve, vendor, product, name, added, ransomware) VALUES ('CVE-2026-1009', 'g', 'p', 'n', 'd', 'Unknown')")
    conn.execute("INSERT INTO epss (cve, score, pct) VALUES ('CVE-2026-1004', 0.9, 0.99)")
    assert run(conn, per_pass=4) == {"asked": 4, "read": 0, "absent": 4, "failed": 0, "waiting": 6}
    assert fake.CALLS[:2] == ["CVE-2026-1009", "CVE-2026-1004"]          # KEV first, then the higher EPSS
    run(conn, NOW + 1, per_pass=4)
    assert run(conn, NOW + 2, per_pass=4)["waiting"] == 0 and len(fake.CALLS) == 10
    assert run(conn, NOW + 3, per_pass=4)["asked"] == 0
    # The time budget ends a pass as well.
    conn.execute("DELETE FROM cve_record")
    ticks = iter(range(0, 1000, 10))
    got = run(conn, NOW + 4, seconds=25, clock=lambda: next(ticks))
    assert 0 < got["asked"] < 10 and got["waiting"] == 10 - got["asked"]


# --- the service's limits --------------------------------------------------------------------------------------------------------

def test_a_429_stops_the_pass_and_nothing_is_asked_before_the_time_it_names(conn):
    matched(conn, "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003")
    fake.OVERRIDE["CVE-2026-1002"] = httpx.Response(429, headers={"ratelimit-reset": "300", "retry-after": "120"})
    got = run(conn)
    assert got["asked"] == 1 and got["waiting"] == 2 and fake.CALLS == ["CVE-2026-1001", "CVE-2026-1002"]
    assert row(conn, "CVE-2026-1002") is None and row(conn, "CVE-2026-1003") is None          # nothing recorded against them
    assert float(store.get_meta(conn, records.UNTIL_KEY)) == NOW + 120                  # Retry-After wins over RateLimit-Reset
    fake.CALLS.clear()
    assert run(conn, NOW + 60)["asked"] == 0 and fake.CALLS == []
    fake.OVERRIDE.clear()
    assert run(conn, NOW + 121)["asked"] == 2


def test_a_quota_nearly_used_stops_the_pass_until_the_reset(conn):
    matched(conn, "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003")
    fake.OVERRIDE["CVE-2026-1001"] = httpx.Response(404, headers={"ratelimit-remaining": "80", "ratelimit-reset": "42"})
    got = run(conn)
    assert got["asked"] == 1 and got["absent"] == 1 and got["waiting"] == 2
    assert float(store.get_meta(conn, records.UNTIL_KEY)) == NOW + 42 and fake.CALLS == ["CVE-2026-1001"]
    fake.OVERRIDE.clear()
    assert run(conn, NOW + 41)["asked"] == 0 and run(conn, NOW + 43)["asked"] == 2
    # Plenty left: no pause.
    matched(conn, "CVE-2026-1004")
    fake.OVERRIDE["CVE-2026-1004"] = httpx.Response(404, headers={"ratelimit-remaining": "24000", "ratelimit-reset": "42"})
    assert run(conn, NOW + 500)["waiting"] == 0


def test_a_server_error_pauses_without_marking_the_cve(conn):
    matched(conn, "CVE-2026-1001", "CVE-2026-1002")
    fake.OVERRIDE["CVE-2026-1001"] = httpx.Response(503)
    got = run(conn)
    assert got["asked"] == 0 and got["waiting"] == 2 and row(conn, "CVE-2026-1001") is None
    assert float(store.get_meta(conn, records.UNTIL_KEY)) == NOW + 60               # no header: a minute


def test_the_wait_is_bounded():
    assert records.wait_until({"retry-after": "1"}, 100.0) == 130.0                  # at least 30 seconds
    assert records.wait_until({"ratelimit-reset": "999999"}, 100.0) == 100.0 + records.WAIT_MAX
    assert records.wait_until({"retry-after": "x"}, 100.0) == 160.0


def test_a_record_over_one_megabyte_is_refused(conn):
    matched(conn, "CVE-2026-111497")
    fake.OVERRIDE["CVE-2026-111497"] = httpx.Response(200, content=b"x" * ((1 << 20) + 1))
    got = run(conn)
    assert got["failed"] == 1 and row(conn, "CVE-2026-111497")["detail"] == "the answer is larger than the limit"
    just = json.dumps({**fake.record("CVE-2026-111497", ("none", "no", "partial")), "pad": "y" * 900_000}).encode()
    assert len(just) < 1 << 20
    fake.OVERRIDE["CVE-2026-111497"] = httpx.Response(200, content=just)
    assert run(conn, NOW + 3601)["read"] == 1


def test_only_https_to_the_services_host_is_accepted_and_a_redirect_is_not_followed(conn):
    matched(conn, "CVE-2026-111497")
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://evil.example/x"})
    cl = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)   # even a client that would follow
    got = asyncio.run(records.resolve(conn, NOW, cl))
    assert got["failed"] == 1 and seen == ["https://cveawg.mitre.org/api/cve/CVE-2026-111497"]
    assert row(conn, "CVE-2026-111497")["detail"] == "HTTP 302"
    # An answer that comes from another host is refused whatever it says.
    other = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"{}")),
                              base_url="https://cveawg.mitre.org")
    assert records.URL.startswith("https://cveawg.mitre.org/") and records.HOST == "cveawg.mitre.org"
    with pytest.raises(records.FetchError, match="not the source"):
        asyncio.run(records._get(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))), "https://evil.example/x"))
    with pytest.raises(records.FetchError, match="not the source"):
        asyncio.run(records._get(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))), "http://cveawg.mitre.org/x"))
    asyncio.run(other.aclose())


def test_a_database_from_before_the_table_still_reads(tmp_path):
    path = tmp_path / "old.db"
    c = store.connect(path)
    c.execute("DROP TABLE cve_record")
    c.execute("PRAGMA user_version=5")
    matched(c, "CVE-2026-1001")
    c.close()
    r = store.connect_reader(path)
    assert records.cached(r) == {} and records.generation(r) == "rec:0:0"
    got = match.host_cves(r, "h")
    assert got[0]["automatable"] is None and got[0]["impact"] is None and got[0]["cvss_score"] is None
    r.close()
    c = store.connect(path)                                  # the chore migrates it
    assert c.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION == 6
    assert c.execute("SELECT COUNT(*) FROM cve_record").fetchone()[0] == 0
    c.close()
