"""The Shodan API source for the outside view: the key (file, permissions, redaction), the Source setting, Test key,
fetching and mapping a host lookup, the key-refused path, the Exposure columns, and backups.

The fake API answers with the shape Shodan documents for GET /shodan/host/{ip} (https://developer.shodan.io/api,
banner fields from https://datapedia.shodan.io/) and GET /api-info. No real key and no real request is used. The
InternetDB source must behave exactly as before, so some tests check that too.
"""

import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import backup, config, db, outside, settings, shodan
from daemonsight.web import provenance
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)
from .test_outside import PUBLIC, SHODAN_VPS, enabled, open_outside, run, section, seed
from .test_settings import CROSS, hub_events, login

KEY = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
OTHER = "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4"
SEEN = "2026-11-10T04:21:17.100000"
SEEN_EPOCH = datetime(2026, 11, 10, 4, 21, 17, 100000, tzinfo=timezone.utc).timestamp()


def banner(port, transport="tcp", product=None, version=None, ts=SEEN, **extra):
    b = {"_shodan": {"module": "https", "crawler": "c0ffee", "id": "x", "options": {}}, "hash": 1, "os": None,
         "opts": {}, "ip": 3405803786, "isp": "Example", "port": port, "hostnames": ["vps.example.net"],
         "location": {"city": None}, "timestamp": ts, "domains": [], "org": "Example", "data": "banner text",
         "asn": "AS64496", "transport": transport, "ip_str": PUBLIC}
    if product:
        b["product"] = product
    if version:
        b["version"] = version
    return {**b, **extra}


def host_reply(ip=PUBLIC):
    """GET /shodan/host/{ip}, the documented shape: top-level host fields and data[] banners."""
    return {
        "region_code": None, "ip": 3405803786, "postal_code": None, "country_code": "US", "city": None,
        "dma_code": None, "last_update": "2026-11-10T04:21:17.100000", "latitude": 37.751, "tags": ["cloud"],
        "area_code": None, "country_name": "United States", "hostnames": ["vps.example.net"], "org": "Example",
        "data": [
            banner(22, product="OpenSSH", version="9.2p1 Debian-2+deb12u3", cpe23=["cpe:2.3:a:openbsd:openssh:9.2p1"]),
            banner(80, product="nginx", version="1.24.0",
                   vulns={"CVE-2023-44487": {"verified": False, "references": [], "summary": "x"}}),
            banner(443, product="nginx", version="1.24.0", ts="2026-11-09T01:00:00.000000"),
            banner(443, "udp", ts="2026-11-08T01:00:00.000000"),
            banner(9123),
        ],
        "asn": "AS64496", "isp": "Example", "longitude": -97.822, "country_code3": None, "domains": [],
        "ip_str": ip, "os": None, "ports": [22, 80, 443, 9123]}


class FakeApi:
    """api.shodan.io and internetdb.shodan.io for tests, and every request seen."""

    def __init__(self, key=KEY, hosts=None, plan="dev", info_status=200, host_status=None, host_body=None):
        self.key = key
        self.hosts = {PUBLIC: host_reply()} if hosts is None else hosts
        self.plan, self.info_status, self.host_status, self.host_body = plan, info_status, host_status, host_body
        self.calls: list[httpx.Request] = []

    def client(self):
        def handler(request):
            self.calls.append(request)
            if request.url.host == "internetdb.shodan.io":
                return httpx.Response(200, json=SHODAN_VPS) if request.url.path == f"/{PUBLIC}" else \
                    httpx.Response(404, json={"detail": "No information available"})
            assert request.url.host == "api.shodan.io" and request.url.scheme == "https"
            if request.url.params.get("key") != self.key:
                return httpx.Response(401, json={"error": "Invalid API key"})
            if request.url.path == "/api-info":
                if self.info_status != 200:
                    return httpx.Response(self.info_status, json={"error": f"nope, key {self.key}"})
                return httpx.Response(200, json={"scan_credits": 100, "usage_limits": {"scan_credits": 100,
                                                 "query_credits": 100, "monitored_ips": 16}, "plan": self.plan,
                                                 "https": False, "unlocked": True, "query_credits": 97,
                                                 "monitored_ips": 3, "unlocked_left": 97, "telnet": False})
            ip = request.url.path.removeprefix("/shodan/host/")
            if self.host_status is not None:
                return httpx.Response(self.host_status, json=self.host_body)
            if ip not in self.hosts:
                return httpx.Response(404, json={"error": "No information available for that IP."})
            return httpx.Response(200, json=self.hosts[ip])
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)

    @property
    def api_calls(self):
        return [r for r in self.calls if r.url.host == "api.shodan.io"]


def shodan_cfg(cfg, **kw):
    enabled(cfg)
    cfg.outside.source = "shodan"
    for k, v in kw.items():
        setattr(cfg.outside, k, v)
    shodan.write_key(cfg, KEY)
    return cfg


def chore(cfg, conn, fake, gap=0):
    return outside.Chore(cfg, conn, fake.client(), gap=gap)


@pytest.fixture
def web(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    fake = FakeApi()
    c = login(TestClient(create_app(hub_cfg, outside_client=fake.client()), follow_redirects=False))
    yield c, conn, hub_cfg, fake
    conn.close()


def flash_of(c):
    """The notice the next page shows (settings page), as text."""
    html = c.get("/settings").text
    m = re.search(r'class="alert[^"]*"[^>]*role="[a-z]+"[^>]*>(.*?)</div>', html, re.S)
    return html, m.group(1) if m else ""


def dump(conn):
    return "\n".join(conn.iterdump())


def surfaces(c, conn, cfg):
    """Every place a key could leak to: the pages, the database, events and findings."""
    pages = [c.get(p).text for p in ("/settings", "/", "/h/testhost/", "/h/testhost/exposure", "/h/testhost/vulnerabilities")]
    raw = b"".join(p.read_bytes() for p in (cfg.db_path, *cfg.db_path.parent.glob("state.db-*")) if p.exists())
    return "\n".join(pages) + dump(conn) + raw.decode("latin-1")


# ---- the Source setting ---------------------------------------------------------------------------------

def test_the_source_defaults_to_internetdb_and_is_a_choice(hub_cfg):  # noqa: F811
    f = settings.BY_KEY["outside.source"]
    assert hub_cfg.outside.source == "internetdb" and settings.default_of(f) == "internetdb"
    assert f.kind == "choice" and [v for v, _ in f.choices] == ["internetdb", "shodan"]
    assert settings.parse(f, "shodan") == "shodan" and settings.parse(f, " internetdb ") == "internetdb"
    for bad in ("", "bing", "SHODAN", "shodan;x"):
        with pytest.raises(settings.Invalid):
            settings.parse(f, bad)
    with pytest.raises(settings.Invalid):
        settings.valid_stored(f, "bing")
    with pytest.raises(settings.Invalid):
        settings.valid_stored(f, 3)
    assert settings.show(f, "shodan") == "Shodan API (your key)"
    assert settings.show(f, "internetdb") == "InternetDB (free, non-commercial)"


def test_the_source_follows_override_then_config_file_then_default(hub_cfg, tmp_path):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    assert outside.source_of(settings.effective(hub_cfg, conn)) == "internetdb"
    f = tmp_path / "c.toml"
    f.write_text('[outside]\nsource = "shodan"\n')
    base = config.load(f)
    assert outside.source_of(settings.effective(base, conn)) == "shodan"
    by = {i["key"]: i for g in settings.describe(base, conn, True) for i in g["fields"]}
    assert by["outside.source"]["source"] == settings.FILE
    settings.save(conn, base, {"outside.source": "internetdb"}, "admin")
    assert outside.source_of(settings.effective(base, conn)) == "internetdb"
    assert hub_events(conn)[-1] == ("Setting changed: Outside view, source: Shodan API (your key) → "
                                    "InternetDB (free, non-commercial)")
    settings.reset(conn, base, "outside.source", "admin")
    assert outside.source_of(settings.effective(base, conn)) == "shodan"


def test_an_unknown_source_in_the_config_file_is_refused_loudly(tmp_path, caplog):
    f = tmp_path / "c.toml"
    f.write_text('[outside]\nsource = "bing"\n')
    with caplog.at_level(logging.WARNING):
        cfg = config.load(f)
    assert cfg.outside.source == "internetdb" and "unknown [outside] source" in caplog.text


def test_choosing_the_shodan_api_without_a_key_is_refused(web):
    c, conn, cfg, fake = web
    r = c.post("/settings", data={"group": "outside", "outside.enabled": "on", "outside.source": "shodan",
                                  "outside.refresh_hours": "24", "outside.addresses": ""})
    assert r.status_code == 400 and "No Shodan API key is saved" in r.text
    assert "outside.source" not in {x["key"] for x in conn.execute("SELECT key FROM settings")}
    shodan.write_key(cfg, KEY)
    r = c.post("/settings", data={"group": "outside", "outside.enabled": "on", "outside.source": "shodan",
                                  "outside.refresh_hours": "24", "outside.addresses": ""})
    assert r.status_code == 303
    assert settings.effective(cfg, conn).outside.source == "shodan"
    assert any("source" in t and "Shodan API" in t for t in hub_events(conn))


def test_the_settings_page_offers_both_sources_and_the_guide(web):
    c, conn, cfg, fake = web
    html = c.get("/settings").text
    assert 'name="outside.source"' in html
    assert "InternetDB (free, non-commercial)" in html and "Shodan API (your key)" in html
    assert "Getting a Shodan API key" in html
    for href in ("https://account.shodan.io/", "https://developer.shodan.io/pricing", "https://developer.shodan.io/api"):
        m = re.search(rf'<a href="{re.escape(href)}"[^>]*>', html)
        assert m and 'target="_blank"' in m.group(0) and 'rel="noopener noreferrer"' in m.group(0)
    assert "Freelancer, Small" in html and "as long as the data is attributed to Shodan" in html
    assert "Membership" in html and "No key saved" in html and "Test key" in html


# ---- the key file ----------------------------------------------------------------------------------------

def test_saving_a_key_writes_a_0600_file_and_nothing_else(web):
    c, conn, cfg, fake = web
    r = c.post("/settings/shodan-key", data={"action": "save", "key": KEY})
    assert r.status_code == 303 and r.headers["location"] == "/settings#outside"
    path = cfg.shodan_key_path
    assert path == cfg.db_path.parent / "shodan.key"
    assert path.read_text().strip() == KEY and oct(path.stat().st_mode & 0o777) == "0o600"
    assert not list(path.parent.glob("*.tmp"))
    assert "Shodan API key saved" in hub_events(conn)
    assert KEY not in surfaces(c, conn, cfg)
    html = c.get("/settings").text
    assert "A key is saved" in html and "Replace the key" in html and "Remove key" in html and KEY not in html


def test_the_key_is_replaced_and_removed(web):
    c, conn, cfg, fake = web
    c.post("/settings/shodan-key", data={"action": "save", "key": KEY})
    c.post("/settings/shodan-key", data={"action": "save", "key": OTHER})
    assert shodan.read_key(cfg) == OTHER
    r = c.post("/settings/shodan-key", data={"action": "remove"})
    assert r.status_code == 303 and not cfg.shodan_key_path.exists()
    assert hub_events(conn).count("Shodan API key saved") == 2 and hub_events(conn)[-1] == "Shodan API key removed"
    assert "No key saved" in c.get("/settings").text
    for e in hub_events(conn):
        assert KEY not in e and OTHER not in e


def test_the_key_cannot_be_removed_while_the_shodan_api_is_the_source(web):
    c, conn, cfg, fake = web
    shodan_cfg(cfg)
    settings.save(conn, cfg, {"outside.source": "shodan"}, "admin")
    c.post("/settings/shodan-key", data={"action": "remove"})
    assert shodan.read_key(cfg) == KEY
    assert "Set Source back to InternetDB" in c.get("/settings").text
    settings.save(conn, cfg, {"outside.source": "internetdb"}, "admin")
    c.post("/settings/shodan-key", data={"action": "remove"})
    assert not cfg.shodan_key_path.exists()


@pytest.mark.parametrize("bad", ["", "short", "has space in it 12345678", "a" * 200, "key=value&x=1_____",
                                 "../../etc/passwd___", "new\nline1234567890"])
def test_a_key_that_cannot_be_one_is_refused(web, bad):
    c, conn, cfg, fake = web
    c.post("/settings/shodan-key", data={"action": "save", "key": bad})
    assert not cfg.shodan_key_path.exists()
    assert "does not look like a Shodan API key" in c.get("/settings").text
    assert "Shodan API key saved" not in hub_events(conn)


def test_the_key_file_can_be_set_in_the_config_file(hub_cfg, tmp_path):  # noqa: F811
    hub_cfg.outside.key_file = str(tmp_path / "elsewhere" / "k")
    assert hub_cfg.shodan_key_path == tmp_path / "elsewhere" / "k"
    shodan.write_key(hub_cfg, KEY)
    assert shodan.read_key(hub_cfg) == KEY and oct(hub_cfg.shodan_key_path.stat().st_mode & 0o777) == "0o600"
    assert settings.read_only(hub_cfg)[[r["key"] for r in settings.read_only(hub_cfg)].index("shodan_key_path")][
        "value"] == str(tmp_path / "elsewhere" / "k")


def test_the_key_routes_need_the_login_and_refuse_cross_site_posts(web, hub_cfg):  # noqa: F811
    c, conn, cfg, fake = web
    anon = TestClient(create_app(cfg, outside_client=fake.client()), follow_redirects=False)
    for action in ("save", "test", "remove"):
        r = anon.post("/settings/shodan-key", data={"action": action, "key": KEY})
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
        r = c.post("/settings/shodan-key", data={"action": action, "key": KEY}, headers=CROSS)
        assert r.status_code == 403
    assert not cfg.shodan_key_path.exists() and not fake.calls


# ---- Test key ---------------------------------------------------------------------------------------------

def test_test_key_shows_the_plan_and_credits_without_saving_a_typed_key(web):
    c, conn, cfg, fake = web
    r = c.post("/settings/shodan-key", data={"action": "test", "key": KEY})
    assert r.status_code == 303
    html, note = flash_of(c)
    assert "Shodan accepted the key" in note and "Plan: dev." in note and "Query credits left: 97." in note
    assert "not saved yet" in note and not cfg.shodan_key_path.exists()
    (call,) = fake.api_calls
    assert call.url.path == "/api-info" and call.url.params["key"] == KEY and not call.url.params.get("minify")
    assert KEY not in html + dump(conn)


def test_test_key_uses_the_saved_key_when_the_box_is_empty(web):
    c, conn, cfg, fake = web
    shodan.write_key(cfg, KEY)
    c.post("/settings/shodan-key", data={"action": "test", "key": ""})
    assert "Shodan accepted the key" in flash_of(c)[1] and fake.api_calls[0].url.params["key"] == KEY


def test_test_key_with_nothing_to_test_makes_no_request(web):
    c, conn, cfg, fake = web
    c.post("/settings/shodan-key", data={"action": "test", "key": ""})
    assert "Enter a key to test, or save one first" in flash_of(c)[1] and not fake.calls
    c.post("/settings/shodan-key", data={"action": "test", "key": "bad key!"})
    assert "does not look like a Shodan API key" in flash_of(c)[1] and not fake.calls


def test_test_key_says_when_shodan_refuses_the_key_and_never_echoes_it(web):
    c, conn, cfg, fake = web
    c.post("/settings/shodan-key", data={"action": "test", "key": OTHER})
    html, note = flash_of(c)
    assert "Shodan refused the API key (HTTP 401): Invalid API key" in note and "at least a Membership" in note
    assert OTHER not in html + dump(conn)
    # A server that echoes the key in its error text is redacted too.
    fake.info_status = 403
    c.post("/settings/shodan-key", data={"action": "test", "key": KEY})
    html, note = flash_of(c)
    assert "HTTP 403" in note and KEY not in html and "REDACTED" in note


def test_test_key_when_shodan_cannot_be_reached(web):
    c, conn, cfg, fake = web

    def boom(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}")
    app = create_app(cfg, outside_client=httpx.AsyncClient(transport=httpx.MockTransport(boom)))
    c2 = login(TestClient(app, follow_redirects=False))
    c2.post("/settings/shodan-key", data={"action": "test", "key": KEY})
    html = c2.get("/settings").text
    assert "Could not reach api.shodan.io: ConnectError" in html and KEY not in html


# ---- redaction ------------------------------------------------------------------------------------------

def test_redact_strips_the_key_parameter_and_any_given_secret():
    url = f"https://api.shodan.io/shodan/host/{PUBLIC}?key={KEY}&history=1"
    out = shodan.redact(f"ConnectError for {url}")
    assert KEY not in out and "key=REDACTED&history=1" in out
    assert shodan.redact(f"x {KEY} y", KEY) == "x REDACTED y"
    assert shodan.redact("KEY=abc123abc123 then Key=zzz") == "KEY=REDACTED then Key=REDACTED"


def test_httpx_request_lines_are_redacted_in_the_log(caplog):
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="httpx")
    fake = FakeApi()
    res = run(outside.fetch_shodan(fake.client(), PUBLIC, KEY))
    assert res.status == "ok"
    assert "HTTP Request" in caplog.text and "key=REDACTED" in caplog.text and KEY not in caplog.text
    info = run(shodan.api_info(fake.client(), KEY))
    assert info.ok and KEY not in caplog.text


def test_a_transport_error_that_names_the_url_is_redacted():
    def boom(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}")
    client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    res = run(outside.fetch_shodan(client, PUBLIC, KEY))
    assert res.status == "error" and KEY not in res.error and "ConnectError" in res.error and "REDACTED" in res.error


# ---- fetching and mapping ---------------------------------------------------------------------------------

def test_the_host_lookup_request_is_a_full_https_get_with_the_key_as_a_parameter_only(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg)
    fake = FakeApi()
    assert run(chore(hub_cfg, conn, fake).run_once()) == 1
    (req,) = fake.calls
    assert req.method == "GET" and req.url.scheme == "https" and req.url.host == "api.shodan.io"
    assert req.url.path == f"/shodan/host/{PUBLIC}"
    # No minify: the minified answer has "no banners", so no per-port transport or time.
    assert dict(req.url.params) == {"key": KEY}
    assert KEY not in "".join(f"{k}: {v}" for k, v in req.headers.items())
    assert req.headers["user-agent"] == f"DaemonSight/{outside.__version__}"


def test_the_documented_reply_maps_to_the_internal_shape():
    data = outside.clean_host(host_reply())
    assert data["source"] == "shodan" and data["ports"] == [22, 80, 443, 9123]
    by = {(s["port"], s["transport"]): s for s in data["services"]}
    assert set(by) == {(22, "tcp"), (80, "tcp"), (443, "tcp"), (443, "udp"), (9123, "tcp")}
    assert by[(22, "tcp")] == {"port": 22, "transport": "tcp", "product": "OpenSSH",
                               "version": "9.2p1 Debian-2+deb12u3", "seen": SEEN_EPOCH}
    assert by[(443, "udp")]["product"] is None and by[(443, "udp")]["transport"] == "udp"
    assert data["hostnames"] == ["vps.example.net"] and data["tags"] == ["cloud"]
    assert data["vulns"] == ["CVE-2023-44487"] and data["cpes"] == ["cpe:2.3:a:openbsd:openssh:9.2p1"]
    assert data["last_update"] == SEEN_EPOCH
    # The same keys the rules read from an InternetDB answer.
    assert {"ports", "cpes", "hostnames", "tags", "vulns"} <= set(data)


def test_the_documented_dns_example_is_udp():
    """The example in Shodan's own REST documentation for 8.8.8.8: port 53 over UDP."""
    doc = {"ip": 134744072, "ip_str": "8.8.8.8", "ports": [53], "hostnames": ["dns.google"], "tags": [],
           "last_update": "2021-01-22T08:49:35.190817",
           "data": [{"port": 53, "transport": "udp", "timestamp": "2021-01-22T08:49:35.190817",
                     "hostnames": ["dns.google"], "data": "\nRecursion: enabled", "hash": -553166942,
                     "_shodan": {"module": "dns-udp"}}]}
    data = outside.clean_host(doc)
    assert data["ports"] == [53] and data["services"][0]["transport"] == "udp"
    assert data["services"][0]["product"] is None


@pytest.mark.parametrize("payload", [[], "x", None, {"data": "no"}, {"ports": "22"}, {"hostnames": {"a": 1}}, {"tags": 3}])
def test_a_reply_that_is_not_the_documented_shape_is_refused(payload):
    assert outside.clean_host(payload) is None


def test_junk_inside_a_good_reply_is_dropped_not_trusted():
    junk = host_reply()
    junk["data"] += [banner(70000), banner(-1), banner(True), banner(25, "TCP\nX"), "x", banner(26, ts="yesterday"),
                     banner(27, product="x" * 500, version="a\x00b"), {"port": 28}]
    junk["ports"] = [22, 70000, "80", None, 22]
    junk["vulns"] = ["CVE-2024-0001", "nonsense", "CVE-2024-0001"]
    junk["tags"] = ["cloud", "bad tag!", "<script>"]
    data = outside.clean_host(junk)
    assert data["ports"] == [22] and data["tags"] == ["cloud"] and "CVE-2024-0001" in data["vulns"]
    ports = {s["port"] for s in data["services"]}
    assert 26 in ports and 27 in ports and not ports & {70000, 25, 28}
    s27 = next(s for s in data["services"] if s["port"] == 27)
    assert s27["product"] is None and s27["version"] is None
    assert next(s for s in data["services"] if s["port"] == 26)["seen"] is None


def test_the_chore_stores_the_mapped_answer_and_opens_the_same_findings(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg)
    fake = FakeApi()
    run(chore(hub_cfg, conn, fake).run_once())
    row = outside.get_rows(conn)[PUBLIC]
    assert row["status"] == "ok" and row["data"]["source"] == "shodan" and row["data"]["ports"] == [22, 80, 443, 9123]
    found = open_outside(conn)
    assert ("outside.unexpected_port", f"{PUBLIC} 9123") in found and ("outside.vulns", PUBLIC) in found
    assert ("outside.unexpected_port", f"{PUBLIC} 22") not in found
    assert KEY not in dump(conn)


def test_a_404_means_shodan_has_no_record(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg)
    run(chore(hub_cfg, conn, FakeApi(hosts={})).run_once())
    row = outside.get_rows(conn)[PUBLIC]
    assert row["status"] == "none" and row["error"] is None and row["data"]["source"] == "shodan"
    assert ("outside.not_seen", f"{PUBLIC} 22") in open_outside(conn)


def test_requests_are_one_per_address_and_spaced(hub_cfg, token, monkeypatch):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg, addresses=["203.0.113.20=testhost", "203.0.113.21=testhost"])
    fake = FakeApi(hosts={PUBLIC: host_reply(), "203.0.113.20": host_reply("203.0.113.20")})
    naps = []

    async def nap(seconds):
        naps.append(seconds)
    monkeypatch.setattr(outside.asyncio, "sleep", nap)
    assert run(chore(hub_cfg, conn, fake, gap=None).run_once()) == 3
    assert [r.url.path for r in fake.api_calls] == [f"/shodan/host/{ip}" for ip in (PUBLIC, "203.0.113.20", "203.0.113.21")]
    assert naps == [shodan.RATE_LIMIT_GAP] * 2 and shodan.RATE_LIMIT_GAP > 1.0     # documented limit: 1 request a second
    # Nothing is due on the next pass.
    assert run(chore(hub_cfg, conn, fake, gap=None).run_once()) == 0


def test_a_429_pauses_the_pass(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg, addresses=["203.0.113.20=testhost"])
    fake = FakeApi(host_status=429, host_body={"error": "slow down"})
    ch = chore(hub_cfg, conn, fake)
    assert run(ch.run_once()) == 1 and ch.paused_until > time.time()
    row = outside.get_rows(conn)[PUBLIC]
    assert row["status"] == "error" and "HTTP 429" in row["error"] and KEY not in row["error"]
    assert run(ch.run_once()) == 0


def test_a_redirect_is_never_followed_so_the_key_cannot_leave(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg)
    seen = []

    def handler(request):
        seen.append(str(request.url.host))
        return httpx.Response(302, headers={"location": f"https://evil.example/?key={KEY}"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    run(outside.Chore(hub_cfg, conn, client, gap=0).run_once())
    assert seen == ["api.shodan.io"]
    assert outside.get_rows(conn)[PUBLIC]["error"] == "HTTP 302"


# ---- a refused key -----------------------------------------------------------------------------------------

def refused_setup(hub_cfg, code=401):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg, addresses=["203.0.113.20=testhost"])
    fake = FakeApi(key=OTHER)              # the saved key (KEY) is not the one the server accepts
    if code != 401:
        fake.key = KEY
        fake.host_status, fake.host_body = code, {"error": f"Access denied, key {KEY}"}
    return conn, fake


@pytest.mark.parametrize("code", [401, 403])
def test_a_refused_key_is_one_finding_and_one_request_and_no_fallback(hub_cfg, token, code):  # noqa: F811
    conn, fake = refused_setup(hub_cfg, code)
    ch = chore(hub_cfg, conn, fake)
    assert run(ch.run_once()) == 1                   # the second address is not even asked
    assert [r.url.host for r in fake.calls] == ["api.shodan.io"]       # and InternetDB is not asked instead
    f = open_outside(conn)
    key_findings = {k: v for k, v in f.items() if k[0] == "outside.key"}
    assert set(key_findings) == {("outside.key", "shodan")}          # one for the host, not one per address
    finding = key_findings[("outside.key", "shodan")]
    assert finding["title"].startswith("Shodan refused the API key") and finding["severity"] == "medium"
    assert "does not fall back to InternetDB" in finding["detail"] and f"HTTP {code}" in finding["detail"]
    text = dump(conn) + str([dict(r) for r in conn.execute("SELECT * FROM events")])
    assert KEY not in text and OTHER not in text
    opened = [r["title"] for r in conn.execute("SELECT title FROM events WHERE kind = 'finding_opened' "
                                               "AND title LIKE 'Shodan refused%'")]
    assert len(opened) == 1                          # one event, not one per pass
    run(ch.run_once())
    run(ch.run_once())
    assert len([r["title"] for r in conn.execute("SELECT title FROM events WHERE title LIKE 'Shodan refused%'")]) == 1
    assert len(fake.api_calls) == 1                  # and no request is repeated within the hour
    for row in outside.get_rows(conn).values():
        assert row["error"].startswith(shodan.KEY_REFUSED) and row["status"] == "error"


def test_a_new_key_is_tried_at_once_and_the_finding_clears(hub_cfg, token):  # noqa: F811
    conn, fake = refused_setup(hub_cfg)
    ch = chore(hub_cfg, conn, fake)
    run(ch.run_once())
    assert any(k[0] == "outside.key" for k in open_outside(conn))
    shodan.write_key(hub_cfg, OTHER)
    assert run(ch.run_once()) == 2
    f = open_outside(conn)
    assert not any(k[0] == "outside.key" for k in f) and ("outside.unexpected_port", f"{PUBLIC} 9123") in f
    assert all(r["error"] is None for r in outside.get_rows(conn).values())
    assert any(r["title"].startswith("Resolved: Shodan refused") for r in conn.execute("SELECT title FROM events"))


def test_no_credits_is_reported_and_stops_the_pass(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    shodan_cfg(hub_cfg, addresses=["203.0.113.20=testhost"])
    fake = FakeApi(host_status=402, host_body={"error": "Insufficient query credits"})
    assert run(chore(hub_cfg, conn, fake).run_once()) == 1
    key_f = [v for k, v in open_outside(conn).items() if k[0] == "outside.key"]
    assert key_f and key_f[0]["title"].startswith("Shodan has no query credits left")
    assert "Insufficient query credits" in key_f[0]["detail"]


def test_the_shodan_source_without_a_saved_key_says_so_and_asks_nobody(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    hub_cfg.outside.source = "shodan"        # as a hand-edited config file could say
    fake = FakeApi()
    assert run(chore(hub_cfg, conn, fake).run_once()) == 0 and not fake.calls
    f = open_outside(conn)
    (kf,) = [v for k, v in f.items() if k[0] == "outside.key"]
    assert "no key is saved" in kf["title"] and "Settings" in kf["howto"]
    # Saving a key fixes it on the next pass, with no wait.
    shodan.write_key(hub_cfg, KEY)
    ch = chore(hub_cfg, conn, fake)
    assert run(ch.run_once()) == 1
    assert not any(k[0] == "outside.key" for k in open_outside(conn))


# ---- switching sources -------------------------------------------------------------------------------------

def test_switching_the_source_refetches_at_once_and_the_internetdb_path_is_unchanged(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    shodan.write_key(hub_cfg, KEY)             # a saved key, with InternetDB selected: the key is not used
    fake = FakeApi()
    run(chore(hub_cfg, conn, fake).run_once())
    (req,) = fake.calls
    assert str(req.url) == f"https://internetdb.shodan.io/{PUBLIC}" and KEY not in str(req.headers) + str(req.url)
    assert "services" not in outside.get_rows(conn)[PUBLIC]["data"] and "source" not in outside.get_rows(conn)[PUBLIC]["data"]
    hub_cfg.outside.source = "shodan"
    run(chore(hub_cfg, conn, fake).run_once())
    assert fake.calls[-1].url.host == "api.shodan.io" and outside.get_rows(conn)[PUBLIC]["data"]["source"] == "shodan"
    hub_cfg.outside.source = "internetdb"
    run(chore(hub_cfg, conn, fake).run_once())
    assert fake.calls[-1].url.host == "internetdb.shodan.io" and "source" not in outside.get_rows(conn)[PUBLIC]["data"]


# ---- rules ------------------------------------------------------------------------------------------------

def rows_for(data):
    now = time.time()
    return {PUBLIC: {"ip": PUBLIC, "first_try": now - 100, "checked_at": now, "fetched_at": now, "status": "ok",
                     "data": data, "error": None}}


def findings(data, source="shodan"):
    from .test_outside import vps_snaps
    from daemonsight.config import ExposureConfig
    exp = ExposureConfig(expected_public=["22/tcp", "80/tcp", "443/tcp", "443/udp"])
    return {f.rule + "|" + f.key: f for f in outside.host_findings("testhost", rows_for(data), vps_snaps(), exp,
                                                                    time.time(), 24, None, source)}


def test_the_detail_names_what_shodan_saw_and_the_basis_ignores_dates():
    a = outside.clean_host(host_reply())
    later = host_reply()
    for b in later["data"]:
        b["timestamp"] = "2026-12-24T00:00:00.000000"
    b = outside.clean_host(later)
    fa, fb = findings(a)[f"outside.unexpected_port|{PUBLIC} 9123"], findings(b)[f"outside.unexpected_port|{PUBLIC} 9123"]
    assert "Shodan saw a service it could not name over TCP, last seen 2026-11-10." in fa.detail
    assert "last seen 2026-12-24" in fb.detail
    assert fa.basis == fb.basis and "2026" not in fa.basis
    assert fa.severity == "high" and "does not say whether the port is TCP or UDP" not in fa.detail
    # A named product appears in the sentence.
    c = host_reply()
    c["ports"].append(8080)
    c["data"].append(banner(8080, product="Apache httpd", version="2.4.57"))
    fc = findings(outside.clean_host(c))[f"outside.unexpected_port|{PUBLIC} 8080"]
    assert "Shodan saw Apache httpd 2.4.57 over TCP, last seen 2026-11-10." in fc.detail


def test_the_internetdb_rules_keep_their_wording():
    f = findings(outside.clean(SHODAN_VPS), source="internetdb")[f"outside.unexpected_port|{PUBLIC} 9123"]
    assert "Shodan's data is up to a week old, and it does not say whether the port is TCP or UDP." in f.detail
    assert "Shodan saw" not in f.detail


# ---- the Exposure page -------------------------------------------------------------------------------------

def test_the_exposure_section_shows_transport_service_and_last_seen_for_the_api(web):
    c, conn, cfg, fake = web
    shodan_cfg(cfg)
    run(chore(cfg, conn, fake).run_once())
    sec = section(c.get("/h/testhost/exposure").text)
    for head in ("Transport", "Service Shodan saw", "Last seen"):
        assert f">{head}<" in sec
    assert "Shodan API" in sec and "Shodan InternetDB" not in sec
    ports = {m.group(1): m.group(0) for m in re.finditer(r'<tr data-row id="outside-[^"]*-(\d+)">.*?</tr>', sec, re.S)}
    assert set(ports) == {"22", "80", "443", "9123"}
    assert "TCP" in re.sub(r"<[^>]+>", "", ports["22"]).upper() and "OpenSSH 9.2p1 Debian-2+deb12u3" in ports["22"]
    assert "nginx 1.24.0" in ports["80"] and "tcp, udp" in ports["443"]
    assert "not named" in ports["9123"] and 'title="2026-11-10 04:21 UTC"' in ports["22"]
    assert f'data-v="{SEEN_EPOCH}"' in ports["22"]
    assert "Data from Shodan" in sec and "as long as the data is attributed to Shodan" in sec
    assert 'data-status-label="unexpected"' in ports["9123"]      # the rules are unchanged: still labelled, never hidden


def test_the_source_panel_shows_a_placeholder_never_the_key(web):
    c, conn, cfg, fake = web
    shodan_cfg(cfg)
    run(chore(cfg, conn, fake).run_once())
    html = c.get("/h/testhost/exposure").text
    sec = section(html)
    assert f"https://api.shodan.io/shodan/host/{PUBLIC}?key=YOUR_KEY" in sec
    import html as htmllib
    assert f"curl -s 'https://api.shodan.io/shodan/host/{PUBLIC}?key=YOUR_KEY'" in htmllib.unescape(sec)
    assert "put your key where it says YOUR_KEY" in sec and "no query credits" in sec
    assert KEY not in surfaces(c, conn, cfg)


def test_the_internetdb_section_keeps_its_columns(web):
    c, conn, cfg, fake = web
    enabled(cfg)
    run(outside.Chore(cfg, conn, fake.client(), gap=0).run_once())
    sec = section(c.get("/h/testhost/exposure").text)
    assert "Shodan InternetDB" in sec and ">Transport<" not in sec and "Service Shodan saw" not in sec
    assert f"curl -s https://internetdb.shodan.io/{PUBLIC}" in sec and "YOUR_KEY" not in sec


def test_the_off_message_points_to_the_api_for_commercial_use(web):
    c, conn, cfg, fake = web
    sec = section(c.get("/h/testhost/exposure").text)
    assert "Outside checks are off" in sec and "non-commercial" in sec and "choose the Shodan API" in sec


def test_a_refused_key_shows_on_the_exposure_page_with_a_link_to_settings(web):
    c, conn, cfg, fake = web
    shodan_cfg(cfg)
    run(outside.Chore(cfg, conn, FakeApi(key=OTHER).client(), gap=0).run_once())
    sec = section(c.get("/h/testhost/exposure").text)
    assert "Shodan refused the API key (HTTP 401)" in sec and 'href="/settings#outside"' in sec
    assert KEY not in sec and OTHER not in sec


# ---- nothing leaks, anywhere -------------------------------------------------------------------------------

def test_the_key_appears_on_no_surface_through_a_whole_use(web, caplog):
    c, conn, cfg, fake = web
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="httpx")
    c.post("/settings/shodan-key", data={"action": "test", "key": KEY})
    c.post("/settings/shodan-key", data={"action": "save", "key": KEY})
    c.post("/settings", data={"group": "outside", "outside.enabled": "on", "outside.source": "shodan",
                              "outside.refresh_hours": "24", "outside.addresses": ""})
    run(chore(cfg, conn, fake).run_once())
    bad = FakeApi(key=OTHER)
    shodan.write_key(cfg, KEY)
    conn.execute("DELETE FROM outside")
    run(outside.Chore(cfg, conn, bad.client(), gap=0).run_once())
    c.post("/settings/shodan-key", data={"action": "test", "key": OTHER})
    text = surfaces(c, conn, cfg) + caplog.text
    for secret in (KEY, OTHER):
        assert secret not in text
    assert os.stat(cfg.shodan_key_path).st_mode & 0o077 == 0
    # The key lives in exactly one place: its file.
    hits = [p for p in cfg.db_path.parent.rglob("*") if p.is_file() and KEY.encode() in p.read_bytes()]
    assert hits == [cfg.shodan_key_path]


# ---- backups ------------------------------------------------------------------------------------------------

def test_a_backup_holds_the_key_and_a_restore_puts_it_back_private(hub_cfg, tmp_path):  # noqa: F811
    conf = tmp_path / "config.toml"
    conf.write_text('host_id = "hub"\n')
    hub_cfg.upload.token_file = str(tmp_path / "none.token")
    conn = db.connect_writer(hub_cfg.db_path)
    shodan.write_key(hub_cfg, KEY)
    path = backup.create(hub_cfg, conf)
    assert "shodan.key" in backup.inspect(path)["files"]
    conn.close()
    shodan.delete_key(hub_cfg)
    assert not hub_cfg.shodan_key_path.exists()
    done = backup.restore(hub_cfg, path, conf)
    assert any(d.startswith("shodan.key") for d in done)
    assert shodan.read_key(hub_cfg) == KEY and oct(hub_cfg.shodan_key_path.stat().st_mode & 0o777) == "0o600"


def test_a_backup_without_a_key_has_no_key_entry(hub_cfg, tmp_path):  # noqa: F811
    conf = tmp_path / "config.toml"
    conf.write_text('host_id = "hub"\n')
    hub_cfg.upload.token_file = str(tmp_path / "none.token")
    db.connect_writer(hub_cfg.db_path).close()
    assert "shodan.key" not in backup.inspect(backup.create(hub_cfg, conf))["files"]


def test_a_backup_with_a_key_at_a_configured_path_restores_to_that_path(hub_cfg, tmp_path):  # noqa: F811
    conf = tmp_path / "config.toml"
    conf.write_text('host_id = "hub"\n')
    hub_cfg.upload.token_file = str(tmp_path / "none.token")
    hub_cfg.outside.key_file = str(tmp_path / "keys" / "shodan")
    db.connect_writer(hub_cfg.db_path).close()
    shodan.write_key(hub_cfg, KEY)
    path = backup.create(hub_cfg, conf)
    shodan.delete_key(hub_cfg)
    backup.restore(hub_cfg, path, conf)
    assert shodan.read_key(hub_cfg) == KEY


def test_the_example_config_documents_the_source_and_the_key_file():
    from pathlib import Path
    text = (Path(__file__).parent.parent / "packaging" / "config.example.toml").read_text()
    assert 'source = "internetdb"' in text and "key_file" in text and "Settings page" in text
    import tomllib
    tomllib.loads(text)          # still valid TOML
