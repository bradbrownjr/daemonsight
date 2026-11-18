"""Shodan's outside view: the InternetDB fetch, the outside.* rules, the chore, and the Exposure section.

The fixture is a VPS that forwards every TCP port except 22, 80, 443, 2083
and 8001 over a WireGuard tunnel to 10.99.0.2 (the real ruleset's shape, in
tests/fixtures/iptables), with Shodan listing ports 22, 80, 443 and 9123.
Addresses are documentation ranges.
"""

import asyncio
import copy
import re
import time
import tomllib
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import db, hub, outside
from daemonsight.config import Config, ExposureConfig
from daemonsight.db import Snapshot
from daemonsight.web import views
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)
from .test_phase2 import listener, vps_firewall

PUBLIC = "203.0.113.10"
EXPECTED = ["22/tcp", "80/tcp", "443/tcp", "443/udp"]
NO_RECORD = (404, {"detail": "No information available"})
SHODAN_VPS = {"ip": PUBLIC, "ports": [22, 80, 443, 9123], "cpes": ["cpe:/a:openbsd:openssh:9.2"],
              "hostnames": ["vps.example.net"], "tags": ["cloud"], "vulns": []}


def vps_ports(public=PUBLIC):
    return {"listeners": [
        listener(22, unit="ssh.service", process="sshd", addresses=("0.0.0.0", "::")),
        listener(80, unit="caddy.service", process="caddy", addresses=("0.0.0.0", "::")),
        listener(443, unit="caddy.service", process="caddy", addresses=("0.0.0.0", "::")),
        listener(443, "udp", unit="caddy.service", process="caddy", addresses=("0.0.0.0", "::")),
        listener(8001, unit="ectlogger.service", process="uvicorn", addresses=("127.0.0.1",), scope="loopback"),
    ], "owners_known": True, "addresses": [
        {"nic": "ens6", "ip": public, "scope": "public"},
        {"nic": "wg0", "ip": "10.99.0.1", "scope": "private"},
        {"nic": "lo", "ip": "127.0.0.1", "scope": "loopback"}]}


def settings(expected=EXPECTED, upstream=()):
    return {"exposure": {"expected_public": list(expected), "upstream_allow": list(upstream), "jail_covers": {}},
            "links": {}, "eph": [32768, 60999], "interval_system": 10, "role": "server"}


def snap(source, data):
    return Snapshot(source, time.time(), True, None, data)


def vps_snaps():
    return {"ports": snap("ports", vps_ports()), "firewall": snap("firewall", vps_firewall()),
            "settings": snap("settings", settings())}


def row(data=SHODAN_VPS, status="ok", fetched=None, error=None, now=None):
    """A stored answer, as outside.get_rows returns it."""
    now = now or time.time()
    clean = outside.clean(data) if data is not None else None
    return {"ip": PUBLIC, "first_try": now - 100, "checked_at": now,
            "fetched_at": now if fetched is None else fetched, "status": status, "data": clean, "error": error}


def seed(conn, host="testhost", fw=None, expected=EXPECTED, upstream=(), public=PUBLIC):
    now = time.time()
    db.put_snapshot(conn, host, "ports", now, True, None, vps_ports(public))
    db.put_snapshot(conn, host, "firewall", now, True, None, fw or vps_firewall())
    db.put_snapshot(conn, host, "settings", now, True, None, settings(expected, upstream))
    db.put_snapshot(conn, host, "system", now, True, None, {
        "os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0", "virt": None, "boot_time": now - 86400,
        "cpu": {"percent": 1.0, "count": 1, "load": [0, 0, 0]},
        "memory": {"total": 1, "available": 1, "percent": 1.0}, "disks": [], "net": {}})
    conn.execute("UPDATE hosts SET last_seen = ?, version = ? WHERE id = ?", (now, "0.1.0 (abc1234)", host))


class FakeShodan:
    """InternetDB for tests: ip -> (status, json), and every request seen."""

    def __init__(self, answers=None):
        self.answers = {PUBLIC: (200, SHODAN_VPS)} if answers is None else answers
        self.calls: list[httpx.Request] = []

    def client(self):
        def handler(request):
            self.calls.append(request)
            code, payload = self.answers.get(request.url.path.lstrip("/"), NO_RECORD)
            if isinstance(payload, bytes):
                return httpx.Response(code, content=payload)
            return httpx.Response(code, json=payload)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


def enabled(cfg, **kw):
    cfg.outside.enabled = True
    for k, v in kw.items():
        setattr(cfg.outside, k, v)
    return cfg


def chore(cfg, conn, shodan):
    return outside.Chore(cfg, conn, shodan.client(), gap=0)


def run(coro):
    return asyncio.run(coro)


def open_outside(conn, host="testhost"):
    return {(r["rule"], r["key"]): r for r in db.open_findings(conn, host) if r["rule"].startswith("outside.")}


# ---- off by default, and no requests when disabled ----------------------------------

def test_off_by_default_with_documented_settings():
    c = Config()
    assert c.outside.enabled is False and c.outside.addresses == [] and c.outside.refresh_hours == 24
    example = (Path(__file__).parent.parent / "packaging" / "config.example.toml").read_text()
    assert "[outside]" in example and "# enabled = false" in example
    assert "non-commercial" in example and "enterprise license" in example
    tomllib.loads(example)  # still valid TOML


def test_no_requests_when_disabled(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    fake = FakeShodan()
    assert hub_cfg.outside.enabled is False
    assert run(chore(hub_cfg, conn, fake).run_once()) == 0
    assert fake.calls == []
    assert conn.execute("SELECT COUNT(*) FROM outside").fetchone()[0] == 0


def test_disabling_closes_the_findings(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    run(chore(hub_cfg, conn, FakeShodan()).run_once())
    assert open_outside(conn)
    outside.clear_findings(conn, time.time())  # what start-up does when [outside] is off
    assert not open_outside(conn)


# ---- the request and the answer --------------------------------------------------------

def test_request_sends_only_the_ip_and_a_generic_user_agent():
    fake = FakeShodan()
    res = run(outside.fetch(fake.client(), PUBLIC))
    (req,) = fake.calls
    assert res.status == "ok" and res.data["ports"] == [22, 80, 443, 9123]
    assert req.method == "GET" and str(req.url) == f"https://internetdb.shodan.io/{PUBLIC}"
    assert req.headers["user-agent"] == outside.USER_AGENT and req.headers["user-agent"].startswith("DaemonSight/")
    assert not req.content and not req.url.query
    assert not {"authorization", "cookie", "x-api-key"} & set(req.headers)


def test_404_means_no_record_and_other_failures_are_errors():
    def one(code, payload=None, **kw):
        fake = FakeShodan({PUBLIC: (code, payload if payload is not None else {})})
        return run(outside.fetch(fake.client(), PUBLIC))
    none = one(404, {"detail": "No information available"})
    assert (none.status, none.data, none.error) == ("none", None, None)
    assert one(500).status == "error" and "HTTP 500" in one(500).error
    assert "HTTP 403" in one(403).error
    limited = run(outside.fetch(httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(429, headers={"retry-after": "120"}))), PUBLIC))
    assert limited.status == "error" and limited.retry_after == 120
    junk = run(outside.fetch(httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(429, headers={"retry-after": "soon"}))), PUBLIC))
    assert junk.retry_after == 3600
    # Not the documented shape, not JSON, too big, a redirect, a dead network: all errors, none raise.
    for content in (b"[1, 2]", b"not json", b'{"ports": "22"}'):
        r = run(outside.fetch(FakeShodan({PUBLIC: (200, content)}).client(), PUBLIC))
        assert r.status == "error" and "documented shape" in r.error
    big = run(outside.fetch(FakeShodan({PUBLIC: (200, b" " * (outside.MAX_BYTES + 10))}).client(), PUBLIC))
    assert big.status == "error" and "larger" in big.error
    redirect = run(outside.fetch(httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "https://evil.example/"}))), PUBLIC))
    assert redirect.status == "error" and "HTTP 302" in redirect.error

    def boom(request):
        raise httpx.ConnectError("no route", request=request)
    dead = run(outside.fetch(httpx.AsyncClient(transport=httpx.MockTransport(boom)), PUBLIC))
    assert dead.status == "error" and "ConnectError" in dead.error


def test_the_answer_is_trimmed_to_what_is_used():
    got = outside.clean({
        "ip": "x", "ports": [22, 22, 0, 70000, "80", True, 443], "cpes": ["cpe:/a:x:y", "bad\x1b[2J", 5, "c" * 300],
        "hostnames": ["a.example", "line\nbreak"], "tags": ["cloud", "<script>", "vpn", "x" * 50],
        "vulns": ["CVE-2024-0001", "not-a-cve", "CVE-2024-0001", "CVE-24-1"], "extra": "ignored"})
    assert got == {"ports": [22, 443], "cpes": ["cpe:/a:x:y"], "hostnames": ["a.example"], "tags": ["cloud", "vpn"],
                   "vulns": ["CVE-2024-0001"]}
    assert outside.clean({}) == {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    assert outside.clean({"ports": 22}) is None and outside.clean("x") is None


def test_only_public_addresses_are_ever_sent():
    for ip in ("10.0.0.1", "192.168.1.5", "172.16.0.9", "100.64.1.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1",
               "fd00::1", "0.0.0.0", "224.0.0.1", "::ffff:10.0.0.1", "nonsense", ""):
        assert outside.sendable(ip) is None, ip
    assert outside.sendable("203.0.113.10") == "203.0.113.10"
    assert outside.sendable("2001:db8::10") == "2001:db8::10"      # IPv6 is accepted
    assert outside.sendable("2001:DB8:0:0:0:0:0:10") == "2001:db8::10"
    assert outside.sendable("::ffff:203.0.113.10") == "203.0.113.10"
    ports = vps_ports()
    ports["addresses"] += [{"nic": "x", "ip": "10.1.1.1", "scope": "public"}, {"nic": "y", "ip": "junk", "scope": "public"}]
    assert outside.public_addresses(ports) == [PUBLIC]   # a snapshot is untrusted: each address is checked again


def test_addresses_come_from_hosts_and_the_config(hub_cfg, token, caplog):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    hub_cfg.outside.addresses = ["198.51.100.7=testhost", "198.51.100.8", "10.0.0.5=testhost", "junk", PUBLIC]
    with caplog.at_level("WARNING", logger="daemonsight.outside"):
        got = outside.targets(conn, hub_cfg)
    assert got == {PUBLIC: {"testhost"}, "198.51.100.7": {"testhost"}}
    assert "10.0.0.5" in caplog.text and "junk" in caplog.text and "198.51.100.8" in caplog.text


# ---- what DaemonSight knows about a port --------------------------------------------

def test_port_9123_names_the_forward_to_the_tunnel():
    lines = outside.explain_port(vps_snaps(), 9123)
    assert len(lines) == 1
    assert "10.99.0.2" in lines[0] and "wg0 tunnel" in lines[0] and "all except 22,80,443,2083,8001" in lines[0]
    assert "ens6" in lines[0]   # the rule only matches traffic arriving on that interface
    # 22 and 80 are listeners, and no forward covers them.
    assert "sshd (unit ssh.service)" in outside.explain_port(vps_snaps(), 22)[0]
    assert "TCP ports" not in " ".join(outside.explain_port(vps_snaps(), 80))  # only the UDP rule covers 80
    # 2083 and 8001 are excluded from the forward, and nothing listens on 2083.
    assert "TCP ports" not in " ".join(outside.explain_port(vps_snaps(), 2083))  # the TCP rule leaves 2083 out
    assert "loopback only" in outside.explain_port(vps_snaps(), 8001)[0]


def test_a_port_with_nothing_behind_it_says_so():
    snaps = vps_snaps()
    snaps["firewall"] = snap("firewall", {"available": False, "reason": "no tools"})
    assert outside.explain_port(snaps, 9123) == ["Nothing on this host listens on it, and no port forward covers it."]


# ---- the rules ---------------------------------------------------------------------------

def findings_for(rows, snaps=None, expected=EXPECTED, matches=None, now=None, refresh=24, upstream=()):
    exposure = ExposureConfig(expected_public=list(expected), upstream_allow=list(upstream))
    got = outside.host_findings("testhost", rows, snaps or vps_snaps(), exposure, now or time.time(), refresh, matches)
    return {(f.rule, f.key): f for f in got}


def test_unexpected_port_high_naming_the_forward():
    fs = findings_for({PUBLIC: row()})
    assert set(fs) == {("outside.unexpected_port", f"{PUBLIC} 9123")}   # 22, 80 and 443 are expected
    f = fs[("outside.unexpected_port", f"{PUBLIC} 9123")]
    assert f.severity == "high" and f.title == f"Shodan sees port 9123 open on {PUBLIC}"
    assert "10.99.0.2" in f.detail and "wg0 tunnel" in f.detail and "not in exposure.expected_public" in f.detail
    assert "up to a week old" in f.detail
    assert f.link == f"/exposure#outside-{PUBLIC}-9123" and f.basis.startswith(f"{PUBLIC}|9123|")
    assert f.howto and "expected_public" in f.howto and f.fix is None


def test_unexpected_port_for_a_listener_names_the_process():
    snaps = vps_snaps()
    data = {**SHODAN_VPS, "ports": [22, 80, 443, 8001]}
    # Open it up: uvicorn now listens on every interface.
    ports = vps_ports()
    ports["listeners"][-1] = listener(8001, unit="ectlogger.service", process="uvicorn", addresses=("0.0.0.0",))
    snaps["ports"] = snap("ports", ports)
    f = findings_for({PUBLIC: row(data)}, snaps)[("outside.unexpected_port", f"{PUBLIC} 8001")]
    assert "uvicorn (unit ectlogger.service)" in f.detail and "bound to 0.0.0.0" in f.detail


def test_unexpected_port_with_nothing_behind_it():
    snaps = vps_snaps()
    snaps["firewall"] = snap("firewall", {"available": False, "reason": "no tools"})
    f = findings_for({PUBLIC: row()}, snaps)[("outside.unexpected_port", f"{PUBLIC} 9123")]
    assert "Nothing on this host listens on it" in f.detail


def test_the_basis_changes_when_what_is_behind_the_port_changes():
    a = findings_for({PUBLIC: row()})[("outside.unexpected_port", f"{PUBLIC} 9123")]
    fw = copy.deepcopy(vps_firewall())
    for fwd in fw["forwards"]:
        fwd["to"] = "10.99.0.3"
    snaps = vps_snaps()
    snaps["firewall"] = snap("firewall", fw)
    b = findings_for({PUBLIC: row()}, snaps)[("outside.unexpected_port", f"{PUBLIC} 9123")]
    assert a.basis != b.basis and "10.99.0.3" in b.detail


def test_not_seen_is_low_and_says_it_may_be_fine():
    only = {**SHODAN_VPS, "ports": [22, 80]}
    fs = findings_for({PUBLIC: row(only)})
    f = fs[("outside.not_seen", f"{PUBLIC} 443")]
    assert f.severity == "low" and ("outside.unexpected_port", f"{PUBLIC} 9123") not in fs
    assert "caddy" in f.detail and "may be fine" in f.detail and "not have scanned it yet" in f.detail
    assert "provider firewall" in f.detail and "443/udp" not in f.key
    assert not [k for k in fs if k[0] == "outside.not_seen" and k[1].endswith(" 22")]
    # 443/udp is forwarded away by the ruleset, so it is not judged reachable here. Only 443 is missing.
    assert [k for k in fs if k[0] == "outside.not_seen"] == [("outside.not_seen", f"{PUBLIC} 443")]


def test_not_seen_when_shodan_has_no_record_of_the_address():
    fs = findings_for({PUBLIC: row(None, status="none")})
    assert {k for k in fs if k[0] == "outside.not_seen"} == {("outside.not_seen", f"{PUBLIC} {p}") for p in (22, 80, 443)}
    assert "no record of this address" in fs[("outside.not_seen", f"{PUBLIC} 22")].detail
    # An IPv6 address Shodan doesn't know says little: not judged.
    v6 = row(None, status="none")
    v6["ip"] = "2001:db8::10"
    assert not findings_for({"2001:db8::10": v6})


def test_not_seen_skips_what_the_firewall_or_provider_keeps_out():
    only = {**SHODAN_VPS, "ports": [22, 80]}
    assert ("outside.not_seen", f"{PUBLIC} 443") not in findings_for(
        {PUBLIC: row(only)}, upstream=["22/tcp", "80/tcp"])
    ports = vps_ports()
    for i in (2, 3):   # caddy's 443 on tcp and udp, now loopback only
        ports["listeners"][i]["addresses"] = ["127.0.0.1"]
        ports["listeners"][i]["scope"] = "loopback"
    snaps = vps_snaps()
    snaps["ports"] = snap("ports", ports)
    assert ("outside.not_seen", f"{PUBLIC} 443") not in findings_for({PUBLIC: row(only)}, snaps)


def test_tagged_is_critical_only_for_the_serious_tags():
    f = findings_for({PUBLIC: row({**SHODAN_VPS, "tags": ["cloud", "malware", "compromised"]})})[("outside.tagged", PUBLIC)]
    assert f.severity == "critical" and "malware, compromised" in f.title
    assert "command-and-control" in f.detail and "cannot confirm" in f.detail and f.howto
    for tags in (["vpn"], ["cdn", "cloud"], ["scanner", "honeypot", "tor", "self-signed"], []):
        assert ("outside.tagged", PUBLIC) not in findings_for({PUBLIC: row({**SHODAN_VPS, "tags": tags})})
    assert ("outside.tagged", PUBLIC) in findings_for({PUBLIC: row({**SHODAN_VPS, "tags": ["c2"]})})
    assert ("outside.tagged", PUBLIC) in findings_for({PUBLIC: row({**SHODAN_VPS, "tags": ["doublepulsar"]})})


def test_vulns_are_medium_guesses_cross_referenced_with_our_own_matches():
    data = {**SHODAN_VPS, "vulns": ["CVE-2023-38408", "CVE-2024-6387", "CVE-2020-1234"]}
    f = findings_for({PUBLIC: row(data)}, matches={"CVE-2024-6387": "fix", "CVE-2019-1": "nofix"})[("outside.vulns", PUBLIC)]
    assert f.severity == "medium" and f.title == f"Shodan lists 3 CVEs for {PUBLIC}"
    assert "guesses" in f.detail and "banner" in f.detail
    assert "1 of them are also in DaemonSight's own package matches for this host: CVE-2024-6387" in f.detail
    none = findings_for({PUBLIC: row(data)}, matches={})[("outside.vulns", PUBLIC)]
    assert "None of them is in DaemonSight's own package matches" in none.detail and "backport" not in none.title
    nodata = findings_for({PUBLIC: row(data)}, matches=None)[("outside.vulns", PUBLIC)]
    assert "no data for this host" in nodata.detail
    # The set of CVEs is the basis: a new one brings an accepted finding back.
    more = findings_for({PUBLIC: row({**data, "vulns": data["vulns"] + ["CVE-2025-1111"]})})[("outside.vulns", PUBLIC)]
    assert more.basis != f.basis
    assert ("outside.vulns", PUBLIC) not in findings_for({PUBLIC: row()})


def test_every_outside_finding_has_a_basis_a_link_and_steps():
    data = {**SHODAN_VPS, "ports": [22, 9123], "tags": ["malware"], "vulns": ["CVE-2024-6387"]}
    fs = findings_for({PUBLIC: row(data)})
    rules_seen = {k[0] for k in fs}
    assert rules_seen == {"outside.unexpected_port", "outside.not_seen", "outside.tagged", "outside.vulns"}
    for f in fs.values():
        assert f.basis and f.link.startswith("/exposure#") and f.howto and f.rule.startswith("outside.")


def test_stale_answers_are_flagged_but_still_used():
    now = time.time()
    fresh = findings_for({PUBLIC: row(fetched=now - 2 * 86400, now=now)}, now=now)
    assert not [k for k in fresh if k[0] == "outside.stale"]
    old = findings_for({PUBLIC: row(fetched=now - 4 * 86400, error="HTTP 500", now=now)}, now=now)
    f = old[("outside.stale", PUBLIC)]
    assert f.severity == "low" and "4 days old" in f.detail and "HTTP 500" in f.detail
    assert ("outside.unexpected_port", f"{PUBLIC} 9123") in old     # the last good answer still counts
    # The limit is three refreshes, and at least 72 hours.
    assert outside.stale_after(24) == 72 * 3600 and outside.stale_after(48) == 144 * 3600
    # Never answered: counted from the first try.
    never = row(None, status="error", error="HTTP 500", now=now)
    never.update(fetched_at=None, first_try=now - 5 * 86400)
    fs = findings_for({PUBLIC: never}, now=now)
    assert set(fs) == {("outside.stale", PUBLIC)} and "never answered" in fs[("outside.stale", PUBLIC)].detail
    young = dict(never, first_try=now - 3600)
    assert findings_for({PUBLIC: young}, now=now) == {}


# ---- the chore -------------------------------------------------------------------------------

def test_the_chore_fetches_once_per_refresh_and_keeps_the_findings(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    fake = FakeShodan()
    c = chore(hub_cfg, conn, fake)
    t0 = time.time()
    assert run(c.run_once(t0)) == 1 and len(fake.calls) == 1        # one address, one request
    got = open_outside(conn)
    assert set(got) == {("outside.unexpected_port", f"{PUBLIC} 9123")} and got[next(iter(got))]["severity"] == "high"
    r = outside.get_rows(conn)[PUBLIC]
    assert r["status"] == "ok" and r["fetched_at"] == t0 and r["data"]["ports"] == [22, 80, 443, 9123]
    events = [e["title"] for e in db.recent_events(conn, "testhost", 10) if e["kind"] == "finding_opened"]
    assert f"Shodan sees port 9123 open on {PUBLIC}" in events
    # Not due again until the refresh time has passed.
    assert run(c.run_once(t0 + 3600)) == 0 and run(c.run_once(t0 + 23 * 3600)) == 0 and len(fake.calls) == 1
    assert run(c.run_once(t0 + 25 * 3600)) == 1 and len(fake.calls) == 2
    # Shodan stops listing 9123: the finding resolves.
    fake.answers[PUBLIC] = (200, {**SHODAN_VPS, "ports": [22, 80, 443]})
    assert run(c.run_once(t0 + 50 * 3600)) == 1
    assert not open_outside(conn)
    assert any(e["title"].startswith("Resolved: Shodan sees port 9123") for e in db.recent_events(conn, "testhost", 10))


def test_a_failed_refresh_keeps_the_last_answer_and_retries_sooner(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    fake = FakeShodan()
    c = chore(hub_cfg, conn, fake)
    t0 = time.time()
    run(c.run_once(t0))
    fake.answers[PUBLIC] = (500, {})
    assert run(c.run_once(t0 + 25 * 3600)) == 1
    r = outside.get_rows(conn)[PUBLIC]
    assert r["error"] == "HTTP 500" and r["fetched_at"] == t0 and r["data"]["ports"] == [22, 80, 443, 9123]
    assert ("outside.unexpected_port", f"{PUBLIC} 9123") in open_outside(conn)    # not flapping on a bad day
    # After an error it asks again within the hour, not a day later.
    assert run(c.run_once(t0 + 25 * 3600 + 1800)) == 0
    fake.answers[PUBLIC] = (200, SHODAN_VPS)
    assert run(c.run_once(t0 + 25 * 3600 + 3700)) == 1 and outside.get_rows(conn)[PUBLIC]["error"] is None
    # Down for days: the stale finding appears next to the old ones.
    fake.answers[PUBLIC] = (500, {})
    t = t0 + 25 * 3600 + 3700
    for step in range(1, 6):
        run(c.run_once(t + step * 24 * 3600))
    assert ("outside.stale", PUBLIC) in open_outside(conn) and ("outside.unexpected_port", f"{PUBLIC} 9123") in open_outside(conn)


def test_a_404_is_stored_as_no_record(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    run(chore(hub_cfg, conn, FakeShodan({})).run_once())
    r = outside.get_rows(conn)[PUBLIC]
    assert r["status"] == "none" and r["data"] is None and r["fetched_at"]
    assert {k[0] for k in open_outside(conn)} == {"outside.not_seen"}


def test_rate_limit_pauses_the_whole_pass(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg, addresses=["198.51.100.7=testhost", "198.51.100.8=testhost"])
    fake = FakeShodan({"198.51.100.7": (429, {})})
    c = chore(hub_cfg, conn, fake)
    t0 = time.time()
    assert run(c.run_once(t0)) == 1 and len(fake.calls) == 1        # stopped after the first 429
    assert c.paused_until >= t0 + 3600
    assert run(c.run_once(t0 + 120)) == 0 and len(fake.calls) == 1  # still paused
    assert run(c.run_once(t0 + 3700)) >= 1


def test_every_address_of_every_host_is_asked_once(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    hub.add_host(conn, "second")
    seed(conn, host="second", public="198.51.100.20")
    enabled(hub_cfg, addresses=["198.51.100.7=testhost", PUBLIC])
    fake = FakeShodan()
    assert run(chore(hub_cfg, conn, fake).run_once()) == 3
    assert sorted(r.url.path for r in fake.calls) == ["/198.51.100.20", "/198.51.100.7", f"/{PUBLIC}"]


def test_a_host_that_uploads_cannot_open_or_close_outside_findings(hub_cfg, token):  # noqa: F811
    from daemonsight.hub import HUB_RULES
    assert "outside." in HUB_RULES
    c = TestClient(create_app(hub_cfg))
    f = {"rule": "outside.unexpected_port", "key": "k", "severity": "high", "title": "t", "detail": "d"}
    assert post(c, body(findings=[f]), token).status_code == 422
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    enabled(hub_cfg)
    run(chore(hub_cfg, conn, FakeShodan()).run_once())
    assert open_outside(conn)
    assert post(c, body(findings=[]), token).status_code == 200      # an upload with no findings
    assert open_outside(conn)


# ---- the Exposure page ---------------------------------------------------------------------------

@pytest.fixture
def web(hub_cfg, token):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    fake = FakeShodan()
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    yield c, conn, hub_cfg, fake
    conn.close()


def accept(c, rule, key, note="known and fine"):
    return c.post("/h/testhost/findings/accept", data={"rule": rule, "key": key, "note": note,
                                                       "next": "/h/testhost/exposure"})


def section(html):
    return html.split('id="outside-title"')[1].split('id="docker-published"')[0]


def test_the_section_says_how_to_turn_it_on_when_it_is_off(web):
    c, conn, cfg, fake = web
    html = c.get("/h/testhost/exposure").text
    sec = section(html)
    assert "Outside checks are off" in sec and "enabled = true under [outside]" in sec and "non-commercial" in sec
    assert "Seen from outside" in html and "internetdb.shodan.io/" not in sec.split("non-commercial")[0]


def test_the_section_lists_every_port_with_a_status(web):
    c, conn, cfg, fake = web
    enabled(cfg)
    assert "not asked yet" in section(c.get("/h/testhost/exposure").text)
    run(chore(cfg, conn, fake).run_once())
    sec = section(c.get("/h/testhost/exposure").text)
    assert PUBLIC in sec and "fetched just now" in sec
    ports = {m.group(1): m.group(0) for m in re.finditer(r'<tr data-row id="outside-[^"]*-(\d+)">.*?</tr>', sec, re.S)}
    assert set(ports) == {"22", "80", "443", "9123"}
    for p in ("22", "80", "443"):
        assert 'data-status-label="expected"' in ports[p]
    assert 'data-status-label="unexpected"' in ports["9123"]
    assert "10.99.0.2" in ports["9123"] and "wg0 tunnel" in ports["9123"]
    assert "sshd (unit ssh.service)" in ports["22"]
    # Hostnames, CPEs and tags, escaped.
    assert "vps.example.net" in sec and "cpe:/a:openbsd:openssh:9.2" in sec and "cloud" in sec
    # The source panel: the exact URL, a curl command to repeat it, the terms.
    assert f"https://internetdb.shodan.io/{PUBLIC}" in sec
    assert f"curl -s https://internetdb.shodan.io/{PUBLIC}" in sec
    assert "enterprise license" in sec and f"DaemonSight/{outside.__version__}" in sec
    assert "Only the IP address is sent" in sec


def test_accepted_and_changed_ports_keep_their_place_with_a_label(web):
    c, conn, cfg, fake = web
    enabled(cfg)
    chore_ = chore(cfg, conn, fake)
    run(chore_.run_once())
    assert accept(c, "outside.unexpected_port", f"{PUBLIC} 9123", note="Test service, closes on Friday").status_code == 303
    row9123 = section(c.get("/h/testhost/exposure").text).split('id="outside-203.0.113.10-9123"')[1].split("</tr>")[0]
    assert 'data-status-label="accepted"' in row9123 and "Test service, closes on Friday" in row9123
    # What is behind the port changes: it is Changed, and counts again.
    fw = copy.deepcopy(vps_firewall())
    for fwd in fw["forwards"]:
        fwd["to"] = "10.99.0.3"
    db.put_snapshot(conn, "testhost", "firewall", time.time(), True, None, fw)
    run(chore_.run_once())
    row9123 = section(c.get("/h/testhost/exposure").text).split('id="outside-203.0.113.10-9123"')[1].split("</tr>")[0]
    assert 'data-status-label="changed"' in row9123 and "10.99.0.3" in row9123
    ov = c.get("/h/testhost/").text
    assert f"Shodan sees port 9123 open on {PUBLIC}" in ov and 'data-status-label="changed"' in ov


def test_the_finding_shows_on_the_overview_and_the_report(web):
    c, conn, cfg, fake = web
    enabled(cfg)
    run(chore(cfg, conn, fake).run_once())
    ov = c.get("/h/testhost/").text
    assert f"Shodan sees port 9123 open on {PUBLIC}" in ov and "1 needs attention" in ov
    assert f'href="/h/testhost/exposure#outside-{PUBLIC}-9123"' in ov
    assert "What to do" in ov and "expected_public" in ov
    rep = c.get("/h/testhost/report.md").text
    assert f"Shodan sees port 9123 open on {PUBLIC}" in rep and "10.99.0.2" in rep
    assert c.get("/h/testhost/").text.count('data-status-label="unexpected"') == 1
    # A row for a port in an accepted state still counts nowhere.
    assert accept(c, "outside.unexpected_port", f"{PUBLIC} 9123").status_code == 303
    page = c.get("/h/testhost/").text
    assert "0 need attention · 1 accepted" in page and 'data-status-label="accepted"' in page


def test_a_hub_without_the_table_still_shows_the_page(hub_cfg, token):  # noqa: F811
    """The web process only reads: a state.db the hub has not migrated yet has no outside table."""
    conn = db.connect_writer(hub_cfg.db_path)
    seed(conn)
    conn.execute("DROP TABLE outside")
    enabled(hub_cfg)
    reader = db.connect_reader(hub_cfg.db_path)
    out = views.exposure(reader, views.host_config(reader, hub_cfg, "testhost"))["outside"]
    assert out["state"] == "ok" and out["addresses"][0]["state"] == "waiting"
