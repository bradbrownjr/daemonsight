"""CrowdSec bans on an OPNsense firewall: the Local API client (GET of /v1/decisions with a filter, and nothing else), what
is asked about, the findings, the key file, the form's dependent option and the Firewall page's card. The Local API is a
fake (tests/fake_crowdsec.py) that copies CrowdSec's filter behaviour, including answering EVERYTHING to an unfiltered
read, so a test can prove the hub never sends one. Addresses are documentation ranges."""

import asyncio
import logging
import re
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import backup, db
from daemonsight.config import Config
from daemonsight.findings import Finding
from daemonsight.remote import crowdsec, poll, store
from daemonsight.remote.client import RemoteError
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .fake_crowdsec import KEY as CSKEY, FakeLapi, decision
from .fake_opnsense import FakeOpnsense, KEY, SECRET
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

URL = "https://fw.test:8443"
LAPI = "http://192.0.2.1:8180"
NOW = 1_795_000_000.0
WAN, WAN2 = "192.0.2.10", "198.51.100.20"        # the fixture firewall's two internet-facing addresses
VPS = "203.0.113.7"
NEVER_IP = "203.0.113.50"


def run(coro):
    return asyncio.run(coro)


class World:
    """A fake firewall and a fake Local API behind one Net."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.fw = FakeOpnsense()
        self.lapi = FakeLapi()
        self.net = self.lapi.attach(self.fw.net())

    def conn(self):
        return db.connect_writer(self.cfg.db_path)

    def add(self, *, never=(NEVER_IP,), key=CSKEY, url=LAPI, host=True):
        c = self.conn()
        store.add(c, self.cfg.data_dir, "fw1", "opnsense", URL, KEY, secret=SECRET, interval=60, now=NOW - 1000,
                  crowdsec_url=url, crowdsec_key=key, crowdsec_never=list(never))
        if host:       # a collector host the hub knows: its address is where the hub saw it upload from
            c.execute("INSERT INTO hosts (id, token_hash, created_at, address) VALUES ('vps', 'x', ?, ?)", (NOW - 1000, VPS))
        c.close()

    def poll(self, at=NOW):
        c = self.conn()
        try:
            run(poll.run_once(c, self.cfg, self.net, at))
        finally:
            c.close()

    def snap(self):
        c = self.conn()
        try:
            return db.get_snapshot(c, "fw1", crowdsec.SNAPSHOT)
        finally:
            c.close()

    def findings(self):
        c = self.conn()
        try:
            return {(r["rule"], r["key"]): r for r in db.open_findings(c, "fw1") if r["rule"].startswith("crowdsec.")}
        finally:
            c.close()


@pytest.fixture
def world(hub_cfg):
    return World(hub_cfg)


# --- the client: GET of /v1/decisions with a filter, and nothing else -------------------------------------------------

GOOD = [{"ip": "192.0.2.10", "limit": 50}, {"range": "10.20.0.0/24", "contains": "true", "limit": 50},
        {"range": "10.20.0.0/24", "contains": "false", "limit": 50}, {"range": "198.51.100.0/24", "contains": "true", "limit": 5},
        {"ip": "2001:db8::1", "limit": 50}, {"origins": "crowdsec", "limit": 500}, {"range": "203.0.113.0/24", "contains": "false", "limit": 50}]
BAD = [{}, {"limit": 50}, {"ip": "192.0.2.10"}, {"origins": "crowdsec"},                 # no limit
       {"ip": "", "limit": 5}, {"ip": "192.0.2.0/24", "limit": 5}, {"ip": "not an ip", "limit": 5},
       {"range": "192.0.2.10", "contains": "true", "limit": 5}, {"range": "192.0.2.0/24", "limit": 5},
       {"range": "192.0.2.0/24", "contains": "yes", "limit": 5}, {"ip": "192.0.2.1", "contains": "true", "limit": 5},
       {"origins": "CAPI", "limit": 5}, {"origins": "crowdsec,CAPI", "limit": 5}, {"origins": "", "limit": 5},
       {"ip": "192.0.2.1", "range": "192.0.2.0/24", "contains": "true", "limit": 5},
       {"ip": "192.0.2.1", "origins": "crowdsec", "limit": 5}, {"scope": "ip", "ip": "192.0.2.1", "limit": 5},
       {"ip": "192.0.2.1", "limit": 0}, {"ip": "192.0.2.1", "limit": 100000}, {"ip": "192.0.2.1", "limit": "5"},
       {"range": "0.0.0.0/0", "contains": "false", "limit": 5}, {"range": "8.0.0.0/8", "contains": "false", "limit": 5},
       {"range": "::/0", "contains": "false", "limit": 5}, {"range": "2000::/16", "contains": "false", "limit": 5},
       {"value": "1.2.3.4", "limit": 5}, {"startup": "true", "limit": 5}, {"origins": "crowdsec", "contains": "true", "limit": 5}]


def test_only_a_filtered_read_with_a_limit_passes_the_check():
    for ok in GOOD:
        crowdsec.Lapi.check_params(ok)
    for bad in BAD:
        with pytest.raises(ValueError):
            crowdsec.Lapi.check_params(bad)


def test_a_wide_private_range_may_be_asked_about_but_a_wide_public_one_may_not():
    crowdsec.Lapi.check_params({"range": "10.0.0.0/8", "contains": "false", "limit": 50})     # a LAN network
    crowdsec.Lapi.check_params({"range": "8.0.0.0/8", "contains": "true", "limit": 50})       # what contains it: a short list
    with pytest.raises(ValueError):
        crowdsec.Lapi.check_params({"range": "8.0.0.0/8", "contains": "false", "limit": 50})


def test_the_client_has_no_way_to_send_anything_but_a_get_of_decisions():
    lapi = crowdsec.Lapi(LAPI, CSKEY, httpx.AsyncClient())
    assert {n for n in dir(lapi) if not n.startswith("_")} == {"aclose", "base", "check_params", "get"}
    assert crowdsec.PATH == "/v1/decisions" and "stream" not in crowdsec.PATH


def test_a_refused_query_sends_nothing(world):
    lapi = crowdsec.Lapi(LAPI, CSKEY, world.net.lapi())
    for bad in BAD:
        with pytest.raises(ValueError):
            run(lapi.get(bad))
    run(lapi.aclose())
    assert world.lapi.requests == []


def test_a_good_read_is_a_get_with_the_key_in_the_header_only(world):
    world.lapi.decisions = [decision(WAN)]
    lapi = crowdsec.Lapi(LAPI, CSKEY, world.net.lapi())
    rows = run(lapi.get({"ip": WAN, "limit": 50}))
    run(lapi.aclose())
    assert [d["value"] for d in rows] == [WAN]
    (r,) = world.lapi.requests
    assert r.method == "GET" and r.url.path == "/v1/decisions" and r.headers["x-api-key"] == CSKEY
    assert CSKEY not in str(r.url) and not r.content and "content-type" not in r.headers
    assert dict(r.url.params) == {"ip": WAN, "limit": "50"}


def test_an_empty_answer_is_null_and_reads_as_no_decisions(world):
    lapi = crowdsec.Lapi(LAPI, CSKEY, world.net.lapi())
    assert run(lapi.get({"ip": "192.0.2.99", "limit": 50})) == []
    run(lapi.aclose())
    assert world.lapi.requests and world.lapi.requests[0].url.params["ip"] == "192.0.2.99"


def test_errors_are_told_apart_and_never_hold_the_key(world):
    for status, kind in ((403, "auth"), (401, "auth"), (400, "http"), (500, "http"), (302, "http")):
        world.lapi.status = status
        lapi = crowdsec.Lapi(LAPI, CSKEY, world.net.lapi())
        with pytest.raises(RemoteError) as e:
            run(lapi.get({"ip": WAN, "limit": 5}))
        assert e.value.kind == kind and CSKEY not in e.value.message
    world.lapi.status = None
    world.lapi.fail = httpx.ConnectError(f"no route to host {CSKEY}")
    lapi = crowdsec.Lapi(LAPI, CSKEY, world.net.lapi())
    with pytest.raises(RemoteError) as e:
        run(lapi.get({"ip": WAN, "limit": 5}))
    assert e.value.kind == "unreachable" and CSKEY not in e.value.message and "***" in e.value.message
    wrong = crowdsec.Lapi(LAPI, "x" * 30, world.lapi.client())
    world.lapi.fail = None
    with pytest.raises(RemoteError) as e:
        run(wrong.get({"ip": WAN, "limit": 5}))
    assert e.value.kind == "auth" and "refused the bouncer key" in e.value.message


@pytest.mark.parametrize("raw, out", [("192.168.1.1:8180", "http://192.168.1.1:8180"), ("http://fw.lan:8180/", "http://fw.lan:8180"),
                                      ("https://fw.lan:8443", "https://fw.lan:8443"), ("[2001:db8::1]:8180", "http://[2001:db8::1]:8180")])
def test_the_address_is_normalized(raw, out):
    assert crowdsec.normalize_url(raw) == out


@pytest.mark.parametrize("raw", ["", "ftp://x", "http://u:p@fw:8180", "http://fw:8180/v1/decisions", "http://fw:8180?x=1", "a b", "http://fw:99999"])
def test_a_bad_address_is_refused(raw):
    with pytest.raises(ValueError):
        crowdsec.normalize_url(raw)


# --- addresses and networks ---------------------------------------------------------------------------------------------

def test_covers_matches_an_address_or_a_network_in_either_direction():
    assert crowdsec.covers("192.0.2.10", "192.0.2.10")
    assert crowdsec.covers("192.0.2.0/24", "192.0.2.10")           # a range ban contains the address
    assert crowdsec.covers("192.0.2.10", "192.0.2.0/24")           # a ban inside the network
    assert crowdsec.covers("192.0.0.0/16", "192.0.2.0/24")
    assert not crowdsec.covers("192.0.3.0/24", "192.0.2.10")
    assert not crowdsec.covers("192.0.2.11", "192.0.2.10")
    assert not crowdsec.covers("2001:db8::/32", "192.0.2.10")      # another family never matches
    assert crowdsec.covers("2001:db8::/32", "2001:db8::5")
    assert not crowdsec.covers("FR", "192.0.2.10") and not crowdsec.covers("", "192.0.2.10")     # a country, not an address


def ifaces():
    return {"interfaces": [
        {"id": "wan", "name": "WAN", "device": "re0", "assigned": True, "gateways": ["192.0.2.1"], "addresses": ["192.0.2.10/24", "fe80::1%re0/64", "2001:db8:1::2/64"]},
        {"id": "lan", "name": "LAN", "device": "re1", "assigned": True, "gateways": [], "addresses": ["10.20.0.1/24"]},
        {"id": "opt2", "name": "Road warriors", "device": "wg0", "assigned": True, "gateways": [], "addresses": ["10.99.0.1/24"]},
        {"id": "", "name": "enc0", "device": "enc0", "assigned": False, "gateways": [], "addresses": ["127.0.0.1/8"]},
        {"id": "opt9", "name": "Spare", "device": "re9", "assigned": True, "gateways": [], "addresses": []}]}


def test_the_firewalls_own_addresses_and_networks_are_the_first_entries():
    from daemonsight.remote import roles
    rl = roles.assign(ifaces()["interfaces"])
    entries, unresolved = crowdsec.protected(ifaces(), rl, [], [], "fw1")
    got = [(e["value"], e["group"], e["net"]) for e in entries]
    assert got == [("10.20.0.0/24", "self", True), ("10.99.0.0/24", "self", True), ("192.0.2.10", "self", False),
                   ("2001:db8:1::2", "self", False)]      # no link-local, no loopback, no interface without an address
    assert unresolved == []
    assert "VPN network" in next(e for e in entries if e["value"] == "10.99.0.0/24")["whys"][0]


def test_hosts_by_address_and_names_are_listed_as_not_checked():
    hosts = [("vps", VPS), ("fw1", "192.0.2.1"), ("tower", "tower.example.lan"), ("empty", None), ("v6", "[2001:db8::7]"), ("lo", "127.0.0.1")]
    entries, unresolved = crowdsec.protected(None, {}, hosts, [], "fw1")
    assert [(e["value"], e["group"]) for e in entries] == [("2001:db8::7", "host"), (VPS, "host")]
    assert unresolved == ["tower"]           # the firewall itself, an empty address and a loopback are skipped without a word


def test_entries_merge_by_value_and_the_firewall_outranks_a_host_and_your_list():
    from daemonsight.remote import roles
    rl = roles.assign(ifaces()["interfaces"])
    entries, _ = crowdsec.protected(ifaces(), rl, [("vps", "192.0.2.10")], ["192.0.2.10", "203.0.113.0/24"], "fw1")
    e = next(x for x in entries if x["value"] == "192.0.2.10")
    assert e["group"] == "self" and len(e["whys"]) == 3
    assert [x["value"] for x in entries].count("192.0.2.10") == 1
    assert next(x for x in entries if x["value"] == "203.0.113.0/24")["net"] is True


def test_an_address_is_one_query_and_a_network_is_two_and_the_total_is_capped():
    entries = [{"value": "192.0.2.10", "net": False}, {"value": "10.20.0.0/24", "net": True}]
    q = [p for _e, p in crowdsec.queries(entries)]
    assert q == [{"ip": "192.0.2.10", "limit": 50}, {"range": "10.20.0.0/24", "contains": "true", "limit": 50},
                 {"range": "10.20.0.0/24", "contains": "false", "limit": 50}]
    many = [{"value": f"10.{i // 250}.{i % 250}.0/24", "net": True} for i in range(300)]
    qs = crowdsec.queries(many)
    assert len(qs) <= crowdsec.MAX_QUERIES and len(qs) % 2 == 0
    for _e, p in qs:
        crowdsec.Lapi.check_params(p)


# --- the never-ban list ------------------------------------------------------------------------------------------------------

def test_the_never_ban_list_is_normalized_and_deduplicated():
    assert store.clean_never_list("192.0.2.7\n198.51.100.0/24, 192.0.2.7;  2001:db8::1/128\n\n10.1.2.3/24") == [
        "192.0.2.7", "198.51.100.0/24", "2001:db8::1", "10.1.2.0/24"]
    assert store.clean_never_list("203.0.113.9/32") == ["203.0.113.9"]
    assert store.clean_never_list("") == [] and store.clean_never_list(None) == []
    assert store.clean_never_list(["192.0.2.7", "192.0.2.7"]) == ["192.0.2.7"]
    assert store.clean_never_list("10.0.0.0/8") == ["10.0.0.0/8"]       # private: allowed whatever its size


@pytest.mark.parametrize("raw", ["not-an-ip", "192.0.2.256", "192.0.2.0/33", "example.com", "192.0.2.7 oops", "0.0.0.0/0", "8.0.0.0/8",
                                 "198.51.0.0/15", "2a00::/32", "::/0", "1.2.3.4/abc", "x" * 80])
def test_a_bad_or_too_wide_entry_is_refused_and_named(raw):
    with pytest.raises(ValueError) as e:
        store.clean_never_list(raw)
    assert raw.split()[-1][:20] in str(e.value) or "too wide" in str(e.value) or "not an IP" in str(e.value)


def test_the_never_ban_list_holds_fifty_at_most():
    fifty = "\n".join(f"192.0.2.{i}" for i in range(1, 51))
    assert len(store.clean_never_list(fifty)) == 50
    with pytest.raises(ValueError, match="At most 50"):
        store.clean_never_list(fifty + "\n192.0.2.200")


def test_a_bouncer_key_has_a_shape():
    assert store.clean_crowdsec_key("  abcdefgh12345678  ") == "abcdefgh12345678"
    for bad in ("", "short", "has space in it 1234", "x" * 201, "tab\tin it12345"):
        with pytest.raises(ValueError):
            store.clean_crowdsec_key(bad)


# --- a whole poll ----------------------------------------------------------------------------------------------------------------

def test_a_poll_asks_about_every_protected_address_and_never_unfiltered(world):
    world.add()
    world.poll()
    qs = world.lapi.queries()
    assert qs
    assert all(sum(k in q for k in ("ip", "range", "origins")) == 1 and "limit" in q for q in qs)
    assert world.lapi.unfiltered == [] and world.lapi.streamed == []
    assert {r.method for r in world.lapi.requests} == {"GET"} and {r.url.path for r in world.lapi.requests} == {"/v1/decisions"}
    asked = {q.get("ip") or q.get("range") for q in qs} - {None}
    assert {WAN, WAN2, VPS, NEVER_IP, "10.20.0.0/24", "10.30.0.0/24", "10.99.0.0/24"} <= asked
    assert {"origins": "crowdsec", "limit": "500"} in qs
    ranges = [q for q in qs if "range" in q]
    assert {q["contains"] for q in ranges} == {"true", "false"}
    s = world.snap()
    assert s.ok and s.data["entries"] and s.data["fails"] == 0 and s.data["local"]["count"] == 0
    assert world.findings() == {}


def test_nothing_is_asked_without_crowdsec_set_up(world):
    c = world.conn()
    store.add(c, world.cfg.data_dir, "fw1", "opnsense", URL, KEY, secret=SECRET, interval=60, now=NOW - 1000)
    c.close()
    world.poll()
    assert world.lapi.requests == [] and world.snap() is None and world.findings() == {}


def test_the_firewalls_own_address_banned_opens_a_high_finding_with_the_fix(world):
    world.add()
    world.lapi.decisions = [decision(WAN, id_=7)]
    world.poll()
    f = world.findings()
    assert set(f) == {("crowdsec.self_banned", WAN)}
    r = f[("crowdsec.self_banned", WAN)]
    assert r["severity"] == "high" and r["title"] == f"CrowdSec is banning this firewall's own address {WAN}"
    assert r["fix"] == f"cscli decisions delete -i {WAN}" and "pf-scan-multi_ports" in r["detail"]
    assert "drops every connection" in r["detail"] and r["link"] == "/firewall#crowdsec"
    assert "cscli allowlists add" in r["howto"] and "does not remove a decision that already exists" in r["howto"]
    assert "cscli alerts list -i " + WAN in r["howto"]
    assert r["basis"] and "3h" not in r["basis"] and "12.5" not in r["basis"]       # no times: Accept stays stable


def test_the_finding_clears_when_the_ban_is_gone_and_its_basis_ignores_the_time_left(world):
    world.add()
    world.lapi.decisions = [decision(WAN, duration="3h59m0s")]
    world.poll(NOW)
    first = world.findings()[("crowdsec.self_banned", WAN)]
    world.lapi.decisions = [decision(WAN, duration="2h10m0s", id_=99)]       # the same ban a while later: new id, less time
    world.poll(NOW + 200)
    again = world.findings()[("crowdsec.self_banned", WAN)]
    assert again["basis"] == first["basis"] and again["id"] == first["id"]
    world.lapi.decisions = []
    world.poll(NOW + 400)
    assert world.findings() == {}
    c = world.conn()
    kinds = [e["kind"] for e in c.execute("SELECT kind FROM events WHERE host='fw1' ORDER BY ts, id")]
    assert "finding_opened" in kinds and "finding_resolved" in kinds
    c.close()


def test_a_ban_on_a_range_that_holds_the_address_and_a_ban_inside_a_lan_network_both_fire(world):
    world.add()
    world.lapi.decisions = [decision("192.0.2.0/24", scenario="crowdsecurity/ssh-bf", id_=1),
                            decision("10.20.0.55", scenario="crowdsecurity/http-probing", id_=2),
                            decision("10.0.0.0/8", id_=3)]
    world.poll()
    f = world.findings()
    assert set(f) == {("crowdsec.self_banned", "192.0.2.0/24"), ("crowdsec.self_banned", "10.20.0.55"), ("crowdsec.self_banned", "10.0.0.0/8")}
    assert "a range that includes this firewall's own address 192.0.2.10" in f[("crowdsec.self_banned", "192.0.2.0/24")]["title"]
    assert f[("crowdsec.self_banned", "192.0.2.0/24")]["fix"] == "cscli decisions delete -r 192.0.2.0/24"
    assert "inside this firewall's network 10.20.0.0/24" in f[("crowdsec.self_banned", "10.20.0.55")]["title"]
    assert "covers this firewall's network" in f[("crowdsec.self_banned", "10.0.0.0/8")]["title"]


def test_a_known_host_or_a_never_ban_address_banned_opens_host_banned(world):
    world.add()
    world.lapi.decisions = [decision(VPS, id_=4), decision(NEVER_IP, scenario="crowdsecurity/http-crawl-non_statics", id_=5),
                            decision("203.0.113.99", id_=6)]            # nothing protects this one
    world.poll()
    f = world.findings()
    assert set(f) == {("crowdsec.host_banned", VPS), ("crowdsec.host_banned", NEVER_IP)}
    a, b = f[("crowdsec.host_banned", VPS)], f[("crowdsec.host_banned", NEVER_IP)]
    assert a["severity"] == "high" and "host vps" in a["detail"] and a["fix"] == f"cscli decisions delete -i {VPS}"
    assert "your never-ban list" in b["detail"] and "cscli allowlists add" in b["howto"]
    world.lapi.decisions = []
    world.poll(NOW + 400)
    assert world.findings() == {}


def test_a_decision_that_is_not_a_ban_is_listed_but_is_not_a_finding(world):
    world.add()
    world.lapi.decisions = [decision(WAN, type_="captcha")]
    world.poll()
    assert world.findings() == {}
    ban = next(e for e in world.snap().data["entries"] if e["value"] == WAN)["bans"][0]
    assert ban["type"] == "captcha"


def test_a_value_that_is_not_an_address_never_reaches_a_command(world):
    world.add()
    world.lapi.decisions = [decision("192.0.2.10; rm -rf /", id_=1), decision("192.0.2.10\n", id_=2)]
    world.poll()
    assert world.findings() == {}                   # not addresses: dropped by the check that the ban covers the address
    f = crowdsec.evaluate({"entries": [{"value": WAN, "group": "self", "net": False, "whys": ["x"],
                                        "bans": [{"id": 1, "origin": "crowdsec", "scenario": "s", "value": "1.2.3.4; reboot",
                                                  "scope": "Ip", "type": "ban", "left": 5}]}], "fails": 0})
    assert len(f) == 1 and f[0].fix is None and "reboot" not in (f[0].howto or "").replace("<address>", "")


def test_decisions_that_the_firewall_sends_are_cut_to_the_fields_kept(world):
    world.add()
    row = decision(WAN) | {"secret_extra": "leak-me", "scenario": "s" * 500, "origin": "o\x1b[31mred"}
    world.lapi.decisions = [row]
    world.poll()
    dump = str(world.snap().data)
    assert "leak-me" not in dump and "\x1b" not in dump and "s" * 300 not in dump


def test_the_local_ban_count_is_by_scenario_and_only_local_decisions(world):
    world.add()
    world.lapi.decisions = [decision("203.0.113.200", scenario="crowdsecurity/ssh-bf", id_=1),
                            decision("203.0.113.201", scenario="crowdsecurity/ssh-bf", id_=2),
                            decision("203.0.113.202", scenario="firewallservices/pf-scan-multi_ports", id_=3),
                            decision("203.0.113.203", scenario="manual", origin="cscli", id_=4)]
    world.poll()
    local = world.snap().data["local"]
    assert local["count"] == 3 and not local["capped"]
    assert local["scenarios"] == [{"scenario": "crowdsecurity/ssh-bf", "count": 2},
                                  {"scenario": "firewallservices/pf-scan-multi_ports", "count": 1}]
    assert world.findings() == {}


def test_the_local_ban_read_is_capped_and_so_is_what_is_stored(world):
    world.add()
    world.lapi.decisions = [decision(f"203.0.113.{i % 250}", scenario=f"s{i}", id_=i) for i in range(1, 700)]
    world.poll()
    local = world.snap().data["local"]
    assert local["capped"] and local["count"] == crowdsec.LOCAL_ROWS and len(local["scenarios"]) == crowdsec.LOCAL_SCENARIOS_KEPT
    assert next(q for q in world.lapi.queries() if "origins" in q)["limit"] == "500"


def test_a_failed_read_keeps_the_last_data_and_opens_unreachable_only_after_two(world):
    world.add()
    world.lapi.decisions = [decision(WAN)]
    world.poll(NOW)
    assert ("crowdsec.self_banned", WAN) in world.findings()
    world.lapi.fail = httpx.ConnectError(f"no route {CSKEY}")
    world.poll(NOW + 200)
    s = world.snap()
    assert not s.ok and "Could not connect" in s.error and CSKEY not in s.error and s.data["fails"] == 1 and s.data["entries"]
    assert set(world.findings()) == {("crowdsec.self_banned", WAN)}                 # the ban holds on the last good read
    world.poll(NOW + 400)
    f = world.findings()
    assert ("crowdsec.unreachable", "lapi") in f and ("crowdsec.self_banned", WAN) in f
    u = f[("crowdsec.unreachable", "lapi")]
    assert u["severity"] == "low" and "Can't read CrowdSec" in u["title"] and CSKEY not in u["detail"] and "cscli bouncers add" in u["howto"]
    c = world.conn()
    row = store.get(c, "fw1")
    assert row["fails"] == 0 and row["last_error"] is None                           # the firewall itself was read fine
    c.close()
    world.lapi.fail = None
    world.poll(NOW + 600)
    assert ("crowdsec.unreachable", "lapi") not in world.findings() and world.snap().ok


def test_a_refused_key_is_an_error_with_no_key_in_it(world):
    world.add(key="w" * 30)
    world.poll()
    s = world.snap()
    assert not s.ok and "refused the bouncer key" in s.error and "w" * 30 not in s.error
    assert not world.lapi.unfiltered
    # one request is enough to know: the others were not sent in a flood
    assert len(world.lapi.requests) <= crowdsec.MAX_QUERIES + 1


def test_the_read_is_not_repeated_more_often_than_every_two_minutes(world):
    world.add()
    world.poll(NOW)
    n = len(world.lapi.requests)
    world.poll(NOW + 61)
    assert len(world.lapi.requests) == n
    world.poll(NOW + 125)
    assert len(world.lapi.requests) == 2 * n


def test_a_missing_key_file_is_an_error_not_a_crash(world):
    world.add()
    store.crowdsec_key_path(world.cfg.data_dir, "fw1").unlink()
    world.poll()
    s = world.snap()
    assert not s.ok and "key file is missing" in s.error and world.lapi.requests == []


def test_accepting_a_ban_finding_is_stable_across_rereads(world):
    world.add()
    world.lapi.decisions = [decision(WAN, duration="3h0m0s")]
    world.poll(NOW)
    c = world.conn()
    f = world.findings()[("crowdsec.self_banned", WAN)]
    fp = crowdsec.evaluate(world.snap().data)[0]
    from daemonsight.findings import fingerprint
    before = fingerprint(fp.rule, fp.key, fp.basis, fp.title)
    c.close()
    world.lapi.decisions = [decision(WAN, duration="1h0m0s", id_=50)]
    world.poll(NOW + 200)
    fp2 = crowdsec.evaluate(world.snap().data)[0]
    assert fingerprint(fp2.rule, fp2.key, fp2.basis, fp2.title) == before and f["rule"] == "crowdsec.self_banned"


def test_the_durations_the_api_sends_are_read():
    assert crowdsec.parse_duration("3h59m12.5s") == 3 * 3600 + 59 * 60 + 12.5
    assert crowdsec.parse_duration("1h0m0s") == 3600 and crowdsec.parse_duration("45s") == 45 and crowdsec.parse_duration("250ms") == 0.25
    assert crowdsec.parse_duration("") is None and crowdsec.parse_duration("-3s") is None and crowdsec.parse_duration("soon") is None


def test_an_empty_or_missing_snapshot_makes_no_findings():
    assert crowdsec.evaluate(None) == [] and crowdsec.evaluate({}) == []
    assert crowdsec.evaluate({"entries": [], "fails": 1}) == []
    assert all(isinstance(f, Finding) for f in crowdsec.evaluate({"entries": [], "fails": 2}, "x"))


# --- the key: a private file, never anywhere else ----------------------------------------------------------------------------------

def test_the_key_is_a_private_file_and_never_in_the_database(world):
    world.add()
    path = store.crowdsec_key_path(world.cfg.data_dir, "fw1")
    assert path.read_text().strip() == CSKEY and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700 and path.name == "fw1.crowdsec-key"
    world.lapi.decisions = [decision(WAN)]
    world.poll()
    c = world.conn()
    dump = "\n".join(str(tuple(r)) for t in ("remotes", "hosts", "snapshots", "events", "findings", "meta") for r in c.execute(f"SELECT * FROM {t}"))
    assert CSKEY not in dump
    assert store.remove(c, world.cfg.data_dir, "fw1")
    c.close()
    assert not path.exists()


def test_the_key_is_not_in_a_log_line_a_page_or_an_event(world, hub_cfg, caplog):
    caplog.set_level(logging.DEBUG)
    world.add()
    world.lapi.decisions = [decision(WAN)]
    world.lapi.fail = None
    world.poll(NOW)
    world.lapi.fail = httpx.ConnectError(f"no route {CSKEY}")
    world.poll(NOW + 200)
    world.poll(NOW + 400)
    assert CSKEY not in caplog.text
    app = create_app(hub_cfg, remote_net=world.net)
    client = TestClient(app, follow_redirects=False)
    assert client.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    for path in ("/h/fw1/", "/h/fw1/firewall", "/h/fw1/report", "/h/fw1/report.md", "/remotes/fw1/edit", "/"):
        r = client.get(path)
        assert r.status_code == 200 and CSKEY not in r.text, path
    c = world.conn()
    for r in c.execute("SELECT title, detail FROM events"):
        assert CSKEY not in f"{r['title']} {r['detail']}"
    c.close()


def test_a_backup_holds_the_key_and_a_restore_brings_it_back(world, tmp_path):
    world.add()
    c = world.conn()
    c.execute("PRAGMA wal_checkpoint(FULL)")
    c.close()
    conf = tmp_path / "config.toml"
    conf.write_text("")
    arch = backup.create(world.cfg, conf, tmp_path / "bk")
    import tarfile
    with tarfile.open(arch) as tar:
        assert "remotes/fw1.crowdsec-key" in tar.getnames() and "remotes/fw1.key" in tar.getnames()
    store.crowdsec_key_path(world.cfg.data_dir, "fw1").unlink()
    backup.restore(world.cfg, arch, conf)
    path = store.crowdsec_key_path(world.cfg.data_dir, "fw1")
    assert path.read_text().strip() == CSKEY and stat.S_IMODE(path.stat().st_mode) == 0o600


def test_member_paths_for_a_backup():
    assert store.member_path("/d", "remotes/fw1.crowdsec-key").name == "fw1.crowdsec-key"
    assert store.member_path("/d", "remotes/fw1.key").name == "fw1.key"
    assert store.member_path("/d", "remotes/../x.crowdsec-key") is None and store.member_path("/d", "remotes/a.crowdsec-key.bak") is None


def test_migration_adds_the_crowdsec_columns_to_a_version_9_database(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    conn = db.connect_writer(path)
    conn.execute("ALTER TABLE remotes DROP COLUMN crowdsec_url")
    conn.execute("ALTER TABLE remotes DROP COLUMN crowdsec_never")
    conn.execute("PRAGMA user_version=9")
    conn.close()
    assert "crowdsec_url" not in {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(remotes)")}
    conn = db.connect_writer(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION == 10
    assert {"crowdsec_url", "crowdsec_never"} <= {r[1] for r in conn.execute("PRAGMA table_info(remotes)")}
    conn.close()


def test_crowdsec_is_a_hub_rule_prefix():
    from daemonsight import hub
    assert "crowdsec." in hub.HUB_RULES and poll.RULE_PREFIX["opnsense"] == ("opnsense.", "crowdsec.")


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
    return {"kind": "opnsense", "name": "fw1", "url": URL, "key": KEY, "secret": SECRET, "tls": "verify", "interval": "60", **kw}


EDIT = dict(action="save", enabled="1", url=URL, key="", secret="", tls="verify", interval="60")


def cs(**kw):
    return {"crowdsec_on": "1", "crowdsec_url": "192.0.2.1:8180", "crowdsec_key": CSKEY, **kw}


def test_the_option_is_a_dependent_option_under_its_checkbox_on_an_opnsense_form_only(web):
    html = web.client.get("/remotes/new?kind=opnsense").text
    assert re.search(r'<input class="form-check-input" type="checkbox" id="crowdsec-on" name="crowdsec_on" value="1">', html)
    assert 'class="ds-subpanel mt-2" id="crowdsec" data-ds-when="crowdsec-on=on"' in html and "Read CrowdSec bans" in html
    sub = html.split('id="crowdsec"')[1].split("</form>")[0]
    for needle in ('name="crowdsec_url"', 'name="crowdsec_key"', 'type="password"', 'name="crowdsec_never"', "<textarea",
                   'value="test-crowdsec"', 'for="crowdsec_url"', 'for="crowdsec_key"', 'for="crowdsec_never"',
                   "cscli bouncers add daemonsight-hub", "prints the key once", "only read decisions", 'formaction="/remotes/new#crowdsec"'):
        assert needle in sub, needle
    form_html = html.split('<form method="post" action="/remotes/new#result"')[1].split("</form>")[0]
    assert 'id="crowdsec"' in form_html and form_html.count("<form") == 0         # one form, one Save
    assert "crowdsec-on" not in web.client.get("/remotes/new?kind=unraid").text
    # The never-ban list has an (i) panel that suggests adding the services you depend on, and ships no vendor ranges.
    assert 'popovertarget="src-never"' in html and "AI provider" in html
    assert check_panels(html) >= 1
    assert not re.search(r"\b(anthropic|openai|160\.79\.)", html, re.I)


def test_test_crowdsec_checks_the_local_api_and_never_touches_the_firewall(web):
    r = web.client.post("/remotes/new", data=form(action="test-crowdsec", key="", secret="", **cs()))
    assert r.status_code == 200 and "Connected to CrowdSec's Local API" in r.text and CSKEY not in r.text
    assert web.fw.requests == [] and web.lapi.queries() == [{"origins": "crowdsec", "limit": "1"}]
    pending = re.search(r'name="pending_crowdsec" value="([^"]+)"', r.text).group(1)
    assert pending and CSKEY not in r.text and "Held in memory" in r.text
    ok = web.client.post("/remotes/new", data=form(action="save", crowdsec_on="1", crowdsec_url="192.0.2.1:8180", pending_crowdsec=pending))
    assert ok.status_code == 303
    assert store.read_crowdsec_key(web.cfg.data_dir, "fw1") == CSKEY
    web.lapi.key = "another-key-another-key-another-key"
    bad = web.client.post("/remotes/new", data=form(action="test-crowdsec", **cs(crowdsec_key="z" * 40)))
    assert bad.status_code == 400 and "CrowdSec: CrowdSec refused the bouncer key" in bad.text and "z" * 40 not in bad.text
    off = web.client.post("/remotes/new", data=form(action="test-crowdsec", crowdsec_url="192.0.2.1:8180", crowdsec_key=CSKEY))
    assert "Tick Read CrowdSec bans first" in off.text


def test_saving_stores_the_address_the_list_and_the_key_file(web):
    r = web.client.post("/remotes/new", data=form(action="save", **cs(crowdsec_never="192.0.2.7, 198.51.100.0/24\n192.0.2.7")))
    assert r.status_code == 303
    c = web.conn()
    row = store.get(c, "fw1")
    assert row["crowdsec_url"] == "http://192.0.2.1:8180" and store.never_list(row) == ["192.0.2.7", "198.51.100.0/24"]
    c.close()
    path = store.crowdsec_key_path(web.cfg.data_dir, "fw1")
    assert path.read_text().strip() == CSKEY and stat.S_IMODE(path.stat().st_mode) == 0o600
    edit = web.client.get("/remotes/fw1/edit").text
    assert CSKEY not in edit and "A key is saved" in edit and 'value="http://192.0.2.1:8180"' in edit
    assert 'id="crowdsec-on" name="crowdsec_on" value="1" checked' in edit and "192.0.2.7\n198.51.100.0/24</textarea>" in edit


def test_a_bad_form_saves_nothing_and_says_which_field(web):
    for kw, msg in (({"crowdsec_url": ""}, "CrowdSec address"), ({"crowdsec_url": "ftp://x"}, "CrowdSec address"),
                    ({"crowdsec_key": ""}, "CrowdSec key: enter the key"), ({"crowdsec_key": "short"}, "CrowdSec key: The bouncer key must be"),
                    ({"crowdsec_never": "192.0.2.7\nnope"}, "Never-ban list: nope: not an IP"),
                    ({"crowdsec_never": "8.0.0.0/8"}, "Never-ban list: 8.0.0.0/8: too wide"),
                    ({"crowdsec_never": "\n".join(f"192.0.2.{i}" for i in range(1, 52))}, "At most 50")):
        r = web.client.post("/remotes/new", data=form(action="save", **cs(**kw)))
        assert r.status_code == 400 and msg in r.text, msg
        assert CSKEY not in r.text
    c = web.conn()
    assert c.execute("SELECT 1 FROM remotes").fetchone() is None
    c.close()
    assert not store.crowdsec_key_path(web.cfg.data_dir, "fw1").exists()


def test_editing_keeps_the_key_replaces_it_or_turns_crowdsec_off(web):
    web.client.post("/remotes/new", data=form(action="save", **cs(crowdsec_never=NEVER_IP)))
    path = store.crowdsec_key_path(web.cfg.data_dir, "fw1")
    base = dict(EDIT, crowdsec_on="1")
    assert web.client.post("/remotes/fw1/edit", data={**base, "crowdsec_url": "http://192.0.2.9:8180", "crowdsec_never": ""}).status_code == 303
    c = web.conn()
    row = store.get(c, "fw1")
    assert row["crowdsec_url"] == "http://192.0.2.9:8180" and store.never_list(row) == [] and path.read_text().strip() == CSKEY
    c.close()
    new = "n" * 40
    assert web.client.post("/remotes/fw1/edit", data={**base, "crowdsec_url": LAPI, "crowdsec_key": new}).status_code == 303
    assert path.read_text().strip() == new
    c = web.conn()
    db.put_snapshot(c, "fw1", crowdsec.SNAPSHOT, time.time(), True, None, {"entries": []})
    c.close()
    assert web.client.post("/remotes/fw1/edit", data=EDIT).status_code == 303
    c = web.conn()
    row = store.get(c, "fw1")
    assert row["crowdsec_url"] is None and row["crowdsec_never"] is None and db.get_snapshot(c, "fw1", crowdsec.SNAPSHOT) is None
    c.close()
    assert not path.exists()
    assert 'id="crowdsec-on" name="crowdsec_on" value="1" checked' not in web.client.get("/remotes/fw1/edit").text


def test_saving_a_system_without_crowdsec_leaves_it_unchanged(web):
    web.client.post("/remotes/new", data=form(action="save"))
    assert web.client.post("/remotes/fw1/edit", data=EDIT).status_code == 303
    c = web.conn()
    assert store.get(c, "fw1")["crowdsec_url"] is None
    c.close()


def test_turning_crowdsec_off_resolves_its_findings_at_the_next_poll(web):
    web.client.post("/remotes/new", data=form(action="save", **cs()))
    web.lapi.decisions = [decision(WAN)]
    web.poll(time.time())
    assert ("crowdsec.self_banned", WAN) in web.findings()
    web.client.post("/remotes/fw1/edit", data=EDIT)
    web.poll(time.time() + 5)
    assert web.findings() == {}


def test_removing_the_system_deletes_the_key_file(web):
    web.client.post("/remotes/new", data=form(action="save", **cs()))
    path = store.crowdsec_key_path(web.cfg.data_dir, "fw1")
    assert path.exists()
    assert web.client.post("/remotes/fw1/remove", data={"confirm": "fw1"}).status_code == 303
    assert not path.exists()


def _page_world(web, decisions=()):
    web.client.post("/remotes/new", data=form(action="save", **cs(crowdsec_never=NEVER_IP)))
    c = web.conn()
    c.execute("INSERT INTO hosts (id, token_hash, created_at, address) VALUES ('vps', 'x', ?, ?)", (NOW, VPS))
    c.close()
    web.lapi.decisions = list(decisions)
    web.poll(time.time())


def test_the_card_before_crowdsec_is_set_up_says_how(web):
    web.client.post("/remotes/new", data=form(action="save"))
    web.poll(time.time())
    html = web.client.get("/h/fw1/firewall").text
    assert 'id="crowdsec"' in html and "CrowdSec bans are not read for this system" in html and 'href="/remotes/fw1/edit#crowdsec"' in html
    assert "data-empty" in html.split('id="crowdsec"')[1].split(">")[0]


def test_the_card_lists_what_was_checked_with_status_labels_and_the_local_count(web):
    _page_world(web, [decision("203.0.113.200", scenario="crowdsecurity/ssh-bf", id_=1)])
    html = web.client.get("/h/fw1/firewall").text
    card = html.split('id="crowdsec"')[1].split("</section>")[0]
    assert "CrowdSec bans none of the" in card and "Not banned" in card and "Expected" in card
    for needle in (WAN, WAN2, VPS, NEVER_IP, "10.20.0.0/24", "This firewall", "A host the hub knows", "Your never-ban list", "host vps"):
        assert needle in card, needle
    assert "Local bans by scenario" in card and "crowdsecurity/ssh-bf" in card and "1 active ban" in card
    assert "cscli decisions list -i " + WAN in card and "cscli decisions list -r 10.20.0.0/24" in card
    assert f"{LAPI}/v1/decisions?ip=" in card and "X-Api-Key" in card and "$KEY" in card and CSKEY not in html
    assert check_panels(html) >= 5


def test_a_ban_shows_in_the_card_as_unexpected_and_on_the_overview_and_in_the_report(web):
    _page_world(web, [decision(WAN, id_=7)])
    card = web.client.get("/h/fw1/firewall").text.split('id="crowdsec"')[1].split("</section>")[0]
    assert "CrowdSec bans 1 of the" in card and "Banned" in card and "pf-scan-multi_ports" in card and "Unexpected" in card
    assert f'id="cs-{WAN}"' in card
    overview = web.client.get("/h/fw1/").text
    assert f"CrowdSec is banning this firewall&#39;s own address {WAN}" in overview or "CrowdSec is banning this firewall" in overview
    assert f"cscli decisions delete -i {WAN}" in overview and "What to do" in overview
    assert "/firewall#crowdsec" in overview
    report = web.client.get("/h/fw1/report.md").text
    assert "CrowdSec is banning" in report


def test_accepting_the_ban_keeps_it_visible_with_its_label(web):
    _page_world(web, [decision(WAN, id_=7)])
    r = web.client.post("/h/fw1/findings/accept", data={"rule": "crowdsec.self_banned", "key": WAN, "note": "testing", "next": "/h/fw1/firewall"})
    assert r.status_code in (200, 303)
    card = web.client.get("/h/fw1/firewall").text.split('id="crowdsec"')[1].split("</section>")[0]
    assert "Accepted" in card and "Banned" in card


def test_the_card_when_the_last_read_failed_shows_the_last_good_one_and_the_error(web):
    _page_world(web, [decision(WAN, id_=7)])
    web.lapi.fail = httpx.ConnectError("no route")
    web.poll(time.time() + 300)
    card = web.client.get("/h/fw1/firewall").text.split('id="crowdsec"')[1].split("</section>")[0]
    assert "The last read failed: Could not connect to CrowdSec" in card and "last good read" in card and WAN in card


def test_untrusted_text_from_crowdsec_is_escaped_on_the_page(web):
    _page_world(web, [decision(WAN, scenario="<script>alert(1)</script>", id_=7)])
    html = web.client.get("/h/fw1/firewall").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_every_section_anchor_exists_with_and_without_crowdsec(web):
    from .test_sections import check_registry
    web.client.post("/remotes/new", data=form(action="save"))
    web.poll(time.time())
    check_registry(web.client, "/h/fw1", "opnsense")
    web.client.post("/remotes/fw1/edit", data=dict(EDIT, **cs()))
    web.lapi.decisions = [decision(WAN)]
    web.poll(time.time() + 5)
    check_registry(web.client, "/h/fw1", "opnsense")
    from daemonsight.web import sections
    assert ("crowdsec", "CrowdSec") in sections.SECTIONS["opnsense"]["firewall"]
