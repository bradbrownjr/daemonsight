"""The OPNsense source: the GET-only client, what is kept from each reply, the roles, the rules, key files, the
poller, the pages and the privacy of the key and secret. Responses come from tests/fixtures/opnsense/, which are
synthetic (documentation addresses, made-up names) in the shape of the real replies."""

import asyncio
import copy
import logging
import re
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import db
from daemonsight.config import Config
from daemonsight.remote import opnsense, opnsense_rules as rules, poll, roles, store
from daemonsight.remote.client import RemoteError, Rest, fingerprint, fmt_fingerprint, normalize_url
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .fake_opnsense import FakeOpnsense, KEY, SECRET, load
from .fake_unraid import make_cert
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

NOW = 1_795_000_000.0
URL = "https://fw.test:8443"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def fake():
    return FakeOpnsense()


@pytest.fixture
def cfg(tmp_path):
    c = Config(host_id="hub", data_dir=str(tmp_path / "data"))
    c.hub.enabled = True
    return c


@pytest.fixture
def conn(cfg):
    c = db.connect_writer(cfg.db_path)
    yield c
    c.close()


def add(conn, cfg, name="fw1", now=NOW - 1000, **kw):
    store.add(conn, cfg.data_dir, name, "opnsense", URL, KEY, secret=SECRET, interval=60, now=now, **kw)
    return store.get(conn, name)


def read_all(fake) -> dict:
    """Every source parsed from the fixtures, keyed by its short name."""
    out = {}

    async def go():
        rest = Rest(URL, KEY, SECRET, fake.net().http(), opnsense.ALLOWED)
        try:
            for name, src in opnsense.SOURCES.items():
                out[name.removeprefix("opnsense_")] = await opnsense.read_source(rest, src)
        finally:
            await rest.aclose()
    run(go())
    return out


@pytest.fixture
def data(fake):
    return read_all(fake)


def evaluate(data, **kw):
    return rules.evaluate(data, kw.pop("now", NOW), **kw)


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


# --- the client sends GET and nothing else -----------------------------------------------------------------------

def test_the_client_only_gets_and_only_the_listed_paths(fake):
    rest = Rest(URL, KEY, SECRET, fake.net().http(), opnsense.ALLOWED)
    assert not [m for m in dir(rest) if m in ("post", "put", "delete", "patch", "request", "send")]
    for bad in ("/api/core/firmware/check", "/api/core/firmware/update", "/api/core/service/restart/unbound",
                "/api/tailscale/status/net", "/api/firewall/filter/apply", "/api/core/firmware/status/", "api/core/firmware/status",
                "/api/core/firmware/status?x=1", ""):
        with pytest.raises(ValueError):
            run(rest.get(bad))
    assert fake.requests == []      # nothing was sent for a refused path
    run(rest.get(opnsense.PATHS["firmware"]))
    run(rest.aclose())
    assert [r.method for r in fake.requests] == ["GET"]


def test_no_listed_endpoint_is_one_that_acts():
    forbidden = ("apply", "reconfigure", "check", "set", "add", "del", "toggle", "start", "stop", "restart", "upgrade",
                 "update", "install", "reboot", "reset", "flush", "kill")
    for key, path in opnsense.PATHS.items():
        segments = path.strip("/").split("/")
        assert segments[0] == "api" and not any(s in forbidden or s.startswith(("set", "add", "del")) and s != "settings"
                                                for s in segments[1:]), path
    assert opnsense.ALLOWED == frozenset(opnsense.PATHS.values())


def test_a_whole_poll_and_a_probe_send_only_gets(conn, cfg, fake):
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    run(opnsense.probe(fake.net(), URL, KEY, SECRET))
    assert fake.requests and {r.method for r in fake.requests} == {"GET"}
    assert {r.url.path for r in fake.requests} <= opnsense.ALLOWED
    assert all(r.url.query == b"" for r in fake.requests)
    assert all("content-type" not in r.headers for r in fake.requests)


def test_the_key_and_secret_go_in_basic_auth_only(fake):
    run(opnsense.probe(fake.net(), URL, KEY, SECRET))
    for r in fake.requests:
        assert r.headers["authorization"].startswith("Basic ")
        assert KEY not in str(r.url) and SECRET not in str(r.url)


def test_a_redirect_is_an_error_and_is_not_followed(fake):
    fake.status = 302
    p = run(opnsense.probe(fake.net(), URL, KEY, SECRET))
    assert {s["state"] for s in p.sources} == {"error"} and all("redirect" in s["note"].lower() for s in p.sources)
    assert {r.url.host for r in fake.requests} == {"fw.test"}


def test_normalize_url_for_opnsense():
    assert normalize_url("fw.example.lan:8443", "opnsense") == "https://fw.example.lan:8443"
    assert normalize_url("https://fw.example.lan/", "opnsense") == "https://fw.example.lan"
    for bad in ("http://fw.lan", "", "https://user:pw@fw.lan", "https://fw.lan/api/core"):
        with pytest.raises(ValueError):
            normalize_url(bad, "opnsense")


# --- the privilege list ------------------------------------------------------------------------------------------

def test_the_privilege_list_matches_the_sources():
    assert [n for n, _ in store.OPNSENSE_PRIVILEGE_USE] == list(store.OPNSENSE_PRIVILEGES)
    assert set(store.OPNSENSE_PRIVILEGES) == set(opnsense.ALL_PRIVILEGES)
    assert [n for n, _ in store.GUIDES["opnsense"]["privileges"]] == list(store.OPNSENSE_PRIVILEGES)
    assert store.OPNSENSE_PRIVILEGES == ("Lobby: Dashboard", "Status: Interfaces", "System: Gateways", "VPN: WireGuard: Status",
                                         "Status: Services", "Firewall: Rules [new]", "Firewall: NAT: Destination NAT",
                                         "System: Firmware", "Services: Caddy", "Tailscale")
    used = {p for s in opnsense.SOURCES.values() for p in s.paths}
    assert used == set(opnsense.PATHS)     # every endpoint belongs to a source


# --- what is kept from each reply --------------------------------------------------------------------------------

def test_parse_firmware(data):
    fw = data["firmware"]
    assert fw["version"] == "26.1.2_3" and fw["new_version"] == "26.1.5" and fw["count"] == 2 and not fw["needs_reboot"]
    assert {p["name"] for p in fw["packages"]} == {"opnsense", "os-example-devel"} and fw["pending_since"] is None


def test_parse_interfaces_keeps_assigned_and_tunnels_only(data):
    ids = [i["id"] for i in data["interfaces"]["interfaces"]]
    assert ids == ["wan", "lan", "opt1", "opt2", "opt3", ""]        # enc0 (unassigned, not a tunnel) is dropped; wg1 stays
    wan = data["interfaces"]["interfaces"][0]
    assert wan["gateways"] == ["192.0.2.1"] and wan["addresses"] == ["192.0.2.10/24"] and wan["blocks_private"]


def test_parse_gateways_and_services_and_system(data):
    gw = data["gateways"]["gateways"][0]
    assert gw["name"] == "WAN_DHCP" and gw["loss"] == 0.0 and gw["delay"] == 4.2
    assert [s["id"] for s in data["services"]["services"]] == ["unbound", "dhcpd", "ntpd"]
    s = data["system"]
    assert s["memory"]["percent"] == 25.0 and s["disks"][0]["percent"] == 20 and s["temperatures"] == [{"device": "cpu 0", "celsius": 45}]


def test_parse_wireguard_cuts_keys_and_shows_an_instance_with_no_peer(data):
    inst = {i["if"]: i for i in data["wireguard"]["instances"]}
    assert inst["wg1"]["peers"] == [] and [p["name"] for p in inst["wg0"]["peers"]] == ["laptop", "phone"]
    laptop, phone = inst["wg0"]["peers"]
    assert len(laptop["key"]) == 8 and laptop["handshake"] == 1_795_000_000 - 60 and phone["handshake"] is None
    dump = repr(data["wireguard"])
    assert "SYNTHETICPUBLICKEY" not in dump and "LAPTOPKEYSYNTHETIC00" not in dump      # only the first eight characters


def test_parse_rules_counts_generated_ones_and_legacy_ones(data):
    r = data["rules"]
    assert len(r["rules"]) == 4 and r["automatic"] == 2 and r["legacy"] == 1
    assert "Default deny" not in repr(r)


def test_parse_nat_resolves_alias_targets_and_ports(data):
    f = {x["uuid"][-1]: x for x in data["nat"]["forwards"]}
    assert f["1"]["target_ips"] == ["10.20.0.8"] and f["1"]["local_ports"] == [80] and f["1"]["dest_ports"] == [8080]
    assert f["2"]["target"] == "web_hosts" and f["2"]["target_ips"] == ["10.20.0.9"]


def test_parse_caddy_keeps_named_fields_and_no_secrets(data):
    c = data["caddy"]
    assert [s["domain"] for s in c["sites"]] == ["app.example.test", "private.example.test"]
    app, private = c["sites"]
    assert app["acl"] == [] and private["acl"] == ["office"] and app["handles"][0]["to"] == ["10.20.0.8"]
    assert app["handles"][0]["port"] == "3000" and private["handles"][0]["scheme"] == "https" and c["service"] == "running"
    dump = repr(c)
    assert "SYNTHETIC-DNS-API-TOKEN" not in dump and "admin@example.invalid" not in dump


def test_parse_tailscale_keeps_counts_not_peers(data):
    t = data["tailscale"]
    assert t["state"] == "Running" and t["peers"] == 2 and t["wants_routes"] == ["10.20.0.0/24"] and t["routes"] == ["10.20.0.0/24"]
    assert "laptop" not in repr(t) and "phone" not in repr(t)


def test_text_from_the_firewall_is_cut_and_cleaned(fake):
    fake.edit("services", lambda d: d["rows"][0].update(description="x" * 500 + "\x1b[31m"))
    svc = read_all(fake)["services"]["services"][0]
    assert len(svc["description"]) <= 100 and "\x1b" not in svc["description"]


# --- roles ------------------------------------------------------------------------------------------------------

def test_roles_are_worked_out_from_what_the_firewall_reports(data):
    got = {k: v["role"] for k, v in rules.interface_roles(data, None).items()}
    assert got == {"wan": "wan", "lan": "lan", "opt1": "lan", "opt2": "vpn", "opt3": "wan"}


@pytest.mark.parametrize("iface,role", [
    ({"id": "opt9", "name": "Uplink", "device": "igb0", "gateways": ["203.0.113.1"], "addresses": ["203.0.113.5/24"]}, "wan"),
    ({"id": "wan2", "name": "WAN2", "device": "igb1", "gateways": [], "addresses": []}, "wan"),
    ({"id": "opt1", "name": "Home", "device": "igb2", "gateways": [], "addresses": ["10.1.0.1/24"]}, "lan"),
    ({"id": "opt2", "name": "VPN", "device": "wg3", "gateways": ["10.9.0.1"], "addresses": ["10.9.0.2/24"]}, "vpn"),
    ({"id": "opt3", "name": "ts", "device": "tailscale0", "gateways": [], "addresses": ["100.64.0.1"]}, "vpn"),
    ({"id": "lo0", "name": "Loopback", "device": "lo0", "gateways": [], "addresses": ["127.0.0.1"]}, "other"),
    ({"id": "opt4", "name": "Empty", "device": "igb3", "gateways": [], "addresses": []}, "other"),
    ({"id": "opt5", "name": "WANDERER", "device": "igb4", "gateways": [], "addresses": ["10.7.0.1/24"]}, "lan"),    # not "wan" as a word
])
def test_classify(iface, role):
    assert roles.classify(iface)[0] == role


def test_an_override_changes_the_role_and_the_findings(data):
    assert not by_rule(evaluate(data), "opnsense.rule_any")
    # The guest network is really untrusted here: a pass-any rule on it would now count, and LAN stays trusted.
    data["rules"]["rules"].append({**data["rules"]["rules"][1], "uuid": "aaaaaaaa-0000-4000-8000-000000000009", "interface": "opt1",
                                   "description": "Guest to anywhere"})
    assert not by_rule(evaluate(data), "opnsense.rule_any")
    got = by_rule(evaluate(data, overrides={"opt1": "wan"}), "opnsense.rule_any")
    assert len(got) == 1 and "Guest" in got[0].title
    assert roles.assign([{"id": "opt1", "name": "Guest", "device": "re2", "gateways": [], "addresses": ["10.30.0.1/24"]}],
                        {"opt1": "wan", "gone": "wan", "opt1x": "banana"})["opt1"]["overridden"]


def test_overrides_are_stored_in_the_hub_and_deleted_with_the_system(conn, cfg):
    add(conn, cfg)
    assert roles.load_overrides(conn, "fw1") == {}
    roles.save_overrides(conn, "fw1", {"opt1": "wan", "opt2": "nonsense"})
    assert roles.load_overrides(conn, "fw1") == {"opt1": "wan"}
    store.remove(conn, cfg.data_dir, "fw1")
    assert roles.load_overrides(conn, "fw1") == {}


# --- the rules --------------------------------------------------------------------------------------------------

def test_fixture_data_findings(data):
    got = {(f.rule, f.key) for f in evaluate(data)}
    assert ("opnsense.updates", "updates") in got and ("opnsense.rule_floating_any", "11111111-aaaa-4aaa-8aaa-000000000004") in got
    assert ("opnsense.nat_all_ports", "22222222-bbbb-4bbb-8bbb-000000000002") in got and ("opnsense.wg_no_peer", "wg1") in got
    assert ("opnsense.caddy_no_acl", "sites") in got
    for f in evaluate(data):
        assert f.rule.startswith("opnsense.") and f.howto and f.link.startswith("/") and f.basis


def test_firmware_updates_and_reboot(data):
    fw = data["firmware"]
    f = by_rule(evaluate(data), "opnsense.updates")[0]
    assert f.severity == "low" and "26.1.5" in f.title and "never starts one" in f.detail
    fw["packages"] += [{"name": f"p{i}", "old": "1", "new": "2", "reason": "upgrade"} for i in range(6)]
    fw["count"] = fw["count_packages"] = len(fw["packages"])
    assert by_rule(evaluate(data), "opnsense.updates")[0].severity == "medium"
    fw["count"] = fw["count_packages"] = 25
    assert by_rule(evaluate(data), "opnsense.updates")[0].severity == "high"
    fw["count"] = fw["count_packages"] = 2
    fw["pending_since"] = NOW - 31 * 86400
    assert by_rule(evaluate(data), "opnsense.updates")[0].severity == "high"
    assert not by_rule(evaluate(data), "opnsense.reboot")
    fw["needs_reboot"] = True
    assert by_rule(evaluate(data), "opnsense.reboot")[0].severity == "medium"
    fw.update(count=0, count_packages=0, packages=[], needs_reboot=False)
    assert not by_rule(evaluate(data), "opnsense.updates")


def test_the_updates_basis_changes_with_the_packages_not_the_count(data):
    a = by_rule(evaluate(data), "opnsense.updates")[0].basis
    data["firmware"]["pending_since"] = NOW - 5 * 86400
    assert by_rule(evaluate(data), "opnsense.updates")[0].basis == a
    data["firmware"]["packages"][0]["new"] = "26.1.6"
    assert by_rule(evaluate(data), "opnsense.updates")[0].basis != a


def test_gateways(data):
    assert not by_rule(evaluate(data), "opnsense.gateway")
    gw = data["gateways"]["gateways"]
    gw[0].update(status="down", status_text="Offline")
    f = by_rule(evaluate(data), "opnsense.gateway")
    assert len(f) == 1 and f[0].severity == "high" and "down" in f[0].title and f[0].link == "/network#gw-WAN_DHCP"
    gw[0].update(status="none", loss=10.0)
    assert by_rule(evaluate(data), "opnsense.gateway")[0].severity == "medium"
    gw[0].update(loss=0.0, delay=300.0)
    assert by_rule(evaluate(data), "opnsense.gateway")
    gw[0].update(delay=299.0)
    assert not by_rule(evaluate(data), "opnsense.gateway")


def test_wireguard_peers_and_instances(data):
    got = {f.key: f for f in by_rule(evaluate(data), "opnsense.wg_peer_stale")}
    assert list(got) == ["wg0:PHONEKEY"] and got["wg0:PHONEKEY"].severity == "low"      # never connected, no keepalive
    peer = data["wireguard"]["instances"][0]["peers"][0]
    peer["handshake"] = NOW - 86401
    got = {f.key: f for f in by_rule(evaluate(data), "opnsense.wg_peer_stale")}
    assert got["wg0:LAPTOPKE"].severity == "medium" and "24 hours" in got["wg0:LAPTOPKE"].title      # a keepalive peer: meant to stay up
    peer["handshake"] = NOW - 86399
    assert "wg0:LAPTOPKE" not in {f.key for f in by_rule(evaluate(data), "opnsense.wg_peer_stale")}
    f = by_rule(evaluate(data), "opnsense.wg_no_peer")
    assert [x.key for x in f] == ["wg1"] and f[0].severity == "high"


def test_pass_rules_on_untrusted_interfaces(data):
    r = data["rules"]["rules"]
    got = {f.rule: f for f in evaluate(data) if f.rule.startswith("opnsense.rule_")}
    assert set(got) == {"opnsense.rule_floating_any"}       # the LAN pass-any rule and the described WAN rules are fine
    r.append({**r[0], "uuid": "bbbbbbbb-0000-4000-8000-00000000000a", "protocol": "any", "destination": "any", "destination_port": "",
              "description": "Everything in"})
    r.append({**r[0], "uuid": "bbbbbbbb-0000-4000-8000-00000000000b", "description": "", "destination_port": "8443"})
    r.append({**r[0], "uuid": "bbbbbbbb-0000-4000-8000-00000000000c", "enabled": False, "protocol": "any", "destination": "any",
              "destination_port": "", "description": "Off"})
    r.append({**r[0], "uuid": "bbbbbbbb-0000-4000-8000-00000000000d", "interface": "lan", "protocol": "any", "destination": "any",
              "destination_port": "", "description": "LAN anything"})
    found = {(f.rule, f.key[-1]) for f in evaluate(data) if f.rule.startswith("opnsense.rule_")}
    assert ("opnsense.rule_any", "a") in found and ("opnsense.rule_no_descr", "b") in found
    assert not {k for _, k in found} & {"c", "d"}        # disabled, and on a trusted interface
    # A rule that names its interface by label (a classic one) is matched too.
    r.append({**r[0], "uuid": "bbbbbbbb-0000-4000-8000-00000000000e", "interface": "WAN", "legacy": True, "protocol": "any",
              "destination": "any", "destination_port": "", "description": "Old any"})
    assert ("opnsense.rule_any", "e") in {(f.rule, f.key[-1]) for f in evaluate(data)}


def test_port_forwards(data):
    got = {f.rule + ":" + f.key[-1]: f for f in evaluate(data) if f.rule.startswith("opnsense.nat_")}
    assert set(got) == {"opnsense.nat_all_ports:2"}          # the DNS redirect is on LAN, and the others have ports
    assert got["opnsense.nat_all_ports:2"].severity == "high"
    data["nat"]["forwards"][1]["enabled"] = False
    assert not by_rule(evaluate(data), "opnsense.nat_all_ports")


def test_a_forward_to_a_host_with_nothing_listening(data):
    hosts = {"web": {"ips": {"10.20.0.8"}, "listeners": [{"proto": "tcp", "port": 22, "addresses": ["0.0.0.0"]}]}}
    dead = by_rule(evaluate(data, hosts=hosts), "opnsense.nat_dead")
    assert len(dead) == 1 and dead[0].key.endswith(":80") and "web" in dead[0].detail and dead[0].severity == "medium"
    hosts["web"]["listeners"].append({"proto": "tcp", "port": 80, "addresses": ["10.20.0.8"]})
    assert not by_rule(evaluate(data, hosts=hosts), "opnsense.nat_dead")
    # No collector host owns the address: nothing is said.
    assert not by_rule(evaluate(data, hosts={"other": {"ips": {"10.20.0.99"}, "listeners": []}}), "opnsense.nat_dead")
    assert not by_rule(evaluate(data, hosts={}), "opnsense.nat_dead")


def test_caddy(data):
    f = by_rule(evaluate(data), "opnsense.caddy_no_acl")
    assert len(f) == 1 and f[0].severity == "info" and "app.example.test" in f[0].detail and "private.example.test" not in f[0].detail
    # Not reachable from the internet (no rule lets 80/443 in): not listed.
    saved = copy.deepcopy(data["rules"])
    data["rules"]["rules"][0]["destination_port"] = "8443"
    data["rules"]["rules"][3]["enabled"] = False         # the floating pass-all rule would open them too
    assert not by_rule(evaluate(data), "opnsense.caddy_no_acl")
    data["rules"] = saved
    data["caddy"]["sites"][1]["acl"] = []
    assert "2 internet-facing" in by_rule(evaluate(data), "opnsense.caddy_no_acl")[0].title
    data["caddy"]["service"] = "stopped"
    assert by_rule(evaluate(data), "opnsense.caddy_down")[0].severity == "high"
    hosts = {"app": {"ips": {"10.20.0.8"}, "listeners": [{"proto": "tcp", "port": 8080, "addresses": ["*"]}]}}
    dead = by_rule(evaluate(data, hosts=hosts), "opnsense.caddy_dead_upstream")
    assert len(dead) == 1 and "10.20.0.8:3000" in dead[0].title
    hosts["app"]["listeners"].append({"proto": "tcp", "port": 3000, "addresses": ["10.20.0.8"]})
    assert not by_rule(evaluate(data, hosts=hosts), "opnsense.caddy_dead_upstream")


def test_the_caddy_list_changes_its_basis_when_a_site_is_added(data):
    a = by_rule(evaluate(data), "opnsense.caddy_no_acl")[0].basis
    extra = copy.deepcopy(data["caddy"]["sites"][0])
    extra.update(uuid="x", domain="new.example.test")
    data["caddy"]["sites"].append(extra)
    assert by_rule(evaluate(data), "opnsense.caddy_no_acl")[0].basis != a


def test_tailscale(data):
    assert not by_rule(evaluate(data), "opnsense.tailscale")
    t = data["tailscale"]
    t["wants_exit_node"] = True
    assert [f.key for f in by_rule(evaluate(data), "opnsense.tailscale")] == ["exit"]
    t["exit_node_option"] = True
    t["wants_routes"] = ["10.20.0.0/24", "10.50.0.0/24"]
    assert [f.key for f in by_rule(evaluate(data), "opnsense.tailscale")] == ["route:10.50.0.0/24"]
    t["state"] = "NeedsLogin"
    assert [f.key for f in by_rule(evaluate(data), "opnsense.tailscale")] == ["state"]
    t["enabled"] = False
    assert not by_rule(evaluate(data), "opnsense.tailscale")


def test_services_disks_and_temperature(data):
    data["services"]["services"][0]["running"] = False
    f = by_rule(evaluate(data), "opnsense.service_stopped")
    assert len(f) == 1 and f[0].link == "/network#svc-unbound"
    d, t = data["system"]["disks"][0], data["system"]["temperatures"][0]
    for pct, sev in ((89, None), (90, "medium"), (94, "medium"), (95, "high")):
        d["percent"] = pct
        got = by_rule(evaluate(data), "opnsense.disk_full")
        assert (got[0].severity if got else None) == sev, pct
    for c, sev in ((79, None), (80, "medium"), (89, "medium"), (90, "high")):
        t["celsius"] = c
        got = by_rule(evaluate(data), "opnsense.temperature")
        assert (got[0].severity if got else None) == sev, c


def test_a_source_that_cannot_be_read_gives_no_findings_and_no_crash(data):
    for name in list(data):
        data[name] = None
    assert evaluate(data) == []


def test_every_hub_rule_prefix_is_known_to_the_hub():
    from daemonsight import hub
    assert "opnsense." in hub.HUB_RULES


# --- key files and the form -------------------------------------------------------------------------------------

def test_the_key_file_has_two_lines_and_is_private(cfg, conn):
    add(conn, cfg)
    path = store.key_path(cfg.data_dir, "fw1")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert path.read_text().split() == [KEY, SECRET] and store.read_credentials(cfg.data_dir, "fw1") == (KEY, SECRET)
    store.write_key(cfg.data_dir, "fw1", "K" * 40, "S" * 40)
    assert store.read_credentials(cfg.data_dir, "fw1") == ("K" * 40, "S" * 40) and not list(path.parent.glob("*.tmp"))
    path.write_text(KEY + "\n")
    assert store.read_credentials(cfg.data_dir, "fw1") is None      # a half-written file is not used
    with pytest.raises(ValueError):
        store.write_key(cfg.data_dir, "fw1", KEY, "short")


def test_an_opnsense_system_needs_a_secret_and_an_unraid_one_must_not_have_one(conn, cfg):
    with pytest.raises(ValueError):
        store.add(conn, cfg.data_dir, "fw1", "opnsense", URL, KEY, now=NOW)
    with pytest.raises(ValueError):
        store.add(conn, cfg.data_dir, "tower", "unraid", "https://tower.test:4443", KEY, secret=SECRET, now=NOW)


def test_the_key_and_secret_are_never_in_the_database(cfg, conn, fake):
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    conn.execute("PRAGMA wal_checkpoint(FULL)")
    for p in cfg.db_path.parent.glob("state.db*"):
        blob = p.read_bytes()
        assert KEY.encode() not in blob and SECRET.encode() not in blob, p.name
    assert KEY not in repr(dict(store.get(conn, "fw1")))


def test_removing_deletes_the_key_file(conn, cfg):
    add(conn, cfg)
    path = store.key_path(cfg.data_dir, "fw1")
    assert path.exists()
    store.remove(conn, cfg.data_dir, "fw1")
    assert not path.exists()


# --- the poller -------------------------------------------------------------------------------------------------

def test_a_poll_stores_every_source_and_opens_findings(conn, cfg, fake):
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    snaps = db.get_snapshots(conn, "fw1")
    assert set(snaps) >= set(opnsense.SOURCES)
    assert all(s.ok for n, s in snaps.items() if n.startswith("opnsense_"))
    open_rules = {r["rule"] for r in conn.execute("SELECT rule FROM findings WHERE host='fw1' AND resolved_at IS NULL")}
    assert {"opnsense.updates", "opnsense.wg_no_peer", "opnsense.nat_all_ports"} <= open_rules
    assert snaps["opnsense_firmware"].data["pending_since"] == NOW
    run(poll.run_once(conn, cfg, fake.net(), NOW + 400))
    assert db.get_snapshot(conn, "fw1", "opnsense_firmware").data["pending_since"] == NOW       # kept, not reset
    h = conn.execute("SELECT version FROM hosts WHERE id='fw1'").fetchone()
    assert h["version"] == "OPNsense 26.1.2_3"


def test_a_finding_resolves_when_the_cause_is_gone(conn, cfg, fake):
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    fake.edit("wireguard", lambda d: d["rows"].append({"if": "wg1", "type": "peer", "public-key": "PEERKEYSYNTHETIC", "endpoint": "203.0.113.9:51821",
                                                       "allowed-ips": "10.98.0.2/32", "latest-handshake": int(NOW + 590), "transfer-rx": 1, "transfer-tx": 1,
                                                       "persistent-keepalive": "25", "name": "site-b", "ifname": "wg1"}))
    run(poll.run_once(conn, cfg, fake.net(), NOW + 600))
    assert not conn.execute("SELECT 1 FROM findings WHERE host='fw1' AND rule='opnsense.wg_no_peer' AND resolved_at IS NULL").fetchone()
    assert conn.execute("SELECT 1 FROM findings WHERE host='fw1' AND rule='opnsense.wg_no_peer' AND resolved_at IS NOT NULL").fetchone()
    assert conn.execute("SELECT 1 FROM events WHERE host='fw1' AND kind='finding_resolved'").fetchone()


def test_a_source_without_privilege_shows_which_one_and_the_rest_work(conn, cfg, fake):
    fake.deny_source("opnsense_rules")
    fake.deny_source("opnsense_firmware")
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    snaps = db.get_snapshots(conn, "fw1")
    r = snaps["opnsense_rules"]
    assert not r.ok and r.error == "Needs privilege Firewall: Rules [new]" and r.data["needs_privilege"] == "Firewall: Rules [new]"
    assert snaps["opnsense_gateways"].ok and snaps["opnsense_nat"].ok
    open_rules = {x["rule"] for x in conn.execute("SELECT rule FROM findings WHERE host='fw1' AND resolved_at IS NULL")}
    assert not {"opnsense.updates", "opnsense.rule_floating_any"} & open_rules and "opnsense.nat_all_ports" in open_rules
    assert store.get(conn, "fw1")["fails"] == 0        # a missing privilege is not an unreachable firewall


def test_a_plugin_that_is_not_installed_is_not_a_problem(conn, cfg, fake):
    fake.absent_source("opnsense_caddy")
    fake.absent_source("opnsense_tailscale")
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    snaps = db.get_snapshots(conn, "fw1")
    for n in ("opnsense_caddy", "opnsense_tailscale"):
        assert snaps[n].ok and snaps[n].data["available"] is False and "Not installed" in snaps[n].data["reason"]
    assert store.get(conn, "fw1")["fails"] == 0


def test_a_refused_key_and_an_unreachable_firewall_are_recorded_without_the_key(conn, cfg, fake):
    add(conn, cfg)
    fake.key = "z" * 40
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    row = store.get(conn, "fw1")
    assert row["fails"] == 1 and "refused" in row["last_error"] and KEY not in row["last_error"] and SECRET not in row["last_error"]
    fake.key = KEY
    fake.fail = httpx.ConnectError(f"boom {KEY} {SECRET}")
    for i in range(1, 5):
        run(poll.run_once(conn, cfg, fake.net(), NOW + 61 * i))
    row = store.get(conn, "fw1")
    assert row["fails"] >= 3 and KEY not in row["last_error"] and SECRET not in row["last_error"]
    assert conn.execute("SELECT 1 FROM findings WHERE host='fw1' AND rule='remote.unreachable' AND resolved_at IS NULL").fetchone()


def test_every_probe_result_lists_each_source(fake):
    fake.deny_source("opnsense_rules")
    fake.absent_source("opnsense_tailscale")
    p = run(opnsense.probe(fake.net(), URL, KEY, SECRET))
    states = {s["title"]: s["state"] for s in p.sources}
    assert p.ok and states["Firewall rules"] == "forbidden" and states["Tailscale"] == "absent" and states["Gateways"] == "ok"
    assert p.missing == ["Firewall: Rules [new]"]
    fake.deny |= {pth for pth in opnsense.PATHS.values()}
    p = run(opnsense.probe(fake.net(), URL, KEY, SECRET))
    assert not p.ok and "may not read anything" in p.problem


def test_a_wrong_key_stops_the_probe(fake):
    with pytest.raises(RemoteError) as e:
        run(opnsense.probe(fake.net(), URL, "wrong" * 8, SECRET))
    assert e.value.kind == "auth" and KEY not in e.value.message


# --- the web pages ----------------------------------------------------------------------------------------------

@pytest.fixture
def app_client(hub_cfg, fake):
    def make():
        return TestClient(create_app(hub_cfg, remote_net=fake.net()), follow_redirects=False)
    return make


@pytest.fixture
def c(app_client):
    client = app_client()
    assert client.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    return client


def form(**kw):
    return {"kind": "opnsense", "name": "fw1", "url": URL, "key": KEY, "secret": SECRET, "tls": "verify", "interval": "60", **kw}


def conn_of(hub_cfg):
    return db.connect_writer(hub_cfg.db_path)


def poll_now(hub_cfg, fake, at=None):
    cn = conn_of(hub_cfg)
    try:
        run(poll.run_once(cn, hub_cfg, fake.net(), at or time.time()))
    finally:
        cn.close()


def test_the_form_for_opnsense(c):
    html = c.get("/remotes/new?kind=opnsense").text
    assert 'name="secret"' in html and "OPNsense · REST API" in html and 'id="privilege-list"' in html
    for name in store.OPNSENSE_PRIVILEGES:
        assert f"<code>{name}</code>" in html
    assert "<details" in html and 'class="col-lg-4"' not in html            # the guide is folded in the card, not beside it
    assert "docs.opnsense.org" in html and 'rel="noopener noreferrer"' in html
    assert 'name="secret"' not in c.get("/remotes/new").text


def test_adding_an_opnsense_system(c, hub_cfg, fake):
    r = c.post("/remotes/new", data=form(action="test"))
    assert r.status_code == 200 and "Connected. The key is accepted." in r.text and 'id="privileges"' in r.text
    assert "Readable" in r.text and "OPNsense 26.1.2_3" in r.text
    assert fake.requests and {q.method for q in fake.requests} == {"GET"}
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()
    r = c.post("/remotes/new", data=form(action="save"))
    assert r.status_code == 303
    row = conn_of(hub_cfg).execute("SELECT * FROM remotes WHERE id='fw1'").fetchone()
    assert row["kind"] == "opnsense" and store.read_credentials(hub_cfg.data_dir, "fw1") == (KEY, SECRET)


def test_a_key_without_a_secret_is_refused(c, hub_cfg):
    r = c.post("/remotes/new", data=form(action="save", secret=""))
    assert r.status_code == 400 and "secret" in r.text and not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()


def test_the_test_lists_the_privilege_a_source_needs(c, hub_cfg, fake):
    fake.deny_source("opnsense_nat")
    fake.absent_source("opnsense_caddy")
    r = c.post("/remotes/new", data=form(action="test"))
    assert "Needs privilege Firewall: NAT: Destination NAT" in r.text and "Plugin not installed" in r.text and "Connected." in r.text
    assert c.post("/remotes/new", data=form(action="save")).status_code == 303       # a missing privilege does not stop the save
    fake.deny |= set(opnsense.PATHS.values())
    r = c.post("/remotes/new", data=form(action="test", name="fw2"))
    assert r.status_code == 200 and "Not saved." in r.text and "may not read anything" in r.text


def test_a_self_signed_firewall_is_pinned_only_after_confirming(c, hub_cfg, fake, tmp_path):
    pem, _, _ = make_cert(tmp_path, "fw.test")
    fp = fmt_fingerprint(fingerprint(pem))
    fake.server_cert = pem
    r = c.post("/remotes/new", data=form(action="test"))
    assert fp in r.text and fake.requests == []         # the key was not sent before the fingerprint was confirmed
    ok = c.post("/remotes/new", data=form(action="test", tls="pin", trust=fp))
    assert "Connected." in ok.text and fake.requests
    assert c.post("/remotes/new", data=form(action="save", tls="pin", pin_confirm=fp)).status_code == 303
    row = conn_of(hub_cfg).execute("SELECT * FROM remotes WHERE id='fw1'").fetchone()
    assert row["tls"] == "pin" and row["tls_pin"] == fingerprint(pem)
    other, _, _ = make_cert(tmp_path / "b", "fw.test")
    fake.server_cert = other
    fake.requests.clear()
    poll_now(hub_cfg, fake, time.time())
    err = store.get(conn_of(hub_cfg), "fw1")["last_error"]
    assert "certificate was not accepted" in err and fake.requests == []


def _added(c, hub_cfg, fake, at=None):
    assert c.post("/remotes/new", data=form(action="save")).status_code == 303
    poll_now(hub_cfg, fake, at)


PAGES = ("/h/fw1/", "/h/fw1/firewall", "/h/fw1/vpn", "/h/fw1/network", "/h/fw1/report", "/h/fw1/report.md")


def test_every_page_renders_with_its_tables_and_labels(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    for path in PAGES:
        assert c.get(path).status_code == 200, path
    fw = c.get("/h/fw1/firewall").text
    assert "Pass rules on internet-facing interfaces" in fw and "Allow HTTPS to Caddy" in fw and "Old SSH rule" in fw
    assert "LAN to anywhere" not in fw and "Anti-lockout" not in fw
    assert 'id="fwd-22222222-bbb' in fw and "Unexpected" in fw and "all ports" in fw
    assert "app.example.test" in fw and "10.20.0.8:3000" in fw and "private.example.test" in fw
    assert 'id="site-app.example.test"' in fw and "Open in OPNsense" in fw
    vpn = c.get("/h/fw1/vpn").text
    assert "laptop" in vpn and "no peer attached" in vpn and "10.20.0.0/24" in vpn and 'id="wg-wg1"' in vpn
    net = c.get("/h/fw1/network").text
    assert "WAN_DHCP" in net and "WAN (internet-facing)" in net and "unbound" in net and "Save roles" in net
    home = c.get("/h/fw1/").text
    assert "Pending firmware updates" in home and "opnsense" in home.lower() and 'id="firmware"' in home and "OPNsense 26.1.2_3" in home
    for html in (fw, vpn, net, home):
        check_panels(html)
    nav = fw
    assert "/h/fw1/firewall" in nav and "/h/fw1/vpn" in nav and "/h/fw1/network" in nav
    assert "/h/fw1/exposure" not in nav and "/h/fw1/disks" not in nav


def test_an_unraid_page_is_not_served_for_a_firewall_and_the_other_way_round(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    for page in ("disks", "containers", "vms", "notifications"):
        assert c.get(f"/h/fw1/{page}").status_code == 404, page


def test_a_row_panel_shows_the_get_request_with_placeholders(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    html = c.get("/h/fw1/firewall").text
    assert "curl -s -u" in html and "$KEY:$SECRET" in html and "/api/firewall/d_nat/search_rule" in html
    assert KEY not in html and SECRET not in html
    for bad in ("-X POST", "-X PUT", "-X DELETE", "--data", " -d "):
        assert bad not in html


def test_findings_link_to_rows_that_exist(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    conn = conn_of(hub_cfg)
    pages = {"": c.get("/h/fw1/").text, "firewall": c.get("/h/fw1/firewall").text, "vpn": c.get("/h/fw1/vpn").text,
             "network": c.get("/h/fw1/network").text}
    rows = conn.execute("SELECT rule, link FROM findings WHERE host='fw1' AND resolved_at IS NULL AND rule LIKE 'opnsense.%'").fetchall()
    assert rows
    for r in rows:
        page, _, frag = r["link"].lstrip("/").partition("#")
        assert page in pages, r["link"]
        assert f'id="{frag}"' in pages[page], (r["rule"], r["link"])


def test_accepting_a_firewall_finding_labels_it_and_a_change_brings_it_back(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    conn = conn_of(hub_cfg)
    assert conn.execute("SELECT 1 FROM findings WHERE host='fw1' AND rule='opnsense.nat_all_ports'").fetchone()
    page = c.get("/h/fw1/firewall").text
    assert "Unexpected" in page
    r = c.post("/h/fw1/findings/accept", data={"rule": "opnsense.nat_all_ports", "key": "22222222-bbbb-4bbb-8bbb-000000000002", "note": "intended", "next": "/h/fw1/firewall"},
               headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    assert "Accepted" in c.get("/h/fw1/firewall").text      # still listed, labelled, never hidden


def test_interface_roles_can_be_overridden_in_the_gui(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    conn = conn_of(hub_cfg)
    assert not conn.execute("SELECT 1 FROM findings WHERE host='fw1' AND rule='opnsense.rule_any'").fetchone()
    r = c.post("/h/fw1/roles", data={"role-opt1": "wan", "role-lan": "auto", "role-wan": "wan", "role-nope": "wan", "role-opt2": "banana"})
    assert r.status_code == 303
    assert roles.load_overrides(conn, "fw1") == {"opt1": "wan"}          # same as automatic, unknown id and unknown role are ignored
    assert conn.execute("SELECT 1 FROM events WHERE host='fw1' AND title='Interface roles changed'").fetchone()
    assert "Guest" in c.get("/h/fw1/network").text and "set by you" in c.get("/h/fw1/network").text
    assert c.post("/h/fw1/roles", data={"role-opt1": "wan"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/h/tower/roles", data={"role-opt1": "wan"}).status_code == 404


def test_a_source_without_privilege_shows_on_its_page(c, hub_cfg, fake):
    fake.deny_source("opnsense_rules")
    _added(c, hub_cfg, fake)
    fw = c.get("/h/fw1/firewall").text
    assert "needs the privilege Firewall: Rules [new]" in fw
    assert c.get("/h/fw1/").status_code == 200


def test_the_key_and_secret_appear_in_no_page_log_or_event(app_client, hub_cfg, fake, caplog):
    caplog.set_level(logging.DEBUG)
    c = app_client()
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    seen = [c.get("/remotes/new?kind=opnsense").text, c.post("/remotes/new", data=form(action="test")).text,
            c.post("/remotes/new", data=form(action="save")).text]
    poll_now(hub_cfg, fake, time.time())
    fake.fail = httpx.ConnectError(f"boom {KEY} {SECRET}")
    for i in range(5):
        poll_now(hub_cfg, fake, time.time() + 61 * i)
    for path in ("/", "/partials/hosts", "/remotes/fw1/edit") + PAGES:
        seen.append(c.get(path).text)
    text = "\n".join(seen)
    for secret in (KEY, SECRET):
        assert secret not in text and secret not in caplog.text
    conn = conn_of(hub_cfg)
    dump = "\n".join(str(tuple(r)) for t in ("events", "findings", "remotes", "snapshots", "metrics", "meta") for r in conn.execute(f"SELECT * FROM {t}"))
    assert KEY not in dump and SECRET not in dump


def test_the_report_lists_firewall_findings_with_what_to_do(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    md = c.get("/h/fw1/report.md").text
    assert "package updates pending" in md and "WireGuard instance" in md and KEY not in md and SECRET not in md


# --- across hosts -----------------------------------------------------------------------------------------------

def test_a_forward_to_a_collector_host_shows_on_that_hosts_exposure_page(c, hub_cfg, fake):
    from .test_hub import body, post
    cn = conn_of(hub_cfg)
    from daemonsight import hub
    token = hub.add_host(cn, "web")
    ports = {"listeners": [{"proto": "tcp", "port": 80, "addresses": ["10.20.0.8"], "scope": "private", "pid": 1, "process": "nginx",
                            "owner": {"kind": "unit", "id": "nginx.service"}}],
             "addresses": [{"ip": "10.20.0.8", "iface": "eth0", "scope": "private"}]}
    assert post(c, body(host="web", snapshots=[{"source": "ports", "taken_at": time.time(), "ok": True, "data": ports}]), token).status_code in (200, 202, 204)
    _added(c, hub_cfg, fake)
    html = c.get("/h/web/exposure").text
    assert "Reached from the internet through" in html and "/h/fw1/firewall#fwd-22222222-bbb" in html and "Web server" in html
    check_panels(html)
