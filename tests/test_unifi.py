"""The UniFi Network source: the GET-only client and its whitelist, what is kept from each reply (and what must not be:
a Wi-Fi passphrase, a client's identity), the rules, the poller, the form and Test, the pages and the privacy of the key.
Replies come from tests/fake_unifi.py, synthetic and in the shape of Ubiquiti's OpenAPI document for UniFi Network 11.0.97."""

import asyncio
import json
import logging
import re
import stat
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from daemonsight import db, settings
from daemonsight.config import Config
from daemonsight.remote import poll, store, unifi, unifi_rules as rules
from daemonsight.remote.client import RemoteError, fingerprint, fmt_fingerprint, normalize_url
from daemonsight.web.app import create_app

from . import fake_unifi as fu
from .conftest import PASSWORD
from .fake_unifi import KEY, FakeUnifi
from .fake_unraid import make_cert
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

NOW = 1_795_000_000.0
URL = "https://unifi.test"
HOUR = 3600.0


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def fake():
    return FakeUnifi()


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


def add(conn, cfg, name="net1", now=NOW - 1000, **kw):
    store.add(conn, cfg.data_dir, name, "unifi", URL, KEY, interval=60, now=now, **kw)
    return store.get(conn, name)


def open_rules(conn, host="net1"):
    return {(r["rule"], r["key"]): r for r in conn.execute("SELECT * FROM findings WHERE host=? AND resolved_at IS NULL", (host,))}


def polled(conn, cfg, fake, at=NOW):
    run(poll.run_once(conn, cfg, fake.net(), at))


def rest_for(fake):
    return unifi.make_rest(URL, KEY, fake.net().http())


# --- the client sends GET and nothing else, to the listed paths and no others -------------------------------------

def test_the_client_only_gets_and_only_the_listed_paths(fake):
    rest = rest_for(fake)
    assert not [m for m in dir(rest) if m in ("post", "put", "delete", "patch", "request", "send")]
    site, dev, wifi = fu.SITE, fu.DEV_AP1, fu.WIFI_HOME
    P = unifi.PREFIX
    refused = [
        f"{P}/v1/sites/{site}/wifi/broadcasts/{wifi}",                          # one network's detail: carries the passphrase
        f"{P}/v1/sites/{site}/wifi/broadcasts/{wifi}?offset=0&limit=200",
        f"{P}/v1/sites/{site}/devices/{dev}",                                   # a device's detail
        f"{P}/v1/sites/{site}/devices/{dev}/actions",                           # an action (restart, upgrade)
        f"{P}/v1/sites/{site}/devices/{dev}/interfaces/ports/1/actions",
        f"{P}/v1/sites/{site}/clients?offset=0&limit=200",                      # clients by name: only the count (limit=0) is allowed
        f"{P}/v1/sites/{site}/clients/{dev}",
        f"{P}/v1/sites/{site}/hotspot/vouchers?offset=0&limit=200",
        f"{P}/v1/sites/{site}/firewall/policies/{dev}",
        f"{P}/v1/sites/{site}/networks?offset=0&limit=200",
        f"{P}/v1/sites/{site}/devices?offset=0&limit=200&filter=x",
        f"{P}/v1/sites/{site}/devices?offset=0&limit=200#x",
        f"{P}/v1/sites/{site}/devices",
        f"{P}/v1/sites/not-an-id/devices?offset=0&limit=200",
        f"{P}/v1/sites/{site}/../{site}/devices?offset=0&limit=200",
        f"{P}/v1/info?x=1", f"{P}/v1/info/", f"{P}/v1/sites/{site}", f"/v1/info", "proxy/network/integration/v1/info", "",
        f"{P}/v2/info", f"{P}/v1/countries",
    ]
    for bad in refused:
        with pytest.raises(ValueError):
            run(rest.get(bad))
    assert fake.requests == []              # nothing was sent for a refused path
    for ok in (unifi.p_info(), unifi.p_sites(), unifi.p_pending(), unifi.p_site(site, "devices"), unifi.p_site(site, "wifi"),
               unifi.p_site(site, "zones"), unifi.p_site(site, "policies"), unifi.p_clients(site), unifi.p_stats(site, dev)):
        rest.check_allowed(ok)
    run(rest.aclose())


def test_a_path_builder_refuses_an_id_that_is_not_an_id():
    for bad in ("", "x", "../etc", fu.SITE + "/..", fu.SITE + "?x"):
        with pytest.raises(ValueError):
            unifi.p_site(bad, "devices")
    with pytest.raises(KeyError):
        unifi.p_site(fu.SITE, "actions")


def test_the_whitelist_has_no_detail_action_or_write_path():
    shown = " ".join(unifi.SHOWN.values())
    for word in ("actions", "vouchers", "restart", "upgrade", "adopt", "{wifiBroadcastId}", "{clientId}", "{networkId}"):
        assert word not in shown
    assert set(unifi.TEMPLATES) == set(unifi.SHOWN)


def test_a_whole_poll_and_a_probe_send_only_gets_to_listed_paths(conn, cfg, fake):
    fu.with_gateway(fake.replies)
    add(conn, cfg)
    polled(conn, cfg, fake)
    run(unifi.probe(fake.net(), URL, KEY))
    assert fake.requests and {r.method for r in fake.requests} == {"GET"}
    for r in fake.requests:
        path = r.url.path + ("?" + r.url.query.decode() if r.url.query else "")
        assert any(p.fullmatch(path) for p in unifi.PATTERNS), path
        assert r.headers["x-api-key"] == KEY and KEY not in str(r.url) and "authorization" not in r.headers
        assert "content-type" not in r.headers and not r.content
    # a client list is only ever asked for its count
    clients = [r for r in fake.requests if r.url.path.endswith("/clients")]
    assert clients and all(r.url.params["limit"] == "0" for r in clients)
    assert {r.url.host for r in fake.requests} == {"unifi.test"}


def test_a_redirect_is_an_error_and_is_not_followed(fake):
    fake.status = 302
    with pytest.raises(RemoteError) as e:
        run(unifi.probe(fake.net(), URL, KEY))
    assert "redirect" in e.value.message.lower() and {r.url.host for r in fake.requests} == {"unifi.test"}


def test_normalize_url_for_unifi():
    assert normalize_url("unifi.example.lan:8443", "unifi") == "https://unifi.example.lan:8443"
    assert normalize_url("https://192.0.2.20/", "unifi") == "https://192.0.2.20"
    for bad in ("http://unifi.lan", "", "https://user:pw@unifi.lan", "https://unifi.lan/proxy/network", "https://unifi.lan?x=1"):
        with pytest.raises(ValueError):
            normalize_url(bad, "unifi")


# --- what is kept ------------------------------------------------------------------------------------------------

def test_parse_a_device_keeps_named_fields_and_cuts_text():
    d = unifi.parse_device({**fu.device(fu.DEV_AP1, "AP-Lobby\x07" + "x" * 300, "U6-Lite", ["accessPoint"], updatable=True),
                            "adoptedAt": "2026-01-01T00:00:00Z", "uplink": {"x": 1}, "somethingElse": "secret"}, fu.SITE)
    assert d["name"].startswith("AP-Lobby") and len(d["name"]) <= 80 and "\x07" not in d["name"]
    assert d["updatable"] is True and d["state"] == "ONLINE" and d["features"] == ["accessPoint"]
    assert set(d) == {"id", "site", "name", "model", "mac", "ip", "state", "firmware", "updatable", "supported", "features",
                      "heartbeat", "down_since", "update_since"}


def test_a_wifi_passphrase_in_a_reply_is_never_stored(conn, cfg, fake):
    add(conn, cfg)
    polled(conn, cfg, fake)
    snap = db.get_snapshot(conn, "net1", "unifi_wifi")
    assert snap.ok and [n["name"] for n in snap.data["networks"]] == ["Home", "Guests"]
    raw = json.dumps(snap.data)
    assert fu.PASSPHRASE not in raw and "passphrase" not in raw.lower() and "presharedKeys" not in raw
    assert snap.data["networks"][0]["security"] == "WPA2_PERSONAL"
    # nowhere in the database, whatever the table
    for table in ("snapshots", "events", "findings", "metrics"):
        for row in conn.execute(f"SELECT * FROM {table}"):  # noqa: S608
            assert fu.PASSPHRASE not in " ".join(str(v) for v in tuple(row))
    assert "passphrase" not in repr(unifi.parse_wifi(fake.replies["wifi"][fu.SITE][0], fu.SITE)).lower()


def test_clients_are_counted_and_never_named(conn, cfg, fake):
    fake.replies["clients"][fu.SITE] = 7
    add(conn, cfg)
    polled(conn, cfg, fake)
    info = db.get_snapshot(conn, "net1", "unifi_info").data
    assert info["clients"] == {fu.SITE: 7} and info["version"] == "10.1.89"
    assert set(info) == {"version", "sites", "clients"}


def test_a_page_of_more_than_200_devices_is_read_in_pages(conn, cfg, fake):
    fake.replies["devices"][fu.SITE] += [fu.device(f"9d1a0000-0000-4000-8000-{i:012d}", f"AP-{i}", "U6-Lite", ["accessPoint"])
                                         for i in range(100, 330)]
    add(conn, cfg)
    polled(conn, cfg, fake)
    assert len(db.get_snapshot(conn, "net1", "unifi_devices").data["devices"]) == 233
    offsets = [r.url.params["offset"] for r in fake.requests if r.url.path.endswith("/devices")]
    assert offsets == ["0", "200"]


# --- the rules: each one fires and each one clears -------------------------------------------------------------------

def inputs(fake, devices=None, wifi=None, gateway=None, pending=None):
    """Rule inputs built by parsing the fake's replies, without a poll."""
    devs = [unifi.parse_device(d, fu.SITE) for d in fake.replies["devices"][fu.SITE]]
    return {"devices": devices or {"devices": devs, "pending": [unifi.parse_pending(p) for p in (pending if pending is not None else fake.replies["pending"])]},
            "wifi": wifi or {"networks": [unifi.parse_wifi(n, fu.SITE) for n in fake.replies["wifi"][fu.SITE]]},
            "gateway": gateway, "info": {"version": "10.1.89"}}


def by_rule(findings):
    return {(f.rule, f.key): f for f in findings}


def test_firmware_updates_are_grouped_low_and_say_why_there_are_no_cves(fake):
    f = by_rule(rules.evaluate(inputs(fake), NOW))
    fw = f[("unifi.fw_update", "firmware")]
    assert fw.severity == "low" and fw.title.startswith("2 UniFi devices")
    assert "AP-Lobby" in fw.detail and "Switch-Closet" in fw.detail and "AP-Warehouse" not in fw.detail
    assert rules.CVE_NOTE in fw.detail and "community.ui.com/releases" in fw.detail
    assert "Update Available" in fw.howto and fw.link == "/devices#devices"
    old = inputs(fake)
    for d in old["devices"]["devices"]:
        if d["updatable"]:
            d["update_since"] = NOW - 31 * 86400
    assert by_rule(rules.evaluate(old, NOW))[("unifi.fw_update", "firmware")].severity == "medium"
    # the basis moves with the set of waiting updates, so an accepted finding comes back when it changes
    one = inputs(fake)
    one["devices"]["devices"][0]["firmware"] = "6.6.56"
    assert by_rule(rules.evaluate(one, NOW))[("unifi.fw_update", "firmware")].basis != fw.basis
    # and it clears when nothing is waiting
    for d in fake.replies["devices"][fu.SITE]:
        d["firmwareUpdatable"] = False
    assert not any(k[0] == "unifi.fw_update" for k in by_rule(rules.evaluate(inputs(fake), NOW)))


def test_an_offline_device_is_a_finding_after_the_threshold_and_clears_when_it_returns(fake):
    fake.replies["devices"][fu.SITE][0]["state"] = "OFFLINE"                 # an access point
    fake.replies["devices"][fu.SITE][2]["state"] = "CONNECTION_INTERRUPTED"  # a switch
    inp = inputs(fake)
    for d in inp["devices"]["devices"]:
        if d["state"] != "ONLINE":
            d["down_since"] = NOW - 1.5 * HOUR
    assert not [k for k in by_rule(rules.evaluate(inp, NOW)) if k[0] == "unifi.device_offline"]     # under 2 hours
    for d in inp["devices"]["devices"]:
        if d["state"] != "ONLINE":
            d["down_since"] = NOW - 3 * HOUR
    got = by_rule(rules.evaluate(inp, NOW))
    ap, sw = got[("unifi.device_offline", fu.DEV_AP1)], got[("unifi.device_offline", fu.DEV_SW)]
    assert ap.severity == "high" and sw.severity == "medium" and "AP-Lobby has been offline for 3 hours" == ap.title
    assert ap.link == "/devices#" + rules.dev_anchor(inp["devices"]["devices"][0]) and "PoE" in ap.howto
    assert not [k for k in by_rule(rules.evaluate(inp, NOW, offline_hours=6)) if k[0] == "unifi.device_offline"]  # the setting
    for d in inp["devices"]["devices"]:
        d["state"], d["down_since"] = "ONLINE", None
    assert not [k for k in by_rule(rules.evaluate(inp, NOW)) if k[0] == "unifi.device_offline"]


def test_a_device_that_is_updating_or_adopting_is_not_offline(fake):
    for st in ("UPDATING", "GETTING_READY", "ADOPTING", "PENDING_ADOPTION"):
        fake.replies["devices"][fu.SITE][0]["state"] = st
        inp = inputs(fake)
        inp["devices"]["devices"][0]["down_since"] = NOW - 9 * HOUR
        assert not [k for k in by_rule(rules.evaluate(inp, NOW)) if k[0] == "unifi.device_offline"], st


def test_a_device_waiting_for_adoption_is_a_finding_until_adopted(fake):
    got = by_rule(rules.evaluate(inputs(fake), NOW))
    p = got[("unifi.pending_adoption", "00:00:5e:00:53:77")]
    assert p.severity == "medium" and "U6-Mesh" in p.title and "192.0.2.77" in p.detail and "unknown device" in p.howto
    assert not [k for k in by_rule(rules.evaluate(inputs(fake, pending=[]), NOW)) if k[0] == "unifi.pending_adoption"]


def test_open_wifi_is_a_finding_unless_it_is_a_guest_portal_or_off(fake):
    nets = fake.replies["wifi"][fu.SITE]
    assert not [k for k in by_rule(rules.evaluate(inputs(fake), NOW)) if k[0].startswith("unifi.wifi")]     # guest portal: open is the point
    nets.append({"id": fu.WIFI_OPEN, "type": "STANDARD", "name": "Cafe", "enabled": True, "metadata": {"origin": "USER_DEFINED"},
                 "network": {"type": "NATIVE"}, "broadcastingFrequenciesGHz": [5], "securityConfiguration": {"type": "OPEN"}})
    f = by_rule(rules.evaluate(inputs(fake), NOW))[("unifi.wifi_open", fu.WIFI_OPEN)]
    assert f.severity == "high" and "Cafe" in f.title and "Settings, WiFi" in f.howto and "accept this finding" in f.howto
    nets[-1]["enabled"] = False
    assert not [k for k in by_rule(rules.evaluate(inputs(fake), NOW)) if k[0] == "unifi.wifi_open"]
    nets[-1].update(enabled=True, securityConfiguration={"type": "WPA2_WPA3_PERSONAL"})
    assert not [k for k in by_rule(rules.evaluate(inputs(fake), NOW)) if k[0] == "unifi.wifi_open"]


def test_legacy_wifi_types_are_flagged_if_a_controller_ever_reports_them(fake):
    nets = fake.replies["wifi"][fu.SITE]
    for kind in ("WEP", "WPA_PERSONAL", "WPA"):
        nets[0]["securityConfiguration"] = {"type": kind}
        assert ("unifi.wifi_legacy", fu.WIFI_HOME) in by_rule(rules.evaluate(inputs(fake), NOW)), kind
    for kind in ("WPA2_PERSONAL", "WPA3_PERSONAL", "WPA2_WPA3_PERSONAL", "WPA2_ENTERPRISE", "WPA3_ENTERPRISE"):
        nets[0]["securityConfiguration"] = {"type": kind}
        assert ("unifi.wifi_legacy", fu.WIFI_HOME) not in by_rule(rules.evaluate(inputs(fake), NOW)), kind


def gw_data(fake):
    fu.with_gateway(fake.replies, allow_in=True)
    return {"present": True, "zones": [{**z, "site": fu.SITE} for z in unifi.parse_zones(fake.replies["zones"][fu.SITE])],
            "policies": [{**p, "site": fu.SITE} for p in unifi.parse_policies(fake.replies["policies"][fu.SITE])]}


def test_a_gateway_policy_that_lets_the_internet_in_is_a_finding(fake):
    gw = gw_data(fake)
    got = by_rule(rules.evaluate(inputs(fake, gateway=gw), NOW))
    f = got[("unifi.gateway_forward", fu.POL_FWD)]
    assert f.severity == "medium" and "Web server" in f.title and "Internal" in f.detail and "no port forwards" in f.detail
    assert not [k for k in got if k[1] in (fu.POL_SYS, fu.POL_OUT)]        # UniFi's own policies are not findings
    for p in gw["policies"]:
        if p["id"] == fu.POL_FWD:
            p["enabled"] = False
    assert not [k for k in by_rule(rules.evaluate(inputs(fake, gateway=gw), NOW)) if k[0] == "unifi.gateway_forward"]
    gw["policies"][-1]["enabled"], gw["policies"][-1]["action"] = True, "BLOCK"
    assert not [k for k in by_rule(rules.evaluate(inputs(fake, gateway=gw), NOW)) if k[0] == "unifi.gateway_forward"]
    assert rules.gateway_rules({"present": False, "zones": [], "policies": []}) == [] and rules.gateway_rules(None) == []


def test_there_is_no_controller_old_finding_because_the_api_has_no_latest_version(fake):
    names = {f.rule for f in rules.evaluate(inputs(fake), NOW)}
    assert "unifi.controller_old" not in names
    # the only "latest" path is a device's own statistics, never a call that names a newer controller version
    assert [v for v in unifi.SHOWN.values() if "latest" in v.lower()] == [unifi.SHOWN["stats"]] and "devices" in unifi.SHOWN["stats"]


# --- the poller ----------------------------------------------------------------------------------------------------

def test_a_poll_stores_every_source_and_opens_findings(conn, cfg, fake):
    add(conn, cfg)
    polled(conn, cfg, fake)
    snaps = db.get_snapshots(conn, "net1")
    assert set(snaps) >= {"unifi_info", "unifi_devices", "unifi_wifi", "unifi_gateway"} and all(s.ok for n, s in snaps.items() if n.startswith("unifi_"))
    got = open_rules(conn)
    assert {("unifi.fw_update", "firmware"), ("unifi.pending_adoption", "00:00:5e:00:53:77")} <= set(got)
    assert not [k for k in got if k[0] in ("unifi.wifi_open", "unifi.device_offline", "unifi.gateway_forward")]
    assert conn.execute("SELECT version FROM hosts WHERE id='net1'").fetchone()["version"] == "UniFi Network 10.1.89"
    assert snaps["unifi_gateway"].data == {"present": False, "zones": [], "policies": []}
    assert not [p for p in fake.paths() if "firewall" in p]                    # no gateway: the firewall is not asked for


def test_the_gateway_is_read_only_when_there_is_one(conn, cfg, fake):
    gw = fu.with_gateway(fake.replies, allow_in=True)
    add(conn, cfg)
    polled(conn, cfg, fake)
    assert any("/firewall/policies" in p for p in fake.paths()) and any("/firewall/zones" in p for p in fake.paths())
    assert ("unifi.gateway_forward", fu.POL_FWD) in open_rules(conn)
    gw["policies"][fu.SITE][-1]["enabled"] = False
    polled(conn, cfg, fake, NOW + 400)                                         # the gateway source is read every five minutes
    assert ("unifi.gateway_forward", fu.POL_FWD) not in open_rules(conn)


def test_offline_is_timed_from_first_sight_and_the_setting_moves_the_threshold(conn, cfg, fake):
    add(conn, cfg)
    polled(conn, cfg, fake)
    fake.replies["devices"][fu.SITE][1]["state"] = "OFFLINE"
    polled(conn, cfg, fake, NOW + 60)
    d = {x["id"]: x for x in db.get_snapshot(conn, "net1", "unifi_devices").data["devices"]}
    assert d[fu.DEV_AP2]["down_since"] == NOW + 60
    assert ("unifi.device_offline", fu.DEV_AP2) not in open_rules(conn)
    polled(conn, cfg, fake, NOW + 60 + 2 * HOUR + 1)
    assert open_rules(conn)[("unifi.device_offline", fu.DEV_AP2)]["severity"] == "high"
    d = {x["id"]: x for x in db.get_snapshot(conn, "net1", "unifi_devices").data["devices"]}
    assert d[fu.DEV_AP2]["down_since"] == NOW + 60                              # kept, not reset
    settings.save(conn, cfg, {"remote.unifi_offline_hours": 6}, "admin")
    polled(conn, cfg, fake, NOW + 60 + 2 * HOUR + 62)
    assert ("unifi.device_offline", fu.DEV_AP2) not in open_rules(conn)         # now under the threshold
    settings.save(conn, cfg, {"remote.unifi_offline_hours": 1}, "admin")
    polled(conn, cfg, fake, NOW + 60 + 2 * HOUR + 124)
    assert ("unifi.device_offline", fu.DEV_AP2) in open_rules(conn)
    fake.replies["devices"][fu.SITE][1]["state"] = "ONLINE"
    polled(conn, cfg, fake, NOW + 60 + 2 * HOUR + 186)
    assert ("unifi.device_offline", fu.DEV_AP2) not in open_rules(conn)
    assert conn.execute("SELECT 1 FROM events WHERE host='net1' AND kind='finding_resolved'").fetchone()


def test_the_last_heartbeat_dates_an_outage_that_began_before_the_hub_saw_it(conn, cfg, fake):
    fake.replies["devices"][fu.SITE][1]["state"] = "OFFLINE"
    fake.replies["stats"][fu.DEV_AP2] = {"lastHeartbeatAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - 5 * HOUR)), "interfaces": {}}
    add(conn, cfg)
    polled(conn, cfg, fake)
    d = {x["id"]: x for x in db.get_snapshot(conn, "net1", "unifi_devices").data["devices"]}
    assert d[fu.DEV_AP2]["heartbeat"] == NOW - 5 * HOUR and d[fu.DEV_AP2]["down_since"] == NOW - 5 * HOUR
    assert ("unifi.device_offline", fu.DEV_AP2) in open_rules(conn)             # at the first poll
    assert any(p.endswith("/statistics/latest") for p in fake.paths())
    # the statistics are asked only for a device that is down
    assert sum(1 for p in fake.paths() if p.endswith("/statistics/latest")) == 1


def test_an_update_waiting_is_timed_from_first_sight(conn, cfg, fake):
    add(conn, cfg)
    polled(conn, cfg, fake)
    polled(conn, cfg, fake, NOW + 31 * 86400)
    assert open_rules(conn)[("unifi.fw_update", "firmware")]["severity"] == "medium"


def test_an_admin_that_may_not_read_a_source_is_told_and_the_rest_work(conn, cfg, fake):
    fake.deny = {"wifi"}
    add(conn, cfg)
    polled(conn, cfg, fake)
    snaps = db.get_snapshots(conn, "net1")
    assert snaps["unifi_wifi"].ok is False and "may not read" in snaps["unifi_wifi"].error and snaps["unifi_wifi"].data["available"] is False
    assert snaps["unifi_devices"].ok and ("unifi.fw_update", "firmware") in open_rules(conn)
    assert store.get(conn, "net1")["fails"] == 0


def test_a_refused_key_and_an_unreachable_controller_are_recorded_without_the_key(conn, cfg, fake):
    add(conn, cfg)
    fake.key = "SOMETHINGELSE0123456789"
    polled(conn, cfg, fake)
    row = store.get(conn, "net1")
    assert row["fails"] == 1 and "refused the API key" in row["last_error"] and KEY not in row["last_error"]
    fake.fail = httpx.ConnectError(f"cannot reach, key {KEY}")
    fake.key = KEY
    polled(conn, cfg, fake, NOW + 100)
    row = store.get(conn, "net1")
    assert row["fails"] == 2 and KEY not in row["last_error"] and "unreachable" not in row["last_error"].lower() or "Could not connect" in row["last_error"]
    fake.fail = None
    polled(conn, cfg, fake, NOW + 400)
    assert store.get(conn, "net1")["fails"] == 0


def test_an_unreachable_controller_opens_the_remote_finding_with_unifi_steps(conn, cfg, fake):
    add(conn, cfg)
    fake.fail = httpx.ConnectError("down")
    for i in range(5):
        polled(conn, cfg, fake, NOW + 100 * i)
    f = open_rules(conn)[("remote.unreachable", "unreachable")]
    assert "Integrations" in f["howto"] and "OPNsense" not in f["howto"]


def test_every_hub_rule_prefix_is_known_to_the_hub():
    from daemonsight import hub
    assert "unifi." in hub.HUB_RULES
    with pytest.raises(ValueError):
        hub.FindingIn(rule="unifi.fw_update", key="k", severity="low", title="t", detail="d")


# --- test connection -----------------------------------------------------------------------------------------------

def test_the_probe_reads_and_says_what_it_cannot_check(fake):
    p = run(unifi.probe(fake.net(), URL, KEY))
    assert p.ok and dict(p.facts)["Version"] == "UniFi Network 10.1.89" and dict(p.facts)["Devices"].startswith("3 adopted")
    assert dict(p.facts)["Gateway"].startswith("None") and dict(p.facts)["Wi-Fi networks"] == "2"
    assert "cannot check that this key is read-only" in p.note and "never tries a write" in p.note and "View Only" in p.note
    assert [s["state"] for s in p.sources] == ["ok", "ok"]
    # it only reads, and it never reads anything that a write would sit beside
    assert {r.method for r in fake.requests} == {"GET"}
    assert not [r for r in fake.requests if r.url.path.rsplit("/", 1)[-1] in ("actions", "adopt")]


def test_the_probe_has_no_way_to_ask_what_the_key_may_do():
    """The check is "is there a self call in the API?". There is none in 11.0.97: the only call that is not about a site, a
    device or a client is /v1/info, which has the version and nothing else."""
    assert unifi.TEMPLATES.keys() == {"info", "sites", "pending", "devices", "stats", "clients", "wifi", "zones", "policies"}
    assert not any(w in " ".join(unifi.SHOWN.values()).lower() for w in ("self", "whoami", "/me", "permissions", "roles"))


def test_a_wrong_key_stops_the_probe(fake):
    with pytest.raises(RemoteError) as e:
        run(unifi.probe(fake.net(), URL, "WRONGKEY0123456789"))
    assert e.value.kind == "auth" and "WRONGKEY" not in e.value.message


def test_an_admin_that_may_read_nothing_is_refused(fake):
    fake.deny = {"devices", "wifi"}
    p = run(unifi.probe(fake.net(), URL, KEY))
    assert not p.ok and "View Only" in p.problem
    fake.deny = {"sites"}
    p = run(unifi.probe(fake.net(), URL, KEY))
    assert not p.ok and "may not read this controller's sites" in p.problem


def test_an_address_that_is_not_a_unifi_api_is_explained(fake):
    fake.replies["sites"] = []
    p = run(unifi.probe(fake.net(), URL, KEY))
    assert not p.ok and "no sites" in p.problem


# --- the form and the pages ----------------------------------------------------------------------------------------

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
    return {"kind": "unifi", "name": "net1", "url": URL, "key": KEY, "tls": "verify", "interval": "60", **kw}


def conn_of(hub_cfg):
    return db.connect_writer(hub_cfg.db_path)


def poll_now(hub_cfg, fake, at=None):
    cn = conn_of(hub_cfg)
    try:
        run(poll.run_once(cn, hub_cfg, fake.net(), at or time.time()))
    finally:
        cn.close()


def test_the_form_for_unifi(c):
    html = c.get("/remotes/new?kind=unifi").text
    assert "UniFi Network · REST API" in html and 'name="secret"' not in html and "View Only" in html
    assert "Making a UniFi key" in html and "<details" in html and "Integrations" in html
    # the long text is behind the (i) button, and says plainly what the key's role does and what cannot be checked
    assert 'popovertarget="src-unifi-key"' in html and "has no read-only key and no call that says what a key may do" in html
    assert "cannot check it" in html and "never writes anything" in html
    assert "developer.ui.com/network/v11.0.97" in html and "help.ui.com" in html and 'rel="noopener noreferrer"' in html
    check_panels(html)
    for other in ("unraid", "opnsense"):
        assert "src-unifi-key" not in c.get(f"/remotes/new?kind={other}").text


def test_test_connection_shows_what_it_found_and_saves_nothing(c, hub_cfg, fake):
    r = c.post("/remotes/new", data=form(action="test"))
    assert r.status_code == 200 and "Connected. The key is accepted and can read." in r.text
    assert "UniFi Network 10.1.89" in r.text and "AP-Lobby" not in r.text and "Readable" in r.text
    assert 'id="key-note"' in r.text and "cannot check that this key is read-only" in r.text
    assert fake.requests and {q.method for q in fake.requests} == {"GET"}
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()


def test_adding_a_unifi_system(c, hub_cfg, fake):
    r = c.post("/remotes/new", data=form(action="save"))
    assert r.status_code == 303
    cn = conn_of(hub_cfg)
    row = cn.execute("SELECT * FROM remotes WHERE id='net1'").fetchone()
    assert row["kind"] == "unifi" and row["url"] == URL
    assert store.read_key(hub_cfg.data_dir, "net1") == KEY
    path = store.key_path(hub_cfg.data_dir, "net1")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_text() == KEY + "\n"
    assert cn.execute("SELECT kind FROM hosts WHERE id='net1'").fetchone()["kind"] == "unifi"
    poll_now(hub_cfg, fake)
    hosts = c.get("/").text
    assert 'href="/remotes/net1/edit"' in hosts and "UniFi Network 10.1.89" in hosts and 'aria-label="Manage net1"' in hosts
    assert 'href="/h/net1/"' in hosts                                     # and it is in the Hosts menu
    edit = c.get("/remotes/net1/edit").text
    assert "Nothing changes on the controller" in edit and KEY not in edit and "A key with" not in edit


def test_validation_is_explained(c, hub_cfg, fake):
    for kw, word in ((dict(url="http://unifi.test"), "https://"), (dict(url=URL + "/proxy/network"), "Give only the controller"),
                     (dict(key=""), "API key"), (dict(key="a b"), "API key"), (dict(interval="5"), "Interval"),
                     (dict(name="bad name"), "Name")):
        r = c.post("/remotes/new", data=form(action="save", **kw))
        assert r.status_code == 400 and word in r.text, kw
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()
    fake.key = "ANOTHERKEY0123456789"
    r = c.post("/remotes/new", data=form(action="test"))
    assert r.status_code == 400 and "refused the API key" in r.text and KEY not in r.text


def test_a_self_signed_controller_is_pinned_only_after_confirming(c, hub_cfg, fake, tmp_path):
    pem, _, _ = make_cert(tmp_path, "unifi.test")
    fp = fmt_fingerprint(fingerprint(pem))
    fake.server_cert = pem
    r = c.post("/remotes/new", data=form(action="test"))
    assert fp in r.text and "UniFi OS's own" in r.text and fake.requests == []     # the key was not sent before the fingerprint was confirmed
    ok = c.post("/remotes/new", data=form(action="test", tls="pin", trust=fp))
    assert "Connected." in ok.text and fake.requests
    assert c.post("/remotes/new", data=form(action="save", tls="pin", pin_confirm=fp)).status_code == 303
    assert conn_of(hub_cfg).execute("SELECT tls, tls_pin FROM remotes WHERE id='net1'").fetchone()["tls_pin"] == fingerprint(pem)
    other, _, _ = make_cert(tmp_path / "b", "unifi.test")
    fake.server_cert = other
    fake.requests.clear()
    poll_now(hub_cfg, fake, time.time())
    assert "certificate was not accepted" in store.get(conn_of(hub_cfg), "net1")["last_error"] and fake.requests == []


def test_a_key_is_replaced_only_when_a_new_one_is_given(c, hub_cfg, fake):
    assert c.post("/remotes/new", data=form(action="save")).status_code == 303
    r = c.post("/remotes/net1/edit", data={"url": URL, "tls": "verify", "interval": "120", "enabled": "1", "action": "save"})
    assert r.status_code == 303 and store.read_key(hub_cfg.data_dir, "net1") == KEY
    assert conn_of(hub_cfg).execute("SELECT interval FROM remotes WHERE id='net1'").fetchone()["interval"] == 120
    new = "REPLACEMENTKEY0123456789abcdef"
    fake.key = new
    assert c.post("/remotes/net1/edit", data={"url": URL, "key": new, "tls": "verify", "interval": "120", "enabled": "1", "action": "save"}).status_code == 303
    assert store.read_key(hub_cfg.data_dir, "net1") == new


def _added(c, hub_cfg, fake, at=None):
    assert c.post("/remotes/new", data=form(action="save")).status_code == 303
    poll_now(hub_cfg, fake, at)


PAGES = ("/h/net1/", "/h/net1/devices", "/h/net1/wifi", "/h/net1/report", "/h/net1/report.md")


def test_every_listed_section_is_in_its_page(c, hub_cfg, fake):
    from .test_sections import check_registry
    _added(c, hub_cfg, fake)
    check_registry(c, "/h/net1", "unifi")
    check_registry(c, "", "hub")


def test_every_page_renders_with_its_tables_and_labels(c, hub_cfg, fake):
    fu.with_gateway(fake.replies, allow_in=True)
    fake.replies["devices"][fu.SITE][1]["state"] = "OFFLINE"
    _added(c, hub_cfg, fake, time.time() - 3 * HOUR)
    poll_now(hub_cfg, fake, time.time())
    for path in PAGES:
        assert c.get(path).status_code == 200, path
    dev = c.get("/h/net1/devices").text
    for word in ("AP-Lobby", "Switch-Closet", "Gateway", "U6-Pro", "192.0.2.11", "update waiting", "Waiting for adoption", "00:00:5e:00:53:77",
                 "Web server", "Offline", "10.1.89", "Connected clients"):
        assert word in dev, word
    assert "UniFi API lists no port forwards" in c.get("/h/net1/").text or "no port forwards" in dev or "port forwards" in dev
    wifi = c.get("/h/net1/wifi").text
    assert "Home" in wifi and "WPA2 personal" in wifi and "Guests" in wifi and "Hotspot portal" in wifi and "2.4, 5 GHz" in wifi
    assert fu.PASSPHRASE not in wifi
    home = c.get("/h/net1/").text
    assert 'id="updates"' in home and "Firmware updates" in home and "AP-Lobby" in home and "Switch-Closet" in home
    assert "UniFi Network" in home
    for html in (dev, wifi, home):
        check_panels(html)
    # no other host kind's pages
    for page in ("disks", "containers", "firewall", "vpn", "network", "exposure"):
        assert c.get(f"/h/net1/{page}").status_code == 404, page
    # the others do not serve UniFi's pages
    assert c.get("/h/hub/devices").status_code == 404


def test_the_pages_work_on_a_phone_every_cell_is_labelled_and_the_nav_lists_them(c, hub_cfg, fake):
    fu.with_gateway(fake.replies, allow_in=True)
    _added(c, hub_cfg, fake)
    for path in ("/h/net1/", "/h/net1/devices", "/h/net1/wifi"):
        html = c.get(path).text
        # the phone layout stacks each row into a card, which needs the column name on every cell (docs/UI.md, Tables on phones)
        for tr in re.findall(r"<tr[^>]*data-row[^>]*>(.*?)</tr>", html, re.S):
            for td in re.findall(r"<td\b([^>]*)>", tr):
                assert "data-label=" in td, (path, td)
        assert 'id="ds-menu-btn"' in html or "ds-menu-btn" in html
        assert 'href="/h/net1/devices"' in html and 'href="/h/net1/wifi"' in html and 'href="/h/net1/report"' in html
        assert 'id="ds-secl-devices"' in html                       # the phone list has the Devices sections
    desktop = c.get("/h/net1/devices").text
    assert 'id="ds-sec-devices"' in desktop and 'aria-label="Sections of ' in desktop


def test_the_firmware_card_says_plainly_there_is_no_cve_list_and_links_the_release_notes(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    home = c.get("/h/net1/").text
    assert "No CVE list: Ubiquiti publishes no feed of security advisories" in home
    assert 'href="https://community.ui.com/releases"' in home and "Release notes" in home
    assert "Why no CVEs are listed" in home and "Security Advisory Bulletins" in home and "does not guess" in home
    # the finding says the same, with its steps
    f = open_rules(conn_of(hub_cfg))[("unifi.fw_update", "firmware")]
    assert "can't list the CVEs these updates fix" in f["detail"] and "Update Available" in f["howto"]
    # nothing was fetched from anywhere else for it: the poller talks to the controller only
    assert {r.url.host for r in fake.requests} == {"unifi.test"}
    # and no CVE finding or CVE row was invented
    assert not [r for r in conn_of(hub_cfg).execute("SELECT rule FROM findings WHERE host='net1'") if r["rule"].startswith("cve.")]
    assert not re.search(r"CVE-\d{4}-\d", home)


def test_a_row_panel_shows_the_get_request_with_a_placeholder(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    html = c.get("/h/net1/devices").text + c.get("/h/net1/wifi").text
    assert 'curl -s -H &#34;X-API-KEY: $KEY&#34;' in html and "/proxy/network/integration/v1/sites/SITE_ID/devices?offset=0&amp;limit=200" in html
    assert KEY not in html
    for bad in ("-X POST", "-X PUT", "-X DELETE", "--data", " -d "):
        assert bad not in html
    assert "Never read" in html and "limit=0" in html


def test_findings_link_to_rows_that_exist(c, hub_cfg, fake):
    fu.with_gateway(fake.replies, allow_in=True)
    fake.replies["devices"][fu.SITE][1]["state"] = "OFFLINE"
    fake.replies["wifi"][fu.SITE].append({"id": fu.WIFI_OPEN, "type": "STANDARD", "name": "Cafe", "enabled": True, "metadata": {"origin": "USER_DEFINED"},
                                          "network": {"type": "NATIVE"}, "broadcastingFrequenciesGHz": [5], "securityConfiguration": {"type": "OPEN"}})
    _added(c, hub_cfg, fake, time.time() - 3 * HOUR)
    poll_now(hub_cfg, fake, time.time())
    pages = {"": c.get("/h/net1/").text, "devices": c.get("/h/net1/devices").text, "wifi": c.get("/h/net1/wifi").text}
    rows = conn_of(hub_cfg).execute("SELECT rule, link FROM findings WHERE host='net1' AND resolved_at IS NULL AND rule LIKE 'unifi.%'").fetchall()
    assert {r["rule"] for r in rows} == {"unifi.fw_update", "unifi.device_offline", "unifi.pending_adoption", "unifi.wifi_open", "unifi.gateway_forward"}
    for r in rows:
        page, _, frag = r["link"].lstrip("/").partition("#")
        assert page in pages, r["link"]
        assert f'id="{frag}"' in pages[page], (r["rule"], r["link"])


def test_accepting_a_unifi_finding_labels_it_and_a_change_brings_it_back(c, hub_cfg, fake):
    fake.replies["wifi"][fu.SITE].append({"id": fu.WIFI_OPEN, "type": "STANDARD", "name": "Cafe", "enabled": True, "metadata": {"origin": "USER_DEFINED"},
                                          "network": {"type": "NATIVE"}, "broadcastingFrequenciesGHz": [5], "securityConfiguration": {"type": "OPEN"}})
    _added(c, hub_cfg, fake, time.time() - 1000)
    assert "Unexpected" in c.get("/h/net1/wifi").text
    r = c.post("/h/net1/findings/accept", data={"rule": "unifi.wifi_open", "key": fu.WIFI_OPEN, "note": "a public hotspot, on purpose", "next": "/h/net1/wifi"})
    assert r.status_code == 303
    html = c.get("/h/net1/wifi").text
    assert "Accepted" in html and "a public hotspot, on purpose" in html
    fake.replies["wifi"][fu.SITE][-1]["name"] = "Cafe 2"
    poll_now(hub_cfg, fake, time.time() + 400)
    assert "Changed" in c.get("/h/net1/wifi").text


def test_the_report_lists_unifi_findings_with_what_to_do(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    html = c.get("/h/net1/report").text
    assert "firmware update waiting" in html and "waiting to be adopted" in html
    md = c.get("/h/net1/report.md").text
    assert "firmware update" in md


def test_the_offline_threshold_is_on_the_settings_page(c, hub_cfg):
    html = c.get("/settings/systems").text
    assert "UniFi device offline for" in html and "remote.unifi_offline_hours" in html or "unifi_offline_hours" in html
    r = c.post("/settings/save", data={"remote.unifi_offline_hours": "4"}) if c.get("/settings/systems").status_code == 200 else None
    cn = conn_of(hub_cfg)
    if r is not None and r.status_code in (200, 303):
        assert settings.effective(hub_cfg, cn).remote.unifi_offline_hours in (4, 4.0, 2.0)
    with pytest.raises(settings.Invalid):
        settings.parse(settings.BY_KEY["remote.unifi_offline_hours"], "0")
    assert settings.parse(settings.BY_KEY["remote.unifi_offline_hours"], "0.5") == 0.5
    assert settings.default_of(settings.BY_KEY["remote.unifi_offline_hours"]) == 2.0


def test_the_key_appears_in_no_page_log_or_event(app_client, hub_cfg, fake, caplog):
    caplog.set_level(logging.DEBUG)
    c = app_client()
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    texts = [c.post("/remotes/new", data=form(action="test")).text]
    assert c.post("/remotes/new", data=form(action="save")).status_code == 303
    poll_now(hub_cfg, fake)
    fake.key = "ROTATEDKEY0123456789abcdefgh"
    poll_now(hub_cfg, fake, time.time() + 500)
    for path in ("/", "/h/net1/", "/h/net1/devices", "/h/net1/wifi", "/h/net1/report", "/remotes/net1/edit"):
        texts.append(c.get(path).text)
    cn = conn_of(hub_cfg)
    for table in ("events", "findings", "snapshots", "settings", "remotes"):
        texts.append(json.dumps([tuple(r) for r in cn.execute(f"SELECT * FROM {table}")], default=str))  # noqa: S608
    texts.append(caplog.text)
    assert all(KEY not in t for t in texts)


def test_backups_hold_the_key_file_and_removing_deletes_it(c, hub_cfg, fake):
    _added(c, hub_cfg, fake)
    from daemonsight import backup
    assert "remotes/net1.key" in store.key_files(hub_cfg.data_dir)
    assert backup  # the backup module takes every key file the store lists, so a UniFi key is in it like the others
    r = c.post("/remotes/net1/remove", data={"confirm": "net1"})
    assert r.status_code == 303 and not store.key_path(hub_cfg.data_dir, "net1").exists()
    assert not conn_of(hub_cfg).execute("SELECT 1 FROM remotes").fetchone()


def test_an_unraid_or_opnsense_system_is_unchanged_by_the_unifi_kind(conn, cfg):
    with pytest.raises(ValueError):
        store.add(conn, cfg.data_dir, "x", "unifi", URL, KEY, secret="SECRETSECRET0123")       # a UniFi key has no secret
    assert store.KINDS["unifi"] == "UniFi Network" and "unifi" not in store.TWO_PART
