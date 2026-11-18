"""Remote systems: the Unraid queries, the read-only guarantees, the Viewer-key check, the rules,
key files and the poller. Responses come from trimmed real ones (tests/fixtures/unraid/)."""

import asyncio
import copy
import os
import re
import stat
import time

import httpx
import pytest

from daemonsight import db, hub
from daemonsight.config import Config
from daemonsight.findings import Finding
from daemonsight.remote import poll, store, unraid, unraid_rules
from daemonsight.remote.client import (Graph, RemoteError, clean_fingerprint, fingerprint, fmt_fingerprint,
                                       normalize_url)

from .fake_unraid import KEY, FakeUnraid, load, make_cert

NOW = 1_795_000_000.0     # a Tuesday in November 2026, after the fixtures' newest dates


def run(coro):
    return asyncio.run(coro)


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


@pytest.fixture
def fake():
    return FakeUnraid()


def add(conn, cfg, name="tower", url="https://tower.test:4443", interval=60, now=NOW - 1000, **kw):
    store.add(conn, cfg.data_dir, name, "unraid", url, KEY, interval=interval, now=now, **kw)
    return store.get(conn, name)


def parsed(source: str, fixture: str | None = None) -> dict:
    d = load(fixture or source.removeprefix("unraid_"))["data"]
    return unraid.parse(source, d, [])


def all_data() -> dict:
    return {s.removeprefix("unraid_"): parsed(s) for s in unraid.SOURCES}


def rules_for(**changes):
    """Findings for the fixture data after `changes` (name -> function that edits that source's dict)."""
    data = all_data()
    for name, fn in changes.items():
        fn(data[name])
    return unraid_rules.evaluate(data, NOW)


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


# --- the queries ----------------------------------------------------------------

def test_every_query_is_a_read():
    for q in unraid.ALL_QUERIES:
        Graph.check_read_only(q)
        assert "mutation" not in q.lower() and "subscription" not in q.lower()
        assert q.startswith("{")
    with pytest.raises(ValueError):
        Graph.check_read_only("mutation { array { start } }")
    with pytest.raises(ValueError):
        Graph.check_read_only("{ array { state } } mutation x { y }")
    with pytest.raises(ValueError):
        Graph.check_read_only("subscription { arrayUpdates }")


def test_the_client_has_no_way_to_send_anything_but_a_query(fake):
    async def go():
        g = Graph("https://tower.test", KEY, fake.net().http())
        with pytest.raises(ValueError):
            await g.query('mutation { docker { startContainer(id: "x") { id } } }')
        await g.aclose()
    run(go())
    assert fake.requests == []     # refused before anything was sent
    assert not [n for n in dir(Graph) if n in ("mutate", "mutation", "post")]


def test_no_request_body_ever_contains_mutation(conn, cfg, fake):
    add(conn, cfg)
    run(unraid.probe(fake.net(), "https://tower.test:4443", KEY))
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    assert len(fake.requests) > 8
    for body in fake.requests:
        assert set(body) == {"query"}
        assert "mutation" not in body["query"].lower() and "subscription" not in body["query"].lower()
    assert set(fake.queries()) <= set(unraid.ALL_QUERIES)


def test_the_key_goes_in_the_x_api_key_header_to_graphql(conn, cfg, fake):
    add(conn, cfg)
    run(poll.run_once(conn, cfg, fake.net(), NOW))
    h = fake.headers[0]
    assert h["x-api-key"] == KEY and h["content-type"] == "application/json"
    assert re.fullmatch(r"DaemonSight/\S+", h["user-agent"])


# --- parsing the real responses -----------------------------------------------------

def test_parse_system():
    s = parsed("unraid_system")
    assert s["version"] == "7.3.2" and s["name"] == "tower-test" and s["kernel"].endswith("Unraid")
    assert s["cpu"]["threads"] == 12 and 0 < s["cpu"]["percent"] < 100
    assert s["memory"]["total"] > s["memory"]["available"] > 0 and s["boot_time"] > 1.7e9


def test_parse_array_disks_and_parity_history():
    a = parsed("unraid_array")
    assert a["state"] == "STARTED"
    kinds = [(d["name"], d["kind"]) for d in a["disks"]]
    assert kinds == [("parity", "parity")] + [(f"disk{i}", "data") for i in range(1, 6)] + [("flash", "flash")]
    d1 = a["disks"][1]
    assert d1["status"] == "DISK_OK" and d1["errors"] == 0 and d1["fs_type"] == "xfs" and 95 < d1["percent"] < 96
    assert a["parity_history"][0]["date"] > a["parity_history"][1]["date"]
    assert a["thresholds"] == {"hot": 45, "max": 55, "warning": 70, "critical": 90}
    assert a["capacity"]["disks_total"] == 30 and 80 < a["capacity"]["percent"] < 90


def test_parse_the_rest():
    d = parsed("unraid_docker")
    assert len(d["containers"]) == 12 and d["containers"][0]["name"] == "app-1"
    assert any(c["update"] for c in d["containers"]) and d["containers"][0]["ports"][0]["type"] == "TCP"
    assert [v["state"] for v in parsed("unraid_vms")["vms"]].count("SHUTOFF") == 5
    n = parsed("unraid_notifications")
    assert n["unread"]["alert"] == 49 and len(n["items"]) == 56 and n["items"][0]["time"] > 1.7e9
    assert n["items"][0]["importance"] == "ALERT" and n["items"][0]["description"] and n["items"][0]["link"].startswith("/")
    assert parsed("unraid_ups")["devices"][0]["status"] == "ONLINE"
    disks = parsed("unraid_disks")["disks"]
    assert disks[1]["device"] == "sdb" and disks[1]["smart"] == "OK" and disks[0]["interface"] == "USB"


def test_vms_that_are_off_are_unavailable_not_an_error():
    assert unraid.parse("unraid_vms", {"vms": None}, ["VMs are not enabled"]) == \
        {"available": False, "reason": "VMs are not enabled"}


def test_text_from_the_server_is_cut_and_cleaned():
    d = {"notifications": {"overview": {"unread": {}}, "alerts": [
        {"id": "x:y", "title": "t" * 500 + "\x1b[31m", "subject": "a\x00b", "importance": "ALERT", "timestamp": None,
         "description": "d" * 900 + "<br>x", "link": "/Main" * 80}], "warnings": []}}
    item = unraid.parse_notifications(d)["items"][0]
    assert len(item["title"]) == 120 and item["subject"] == "ab" and "\x1b" not in item["title"]
    assert len(item["description"]) == 300 and len(item["link"]) == 100
    tagged = {"notifications": {"overview": {"unread": {}}, "alerts": [
        {"id": "x:y", "title": "t", "subject": "s", "importance": "ALERT", "timestamp": None,
         "description": "Errors<br>found <b>here</b>\nand there", "link": None}], "warnings": []}}
    assert unraid.parse_notifications(tagged)["items"][0]["description"] == "Errors found here and there"


# --- the key may only read -------------------------------------------------------------

def test_a_viewer_key_passes_and_admin_does_not():
    assert unraid.key_problem(load("me_viewer")["data"]["me"]) is None
    msg = unraid.key_problem(load("me_admin")["data"]["me"])
    assert "ADMIN" in msg and "Settings \u2192 Management Access \u2192 API Keys" in msg and "Viewer" in msg
    mixed = unraid.key_problem(load("me_viewer_with_write")["data"]["me"])
    assert mixed and "docker" in mixed and "role" not in mixed.split("permission")[0].replace("Viewer", "")
    assert unraid.key_problem({"roles": [], "permissions": [{"resource": "ARRAY", "actions": ["READ_ANY"]}]}) is None
    assert unraid.key_problem({"roles": ["VIEWER", "CONNECT"], "permissions": []})
    assert unraid.key_problem({"roles": ["GUEST"], "permissions": []})


def test_probe_reports_what_it_found(fake):
    p = run(unraid.probe(fake.net(), "https://tower.test:4443", KEY))
    assert p.ok and p.roles == ["VIEWER"] and p.name == "tower-test" and p.version == "7.3.2"
    assert p.array_state == "STARTED" and p.disks == 6 and p.containers == 12


def test_probe_stops_at_a_key_that_can_change_things(fake):
    fake.replies[unraid.Q_ME] = load("me_admin")
    p = run(unraid.probe(fake.net(), "https://tower.test:4443", KEY))
    assert not p.ok and p.roles == ["ADMIN"] and "Viewer" in p.problem
    assert fake.queries() == [unraid.Q_ME]     # nothing else was asked of an over-privileged key


def test_probe_errors_are_clear_and_never_hold_the_key(fake):
    for exc, kind in ((httpx.ConnectTimeout("timed out"), "unreachable"), (httpx.ConnectError(f"refused {KEY}"), "unreachable")):
        fake.fail = exc
        with pytest.raises(RemoteError) as e:
            run(unraid.probe(fake.net(), "https://tower.test:4443", KEY))
        assert e.value.kind == kind and KEY not in e.value.message
    fake.fail = None
    with pytest.raises(RemoteError) as e:
        run(unraid.probe(fake.net(), "https://tower.test:4443", "wrong-key-wrong-key"))
    assert e.value.kind == "auth"
    fake.status = 302
    with pytest.raises(RemoteError) as e:
        run(unraid.probe(fake.net(), "https://tower.test:4443", KEY))
    assert "redirect" in e.value.message.lower()


def test_a_huge_reply_is_refused(fake):
    fake.replies[unraid.Q_ME] = {"data": {"me": {"name": "x" * (9 << 20), "roles": [], "permissions": []}}}
    with pytest.raises(RemoteError) as e:
        run(unraid.probe(fake.net(), "https://tower.test:4443", KEY))
    assert "larger" in e.value.message


# --- addresses and fingerprints -----------------------------------------------------------

def test_normalize_url():
    assert normalize_url("https://tower.example.lan") == "https://tower.example.lan"
    assert normalize_url("tower.example.lan:4443/") == "https://tower.example.lan:4443"
    assert normalize_url("https://192.0.2.10:4443/graphql") == "https://192.0.2.10:4443"
    assert normalize_url("https://[2001:db8::1]:4443") == "https://[2001:db8::1]:4443"
    for bad in ("http://tower.lan", "", "https://", "ftp://x", "https://u:p@host", "https://host/x/y", "https://host?x=1",
                "https://host:99999", "https://ho st", "x" * 400):
        with pytest.raises(ValueError):
            normalize_url(bad)
    with pytest.raises(ValueError, match="plain text"):
        normalize_url("http://tower.lan")


def test_fingerprints(tmp_path):
    pem, _, _ = make_cert(tmp_path)
    fp = fingerprint(pem)
    assert re.fullmatch(r"[0-9a-f]{64}", fp)
    pretty = fmt_fingerprint(fp)
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", pretty)
    assert clean_fingerprint(pretty) == fp == clean_fingerprint(" " + fp.upper() + "\n")
    assert clean_fingerprint("abc") is None and clean_fingerprint(None) is None


# --- the rules ----------------------------------------------------------------------------------

def test_fixture_data_findings_and_their_links():
    f = unraid_rules.evaluate(all_data(), NOW)
    full = by_rule(f, "unraid.disk_full")
    # Real data: four data disks over 95%, and the array at 84% is under 90%.
    assert sorted((x.key, x.severity) for x in full) == [("disk1", "high"), ("disk2", "high"), ("disk3", "high"), ("disk5", "high")]
    assert not by_rule(f, "unraid.array_state") and not by_rule(f, "unraid.disk_errors") and not by_rule(f, "unraid.ups")
    old = by_rule(f, "unraid.parity_old")
    assert old and old[0].severity == "low" and "days ago" in old[0].title      # the last good check is August
    assert not by_rule(f, "unraid.parity_errors")      # the last completed check had 0 errors
    updates = by_rule(f, "unraid.container_updates")
    assert len(updates) == 1 and not by_rule(f, "unraid.container_update")
    assert updates[0].title == f"{sum(1 for c in parsed('unraid_docker')['containers'] if c['update'])} containers have updates"
    assert by_rule(f, "unraid.unclean_shutdown") and by_rule(f, "unraid.notification")
    for x in f:
        assert x.fix is None and x.basis, x.rule            # decisions: no command, and a basis
        assert x.howto and all(ln.strip() for ln in x.howto.split("\n")), x.rule     # every Unraid rule says what to do
        assert x.link.startswith("/") and not x.link.startswith("//")
        assert len(x.key) <= 300 and len(x.title) <= 300 and len(x.detail) <= 4000


def test_disk_full_thresholds_per_disk_and_array():
    def edit(a):
        a["disks"][1]["percent"], a["disks"][2]["percent"], a["disks"][3]["percent"] = 89.9, 90.0, 94.9
        a["disks"][4]["percent"] = 95.0      # disk4; disk5 stays at its real 97%
        a["capacity"]["percent"] = 91.0
    sev = {x.key: x.severity for x in by_rule(rules_for(array=edit), "unraid.disk_full")}
    assert sev == {"disk2": "medium", "disk3": "medium", "disk4": "high", "disk5": "high", "array": "medium"}
    assert "disk1" not in sev                # 89.9% is under the line
    assert {x.key: x.severity for x in by_rule(rules_for(array=lambda a: a["capacity"].update(percent=95)),
                                               "unraid.disk_full")}["array"] == "high"
    # The band is part of the basis, so a disk that goes from medium to high comes back if it was accepted.
    f = {x.key: x.basis for x in by_rule(rules_for(array=edit), "unraid.disk_full")}
    assert f["disk3"] == "disk3:medium" and f["disk4"] == "disk4:high"


def test_array_not_started():
    f = by_rule(rules_for(array=lambda a: a.update(state="STOPPED")), "unraid.array_state")
    assert len(f) == 1 and f[0].severity == "high" and "stopped" in f[0].detail and f[0].link == "/disks#array"
    # No parity findings while the array is down.
    assert not by_rule(rules_for(array=lambda a: a.update(state="STOPPED")), "unraid.parity_old")
    assert by_rule(rules_for(array=lambda a: a.update(state="RECON_DISK")), "unraid.array_state")[0].severity == "medium"


@pytest.mark.parametrize("status", ["DISK_DSBL", "DISK_NP_DSBL", "DISK_NP_MISSING", "DISK_INVALID", "DISK_WRONG", "DISK_DSBL_NEW"])
def test_a_disk_that_is_disabled_missing_or_emulated(status):
    f = by_rule(rules_for(array=lambda a: a["disks"][2].update(status=status)), "unraid.disk_state")
    assert len(f) == 1 and f[0].key == "disk2" and f[0].severity == "high" and f[0].link == "/disks#disk-disk2"
    assert status in f[0].detail


def test_ok_and_empty_slot_statuses_make_no_disk_finding():
    for status in ("DISK_OK", "DISK_NP", "DISK_NEW"):
        assert not by_rule(rules_for(array=lambda a: a["disks"][2].update(status=status)), "unraid.disk_state")


def test_disk_errors_count_errors_not_io_requests():
    def edit(a):
        a["disks"][1]["reads"], a["disks"][1]["writes"] = 5_000_000, 7_000_000      # I/O request counts: not errors
        a["disks"][3]["errors"] = 3
    f = by_rule(rules_for(array=edit), "unraid.disk_errors")
    assert [(x.key, x.severity) for x in f] == [("disk3", "high")] and "3 read or write errors" in f[0].title
    assert f[0].basis == "disk3:3"          # a changed count brings back an accepted finding


def test_disk_temperature_uses_unraids_own_thresholds():
    def hot(t):
        return lambda a: a["disks"][1].update(temp=t)
    assert not by_rule(rules_for(array=hot(44)), "unraid.disk_temp")
    f = by_rule(rules_for(array=hot(45)), "unraid.disk_temp")
    assert f[0].severity == "medium" and "45" in f[0].detail and "Settings \u2192 Disk Settings" in f[0].detail
    assert by_rule(rules_for(array=hot(55)), "unraid.disk_temp")[0].severity == "high"

    def custom(a):
        a["thresholds"].update(hot=50, max=60)
        a["disks"][1]["temp"] = 49
    assert not by_rule(rules_for(array=custom), "unraid.disk_temp")     # the user's own limit
    # SSDs: Unraid's defaults (the API doesn't expose them).
    def ssd(a):
        a["disks"][1].update(rotational=False, temp=59)
    assert not by_rule(rules_for(array=ssd), "unraid.disk_temp")
    assert by_rule(rules_for(array=lambda a: a["disks"][1].update(rotational=False, temp=60)), "unraid.disk_temp")
    # Spun-down disks have no temperature; the boot flash is never judged.
    assert not by_rule(rules_for(array=lambda a: a["disks"][1].update(temp=None)), "unraid.disk_temp")
    assert not by_rule(rules_for(array=lambda a: a["disks"][-1].update(temp=90)), "unraid.disk_temp")
    # Without the thresholds, HDDs fall back to Unraid's shipped 45 and 55.
    assert by_rule(rules_for(array=lambda a: (a.update(thresholds={}), a["disks"][1].update(temp=46))), "unraid.disk_temp")


def test_smart_status_not_ok():
    def edit(d):
        d["disks"][2]["smart"] = "UNKNOWN"      # /dev/sdc is disk1
    f = by_rule(rules_for(disks=edit), "unraid.disk_smart")
    assert [(x.key, x.severity) for x in f] == [("disk1", "medium")] and "UNKNOWN" in f[0].detail
    # The boot flash (USB, UNKNOWN in the real data) and unassigned devices are not judged.
    assert not by_rule(unraid_rules.evaluate(all_data(), NOW), "unraid.disk_smart")


def test_parity_check_errors_and_age():
    def with_errors(a):
        a["parity_history"].insert(0, {"status": "COMPLETED", "date": NOW - 86400 * 3, "errors": 4, "duration": 1, "speed": ""})
    f = rules_for(array=with_errors)
    pe = by_rule(f, "unraid.parity_errors")
    assert len(pe) == 1 and pe[0].severity == "high" and "4 errors" in pe[0].title
    assert not by_rule(f, "unraid.parity_old")              # a check 3 days ago
    def fresh_clean(a):
        a["parity_history"].insert(0, {"status": "COMPLETED", "date": NOW - 86400, "errors": 0, "duration": 1, "speed": ""})
    assert not by_rule(rules_for(array=fresh_clean), "unraid.parity_errors")
    # Boundary: 100 days.
    def aged(days):
        return lambda a: a.update(parity_history=[{"status": "COMPLETED", "date": NOW - 86400 * days, "errors": 0}],
                                  parity_check={"status": "NEVER_RUN", "running": False})
    assert not by_rule(rules_for(array=aged(99)), "unraid.parity_old")
    assert by_rule(rules_for(array=aged(101)), "unraid.parity_old")
    assert "never" == by_rule(rules_for(array=lambda a: a.update(parity_history=[], parity_check={})), "unraid.parity_old")[0].basis
    # A check that is running now is not "old"; an array with no parity disk has nothing to check.
    assert not by_rule(rules_for(array=lambda a: (aged(300)(a), a["parity_check"].update(running=True))), "unraid.parity_old")
    assert not by_rule(rules_for(array=lambda a: a.update(disks=[d for d in a["disks"] if d["kind"] != "parity"])), "unraid.parity_old")


def test_container_updates_are_one_low_finding_with_the_names():
    f = by_rule(rules_for(), "unraid.container_updates")
    names = sorted((c["name"] for c in parsed("unraid_docker")["containers"] if c["update"]), key=str.lower)
    assert len(f) == 1 and f[0].severity == "low" and f[0].fix is None and f[0].link == "/containers" and f[0].key == "all"
    assert f[0].title == f"{len(names)} containers have updates" and all(n in f[0].detail for n in names)
    assert f[0].basis == ",".join(names)            # a new container with an update brings back an accepted finding
    assert "Check for Updates" in f[0].howto and "Update All" in f[0].howto and ":latest" in f[0].howto
    one = by_rule(rules_for(docker=lambda d: [c.update(update=(i == 1)) for i, c in enumerate(d["containers"])]),
                  "unraid.container_updates")
    assert one[0].title == "1 container has an update"
    assert not by_rule(rules_for(docker=lambda d: [c.update(update=False) for c in d["containers"]]), "unraid.container_updates")
    assert not by_rule(rules_for(docker=lambda d: [c.update(update=None) for c in d["containers"]]), "unraid.container_updates")

    def many(d):
        d["containers"] = [{"name": f"c{i:03d}", "image": "x", "state": "RUNNING", "update": True} for i in range(55)]
    big = by_rule(rules_for(docker=many), "unraid.container_updates")[0]
    assert big.title == "55 containers have updates" and "c039" in big.detail and "c040" not in big.detail and "and 15 more" in big.detail


def test_ups_on_battery_and_low_charge():
    def ups(**kw):
        return lambda u: u["devices"][0].update(**kw)
    assert not by_rule(rules_for(ups=ups()), "unraid.ups")
    f = by_rule(rules_for(ups=ups(status="ONBATT", charge=80)), "unraid.ups")
    assert len(f) == 1 and f[0].severity == "medium" and "battery" in f[0].title and f[0].link == "/#ups"
    assert by_rule(rules_for(ups=ups(status="On Battery", charge=25)), "unraid.ups")[0].severity == "high"
    assert by_rule(rules_for(ups=ups(status="ONLINE LOWBATT", charge=90)), "unraid.ups")[0].severity == "high"
    low = by_rule(rules_for(ups=ups(charge=49)), "unraid.ups")
    assert low[0].severity == "medium" and "49%" in low[0].title
    assert not by_rule(rules_for(ups=ups(charge=50)), "unraid.ups")
    rep = by_rule(rules_for(ups=ups(health="Replace")), "unraid.ups")
    assert rep[0].severity == "low" and rep[0].key.endswith(":battery")
    assert not by_rule(rules_for(ups=lambda u: u.update(devices=[])), "unraid.ups")


# --- key files ---------------------------------------------------------------------------------

def test_key_files_are_private_and_replaceable(cfg, conn):
    add(conn, cfg)
    path = store.key_path(cfg.data_dir, "tower")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert store.read_key(cfg.data_dir, "tower") == KEY
    other = "b" * 40
    store.write_key(cfg.data_dir, "tower", other)
    assert store.read_key(cfg.data_dir, "tower") == other and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(path.parent.glob("*.tmp"))
    for bad in ("short", "has space in it", "x" * 300, "", "tab\tkey1234"):
        with pytest.raises(ValueError):
            store.clean_key(bad)
    for bad_id in ("../x", "a/b", ""):
        with pytest.raises(ValueError):
            store.key_path(cfg.data_dir, bad_id)


def test_the_key_is_never_in_the_database(cfg, conn):
    add(conn, cfg)
    conn.execute("PRAGMA wal_checkpoint(FULL)")
    for p in cfg.db_path.parent.glob("state.db*"):
        assert KEY.encode() not in p.read_bytes(), p.name
    row = store.get(conn, "tower")
    assert KEY not in repr(dict(row)) and KEY not in repr(dict(conn.execute("SELECT * FROM hosts").fetchone()))


def test_a_remote_has_no_upload_token_and_hub_commands_skip_it(cfg, conn):
    add(conn, cfg)
    h = conn.execute("SELECT * FROM hosts WHERE id='tower'").fetchone()
    assert h["kind"] == "unraid" and h["token_hash"] == "remote:tower" and not re.fullmatch(r"[0-9a-f]{64}", h["token_hash"])
    assert hub.host_for_token(conn, "remote:tower") is None and hub.host_for_token(conn, h["token_hash"]) is None
    # `hub update` leaves it alone, one by one or all at once, and it never counts as behind.
    assert hub.request_update(conn, "tower", "abc1234", NOW) is False
    conn.execute("UPDATE hosts SET last_seen=?, version='x' WHERE id='tower'", (NOW,))
    assert hub.request_update_all(conn, "abc1234", NOW) == []
    assert not hub.behind(conn.execute("SELECT * FROM hosts WHERE id='tower'").fetchone(), "abc1234")
    # It is never "silent": nobody uploads for it.
    hub.check_silent(conn, NOW + 10**6)
    assert not conn.execute("SELECT 1 FROM findings WHERE rule='host.silent'").fetchone()
    with pytest.raises(ValueError):
        hub.add_host(conn, "tower")


def test_removing_deletes_the_key_file_and_history(cfg, conn):
    add(conn, cfg)
    db.put_snapshot(conn, "tower", "unraid_array", NOW, True, None, {"state": "STARTED"})
    db.add_metrics(conn, "tower", NOW, {"cpu.percent": 1.0})
    db.add_event(conn, "tower", NOW, "x", "t")
    db.reconcile_findings(conn, "tower", NOW, [Finding("unraid.disk_full", "d", "low", "t", "d")])
    path = store.key_path(cfg.data_dir, "tower")
    assert path.exists()
    assert hub.revoke_host(conn, "tower", purge=True, data_dir=cfg.data_dir)
    assert not path.exists()
    for table in ("snapshots", "metrics", "findings", "events", "hosts", "remotes"):
        col = "id" if table in ("hosts", "remotes") else "host"
        assert not conn.execute(f"SELECT 1 FROM {table} WHERE {col}='tower'").fetchone(), table
    assert not hub.revoke_host(conn, "tower", data_dir=cfg.data_dir)


def test_a_collector_cannot_send_a_hub_rule():
    from pydantic import ValidationError
    for rule in ("unraid.disk_full", "remote.unreachable", "host.silent", "cve.package"):
        with pytest.raises(ValidationError):
            hub.FindingIn(rule=rule, key="k", severity="low", title="t", detail="d")
    hub.FindingIn(rule="pkg.updates", key="k", severity="low", title="t", detail="d")


# --- the poller ----------------------------------------------------------------------------------

def poll_at(conn, cfg, fake, now):
    return run(poll.run_once(conn, cfg, fake.net(), now))


def test_a_poll_stores_every_source_and_opens_findings(conn, cfg, fake):
    add(conn, cfg)
    assert poll_at(conn, cfg, fake, NOW) == 1
    snaps = db.get_snapshots(conn, "tower")
    assert set(snaps) == set(unraid.SOURCES) and all(s.ok for s in snaps.values())
    r = store.get(conn, "tower")
    assert r["last_ok"] == NOW and r["last_error"] is None and r["fails"] == 0
    assert conn.execute("SELECT last_seen, version FROM hosts WHERE id='tower'").fetchone()["version"] == "Unraid 7.3.2"
    rules = {f["rule"] for f in db.open_findings(conn, "tower")}
    assert {"unraid.disk_full", "unraid.parity_old", "unraid.container_updates", "unraid.notification",
            "unraid.unclean_shutdown"} <= rules
    assert not any(r == "unraid.container_update" for r in rules)
    assert db.metric_series(conn, "tower", "cpu.percent", 0)[0][0] == NOW
    assert any(e["title"].startswith("Disk") or e["title"] for e in db.recent_events(conn, "tower"))
    # The first request each poll is `me`.
    assert fake.queries()[0] == unraid.Q_ME


def test_cheap_sources_every_interval_expensive_ones_every_five_minutes(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    first = fake.queries()
    assert unraid.Q_DISKS in first and unraid.Q_NOTIFICATIONS in first
    fake.requests.clear()
    assert poll_at(conn, cfg, fake, NOW + 30) == 0          # not due yet
    assert poll_at(conn, cfg, fake, NOW + 60) == 1
    q = fake.queries()
    assert unraid.Q_ARRAY in q and unraid.Q_DOCKER in q and unraid.Q_UPS in q
    assert unraid.Q_DISKS not in q and unraid.Q_NOTIFICATIONS not in q
    fake.requests.clear()
    poll_at(conn, cfg, fake, NOW + 300)
    assert unraid.Q_DISKS in fake.queries() and unraid.Q_NOTIFICATIONS in fake.queries()


def test_a_disabled_system_is_not_polled(conn, cfg, fake):
    add(conn, cfg)
    store.set_enabled(conn, "tower", False)
    assert poll_at(conn, cfg, fake, NOW) == 0 and fake.requests == []


def test_unreachable_is_a_finding_only_after_a_few_polls(conn, cfg, fake):
    add(conn, cfg, now=NOW - 5)
    poll_at(conn, cfg, fake, NOW)                      # a good read
    fake.fail = httpx.ConnectTimeout("t")
    t = NOW + 60
    poll_at(conn, cfg, fake, t)
    r = store.get(conn, "tower")
    assert r["fails"] == 1 and "did not answer" in r["last_error"] and r["last_ok"] == NOW
    assert "remote.unreachable" not in {f["rule"] for f in db.open_findings(conn, "tower")}    # one missed poll is nothing
    ev = [e["title"] for e in db.recent_events(conn, "tower", 50)]
    assert "Could not read this system" in ev
    poll_at(conn, cfg, fake, NOW + 120)
    poll_at(conn, cfg, fake, NOW + 181)                # past three intervals and three minutes since the last good read
    f = [x for x in db.open_findings(conn, "tower") if x["rule"] == "remote.unreachable"]
    assert len(f) == 1 and f[0]["severity"] == "high" and "did not answer" in f[0]["detail"] and f[0]["fix"] is None
    # The system's stored readings and findings are left as they were.
    assert any(x["rule"] == "unraid.disk_full" for x in db.open_findings(conn, "tower"))
    assert db.get_snapshot(conn, "tower", "unraid_array").taken_at == NOW
    # Coming back resolves it and says so; the event for the first failure isn't repeated every poll.
    fake.fail = None
    poll_at(conn, cfg, fake, NOW + 250)
    assert not [x for x in db.open_findings(conn, "tower") if x["rule"] == "remote.unreachable"]
    ev = [e["title"] for e in db.recent_events(conn, "tower", 50)]
    assert ev.count("Could not read this system") == 1 and "Reading this system again" in ev
    r = store.get(conn, "tower")
    assert r["fails"] == 0 and r["last_error"] is None


def test_a_missing_key_file_is_an_error_not_a_crash(conn, cfg, fake):
    add(conn, cfg)
    store.key_path(cfg.data_dir, "tower").unlink()
    poll_at(conn, cfg, fake, NOW)
    assert "key file is missing" in store.get(conn, "tower")["last_error"] and fake.requests == []


def test_a_key_that_gained_more_than_viewer_stops_the_poll(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    fake.replies[unraid.Q_ME] = load("me_admin")
    fake.requests.clear()
    poll_at(conn, cfg, fake, NOW + 60)
    assert fake.queries() == [unraid.Q_ME]
    r = store.get(conn, "tower")
    assert r["fails"] == 1 and "Viewer" in r["last_error"] and KEY not in r["last_error"]


def test_one_failing_source_keeps_its_data_and_the_others_go_on(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    before = db.get_snapshot(conn, "tower", "unraid_docker").data
    fake.replies[unraid.Q_DOCKER] = {"data": {"docker": None}, "errors": [{"message": "docker is down"}]}
    poll_at(conn, cfg, fake, NOW + 60)
    d = db.get_snapshot(conn, "tower", "unraid_docker")
    assert not d.ok and "docker is down" in d.error and d.data == before      # the last data stays
    assert db.get_snapshot(conn, "tower", "unraid_array").taken_at == NOW + 60
    assert store.get(conn, "tower")["fails"] == 0           # the server itself answered
    assert any(f["rule"] == "unraid.container_updates" for f in db.open_findings(conn, "tower"))


def test_a_field_error_with_data_is_a_warning_not_a_failure(conn, cfg, fake):
    add(conn, cfg)
    fake.errors[unraid.Q_DOCKER] = [{"message": "update status is not available"}]
    poll_at(conn, cfg, fake, NOW)
    assert db.get_snapshot(conn, "tower", "unraid_docker").ok


def test_findings_clear_when_the_server_fixes_things(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    assert any(f["rule"] == "unraid.container_updates" for f in db.open_findings(conn, "tower"))
    fake.set(unraid.Q_DOCKER, lambda d: [c.update(isUpdateAvailable=False) for c in d["docker"]["containers"]])
    poll_at(conn, cfg, fake, NOW + 60)
    assert not any(f["rule"] == "unraid.container_updates" for f in db.open_findings(conn, "tower"))
    assert any(e["title"].startswith("Resolved:") for e in db.recent_events(conn, "tower", 100))


def test_polling_never_touches_other_hosts_findings(conn, cfg, fake):
    add(conn, cfg)
    conn.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('web1', 'x', 1)")
    db.reconcile_findings(conn, "web1", NOW, [Finding("pkg.updates", "u", "low", "t", "d"),
                                              Finding("host.clock_skew", "clock", "low", "c", "d")])
    poll_at(conn, cfg, fake, NOW)
    assert {f["rule"] for f in db.open_findings(conn, "web1")} == {"pkg.updates", "host.clock_skew"}


def test_the_key_never_reaches_the_database_events_or_errors(conn, cfg, fake):
    add(conn, cfg)
    fake.fail = httpx.ConnectError(f"cannot connect with {KEY}")
    for i in range(6):
        poll_at(conn, cfg, fake, NOW + 60 * i)
    fake.fail = None
    poll_at(conn, cfg, fake, NOW + 600)
    dump = "\n".join(str(tuple(r)) for t in ("remotes", "events", "findings", "snapshots", "hosts")
                     for r in conn.execute(f"SELECT * FROM {t}"))
    assert KEY not in dump
