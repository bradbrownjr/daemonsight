"""Caddy, fail2ban and nftables sources, and the rules built on them."""

import asyncio
import base64
import json
import os
import pickle
from pathlib import Path

import httpx
import pytest

from daemonsight import findings
from daemonsight.collector.sources import SourceUnavailable
from daemonsight.collector.sources.caddy import CaddySource, parse_config, parse_dial
from daemonsight.collector.sources.fail2ban import END, Fail2banSource, safe_loads
from daemonsight.collector.sources.firewall import port_verdict, summarize
from daemonsight.db import Snapshot

FIX = Path(__file__).parent / "fixtures"


def adapter_json(name: str) -> dict:
    """The JSON half of one of Caddy's own adapter test cases."""
    text = (FIX / "caddy" / f"{name}.caddyfiletest").read_text()
    return json.loads(text.split("----------\n", 1)[1])


def snap(source, data, ok=True, error=None):
    return Snapshot(source, 0.0, ok, error, data)


# ---- Caddy ------------------------------------------------------------------

def test_parse_dial():
    assert parse_dial("localhost:8001") == {"network": "tcp", "host": "localhost", "port": 8001,
                                            "text": "localhost:8001"}
    assert parse_dial("[::1]:9000")["port"] == 9000
    assert parse_dial("unix//run/app.sock")["path"] == "/run/app.sock"
    assert parse_dial("{http.request.host}:80")["network"] == "placeholder"
    assert parse_dial("whoami")["port"] is None


def test_caddy_sites_from_real_adapter_output():
    s = parse_config(adapter_json("portless_upstream"))
    hosts = {x["host"]: x for x in s["sites"]}
    assert set(hosts) == {"whoami.example.com", "app.example.com", "unix.example.com"}
    assert hosts["app.example.com"]["handlers"][0]["upstreams"][0]["port"] == 80
    assert hosts["unix.example.com"]["handlers"][0]["upstreams"][0]["network"] == "unix"
    assert s["admin"] == {"listen": "localhost:2019", "disabled": False}
    assert s["servers"][0]["listen"] == [":443"]


def test_caddy_nested_handle_hosts():
    # "*.example.com" with "handle @foo" blocks matching inner hosts.
    s = parse_config(adapter_json("wildcard_pattern"))
    hosts = {x["host"]: x for x in s["sites"]}
    assert {"foo.example.com", "bar.example.com", "*.example.com"} <= set(hosts)
    assert hosts["foo.example.com"]["handlers"][0]["kind"] == "respond"
    # The abort fallback has no IP matcher, so it restricts nothing.
    assert hosts["*.example.com"]["allow"] == []


def test_caddy_ip_restriction():
    # "@outside not remote_ip 10.0.0.0/8; abort @outside; reverse_proxy :8080",
    # built from the JSON shapes in the adapter cases above: "not" from
    # matcher_syntax, abort from wildcard_pattern.
    cfg = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [{
        "match": [{"host": ["lan.example.com"]}], "terminal": True,
        "handle": [{"handler": "subroute", "routes": [
            {"match": [{"not": [{"remote_ip": {"ranges": ["10.0.0.0/8"]}}]}],
             "handle": [{"handler": "static_response", "abort": True}]},
            {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:8080"}]}]},
        ]}]}, {
        "match": [{"host": ["public.example.com"]}], "terminal": True,
        "handle": [{"handler": "subroute", "routes": [
            {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:8081"}]}]}]}]},
    ]}}}}}
    hosts = {x["host"]: x for x in parse_config(cfg)["sites"]}
    assert hosts["lan.example.com"]["allow"] == ["10.0.0.0/8"]
    assert hosts["public.example.com"]["allow"] == []


async def test_caddy_source_sends_only_get():
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.method, request.url.path, request.headers["host"]))
        if request.url.path == "/config/":
            return httpx.Response(200, json=adapter_json("portless_upstream"))
        return httpx.Response(200, json=[{"address": "app:80", "num_requests": 0, "fails": 2}])

    src = CaddySource(60, "localhost:2019")
    src._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://localhost:2019")
    data = await src.collect()
    await src.close()
    assert {m for m, _, _ in seen} == {"GET"}
    assert seen[0][2] == "localhost:2019"  # the admin API checks Host on TCP
    assert data["upstream_status"][0]["fails"] == 2
    assert src.metrics(data) == {"caddy.fails.app:80": 2.0}


async def test_caddy_source_unavailable(tmp_path):
    src = CaddySource(60, f"unix/{tmp_path}/none.sock")
    with pytest.raises(SourceUnavailable):
        await src.collect()
    await src.close()


# ---- fail2ban ---------------------------------------------------------------

def recorded() -> dict:
    data = json.loads((FIX / "fail2ban-1.1.0.json").read_text())
    return {tuple(x["cmd"]): base64.b64decode(x["reply_b64"]) for x in data["exchanges"]}


@pytest.fixture
async def fake_f2b(tmp_path):
    """A Unix socket that answers with replies recorded from fail2ban 1.1.0."""
    replies = recorded()
    path = str(tmp_path / "f2b.sock")
    received = []

    async def serve(reader, writer):
        try:
            while True:
                raw = await reader.readuntil(END)
                msg = raw[: -len(END)]
                if msg.startswith(b"<F2B_CLOSE_COMMAND>"):
                    break
                cmd = tuple(pickle.loads(msg))
                received.append(cmd)
                writer.write(replies[cmd] + END)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        writer.close()

    server = await asyncio.start_unix_server(serve, path)
    yield path, received
    server.close()
    await server.wait_closed()


async def test_fail2ban_source_on_recorded_replies(fake_f2b):
    path, received = fake_f2b
    data = await Fail2banSource(60, path).collect()
    assert data["version"] == "1.1.0"
    jails = {j["name"]: j for j in data["jails"]}
    web, jrnl = jails["web"], jails["jrnl"]
    assert web["backend"] == "file" and web["logpaths"][0]["path"] == "/tmp/claude-1000/ds-f2b/web.log"
    assert web["banned_now"] == 2 and web["maxretry"] == 2 and web["ignoreip"] == ["127.0.0.1"]
    assert [b["ip"] for b in web["bans"]] == ["203.0.113.5", "198.51.100.7"]
    assert web["bans"][0]["seconds"] == 600
    assert jrnl["backend"] == "systemd" and jrnl["units"] == ["ssh.service"]
    # Read-only commands only.
    assert {c[0] for c in received} <= {"version", "status", "get"}


def test_fail2ban_error_reply_and_refusal():
    err = recorded()[("status", "nope")]
    code, exc = safe_loads(err)
    assert code == 1 and type(exc).__name__ == "UnknownJailException"

    class Evil:
        def __reduce__(self):
            return (os.system, ("true",))

    with pytest.raises(pickle.UnpicklingError):
        safe_loads(pickle.dumps(Evil()))


# ---- nftables (shapes from libnftables-json(5); not yet real output) ----------

def m(field, right, proto="tcp", op="=="):
    return {"match": {"op": op, "left": {"payload": {"protocol": proto, "field": field}}, "right": right}}


RULESET = {"nftables": [
    {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "filter", "handle": 1}},
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
               "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "filter", "name": "lan_only", "handle": 2}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
        {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
        {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [m("dport", 22), {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
        m("dport", {"set": [80, 443]}), {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
        m("dport", 443, proto="udp"), {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
        {"jump": {"target": "lan_only"}}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "lan_only", "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                   "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}},
        m("dport", {"range": [8000, 8999]}), {"accept": None}]}},
]}


def test_firewall_summary_and_verdicts():
    fw = summarize(RULESET)
    assert fw["filtering"] is True and fw["docker_nat"] is False
    chain = fw["input"][0]
    assert chain["policy"] == "drop" and chain["default"] == "drop" and not chain["accept_all"]
    assert port_verdict(fw, "tcp", 22)["state"] == "open"
    assert port_verdict(fw, "tcp", 443)["state"] == "open"
    assert port_verdict(fw, "udp", 443)["state"] == "open"
    assert port_verdict(fw, "udp", 22)["state"] == "blocked"
    r = port_verdict(fw, "tcp", 8466)
    assert r["state"] == "restricted" and "from" in r["why"]
    assert port_verdict(fw, "tcp", 3306)["state"] == "blocked"


def test_firewall_policy_accept_and_unknown_match():
    rs = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input",
                   "prio": 0, "policy": "accept"}},
        {"chain": {"family": "inet", "table": "fw", "name": "in", "type": "filter", "hook": "input",
                   "prio": 0, "policy": "drop"}},
        # An xt match from iptables-nft: not understood, so only conditional.
        {"rule": {"family": "inet", "table": "fw", "chain": "in", "expr": [
            {"xt": {"type": "match", "name": "recent"}}, m("dport", 25), {"accept": None}]}},
    ]}
    fw = summarize(rs)
    assert port_verdict(fw, "tcp", 25)["state"] == "restricted"
    assert port_verdict(fw, "tcp", 26)["state"] == "blocked"
    only_accept = summarize({"nftables": [rs["nftables"][0]]})
    assert port_verdict(only_accept, "tcp", 26)["state"] == "unfiltered"


# ---- Rules ------------------------------------------------------------------

def listener(port, proto="tcp", scope="all", addresses=("0.0.0.0",), unit=None, process=None):
    owner = {"kind": "unit", "id": unit} if unit else {"kind": "unknown", "id": None}
    return {"proto": proto, "port": port, "addresses": list(addresses), "scope": scope,
            "pid": 1, "process": process, "owner": owner}


def ports_data(listeners, public=True):
    addrs = [{"nic": "eth0", "ip": "203.0.113.10" if public else "10.6.26.3",
              "scope": "public" if public else "private"}]
    return {"listeners": listeners, "owners_known": True, "addresses": addrs}


def test_expose_unexpected_uses_firewall(cfg):
    snaps = {
        "ports": snap("ports", ports_data([
            listener(22, unit="ssh.service", process="sshd"),
            listener(3306, unit="mariadb.service", process="mariadbd"),
            listener(8000, process="python3"),
            listener(9000, addresses=("127.0.0.1",), scope="loopback"),
        ])),
        "firewall": snap("firewall", summarize(RULESET)),
    }
    got = {f.key: f for f in findings.evaluate(snaps, cfg) if f.rule == "expose.unexpected"}
    assert set(got) == {"3306/tcp", "8000/tcp"}
    assert got["3306/tcp"].severity == "medium"  # blocked by the firewall
    assert got["8000/tcp"].severity == "medium"  # LAN-only by rule: restricted

    snaps["firewall"] = snap("firewall", {"available": False, "reason": "nft is not installed"})
    got = {f.key: f for f in findings.evaluate(snaps, cfg) if f.rule == "expose.unexpected"}
    assert got["3306/tcp"].severity == "critical"


def test_lan_host_wildcard_bind_is_not_internet(cfg):
    snaps = {"ports": snap("ports", ports_data([listener(3306)], public=False))}
    assert not [f for f in findings.evaluate(snaps, cfg) if f.rule == "expose.unexpected"]


def test_route_upstream_down_and_failing(cfg):
    caddy = parse_config(adapter_json("portless_upstream"))
    caddy["sites"].append({"host": "local.example.com", "server": "srv0", "listen": [":443"], "allow": [],
                           "handlers": [{"kind": "proxy", "paths": [], "allow": [], "upstreams": [
                               parse_dial("localhost:8001"), parse_dial("127.0.0.1:8002")]}]})
    caddy["upstream_status"] = [{"address": "localhost:8001", "num_requests": 0, "fails": 0},
                                {"address": "app:80", "num_requests": 0, "fails": 3}]
    snaps = {"caddy": snap("caddy", caddy),
             "ports": snap("ports", ports_data([listener(8001, addresses=("127.0.0.1",), scope="loopback")]))}
    fs = findings.evaluate(snaps, cfg)
    down = {f.key for f in fs if f.rule == "route.upstream_down"}
    # app:80 is another host; the unix socket path doesn't exist here.
    assert down == {"local.example.com 127.0.0.1:8002", "unix.example.com unix//path/to/socket"}
    assert {f.key for f in fs if f.rule == "route.upstream_failing"} == {"app:80"}
    admin = [f for f in fs if f.rule == "caddy.admin_tcp"]
    assert admin and admin[0].severity == "low"


def test_jail_coverage(cfg):
    ports = snap("ports", ports_data([
        listener(22, unit="ssh.service", process="sshd"),
        listener(443, unit="caddy.service", process="caddy"),
        listener(25, unit="postfix@-.service", process="master"),
    ]))
    jails = [
        {"name": "sshd", "units": [], "logpaths": [{"path": "/var/log/auth.log", "exists": True}]},
        {"name": "caddy-auth", "units": [], "logpaths": [{"path": "/var/log/caddy/access.log", "exists": True}]},
        {"name": "old", "units": [], "logpaths": [{"path": "/var/log/gone.log", "exists": False}]},
    ]
    snaps = {"ports": ports, "fail2ban": snap("fail2ban", {"version": "1.1.0", "jails": jails})}
    fs = findings.evaluate(snaps, cfg)
    assert {f.key for f in fs if f.rule == "jail.uncovered"} == {"postfix@-.service"}
    assert {f.key for f in fs if f.rule == "jail.log_missing"} == {"old /var/log/gone.log"}

    cfg.exposure.jail_covers = {"old": ["postfix@-.service"]}
    assert not [f for f in findings.evaluate(snaps, cfg) if f.rule == "jail.uncovered"]

    snaps["fail2ban"] = snap("fail2ban", {"available": False, "reason": "fail2ban is not running"})
    fs = [f for f in findings.evaluate(snaps, cfg) if f.rule == "jail.uncovered"]
    assert len(fs) == 3 and "not running" in fs[0].detail


# ---- Pages ------------------------------------------------------------------

def test_phase2_pages_render(cfg):
    from fastapi.testclient import TestClient

    from daemonsight import db
    from daemonsight.web.app import create_app

    from .conftest import PASSWORD

    conn = db.connect_writer(cfg.db_path)
    ts = db.now()
    caddy = parse_config(adapter_json("portless_upstream"))
    caddy["upstream_status"] = [{"address": "app:80", "num_requests": 0, "fails": 1}]
    caddy["admin_address"] = "localhost:2019"
    db.put_snapshot(conn, "testhost", "caddy", ts, True, None, caddy)
    db.put_snapshot(conn, "testhost", "firewall", ts, True, None, summarize(RULESET))
    db.put_snapshot(conn, "testhost", "ports", ts, True, None, ports_data([
        listener(22, unit="ssh.service", process="sshd"), listener(3306, unit="mariadb.service")]))
    db.put_snapshot(conn, "testhost", "fail2ban", ts, True, None, {"version": "1.1.0", "jails": [{
        "name": "sshd", "backend": "systemd", "logpaths": [], "journalmatch": ["_SYSTEMD_UNIT=ssh.service"],
        "units": ["ssh.service"], "failed_now": 1, "failed_total": 9, "banned_now": 1, "banned_total": 4,
        "bans": [{"ip": "203.0.113.5", "banned_at": "2026-11-17 18:58:09", "seconds": -1, "until": None}],
        "bantime": -1, "findtime": 600, "maxretry": 5, "ignoreip": [], "actions": ["nftables"]}]})
    conn.close()

    c = TestClient(create_app(cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303

    html = c.get("/exposure").text
    assert "203.0.113.10" in html and "3306/tcp" in html
    assert "Blocked" in html and "inet filter input" in html
    assert c.get("/partials/exposure").text.startswith('<div id="live"')

    html = c.get("/routes").text
    assert "unix.example.com" in html and "app:80" in html and "1 recent failures" in html
    assert "localhost:2019" in html

    html = c.get("/fail2ban").text
    assert "sshd" in html and "permanent" in html and "203.0.113.5" in html
    assert "mariadb.service" in html  # public with no jail
    assert 'aria-current="page" href="/fail2ban"' in html

    html = c.get("/").text
    assert "Caddy sites" in html and "1 addresses banned now" in html


def test_caddy_same_host_two_servers_vars_root_and_conditions():
    # Shapes seen on a real VPS config (Caddy 2.x): one host on two servers, a
    # "root" directive (vars handler) read by a later file_server, and a
    # header_regexp route that only applies to some clients.
    def site(host_list, routes):
        return {"match": [{"host": host_list}], "terminal": True,
                "handle": [{"handler": "subroute", "routes": routes}]}
    cfg = {"apps": {"http": {"servers": {
        "srv0": {"listen": [":2083"], "routes": [site(["example.com"], [
            {"match": [{"path": ["/hook/*"]}], "handle": [{"handler": "static_response", "status_code": 301,
                                                          "headers": {"Location": ["https://elsewhere.example:2083"]}}]}])]},
        "srv1": {"listen": [":443"], "routes": [site(["example.com"], [
            {"group": "g1", "match": [{"path": ["/news/*"], "header_regexp": {"User-Agent": {"pattern": "bot"}}}],
             "handle": [{"handler": "subroute", "routes": [
                 {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:8011"}]}]}]}]},
            {"group": "g1", "handle": [{"handler": "subroute", "routes": [
                {"handle": [{"handler": "vars", "root": "/srv/site/dist"}]},
                {"match": [{"file": {"try_files": ["{http.request.uri.path}", "/index.html"]}}],
                 "handle": [{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}]},
                {"handle": [{"handler": "file_server"}]}]}]},
        ])]},
    }}}}
    sites = parse_config(cfg)["sites"]
    assert [(s["host"], s["listen"]) for s in sites] == [("example.com", [":2083"]), ("example.com", [":443"])]
    h = {x["kind"]: x for x in sites[1]["handlers"]}
    assert h["proxy"]["when"] == ["header_regexp"]
    assert h["files"]["root"] == "/srv/site/dist" and h["files"]["when"] == []


# ---- iptables-save (shape of a real nf_tables-backend VPS) -------------------

def vps_firewall():
    from daemonsight.collector.sources.firewall import parse_iptables_save, summarize_parts
    d = FIX / "iptables"
    return summarize_parts([parse_iptables_save((d / "vps-v4.txt").read_text(), "ip"),
                            parse_iptables_save((d / "vps-v6.txt").read_text(), "ip6")], "iptables-save")


def test_iptables_save_summary():
    fw = vps_firewall()
    v4 = [c for c in fw["input"] if c["family"] == "ip"][0]
    assert v4["policy"] == "accept" and v4["default"] == "accept"
    assert {(o["proto"], o["from"]) for o in v4["open"]} == {("tcp", 80), ("tcp", 443), ("tcp", 8000)}
    fwd = {f["proto"]: f for f in fw["forwards"]}
    assert fwd["tcp"]["ports"] == "all except 22,80,443,2083,8001" and fwd["tcp"]["copies"] == 2
    assert fwd["udp"]["ports"] == "all except 51820" and fwd["tcp"]["conditions"] == ["in ens6"]
    assert fw["duplicates"] == 5 and fw["odd_names"] == ["$1"]
    assert port_verdict(fw, "tcp", 3306)["state"] == "forwarded"
    assert port_verdict(fw, "tcp", 8001)["state"] == "unfiltered"
    assert port_verdict(fw, "tcp", 8001, "ip6")["state"] == "unfiltered"


def test_iptables_drop_policy_with_fail2ban_chains():
    from daemonsight.collector.sources.firewall import parse_iptables_save, summarize_parts
    text = "\n".join([
        "*filter", ":INPUT DROP [0:0]", ":f2b-sshd - [0:0]",
        "-A INPUT -i lo -j ACCEPT",
        "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd",
        "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A INPUT -s 10.0.0.0/8 -p tcp -m multiport --dports 8000:8999 -j ACCEPT",
        "-A f2b-sshd -s 203.0.113.9/32 -j REJECT --reject-with icmp-port-unreachable",
        "-A f2b-sshd -j RETURN", "COMMIT"])
    fw = summarize_parts([parse_iptables_save(text, "ip")], "iptables-save")
    assert fw["filtering"] and fw["duplicates"] == 0
    assert port_verdict(fw, "tcp", 22)["state"] == "open"
    assert port_verdict(fw, "tcp", 8443)["state"] == "restricted"
    assert port_verdict(fw, "tcp", 9000)["state"] == "blocked"


def test_vps_findings(cfg):
    snaps = {
        "firewall": snap("firewall", vps_firewall()),
        "ports": snap("ports", {"listeners": [
            listener(22, unit="ssh.service", process="sshd", addresses=("0.0.0.0", "::")),
            listener(8001, unit="ectlogger.service", process="uvicorn", addresses=("0.0.0.0",)),
            listener(3306, unit="mariadb.service", process="mariadbd", addresses=("0.0.0.0",)),
        ], "owners_known": True, "addresses": [
            {"nic": "ens6", "ip": "203.0.113.10", "scope": "public"},
            {"nic": "ens6", "ip": "2001:db8::10", "scope": "public"}]}),
    }
    fs = {(f.rule, f.key): f for f in findings.evaluate(snaps, cfg)}
    fwd = fs[("expose.forward_all", "ip tcp 10.99.0.2")]
    assert fwd.severity == "high" and fwd.title.startswith("All TCP ports except 22,80,443,2083,8001")
    assert ("expose.forward_all", "ip udp 10.99.0.2") in fs
    assert fs[("firewall.default_accept", "ip")].severity == "medium"
    assert "80, 443, 8000" in fs[("firewall.default_accept", "ip")].detail
    assert ("firewall.default_accept", "ip6") in fs
    assert "$1" in fs[("firewall.duplicate_rules", "dups")].detail
    # 8001 bypasses Caddy when bound to 0.0.0.0; 3306 is forwarded away, so not local exposure.
    assert fs[("expose.unexpected", "8001/tcp")].severity == "critical"
    assert ("expose.unexpected", "3306/tcp") not in fs
