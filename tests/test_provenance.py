"""Source panels: what each card and row says about where its data came from."""

import re

from daemonsight.config import Config
from daemonsight.web import provenance as prov


def values(panel, kind=None):
    return [e.get("value") or e.get("href") for e in panel["entries"] if kind is None or e["kind"] == kind]


def test_unit_panel_names_its_files():
    p = prov.unit({"name": "my app.service", "fragment": "/etc/systemd/system/my app.service",
                   "dropins": ["/etc/systemd/system/my app.service.d/override.conf"]})
    assert values(p, "file") == ["/etc/systemd/system/my app.service",
                                 "/etc/systemd/system/my app.service.d/override.conf"]
    assert "systemctl status 'my app.service'" in values(p, "cmd")


def test_container_panel_uses_compose_labels():
    p = prov.container({"name": "web", "project": "blog", "compose_dir": "/srv/blog",
                        "compose_files": ["/srv/blog/compose.yaml"]})
    assert values(p, "file") == ["/srv/blog", "/srv/blog/compose.yaml"]
    assert "docker compose -p blog ps" in values(p, "cmd")


def test_jail_panel_quotes_and_skips_or_marker():
    p = prov.jail({"name": "sshd", "logpaths": [{"path": "/var/log/auth.log", "exists": True}],
                   "journalmatch": ["_SYSTEMD_UNIT=ssh.service", "+", "_COMM=sshd"]})
    cmds = values(p, "cmd")
    assert "sudo grep -rln '^[[]sshd[]]' /etc/fail2ban/" in cmds
    assert "journalctl _SYSTEMD_UNIT=ssh.service _COMM=sshd -n 50 --no-pager" in cmds
    assert values(p, "file") == ["/var/log/auth.log"]


def test_caddy_commands_follow_admin_address():
    assert prov.caddy_curl("unix//run/caddy/admin.sock", "/config/") == \
        "curl -s --unix-socket /run/caddy/admin.sock http://localhost/config/"
    assert prov.caddy_curl("tcp/127.0.0.1:2019", "/config/") == "curl -s http://127.0.0.1:2019/config/"


def test_listener_links_to_its_owner():
    p = prov.listener({"port": 22, "proto": "tcp", "owner": {"kind": "unit", "id": "ssh.service"}, "pid": 812})
    assert "/services?units=all#unit-ssh.service" in values(p, "link")
    p = prov.listener({"port": 80, "proto": "tcp", "owner": {"kind": "container", "id": "abc123"}},
                      {"abc123": "web"})
    assert "/services#ctr-web" in values(p, "link")


def test_chain_commands_by_backend():
    assert values(prov.chain({"family": "ip", "table": "filter", "chain": "INPUT"}))[0] == \
        "sudo iptables -t filter -S INPUT"
    assert values(prov.chain({"family": "inet", "table": "filter", "chain": "input"}))[0] == \
        "sudo nft list chain inet filter input"


def test_web_ui_links_from_config_are_http_only():
    cfg = Config()
    cfg.links = {"caddy": "https://router.example/ui/caddy", "fail2ban": "javascript:alert(1)"}
    assert values(prov.section("caddy", cfg), "url") == ["https://router.example/ui/caddy"]
    assert values(prov.section("fail2ban", cfg), "url") == []


def check_panels(html: str) -> int:
    """Every button opens a panel that exists, and no panel id repeats."""
    ids = re.findall(r'<div popover id="([^"]+)"', html)
    assert len(ids) == len(set(ids)), "duplicate panel id"
    for target in set(re.findall(r'class="ds-src-btn" popovertarget="([^"]+)"', html)):
        assert target in ids, target
    return len(ids)


def test_findings_link_to_their_row():
    """A finding's link names a row id that the page renders."""
    from daemonsight.findings import anchor
    assert anchor("port", 2083, "tcp") == "port-2083-tcp"
    assert anchor("site", "a.example.com, b.example.com") == "site-a.example.com_b.example.com"
    assert anchor("fwd", "ip", "tcp", "10.0.0.2:80") == "fwd-ip-tcp-10.0.0.2_80"


def _caddy(n_sites=2):
    return {"servers": [{"name": "srv0", "listen": [":443", "udp/:443"]},
                        {"name": "srv1", "listen": ["[::]:2083"]}],
            "sites": [{"host": f"h{i}.example.com", "server": "srv0"} for i in range(n_sites)]
                     + [{"host": "panel.example.com", "server": "srv1"}]}


def _caddy_row(**kw):
    return {"proto": "tcp", "port": 443, "pid": 5, "process": "caddy",
            "owner": {"kind": "unit", "id": "caddy.service"}, **kw}


def test_listener_process_details():
    import time
    p = prov.listener(_caddy_row(cmdline="caddy run --config /etc/caddy/Caddyfile", exe="/usr/bin/caddy",
                                 user="caddy", started=time.time() - 3 * 86400))
    by = {e["label"]: e for e in p["entries"]}
    assert by["Command"]["kind"] == "text" and by["Command"]["value"].startswith("caddy run")
    assert by["Program"]["kind"] == "file" and by["Runs as"]["value"] == "caddy"
    assert "ago" in by["Started"]["value"] and "Process" in by
    bare = prov.listener({"proto": "tcp", "port": 1, "pid": None, "owner": {"kind": "unknown", "id": None}})
    assert not {"Command", "Program", "Runs as", "Started"} & {e["label"] for e in bare["entries"]}


def test_listener_caddy_sites_link_to_routes_rows():
    p = prov.listener(_caddy_row(), caddy=_caddy())
    links = [(e["href"], e["text"]) for e in p["entries"] if e["label"] == "Caddy site"]
    assert links == [("/routes#site-h0.example.com", "h0.example.com"),
                     ("/routes#site-h1.example.com", "h1.example.com")]
    udp = prov.listener(_caddy_row(proto="udp"), caddy=_caddy())
    assert len([e for e in udp["entries"] if e["label"] == "Caddy site"]) == 2
    other = prov.listener(_caddy_row(port=2083), caddy=_caddy())
    assert [e["text"] for e in other["entries"] if e["label"] == "Caddy site"] == ["panel.example.com"]
    assert not [e for e in prov.listener(_caddy_row(port=80), caddy=_caddy())["entries"] if "Caddy" in e["label"]]
    not_caddy = _caddy_row(process="nginx", owner={"kind": "unknown", "id": None})
    assert not [e for e in prov.listener(not_caddy, caddy=_caddy())["entries"] if "Caddy" in e["label"]]


def test_listener_caddy_sites_capped():
    p = prov.listener(_caddy_row(), caddy=_caddy(12))
    assert len([e for e in p["entries"] if e["label"] == "Caddy site"]) == 8
    more = [e for e in p["entries"] if e["label"] == "More Caddy sites"]
    assert more and more[0]["href"] == "/routes"
