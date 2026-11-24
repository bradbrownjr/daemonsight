"""A Caddy site or handler behind an access list that allows only private addresses is not reached from the internet.

Live 2026-11-24: six Unraid images were rated Critical as "reached from the internet through Caddy site ..." while those
sites (lidarr, radarr, sabnzbd, sonarr, tts, mawline) carried the firewall's "LAN Only" access list."""
import pytest

from daemonsight.remote import opnsense_rules as rules

LAN_ONLY = {"name": "LAN Only", "ips": ["10.6.26.0/24", "100.64.0.0/10", "10.6.27.0/24"], "invert": False}
# Documentation ranges (203.0.113.0/24 ...) are not globally routable, so these use public resolver addresses.
ONE_PUBLIC = {"name": "Uploads", "ips": ["9.9.9.9/32"], "invert": False}
MIXED = {"name": "Mixed", "ips": ["192.168.1.0/24", "8.8.8.0/24"], "invert": False}
INVERTED = {"name": "Not LAN", "ips": ["10.0.0.0/8"], "invert": True}
ACLS = {a["name"]: a for a in (LAN_ONLY, ONE_PUBLIC, MIXED, INVERTED)}


@pytest.mark.parametrize("names, want", [
    (["LAN Only"], True), (["Uploads"], False), (["Mixed"], False), (["Not LAN"], False), (["Missing"], False), ([], False),
    (["Uploads", "LAN Only"], True)])                                    # Caddy applies every list, so one LAN-only list is enough
def test_which_access_lists_keep_the_internet_out(names, want):
    assert rules._lan_only(names, ACLS) is want


def site(domain, acl=(), handle_acl=(), basic_auth=False):
    return {"enabled": True, "domain": domain, "port": "", "tls": True, "acl": list(acl), "basic_auth": basic_auth,
            "handles": [{"enabled": True, "kind": "reverse_proxy", "to": ["10.6.26.2"], "port": "8001", "scheme": "http",
                         "acl": list(handle_acl), "basic_auth": False, "forward_auth": False}]}


def test_reach_into_leaves_out_sites_and_handlers_behind_a_lan_only_list(monkeypatch):
    monkeypatch.setattr(rules, "open_ports", lambda r, roles: {80, 443})
    data = {"nat": {"forwards": []}, "rules": {"x": 1},
            "caddy": {"acls": list(ACLS.values()), "global_acl": [],
                      "sites": [site("open.example.com"), site("lan.example.com", acl=["LAN Only"]),
                                site("handler.example.com", handle_acl=["LAN Only"]), site("pw.example.com", basic_auth=True),
                                site("vps.example.com", acl=["Uploads"])]}}
    got = sorted(e["name"] for e in rules.reach_into(data, {}, {"10.6.26.2"}))
    # A password still leaves the site reachable; a list that allows a public address is public.
    assert got == ["open.example.com", "pw.example.com", "vps.example.com"]


def test_a_lan_only_global_list_covers_every_site(monkeypatch):
    monkeypatch.setattr(rules, "open_ports", lambda r, roles: {80, 443})
    data = {"nat": {"forwards": []}, "rules": {"x": 1},
            "caddy": {"acls": [LAN_ONLY], "global_acl": ["LAN Only"], "sites": [site("open.example.com")]}}
    assert rules.reach_into(data, {}, {"10.6.26.2"}) == []
