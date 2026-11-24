"""The sections of each page, for the jump menu beside each nav tab (base.html, app.js).

SECTIONS maps a host kind to {page key: [(anchor id, label), ...]}. The page keys are the nav tab keys in
base.html. Kind "" is a host the collector reports on; "hub" holds the Hosts page. An anchor is the id of an
element that every render of that page has (a card that is empty still renders), so a menu item never links to
nothing; tests/test_sections.py checks each one against the rendered pages. A page with fewer than two sections
gets no menu (except Hosts, whose menu also lists the hosts).
"""

SECTIONS: dict[str, dict[str, list[tuple[str, str]]]] = {
    "": {
        "overview": [("findings", "Findings"), ("glance", "At a glance"), ("events", "Recent changes")],
        "exposure": [("listeners", "Listeners not on loopback"), ("firewall", "Firewall input chains"),
                     ("forwards", "Port forwards"), ("outside", "Seen from outside"),
                     ("docker-published", "Docker published ports")],
        "services": [("containers", "Containers"), ("units", "systemd services"), ("ports", "Listening sockets")],
        "packages": [("security", "Security updates"), ("other", "Other updates"), ("held", "Held packages"),
                     ("reboot", "Reboot and restarts"), ("auto", "Automatic updates"), ("lists", "Package lists")],
        "vulnerabilities": [("summary", "This host"), ("packages", "Packages"), ("feeds", "Data feeds")],
        "fail2ban": [("jails", "Jails"), ("coverage", "Public services and their jails"), ("bans", "Banned now")],
        "report": [("steps", "Steps"), ("decide", "Decide"), ("all", "All findings"), ("accepted", "Accepted")],
    },
    "unraid": {
        "overview": [("findings", "Findings"), ("glance", "At a glance"), ("events", "Recent changes")],
        "disks": [("array", "Array"), ("disks", "Disks")],
        "docker": [("images", "Unused images"), ("volumes", "Unused volumes"), ("cache", "Build cache")],
        "images": [("image-list", "Images"), ("image-coverage", "What is checked")],
        "report": [("steps", "Steps"), ("decide", "Decide"), ("all", "All findings"), ("accepted", "Accepted")],
    },
    "opnsense": {
        "overview": [("findings", "Findings"), ("glance", "At a glance"), ("events", "Recent changes")],
        "firewall": [("rules", "Pass rules"), ("forwards", "Port forwards"), ("caddy", "Caddy sites"),
                    ("crowdsec", "CrowdSec")],
        "vpn": [("wireguard", "WireGuard"), ("tailscale", "Tailscale")],
        "network": [("gateways", "Gateways"), ("interfaces", "Interfaces and their roles"), ("services", "Services")],
        "report": [("steps", "Steps"), ("decide", "Decide"), ("all", "All findings"), ("accepted", "Accepted")],
    },
    "unifi": {
        "overview": [("findings", "Findings"), ("updates", "Firmware updates"), ("glance", "At a glance"), ("events", "Recent changes")],
        "devices": [("controller", "Controller"), ("devices", "Devices"), ("pending", "Waiting for adoption"),
                    ("gateway", "Gateway firewall")],
        "report": [("steps", "Steps"), ("decide", "Decide"), ("all", "All findings"), ("accepted", "Accepted")],
    },
    # Hosts' menu is the hosts themselves, then "Recent hub changes" (base.html builds it from menu_hosts); the
    # registry holds the fixed tail only, as the fallback when no host list is passed.
    "hub": {
        "hosts": [("hub-events", "Recent hub changes")],
    },
}


def for_host(kind: str | None) -> dict[str, list[tuple[str, str]]]:
    """The jump menus for a host of this kind (None or "" for a collector host), plus the hub's Hosts page."""
    return {**SECTIONS.get(kind or "", SECTIONS[""]), **SECTIONS["hub"]}
