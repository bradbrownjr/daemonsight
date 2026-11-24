"""Findings from what the hub has read from a UniFi Network controller.

Pure functions of the stored snapshots, like opnsense_rules.py: `evaluate` takes each source's latest data and returns the
findings that hold now; the poller makes the open `unifi.*` findings match. Links are paths on the host's own pages
(`/devices#dev-ab12`); the page code adds the `/h/<host>` prefix.

Thresholds, and where they come from:

* Offline: a device in the state OFFLINE, CONNECTION_INTERRUPTED or ISOLATED (the API's `state` enum, UniFi Network 11.0.97)
  for `offline_hours` or more, 2 by default, a setting (Settings, Remote systems). The API does not say how long: the
  hub counts from its first sight of the state, or from the device's last heartbeat when that is earlier
  (`GET .../statistics/latest`, `lastHeartbeatAt`). Own choice for the default (the owner's). A gateway or an access point
  is High, a switch or other device Medium.
* Firmware update: `firmwareUpdatable` is a flag. Low; Medium once the hub has seen it waiting for 30 days. Own choice.
  The API names no target version, so the finding cannot list the CVEs the update fixes (see CVE_NOTE).
* Open Wi-Fi: an enabled network with the security type OPEN and no hotspot portal. A hotspot portal (CAPTIVE_PORTAL or
  PASSPOINT) marks a guest network, the only guest marker the API has.
* Gateway: an enabled firewall policy that allows traffic from the External zone to another zone and is not one of
  UniFi's system-defined policies. The API lists no port forwards; this is the nearest thing it shows.

Where the "What to do" steps get their menu paths: UniFi Network's Devices page (Update Available, Pending Adoption:
https://help.ui.com/hc/en-us/articles/204910064 and /360012622613) and Settings, WiFi (/26136823938583, /23948850278295).
"""

from __future__ import annotations

import re

from ..findings import Finding, anchor, digest
from . import unifi

UPDATE_MEDIUM_DAYS = 30
LISTED = 12
DEFAULT_OFFLINE_HOURS = 2.0

CVE_NOTE = ("DaemonSight can't list the CVEs these updates fix. The UniFi API says only that an update exists, not which "
            "version it brings, and Ubiquiti publishes its security advisories as web pages with no feed or API to match "
            "against. Read the release notes (community.ui.com/releases) before you update.")


def steps(*lines: str) -> str:
    return "\n".join(lines)


def _hours(seconds: float) -> str:
    d = seconds / 86400
    return f"{d:.0f} days" if d >= 2 else f"{seconds / 3600:.0f} hours"


def _utc(ts: float) -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def dev_anchor(d: dict) -> str:
    return anchor("dev", d["id"][:12] or d["mac"])


def wifi_anchor(n: dict) -> str:
    return anchor("wifi", n["id"][:12] or n["name"])


HOWTO_UPDATE = steps(
    "In the UniFi Network app open Devices: a device with a firmware update shows Update Available",
    "Read the release notes first (community.ui.com/releases). DaemonSight cannot say which security fixes are in an update",
    "Update an access point or switch off hours: it restarts and drops what is connected to it. Update a gateway last, in a quiet window",
    "DaemonSight sends no update command; the API's upgrade action is a write and the key should not be able to do it",
    "If you are holding an update back on purpose, accept this finding with a note. It comes back when the set of waiting updates changes")
HOWTO_OFFLINE = steps(
    "Open Devices and find this device: check its power, its cable and its PoE port first",
    "A device that is on but shows Offline may have lost its path to the controller (a changed VLAN or inform address). Adoption: https://help.ui.com/hc/en-us/articles/360012622613",
    "If you removed the device on purpose, remove (forget) it in Devices so it stops being listed",
    "The finding goes away when the controller shows the device online again. If it is a spare that is off on purpose, accept this finding with a note")
HOWTO_PENDING = steps(
    "Open Devices: a device waiting for adoption shows Pending Adoption, with its model and address",
    "If you recognise it, adopt it. If you don't, find where it is plugged in: an unknown device on your network is worth a look",
    "To get rid of one you don't want, unplug it or block its port; DaemonSight cannot remove it",
    "If it is a device you are setting up later, accept this finding with a note")
HOWTO_OPEN = steps(
    "Open Settings, WiFi and edit this network",
    "Set its security protocol to WPA2 or WPA3 personal and a passphrase, or move it behind a Hotspot Portal if it is for guests",
    "If it is a deliberate open network (a public hotspot), accept this finding with a note saying why")
HOWTO_LEGACY = steps(
    "Open Settings, WiFi and edit this network",
    "WEP and original WPA are broken. Set its security protocol to WPA2 or WPA3 personal",
    "If an old device needs it, give that device its own network, and accept this finding with a note")
HOWTO_FORWARD = steps(
    "Open Settings, Policy Table (the zone-based firewall) and find this policy: it allows traffic from the External zone, the internet, into another zone",
    "Narrow it to the one service and the one destination that need it, or turn it off. A port forward made in UniFi may add a policy like this",
    "If it is intentional, accept this finding with a note. It comes back, as Changed, when the policy changes")


def firmware_rules(devices: dict | None, now: float) -> list[Finding]:
    waiting = [d for d in (devices or {}).get("devices", []) if d.get("updatable")]
    if not waiting:
        return []
    n = len(waiting)
    oldest = min((d.get("update_since") or now) for d in waiting)
    behind = now - oldest
    sev = "medium" if behind > UPDATE_MEDIUM_DAYS * 86400 else "low"
    names = sorted(f"{d['name']} ({d['model'] or 'device'}, {d['firmware'] or 'version unknown'})" for d in waiting)
    shown = ", ".join(names[:LISTED]) + (f" and {n - LISTED} more" if n > LISTED else "")
    detail = (f"The controller says {n} device{'s have' if n != 1 else ' has'} a firmware update waiting: {shown}."
              + (f" The hub has seen an update waiting for {_hours(behind)}." if behind > 3600 else "") + " " + CVE_NOTE)
    basis = digest(f"{d['id']}={d['firmware']}" for d in waiting)
    return [Finding("unifi.fw_update", "firmware", sev, f"{n} UniFi device{'s' if n != 1 else ''} with a firmware update waiting",
                    detail[:3900], "/devices#devices", None, basis, HOWTO_UPDATE)]


def offline_rules(devices: dict | None, now: float, offline_hours: float) -> list[Finding]:
    out = []
    for d in (devices or {}).get("devices", []):
        if d.get("state") not in unifi.DOWN_STATES:
            continue
        since = d.get("down_since") or now
        if now - since < offline_hours * 3600:
            continue
        kind = unifi.kind_of(d)
        sev = "high" if kind in ("gateway", "access point") else "medium"
        label = unifi.STATE_LABEL.get(d["state"], d["state"].title())
        out.append(Finding("unifi.device_offline", d["id"], sev, f"{d['name']} has been offline for {_hours(now - since)}",
                           f"The controller shows the {kind} {d['name']} ({d['model'] or 'model unknown'}, {d['ip'] or 'no address'}) as "
                           f"{label.lower()}. The hub has seen it that way since {_utc(since)}.",
                           "/devices#" + dev_anchor(d), None, f"{d['id']}:{d['state']}", HOWTO_OFFLINE))
    return out


def pending_rules(devices: dict | None) -> list[Finding]:
    out = []
    for p in (devices or {}).get("pending", []):
        key = p["mac"] or p["ip"]
        if not key:
            continue
        out.append(Finding("unifi.pending_adoption", key, "medium", f"{p['model'] or 'A device'} is waiting to be adopted",
                           f"A {p['model'] or 'UniFi device'} at {p['ip'] or 'an unknown address'} (MAC {p['mac'] or '?'}) is on the network and "
                           "asking to be adopted by this controller.", "/devices#pending", None, key, HOWTO_PENDING))
    return out


def wifi_rules(wifi: dict | None) -> list[Finding]:
    out = []
    for n in (wifi or {}).get("networks", []):
        if not n.get("enabled") or unifi.is_guest(n):
            continue
        link = "/wifi#" + wifi_anchor(n)
        if n["security"] == "OPEN":
            out.append(Finding("unifi.wifi_open", n["id"], "high", f"Wi-Fi network {n['name']} has no password",
                               f"The network {n['name']} is switched on with no security, and has no hotspot portal. Anyone in range can "
                               "join it and, unless it is isolated, reach what is on it.", link, None, f"{n['name']}:OPEN", HOWTO_OPEN))
        elif unifi.LEGACY_SECURITY.match(n["security"]):
            out.append(Finding("unifi.wifi_legacy", n["id"], "medium", f"Wi-Fi network {n['name']} uses {n['security_label']}",
                               f"The network {n['name']} reports the security type {n['security']}, which is older than WPA2.",
                               link, None, f"{n['name']}:{n['security']}", HOWTO_LEGACY))
    return out


def gateway_rules(gw: dict | None) -> list[Finding]:
    if not gw or not gw.get("present"):
        return []
    external = {z["id"] for z in gw.get("zones", []) if z["name"].strip().lower() == "external"}
    if not external:
        return []
    names = {z["id"]: z["name"] for z in gw.get("zones", [])}
    out = []
    for p in gw.get("policies", []):
        if not (p["enabled"] and p["action"] == "ALLOW" and p["source_zone"] in external
                and p["dest_zone"] and p["dest_zone"] not in external and p["origin"] != "SYSTEM_DEFINED"):
            continue
        dest = names.get(p["dest_zone"]) or "another zone"
        what = ("any port" if not p["dest_ports"] else "named ports") + (f" ({p['dest_filter'].lower().replace('_', ' ')} match)" if p["dest_filter"] else "")
        out.append(Finding("unifi.gateway_forward", p["id"], "medium", f"Firewall policy {p['name'] or p['id'][:8]} lets the internet in",
                           f"The enabled policy {p['name'] or p['id']} allows traffic from the External zone into {dest} ({what}). "
                           + (p["description"] + " " if p["description"] else "") +
                           "The UniFi API lists no port forwards, so this policy list is what DaemonSight can see of inbound access.",
                           "/devices#gateway", None, f"{p['name']}:{dest}:{p['dest_ports']}:{p['dest_filter']}", HOWTO_FORWARD))
    return out


def evaluate(inputs: dict[str, dict | None], now: float, offline_hours: float = DEFAULT_OFFLINE_HOURS) -> list[Finding]:
    """`inputs` maps info, devices, wifi and gateway to each source's latest data (None when it can't be read)."""
    dev = inputs.get("devices")
    return (firmware_rules(dev, now) + offline_rules(dev, now, offline_hours) + pending_rules(dev)
            + wifi_rules(inputs.get("wifi")) + gateway_rules(inputs.get("gateway")))
