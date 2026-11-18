"""Interface roles for a firewall the hub reads: which networks face the internet.

A rule such as "a pass rule on an internet-facing interface" must not depend on the interface being called "wan".
Each interface gets one of four roles, worked out from what the firewall reports about it, and the owner can
override any of them per system (stored hub-side, in the `meta` table).

* `wan`    untrusted, internet-facing: has an upstream gateway, or is named WAN
* `lan`    trusted: a network the firewall serves, with an address and no upstream gateway
* `vpn`    a tunnel (WireGuard, OpenVPN, Tailscale, IPsec ...)
* `other`  loopback, unassigned, or anything that fits none of the above

This module knows nothing about OPNsense. A source turns what its firewall reports into the normalised interface
dicts below, so the same checks can be used for another product (a FortiGate, say) later.

Normalised interface (what `classify` reads):
    id            the firewall's own identifier for it ("wan", "opt1"); rules refer to this
    name          the label the owner sees ("WAN", "44Connect")
    device        the device name ("re0", "wg0", "tailscale0")
    gateways      upstream gateway addresses attached to the interface (list, may be empty)
    addresses     the interface's own addresses (list of strings, may be empty)
    assigned      False for a device the firewall lists but has not assigned an interface to
"""

from __future__ import annotations

import json
import re

from .. import db

ROLES = ("wan", "lan", "vpn", "other")
ROLE_LABEL = {"wan": "WAN (internet-facing)", "lan": "LAN (trusted)", "vpn": "VPN", "other": "Other"}
# Internet-facing is a fact, not a fault, so it is yellow, not red; red stays for findings.
ROLE_BADGE = {"wan": "bg-yellow-lt", "lan": "bg-green-lt", "vpn": "bg-azure-lt", "other": "bg-secondary-lt"}
# Beside an interface's own name, where "WAN (internet-facing)" would repeat it.
ROLE_SHORT = {"wan": "internet-facing", "lan": "trusted", "vpn": "VPN", "other": "other"}

# Device-name prefixes of tunnels (FreeBSD and Linux names). A tunnel's "gateway" is the far end of the tunnel, not
# a provider, so a tunnel is a VPN even when a gateway is attached.
VPN_PREFIXES = ("wg", "tun", "tap", "ovpn", "ipsec", "tailscale", "ts", "gif", "gre", "zt", "ppp", "vti")
LOOPBACK_PREFIXES = ("lo", "enc", "pflog", "pfsync")
_NAMED_WAN = re.compile(r"(?<![a-z0-9])wan\d*(?![a-z0-9])", re.I)
_DIGITS = re.compile(r"\d+$")


def device_kind(device: str) -> str:
    base = _DIGITS.sub("", (device or "").lower())
    if base in VPN_PREFIXES:
        return "vpn"
    if base in LOOPBACK_PREFIXES:
        return "loopback"
    return "physical"


def classify(iface: dict) -> tuple[str, str]:
    """(role, why) for a normalised interface, before any override. `why` is a short sentence for the page."""
    kind = device_kind(iface.get("device") or "")
    if kind == "loopback":
        return "other", "loopback or internal device"
    if kind == "vpn":
        return "vpn", f"tunnel device {iface.get('device')}"
    gws = [g for g in (iface.get("gateways") or []) if g]
    named = any(_NAMED_WAN.search(str(iface.get(k) or "")) for k in ("id", "name"))
    if named:
        return "wan", "named WAN" + (f", with upstream gateway {gws[0]}" if gws else "")
    if gws:
        return "wan", f"has an upstream gateway ({gws[0]})"
    if iface.get("assigned") is False:
        return "other", "no interface assigned to this device"
    if iface.get("addresses"):
        return "lan", "has an address and no upstream gateway"
    return "other", "no address"


def assign(ifaces: list[dict], overrides: dict | None = None) -> dict[str, dict]:
    """Roles for every interface, keyed by its id: {"role", "auto", "why", "overridden"}. An override names a role
    for an id; a value that is not a role, or an id the firewall no longer has, is ignored."""
    overrides = overrides or {}
    out: dict[str, dict] = {}
    for i in ifaces:
        key = str(i.get("id") or "")
        if not key:
            continue
        auto, why = classify(i)
        forced = overrides.get(key)
        overridden = forced in ROLES and forced != auto
        out[key] = {"role": forced if overridden else auto, "auto": auto, "why": "set by you" if overridden else why,
                    "overridden": overridden, "name": i.get("name") or key, "device": i.get("device") or ""}
    return out


def internet_facing(role: str | None) -> bool:
    """Rules about "internet-facing" things ask this, never the interface's name."""
    return role == "wan"


def lookup(roles: dict[str, dict]) -> dict[str, str]:
    """Names a rule may use for an interface -> its id: the id itself and the label, lower-cased. (A classic rule
    names its interface by label, a newer one by id.)"""
    out: dict[str, str] = {}
    for key, r in roles.items():
        out[key.lower()] = key
        out.setdefault(str(r.get("name") or "").lower(), key)
    return out


def rule_roles(interface: str | None, roles: dict[str, dict]) -> list[str]:
    """The roles of the interfaces a rule is bound to (`interface` is a comma list of ids or labels; empty means
    every interface, which is a floating rule and is not answered here). Names not recognised (a group) give no role."""
    names = lookup(roles)
    out = []
    for part in str(interface or "").split(","):
        key = names.get(part.strip().lower())
        if key:
            out.append(roles[key]["role"])
    return out


# --- overrides, stored by the hub -------------------------------------------------------------

def _meta_key(host: str) -> str:
    return f"roles:{host}"


def load_overrides(conn, host: str) -> dict[str, str]:
    raw = db.get_meta(conn, _meta_key(host))
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return {str(k): v for k, v in data.items() if isinstance(data, dict) and v in ROLES} if isinstance(data, dict) else {}


def save_overrides(conn, host: str, overrides: dict[str, str]) -> None:
    clean = {str(k)[:60]: v for k, v in overrides.items() if v in ROLES}
    db.set_meta(conn, {_meta_key(host): json.dumps(clean, sort_keys=True)})


def delete_overrides(conn, host: str) -> None:
    conn.execute("DELETE FROM meta WHERE key = ?", (_meta_key(host),))
