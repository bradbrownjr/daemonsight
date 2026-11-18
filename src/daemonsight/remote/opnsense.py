"""The OPNsense REST API: which endpoints the hub reads, what is kept from each reply, and the connection test.

Everything here is a GET. The endpoints were checked against OPNsense's source (github.com/opnsense/core and
github.com/opnsense/plugins, controllers and `ACL.xml`) and run against a real firewall (26.7.9_3, with os-caddy and
os-tailscale), read-only; the findings are in docs/DESIGN.md, "OPNsense". Auth is HTTP basic with the API key as the
user name and the secret as the password (https://docs.opnsense.org/development/how-tos/api.html). A reply is JSON;
the client sends no Content-Type header, because OPNsense answers an empty body that claims to be JSON with 400
"Invalid JSON syntax" (core `ApiControllerBase::parseJsonBodyData`).

OPNsense has no "read-only" privilege: a privilege covers a whole page, read and write alike (`ACL.xml` patterns such
as `api/firewall/d_nat/*`). Read-only is therefore enforced here: `client.Rest` sends GET only and only to `PATHS`.
A source whose privilege is missing answers 403 (`{"status": 403, "message": "Forbidden"}`, core
`ApiControllerBase::beforeExecuteRoute`); that source shows "needs privilege X" and the others carry on.

Some replies hold secrets the hub must not keep. `caddy/reverse_proxy/get` returns the whole Caddy model,
including the DNS provider API key and the ACME e-mail; `wireguard/service/show` returns public keys. The parsers
below copy named fields and nothing else.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass, field

from . import roles
from .client import Net, RemoteError, Rest, scrub
from .unraid import num, text

# --- the endpoints ---------------------------------------------------------------------------------------------

PATHS = {
    "firmware": "/api/core/firmware/status",
    "gateways": "/api/routes/gateway/status",
    "wireguard": "/api/wireguard/service/show",
    "interfaces": "/api/interfaces/overview/export",
    "services": "/api/core/service/search",
    "rules": "/api/firewall/filter/search_rule",
    "nat": "/api/firewall/d_nat/search_rule",
    "caddy": "/api/caddy/reverse_proxy/get",
    "caddy_status": "/api/caddy/service/status",
    "tailscale": "/api/tailscale/status/status",
    "tailscale_settings": "/api/tailscale/settings/get",
    "resources": "/api/diagnostics/system/system_resources",
    "disk": "/api/diagnostics/system/system_disk",
    "temperature": "/api/diagnostics/system/system_temperature",
}
ALLOWED = frozenset(PATHS.values())

FAST, SLOW = "fast", "slow"
SLOW_SECONDS = 300
ROWS_MAX = 1500


@dataclass(frozen=True)
class Source:
    name: str                  # the snapshot name
    title: str
    privilege: str             # the OPNsense privilege that grants every path below (its ACL.xml <name>)
    paths: tuple[str, ...]     # keys of PATHS
    tier: str
    menu: str                  # where the owner finds the same thing in the OPNsense UI
    optional: bool = False     # not reading it is not a problem with the firewall (a plugin that isn't installed)


SOURCES: dict[str, Source] = {s.name: s for s in (
    Source("opnsense_system", "Resources", "Lobby: Dashboard", ("resources", "disk", "temperature"), FAST,
           "Lobby, Dashboard (the System Information and Disk widgets)"),
    Source("opnsense_interfaces", "Interfaces", "Status: Interfaces", ("interfaces",), FAST, "Interfaces, Overview"),
    Source("opnsense_gateways", "Gateways", "System: Gateways", ("gateways",), FAST, "System, Gateways, Configuration"),
    Source("opnsense_wireguard", "WireGuard", "VPN: WireGuard: Status", ("wireguard",), FAST, "VPN, WireGuard, Status"),
    Source("opnsense_services", "Services", "Status: Services", ("services",), FAST, "System, Diagnostics, Services"),
    Source("opnsense_tailscale", "Tailscale", "Tailscale", ("tailscale", "tailscale_settings"), FAST,
           "VPN, Tailscale, Status and Settings", optional=True),
    Source("opnsense_firmware", "Firmware", "System: Firmware", ("firmware",), SLOW, "System, Firmware, Status"),
    Source("opnsense_rules", "Firewall rules", "Firewall: Rules [new]", ("rules",), SLOW, "Firewall, Rules [new]"),
    Source("opnsense_nat", "Port forwards", "Firewall: NAT: Destination NAT", ("nat",), SLOW,
           "Firewall, NAT, Destination NAT"),
    Source("opnsense_caddy", "Caddy sites", "Services: Caddy", ("caddy", "caddy_status"), SLOW,
           "Services, Caddy Web Server, Reverse Proxy", optional=True),
)}

# The plugin sources: a firewall without os-caddy or os-tailscale answers 404 for them, which is "not installed".
OPTIONAL = frozenset(n for n, s in SOURCES.items() if s.optional)
ALL_PRIVILEGES = tuple(dict.fromkeys(s.privilege for s in SOURCES.values()))
SNAPSHOT_PREFIX = "opnsense_"


# The page in OPNsense's own web UI for each source (core and plugin `Menu.xml` files), to open from a panel.
UI_PATH = {
    "opnsense_system": "/ui/core/dashboard", "opnsense_interfaces": "/ui/interfaces/overview",
    "opnsense_gateways": "/ui/routing/configuration", "opnsense_wireguard": "/ui/wireguard/diagnostics/",
    "opnsense_services": "/ui/core/service", "opnsense_tailscale": "/ui/tailscale/status",
    "opnsense_firmware": "/ui/core/firmware#status", "opnsense_rules": "/ui/firewall/filter",
    "opnsense_nat": "/ui/firewall/d_nat", "opnsense_caddy": "/ui/caddy/reverse_proxy",
}


def due(now: float, taken_at: float | None, tier: str, interval: int) -> bool:
    gap = interval if tier == FAST else max(SLOW_SECONDS, interval)
    return taken_at is None or now - taken_at >= gap - 1


# --- helpers ---------------------------------------------------------------------------------------------------

_TAG = re.compile(r"<[^>]*>")


def _rows(d) -> list[dict]:
    rows = d.get("rows") if isinstance(d, dict) else None
    return [r for r in (rows or []) if isinstance(r, dict)][:ROWS_MAX]


def _vals(x) -> list:
    """PHP gives an empty map as [] and a filled one as an object."""
    if isinstance(x, dict):
        return list(x.values())
    return list(x) if isinstance(x, list) else []


def _items(x):
    return list(x.items()) if isinstance(x, dict) else []


def _flag(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes")


def _pct(v) -> float | None:
    m = re.match(r"^\s*(-?[0-9.]+)\s*%", str(v or ""))
    return float(m.group(1)) if m else None


def _ms(v) -> float | None:
    m = re.match(r"^\s*(-?[0-9.]+)\s*ms", str(v or ""))
    return float(m.group(1)) if m else None


def selected(v) -> list[str]:
    """The chosen values of an OPNsense model field. A text field is its own value; a choice field is a map (or a
    list) of options each carrying `selected`."""
    if isinstance(v, dict):
        return [str(k) for k, x in v.items() if isinstance(x, dict) and _flag(x.get("selected"))]
    if isinstance(v, list):
        return [str(x.get("value")) for x in v if isinstance(x, dict) and _flag(x.get("selected"))]
    return [str(v)] if v not in ("", None) else []


def _clean_selected(v) -> list[str]:
    return [x for x in selected(v) if x != ""]


def alias_values(meta, raw: str) -> tuple[list[str], bool]:
    """What an address or port field stands for: ([values], complete). `meta` is the row's `alias_meta_<field>`,
    which holds the alias's own summary ("192.168.1.2", or "<strong>note</strong><br/>192.168.1.8"). A field that is
    not an alias is its own value. An alias summary that OPNsense shortened is incomplete."""
    raw = text(raw, 200)
    if not raw:
        return [], True
    items = [m for m in (meta or []) if isinstance(m, dict)]
    out: list[str] = []
    complete = True
    if not items:
        return [p.strip() for p in raw.split(",") if p.strip()], True
    for m in items:
        if not m.get("isAlias"):
            out.append(text(m.get("value"), 120))
            continue
        summary = str(m.get("summary") or "")
        summary = _TAG.sub(" ", summary.split("<br/>")[-1] if "<br/>" in summary else summary)
        if "..." in summary or "…" in summary:
            complete = False
        out += [t.strip(" ,") for t in re.split(r"[,\s]+", summary.replace("...", " ").replace("…", " ")) if t.strip(" ,")]
    return [v for v in out if v], complete


def ips_of(values: list[str]) -> list[str]:
    """The single addresses among `values` (a /32 or /128 counts; a network or a name does not)."""
    out = []
    for v in values:
        base, _, bits = v.partition("/")
        try:
            ip = ipaddress.ip_address(base)
        except ValueError:
            continue
        if not bits or int(bits or 0) == (32 if ip.version == 4 else 128):
            out.append(str(ip))
    return out


def ports_of(values: list[str]) -> list[int] | None:
    """The single port numbers among `values`; None when one of them is a range (a range is not a list of ports
    to check)."""
    out: list[int] = []
    for v in values:
        if v.isdigit() and 0 < int(v) < 65536:
            out.append(int(v))
        else:
            return None
    return out


# --- parsers ---------------------------------------------------------------------------------------------------

def _version_base(v: str) -> str:
    """OPNsense's own reduction of a version for comparing it with the changelog (Diagnostics SystemController,
    `systemInformationAction`): cut at ".0", "p", "_" or "-"."""
    return re.split(r"\.0|[p_-]", v or "")[0]


def parse_firmware(d: dict) -> dict:
    prod = d.get("product") if isinstance(d.get("product"), dict) else {}
    version = text(prod.get("product_version") or d.get("product_version"), 40)
    latest = text(prod.get("product_latest"), 40)
    major = text(d.get("upgrade_major_version"), 40)

    def listing(x, cap=200):
        out = []
        for p in _vals(x)[:cap]:
            if isinstance(p, dict):
                out.append({"name": text(p.get("name"), 80), "old": text(p.get("old"), 60), "new": text(p.get("new"), 60),
                            "reason": text(p.get("reason"), 20)})
        return out

    packages, sets = listing(d.get("all_packages")), listing(d.get("all_sets"))
    status = text(d.get("status"), 20)
    new = latest if latest and latest != _version_base(version) else major
    if not new:
        new = next((p["new"] for p in sets + packages if p["name"] in ("opnsense", "opnsense-devel") and p["new"]), "")
    return {
        "version": version, "latest": latest, "new_version": new, "status": status,
        "message": text(d.get("status_msg"), 200), "packages": packages, "sets": sets,
        "count": len(packages) + (0 if packages else len(sets)), "count_packages": len(packages), "count_sets": len(sets),
        "needs_reboot": _flag(d.get("status_reboot")) or (status in ("update", "upgrade") and _flag(d.get("needs_reboot"))),
        "last_check": text((d.get("last_check") or (d.get("product_check") or {}).get("last_check")), 60),
        "major": major, "name": text(prod.get("product_name"), 40) or "OPNsense", "series": text(prod.get("product_series"), 20),
        "os": text(d.get("os_version"), 60),
        "connection": text(d.get("connection"), 20), "repository": text(d.get("repository"), 20),
        "pending_since": None,     # the poller fills this in: when updates were first seen waiting
    }


def parse_gateways(d: dict) -> dict:
    out = []
    for g in [x for x in (d.get("items") or []) if isinstance(x, dict)][:40]:
        out.append({"name": text(g.get("name"), 60), "address": text(g.get("address"), 60), "status": text(g.get("status"), 20).lower(),
                    "status_text": text(g.get("status_translated"), 40), "loss": _pct(g.get("loss")),
                    "delay": _ms(g.get("delay")), "stddev": _ms(g.get("stddev")), "monitor": text(g.get("monitor"), 60)})
    return {"gateways": out}


def parse_interfaces(d) -> dict:
    out = []
    for e in [x for x in (d if isinstance(d, list) else []) if isinstance(x, dict)][:120]:
        ident, device = text(e.get("identifier"), 30), text(e.get("device"), 30)
        if not ident:
            # A device nobody assigned an interface to (enc0, pflog0): only a tunnel is worth listing.
            if roles.device_kind(device) != "vpn":
                continue
        addrs = [a for a in (text(e.get("addr4"), 60), text(e.get("addr6"), 80)) if a]
        for v in (e.get("ipv4") or []):
            if isinstance(v, dict) and v.get("ipaddr"):
                a = text(v["ipaddr"], 60)
                if a not in addrs and not any(x.split("/")[0] == a for x in addrs):
                    addrs.append(a)
        cfg = e.get("config") if isinstance(e.get("config"), dict) else {}
        out.append({"id": ident, "name": text(e.get("description"), 60) or ident or device, "device": device,
                    "assigned": bool(ident), "enabled": bool(e.get("enabled")), "status": text(e.get("status"), 20),
                    "addresses": addrs[:8], "gateways": [text(g, 60) for g in (e.get("gateways") or [])][:6],
                    "link_type": text(e.get("link_type"), 20), "vlan": num(e.get("vlan_tag")),
                    "blocks_private": _flag(cfg.get("blockpriv")), "blocks_bogons": _flag(cfg.get("blockbogons"))})
    return {"interfaces": out}


def parse_wireguard(d: dict) -> dict:
    """Instances and their peers, from `wg show` as OPNsense reports it. A peer that was unlinked from its instance
    is simply absent: an instance with no peer records is how that shows. Public keys are cut to eight characters
    (enough to tell two unnamed peers apart); nothing else secret is in the reply."""
    inst: dict[str, dict] = {}
    for r in _rows(d):
        iface = text(r.get("if"), 20)
        if not iface:
            continue
        cur = inst.setdefault(iface, {"if": iface, "name": "", "status": "", "port": None, "peers": []})
        if r.get("type") == "interface":
            cur.update(name=text(r.get("name") or r.get("ifname"), 60), status=text(r.get("status"), 12),
                       port=num(r.get("listen-port")))
        elif r.get("type") == "peer" and len(cur["peers"]) < 100:
            hs = num(r.get("latest-handshake"))
            cur["peers"].append({"name": text(r.get("name"), 60), "key": text(r.get("public-key"), 8),
                                 "endpoint": text(r.get("endpoint"), 80), "allowed": text(r.get("allowed-ips"), 200),
                                 "handshake": hs if hs else None, "rx": num(r.get("transfer-rx")),
                                 "tx": num(r.get("transfer-tx")), "keepalive": text(r.get("persistent-keepalive"), 10)})
            if not cur["name"]:
                cur["name"] = text(r.get("ifname"), 60)
    return {"instances": sorted(inst.values(), key=lambda i: i["if"])}


def parse_services(d: dict) -> dict:
    out = [{"id": text(r.get("id"), 80), "name": text(r.get("name"), 60), "description": text(r.get("description"), 100),
            "running": _flag(r.get("running")), "locked": _flag(r.get("locked"))} for r in _rows(d)]
    return {"services": out}


def _rule(r: dict) -> dict:
    return {"uuid": text(r.get("uuid"), 60), "legacy": bool(r.get("legacy")), "enabled": _flag(r.get("enabled")),
            "action": text(r.get("action"), 10).lower(), "interface": text(r.get("interface"), 80),
            "interface_not": _flag(r.get("interfacenot")), "direction": text(r.get("direction"), 6).lower(),
            "protocol": text(r.get("protocol"), 20).lower(), "ipprotocol": text(r.get("ipprotocol"), 8),
            "source": text(r.get("source_net"), 120), "source_port": text(r.get("source_port"), 60),
            "destination": text(r.get("destination_net"), 120), "destination_port": text(r.get("destination_port"), 60),
            "description": text(r.get("description") or r.get("descr"), 200), "sequence": text(r.get("sequence"), 12),
            "quick": _flag(r.get("quick")), "log": _flag(r.get("log"))}


def parse_rules(d: dict) -> dict:
    """The firewall's own rules. `search_rule` also returns classic rules from before the migration (`legacy`) and
    the rules OPNsense generates itself (`is_automatic`: anti-lockout, default deny, IPv6 housekeeping); the
    generated ones are counted and left out."""
    rows = _rows(d)
    rules = [_rule(r) for r in rows if not r.get("is_automatic")]
    return {"rules": rules, "automatic": sum(1 for r in rows if r.get("is_automatic")),
            "legacy": sum(1 for r in rules if r["legacy"]), "total": num(d.get("total")) or len(rows)}


def parse_nat(d: dict) -> dict:
    out = []
    automatic = 0
    for r in _rows(d):
        if r.get("is_automatic"):
            automatic += 1
            continue
        tvals, t_ok = alias_values(r.get("alias_meta_target"), r.get("target"))
        dvals, d_ok = alias_values(r.get("alias_meta_destination.port"), r.get("destination.port"))
        lvals, l_ok = alias_values(r.get("alias_meta_local-port"), r.get("local-port"))
        out.append({"uuid": text(r.get("uuid"), 60), "enabled": not _flag(r.get("disabled")), "no_redirect": _flag(r.get("nordr")),
                    "interface": text(r.get("interface"), 80), "protocol": text(r.get("protocol"), 20).lower(),
                    "source": text(r.get("source.network"), 120), "destination": text(r.get("destination.network"), 120),
                    "destination_port": text(r.get("destination.port"), 60), "target": text(r.get("target"), 120),
                    "target_ips": ips_of(tvals)[:20], "target_known": t_ok,
                    "local_port": text(r.get("local-port"), 60), "local_ports": ports_of(lvals) if l_ok else None,
                    "dest_ports": ports_of(dvals) if d_ok else None,
                    "description": text(r.get("descr"), 200), "sequence": text(r.get("sequence"), 12),
                    "reflection": text(r.get("natreflection"), 20)})
    return {"forwards": out, "automatic": automatic}


def _sites(model: dict) -> dict:
    """Sites and their handlers from the Caddy model. Only the fields named here are kept."""
    rp = model.get("reverseproxy") if isinstance(model.get("reverseproxy"), dict) else {}
    general = model.get("general") if isinstance(model.get("general"), dict) else {}
    acls = {}
    for uid, a in _items(rp.get("accesslist")):
        if isinstance(a, dict):
            acls[str(uid)] = {"name": text(a.get("accesslistName"), 60), "ips": [text(i, 60) for i in _clean_selected(a.get("clientIps"))][:20],
                              "invert": _flag(a.get("accesslistInvert"))}

    def acl_names(v) -> list[str]:
        return [acls.get(u, {}).get("name") or u[:8] for u in _clean_selected(v)]

    sites: dict[str, dict] = {}
    for uid, r in _items(rp.get("reverse")):
        if isinstance(r, dict):
            tls = _clean_selected(r.get("DisableTls"))
            sites[str(uid)] = {"uuid": str(uid), "domain": text(r.get("FromDomain"), 160), "port": text(r.get("FromPort"), 8),
                               "enabled": _flag(r.get("enabled")), "acl": acl_names(r.get("accesslist")),
                               "basic_auth": bool(_clean_selected(r.get("basicauth"))),
                               "tls": "off" if tls == ["http://"] else "on", "description": text(r.get("description"), 120),
                               "parent": "", "handles": []}
    for uid, r in _items(rp.get("subdomain")):
        if isinstance(r, dict):
            parent = (_clean_selected(r.get("reverse")) or [""])[0]
            sites[str(uid)] = {"uuid": str(uid), "domain": text(r.get("FromDomain"), 160), "port": "", "enabled": _flag(r.get("enabled")),
                               "acl": acl_names(r.get("accesslist")), "basic_auth": bool(_clean_selected(r.get("basicauth"))),
                               "tls": "on", "description": text(r.get("description"), 120), "parent": parent, "handles": []}
    for uid, h in _items(rp.get("handle")):
        if not isinstance(h, dict):
            continue
        site_id = (_clean_selected(h.get("subdomain")) or _clean_selected(h.get("reverse")) or [""])[0]
        site = sites.get(site_id)
        if site is None or len(site["handles"]) >= 40:
            continue
        scheme = (_clean_selected(h.get("HttpTls")) or ["http://"])[0]
        site["handles"].append({"uuid": str(uid), "enabled": _flag(h.get("enabled")),
                                "kind": (_clean_selected(h.get("HandleDirective")) or [""])[0],
                                "path": text(h.get("HandlePath"), 120), "to": _clean_selected(h.get("ToDomain"))[:4],
                                "port": text(h.get("ToPort"), 8), "scheme": scheme.removesuffix("://"),
                                "acl": acl_names(h.get("accesslist")), "basic_auth": bool(_clean_selected(h.get("basicauth"))),
                                "forward_auth": _flag(h.get("ForwardAuth")), "description": text(h.get("description"), 120)})
    return {"sites": list(sites.values())[:400], "acls": [{"uuid": u, **a} for u, a in acls.items()],
            "global_acl": acl_names(general.get("accesslist")), "enabled": _flag(general.get("enabled"))}


def parse_caddy(responses: dict) -> dict:
    model = responses["caddy"].get("caddy")
    if not isinstance(model, dict):
        raise ValueError("no caddy model")
    out = _sites(model)
    status = responses.get("caddy_status") or {}
    out["service"] = text(status.get("status"), 20).lower()
    return out


def parse_tailscale(responses: dict) -> dict:
    st = responses.get("tailscale") if isinstance(responses.get("tailscale"), dict) else {}
    cfg = (responses.get("tailscale_settings") or {}).get("settings") or {}
    subnets = cfg.get("subnets") if isinstance(cfg.get("subnets"), dict) else {}
    wanted = [text(s.get("subnet"), 60) for s in _vals(subnets.get("subnet4")) if isinstance(s, dict) and s.get("subnet")]
    me = st.get("Self") if isinstance(st.get("Self"), dict) else {}
    return {
        "enabled": _flag(cfg.get("enabled")), "wants_exit_node": _flag(cfg.get("advertiseExitNode")),
        "wants_routes": wanted[:40], "accepts_routes": _flag(cfg.get("acceptSubnetRoutes")),
        "state": text(st.get("BackendState"), 30), "error": text(st.get("error"), 200), "version": text(st.get("Version"), 30),
        "health": [text(h, 160) for h in (st.get("Health") or [])][:5] if isinstance(st.get("Health"), list) else [],
        "auth_needed": bool(st.get("AuthURL")),
        "ips": [text(i, 60) for i in (st.get("TailscaleIPs") or [])][:4],
        "routes": [text(r, 60) for r in (me.get("PrimaryRoutes") or [])][:40],
        "allowed": [text(r, 60) for r in (me.get("AllowedIPs") or [])][:40],
        "exit_node_option": bool(me.get("ExitNodeOption")), "online": bool(me.get("Online")),
        "peers": len(st.get("Peer") or {}),
    }


def parse_system(responses: dict) -> dict:
    mem = (responses.get("resources") or {}).get("memory") or {}
    total, used = num(mem.get("total")), num(mem.get("used"))
    disks = []
    for d in [x for x in ((responses.get("disk") or {}).get("devices") or []) if isinstance(x, dict)][:40]:
        pct = num(d.get("used_pct"))
        disks.append({"mount": text(d.get("mountpoint"), 80), "device": text(d.get("device"), 80), "type": text(d.get("type"), 20),
                      "total": num(d.get("total_bytes")), "used": num(d.get("used_bytes")), "percent": pct})
    temps = []
    for t in [x for x in (responses.get("temperature") or []) if isinstance(x, dict)][:40] if isinstance(responses.get("temperature"), list) else []:
        v = num(t.get("temperature"))
        if v is not None:
            temps.append({"device": text(t.get("device"), 80), "celsius": v})
    return {"memory": {"total": total, "used": used, "percent": round(used / total * 100, 1) if total and used is not None else None},
            "disks": disks, "temperatures": temps}


def parse(source: str, responses: dict) -> dict:
    """`responses` maps each PATHS key the source reads to its parsed JSON."""
    first = responses[SOURCES[source].paths[0]]
    return {
        "opnsense_system": lambda: parse_system(responses),
        "opnsense_interfaces": lambda: parse_interfaces(first),
        "opnsense_gateways": lambda: parse_gateways(first),
        "opnsense_wireguard": lambda: parse_wireguard(first),
        "opnsense_services": lambda: parse_services(first),
        "opnsense_tailscale": lambda: parse_tailscale(responses),
        "opnsense_firmware": lambda: parse_firmware(first),
        "opnsense_rules": lambda: parse_rules(first),
        "opnsense_nat": lambda: parse_nat(first),
        "opnsense_caddy": lambda: parse_caddy(responses),
    }[source]()


# --- reading ---------------------------------------------------------------------------------------------------

def forbidden_data(src: Source) -> dict:
    """What a source stores when the user may not read it: the page shows `reason`, the rules see no data."""
    return {"available": False, "needs_privilege": src.privilege,
            "reason": f"This user needs the privilege {src.privilege} (System, Access, Users, Effective Privileges)."}


def not_installed_data(src: Source) -> dict:
    return {"available": False, "reason": f"Not installed: the firewall has no {src.title} plugin ({src.privilege})."}


async def read_source(rest: Rest, src: Source) -> dict:
    """GET every path of a source and parse it. Raises RemoteError (forbidden, auth, tls, unreachable, http)."""
    got = {}
    for key in src.paths:
        got[key] = await rest.get(PATHS[key])
    return parse(src.name, got)


def error_text(exc: Exception, *secrets: str | None) -> str:
    msg = exc.message if isinstance(exc, RemoteError) else f"{type(exc).__name__}: {exc}"
    return scrub(msg, *secrets)[:300] if secrets else msg[:300]


# --- test connection -------------------------------------------------------------------------------------------

@dataclass
class Probe:
    """What a test found. `problem` is set when the system can't be used; `sources` lists every source with
    "ok", "needs privilege X", "not installed" or an error."""
    problem: str | None = None
    sources: list[dict] = field(default_factory=list)
    facts: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.problem is None

    @property
    def missing(self) -> list[str]:
        return [s["privilege"] for s in self.sources if s["state"] == "forbidden"]


async def probe(net: Net, url: str, key: str, secret: str, tls: str = "verify", pem: str | None = None) -> Probe:
    """Read every source once (all GET) to see what this user may read. Raises RemoteError when the firewall can't be
    reached or refuses the key. A source that answers 403 is listed with the privilege it needs, and does not stop
    the others; a user that may read nothing is refused."""
    rest = Rest(url, key, secret, net.http(tls, pem), ALLOWED)
    out = Probe()
    parsed: dict[str, dict] = {}
    try:
        async def one(src: Source):
            try:
                return src, await read_source(rest, src), None
            except RemoteError as exc:
                return src, None, exc
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                return src, None, exc
        results = await asyncio.gather(*(one(s) for s in SOURCES.values()))
    finally:
        await rest.aclose()
    for src, data, exc in results:
        if isinstance(exc, RemoteError) and exc.kind in ("auth", "tls", "unreachable"):
            raise exc
        entry = {"title": src.title, "privilege": src.privilege, "menu": src.menu, "optional": src.optional}
        if exc is None:
            entry["state"], entry["note"] = "ok", ""
            parsed[src.name] = data
        elif isinstance(exc, RemoteError) and exc.kind == "forbidden":
            entry["state"], entry["note"] = "forbidden", f"needs privilege {src.privilege}"
        elif isinstance(exc, RemoteError) and exc.kind == "missing" and src.optional:
            entry["state"], entry["note"] = "absent", "plugin not installed"
        else:
            entry["state"], entry["note"] = "error", error_text(exc, key, secret)
        out.sources.append(entry)
    if all(s["state"] == "forbidden" for s in out.sources):
        out.problem = ("The key is accepted, but its user may not read anything DaemonSight asks for. Give the user the "
                       "privileges listed on this page (System, Access, Users, Effective Privileges) and test again.")
        return out
    fw = parsed.get("opnsense_firmware")
    if fw:
        out.facts.append(("Version", f"{fw['name']} {fw['version']}".strip()))
    if "opnsense_interfaces" in parsed:
        out.facts.append(("Interfaces", str(len(parsed["opnsense_interfaces"]["interfaces"]))))
    if "opnsense_gateways" in parsed:
        out.facts.append(("Gateways", str(len(parsed["opnsense_gateways"]["gateways"]))))
    if "opnsense_rules" in parsed:
        out.facts.append(("Firewall rules", str(len(parsed["opnsense_rules"]["rules"]))))
    if "opnsense_nat" in parsed:
        out.facts.append(("Port forwards", str(len(parsed["opnsense_nat"]["forwards"]))))
    return out


# --- what the collectors see, for the cross-checks -------------------------------------------------------------

def collector_hosts(conn) -> dict[str, dict]:
    """Every host a collector reports for (not a system the hub reads over an API) that has sent its listening
    sockets: {host: {"ips": {its own addresses}, "listeners": [{"proto", "port", "addresses"}]}}. A forward or a Caddy
    upstream is compared with it only when the target address belongs to one of these hosts; anything else is
    skipped, since nothing says what listens there."""
    from .. import db
    out: dict[str, dict] = {}
    for h in conn.execute("SELECT id FROM hosts WHERE kind IS NULL"):
        snap = db.get_snapshot(conn, h["id"], "ports")
        d = snap.data if snap and snap.data else None
        if not d or not isinstance(d.get("listeners"), list):
            continue
        ips = {a["ip"] for a in d.get("addresses", []) if isinstance(a, dict) and a.get("ip")}
        lis = [{"proto": x.get("proto"), "port": x.get("port"), "addresses": list(x.get("addresses") or [])}
               for x in d["listeners"] if isinstance(x, dict) and isinstance(x.get("port"), int)]
        if ips:
            out[h["id"]] = {"ips": ips, "listeners": lis}
    return out


def reach_by_listener(conn, ips: set[str]) -> dict[tuple[str, int], list[dict]]:
    """For a host with these addresses: {(proto, port): [{"fw": firewall host id, "how", "name", "anchor"}]} over every
    OPNsense system the hub reads, for its Exposure page ("Reached from the internet through ...")."""
    from .. import db
    from . import opnsense_rules, roles as roles_mod
    out: dict[tuple[str, int], list[dict]] = {}
    for r in conn.execute("SELECT id FROM remotes WHERE kind = 'opnsense' AND enabled = 1"):
        snaps = db.get_snapshots(conn, r["id"])
        data = {n.removeprefix(SNAPSHOT_PREFIX): (s.data if (s := snaps.get(n)) and s.data and s.data.get("available") is not False else None)
                for n in SOURCES}
        roles = opnsense_rules.interface_roles(data, roles_mod.load_overrides(conn, r["id"]))
        if not roles:
            continue
        for e in opnsense_rules.reach_into(data, roles, ips):
            for proto in e["protos"]:
                out.setdefault((proto, e["port"]), []).append({"fw": r["id"], "how": e["how"], "name": e["name"], "anchor": e["anchor"]})
    return out
