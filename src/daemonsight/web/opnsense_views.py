"""What the pages show for an OPNsense firewall the hub reads over its REST API. Same shapes as unraid_views.py
(tables with data-label cells, row anchors that findings link to, source panels naming the GET request), built from
the `opnsense_*` snapshots the poller (remote/poll.py) stores.

Every table row that a finding is about carries the finding's label (Unexpected, Accepted, Changed) and a panel with
Accept, like the Exposure page. A row nothing was found about shows a dash.
Text from the firewall (descriptions, names) is untrusted: cut to a length, stripped of control characters by the
parsers, and escaped by the templates."""

from __future__ import annotations

import time

from .. import db, findings as rules
from ..config import Config
from ..remote import opnsense, opnsense_rules, roles as roles_mod, store
from . import provenance as prov
from . import views
from .views import fmt_ago, fmt_bytes, fmt_duration, level_class, pct_class, status_of

PAGES = ("overview", "firewall", "vpn", "network")


def _data(snaps: dict, source: str) -> dict | None:
    s = snaps.get(source)
    return s.data if s and s.data and s.data.get("available") is not False else None


def _remote(conn, host: str):
    return store.get(conn, host)


def _panels(conn, cfg: Config) -> tuple[str | None, int]:
    r = _remote(conn, cfg.host_id)
    return (r["url"], r["interval"]) if r else (None, 60)


def _states(snaps: dict) -> dict:
    return {src.title: views._source_state(snaps, name) for name, src in opnsense.SOURCES.items()}


def _short(snaps: dict) -> dict[str, dict | None]:
    return {n.removeprefix(opnsense.SNAPSHOT_PREFIX): _data(snaps, n) for n in opnsense.SOURCES}


def _roles(conn, host: str, snaps: dict) -> dict[str, dict]:
    return opnsense_rules.interface_roles(_short(snaps), roles_mod.load_overrides(conn, host))


def _by_key(conn, host: str, prefix: str = "opnsense.") -> dict[tuple[str, str], dict]:
    active, held = views.findings_lists(conn, host)
    return {(f["rule"], f["key"]): f for f in active + held if f["rule"].startswith(prefix)}


def _status(finding: dict | None) -> dict | None:
    return status_of(False, finding) if finding else None


def _src(base: dict, finding: dict | None, anchor: str) -> dict:
    return {**base, "finding": finding, "anchor": anchor}


def _ago(ts) -> str:
    return fmt_ago(ts) if ts else "never"


def _when(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts else "never"


# --- Overview --------------------------------------------------------------------------------------------------

def overview(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    sysd, fw = d["system"], d["firmware"]
    hour_ago = time.time() - 3600

    tiles = None
    if sysd and (sysd.get("memory", {}).get("percent") is not None or sysd.get("disks")):
        mem = sysd["memory"]
        disks = [x for x in sysd.get("disks", []) if x.get("percent") is not None]
        root = next((x for x in disks if x["mount"] == "/"), disks[0] if disks else None)
        tiles = {
            "cpu": None,
            "mem": {"percent": mem.get("percent") or 0, "used": fmt_bytes(mem.get("used")), "total": fmt_bytes(mem.get("total")),
                    "pct": pct_class(mem.get("percent")), "level": level_class(mem.get("percent"))},
            "disk": None if not root else {
                "mount": root["mount"], "percent": root["percent"], "used": fmt_bytes(root.get("used")),
                "total": fmt_bytes(root.get("total")), "pct": pct_class(root["percent"]),
                "level": level_class(root["percent"], 80, 90), "others": len(disks) - 1},
            "net": None,
        }

    glance = []
    if fw:
        note = " · ".join(x for x in (fw.get("os") or "", f"{fw['new_version']} available" if fw.get("count") and fw.get("new_version") else "") if x)
        glance.append({"id": "firmware", "title": fw.get("name") or "OPNsense", "value": fw.get("version") or "?", "note": note or None})
        if fw.get("count"):
            glance.append({"title": "Pending updates", "value": f"{fw['count']} waiting",
                           "alert": "reboot needed" if fw.get("needs_reboot") else None, "link": "/#firmware"})
        else:
            glance.append({"title": "Updates", "value": "None pending", "alert": None, "note": f"Last check {fw['last_check']}" if fw.get("last_check") else None})
    ifaces = d["interfaces"]
    roles = _roles(conn, host, snaps)
    if ifaces:
        counts = {r: sum(1 for x in roles.values() if x["role"] == r) for r in roles_mod.ROLES}
        glance.append({"title": "Interfaces", "value": f"{counts['wan']} internet-facing, {counts['lan']} LAN, {counts['vpn']} VPN",
                       "alert": None, "link": "/network#interfaces"})
    gw = d["gateways"]
    if gw:
        gws = gw["gateways"]
        up = sum(1 for g in gws if g["status"] not in ("down", "force_down"))
        glance.append({"title": "Gateways", "value": f"{up} of {len(gws)} up", "alert": "down" if up < len(gws) else None, "link": "/network#gateways"})
    wg = d["wireguard"]
    if wg:
        peers = [p for i in wg["instances"] for p in i["peers"]]
        now = time.time()
        live = sum(1 for p in peers if p.get("handshake") and now - p["handshake"] <= 300)
        glance.append({"title": "WireGuard", "value": f"{len(wg['instances'])} instance{'s' if len(wg['instances']) != 1 else ''}, {live} of {len(peers)} peers connected",
                       "alert": None, "link": "/vpn#wireguard"})
    ts = d["tailscale"]
    if ts and ts.get("enabled"):
        glance.append({"title": "Tailscale", "value": ts.get("state") or "not running", "alert": None if ts.get("state") == "Running" else "check it", "link": "/vpn#tailscale"})
    rl = d["rules"]
    if rl:
        glance.append({"title": "Firewall rules", "value": f"{len(rl['rules'])} configured",
                       "note": f"{rl['legacy']} classic" + (f", {rl['automatic']} generated by OPNsense" if rl.get("automatic") else ""), "link": "/firewall#rules"})
    nat = d["nat"]
    if nat:
        glance.append({"title": "Port forwards", "value": f"{sum(1 for f in nat['forwards'] if f['enabled'])} enabled", "link": "/firewall#forwards"})
    cd = d["caddy"]
    if cd:
        glance.append({"title": "Caddy", "value": f"{sum(1 for s in cd['sites'] if s['enabled'])} sites", "note": cd.get("service") or None, "link": "/firewall#caddy"})
    sv = d["services"]
    if sv:
        stopped = [x for x in sv["services"] if not x["running"]]
        glance.append({"id": "services", "title": "Services", "value": f"{len(sv['services']) - len(stopped)} of {len(sv['services'])} running",
                       "alert": f"{len(stopped)} stopped" if stopped else None, "link": "/network#services"})
    r = _remote(conn, host)
    if r:
        glance.append({"title": "Last read", "value": _ago(r["last_poll"]) if r["last_poll"] else "never",
                       "alert": (r["last_error"] or "")[:120] if r["fails"] else None})

    firmware = None
    if fw and fw.get("count"):
        firmware = {"rows": [{"name": p["name"], "old": p["old"], "new": p["new"], "reason": p["reason"]} for p in (fw["packages"] or fw["sets"])][:60],
                    "count": fw["count"], "version": fw.get("version"), "new": fw.get("new_version"), "reboot": fw.get("needs_reboot"),
                    "last_check": fw.get("last_check"), "since": _ago(fw.get("pending_since")) if fw.get("pending_since") else None}
    resources = None
    if sysd and (sysd.get("disks") or sysd.get("temperatures")):
        resources = {"disks": [{"mount": x["mount"], "device": x["device"], "type": x["type"], "percent": x.get("percent"),
                                "level": level_class(x.get("percent"), 80, 90), "pct": pct_class(x.get("percent")),
                                "used": fmt_bytes(x.get("used")), "total": fmt_bytes(x.get("total"))} for x in sysd["disks"]],
                     "temps": [{"device": t["device"], "celsius": t["celsius"],
                                "class": "text-red" if t["celsius"] >= opnsense_rules.TEMP_HIGH else "text-orange" if t["celsius"] >= opnsense_rules.TEMP_MEDIUM else ""}
                               for t in sysd["temperatures"]]}
    return {
        "host": views._host(cfg, snaps), "tiles": tiles, **views.findings_overview(conn, host),
        "events": views.events_list(conn, host), "glance": glance, "sources": {k: v for k, v in _states(snaps).items() if v["state"] != "ok"},
        "top": None, "firmware": firmware, "resources": resources,
        "src": {"system": prov.opnsense_section("opnsense_system", url, interval), "findings": prov.section("findings", cfg),
                "events": prov.section("events", cfg), "firmware": prov.opnsense_section("opnsense_firmware", url, interval),
                "resources": prov.opnsense_section("opnsense_system", url, interval)},
    }


# --- Firewall --------------------------------------------------------------------------------------------------

def _rule_row(r: dict, where: str, findings: dict, url: str | None) -> dict:
    f = next((findings.get((rule, r["uuid"])) for rule in ("opnsense.rule_any", "opnsense.rule_floating_any", "opnsense.rule_no_descr")
              if findings.get((rule, r["uuid"]))), None)
    anchor = rules.anchor("rule", r["uuid"][:12])
    dest = " ".join(x for x in (r["destination"] or "any", (":" + r["destination_port"]) if r["destination_port"] else "") if x)
    return {"anchor": anchor, "where": where, "protocol": (r["protocol"] or "any").upper() if r["protocol"] else "any",
            "source": r["source"] or "any", "destination": dest.replace(" :", ":"), "description": r["description"],
            "origin": "Classic" if r["legacy"] else "New", "seq": r["sequence"], "seq_v": views._sortval(int(r["sequence"]) if r["sequence"].isdigit() else None),
            "status": _status(f),
            "src": _src(prov.opnsense_row(f"Rule {r['description'] or r['uuid'][:8]}", "opnsense_rules", url), f, anchor)}


def _site_row(s: dict, bare: set[str], exposed: set[int] | None, findings: dict, url: str | None, global_acl: list[str]) -> dict:
    ups = []
    for h in s["handles"]:
        if h["kind"] in ("reverse_proxy", "") and h["to"]:
            port = h["port"] or ("443" if h["scheme"] == "https" else "80")
            ups.append(f"{', '.join(h['to'])}:{port} ({h['scheme']})" + ("" if h["enabled"] else " disabled"))
    acl = sorted(set(s["acl"]) | set(global_acl) | {a for h in s["handles"] for a in h["acl"]})
    auth = s["basic_auth"] or any(h["basic_auth"] or h["forward_auth"] for h in s["handles"])
    ports = opnsense_rules.site_ports(s)
    facing = None if exposed is None else any(p in exposed for p in ports)
    dead = next((f for (rule, key), f in findings.items() if rule == "opnsense.caddy_dead_upstream" and key.startswith(s["uuid"] + ":")), None)
    f = dead or (findings.get(("opnsense.caddy_no_acl", "sites")) if s["domain"] in bare else None)
    anchor = rules.anchor("site", s["domain"])
    return {"anchor": anchor, "domain": s["domain"], "enabled": s["enabled"], "upstreams": ups,
            "access": ", ".join(acl) if acl else ("password" if auth else "none"), "open": not acl and not auth,
            "facing": {True: "Yes", False: "No", None: "Unknown"}[facing],
            "facing_badge": {True: "bg-yellow-lt", False: "bg-secondary-lt", None: "bg-secondary-lt"}[facing],
            "tls": s["tls"], "description": s["description"], "status": _status(f),
            "src": _src(prov.opnsense_row(f"Caddy site {s['domain']}", "opnsense_caddy", url), f, anchor)}


def firewall(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    roles = _roles(conn, host, snaps)
    findings = _by_key(conn, host)
    names = roles_mod.lookup(roles)

    rl = d["rules"]
    untrusted = opnsense_rules.untrusted_rules(rl, roles) if rl and roles else []
    rule_rows = [_rule_row(r, w, findings, url) for r, w in untrusted]
    rule_rows.sort(key=lambda x: (x["where"], int(x["seq_v"]) if x["seq_v"] else 10 ** 9))

    nat_rows = []
    for f in (d["nat"] or {}).get("forwards", []):
        key = next((names[p.strip().lower()] for p in f["interface"].split(",") if p.strip().lower() in names), "")
        role = roles.get(key, {}).get("role") if key else None
        facing = opnsense_rules.forward_on_untrusted(f, roles) is not None if roles else None
        fnd = findings.get(("opnsense.nat_all_ports", f["uuid"])) or next(
            (x for (rule, k), x in findings.items() if rule == "opnsense.nat_dead" and k.startswith(f["uuid"] + ":")), None)
        anchor = rules.anchor("fwd", f["uuid"][:12])
        port = f["destination_port"] or "all ports"
        nat_rows.append({"anchor": anchor, "enabled": f["enabled"], "no_redirect": f["no_redirect"],
                         "interface": roles[key]["name"] if key else (f["interface"] or "all"),
                         "role": roles_mod.ROLE_SHORT.get(role, "role unknown") if role else "role unknown",
                         "role_badge": roles_mod.ROLE_BADGE.get(role, "bg-secondary-lt"), "facing": bool(facing),
                         "protocol": (f["protocol"] or "any").upper(), "port": port, "port_bad": not f["destination_port"],
                         "target": f["target"] + (f" ({', '.join(f['target_ips'])})" if f["target_ips"] and f["target_ips"] != [f["target"]] else ""),
                         "local_port": f["local_port"], "description": f["description"], "status": _status(fnd),
                         "src": _src(prov.opnsense_row(f"Port forward {f['description'] or f['uuid'][:8]}", "opnsense_nat", url), fnd, anchor)})
    cd = d["caddy"]
    exposed = opnsense_rules.open_ports(rl, roles) if rl and roles else None
    bare = set(opnsense_rules.bare_sites(cd, rl, roles)) if cd and rl and roles else set()
    site_rows = [_site_row(s, bare, exposed, findings, url, (cd or {}).get("global_acl") or []) for s in (cd or {}).get("sites", [])]
    unlisted = (len(rl["rules"]) - len(untrusted)) if rl else 0
    return {
        "host": views._host(cfg, snaps), "rule_rows": rule_rows, "nat_rows": nat_rows, "site_rows": site_rows,
        "rules_state": views._source_state(snaps, "opnsense_rules"), "nat_state": views._source_state(snaps, "opnsense_nat"),
        "caddy_state": views._source_state(snaps, "opnsense_caddy"), "no_roles": not roles,
        "unlisted": unlisted, "automatic": (rl or {}).get("automatic", 0), "legacy": (rl or {}).get("legacy", 0),
        "caddy_service": (cd or {}).get("service"), "bare": len(bare),
        "src": {"rules": prov.opnsense_section("opnsense_rules", url, interval), "nat": prov.opnsense_section("opnsense_nat", url, interval),
                "caddy": prov.opnsense_section("opnsense_caddy", url, interval)},
    }


# --- VPN -------------------------------------------------------------------------------------------------------

def vpn(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    findings = _by_key(conn, host)
    now = time.time()
    insts = []
    for i in (d["wireguard"] or {}).get("instances", []):
        peers = []
        for p in i["peers"]:
            hs = p.get("handshake")
            key = f"{i['if']}:{p.get('key') or p.get('name') or 'peer'}"
            f = findings.get(("opnsense.wg_peer_stale", key))
            anchor = rules.anchor("wgpeer", key)
            age = (now - hs) if hs else None
            peers.append({"anchor": anchor, "name": p.get("name") or p.get("key") or "peer", "endpoint": p.get("endpoint") or "—",
                          "allowed": p.get("allowed") or "—", "age": fmt_duration(age) + " ago" if age is not None else "never",
                          "age_v": views._sortval(age), "when": _when(hs),
                          "state": "connected" if age is not None and age <= 300 else ("quiet" if age is not None and age <= opnsense_rules.WG_STALE_SECONDS else "no handshake"),
                          "state_badge": "bg-green-lt" if age is not None and age <= 300 else ("bg-yellow-lt" if age is not None and age <= opnsense_rules.WG_STALE_SECONDS else "bg-red-lt"),
                          "traffic": f"{fmt_bytes(p.get('rx'))} in · {fmt_bytes(p.get('tx'))} out",
                          "keepalive": "off" if (p.get("keepalive") or "off") == "off" else f"{p['keepalive']} s",
                          "status": _status(f),
                          "src": _src(prov.opnsense_row(f"WireGuard peer {p.get('name') or p.get('key')}", "opnsense_wireguard", url), f, anchor)})
        f = findings.get(("opnsense.wg_no_peer", i["if"]))
        anchor = rules.anchor("wg", i["if"])
        insts.append({"anchor": anchor, "name": i.get("name") or i["if"], "if": i["if"], "status_text": i.get("status") or "?",
                      "port": int(i["port"]) if i.get("port") else None, "peers": peers, "status": _status(f),
                      "src": _src(prov.opnsense_row(f"WireGuard instance {i.get('name') or i['if']}", "opnsense_wireguard", url), f, anchor)})
    ts = d["tailscale"]
    tsv = None
    if ts:
        live = set(ts.get("routes", [])) | set(ts.get("allowed", []))
        rows = []
        for r in ts.get("wants_routes", []):
            f = findings.get(("opnsense.tailscale", f"route:{r}"))
            rows.append({"route": r, "ok": r in live, "status": _status(f), "src": _src(prov.opnsense_row(f"Tailscale route {r}", "opnsense_tailscale", url), f, rules.anchor("tsroute", r))})
        fe = findings.get(("opnsense.tailscale", "exit"))
        fs = findings.get(("opnsense.tailscale", "state"))
        exit_on = bool(ts.get("exit_node_option") or "0.0.0.0/0" in live)
        tsv = {"enabled": ts.get("enabled"), "state": ts.get("state") or ts.get("error") or "unknown", "version": ts.get("version"),
               "ips": ", ".join(ts.get("ips", [])), "peers": ts.get("peers"), "routes": rows, "wants_exit": ts.get("wants_exit_node"),
               "exit_on": exit_on, "exit_status": _status(fe), "state_status": _status(fs), "health": ts.get("health", []),
               "src_exit": _src(prov.opnsense_row("Tailscale exit node", "opnsense_tailscale", url), fe, "tsexit"),
               "src_state": _src(prov.opnsense_row("Tailscale state", "opnsense_tailscale", url), fs, "tailscale")}
    return {
        "host": views._host(cfg, snaps), "instances": insts, "tailscale": tsv,
        "wg_state": views._source_state(snaps, "opnsense_wireguard"), "ts_state": views._source_state(snaps, "opnsense_tailscale"),
        "src": {"wireguard": prov.opnsense_section("opnsense_wireguard", url, interval), "tailscale": prov.opnsense_section("opnsense_tailscale", url, interval)},
    }


# --- Gateways and interfaces -----------------------------------------------------------------------------------

def network(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    d = _short(snaps)
    url, interval = _panels(conn, cfg)
    findings = _by_key(conn, host)
    roles = _roles(conn, host, snaps)
    by_gw_addr: dict[str, str] = {}
    iface_rows = []
    for i in (d["interfaces"] or {}).get("interfaces", []):
        r = roles.get(i["id"])
        role, why = (r["role"], r["why"]) if r else roles_mod.classify(i)
        for g in i["gateways"]:
            by_gw_addr[g] = i["name"]
        iface_rows.append({"anchor": rules.anchor("if", i["id"] or i["device"]), "id": i["id"], "name": i["name"], "device": i["device"],
                           "assigned": i["assigned"], "status": i["status"] or "?", "up": i["status"] == "up",
                           "addresses": ", ".join(i["addresses"]) or "—", "gateways": ", ".join(i["gateways"]) or "—",
                           "role": roles_mod.ROLE_LABEL[role], "role_key": role, "role_badge": roles_mod.ROLE_BADGE[role], "why": why,
                           "auto": r["auto"] if r else role, "overridden": bool(r and r["overridden"]),
                           "auto_label": roles_mod.ROLE_LABEL.get(r["auto"] if r else role, "Other"),
                           "src": prov.opnsense_row(f"Interface {i['name']}", "opnsense_interfaces", url)})
    gw_rows = []
    for g in (d["gateways"] or {}).get("gateways", []):
        f = findings.get(("opnsense.gateway", g["name"]))
        anchor = rules.anchor("gw", g["name"])
        bad = g["status"] in ("down", "force_down")
        gw_rows.append({"anchor": anchor, "name": g["name"], "address": g["address"], "interface": by_gw_addr.get(g["address"], "—"),
                        "state": g["status_text"] or g["status"], "state_badge": "bg-red text-red-fg" if bad else ("bg-yellow-lt" if g["status"] not in ("none", "") else "bg-green-lt"),
                        "loss": f"{g['loss']:.1f}%" if g["loss"] is not None else "—", "loss_v": views._sortval(g["loss"]),
                        "delay": f"{g['delay']:.1f} ms" if g["delay"] is not None else "—", "delay_v": views._sortval(g["delay"]),
                        "monitor": g["monitor"] if g["monitor"] not in ("", "~") else "—", "status": _status(f),
                        "src": _src(prov.opnsense_row(f"Gateway {g['name']}", "opnsense_gateways", url), f, anchor)})
    svc_rows = []
    for x in (d["services"] or {}).get("services", []):
        f = findings.get(("opnsense.service_stopped", x["id"]))
        anchor = rules.anchor("svc", x["id"])
        svc_rows.append({"anchor": anchor, "id": x["id"], "description": x["description"] or x["name"], "running": x["running"],
                         "locked": x["locked"], "status": _status(f),
                         "src": _src(prov.opnsense_row(f"Service {x['id']}", "opnsense_services", url), f, anchor)})
    svc_rows.sort(key=lambda x: (x["running"], x["id"]))
    return {
        "host": views._host(cfg, snaps), "interfaces": iface_rows, "gateways": gw_rows, "services": svc_rows,
        "if_state": views._source_state(snaps, "opnsense_interfaces"), "gw_state": views._source_state(snaps, "opnsense_gateways"),
        "svc_state": views._source_state(snaps, "opnsense_services"), "ROLES": [(r, roles_mod.ROLE_LABEL[r]) for r in roles_mod.ROLES],
        "src": {"interfaces": prov.opnsense_section("opnsense_interfaces", url, interval), "gateways": prov.opnsense_section("opnsense_gateways", url, interval),
                "services": prov.opnsense_section("opnsense_services", url, interval)},
    }


PAGE_FUNCS = {"overview": overview, "firewall": firewall, "vpn": vpn, "network": network}
