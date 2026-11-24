"""Findings from what the hub has read from an OPNsense firewall.

Pure functions of the stored snapshots, like unraid_rules.py: `evaluate` takes each source's latest data and returns
the findings that hold now; the poller makes the open `opnsense.*` findings match. Links are paths on the host's own
pages (`/firewall#rule-ab12`); the page code adds the `/h/<host>` prefix.

"Internet-facing" always comes from interface roles (roles.py), never from an interface being called "wan": a pass
rule counts when it is bound to an interface whose role is `wan`, or to no interface at all (a floating rule applies
to every interface, the internet-facing one included).

Thresholds, and where they come from. Where the number is DaemonSight's own choice it says so.

* Firmware: OPNsense's own firmware status (`/api/core/firmware/status`) is the last check's result; DaemonSight never
  starts a check. The API does not say how old an update is, so "behind for more than 30 days" is counted from when the
  hub first saw updates waiting (`pending_since`). 5 packages or a new release: Medium; 20 packages or 30 days: High.
  Own choice. When the CVE chore found CVEs that the offered release fixes (remote/opnsense_cves.py, from OPNsense's
  changelog), the finding names them and is at least Medium, and High when one is on CISA's KEV list or has an EPSS score
  at or above `[cve] epss_high`: the rule for a Debian host's package (cve/match.py `package_findings`). A security advisory
  of the changelog that names no CVE (not resolved, or none published) also makes it at least Medium, and High when GitHub
  rates it High or Critical (`opnsense_cves.summary`; errata and plugin notes do not count). Own choice.
* Unseen release (`opnsense.unseen_release`): the changelog has a release or hotfix in the firewall's series above what it
  runs and above what its last check showed (`latest`, `new_version`, the OPNsense package of a pending update), and that
  check is 2 days or more old, missing or unreadable. The age is DaemonSight's choice (the owner's). `last_check` is
  written by `scripts/firmware/check.sh` as `$(date)`; remote/opnsense.py `last_check_ts` reads it. The severity is
  `opnsense_cves.summary(...)["severity"]`, the same call the updates finding uses, and Low with no CVE and no advisory.
* Gateways: OPNsense's own alarm states (`status` is `down`, `loss`, `delay` or `delay+loss`, from
  `scripts/routes/gateway_status.php`) plus loss of 10% or more, or a round trip of 300 ms or more. Own choice.
* WireGuard: no handshake for a day. WireGuard sends a handshake about every 2 minutes while a peer has traffic or a
  keepalive (OPNsense itself calls a peer stale after 300 s: `Wireguard/Api/ServiceController.php`), so a day with none
  means the peer is not connected. A peer with persistent keepalive set is meant to stay up: Medium; others Low.
* Disk usage 90% Medium, 95% High (the same as the Unraid rules). Temperature 80 C Medium, 90 C High: own choice; OPNsense
  has no thresholds to read.

Where the "What to do" steps get their menu paths (OPNsense core menu files, `Menu/Menu.xml`):
Firewall, Rules (`/ui/firewall/filter`); Firewall, NAT, Destination NAT (`/ui/firewall/d_nat`); System, Firmware, Status
(`/ui/core/firmware#status`); System, Gateways, Configuration; VPN, WireGuard (Instances and Peers); Services, Caddy Web
Server, Reverse Proxy (`/ui/caddy/reverse_proxy`); VPN, Tailscale. Docs: https://docs.opnsense.org/manual/.
"""

from __future__ import annotations

import re

from ..cve import opnsense
from ..findings import Finding, anchor, digest
from . import opnsense_cves
from . import roles as roles_mod

FW_UI = "the OPNsense web UI"
UPDATES_MEDIUM_PACKAGES, UPDATES_HIGH_PACKAGES = 5, 20
UPDATES_HIGH_DAYS = 30
GATEWAY_LOSS, GATEWAY_DELAY_MS = 10.0, 300.0
WG_STALE_SECONDS = 86400
DISK_MEDIUM, DISK_HIGH = 90.0, 95.0
TEMP_MEDIUM, TEMP_HIGH = 80.0, 90.0
LISTED = 25
WILDCARDS = {"0.0.0.0", "::", "*", ""}
ANY = {"", "any"}
ANY_PROTOCOL = {"", "any", "tcp", "udp", "tcp/udp"}
SELF_DEST = {"(self)", "wanip", "this firewall"}


def steps(*lines: str) -> str:
    return "\n".join(lines)


def _days(seconds: float) -> str:
    d = seconds / 86400
    return f"{d:.0f} days" if d >= 2 else f"{seconds / 3600:.0f} hours"


# --- firmware --------------------------------------------------------------------------------------------------

HOWTO_UPDATES = steps(
    "Read what changed first: System, Firmware, Changelog (it lists each release's notes)",
    "Back up the configuration: System, Configuration, Backups, Download configuration",
    "Open System, Firmware, Status and press Check for updates, then Update. DaemonSight only reads; it never starts a check or an update",
    "Plan for the firewall to be offline while it installs, and for a reboot if the page says one is needed",
    "This finding goes away when the firewall's next firmware check shows nothing pending")
HOWTO_REBOOT = steps(
    "The pending update changes the kernel or base system, so it takes effect only after a reboot",
    "Pick a time when the network can be offline for a few minutes, then use Power, Reboot (or install the update, which reboots when it must)")


HOWTO_UPDATES_CVES = (
    "The Updates card on this firewall's Overview page lists the CVEs, each with its exploit score, whether CISA lists it as exploited, and the release that fixes it",
    "Read the changelog for the version being offered: {url} (or System, Firmware, Changelog in the firewall)",
    "Back up the configuration: System, Configuration, Backups, Download configuration",
    "Open System, Firmware, Updates to see the pending updates and install them. DaemonSight only reads; it never starts a check or an update",
    "Plan for the firewall to be offline while it installs, and for a reboot if the page says one is needed",
    "This finding goes away when the firewall's next firmware check shows nothing pending")


def _worse(a: str, b: str | None) -> str:
    order = ("low", "medium", "high")
    return b if b and order.index(b) > order.index(a) else a


def _cve_text(cv: dict) -> tuple[dict, str]:
    """The ranking of a pending update's CVEs and advisories, and the sentence about them for the finding's detail."""
    s = opnsense_cves.summary(cv["cves"], cv["epss_high"], cv.get("advisories"))
    n, k = len(s["fixable"]), len(s["unresolved"])
    if n:
        top = ", ".join(opnsense_cves.describe(c) for c in s["fixable"][:opnsense_cves.SHOWN])
        top += f" and {n - opnsense_cves.SHOWN} more" if n > opnsense_cves.SHOWN else ""
        text = (f" Updating to {cv['plan']['offered']} fixes {n} {'CVE' if n == 1 else 'CVEs'} named in OPNsense's changelog or "
                "in the FreeBSD and GitHub advisories it lists"
                + (f", {len(s['kev'])} on CISA's list of exploited vulnerabilities (KEV)" if s["kev"] else "")
                + (f", {len(s['hot'])} with a high exploit score" if s["hot"] else "") + f". Top CVEs: {top}.")
    else:
        text = f" Updating to {cv['plan']['offered']} fixes security advisories named in OPNsense's changelog."
    if k:
        high = sum(1 for a in s["unresolved"] if a.get("severity") in ("high", "critical"))
        text += (f" {k} security {'advisory' if k == 1 else 'advisories'} (FreeBSD and GitHub) "
                 f"{'names' if k == 1 else 'name'} no CVE yet, so {'it is' if k == 1 else 'they are'} not ranked; "
                 f"{'it is' if k == 1 else 'they are'} listed on the page"
                 + (f" and GitHub rates {high} of them High or Critical" if high else "") + ".")
    return s, text


HOWTO_UNSEEN = (
    "Check now: System, Firmware, Status, Check for updates. DaemonSight only reads; it never starts a check or an update",
    "So it checks on its own: System, Settings, Cron, add a job with the command 'Firmware update check' and run it daily",
    "Read what changed: {url}")


def unseen_rules(fw: dict | None, now: float, cves: dict | None) -> list[Finding]:
    """`opnsense.unseen_release`: a newer release in the firewall's series than it runs and than its last check showed, with
    that check two days or more old. Clears when the check shows the release (then `opnsense.updates` is the finding)."""
    st = opnsense_cves.unseen_state(fw, cves, now)
    if not st or not st["ready"]:
        return []
    s = opnsense_cves.summary(st["cves"], st["epss_high"], st["advisories"])
    sev = s["severity"] or "low"
    title = opnsense_cves.unseen_title(st, now)
    detail = (f"The firewall runs {fw.get('name') or 'OPNsense'} {st['plan']['installed']}. OPNsense's changelog lists "
              f"{st['version']}, which its last firmware check ({st['last_check'] or 'time unknown'}) did not show: that check "
              f"offered nothing above {st['plan']['seen']}.")
    if s["fixable"] or s["unresolved"]:
        _s, text = _cve_text({"cves": st["cves"], "epss_high": st["epss_high"], "advisories": st["advisories"],
                              "plan": {"offered": st["version"]}})
        detail += text
    url = opnsense.changelog_url(st["version"])
    return [Finding("opnsense.unseen_release", "unseen", sev, title[:300], detail[:3900], "/#firmware", None, st["version"],
                    steps(*(x.format(url=url) for x in HOWTO_UNSEEN)))]


def firmware_rules(fw: dict | None, now: float, cves: dict | None = None) -> list[Finding]:
    out = unseen_rules(fw, now, cves)
    if not fw or not (fw.get("count") or fw.get("needs_reboot")):
        return out
    n, sets = fw.get("count_packages") or 0, fw.get("count_sets") or 0
    since = fw.get("pending_since")
    behind = (now - since) if since else 0
    if fw.get("count"):
        sev = "low"
        if n >= UPDATES_HIGH_PACKAGES or behind > UPDATES_HIGH_DAYS * 86400:
            sev = "high"
        elif n >= UPDATES_MEDIUM_PACKAGES or sets or fw.get("major"):
            sev = "medium"
        new = fw.get("new_version")
        what = f"{n} package update{'s' if n != 1 else ''}" if n else f"a new release ({new or 'see System, Firmware'})"
        title = f"{what} pending" + (f" (to {new})" if new and n else "")
        detail = (f"The firewall's last firmware check ({fw.get('last_check') or 'time unknown'}) found {what} waiting. "
                  f"It runs {fw.get('name') or 'OPNsense'} {fw.get('version') or '?'}."
                  + (f" The hub has seen updates waiting for {_days(behind)}." if since and behind > 3600 else "")
                  + (" Installing them needs a reboot." if fw.get("needs_reboot") else "")
                  + " The check result is only as new as the firewall's last check; DaemonSight never starts one.")
        names = sorted({p["name"] for p in fw.get("packages", [])} | {p["name"] for p in fw.get("sets", [])})
        basis = digest(f"{p['name']}={p['new']}" for p in fw.get("packages", []) + fw.get("sets", [])) if names else "updates"
        howto = HOWTO_UPDATES
        # The CVEs the update fixes (the hub's CVE chore matched them against the changelog). Severity follows the Debian
        # host rule: KEV or a high EPSS score is High, any other fixable CVE Medium. The basis carries the offered version
        # and the CVE ids, so an accepted finding comes back when either changes.
        s = opnsense_cves.summary(cves["cves"], cves["epss_high"], cves.get("advisories")) if cves and cves.get("state") == "ok" else None
        if s and (s["fixable"] or s["unresolved"]):
            s, text = _cve_text(cves)
            sev = _worse(sev, s["severity"])
            title += "; " + opnsense_cves.headline(len(s["fixable"]), len(s["kev"]), lower=True, adv=len(s["unresolved"]))
            detail += text
            # The CVE ids, and the advisories that name none: a CVE resolved later changes the basis, as a new CVE does.
            ids = [c["cve"] for c in s["fixable"]] + [a["ref"] for a in s["unresolved"]]
            basis = f"{basis}:{cves['plan']['offered']}:{digest(ids)}"
            howto = steps(*(x.format(url=opnsense.changelog_url(cves["plan"]["offered"])) for x in HOWTO_UPDATES_CVES))
        out.append(Finding("opnsense.updates", "updates", sev, title[:300], detail[:3900], "/#firmware", None, basis, howto))
    if fw.get("needs_reboot"):
        out.append(Finding("opnsense.reboot", "reboot", "medium", "A reboot is needed to finish the pending update",
                           "The firewall says the pending firmware update needs a reboot to take effect.", "/#firmware", None,
                           "reboot", HOWTO_REBOOT))
    return out


# --- gateways --------------------------------------------------------------------------------------------------

HOWTO_GATEWAY_DOWN = steps(
    "Check the link to the provider: the modem or ONT lights, the cable, and whether other devices on that line work",
    "Open System, Gateways, Configuration: the gateway's monitor IP is what OPNsense pings (dpinger). A monitor address that stops answering marks the gateway down even when the link is fine",
    "If the monitor address is the problem, pick another one (the provider's gateway or a stable public address)",
    "The finding goes away when OPNsense sees the gateway answering again")
HOWTO_GATEWAY_QUALITY = steps(
    "Look at System, Gateways, Configuration: the loss and latency alarm levels are set on each gateway",
    "Brief spikes are normal on a busy link. If it stays, test the line from another device and call the provider",
    "If the monitor address is far away or rate-limits pings, choose a nearer one")


def gateway_rules(g: dict | None) -> list[Finding]:
    out = []
    for gw in (g or {}).get("gateways", []):
        name, st = gw["name"], gw.get("status") or ""
        loss, delay = gw.get("loss"), gw.get("delay")
        link = "/network#" + anchor("gw", name)
        if st in ("down", "force_down"):
            out.append(Finding("opnsense.gateway", name, "high", f"Gateway {name} is down",
                               f"OPNsense reports gateway {name} ({gw.get('address') or '?'}) as {gw.get('status_text') or st}; it monitors "
                               f"{gw.get('monitor') or 'no address'}." + (" The status is forced down by the owner." if st == "force_down" else ""),
                               link, None, f"{name}:down", HOWTO_GATEWAY_DOWN))
            continue
        bad = st in ("loss", "delay", "delay+loss") or (loss is not None and loss >= GATEWAY_LOSS) or (delay is not None and delay >= GATEWAY_DELAY_MS)
        if bad:
            bits = [f"{loss:.1f}% packet loss" if loss is not None else "", f"{delay:.0f} ms round trip" if delay is not None else ""]
            out.append(Finding("opnsense.gateway", name, "medium", f"Gateway {name}: {gw.get('status_text') or 'degraded'}",
                               f"Gateway {name} ({gw.get('address') or '?'}) shows {', '.join(b for b in bits if b) or st} to "
                               f"{gw.get('monitor') or 'its monitor address'}. OPNsense's own state is {gw.get('status_text') or st}.",
                               link, None, f"{name}:degraded", HOWTO_GATEWAY_QUALITY))
    return out


# --- WireGuard -------------------------------------------------------------------------------------------------

HOWTO_WG_PEER = steps(
    "Open VPN, WireGuard, Status: it lists each peer with its last handshake and the endpoint it was last seen from",
    "Check the other end: is that device on, online and running its tunnel? Does its config still name this firewall's public key and endpoint?",
    "Check VPN, WireGuard, Peers: the peer must be ticked in its instance (Instances, then the Peers field). A peer that is not linked to an instance never connects",
    "If it is a laptop or phone that is often off, accept this finding with a note")
HOWTO_WG_NO_PEER = steps(
    "Open VPN, WireGuard, Instances and edit this instance: the Peers field is empty, so nobody can connect through it",
    "Pick the peer(s) that belong to it and save, then Apply. (OPNsense lets a peer come unlinked, for example while another instance is set up)",
    "If the instance is not used any more, disable or delete it instead",
    "Check VPN, WireGuard, Status afterwards: the peer's last handshake should be within a few minutes")


def wireguard_rules(w: dict | None, now: float) -> list[Finding]:
    out = []
    for inst in (w or {}).get("instances", []):
        iface, name = inst["if"], inst.get("name") or inst["if"]
        link = "/vpn#" + anchor("wg", iface)
        if not inst["peers"]:
            out.append(Finding("opnsense.wg_no_peer", iface, "high", f"WireGuard instance {name} has no peer",
                               f"The instance {name} ({iface}) is up but has no peer attached, so no tunnel can come up through it.",
                               link, None, iface, HOWTO_WG_NO_PEER))
            continue
        for p in inst["peers"]:
            hs = p.get("handshake")
            if hs and now - hs <= WG_STALE_SECONDS:
                continue
            label = p.get("name") or p.get("key") or "peer"
            kept_up = (p.get("keepalive") or "off") != "off"
            ago = f"for {_days(now - hs)}" if hs else "since the tunnel started"
            when = f"{ago} (last on {_utc(hs)})" if hs else ago
            out.append(Finding("opnsense.wg_peer_stale", f"{iface}:{p.get('key') or label}", "medium" if kept_up else "low",
                               f"WireGuard peer {label} has not connected {ago}",
                               f"No handshake from peer {label} on {name} ({iface}) {when}. "
                               + ("The peer has persistent keepalive set, so it is meant to stay connected." if kept_up
                                  else "It has no keepalive, so it may simply be a device that is off."),
                               link, None, f"{iface}:{p.get('key') or label}", HOWTO_WG_PEER))
    return out


def _utc(ts: float) -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


# --- firewall rules --------------------------------------------------------------------------------------------

HOWTO_RULE_ANY = steps(
    "Open Firewall, Rules and find this rule (its description and source are in this finding)",
    "A pass rule from any source to any destination on an internet-facing interface lets the whole internet reach everything behind it, and it can override every block rule below it",
    "Replace it with rules for the services that need to be reachable, one port each, then delete this one",
    "If it is intentional (a lab, a test), accept this finding with a note saying why")
HOWTO_RULE_FLOATING = steps(
    "Open Firewall, Rules and look at the floating view: this rule has no interface, so it applies to every interface, the internet-facing one included",
    "Bind it to the interface it is meant for, or narrow its source to the networks that need it, then Apply",
    "If it is intentional (for example a VPN rule with a limited source), accept this finding with a note")
HOWTO_RULE_DESCR = steps(
    "Open Firewall, Rules, edit this rule and give it a description that says what it is for and who asked for it",
    "If nobody remembers what it is for, check its hit counts (Firewall, Log Files, Live View) before removing it",
    "A pass rule on an internet-facing interface should always be explainable")
HOWTO_NAT_ALL = steps(
    "Open Firewall, NAT, Destination NAT and find this forward",
    "With no destination port it forwards every port of that protocol to the target, so everything on the target host is reachable from the internet",
    "Set the destination port (and the redirect target port) to the one service it is for, and make the matching pass rule match",
    "If it is intentional, accept this finding with a note")
HOWTO_NAT_DEAD = steps(
    "Open Firewall, NAT, Destination NAT: this forward sends traffic to a host and port where DaemonSight's collector on that host sees nothing listening",
    "Check that the service is running on the target, and that it listens on that address and port (ss -ltnup on the host)",
    "If the service was removed or moved, delete or edit the forward and its pass rule, so the firewall does not keep a hole open for nothing")


def _is_any(v: str) -> bool:
    return (v or "").strip().lower() in ANY or v in ("0.0.0.0/0", "::/0")


def catch_all(r: dict) -> str | None:
    """What kind of catch-all a pass rule is: "any" (any source to any destination, any port), "self" (any source to
    the firewall itself, any port), or None."""
    if (r.get("protocol") or "") not in ANY_PROTOCOL or not _is_any(r.get("source", "")):
        return None
    if (r.get("destination_port") or "").strip().lower() not in ANY:
        return None
    dst = (r.get("destination") or "").strip().lower()
    if _is_any(dst):
        return "any"
    return "self" if dst in SELF_DEST else None


def _rule_label(r: dict) -> str:
    return r.get("description") or f"{r.get('action', 'pass')} rule {r['uuid'][:8]}"


def untrusted_rules(rules: dict | None, roles: dict[str, dict]) -> list[tuple[dict, str]]:
    """The enabled pass rules (inbound) that reach an internet-facing interface: (rule, where) with where "floating" for
    a rule with no interface and the interface's name otherwise."""
    out = []
    for r in (rules or {}).get("rules", []):
        if not r["enabled"] or r["action"] != "pass" or r["direction"] == "out" or r.get("interface_not"):
            continue
        if not r["interface"].strip():
            out.append((r, "floating"))
            continue
        names = roles_mod.lookup(roles)
        hit = [roles[names[p.strip().lower()]] for p in r["interface"].split(",") if p.strip().lower() in names]
        wan = next((h for h in hit if roles_mod.internet_facing(h["role"])), None)
        if wan:
            out.append((r, wan["name"]))
    return out


def rule_rules(rules: dict | None, roles: dict[str, dict]) -> list[Finding]:
    out = []
    for r, where in untrusted_rules(rules, roles):
        kind, label = catch_all(r), _rule_label(r)
        link = "/firewall#" + anchor("rule", r["uuid"][:12])
        port = f" ({r['protocol'] or 'any'})" if r.get("protocol") else ""
        src = r["source"] or "any"
        if kind and where == "floating":
            out.append(Finding("opnsense.rule_floating_any", r["uuid"], "high", f"A floating pass rule lets {src} reach everything",
                               f"The rule \"{label}\" has no interface, so it applies to every interface including the internet-facing one, "
                               f"and passes{port} traffic from {src} to {r['destination'] or 'any destination'}, any port.",
                               link, None, r["uuid"], HOWTO_RULE_FLOATING))
        elif kind:
            tail = "any destination" if kind == "any" else "the firewall itself"
            out.append(Finding("opnsense.rule_any", r["uuid"], "high", f"Pass any to {tail} on {where}",
                               f"The rule \"{label}\" on {where}, an internet-facing interface, passes{port} traffic from any source to {tail}, any port.",
                               link, None, r["uuid"], HOWTO_RULE_ANY))
        elif not r["description"].strip():
            out.append(Finding("opnsense.rule_no_descr", r["uuid"], "low", f"A pass rule on {where} has no description",
                               f"A pass rule on {where} ({'floating, so it applies to the internet-facing interface too' if where == 'floating' else 'internet-facing'}) "
                               f"from {src} to {r['destination'] or 'any'}{(':' + r['destination_port']) if r['destination_port'] else ''} "
                               f"has no description, so nobody can tell what it is for.", link, None, r["uuid"], HOWTO_RULE_DESCR))
    return out


# --- port forwards ---------------------------------------------------------------------------------------------

def forward_on_untrusted(f: dict, roles: dict[str, dict]) -> str | None:
    """The name of the internet-facing interface a forward is bound to, "all interfaces" for one with none, else None."""
    if not f["interface"].strip():
        return "all interfaces"
    names = roles_mod.lookup(roles)
    for p in f["interface"].split(","):
        key = names.get(p.strip().lower())
        if key and roles_mod.internet_facing(roles[key]["role"]):
            return roles[key]["name"]
    return None


def listening(host: dict, ip: str, proto: str, port: int) -> bool:
    protos = ("tcp", "udp") if proto in ("", "any", "tcp/udp") else (proto,)
    for lis in host.get("listeners", []):
        if lis["proto"] in protos and lis["port"] == port and any(a in WILDCARDS or a == ip for a in lis.get("addresses", [])):
            return True
    return False


def host_of(hosts: dict[str, dict] | None, ip: str) -> tuple[str, dict] | None:
    for name, h in (hosts or {}).items():
        if ip in h.get("ips", ()):
            return name, h
    return None


def nat_rules(nat: dict | None, roles: dict[str, dict], hosts: dict[str, dict] | None) -> list[Finding]:
    out = []
    for f in (nat or {}).get("forwards", []):
        if not f["enabled"] or f["no_redirect"]:
            continue
        where = forward_on_untrusted(f, roles)
        if where is None:
            continue
        link = "/firewall#" + anchor("fwd", f["uuid"][:12])
        label = f["description"] or f"forward {f['uuid'][:8]}"
        target = f["target"] or "?"
        if (f["destination_port"] or "").strip().lower() in ANY and (f["protocol"] or "") in ANY_PROTOCOL:
            out.append(Finding("opnsense.nat_all_ports", f["uuid"], "high", f"Forward \"{label}\" has no destination port",
                               f"The port forward \"{label}\" on {where} sends every {f['protocol'] or 'any'} port to {target}, so everything "
                               "the target host listens on is reachable from the internet.", link, None, f["uuid"], HOWTO_NAT_ALL))
            continue
        # Does the host behind it listen? Only when the target is one address that a collector host owns, and the
        # port is a plain number (an alias or a range is not resolved here).
        same = f["local_port"].strip().lower() in ANY
        ports = f["dest_ports"] if same else f["local_ports"]
        if not ports or len(f["target_ips"]) != 1:
            continue
        found = host_of(hosts, f["target_ips"][0])
        if not found:
            continue
        hname, h = found
        for p in ports[:20]:
            if not listening(h, f["target_ips"][0], f["protocol"], p):
                out.append(Finding("opnsense.nat_dead", f"{f['uuid']}:{p}", "medium",
                                   f"Forward \"{label}\" goes to {target}:{p}, where nothing listens",
                                   f"The forward \"{label}\" on {where} sends {f['protocol'] or 'any'} port {p} to {target} ({f['target_ips'][0]}), "
                                   f"which is host {hname}. Its collector reports nothing listening on {p}/{f['protocol'] or 'any'}.",
                                   link, None, f"{f['uuid']}:{p}", HOWTO_NAT_DEAD))
    return out


# --- Caddy -----------------------------------------------------------------------------------------------------

HOWTO_CADDY_NO_ACL = steps(
    "This is information, not an alarm: a public site (a blog, a status page) is meant to be open to everyone",
    "For each site that should not be public, open Services, Caddy Web Server, Reverse Proxy, edit the domain (or its handler) and pick an Access List; the access lists are defined under the same menu",
    "If every site listed here is meant to be public, accept this finding with a note. It comes back, as Changed, when a site is added or removed from the list")
HOWTO_CADDY_UPSTREAM = steps(
    "Open Services, Caddy Web Server, Reverse Proxy and check this handler's upstream (the 'Backend Domain' and 'Backend Port')",
    "Check that the service is running on that host and listens on that port (ss -ltnup on the host)",
    "If the service moved or was removed, edit or delete the site, so visitors don't get an error page")
HOWTO_CADDY_DOWN = steps(
    "Open System, Diagnostics, Services and start Caddy, or Services, Caddy Web Server, General Settings and press Apply",
    "If it won't start, Services, Caddy Web Server, Log File shows why (a bad site, a port already in use, a certificate that failed)",
    "Until it runs, every site it serves is offline")


def _site_open(s: dict, global_acl: list[str]) -> bool:
    """True when nothing restricts who may reach the site: no access list or password anywhere on it."""
    if global_acl or s["acl"] or s["basic_auth"]:
        return False
    live = [h for h in s["handles"] if h["enabled"]]
    return bool(live) and not any(h["acl"] or h["basic_auth"] or h["forward_auth"] for h in live)


def open_ports(rules: dict | None, roles: dict[str, dict]) -> set[int] | None:
    """The TCP ports that an internet-facing pass rule lets reach this firewall itself (rules to `(self)`, the WAN
    address or any destination), for the ones a Caddy site can use: a rule with no port opens 80 and 443. None when
    the rules aren't known: the caller then can't say a site is internet-facing."""
    if rules is None:
        return None
    ports: set[int] = set()
    for r, _where in untrusted_rules(rules, roles):
        if r["protocol"] not in ANY_PROTOCOL or not _is_any(r["source"]):
            continue
        if not (_is_any(r["destination"]) or r["destination"].strip().lower() in SELF_DEST):
            continue
        spec = r["destination_port"].strip()
        if spec.lower() in ANY:
            ports.update((80, 443))
            continue
        for tok in re.split(r"[,\s]+", spec):
            m = re.fullmatch(r"(\d+)(?:[:-](\d+))?", tok)
            if m:
                lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
                ports.update(p for p in (80, 443) if lo <= p <= hi)
                if lo == hi:
                    ports.add(lo)
    return ports


def site_ports(s: dict) -> list[int]:
    if s["port"].isdigit():
        return [int(s["port"])]
    return [443] if s["tls"] == "on" else [80]


def bare_sites(c: dict | None, rules: dict | None, roles: dict[str, dict]) -> list[str]:
    """Domains of the enabled Caddy sites that a firewall rule lets the internet reach and that have no access list or
    password. Empty when the rules aren't known."""
    exposed = open_ports(rules, roles)
    if not c or exposed is None:
        return []
    return sorted(s["domain"] for s in c.get("sites", [])
                  if s["enabled"] and s["domain"] and _site_open(s, c.get("global_acl") or []) and any(p in exposed for p in site_ports(s)))


def caddy_rules(c: dict | None, rules: dict | None, roles: dict[str, dict], hosts: dict[str, dict] | None) -> list[Finding]:
    if not c:
        return []
    out = []
    sites = [s for s in c.get("sites", []) if s["enabled"] and s["domain"]]
    if sites and c.get("enabled") and c.get("service") and c["service"] != "running":
        out.append(Finding("opnsense.caddy_down", "service", "high", "Caddy is not running",
                           f"OPNsense reports the Caddy service as {c['service']}, with {len(sites)} enabled site{'s' if len(sites) != 1 else ''}. "
                           "None of them is being served.", "/firewall#caddy", None, "service", HOWTO_CADDY_DOWN))
    bare = bare_sites(c, rules, roles)
    if bare:
        listed = ", ".join(bare[:LISTED]) + (f" and {len(bare) - LISTED} more" if len(bare) > LISTED else "")
        out.append(Finding("opnsense.caddy_no_acl", "sites", "info",
                           f"{len(bare)} internet-facing Caddy site{'s have' if len(bare) != 1 else ' has'} no access list",
                           f"A firewall rule lets the internet reach Caddy, and these sites have no access list or password, so anyone can "
                           f"open them: {listed}. Public sites are legitimate; this is a list to check, not a fault.",
                           "/firewall#caddy", None, digest(bare), HOWTO_CADDY_NO_ACL))
    for s in sites:
        for h in s["handles"]:
            if not h["enabled"] or h["kind"] not in ("reverse_proxy", ""):
                continue
            ips = [t for t in h["to"] if re.fullmatch(r"[0-9.]+|[0-9a-f:]+", t)]
            if len(ips) != 1:
                continue
            found = host_of(hosts, ips[0])
            if not found:
                continue
            port = int(h["port"]) if h["port"].isdigit() else (443 if h["scheme"] == "https" else 80)
            hname, host = found
            if not listening(host, ips[0], "tcp", port):
                out.append(Finding("opnsense.caddy_dead_upstream", f"{s['uuid']}:{h['uuid']}", "medium",
                                   f"Caddy site {s['domain']} points at {ips[0]}:{port}, where nothing listens",
                                   f"The site {s['domain']} proxies to {ips[0]}:{port}, which is host {hname}; its collector reports nothing "
                                   f"listening on {port}/tcp, so visitors get an error.", "/firewall#" + anchor("site", s["domain"]), None,
                                   f"{s['uuid']}:{h['uuid']}", HOWTO_CADDY_UPSTREAM))
    return out


# --- what a firewall lets reach a host ---------------------------------------------------------------------------

def reach_into(data: dict[str, dict | None], roles: dict[str, dict], ips: set[str]) -> list[dict]:
    """What this firewall lets the internet reach on a host with these addresses: port forwards whose target is one
    of them, and Caddy sites that are internet-facing and proxy to one of them. Each entry is
    {"how": "forward" | "caddy", "name", "protos": ["tcp", ...], "port": int, "anchor"}. Only plain port numbers
    are matched; an alias or a range that can't be resolved is left out, never guessed."""
    out = []
    for f in (data.get("nat") or {}).get("forwards", []):
        if not f["enabled"] or f["no_redirect"] or forward_on_untrusted(f, roles) is None:
            continue
        ip = next((i for i in f["target_ips"] if i in ips), None)
        same = f["local_port"].strip().lower() in ANY
        ports = f["dest_ports"] if same else f["local_ports"]
        if not ip or not ports:
            continue
        protos = ["tcp", "udp"] if f["protocol"] in ("", "any", "tcp/udp") else [f["protocol"]]
        for p in ports[:20]:
            out.append({"how": "forward", "name": f["description"] or f["uuid"][:8], "protos": protos, "port": p,
                        "anchor": anchor("fwd", f["uuid"][:12])})
    cd = data.get("caddy")
    exposed = open_ports(data.get("rules"), roles) if data.get("rules") else None
    if cd and exposed is not None:
        for s in cd.get("sites", []):
            if not s["enabled"] or not any(p in exposed for p in site_ports(s)):
                continue
            for h in s["handles"]:
                ips_h = [t for t in h["to"] if t in ips]
                if h["enabled"] and ips_h and h["kind"] in ("reverse_proxy", ""):
                    out.append({"how": "caddy", "name": s["domain"], "protos": ["tcp"],
                                "port": int(h["port"]) if h["port"].isdigit() else (443 if h["scheme"] == "https" else 80),
                                "anchor": anchor("site", s["domain"])})
    return out


# --- Tailscale -------------------------------------------------------------------------------------------------

HOWTO_TS_STATE = steps(
    "Open VPN, Tailscale, Status: it shows the state and, when a login is needed, a login link",
    "If it says NeedsLogin, authenticate this firewall again (VPN, Tailscale, Authentication). Logging in again clears the routes this node advertises, so check them afterwards",
    "If the service is stopped, check VPN, Tailscale, Settings: Enable must be ticked")
HOWTO_TS_ROUTES = steps(
    "Tailscale only uses a subnet route or exit node that is both advertised by this firewall and approved in the Tailscale admin console (Machines, this device, Edit route settings)",
    "Check this firewall first: VPN, Tailscale, Settings lists the subnets to advertise, and the Advertise exit node box. Save and Apply, then look at Status",
    "Then check the admin console: approve the routes under the device's route settings (unless an autoApprovers policy does it)",
    "Re-authenticating the firewall clears the advertised routes, so a route that disappeared after a login is expected: re-apply the settings")


def tailscale_rules(t: dict | None) -> list[Finding]:
    if not t or not t.get("enabled"):
        return []
    out = []
    state = t.get("state") or ""
    if state != "Running":
        why = t.get("error") or (f"Tailscale's state is {state}." if state else "Tailscale reports no state.")
        out.append(Finding("opnsense.tailscale", "state", "high", "Tailscale is not running",
                           f"The plugin is enabled in its settings, but {why}" + (" It needs a login." if t.get("auth_needed") else ""),
                           "/vpn#tailscale", None, "state", HOWTO_TS_STATE))
        return out
    live = set(t.get("routes", [])) | set(t.get("allowed", []))
    for r in t.get("wants_routes", []):
        if r not in live:
            out.append(Finding("opnsense.tailscale", f"route:{r}", "medium", f"Tailscale is not routing {r}",
                               f"The plugin's settings advertise the subnet {r}, but Tailscale does not list it as an approved route for "
                               "this node. It is not advertised yet (re-authenticating clears routes) or it is not approved in the admin console.",
                               "/vpn#tailscale", None, f"route:{r}", HOWTO_TS_ROUTES))
    if t.get("wants_exit_node") and not (t.get("exit_node_option") or "0.0.0.0/0" in live):
        out.append(Finding("opnsense.tailscale", "exit", "medium", "Tailscale is not offering an exit node",
                           "The plugin's settings advertise this firewall as an exit node, but Tailscale does not show it as an approved exit node "
                           "(ExitNodeOption means offered and approved). It is not advertised, or not approved in the admin console.",
                           "/vpn#tailscale", None, "exit", HOWTO_TS_ROUTES))
    return out


# --- services and resources ------------------------------------------------------------------------------------

HOWTO_SERVICE = steps(
    "Open System, Diagnostics, Services and start the service (the play button), then check it stays running",
    "If it stops again, its log says why: System, Log Files, General, or the service's own log page",
    "A service that is enabled but stopped is usually a configuration error")
HOWTO_DISK = steps(
    "Open Lobby, Dashboard, the Disk widget, to see which mount point is full",
    "Common causes: a large log (System, Log Files, Settings: reduce how many days are kept), old firmware snapshots (System, Snapshots) or old package caches",
    "A tmpfs mount (/var/log, /tmp) fills memory, not the disk: clear its largest files or reboot",
    "Don't delete files from the shell unless you know what they are")
HOWTO_TEMP = steps(
    "Check airflow: the vents, the fan, dust, and the room temperature",
    "A firewall that runs hot all the time may be under heavy load: Lobby, Dashboard shows the CPU widget",
    "At the sensor's critical level the machine may shut down on its own")
SKIP_MOUNT_TYPES = {"devfs", "fdescfs", "procfs"}


def service_rules(s: dict | None) -> list[Finding]:
    out = []
    for x in (s or {}).get("services", []):
        if not x["running"]:
            out.append(Finding("opnsense.service_stopped", x["id"], "medium", f"The {x['description'] or x['name']} service is stopped",
                               f"OPNsense lists the service {x['id']} ({x['description'] or x['name']}) among its enabled services, and it is not running.",
                               "/network#" + anchor("svc", x["id"]), None, x["id"], HOWTO_SERVICE))
    return out


def resource_rules(sysd: dict | None) -> list[Finding]:
    out = []
    for d in (sysd or {}).get("disks", []):
        pct = d.get("percent")
        if pct is None or d["type"] in SKIP_MOUNT_TYPES or pct < DISK_MEDIUM:
            continue
        band = "high" if pct >= DISK_HIGH else "medium"
        out.append(Finding("opnsense.disk_full", d["mount"], band, f"{d['mount']} is {pct:.0f}% full",
                           f"The {d['type']} filesystem mounted at {d['mount']} ({d['device']}) is {pct:.0f}% full.",
                           "/#resources", None, f"{d['mount']}:{band}", HOWTO_DISK))
    for t in (sysd or {}).get("temperatures", []):
        c = t["celsius"]
        if c < TEMP_MEDIUM:
            continue
        band = "high" if c >= TEMP_HIGH else "medium"
        out.append(Finding("opnsense.temperature", t["device"], band, f"A sensor reads {c:.0f} °C",
                           f"The sensor {t['device']} reads {c:.0f} °C. DaemonSight warns at {TEMP_MEDIUM:.0f} °C and again at {TEMP_HIGH:.0f} °C; "
                           "OPNsense has no limits of its own to read.", "/#resources", None, f"{t['device']}:{band}", HOWTO_TEMP))
    return out


# --- everything ------------------------------------------------------------------------------------------------

def interface_roles(data: dict[str, dict | None], overrides: dict[str, str] | None) -> dict[str, dict]:
    return roles_mod.assign((data.get("interfaces") or {}).get("interfaces", []), overrides)


def evaluate(data: dict[str, dict | None], now: float, overrides: dict[str, str] | None = None,
             hosts: dict[str, dict] | None = None, cves: dict | None = None) -> list[Finding]:
    """`data` maps short source names (firmware, gateways, interfaces, wireguard, rules, nat, caddy, tailscale,
    services, system) to their latest stored data, or None when that source can't be read (no privilege, not
    installed, never read). `overrides` are the owner's interface roles. `hosts` maps a hub host to
    {"ips": {...}, "listeners": [{"proto", "port", "addresses"}]}, for the checks that compare a forward or a
    site with what a collector sees listening. `cves` is what the CVE chore found for the pending update
    (opnsense_cves.load); without it the updates finding has no CVEs in it."""
    roles = interface_roles(data, overrides)
    out: list[Finding] = []
    out += firmware_rules(data.get("firmware"), now, cves)
    out += gateway_rules(data.get("gateways"))
    out += wireguard_rules(data.get("wireguard"), now)
    if roles:
        out += rule_rules(data.get("rules"), roles)
        out += nat_rules(data.get("nat"), roles, hosts)
    out += caddy_rules(data.get("caddy"), data.get("rules") if roles else None, roles, hosts)
    out += tailscale_rules(data.get("tailscale"))
    out += service_rules(data.get("services"))
    out += resource_rules(data.get("system"))
    return out
