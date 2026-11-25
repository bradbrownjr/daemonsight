"""Whether a system is publicly exposed: the first variable of CISA BOD 26-04's Table 1 (cve/priority.py).

The implementation guidance says what to do when exposure data is missing: treat an asset with a publicly routable IP address
(IPv4 or IPv6) as public, or one whose asset type tag is "network" (https://www.cisa.gov/news-events/directives/
bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk, "best-effort logic"). Otherwise it is internal.
DaemonSight has real exposure data for most of what it watches, so that rule is the fallback, not the first choice:

* A host with a collector: the listeners the collector reports that the internet can reach (a public address or a wildcard
  bind on a host with one, past the host firewall and the provider's allow list), Docker's published ports on a public
  address, and the port forwards and Caddy sites of the hub's OPNsense systems that lead to the host's addresses. This is
  what the Exposure page shows (findings.public_listeners, remote/opnsense.reach_by_listener).
* A container image on a host with a collector: exposed when a running container from it is reached from the internet by one of
  these routes (the first that holds is quoted). Docker publishes a port on all interfaces, or on a public address, of a host that
  has a public address, and the provider's allow list passes it. Or an OPNsense port forward leads to a port it publishes on a
  non-loopback address. Or an internet-facing Caddy site on the host proxies to it (its published port on this host, or its name
  on a Docker network) and Caddy itself can be reached from the internet. A container that publishes to 127.0.0.1 only is exposed
  through the last route and no other. A container on the host network is judged by the listeners the collector reports for it.
  See collector_image_exposures and DESIGN.md, "Collector hosts: image CVEs".
* An OPNsense firewall: always exposed. It is a network device, which the guidance treats as public, and its own interfaces
  face the internet.
* An Unraid container image: exposed when a running container from it publishes a port that an OPNsense port forward or Caddy site
  sends the internet to, on the Unraid system's address. Without that link (the Unraid address is a name, no firewall is
  read, the container uses host networking and publishes no port) the guidance's fallback decides: public only when the
  Unraid address is publicly routable and the container publishes a port on it.

Each answer carries the evidence that decided it, which the findings and the pages quote ("port 443 is forwarded by firewall
opn").
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Exposure:
    exposed: bool
    why: str            # the evidence, one short sentence fragment
    data: bool = True   # decided from data DaemonSight holds (False: the guidance's best-effort rule decided)

    @property
    def label(self) -> str:
        return "public" if self.exposed else "internal"


WIDE = ("", "0.0.0.0", "::", "[::]", "*")
FIREWALL = Exposure(True, "a firewall is a network device, which CISA's guidance treats as public", False)


def _public_ip(value) -> str | None:
    from .. import outside
    return outside.sendable(value) if value else None


def _list(items: list[str], more: int = 0) -> str:
    return ", ".join(items) + (f" and {more} more" if more else "")


def _forward_text(v: dict) -> str:
    how = f"forward {v['name']!r}" if v["how"] == "forward" else f"Caddy site {v['name']}"
    return f"{how} on {v['fw']}"


def unknown(addresses: list[str | None], what: str = "its address") -> Exposure:
    """The guidance's best-effort rule: public when the system has a publicly routable address, otherwise internal."""
    for a in addresses:
        if _public_ip(a):
            return Exposure(True, f"{what} {a} is publicly routable (exposure data is missing)", False)
    return Exposure(False, "exposure data is missing and it has no publicly routable address", False)


# --- a host with a collector -----------------------------------------------------------------------------------------------

def host_exposure(conn, cfg, host: str) -> Exposure:
    """`cfg` is the config as that host sees it (web.views.host_config: its expected ports and provider allow list)."""
    from .. import db, findings as rules
    from ..remote import opnsense as opn_mod
    snaps = db.get_snapshots(conn, host)
    ports = snaps["ports"].data if snaps.get("ports") and snaps["ports"].data and snaps["ports"].data.get("available") is not False else None
    row = conn.execute("SELECT address FROM hosts WHERE id = ?", (host,)).fetchone()
    if ports is None:
        return unknown([row["address"] if row else None])
    pub = rules.host_is_public(ports)
    eph = (32768, 60999)
    st = snaps.get("settings")
    if st and st.data and len(st.data.get("eph") or []) == 2:
        eph = (int(st.data["eph"][0]), int(st.data["eph"][1]))
    reasons: list[str] = []
    for r in rules.public_listeners(snaps, {"eph": eph}):
        if not rules.upstream_allows(cfg, r["proto"], r["port"]):
            continue
        fw = rules.firewall_state(snaps, r["proto"], r["port"], r["addresses"])
        if fw["state"] in ("blocked", "forwarded"):
            continue
        who = f" ({r['process']})" if r.get("process") else ""
        reasons.append(f"port {r['port']}/{r['proto']}{who} listens on a public address and the host firewall lets it through")
    if pub:
        docker = (snaps.get("docker").data if snaps.get("docker") and snaps["docker"].data else None) or {}
        for c in docker.get("containers", []):
            if c.get("status") != "running":
                continue
            for p in c.get("ports", []):
                if p.get("host_ip") in WIDE and isinstance(p.get("host_port"), int):
                    reasons.append(f"Docker publishes port {p['host_port']}/{p['proto']} ({c['name']}) on all interfaces of a host with a public address")
    own_ips = {a["ip"] for a in ports.get("addresses", []) if isinstance(a, dict) and a.get("ip")}
    through = opn_mod.reach_by_listener(conn, own_ips) if own_ips else {}
    for (proto, port), via in sorted(through.items()):
        reasons.append(f"port {port}/{proto} is reached from the internet through {_forward_text(via[0])}")
    if reasons:
        return Exposure(True, reasons[0] + (f" (and {len(reasons) - 1} more)" if len(reasons) > 1 else ""))
    if pub:
        return Exposure(False, "it has a public address, but no listener, published port or forward lets the internet reach it")
    return Exposure(False, "no listener is reachable from the internet and no firewall forward leads to it")


# --- a container image -------------------------------------------------------------------------------------------------------

def _address_of(conn, host: str) -> str | None:
    from urllib.parse import urlsplit
    row = conn.execute("SELECT url FROM remotes WHERE id = ?", (host,)).fetchone()
    return urlsplit(row["url"] or "").hostname if row else None


def image_exposures(conn, host: str, data: dict | None, unraid_docker: dict | None) -> dict[str, Exposure]:
    """image id -> Exposure for every image a container of the Unraid system `host` uses. `data` is the system's stored Docker
    summary (`containers` with name, image_id and state), `unraid_docker` what the Unraid API listed (`containers` with their
    published `ports`: ip, public, type). The Unraid system's address is the host of its URL."""
    from ..remote import opnsense as opn_mod
    address = _address_of(conn, host)
    from ..outside import sendable
    ip = sendable(address) if address else None
    literal = False
    if address:
        import ipaddress
        try:
            ipaddress.ip_address(address.split("%", 1)[0])
            literal = True
        except ValueError:
            pass
    through = opn_mod.reach_by_listener(conn, {address}) if literal else {}
    ports_by_name = {c.get("name"): c.get("ports") or [] for c in (unraid_docker or {}).get("containers", [])}
    by_image: dict[str, list[dict]] = {}
    for c in (data or {}).get("containers", []):
        if c.get("image_id") and c.get("state") == "running":
            by_image.setdefault(c["image_id"], []).append(c)
    out: dict[str, Exposure] = {}
    for iid in {e["image_id"] for e in (data or {}).get("image_packages") or []}:
        cs = by_image.get(iid, [])
        published: list[tuple[str, int, str]] = []     # (proto, host port, container)
        for c in cs:
            for p in ports_by_name.get(c["name"], []):
                if isinstance(p.get("public"), int) and (p.get("ip") in WIDE or p.get("ip") == address):
                    published.append(((p.get("type") or "TCP").lower(), p["public"], c["name"]))
        hits = [(proto, port, name, through[(proto, port)][0]) for proto, port, name in published if (proto, port) in through]
        if hits:
            proto, port, name, via = hits[0]
            more = f" (and {len(hits) - 1} more)" if len(hits) > 1 else ""
            out[iid] = Exposure(True, f"port {port}/{proto} of container {name} is reached from the internet through {_forward_text(via)}{more}")
        elif not cs:
            out[iid] = Exposure(False, "no running container uses it", False)
        elif not published:
            out[iid] = Exposure(False, "its running containers publish no port (a container on the host network lists none, which cannot be checked)", False)
        elif ip and literal:
            out[iid] = Exposure(True, f"it publishes port {published[0][1]}/{published[0][0]} on {address}, which is publicly routable (no port forward was needed)", False)
        elif through or literal:
            out[iid] = Exposure(False, f"no firewall port forward or Caddy site leads to its published ports ({_list([f'{p}/{t}' for t, p, _n in published[:3]], max(len(published) - 3, 0))})")
        else:
            out[iid] = Exposure(False, "the system's address is a name, so no firewall forward can be matched, and it has no publicly routable address", False)
    return out


def firewall_exposure() -> Exposure:
    return FIREWALL


# --- a container image on a host with a collector -----------------------------------------------------------------------------

LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _is_loopback(ip: str | None) -> bool:
    import ipaddress
    if ip in LOOPBACK:
        return True
    try:
        return ipaddress.ip_address(str(ip).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _ok_data(snaps: dict, name: str) -> dict | None:
    s = snaps.get(name)
    return s.data if s and s.data and s.data.get("available") is not False else None


def _listen_port(spec: str) -> tuple[str, int] | None:
    """(host part, port) of a Caddy listen address (":443", "0.0.0.0:443", "[::1]:8080", "tcp/:443"); None for a Unix socket or a
    form that is not one."""
    if "/" in spec.split(":", 1)[0]:
        spec = spec.split("/", 1)[1]
    if spec.startswith("unix"):
        return None
    host, sep, port = spec.rpartition(":")
    if not sep or not port.isdigit():
        return None
    return host.strip("[]"), int(port)


def _service_name(container: dict) -> str | None:
    """The Docker Compose service a container is likely to be, from its name "<project>-<service>-<n>" (Compose v2). A Caddy that
    proxies to `app:8080` on a Compose network names the service, not the container. An inference, used only to match a Caddy
    upstream."""
    project, name = container.get("project"), container.get("name") or ""
    if not project or not name.startswith(project + "-"):
        return None
    rest = name[len(project) + 1:]
    head, _, tail = rest.rpartition("-")
    return head if head and tail.isdigit() else rest or None


def _site_audience(site: dict) -> str:
    """"internet" or "lan" for a Caddy site, from its access list (`remote_ip` ranges, collector/sources/caddy.py): no list is anyone; a
    list of private ranges only is LAN-only (the same test as opnsense_rules._lan_only); any other list still lets internet
    addresses in."""
    import ipaddress
    allow = site.get("allow") or []
    if not allow:
        return "internet"
    try:
        if all(not ipaddress.ip_network(str(r).strip(), strict=False).is_global for r in allow):
            return "lan"
    except ValueError:
        pass
    return "internet"


def collector_image_exposures(conn, cfg, host: str, data: dict | None) -> dict[str, Exposure]:
    """image id -> Exposure for every image in a collector host's stored image data (`data`, hub.merge_docker_images). `cfg` is
    the config as that host sees it (web.views.host_config: its provider allow list). Everything comes from what the hub holds for
    the host: its Docker snapshot (published ports), its listeners and addresses, its firewall, its Caddy sites, and the hub's
    OPNsense systems. Without the host's ports and Docker data the guidance's best-effort rule decides (`unknown`)."""
    from .. import db, findings as rules
    from ..collector.sources.caddy import is_local
    from ..remote import opnsense as opn_mod
    snaps = db.get_snapshots(conn, host)
    ids = [e["image_id"] for e in (data or {}).get("image_packages") or []]
    row = conn.execute("SELECT address FROM hosts WHERE id = ?", (host,)).fetchone()
    ports, docker, caddy = _ok_data(snaps, "ports"), _ok_data(snaps, "docker"), _ok_data(snaps, "caddy")
    caddy_state = "unread" if snaps.get("caddy") is None else "read" if caddy else "none"      # "none": no Caddy on the host
    public_own = [a["ip"] for a in (ports or {}).get("addresses", []) if isinstance(a, dict) and a.get("scope") == "public"]
    address = row["address"] if row else None
    if ports is None or docker is None:
        return {i: unknown([address, *public_own]) for i in ids}
    pub = rules.host_is_public(ports)
    own = {a["ip"] for a in ports.get("addresses", []) if isinstance(a, dict) and a.get("ip")}
    through = opn_mod.reach_by_listener(conn, own) if own else {}
    published = {(p.get("proto"), p.get("host_port")) for c in docker.get("containers", []) for p in c.get("ports", [])}
    by_name = {c.get("name"): c for c in docker.get("containers", [])}
    listeners = ports.get("listeners", [])

    def binding_reason(proto: str, port: int, ip: str | None, who: str) -> str | None:
        """Why the internet reaches this host port, or None. The provider's allow list can rule it out."""
        if _is_loopback(ip) or not rules.upstream_allows(cfg, proto, port):
            return None
        if ip in WIDE and pub:
            return f"port {port}/{proto} of {who} is published on all interfaces of a host with a public address"
        if ip not in WIDE and _public_ip(ip):
            return f"port {port}/{proto} of {who} is published on the public address {ip}"
        if (proto, port) in through and (ip in WIDE or ip in own):
            return f"port {port}/{proto} of {who} is reached from the internet through {_forward_text(through[(proto, port)][0])}"
        return None

    def caddy_reaches(site: dict) -> str | None:
        """Why the internet can reach this Caddy site's listener, or None: a Docker-published port or a public listener on a host
        with a public address, or an OPNsense forward to it."""
        for spec in site.get("listen") or [":443", ":80"]:
            hp = _listen_port(spec)
            if hp is None or _is_loopback(hp[0]) or not rules.upstream_allows(cfg, "tcp", hp[1]):
                continue
            port = hp[1]
            if ("tcp", port) in published and pub:
                return f"Caddy is published on port {port}/tcp of a host with a public address"
            if ("tcp", port) in through:
                return f"port {port}/tcp is reached from the internet through {_forward_text(through[('tcp', port)][0])}"
            for r in listeners:
                if r["proto"] == "tcp" and r["port"] == port and rules.reach(r, pub) == "internet" \
                        and rules.firewall_state(snaps, "tcp", port, r["addresses"])["state"] not in ("blocked", "forwarded"):
                    return f"Caddy listens on port {port}/tcp, which the internet can reach"
        return None

    by_image: dict[str, list[dict]] = {}
    for c in (data or {}).get("containers", []):
        if c.get("image_id") and c.get("state") == "running":
            by_image.setdefault(c["image_id"], []).append(c)
    out: dict[str, Exposure] = {}
    for iid in ids:
        names = [c["name"] for c in by_image.get(iid, [])]
        if not names:
            out[iid] = Exposure(False, "no running container uses it", False)
            continue
        reasons: list[str] = []
        bound: set[str] = set()                # what the containers bind, for the explanation when nothing exposes them
        proxied = seen = False
        for name in names:
            dc = by_name.get(name)
            if dc is None:
                continue
            seen = True
            who = f"container {name}"
            bindings = [(p.get("proto") or "tcp", p.get("host_port"), p.get("host_ip") or "0.0.0.0") for p in dc.get("ports", [])
                        if isinstance(p.get("host_port"), int)]
            for r in listeners:                # a container on the host network publishes nothing; its listeners are its bindings
                o = r.get("owner") or {}
                if o.get("kind") == "container" and o.get("id") == dc.get("id"):
                    bindings += [(r["proto"], r["port"], a) for a in r.get("addresses") or []]
            for proto, port, ip in bindings:
                bound.add(f"{ip}:{port}/{proto}")
                why = binding_reason(proto, port, ip, who)
                if why:
                    reasons.append(why)
            if not caddy:
                continue
            svc = _service_name(dc)
            tcp_ports = {port for proto, port, _ip in bindings if proto == "tcp"}
            for site in caddy.get("sites", []):
                if _site_audience(site) != "internet":
                    continue
                for h in site.get("handlers", []):
                    for u in h.get("upstreams", []) if h.get("kind") == "proxy" else []:
                        on_host = bool(u.get("port")) and u["port"] in tcp_ports and is_local(u.get("host"), own)
                        on_network = bool(u.get("host")) and u["host"] in (name, svc)
                        if not (on_host or on_network):
                            continue
                        proxied = True
                        via = caddy_reaches(site)
                        if via:
                            reasons.append(f"Caddy site {site['host']} proxies to {who} ({u.get('text')}) and {via}")
        if reasons:
            out[iid] = Exposure(True, reasons[0] + (f" (and {len(reasons) - 1} more)" if len(reasons) > 1 else ""))
        elif not seen or (not bound and not proxied and caddy_state == "unread"):
            out[iid] = unknown([address, *public_own])          # the host's Caddy sites were never read: cannot tell
        else:
            shown = sorted(bound)
            parts = [f"it publishes {_list(shown[:3], max(len(shown) - 3, 0))}, which the internet cannot reach (loopback, a host with no "
                     "public address, or blocked by the provider's allow list)" if bound else "it publishes no port"]
            if proxied:
                parts.append("a Caddy site proxies to it, but the internet cannot reach Caddy")
            elif caddy_state == "read":
                parts.append("no internet-facing Caddy site on this host proxies to it")
            elif caddy_state == "none":
                parts.append("the host has no Caddy")
            out[iid] = Exposure(False, "; ".join(parts))
    return out
