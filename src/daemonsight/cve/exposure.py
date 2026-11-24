"""Whether a system is publicly exposed: the first variable of CISA BOD 26-04's Table 1 (cve/priority.py).

The implementation guidance says what to do when exposure data is missing: treat an asset with a publicly routable IP address
(IPv4 or IPv6) as public, or one whose asset type tag is "network" (https://www.cisa.gov/news-events/directives/
bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk, "best-effort logic"). Otherwise it is internal.
DaemonSight has real exposure data for most of what it watches, so that rule is the fallback, not the first choice:

* A host with a collector: the listeners the collector reports that the internet can reach (a public address or a wildcard
  bind on a host with one, past the host firewall and the provider's allow list), Docker's published ports on a public
  address, and the port forwards and Caddy sites of the hub's OPNsense systems that lead to the host's addresses. This is
  what the Exposure page shows (findings.public_listeners, remote/opnsense.reach_by_listener).
* An OPNsense firewall: always exposed. It is a network device, which the guidance treats as public, and its own interfaces
  face the internet.
* A container image: exposed when a running container from it publishes a port that an OPNsense port forward or Caddy site
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
