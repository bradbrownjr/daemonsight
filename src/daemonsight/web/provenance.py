"""Where each fact came from, and where to look at it yourself.

Every card and row can carry a "source" panel built here:
  read     how DaemonSight read it (API call, file, socket)
  entries  places to check it by hand:
             {"kind": "file", "label", "value"}   a path, with a copy button
             {"kind": "cmd",  "label", "value"}   a shell command, with a copy button
             {"kind": "text", "label", "value"}   text to copy, not a command to run
             {"kind": "plain", "label", "value"}  a short fact, no copy button
             {"kind": "link", "label", "href", "text"}  a page in DaemonSight
             {"kind": "url",  "label", "href", "text"}  another web UI ([links] in the config)

Commands only read; nothing here suggests changing anything.
"""

from __future__ import annotations

import shlex

from ..config import Config

SECTION_READ = {
    "system": "psutil: cpu_percent, virtual_memory, disk_usage and net_io_counters, which read /proc",
    "systemd": "systemd over D-Bus: Manager.ListUnitsByPatterns, then Properties.GetAll on each unit",
    "ports": "psutil.net_connections(); the owner comes from /proc/<pid>/cgroup",
    "docker": "Docker Engine API on the Docker socket, GET requests only",
    "caddy": "Caddy admin API: GET /config/ and GET /reverse_proxy/upstreams",
    "fail2ban": "fail2ban control socket: status, status <jail> and get <jail> commands",
    "firewall": "iptables-save and ip6tables-save, and nft -j list ruleset for native nft tables",
    "packages": "apt-get -s dist-upgrade (a simulation), apt-mark showhold, dpkg-query, /var/run/reboot-required and, if installed, needrestart -b -r l",
    "findings": "DaemonSight's rules, applied to the latest reading from each source",
    "events": "DaemonSight compares each new reading with the one before it",
}

SECTION_TITLE = {
    "system": "System health", "systemd": "systemd services", "ports": "Listening sockets",
    "docker": "Containers", "caddy": "Caddy", "fail2ban": "fail2ban", "firewall": "Firewall", "packages": "Packages",
    "findings": "Findings", "events": "Recent changes",
}


def cmd(label: str, value: str) -> dict:
    return {"kind": "cmd", "label": label, "value": value}


def file(label: str, value: str) -> dict:
    return {"kind": "file", "label": label, "value": value}


def text(label: str, value: str) -> dict:
    return {"kind": "text", "label": label, "value": value}


def plain(label: str, value: str) -> dict:
    return {"kind": "plain", "label": label, "value": value}


def link(label: str, href: str, text: str) -> dict:
    return {"kind": "link", "label": label, "href": href, "text": text}


def q(value: str) -> str:
    return shlex.quote(value)


def _web_ui(cfg: Config, source: str) -> list[dict]:
    url = (cfg.links or {}).get(source)
    if not url or not url.startswith(("https://", "http://")):
        return []
    return [{"kind": "url", "label": "Web UI", "href": url, "text": url}]


def caddy_curl(admin: str | None, path: str) -> str:
    admin = admin or "localhost:2019"
    if admin.startswith("unix/"):
        return f"curl -s --unix-socket {q(admin[5:])} http://localhost{path}"
    return f"curl -s {q('http://' + admin.removeprefix('tcp/') + path)}"


def section(source: str, cfg: Config, extra: dict | None = None) -> dict:
    """The panel for a whole card."""
    extra = extra or {}
    entries: list[dict] = []
    if source == "system":
        entries = [cmd("Load", "uptime"), cmd("Memory", "free -h"), cmd("Disks", "df -h"),
                   cmd("Traffic per interface", "ip -s link")]
    elif source == "systemd":
        entries = [cmd("Running services", "systemctl list-units --type=service"),
                   cmd("Failed units", "systemctl --failed")]
    elif source == "ports":
        entries = [cmd("All listeners with owners", "sudo ss -ltnup")]
    elif source == "docker":
        entries = [file("Socket", cfg.collector.docker_socket), cmd("Containers", "docker ps -a")]
    elif source == "caddy":
        admin = extra.get("admin")
        entries = [cmd("Live config", caddy_curl(admin, "/config/") + " | python3 -m json.tool"),
                   cmd("Upstream health", caddy_curl(admin, "/reverse_proxy/upstreams")),
                   cmd("Which Caddyfile the service loads", "systemctl cat caddy")]
    elif source == "fail2ban":
        entries = [file("Socket", cfg.collector.fail2ban_socket), cmd("Jails", "sudo fail2ban-client status"),
                   cmd("Jail configuration", "ls /etc/fail2ban/jail.local /etc/fail2ban/jail.d/")]
    elif source == "firewall":
        entries = [cmd("IPv4 rules", "sudo iptables-save"), cmd("IPv6 rules", "sudo ip6tables-save"),
                   cmd("nftables", "sudo nft list ruleset")]
    elif source == "packages":
        entries = [cmd("Pending updates", "apt list --upgradable"), cmd("Held packages", "apt-mark showhold")]
    elif source == "findings":
        entries = [{"kind": "url", "label": "Rules", "text": "Rule list in DESIGN.md",
                    "href": "https://github.com/bradbrownjr/daemonsight/blob/main/docs/DESIGN.md#findings"}]
    return {"title": SECTION_TITLE.get(source, source), "read": SECTION_READ.get(source),
            "entries": entries + _web_ui(cfg, source)}


PACKAGES_PARTS = {
    "security": ("Security updates", "apt-get -s dist-upgrade: Inst lines whose origin is a security archive",
                 [cmd("Pending updates", "apt list --upgradable"),
                  cmd("Where one comes from", "apt-cache policy <package>")]),
    "other": ("Other updates", "apt-get -s dist-upgrade: the remaining Inst lines",
              [cmd("Pending updates", "apt list --upgradable")]),
    "held": ("Held packages", "apt-mark showhold", [cmd("Held packages", "apt-mark showhold")]),
    "reboot": ("Reboot and restarts",
               "/var/run/reboot-required, dpkg-query for linux-image packages, and needrestart -b -r l",
               [file("Reboot flag", "/var/run/reboot-required.pkgs"),
                cmd("Why a reboot is needed", "cat /var/run/reboot-required.pkgs"),
                cmd("Running kernel", "uname -r"), cmd("Installed kernels", "dpkg -l 'linux-image-*'"),
                cmd("Services on old libraries", "sudo needrestart -b -r l")]),
    "lists": ("Package lists", "The newest modification time of /var/lib/apt/lists/*InRelease",
              [cmd("Newest lists", "ls -lt /var/lib/apt/lists/*InRelease | head -3"),
               cmd("apt's timers", "systemctl list-timers 'apt-daily*'")]),
}


def packages(part: str) -> dict:
    title, read, entries = PACKAGES_PARTS[part]
    return {"title": title, "read": read, "entries": list(entries)}


def unit(u: dict) -> dict:
    name = u["name"]
    entries = []
    if u.get("fragment"):
        entries.append(file("Unit file", u["fragment"]))
    for d in u.get("dropins") or []:
        entries.append(file("Drop-in", d))
    entries += [cmd("Status", f"systemctl status {q(name)}"),
                cmd("Log", f"journalctl -u {q(name)} -n 100 --no-pager"),
                cmd("Unit with drop-ins", f"systemctl cat {q(name)}")]
    return {"title": name, "read": "D-Bus Properties.GetAll on the unit and its service", "entries": entries}


def container(c: dict) -> dict:
    name = c["name"]
    entries = []
    if c.get("compose_dir"):
        entries.append(file("Compose folder", c["compose_dir"]))
    for f in c.get("compose_files") or []:
        entries.append(file("Compose file", f))
    entries += [cmd("Details", f"docker inspect {q(name)}"),
                cmd("Log", f"docker logs --tail 100 {q(name)}")]
    if c.get("project"):
        entries.append(cmd("Compose project", f"docker compose -p {q(c['project'])} ps"))
    return {"title": f"Container {name}", "read": "Docker API: GET /containers/{id}/json, /stats, /logs",
            "entries": entries}


def _listen_port(addr: str) -> tuple[str, int] | None:
    """('tcp'|'udp', port) from a Caddy listen string such as ':443', '[::]:2083' or 'udp/:443'."""
    net = "tcp"
    if "/" in addr:
        net, addr = addr.split("/", 1)
    if net not in ("tcp", "udp", "tcp4", "tcp6", "udp4", "udp6"):
        return None
    port = addr.rsplit(":", 1)[-1].split("-")[0]
    return ("udp" if net.startswith("udp") else "tcp", int(port)) if port.isdigit() else None


def caddy_sites_on(proto: str, port: int, caddy: dict | None) -> list[str]:
    """Hosts of the Caddy sites served on this port, in config order."""
    hosts: list[str] = []
    for srv in (caddy or {}).get("servers", []):
        if any(_listen_port(a) == (proto, port) for a in srv.get("listen") or []):
            for site in (caddy or {}).get("sites", []):
                if site["server"] == srv["name"] and site["host"] not in hosts:
                    hosts.append(site["host"])
    return hosts


CADDY_SITE_LIMIT = 8


def _is_caddy(r: dict) -> bool:
    owner = r.get("owner") or {}
    return (r.get("process") or "") == "caddy" or (
        owner.get("kind") == "unit" and str(owner.get("id") or "").startswith("caddy."))


def listener(r: dict, names: dict | None = None, caddy: dict | None = None) -> dict:
    from ..findings import anchor
    from .views import fmt_ago  # views imports this module, so import it late
    flag = "-ltnp" if r["proto"] == "tcp" else "-lunp"
    entries = [cmd("Socket and owner", f"sudo ss {flag} 'sport = :{r['port']}'")]
    owner = r.get("owner") or {}
    if owner.get("kind") == "unit" and owner.get("id"):
        entries.append(link("Owned by", f"/services?units=all#unit-{owner['id']}", owner["id"]))
    elif owner.get("kind") == "container" and owner.get("id"):
        name = (names or {}).get(owner["id"], owner["id"][:12])
        entries.append(link("Owned by", f"/services#ctr-{name}", f"container {name}"))
    if r.get("cmdline"):
        entries.append(text("Command", r["cmdline"]))
    if r.get("exe"):
        entries.append(file("Program", r["exe"]))
    if r.get("user"):
        entries.append(plain("Runs as", r["user"]))
    if r.get("started"):
        entries.append(plain("Started", fmt_ago(r["started"])))
    if r.get("pid"):
        entries.append(file("Process", f"/proc/{r['pid']}/"))
    if caddy and _is_caddy(r):
        hosts = caddy_sites_on(r["proto"], r["port"], caddy)
        for h in hosts[:CADDY_SITE_LIMIT]:
            entries.append(link("Caddy site", f"/routes#{anchor('site', h)}", h))
        if len(hosts) > CADDY_SITE_LIMIT:
            entries.append(link("More Caddy sites", "/routes", f"{len(hosts) - CADDY_SITE_LIMIT} more"))
    return {"title": f"Port {r['port']}/{r['proto']}",
            "read": "psutil.net_connections(); owner from /proc/<pid>/cgroup", "entries": entries}


def caddy_site(site: dict, admin: str | None) -> dict:
    srv = site["server"]
    entries = [cmd("This server's routes",
                   caddy_curl(admin, f"/config/apps/http/servers/{srv}/routes") + " | python3 -m json.tool"),
               cmd("Which Caddyfile the service loads", "systemctl cat caddy")]
    for h in site.get("handlers", []):
        for u in h.get("upstreams", []):
            if u.get("port"):
                entries.append(link("Upstream", f"/exposure#port-{u['port']}-tcp", u["text"]))
    return {"title": site["host"], "read": f"Caddy admin API, server {srv}", "entries": entries}


def jail(j: dict) -> dict:
    name = j["name"]
    entries = [cmd("Status", f"sudo fail2ban-client status {q(name)}"),
               cmd("Where it is defined", f"sudo grep -rln {q('^[[]' + name + '[]]')} /etc/fail2ban/")]
    for lp in j.get("logpaths", []):
        entries.append(file("Watches", lp["path"]))
    if j.get("journalmatch"):
        matches = " ".join(q(m) for m in j["journalmatch"] if m != "+")
        entries.append(cmd("Journal it reads", f"journalctl {matches} -n 50 --no-pager"))
    entries.append(cmd("Bans with times", f"sudo fail2ban-client get {q(name)} banip --with-time"))
    return {"title": f"Jail {name}", "read": f"fail2ban control socket: status {name}, get {name} <setting>",
            "entries": entries}


def chain(c: dict) -> dict:
    fam, table, name = c["family"], c["table"], c["chain"]
    if fam in ("ip", "ip6") and table in ("filter", "nat", "raw", "mangle"):
        tool = "iptables" if fam == "ip" else "ip6tables"
        entries = [cmd("Rules", f"sudo {tool} -t {table} -S {name}"),
                   cmd("With counters", f"sudo {tool} -t {table} -L {name} -nv")]
    else:
        entries = [cmd("Rules", f"sudo nft list chain {fam} {table} {name}")]
    return {"title": f"{fam} {table} {name}", "read": SECTION_READ["firewall"], "entries": entries}


def forward(f: dict) -> dict:
    tool = "iptables" if f.get("family_raw", "ip") == "ip" else "ip6tables"
    return {"title": f"Forward to {f['to']}", "read": "The nat table's prerouting chain, from iptables-save or nft",
            "entries": [cmd("NAT rules", f"sudo {tool} -t nat -S PREROUTING"),
                        cmd("With counters", f"sudo {tool} -t nat -L PREROUTING -nv")]}


PAGE_NAME = {"/": "Overview", "/exposure": "Exposure", "/routes": "Routes", "/services": "Services",
             "/fail2ban": "fail2ban", "/packages": "Packages"}

RULE_SOURCE = {"svc": "systemd", "ctr": "docker", "expose": "ports", "route": "caddy", "caddy": "caddy",
               "jail": "fail2ban", "firewall": "firewall", "pkg": "packages", "sys": "system", "collector": "events"}


def finding(rule: str, link_href: str | None) -> dict:
    src = RULE_SOURCE.get(rule.split(".", 1)[0], "findings")
    entries = [{"kind": "url", "label": "Rule", "text": f"{rule} in DESIGN.md",
                "href": "https://github.com/bradbrownjr/daemonsight/blob/main/docs/DESIGN.md#findings"}]
    if link_href:
        page = PAGE_NAME.get(link_href.split("#", 1)[0].split("?", 1)[0], link_href)
        entries.append(link("Seen on", link_href, f"{page} page"))
    return {"title": rule, "read": SECTION_READ.get(src), "entries": entries}
