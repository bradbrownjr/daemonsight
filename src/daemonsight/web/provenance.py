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
    "opnsense": "The OPNsense REST API, read by the hub with GET requests only (a dedicated user's API key)",
    "cve": "The hub matches this host's installed packages against the Debian security tracker, EPSS scores and "
           "CISA's KEV list; the host downloads nothing",
    "outside": "Shodan, asked by the hub about this host's public addresses: its free InternetDB, or the Shodan API "
               "with the owner's key. Only the IP address is sent (the API also gets the key), with a generic "
               "User-Agent, DaemonSight/<version>. The answer is Shodan's scan data, up to a week old, compared "
               "with what DaemonSight reads from inside the host",
    "unraid": "The hub's read-only GraphQL queries to the Unraid API, checked against DaemonSight's Unraid rules",
    "remote": "The hub's last attempt to read this system's API",
    "findings": "DaemonSight's rules, applied to the latest reading from each source",
    "events": "DaemonSight compares each new reading with the one before it",
}


def outside_address(ip: str, row: dict | None, source: str = "internetdb") -> dict:
    """The panel for one address in "Seen from outside": the exact request, and how to repeat it. The Shodan API's
    request shows key=YOUR_KEY: the real key is never put in a panel."""
    from .. import outside, shodan
    from .views import fmt_when
    if source == "shodan":
        shown = f"{shodan.HOST_URL}{ip}?key=YOUR_KEY"
        entries = [plain("Request", shown),
                   cmd("Check it yourself (put your key where it says YOUR_KEY)", f"curl -s {q(shown)}"),
                   plain("Sent", f"The IP address and your API key, over HTTPS to api.shodan.io only, with the User-Agent "
                                 f"{outside.USER_AGENT}. The key is saved on the hub, never shown, and removed from every "
                                 "log line and error"),
                   plain("Cost", "Host lookups use no query credits (Shodan's API book); the limit is 1 request a second"),
                   plain("Updated", "Shodan crawls the internet at least once a week"),
                   plain("Terms", outside.SHODAN_TERMS),
                   {"kind": "url", "label": "About the host lookup", "text": shodan.DOCS, "href": shodan.DOCS}]
        read = ("The hub asks the Shodan API about this address once per refresh, with the key saved on the Settings "
                "page, and keeps the answer. HTTP 404 means Shodan has no record of the address; 401 or 403 means "
                "the key was refused. The reply is untrusted text: it is checked for shape and size, stored as data, "
                "and shown escaped")
    else:
        entries = [{"kind": "url", "label": "Request", "text": outside.URL + ip, "href": outside.URL + ip},
                   cmd("Check it yourself", f"curl -s {q(outside.URL + ip)}"),
                   plain("Sent", f"Only the IP address, with the User-Agent {outside.USER_AGENT}"),
                   plain("Updated", "InternetDB updates once a week; it returns no banners"),
                   plain("Terms", outside.TERMS),
                   {"kind": "url", "label": "About InternetDB", "text": outside.DOCS, "href": outside.DOCS}]
        read = ("The hub asks InternetDB about this address once per refresh and keeps the answer. "
                "HTTP 404 means Shodan has no record of the address. The reply is untrusted text: it is checked "
                "for shape and size, stored as data, and shown escaped")
    if row and row.get("fetched_at"):
        entries.append(plain("Answer fetched", fmt_when(row["fetched_at"])))
    return {"title": f"Shodan's view of {ip}", "read": read, "entries": entries}


def outside_port(ip: str, port: int, lines: list[str], source: str = "internetdb") -> dict:
    from .. import outside, shodan
    entries = [text("What DaemonSight knows", ln) for ln in lines]
    if source == "shodan":
        shown = f"{shodan.HOST_URL}{ip}?key=YOUR_KEY"
        entries += [cmd("Who listens here", f"sudo ss -ltnup 'sport = :{port}'"),
                    cmd("Shodan's record (put your key where it says YOUR_KEY)", f"curl -s {q(shown)}")]
        read = "Shodan's scan data (the Shodan API), compared with this host's own readings"
    else:
        entries += [cmd("Who listens here", f"sudo ss -ltnup 'sport = :{port}'"),
                    cmd("Shodan's record", f"curl -s {q(outside.URL + ip)}")]
        read = "Shodan's scan data (InternetDB), compared with this host's own readings"
    return {"title": f"Port {port} on {ip}", "read": read, "entries": entries}


def cve_packages() -> dict:
    return {"title": "Packages with CVEs",
            "read": "The hub compares each installed source package and version with the Debian security tracker "
                    "(Debian version order), for this host's release only",
            "entries": [cmd("Debian's own scanner (sudo apt install debsecan)",
                            "debsecan --suite $(. /etc/os-release && echo $VERSION_CODENAME) --only-fixed"),
                        cmd("Installed source versions",
                            "dpkg-query -W -f '${source:Package} ${source:Version}\\n' | sort -u"),
                        url("Debian security tracker", "https://security-tracker.debian.org/tracker/",
                            "security-tracker.debian.org")]}


def cve_inventory() -> dict:
    return {"title": "Package list",
            "read": "The collector's dpkg-query output, sent with its uploads when it changes (and once a day)",
            "entries": [cmd("The list the collector reads",
                            "dpkg-query -W -f '${db:Status-Abbrev} ${source:Package} ${source:Version} ${Package} "
                            "${Version}\\n'")]}


def cve_feed(feed, row) -> dict:
    entries = [{"kind": "url", "label": "Source", "text": feed.url, "href": feed.url},
               {"kind": "url", "label": "About the data", "text": feed.docs, "href": feed.docs},
               plain("Terms", feed.terms),
               cmd("Check it yourself", f"curl -sI {q(feed.url)}")]
    if row is not None and row["last_modified"]:
        entries.append(plain("Last-Modified the hub saw", row["last_modified"]))
    return {"title": feed.title,
            "read": "Downloaded by the hub, not by this host, with If-None-Match and If-Modified-Since so an "
                    "unchanged file costs one small request. The request carries only a generic User-Agent, "
                    "DaemonSight/<version>",
            "entries": entries}


PACKAGES_READ_DNF = ("dnf check-upgrade -C --json (and --security), rpm -q, dnf versionlock list, "
                     "dnf needs-restarting -C, and the cached metadata under /var/cache/libdnf5; "
                     "nothing is downloaded or installed")

SECTION_TITLE = {
    "system": "System health", "systemd": "systemd services", "ports": "Listening sockets",
    "docker": "Containers", "caddy": "Caddy", "fail2ban": "fail2ban", "firewall": "Firewall", "packages": "Packages",
    "findings": "Findings", "events": "Recent changes", "cve": "Vulnerabilities",
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


def url(label: str, href: str, text: str) -> dict:
    return {"kind": "url", "label": label, "href": href, "text": text}


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
    elif source == "packages" and extra.get("backend") == "dnf":
        entries = [cmd("Pending updates", "dnf check-upgrade -C"), cmd("Held packages", "dnf versionlock list")]
    elif source == "packages":
        entries = [cmd("Pending updates", "apt list --upgradable"), cmd("Held packages", "apt-mark showhold")]
    elif source == "findings":
        entries = [{"kind": "url", "label": "Rules", "text": "Rule list in DESIGN.md",
                    "href": "https://github.com/bradbrownjr/daemonsight/blob/main/docs/DESIGN.md#findings"}]
    read = PACKAGES_READ_DNF if source == "packages" and extra.get("backend") == "dnf" else SECTION_READ.get(source)
    return {"title": SECTION_TITLE.get(source, source), "read": read,
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
    "auto": ("Automatic updates",
             "apt-config shell L APT::Periodic::Update-Package-Lists U APT::Periodic::Unattended-Upgrade, "
             "systemctl is-enabled apt-daily-upgrade.timer, and whether /usr/bin/unattended-upgrade exists",
             [cmd("The two settings", "apt-config dump | grep Periodic"),
              file("Where unattended-upgrades sets them", "/etc/apt/apt.conf.d/20auto-upgrades"),
              cmd("The timer that runs it", "systemctl list-timers 'apt-daily-upgrade*'"),
              cmd("Is it installed?", "dpkg -s unattended-upgrades"),
              cmd("What it did", "sudo tail /var/log/unattended-upgrades/unattended-upgrades.log")]),
}


PACKAGES_PARTS_DNF = {
    "security": ("Security updates", "dnf check-upgrade -C --security --json: upgrades covered by a security advisory",
                 [cmd("Pending security updates", "dnf check-upgrade -C --security"),
                  cmd("Advisories", "dnf advisory list --security"),
                  cmd("Where one comes from", "dnf info <package>")]),
    "other": ("Other updates", "dnf check-upgrade -C --json: the upgrades that no security advisory covers",
              [cmd("Pending updates", "dnf check-upgrade -C")]),
    "held": ("Held packages", "dnf versionlock list", [file("Lock file", "/etc/dnf/versionlock.toml"),
                                                       cmd("Held packages", "dnf versionlock list")]),
    "reboot": ("Reboot and restarts",
               "dnf needs-restarting -C --json (-s for services), and rpm -q kernel-core against uname -r",
               [cmd("Reboot needed?", "sudo dnf needs-restarting -C"),
                cmd("Running kernel", "uname -r"),
                cmd("Installed kernels", "rpm -q kernel-core"),
                cmd("Services on old libraries", "sudo dnf needs-restarting -C -s")]),
    "lists": ("Package lists", "The newest modification time of /var/cache/libdnf5/*/repodata/repomd.xml",
              [cmd("Newest metadata", "ls -lt /var/cache/libdnf5/*/repodata/repomd.xml | head -3"),
               cmd("dnf's timer", "systemctl list-timers 'dnf5-makecache*'"),
               cmd("Refresh now", "sudo dnf makecache")]),
    "auto": ("Automatic updates",
             "rpm -q dnf5-plugin-automatic, systemctl is-enabled dnf5-automatic.timer, and apply_updates and "
             "upgrade_type under [commands] in dnf5 automatic's config files",
             [cmd("Is the plugin installed?", "rpm -q dnf5-plugin-automatic"),
              cmd("The timer", "systemctl list-timers 'dnf5-automatic*'"),
              file("Your settings", "/etc/dnf/automatic.conf"),
              file("Shipped defaults", "/usr/share/dnf5/dnf5-plugins/automatic.conf"),
              cmd("What it did", "journalctl -u dnf5-automatic.service -n 50 --no-pager")]),
}


def packages(part: str, backend: str = "apt") -> dict:
    table = PACKAGES_PARTS_DNF if backend == "dnf" else PACKAGES_PARTS
    title, read, entries = table[part]
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
CADDY_HANDLER_LIMIT = 6
HANDLER_KIND = {"proxy": "Proxy", "files": "Files", "redirect": "Redirect", "respond": "Respond"}


def caddy_handler_text(h: dict) -> str:
    """One Caddy handler as a line, e.g. "Redirect /cpanelwebcall/* → <target>"."""
    kind = HANDLER_KIND.get(h.get("kind"), str(h.get("kind") or "Handle").title())
    paths = " ".join(h.get("paths") or [])
    if h.get("kind") == "proxy":
        to = ", ".join(u.get("text", "") for u in h.get("upstreams") or []) or "dynamic upstream"
    elif h.get("kind") == "files":
        to = h.get("root") or "site root"
    elif h.get("kind") == "redirect":
        to = h.get("target") or ""
    else:
        to = str(h.get("status") or 200)
    return " ".join(x for x in (kind, paths, "→", to) if x)


def caddy_handlers_on(proto: str, port: int, host: str, caddy: dict | None) -> list[str]:
    """What a site does on this port: its handlers, as lines."""
    out: list[str] = []
    servers = {s["name"] for s in (caddy or {}).get("servers", [])
               if any(_listen_port(a) == (proto, port) for a in s.get("listen") or [])}
    for site in (caddy or {}).get("sites", []):
        if site["server"] in servers and site["host"] == host:
            out += [caddy_handler_text(h) for h in site.get("handlers", [])]
    return out


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
            lines = caddy_handlers_on(r["proto"], r["port"], h, caddy)
            for line in lines[:CADDY_HANDLER_LIMIT]:
                entries.append(text("Handles", line))
            if len(lines) > CADDY_HANDLER_LIMIT:
                entries.append(plain("Handles", f"{len(lines) - CADDY_HANDLER_LIMIT} more on the Routes page"))
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
             "/fail2ban": "fail2ban", "/packages": "Packages", "/vulnerabilities": "Vulnerabilities",
             "/disks": "Array & disks", "/containers": "Containers", "/vms": "VMs", "/notifications": "Notifications",
             "/firewall": "Firewall", "/vpn": "VPN", "/network": "Gateways & interfaces"}

RULE_SOURCE = {"unraid": "unraid", "opnsense": "opnsense", "remote": "remote", "svc": "systemd", "ctr": "docker", "expose": "ports", "route": "caddy", "caddy": "caddy",
               "jail": "fail2ban", "firewall": "firewall", "pkg": "packages", "sys": "system", "os": "system", "collector": "events",
               "cve": "cve", "outside": "outside"}


def os_release() -> dict:
    """The panel for the newest stable Unraid release, which is not read from the server's API."""
    from ..remote import release
    return {"title": "Newest stable Unraid release",
            "read": "The Unraid API has no update field. The hub reads Unraid's public release page once a day and "
                    "compares it with the version the API reports. The request is the same for every server, with only "
                    "a generic User-Agent, DaemonSight/<version>; nothing about this server is sent",
            "entries": [cmd("Check it yourself", f"curl -s {q(release.URL)}"),
                        {"kind": "url", "label": "How Unraid's own check works", "text": "UnraidCheck.php in the Unraid API repository",
                         "href": "https://github.com/unraid/api/blob/main/plugin/source/dynamix.unraid.net/usr/local/emhttp/plugins/dynamix.plugin.manager/include/UnraidCheck.php"},
                        plain("Unraid web UI", "Tools, Update OS")]}


def finding(rule: str, link_href: str | None) -> dict:
    if rule == "unraid.os_update":
        panel = os_release()
        panel["entries"].insert(0, {"kind": "url", "label": "Rule", "text": f"{rule} in DESIGN.md",
                                    "href": "https://github.com/bradbrownjr/daemonsight/blob/main/docs/DESIGN.md#findings"})
        return panel
    src = RULE_SOURCE.get(rule.split(".", 1)[0], "findings")
    entries = [{"kind": "url", "label": "Rule", "text": f"{rule} in DESIGN.md",
                "href": "https://github.com/bradbrownjr/daemonsight/blob/main/docs/DESIGN.md#findings"}]
    if link_href:
        page = PAGE_NAME.get(link_href.split("#", 1)[0].split("?", 1)[0], link_href)
        entries.append(link("Seen on", link_href, f"{page} page"))
    return {"title": rule, "read": SECTION_READ.get(src), "entries": entries}


# --- Unraid (read by the hub over GraphQL) -----------------------------------

UNRAID_TITLE = {
    "unraid_system": "System", "unraid_array": "Array and parity", "unraid_disks": "Disks (SMART)",
    "unraid_docker": "Containers", "unraid_folders": "Docker folders", "unraid_vms": "Virtual machines", "unraid_notifications": "Notifications",
    "unraid_ups": "UPS", "unraid_stats": "Container CPU and memory",
}
UNRAID_UI = {
    "unraid_system": "Dashboard", "unraid_array": "Main, Array Operation", "unraid_disks": "Main, click a disk, SMART",
    "unraid_docker": "Docker", "unraid_folders": "Docker (the folders you arranged)", "unraid_vms": "VMs", "unraid_notifications": "the bell icon in the header",
    "unraid_ups": "Settings, UPS Settings",
    "unraid_stats": "Docker, Advanced View, the CPU & Memory load column",
}


def unraid_section(source: str, url: str | None = None, interval: int = 60) -> dict:
    """The panel for one Unraid source: the exact query, how often, and how to look yourself."""
    from ..remote import client, unraid
    query = unraid.QUERY_OF[source]
    tier = unraid.SOURCES[source][2] if source in unraid.SOURCES else unraid.STATS_TIER
    every = f"{max(unraid.SLOW_SECONDS, interval) // 60} min" if tier == unraid.SLOW else f"{interval} s"
    if source == unraid.STATS:
        # A subscription over a WebSocket, not a query: no curl form. It is `docker stats` on the server.
        return {"title": UNRAID_TITLE[source],
                "read": "Unraid's GraphQL API, the one read-only subscription the hub sends, over a WebSocket "
                        f"(graphql-transport-ws, on /graphql): {query}",
                "entries": [plain("Unraid web UI", UNRAID_UI[source]),
                            plain("How often", f"Sampled for a few seconds every {every}: the hub stops as soon as every running container "
                                               f"has reported, and after {int(client.SAMPLE_SECONDS)} s at most. Unraid runs docker stats "
                                               "only while the hub is subscribed"),
                            cmd("The same figures, on the server", "docker stats --no-stream"),
                            plain("What the figures are", "CPU is Docker's reading over about one second, where 100% is one core. "
                                                          "Without a memory limit Docker reports the server's memory as the limit.")]}
    entries = [plain("Unraid web UI", UNRAID_UI[source]), plain("How often", f"The hub reads it every {every}")]
    if url:
        body = '{"query":' + _json_str(query) + "}"
        entries.append(text("The same read-only query, with your Viewer key in $KEY",
                            f"curl -s -H \"x-api-key: $KEY\" -H 'Content-Type: application/json' -d {q(body)} {q(url + '/graphql')}"))
        entries.append(plain("curl and a self-signed certificate", "add --cacert with the certificate you pinned, or -k on a network you trust"))
    return {"title": UNRAID_TITLE[source],
            "read": f"Unraid's GraphQL API, read-only query (never a mutation): {query}",
            "entries": entries}


def _json_str(value: str) -> str:
    import json
    return json.dumps(value)


def unraid_disk(d: dict, model: str | None = None) -> dict:
    entries = [plain("Unraid web UI", "Main, click the disk's name")]
    if d.get("device"):
        entries += [cmd("SMART report, on the server", f"smartctl -a {q('/dev/' + d['device'])}")]
    return {"title": f"Disk {d['name']}" + (f" ({model})" if model else ""),
            "read": "GraphQL: array { parities disks caches boot } for the status, errors and usage; "
                    "disks { smartStatus temperature } for SMART", "entries": entries}


def unraid_container(c: dict) -> dict:
    return {"title": f"Container {c['name']}", "read": "GraphQL: docker { containers { ... isUpdateAvailable } }",
            "entries": [plain("Unraid web UI", "Docker tab"), cmd("On the server", f"docker inspect {q(c['name'])}")]}


def unraid_remote(row) -> dict:
    return {"title": "Last read", "read": "The hub's last attempt to read this server's API",
            "entries": [plain("Address", row["url"]),
                        plain("Certificate", "pinned" if row["tls"] == "pin" else "checked against the CA store")]}


# --- OPNsense (read by the hub over REST, GET only) --------------------------------------------------------

def opnsense_section(source: str, url: str | None = None, interval: int = 60) -> dict:
    """The panel for one OPNsense source: the exact GET requests, how often, the page in OPNsense's own UI, and
    curl commands with placeholders ($KEY and $SECRET: the real ones are never shown anywhere)."""
    from ..remote import opnsense
    src = opnsense.SOURCES[source]
    every = f"{max(opnsense.SLOW_SECONDS, interval) // 60} min" if src.tier == opnsense.SLOW else f"{interval} s"
    paths = [opnsense.PATHS[k] for k in src.paths]
    entries = [plain("OPNsense web UI", src.menu), plain("Privilege it needs", src.privilege),
               plain("How often", f"The hub reads it every {every}")]
    if url and opnsense.UI_PATH.get(source):
        entries.append({"kind": "url", "label": "Open in OPNsense", "href": url + opnsense.UI_PATH[source],
                        "text": url + opnsense.UI_PATH[source]})
    for path in paths:
        entries.append(text("The same read-only request, with the key in $KEY and the secret in $SECRET",
                            f"curl -s -u \"$KEY:$SECRET\" {q((url or 'https://FIREWALL') + path)}"))
    if url:
        entries.append(plain("curl and a self-signed certificate", "add --cacert with the certificate you pinned, or -k on a network you trust"))
    return {"title": src.title, "read": "OPNsense REST API, GET only: " + ", ".join(paths), "entries": entries}


def opnsense_row(title: str, source: str, url: str | None, extra: list[dict] | None = None) -> dict:
    """The panel for one table row: which source it came from, and the page in OPNsense where it can be changed."""
    from ..remote import opnsense
    src = opnsense.SOURCES[source]
    entries = [plain("OPNsense web UI", src.menu)]
    if url and opnsense.UI_PATH.get(source):
        entries.append({"kind": "url", "label": "Open in OPNsense", "href": url + opnsense.UI_PATH[source],
                        "text": url + opnsense.UI_PATH[source]})
    entries += extra or []
    entries.append(plain("Read from", f"{', '.join(opnsense.PATHS[k] for k in src.paths)} (GET)"))
    return {"title": title, "read": f"The hub's reading of {src.title.lower()}: see the card's panel for the request", "entries": entries}
