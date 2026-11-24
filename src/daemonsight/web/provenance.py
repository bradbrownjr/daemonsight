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
    "cve": "The hub matches this host's installed packages against the Debian security tracker (Ubuntu: Canonical's "
           "OVAL data), EPSS scores, CISA's KEV list and CISA's SSVC ratings (CVE Services); the host downloads nothing",
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


UBUNTU_OVAL = "https://security-metadata.canonical.com/oval/"


def prioritisation() -> list[dict]:
    """The entries that explain a deadline, for every CVE panel: the table's name and links (from the table in force), the four
    inputs, the estimate rule and where CISA's rating is read."""
    from ..cve import priority, records
    t = priority.current()
    return [url(f"{t.name} ({t.title})", t.url, t.url),
            url(f"{t.table_name}, as published", t.table_url, t.table_url),
            plain("Deadline", f"Each CVE gets a deadline from {t.name}'s {t.table_name} (version {t.version} of the table file, "
                              f"{t.source}): whether the system is publicly exposed, whether the CVE is in CISA's KEV catalog, "
                              "whether an attacker can automate it (CISA's SSVC rating) and its technical impact (total or partial). "
                              "An update or image takes the worst CVE it fixes. CVSS is shown for information and sets nothing"),
            plain("Estimates", "Where CISA has not rated a CVE, DaemonSight estimates Automatable from the EPSS probability "
                               "(yes at or above the Settings value, FIRST's \"approximately the 90th percentile (>=0.04)\") and assumes "
                               "partial impact, and marks both \"estimated by DaemonSight\""),
            url("CISA's rating comes from", records.DOCS, "GET https://cveawg.mitre.org/api/cve/<CVE-ID> (CISA-ADP container)"),
            url("FIRST: using EPSS", priority.EPSS_URL, priority.EPSS_URL)]


def cve_packages(distro: str = "debian", release: str | None = None) -> dict:
    if distro == "ubuntu":
        rel = release or "$(. /etc/os-release && echo $VERSION_CODENAME)"
        return {"title": "Packages with CVEs",
                "read": "The hub compares each installed source package and version with Canonical's Ubuntu OVAL data for this "
                        "host's release (dpkg version order). A fix that exists only in Ubuntu Pro's ESM archives is shown as such, "
                        "and counts as available only when the host has that Pro service on",
                "entries": [cmd("What Ubuntu Pro covers on this host", "pro security-status"),
                            cmd("One CVE: what would be done (Pro's own check, changes nothing)", "sudo pro fix CVE-2024-6387 --dry-run"),
                            cmd("Updates apt offers (refresh the lists first)", "apt list --upgradable"),
                            cmd("Installed source versions",
                                "dpkg-query -W -f '${source:Package} ${source:Version}\\n' | sort -u"),
                            cmd("The OVAL lines for one source package", f"curl -s {q(UBUNTU_OVAL + 'com.ubuntu.' + rel + '.cve.oval.xml.bz2')} "
                                                                        "| bzcat | grep -F 'openssl source package in'"),
                            url("Ubuntu's CVE pages", "https://ubuntu.com/security/cves", "ubuntu.com/security/cves"),
                            url("Ubuntu Security Notices", "https://ubuntu.com/security/notices", "ubuntu.com/security/notices"),
                            *prioritisation()]}
    return {"title": "Packages with CVEs",
            "read": "The hub compares each installed source package and version with the Debian security tracker "
                    "(Debian version order), for this host's release only",
            "entries": [cmd("Debian's own scanner (sudo apt install debsecan)",
                            "debsecan --suite $(. /etc/os-release && echo $VERSION_CODENAME) --only-fixed"),
                        cmd("Installed source versions",
                            "dpkg-query -W -f '${source:Package} ${source:Version}\\n' | sort -u"),
                        url("Debian security tracker", "https://security-tracker.debian.org/tracker/",
                            "security-tracker.debian.org"),
                        *prioritisation()]}


def cve_inventory(distro: str = "debian") -> dict:
    entries = [cmd("The list the collector reads",
                   "dpkg-query -W -f '${db:Status-Abbrev} ${source:Package} ${source:Version} ${Package} "
                   "${Version}\\n'")]
    if distro == "ubuntu":
        entries.append(file("Ubuntu Pro ESM services that are on (a file exists for each)",
                            "/etc/apt/sources.list.d/ubuntu-esm-infra.sources  ubuntu-esm-apps.sources  (or .list)"))
        entries.append(plain("Ubuntu kernels", "Only the running kernel's image is listed. A signed image's source (linux-signed-aws) is "
                                               "listed under the name Canonical's data uses (linux-aws)"))
    return {"title": "Package list",
            "read": "The collector's dpkg-query output, sent with its uploads when it changes (and once a day)"
                    + (", with which Ubuntu Pro ESM services are on" if distro == "ubuntu" else ""),
            "entries": entries}


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
             "/disks": "Array & disks", "/containers": "Containers", "/docker": "Docker storage", "/images": "Container images", "/vms": "VMs", "/notifications": "Notifications",
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


# --- Docker storage (read from the Docker reader) ---------------------------------------------------------------

DOCKER_PAGE = {
    "images": ("Unused images", "Images no container uses, from the reader's list of Docker's images, with each one's "
                                "container use worked out by DaemonSight"),
    "volumes": ("Unused volumes", "Volumes no container references, with their size and reference count from Docker's data usage"),
    "cache": ("Build cache", "The count and size of Docker's build cache, from Docker's data usage"),
}
DOCKER_CLI = {
    "images": ("docker image ls --no-trunc", "Images"),
    "volumes": ("docker volume ls", "Volumes"),
    "cache": ("docker system df -v", "Build cache"),
}
ARRIVED_NOTE = ("Docker does not record who pulled an image or why. \"Arrived\" is the time Docker last tagged the image on "
                "this server (Metadata.LastTagTime) or, when that is empty, the date the image was built, which can be "
                "long before it was pulled. The hint is DaemonSight's guess from what it can see")


def docker_section(kind: str, reader_url: str | None) -> dict:
    """The panel of one Docker storage card: the reader's endpoint, the Docker calls behind it and the matching CLI."""
    title, what = DOCKER_PAGE[kind]
    cli, ui = DOCKER_CLI[kind]
    entries = [plain("Reader endpoint", f"GET {reader_url or 'http://<reader>:8467'}/v1/summary, with the reader's bearer token"),
               plain("Docker calls", "GET /containers/json?all=1, /images/json?all=0&digests=1, /images/<id>/json "
                                               "(unused images only), /volumes and /system/df?verbose=1 (at most every 30 minutes), "
                                               "all on the Docker socket, read-only"),
               plain("How often", "The hub reads the reader every 10 minutes at most"),
               cmd("On the server", cli)]
    if kind == "images":
        entries.append(plain("Arrived", ARRIVED_NOTE))
        entries.append(cmd("Untagged only", "docker image ls --filter dangling=true --no-trunc"))
    if kind == "volumes":
        entries.append(plain("Data loss", "A volume can hold the only copy of a database. Check before removing one"))
    if reader_url:
        entries.append(text("Same read, $TOKEN",
                            f"curl -s -H \"Authorization: Bearer $TOKEN\" {q(reader_url + '/v1/summary')}"))
    return {"title": title, "read": f"The Docker reader on this server (a second DaemonSight container, GET only): {what}",
            "entries": entries}


def docker_image(i: dict) -> dict:
    ref = " ".join(q(t) for t in i["tags"]) if len(i["tags"]) > 1 else q(i["short"])
    entries = [plain("Hint", i["hint"]["text"]),
               plain("Arrived", ARRIVED_NOTE),
               cmd("Inspect it", f"docker image inspect --format '{{{{json .Metadata}}}}' {q(i['short'])}"),
               cmd("Remove it", f"docker image rm {ref}"),
               plain("Note", "DaemonSight never removes anything. Run the command yourself once you are sure")]
    if i["labels"].get("org.opencontainers.image.source"):
        entries.insert(1, plain("Source label", i["labels"]["org.opencontainers.image.source"]))
    return {"title": f"Image {i['name']}", "read": "The Docker reader: the image's tags, digests, size, LastTagTime and "
                                                    "labels (only org.opencontainers.image.* and net.unraid.*)",
            "entries": entries}


# --- Container images (package lists read by the Docker reader, matched on the hub) ----------------------------------------

IMAGES_READ = ("GET /containers/{id}/archive?path=<p> on the Docker socket (Engine API operation ContainerArchive), for "
               "exactly four paths: /usr/lib/os-release, /etc/os-release, /var/lib/dpkg/status and /lib/apk/db/installed. "
               "One running container per image is read, once, and again only when the image changes")


def images_section(reader_url: str | None) -> dict:
    """The panel of the Container images card: where the lists come from, how they are matched, and the CLI."""
    entries = [plain("Reader endpoint", f"GET {reader_url or 'http://<reader>:8467'}/v1/summary, field image_packages"),
               plain("Docker call", IMAGES_READ),
               plain("Limits", "Each file is capped (16 MB dpkg, 4 MB apk, 64 KB os-release) and must be a single regular file in the tar "
                               "stream; a link is not followed and nothing is written to disk. At most 10 images are read per minute"),
               plain("Support status", "Debian, Ubuntu and Fedora bases use the same release data as a host (distro-info). Alpine and "
                                       "CentOS Linux use endoflife.date's end dates, bundled with DaemonSight"),
               plain("CVEs", "Debian images: each package is matched by its source package and version against Debian's security "
                             "tracker. Ubuntu images: against Canonical's Ubuntu OVAL file for the image's release "
                             "(security-metadata.canonical.com/oval). Alpine images: each package's origin and version against Alpine's "
                             "security database (secdb.alpinelinux.org, main.json and community.json of the image's release). All are "
                             "given a deadline by CISA BOD 26-04 as a host's packages are. A CVE counts as fixable only when the source names "
                             "a fixed version; secdb lists fixes only, so an Alpine image has no unfixed count; a fix that exists only "
                             "in Ubuntu Pro's ESM archives is shown but is not one an image can take"),
               *prioritisation(),
               cmd("One image's packages, on the server", "docker cp -L <container>:/var/lib/dpkg/status - | tar -xO"),
               plain("Alpine instead", "docker cp -L <container>:/lib/apk/db/installed - | tar -xO"),
               cmd("Its OS", "docker cp -L <container>:/usr/lib/os-release - | tar -xO")]
    if reader_url:
        entries.append(text("Same read, $TOKEN", f"curl -s -H \"Authorization: Bearer $TOKEN\" {q(reader_url + '/v1/summary')}"))
    return {"title": "Container images", "read": "The Docker reader on this server (GET only) and the hub's CVE data", "entries": entries}


ALPINE_TRACKER = "https://security.alpinelinux.org/vuln/"


def docker_image_row(r: dict) -> dict:
    """The panel of one container image: what was read, how, and the CLI for that image."""
    from ..cve import match
    cname = r["read_container"] or (r["containers"][0] if r["containers"] else "<container>")
    entries = [plain("Base OS", f"{r['os_name']}" + (f", {r['support']['label']}" if r["support"]["status"] != "unknown" else "")),
               plain("Packages", f"{r['count']} read with {r['manager']}" if r["manager"] else (r["error"] or "not read")),
               plain("Read through container", cname)]
    c = r.get("cve")
    alpine = r.get("kind") == "alpine"
    ubuntu = r.get("kind") == "ubuntu"
    if c and c.get("state") == "matched":
        entries.append(plain("CVEs", f"{len(c['fixable'])} fixable" if alpine else f"{len(c['fixable'])} fixable, {c['unfixed']} with no fix yet"
                             + (f", {len(c['esm'])} fixed only in Ubuntu Pro (ESM)" if c.get("esm") else "")))
        if c.get("note"):
            entries.append(plain("Note", c["note"]))
        for x in c["fixable"][:5]:
            entries.append({"kind": "url", "label": x["cve"],
                            "text": match._describe(x, "Ubuntu priority" if ubuntu else "Debian urgency").removeprefix(x["cve"]).strip(" ()") or x["cve"],
                            "href": ALPINE_TRACKER + x["cve"] if alpine else (match.UBUNTU_CVE_URL if ubuntu else match.TRACKER_URL) + x["cve"]})
    if ubuntu and r.get("ubuntu_release"):
        rel = r["ubuntu_release"]
        src = c["fixable"][0]["source"] if c and c.get("state") == "matched" and c["fixable"] else "<source package>"
        entries.append({"kind": "url", "label": "Matched against", "text": f"{UBUNTU_OVAL}com.ubuntu.{rel}.cve.oval.xml.bz2",
                        "href": UBUNTU_OVAL})
        entries.append(cmd("The same lookup in the OVAL file", f"curl -s {q(UBUNTU_OVAL + 'com.ubuntu.' + rel + '.cve.oval.xml.bz2')} | bzcat "
                                                              f"| grep -F {q(src + ' source package in')}"))
        entries.append(cmd("Updates the container's own apt sees", f"docker exec {q(cname)} apt list --upgradable"))
        entries.append(plain("That command", "Lists packages the container's package index offers newer versions of (run apt update first "
                                             "when the image ships no index; that writes only inside the container). It lists updates, "
                                             "not CVEs: look a CVE up on ubuntu.com/security/<CVE>. pro security-status needs the "
                                             "Pro client, which a container image does not have"))
    if alpine and r.get("alpine_release"):
        rel = r["alpine_release"]
        entries.append({"kind": "url", "label": "Matched against", "text": f"https://secdb.alpinelinux.org/{rel}/main.json and community.json",
                        "href": f"https://secdb.alpinelinux.org/{rel}/"})
        origin = c["fixable"][0]["source"] if c and c.get("state") == "matched" and c["fixable"] else "<origin>"
        entries.append(cmd("The same lookup in secdb", f"curl -s https://secdb.alpinelinux.org/{rel}/main.json "
                                                        f"https://secdb.alpinelinux.org/{rel}/community.json | jq '.packages[].pkg | select(.name == \"{origin}\")'"))
        entries.append(cmd("Updates the container's own apk sees", f"docker exec {q(cname)} apk version -l '<'"))
        entries.append(plain("That command", "Compares the installed packages with the container's package index (apk update first when "
                                             "the image ships none; that writes only inside the container). It lists updates, not CVEs: "
                                             "apk list --upgradable gives the same list"))
        entries.append(cmd("Compare two versions with apk", "apk version -t 3.5.4-r0 3.5.5-r0"))
    path = "/lib/apk/db/installed" if r["manager"] == "apk" else "/var/lib/dpkg/status"
    entries.append(cmd("Its packages", f"docker cp -L {q(cname)}:{path} - | tar -xO"))
    entries.append(cmd("Its OS", f"docker cp -L {q(cname)}:/usr/lib/os-release - | tar -xO"))
    entries.append(plain("Fix", "Update the image: on Unraid, Docker tab, Check for Updates, then apply. "
                                + ("apk upgrade" if alpine else "apt upgrade") + " inside a container does not persist"))
    return {"title": f"Image {r['name']}", "read": "The Docker reader's package list for this image, and the hub's matching of it", "entries": entries}


def docker_volume(v: dict) -> dict:
    return {"title": f"Volume {v['name'][:24]}" + ("..." if len(v["name"]) > 24 else ""),
            "read": "The Docker reader: the volume's name, driver, creation time, compose labels, size and reference "
                    "count (from Docker's data usage)",
            "entries": [plain("Hint", v["hint"]),
                        plain("Data loss", "This volume can hold the only copy of a database. Removing it cannot be undone"),
                        cmd("Look inside it", f"docker run --rm -v {q(v['name'])}:/v:ro alpine ls -la /v"),
                        cmd("Remove it", f"docker volume rm {q(v['name'])}"),
                        plain("Note", "DaemonSight never removes anything. Run the command yourself once you are sure")]}


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


def opnsense_cves(c: dict | None, unseen: bool = False) -> dict:
    """The panel of the CVE list on the firewall's updates card: where the data comes from and how to check it in OPNsense."""
    from ..cve import advisories, opnsense
    p = (c or {}).get("plan") or {}
    span = f"{p['installed']} to {p['offered']}" if p.get("ok") else "the pending update"
    entries = [url("Changelog data", opnsense.REPO, opnsense.REPO),
               url("Downloaded as", opnsense.URL, opnsense.URL),
               url("The same notes, rendered", opnsense.DOCS_URL, opnsense.DOCS_URL),
               plain("Terms", "BSD 2-Clause licence, https://github.com/opnsense/changelog/blob/master/LICENSE"),
               plain("Matched", f"Every changelog section above {p['installed']} and up to {p['offered']} (releases and the hotfixes "
                                "under them), in OPNsense's own version order" if p.get("ok") else
                                "Needs a new OPNsense release in the pending update"),
               plain("What counts", "A CVE id written in a patch-note line, or in a footnote that line points to. A line that names only a "
                                    "FreeBSD or GitHub security advisory counts through the CVE ids that advisory lists, which the hub "
                                    "asks for once (below). An advisory with none stays listed, not ranked, and makes the finding "
                                    "at least Medium (an interim floor outside the BOD 26-04 table). Errata notices and plugin notes are not counted. CVE ids mentioned only in a "
                                    "release's introduction are not counted. Treat the number as a floor"),
               url("FreeBSD advisories", advisories.SA_DOCS, advisories.SA_URL.format(id="<year>:<n>.<module>")),
               url("GitHub advisories", advisories.GH_DOCS, advisories.GH_URL.format(id="<GHSA id>")),
               plain("In OPNsense", f"System, Firmware, Changelog: open each release from {span} and read the lines that name a CVE"),
               plain("Audit of the installed packages", "System, Firmware, Status, Run an audit, Security runs pkg audit, FreeBSD's check of "
                                                         "what is installed against its vulnerability database. DaemonSight never runs it"),
               *prioritisation(),
               cmd("Check the download", f"curl -sI {q(opnsense.URL)}")]
    if p.get("ok"):
        entries.append(url("The offered version's changelog", opnsense.changelog_url(p["offered"]), opnsense.changelog_url(p["offered"])))
    return {"title": "CVEs the newest release fixes" if unseen else "CVEs this update fixes", "read": "The hub downloads OPNsense's published changelog, keeps the sections the pending "
                                                       "update brings and gives the CVE ids in them a deadline by CISA BOD 26-04 (a firewall is always exposed). "
                                                       "Nothing is sent to the firewall", "entries": entries}


CROWDSEC_DOCS ="https://docs.crowdsec.net/docs/next/local_api/authentication"


def crowdsec_section(url: str | None, interval: int = 60, sample: str = "192.0.2.10") -> dict:
    """The panel of the CrowdSec card: the Local API request behind it and the matching cscli command. The bouncer key
    is never shown; a command that needs it names it as $KEY."""
    from ..remote import crowdsec
    base = url or "http://FIREWALL:8180"
    every = max(crowdsec.READ_EVERY, interval)
    entries = [plain("Local API endpoint", f"GET {base}{crowdsec.PATH}?ip=<address>, with the bouncer's key in the X-Api-Key header"),
               plain("What is asked", "One filtered read per protected address (ip=), two per network (range= with contains true and "
                                      "false), and one for the local decisions (origins=crowdsec). Never /v1/decisions/stream, never an unfiltered read"),
               plain("How often", f"The hub reads it every {every // 60} min" if every % 60 == 0 else f"The hub reads it every {every} s"),
               cmd("On the firewall", f"cscli decisions list -i {sample}"),
               cmd("Local bans", "cscli decisions list --origin crowdsec"),
               text("The same read, with the key in $KEY", f"curl -s -H \"X-Api-Key: $KEY\" {q(f'{base}{crowdsec.PATH}?ip={sample}&limit=50')}"),
               plain("The key", "A bouncer key: it can only read decisions. cscli bouncers list shows it on the firewall"),
               {"kind": "url", "label": "CrowdSec docs", "text": "Authentication: bouncer keys", "href": CROWDSEC_DOCS}]
    return {"title": "CrowdSec", "read": "CrowdSec's Local API on the firewall, GET only", "entries": entries}


def crowdsec_row(value: str, whys: list[str], url: str | None) -> dict:
    from ..remote import crowdsec
    base = url or "http://FIREWALL:8180"
    flag, param = ("-r", "range") if "/" in value else ("-i", "ip")
    entries = [plain("Checked because", "; ".join(whys)),
               cmd("On the firewall", f"cscli decisions list {flag} {q(value)}"),
               text("The same read, with the key in $KEY",
                    f"curl -s -H \"X-Api-Key: $KEY\" {q(f'{base}{crowdsec.PATH}?{param}={value}&limit=50' + ('&contains=true' if param == 'range' else ''))}")]
    return {"title": f"CrowdSec and {value}", "read": "The Local API's decisions that contain or overlap this address", "entries": entries}


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
