<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark-256.png">
    <img src="assets/logo-256.png" alt="DaemonSight logo" width="180">
  </picture>
</p>

<h1 align="center">DaemonSight</h1>

<p align="center">One view of what a Linux server exposes, what is watching it, and what is out of date.</p>

---

**Status:** phase 3 of 5 is under way: package updates and CVE matching are
built, and image scanning is next. The collector reads system health, systemd
services, listening sockets, Docker, Caddy, fail2ban, the firewall and pending
package updates. The web UI has Overview, Exposure, Routes, Services,
fail2ban, Packages and (on a hub) Vulnerabilities pages, and a stacked layout
on phones. Findings link to
the row they are about, and a port's panel shows the process behind it.

- **Hub.** A container image (with an Unraid template) shows every host on
  one page. Each host's collector uploads to it over HTTPS.
- **CVE matching on the hub.** Hosts report which packages they have; the
  hub matches them against the Debian security tracker and ranks the hits
  with CISA's known-exploited list and EPSS scores. One finding per package,
  and a Vulnerabilities page with the CVEs behind it. Debian and Raspberry Pi
  OS hosts get the full list; Fedora hosts report their pending security
  advisories. Ubuntu is next. Hosts download nothing and run no scanner.
- **Unraid, read over its API.** The hub polls an Unraid server with a
  Viewer-only API key, with no agent on the server. Add it on the Hosts page
  ("Add a system"): Test connection shows the server, version, array state
  and the key's roles, and a key that could change anything is refused. The
  server gets its own pages (array and disks, containers grouped by your
  Docker folders, VMs, notifications with the date and text of every unread
  alert) and findings for full or hot disks, disk errors, a stopped array, an
  old parity check (with what the check found and when one was cancelled),
  unclean shutdowns (counted and dated), one finding for all container
  updates, a newer Unraid release, unread alerts grouped by title, and the
  UPS. Each finding from the hub's own rules has a "What to do" list of plain
  steps. Notices that DaemonSight already checks live (disk usage,
  temperature, parity checks) are not repeated as findings but stay listed on
  the Notifications page. Each container shows its CPU and memory, sampled for
  a few seconds every minute, and the Overview lists the five busiest by CPU
  and by memory. Certificates are verified, or you pin one after confirming
  its fingerprint. See [SECURITY.md](SECURITY.md).
- **Automatic updates.** The Packages page shows whether unattended-upgrades
  (apt) or dnf5-automatic (Fedora) will install security updates, and a
  low finding says how to turn it on.
- **Fixes on findings.** A finding that has one command to resolve it shows
  that command in a block with a Copy button. Findings with no single
  command, such as an exposed port, are decisions.
- **Accept with a note.** On a hub, an open finding can be accepted with a
  note. It leaves the counts, badges and report steps but stays in the list,
  in place, with an Accepted label and its note (on hover, and in the row).
  It comes back, labelled Changed and counted again, when what you accepted
  changes, such as a new CVE in the same package. It is deleted when the
  finding resolves. The Overview list has an "All" and a "Needs attention"
  filter, and the report keeps its own Accepted section.
- **Status labels.** Every list says where each item stands: Unexpected (not
  expected, not accepted), Accepted, Changed (accepted, but what it was
  about has changed) or Expected (listed in `exposure.expected_public`). Only
  Unexpected and Changed count as needing attention. Nothing is hidden: the
  Exposure page has a Status column on every listener and port forward, with a
  dash for what the internet can't reach.
- **Seen from outside (Shodan).** Off by default. A hub can ask Shodan's free
  InternetDB what the internet sees of each host's public addresses, once a
  day, sending only the IP address. The Exposure page lists each port Shodan
  sees with a status and what DaemonSight knows about it (the process, or the
  port forward and the tunnel it goes through), and findings flag a port
  nobody expected, an expected port Shodan doesn't see, Shodan's compromise
  tags and its CVE guesses. Turn it on from the Settings page. InternetDB is
  free for non-commercial use only: see [docs/INSTALL.md](docs/INSTALL.md),
  "Outside checks".
- **Per-host report.** One page per host (`/h/<host>/report`, or `/report` on
  a single host) puts the open findings in order: install updates, restart
  services, reboot, automatic updates, then the rest, each step with its
  commands merged and a Copy button. Copy it as text, download it as
  Markdown, or print it.
- **Updates from the hub.** The hub's Hosts page, or `daemonsight hub
  update`, moves hosts to the hub's own commit. A host can turn this off.
- **Retention and backups.** Retention sets how long history stays;
  scheduled backups and `daemonsight restore` cover the database, config and
  secrets.
- **Settings page and account menu.** The button at the right of the header
  opens one menu with Settings, the theme (Light, Dark or Auto), "Hide empty
  sections" and Log out. On a hub the Settings page changes the outside view,
  CVE checks, retention, backups and remote polling without a restart; each
  setting shows whether it comes from the Default, the Config file or "Set
  here", and can be reset. What controls login or where the server listens
  stays in the config file. On a host without a hub the page shows the
  running values read-only. See [docs/INSTALL.md](docs/INSTALL.md#the-settings-page).

The OPNsense API, log collection and alerts are planned. See [docs/DESIGN.md](docs/DESIGN.md).

## Install

Debian 12 or 13, Ubuntu or Fedora, Python 3.11 or newer (on Fedora:
`sudo dnf install git python3`, see [docs/INSTALL.md](docs/INSTALL.md#fedora)):

```bash
sudo apt install git python3-venv
git clone https://github.com/bradbrownjr/daemonsight.git
cd daemonsight
sudo ./install.sh
sudo daemonsight set-password
sudo systemctl start daemonsight-web
```

The UI listens on `127.0.0.1:8466`. Open it over SSH
(`ssh -L 8466:127.0.0.1:8466 you@server`) or through a reverse proxy limited
to your LAN. Update later with `sudo daemonsight-update`.

[docs/INSTALL.md](docs/INSTALL.md) covers the install options, reverse
proxies, which ports to list as public, running a hub, updating, and removal.

## Why

Existing tools each cover part of the job. Netdata and Beszel show health and
traffic, fail2ban dashboards show bans, Caddy UIs show routes, and scanners find
CVEs. None of them check these against each other, and those cross-checks are
where the gaps are:

- A port listening on a public interface with no Caddy route or firewall rule in front of it
- A Caddy route whose upstream is down or not listening
- A public service whose logs no fail2ban jail is watching
- A host package with a known CVE that has a fix available, or that is being exploited

DaemonSight collects from the tools already on the server and reports on
these gaps.

## Planned coverage

| Area | Source |
|------|--------|
| Caddy routes and upstreams | Caddy admin API (`localhost:2019`) |
| systemd services | systemd over D-Bus |
| fail2ban jails, filters, log paths, bans | `fail2ban-client` / fail2ban socket |
| Docker containers, health, logs | Docker API through a read-only socket proxy |
| Listening and open ports | `ss` / `/proc/net`, nftables rules |
| Network traffic, CPU, memory, disk | `/proc`, psutil |
| CVEs in host packages | Debian security tracker, CISA KEV and EPSS, matched on the hub; Fedora security advisories (dnf5) |
| CVEs in container images | Planned |

Targets: a Debian VPS running Caddy and Docker, and Debian LXC containers.

## Security

How DaemonSight protects the hosts it runs on, and how to report a
vulnerability: [SECURITY.md](SECURITY.md).

## Design notes

Full plan: [docs/DESIGN.md](docs/DESIGN.md). The UI is server-rendered with
FastAPI, HTMX and Tabler, with no Node build step.

- **Split privileges.** A small root collector writes snapshots. The web UI
  runs as an unprivileged user and only reads them.
- **Not public by default.** The UI binds to localhost or a WireGuard
  interface. A monitoring dashboard on a VPS is itself something to attack.
- **Alerts on change (planned, phase 4).** Examples: a new listening port, a new CVE with a fix,
  a stopped jail, a failed service.

## License

MIT. See [LICENSE](LICENSE).

Portions of this project were developed with AI assistance (Claude).
