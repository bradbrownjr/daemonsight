<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark-256.png">
    <img src="assets/logo-256.png" alt="DaemonSight logo" width="180">
  </picture>
</p>

<h1 align="center">DaemonSight</h1>

<p align="center">One view of what a Linux server exposes, what is watching it, and what is out of date.</p>

---

**Status:** phase 2 of 5 is done, and phase 3 (CVE scanning) is next. The
collector reads system health, systemd services, listening sockets, Docker,
Caddy, fail2ban and the firewall. The web UI has Overview, Exposure, Routes,
Services and fail2ban pages, and a stacked layout on phones. Findings link to
the row they are about, and a port's panel shows the process behind it.

- **Hub.** A container image (with an Unraid template) shows every host on
  one page. Each host's collector uploads to it over HTTPS.
- **Updates from the hub.** The hub's Hosts page, or `daemonsight hub
  update`, moves hosts to the hub's own commit. A host can turn this off.
- **Retention and backups.** `[retention]` sets how long history stays;
  scheduled backups and `daemonsight restore` cover the database, config and
  secrets.

Remote sources (OPNsense and Unraid APIs), log collection and alerts are
planned. See [docs/DESIGN.md](docs/DESIGN.md).

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
traffic, fail2ban dashboards show bans, Caddy UIs show routes, and Trivy finds
CVEs. None of them check these against each other, and those cross-checks are
where the gaps are:

- A port listening on a public interface with no Caddy route or firewall rule in front of it
- A Caddy route whose upstream is down or not listening
- A public service whose logs no fail2ban jail is watching
- A running container or host package with a known CVE that has a fix available

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
| CVEs in host packages and container images | Trivy (`rootfs` and `image`), `debsecan` |

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
