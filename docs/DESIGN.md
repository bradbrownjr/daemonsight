# DaemonSight design

Status: draft for review, 2026-11-15.

## Goal

One page that shows what a Linux server exposes, what is watching it, and
what is out of date. DaemonSight also checks those facts against each other and
reports the gaps between them as findings.

Targets for v1:

- Debian 12 VPS: Caddy, Docker, fail2ban, nftables, WireGuard. Python 3.11.
- Debian 13 LXC containers. Python 3.13.

## Not in v1

- Log storage or shipping. DaemonSight reads logs to answer specific questions; it is not a SIEM.
- Changing the host. v1 is read-only: no bans, restarts or firewall edits.
- More than one host per install. Each host runs its own copy. A central view comes later.
- Podman, Kubernetes, nginx, Apache, iptables-legacy.

## Architecture

```
                 root                                 user: daemonsight
 ┌──────────────────────────────┐                 ┌─────────────────────┐
 │ daemonsight-collector        │                 │ daemonsight-web     │
 │  system · systemd · ports    │   writes        │  FastAPI + Jinja2   │
 │  docker · caddy · fail2ban   ├──────────┐      │  HTMX, read-only    │
 │  nftables · findings · alerts│          ▼      │                     │
 └──────────────────────────────┘   /var/lib/daemonsight/state.db ◄──────┤
 ┌──────────────────────────────┐          ▲      └──────────┬──────────┘
 │ daemonsight-scan (timer, 6 h)│  writes  │                 │ 127.0.0.1 or wg0
 │  trivy · debsecan            ├──────────┘                 ▼
 └──────────────────────────────┘                     browser (via Caddy)
```

Three systemd units:

| Unit | Runs as | Does |
|------|---------|------|
| `daemonsight-collector.service` | root | Long-running asyncio loop. Each source has its own interval. Writes snapshots, computes findings, sends alerts. |
| `daemonsight-scan.service` + `.timer` | root | Oneshot every 6 hours. Runs Trivy and debsecan, writes results. Separate because scans are slow and memory-heavy. |
| `daemonsight-web.service` | `daemonsight` | Serves the UI. Opens the database read-only. Never touches sockets, logs or tools. |

The split exists because the collector needs privileges the web process must
never have: the Docker socket (equivalent to root), the fail2ban socket, other
users' process details, the firewall ruleset and log files. If the web process
is compromised, the attacker gets a read-only view of data already on the page.

Later: replace full root in the collector with a capability set. Which
capabilities each source needs is listed under "To verify".

## Data sources

| Area | Source | Interval | Notes |
|------|--------|----------|-------|
| CPU, memory, disk, network | psutil: `cpu_percent`, `virtual_memory`, `disk_usage`, `net_io_counters(pernic=True)` | 15 s | Kept as time series. |
| systemd services | D-Bus `org.freedesktop.systemd1.Manager.ListUnits`; per unit `ActiveState`, `SubState`, `ActiveEnterTimestamp`; per service `NRestarts`, `MemoryCurrent`, `CPUUsageNSec` | 30 s | systemd docs: read access is granted to all clients, so this source needs no privilege. [1] |
| Listening ports | `psutil.net_connections()` (fd, family, type, laddr, raddr, status, pid), or `/proc/net/{tcp,tcp6,udp,udp6}` plus socket inodes | 60 s | PID → owner via `/proc/<pid>/cgroup`: a systemd unit, or `docker-<id>.scope` for a container. [2] |
| Docker | Engine API on `/var/run/docker.sock`: container list, inspect (`State.Health`, `State.OOMKilled`, port bindings), logs, one-shot stats | 30 s | The client sends GET only. A socket proxy is needed only if the collector itself runs in a container; Tecnativa's blocks POST by default. [3] |
| Caddy | `GET /config/` for servers and routes, `GET /reverse_proxy/upstreams` for `address`, `num_requests`, `fails` | 60 s | Default `localhost:2019`; also supports a Unix socket, which Caddy recommends. [4] |
| fail2ban | `fail2ban-client status`, `status <jail>`, `get <jail> logpath / findtime / bantime / maxretry / failregex`, `get <jail> banip --with-time`, `banned` | 60 s | No JSON output, so the text is parsed. Tests pin the parser to the fail2ban versions in Debian 12 and 13. [5] |
| Firewall | `nft -j list ruleset` | 5 min | JSON schema in libnftables-json(5). [6] Docker's NAT chains are how DaemonSight spots published ports that skip the input chain. |
| CVEs, host | `trivy rootfs --scanners vuln --format json /` with `--skip-dirs` for `/proc`, `/sys`, `/var/lib/docker` | 6 h | Without `--pkg-types os` it also finds language packages (Python venvs, `node_modules`) of apps on the host. [7][8] |
| CVEs, images | `trivy image --format json <image>` for each running image | 6 h | Fields used: `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Status`, `Severity`. [8] |
| CVEs, cross-check | `debsecan --suite <codename> --only-fixed --format detail` | 6 h | Debian's own view of fixable packages. Needs network access. [9] |

Trivy caveats from its docs: it uses only the OS vendor's advisories for OS
packages, and it skips packages from third-party apt repos (Docker, NVIDIA and
others). [7] DaemonSight lists those packages as "not scanned" rather than
"clean". Trivy is itself installed from Aqua's apt repo, so it is in that list
too.

## Findings

A finding is a rule applied to the latest snapshots. Each has a stable key, so
DaemonSight knows when it first appeared and when it cleared.

| Rule | Fires when | Severity |
|------|------------|----------|
| `expose.unexpected` | A listener on a public address is not in the host's expected list | Critical if the firewall lets it through, else Medium |
| `expose.docker_bypass` | A Docker port is published on 0.0.0.0 or :: | Critical |
| `route.upstream_down` | A Caddy upstream's dial address has no listener | Medium |
| `route.upstream_failing` | An upstream's `fails` is above zero and rising | Medium |
| `jail.uncovered` | A public service (listener or Caddy host) has no jail reading its logs | High |
| `jail.log_missing` | A jail's `logpath` does not exist | Medium |
| `cve.fixable_exposed` | A fixable CVE sits in a package or image whose process owns a public listener or Caddy upstream | The CVE's severity, raised one level |
| `cve.fixable` | Any other fixable CVE | The CVE's severity |
| `svc.failed` | A unit is in `failed` | High |
| `ctr.down` | A container exited non-zero, is unhealthy, or was OOM-killed | High |
| `caddy.admin_tcp` | The admin API listens on TCP instead of a Unix socket | Low |
| `tls.expiring` | A served certificate expires within 14 days | High |
| `sys.disk` / `sys.memory` | Above 90% for 15 minutes | Medium |

A restart is a moment, not a state, so restarts of units and containers are
recorded as events under "Recent changes" rather than as findings. So are new
and closed listeners.

Linking a Caddy host to a jail can't be fully automatic, because Caddy can log
per site or globally. DaemonSight guesses the link from each jail's `logpath`
and the route's log settings. A config file can override the guess.

## Storage

SQLite in WAL mode at `/var/lib/daemonsight/state.db`. The collector and
scanner write; the web process opens it with `mode=ro`.

- `snapshots`: source, taken_at, ok, error, data (JSON). The latest row per source is current state.
- `findings`: rule, key, severity, first_seen, last_seen, resolved_at, details (JSON).
- `events`: changes worth showing in "Recent changes": a new port, a ban spike, a unit going down.
- `metrics`: ts, name, value. 15-second points kept 48 hours, 5-minute averages kept 30 days.

## Web UI

Stack, all pinned and served from the app's own `static/` folder. Nothing
loads from a CDN at runtime, and there is no Node build step.

| Piece | Version | License |
|-------|---------|---------|
| FastAPI + Jinja2 | current | MIT / BSD |
| HTMX | 2.0.11 | 0BSD |
| Tabler (CSS only) | 1.7.5 | MIT |
| Tabler Icons | 3.52.0 | MIT |
| uPlot | 1.6.32 | MIT |

Why not React and MUI like ECTLogger: DaemonSight runs on the machine it
protects, so its own dependency tree is attack surface and shows up in its own
CVE scan. The pages are tables and a few charts that refresh every 30–60
seconds, which server-rendered HTML with HTMX handles well.

Theme: Tabler's dark mode with the `slate` base and `cyan` primary, which
matches the logo's gem. Light mode is a toggle. Tabler ships both as built-in
attributes (`data-bs-theme`, `data-bs-theme-base`, `data-bs-theme-primary`), so
there is no custom CSS to maintain.

Pages: Overview, Exposure, Caddy routes, Services and containers, fail2ban,
Vulnerabilities.

Access: the web process binds to 127.0.0.1 (behind Caddy) or to the WireGuard
address, never to a public address. It also has its own login (one admin
password, argon2 hash, session cookie), so a Caddy mistake doesn't expose it.

## Alerts

Sent by the collector when a finding opens or clears, once per change. v1
supports ntfy and SMTP email. Daily digest optional.

## Install and deploy

- `install.sh` for v1: creates a venv in `/opt/daemonsight`, the `daemonsight` user, the three units and `/etc/daemonsight/config.toml`. A `.deb` comes later.
- Requires `fail2ban`, `nftables` and `debsecan` from Debian, and Trivy from Aqua's apt repo.
- Testing order: beta LXC first (Claude Code runs there), then alpha, then the VPS.
- VPS: the web process on `127.0.0.1:8466`, reached over WireGuard, or through Caddy with the hostname restricted to the WireGuard range.
- LXC: the kernel belongs to the Unraid host, so kernel CVEs are skipped when `systemd-detect-virt` reports a container. An unprivileged LXC may not be able to read the nftables ruleset; that source then shows "unavailable" instead of failing.

## Phases

1. Skeleton: config, SQLite, collector loop, system/systemd/ports/Docker sources, Overview and Services pages, login.
2. Caddy, fail2ban, nftables sources. Exposure, Routes and fail2ban pages. The `expose`, `route` and `jail` rules.
3. Scanner unit, Trivy and debsecan. Vulnerabilities page. The `cve` rules.
4. Alerts, recent-changes feed, history charts.
5. `.deb` package and docs.

Later: a central view across hosts, actions (ban, unban, restart), CrowdSec,
Podman, and an optional check from outside the host to confirm what's
reachable from the internet.

Central view plan: every install, full or `--collector`, can serve its
snapshots read-only on a tunnel address with a per-host token. One install's
web UI lists the other hosts and pulls from them. The hub should sit on the
home LAN and pull from the VPS, not the other way round, so a compromised VPS
holds no credential or route into the LAN.

## Answered in phase 1

- **psutil needs root for socket owners.** Run unprivileged on Debian 13 with psutil 7.2.2, `net_connections()` lists every listener but returns `pid=None` for sockets of other users.
- **D-Bus library: dbus-fast 5.2.** Unprivileged `ListUnitsByPatterns` and `Properties.GetAll` work as the systemd docs say. The system bus rejects more than 128 pending replies per connection (`LimitsExceeded`, `max_replies_per_connection`), so property reads are capped at 32 in flight.
- **Docker API** paths, the health states, the log frame format and the CPU formula are taken from the v1.47 OpenAPI spec. The collector uses the server's own `ApiVersion` from `GET /version`. Not yet run against a real Docker host.
- **Read-only SQLite** works while the collector holds the database open; when it's stopped, the web falls back to `immutable=1`.
- **Web port** is 8466. 8090 is common and was already taken on beta.
- **`expose.docker_bypass`** moved into phase 1: it needs only Docker data.

## To verify

- Whether `nft list ruleset` needs `CAP_NET_ADMIN`. nft(8) doesn't say.
- Which capabilities could replace full root for the collector (likely `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, plus Docker socket access).
- Whether to talk to the fail2ban socket directly instead of parsing `fail2ban-client` output.
- The Docker source on a real Docker host (alpha or the VPS).
- The systemd sandboxing in `daemonsight-web.service` inside an unprivileged LXC.

## Sources

1. systemd D-Bus API: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
2. psutil: https://psutil.io/
3. docker-socket-proxy: https://github.com/Tecnativa/docker-socket-proxy
4. Caddy admin API: https://caddyserver.com/docs/api
5. fail2ban-client(1), Debian 12: https://manpages.debian.org/bookworm/fail2ban/fail2ban-client.1.en.html
6. nft(8), Debian 12: https://manpages.debian.org/bookworm/nftables/nft.8.en.html
7. Trivy OS package scanning: https://trivy.dev/v0.43/docs/scanner/vulnerability/os
8. Trivy rootfs and JSON reporting: https://trivy.dev/docs/latest/target/rootfs/ and https://trivy.dev/docs/latest/configuration/reporting/
9. debsecan(1), Debian 12: https://manpages.debian.org/bookworm/debsecan/debsecan.1.en.html
