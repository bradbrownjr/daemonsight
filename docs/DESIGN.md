# DaemonSight design

Status: phases 1, 2 and 2c are built; phase 3 is next. Updated 2026-11-18.

## Goal

One page that shows what a Linux server exposes, what is watching it, and
what is out of date. DaemonSight also checks those facts against each other and
reports the gaps between them as findings.

Targets for v1:

- Debian 12 VPS: Caddy, Docker, fail2ban, nftables, WireGuard. Python 3.11.
- Debian 13 LXC containers. Python 3.13.

## Not in v1

- Log storage or shipping. DaemonSight reads logs to answer specific questions; it is not a SIEM. Log collection is planned after phase 3; see "Log collection and auditing (planned)".
- Changing the host. v1 is read-only: no bans, restarts or firewall edits.
- A hub that ships as anything but a container. A collector-and-web install can't also be a hub.
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

Systemd units. `daemonsight-scan` arrives with phase 3.

| Unit | Runs as | Does |
|------|---------|------|
| `daemonsight-collector.service` | root | Long-running asyncio loop. Each source has its own interval. Writes snapshots, computes findings, sends alerts. |
| `daemonsight-scan.service` + `.timer` | root | Oneshot every 6 hours. Runs Trivy and debsecan, writes results. Separate because scans are slow and memory-heavy. |
| `daemonsight-web.service` | `daemonsight` | Serves the UI. Opens the database read-only. Never touches sockets, logs or tools. |
| `daemonsight-update.path` + `.service` | root | Installs an update the hub asked for. See "Updates from the hub". |

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
| Listening ports | `psutil.net_connections()` (fd, family, type, laddr, raddr, status, pid), or `/proc/net/{tcp,tcp6,udp,udp6}` plus socket inodes | 60 s | PID → owner via `/proc/<pid>/cgroup`: a systemd unit, or `docker-<id>.scope` for a container. Per process it also records the command line (secrets masked, cut to 400 characters), the executable, the user and the start time. [2] |
| Docker | Engine API on `/var/run/docker.sock`: container list, inspect (`State.Health`, `State.OOMKilled`, port bindings), logs, one-shot stats | 30 s | The client sends GET only. A socket proxy is needed only if the collector itself runs in a container; Tecnativa's blocks POST by default. [3] |
| Caddy | `GET /config/` for servers and routes, `GET /reverse_proxy/upstreams` for `address`, `num_requests`, `fails` | 60 s | Default `localhost:2019`; also supports a Unix socket, which Caddy recommends. On TCP the admin API checks the Host header (admin.go `checkHost`); on a Unix socket it doesn't. [4] |
| fail2ban | The server's control socket (`/var/run/fail2ban/fail2ban.sock`): `status`, `status <jail>`, `get <jail> logpath / journalmatch / bantime / findtime / maxretry / ignoreip / actions`, `get <jail> banip --with-time` | 60 s | Pickled Python values framed by `<F2B_END_COMMAND>`, read with an unpickler that accepts builtins only. See "Answered in phase 2". [5] |
| Firewall | `iptables-save` and `ip6tables-save` when installed; `nft -j list ruleset` for native nft tables | 5 min | Input chains (default verdict, ports accepted, following jumps) and DNAT forwards. With iptables' nf_tables backend, nft shows extension matches such as multiport only as opaque `xt` expressions, so iptables-save is read for those tables. [6] |
| Packages | `apt-get -s -o Debug::NoLocking=1 dist-upgrade` (a simulation: pending upgrades, with the archive each comes from, so security updates are known), `apt-mark showhold`, `dpkg-query` for installed `linux-image-*`, `/var/run/reboot-required(.pkgs)`, the mtime of `/var/lib/apt/lists/*InRelease`, `systemctl is-enabled apt-daily.timer`, and `needrestart -b -r l` if installed | 1 h | Never runs `apt update`; the host's apt timers do, and the lists' age is reported. The simulation needs no root and changes nothing. A kernel that no installed `linux-image` package matches (an LXC, a custom kernel) is "managed by the host" and raises nothing. needrestart's batch mode lists services using old libraries without restarting them. [12][13] |
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
| `expose.forward_all` | A DNAT rule forwards more than 1000 ports (for example "all except 22, 80, 443") to another host | High |
| `firewall.default_accept` | A host with a public address has no input chain that drops by default, per IPv4 and IPv6 | Medium |
| `firewall.duplicate_rules` | The same rule appears more than once (a script adding rules on every run) | Low |
| `route.upstream_down` | A Caddy upstream's dial address has no listener | Medium |
| `route.upstream_failing` | An upstream's `fails` is above zero (Caddy only counts fails with passive health checks on) | Medium |
| `jail.uncovered` | A public service (listener or Caddy host) has no jail reading its logs | High |
| `jail.log_missing` | A jail's `logpath` does not exist | Medium |
| `pkg.security_updates` | A pending update comes from a security archive | High; Medium if the package lists are over 3 days old |
| `pkg.updates` | Updates are pending, none of them security | Low |
| `pkg.reboot` | `/var/run/reboot-required` exists, or a newer kernel than the running one is installed | Medium |
| `pkg.restart` | needrestart lists services using old libraries | Low |
| `pkg.lists_stale` | The package lists are over 3 days old | Low |
| `cve.fixable_exposed` | A fixable CVE sits in a package or image whose process owns a public listener or Caddy upstream | The CVE's severity, raised one level |
| `cve.fixable` | Any other fixable CVE | The CVE's severity |
| `svc.failed` | A unit is in `failed` | High |
| `ctr.down` | A container exited non-zero, is unhealthy, or was OOM-killed | High |
| `caddy.admin_tcp` | The admin API listens on TCP instead of a Unix socket | Low |
| `tls.expiring` | A served certificate expires within 14 days (phase 4) | High |
| `sys.disk` / `sys.memory` | Above 90% for 15 minutes | Medium |

A restart is a moment, not a state, so restarts of units and containers are
recorded as events under "Recent changes" rather than as findings. So are new
and closed listeners.

Linking a Caddy host to a jail can't be fully automatic, because Caddy can log
per site or globally. DaemonSight guesses the link from each jail's `logpath`
and the route's log settings. A config file can override the guess.

## Storage

SQLite in WAL mode at `/var/lib/daemonsight/state.db`. The collector and
scanner write; the web process opens it with `mode=ro`. On a hub, the hub's
web process is the writer.

`[retention]` sets how long rows stay: metric points 48 hours by default,
events and resolved findings for good. The collector prunes its own host's
rows hourly; the hub prunes every host's. Open findings are never pruned.

- `snapshots`: source, taken_at, ok, error, data (JSON). The latest row per source is current state.
- `findings`: rule, key, severity, first_seen, last_seen, resolved_at, details (JSON).
- `events`: changes worth showing in "Recent changes": a new port, a ban spike, a unit going down.
- `metrics`: ts, name, value. Raw points for `[retention] metrics_hours`. Longer history as 5-minute averages is planned with the charts (phase 4).

Backups (`backup.py`): one owner-only `.tar.gz` with a consistent copy of
the database (SQLite's online backup API, so the writer keeps running), the
config, the password hash, the session secret and any upload token, plus a
manifest. The folder is 0700 and each archive 0600. The hub, and a collector that keeps its own data, make one every
`[backup] interval_hours` (24) and keep `keep` (7). A collector that
uploads skips them unless `interval_hours` is set: the hub's backups hold
its history. `daemonsight restore` refuses while the writer
holds `daemonsight.lock` in the data folder, checks the archive's names (it
never extracts by path), the database's integrity and its schema version,
and keeps every file it replaces as `<name>.before-restore`.

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

Only Tabler's CSS and HTMX are vendored so far. Tabler Icons and uPlot come
with the charts (phase 4).

Why not React and MUI like ECTLogger: DaemonSight runs on the machine it
protects, so its own dependency tree is attack surface and shows up in its own
CVE scan. The pages are tables and a few charts that refresh every 30–60
seconds, which server-rendered HTML with HTMX handles well.

Theme: Tabler's dark mode with the `slate` base and `cyan` primary, which
matches the logo's gem. Light mode is a toggle. Tabler ships both as built-in
attributes (`data-bs-theme`, `data-bs-theme-base`, `data-bs-theme-primary`), so
there is no custom CSS to maintain.

Pages: Overview, Exposure, Caddy routes, Services and containers, fail2ban, Packages.
On a hub, Hosts is the front page. Vulnerabilities comes with phase 3.

Row links: a finding links to the row it is about, such as an Exposure port,
a Caddy site, a forward or a jail (the row's `id` is built by
`findings.anchor`). `app.js` (`showTarget`) scrolls to that row, clears a
filter that hides it and flashes it once; the flash is off under
`prefers-reduced-motion`.

Phones: below 768 px each table row becomes a stacked card, one labelled line
per cell, with the header row hidden from view but kept for screen readers.

Source panels: every card and most rows have an (i) button. It opens a panel
with two parts. "Read from" says how DaemonSight got the data (the D-Bus call,
the API path, the socket command). "Check it yourself" lists the unit file and
drop-ins, the Compose folder and files, a jail's log paths, and read-only
commands to copy (`systemctl status`, `journalctl -u`, `docker logs`,
`fail2ban-client status`, `iptables -S`, `ss -ltnp`). Some entries link to the
row that owns the item: a port links to its unit or container. A port's panel
also shows its process's command line (masked), program, user and start time,
and the Caddy sites served on that port when Caddy owns it. A `[links]`
table in the config adds a web UI link per source, such as the OPNsense Caddy
page. The panels are native HTML popovers, so they need no script library and
work under the CSP. The 30-second refresh waits while one is open. The unit
file comes from the `FragmentPath` and `DropInPaths` properties [1]; the
Compose folder and files come from the labels Compose sets on each container
(`com.docker.compose.project.working_dir`, `...config_files`) [10].

Access: the web process binds to 127.0.0.1 (behind Caddy) or to the WireGuard
address, never to a public address. It also has its own login (one admin
password, argon2 hash, session cookie), so a Caddy mistake doesn't expose it.

## Alerts

Sent by the collector when a finding opens or clears, once per change. v1
supports ntfy and SMTP email. Daily digest optional.

## Install and deploy

- `install.sh` for v1: creates a venv in `/opt/daemonsight`, the `daemonsight` user, the units (including the update path unit) and `/etc/daemonsight/config.toml`, and records its options in `/etc/daemonsight/install.options`. A `.deb` comes later.
- `daemonsight-update` (in `/usr/local/sbin`) updates from GitHub into a root-owned clone and reruns `install.sh` with the recorded options. After installing it waits 20 seconds and goes back to the previous commit if the collector isn't running. Installing only from GitHub, never a user's checkout, is what makes a password-less sudo rule for it reasonable on a development server. See [INSTALL.md](INSTALL.md#update).
- Requires `fail2ban`, `nftables` and `debsecan` from Debian, and Trivy from Aqua's apt repo.
- Testing order: beta LXC first (Claude Code runs there and updates it with `sudo daemonsight-update` after each push), then alpha, then the VPS.
- VPS: the web process on `127.0.0.1:8466`, reached over WireGuard, or through Caddy with the hostname restricted to the WireGuard range.
- LXC: the kernel belongs to the Unraid host, so kernel CVEs are skipped when `systemd-detect-virt` reports a container. An unprivileged LXC may not be able to read the nftables ruleset; that source then shows "unavailable" instead of failing.

## Phases

1. Skeleton: config, SQLite, collector loop, system/systemd/ports/Docker sources, Overview and Services pages, login. Done.
2. Caddy, fail2ban, nftables sources. Exposure, Routes and fail2ban pages. The `expose`, `route` and `jail` rules. Done.
   2b. Remote sources: the OPNsense API (Caddy plugin routes, firewall, gateways, WireGuard, firmware) and the Unraid API (array, disks, containers, VMs). Each shows as its own host. See "Remote sources". Planned.
   2c. The hub: collectors upload to one install that shows every host, with the container image and Unraid template, retention and backups, and updates from the hub. See "Hub". Done.
3. Package and CVE checks.
   3a. Pending updates, reboots, services on old libraries: the `packages` source, `pkg` rules and Packages page. Done.
   3b. Next: CVE matching on the hub, from the Debian security tracker.
   3c. Next: CVEs in container images (Trivy), with the Vulnerabilities page and the `cve` rules.
4. Alerts, recent-changes feed, history charts.
5. `.deb` package and docs.

Planned after phase 3: log collection and auditing. See "Log collection and
auditing (planned)".

Later: actions (ban, unban, restart), CrowdSec,
Podman, and an optional check from outside the host to confirm what's
reachable from the internet.

See "Hub" for the central view.

## Hub

One install acts as the hub and shows every host. Collectors push to it over
HTTPS, the way RMM agents and Wazuh agents report in: a Wazuh agent opens the
connection to its server on TCP 1514 and enrolls on TCP 1515, which gives it
its own key [11]. Nothing connects to a collector.

Why push, not pull:

- No VPN or inbound port on any host. A collector only makes outbound
  HTTPS connections, so hosts behind NAT or CGNAT can report.
- A collector holds one token that can only write its own host's data. That
  token gives no access to the hub's network or to other hosts.
- Each collector keeps its own SQLite, so when the hub is down it sends the
  backlog later.
- A host that stops reporting is a finding (`host.silent`). An intruder or
  miner that stops the collector shows up that way.

The cost is an upload address the internet can reach. The rules below limit
what that address accepts.

### Upload

A collector with a URL under `[upload]` runs an uploader beside its sources
(`collector/upload.py`). Every `interval` seconds (30) it sends one `POST` to
`/api/v1/ingest` with `Authorization: Bearer <token>` and a gzipped JSON body:
`host`, `seq`, `sent_at`, its version, its longest interval, its own
`[exposure]` and `[links]` settings and ephemeral port range, whether
`[upload] remote_update` is on, the result of its last update, the snapshots
that changed, the metrics and events the hub hasn't confirmed (up to 20,000
and 1,000 a time; the rest follows a second later), and its open findings.

- **Cursors** follow write order: the last snapshot sent per source, the
  last metric row, the last event id. They move only when the hub answers
  200, so a down hub loses nothing. Timestamps can't be cursors: a source
  stamps its reading when it starts and writes it when it finishes, so a
  slow source can write an older time after a fast one wrote a newer one.
- **Resending is harmless.** If the hub stored an upload but the reply was
  lost, the collector sends the same data again. Snapshots only move
  forward, metric points with the same time and name are replaced, and
  events are keyed by their id on the collector (`events.src_id`).
- **Tokens:** 32 random bytes from `daemonsight hub add-host`. The hub
  stores only a SHA-256 of each token, paired with one host id, and looks
  tokens up by that hash. A body whose `host` doesn't match its token's
  host is refused. `hub revoke` deletes the token; `--purge` also deletes
  the host's data. On the collector, `set-upload-token` writes the token
  root-only (0600).
- **Order:** `seq` is the collector's clock in milliseconds and must be
  higher than the last one accepted, so a reinstalled collector still
  counts up. An older one gets 409 with the hub's last `seq`, and the
  collector jumps past it.
- **Checks:** gzip or plain JSON only; 8 MiB before unpacking and 48 MiB
  after (a small gzip can unpack to gigabytes); a pydantic schema that sets
  the type and length of every field (`hub.py`); the top-level shape of
  each source's data; links only as paths on the site; no `host.*` findings
  from a collector; NaN and Infinity refused. Ten bad tokens from one address
  in five minutes block that address; one host may upload 120 times a minute.
- **TLS:** `[upload] url` must be `https://`, except to a hub on the same
  machine, and the certificate is checked against the system CA store with
  no setting to turn that off.
- **One command:** the reply is `{"last_seq": n}`, plus `update_to` (a
  commit) when the hub has asked the host to update. The collector acts on
  nothing else in it. See "Updates from the hub". Other actions (ban, unban,
  restart) would need their own design.
- **Findings:** each collector works out its own findings with its own
  `[exposure]` settings and sends them. The hub adds `host.silent` (High)
  when a host misses three of its longest intervals, or never reports within
  ten minutes of being added, and `host.clock_skew` (Low) when `sent_at` is
  more than five minutes off the hub's clock.
- **Logging:** every refusal is logged as `Refused upload from <address>:
  <reason>`. The fail2ban filter counts only the bad-token ones, so a
  collector that sends one malformed upload isn't banned.

A compromised host can still send false data about itself. That is true of
any agent, push or pull. `host.silent` and a provider's own alarms (CPU,
traffic) are the checks it can't forge.

### Pages

On a hub, `/` lists the hosts: state, last upload, open findings by
severity, system, version and the address it uploads from. The Version
column holds the update buttons (see "Updates from the hub"). Each host's pages
are the usual ones under `/h/<host>/`, built with that host's own settings
from its last upload, so its Exposure page uses its own `expected_public`
and `upstream_allow`. A single-host install keeps its URLs.

The hub's web process is the database writer (it stores uploads); on a host
the web process stays read-only.

### Updates from the hub

The hub can ask a host to update to the hub's own commit. It is the only
thing the hub can make a host do. The pieces:

- **Request.** From the Hosts page ("Update to <commit>" for one host,
  "Update N hosts" for all) or `daemonsight hub update NAME|--all`, the hub
  sets `update_to` and `update_asked` on the host's row. Only hosts that have
  reported, run another commit and haven't turned updates off are offered.
  A request that hasn't been picked up can be cancelled. The page's update
  action refuses cross-site posts.
- **Reply.** While `update_to` is set, each upload's reply carries it as
  `update_to`, unless the upload said `remote_update` is off.
- **Collector.** `collector/remote_update.py` checks the value is a commit
  (7 to 40 hex characters) and not the host's own, and that
  `[upload] remote_update` is on. It then writes the commit to
  `update.request` in the data folder (0600). It installs nothing itself,
  because installing restarts it, and it runs under systemd's sandboxing.
  If a request is waiting, or the last attempt at that commit
  started or ended less than an hour ago, it does nothing, so a failing
  update isn't retried every 30 seconds.
- **Path and service.** `daemonsight-update.path` starts
  `daemonsight-update.service` when `update.request` exists. The service runs
  `daemonsight-update --hub-request` as root, unsandboxed, with a 20 minute
  limit.
- **Commit check.** The script deletes the request, reads the commit from it,
  and re-checks `remote_update` from the host's own config. It fetches the
  GitHub repo into its root-owned clone and refuses a commit that isn't in
  it, or that is neither an ancestor of `origin/main` nor contained in a
  `v*` tag. The hub never names a repository.
- **Result.** The script writes `update.result` (`ref`, `status`, `at`,
  `detail`; 0640). The collector sends it with each upload. `detail` is a
  fixed phrase from the script, never command output. Statuses: `running`,
  `done`, `failed` (the script stopped with an error), `refused` (updates
  off, or the commit isn't in the repo or on main or a release tag) and
  `rolled_back`.
- **Rollback.** After installing, the script waits 20 seconds. If
  `daemonsight-collector` isn't active, it installs the commit it replaced
  and reports `rolled_back`. When the previous commit is unknown, it reports
  `failed` and leaves the new one.
- **Hub side.** On each upload the hub compares what the host reports with
  the request. If the host's version now ends in the target commit, it
  clears `update_to` and logs an event, "Updated to <commit>". If the host
  reports `failed`, `refused` or `rolled_back` for that commit, dated after
  the request, it clears `update_to` and logs a medium event, "Update to
  <commit> failed", "was refused" or "failed and was rolled back", with the
  detail. Until one of those, the Hosts page shows "Updating to <commit>".
  A host that reports `remote_update` off gets no `update_to`.
- **`[upload] remote_update`** is on by default and is set only in the host's
  own config. The hub can't change it; it only learns the value from the
  upload.
- **Deploy order.** The target is the hub's own commit, so update the hub
  first, then the hosts. On a hub whose commit isn't known (an image built
  without a revision), there is nothing to offer.

### Reverse proxy

The hub's web UI and its upload route share one port, behind Caddy:

- The dashboard keeps a LAN-only access list.
- Uploads from outside use their own hostname, with an access list limited
  to each remote collector's fixed address, proxying only
  `/api/v1/ingest`.
- Set `web.trusted_proxies` to the proxy's address.

### Container image

The hub ships as an image on GitHub Container Registry
(`ghcr.io/bradbrownjr/daemonsight`), built by `.github/workflows/image.yml`
after the tests pass: `edge` and `sha-<commit>` from every push to `main`,
the version and `latest` from a `v*` tag. amd64 only for now. The base image
and every action are pinned to a digest or commit.

It runs as uid 10001 with everything in `/data`: the config (written from
`packaging/docker/hub.toml` on first start), the password, the session
secret, the database, `backups/` and `daemonsight.log` (`log_file`, rotated
at 5 MB, four files). The remote sources in phase 2b (OPNsense, Unraid)
will run in the hub, since they are API calls from the LAN.

`deploy/unraid/daemonsight.xml` is an Unraid template for it: icon, web UI
link, the read-only and no-capabilities options, and a data path and port.
It sets no restart policy, so Unraid's autostart list starts the container.
The Docker tab then manages it, including updating it from the new image.

Collectors stay native packages on each Linux host (LXC, VPS). They need root,
the host's D-Bus, `/proc` and netlink, which a container would only get by
giving up its isolation.

## Remote sources (phase 2b)

Appliances that can't run the collector are read over their own APIs by a
collector on the LAN. Each one is stored under its own `host` id, so the UI
shows it as another host. On a hub install the hub runs these sources itself.
Keys live in root-only files under `/etc/daemonsight/`, and the client sends
only reads. Rows are marked unverified until they have run against your
devices.

### OPNsense

OPNsense privileges cover a whole page, read and write alike; there is no
read-only variant. The key therefore can change what these privileges cover,
and DaemonSight's client is limited to GET in code. Use a dedicated user that
has only these privileges (names from the firewall's own `ACL.xml` files):

| Privilege | Endpoints read | Gives |
|-----------|----------------|-------|
| Services: Caddy | `/api/caddy/reverse_proxy/get`, `/api/caddy/service/status` | Sites and handlers: domain, upstream host/port/scheme, access list, health check settings. Cross-checks: a site pointing at a LAN host and port where nothing listens; an internet-facing site with no access list |
| Firewall: NAT: Destination NAT | `/api/firewall/d_nat/search_rule` | Port forwards: which LAN host and port each WAN port reaches. Cross-checks: a forward to a host where nothing listens; a forward with no destination port, which catches every port of that protocol |
| Firewall: Rules [new] | `/api/firewall/filter/search_rule` | Rules created through the API or the new UI. Cross-checks: floating pass-all rules, rules with no description |
| System: Gateways | `/api/routes/gateway/status` | WAN gateway up/down, loss, latency |
| VPN: WireGuard: Status | `/api/wireguard/service/show` | Each tunnel's peers and last handshake, so a peer that stops connecting or comes unlinked shows up |
| Status: Interfaces | `/api/interfaces/overview/export` | Interface state and addresses |
| Status: Services | `/api/core/service/search` | Which firewall services are running |
| System: Firmware | `/api/core/firmware/status` | Pending updates and whether a reboot is needed (the GET form of this endpoint is unverified) |
| Lobby: Dashboard | `/api/diagnostics/system/system_resources`, `system_disk`, `system_temperature` | CPU, memory, disk, temperatures |
| Tailscale | `/api/tailscale/status/*` | Whether the subnet routes and exit node are still advertised |

Legacy rules (the classic per-interface pages) are not in the new filter API;
they need the config backup endpoint, which is effectively full access, so
they are left out.

### Unraid

Unraid's API has a `VIEWER` role, "Read-only access to all resources" (enum
`Role` in the API's generated schema), so this key is read-only on the
server's side too. GraphQL over HTTPS with an `x-api-key` header. Introspection
is usually off, so queries are written from the published schema
(github.com/unraid/api, `api/generated-schema.graphql`).

| Query | Gives |
|-------|-------|
| `array` | Array state, capacity, parity and cache disks, `parityCheckStatus` |
| `array.disks` / `disks` | Per disk: status, temperature, read/write/error counts, `smartStatus`, spinning |
| `parityHistory` | Last parity checks: date, duration, errors |
| `docker.containers` | State, ports, auto-start, `isUpdateAvailable` |
| `vms` | Each VM's state |
| `notifications` | Unread warnings and alerts Unraid has raised |
| `shares` | Per share: free, used, cache setting |
| `upsDevices` | Battery and load, if a UPS is attached |
| `metrics` | CPU, memory, temperature |

New rules from these: disk errors or a failed SMART status, a disk above its
temperature warning, parity check errors, array not started, a container with
an update available, an unread Unraid alert, a WireGuard peer with no
handshake in a set time, a gateway down, a port forward to nothing.

### Provider firewalls

Many VPS hosts sit behind a cloud firewall policy that the host can't see.
`exposure.upstream_allow` lists the ports it lets in; findings about ports
outside it are dropped, and forward and default-accept findings drop to Low.
A candidate source to fill it automatically: the IONOS Cloud Server API
(`https://cloudpanel-api.ionos.com/v1`, `X-TOKEN` header, `GET
/firewall_policies`), unverified for VPS products.

### Signs of a compromised host (planned)

Provider alarms (CPU, network, disk) work even when an attacker stops the
monitoring on the host; these rules say which process is responsible:

- A process using most of a CPU for 30 minutes that no known unit or container owns
- A running process whose executable is deleted, or lives in /tmp, /var/tmp or /dev/shm
- Outbound connections to well-known mining pool ports (3333, 4444, 5555, 7777, 14444) or `stratum+tcp`
- A new systemd unit, timer or cron entry
- Outbound traffic or packet rate far above the host's own recent baseline

## Log collection and auditing (planned)

Planned after phase 3. Nothing here is built.

Goal: replace the LogWard stack on the Unraid server (Fluent Bit receiving
syslog on 514/udp and 514/tcp, TimescaleDB, its own web UI) with log
collection in DaemonSight, so one tool shows a host's state and its logs.

### Inputs

- **Hosts with a collector** send their systemd journal through the existing
  upload, with a cursor like the one for events, so nothing is lost while the
  hub is down.
- **Devices that can't run a collector** (a firewall, Wi-Fi access points,
  switches) send syslog straight to the hub: RFC 3164 and RFC 5424 over UDP
  and TCP, and TLS (6514) where the device supports it.

### Storage

On the hub, in a separate database file from `state.db`, so log volume can't
crowd out the rest. It gets its own `[retention]` setting and full-text
search. SQLite FTS5 is the first candidate; it needs measuring at real
volume.

### Finding problems

In order of effort:

1. **Built-in rules** for known patterns: repeated SSH or web login
   failures, sudo use, the OOM killer, kernel disk and filesystem errors,
   segfaults, units failing, disks filling. Each raises a finding or event
   with a link to the matching lines.
2. **Your own rules:** a match pattern, a severity and optionally a count
   within a window. Possibly in an existing shared format such as Sigma
   rules (to research).
3. **Rate spikes:** a source or severity logging far more than its usual
   rate.
4. **New kinds of messages:** group lines into templates (for example with
   the Drain algorithm, to research) and flag a template never seen before.

### Auditing

A trail of who did what, per host and across hosts: logins and their source
address, sudo commands, user and group changes, package installs and
removals, service and config changes.

### Pages

A Logs page per host and across hosts, with filter and search. Findings link
to the lines behind them.

### Open questions

- Volume, and how long SQLite holds up.
- What to keep and what to drop.
- The move from LogWard. Both can't listen on 514 at once, so point devices
  at the hub one at a time.
- Whether the journal upload should be opt-in per host.

## Answered in phase 1

- **psutil needs root for socket owners.** Run unprivileged on Debian 13 with psutil 7.2.2, `net_connections()` lists every listener but returns `pid=None` for sockets of other users.
- **D-Bus library: dbus-fast 5.2.** Unprivileged `ListUnitsByPatterns` and `Properties.GetAll` work as the systemd docs say. The system bus rejects more than 128 pending replies per connection (`LimitsExceeded`, `max_replies_per_connection`), so property reads are capped at 32 in flight.
- **Docker API** paths, the health states, the log frame format and the CPU formula are taken from the v1.47 OpenAPI spec. The collector uses the server's own `ApiVersion` from `GET /version`. Not yet run against a real Docker host.
- **Read-only SQLite** works while the collector holds the database open; when it's stopped, the web falls back to `immutable=1`.
- **Web port** is 8466. 8090 is common and was already taken on beta.
- **`expose.docker_bypass`** moved into phase 1: it needs only Docker data.

## Answered in phase 2

- **fail2ban: socket, not CLI text.** fail2ban 1.1.0's client and server exchange `pickle.dumps(value) + b"<F2B_END_COMMAND>"` (client/csocket.py, server/asyncserver.py); replies are `(0, result)` or `(1, exception)` (server/transmitter.py); `IPAddr.__reduce__` pickles addresses as `str` (server/ipdns.py). So results are builtins. The collector's unpickler accepts only builtin data types and exceptions, plus fail2ban's own exception names as empty stand-ins. Tested against a real `fail2ban-server` run unprivileged; the raw replies are kept in `tests/fixtures/fail2ban-1.1.0.json`. Debian 12's 1.0.2 uses the same transmitter commands but hasn't been tested.
- **Caddy JSON** field names come from the v2.11.9 source (routes.go, subroute.go, reverseproxy.go, matchers.go, ip_matchers.go). Tests parse Caddy's own adapter test cases (`tests/fixtures/caddy/`), which pair a Caddyfile with the JSON Caddy produces.
- **iptables-save, not only nft.** A Debian 12 VPS with iptables 1.8.9 (nf_tables backend) had no `nft` binary at all. Its ruleset is read with `iptables-save`; the test fixture `tests/fixtures/iptables/vps-v4.txt` has the same shape with documentation addresses.
- **A wildcard bind is only "internet" when the host has a public address.** On a LAN host such as an LXC behind NAT, 0.0.0.0 means reachable from the LAN.

## To verify

- Whether `nft list ruleset` needs `CAP_NET_ADMIN`. nft(8) doesn't say.
- Which capabilities could replace full root for the collector (likely `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, plus Docker socket access).
- The nft JSON reader against real `nft -j list ruleset` output from a host with native nft tables (written from libnftables-json(5) only).
- The Caddy source against the VPS's Caddy.
- fail2ban 1.0.2 on Debian 12.
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
10. Docker Compose labels: https://github.com/docker/compose/blob/main/pkg/api/labels.go
11. Wazuh architecture: https://documentation.wazuh.com/current/getting-started/architecture.html
12. apt-get(8) (`-s` simulation, `Debug::NoLocking`), Debian 13: https://manpages.debian.org/trixie/apt/apt-get.8.en.html
13. needrestart(1) and batch mode output: https://github.com/liske/needrestart (man/needrestart.1, README.batch.md)
