# DaemonSight design

Status: phases 1, 2, 2c, 3a and 3b are built; 3c is next. Updated 2026-11-18.

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
- A hub that ships as anything but a container. A collector-and-web install can't also be a hub. (So a standalone host's Vulnerabilities page only says CVE matching runs on a hub.)
- Podman, Kubernetes, nginx, Apache, iptables-legacy.

## Architecture

```
                 root                                 user: daemonsight
 ┌──────────────────────────────┐                 ┌─────────────────────┐
 │ daemonsight-collector        │                 │ daemonsight-web     │
 │  system · systemd · ports    │   writes        │  FastAPI + Jinja2   │
 │  docker · caddy · fail2ban   ├──────────┐      │  HTMX, read-only    │
 │  nftables · packages         │          ▼      │                     │
 │  findings · alerts           │   /var/lib/daemonsight/state.db ◄──────┤
 └──────────────────────────────┘                  └──────────┬──────────┘
                                                              │ 127.0.0.1 or wg0
                                                              ▼
                                                      browser (via Caddy)
```

Systemd units. There is no scan unit: CVE matching runs on the hub
(see "CVE matching"), so a host runs no scanner and downloads no
vulnerability data.

| Unit | Runs as | Does |
|------|---------|------|
| `daemonsight-collector.service` | root | Long-running asyncio loop. Each source has its own interval. Writes snapshots, computes findings, sends alerts. |
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
| Operating system | `/etc/os-release`: `PRETTY_NAME`, `ID`, `ID_LIKE`, `VERSION_ID`, `VERSION_CODENAME`; `platform.release()` for the kernel; release dates from the distro-info-data CSVs | 15 s (with the system snapshot) | The snapshot carries `os`, `os_id`, `os_like`, `version_id`, `version_codename` and `kernel`. Only Debian, Ubuntu and Fedora are judged (Fedora's dates are in `data/fedora/fedora.csv`, from endoflife.date, MIT licence, see its README); Raspberry Pi OS (`raspbian`) is looked up as Debian by codename. Any other ID has no support status and raises no finding. `/usr/share/distro-info/<distro>.csv` is read first when it has the release (it is newer where the `distro-info-data` package is installed); otherwise the copy bundled in `src/daemonsight/data/distro-info/` is used (ISC licence, see its README). Dates are judged against today when a finding is evaluated. [14] |
| systemd services | D-Bus `org.freedesktop.systemd1.Manager.ListUnits`; per unit `ActiveState`, `SubState`, `ActiveEnterTimestamp`; per service `NRestarts`, `MemoryCurrent`, `CPUUsageNSec` | 30 s | systemd docs: read access is granted to all clients, so this source needs no privilege. [1] |
| Listening ports | `psutil.net_connections()` (fd, family, type, laddr, raddr, status, pid), or `/proc/net/{tcp,tcp6,udp,udp6}` plus socket inodes | 60 s | PID → owner via `/proc/<pid>/cgroup`: a systemd unit, or `docker-<id>.scope` for a container. Per process it also records the command line (secrets masked, cut to 400 characters), the executable, the user and the start time. [2] |
| Docker | Engine API on `/var/run/docker.sock`: container list, inspect (`State.Health`, `State.OOMKilled`, port bindings), logs, one-shot stats | 30 s | The client sends GET only. A socket proxy is needed only if the collector itself runs in a container; Tecnativa's blocks POST by default. [3] |
| Caddy | `GET /config/` for servers and routes, `GET /reverse_proxy/upstreams` for `address`, `num_requests`, `fails` | 60 s | Default `localhost:2019`; also supports a Unix socket, which Caddy recommends. On TCP the admin API checks the Host header (admin.go `checkHost`); on a Unix socket it doesn't. [4] |
| fail2ban | The server's control socket (`/var/run/fail2ban/fail2ban.sock`): `status`, `status <jail>`, `get <jail> logpath / journalmatch / bantime / findtime / maxretry / ignoreip / actions`, `get <jail> banip --with-time` | 60 s | Pickled Python values framed by `<F2B_END_COMMAND>`, read with an unpickler that accepts builtins only. See "Answered in phase 2". [5] |
| Firewall | `iptables-save` and `ip6tables-save` when installed; `nft -j list ruleset` for native nft tables | 5 min | Input chains (default verdict, ports accepted, following jumps) and DNAT forwards. With iptables' nf_tables backend, nft shows extension matches such as multiport only as opaque `xt` expressions, so iptables-save is read for those tables. [6] |
| Packages | `apt-get -s -o Debug::NoLocking=1 dist-upgrade` (a simulation: pending upgrades, with the archive each comes from, so security updates are known), `apt-mark showhold`, `dpkg-query` for installed `linux-image-*`, `/var/run/reboot-required(.pkgs)`, the mtime of `/var/lib/apt/lists/*InRelease`, `systemctl is-enabled apt-daily.timer`, and `needrestart -b -r l` if installed | 1 h | Never runs `apt update`; the host's apt timers do, and the lists' age is reported. The simulation needs no root and changes nothing. A kernel that no installed `linux-image` package matches (an LXC, a custom kernel) is "managed by the host" and raises nothing. needrestart's batch mode lists services using old libraries without restarting them. [12][13] |
| Packages, Fedora | `dnf check-upgrade -C --json` and `--security --json` (exit 100 means updates; `-C` is cache-only), `rpm -q --qf` for installed versions, `dnf versionlock list`, `dnf needs-restarting -C --json` (exit 1 means reboot) and `-C -s` (services), `rpm -q kernel-core` against `uname -r`, the mtime of `/var/cache/libdnf5/*/repodata/repomd.xml`, `systemctl is-enabled dnf5-makecache.timer` | 1 h | Same data shape as apt, plus `backend: "dnf"`. The collector picks apt if `dpkg` and `apt-get` are on PATH, else dnf if `dnf` and `rpm` are, and needs dnf5 (dnf4 reports the source unavailable). A package is "security" when `check-upgrade --security` lists it. Never downloads or installs; with no cache, `check-upgrade -C` exits 1 with "Cache-only enabled but no cache" and the updates part reports that. `needs-restarting -C` also needs file lists in the cache; without them the reboot part falls back to `/run/reboot-required` (written by dnf5 as root) and the kernel check. No versionlock plugin means nothing is held. [15][16][17][18] |
| Automatic updates, apt | `apt-config shell L APT::Periodic::Update-Package-Lists U APT::Periodic::Unattended-Upgrade`, `systemctl is-enabled apt-daily-upgrade.timer`, and whether `/usr/bin/unattended-upgrade` exists | 1 h (with Packages) | `auto_updates` in the packages snapshot. On when the program is installed, `Unattended-Upgrade` is not `0` and the timer isn't disabled. `apt.conf(5)`: the `APT::Periodic` options are days between runs, and `apt-daily-upgrade.timer` is what runs `unattended-upgrade`. [19][20] |
| Automatic updates, Fedora | `rpm -q dnf5-plugin-automatic`, `systemctl is-enabled dnf5-automatic.timer`, and `apply_updates` and `upgrade_type` under `[commands]` of the files dnf5-automatic reads, in its documented order (later wins) | 1 h (with Packages) | On when the plugin is installed, the timer is enabled and `apply_updates` is on. Fedora's shipped default is `apply_updates = no`: the timer then only downloads. [21] |
| Installed packages (apt) | `dpkg-query -W -f '${db:Status-Abbrev}\t${source:Package}\t${source:Version}\t${Package}\t${Version}\n'`, plus `/etc/os-release` | 1 h, only when `[upload]` is set | The `inventory` source. One row per source package and version, with its binary packages. Sent to the hub in the upload's own `inventory` field (see "CVE matching"). [22] |
| Pending advisories (Fedora) | `dnf advisory list --updates --security --json -C` and `dnf advisory info --updates --security --json -C`; CVE ids are read from each advisory's description and reference titles | 1 h, only when `[upload]` is set | Fedora's advisories carry Bugzilla references, not CVE-type ones, so `--with-cve` and `--cves=` match nothing; the CVE ids are in the text. [23] |
| Debian security tracker | `https://security-tracker.debian.org/tracker/data/json` | hub, 24 h | Read by the hub, a CVE at a time. Fields kept: status, fixed version, urgency, nodsa reason, a short description. [24][25] |
| EPSS | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | hub, 24 h | All scores. Free, no registration; FIRST asks for attribution. [26][27] |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | hub, 24 h | CC0 1.0. [28] |

Not used: Trivy. Two of its releases were compromised (GHSA-69fq-xp46-6x23
and GHSA-mcj4-mphf-j9ff), and a scanner binary on every host is the
attack surface this design avoids. debsecan reads the same Debian tracker
data; the Vulnerabilities page offers it as a command to cross-check by hand. [9]

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
| `pkg.lists_stale` | The package lists are over 3 days old (age is the newest list file, which apt dates by the repository's publish time). Names an unset `APT::Periodic::Update-Package-Lists`, the usual cause when apt-daily.timer runs but does nothing. When `pkg.auto_updates_off` also fires it points there for the fix instead of repeating it | Low |
| `pkg.auto_updates_off` | Nothing installs updates on its own: apt, unattended-upgrades missing, switched off (`Unattended-Upgrade` is `0` or unset) or its `apt-daily-upgrade.timer` disabled; Fedora, `dnf5-plugin-automatic` missing, its timer not enabled, or `apply_updates` off. Not raised for `role = "workstation"` (desktops update through the software centre) or when the collector couldn't read the settings | Low |
| `cve.package` | One per source package on the hub: an open or fixable CVE is on CISA's KEV list, or a fixable one has an EPSS score of 0.10 or more (`[cve] epss_high`): High. Otherwise a fix is available: Medium. Unfixed CVEs that aren't on KEV, and "won't fix or minor" ones, make no finding. | High or Medium |
| `cve.feed_stale` | A feed has had no successful fetch (a 200 or a 304) for over 3 days. Opened on every host with a package list | Low |
| `os.lts` | A Debian release is past regular support and inside LTS, or an Ubuntu release is past standard support and inside ESM | Low; Medium within 180 days of the end of LTS or ESM |
| `os.eol_soon` | A Fedora release is within 60 days of its EOL date | Low |
| `os.eol` | A Debian release is past LTS (paid ELTS only, or nothing), an Ubuntu release is past ESM, or a Fedora release is past its EOL date | High |
| `svc.failed` | A unit is in `failed` | High |
| `ctr.down` | A container exited non-zero, is unhealthy, or was OOM-killed | High |
| `caddy.admin_tcp` | The admin API listens on TCP instead of a Unix socket | Low |
| `tls.expiring` | A served certificate expires within 14 days (phase 4) | High |
| `sys.disk` / `sys.memory` | Above 90% for 15 minutes | Medium |
| `remote.unreachable` | The hub could not read a remote system for 3 polls and at least 3 minutes (see "Unraid"). Its last readings and findings stay as they were | High |
| `unraid.disk_full` | A disk, or the array's data disks together, is at 90% or more | Medium; High at 95% |
| `unraid.disk_state` | A disk is disabled, missing, invalid, wrong or emulated (`DISK_DSBL`, `DISK_NP_DSBL`, `DISK_NP_MISSING`, `DISK_INVALID`, `DISK_WRONG`, `DISK_DSBL_NEW`) | High |
| `unraid.disk_errors` | `numErrors` above zero on an array or cache disk | High |
| `unraid.disk_temp` | A disk at or over Unraid's own warning (Medium) or critical (High) temperature: the `display` values for hard disks; 60 and 70 C for SSDs and NVMe, which the API doesn't expose; 45 and 55 C for hard disks if `display` can't be read | Medium or High |
| `unraid.disk_smart` | `smartStatus` is not `OK` for a disk that is not a USB device. The API can't say "failed": it returns `OK` or `UNKNOWN` | Medium |
| `unraid.array_state` | The array is not `STARTED`: stopped, or in a reconstruction state | High when stopped; Medium otherwise |
| `unraid.parity_errors` | The last completed parity check found errors. The detail says what a sync error is, whether an unclean shutdown was recorded shortly before the check (from the notifications), whether a later check was cancelled or failed (from `parityHistory`) and that the sector numbers are only in Unraid's syslog for that boot. A later clean check ends the finding | High |
| `unraid.parity_old` | No completed parity check, or the last one was over 100 days ago and none is running. When `parityHistory` shows a check cancelled or failed after the last completed one, the detail says when it started and after how long it stopped. Not raised while the array is stopped or has no parity disk | Low |
| `unraid.container_updates` | One finding when any container has `isUpdateAvailable`: "N containers have updates", the names (40 shown, then "and N more") and a link to the Containers page. The basis is the sorted names, so an accepted finding returns when a different container needs an update. Replaces the old `unraid.container_update`, one finding per container; its open findings are resolved at the first poll | Low |
| `unraid.unclean_shutdown` | Unraid's unread alerts with the subject "Unclean shutdown detected" (Parity Check Tuning plugin, or Unraid itself), grouped into one finding: "Unraid shut down uncleanly N times since DATE", every date in the detail. The basis is the set of times, so a new crash brings back an accepted finding | Medium |
| `unraid.notification` | Every other unread warning or alert, one finding per distinct title (repeats grouped; the detail has the newest subject and description, the count and the newest and oldest date), plus one summary, "N unread Unraid alerts and warnings", for the whole inbox. Notices about conditions DaemonSight checks live are dropped as findings (see "Notifications") but stay on the Notifications page. The text is the server's, cut and escaped | Medium when the group has an alert, Low for warnings; the summary is Low |
| `unraid.os_update` | The newest stable Unraid release is newer than the version the API reports (see "The newest release"). "Unraid X is available (running Y)", with a link to the release notes. The basis is the new version | Low |
| `outside.unexpected_port` | Shodan's InternetDB lists a port as open on one of the host's public addresses and the port is not in `exposure.expected_public` (any protocol: InternetDB gives port numbers only; the Shodan API source names the transport and the software in the detail, but the rule still compares port numbers). The detail says what DaemonSight knows about it: a listener on the host (process, unit or container), a DNAT forward that covers it (its target, and the interface or tunnel that reaches it), a container that publishes it, or that nothing on the host listens on it. Key `<ip> <port>` (see "The outside view") | High |
| `outside.not_seen` | A port DaemonSight judges internet-reachable (listening on a public address, past the host and provider firewalls, not forwarded away) and expected is not in Shodan's list for the address. Worded as possibly fine: not scanned yet, or blocked by a provider firewall. When Shodan has no record of the address, one per expected port, with that said. Not raised for an IPv6 address Shodan has no record of | Low |
| `outside.tagged` | Shodan tags the address `compromised`, `malware`, `c2` or `doublepulsar`. Other tags (cloud, cdn, vpn, scanner, honeypot, tor, self-signed ...) are shown on the Exposure page and make no finding | Critical |
| `outside.vulns` | Shodan lists CVEs for the address. The detail says they are guesses from service banners and names which of them DaemonSight's own `cve.*` matches for the host also have | Medium |
| `outside.stale` | No good answer for an address for three refreshes (at least 72 hours). The other `outside.*` findings keep following the last good answer | Low |
| `outside.key` | Only with the Shodan API source: Shodan refused the key (HTTP 401 or 403), has no query credits, or the source is the Shodan API but no key is saved. One per host, key `shodan`, raised at the first failed pass instead of after 72 hours. The detail says nothing is falling back to InternetDB | Medium |
| `unraid.ups` | The UPS is on battery (Medium; High at 30% charge or below, or when it reports low battery), charge under 50% (Medium), or its battery needs replacing (Low) | Medium, High or Low |

Hub rules for remote systems (`remote.*`, `unraid.*`) and the outside view (`outside.*`) are computed by the hub
and kept by its reconcile, like `host.*` and `cve.*`; a collector's upload
may not carry them. Each has no fix command (they are decisions), a basis
that brings an accepted finding back when it changes (for example `disk3:high`
when a disk crosses 95%), a link to the row it is about and a `howto` of plain
steps. The menu paths in the steps are the ones in Unraid's docs and webgui
source [38] to [42]; where a path could not be verified the step says "in the
Unraid web UI".

#### Notifications

Unraid's unread inbox mixes notices DaemonSight already checks live, one-off
events and everything else. Each notification is classified once
(`remote/unraid_notify.py`, one pattern table with the sources of the
formats in its header comment; every pattern was also checked against a real
inbox of 235 unread warnings and alerts):

| Kind | Title pattern (subject) | What DaemonSight does |
|------|------------------------|-----------------------|
| disk usage | `Unraid <disk> disk utilization` | Dropped as a finding; covered by `unraid.disk_full` |
| disk temperature | `Unraid <disk> temperature` | Dropped; covered by `unraid.disk_temp` |
| parity check or sync | `Unraid Parity check`, `Parity-Check`, `Parity-Sync`, `Read-Check`; and Parity Check Tuning with a subject like `... Parity-Check finished (N errors)` or `canceled` | Dropped; covered by `unraid.parity_errors` and `unraid.parity_old`, which read `parityHistory` |
| rebuild or clear | `Unraid Data-Rebuild`, `Unraid Disk-Clear` | Dropped; covered by `unraid.array_state` while it runs |
| Docker update | `Docker - <name> [<version>]` | Dropped; covered by `unraid.container_updates` |
| unclean shutdown | any title, subject `... Unclean shutdown detected` | One finding, `unraid.unclean_shutdown` |
| Fix Common Problems | `Fix Common Problems - <server>` | A finding per title; steps: Settings → User Utilities → Fix Common Problems |
| SMART attribute | `Unraid <disk> SMART health [<id>]` | A finding per title; steps: the disk's SMART report |
| disk in error, array errors | `Unraid <disk> error`, `Unraid array errors` | A finding per title |
| Docker image disk | `Docker high image disk utilization` (or critical) | A finding per title; steps: Container Size, Docker vDisk size |
| anything else | | A finding per title, with the generic step: read it in Unraid (the bell icon) and archive it once handled |

All of them are listed on the Notifications page with date, title, subject,
description and what DaemonSight does with each, so nothing is hidden by being
dropped as a finding. The hub reads them with `list(filter: {type: UNREAD,
importance: ALERT|WARNING, ...})` rather than `warningsAndAlerts`: that field
drops repeats (one notification per importance, title, subject, description
and link) and stops at 50, so thirteen unclean-shutdown alerts came back as
one, and `list`'s `limit` counts the newest files of any importance before it
filters, so it is set to 2,000 (`truncated` is shown when the inbox is
larger). At most 400 are stored, alerts first. Archived notifications drop out
of the inbox and so out of these findings.

### Finding fields

| Field | Meaning |
|-------|---------|
| `rule`, `key` | Which rule, and which thing it found. One open finding per pair. |
| `severity`, `title`, `detail`, `link` | What the page shows. `link` is a path on this site (a row's anchor). |
| `fix` | The exact command or commands that resolve it, one per line. `None` when no single command does: an exposed port needs a decision. Commands that differ by package system (apt or dnf) follow the host's. A line starting with `#` is a comment for the person pasting it. |
| `basis` | What the finding is about, without numbers that drift. `None` means the title. Accepting a finding is tied to a hash of the rule, key and basis. |
| `howto` | Optional plain-language steps, one per line, shown under the detail as "What to do" (a numbered list) on the Overview, the report page and the Markdown report. Only the hub's own rules (`unraid.*`, `remote.*`, `cve.feed_stale`) set it. A finding with `howto` and no `fix` is still a decision in the report, with its steps shown. Stored in the `findings` table (schema 6); never in an upload: `FindingIn` has no such field and the collector's upload leaves it out, so older hubs and collectors are unaffected. |

`fix` and `basis` are stored in the `findings` table (NULL for rows from before
schema 4) and travel in the upload's findings. Both are optional in the upload,
so a collector from before they existed still reports. The hub refuses a `fix`
with control or format characters (other than newlines) or over 2,000
characters. The collector leaves the two keys out of the upload when they are
`None`, so a collector updated ahead of its hub still reports unless it has a
fix to send; update the hub first.

The report's step for a rule is a fixed mapping (`findings.STEP_OF`), not a
stored field, so older collectors get steps too. A finding with a `fix` joins
the card for its step; with no `fix` it is listed as a decision.

| Rule | `fix` | Step | `basis` |
|------|-------|------|---------|
| `pkg.security_updates` | `apt upgrade` or `dnf upgrade --refresh` | upgrade | The set of package names. A new one brings it back. |
| `pkg.updates` | same | upgrade | Constant. Accepting it means "regular updates may wait here". |
| `pkg.lists_stale` | `apt update`, only when the finding itself advises it (the Update-Package-Lists case) | upgrade | Constant (the age drifts). |
| `cve.package` | the upgrade command when a fix exists; apt adds `apt update` first when apt isn't offering it yet. None when no fix exists. For the kernel (`linux`): `sudo reboot` when a newer kernel is already installed (`pkg.reboot` is open), otherwise the upgrade followed by `sudo reboot` | upgrade; reboot for the kernel | The set of CVE ids. A new CVE brings it back. |
| `pkg.restart` | `needrestart -r a` (apt) or `systemctl restart` with the listed services (dnf) | restart | The set of service names. |
| `pkg.reboot` | `sudo reboot` | reboot | The newer kernel version, if any. |
| `pkg.auto_updates_off` | The install or enable commands for the host's system. None when the fix is a config edit | auto-updates | The title. |
| `os.eol_soon` | The three `dnf system-upgrade` commands | os-upgrade | The title (it holds the EOL date). |
| `os.lts`, `os.eol` | None | os-upgrade | The title. |
| `expose.unexpected` | None | none | Port, protocol, process name and severity. |
| `expose.docker_bypass` | None | none | Port, protocol and container name. |
| `expose.forward_all` | None | none | Family, protocol, destination, port list and, with an upstream policy, the ports it lets in. |
| `jail.uncovered` | None | none | Service name and port. |
| `caddy.admin_tcp` | None | none | The admin address. |
| `sys.disk` | None | none | Mount point and severity. 86% to 88% is no change; crossing into High is. |
| `sys.memory` | None | none | Constant. |
| `firewall.duplicate_rules` | None | none | Constant (the count drifts). |
| `outside.unexpected_port` | None | none | IP, port and a digest of what DaemonSight knows about the port (process, forward target). |
| `outside.not_seen`, `outside.stale` | None | none | IP (and port, for `not_seen`). |
| `outside.tagged` | None | none | IP and the critical tags. |
| `outside.vulns` | None | none | IP and a digest of the CVE list. |
| Others (`svc.failed`, `ctr.down`, `route.*`, `jail.log_missing`, `firewall.default_accept`, `collector.source`, `cve.feed_stale`, `host.*`) | None | none | The title. |

`svc.failed` has no `fix`: its detail advises `journalctl -u <unit>`, which
finds the cause and doesn't resolve it.

Steps run in this order: upgrade, restart, reboot, auto-updates, any finding
with a `fix` and no step (one card each), then os-upgrade. In the upgrade
step, `apt update` comes before `apt upgrade`. When a kernel package has a
CVE fix pending and `pkg.reboot` is also open, the upgrade card says to reboot
afterwards. A kernel that is already installed but not running is
`pkg.reboot`'s job: the CVE matcher compares the installed package version, so
it no longer reports a fixed kernel.

### Accepting a finding

An open finding can be accepted with a note of 1 to 500 characters. The
acceptance lives in the `accepted` table (host, rule, key, fingerprint, note,
accepted_at, accepted_by), and the finding stays in `findings`.

- Accepted findings are left out of counts, severity badges and lists of what
  needs attention: the Overview card's count, the Hosts page severity summary
  and its "Reboot needed" badge, and the report's steps and severity groups.
  They are not hidden. They stay in the Overview findings list, in place, with
  an Accepted label and the note, who and when (see "Status labels"), and
  the report keeps its own "Accepted" section. A host's "Not reporting" state
  still follows `host.silent`, because it says what the host is doing.
- The fingerprint is a SHA-256 of rule, key and basis. When the open finding's
  fingerprint differs from the accepted one, the finding is open again, with
  "Accepted on <date> (<note>) — this has changed since". Accepting it again
  replaces the acceptance.
- When a finding resolves, its acceptance is deleted. If it returns, it is a
  new finding.
- A port's panel on the Exposure page ends with that port's exposure finding:
  a note field with Accept risk and Cancel, or, once accepted, the note and
  Un-accept. Accepting from there returns to the port's row. The panel also
  lists what each Caddy site on the port does (its handlers), so the decision
  can be made from the panel.
- Accepting and un-accepting write "Accepted: <title>" and "Un-accepted:
  <title>" to Recent changes, with the note.
- Only a hub can accept. The web process of a single host opens the database
  read-only and stays that way, so its pages show no Accept buttons. A hub's web
  process is the writer already. `accepted_by` is the session's user name,
  which is `admin`, the only login.
- Routes: `POST /h/<host>/findings/accept` (rule, key, note, next) and
  `POST /h/<host>/findings/unaccept` (rule, key, next). Both need the login and
  refuse a cross-site request as `/hosts/update` does, then redirect to `next`
  (a local path, with the finding's anchor) and show a one-line notice.
- Only collectors from this version send `basis`. A finding from an older
  collector has the title as its basis, so an accepted `sys.disk` finding
  returns once when its collector is updated, then follows the new basis.

### The report

Each host has a report at `/h/<host>/report` on a hub and `/report` on a single
host, linked from the Hosts page, the Overview and the menu. `report.build`
makes one structure from the database and two renderers use it: the page and
`to_markdown`. `GET .../report.md` needs the login and sends
`text/markdown; charset=utf-8` with `Content-Disposition: attachment;
filename=<host>-report-<date>.md`. "Copy as text" copies the same Markdown from
a hidden text area.

It shows a header (host, OS and support status, kernel, uptime, role, last
upload, DaemonSight version, time generated), then:

1. **Steps:** one card per step with the merged commands and a Copy button, and
   the findings it clears, each linked to its row.
2. **Decide:** findings with no `fix`, with their detail.
3. **All findings:** Do now (critical and high), Do soon (medium), When
   convenient (low).
4. **Accepted:** with notes. A finding whose acceptance changed shows as open,
   flagged, not here.

Text from a host is untrusted. The page escapes it. The Markdown escapes every
character with a meaning inside a line, puts each part of a finding in its own
paragraph, and fences commands with a fence longer than any run of backticks in
them. The commands are shown to be copied, never run by DaemonSight; read them
before you paste. A print stylesheet hides the menu, buttons and forms, and
keeps steps and findings from splitting across pages.

Fedora has no LTS: a release is "Supported" until its EOL date, then "End of
life". A release whose EOL is not announced yet counts as supported with no
date; Rawhide is not judged. `os.eol_soon` reads "Fedora 43 support ends on
<date>" and gives the upgrade steps to the current release:
`sudo dnf upgrade --refresh`, `sudo dnf system-upgrade download --releasever=N`,
`sudo dnf system-upgrade reboot` [17].

`os.lts`, `os.eol_soon` and `os.eol` link to the "Operating system" entry under "At a glance"
on Overview (`/#os`). Both name the current release (Debian's newest stable,
Ubuntu's newest LTS) as the upgrade target. The status text is one of
"Supported", "LTS until <date>", "ESM only (Ubuntu Pro) until <date>", "No free
security updates (ELTS only, paid) since <date>" or "End of life".

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
rows hourly; the hub prunes every host's. Open findings are never pruned. On a
hub the Settings page can change it (see "Settings and configuration
precedence").

- `snapshots`: source, taken_at, ok, error, data (JSON). The latest row per source is current state.
- `findings`: rule, key, severity, title, detail, link, fix, basis, howto (schema version 6), first_seen, last_seen, resolved_at.
- `accepted`: host, rule, key, fingerprint, note, accepted_at, accepted_by. Written by the hub's web process (see "Accepting a finding"). Schema version 4.
- `remotes` (schema version 5): id, kind (`unraid`), url, enabled, tls (`verify` or `pin`), tls_pin (SHA-256 of the pinned certificate), tls_cert (its PEM), interval, created_at, last_ok, last_error, fails. A remote system is also a row in `hosts` with `hosts.kind` set (collector hosts have `kind` NULL) and a `token_hash` of `remote:<id>`, which no upload token can equal. The API key is not in the database: it is `<data>/remotes/<id>.key`, mode 0600 in a 0700 folder.
- `outside` (schema version 7): ip, first_try, checked_at, fetched_at, status (`ok`, `none` for a 404, `error`), data (the cleaned answer, JSON: an InternetDB answer as is; a Shodan API answer carries `source: "shodan"`, `services` and `last_update` as well), error. Hub only; see "The outside view".
- `settings` (schema version 8): key, value (JSON), changed_at, changed_by. Hub only: what was saved on the Settings page, over the config file. See "Settings and configuration precedence".
- `events`: changes worth showing in "Recent changes": a new port, a ban spike, a unit going down. Events are per host (`host` is NOT NULL and every list filters by it). A change that belongs to no host, a setting changed on the hub, is stored with the reserved host `""` (`db.HUB_HOST`), which no host id can equal (`hub.HOST_RE` needs at least one character). They show under "Recent hub changes" on the hub's Hosts page and on the Settings page, never under a host. The same retention applies to them. This reuses the one events table and its pruning, instead of a second log with its own retention and display code.
- `metrics`: ts, name, value. Raw points for `[retention] metrics_hours`. Longer history as 5-minute averages is planned with the charts (phase 4).

Backups (`backup.py`): one owner-only `.tar.gz` with a consistent copy of
the database (SQLite's online backup API, so the writer keeps running), the
config, the password hash, the session secret, any upload token and the
remote systems' key files (`remotes/<id>.key`, checked by name on restore
and written back 0600), plus a manifest. The folder is 0700 and each archive 0600. The hub, and a collector that keeps its own data, make one every
`[backup] interval_hours` (24) and keep `keep` (7). A collector that
uploads skips them unless `interval_hours` is set: the hub's backups hold
its history. `daemonsight restore` refuses while the writer
holds `daemonsight.lock` in the data folder, checks the archive's names (it
never extracts by path), the database's integrity and its schema version,
and keeps every file it replaces as `<name>.before-restore`.

### Settings and configuration precedence

A setting's effective value is, in this order: a row in `settings` (set on
the Settings page), the config file, the default in `config.py`. The file is
never rewritten. `settings.py` holds the list of editable fields (`FIELDS`:
key, label, type, range, help), which is also the list of what a POST may
carry: any other name refuses the whole request. `READ_ONLY` lists what the
page shows but never edits (listen address and port, trusted proxies, cookie
and session settings, password and secret files, data, database and backup
folders, log file, hub flag and upload limits, upload settings), each with its
reason: a mistake there could lock the administrator out of the page needed to
fix it.

Editable on a hub: `outside.enabled`, `outside.source` (a choice of two, kind `choice`), `outside.addresses`,
`outside.refresh_hours`, `cve.enabled`, `cve.refresh_hours`, `cve.epss_high`,
all three `retention.*`, `backup.interval_hours` (blank is automatic, stored
as null), `backup.keep`, and `remote.enabled`. `backup.dir` is read-only: it
decides where files holding secrets are written. `outside.key_file` (the Shodan key's path) is read-only for the same reason.

`config.load` records which keys the file set (`Config.file_keys`), so the
page can say Config file or Default. `settings.effective(base, conn)` returns
a copy of the config with the valid rows applied (a row that doesn't fit its
field, or names an unknown key, is logged and ignored), or `base` itself when
there are none. Only a hub reads the table: the web process of any other
install opens the database read-only, so it shows file and default values
only. The old `[collector] metrics_retention_hours` is cleared when a
`retention.metrics_hours` row is applied, or it would still win.

Live reload, per consumer. The hub's web process is the only writer of the
table and runs the chores, so a saved change is visible to the next read.

| Consumer | When it reads |
|---|---|
| `cve.run.Chore` | start of every `run_once` (each minute). Off: closes `cve.*` findings and returns. A new `epss_high` or turning it on again recomputes the findings |
| `outside.Chore` | start of every `run_once`. Off: closes `outside.*` findings and returns 0. Addresses and `refresh_hours` are used from that pass |
| `remote.poll.loop` | every 5 seconds, before it reads the systems |
| `_hub_chores` (retention, backups) | every minute; pruning stays hourly, with the values read at that pass |
| Pages (`views`, Exposure and Vulnerabilities text) | per request, through `settings.effective(cfg, conn)` on the reader connection |

All three loops now start with the hub whatever the file says, and each decides
every pass, so nothing needs a restart. They used to start only when enabled in
the file.

`POST /settings` needs the login and the same `Sec-Fetch-Site` check as the
other hub POSTs. It parses every posted value (`settings.parse`: whole numbers
for integers, finite numbers in range for decimals, On or Off, public IP
addresses with `ip` or `ip=hostid` for the address list), and saves nothing
unless all are valid; on an error the page is drawn again with the messages and
what was typed. `outside.source = shodan` is refused when no Shodan key is saved. A value equal to the one in effect is skipped. `reset=<key>`
deletes the row. Each change or reset also writes a hub-wide event, such as
"Setting changed: Outside view, enabled: off → on" or "Setting reset: Backups,
keep: 20 → 3 (config file)", in the same transaction. The Shodan API key is not
a setting and is never in the table: it has its own route, described under "The
outside view".

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
matches the logo's gem. The account menu chooses Light, Dark or Auto, kept in
the `theme` cookie (dark until chosen). Auto follows `prefers-color-scheme`:
the server renders dark and `/static/theme.js`, loaded in the head, corrects it
before the page paints and follows later changes; the logo is a `picture` with
a dark source for the same media query. Tabler ships both as built-in
attributes (`data-bs-theme`, `data-bs-theme-base`, `data-bs-theme-primary`), so
there is no custom CSS to maintain.

Pages: Overview, Exposure, Caddy routes, Services and containers, fail2ban, Packages, and on a hub Vulnerabilities.
On a hub, Hosts is the front page.

Hosts page: a host with an open `pkg.reboot` finding shows a "Reboot needed"
badge in its State cell, linking to that host's Packages page
(`/h/<host>/packages#reboot`). The System cell shows the OS, the running kernel
and the uptime; a support status other than "Supported" (such as "LTS until
2028-06-30") shows as a badge beside the OS. On Overview, "At a glance" lists
the OS with its support status.

Phone menu: the header chip on a phone shows only the status dot and host name.
The top of the menu panel holds one line with the OS, its support status when it
is not plain "Supported", the kernel and the uptime. It appears on host pages
only, never on the hub's Hosts page. The desktop header is unchanged.

Row links: a finding links to the row it is about, such as an Exposure port,
a Caddy site, a forward or a jail (the row's `id` is built by
`findings.anchor`). `app.js` (`showTarget`) scrolls to that row, clears a
filter that hides it and flashes it once; the flash is off under
`prefers-reduced-motion`.

### Layout and wording rules

These apply to every page. Check each layout change in a browser at desktop
(1400 px) and phone (390 px) widths before it ships.

- **Symmetry all the way down.** A page picks its columns once and keeps them
  to the bottom: every card in a column is the same width, and column edges
  line up from the first card to the last. A page may have one column or a main
  column with a side column (a host's Overview), but a card is never narrowed
  in one place to make room for something beside it. A guide that would sit
  beside one card goes inside it, folded (`details`).
- **Short up front.** A card opens with one sentence at most. Longer text
  (terms, caveats, how something is worked out) goes behind an (i) button in the
  card title that opens a popover, or in a small note at the foot of the page.
  On the Settings page that is a group's `note`, `note_title` and `note_links`
  in `settings.GROUPS`; on data pages it is the source panel (`src_button`,
  `src_panel`).
- **Alerts are for now.** A coloured alert box is for something that just
  happened or needs action now (a save, an error). Standing information never
  goes in one.
- **Dependent options sit under their control.** An option that only matters
  for one value of another setting (the Shodan key under Source) is indented
  under it (`.ds-subpanel`) and shown only while that value is chosen
  (`data-ds-when="<select id>=<value>"`, read by `app.js`). Without JavaScript
  it stays visible. It belongs to the same form and the same Save button; any
  other action on it posts that form elsewhere with `formaction`, never a
  nested form.
- **Field help.** One or two short sentences under the control; the default and
  allowed range go on the line below.
- **Menus.** Toggles and choices come first. Then a line, then things you go to
  or do, as menu items with an icon, full width and a hover background, so they
  never look like labels. The account menu is Theme, Hide empty sections, a
  line, Settings, Log out.
- **Navigation.** The header's sections are tabs. "Add a system" is a +, and a
  vertical line separates hub-wide items from the host's own sections.
- **Secrets.** Never shown back. A badge says whether one is saved ("A key is
  saved").

### Status labels

Every list says where each item stands, with one label:

| Label | Meaning | Counts as needing attention |
|-------|---------|-----------------------------|
| Unexpected | Not expected and not accepted | Yes |
| Accepted | Accepted with a note; the note shows on hover (the label's title) and in the row | No |
| Changed | Accepted, but its basis changed since (the fingerprint no longer matches) | Yes |
| Expected | Listed in `exposure.expected_public` | No |

Accepted and expected items are never hidden: an inline label and a filter
replace separate sections. Totals, severity badges, the report's steps and the
Hosts page count only Unexpected and Changed (`db.findings_state` "active").

- **Overview findings list.** All open findings, in severity order, in one
  list. Each row has its severity badge and a status label; an Accepted row
  shows its note, who and when, and an Un-accept button instead of the fix
  and steps; a Changed row shows the "this has changed since" note and
  "Accept again". The card's count reads "N need attention", plus "M
  accepted" when there are any, and the Hosts page counts the same set.
  When any finding is accepted, a small "All" / "Needs attention" switch
  appears (script only: without scripts everything is listed). "Needs
  attention" hides rows whose `data-status` is not `unexpected` or `changed`
  and says so when none are left. The choice is kept in `localStorage` under
  `daemonsight:findingsFilter`, read and written inside the same `try/catch`
  as the other saved settings, and applied again after each refresh.
  `views.findings_overview` builds the list; the Unraid Overview shares the
  template and calls it too. The report still uses `views.findings_lists`.
- **Exposure page.** A Status column on each listener row and each port
  forward row: Expected, Accepted, Changed, Unexpected, or a dash when the
  internet can't reach it (the host has no public address, the provider
  firewall's `upstream_allow` lets none of its ports in, the firewall forwards
  it to another host, or it is an unconnected UDP client socket). Derived in
  this order: the acceptance state of the row's finding (`expose.unexpected`
  or `expose.docker_bypass` for a listener, `expose.forward_all` for a forward:
  Accepted, or Changed when its basis moved); else Expected when the port is
  in `exposure.expected_public`; else Unexpected. A forward is Expected only
  when it forwards at most 1000 ports and every one of them is listed; a wide
  forward never is. A forward that is not wide and not listed is Unexpected
  but makes no finding of its own (only `expose.forward_all` does). The old
  "Expected: Yes/No" column is gone; this replaces it. A forward row's panel
  can accept `expose.forward_all`, and a Docker-published port's panel can
  accept `expose.docker_bypass`, as a port's panel can accept
  `expose.unexpected`.

Account menu: one button at the right of the header (a person icon, label
"Account and settings") opens a native popover (`popovertarget`), the same
API as the source panels, with no library and no inline script. The panel holds a
Settings link, Theme (Light, Dark, Auto; three submit buttons of a form posting
to `/theme`, the pressed one marked `aria-pressed`), "Hide empty sections" (same
`hideEmpty` storage key) and Log out. Escape and a click outside close it
natively and focus returns to the button; `app.js` (`initAccount`) places it
under the button and moves focus to its first item. The filter box stays in the
header. Every install, hub or single host, has the same menu.

Phones: below 768 px each table row becomes a stacked card, one labelled line
per cell, with the header row hidden from view but kept for screen readers.
The header shows the logo, host and a Menu button; the section links and the
account panel's items (Settings, Theme, "Hide empty sections", Log out) open in
a panel below it (script only; without it the header is unchanged). The same
panel is drawn inline there, not as a nested popover, and the account button
is hidden; a browser without popover support gets the same inline panel. The filter box stays visible. A
page note such as the one on Exposure is a details element with a one-line
summary; it starts closed on a phone, remembers if the reader opened it, and
is always open on wider screens.

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
   2b. Remote sources: the Unraid API (array, disks, containers, VMs, notifications, UPS), done, and the OPNsense API (firewall rules and port forwards, Caddy, gateways, WireGuard, Tailscale, firmware), done. Each shows as its own host. See "Remote sources".
   2c. The hub: collectors upload to one install that shows every host, with the container image and Unraid template, retention and backups, and updates from the hub. See "Hub". Done.
3. Package and CVE checks.
   3a. Pending updates, reboots, services on old libraries: the `packages` source, `pkg` rules and Packages page. Done for apt and, since Fedora support, for dnf5 too.
   3b. CVE matching on the hub: collectors send installed packages (source name and version) and the release; the hub matches them against the Debian security tracker, ranks by EPSS and CISA's KEV list, and raises one finding per package. Vulnerabilities page, `cve.*` rules, and Fedora's pending advisories. No scanner binary on the hosts. Done for Debian and Raspberry Pi OS; Ubuntu is next (see "CVE matching"). See also the automatic-updates advice in 3a (`pkg.auto_updates_off`).
   3c. CVEs in container images: the package list read from each running Debian- or Ubuntu-based container through the Docker API, matched the same way; Alpine through its security database. Trivy may come later, opt-in and pinned, for other bases.
4. Alerts, recent-changes feed, history charts with drill-down. See "History charts and drill-down (planned)".
5. `.deb` package and docs.

Planned after phase 3, in this order: log collection and auditing, then a
Windows agent. Traffic maps can come any time after phase 3. See "Log
collection and auditing (planned)", "Windows agent (planned)" and "Maps
(planned)".

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
and 1,000 a time; the rest follows a second later), and its open findings. A
host with the `inventory` source also sends its installed packages as a
top-level `inventory` field (see "CVE matching").

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
  each source's data; links only as paths on the site; no `host.*`, `cve.*`, `remote.*`, `unraid.*` or `outside.*`
  findings from a collector; NaN and Infinity refused. An `inventory` the
  hub can't read is dropped, not a reason to refuse the upload. Ten bad tokens from one address
  in five minutes block that address; one host may upload 120 times a minute.
- **TLS:** `[upload] url` must be `https://`, except to a hub on the same
  machine, and the certificate is checked against the system CA store with
  no setting to turn that off.
- **One command:** the reply is `{"last_seq": n}`, plus `update_to` (a
  commit) when the hub has asked the host to update. The collector acts on
  nothing else in it. See "Updates from the hub". Other actions (ban, unban,
  restart) would need their own design.
- **Findings:** each collector works out its own findings with its own
  `[exposure]` settings and sends them. The hub adds the `cve.*` findings (see
  "CVE matching"), `host.silent` (High)
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
and `upstream_allow`. A single-host install keeps its URLs. Severity counts leave out accepted
findings, and each row links to the host's report.

The hub's web process is the database writer (it stores uploads); on a host
the web process stays read-only.

### Roles

A collector's top-level `role` is `server` (the default) or `workstation`; it
travels in the upload's settings (`settings.role`, optional, so older
collectors count as servers). A workstation is a laptop or desktop that is
often off or asleep. The one thing the role changes today is silence: when a
workstation misses three intervals the hub opens `host.silent` at Low,
titled "Offline since <UTC time>", and the Hosts page shows the state
"Offline" (secondary badge) instead of the red "Not reporting". A host that
was added but never reported stays "Never reported" at High for both roles:
that is a setup problem. The Hosts page shows a "Workstation" badge by the
name, and a single host's Overview shows the role under "At a glance", only
for workstations.

#### Planned for workstations

- LAN-only desktop services (KDE Connect, CUPS, mDNS) count as expected
  instead of raising exposure findings.
- Reboot findings at a lower severity, since desktops reboot often.
- Flatpak updates shown beside dnf's.
- Quieter alerts, once alerts exist.

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
secret, the database, `cve.db` and the saved feed files in `cve/` (about 60
MB; not backed up, since the hub downloads them again), `backups/` and
`daemonsight.log` (`log_file`, rotated at 5 MB, four files). The hub needs
outbound HTTPS to `security-tracker.debian.org`, `epss.empiricalsecurity.com`
and `www.cisa.gov`; it works without them, with `cve.feed_stale` after 3 days. The remote sources in phase 2b (OPNsense, Unraid)
will run in the hub, since they are API calls from the LAN.

`deploy/unraid/daemonsight.xml` is an Unraid template for it: icon, web UI
link, the read-only and no-capabilities options, and a data path and port.
It sets no restart policy, so Unraid's autostart list starts the container.
The Docker tab then manages it, including updating it from the new image.

Collectors stay native packages on each Linux host (LXC, VPS). They need root,
the host's D-Bus, `/proc` and netlink, which a container would only get by
giving up its isolation.

## CVE matching

Phase 3b. The hub finds known vulnerabilities in what its hosts have
installed. A host downloads nothing and runs no scanner: it reports its
package list, and the hub does the rest.

```
collector ── dpkg-query ──► inventory ──(upload field)──► hub ── match ──► findings, page
                                                           ▲
          Debian tracker · EPSS · CISA KEV ── HTTPS ───────┘  (24 h, conditional)
```

### What a host sends

The `inventory` source (`collector/sources/inventory.py`) runs hourly, and only
when `[upload]` is set. It reads `dpkg-query -W -f` with `db:Status-Abbrev`,
`source:Package`, `source:Version`, `Package` and `Version` [22], keeps the
installed packages, and groups them by source package and source version. The
tracker is keyed by source package, and a rebuild such as `2.3.2-2+b1`
changes `Version` but not `source:Version`. Binary names are listed per
source (up to 30), left out when they equal the source name. The release comes
from `/etc/os-release` (`ID`, `VERSION_ID`, `VERSION_CODENAME`). On a Fedora host
the inventory carries pending security advisories instead (see below).

Size, measured on a Debian 13 desktop with 1,307 installed packages: 774
source packages, 41 KB of JSON, 13 KB gzipped. The collector sends it when its
hash changes and again after 24 hours, so a hub that lost it recovers.
That is far under the hub's 8 MiB upload limit, so nothing else was needed.

**Compatible with older hubs and collectors.** The earlier `packages`
source broke an old hub: `SnapshotIn.source` is a fixed list, so a snapshot
from an unknown source gets the whole upload a 422. So the inventory is not a
snapshot. It is its own top-level field, `inventory`, and `Upload` ignores
unknown top-level fields. An old hub takes the rest of the upload and drops
the field. In the other direction, an old collector just sends no
inventory, and the page says so. A new hub is also safe against its own
field changing: `InventoryIn` ignores unknown fields inside it, and an
inventory it can't read (a newer `v`, a bad value) is dropped with a log line
instead of refusing the upload. A collector can't send `cve.*` findings, and
an upload never closes the hub's own.

Deploy order: any. Update the hub first to get matching; a host updated
first just has its inventory ignored until then. The usual order (hub, then
hosts) is the one to follow. A host needs no new config.

### What the hub downloads

A chore (`cve/run.py`) runs next to the hub's other chores. Every `[cve]
refresh_hours` (24) it asks each feed again with `If-None-Match` and
`If-Modified-Since`, so an unchanged file costs one small request. Files
are saved under `<data_dir>/cve/`, parsed in a worker thread, and loaded into
`<data_dir>/cve.db` (SQLite, its own file, not part of backups: it can all be
downloaded again). Requests carry the User-Agent `DaemonSight/<version>` and
nothing else about the hub or its hosts. A redirect may only stay on the
feed's own host, and a download is capped (400 MB decoded for the tracker,
100 MB EPSS, 50 MB KEV). A feed that fails is retried an hour later; the last
good data stays in use. Nothing here runs in a request.

| Feed | Size as served | After decoding | Notes |
|------|---------------|----------------|-------|
| Debian security tracker | 14.96 MB gzip | 90.5 MB JSON, 81,701 CVE entries, 4,200 source packages | Has `Last-Modified`, no `ETag`. |
| EPSS | 2.85 MB gzip | 407,165 scores | `-current` redirects to the day's file; the day's file has `ETag` and `Last-Modified`. First line is `#model_version:...,score_date:...`. All scores are kept: loading them took 2.4 s. |
| CISA KEV | 0.20 MB gzip | 1,782 entries | `ETag` and `Last-Modified`. |

**Memory.** The tracker's `linux` entry alone is 35 MB of JSON. `json.load` on
the whole file peaked at 364 MB of resident memory, too much for a small
container, so `cve/tracker.py` reads the file two levels deep with
`json.JSONDecoder.raw_decode`, one CVE entry at a time, standard library only.
The same pass over the real file: 81,701 entries, 2.3 s, 19 MB peak. Loading
the entries for Debian 12 and 13 into SQLite took 5.6 s with 61 MB peak for the
whole process (interpreter and imports included): 124,010 rows and 58,845
descriptions, and `cve.db` with all EPSS scores is 41 MB. Only the releases the
hub's hosts run are kept; a host on a new release makes the hub parse the saved
file again, without downloading.

`feed` records, per feed, the last attempt, the last success (a 200 or a 304),
the last change, the status, row count and size. A feed with no success for 3
days raises `cve.feed_stale` (Low) on every host with an inventory.

### Matching

For each installed source package at version V on the host's release, each
tracker row for that release gives a state. This follows `Issue.get_status` in
the maintainers' own reader (`bin/tracker_data.py`) [25]:

| Tracker row | State |
|-------------|-------|
| `resolved`, fixed version `0` | Not affected: not stored |
| `resolved`, V at or past the fixed version | Fixed already: not stored |
| `resolved`, V older than the fixed version | **Fix available** (an update fixes it) |
| `open` | **No fix yet** |
| `open` or `resolved` with `nodsa` (minor issue, ignored, postponed), or urgency `unimportant` or `end-of-life` | **Won't fix or minor**: listed, never a finding |
| `undetermined` | **Being assessed**: listed, never a finding |

Raspberry Pi OS (`raspbian`) is looked up as Debian by its codename, as
`distro.py` does. Ubuntu and other derivatives aren't matched yet; the page
says so.

**Version order** is `cve/debver.py`, written from Debian Policy 5.6.12
(`[epoch:]upstream[-revision]`, the revision after the last hyphen, runs of
non-digits compared with `~` before everything, runs of digits as numbers) [29].
python-debian does this too but is GPL. It was checked against `dpkg
--compare-versions` on this Debian 13 machine: 6,200 pairs of real versions from
the tracker (3,000 pairs of two versions of the same package, 3,000 random
pairs, 200 equal pairs) gave no difference, and all 20,910 distinct versions
in the file were accepted or refused the same way (one malformed version,
`1:0.23.0+dfsg-`, is refused by both, so that row is skipped). A seeded sample
of 155 real versions and 600 pairs is kept as a test.

### Findings

One `cve.package` finding per source package, keyed by the package and linked
to its row on the Vulnerabilities page (`/vulnerabilities#cve-<package>`):

- **High** if an open or fixable CVE in it is on CISA's KEV list, or a fixable one
  has an EPSS score at or above `[cve] epss_high`.
- **Medium** if a fix is available.
- Otherwise none. An unfixed CVE that isn't on KEV, and any "won't fix or
  minor" one, shows only on the page. A KEV CVE that Debian calls minor
  (the tracker's `nodejs` and `openssh` rows for CVE-2026-111497 and
  CVE-2026-123158 were such cases on this machine) is flagged on the page but
  makes no finding.

**The EPSS threshold.** FIRST's FAQ says "There is no universal threshold",
that 0.10 (10%) "is commonly cited in the field but carries no special
authority from EPSS", and that 0.10 "currently sits around the 95th
percentile" [27]. A cut-off of 0.5 would flag almost nothing, so the default is
0.10, and `[cve] epss_high` changes it. On the Debian 13 test host, with all 448
unfixed and 141 fixable CVEs matched, none had an EPSS score of 0.10 or more,
so the choice changed no finding there. The finding says "high exploit score"
rather than calling anything critical, since FIRST says EPSS defines no such labels.

**How it reads next to `pkg.security_updates`.** That rule says what apt will
install (names from `apt-get -s dist-upgrade`) and that it matters; this one
says why, by CVE. Each `cve.package` detail checks the host's own packages
snapshot: "apt lists this update on the Packages page", or "apt isn't offering
it yet: run sudo apt update, and check the host's apt sources include the
security archive", which is the case that `pkg.security_updates` can't see.
Both give `sudo apt upgrade` as the fix.

### The Vulnerabilities page

A nav item on a hub's host pages. A summary card (CVEs with a fix, on KEV, no
fix yet, minor; the release and how old the package list is), then a table
of packages, one row each, with `id` from `findings.anchor("cve", name)`: package
and its binaries, installed and fixed versions, CVE counts by state, the top
CVE (a link to `https://security-tracker.debian.org/tracker/<CVE>`) with a KEV
badge, its EPSS score and Debian urgency, and a `details` list of up to 30 CVEs
with description, state, EPSS and fix. Every cell has `data-label`, so rows
stack as cards on a phone. A "Data feeds" card shows each feed's state, the
last check and success, rows and size, each with a source panel: the URL, the
feed's documentation, its terms, and a `curl -I` to check it by hand. Feed text
(descriptions, names) is untrusted: the page relies on autoescaping, never
`|safe`, and every field is cut to a fixed length when stored.

Limits, all shown or documented rather than hidden:

- A package installed from another repository (Docker, NodeSource) is matched
  by name and may be wrong. `dpkg-query` doesn't say where a package came from.
- The tracker lists kernel CVEs under the `linux` source. Debian's kernel
  images come from `linux-signed-<arch>`, whose version (`6.1.164+1`) isn't
  the kernel's, so the collector lists the running kernel's image
  (`linux-image-<uname -r>`) under `linux` with the image's own version
  (`6.1.164-1`), which is the kernel's. Other installed kernels aren't running
  and are left out. Kernel CVEs are matched only when a kernel image is
  listed: a container on its host's kernel, or a host on a kernel Debian
  didn't build, can have `linux-libc-dev` (headers) without running that
  kernel. After a kernel update, the running kernel still matches until the
  reboot, which is the point.
- Debian's tracker covers the release's own archives. Backports aren't
  tracked per release.

### Fedora

Fedora's advisories can be read with dnf5 without downloading anything:
`dnf advisory list --updates --security --json -C` gives one row per affected
package (`name`, `severity`, `nevra`) and `dnf advisory info --updates
--security --json -C` gives each advisory's description and references
[23]. `--updates` means "newer versions of installed packages for which a
newer version is available"; on `fedora:44` it printed the same four advisories as the
default `--available`. The list holds installed packages only; the info's package
collection spans every architecture and subpackage (debuginfo, devel), so the
collector takes package names from the list. The CVE ids are read from the description and the
reference titles with a pattern, because Fedora references are of type
`bugzilla`: `--with-cve` and `--cves=` returned nothing on `fedora:44` for an
advisory whose reference title names CVE-2026-92823. The collector sends each
pending advisory's id, severity, CVE ids and the installed package names it
updates. The hub ranks them with EPSS and KEV like any other CVE; each is "fix
available" (an update is pending), and the page links the advisory on
bodhi.fedoraproject.org. **Fedora's unfixed CVEs are not available this way**,
and the page says so.

### Ubuntu (next)

Canonical publishes its CVE data as Ubuntu OVAL ("recommended", all supported
releases; https://ubuntu.com/security/oval) and as a JSON API that it says
is "still a work in progress and subject to change" and not for automations
[30]. The next step is an OVAL reader with the same streaming approach,
keyed by Ubuntu release (`VERSION_CODENAME`), and the same states. The Debian
version comparison applies to Ubuntu versions unchanged.

## The outside view

What the internet sees of a host, from Shodan, set beside what DaemonSight
knows from inside. A host can't see its own provider firewall, other devices
answering on its address, or a forward's far end; an outside scan can. Off by
default, on the hub only (`[outside]`, or Settings, Outside view).

There are two sources, chosen by Settings, Outside view, Source (`[outside]
source`): **InternetDB** (the default: free for non-commercial use, no key) and
the **Shodan API** with the owner's own key (the route for use InternetDB's
terms do not cover). Both feed the same rules.

### What InternetDB is

Checked 2026-11-18, against the published page [49] and by requests to
documentation addresses and a few well-known public ones (not any address of
the owner's). What follows is stated as the page says it, or as observed.

- `GET https://internetdb.shodan.io/<ip>` returns `{ip, ports, cpes,
  hostnames, tags, vulns}` as JSON. Observed: `ports` are integers, with no
  protocol (a record lists UDP ports such as 161 beside TCP ones); `vulns` is
  a list of CVE ids; `tags` are lower-case words. It "doesn't return any
  banners". A published page says all this and gives IPv4 examples only.
- An address with no record, and a malformed address, both give HTTP 404 and
  `{"detail":"No information available"}`. So a 404 means "no record", not
  "bad input", and DaemonSight only ever sends a validated IP. A POST gives
  405; a trailing slash gives a 307 redirect (DaemonSight follows no redirects).
- "The API gets updated once a week." No key or account is needed.
- Terms: "It's free for non-commercial use!" and "If you're using the
  InternetDB API to make money then you need an enterprise license." [49] That
  is why `[outside] enabled` is false by default and the licence is in
  `config.example.toml`, INSTALL.md and README.
- **IPv6 works.** The page is silent on it; observed: two well-known public
  IPv6 addresses returned records in the same shape. A documentation IPv6
  address returned the same 404 as an unknown IPv4 one. So IPv6 addresses are
  checked. How much of IPv6 Shodan scans is unverified, which is why an IPv6
  address with no record produces no `outside.not_seen` finding.
- **Rate limit.** Shodan's API book says InternetDB "has a rate limit that
  allows bursts of up to 10,000 requests per second" [53] (the page was
  checked 2026-11-18, after this section was first written, when the limit was
  thought undocumented). Responses carried no rate-limit headers;
  they came through Cloudflare with `cache-control: public, max-age=432000`
  (five days). DaemonSight asks each address at most once per `refresh_hours`
  (24 by default), a second apart, and stops for the pass on an HTTP 429,
  honouring `Retry-After` up to a day. What a real 429 looks like is
  unverified.
- **Tags.** Shodan's own help pages list no tag values (its search-filters
  page marks the `tag` filter as restricted to higher API plans [51]). The
  values used here come from a third-party client library that documents each
  one [50]: `cloud`, `compromised` ("only applied to NoSQL databases that
  have been compromised for ransomware"), `cryptocurrency`, `database`,
  `devops`, `doublepulsar` (SMB banners that answer the DoublePulsar
  backdoor handshake), `honeypot`, `ics`, `iot`, `malware` ("verified command
  and control servers"), `medical`, `onion`, `scanner`, `self-signed`,
  `starttls`, `tor`, `videogame` and `vpn`. The list is incomplete: `cdn` and
  `pqc` came back in real answers and are not in it. `c2` is on the owner's
  list and in an unofficial list of Shodan's most used tags [50], and is not in
  the library. Shodan's own banner schema, checked later [56], lists `c2`,
  `compromised`, `doublepulsar` and `malware` among its tag values (31 in
  all, including `cdn` and `pqc`), so all four critical tags are now
  confirmed by Shodan itself.

### The Shodan API source

Checked 2026-11-18 against Shodan's published pages (cited), not against the
live API: there was no key, and no request was sent to api.shodan.io. The code
and its tests use a fake server with the documented reply shape.

- **The call.** `GET https://api.shodan.io/shodan/host/{ip}?key={YOUR_API_KEY}`
  "Returns all services that have been found on the given host IP", with the
  options `history` (default false) and `minify` ("True to only return the
  list of ports and the general host information, no banners") [52]. A reply
  has host fields (`ip_str`, `ports`, `hostnames`, `tags`, `last_update`, ...)
  and `data`, a list of banners, each with `port`, `transport` (`tcp` or
  `udp`; the documented example is `53` over `udp`) and `timestamp` ("Date
  and time that the banner was collected in UTC time") [52][56]. `product`,
  `version`, `cpe23` and `vulns` (an object keyed by CVE id) are optional
  banner properties in Shodan's banner schema, and "you need to check for the
  existence of a property" [56]. The REST page's example does not show them.
- **Why not `minify`.** The minified answer has "no banners", so no per-port
  transport, product or time. DaemonSight uses the full lookup and keeps
  `ports`, and per port and transport `product`, `version` and the time Shodan
  last saw it.
- **Cost.** "IP lookups don't consume query credits" [53]. Query credits are
  used by searches (`/shodan/host/search`, and only with a filter or past page
  one) and domain lookups; they reset at the start of each month [53][55].
  `GET /api-info` is not described as using any.
- **Who may look up IPs.** Shodan's help says "Looking up IPs via the main
  Shodan REST API requires at least a Shodan Membership (one-time payment of
  $49 for lifetime account upgrade). For free IP lookups check out the
  InternetDB API." [55] The pricing page's comparison table lists "IP lookups"
  under Membership, Freelancer, Small Business, Corporate and Enterprise [54].
  A free account therefore cannot use this source. What a free account's key
  gets back is unverified; the official Python client turns HTTP 401 into the
  server's message (or "Invalid API key") and 403 into "Access denied (403
  Forbidden)" [57], and DaemonSight treats both as "key refused".
- **Rate limit.** "All API plans are subject to a rate limit of 1 request per
  second" [54]; the official client defaults to one request a second [57].
  DaemonSight makes one request per address per refresh, 1.2 seconds apart.
  What a 429 looks like, and whether it carries `Retry-After`, is unverified;
  it is handled as for InternetDB (stop the pass, honour the header up to a
  day, else an hour).
- **Authentication.** Only the `key` query parameter is documented [52], and
  the official client sends it that way [57]. No header is documented, so none
  is used, and the key travels in a URL. Over HTTPS the URL path and query are
  inside the encrypted request, but httpx logs the full URL of every request at
  INFO, and a library's error text can contain it. So `shodan.redact` strips
  `key=...` from every error text DaemonSight stores or shows, and a logging
  filter on the `httpx` and `httpcore` loggers rewrites those lines (a test
  asserts it with the log at DEBUG). Redirects are never followed, so the key
  cannot be handed to another host.
- **Errors.** "A non-200 status code in the response indicates an error
  occurred" with a body like `{"error": "Invalid IP"}` [52]. The exact status
  and body for a bad key, for an address with no information and for a missing
  Membership are not documented; 404 is taken as "no record" (what
  InternetDB does), 401 and 403 as "key refused", 402 or an error text that
  contains "credit" as "no credits". Unverified against the live API.
- **`GET /api-info?key=...`** "Returns information about the API plan
  belonging to the given API key" (`plan`, `query_credits`, `scan_credits`,
  `usage_limits`, `monitored_ips`, ...) [52]. Test key calls it and shows the
  plan name as Shodan gives it and the credits. DaemonSight does not map plan
  names to what a plan may be used for: the documented example plan is
  `stream-100`, and the names of the Membership and Freelancer plans are not
  published.
- **Commercial use.** Shodan's pricing page lists "Commercial Use" as a
  feature of the Freelancer ($69 a month), Small Business ($359) and Corporate
  ($1099) API plans (prices as seen 2026-11-18) [54]. Its FAQ answers "Can we
  use the API to build products?" with "Yes, you can integrate the API in your
  products as long as the data is attributed to Shodan." [54] The Enterprise
  Data License "provides rights to commercial use without attribution" [58].
  The one-time Membership is described only as "a lifetime account upgrade to
  browse more results, monitor some IPs and dive into the API" [54]; no page
  read says it allows or forbids commercial use, and no terms-of-service page
  was found (www.shodan.io/legal, /terms and /about/terms are 404, and the
  membership purchase page needs a login). **Whether the Membership may be used
  commercially is unverified**; the Settings note says so and tells the owner
  to ask Shodan. DaemonSight attributes: the Exposure section and the source
  panels say the data is from Shodan.
- **InternetDB and a key.** InternetDB's own page says "No, you don't need to
  have a Shodan account or a Shodan API key in order to use the InternetDB
  API", and its OpenAPI description has no key parameter [49]. A key does not
  change its terms, so DaemonSight sends none to it. The commercial route
  Shodan names for InternetDB is an "enterprise license" [49]. Shodan's pricing
  page is not consistent about it: the Corporate plan card lists "InternetDB
  API Commercial Use", while the comparison table ticks InternetDB only under
  Enterprise [54]. DaemonSight does not rely on either: the commercial route it
  offers is the REST API on a plan that lists Commercial Use.

**The key.** One line in `<data>/shodan.key` (or `[outside] key_file`), mode
0600, written atomically. It is never in the `settings` table, an event, a
log line, a page or an error, and it is not shown after it is saved. The
Settings page takes it in the Outside view form, under Source: saving the
group writes the key file first (the `shodan_key` field never reaches the
`settings` table), and Test key and Remove key post the same form to `POST
/settings/shodan-key` (login required, cross-site posts refused, one action per
request). Saving and removing write the hub events "Shodan API key saved"
and "Shodan API key removed" (who, never the key). Choosing the Shodan API as
the source is refused without a saved key, and removing the key is refused while
it is the source. If the file is missing anyway (a hand-edited config), the
chore asks nobody and raises `outside.key`. A backup carries the file, like
the other secrets.

### What it asks, and when

`outside.Chore` runs on the hub's event loop, as the CVE chore does, and
never blocks a page request: the fetches are async and the rest is a few small
queries. Every minute it:

1. Collects the addresses: for each host, the ports snapshot's `addresses`
   with scope `public` (each checked again: it must parse and not be
   private, loopback, link-local, multicast or special), plus `[outside]
   addresses`. An entry `ip=host` is attached to that host; a plain `ip` to
   the host that reports it, and is dropped with a log line when no host does.
2. Fetches each address that is due: never asked; or its last attempt was
   `refresh_hours` ago (an hour after a failure); or its stored answer came
   from the other source (the source was changed). One request per address. The
   InternetDB request is `GET https://internetdb.shodan.io/<ip>`, a second
   apart, with `User-Agent: DaemonSight/<version>` and nothing else. The Shodan
   API request is `GET https://api.shodan.io/shodan/host/<ip>?key=...`, 1.2
   seconds apart, the key read from its file at the start of each pass. If the
   key is refused or Shodan has no credits, the pass stops, every address left
   in it gets the same error without a request, and nothing is asked again for
   an hour, or until the key or the source changes. It never falls back to
   InternetDB.
3. Stores the cleaned answer in the `outside` table of `state.db` (ip,
   first_try, checked_at, fetched_at, status `ok`, `none` or `error`, data,
   error), schema version 7. A failed fetch keeps the old answer and sets
   `error`, so findings don't flap on a bad day. A 404 is stored as `none`.
4. Recomputes each host's `outside.*` findings with `db.reconcile_findings(...,
   only_prefix="outside.")` and writes `finding_opened` and `finding_resolved`
   events, as `cve.*` does. A collector's upload can't carry them and never
   closes them (`hub.HUB_RULES`).

With Enabled off (the Settings page, or `enabled = false` in the file) the hub
makes no requests, and at its next pass (not only at start-up) closes any
`outside.*` finding left from when it was on. The chore reads its settings at
the start of every pass.

### Rules

Keys are `<ip> <port>` for ports and `<ip>` for the rest. Each has a basis, a
link to the row or address it is about, and a `howto` of plain steps; none has a
fix command (they are decisions).

| Rule | Severity | Basis |
|------|----------|-------|
| `outside.unexpected_port` | High | IP, port and a digest of what DaemonSight knows about the port (process, forward target), so an accepted finding comes back as Changed when what is behind the port changes |
| `outside.not_seen` | Low | IP and port |
| `outside.tagged` | Critical | IP and the critical tags present |
| `outside.vulns` | Medium | IP and a digest of the CVE list, so a new CVE brings an accepted finding back |
| `outside.stale` | Low | IP |
| `outside.key` | Medium | The kind of problem (`refused`, `missing`, `credits`), so it does not reopen when the text changes |

What DaemonSight knows about a port (`outside.explain_port`) comes from the
host's own readings: its listeners (process, unit or container, bound
addresses), the containers that publish it, and the firewall snapshot's DNAT
forwards that cover it, grouped by target with the interface that reaches the
target (the host address in the same /24 or /64 names it, and a name like
`wg0` is called a tunnel; it is a guess from addresses without prefix lengths,
and worded as one). With none of those it says nothing on the host listens on
it and no forward covers it. Example, from the test fixture: a VPS forwards
every TCP port except 22, 80, 443, 2083 and 8001 over its `wg0` tunnel to
10.99.0.2, and Shodan lists ports 22, 80, 443 and 9123. Port 9123 gives a
high `outside.unexpected_port` whose detail names the forward to 10.99.0.2.

With the Shodan API source the `outside.unexpected_port` detail also says what
Shodan saw: for example "Shodan saw nginx 1.24.0 over TCP, last seen
2026-11-10." Last-seen dates are in the detail only, never in the basis, so an
accepted finding does not come back each time Shodan rescans.

`outside.vulns` cross-references DaemonSight's own matches: it reads the
host's rows in `cve.db` and names the CVE ids both have. Shodan matches the
version a banner shows against known CVEs, and distributions backport fixes
without changing it, so the overlap is usually small; the finding says so.

### The Exposure page section

"Seen from outside", after the port forwards. If the hub has outside checks off
it is one line saying how to turn them on (the Settings page, with a link; and
that InternetDB is free for non-commercial use only); on a single host it says outside checks run on a
hub. Otherwise, per address: when it was fetched (and "stale" past three
refreshes), the last error if any, then a table with each port Shodan lists,
its status label (Expected when the port number is in `exposure.expected_public`
on any protocol, else the acceptance state of its `outside.unexpected_port`
finding, else Unexpected) and what DaemonSight knows about it; the expected
ports Shodan did not list; hostnames, CPEs and tags (critical ones in red); and
the CVE ids with links to NVD, marked where DaemonSight's own matches have
them. The address's source panel gives the exact URL, a `curl` command to
repeat the request, what is sent, how often Shodan updates and the terms. With
the Shodan API source the table also has Transport (`tcp`/`udp`), Service
Shodan saw (product and version, or "not named" / "no banner") and Last seen
(relative, with the UTC time on hover), and the panel shows the request and the
`curl` command with `key=YOUR_KEY`, a placeholder: the real key is never put in
a page. A refused key shows its message beside the address, with a link to
Settings. A port's panel has the finding's accept form. Shodan's text is escaped like all
host text.

Limits: Shodan's view is a week old at best, covers the ports it scans, and
InternetDB can't say TCP from UDP (the Shodan API can, but `exposure.expected_public`
is still compared by port number). An address attached to a host with no uploaded
settings has an empty expected list, so every port Shodan sees is unexpected.

## Remote sources (phase 2b)

Appliances that can't run the collector are read over their own APIs. Each
one is stored under its own `host` id, so the UI shows it as another host.
The hub runs these sources itself: a background task, started with the hub
like the CVE loop, polls each enabled system. Systems are added, edited,
disabled and removed in the hub's web UI (Hosts, "Add a system"); there is no
config file entry for them. `[remote] enabled = false`, or "Read remote systems"
on the Settings page, switches the polling off; the loop reads it every pass. Keys are files under the hub's data folder, never in the database or
`config.toml`, and the client sends only reads. Unraid and OPNsense are done.

### OPNsense

Done. The hub reads the OPNsense REST API with HTTP basic auth: the API key is
the user name and the API secret the password
(https://docs.opnsense.org/development/how-tos/api.html). Every request is a
GET. Each source below is stored as an `opnsense_*` snapshot, polled by
`remote/poll.py`, turned into findings by `remote/opnsense_rules.py`, and shown on
the firewall's own pages (Overview, Firewall, VPN, Gateways & interfaces,
Report).

**What the key can do.** OPNsense has no read-only privilege. A privilege covers a
whole page, read and write alike: `ACL.xml` lists patterns such as
`api/firewall/d_nat/*`, with no split by method
(github.com/opnsense/core, `src/opnsense/mvc/app/models/OPNsense/*/ACL/ACL.xml`;
the plugins have their own in github.com/opnsense/plugins). A key with the
privileges below can therefore also change what those pages cover, and nothing
on the server side limits it to reading. DaemonSight's client is limited to GET in
code (see "Read-only in the hub"). The key's user should be dedicated, in no
group, and hold only these privileges. Whether the key has more than that is not
something the API can say (there is no `me` call), so it is documented, not
checked.

Privilege names are the `<name>` entries from `ACL.xml`, and each endpoint is
matched by a pattern of the same file.

| Source (snapshot) | Privilege | Endpoints (all GET) | ACL pattern | Kept | Cadence |
|-------------------|-----------|---------------------|-------------|------|---------|
| `opnsense_system` | Lobby: Dashboard | `/api/diagnostics/system/system_resources`, `system_disk`, `system_temperature` | `api/diagnostics/system/system_*` | Memory use, each mount's use, sensor temperatures | `interval` |
| `opnsense_interfaces` | Status: Interfaces | `/api/interfaces/overview/export` | `api/interfaces/overview/*` | Identifier, label, device, status, addresses, upstream gateways | `interval` |
| `opnsense_gateways` | System: Gateways | `/api/routes/gateway/status` | `api/routes/gateway/status` | Name, address, state, loss, round trip, monitor address | `interval` |
| `opnsense_wireguard` | VPN: WireGuard: Status | `/api/wireguard/service/show` | `api/wireguard/service/*` | Instances, peers, last handshake, traffic, keepalive; public keys cut to 8 characters | `interval` |
| `opnsense_services` | Status: Services | `/api/core/service/search` | `api/core/service/*` | Which enabled services run | `interval` |
| `opnsense_tailscale` | Tailscale | `/api/tailscale/status/status`, `/api/tailscale/settings/get` | `api/tailscale/status/*`, `api/tailscale/settings/*` | State, version, routes, exit node, and the subnets and exit node the settings advertise; peers as a count only | `interval` |
| `opnsense_firmware` | System: Firmware | `/api/core/firmware/status` | `api/core/firmware/*` | Version, pending packages and sets, new version, reboot needed, last check | 5 min |
| `opnsense_rules` | Firewall: Rules [new] | `/api/firewall/filter/search_rule` | `api/firewall/filter/*` | Rules: interface, action, source, destination, port, description | 5 min |
| `opnsense_nat` | Firewall: NAT: Destination NAT | `/api/firewall/d_nat/search_rule` | `api/firewall/d_nat/*` | Port forwards: interface, protocol, ports, target (alias resolved) | 5 min |
| `opnsense_caddy` | Services: Caddy | `/api/caddy/reverse_proxy/get`, `/api/caddy/service/status` | `api/caddy/*` | Sites, handlers, upstreams, access lists | 5 min |

The cadence is `interval` (30 to 3600 s, default 60) or five minutes if that is
longer, as for Unraid.

**Verified against a real firewall (read-only).** Each endpoint above was
requested with GET on one firewall (OPNsense 26.7 with os-caddy and
os-tailscale) and answered 200 with the shape the parsers expect. The sample
replies were used only to see the shapes. The test fixtures
(`tests/fixtures/opnsense/`) are synthetic: documentation addresses
(RFC 5737, RFC 1918), made-up names, no real host, domain, key or peer. A path
under a plugin that is not installed answers 404 with
`{"errorMessage": ...}`, which is shown as "Plugin not installed". 403 for a
missing privilege is from the source (`ApiControllerBase::beforeExecuteRoute`
answers `{"status": 403, "message": "Forbidden"}`); it was not tried against a
restricted user on the real firewall, so the shape of that reply and the
"needs privilege X" display rest on the source and the tests.

**GETs that act.** Some OPNsense GET endpoints still do something. Before an
endpoint went into the table its controller was read in github.com/opnsense/core
or github.com/opnsense/plugins. `/api/core/firmware/status` is the one the older
notes called unverified: in `FirmwareController::statusAction` a GET returns the
cached result of the last check (`firmware product`, `product_check`), and only a
POST runs `firmware probe`, so DaemonSight reads what the firewall last found
and never starts a check. Endpoints that look like reads but act, such as
`/api/core/firmware/check` and `/api/tailscale/status/net`, are not in the list
and the client refuses them. `/api/tailscale/settings/get` is the inherited
read-only `getAction`.

**Classic rules are in the list.** An earlier note said classic (legacy)
per-interface rules are not in the new filter API and would need the config
backup. That is wrong: `search_rule` returns them with `legacy` set, and the
automatic rules OPNsense generates (anti-lockout, default deny) with
`is_automatic`. Both appear; the generated ones are counted and left out of the
lists. A classic rule names its interface by label ("WAN"), a new one by
identifier ("wan"), and both are matched.

**What is left out of what the API returns.** The parsers copy named fields and
nothing else, because some replies hold secrets: `caddy/reverse_proxy/get`
returns the whole Caddy model, including the DNS provider API key and the ACME
e-mail; `wireguard/service/show` returns public keys; the Tailscale status
returns peer names. None of those is stored. A test plants a secret in the Caddy reply and checks
it is not in what the parser keeps.

**Interface roles** (`remote/roles.py`, shared so another product can use it).
"Internet-facing" never means "called WAN". Each interface gets one role, worked
out in this order and overridable per system:

1. the owner's override (Gateways & interfaces page, stored in the hub's `meta`
   table, never sent to the firewall);
2. a tunnel device (wg, tun, tap, ovpn, ipsec, tailscale, gif, gre, zt, ppp, vti):
   VPN, even with a gateway attached (a tunnel's gateway is the far end);
3. named WAN (`wan`, `wan2`) or with an upstream gateway: WAN, the only role
   that counts as untrusted;
4. loopback and internal devices (lo, enc, pflog, pfsync): other;
5. unassigned device: other; with an address and no gateway: LAN; otherwise
   other.

A rule or forward is on an untrusted interface when it is bound to a WAN
interface, or to none (floating rules and forwards with no interface apply to
all of them).

**Findings.** Each has a "What to do" list, a basis for Accept and a link to
its row. Accepted, Changed and Unexpected labels are shown inline in every
table; nothing is hidden.

| Rule | Severity | When |
|------|----------|------|
| `opnsense.updates` | Low; Medium at 5 packages or a new release; High at 20 packages or waiting more than 30 days | The last firmware check found updates. "Waiting" counts from when the hub first saw them. The basis is the package names and versions, so a new update brings an accepted finding back |
| `opnsense.reboot` | Medium | The pending update needs a reboot |
| `opnsense.gateway` | High down; Medium degraded | Gateway down, loss of 10% or more, or round trip of 300 ms or more |
| `opnsense.wg_no_peer` | High | An instance with no peer (an unlinked peer vanishes from the reply, so this is how it shows) |
| `opnsense.wg_peer_stale` | Medium with keepalive, else Low | No handshake for a day, or never |
| `opnsense.rule_any` | High | A pass rule on a WAN interface from any source to any destination (or to the firewall), any port |
| `opnsense.rule_floating_any` | High | The same as a floating rule |
| `opnsense.rule_no_descr` | Low | A pass rule on a WAN interface, or floating, with no description |
| `opnsense.nat_all_ports` | High | A forward on a WAN interface with no destination port: every port of that protocol |
| `opnsense.nat_dead` | Medium | A forward to a host a collector reports on, where nothing listens on the target port. Only when the target is one address that a collector host owns and the port is a plain number; anything else is skipped silently |
| `opnsense.caddy_down` | High | Caddy is enabled with sites and its service is not running |
| `opnsense.caddy_no_acl` | Info | Internet-facing sites with no access list or password: one finding listing them. A firewall rule on a WAN interface must let 80, 443 or the site's own port reach the firewall. Public sites are legitimate, so this is a list to check |
| `opnsense.caddy_dead_upstream` | Medium | A site proxies to a collector host's address and port where nothing listens |
| `opnsense.tailscale` | High not running; Medium for a subnet or exit node the settings advertise but Tailscale does not list as approved | Only when the plugin is enabled in its settings |
| `opnsense.service_stopped` | Medium | An enabled service is not running |
| `opnsense.disk_full` | Medium at 90%; High at 95% | Any real mount |
| `opnsense.temperature` | Medium at 80 C; High at 90 C | Any sensor |

The thresholds are DaemonSight's own choices (OPNsense publishes none for
updates, loss, latency, disk or temperature), apart from the gateway alarm states
OPNsense reports itself (`scripts/routes/gateway_status.php`). Caddy has no
per-site upstream health in its API, so "upstream is down" is limited to the
hub-host check above plus "Caddy is not running".

**Cross-host.** A port forward or an internet-facing Caddy site whose target is
an address of a host the hub has collector data for appears on that host's
Exposure page under the port: "Reached from the internet through OPNsense port
forward X on fw", linked to the forward's row. It matches by address and only
plain port numbers; an alias that can't be resolved or a range is left out,
never guessed.

**Not built.** DHCP leases and firewall logs. Their toggles on the Settings
page are not there either; they come with the code that reads them. Open
follow-ups: a FortiGate source on the same `roles.py`; hub-side DHCP
reservation checks; the Overview's two-column layout is shared with the other
host kinds and was not reworked here (see "Layout and wording rules").

**Read-only in the hub.** `remote/client.py` has `Rest`: it has no method that
sends anything but GET (`get` asks httpx for a GET with no body and no
Content-Type), it refuses any path that is not in `opnsense.PATHS` (compared as a
whole string, so a query string or a trailing slash is refused), follows no
redirects, caps a reply at 8 MiB, and scrubs the key and secret from every
error. Tests send a real poll and a probe through a fake firewall that fails on
any request that is not a GET, has a body or has a Content-Type, and check that
the paths are all in the list. OPNsense answers an empty body that claims to be
JSON with 400 "Invalid JSON syntax" (`ApiControllerBase::parseJsonBodyData`),
which is why no Content-Type is sent.

**TLS and key files** work as for Unraid (verify, or pin one certificate after
confirming its fingerprint). The key and secret are two lines of
`<data>/remotes/<id>.key`, mode 0600 in a 0700 folder. A missing privilege
(403) never fails the whole system: that source shows "needs privilege X" and
the rest carry on. A key that every source refuses is rejected at Test
connection.

Sources: OPNsense API docs https://docs.opnsense.org/development/how-tos/api.html;
users and privileges https://docs.opnsense.org/manual/how-tos/user-local.html;
core source https://github.com/opnsense/core (ACL.xml, `Menu.xml`, the API
controllers named above); plugin source https://github.com/opnsense/plugins
(`www/caddy`, `security/tailscale`).

### Unraid

Done. The hub reads the Unraid GraphQL API with an `x-api-key` header
[31][32]. Unraid's API has a `VIEWER` role, "Read-only access to all
resources" (enum `Role` in `api/generated-schema.graphql`, github.com/unraid/api)
[33], so the key is read-only on the server's side too. The hub's own client
is read-only as well (see below), with one named exception: a single
subscription for container CPU and memory (see "Container CPU and memory").

Data flow:

```
 hub web process (the writer)                       Unraid server
 ┌──────────────────────────────────────┐   HTTPS   ┌──────────────────────┐
 │ remote/poll.py   one task per hub    │  POST     │ /graphql             │
 │  every `interval`: me, system, array,├──────────►│ x-api-key: Viewer key│
 │  docker, vms, ups; every 5 min: disks│  query    │ (read-only role)     │
 │  and notifications                   │◄──────────┤                      │
 │  every `interval`, beside the queries│  WebSocket│ /graphql             │
 │  once the container list is read:    ├──────────►│ docker stats, while  │
 │  a few seconds of container stats    │  1 subscr.│ subscribed           │
 │ snapshots unraid_*  ─► unraid_rules  │◄──────────┤                      │
 │  ─► findings, events, metrics        │  JSON     └──────────────────────┘
 └──────────────────────────────────────┘
```

**Queries.** All are written from the published schema [33]; none is a
mutation. Every HTTP request body is `{"query": ...}` and nothing else. The
one WebSocket message that carries a document is the subscription below.

| Source (snapshot) | Query | Schema reference |
|-------|-------|------------------|
| key check | `me { name roles permissions { resource actions } }` | `Query.me: UserAccount`; `UserAccount.roles: [Role!]!`, `permissions: [Permission!]` |
| `unraid_system` | `vars { name version }`, `info { os { hostname release kernel uptime } versions { core { unraid api } } cpu { brand cores threads } }`, `metrics { cpu { percentTotal } memory { total available percentTotal swapTotal swapUsed } }` | `Query.vars`, `Query.info`, `Query.metrics` |
| `unraid_array` | `array { state capacity { kilobytes { free used total } disks { used total } } parityCheckStatus { ... } parities disks caches boot }`, `display { hot max warning critical }`, `parityHistory { date duration speed status errors }` | `UnraidArray`, `ArrayDisk`, `ArrayCapacity`, `ParityCheck`, `Display` |
| `unraid_disks` | `disks { device type name vendor size interfaceType smartStatus temperature isSpinning }` | `Query.disks: [Disk!]!`, `Disk.smartStatus: DiskSmartStatus` |
| `unraid_docker` | `docker { containers { id names image state status autoStart isUpdateAvailable isOrphaned ports { ip privatePort publicPort type } } }` | `Docker.containers`, `DockerContainer` |
| `unraid_vms` | `vms { domains { name state } }` (null when VMs are off) | `Vms.domains`, `VmDomain` |
| `unraid_notifications` | `notifications { overview { unread { info warning alert total } } alerts: list(filter: {type: UNREAD, importance: ALERT, offset: 0, limit: 2000}) { id title subject description importance link timestamp } warnings: list(filter: {... WARNING ...}) { same fields } }` | `Notifications.overview`, `Notifications.list(filter: NotificationFilter!)`, `Notification` (`description: String!`, `link: String`), `NotificationFilter { importance type offset limit }` |
| `unraid_folders` | `docker { organizer { version views { id name rootId flatEntries { id type name parentId depth position path hasChildren childrenIds meta { names } } } } }` | `Docker.organizer: ResolvedOrganizerV1!`, `ResolvedOrganizerView`, `FlatOrganizerEntry` |
| `unraid_ups` | `upsDevices { id name model status battery { chargeLevel estimatedRuntime health } power { loadPercentage } }` | `Query.upsDevices: [UPSDevice!]!` |
| `unraid_stats` | subscription `dockerContainerStats { id cpuPercent memUsage memPercent }` (over a WebSocket, not a query) | `Subscription.dockerContainerStats: DockerContainerStats!`; `DockerContainerStats { id: PrefixedID!, cpuPercent: Float!, memUsage: String!, memPercent: Float! }` |

The exact strings are the constants in `src/daemonsight/remote/unraid.py`.

**The key check.** `me` returns the key's own stored roles and any explicit
permissions (api `user.resolver.ts` and `auth.service.ts`, `validateApiKeyCasbin`),
so a key can be asked what it can do. The hub accepts a key only when its
roles are a subset of `{VIEWER}` and none of its explicit permissions has an
action other than `READ_*`. It runs on "Test connection", on save, and again at
the start of every poll, so a key that is later given more power stops the
poll with a clear error instead of being used. The refusal names the roles and
the resources it could change, and says where to make a Viewer key: Settings
→ Management Access → API Keys. Nothing else is asked of an over-privileged
key.

**Read-only in the hub.** `remote/client.py` has two ways to talk to the
server. `Graph.query` refuses any document that does not start with `{` or
`query`, or that contains `mutation` or `subscription`, before sending, follows
no redirects, and caps a reply at 8 MiB. `Graph.sample` is the only code that
opens a WebSocket: it accepts exactly one document, the constant
`STATS_SUBSCRIPTION`, compared as a whole string (so not "a subscription that
looks like it", and not that text with anything added), and raises before
connecting for anything else. It is a separate method so that loosening one
guard never loosens the other, and `query` still refuses the allowed
subscription. Tests assert that no other subscription and no mutation can be
sent, and that no request body or WebSocket message the poller sends contains
"mutation".

**TLS.** Verification is on by default, with the system's trust store (httpx
`verify=True`) [34]. Unraid's own HTTPS certificate is self-signed unless the
owner installed a real one (Settings → Management Access), so there is a
second mode: pin one certificate. On Test connection the hub fetches the
certificate with `ssl.get_server_certificate`, which does not verify it [35],
and shows its SHA-256 fingerprint to confirm against Unraid's own certificate
page. Nothing is pinned, and no key is sent, until the form is sent back with
that fingerprint; the hub then fetches again and refuses if it differs.
Connections in `pin` mode use an `ssl.SSLContext` whose only trust anchor is the
stored certificate (`load_verify_locations(cadata=...)`), `CERT_REQUIRED`, TLS
1.2 or later, and `VERIFY_X509_PARTIAL_CHAIN` so a self-signed leaf counts as a
trust anchor [35]. Host-name checking is off in that mode, since the pin, not
the name, says which server this is. The handshake proves the server holds
the pinned certificate's private key, so there is no gap between "checked" and
"used". A changed certificate fails the connection before any request, so the
key is never sent to it. There is no "don't verify" option.

**Polling.** Two tiers, per system:

- Every `interval` (default 60 s, 30 s to 1 hour): `me`, system, array
  (with `display` and `parityHistory`), docker, vms, ups. These are cheap
  to ask of the server (the whole set took well under a second on the test server).
- Every 5 minutes, or `interval` if that is longer: disks (SMART status, about
  2.4 s on the test server, because it asks each device), notifications
  (about 1.1 s per list, 2.1 s for alerts and warnings) and the Docker folders.
- Once a day, for the whole hub: the newest stable release (below).

The container statistics are sampled in the same poll, every `interval` (the
fast tier), as a task that starts once the container list is read and runs
beside the remaining queries (below). It has its own timeout (at most 5 s of
collection) and never ends the poll.

Requests use httpx timeouts (5 s to connect, 20 s for anything else). A source that fails
keeps its previous data and records its error on its snapshot; the other
sources go on. A connection, TLS, authentication or key-check failure ends the
poll: `remotes.last_error` and `fails` are set, one event ("Could not read this
system") is written on the first failure, and the system's readings and
findings stay as they were. After 3 intervals and at least 3 minutes without a
good read, `remote.unreachable` (High) opens; the next good read resolves it
and writes "Reading this system again". `host.silent` is not used, since
nobody uploads for a remote system, and `hub update` skips these hosts.

**Container CPU and memory.** `unraid_stats`. Unraid has these only as a
subscription: `Subscription.dockerContainerStats` in
`api/generated-schema.graphql`, and no query or field on `DockerContainer`
carries them [33][44]. What was read and checked live (read-only, against a
real Unraid with 93 containers, 69 running):

- *Protocol.* The API server speaks `graphql-ws`, the library, so the
  WebSocket sub-protocol is `graphql-transport-ws`, at `/graphql` (the same
  path as HTTP): `api/src/unraid-api/graph/graph.module.ts`
  (`subscriptions: { 'graphql-ws': ... }`) and `request-protection.ts`
  (`path: '/graphql'`); the message flow is the graphql-ws protocol [45]:
  `connection_init`, `connection_ack`, `subscribe`, `next` ..., `complete`.
  The legacy `subscriptions-transport-ws` is not used (the server's own
  client, `internal-graphql-client.factory.ts`, is `graphql-ws`'s `createClient`).
- *The key.* Passed the way Unraid's own client passes it: in the
  `connection_init` payload as `{"x-api-key": <key>}` (`internal-graphql-client.factory.ts`,
  `connectionParams`). `authentication.guard.ts` merges those connection
  parameters into the request headers, and `header.strategy.ts` reads
  `x-api-key` from them, so it is the same check as the HTTP header. The key is
  in the first message after the TLS handshake and in no URL or header of the
  upgrade request. Checked live: the handshake and a stream with an Admin key.
- *What it carries.* One message per container per tick, `id` included and no
  name: `id` is the PrefixedID `<server id>:<64 hex digits>`, the same value as
  `DockerContainer.id`, so the hub adds `id` to the containers query and maps
  it to the name. Ticks were about 0.5 s apart live, and the first message
  arrived 1 to 2 s after subscribing (the server starts `docker stats` then:
  `docker-stats.service.ts` runs `docker stats --format ... --no-trunc` while
  there is at least one subscriber and kills it when the last one leaves; the
  topic is registered in `docker.resolver.ts` with `SubscriptionTrackerService`).
  All 69 running containers had reported by the end of the first tick.
  Docker refreshes each figure once a second, so every second message repeats
  the one before. `memUsage` is Docker's own text, `<used> / <limit>` in binary
  units with four significant digits (`970MiB / 94.28GiB`; `-- / --` while a
  container stops) [46]; without a memory limit Docker reports the host's memory
  as the limit, which the page says ("host memory, no limit") when the limit is
  within 2% of the server's memory.
- *A defect worked around.* Unraid does not strip the terminal control codes
  that `docker stats` prints before the first line of each refresh, so the
  first container's `id` arrived as `<server id>:ESC[H<id>` or
  `<server id>:ESC[J ESC[H<id>` (seen live; `docker-stats.service.ts` strips
  only `ESC[...m` and `ESC[...K`). The hub removes such sequences and keeps the
  last 64 hex digits; anything else is ignored.
- *Permission.* The subscription requires `READ_ANY` on `DOCKER`
  (`@UsePermissions` in `docker.resolver.ts`), and the Viewer role has `READ_ANY`
  on every resource except `API_KEY` (`api/src/unraid-api/auth/casbin/policy.ts`),
  so a Viewer key may subscribe. This was read from the source; it was not
  tried with a Viewer key (the key available for testing was an Admin key, and
  making a key is a change). See "To verify".

How it is sampled. Each poll, once the container list is read, `Graph.sample`
opens one WebSocket to `/graphql` with the same TLS mode as the queries (the
CA store, or the pinned certificate; never "don't verify"), sends
`connection_init`, waits up to 5 s for `connection_ack`, sends the subscription,
and reads `next` messages until every running container has reported or 5 s have
passed, then sends `complete` and closes (code 1000). It follows no redirects
(the library's own redirect handling is switched off), uses no proxy from the
environment and no compression, answers `ping` with `pong`, reads at most 5000
messages of at most 16 KiB each, and gives the library a logger that never
emits (websockets logs frames at debug level, and the first frame holds the
key). A failed sample (no connection, refused key, no reports, a bad message)
keeps the last data, which the pages show with its age and the error, and
the rest of the poll goes on; a failed sample never stops the poll or opens a
finding.

Stored per container: `cpu` (Docker's figure for about one second, where 100 is
one core and a multi-core container can pass 100), `mem_percent`, `mem_used` and
`mem_limit` in bytes (parsed from `memUsage`), and `sampled_at`. Pages: the
Containers page has sortable CPU and Memory columns (used, and the percent of its
limit) and a note saying how old the reading is; the Overview has "Top
containers", the five busiest by CPU and the five largest by memory among the
running ones, each linking to its row. VMs have no statistics in the API and are
not included.

No findings come from these readings. A threshold such as "a container is using
most of a core for an hour" needs history, not one sample a minute earlier; it
comes with the history charts (phase 4, "History charts and drill-down").
Until then the readings are shown, not judged.

Cost, measured against the owner's server (93 containers, 69 running; one
Python process on the same machine, the median of 8 samples after a warm-up):
about 22 ms of CPU per sample (TLS handshake, the exchange, parsing and
encoding what is stored), 1.1 s of wall time (the sample ends when the last of
the 69 has reported), a peak of about 0.6 MB of Python heap (measured with
`tracemalloc`) and under 0.25 MB of growth in resident memory, with 9.4 KB
stored per sample. At one sample a minute that is under 0.05% of one core.
Importing the WebSocket library adds about 3.9 MB to the process once. The cost
on the Unraid side (`docker stats` started and stopped each sample, for about a
second) was not measured: the `docker stats` process was not visible from where
the measurement ran.

The library is `websockets` (BSD-3-Clause), pinned to 17.4 [47]. It is the
widely used asyncio WebSocket client, has no dependencies of its own (a C speed-up
is optional and ships as wheels for CPython 3.13 on x86-64 and arm64 Linux, so
the hub image needs no compiler), supports Python 3.11 to 3.15 as the hub does,
and takes an `ssl.SSLContext`, which is how the pinned certificate is applied.
`httpx-ws` (0.10.0) was the other candidate: it would sit on httpx's transport,
but it adds `wsproto` and `anyio` to the install, and its handling of redirects
and proxies was not examined; `aiohttp` would add a second full HTTP client. One behaviour of `websockets` is turned off
on purpose: its `connect` follows HTTP redirects with no option to refuse them,
so the hub subclasses `connect` and overrides `process_redirect` to return the
redirect as an error (the same rule as for queries). Both are documented in the
library's reference [47].

**Docker folders.** `unraid_folders` is the Docker tab's folder tree. The
Containers page groups the containers by folder in the owner's order, with a
count per folder (a nested folder is headed "Parent / Child"), and puts the rest
in "Ungrouped", in their order under the root. Every container appears exactly
once; a name in a folder that Docker no longer has is ignored. It is the one
source whose failure is not shown as a source problem: an older Unraid has no
`organizer`, and then the page lists the containers flat with a note.

**The newest release.** The API has no update field (no release or update
field on `Query`, `Info` or `Vars` in `generated-schema.graphql` [33]). Unraid's
own "Update OS" check, `UnraidCheck.php` in the Unraid API repository [43],
reads `https://releases.unraid.net/os` with the query `branch`, `current_version`
and, for a registered server, `update_exp` (its license expiry). The page is
public and needs no account. DaemonSight does not send the server's details:
the hub asks for `https://releases.unraid.net/os?branch=stable`, the same
request for every server, once a day (a failed fetch is retried after six
hours) and only while an Unraid system is enabled, with the User-Agent
`DaemonSight/<version>` and nothing else. The reply (`version`, `date`,
`changelogPretty`) is kept in the `meta` table; only a stable `x.y.z` version
and a release-notes address on `docs.unraid.net` or `releases.unraid.net` are
accepted. `unraid.os_update` compares it with `vars.version`. Menu path:
Tools → Update OS (`Update.page`, title "Update OS"; the notice Unraid sends
links to `/Tools/Update`) [43]. Boot device backup: Main, Boot Device (called
Flash before 7.3.0), Boot Device Backup [41].

**Pages.** `/h/<id>/` Overview ("At a glance": version, uptime, array state,
capacity, CPU, memory, UPS, unread notifications, and "Top containers"), Array & disks, Containers,
VMs and Notifications. Cells carry `data-label`, rows have anchors
(`disk-disk1`, `ctr-<name>`, `vm-<name>`, `notif-<id>`) that findings link to,
and each section's panel names the GraphQL query, its curl form and the Unraid
page to compare with. The Hosts page shows "Unraid <version> · API" (and "<new> available" when a newer stable release is out), the address, the
last poll and the last error. At a glance shows the version the same way. Report and Accept are the same as for any host. On every host's Overview the system tiles sit at the top of the main column, and the side column runs from the top, level with them.
Text from the server (container names, notification titles) is untrusted: cut
to a length, stripped of control characters and escaped by the templates.

**Facts about the API that shaped the rules** (checked against the schema and
a real Unraid 7.3.2 server, read-only):

- `smartStatus` is `OK` or `UNKNOWN` only (api `disks.service.ts` maps
  anything else to `UNKNOWN`), so "SMART failed" can't be reported; the rule
  is "SMART status not OK" at Medium, with USB devices (the boot flash)
  excluded.
- `numReads` and `numWrites` count I/O requests, not errors ("Count of I/O
  read requests sent to the device I/O drivers" in the schema), so only
  `numErrors` makes a finding.
- `display.hot` and `display.max` are the disk temperature thresholds in
  degrees C; `display.warning` and `display.critical` are disk usage
  percentages (default 70 and 90). The SSD thresholds are not exposed;
  Unraid's shipped defaults are 60 and 70 (webgui `default.cfg`) [36].
  A threshold set on one disk in Unraid is not visible to the API.
- `ArrayDisk.temp` is in degrees C and null for a spun-down disk. A
  disk's usage comes from `fsSize`, `fsFree` and `fsUsed` in kilobytes.
- `metrics.memory.percentTotal` is used for memory instead of working it out
  from used and total.
- `vms` can be null when the VM service is off; that is "not available",
  not an error.

The parity age limit (100 days) follows Unraid's advice to check "on a
monthly or quarterly basis" [37]; 90% and 95% for usage are DaemonSight's
own choice.

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

## Windows agent (planned)

A collector for Windows, after log collection, because most of what matters
on Windows is in the Event Log and needs the same rules engine.

What it would report:

- Windows Update status and a pending reboot.
- Application updates from winget.
- Defender: real-time protection on or off, signature age, detections.
- BitLocker status per drive, and the firewall profiles.
- Services and listening ports (psutil works on Windows).
- Security events from the Event Log: failed and successful logons (4625,
  4624), new users and changes to the administrators group (4720, 4732), new
  services (7045), the audit log cleared (1102), Defender detections. Matched
  by the log rules engine, which could also run Sigma rules, the format tools
  such as Hayabusa and Chainsaw use for Windows event logs.

Open questions:

- Packaging: a Windows service built from Python, an MSI installer, and code
  signing so SmartScreen doesn't warn.
- winget is built for a signed-in user. Running it as the SYSTEM account is
  awkward and its text output isn't a stable interface; the
  `Microsoft.WinGet.Client` PowerShell module may be better. Verify both.
- Overlap with Wazuh, whose agent already collects Windows events, checks
  vulnerabilities and runs detection rules. Decide whether DaemonSight does
  this itself or reads from Wazuh (see source 11).

## Maps (planned)

Pictures of how traffic reaches a service, drawn as SVG on the server, so they
work under the current CSP and on phones.

- **One host:** internet → provider firewall → host firewall or port forward →
  Caddy site → listener → process or container. Each step is coloured open,
  blocked or LAN only, and links to the row and source panel it came from.
- **Across hosts, on a hub:** links between machines from data already
  collected: a Caddy upstream that points at another host's listener, a port
  forward to another host's address, WireGuard tunnels. Richer once remote
  sources (phase 2b) bring in the firewall and Unraid.
- **Where bans come from:** fail2ban bans on a world map. Needs a GeoIP
  database whose licence allows bundling or download (DB-IP's free tier is
  one to check). Lower priority.

## History charts and drill-down (planned)

Phase 4 charts for CPU, memory, disk and traffic, where clicking a point
shows what was using it at that moment.

| Chart | Drill-down | From |
|---|---|---|
| CPU | Top processes and containers | One psutil pass a minute (top 10); per-container CPU from the cgroup files |
| Memory | Top processes and containers by resident memory | Same samples |
| Disk I/O | Top processes by reads and writes | psutil per-process I/O counters (root) |
| Disk space | Which mount filled, and when | Already collected per mount; folder sizes only on request |
| Network | Per interface; per container on Docker hosts | Interface counters; container counters from the cgroup or Docker. Per-process traffic needs eBPF, so not at first |

Each drill-down row links to its row on Services. The samples get their own
retention setting.

For a system read from Unraid, per-container CPU and memory already arrive each
poll (`unraid_stats`, see "Container CPU and memory" under Unraid), but only the
latest sample is kept and nothing is judged. The history and the thresholds
(for example, a container above most of a core for an hour, or close to its
memory limit) belong here, not in the Unraid rules, because one sample a minute
cannot tell a spike from a steady load.

The collector must stay light:

- Budget: under 1% of one CPU core on average and about 60 MB of memory on a
  small VPS. Anything that would break it is off by default.
- Cheap sources first: container CPU and memory from the cgroup files the
  kernel already keeps, not Docker's stats API, which takes two samples per
  container.
- Anything that walks a disk runs only when asked for, never on a schedule.
- The collector records its own CPU and memory, shows them on the Overview,
  and raises a low finding when it goes over budget.

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
- Fedora: `dnf needs-restarting -C -s` output (the parser takes lines naming `*.service`; not captured, since a container has no D-Bus), the JSON for "no reboot needed", the whole collector on a real Fedora 44 KDE host, and `install.sh` under SELinux enforcing. dnf5 was tested in `fedora:44` containers only.
- CVE matching: the whole path on a real hub with real hosts (tested here against the real feeds and a real dpkg inventory, with the downloads and the hub's pages exercised by fakes of the three servers); Fedora advisories on a host with updates pending beyond the captured sample; what `apt install unattended-upgrades` writes on Debian 12 and 13 (read from the package scripts, not run); whether `dnf5-automatic.timer` set up from the steps in `pkg.auto_updates_off` installs security updates on a real Fedora 44 host (the config keys come from the docs and the shipped file, the run was not tested).
- Whether the Docker source works against Podman's Docker-compatible socket.
- The Docker source on a real Docker host (alpha or the VPS).
- The systemd sandboxing in `daemonsight-web.service` inside an unprivileged LXC.
- Unraid: every query ran against one real server (7.3.2) with an Admin key, read-only, and the fixtures in `tests/fixtures/unraid/` are trimmed copies of those replies. Not seen on a real server: the `me` reply for a Viewer-only key (its shape is read from the API source and the Admin reply, not captured), a failing SMART disk, an array that is stopped, a UPS on battery, and a Viewer key being refused or accepted by each query. The first poll with a real Viewer key is the check.
- Unraid: the "how to use the API" page lists only the roles admin, connect and guest, while the schema and the CLI example (`--roles ADMIN,VIEWER`) have `VIEWER`; the Viewer role comes from the schema [33] and [32], and a Viewer key was not available to test.
- Unraid: whether the API gives a threshold for a disk with its own temperature setting, and the SSD thresholds (the schema has no field).
- Unraid: the notification, folder and release queries ran against the real server with an Admin key, read-only; a Viewer key reading `Notifications.list` and `Docker.organizer` was not tried. The release page was fetched without parameters and with `branch=stable`; its reply shape is what the fixture copies. Unverified: the exact label of the notification bell's "Archive all" (taken from the brief; the webgui source has no such string in the files searched), whether an acknowledged SMART attribute (the Dashboard's orange icon) still sends a notification when it changes again (the SMART docs say so), and that a history entry's `date` is the time the check ended (observed: it matches the finish notice within seconds).
- Unraid: the container statistics subscription ran against the real server with an Admin key, read-only (the handshake, the stream, the id format and its control-code prefix, `memUsage`). Not tried with a Viewer key: the source gives a Viewer `READ_ANY` on `DOCKER`, which the subscription needs, but no Viewer key was available. Run it once with a real Viewer key before relying on it. The cost on the Unraid side (`docker stats` started and stopped each sample) was not measured, and the figure for "no memory limit" assumes Docker reports the host's memory as the limit (seen here: 94.28 GiB on a server with that much RAM).
- Outside view: the whole chore against the real InternetDB from a real hub with real hosts (tests use a fake server with the documented reply shape, and the requests were checked by hand against documentation addresses and public ones); what an HTTP 429 from InternetDB looks like and whether it sends `Retry-After`; whether Shodan scans IPv6 widely; and the tag values beyond the 31 in Shodan's banner schema [56].
- Shodan API source: never run against the live API (no key was available; no request was sent to api.shodan.io). Unverified: the status code and body for a bad key, for an address Shodan has no information on, and for a free account's key (401, 403 and 404 are assumed from the official client's handling and from InternetDB); what a 429 looks like and whether it sends `Retry-After`; whether a full host lookup carries `product`, `version`, `cpe23` and `vulns` for every banner (the REST page's example shows none, the banner schema lists them as optional); whether the host reply has a top-level `vulns` (it is read if present, and banner `vulns` are read too); the biggest real reply (the cap is 4 MiB); whether the one-time Membership allows commercial use; and which plan name `api-info` returns for each plan. Run Test key and one real refresh with a real key before relying on it.

## Sources

1. systemd D-Bus API: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
2. psutil: https://psutil.io/
3. docker-socket-proxy: https://github.com/Tecnativa/docker-socket-proxy
4. Caddy admin API: https://caddyserver.com/docs/api
5. fail2ban-client(1), Debian 12: https://manpages.debian.org/bookworm/fail2ban/fail2ban-client.1.en.html
6. nft(8), Debian 12: https://manpages.debian.org/bookworm/nftables/nft.8.en.html
7. Trivy: not used (see "Data sources"); advisories https://github.com/advisories/GHSA-69fq-xp46-6x23 and https://github.com/advisories/GHSA-mcj4-mphf-j9ff
8. (unused)
9. debsecan(1), Debian 12: https://manpages.debian.org/bookworm/debsecan/debsecan.1.en.html
10. Docker Compose labels: https://github.com/docker/compose/blob/main/pkg/api/labels.go
11. Wazuh architecture: https://documentation.wazuh.com/current/getting-started/architecture.html
12. apt-get(8) (`-s` simulation, `Debug::NoLocking`), Debian 13: https://manpages.debian.org/trixie/apt/apt-get.8.en.html
13. needrestart(1) and batch mode output: https://github.com/liske/needrestart (man/needrestart.1, README.batch.md)
14. distro-info-data (release dates, ISC licence): https://salsa.debian.org/debian/distro-info-data and its `debian/copyright`; Debian LTS: https://wiki.debian.org/LTS
15. dnf5 check-upgrade (exit code 100, `--security`, `--json`): https://dnf5.readthedocs.io/en/latest/commands/check-upgrade.8.html; global `--cacheonly`: https://dnf5.readthedocs.io/en/latest/dnf5.8.html
16. dnf5 needs-restarting (exit code 1, `/run/reboot-required`, `--services`): https://dnf5.readthedocs.io/en/latest/dnf5_plugins/needs_restarting.8.html; versionlock (`/etc/dnf/versionlock.toml`): https://dnf5.readthedocs.io/en/latest/commands/versionlock.8.html
17. dnf5 system-upgrade: https://dnf5.readthedocs.io/en/latest/commands/system-upgrade.8.html
18. Fedora release dates: endoflife.date, https://endoflife.date/api/v1/products/fedora (MIT); SELinux domain for services run from `/opt`: https://www.mankier.com/8/unconfined_service_selinux
19. apt.conf(5) (`APT::Periodic::Update-Package-Lists`, `Unattended-Upgrade`), Debian 13: https://manpages.debian.org/trixie/apt/apt.conf.5.en.html; the timers: https://wiki.debian.org/UnattendedUpgrades ("Modify the schedule via systemd": `apt-daily.timer` downloads, `apt-daily-upgrade.timer` upgrades)
20. unattended-upgrades package, Debian 13 (2.12) and 12 (2.9.1+nmu3), read from the .deb files (`dpkg-deb -e`): its `config` script asks `unattended-upgrades/enable_auto_updates` at debconf priority low with Default `true`; its `postinst` reads the answer with `db_get` (the default counts when the question is skipped) and, on `true`, installs `/usr/share/unattended-upgrades/20auto-upgrades` (`APT::Periodic::Update-Package-Lists "1"` and `APT::Periodic::Unattended-Upgrade "1"`) as `/etc/apt/apt.conf.d/20auto-upgrades`. The Debian wiki says to run `dpkg-reconfigure unattended-upgrades` to enable or check it. Not confirmed by running it: the `debian:13` and `debian:12` containers on the test server stalled at `apt-get install` (slow downloads), so what the install writes to `/etc/apt/apt.conf.d/` is from reading the scripts. See "To verify".
21. dnf5 automatic (config files and their order, `[commands]` `apply_updates` default False, `upgrade_type`, `dnf5-automatic.timer`): https://dnf5.readthedocs.io/en/latest/dnf5_plugins/automatic.8.html. In `fedora:44` the package `dnf5-plugin-automatic` ships `/usr/share/dnf5/dnf5-plugins/automatic.conf` (`apply_updates = no`, `upgrade_type = default`), the user file `/etc/dnf/automatic.conf`, and `dnf5-automatic.timer` (`OnCalendar=*-*-* 6:00`, `WantedBy=timers.target`)
22. dpkg-query(1), Debian 13 (`source:Package`, `source:Version` since dpkg 1.16.2; `db:Status-Abbrev`): https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html
23. dnf5 advisory (`list`, `info`, `--updates`, `--security`, `--with-cve`, `--json`): https://dnf5.readthedocs.io/en/latest/commands/advisory.8.html; output captured from `fedora:44` (dnf5 5.4.x), kept in `tests/fixtures/dnf/`
24. Debian security tracker JSON export: https://security-tracker.debian.org/tracker/data/json (linked from https://security-tracker.debian.org/tracker/ as "All information in JSON format"); served with `Content-Encoding: gzip` and `Last-Modified`
25. The tracker's own reader of that JSON, `bin/tracker_data.py` (`Issue.get_status`), and its web service `bin/tracker_service.py` (`data/json`): https://salsa.debian.org/security-tracker-team/security-tracker. The JSON has no schema document; the field layout in `cve/tracker.py` is read from the file and from that reader
26. EPSS, "Get the Data" (the daily CSV URL, its redirect, the three fields, the model-version comment line, free of charge with no registration): https://www.first.org/epss/data
27. EPSS FAQ (probability meaning, "no universal threshold", 0.10 "commonly cited ... no special authority", about the 95th percentile, attribution requested): https://www.first.org/epss/faq
28. CISA Known Exploited Vulnerabilities catalog and its JSON feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog; licence (CC0 1.0): https://www.cisa.gov/sites/default/files/licenses/kev/license.txt
29. Debian Policy 5.6.12, Version: https://www.debian.org/doc/debian-policy/ch-controlfields.html#version; dpkg's `verrevcmp` in lib/dpkg/version.c
30. Ubuntu CVE data (OVAL "recommended"; the JSON API "still a work in progress"): https://ubuntu.com/security/cves/about and https://ubuntu.com/security/oval
31. Unraid API, using the GraphQL API (the `x-api-key` header, the `/graphql` endpoint on the server's web address): https://docs.unraid.net/API/how-to-use-the-api/
32. Unraid API, API keys and roles (Settings → Management Access → API Keys): https://docs.unraid.net/API/programmatic-api-key-management/
33. Unraid API source: `api/generated-schema.graphql` (all types and fields above, `enum Role`), `api/src/unraid-api/graph/user/user.resolver.ts` (`me`), `api/src/unraid-api/auth/auth.service.ts` (`validateApiKeyCasbin`), `api/src/unraid-api/graph/resolvers/disks/disks.service.ts` (`smartStatus`): https://github.com/unraid/api
34. httpx SSL (`verify` accepts `True` or an `ssl.SSLContext`): https://www.python-httpx.org/advanced/ssl/
35. Python `ssl`: `get_server_certificate` ("without validation"), `SSLContext.load_verify_locations(cadata=...)`, `VERIFY_X509_PARTIAL_CHAIN`, `CERT_REQUIRED`: https://docs.python.org/3/library/ssl.html
36. Unraid webgui `emhttp/plugins/dynamix/default.cfg` (`hot`, `max`, `hotssd`, `maxssd`) and `DiskSettings.page`: https://github.com/unraid/webgui
37. Unraid docs, array health and maintenance (parity checks "on a monthly or quarterly basis"): https://docs.unraid.net/unraid-os/using-unraid-to/manage-storage/array/array-health-and-maintenance/
38. Unraid docs, unclean shutdowns (Settings → Syslog Server, Settings → UPS Settings, "Unsafe Shutdown" starts a parity check, shutdown time-outs): https://docs.unraid.net/unraid-os/troubleshooting/common-issues/unclean-shutdowns/
39. Unraid docs, capture diagnostics and logs (persistent logs: Settings → Syslog Server, "Mirror syslog to boot drive", remote and local syslog server; "if the system crashes, the system log will be lost"; Tools → Diagnostics, Tools → Syslog): https://docs.unraid.net/unraid-os/troubleshooting/diagnostics/capture-diagnostics-and-logs/ and the page's source `emhttp/plugins/dynamix/SyslogSettings.page` in https://github.com/unraid/webgui
40. Unraid docs, shares (Shares tab, click a share: Allocation method, Split level, Minimum free space; changes affect only new files; split level takes priority over free space): https://docs.unraid.net/unraid-os/using-unraid-to/manage-storage/shares/ ; SMART reports: https://docs.unraid.net/unraid-os/system-administration/monitor-performance/smart-reports-and-disk-health/ ; replacing disks: https://docs.unraid.net/unraid-os/using-unraid-to/manage-storage/array/replacing-disks-in-array/ ; system crashes (Memtest86+): https://docs.unraid.net/unraid-os/troubleshooting/common-issues/system-crashes-and-stability/
41. Unraid docs, secure your boot drive (Boot Device Backup): https://docs.unraid.net/unraid-os/system-administration/secure-your-server/secure-your-boot-drive/ ; array health (Check, "Write corrections to parity", first 100 error addresses, 4 KiB blocks, Settings → Scheduler → Parity Check): see [37]
42. Unraid webgui, `emhttp/plugins/dynamix/scripts/monitor` (the notification titles and subjects), `plugins/dynamix.docker.manager/DockerContainers.page` (Check for Updates, Update All, Container Size buttons), `DockerSettings.page` (Docker vDisk size), `scripts/dockerupdate` (Docker update notice), `ParityCheck.page` (Settings → Scheduler → Parity Check): https://github.com/unraid/webgui ; Parity Check Tuning plugin, `parity.check.tuning.php` (its notices): https://github.com/itimpi/parity.check.tuning ; Fix Common Problems, `scripts/scan.php` and `FixProblems.page` (menu Utilities; "Investigate at Settings / User Utilities / Fix Common Problems"): https://github.com/Squidly271/fix.common.problems
43. Unraid API repository, `plugin/source/dynamix.unraid.net/usr/local/emhttp/plugins/dynamix.plugin.manager/include/UnraidCheck.php` (`BASE_RELEASES_URL`, the request parameters), `.../scripts/unraidcheck`, `.../Update.page` (title "Update OS"), and `api/src/unraid-api/graph/resolvers/notifications/notifications.service.ts` (`getWarningsAndAlerts` and `loadNotificationsFromPaths`): https://github.com/unraid/api ; the release page: https://releases.unraid.net/os
44. Unraid API source for the statistics subscription: `api/src/unraid-api/graph/resolvers/docker/docker.resolver.ts` (`dockerContainerStats`, `@UsePermissions` `READ_ANY` on `DOCKER`, `SubscriptionTrackerService` start and stop), `docker-stats.service.ts` (`docker stats --no-trunc` with a `--format` of the ID, CPUPerc, MemUsage, MemPerc, NetIO and BlockIO fields, one `pubsub.publish` per output line), `api/src/unraid-api/graph/graph.module.ts` and `request-protection.ts` (`graphql-ws`, path `/graphql`), `auth/authentication.guard.ts`, `auth/header.strategy.ts`, `shared/internal-graphql-client.factory.ts` (`connectionParams` with `x-api-key`), `auth/casbin/policy.ts` (Viewer: `READ_ANY` on every resource but `API_KEY`): https://github.com/unraid/api (read at commit 023a3ca, November 2026)
45. GraphQL over WebSocket protocol (sub-protocol `graphql-transport-ws`; `ConnectionInit`, `ConnectionAck`, `Ping`, `Pong`, `Subscribe`, `Next`, `Error`, `Complete`; close codes 4400, 4401, 4403, 4408, 4409, 4429): https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md
46. Docker CLI, `cli/command/container/formatter_stats.go` (`MemUsage`: `units.BytesSize(used) + " / " + units.BytesSize(limit)`, `"-- / --"` when invalid) and docker/go-units `size.go` (`BytesSize` is `%.4g` with `B, KiB, MiB, GiB, TiB, PiB, EiB, ZiB, YiB`): https://github.com/docker/cli and https://github.com/docker/go-units
47. websockets 17.4 (BSD-3-Clause; asyncio client `websockets.asyncio.client.connect`: `ssl`, `subprotocols`, `proxy`, `compression`, `max_size`, `open_timeout`, `close_timeout`, `logger`, and `process_redirect`, which follows redirects by default): https://websockets.readthedocs.io/ and the package source, https://github.com/python-websockets/websockets ; the file listing for 17.4, uploaded 2026-10-30, with wheels for CPython 3.13 on manylinux x86-64 and aarch64: https://pypi.org/project/websockets/17.4/ ; httpx-ws 0.10.0 (requires anyio, httpcore, httpx and wsproto): https://pypi.org/project/httpx-ws/
48. Unraid webgui, `emhttp/plugins/dynamix.docker.manager/DockerContainers.page` (the "CPU & Memory load" column, Advanced View): https://github.com/unraid/webgui
49. Shodan InternetDB, the published page (what it returns, "updated once a week", "free for non-commercial use", the enterprise licence for revenue-generating use, no key needed, no banners): https://internetdb.shodan.io/ . Reply shape, the 404 body `{"detail":"No information available"}`, IPv6 records, the 405 and 307 responses and the cache headers were observed with requests on 2026-11-18
50. Shodan tag values: a third-party Go client library's tag list with a description of each, https://pkg.go.dev/github.com/denisgubin/shodan/models/tags ; an unofficial list of the most used tags, https://gainsec.com/2022/02/07/top-20-shodan-general-search-tags/ . Neither is Shodan's own documentation
51. Shodan search filters (the `tag` filter is restricted to higher API plans; no values listed): https://www.shodan.io/search/filters ; Shodan help, what Shodan indexes (the data comes from service banners): https://help.shodan.io/the-basics/what-is-shodan
52. Shodan REST API reference, read 2026-11-18: `GET /shodan/host/{ip}` (parameters `history` and `minify`, the `key` query parameter in every example, the response example with `ports`, `data` banners, `transport` and `timestamp`), `GET /api-info` (the `plan`, `query_credits`, `scan_credits` example), and "Error Handling" ("A non-200 status code ... {"error": "Invalid IP"}"): https://developer.shodan.io/api
53. Shodan book, "Shodan API" (query, scan and alert credits; "IP lookups don't consume query credits"; credits reset monthly; history up to 90 days; Shodan crawls at least weekly): https://book.shodan.io/developer-apis/shodan-api/ ; "InternetDB" ("bursts of up to 10,000 requests per second", weekly update, `vulns` includes verified and unverified): https://book.shodan.io/developer-apis/internetdb/
54. Shodan plans and pricing (Freelancer, Small Business and Corporate list "Commercial Use"; "All API plans are subject to a rate limit of 1 request per second"; the FAQ "Can we use the API to build products?"; the comparison table's IP lookups and InternetDB rows; the Membership as "a one-time payment for a lifetime account upgrade"), read 2026-11-18: https://developer.shodan.io/pricing (redirects to https://account.shodan.io/billing)
55. Shodan help center: "Looking up IP Information" ("requires at least a Shodan Membership (one-time payment of $49 ...)"): https://help.shodan.io/developer-fundamentals/looking-up-ip-info ; "Shodan Credits Explained": https://help.shodan.io/the-basics/credit-types-explained ; "Account Management FAQ" (the Membership is a lifetime upgrade): https://help.shodan.io/the-basics/account-faq
56. Shodan Datapedia, the banner reference and JSON schema v29 (`product`, `version`, `transport`, `timestamp` in UTC, `vulns`, `cpe23`, and the Tag values `c2`, `compromised`, `doublepulsar`, `malware` ...): https://datapedia.shodan.io/ and https://datapedia.shodan.io/banner.schema.json
57. Shodan's official Python client, `shodan/client.py` (`params['key'] = self.api_key`, `api_rate_limit = 1`, HTTP 401 and 403 handling, `host(ips, history, minify)` taking a comma-separated list): https://github.com/achillean/shodan-python
58. Shodan Enterprise ("The Enterprise Data License provides rights to commercial use without attribution"): https://enterprise.shodan.io/
