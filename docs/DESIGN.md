# DaemonSight design

Status: phases 1, 2, 2c, 3a and 3b are built (CVE matching for Debian, Raspberry Pi OS, Ubuntu and Fedora hosts); phase 3c parts 1 to 3 (container images: end-of-life bases, Debian, Alpine and Ubuntu CVEs) are built. Phase 4 part 1 (alert channels, alerts and digests) is built. Updated 2026-11-24.

## Goal

One hub that shows, across your whole stack (Linux servers and their
containers, Unraid, OPNsense), what each system exposes, what is watching it,
and what is out of date. DaemonSight also checks those facts against each other and
reports the gaps between them as findings.

**Core rule: every system shows its available updates and the CVEs each one
fixes.** This is a key feature, not an extra. A new source isn't finished
until it shows both, or the page says plainly why it can't (no advisory data
from the vendor) and what is missing. Where an API can only list updates with a
wider permission, read the update list some other way (a collector on the
host, or a published advisory feed) rather than widen the key.

Targets for v1:

- Debian 12 VPS: Caddy, Docker, fail2ban, nftables, WireGuard. Python 3.11.
- Debian 13 LXC containers. Python 3.13.

## Not in v1

- Log storage or shipping. DaemonSight reads logs to answer specific questions; it is not a SIEM. Log collection is planned after phase 3; see "Log collection and auditing (planned)".
- Changing the host. v1 is read-only: no bans, restarts or firewall edits.
- A hub that ships as anything but a container. A collector-and-web install can't also be a hub. (So a standalone host's Vulnerabilities page only says CVE matching runs on a hub.)
- Kubernetes, nginx, Apache, iptables-legacy. Podman has no support of its own: `[collector] docker_socket` can point at Podman's Docker-compatible socket, which has not been tried (see INSTALL.md).

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
| `daemonsight-uninstall.path` + `.service` | root | Uninstalls DaemonSight when the hub asked. See "Uninstall from the hub". |

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
| CISA's SSVC rating (Automatable, Technical Impact) | `https://cveawg.mitre.org/api/cve/<CVE-ID>` | hub, a CVE at a time, again after 7 days | The CVE Services record of each CVE the hub has matched; its "CISA-ADP" container has the rating, and the record's CVSS is kept for display. No key. [86][87] |

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
| `cve.package` | One per source package on the hub: a CVE an update fixes, or one on CISA's KEV list that has no fix yet. The severity is the worst of its CVEs by CISA BOD 26-04's Table 1 (see "Prioritisation"): 3 days is Critical, 14 days High, 60 days Medium, "fix on system upgrade" Low. Unfixed CVEs that aren't on KEV make no finding. | Critical, High, Medium or Low |
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
| `docker.superseded_images` | Only with a Docker reader (see "Docker reader"). Images with no tag that no container uses, each with a newer image of the same repository in use: "N old image versions left by updates, X GB". Fix: `docker image prune`. The basis is the set of image ids (no sizes or dates), so an accept holds until a different image shows up | Low |
| `docker.unused_images` | Tagged images no container, running or stopped, uses ("N images no container uses, X GB"), without the superseded ones. Fix: one `docker image rm` line per image (the short id, or the tags when the image has several; at most about 1,700 characters, then a comment line). The basis is the set of image ids | Info |
| `docker.unused_volumes` | Volumes no container mounts. The "What to do" steps open with a data-loss warning (a volume can hold the only copy of a database). No `fix`: one `docker volume rm` per volume is in each row's source panel, and a prune-all command is never offered. The basis is the set of volume names | Info |
| `docker.build_cache` | Docker's build cache is over 5 GB (decimal, as Docker prints sizes). Fix: `docker builder prune`. The basis is constant, so the size can drift | Info |

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

SQLite in WAL mode at `/var/lib/daemonsight/state.db`. The collector
writes; the web process opens it with `mode=ro`. On a hub, the hub's
web process is the writer.

`[retention]` sets how long rows stay: metric points 48 hours by default,
events and resolved findings for good. The collector prunes its own host's
rows hourly; the hub prunes every host's. Open findings are never pruned. On a
hub the Settings page can change it (see "Settings and configuration
precedence").

- `snapshots`: source, taken_at, ok, error, data (JSON). The latest row per source is current state.
- `findings`: rule, key, severity, title, detail, link, fix, basis, howto (schema version 6), first_seen, last_seen, resolved_at.
- `accepted`: host, rule, key, fingerprint, note, accepted_at, accepted_by. Written by the hub's web process (see "Accepting a finding"). Schema version 4.
- `remotes` (schema version 5): id, kind (`unraid` or `opnsense`), url, enabled, tls (`verify` or `pin`), tls_pin (SHA-256 of the pinned certificate), tls_cert (its PEM), interval, created_at, last_ok, last_error, fails. A remote system is also a row in `hosts` with `hosts.kind` set (collector hosts have `kind` NULL) and a `token_hash` of `remote:<id>`, which no upload token can equal. Schema 9 added `reader_url` (an Unraid server's Docker reader) and schema 10 added `crowdsec_url` and `crowdsec_never` (an OPNsense firewall's CrowdSec Local API and its never-ban list). The secrets are not in the database: each is a file in `<data>/remotes/`, mode 0600 in a 0700 folder: `<id>.key` (the API key), `<id>.reader-token` (the Docker reader's token) and `<id>.crowdsec-key` (the CrowdSec bouncer key).
- `hosts` (schema version 11 added `upload_interval`, `uninstall_state`, `uninstall_asked` and `uninstall_detail`): see "Uninstall from the hub".
- `outside` (schema version 7): ip, first_try, checked_at, fetched_at, status (`ok`, `none` for a 404, `error`), data (the cleaned answer, JSON: an InternetDB answer as is; a Shodan API answer carries `source: "shodan"`, `services` and `last_update` as well), error. Hub only; see "The outside view".
- `settings` (schema version 8): key, value (JSON), changed_at, changed_by. Hub only: what was saved on the Settings page, over the config file. See "Settings and configuration precedence".
- `events`: changes worth showing in "Recent changes": a new port, a ban spike, a unit going down. Events are per host (`host` is NOT NULL and every list filters by it). A change that belongs to no host, a setting changed on the hub, is stored with the reserved host `""` (`db.HUB_HOST`), which no host id can equal (`hub.HOST_RE` needs at least one character). They show under "Recent hub changes" on the hub's Hosts page and on the Settings page, never under a host. The same retention applies to them. This reuses the one events table and its pruning, instead of a second log with its own retention and display code.
- `findings.deadline_days` (schema version 12): the remediation timeline in days (CISA BOD 26-04) of a `cve.package`, `docker.image_cves` or `opnsense.updates` finding, counted from `first_seen`; NULL when the finding has none. Used by the alert channels' deadline reminders and the digests' overdue list.
- `notify_channels`, `notify_seen`, `notify_events` (schema version 12): the alert channels, what each has been told about each open finding, and the outbox. Hub only; see "Alerts, digests and reports (phase 4)". A channel's secret is a file, not a row: `<data>/notify/<id>.secret`, mode 0600 in a 0700 folder.
- `metrics`: ts, name, value. Raw points for `[retention] metrics_hours`. Longer history as 5-minute averages is planned with the charts (phase 4).

Backups (`backup.py`): one owner-only `.tar.gz` with a consistent copy of
the database (SQLite's online backup API, so the writer keeps running), the
config, the password hash, the session secret, any upload token, the Shodan
key (`shodan.key`), the alert channels' secrets (`notify/<id>.secret`) and the remote systems' key files (`remotes/<id>.key`,
`remotes/<id>.reader-token` and `remotes/<id>.crowdsec-key`, checked by name
on restore and written back 0600), plus a manifest. The folder is 0700 and each archive 0600. The hub, and a collector that keeps its own data, make one every
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
`outside.refresh_hours`, `cve.enabled`, `cve.refresh_hours`, `cve.epss_automatable`,
all three `retention.*`, `backup.interval_hours` (blank is automatic, stored
as null), `backup.keep`, `remote.enabled` and `notify.hub_url` (the address alert links point at, kind `url`). The alert channels are not settings rows: they have their own pages (see "Alerts, digests and reports (phase 4)"). `backup.dir` is read-only: it
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
| `cve.run.Chore` | start of every `run_once` (each minute). Off: closes `cve.*` findings and returns. A new `epss_automatable` or turning it on again recomputes the findings |
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

Why not React and MUI: DaemonSight runs on the machine it
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

Phone header: two rows (docs/UI.md, "Navigation"). Row 1 is the logo and the host
pill, whose name truncates; row 2 is the filter with the menu button beside it.
The top of the menu panel holds one line with the OS, its support status when it
is not plain "Supported", the kernel and the uptime. It appears on host pages
only, never on the hub's Hosts page. The desktop header is unchanged.

Row links: a finding links to the row it is about, such as an Exposure port,
a Caddy site, a forward or a jail (the row's `id` is built by
`findings.anchor`). `app.js` (`showTarget`) scrolls to that row, clears a
filter that hides it and flashes it once; the flash is off under
`prefers-reduced-motion`.

### Screenshots

The README pictures (`docs/images/*.png`) come from `scripts/screenshots.py`. It starts the web app as a hub with sample data (made-up hosts and documentation addresses), reusing the fakes in `tests/` (Unraid, OPNsense, Docker reader, CrowdSec) so the pictures and the tests describe the same servers, and photographs it with Playwright's Chromium in the dark theme. The clock, the date and the version string are frozen and animation is off, so a run with the same code gives the same files. The `Screenshots` workflow runs it on pushes to main that touch `src/daemonsight/web/`, the script or the workflow, and commits any changed images. To preview locally: `pip install -e .[screenshots]`, `playwright install chromium`, `python scripts/screenshots.py`. A new page that deserves a picture is a new `shoot` line in the script.

### Layout and wording rules

The layout and wording rules live in [UI.md](UI.md).

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
- **Exposure page.** Under the title, one neutral line says the public address,
  the number of expected public ports and what the provider firewall lets in,
  or that the host has no public address. Its (i) button opens the full
  explanation and port lists. A red badge on the line, "N unexpected" (or
  "unexpected or changed"), links to the listeners; it shows only when a
  listener is Unexpected or Changed. A Status column on each listener row and each port
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

Section menus: a nav tab with two or more sections has a chevron menu (`web/sections.py`; the active tab's is rebuilt
from the page by `app.js`). On a hub the Hosts tab's menu is the exception: `render()` passes `menu_hosts` (one light
read, `views.hosts_menu`, hosts A to Z with a status dot), and `base.html` lists them, a line, then "Recent hub changes".
It is never rebuilt by `app.js`; the current host is marked `aria-current`, and a long list scrolls in the popover.

Phones: below 768 px each table row becomes a stacked card, one labelled line
per cell, with the header row hidden from view but kept for screen readers.
The header shows the logo, host and a Menu button; the section links and the
account panel's items (Settings, Theme, "Hide empty sections", Log out) open in
a panel below it (script only; without it the header is unchanged). The same
panel is drawn inline there, not as a nested popover, and the account button
is hidden; a browser without popover support gets the same inline panel. The filter box stays visible. The
Exposure page's summary line and (i) popover work the same at every width.

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

## Alerts, digests and reports (phase 4)

The goal is a product other people use: administrators, stakeholders and executives get what
they need from the hub without logging in. Owner decisions, 2026-11-24. Sent by the hub, not the
collectors, since the hub has every finding.

**Built (part 1):** channels, immediate alerts and scheduled digests, described below. **Planned (part 2):**
scheduled reports, at the end of this section. Code: `src/daemonsight/notify/` (`channels.py` what a channel is and where its
secret lives, `engine.py` the chore, `render.py` the four message formats, `send.py` the four senders, `schedule.py`
digest times) and `web/notify_routes.py` (the Settings page's routes).

### Alert channels (built)

Configured on the Settings page, under Notifications, "Notification channels": any number of channels, each of Ntfy, Slack,
Discord or email, each added, edited, tested (Send test) and removed there. Each channel has:

| Setting | Notes |
|---|---|
| Name | 1 to 40 characters, unique (ignoring case). Shown on the Settings page only |
| Type-specific fields | Ntfy: server, topic, login (none, access token, or user name and password). Slack and Discord: the webhook URL. Email: server, connection, port, user name, From, recipients (up to 20) |
| Severities | Which severities it receives. Default Critical and High |
| Send | Immediately, in a digest, or both |
| Resolved alerts | Off by default. Digests always list what resolved |
| Deadline reminders | On by default |
| Digest schedule | Daily, weekly (a weekday) or monthly (a day 1 to 28), at a time, in the hub's time zone. "Skip empty digests", on by default |

Setting "Hub address for links" (`[notify] hub_url`, a Settings field) is the address every link points at. Blank, it is filled in
with the address the administrator is using the first time a channel is saved. Every message names "DaemonSight <version>"
(with the commit, as the pages do) and, when known, the hub's address in its footer; email also carries the logo, an inline image
by Content-ID (`web/static/logo-256.png`, the same file as `assets/logo-256.png`; a test compares them), never a remote URL.

**Allowed destinations.** Checked on the whole URL (a look-alike host, a user name before the host, a query string or a port is
refused):

| Type | Allowed |
|---|---|
| Slack | `https://hooks.slack.com/services/<a>/<b>/<c>` |
| Discord | `https://discord.com/api/webhooks/<id>/<token>`. `discordapp.com` is not accepted: Discord's documentation names no host for webhooks other than `discord.com/api` [96][99], and forum reports say the old host answers 403 |
| Ntfy | Any `https://` server (a path may follow), or `http://` to this machine (`localhost`, 127.0.0.0/8, `::1`) only |
| Email | An SMTP server over implicit TLS (465) or STARTTLS (587). There is no unencrypted option |

**Secrets.** A webhook URL is the credential (anyone who has it can post to that channel), so it is kept like a remote system's key:
a file `<data>/notify/<channel id>.secret`, mode 0600 in a 0700 folder, written atomically, never in the database, a page, an
event, a log line or an error text. The same holds for an Ntfy token or password and the SMTP password. The Settings page shows a
badge ("A webhook URL is saved") and a blank password box: blank keeps the secret, a typed value replaces it. Backups carry the
files (`notify/<id>.secret`, checked by name on restore). Removing a channel deletes its file. An error from a service is cut to its
own short error word and passed through a redaction of the channel's secrets before it is stored.

**Recent hub changes** records a channel being added ("Notification channel added: Ops (Slack)", with its severities and mode), changed
(what changed, by name: "severities, webhook URL"; never the value) and removed, and "Gave up sending to <name>" (see below).

#### What each service documents

Read 2026-11-24 from each service's own documentation; mark in brackets is the source number below. Nothing was sent to any real
service: the tests use fake servers that enforce these limits.

| Service | Facts used | Where |
|---|---|---|
| Ntfy | JSON publish: POST to the server's root URL with `topic`, `message`, `title`, `tags`, `priority` (1 to 5; 5 is max or urgent), `click`, `markdown` and others. Tags that match an emoji short code become an emoji. A message is "up to 4,096 bytes" (more becomes an attachment); the title is limited to 1 KB and all tags to 512 bytes (HTTP 400 beyond). Access tokens go as `Authorization: Bearer tk_...`; user name and password as Basic auth. Default rate limit: 60 requests at once, then one every 5 seconds per visitor (`visitor-request-limit-burst`, `visitor-request-limit-replenish`) | [90][91] |
| Slack | Incoming webhook: POST JSON with `text` or `blocks`; the URL contains a secret. Errors `invalid_payload`, `no_text`, `action_prohibited`, `no_service`, `no_active_hooks`, `invalid_token`, `channel_not_found`, `channel_is_archived` (HTTP 400, 403, 404). Up to 50 blocks in a message; a section's text 1 to 3,000 characters; a header's text 150 characters (plain text); a context block 10 elements. `&`, `<` and `>` must be written as `&amp;`, `&lt;` and `&gt;`; mentions are written `<!channel>`, `<!here>`, `<!everyone>`. Incoming webhooks: "no more than one message per second per channel", short bursts allowed; HTTP 429 with a `Retry-After` header | [92][93][94][95] |
| Discord | Execute Webhook: `POST /webhooks/{id}/{token}`; at least one of `content`, `embeds`, ...; `content` up to 2,000 characters; up to 10 embeds; `allowed_mentions` controls mentions (`parse` is a list of `roles`, `users`, `everyone`; empty mentions nobody); `flags` may be `SUPPRESS_EMBEDS`, `SUPPRESS_NOTIFICATIONS`. Embed limits: title 256, description 4,096, 25 fields, field name 256, field value 1,024, footer text 2,048, author name 256, and 6,000 for all of them together across a message. `color` is an integer. Rate limits: `X-RateLimit-Limit`, `-Remaining`, `-Reset`, `-Reset-After`, `-Bucket`; a 429 carries `Retry-After` and `retry_after` (seconds, a float) and `global`; 10,000 invalid requests (401, 403, 429) in 10 minutes brings an IP block. API clients "must provide a valid User Agent" (`DiscordBot ($url, $versionNumber)`), or may be blocked | [96][97][98][99] |
| Email | `smtplib.SMTP_SSL(host, port, context=...)` for implicit TLS (default port 465) and `SMTP.starttls(context=...)` after `ehlo()`; `login()` tries the methods the server advertises; `ssl.create_default_context()` gives `CERT_REQUIRED` and, with `PROTOCOL_TLS_CLIENT`, host name checking. A message with an inline image: `make_msgid()`, `add_alternative(..., subtype='html')`, then `get_payload()[1].add_related(data, 'image', 'png', cid=...)`, with the HTML naming `cid:` and the id without its angle brackets | [100][101] |
| Gmail | `smtp.gmail.com`, port 465 (SSL) or 587 (TLS); needs the Gmail or Workspace user name and an app password; an app password needs 2-Step Verification, is 16 characters, and is not offered for accounts with only security keys, for work or school accounts the organisation restricts, or with Advanced Protection | [102][103] |
| Microsoft 365 | Client SMTP submission (SMTP AUTH): `smtp.office365.com`, port 587 (or 25), STARTTLS (TLS 1.2 or 1.3), a licensed mailbox with SMTP AUTH enabled for it (disabled by default for organisations made after January 2020); port 465 "doesn't support the required versions of TLS"; basic authentication for client submission "is scheduled for deprecation" and Microsoft recommends OAuth | [104] |

#### What each message looks like

One layout, drawn four ways (`notify/render.py`). Each finding line has the severity, the title, the host, its deadline
("due Thu 26 Nov 14:00 EST" or "overdue since ...") and a link to the finding on the hub (`<hub>/h/<host>` plus the finding's
own link). What does not fit ends with "and N more", with a link to the hub.

| Channel | Layout | Limits kept to |
|---|---|---|
| Ntfy | JSON: `title`, plain-text `message`, `priority` and `tags` from the worst severity (critical 5 and `rotating_light`, high 4, medium 3, low 2, info 1; a digest or a test is 3), `click` is the finding's link when the message has one finding, else the hub. No `markdown` flag, so text is shown as text | message under 3,700 of the 4,096 bytes; title 250 characters |
| Slack | A header, the summary and counts, one section block per chunk of up to 2,800 characters (`*Critical* <link\|title> · host · due ...`), "and N more", then a context block with the footer. Also a top-level `text` (what a notification shows) | at most 50 blocks, 3,000 characters a section, 150 in the header |
| Discord | One embed: title, description (a `__section__` heading and `**Critical** [title](link) · host · due ...` lines), counts as inline fields for a digest, a footer, a timestamp, and a colour by severity (critical red, high orange, medium amber, low blue, only resolutions green, test teal); `allowed_mentions` with an empty `parse` | description under 3,800 of 4,096; all embed text under 6,000, checked before sending |
| Email | `multipart/alternative`: plain text, then `multipart/related` with the HTML and the logo (`Content-ID`, `Content-Disposition: inline`). Tables, inline styles, no scripts, no remote images. Subject: the headline. `Auto-Submitted: auto-generated` | up to 100 findings a section, then "and N more" |

**Neutralising.** A finding's text can hold anything a package name, a server's own message or a hostile host puts there. So:
Ntfy gets plain text; Slack gets `&`, `<` and `>` as entities (so `<!channel>`, `<@U123>` and a pasted `<url|text>` can't form) and a
zero-width space after `*`, `_`, `~`, a backquote and `@`; Discord gets a backslash before Markdown characters and `<`, a
zero-width space after `@`, and `allowed_mentions: {"parse": []}`, which is Discord's own switch for mentioning nobody; email
passes every value through `html.escape`, and a link is only ever the hub's own address (a finding's link must start with one
slash, anything else is dropped). Control characters and line breaks become spaces in every title and header, so a finding can't
add an email header. The tests feed each renderer `<!channel> @everyone <@U123> <https://evil.example|click> *bold* [a](https://evil.example)`.

### Alerts (built)

Which finding changes make a message, per channel (`notify/engine.py`):

- **Opens** at a selected severity.
- **Gets worse**: its severity rises into a selected one, or rises past what the channel was already told. A finding announced at
  High that dips to Medium (not selected) and returns to High is not announced again; going on to Critical is.
- **Resolves**, if the channel wants it (and the channel had been told about it).
- **A deadline** (CISA BOD 26-04; see "Prioritisation"): once when it is about to pass, 1 day before for 14 and 60 day items and 12 hours
  before for 3 day items; and once when it has passed. A finding found already past its deadline gets only the second. Findings
  with no deadline ("fix on system upgrade") have none.

The clock runs from the finding's `first_seen`, when DaemonSight first saw it. BOD 26-04's own clocks start from other events (for
example when a CVE joins the KEV list), which DaemonSight does not track, so this is a stated simplification. The finding's
`deadline_days` (schema 12; set by `cve.package`, `docker.image_cves` and `opnsense.updates` from the worst CVE's rating) carries the
timeline; a raised severity can shorten it, and the clock does not restart.

**Accepted findings never alert**: not on opening, not for their deadline, not on resolving. A finding accepted before it was announced
is announced when the acceptance is revoked, or when it changes and so comes back (see "Accepting a finding").

**A new channel does not announce what the hub already knew**: findings first seen at or before the channel was created are noted
silently, including their deadlines that had already passed. Only what happens afterwards makes a message. It still reports one of
them resolving, if it wants resolved alerts.

**Durable state (the outbox).** Three tables in the hub's database (schema 12): `notify_channels`, `notify_seen` (what each channel has
been told about each open finding: its last severity, the worst severity announced, whether it was accepted, whether the deadline
reminders were sent) and `notify_events` (one row per change per channel, with its state `pending`, `sent`, `gave_up` or `none`,
the attempts and the next try). A unique index on (channel, finding, kind, severity, first seen) means the same change can't be
queued twice, even if `notify_seen` is lost; a finding that resolves and opens again has a new `first_seen` and is a new finding. A
pass runs every 20 seconds and finds changes by comparing, not by hooking into where findings are written, so a change made by the
poll loops, the CVE chore, an upload or the hub's own rules is seen the same way, and one that happened while the hub was down is
sent after it starts.

**Grouping.** Rows are sent when they are 15 seconds old, so what one poll found goes out together: ONE message per channel, however
many findings, sections in the order Past deadline, Deadline soon, New, Worse, Resolved, each worst severity first. The headline counts
them ("DaemonSight: 3 new, 1 worse").

**Failures.** A failed send keeps its rows pending and tries again after 30 s, 1 min, 2, 5, 10, 20, 30 min, then every hour; after a 429, at
least as long as the service asked (`Retry-After`, or Discord's `retry_after`). New changes join the retry. After 24 hours without a
success the rows are given up: the channel row records the time and the count, the Settings page shows "Gave up on N messages", an event
"Gave up sending to <name>" is written, and no more tries are made. A refusal that will not change (HTTP 400, 401, 403, 404, 410,
413, a refused login or recipients, an untrusted certificate) is given up after 5 tries. The channel's last error is shown with its
age, and cleared by the next success (including a test). Slack sends are at least 1.1 s apart per channel; a Discord bucket that is
used up is waited out (`X-RateLimit-Remaining` 0, `X-RateLimit-Reset-After`). No redirect is followed, a response is read to at most
64 KB, and a request times out after 20 s.

**Send test** posts a one-line test message with the form as typed (a newly typed secret, else the saved one) and saves nothing. It
shows the outcome in an alert box on the page.

### Digests (built)

A digest lists what **opened**, **got worse** or **resolved** since the channel's last digest, the **current open count by severity**
(for the severities the channel receives) and anything **overdue** (past its deadline, as of the digest). A finding that opened and
resolved between two digests is not reported. It is sent on schedule even when nothing changed, as "No changes; N open (critical,
high)", unless the channel has "Skip empty digests" on, which is the default. "Empty" means no changes and nothing overdue: an overdue
finding is worth a message. The window and the changes are recorded when the digest is queued and read when it is sent, so a digest
that fails and is retried still carries them, and a digest given up leaves its changes for the next one. With "both", a change goes out at
once and is also in the next digest.

**Schedule.** Daily, weekly (a weekday) or monthly (day 1 to 28, so every month has one) at HH:MM in **the hub's time zone**, which it
reads from the `TZ` environment variable (the container image and Unraid's template set it), else `/etc/timezone`, else the zone
`/etc/localtime` points to, else UTC. The zone is shown on the Settings page. A wall-clock time is kept across clock changes: 08:00 is 08:00
before and after, so the gap is 23 or 25 hours that day; a time that does not exist (02:30 when the clocks go forward) runs an hour later,
at 03:30; one that happens twice (01:30 when they go back) runs at the first. The tests cover America/New_York in 2026 (forward 8 March, back
1 November). The IANA database comes from the system, or from the `tzdata` package, which is a dependency for images that have none.
After a digest the next time is computed from now, so a hub that was off sends one digest, not a backlog.

### Scheduled reports (planned, part 2)

A fuller document on its own schedule: daily, weekly, monthly, quarterly or annual. Two kinds, chosen per schedule, for different
readers:

- **Executive summary:** plain language, no commands. Risk at a glance (open findings by
  severity, overdue against the BOD 26-04 deadlines, the trend since the last report), what
  improved, what needs a decision, and how fast fixes happened against their deadlines over
  the period (monthly and longer).
- **Remediation plan:** for administrators. Work grouped by deadline (overdue, 3 days,
  14 days, 60 days, at the next upgrade), then by system. Each item has the fix command and
  why it is ranked there (exposed, known exploited, automatable, impact). Plus new exposure,
  end-of-life systems, and accepted items that changed.

The scope is the whole hub or a chosen set of hosts, so one hub can report separately on
different groups of systems. Reports are kept on the hub as pages under a Reports archive.
Email carries the report, with a PDF attached; the other channels send the summary and a link.
How the PDF is made (a library inside the hub image, or Chromium) is to be researched for image
size and security before building. They will reuse the channels, schedules and history built here.

**Identification.** Every report, digest and email footer names the product, its version and
its logo ("DaemonSight 0.x.y"), with the hub's address, so any reader knows where it came from.
The organisation's own name can head the report; the DaemonSight footer stays.

**What was not verified** (alert channels). No message was sent to a real Ntfy, Slack or Discord service, or a real mail server: the
payloads were checked against each service's documentation and a fake that enforces its limits, and SMTP against a fake server over real
TLS sockets with a throwaway certificate.

- Ntfy: the topic's allowed characters (letters, digits, `-` and `_`, 64) are from Ntfy's behaviour as commonly described, not from the pages read; the
  emoji short codes used as tags (`rotating_light`, `warning`, `large_orange_diamond`, `information_source`, `white_check_mark`, `bell`, `clipboard`)
  were not checked against Ntfy's emoji list (an unknown one is shown as plain text under the notification).
- Slack: the incoming-webhook page does not give a message-text length limit or a rate limit (the rate limit is from the Web API's page, which
  names incoming webhooks); whether `*`, `_` and the like inside a link's label would format is not documented, so the zero-width space is a
  precaution, not a tested fix; that every webhook URL has the form `/services/<a>/<b>/<c>` is from the page's example.
- Discord: the webhook page does not name the host (`discord.com/api` is the API's base URL [99], and Discord's support article on webhooks
  could not be fetched, HTTP 403); the colour is an integer per the embed object, and that Discord counts the characters as the limits say was not
  tried.
- Email: Gmail's two pages disagree (an app password is described, and the same page says Google Workspace accounts no longer support less secure
  apps, "devices that ask for a username and password"): whether a given account may use an app password for SMTP could not be confirmed.
  Microsoft says client submission with basic authentication is scheduled for deprecation and recommends OAuth, which DaemonSight does not
  support (the login is PLAIN, LOGIN or CRAM-MD5, whatever the server advertises); the retirement date was not read. A relay by IP address (no
  login) works with an empty user name.

## Install and deploy

- `install.sh` for v1: creates a venv in `/opt/daemonsight`, the `daemonsight` user, the units (including the update path unit) and `/etc/daemonsight/config.toml`, and records its options in `/etc/daemonsight/install.options`. A `.deb` comes later.
- `daemonsight-update` (in `/usr/local/sbin`) updates from GitHub into a root-owned clone and reruns `install.sh` with the recorded options. After installing it waits 20 seconds and goes back to the previous commit if the collector isn't running. Installing only from GitHub, never a user's checkout, is what makes a password-less sudo rule for it reasonable on a development server. See [INSTALL.md](INSTALL.md#update).
- `install.sh` needs `python3` 3.11 or newer with its `venv` module (Fedora's `python3` includes it) and `git`, which `daemonsight-update` uses. `fail2ban` and `nftables` are optional: each source reports itself unavailable without its tool. Nothing else is installed: no `debsecan` and no Trivy (see "Data sources").
- Testing order: a test LXC first (updated with `sudo daemonsight-update` after each push), then a second test host, then the production VPS.
- VPS: the web process on `127.0.0.1:8466`, reached over WireGuard, or through Caddy with the hostname restricted to the WireGuard range.
- LXC: the kernel belongs to the Unraid host, so kernel CVEs are skipped when `systemd-detect-virt` reports a container. An unprivileged LXC may not be able to read the nftables ruleset; that source then shows "unavailable" instead of failing.

## Phases

1. Skeleton: config, SQLite, collector loop, system/systemd/ports/Docker sources, Overview and Services pages, login. Done.
2. Caddy, fail2ban, nftables sources. Exposure, Routes and fail2ban pages. The `expose`, `route` and `jail` rules. Done.
   2b. Remote sources: the Unraid API (array, disks, containers, VMs, notifications, UPS), done, and the OPNsense API (firewall rules and port forwards, Caddy, gateways, WireGuard, Tailscale, firmware), done. Each shows as its own host. See "Remote sources".
   2c. The hub: collectors upload to one install that shows every host, with the container image and Unraid template, retention and backups, and updates from the hub. See "Hub". Done.
3. Package and CVE checks.
   3a. Pending updates, reboots, services on old libraries: the `packages` source, `pkg` rules and Packages page. Done for apt and, since Fedora support, for dnf5 too.
   3b. CVE matching on the hub: collectors send installed packages (source name and version) and the release; the hub matches them against the Debian security tracker, rates each CVE with CISA BOD 26-04's table (see "Prioritisation"), and raises one finding per package. Vulnerabilities page, `cve.*` rules, and Fedora's pending advisories. No scanner binary on the hosts. Done for Debian, Raspberry Pi OS and Ubuntu (see "CVE matching" and "CVE matching: Ubuntu"). See also the automatic-updates advice in 3a (`pkg.auto_updates_off`).
   3c. CVEs in container images: the package list read from each running Debian- or Ubuntu-based container through the Docker API, matched the same way; Alpine through its security database. Trivy may come later, opt-in and pinned, for other bases. Parts 1 to 3 are done: the reader reads each running image's package list, the Container images page shows each image's base OS and support status (`docker.eol_base`), Debian images are matched against the Debian tracker, Alpine images against Alpine's security database and Ubuntu images against Canonical's OVAL data (`docker.image_cves`). See "Docker reader", "Container images", "CVE matching: Alpine images" and "CVE matching: Ubuntu".
4. Alerts (Ntfy, Slack, Discord, email) and digests: done. Then scheduled reports, then history charts with drill-down. See "Alerts, digests and reports (phase 4)" and "History charts and drill-down (planned)".
5. `.deb` package and docs.

Planned after phase 3, in this order: log collection and auditing, then a
Windows agent. Traffic maps can come any time after phase 3. See "Log
collection and auditing (planned)", "Windows agent (planned)" and "Maps
(planned)".

Later: actions (ban, unban, restart, and CrowdSec decisions;
read-only CrowdSec ban findings have shipped), Podman, and an optional check from outside the host to confirm what's
reachable from the internet.

See "Hub" for the central view.

### Planned sources (staged)

Each source below is read over its own API with a dedicated least-privilege key, GET only, through the same
client, certificate pin and finding pipeline as OPNsense and Unraid. The detail for each is in its subsection.

#### Updates and CVEs on every source

Per the core rule in "Goal", these gaps are on the roadmap:

- **OPNsense:** done for releases: the CVEs a pending release or hotfix fixes
  come from the project's own changelog (see "OPNsense updates and CVEs"). Still
  open: package updates outside a release. The advisories the changelog names
  without a CVE id are resolved to CVE ids (see "Security advisories in the
  changelog"). FreeBSD's VuXML (the data behind `pkg audit`) is the next source
  for package updates; not researched.
- **Unraid:** OS updates are shown with no CVE data. Research whether Unraid
  publishes security notes per release that can be matched.
- **Proxmox VE and PBS:** they run on Debian, so a collector on the node gives
  pending updates and Debian CVEs with no wider API role. Proxmox's own
  packages (`pve-*`, `proxmox-*`) aren't in Debian's tracker; research whether
  Proxmox publishes advisories for them before building.
- **UniFi:** done as far as it can be: Ubiquiti publishes no machine-readable
  advisory data, so the card says so and links the release notes (see "UniFi
  Network").
- **FortiGate, Meraki, Aruba, XCP-ng:** each design lists where its
  firmware or patch advisories come from, or says none exist.

#### Built

**UniFi Network** is built; see "UniFi Network" under "Remote sources".

#### Staged, built when someone needs it

**Proxmox VE, with Proxmox Backup Server and the community Helper-Scripts.** Reads the PVE API with an API token
under the built-in PVEAuditor role and the PBS API with the built-in Audit role. Findings: no recent backup for a guest, a failed backup, a
datastore nearly full, a failed verify or garbage-collection job, a certificate expiring, an enterprise
repository without a subscription, the firewall off at datacenter level, Ceph not healthy, HA problems.
Pending updates and their CVEs come from a collector on each node (see "Updates and CVEs on every source"),
so the API token never needs Sys.Modify. Guests tagged `community-script` by the Helper-Scripts project are listed with a plain note
on how their `update` command works. See [Proxmox VE](planned-sources.md#proxmox-ve), [Proxmox Helper-Scripts](planned-sources.md#proxmox-helper-scripts-community-overlay) and [Proxmox Backup Server](planned-sources.md#proxmox-backup-server).

**Proxmox Mail Gateway and Datacenter Manager (only if worthwhile).** PMG has no confirmed API token, so it would
need a password login; deferred. PDM mostly repeats what PVE and PBS give directly; not planned. See
[Proxmox Mail Gateway](planned-sources.md#proxmox-mail-gateway-brief-recommend-later) and [Proxmox Datacenter Manager](planned-sources.md#proxmox-datacenter-manager-recommend-not-supporting).

**XCP-ng.** Read through the Xen Orchestra REST API with a token for a user whose RBAC role holds read actions
only (XAPI's own read-only role needs Active Directory, so reading XAPI directly would need the root
password). Findings: patches waiting, a storage repository nearly full, a running VM with no backup job, a failed
backup, an old snapshot. See [XCP-ng](planned-sources.md#xcp-ng).

**FortiGate.** Reads the FortiOS REST API with a REST API administrator on a read-only access profile and
trusted hosts. Findings: firmware update, expiring FortiGuard licences, any-to-any policies, internet-facing
virtual IPs, management reachable from the WAN. See [FortiGate](planned-sources.md#fortigate-fortinet).

**Meraki.** Reads the Dashboard API with the key of a read-only organization administrator, paced to the
10 calls per second limit. Findings: licence expiry, device offline, firmware behind, open Wi-Fi, port forwards.
See [Meraki](planned-sources.md#meraki-cisco).

**Aruba.** Aruba Central first, with a read-scope token from a View Only user. Token refresh is a POST to the
OAuth endpoint, so it needs one documented exception to GET only. Findings: access point or switch offline,
firmware behind, open Wi-Fi, licence expiry. See [Aruba](planned-sources.md#aruba-hpe-aruba-networking).

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

### Managing hosts in the web UI

`web/host_routes.py` (hub only) adds, updates, re-keys, revokes and removes
collector hosts. It calls the functions behind the CLI (`hub.add_host`,
`request_update`, `cancel_update`, `revoke_host`) and adds `hub.replace_token`,
`hub.data_counts` and `hub.forget_cves`; it keeps no logic of its own.

- **Pages.** The Hosts table's last column, Manage, links every row: an API
  system to `/remotes/<id>/edit`, a collector host to `/hosts/<id>/manage`
  (`/hosts/new` adds one). Replace token, Revoke and Remove each have a
  confirmation page at `/hosts/<id>/manage/<token|revoke|remove>`; Remove
  lists what it deletes and needs the host's name typed.
- **Actions.** All are POSTs behind the login, and refuse cross-site requests
  with the same `Sec-Fetch-Site` check as `/hosts/update`. They apply only to
  hosts uploaded for (`kind IS NULL`); an API system has its own pages.
- **Replace token** overwrites `token_hash` and keeps the row, so history and
  settings stay and the old token fails at once. The CLI has no single
  command for this (it is `hub revoke` then `hub add-host`).
- **Remove** is `revoke_host(purge=True)`: the host's rows in snapshots,
  metrics, findings, events and accepted (`hub.PURGE_TABLES`), its row in
  hosts, and its CVE matches in `cve.db` (`match` and `matched`), which the
  CLI's `--purge` now clears too. It is one transaction in the hub database.
- **Revoked hosts.** A revoked host's row is deleted, so it is not listed and
  there is no "Allow again" button. Adding the same name again issues a new
  token, and the kept history shows under it. That is the CLI's behaviour too.
- **Tokens.** Shown once, in the response to the POST that made them (no
  redirect, flash or database copy), with `Cache-Control: no-store`, and never
  logged. The install command's URL comes from the request (`base_url`, which
  follows the proxy headers the web server trusts).
- **Events.** Each action adds an event with an empty host, shown under Recent
  hub changes, and so do adding and removing an API system.

### Updates from the hub

The hub can ask a host to update to the hub's own commit. With "Uninstall from
the hub" below, it is one of the two things the hub can make a host do. The
pieces:

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

### Uninstall from the hub

Remove from hub can first uninstall the collector on the host, the way an RMM
tool removes its agent. The pieces:

- **Request.** Remove from hub on a reporting host has the box "Uninstall the
  collector first", ticked. With it ticked, the hub does not revoke. It sets
  `hosts.uninstall_state = 'pending'` (and `uninstall_asked`) on the host's row,
  so a restart of the hub keeps it, and records "Uninstall requested". The
  host's page says "Waiting for NAME to check in" with the host's upload
  interval, which the collector sends as the top-level upload field
  `upload_interval` (top-level so an older hub, which ignores unknown
  top-level fields, still takes the upload; `settings` is strict and must not
  gain fields). `daemonsight hub uninstall NAME [--cancel]` does the same.
- **Reply.** Only while a host is `pending`, the reply to its authenticated
  upload carries `uninstall: true`, next to `last_seq`.
- **Collector.** `Uploader._hub_uninstall` (`collector/upload.py`) acts only on
  a 2xx reply to an upload sent with the host's token to `[upload] url`
  (checked as for every upload: HTTPS, or this machine; certificates verified;
  redirects not followed), whose `last_seq` is the number it sent and whose
  `uninstall` is the boolean `true`. A 401, 403, 404, TLS error or unreachable
  hub raises before any reply is read. It then checks
  `[collector] allow_remote_uninstall` (default true, set only in the host's
  own config) and that `daemonsight-uninstall.path` is installed. If either
  fails it sends `uninstall: "refused"` with a fixed `uninstall_detail`
  phrase in its next upload, until the hub stops asking.
  Otherwise it logs a warning to the journal, sends a final upload with
  `uninstall: "started"`, and then writes `uninstall.request`
  (`collector/remote_uninstall.py`; 0600) in the data folder. If the final
  upload can't be sent, the uninstall goes ahead anyway; the hub keeps showing
  "Waiting" and the admin can Remove anyway. If the request can't be
  written it answers `uninstall: "failed"`.
- **Path and service.** `daemonsight-uninstall.path` starts
  `daemonsight-uninstall.service` when the request exists. It runs
  `daemonsight uninstall --hub-request` as root, unsandboxed, the same hand-off
  as updates, because the collector's sandbox (read-only `/etc`) can't remove
  its own units and removing itself would cut off the final upload. With
  `--hub-request` the command does nothing without the request file, and
  re-reads `allow_remote_uninstall` from the host's config.
- **`daemonsight uninstall`** (`uninstall.py`, standard library only, because
  it deletes the package it runs from). Without `--yes` it lists and changes
  nothing. With it: stop and disable the collector, web and path units (never
  the oneshot services, one of which is itself), delete the units, the two
  commands in `/usr/local`, the fail2ban jail and filter, the sudoers rule,
  `daemon-reload`, remove the `daemonsight` user when its home is the data
  folder and its shell is `nologin` (the account `install.sh` makes), then
  delete `/opt/daemonsight`, `/etc/daemonsight` and `/var/lib/daemonsight`.
  The list is `install.sh`'s, plus the two optional files INSTALL.md names;
  `tests/test_uninstall.py` compares it with `install.sh`. It is idempotent.
- **Hub side.** `hub.handle_uninstall_ack` runs after an upload is stored. For
  a host that is `pending`: `started` revokes and purges it (one transaction,
  as Remove does) and records "Host uninstalled and removed"; `refused` or
  `failed` stops the asking, keeps the host, and shows the reason with Cancel
  uninstall and Remove anyway. For any other host the answer is ignored.
  Remove anyway revokes and purges at once, records it, and the next page
  links the manual steps in INSTALL.
- **A refused token.** On 401 or 403 the uploader raises `TokenRejected`,
  stores `upload.rejected_at` and `upload.rejected_status` in the collector's
  `meta` table, and retries once an hour (`REJECTED_RETRY`) instead of backing
  off to five minutes. `daemonsight status` and every page of the host's own
  web UI show "the hub rejected this host's upload token". The marks clear on
  the next accepted upload.

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
outbound HTTPS to `security-tracker.debian.org`, `epss.empiricalsecurity.com`,
`www.cisa.gov` and `cveawg.mitre.org`, plus `secdb.alpinelinux.org` for Alpine images and `codeload.github.com` for an OPNsense firewall with a release
update pending; it works without them, with `cve.feed_stale` after 3 days. The remote sources (OPNsense, Unraid)
run in the hub, since they are API calls from the LAN.

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
          Debian tracker · Ubuntu OVAL · EPSS · CISA KEV ──┘  (HTTPS, 24 h, conditional)
                          CVE Services (CISA's SSVC rating, a CVE at a time) ──┘
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
good data stays in use. Nothing here runs in a request. Alpine's security database is the exception to "three feeds": its files are
fetched only for the Alpine releases the hub's container images run (see "CVE matching: Alpine images"). So is the OPNsense project's
changelog, one tarball fetched while an enabled OPNsense system exists (see "OPNsense updates and CVEs"); the advisories it names are
then asked for one by one, once each, from `www.freebsd.org` and `api.github.com` (see "Security advisories in the changelog"). Canonical's Ubuntu OVAL files are
fetched only for the Ubuntu releases the hub's hosts and images run (see "CVE matching: Ubuntu").

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
| `open` or `resolved` with `nodsa` (minor issue, ignored, postponed), or urgency `end-of-life` | **Won't fix or minor**: listed, never a finding |
| urgency `unimportant` | The state above (fix available or no fix yet), and the vendor rule of "Prioritisation" can lower its urgency to Low |
| `undetermined` | **Being assessed**: listed, never a finding |

Raspberry Pi OS (`raspbian`) is looked up as Debian by its codename, as
`distro.py` does. Ubuntu has its own matcher (see "CVE matching: Ubuntu"); other
derivatives (Linux Mint, Pop!_OS) aren't matched, and the page says so.

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

- Its severity and deadline are those of the worst CVE the package has that an update fixes (or, on a host, a KEV CVE that has no
  fix yet), by CISA BOD 26-04's Table 1: "Prioritisation (CISA BOD 26-04)" below. The title says the deadline ("brotli:
  CVE-2026-111497 is being exploited (CISA KEV); fix within 14 days"), the detail starts with it, and the "What to do" panel names
  the four inputs of the worst CVE.
- Otherwise none. An unfixed CVE that isn't on KEV, and any "won't fix or minor" one, shows only on the page. A KEV CVE that Debian
  calls minor is flagged on the page, and counts as a KEV CVE for the table.

**How it reads next to `pkg.security_updates`.** That rule says what apt will
install (names from `apt-get -s dist-upgrade`) and that it matters; this one
says why, by CVE. Each `cve.package` detail checks the host's own packages
snapshot: "apt lists this update on the Packages page", or "apt isn't offering
it yet: run sudo apt update, and check the host's apt sources include the
security archive", which is the case that `pkg.security_updates` can't see.
Both give `sudo apt upgrade` as the fix.

### Prioritisation (CISA BOD 26-04)

Every update and CVE finding takes its severity from one model, `cve/priority.py`, so that a host package, a container image and
an OPNsense update with the same CVE are rated the same way. The model is CISA's Binding Operational Directive 26-04,
"Prioritizing Security Updates Based on Risk", of June 10, 2026 [83][84]. It binds federal agencies only. DaemonSight borrows its
timelines as a published, risk-based default that an administrator can read and check, and adds nothing of its own to the table.

**Why this and not CVSS.** The directive's implementation guidance says that "CVSS scores such as 'critical' or 'high' do not
prescribe specific actions" [84], and FIRST's CVSS v4.0 user guide says the base score "should not be used alone to assess risk"
[89]. The table asks four questions about one CVE on one system, and answers with a number of days. The old rule (KEV, or an EPSS score of 0.10 and above, is High;
any fix is Medium) was a local guess. CVSS is kept as information only: the record's CVSS is shown, with its source, and decides
nothing.

**The four inputs.**

| Input | Where it comes from |
|---|---|
| Publicly exposed | Per system, see "Exposure per system" below. |
| In the KEV catalog | CISA's catalog, the `kev` table loaded from the feed. |
| Automatable by an adversary | The "Automatable" decision point of CISA's SSVC rating, in the CVE record's "CISA-ADP" container (`cve/records.py`) [86][87]. Where CISA has not rated the CVE: estimated, see "When CISA has not rated a CVE". |
| Technical impact | SSVC's "Technical Impact", total or partial, from the same container. Estimated as partial where CISA has not rated the CVE. |

**Table 1.** Written out from the directive's table image [85] and kept as data (see "The table is a data file"). Days are calendar
days; the severity is the one DaemonSight gives the timeline.

| Row | Exposed | KEV | Automatable | Impact | Timeline | Severity |
|---|---|---|---|---|---|---|
| 1 | yes | yes | yes | total | 3 days and forensic triage | Critical |
| 2 | yes | yes | yes | partial | 3 days | Critical |
| 3 | yes | yes | no | total | 3 days and forensic triage | Critical |
| 4 | yes | yes | no | partial | 14 days | High |
| 5 | yes | no | yes | total | 3 days | Critical |
| 6 | yes | no | yes | partial | 14 days | High |
| 7 | yes | no | no | total | 14 days | High |
| 8 | yes | no | no | partial | 60 days | Medium |
| 9 | no | yes | yes | total | 3 days and forensic triage | Critical |
| 10 | no | yes | yes | partial | 14 days | High |
| 11 | no | yes | no | total | 14 days | High |
| 12 | no | yes | no | partial | 14 days | High |
| 13 | no | no | yes | total | 60 days | Medium |
| 14 | no | no | yes | partial | 60 days | Medium |
| 15 | no | no | no | total | fix on system upgrade | Low |
| 16 | no | no | no | partial | fix on system upgrade | Low |

The rows with forensic triage (1, 3 and 9) put the five triage steps of the directive in the finding's "What to do" panel: scope,
preserve evidence, contain, analyse, decide. The severity follows the timeline and not the triage.

**One finding takes the worst CVE it fixes.** A package, an image or a firewall update fixes several CVEs; each is rated, and the
finding's severity, deadline and wording are those of the most urgent one: the shortest deadline, forensic triage before none, then
the higher EPSS probability, then a KEV CVE, the table row, a fix over none and the CVE id. The old KEV and EPSS rules are gone.

**When CISA has not rated a CVE.** CISA rates "new and recent CVEs" [87], so many older ones, and every CVE whose record has no
CISA-ADP container, have no Automatable and Technical Impact. Then:

- Automatable is "yes" when the CVE's EPSS probability is at least `[cve] epss_automatable` (default 0.04, a Settings field),
  otherwise "no". FIRST says to use the probability and the percentile together, that a threshold is "a very localized effort",
  and that about the 90th percentile, at the time a probability of roughly 0.04, matches the effort of patching every CVSS Critical
  [88]. The default is that number. This is an estimate and it says so.
- Technical Impact is "partial".
- Every estimated value is labelled "estimated by DaemonSight" in the finding's "What to do" panel and on the page. A CVE with no
  EPSS score at all counts as not automatable.

**The vendor rule.** Debian's urgency `unimportant` and Ubuntu's priority `negligible` are the distribution's own statement that
the issue is not worth a security update by itself. Such a CVE is rated Low ("fix on system upgrade") only when the system is not
exposed and the CVE is not in the KEV catalog. An exposed system, or a KEV CVE, follows the table whatever the vendor says; the
page says when the rule lowered a CVE. `end-of-life` and `nodsa` keep their old meaning ("won't fix or minor": listed, never a
finding).

**The interim rule for advisories (outside the table).** An OPNsense security advisory that names no CVE, whether not asked about
yet, failed or naming none, cannot be put in the table. Until CISA's table covers such a case, an unresolved advisory makes an
OPNsense update at least Medium, and High when GitHub rates it High or Critical (unchanged from before), and a CVE that ranks higher
is never lowered by it. The finding's text says this rule is not CISA's.

**Exposure per system** (`cve/exposure.py`). The deciding evidence is recorded and shown beside the first input.

| System | Exposed when |
|---|---|
| A collector host | The same data as the Exposure page: a listener the host firewall lets through on a public address, or a port the hub sees forwarded to the host by an OPNsense port forward or Caddy site. A public address with no such listener is not exposed. A host with no exposure data counts as exposed when an address the hub knows is publicly routable. |
| An OPNsense firewall | Always: it is the network's edge (the directive's network-device case [84]). |
| A container image | A running container of the image publishes a port on all addresses (or the host's address) that an OPNsense port forward or Caddy site leads to on the Unraid host, matched by the Unraid system's address. With no firewall read, the Unraid system's address decides: exposed only when publicly routable. An image no container runs, or whose containers publish no port, is not exposed. |
| Unknown | Exposed only when the address is publicly routable (IPv4 or IPv6; private, CGNAT, link-local and ULA are not). |

Whether a port forward leads to a container is decided by the port and the Unraid host's address, not by the container: a forward
to the Unraid host's port 8080 and a container that publishes 8080 are linked. A forward that goes to the host and a container
that publishes nothing are not. That link is a conservative inference and the page's evidence line says which forward it used.

A Caddy site counts only when nothing keeps the internet out at the network level. A site, handler or global access list
whose allowed ranges are all not globally routable (RFC 1918, Tailscale's 100.64.0.0/10, loopback, ULA) makes the site
LAN-only, so it is not exposure (`opnsense_rules._lan_only`). An inverted list, an unknown list name or a list that allows any
public address is not trusted to do that. Basic auth and forward auth don't count: the site is still reachable, just behind a
password. Found live on 2026-11-24, when six images behind the "LAN Only" list were rated Critical.

**CVE Services** (`cve/records.py`). The hub asks `GET https://cveawg.mitre.org/api/cve/<CVE-ID>` for each CVE it has matched, one
at a time, and keeps the result in `cve_record` (`cve.db`, schema 6): the SSVC values, the CVSS (the CNA's first, else CISA's, newest version first) with its
source and the time read. No key is needed (the OpenAPI document calls the operation "accessible to all users") [86]. A kept record
is asked for again after 7 days while the CVE is still matched, and at once when its KEV status has changed since. A CVE the service
does not know (404) is asked again after a day; a failure after an hour. The pass is spread: at most 100 requests and 20 seconds a pass, the
KEV and high-EPSS CVEs first. The `RateLimit-*` headers (the service's policy was `25000;w=60`) and a 429 or 5xx stop the pass until
the time the service named. HTTPS only, the answer must come from `cveawg.mitre.org`, no redirect is followed, a body over 1 MB is
refused, and only a few short fields are kept. The request carries the generic User-Agent `DaemonSight/<version>` and nothing else.
A hub whose `cve.db` predates the table reads without it (every CVE is "not rated by CISA") until the chore migrates it.

**Accepted findings stay accepted.** The basis of a finding is the package or image and its CVE ids, never its severity, deadline or
rating, so a change of exposure, of CISA's rating or of KEV status changes the severity of an accepted finding and leaves it accepted. A new CVE in the package brings it back.

**What the pages show.** Every finding says its deadline: "Fix within 3 days (CISA BOD 26-04 timeline)" or "Fix at the next
upgrade". The (i) panel of a finding and of each card explains the four inputs for the worst CVE, with the evidence and the
estimate marks. The CVE tables on the Vulnerabilities, Container images and OPNsense cards have a "Fix within" column and show EPSS
as the probability with its percentile, "15.3% (92nd)", as FIRST recommends [88]. Rows sort by the table's urgency, then EPSS. The directive's name is
read from the table file.

#### The table is a data file

The table is data, not code, so a successor to BOD 26-04 can be picked up by replacing a file, without a release. The bundled file
is `src/daemonsight/data/priority/bod-26-04.json`, shipped in the package. `priority.load` reads it, or
`<data_dir>/priority/override.json` when that file exists and is valid. Only the hub reads either. An invalid override is refused as a whole, the reason
is logged once ("Ignoring ... Using the bundled bod-26-04.json table"), and the bundled table is used. The override is re-read when its
modification time changes. Nothing in the file is executed, expanded or used as a template: it is parsed as JSON, checked and read as
plain values. A file over 64 KB is refused.

The format, checked strictly (exact keys at every level, no extras):

| Key | Content |
|---|---|
| `version` | A whole number. |
| `directive` | `name` ("CISA BOD 26-04", used in every finding's wording), `title`, `table_name` ("Table 1"), `url`, `guidance_url`, `table_url` (https addresses) and `date` (YYYY-MM-DD); optionally `table_sha256` (the SHA-256 of the image at `table_url`, 64 lowercase hex digits, which the watcher compares). |
| `inputs` | The four inputs and their allowed values: `exposed`, `kev` and `automatable` are `yes` or `no`, `impact` is `total` or `partial`. Fixed: the program decides the inputs, the file only the answers. |
| `rows` | Exactly 16 rows, one for each combination of the inputs, each with `row` (1 to 16), the four inputs, `timeline` (the directive's words), `days` (a whole number, or null for "fix on system upgrade") and `triage` (true or false). |
| `severity` | Maps each timeline the rows use to a severity: a day count as a string, or `upgrade` for null, to `critical`, `high`, `medium` or `low`. It must list exactly the timelines the rows use. |
| `triage_steps` | One to ten short texts, shown for the rows with `triage` true. |

A file that is missing a row, repeats a combination, names an unknown severity, has a key that is not listed, or has a value of the wrong
type, is refused. The tests cover each of these and that an override is preferred over the bundled file.

#### When the directive changes

CISA publishes the table only as an image, so turning a new directive into a table needs a person. DaemonSight automates noticing
the change and spreading the result, not reading the image.

**Detection (the watcher).** `.github/workflows/directive-watch.yml` runs `scripts/check_directive.py` monthly (the 3rd, 06:17 UTC) and on demand. Monthly is plenty: CISA has issued 15 BODs
since 2015, and the prioritisation directive was replaced in June 2026 after BOD 22-01 had stood since late 2021 (CISA's
directives list, https://www.cisa.gov/news-events/directives/all, read 2026-11-24). Standard runners are free for public
repositories (GitHub Docs, "About billing for GitHub Actions"). GitHub disables scheduled workflows in a public repository
after 60 days with no repository activity (GitHub Docs, "Events that trigger workflows", `schedule`): if the repository goes
quiet, re-enable the workflow in the Actions tab or run it by hand.
It reads the active table file (`src/daemonsight/data/priority/current.json` names it) and fetches `directive.url` and
`directive.table_url` from it. It opens an issue titled "CISA directive change: review the prioritisation table", unless one is
already open, when:

- the directive's page says it was revoked or superseded. When CISA revoked BOD 22-01 its page gained the paragraph "This Directive
  has been revoked. It is superseded by BOD 26-04.", its title gained "(Revoked)" and its address gained "-revoked" (the old address
  now redirects; archived page dated June 10, 2026). The script looks at that wording in the page's title, heading and opening text,
  not at the list of other directives at the foot of the page, which names revoked ones; or
- the SHA-256 of the table image differs from `directive.table_sha256`.

A page that cannot be fetched, an image that is not an image, or a table file with no `table_sha256` fails the run instead, so it
shows in Actions. No issue is opened for that. The workflow has `issues: write` and `contents: read` only.

**The maintainer's steps.**

1. Read the new table from CISA's page and transcribe it into `src/daemonsight/data/priority/<directive>.json` in the format above, with
   a `version` higher than the one in force. Compare every row with the image.
2. Put the SHA-256 of the new image in `directive.table_sha256` (`curl -s <table_url> | sha256sum`).
3. Point `current.json` at the new file: `{"table": "<directive>.json"}`.
4. Run the tests and push to `main`. Hubs fetch the new file from there; the next release bundles it. The old table file can stay.

If the table changed but the directive did not, edit the same file, raise its `version` and update the hash.

**How hubs pick it up.** Once a week the CVE chore (`cve/priority_fetch.py`) asks `raw.githubusercontent.com` for
`.../main/src/daemonsight/data/priority/current.json` and for the file it names, each with a conditional request (ETag and
Last-Modified), over https, a redirect only to the same host, at most 256 KB each. The table goes through the same strict check as
any file (`priority.parse`) and is accepted only when its `version` is greater than the bundled table's and than the fetched one already installed. It is
written atomically to `<data_dir>/priority/override.json`, so `priority.load` uses it from the next pass; no restart and no release.
A table that fails the check, is too big or cannot be fetched changes nothing: what was in force stays, and the Data feeds card on
the Vulnerabilities page shows the reason beside the table's line (a failure is asked again after an hour). When a new table is
installed the hub logs it, adds "Prioritisation table updated to <directive name> v<version>" to Recent hub changes, and the next pass
rates every finding again. The card also shows the table in force: directive, version, where it came from (bundled, fetched or a file
placed by hand) and when.

The Settings switch "Fetch prioritisation table updates from the DaemonSight repository" (`[cve] priority_updates`, default on)
turns this off: no request is made and a fetched table is removed, leaving only the bundled one. A table an administrator put at
`override.json` is never replaced or removed by this: it keeps winning, and the card says a fetched one was not installed. A
fetched table is dropped when the bundled one has caught up with it (a release that carries the same or a newer version).

**Sources of the classification.** The directive and its guidance [83][84], the table image [85], the CVE Services API and its
terms [86], CISA's Vulnrichment (the SSVC fields in the ADP container) [87], FIRST on using EPSS and its percentiles [88] and FIRST's CVSS v4.0 user guide [89].
What was not verified: the directive's table was read from its image, not from a text version, so row 3's "forensic triage" and the
treatment of a CVE with no SSVC rating are DaemonSight's reading; the link between a container's published port and an OPNsense port
forward is an inference from the host's address and the port.

### The Vulnerabilities page

A nav item on a hub's host pages. A summary card (CVEs with a fix, on KEV, no
fix yet, minor; the release and how old the package list is), then a table
of packages, one row each, with `id` from `findings.anchor("cve", name)`: package
and its binaries, installed and fixed versions, CVE counts by state, the top
CVE (a link to `https://security-tracker.debian.org/tracker/<CVE>`) with a KEV
badge, its "Fix within" deadline, its EPSS probability with percentile and Debian urgency, and a `details` list of up to 30 CVEs
with description, state, deadline, EPSS and fix. Every cell has `data-label`, so rows
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
updates. The hub rates them like any other CVE (see "Prioritisation"); each is "fix
available" (an update is pending), and the page links the advisory on
bodhi.fedoraproject.org. **Fedora's unfixed CVEs are not available this way**,
and the page says so.

### CVE matching: Ubuntu

Ubuntu hosts (collectors) and Ubuntu-based container images are matched against Canonical's CVE OVAL files. The hub downloads
them as it does the other feeds; the host and an image's reader send only the package list they already send (a host also says
which Ubuntu Pro services are on).

**The choice** (the three sources read on 2026-11-24).

| | Ubuntu OVAL, CVE variant [71] | Ubuntu Security API [72] | OSV [73] |
|---|---|---|---|
| Shape | One `com.ubuntu.<codename>.cve.oval.xml.bz2` per release: 11.9 MB download and 284 MB of XML for noble, 8.6 MB and 191 MB for focal | JSON over HTTP, paged (`limit` and `offset`), filtered by release, package or status | One tarball, `osv-all.tar.xz`, 60.95 MB, every release and USN in it |
| Fixed version per source package and release | Yes, in each criterion's comment, with the archive pocket | Yes, per package status | Yes (ranges with a `fixed` event), fixed only |
| Needs fix, deferred, not affected | One unfixed state: "might be affected and may need fixing" (needed, needs-triage, pending, deferred and ignored all come out as this, see below). No "not affected" row: such a package is absent. | Every status (`needed`, `needs-triage`, `pending`, `deferred`, `ignored`, `not-affected`, `released`) per package and release | Fixes only; nothing for an unfixed CVE |
| Priority | `advisory/cve/@priority` (negligible to critical) | `priority` | `severity` entry of type `Ubuntu` ("high") |
| ESM (Pro) | Pocket named in the comment: `esm-infra/<release>`, `esm-apps/<release>`; the version carries `+esm` or `~esm` | Status per package and release (the pocket was not looked at) | `ecosystem_specific.availability` (seen: "No subscription required"); the Pro ecosystems were not looked at |
| Conditional GET | Yes: `ETag` and `Last-Modified`, `If-None-Match` answers 304; `x-cache-status: HIT` (cached in front) | Not published | Tarball only; any change refetches 61 MB |
| Stability | Canonical's "recommended" dataset | "Still a work in progress and subject to change. Please don't use it in production environments or automations." Seen: some queries answered HTTP 504 (the firefox, thunderbird and mysql ones), and a full pass over a release is many paged requests | Published by Canonical |
| Licence | Creative Commons Attribution-ShareAlike 4.0 (`LICENSE` in the same directory) | None stated on the page | Same `LICENSE` |

OVAL was chosen: it is the one source with fixes, the unfixed state and the priority in a file one conditional GET fetches
per release, it is Canonical's recommended dataset, and the API asks not to be used from automations. OSV has no unfixed CVEs
at all, so "no fix yet" could not be shown, and a 61 MB tarball for every release is a download for each release a hub does not
run. The cost is the size of the XML (below) and one lump of status (below).

**What the OVAL file holds** (read in the noble file, 37,611 `vulnerability` definitions, one per CVE, and the focal one).

- A definition has the CVE id (`reference[@source='CVE']`), a description that ends with Canonical's "Update Instructions" text
  (cut at that line), and `advisory/cve/@priority`.
- Its `criteria` lists one `criterion` per affected source package. The comment names the source package, the pocket and the
  status, and holds the fixed version. The test, object and state elements that follow work on binary names and are not needed:

      libxmltok source package in esm-apps/noble, is affected and has been fixed (note: '1.2-4.1ubuntu2.24.0.4.1+esm3').
      cadaver source package in noble, might be affected and may need fixing.

  The pocket is the release name for the standard archives and `esm-infra/<release>` or `esm-apps/<release>` for Ubuntu Pro's.
- A kernel is a pair per flavor: "Is kernel 'linux-aws' running?" and "'linux-aws' kernel in noble was vulnerable but has been
  fixed (note: '6.8.0-1009.9')", or the running check alone when no fix exists. One kernel CVE lists every flavor, so a release's
  kernel rows run to hundreds of thousands; the hub keeps them only for the flavors its hosts run (below).
- **One status for everything unfixed.** Canonical's generator, `oval_lib.py` in the ubuntu-cve-tracker repository [74], turns the
  tracker's `needed`, `needs-triage`, `pending`, `deferred` and `ignored` into the same internal status, and the file says "might be
  affected and may need fixing" for it. The file does not say which one it was; the API does. This was checked on one CVE of each
  status from the API against the OVAL file (`deferred`, `ignored`, `needed`, `needs-triage` and a `pending` one: all are "open"
  in the file, or the package is absent for a kernel flavor the file does not list). So the page cannot show "deferred" or "ignored" apart from
  "needed": every unfixed CVE is "no fix yet", and only the priority tells a negligible one from a real one. A package the tracker
  marks `not-affected` or `DNE` is not in the definition.
- The published OVAL page [71] describes the USN and OCI variants and does not mention the CVE or `pkg` ones, which the directory also
  has for every release; what the CVE file holds here comes from reading it and the generator [74], not from Canonical's description.
- Update rate: noble's file was last modified 2026-11-19 19:37 UTC and focal's 20:39, read five days later. No schedule is published.
  The files change when the tracker does; the hub asks once a day.

**The supported releases.** The hub downloads a file only for a release a host or an image runs (`VERSION_CODENAME`, or the
release name for the `VERSION_ID` in the bundled distro-info data when an image's os-release lacks it [14]). The directory has
files from `trusty` to `stonking` (26.10). The bundled distro-info data [14] gives, on 2026-11-24, standard support to 2027-06-01
for 22.04, to 2029-05-31 for 24.04 and to 2031-05-29 for 26.04, with ESM (Ubuntu Pro) to 2032-04-21, 2034-04-25 and 2036-04-23. A release the directory has no file for answers 404 and is shown as "not in Canonical's OVAL data".

**dpkg version order.** An Ubuntu version is a dpkg version: `[epoch:]upstream[-revision]` with `ubuntu`, `build` and `+esm`
or `~esm` in the revision (Debian Policy 5.6.12 [29]). `cve/debver.py` is used unchanged. All 6,149 distinct fixed versions in the noble and
focal files parse. 6,000 pairs among them (half random, half within one upstream version) were compared with `dpkg --compare-versions` (1.22.22, on
this Debian 13 machine, not on Ubuntu) with no difference; `tests/fixtures/cve/ubuntu-versions.txt` keeps 150 of the versions
and `tests/test_ubuntu.py` compares 600 pairs of them. The ordering that matters for ESM: `1.0-1ubuntu1+esm2` is above `1.0-1ubuntu1` and below
`1.0-1ubuntu2`, and `1.0-1ubuntu1~esm5` is below `1.0-1ubuntu1`.

**Source packages.** The OVAL file names source packages. A host's inventory already lists them from the dpkg `Source:` field and
version (`source:Package` and `source:Version` [22]); an image's reader sends the same two fields. One exception, the kernel: Ubuntu
builds signed kernels from `linux-signed-<flavor>` sources whose names the OVAL file does not use (it says `linux-aws`, `linux-hwe-6.8`).
The collector lists only the running kernel's image (as for Debian, so a host's other installed kernels and a container's
`linux-libc-dev` headers are not matched), under the unsigned source name (`linux-signed-aws` is `linux-aws`) and the image's own
version, which is the kernel's. That naming was read from the archive's Packages index, not seen on a host with every kernel flavor.

**Fetching** (`cve/feeds.py`, `cve/run.py`). For each release a host or an image runs, one file from
`security-metadata.canonical.com` only, with `If-None-Match` and `If-Modified-Since`, at most once per `[cve] refresh_hours` (24)
and an hour after an error. Redirects may not leave that host. A download is capped at 80 MB compressed and 1.5 GB decoded (the
real files are 11.9 and 284 MB), must start with the bzip2 magic, and is kept under `<data_dir>/cve/ubuntu-<release>.oval.xml.bz2`.
It is read as a stream (`xml.etree.ElementTree.iterparse`, clearing each definition, stopping at the end of `definitions`), 21 to 27 s
for noble and 18 s for focal on the build machine, 67 MB of resident memory for the whole process. A bad file (not XML, not OVAL, over the
caps) keeps the last copy and the Data feeds card shows "The last download failed (...)". HTTP 404 is an answer: the feed row says
`absent`, nothing is matched and nothing is raised, and the page says "Ubuntu 22.04: not in Canonical's OVAL data". A release that no
host or image runs any more is dropped with its rows, saved file and feed row. A release nothing has data for yet says "OVAL data not
downloaded yet" and raises nothing. Rows go into the `ubu` table (release, source, pocket, kernel flag, state, fixed version, one row
per source and pocket; CVE ids, priority and a 200-character description in `ubu` and `ubu_cve`), 45,419 rows for noble and 33,944
for focal with `linux` and `linux-aws` kept; `cve.db` is schema 4 (3 before; an older hub refuses a newer file, which can be deleted
and downloaded again). The kernel rows are filtered: only the flavors a host or image on that release reports are loaded, and the
saved file is read again (no download) when a host reports a new flavor. Without that filter, one release would have about 500,000
kernel rows. The CVE text is kept in `ubu_cve`, not in the Debian `cve` table, which the Debian loader empties.

**Matching** (`cve/ubuntu.py`). One call per host or image, for its release: each source package (and its version) is looked up
with its pockets. Per CVE and source:

| Rows for the source | Installed vs the fixed version | State |
|---|---|---|
| fixed in the release's own archive | older | **Fix available** (`apt upgrade` takes it) |
| fixed only in `esm-infra` or `esm-apps` (or the version has `+esm`) | older, the host has no such Pro service | **Fix needs Ubuntu Pro** |
| the same | older, the host has that Pro service on | **Fix available** |
| any fixed row | at or past the highest fixed version | Fixed already: not stored |
| "might be affected" only | | **No fix yet** |
| any, and the CVE's priority is negligible | | The state above; the vendor rule of "Prioritisation" lowers it to Low when the host is not exposed and the CVE is not in KEV |

When a package has a fix in the standard archive and a later one in ESM, the highest fixed version decides. A fix in an
ESM pocket is "fix needs Ubuntu Pro" and not counted as `apt upgrade`-fixable unless the host has that service on. A container image has no Pro:
its ESM fixes are always "needs Pro", shown on the page and never raised as a finding.

**Ubuntu Pro on the host.** Pro writes an apt source file for each service it enables, `ubuntu-esm-infra` and `ubuntu-esm-apps`
(`.sources` or `.list`, under `/etc/apt/sources.list.d/`); the Pro client's `esm.py` and `apt.py` [75] show the names and that
`pro disable` removes them. The collector looks for those files (a glob, no command and no root) and sends `esm: ["infra", "apps"]`
with the inventory (a collector that does not look sends nothing, and the page says "not known"). A hub with `esm` unknown treats
every ESM fix as "needs Pro" and the match note says so. `pro security-status`, which prints what Pro covers, and `pro fix <CVE>
--dry-run` (Pro's own check; nothing is changed) exist in the client's source [75]; the page names them in the (i) panel. The `-dry-run`
form's root requirement was not checked. Whether a file's presence means the service is on (an expired subscription, a disabled but
not removed file) was not checked either.

**When these findings resolve.** A rule that does not emit a finding resolves it, so "not known yet" must never look like "no CVEs". After a restart the reader sends every image as "not read yet". An image ID is a content hash, so its packages cannot change: `docker_storage.parse_summary` keeps the last good read of the same ID (marked `carried`, with its own `read_at`) while the new entry is "not read yet" or "not read: stopped", never over a newer failed read and never for an ID the reader no longer lists. That keeps the matches, `docker.eol_base` and the Container images page steady across a restart. Should the matches still be missing (the chore forgets matches whose image has no inventory, `_forget`), there is nothing to match for a while. An image's `docker.image_cves` finding resolves only when the image was matched in the current CVE data with no fixable CVE left, or when the image is gone: not in the reader's image list and used by no container (a reachable reader with no image and no container resolves them all). While its packages are not read, the read failed, its matches are pending (also when they were made for another package list) or its release data is missing, the rule emits the open finding again unchanged (`findings.held`, fed from the open findings by `poll.open_findings`). With no package data at all (no summary, a reader without package lists, an empty list) every open image finding is kept. With `[cve]` off they close as before. The same holds for `opnsense.updates` (kept unchanged while the update's CVEs are not matched) and `opnsense.unseen_release` (kept while the changelog is not loaded or its CVEs are not matched, unless the firewall's last check is recent). The chore leaves a host's `cve.package` findings alone until the host has a `matched` row.

**Findings and the pages.** The same rules: `cve.package` for a host and `docker.image_cves` for an image, stored under the host id or
the image's pseudo-host (`docker:<system>:<image id>`), so the severity is the worst CVE's by CISA BOD 26-04 (see "Prioritisation"), including a KEV CVE that has no fix yet (a host only). Titles say the release
(`nginx:1.27 (Ubuntu 24.04): 2 fixable CVEs`). A host's finding for a package whose only fix is ESM is rated the same way, with the title
"... fixed only in Ubuntu Pro (ESM)", and its fix is `pro security-status`, `sudo pro enable esm-infra esm-apps`, `sudo apt update` and
`sudo apt upgrade`. An ESM-only CVE does not raise a finding for an image. The Vulnerabilities page shows "Fix needs Ubuntu Pro" beside
"Fix available", a "needs Pro" badge, "Priority" for Debian's "Urgency", links to `https://ubuntu.com/security/<CVE>`, a line saying whether Pro ESM is
on, and the Data feeds card lists each Ubuntu file with its URL, licence and a `curl -I`. The Container images page counts Ubuntu images and
shows the "fixed only in Ubuntu Pro (ESM)" count beside "with no fix yet". The (i) panels give the equivalent checks:
`pro security-status` and `apt list --upgradable` on a host, `docker exec <container> apt list --upgradable` for an image (which lists updates,
not CVEs), and a `curl ... | bzcat | grep -F '<source> source package in'` lookup in the OVAL file.

Not verified: the whole path on a live hub with a real Ubuntu host and container (tested against trimmed copies of the real noble and focal
files, fakes of the server, and the parser on the full files on 2026-11-24); that a service's apt source file on a real host is
named as read in the Pro client's source (and that its absence means off); the signed-kernel naming on a host with every flavor; that the
unfixed statuses are lumped as read in the generator (checked on one example of each status, and from the generator's own mapping, not
from its documentation, which words the statuses differently); the needed, pending and needs-triage mapping beyond that; `pro fix --dry-run`
as an unprivileged user; and the parse time on a smaller machine (a hub with a slow disk will take longer than the 21 to 27 s measured here).

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
`config.toml`, and the client sends only reads. Unraid, OPNsense and UniFi are done.

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
| `opnsense.updates` | Low; Medium at 5 packages or a new release; High at 20 packages or waiting more than 30 days. With CVEs the update fixes: the worst CVE's severity by CISA BOD 26-04 (a firewall is always exposed; see "Prioritisation"). Security advisories with no CVE: at least Medium, High when GitHub rates one High or Critical (an interim rule outside the table) | The last firmware check found updates. "Waiting" counts from when the hub first saw them. The basis is the package names and versions, and with CVEs also the offered version and the CVE ids, so a new update, another offered version or a new CVE brings an accepted finding back. See "OPNsense updates and CVEs" |
| `opnsense.unseen_release` | `opnsense_cves.summary(...)["severity"]` of the CVEs and advisories the newest release fixes (the call `opnsense.updates` uses); Low with none | The changelog has a release or hotfix in the firewall's series above what it runs and above what its last check showed, and that check is 2 days or more old, missing or unreadable. Clears when the firewall checks. The basis is that version. See "OPNsense updates and CVEs" |
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
host kinds and was not reworked here (see UI.md).

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

### OPNsense updates and CVEs

Per the core rule in "Goal": the firewall's pending firmware update shows the CVEs it fixes, ranked as a host's are. The source is
the OPNsense project's own changelog [66], the repository the firewall's System, Firmware, Changelog tab is built from. Read on
2026-11-24 (README, LICENSE, `Links/`, and all 357 files under `community/`).

**What the changelog is.**

- Layout: `community/<series>/<release>`, one plain-text file per release and no extension. `<series>` is `YY.1` or `YY.7`
  (24 directories, `15.1` to `26.7`). `<release>` is `26.7` (the major release itself), `26.7.10`, a few four-part ones
  (`15.1.6.1`), and `26.7.r1`, `26.1.b` for release candidates and betas. `business/<series>/` (`YY.4`, `YY.10`) is the Business
  Edition. There is no file for a hotfix such as `26.1.11_3`.
- Format (the README and the files): `@ July 21, 2026` first, prose, then `o ` bullets (a continuation line is indented), then a `--`
  line and numbered footnotes. A footnote is `[n] KIND:ID` and a bullet points to it with `[n]`. The kinds that name a security
  issue are `CVE:CVE-2026-57154` (23 footnotes), `GHSA:...` (an advisory in OPNsense's own code, no CVE id) and `FREEBSD-SA:26:74.ktls`
  (a FreeBSD advisory; the file does not name its CVE ids). `Links/CVE` turns a CVE footnote into
  `https://www.cve.org/cverecord?id=%s`. Many files, old and new, also type the id in the bullet, and the oldest give a cve.mitre.org URL as the footnote.
- Hotfixes: a line `A hotfix release was issued as 26.1.11_3:` (126 times) starts the bullets of that hotfix inside the release's file.
  `Out of band hotfix for PHP CVE-2026-109618 and CVE-2026-109619:` (26.1.11, 26.7.7) is a lead line that names the CVEs of the
  bullet under it. The `_3` is pkg's package revision [67], not a release: the firewall's installed version is `26.1.11_3`.
- Licence: BSD 2-Clause, `Copyright (c) 2015-2021 Franco Fichtner`. The terms are shown on the Vulnerabilities page and the
  fixtures here keep the file. The text is not republished by DaemonSight: it keeps the CVE ids and the one bullet each came from.

**Counting.** A CVE counts when a patch-note bullet has its id in the text or points to a `CVE:` footnote, or when the bullet sits
under a lead line that names it. 50 distinct CVE ids came out of the 317 release files, in 32 of them (the 40 `.rN` and `.b` files are skipped, as the
firewall's own changelog list skips them unless it runs a development version [68]). CVE ids that appear only in a release's
introduction are not counted: 24.7.3 says CVE-2024-6640 "resurfaces" (not fixed), 23.7.8 says "we are aware of" CVE-2023-5678 and
21.1.6 says CVE-2020-15078 "does not affect" the shipped version, while 21.7.2 lists four CVEs as addressed. Telling those apart needs
reading sentences, so none is guessed. The count is a floor: many fixes appear only as a FreeBSD or GitHub advisory with no CVE id
(267 distinct advisory references against the 50 CVE ids), and some may not be in the file at all. The hub asks each advisory's
publisher for its CVE ids; the ones it names join the count and are ranked. An advisory that names none stays an advisory, listed on the
card and rated by `summary()` (see "Security advisories in the changelog" below).

**What docs.opnsense.org adds.** Nothing for this. `CE_releases.html` [69] is an index that links one page per series
(`releases/CE_26.1.html`), and those pages are the same repository rendered (the CVE set of 26.1 on the page equals the files'),
with each footnote linked to cve.org. It also lags: on 2026-11-24 it said the latest version was 26.7.9 while the repository had
26.7.10, dated that day. The repository is read, and the page's URL is shown as the human-readable copy.

**Getting it without a request per file.** The GitHub contents and trees APIs list names, not text, so reading N releases takes N
requests. The repository's archive, `https://codeload.github.com/opnsense/changelog/tar.gz/refs/heads/master`, is one request of
0.6 MB (627,386 bytes on 2026-11-24, all series and the business edition), has an `ETag` and answers `If-None-Match` with 304
(tried) [70]. The ETag is the archive's, so it should change with any commit to the repository (not tested), and a day's check can then cost the 0.6 MB; at one check per 24 hours that is small. The
chore keeps the tarball under `<data_dir>/cve/opnsense-changelog.tar.gz`, reads only `community/<series>/<release>` files of the series
it needs, and never extracts anything (`tarfile` in stream mode; only plain files with exactly that name; each file capped at 256 KB,
the archive at 20 MB compressed and 400 MB as listed). The firewall itself downloads a signed `changelog.txz` from its mirror
(`changelog.sh`, `opnsense-update -X` [68]); the file is at `pkg.opnsense.org/FreeBSD:14:amd64/26.1/sets/changelog.txz` (a HEAD
request answered 200, 245 KB), but checking its signature needs OPNsense's fingerprints, and the mirror's path for each release is
not documented, so it is not used. Unverified.

**Version order.** Nothing in DaemonSight ordered OPNsense versions: `opnsense._version_base` copies the firewall's reduction (cut at
`.0`, `p`, `_`, `-`) to compare with the changelog list, which drops `_N` and cannot order anything. `cve/opnver.py` defines the
order from pkg's `libpkg/pkg_version.c` [67]: dotted numeric parts (missing parts are 0, so `26.7` equals `26.7.0`), then the
`_N` revision as a number, so `26.1.11 < 26.1.11_3 < 26.1.11_10 < 26.1.12 < 26.7`. A release candidate, a beta or any other form is not
a version and is never compared. The epoch (`,N`) is refused as unknown for OPNsense.

**Which sections a pending update brings.** The installed version is the firmware status's `product_version` (`26.1.2_3`). The
offered version is the `new` of the `opnsense` package in the pending list (`26.1.5`, or `26.1.11_10` for a hotfix), and for a major
upgrade, which lists sets and no packages, the release in `upgrade_major_version` (`26.7`; `check.sh` fills it from `opnsense-update
-vR`) [68]. A section is a release, or a hotfix under it. The CVEs fixed by the update are those in every section with
installed < version <= offered. A CVE named in several of them is reported at the highest (the later mention finishes the fix, as for
Alpine). The out-of-band hotfix lines carry no version of their own, so they are put under the hotfix version printed before them
(26.1.11_10) or, with none, under the release (26.7.7). That placement is a reading of the files, not stated by them: unverified.
Only the series from the installed one to the offered one are loaded (`26.1` and `26.7` for an upgrade from 26.1.11 to 26.7). A
Business Edition version (`YY.4`, `YY.10`) is not read: the card says so and lists none. Whether the pending list's
`new` has the `_N` hotfix suffix on a real firewall was not seen (the fixture's shape follows `check.sh` and the changelog's own
wording): unverified.

**Matching.** `cve/run.py` makes a firewall's CVEs under the pseudo-host `opnsense:<system id>` in `cve.db` (a host id has no colon,
so it cannot clash; image CVEs use `docker:<host>:<image id>` the same way). `match` rows: source `opnsense`, state `fix`, `installed` the
running version, `fixed` the section that names the CVE (a line, or an advisory that lists it); `opn_fix` holds the changelog line as
the evidence, `opn_release` each release's date, `opn_adv` what each advisory named. The KEV flag and EPSS score come from the same tables as for a host, so the ranking is the same. The rows are made again
when the plan (installed and offered), the series loaded or the changelog data changes.

**Fetching** (`cve/feeds.py`, `cve/run.py`). While at least one enabled OPNsense system exists, whether or not an update is pending (see "A release the firewall has not been offered"). At most once
per `[cve] refresh_hours` (24; an hour after an error) with `If-None-Match` and `If-Modified-Since`, one host (`codeload.github.com`,
no other redirect target), generic User-Agent. A failure (HTTP error, not a tarball, no `community/` files, a file over the cap)
keeps the last good rows, records the error on the feed's row and shows "The last try to read OPNsense's changelog failed: ... These are
from the last good copy, N ago." on the card. A change in the series a firewall needs is read from the saved file without
downloading. When no enabled firewall is left, the file, rows and feed row are dropped. The Vulnerabilities page lists
the feed while it exists. `cve.db` is schema 5 (3 added `opn_release` and `opn_fix`, 5 adds `opn_adv`; an older hub refuses it, and `cve.db` can be deleted).

**The finding** (`opnsense.updates`, in `remote/opnsense_rules.py`, reading `remote/opnsense_cves.py`). With CVEs it adds "; fixes N
CVEs (K known exploited)" to the title and the count and the top four to the detail. Severity is the worst CVE's by CISA BOD 26-04, as for a host
package and an image (`cve/priority.py`; a firewall is always exposed, so the exposure input is yes): the title says "fix within N days" and the detail starts
with the deadline; the finding's own rule (packages, a new
release, days waiting) can still make it higher. A security advisory of the changelog that names no CVE (see "Security advisories in the
changelog") makes it at least Medium, and High when GitHub rates one High or Critical. The basis is the package list, the offered version, the CVE ids and the
unresolved advisories, so an accepted
finding comes back when the offered version or a CVE changes (a CVE newly added to KEV, or a new CISA rating, changes the severity, not the basis, as for a
host). "What to do": the card, the changelog link for the offered version, System, Firmware, Updates (`Menu.xml`: Status, Settings,
Changelog, Updates, Plugins, Packages) [68].

**The card** (Overview, "Pending firmware updates"). One line, "Fixes N CVEs (K known exploited)", then a table (CVE linked to
cve.org, EPSS, KEV, the release with its date linked to the changelog file, the changelog line), the advisories folded under it, and an
(i) panel in the style of the Container images page: the source URLs and terms, what counts, and the same check in the firewall
(System, Firmware, Changelog, read each release from the installed version to the offered one; System, Firmware, Status, Run an audit,
Security runs `pkg audit -F`, `scripts/firmware/security.sh` [68]). Without a result it says why in one sentence: CVE matching is off,
the update has no new release (package updates only), the versions cannot be ordered, the series is not read, or the hub has not read
the changelog yet.

**A release the firewall has not been offered** (`opnsense.unseen_release`). Found 2026-11-24: a firewall on 26.7.9_3 showed
`latest` 26.7.9, `status` `none`, "There are no updates available on the selected mirror." and a `last_check` of Nov 18, while the
changelog already had 26.7.10. With no update pending the hub never read the changelog, so it had nothing to say. The changelog is
now read whenever an enabled OPNsense system exists, keeping the firewall's series and the two after it (`opnver.next_series`), and
the rule fires only when both hold:

1. The changelog has a release or hotfix version in the firewall's series that is above the installed version and above what its
   last check showed: the highest of `latest`, `new_version` and the `new` of the OPNsense package of a pending update, all in that
   series (a major upgrade on offer says nothing about this series). The order is `opnver`'s. The hotfix versions come from the
   section headers, kept in `cve.db` `meta` key `opn_versions`, because a hotfix with no CVE has no row in `opn_fix`.
2. `last_check` is 2 days or more old, missing or unreadable. Two days is the owner's rule ("only stale if there's a new version AND
   the firewall hasn't checked in a couple of days"), not an OPNsense value. An unreadable value counts as an unknown age and fires.

It clears when the firewall checks: `latest` or `new_version` catches up, and if the release is then offered `opnsense.updates` takes
over. Both cannot name the same version, because condition 1 is above what the pending update offers. A newer series alone (27.1
while on 26.7, a major upgrade) raises no finding; the card gets one line, shown only when the check is also 2 days old.

*`last_check`.* `scripts/firmware/check.sh` sets `last_check=$(date)` (the file's header lists it as `last_check:
<date_time_stamp>`), and the status API returns it as is [76]. `date` with no format uses `%+` [77], which in FreeBSD's C locale is
`%a %b %e %H:%M:%S %Z %Y` [78]: `Wed Nov 18 08:45:50 EST 2026`, the day space-padded under 10. The zone is the firewall's own
abbreviation. `remote/opnsense.py` `last_check_ts` maps UTC, GMT, EST, EDT, CST, CDT, MST, MDT, PST, PDT and a few more, reads a
numeric abbreviation (`+03`) as that offset, and reads any other abbreviation as UTC, at most 14 hours off against a 48-hour
threshold. The string `unknown` (what the script writes before a check succeeds) and anything else that does not match give no time.
Unverified: the format on a firewall set to another locale, and the abbreviations of zones not in the map.

*The finding.* Title "26.7.10 is out (fixes N CVEs); the firewall hasn't checked since Nov 18" (the count is left out at 0; with no
readable time: "the firewall's last check time is unknown"). Detail: the installed and seen versions, then the same sentence and top
CVEs as `opnsense.updates`. Severity is `opnsense_cves.summary(...)["severity"]` on the CVEs of the range from the installed version
to the newest one with that range's advisories, the call `opnsense.updates` makes, with no floor or mapping of its own, and Low with no
CVE and no advisory; a test holds both rules to the
same severity for the same CVE set. The basis is the newest unseen version. "What to do": Check now: System, Firmware, Status, Check
for updates (`Menu.xml`) [68]; so it checks on its own: System, Settings, Cron (`Cron/Menu/Menu.xml`: System, Settings, Cron), add a
job whose command is "Firmware update check", daily. That is the description of the configd action `firmware poll`
(`actions_firmware.conf`: `[poll]`, `message: Running firmware update status via cron`, `description: Firmware update check`), and the
Cron model's `command` field lists configd actions by description (`Cron.xml`, `ConfigdActionsField`) [79]; then the changelog link.

*Matching.* The range is matched like a pending update's under the pseudo-host `opnsense-unseen:<system id>` (a plan of installed
and newest), so a CVE's KEV flag and EPSS score come from the same tables. Rows are kept only while the plan holds.

*The card.* When the finding's two conditions hold the Overview shows "Firmware release not yet seen" (or, with an update pending, a
second block under the pending one) with the finding's sentence, "The firewall has not been offered 26.7.10 yet. These CVEs are fixed
between 26.7.9_3 and 26.7.10; the firewall's last check showed nothing above 26.7.9", the CVE table, the advisories and an (i)
panel.

**Package updates outside a release.** The status lists plugin and third-party packages (`os-*`, `php`, `curl`) as pending too. The
changelog covers a release's bundled ports and plugins only as bullets (`ports: php 8.5.13[37]`, `plugins: os-caddy 2.2.4[3]`) and names
a CVE for few of them. A pending package with no new release gets no CVE list, and the card says so. Later option, not built: the
firewall's own `pkg audit` (System, Firmware, Status, Run an audit, Security) uses FreeBSD's VuXML database of the installed packages;
the hub could match the firewall's package list against the VuXML file. Not researched here.

Not verified: that the hub's whole path ran against a live firewall (no live system was used; the firewall reply is the synthetic
fixture and the changelog files are real); what `all_packages` shows for the `opnsense` package when a hotfix is offered on a real
firewall; that `upgrade_major_version` names the series the next major upgrade lands on; the file layout before 15.1 (not in the
repository); the Business Edition's `business/` files (different series, not parsed).

### Security advisories in the changelog

Found 2026-11-24. The live `community/26.7/26.7.10` has no CVE id in a line or a footnote, so the hub read it as a routine release
("26.7.10 is out", Low). Its footnotes name 21 FreeBSD security advisories (`FREEBSD-SA:26:74.ktls` to `26:94.tmpfs`; the brief
counted 9, `74` to `82`, and the file has 12 more), 2 GitHub advisories (`GHSA-f35q-c34m-pfw3`, `GHSA-89wp-xvvm-9pp4`), 4 FreeBSD errata
(`FREEBSD-EN:26:29` to `26:32`), plugin notes (`PLUGINS:`) and version notes (`PHP8:8.5.13`). It is a security release. The parser
kept the 23 advisories as `adv` rows; they were counted and listed, and nothing ranked them. The hub now asks each advisory's
publisher for its CVE ids, once, so the release's CVEs join the set that KEV and EPSS rank.

**Which footnote kinds exist.** Counted over every footnote of the 317 release files under `community/` on 2026-11-24: `FREEBSD-SA` 246, `FREEBSD-EN`
132, `GHSA` 24 (23 distinct), `CVE` 23, `FREEBSD-GH` 46, `FREEBSD-BZ` 8, `FREEBSD-RN` 8, `PLUGINS` 466, and about 40 kinds that name a
software version (`PHP5`, `PHP7`, `PHP8` 145, `NSS` 81, `SQLITE` 60, `CURL` 54, `OPENVPN`, `UNBOUND`, `OPENSSH`, `LIBRESSL`, `SUDO`,
`PYTHON`, `OPENSSL`, `EXPAT`, ...) [66]. Handled: `FREEBSD-SA` and `GHSA`, the two with a machine-readable record that names CVEs.
Not handled, and why:

- The version notes (`PHP8:8.5.13`, `NSS:1.134`, `CURL:7.68.0`): the footnote names a version, not an issue. A CVE list for a PHP or
  curl version needs NVD or the project's own list, which is another source. Not researched. (Real PHP fixes do reach the card when
  the changelog types the CVE id in the line, as 26.1.11 and 26.7.7 do.)
- `FREEBSD-EN`: not security advisories (below). Left out of every count.
- `FREEBSD-GH`, `FREEBSD-BZ`, `FREEBSD-RN`, `SRC`, `CORE`, `DOCS`, `PLUGINS`: a commit, a bug report, release notes, an issue,
  a manual page or a plugin directory. None is an advisory.
- Bullets that say "security" or "vulnerability" with no footnote (23 in the files, most about settings such as "strict security
  mode"; one is "src: fix out-of-bounds read vulnerability in libarchive"): no identifier, so nothing to look up.

**FreeBSD** [80]. Two fetched: `FreeBSD-SA-26:74.ktls` has `CVE Name:       CVE-2026-101313`, and `FreeBSD-SA-26:76.ocs_fc` has
`CVE Name:       CVE-2026-127752, CVE-2026-127753, CVE-2026-127754` (one line, ids separated by commas). All 21 advisories of 26.7.10
were fetched: each has the line, 25 CVE ids between them, 3 at most in one. Older ones read the same (19:08, 18:10, 23:06, 24:04,
25:08). The advisory is a plain-text, PGP-signed file at `https://www.freebsd.org/security/advisories/FreeBSD-SA-26:74.ktls.asc`
(HTTP 200, `text/plain`, 5 to 9 KB). `https://security.freebsd.org/advisories/<same name>` answers 301 to that address, so the hub asks
`www.freebsd.org` directly and follows no redirect. The module part of the name matters (`26:74.ktls`, not `26:74`: the short form is a
404). The index (`/security/advisories/`, 205 KB of HTML) and the RSS feed (`/security/feed.xml`) list advisory names and dates and no
CVE ids, so one file cannot cover many advisories: one request per advisory. FreeBSD's VuXML (`vuxml.freebsd.org/freebsd/vuln.xml.bz2`,
1.4 MB, 10.5 MB decoded) puts a `cvename` next to a `freebsdsa` for only 474 of its 6,880 entries; it was not used. The header block's
other fields are `Topic:`, `Category:`, `Module:`, `Announced:`, `Credits:`, `Affects:`, `Corrected:`. Only `Topic:` (kept as a short
title) and `CVE Name:` (and the indented lines after it) are read, and only before the line "For general information" (the sections
below it can say anything). A page that is not that advisory (the name is not in its first lines) is a failure, not an answer. The
advisory's PGP signature is not checked. Errata notices are not security advisories: they are a separate document type ("Errata
Notice" in the header; the security page says an issue "will receive a Security Advisory or an Errata Notice" [80]), and the two read,
`FreeBSD-EN-26:32.zfs` and `FreeBSD-EN-26:29.tzdata`, have no `CVE Name:` field and no "CVE" at all. They are never asked for and are
not counted.

**GitHub** [81]. `GET https://api.github.com/advisories/GHSA-f35q-c34m-pfw3` (the global advisory database) answered 404 for both
advisories of 26.7.10: an advisory published on a repository's own security page is not in it. `GET
https://api.github.com/repos/opnsense/core/security-advisories/GHSA-f35q-c34m-pfw3` answered 200 with no token ("Anyone can access any
published security advisory on a public repository"). Both, as returned:

| Advisory | `cve_id` | `severity` | `cvss.score` | `state` | Summary |
|---|---|---|---|---|---|
| `GHSA-f35q-c34m-pfw3` | null | high | 7.2 | published | Unquoted PPP password in mpd_*.conf allows root command execution (incomplete fix of CVE-2026-57154) |
| `GHSA-89wp-xvvm-9pp4` | null | high | 7.2 | published | Authenticated Root Command Injection via Firmware `flavour`/`subscription` Settings (incomplete fix of CVE-2026-119409) |

Four older ones of the changelog, for the shape: `GHSA-2v2x-m4j7-76pv` has `cve_id` CVE-2026-63442 (high, 8.1), `GHSA-33q4-wcv7-r8fr`
has none (high, 8.1), `GHSA-2f7g-25f3-55v7` and `GHSA-2w8j-hpp2-8rfj` have none (medium, no score). So an OPNsense advisory can carry a
CVE id, and `severity` can be set while `cvss.score` is null. A summary may name another CVE ("incomplete fix of CVE-2026-57154"); that
is the earlier fix, not this advisory's, so the description and summary are never read for ids, only `cve_id`. The reply is 17 to 20 KB
(mostly the description and the reporters' profile fields, none of which is kept). Rate limit [82]: 60 requests an hour per address
with no token (the replies carried `x-ratelimit-limit: 60`, `x-ratelimit-remaining`, `x-ratelimit-used`, `x-ratelimit-reset` as epoch
seconds and `x-ratelimit-resource: core`; the research used about 15 of them). Over the limit the answer is 403 or 429; "do not retry
before `x-ratelimit-reset`", or before `retry-after` seconds when that header is present. Not provoked here: a real 403 was not seen, so
that the headers are on it is the documentation's word.

**What the hub does** (`cve/advisories.py`, `cve/run.py`).

- Which advisories: those of the changelog sections a firewall needs, the pending range and the unseen range, and no others (a firewall
  on the newest release asks for nothing). A reference that is not `FREEBSD-SA:` or `GHSA:` is never asked for.
- Once, for good: an answer is kept in `cve.db` `opn_adv` (reference, `ok`, CVE ids, GitHub's `severity` and `score`, a short title) and
  never asked again, because a published FreeBSD advisory does not change. It stays when no firewall needs the changelog any more. A
  failure (HTTP error, 404, not that advisory, too big, not JSON) is stored with a reason and tried again after `[cve] refresh_hours`
  (24). A GitHub advisory can be given a CVE id after it is published, so one that resolved to none is asked again after 7 days (own
  choice) for as long as a pending or unseen range still names it; a CVE it names then is kept for good and the firewall is matched
  again. A failed recheck keeps the earlier answer and waits another 7 days. A FreeBSD advisory that named no CVE is not rechecked.
- Politely: at most 40 advisories in a pass; one request at a time, 0.5 s apart on `www.freebsd.org` and 1 s apart on `api.github.com`
  (the hub's own choice; neither site states a limit for this). A 429 or 503 from either stops that host for the pass. A 403 or 429 from
  GitHub stops GitHub until the time its headers give (`retry-after`, else `x-ratelimit-reset` when `x-ratelimit-remaining` is 0, else an
  hour; at least a minute and at most six hours, so a hostile header cannot park it for long), kept in `meta` `opn_gh_until`; nothing is
  held against the advisory. An answer that says no request is left stops GitHub until the reset too.
- Safely: HTTPS only, the host must be the one asked, no redirect is followed (a 3xx is a failure), 128 KB at most for FreeBSD and 512 KB
  for GitHub, standard library parsing, and only CVE ids that match `CVE-YYYY-NNNN` and a rating from the four GitHub words are kept.
  The two hosts are in SECURITY.md.
- Matching: the CVEs an advisory names join the section's CVE set (`opnsense.match_host`) and are ranked with KEV and EPSS like any
  other. A CVE named by a line and by an advisory is one row, at the highest section that names it. The card's table says "via
  FreeBSD-SA-26:74.ktls" under the line (and the finding's top CVEs say it too). The firewall is matched again when the set of
  answers changes (`cve.db` generation).
- Unresolved advisories (not asked yet, failed, or naming no CVE) stay in the advisories list. Titles: "fixes 27 CVEs and 2 other
  security advisories", or "fixes 2 security advisories" with no CVE (singular as needed). Severity, in the one `summary()` that
  `opnsense.updates` and `opnsense.unseen_release` both call: an unresolved security advisory makes it at least Medium (own choice: a
  security fix that cannot be ranked is not routine), and High when GitHub rates one High or Critical and no CVE ranks higher already
  (GitHub's rating is the project's own, so it is taken as given). A CVE that ranks higher is never lowered. Errata and plugin notes do
  not count. The `opnsense.updates` basis adds the unresolved references, so an advisory that later names a CVE brings an accepted
  finding back, as a new CVE does.
- Card: the advisories folded under the CVE table, "23 security advisories in the changelog; 2 with no CVE yet, not ranked", and for each
  one its name linked to the advisory, the release, and its CVEs (linked to cve.org), "no CVE published", "CVE lookup pending" or "CVE
  lookup failed, tried again later", and GitHub's rating and score. The (i) panel adds the two address patterns.

Result for 26.7.10 against the real answers: 25 CVE ids through FreeBSD, 2 GitHub advisories with no CVE (both High), so the unseen
finding reads "26.7.10 is out (fixes 25 CVEs and 2 other security advisories); the firewall hasn't checked since Nov 18" at High (before:
"26.7.10 is out; ...", Low). For a firewall on 26.7.1 the range adds 26.7.7's two PHP CVEs: 27.

Not verified: a live hub fetching the real sites (the tests use fakes of both, made from the real answers saved on 2026-11-24); a real
403 or 429 from GitHub; that the FreeBSD site stays at `www.freebsd.org/security/advisories/` (the `security.freebsd.org` address
redirects there today); the PGP signature; the field's definition on FreeBSD's side (read from 25 advisories, the "how to read an
advisory" page was not found).

### CrowdSec bans on an OPNsense firewall

Optional, per firewall. On 2026-11-19 the firewall's CrowdSec banned the firewall's own WAN address twice (scenario
`firewallservices/pf-scan-multi_ports`); its pf bouncer then dropped the states of every NAT'd connection, and the cascade got an AI
provider's API address banned for four hours. DaemonSight now reads CrowdSec's Local API (LAPI) and opens a finding when a ban
covers an address it should never see banned, instead of the owner finding out through an outage. (The pf bouncer kills the states of
every banned address that has any: `pfctl -k <ip>` and `pfctl -k 0.0.0.0/0 -k <ip>` in `add()`, cs-firewall-bouncer
`pkg/pf/pf_context.go`, read 2026-11-19. A ban on the firewall's WAN address therefore drops every NAT'd connection.)

**What is read.** One endpoint, `GET /v1/decisions`, on the LAPI, with a bouncer's API key in the `X-Api-Key` header. Nothing else is
called. Read from the CrowdSec source (github.com/crowdsecurity/crowdsec, `master`, read 2026-11-24) and docs, and checked on a live firewall
(see "Verified live" below):

| Fact | Source |
|------|--------|
| `GET /v1/decisions` ("Returns information about existing decisions") takes `scope`, `value`, `type`, `ip` ("shorthand for scope=ip&value="), `range`, `contains` (boolean: "a decision that contains the value, or that is contained within the value"), `origins`, `scenarios_containing`, `scenarios_not_containing`; its security is `APIKeyAuthorizer`, the header `X-Api-Key` | `pkg/models/localapi_swagger.yaml` |
| The route is in the API-key group; `/alerts`, `DELETE /decisions`, `/allowlists` and the rest are in the machine (JWT) group | `pkg/apiserver/controllers/controller.go` (`apiKeyAuth` and `jwtAuth`) |
| A bouncer key "can only read decisions"; a machine (login and password) "can read, create and delete decisions" | docs, Local API, Authentication (https://docs.crowdsec.net/docs/next/local_api/authentication) |
| A wrong or missing key is HTTP 403, `{"message": "access forbidden"}` (not 401) | `pkg/apiserver/middlewares/v1/api_key.go` |
| Decision fields: `id`, `origin`, `type`, `scope`, `value`, `duration`, `until`, `scenario`, `simulated`, `uuid`. A GET answers `id`, `duration`, `scenario`, `scope`, `value`, `type`, `origin` and `uuid`; it sets neither `until` nor `simulated`. `duration` is the time left (until minus now), a Go duration such as `3h59m12.5s` | swagger `Decision`; `FormatDecisions` in `pkg/apiserver/controllers/v1/decisions.go` |
| No decisions is JSON `null`, not `[]`: `FormatDecisions` returns a nil slice. The hub reads both as none | `FormatDecisions` |
| Only active decisions (`until` in the future) and, by default, no simulated ones | `QueryDecisionWithFilter` in `pkg/database/decisions.go`; `applyDecisionFilter` in `pkg/database/decisionfilter.go` |
| `ip` and `range` both take an address or a CIDR (`Addr2Ints` handles a value with a slash). `contains` defaults to true: decisions that contain the query. `contains=false`: decisions inside it. Address families never match each other (the size is part of the filter). An invalid value is a 400 | `applyDecisionFilter`, `decisionIPFilter`; `pkg/types/ip.go`, `pkg/csnet/ip.go` |
| `origins` is a comma list, matched exactly. Origins in the source: `cscli`, `crowdsec`, `console`, `cscli-import`, `lists`, `CAPI`, `remediation_sync`. `crowdsec` is a decision a local scenario made | `pkg/types/constants.go` |
| `limit` and `offset` are read by `applyDecisionFilter` but are not in the swagger file | `decisionfilter.go` |
| With none of `ip`, `range`, `origins` and the like, **no address filter is applied: the answer is every active decision**, the community blocklist (tens of thousands) included | `decisionIPFilter` (`case 0` returns the query unchanged) |
| `/v1/decisions/stream` is a bouncer's sync call: "Returns a list of new/expired decisions. Intended for remediation component that need to "stream" decisions". With `startup=true` it sends the full list. Not used. (Its handler was not read; that it moves the bouncer's pull state is from the project brief. `GET /v1/decisions` also stamps the bouncer's last-pull time, at most once a minute: harmless, read in `GetDecision`) | swagger `getDecisionsStream`; `controller.go` (`LimitStreamConcurrency`, `StreamDecision`) |

**What is never done, and how that is enforced.** `crowdsec.Lapi.check_params` runs before any request and refuses what is not one of
these three reads, each with a `limit`: `ip=<one address>`; `range=<cidr>` with `contains=true` or `false`; `origins=crowdsec`. So there
is no call to `/v1/decisions/stream`, no read without an address or origin filter (the fake LAPI in the tests answers the whole
community list to one, and a test asserts the hub never sends it), and no `scope`, `value`, `type`, `startup` or other parameter. A
`contains=false` read of a public range wider than /16 (IPv6: /48) is refused, since what lies inside it could be most of the
community blocklist. The client sends GET only, follows no redirects (the key would go to the new address), caps a reply at 8 MiB,
and scrubs the key from every message.

**Why a bouncer key.** A bouncer can only read decisions; a machine's credentials can also push alerts and delete decisions. The key
file is `<data>/remotes/<id>.crowdsec-key`: 0600 in the 0700 folder, written atomically, never shown back, deleted when the option is
turned off or the system removed, and included in backups. On the firewall: `cscli bouncers add daemonsight-hub`
(https://docs.crowdsec.net/docs/next/cscli/cscli_bouncers_add). CrowdSec stores the key hashed (`HashSHA512` in
`CreateBouncer`), so it cannot show it again; the docs page does not say "printed once", the hash does. A key is bound to the first
address that uses it: a second client with the same key makes a second bouncer row (`api_key.go`), so give the hub its own key.
The hub's requests name themselves `DaemonSight/<version>`, which `cscli bouncers list` shows as the bouncer's type and version.

**What is asked about** (`crowdsec.protected`), merged by value, at most 160 reads per pass:

1. The firewall's own addresses: each address on an internet-facing interface (role `wan`, from `remote/roles.py`) with `ip=`; the
   network of each LAN and VPN interface with `range=` twice (a ban that covers it: `contains=true`; a ban of anything inside:
   `contains=false`). Link-local and loopback addresses are left out.
2. Every host the hub knows: a collector's address (what the hub saw it upload from), a remote system's address when its URL has an IP. A host the hub knows only by name is
   listed on the card as not checked.
3. The owner's never-ban list (the system form), at most 50 addresses or networks, each a single IP or a CIDR, normalised. DaemonSight
   ships no vendor ranges; the field's (i) help suggests adding the services the owner depends on, such as an AI provider's range.
4. `origins=crowdsec&limit=500` for the local decisions: counted by scenario (top 20 kept), shown on the card. Capped, and marked
   "at least" when the cap is reached.

Every decision that comes back is checked again against the address it was asked about (`crowdsec.covers`, address ranges that
overlap), cut to named fields and lengths, and capped at 10 per address. A value that is not an address or a network never reaches a
command.

**Findings.** Prefix `crowdsec.` in `HUB_RULES` and `poll.RULE_PREFIX`. `basis` is the scenario and origin, with no times, so Accept
survives a re-ban. Only a decision of type `ban` is a finding; any other type is listed on the card.

| Rule | Severity | When | Fix |
|------|----------|------|-----|
| `crowdsec.self_banned` | High | A ban covers an address of this firewall, or is inside or covers one of its LAN or VPN networks. The key is the decision's value | `cscli decisions delete -i <address>` (or `-r <range>`) |
| `crowdsec.host_banned` | High | A ban covers a host the hub knows, or an address on the never-ban list | the same |
| `crowdsec.unreachable` | Low | The last two reads in a row failed (the key is never in the text). The last good bans stay as findings | none |

The "What to do" steps give the fix, how to find out why (`cscli alerts list -i <address>`, `cscli alerts inspect <id> -d`) and how to
stop it coming back with an allowlist (`cscli allowlists create <name> -d "..."`, then `cscli allowlists add <name> <address> -d "..."`).
Per CrowdSec's allowlist page, an allowlist drops matching local alerts, removes matching addresses from blocklist pulls before they are
stored, and makes `cscli decisions add` refuse the value; the page does not say that adding an entry removes a decision that already
exists, so the steps say to run the fix as well (https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists;
cscli flags: https://docs.crowdsec.net/docs/next/cscli/cscli_allowlists_add, `_create`, `cscli_decisions_delete`, `cscli_decisions_list`,
`cscli_alerts_list`, `cscli_alerts_inspect`).

**Hub side.** Schema 10 adds `remotes.crowdsec_url` and `remotes.crowdsec_never` (a JSON list). The poll (`remote/poll.py`,
`read_crowdsec`) reads at most every two minutes (or the system's interval if longer) and stores the snapshot `opnsense_crowdsec`.
A failed read keeps the last data, counts the failure and never fails the poll. Turning the option off deletes the key file, the
columns and the snapshot, and the findings resolve at the next poll. The Add and Edit form for an OPNsense system has "Read CrowdSec
bans" as a dependent option (address, key, never-ban list, Test CrowdSec); the Firewall page has a CrowdSec card (`web/sections.py`
anchor `crowdsec`) with what was checked, status labels and the local ban count.

**Verified live (2026-11-24).** On an OPNsense firewall with os-crowdsec 1.0.12 and CrowdSec 1.8.2:

- The plugin's Local API listens on the firewall's LAN address, port 8180. The address is `api_url` in
  `/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml` on the firewall.
- `cscli bouncers add <name> -o raw` prints only the key.
- A filtered `GET /v1/decisions` with that key worked from a hub container on an Unraid server.
- `cscli bouncers list` shows the bouncer as validated, with the hub's source address. A hub in a bridge-mode container shows
  as the Unraid server's address.

**Unverified.** Still read from the source and not seen live: the `null` for no decisions; that `limit` works (it is in the
source, not the swagger file, and an older CrowdSec that ignores it would only return more rows, which the hub still cuts to
size); the status for a wrong key (403, from `api_key.go`). The docs name no version in which allowlists arrived (the swagger
on `master` has them). LAPI TLS: a `https://` address is checked against the usual authorities only; pinning a self-signed LAPI
certificate is not built.

### UniFi Network

Done, and not yet seen against a live controller (see "Unverified" below). The hub reads the UniFi Network Integration
API with one API key in the `X-API-KEY` header. Every request is a GET. Each source is stored as a `unifi_*` snapshot,
polled by `remote/poll.py`, turned into findings by `remote/unifi_rules.py`, and shown on the controller's own pages
(Overview, Devices, Wi-Fi, Report).

**Sources.** The API is Ubiquiti's published OpenAPI document for UniFi Network 11.0.97
(https://developer.ui.com/network/v11.0.97/openapi.json, read 2026-11-24; the list of operations is in
https://developer.ui.com/network/v11.0.97/llms.txt, which also states that all APIs use the `X-API-KEY` header). A local
console serves it at `https://<console>/proxy/network/integration`. Lists are paged with `offset` and `limit` (at most
200); the hub reads at most 5 pages of a list and 10 sites.

| Snapshot | Reads | Cadence |
|----------|-------|---------|
| `unifi_info` | `/v1/info` (application version), `/v1/sites`, and per site `/clients` asked with `limit=0`, which gives only the count | the interval |
| `unifi_devices` | `/v1/sites/{siteId}/devices` (name, model, state, firmware, `firmwareUpdatable`, `supported`, features), `/v1/pending-devices`, and for a device that is not online `/devices/{deviceId}/statistics/latest` (`lastHeartbeatAt`; at most 20 a poll) | the interval |
| `unifi_wifi` | `/v1/sites/{siteId}/wifi/broadcasts` (name, enabled, security type, bands, hotspot type) | 5 minutes, or the interval if longer |
| `unifi_gateway` | only when a site has a device with the `gateway` feature: `/firewall/zones` and `/firewall/policies` | 5 minutes, or the interval if longer |

The whitelist is these path patterns and nothing else, each compared as a whole string with its query. A detail path,
an action path (restart, upgrade, adopt), a voucher, a client list with names and any other query are refused before a
request is sent. It is the same `Rest` class as OPNsense, with the key in a header and a list of patterns where
OPNsense has a list of strings.

**What the key can do, and what Test checks.** The document declares no security scheme, so it says nothing about a
key's scope, and it has no "who am I" operation: the only call that is not about a site, a device or a client is
`GET /v1/info`, which returns the version. Third-party write-ups say a key has the permissions of the admin who made it
(https://artofwifi.net/blog/unifi-api-authentication-local-admin-vs-api-key-vs-site-manager); Ubiquiti's help article
(https://help.ui.com/hc/en-us/articles/30076656117655) describes making a key in the Network app under Integrations. So
there is no read-only key, and DaemonSight cannot check what a key may do. Test connection reads the version, sites,
devices and Wi-Fi list, reports "Connected. The key is accepted and can read.", and always shows that it cannot check the
key is read-only, that it never tries a write, and that the key should belong to a local admin with the View Only role.
It refuses a key that cannot read the sites or cannot read any of the devices and Wi-Fi networks, and a controller with
no sites.

**Secrets.** The Wi-Fi list carries only each network's security type. The detail of one network carries `passphrase`
and `presharedKeys` (the `...DetailDto` schemas in the document), and the whitelist never allows that path. The parser
copies named fields only, so a passphrase that did arrive in a list would be dropped; a test feeds one and checks it is in
no table. Clients are counted (`limit=0`) and never listed: a client's name, MAC and address are not read.

**Findings.** Each has a "What to do" list with the UI path, and an accept basis (what an acceptance is tied to, so the
finding returns as Changed when that changes).

| Rule | Severity | Raised when | Accept basis |
|------|----------|-------------|--------------|
| `unifi.fw_update` | low; medium once the hub has seen an update waiting for 30 days | any device has `firmwareUpdatable`; one finding for all, listing them | the set of devices and their firmware versions |
| `unifi.device_offline` | high for an access point or gateway, medium for other devices | state OFFLINE, CONNECTION_INTERRUPTED or ISOLATED for the offline setting or longer (2 hours by default, Settings, Remote systems) | the device |
| `unifi.pending_adoption` | medium | a device in `pending-devices` | the device's MAC |
| `unifi.wifi_open` | high | an enabled network with security type OPEN that is not a hotspot portal (a guest portal is open on purpose) | the network |
| `unifi.wifi_legacy` | medium | an enabled network with a WEP or original WPA type; the 11.0.97 enum lists neither, so this fires only if a controller reports one | the network |
| `unifi.gateway_forward` | medium | gateway sites only: an enabled ALLOW firewall policy from the External zone into another zone that UniFi did not define itself | the policy |

The API has no offline time, so the hub counts from its first sight of the state, or from the device's last heartbeat
when that is earlier, so an outage that began before the hub looked is dated correctly at the first poll.

**Updates and CVEs.** The core rule is that an update comes with the CVEs it fixes. For UniFi this cannot be done, and the
card says so. The API gives a flag (`firmwareUpdatable`) and no target version, so a pending update cannot be matched to
anything. Ubiquiti publishes its security advisories as "Security Advisory Bulletins" posts on community.ui.com, with no
feed or API to read them from, and releases at https://community.ui.com/releases. CVE.org holds records for the Network
Application (with version ranges), but there is no list to discover them from and nothing maps a device's firmware to one.
So DaemonSight does not guess a mapping, does not rank anything with `cve/priority.py`, and invents no CVE. The Overview's
Firmware updates card lists the devices with an update waiting, links the release notes and states that Ubiquiti
publishes no machine-readable advisory data; its (i) panel gives the reasons and the CISA BOD 26-04 entries a mapping
would use (network devices count as exposed). A follow-up could match the Network Application's own version against its
CVE.org records, which would cover the controller and not the devices.

**What the API does not give.** There is no latest controller version, so there is no "controller is out of date"
finding and the page says it cannot tell. There is no NAT or port-forward operation, so the gateway rule reads firewall
policies and the page says it lists no port forwards. There is no target firmware version (above). Unsupported-device,
WPA3-only and WAN-down findings were left out: the first two are not requested and WAN-down needs an endpoint this
version's document does not list for it.

**Pages.** Overview (findings, a Firmware updates card, at a glance, recent changes), Devices (controller and sites,
devices, devices waiting for adoption, gateway firewall), Wi-Fi (networks with security type, bands and guest portal) and
Report. Each table has (i) panels naming the GET request with a `$KEY` placeholder; Manage on the Hosts page opens the
edit page.

**TLS.** UniFi OS presents a self-signed certificate unless one is installed, so the certificate pin applies as for the
other systems.

**Unverified.** Nothing here has been run against a controller; replies are synthetic, in the shape of the 11.0.97
document. Only a live controller can confirm: that a View Only admin can create an Integrations key at all, and that its
key can read everything above and cannot write; what `statistics/latest` returns for an offline device (the heartbeat
dating depends on it); the name of the zone for the internet ("External") and whether the policies UniFi makes for a port
forward appear as ALLOW policies from it; the menu names used in the how-tos (Admins, Integrations, Devices, Settings, WiFi,
Policy Table), taken from Ubiquiti's help pages and the app; the port and address of a standalone self-hosted Network
application (only UniFi OS consoles and UniFi OS Server are assumed); and whether the 10.x controllers the owner runs serve
every endpoint of the 11.0.97 document.

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
trust anchor [35]. It also sets OpenSSL's `X509_V_FLAG_NO_CHECK_TIME` (0x200000
in `include/openssl/x509_vfy.h`; Python's `ssl` has no name for it but passes
`verify_flags` to OpenSSL unchanged), so an expired pinned certificate is still
trusted: the pin names the certificate, and an appliance's self-signed one
often expires unnoticed (found on an OPNsense firewall). The `verify` mode keeps
the date check. Host-name checking is off in that mode, since the pin, not
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
a real Unraid server with a large container count):

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
  Every running container had reported by the end of the first tick.
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

Cost, measured against a large Unraid server (about a hundred containers; one
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

### Docker reader

Unraid's GraphQL API lists containers but not Docker's images, volumes or build cache. On the server this was built for,
45 of 136 images were unused (40.6 GB), 646 of 667 volumes were unused (32.6 GB) and the build cache was 16.4 GB. The hub
gets those figures from a second process, `daemonsight docker-reader`, run from the same image as its own container.
Nothing here deletes anything; the findings give the command and the person runs it.

Data flow:

```
 Docker daemon          Docker reader container                hub container
 ┌────────────┐  unix   ┌───────────────────────┐  HTTP, bearer ┌───────────────────────┐
 │ Engine API │ socket  │ docker_reader.py      │  token, over  │ remote/poll.py        │
 │ (root)     │◄────────┤ GET only, fixed       │  the network  │  every 10 min at most │
 │            │  GET    │ targets, no inspect   │  `daemonsight`│ GET /v1/summary       │
 └────────────┘         │ serves /v1/summary    │◄──────────────┤ snapshot              │
                        │ and /v1/health only   │   JSON        │ unraid_docker_storage │
                        │ publishes no port     │               │  ─► docker.* findings │
                        └───────────────────────┘               └───────────────────────┘
```

**The reader is not a proxy.** It serves two routes, `GET /v1/summary` and `GET /v1/health`, both behind a bearer token.
No path, query or body of the caller's is passed to Docker. The summary is computed in the reader from the reads below and
cut to the fields listed here, so the hub cannot ask Docker anything else. FastAPI's docs and OpenAPI routes are off, and
there is no request log.

**What the reader asks Docker.** `docker_reader.Docker.get` sends GET, over the unix socket, to a fixed list, compared as a
whole string (a test tries about 25 near misses). `/_ping` and `/version` are unversioned; every other path carries the
version prefix, the lower of the daemon's `ApiVersion` and 1.54, the newest version whose reference was read. All
citations are the Engine API reference, https://docs.docker.com/reference/api/engine/version/v1.54/ (its swagger file is
https://docs.docker.com/reference/api/engine/version/v1.54.yaml).

| Target | Operation (swagger id) | Used for |
|--------|------------------------|----------|
| `GET /_ping` | Ping (SystemPing) | `/v1/health`: Docker answers `OK` |
| `GET /version` | Get version (SystemVersion) | `ApiVersion`, `MinAPIVersion`, `Version` |
| `GET /containers/json?all=1` | List containers (ContainerList); `all`: "Return all containers. By default, only running containers are shown" | `Names`, `Image`, `ImageID`, `State`, and the names of `volume` mounts from `Mounts` |
| `GET /images/json?all=0&digests=1` | List Images (ImageList); `all`: "Only images from a final layer (no children) are shown by default"; `digests`: "Show digest information as a `RepoDigests` field" | `Id`, `RepoTags`, `RepoDigests`, `Created`, `Size`, `Labels` |
| `GET /images/{id}/json` | Inspect an image (ImageInspect), for an image no container uses, and only with a `sha256:` id of 64 hex digits | `Metadata.LastTagTime`, `Config.Labels` |
| `GET /volumes` | List volumes (VolumeList) | `Name`, `Driver`, `CreatedAt`, `Labels` |
| `GET /system/df?verbose=1` | Get data usage information (SystemDataUsage); `verbose`: "Show detailed information on space usage" | volume `UsageData` (`Size`, `RefCount`); build cache `TotalCount` and `TotalSize` (from API 1.52; before it `Volumes` and `BuildCache` arrays, which are read too) |
| `GET /containers/{id}/archive?path=<p>` | Get an archive of a filesystem resource in a container (ContainerArchive; "Get a tar archive of a resource in the filesystem of container id"; produces `application/x-tar`) | One file per read, only for the four paths below, with the container's 64-hex id |

Why `all=0` and not `all=1`: with `all=0` the list already has dangling images (untagged leaves, the ones `docker image
prune` removes). `all=1` adds the intermediate layers of builds, which nobody can remove on their own and which would show
up as unused images. `digests=1` is needed because an untagged image keeps its `repo@sha256:` names only in `RepoDigests`,
and the hint for a superseded image reads the repository from there.

Never called: `/containers/{id}/json` (inspect), because it returns each container's `Config.Env`, where passwords live.
A fake engine in the tests puts `Env`, `Cmd` and a secret label where the real Docker has them and a test checks none of it
comes out of the reader. The image inspect reply has `Config.Env`, `Cmd` and `Entrypoint` too; they are dropped as the reply
arrives and never stored, logged or sent.

`/system/df` is very slow on a loaded server (a read of `docker system df -v` on the first server did not finish in 15
minutes), so it never runs inside a request. A background task in the reader runs it, then waits 30 minutes from the end of
the read before the next. The summary is answered at once from what is cached and carries `df_at` (when the sizes were read;
null until the first read ends), `df_running` and `df_error`. A volume's reference count comes from the containers' mounts
until df is read, so unused volumes are known straight away and only their sizes wait. A failed df read keeps the last good one.

**Fields kept.** Anything else Docker returns is dropped in the reader, and the hub trims the reply again.

- Images: `id`, `tags`, `digests`, `created`, `size`, `last_tag` (from `Metadata.LastTagTime`; Docker uses
  `0001-01-01T00:00:00Z` for "never", seen live on pulled images, so that is null), `labels` (only keys starting
  `org.opencontainers.image.` or `net.unraid.`, values cut to 200 characters; an image with no labels has null, seen live) and
  `in_use`. `last_tag` is read only for unused images.
- Containers: `name`, `image`, `image_id`, `state`.
- Volumes: `name`, `created`, `driver`, `labels` (only `com.docker.compose.`), `anonymous` (the label
  `com.docker.volume.anonymous`, which Docker sets on an anonymous volume, seen live, or a 64-hex name), `size`, `refs`.
- Build cache: `count` and `size`. Also `images_reclaimable` when df has it, the Docker `version` and `api`.

**Auth.** A bearer token, required on both routes, compared in constant time (`hmac.compare_digest` over the SHA-256 of each
side, so the length is not leaked either). A wrong or missing token costs a quarter second and gets a 401; the request never
reaches Docker. The token comes from a file (`--token-file`): the reader refuses to start unless it is a regular file, not
a symlink, with no access for group or others (0600), and at least 32 printable characters. It is never an environment
variable, an argument, a log line or a page. The hub keeps its copy in `<data>/remotes/<id>.reader-token` (0600, in the
0700 folder, written atomically, backed up with the keys, deleted with the system).

**Network.** The reader publishes no port. It and the hub are on a user-defined bridge network, created once with
`docker network create daemonsight`. On a user-defined bridge, "containers can resolve each other by name or alias" and the
network "supports port publishing", so the hub keeps its published port while it reaches the reader as
`http://daemonsight-docker-reader:8467` (https://docs.docker.com/engine/network/drivers/bridge/). The link is plain http,
so the token travels in clear on that network; only the two containers are on it. The hub's client (`Net.reader`) follows
no redirects and ignores proxy settings from the environment.

**Hub side.**

- The Unraid system's Add and Edit form has an optional "Read images and volumes" checkbox. Ticked, it shows (indented under
  it, `data-ds-when`, the same form and Save) the reader's address and token, and a Test reader button that calls
  `/v1/health` and shows the Docker version and API version. The saved token is never shown back: a badge says one is saved.
  Unticking and saving deletes the token file and the stored data. Schema 9 adds `remotes.reader_url`.
- The poll (`remote/poll.py`, `read_docker_storage`) reads `/v1/summary` on the system's interval but at most every 10
  minutes, and stores it as the snapshot `unraid_docker_storage` (volumes cut to the unused ones plus counts). A failed read
  keeps the last data and shows its error on the page; it never fails the poll, as with the container statistics.
- `remote/docker_storage.py` has the hints and the findings (rules `docker.*`, listed under "Findings").
- The page is its own tab, Docker storage (`/docker`): it would double the length of the Containers page, which already has
  every container, and it has three cards of its own (Unused images, Unused volumes, Build cache), registered in
  `web/sections.py`. Each card has a source (i) panel with the reader endpoint, the Docker calls behind it and the matching
  `docker` command. Every row has a status word (the existing Unexpected, Accepted, Changed labels: a row takes its finding's
  status) and its own panel with the command to look at it and to remove it, and the panel's Accept form accepts the
  finding. Images are listed up to 150 and volumes up to 100, largest first; the findings count all of them.

**Where an image came from.** Docker does not record who pulled an image or why, so the hint is a guess, shown as text. In
order, the first match wins, and every row also shows when the image arrived: `LastTagTime`, else `Created` (the build date,
which can be long before the pull), labelled "tagged" or "built".

1. Superseded: the image has no tag and an image from the same repository that a container uses is newer. The repository is
   the name in `RepoDigests` (an untagged image keeps those), or the same `org.opencontainers.image.source` label. "old
   version of X left by an update; safe to remove".
2. Removed app: the hub once saw an Unraid-managed container (`isOrphaned` false, which the schema says is "no template
   found") run this repository and none uses it now. "app X was removed from Unraid; its template may still be there". The
   Unraid API lists a template only through a container that has it (`DockerContainer.templatePath`; there is no list of
   templates in `api/generated-schema.graphql`) and the reader cannot see `/boot` where `dockerMan/templates-user` lives, so a
   template whose container is gone cannot be read. The hub remembers the apps it has seen (`apps_seen`, up to 300) and calls
   an image "removed" only for those, so this hint appears only for apps removed after the hub began watching. It does not
   check that the template is still there; the text says "may".
3. Source label: "from" the `org.opencontainers.image.source` value, as given.
4. Bare base image (debian, ubuntu, fedora, alpine, python, node and a few more) with no container and no remembered app:
   "base image, probably pulled for a build or a test".
5. "no hint".

Volumes: in use or not (a container, running or not, mounts it), anonymous or named, and the compose project label when
present. An unused anonymous volume's hint is "left by a container that was removed"; a named one from a compose project
says so.

Sizes: Docker's `Size` for an image counts every layer, including ones shared with other images, so the total of unused
images is more than removing them would free (`ImagesDiskUsage.Reclaimable` is the better figure and is kept when df has
it). The page says so.

**Not built: VM statistics.** Unraid's API gives a VM's name and state only. CPU and memory for VMs could come from libvirt's
read-only connection, `virsh -r domstats`. That is unverified: the command, its fields and whether a container can reach the
libvirt socket were not checked, so it is not built and is not a promise.

**Verified on the real server** (read-only commands over ssh, shapes and counts only): `docker version` gave Engine API 1.54.
`docker image ls --no-trunc --format json` has `ID`, `Repository`, `Tag`, `Digest`, `Size`, `CreatedAt`, `Containers`; it listed
109 images, none untagged, 17 with no container. `docker image inspect --format` gave `Metadata.LastTagTime` as the zero time
(`0001-01-01T00:00:00Z`) on pulled images and `Config.Labels` as null on an image with none. `docker volume ls --format json`
listed 667 volumes (653 with a 64-hex name), each with `Name`, `Driver`, `Labels` (an anonymous volume has
`com.docker.volume.anonymous=`) and `Size` "N/A". `docker system df -v --format json` took 16 minutes 43 seconds on this loaded
server (an earlier try was cut off at 15 minutes), which is why the reader runs it in the background. It listed 142 images (34
untagged, which `docker image ls` does not show: they are the intermediate layers that `all=0` leaves out, so the unused count on
the page is lower than a count of every image with no container), 667 volumes (646 with no link, 20 with one, one with three)
and 236 build cache records, none in use. That is the CLI's own formatting of the data, not the Engine API's JSON.

Not verified: the exact requests on the wire against this daemon, and the JSON shape of `/system/df?verbose=1` from API 1.52 on,
which is read from the reference and tested against a fake engine only; what group Unraid's `/var/run/docker.sock` has;
that `--group-add` with a name that does not exist stops the container from starting (it is meant to); and whether this
Unraid version's hub template offers "Additional Networks".

### Container images (phase 3c, part 1)

Which images the containers run, what operating system and packages each holds, whether that base still gets security
updates and which Debian packages have CVEs an update fixes. Sources: https://docs.docker.com/reference/api/engine/version/v1.54.yaml
(`GET /containers/{id}/archive`, operationId ContainerArchive; its sibling `PUT` is PutContainerArchive, "Extract an archive of
files or folders to a directory in a container", and `HEAD` is ContainerArchiveInfo; neither is ever sent).

**Reading the lists** (`docker_reader.py`, `docker_packages.py`).

- Four paths, fixed in code and URL-encoded: `/usr/lib/os-release`, `/etc/os-release` (a symlink to the first on most images;
  an archive of a symlink holds the link, which is not followed, so the first is read first), `/var/lib/dpkg/status` (Debian,
  Ubuntu) and `/lib/apk/db/installed` (Alpine). The id must be 64 hex digits. `Docker.check_allowed` takes the method as well
  and refuses anything but GET.
- The tar reply is read from memory with `tarfile` in streaming mode (`r|`): one member, a regular file, within the cap (64 KB
  os-release, 16 MB dpkg, 4 MB apk), nothing written to disk. A link, a directory, a second member, a gzip stream or a cut
  stream is refused with a short message.
- os-release gives `ID`, `ID_LIKE`, `VERSION_ID`, `VERSION_CODENAME`, `PRETTY_NAME`. dpkg status: only stanzas whose `Status` is
  exactly `install ok installed` (`deinstall ok installed` is not), with `Package`, `Version`, `Source` and its optional
  version in parentheses (`Source: brotli (1.0.9-2)`: the tracker is keyed by the source name and that version, which differ
  from the binary's after a rebuild such as `1.0.9-2+b6`) and `Architecture` (a package present for two architectures is one
  entry). apk: `P:` name, `V:` version, `o:` origin. A package is `[name, source, version, source version]` with the last two
  left empty when they equal the first and third; at most 4,000 per image.
- An OS with neither dpkg nor apk (CentOS, Void, Arch) says "packages not read: <name> does not use dpkg or apk" and is never
  read again. An image with no package database (distroless) says so and is tried again after 30 minutes, as is any read that
  failed.
- Per image, not per container: the first running container by name is read once and kept by image id in the reader's memory;
  a new image id (an update) reads again. Images only stopped containers use are "not read: stopped". A background task reads at
  most 10 images per minute, so the first full pass over about a hundred images takes ten minutes and a loaded server is never
  asked for much at once. The summary carries `image_packages` for every image a container uses, with `read_at`, `os`,
  `manager`, `count`, `packages` and `error`; "not read yet" marks one still waiting. The summary keeps `v: 1`: an older hub
  ignores the field, and a newer hub with an older reader shows "does not send package lists yet". Memory: the reply and its
  parsed text are held at once, a few tens of MB for a 16 MB file, inside the template's 256 MB limit.

**Base OS and end of life** (`remote/docker_images.py`, `distro.evaluate_image`). The same code path as hosts: Debian, Ubuntu and
Fedora go through `distro.evaluate` (distro-info data, Fedora's endoflife.date copy). Alpine and CentOS Linux read
endoflife.date's data, bundled in `data/endoflife/` (https://endoflife.date/api/v1/products/alpine-linux/ and `.../centos/`;
the address `.../alpine/` redirects to `alpine-linux`, the product name this uses). Alpine's cycle is the first two parts of
`VERSION_ID` (3.17.2 is 3.17); CentOS Stream shares `ID=centos` and is not judged; a release the data does not list is
"unknown", never "supported". Finding `docker.eol_base` (Medium, one for the system, key `all`): every image whose status is
`eol`, or `ended` (Debian past LTS: only paid ELTS covers it). An image on Debian LTS or Ubuntu ESM still gets some updates,
so the page shows it in yellow and the finding does not count it. The basis is the set of image repositories and release names
(`nginx@Debian 10`), with no dates and no patch versions, so an acceptance stays until the set changes.

**Debian CVEs** (`cve/run.py`, `cve/match.py`, `docker_images.py`). The CVE chore matches each Debian image like a host: a
pseudo inventory (source packages with their source versions and binary names) under the id `docker:<system>:<image id, 16
hex>`, which cannot collide with a host id (no colons there). The release comes from the codename, or from `VERSION_ID` through
Debian's release data when the codename is absent; Raspberry Pi OS counts as Debian; a Debian derivative with its own id is
"not matched". The chore loads the tracker for the images' releases as well as the hosts', and keeps their rows in the same
`match` table. Kernel sources are skipped without a kernel image, as for a host, so `linux-libc-dev` raises nothing. At each poll
the hub reads those rows (`load_cves`) and `docker.image_cves` is evaluated with the Unraid rules: no schema change.

One finding per image, key the image's name (the tag a container uses, else the image's first tag), linked to its row on the
Container images page.

- The severity is the worst fixable CVE's by CISA BOD 26-04 (see "Prioritisation"), the image's exposure being decided from the
  published ports and the firewall's forwards. Title: `nginx:1.27 (Debian 12): 3 fixable CVEs, 1 known exploited; fix within 14 days`.
- Only a CVE the tracker lists as fixed in a newer version counts (a host's `fix` state). CVEs with no fix yet are counted on
  the page as information and raise nothing, because updating the image cannot fix them; this differs from a host's
  `cve.package`, which also counts an unfixed KEV CVE since a host's owner can mitigate it. "Minor" and "being assessed"
  rows are not counted.
- The basis is the image repository and the sorted ids of the fixable CVEs: an accepted finding stays through a rebuilt image
  with the same CVEs and returns as Changed when the set changes.
- Fix: update the image (Unraid: Docker tab, Check for Updates, apply; or pull a newer tag). `apt upgrade` inside a container
  does not persist. If no newer image exists, the maintainer has not rebuilt it.
- Ubuntu images are matched against Canonical's OVAL data (see "CVE matching: Ubuntu"): the same finding and ranking, "Ubuntu
  priority" in the text, and a fix that exists only in Ubuntu Pro's ESM archives is counted and shown apart ("fixed only in Ubuntu Pro
  (ESM)") and never raised, since an image has no Pro. Alpine images are matched against Alpine's security database (a later subsection).
- A release the tracker no longer lists has no rows, so an end-of-life Debian image may show no CVEs; the end-of-life finding
  covers it.

**The page.** Its own tab, Container images (`/images`), because the Docker storage page already lists up to 250 rows and this
one has a row per image in use. Cards: Images in use (a sentence, then a table: image, base OS, support, packages, fixable CVEs
with a KEV badge, the worst CVE's "Fix within" deadline and the top EPSS probability, status; the status label is the image's finding's, Accepted rows stay visible) and What
is checked (counts: read, Debian matched, Ubuntu matched, Alpine, other OS, stopped, waiting, failed). Each row's (i) panel names the
reader endpoint, the Docker call and the equivalent command: `docker cp -L <container>:/var/lib/dpkg/status - | tar -xO`.
Registered in `web/sections.py`. The Overview's glance has a line for it.

Not verified: the exact bytes Docker 29 sends for a one-file archive and for a symlink on a live server (the tests build
the tar with Python's `tarfile`; the swagger file only says the reply is a tar stream), and that a reader on a large
Unraid server finishes its first pass in ten minutes.

### CVE matching: Alpine images (phase 3c, part 2)

Alpine images are matched against Alpine's security database, "secdb" [61]. The hub downloads it, as it does the other feeds; an
image's reader sends only the package list it already sends.

**What secdb is** (read from the files on 2026-11-24 [61]).

- `https://secdb.alpinelinux.org/` lists `edge/` and one directory per release, `v3.2/` to `v3.24/`, plus `last-update` (a Unix
  time, 11 bytes) and `license.txt`. A release has `main.json` and `community.json` (and the same as YAML). `edge/main.json`
  exists; `v3.1/` and `v3.99/` answer 404.
- The shape: an object with `reponame`, `distroversion`, `archs`, `urlprefix`, `apkurl` and `packages`, a list of objects
  each holding one `pkg` with a `name` and `secfixes`, a mapping of a version to a list of entries (strings). v3.23's `main.json`
  has 285 packages and is 99 KB; `community.json` has 461 and is 167 KB.
- `name` is the origin (source) package. `openssl` is listed and `libcrypto3` and `libssl3` are not, and `docker_packages.py`
  keeps each package's `o:` origin from the installed database, so a package is looked up by its origin.
- A key is the version that fixed the CVEs under it, in apk's version format (`3.5.4-r0`). A CVE is open for an installed
  version below it.
- The key `"0"` is not a version. In v3.23, 32 packages in `main` and 16 in `community` have one. The Alpine maintainers write
  the CVEs that never affected their package there; this is a habit, not a documented rule. Alpine's apk-tools list answered
  the question "all false-positive CVEs are listed with the version 0?" with "it has become somewhat a norm to mark them as 0"
  and added that the proper place is the `security-rejections` repository [62]. The APKBUILD manual has no entry for `secfixes` [62].
  Those entries are ignored. Two CVEs (postgresql17 and 18, CVE-2026-14681) are under `"0"` and also under a fixed version; the
  fixed version still counts.
- An entry is a string and may carry text after the id: `"CVE-2021-27219 GHSL-2021-045"`, `"CVE-2020-11501 GNUTLS-SA-2020-03-31"`
  (378 of 3,932 entries in `main`, 22 of 7,347 in `community`). The first word is the id. Entries whose first word is not a CVE id
  (`ALPINE-13661`, `ZDI-CAN-22300`, `GHSA-...`, `RUSTSEC-...`; 21 and 25) cannot be ranked by KEV or EPSS and are dropped.
- The same CVE can sit under several versions of one package (`intel-ucode`, `cacti`: 13 and 44 cases), a partial fix and then the
  rest. The highest version is used: the installed one has to reach it.
- There is no list of CVEs without a fix: secdb records fixes only. An Alpine image has fixable CVEs and no unfixed count, and the
  page says so.
- Updates: the files change when maintainers push `secfixes` data. On 2026-11-24 v3.23's `main.json` was modified 01:45 UTC and
  its `community.json` six days earlier, v3.12's in September 2025, and `last-update` at 03:34. No schedule is published that I
  found. Each file has `ETag` and `Last-Modified`.
- Licence: the site's `license.txt` is Creative Commons Attribution-ShareAlike 4.0 International. DaemonSight downloads the
  files, keeps the rows it needs to match and republishes nothing, and the Vulnerabilities page names the source. I read no
  usage terms beyond that file (the project README at gitlab.alpinelinux.org/alpine/security/secdb was not reachable from here).

**Fetching** (`cve/feeds.py`, `cve/run.py`). For each Alpine release the hub's images run (`v` plus major.minor of `VERSION_ID`,
3.23.2 is `v3.23`) it fetches `main.json` and `community.json` from `secdb.alpinelinux.org` only, with `If-None-Match` and
`If-Modified-Since`, at most once per `[cve] refresh_hours` (24) per file and an hour after an error. A download is capped at 20 MB
(the real files are 0.1 to 0.2 MB), kept under `<data_dir>/cve/alpine-<release>-<repo>.json.gz` and loaded into the `apk` table of
`cve.db` (schema 2 then, 3 since the OPNsense changelog tables; an older hub refuses a newer `cve.db`, which can be deleted and downloaded again) in one transaction per
file. A failure (HTTP error, bad file, a version that does not parse) keeps the last good rows and the page shows
"The last download failed (...); the copy from the earlier download is used". A release that no image runs any more is dropped:
its rows, saved files and feed rows. HTTP 404 is an answer, not an error: the feed row says "absent", the page says "Alpine 3.x: not in
Alpine's security database" and nothing is matched or raised for that release. An image whose `VERSION_ID` is not a plain
release number (an edge image has `3.24.0_alpha...`) is "Release not named (edge?): not matched"; secdb has an `edge/`
directory, but how an edge image names its snapshot was not checked, so it is not mapped. The Vulnerabilities page's Data feeds
card lists each file.

**Matching** (`cve/alpine.py`, `remote/docker_images.py`). Under the pseudo-host `docker:<system>:<image id>` (as for Debian) an
Alpine image's packages are grouped by origin (`o:`, or the package's own name). One installed version per origin: when
subpackages differ, the lowest is used and the row says so ("1 origin has subpackages at different versions, matched at the
lowest (openssl)"). A version apk cannot parse is skipped and counted. A CVE is "fixable" when secdb lists a fixed version for
that origin and the installed version is lower; the highest fixed version of the CVE counts. The rows go into the same `match`
table (`source` is the origin, `state` is `fix`, `fixed` the version), so KEV and EPSS ranking, `cve_summary` and
`docker.image_cves` work unchanged. Severity is the Debian images' rule: the worst fixable CVE's by CISA BOD 26-04. The finding's title says the release (`web (Alpine 3.23): 4 fixable CVEs, 1 known exploited`),
its detail says "Alpine's security database (secdb)", its fix says `apk upgrade` inside a container does not persist, and its
basis stays the image repository and the sorted ids of the fixable CVEs. The matched rows are redone when any of the secdb files
changed. CVE descriptions come from the Debian tracker's text, so an Alpine-only CVE has none.

**Version order** is `cve/apkver.py`, written from apk-tools' `src/version.c` [63]: a number, more
numbers after dots, an optional letter, any `_suffix` with optional digits, an optional `~` and hex digits, and an optional `-r` and digits; a number with a leading zero is compared as text; suffixes order `_alpha` < `_beta` < `_pre` < `_rc` < none < `_cvs`
< `_svn` < `_git` < `_hg` < `_p`; a version that does not parse is compared as far as it does, as apk does. It was read at apk-tools
v3.0.9 (commit `f419028ee18aabcfb405400f899572fb0a949331`, 2026-11-02, the apk-tools of Alpine 3.23: `main/apk-tools/APKBUILD` on
`3.23-stable` has `pkgver=3.0.9`); `src/version.c` is identical at v3.0.10 and at master (`c7b05e07`, 2026-11-23), with `apk_blob_pull_uint` and
`apk_blob_sort` from `src/blob.c` and the character classes from `src/ctype.c`. The test is apk-tools' own table, `test/unit/version.data` at that
commit, copied to `tests/fixtures/cve/apk-version.data` (792 lines with comments and blanks; the 16 with `~` as an operator are apk's fuzzy dependency match
and are skipped): all the rest pass, among them the 18446744073709551615 and 18446744073709551616 limits and the invalid versions. apk-tools is
GPL-2.0-only, DaemonSight MIT: the Python is written from the rules, not copied from the C, and the table is data kept unchanged under a header
that names its source. apk-tools 2.x (v2.14.13) has other code for the same job (leading zeros count as a negative number, no `~hash`
token); the 3.x rules are used, and whether 2.x orders any version differently beyond leading zeros was not checked.

**The page.** The Fixable CVEs cell shows the count with the KEV badge and the top EPSS score; there is no "no fix yet" line. The
coverage card says how many Alpine images were matched and, per release, when secdb was last checked or why it was not. The (i)
panel of an image names the secdb files, the matching `curl ... | jq` lookup for the top origin, the container's own
`apk version -l '<'` (lists packages whose installed version is lower than the index's, per apk-version(8); `apk list --upgradable`
lists the same, per apk-list(8) [64]; both need a package index, and `apk update` inside the container writes only there) and
`apk version -t <a> <b>` to compare two versions. Each CVE links to `https://security.alpinelinux.org/vuln/<CVE>` [65].

Not verified: the whole path on a live hub with a real Alpine container (tested against synthetic secdb files and a fake of the
server, and the parser against the real v3.23 files on 2026-11-24, not a running hub); how an Alpine edge image's `VERSION_ID`
looks; that `apk version -l '<'` inside a stock image prints what the page suggests without `apk update`; the secdb project's own README.

### Collector hosts: image CVEs

A Linux server with a collector (not an Unraid system) gets the same image checks as the Docker reader gives an Unraid system: each
running container's image is read for its OS and packages, matched like a host, and `docker.image_cves` is raised with the Unraid
wording, how-tos, deadlines and held/resolve rules. The collector reads from the same engine API the Docker source already uses.
Sources: https://docs.docker.com/reference/api/engine/version/v1.54.yaml [105] (`GET /containers/{id}/archive`, ContainerArchive: a
tar stream, 404 when the path is missing; `GET /containers/json?all=1`, ContainerList). The `PUT` of the archive URL
(PutContainerArchive, which writes into a container) and its `HEAD` are never sent.

**On the collector** (`collector/sources/docker_images.py`).

- A source named `docker_images`, built only when `[upload]` has a URL (a host with no hub has nothing to send the lists to). It
  reuses `docker_reader.Docker` (GET only, the fixed target list, capped replies) and `docker_packages` (the four paths, the
  caps and the dpkg and apk parsers), so the paths read and the limits are the Docker reader's, described under "Container images
  (phase 3c, part 1)". Nothing is written to disk.
- Per image id, not per container: the first running container by name is read; the result is cached by image id. A read
  that worked is kept until the image id changes. An OS without dpkg or apk is also kept ("does not use dpkg or apk"). Any other
  failure (a distroless image with no database, a Docker error) is tried again after 30 minutes. At most 10 images are read per look
  (`interval_docker_images`, 300 s), so the first pass over 25 images takes three looks. An image only stopped containers use is
  "not read: stopped": Docker can also archive a stopped container, but that was not tried, so it is not used. The cache is
  restored from the collector's last stored snapshot at start, so a collector restart reads nothing again.
- Off switch: `[collector] docker_read_packages = false`. The source then reports "unavailable" and the hub shows the reason.
  With no Docker socket the same. `docker_socket` is the one the Docker source uses.
- The payload is a top-level field `docker_images` of the upload (not a snapshot): `v`, `engine`, `containers`
  (name, image, image id, state), `images` (id, tags, digests) and `image_packages`, one entry per image id with `os`, `manager`,
  `count`, `packages`, `error`, `read_at` and `hash`. An older hub ignores the unknown field; a hub that cannot read it drops it
  and still stores the rest of the upload (the field is wrapped, so a bad field is a warning, not a 422).
- What goes on the wire (`collector/upload.py`). A package list is sent only when the image id's `hash` (sha256 of
  os, manager, count and packages, cut to 32 hex digits) differs from the last hash the hub accepted, when the hub asked for the
  list (below), or once a day. Otherwise the entry carries the hash and count with an empty list. When nothing changed since the
  last accepted upload the field is left out. The sent hashes are saved only after the hub answered 200, so an upload the hub
  did not take is sent again in full.

**On the hub** (`hub.py`).

- Checked as strictly as the rest of the upload: an image id must be `sha256:` and 64 lower-case hex digits; a package is four
  printable strings (name, source, version, source version) cut to 100 characters, the name not empty; the manager is `dpkg` or
  `apk`; at most 4,000 packages per image, 40,000 per upload, 1,000 image entries, 3,000 images, 2,000 containers; an image id
  sent twice, NaN and infinity are refused. An unreadable field is dropped with a warning. A collector can not send it as a
  snapshot (`docker_images` is not an accepted source name) and can not send a `docker.*` finding (those are the hub's
  rules: `HUB_RULES`).
- Stored as the snapshot `docker_images` for the host, in the Unraid summary's shape (`image_packages`, `containers`, `images`),
  with `source: "collector"`. A hash-only entry takes the list the hub already holds when both the image id and the hash
  match. If they do not (the hub lost the list, or its copy is of another version), the entry is stored as "not read yet"
  and the reply to the upload carries `docker_images_resend`: the image ids to send in full (at most 100; the collector honours
  an id at most once every 10 minutes). "Not read yet" and "not read: stopped" carry the last good read of that image id
  forward, marked `carried`, like `_carry_packages` does for an Unraid system's reader. A read that failed is stored as the
  failure it is.
- The CVE chore (`cve/run.py`) matches each Debian, Ubuntu and Alpine image under the pseudo-host
  `docker:<host>:<image id, 16 hex>`, next to the Unraid ones (the host id cannot hold a colon). It then evaluates each
  collector host's snapshot with `docker_images.evaluate(..., platform="host")` and sets that host's `docker.` findings
  (`_set_cve_findings`). `HUB_RULES` includes `docker.`, so an upload never reconciles those findings away.
- No flapping. A finding is kept open while its data is unknown: a collector restart or a hub restart (carry-forward and the
  stored snapshot), the CVE database being rebuilt (the `held` and `prior` rules the Unraid findings use), a hash the hub holds
  no list for. It resolves only when a read shows the CVEs fixed or the image gone. Tests cover each case.
- Turning CVE matching off clears these findings.

**Exposure** (`cve/exposure.py`, `collector_image_exposures`). An image is rated for the exposure of the containers that run it
(the worst one counts). The reason is written into the finding's text under "Publicly exposed", and the rating follows CISA BOD
26-04's Table 1, which ranks a CVE higher when the product is internet-facing [83][84]. The rules run in this order:

1. A port published on loopback (127.0.0.1 or ::1) is not exposed by itself.
2. A port published on 0.0.0.0 or :: on a host with a publicly routable address (the `ports` snapshot's address list) is
   exposed, unless the provider's allow list (`[exposure] upstream_allow`) leaves the port out.
3. A port published on a specific public address is exposed.
4. A published port the firewall's forward leads to (`reach_by_listener`: an OPNsense port forward or a Caddy listener) is exposed
   when the binding is wide or one of the host's own addresses.
5. A container on the host network is judged by the listeners the collector reports as owned by its container id.
6. A Caddy site that proxies to the container is exposed when the site is open to the internet and Caddy itself is reachable. A
   site is open to the internet when it has no `allow` list, or an allow list with a public range (an allow list of private
   ranges only is "lan"). The site finds the container by a published port with a local upstream (`127.0.0.1`, `localhost`,
   `::1` or one of the host's own addresses) or, for Caddy in a container, by the container's name or its Compose service name.
   Caddy is reachable when it publishes a port on a public host, when a firewall forward leads to it, or when it listens on a
   public address that the host firewall does not block. This is the case that makes a container bound to 127.0.0.1 exposed
   behind a host Caddy site.
7. Unknown: no `ports` or `docker` snapshot, the container not found, or no bindings and a Caddy that was never read. Then the
   best-effort rule for hosts decides (`exposure.unknown`: a publicly routable host address is treated as public) and the text
   says the data is missing.
8. Otherwise not exposed, with the reasons: for example "it publishes 127.0.0.1:8080/tcp, which the internet cannot reach (loopback,
   a host with no public address, or blocked by the provider's allow list); no internet-facing Caddy site on this host proxies to
   it" or "the host has no Caddy". An image no running container uses is not exposed.

The Compose service name is taken from the container name `<project>-<service>-<number>`, which is the name Compose generates
by default; the project label comes from `com.docker.compose.project`. A container with its own `container_name` is found by that
name only. Sources for the Caddy data: https://caddyserver.com/docs/api [4].

**Payload numbers** (measured on the test fixtures, `tests/test_collector_images.py`: 30 images of 300 Debian packages each,
more than a typical image):

| Upload | Unpacked | Gzipped |
|---|---|---|
| First upload, 9,000 packages in full | 489,562 bytes | 38,515 bytes |
| Hashes only, 30 images, nothing changed | 14,544 bytes | 2,634 bytes |
| One image changed, 29 hashes and one list | not measured | 5,088 bytes |

The hub's cap on an upload is `max_upload_mb` = 8 gzipped and `max_unpacked_mb` = 48, so the first upload is under 0.5 percent of the
first and about 1 percent of the second. At the hub's own limit (40,000 packages) the field is about 2 MB unpacked. On the collector, the
cost is the Docker calls: two list reads each look, and one archive read per image that is new or changed.

**The page.** A collector host's Container images tab (`/h/<host>/images`, hub mode only) uses the same table, cells and coverage
card as an Unraid system's page (`web/image_views.py`, shared by both), with these differences: the source text says the lists come
from the collector, the (i) panel names the collector's read and a `docker compose pull` fix, there is no reader endpoint, and
an image of a collector that sent no lists (an older version) is listed from its Docker snapshot as "Not read" and "Not
checked", with a line saying the page needs the newer collector, so "not read" is never shown as "no CVEs".

Not verified: that Docker archives a stopped container's files (not used); Compose's default container name format `<project>-<service>-<number>`
(not checked against Compose's documentation or source; the
container_name entry of the services reference says only that the default is "a name generated by default"); how a real VPS with Caddy in a container and Docker's published ports
behaves next to the host firewall (Docker writes its own iptables rules for published ports); the whole path on a live hub and
collector (tested against a fake engine on a unix socket and the hub's test client).

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
- **Web port** is 8466. 8090 is common and was already taken on the test LXC.
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
- Ubuntu CVE matching: see "CVE matching: Ubuntu" (not run on a live hub with a real Ubuntu host or container; the Pro service files, the signed-kernel names and `pro fix --dry-run` were read from the Pro client's and the archive's files, not seen on a host).
- Alpine CVE matching: see "CVE matching: Alpine images" (not run on a live hub with a real Alpine container; edge images' `VERSION_ID` and `apk version -l '<'` output in a stock image were not seen).
- OPNsense update CVEs: see "OPNsense updates and CVEs" (the changelog files are real and the parser was run on all 317 release files; the whole path was not run on a live hub with a real firewall; the offered version of a hotfix in a real firmware status, the placement of out-of-band hotfix lines, and the Business Edition files were not checked). The advisory lookups: see "Security advisories in the changelog".
- CrowdSec: the read path was checked on a live firewall on 2026-11-24 (see "CrowdSec bans on an OPNsense firewall"). Still read from the source only: `null` for no decisions, `limit`, the 403 for a wrong key and the `duration` format. That the pf bouncer drops the states of a banned address is the owner's account, not read from its source.
- Whether the Docker source works against Podman's Docker-compatible socket.
- The Docker source on a real Docker host other than Unraid's.
- The systemd sandboxing in `daemonsight-web.service` inside an unprivileged LXC.
- Unraid: every query ran against one real server (7.3.2) with an Admin key, read-only, and the fixtures in `tests/fixtures/unraid/` are trimmed copies of those replies. Not seen on a real server: the `me` reply for a Viewer-only key (its shape is read from the API source and the Admin reply, not captured), a failing SMART disk, an array that is stopped, a UPS on battery, and a Viewer key being refused or accepted by each query. The first poll with a real Viewer key is the check.
- Unraid: the "how to use the API" page lists only the roles admin, connect and guest, while the schema and the CLI example (`--roles ADMIN,VIEWER`) have `VIEWER`; the Viewer role comes from the schema [33] and [32], and a Viewer key was not available to test.
- Unraid: whether the API gives a threshold for a disk with its own temperature setting, and the SSD thresholds (the schema has no field).
- Unraid: the notification, folder and release queries ran against the real server with an Admin key, read-only; a Viewer key reading `Notifications.list` and `Docker.organizer` was not tried. The release page was fetched without parameters and with `branch=stable`; its reply shape is what the fixture copies. Unverified: the exact label of the notification bell's "Archive all" (taken from the brief; the webgui source has no such string in the files searched), whether an acknowledged SMART attribute (the Dashboard's orange icon) still sends a notification when it changes again (the SMART docs say so), and that a history entry's `date` is the time the check ended (observed: it matches the finish notice within seconds).
- Unraid: the container statistics subscription ran against the real server with an Admin key, read-only (the handshake, the stream, the id format and its control-code prefix, `memUsage`). Not tried with a Viewer key: the source gives a Viewer `READ_ANY` on `DOCKER`, which the subscription needs, but no Viewer key was available. Run it once with a real Viewer key before relying on it. The cost on the Unraid side (`docker stats` started and stopped each sample) was not measured, and the figure for "no memory limit" assumes Docker reports the host's memory as the limit (seen here: 94.28 GiB on a server with that much RAM).
- Outside view: the whole chore against the real InternetDB from a real hub with real hosts (tests use a fake server with the documented reply shape, and the requests were checked by hand against documentation addresses and public ones); what an HTTP 429 from InternetDB looks like and whether it sends `Retry-After`; whether Shodan scans IPv6 widely; and the tag values beyond the 31 in Shodan's banner schema [56].
- Shodan API source: never run against the live API (no key was available; no request was sent to api.shodan.io). Unverified: the status code and body for a bad key, for an address Shodan has no information on, and for a free account's key (401, 403 and 404 are assumed from the official client's handling and from InternetDB); what a 429 looks like and whether it sends `Retry-After`; whether a full host lookup carries `product`, `version`, `cpe23` and `vulns` for every banner (the REST page's example shows none, the banner schema lists them as optional); whether the host reply has a top-level `vulns` (it is read if present, and banner `vulns` are read too); the biggest real reply (the cap is 4 MiB); whether the one-time Membership allows commercial use; and which plan name `api-info` returns for each plan. Run Test key and one real refresh with a real key before relying on it.
- Alert channels: see "What was not verified" under "Alerts, digests and reports (phase 4)". Nothing was sent to a real Ntfy, Slack, Discord or mail server; the owner's own channels are the first live test.

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
30. Ubuntu CVE data (OVAL "recommended"; the JSON API "still a work in progress"): https://ubuntu.com/security/cves/about and https://ubuntu.com/security/oval (chosen in "CVE matching: Ubuntu": [71] to [73])
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
59. CrowdSec Local API: `pkg/models/localapi_swagger.yaml` (`getDecisions`, `getDecisionsStream`, `Decision`, `securityDefinitions`), `pkg/apiserver/controllers/controller.go` (the `apiKeyAuth` and `jwtAuth` route groups), `controllers/v1/decisions.go` (`GetDecision`, `FormatDecisions`), `pkg/apiserver/middlewares/v1/api_key.go` (403 `access forbidden`, bouncers bound to an address), `pkg/database/decisions.go` and `decisionfilter.go` (`QueryDecisionWithFilter`, `applyDecisionFilter`), `pkg/types/ip.go`, `pkg/types/constants.go` (origins): https://github.com/crowdsecurity/crowdsec (`master`, read 2026-11-24)
60. CrowdSec docs: Local API authentication (bouncer keys "can only read decisions"): https://docs.crowdsec.net/docs/next/local_api/authentication ; centralized allowlists: https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists ; cscli: `bouncers add` (`cscli bouncers add MyBouncerName`), `decisions delete` (`-i`, `-r`), `decisions list` (`-i`, `-r`, `--origin`), `allowlists create` (`-d`), `allowlists add` (`-e`, `-d`), `alerts list` (`-i`), `alerts inspect` (`-d`): https://docs.crowdsec.net/docs/next/cscli/
61. Alpine security database (secdb): https://secdb.alpinelinux.org/ (index, `last-update`, `license.txt`: Creative Commons Attribution-ShareAlike 4.0), `v3.23/main.json`, `v3.23/community.json`, `edge/main.json`, `v3.9/*.json`; read and counted on 2026-11-24
62. The `"0"` key: Alpine apk-tools mailing list, "Question about secfixes in APKBUILD", 2024-11-16: https://lists.alpinelinux.org/~alpine/apk-tools/%3C20241116073528.75a751c2%40gmacedo.com%3E ; APKBUILD(5) of abuild, which has no `secfixes` entry: https://man.archlinux.org/man/extra/abuild/APKBUILD.5.en
63. apk-tools (GPL-2.0-only): `src/version.c`, `src/blob.c` (`apk_blob_pull_uint`, `apk_blob_sort`), `src/ctype.c`, `test/unit/version.data` and `test/unit/version_test.c` at tag v3.0.9 (commit f419028ee18aabcfb405400f899572fb0a949331), https://gitlab.alpinelinux.org/alpine/apk-tools ; the apk-tools version of Alpine 3.23: https://gitlab.alpinelinux.org/alpine/aports/-/blob/3.23-stable/main/apk-tools/APKBUILD (`pkgver=3.0.9`)
64. apk-version(8) (`--limit`/`-l` with `<`, `>`, `=`; `--test`/`-t`; `--check`/`-c`) and apk-list(8) (`--upgradable`/`-u`), `doc/apk-version.8.scd` and `doc/apk-list.8.scd` at apk-tools v3.0.9
65. Alpine Security Tracker, one CVE: https://security.alpinelinux.org/vuln/CVE-2021-42375 (answers only when the request accepts `text/html`, `application/json` or `application/ld+json`; otherwise 406)
66. OPNsense changelog repository (BSD 2-Clause): https://github.com/opnsense/changelog, its README (the file format), `LICENSE`, `Links/` (the URL of each footnote kind: `CVE`, `GHSA`, `FREEBSD-SA`), `Makefile`, and the files under `community/`, read 2026-11-24 (357 files, 24 series; contents API https://api.github.com/repos/opnsense/changelog/contents/community)
67. FreeBSD pkg, `libpkg/pkg_version.c` (`split_version`, `get_component`, `pkg_version_cmp`: `${PORTVERSION}[_${PORTREVISION}][,${PORTEPOCH}]`; the epoch, then the dotted version, then the revision): https://github.com/freebsd/pkg/blob/master/libpkg/pkg_version.c, read 2026-11-24
68. OPNsense core (BSD 2-Clause), read 2026-11-24 at master: `src/opnsense/mvc/app/controllers/OPNsense/Core/Api/FirmwareController.php` (`statusAction`, `infoAction` skipping development changelog items), `src/opnsense/scripts/firmware/latest.php` and `product.php` (`product_latest` is the newest changelog version of the installed series, with `_N` cut), `check.sh` (`upgrade_major_version` from `opnsense-update -vR`), `changelog.sh` (the firewall's signed `changelog.txz` from `opnsense-update -X`), `security.sh` (`pkg audit -F`), `src/opnsense/mvc/app/models/OPNsense/Core/Menu/Menu.xml` (System, Firmware: Status, Settings, Changelog, Updates, Plugins, Packages) and `views/OPNsense/Core/firmware.volt` ("Run an audit", Security): https://github.com/opnsense/core
69. OPNsense documentation, Community Edition releases: https://docs.opnsense.org/CE_releases.html (an index of series pages) and https://docs.opnsense.org/releases/CE_26.1.html (the same notes rendered, CVE footnotes linked to cve.org), read 2026-11-24
70. The repository archive as served: `https://codeload.github.com/opnsense/changelog/tar.gz/refs/heads/master` answered 200 with an `ETag` (627,386 bytes) and 304 for `If-None-Match`, tried 2026-11-24
71. Canonical's Ubuntu OVAL: https://ubuntu.com/security/oval (the "recommended" dataset; variants) and the files https://security-metadata.canonical.com/oval/ (`com.ubuntu.<codename>.cve.oval.xml.bz2`, `.pkg.`, `.usn.` and `noble.oci.` variants for `trusty` to `stonking`; `LICENSE`: Creative Commons Attribution-ShareAlike 4.0). Read 2026-11-24: noble 11,925,399 bytes (`last-modified` 2026-11-19 19:37:14 GMT, `etag` present, served by nginx behind a cache), focal 8,562,079 bytes; `If-None-Match` answers 304; the parser was run on both files in full
72. Ubuntu Security API and its page: https://ubuntu.com/security/cves/about ("still a work in progress and subject to change. Please don't use it in production environments or automations"); endpoints under https://ubuntu.com/security/cves.json and https://ubuntu.com/security/notices.json, tried 2026-11-24: pages of 20 to 96 CVEs, some queries answered 504
73. Ubuntu OSV data: https://security-metadata.canonical.com/osv/ (`osv-all.tar.xz`, 60.95 MB, modified 2026-11-24 06:14; the `LICENSE` is the same directory's); the OSV schema: https://ossf.github.io/osv-schema/
74. Canonical's OVAL generator, `oval_lib.py` and `generate-oval` in the ubuntu-cve-tracker repository (status mapping, the "might be affected and may need fixing" wording, the kernel and ESM pocket handling): https://git.launchpad.net/ubuntu-cve-tracker (read 2026-11-24; the file the published OVAL header names)
75. Ubuntu Pro client (GPL-3.0), `uaclient/apt.py`, `uaclient/entitlements/esm.py`, `enable.py` and `security.py`/`fix.py` (`--dry-run`, the repo file names and their removal on disable): https://github.com/canonical/ubuntu-pro-client ; its documentation of apt's ESM messages and `pro security-status`: https://documentation.ubuntu.com/pro-client/en/latest/ (read 2026-11-24 from the repository and the pages; not run on a host)
76. OPNsense core `src/opnsense/scripts/firmware/check.sh` at master, read 2026-11-24: `last_check=$(date)`, written into the JSON as `"last_check":"${last_check}"` (initial value `unknown`); `src/opnsense/mvc/app/controllers/OPNsense/Core/Api/FirmwareController.php` returns the check's JSON
77. FreeBSD `date(1)` (`bin/date/date.1`, "The format string for the default display is `%+`"), https://github.com/freebsd/freebsd-src/blob/main/bin/date/date.1, read 2026-11-24
78. FreeBSD libc `lib/libc/stdtime/timelocal.c`, C locale `date_fmt`: `"%a %b %e %H:%M:%S %Z %Y"`, read 2026-11-24
79. OPNsense core, read 2026-11-24: `src/opnsense/service/conf/actions.d/actions_firmware.conf` (`[poll]`: `command:/usr/local/opnsense/scripts/firmware/launcher.sh -r 1500 check`, `description:Firmware update check`), `src/opnsense/mvc/app/models/OPNsense/Cron/Cron.xml` (`command` is a `ConfigdActionsField`), `Base/FieldTypes/ConfigdActionsField.php` (lists actions by `description`), `Cron/Menu/Menu.xml` (System, Settings, Cron). The firewall's own cron list was not opened
80. FreeBSD security advisories, read 2026-11-24: https://www.freebsd.org/security/ (Security Advisory and Errata Notice as separate kinds), the index https://www.freebsd.org/security/advisories/, the feed https://www.freebsd.org/security/feed.xml, 21 advisories `https://www.freebsd.org/security/advisories/FreeBSD-SA-26:74.ktls.asc` to `26:94.tmpfs.asc` (`CVE Name:` in each; `security.freebsd.org/advisories/...` answers 301 to this address), `FreeBSD-EN-26:29.tzdata.asc` and `FreeBSD-EN-26:32.zfs.asc` (no CVE field), and VuXML https://vuxml.freebsd.org/freebsd/vuln.xml.bz2
81. GitHub REST API, read and called 2026-11-24 with no token: `GET /advisories/{ghsa_id}` (global advisories, 404 for OPNsense's) https://docs.github.com/en/rest/security-advisories/global-advisories, and `GET /repos/opnsense/core/security-advisories/{ghsa_id}` (200; "Anyone can access any published security advisory on a public repository") https://docs.github.com/en/rest/security-advisories/repository-advisories#get-a-repository-security-advisory
82. GitHub REST API rate limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api ("The primary rate limit for unauthenticated requests is 60 requests per hour"; 403 or 429 when exceeded, `x-ratelimit-remaining` 0, "should not retry your request until after the time specified by the `x-ratelimit-reset` header"; `retry-after` for a secondary limit)
83. CISA Binding Operational Directive 26-04, "Prioritizing Security Updates Based on Risk" (June 10, 2026; Table 1, the four variables and the timelines; it binds federal agencies): https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
84. CISA, BOD 26-04 implementation guidance ("CVSS scores such as 'critical' or 'high' do not prescribe specific actions"; longer timelines are acceptable where the issue is not in the KEV or has no CVE id; the directive's treatment of network devices): https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
85. Table 1 of the directive as an image (the 16 rows were written out from it by hand): https://www.cisa.gov/sites/default/files/styles/large/public/2026-06/BOD_26-04_Table_1_Remediation_Timelines_0.png
86. CVE Services API, `GET /cve/{id}` (operation `cveGetSingle`, "accessible to all users", the `RateLimit-*` headers and the 429), read 2026-11-24: https://cveawg.mitre.org/api-docs/openapi.json ; the program's terms of use: https://www.cve.org/Legal/TermsOfUse
87. CISA Vulnrichment, the SSVC decision points (Exploitation, Automatable, Technical Impact) that CISA adds to CVE records as the "CISA-ADP" container: https://github.com/cisagov/vulnrichment
88. FIRST, using EPSS (the probability with its percentile, a threshold as "a very localized effort", about the 90th percentile and a probability near 0.04 matching the effort of patching CVSS Critical) and how the percentile is calculated: https://www.first.org/epss/using-epss and https://www.first.org/epss/articles/prob_percentile_bins
89. FIRST, CVSS v4.0 user guide (a base score "should not be used alone to assess risk"): https://www.first.org/cvss/v4.0/user-guide
90. Ntfy, "Publishing" (JSON publish to the root URL and its fields; priority 1 to 5; tags and emoji short codes; `click`; `markdown`; message limit 4,096 bytes, title 1 KB, tags 512 bytes; Basic and Bearer (`tk_`) authentication; the default rate limit), read 2026-11-24: https://docs.ntfy.sh/publish/
91. Ntfy, "Configuring the server" (`visitor-request-limit-burst` 60 and `visitor-request-limit-replenish` 5 s), read 2026-11-24: https://docs.ntfy.sh/config/
92. Slack, incoming webhooks (the URL form, `text` and `blocks`, the error words), read 2026-11-24: https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/
93. Slack, Block Kit (50 blocks a message): https://docs.slack.dev/reference/block-kit/blocks/ ; section block (text 3,000 characters, 10 fields of 2,000): https://docs.slack.dev/reference/block-kit/blocks/section-block/ ; header block (150 characters, plain text): https://docs.slack.dev/reference/block-kit/blocks/header-block/ ; context block (10 elements): https://docs.slack.dev/reference/block-kit/blocks/context-block/ ; text object (3,000 characters, `mrkdwn`, `verbatim`): https://docs.slack.dev/reference/block-kit/composition-objects/text-object/ ; all read 2026-11-24
94. Slack, formatting message text (`&`, `<` and `>` as entities; `<!here>`, `<!channel>`, `<!everyone>`; link syntax), read 2026-11-24: https://docs.slack.dev/messaging/formatting-message-text/
95. Slack, rate limits (incoming webhooks: one message a second per channel, short bursts; HTTP 429 and `Retry-After`), read 2026-11-24: https://docs.slack.dev/apis/web-api/rate-limits/
96. Discord, webhook resource (Execute Webhook: `content` 2,000 characters, up to 10 embeds, `allowed_mentions`, `flags`; no host named), read 2026-11-24: https://docs.discord.com/developers/resources/webhook
97. Discord, message resource (embed limits; the allowed mentions object), read 2026-11-24: https://docs.discord.com/developers/resources/message
98. Discord, rate limits (the `X-RateLimit-*` headers, `Retry-After` and `retry_after`, `global`, 10,000 invalid requests in 10 minutes), read 2026-11-24: https://docs.discord.com/developers/topics/rate-limits
99. Discord, API reference (the base URL `https://discord.com/api`; clients must send a valid User-Agent; `discordapp.com` appears only as the CDN host), read 2026-11-24: https://docs.discord.com/developers/reference
100. Python, `smtplib` (`SMTP_SSL`, `starttls(context=...)`, `login`, the exceptions) https://docs.python.org/3/library/smtplib.html and `ssl` (`create_default_context`, `CERT_REQUIRED`, `check_hostname`) https://docs.python.org/3/library/ssl.html, read 2026-11-24
101. Python, email examples (an HTML message with an inline image: `make_msgid`, `add_alternative`, `add_related(..., cid=...)`), read 2026-11-24: https://docs.python.org/3/library/email.examples.html
102. Google, "Sign in with app passwords" (needs 2-Step Verification; 16 characters; not available with only security keys, with work or school accounts the organisation restricts, or with Advanced Protection), read 2026-11-24: https://support.google.com/mail/answer/185833
103. Google Workspace, "Send email from a printer, scanner, or app" (`smtp.gmail.com`, port 465 SSL and 587 TLS, authentication, app password, the statement about less secure apps from 1 May 2025), read 2026-11-24: https://knowledge.workspace.google.com/admin/gmail/send-email-from-a-printer-scanner-or-app
104. Microsoft, "How to set up a multifunction device or application to send email using Microsoft 365 or Office 365" (client SMTP submission: `smtp.office365.com`, port 587, TLS 1.2 or 1.3, SMTP AUTH per mailbox, port 465 unsupported; basic authentication scheduled for deprecation), read 2026-11-24: https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365
105. Docker Engine API v1.54 (swagger): https://docs.docker.com/reference/api/engine/version/v1.54.yaml (ContainerArchive: `GET /containers/{id}/archive?path=`, a tar stream, 404 when missing; PutContainerArchive and ContainerArchiveInfo are the `PUT` and `HEAD` of the same URL; ContainerList: `GET /containers/json?all=1`), read 2026-11-25.
