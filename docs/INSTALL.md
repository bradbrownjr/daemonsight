# Install, configure and update

DaemonSight runs on Debian 12 or 13, Ubuntu, and Fedora (tested on Fedora 44
containers), with Python 3.11 or newer. Commands run on the host being watched,
except under "Run a hub".

## Install

```bash
sudo apt install git python3-venv
git clone https://github.com/bradbrownjr/daemonsight.git
cd daemonsight
sudo ./install.sh
sudo daemonsight set-password
sudo systemctl start daemonsight-web
```

`install.sh` creates the `daemonsight` user, a Python environment in
`/opt/daemonsight`, the config folder `/etc/daemonsight`, the database folder
`/var/lib/daemonsight`, and these systemd units:

| Unit | Runs as | Does |
|---|---|---|
| `daemonsight-collector` | root | Reads every source and writes the database |
| `daemonsight-web` | `daemonsight` | Shows the pages |
| `daemonsight-update.path` and `.service` | root | Installs an update the hub asks for (see "Updating from the hub") |

Options:

| Option | Installs |
|---|---|
| (none) | Collector and web UI, or the options used last time |
| `--collector` | The collector only, for a host that doesn't need its own UI |
| `--web` | Collector and web UI again, after `--collector` |
| `--fail2ban` | Also a jail that bans addresses failing the login (see [SECURITY.md](../SECURITY.md#fail2ban)) |

The options are saved in `/etc/daemonsight/install.options`, so updates keep
them.

### Fedora

Fedora's `python3` includes the venv module, so the only packages needed are
Python and git (a minimal install may lack git):

```bash
sudo dnf install git python3
git clone https://github.com/bradbrownjr/daemonsight.git
cd daemonsight
sudo ./install.sh
```

The rest is the same as above. Notes:

- **SELinux.** No policy change is needed with SELinux enforcing. Files under
  `/opt` are labeled `usr_t`, and a systemd service that runs a program
  labeled `usr_t` or `bin_t` runs in the `unconfined_service_t` domain
  ([unconfined_service_selinux(8)](https://www.mankier.com/8/unconfined_service_selinux)).
  `install.sh` runs `restorecon` on its folders anyway. If the collector is
  denied something, look in `sudo ausearch -m avc -ts recent`. This was not
  tested on a host with SELinux enforcing.
- **firewalld.** The collector only makes outbound connections to the hub, so
  nothing is opened. The web UI listens on `127.0.0.1` by default, which
  firewalld does not touch. Only a UI listening on a LAN address needs
  `sudo firewall-cmd --add-port=8466/tcp --permanent` and a reload.
- **Packages.** The Packages page uses dnf5 (Fedora 41 and newer). See
  "Updates and reboots".
- **Podman.** The Docker source reads `/var/run/docker.sock`. Where Docker is
  absent and Podman's rootful socket is on, point it there. Podman's socket
  has a Docker-compatible API ([podman-system-service(1)](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html)),
  but DaemonSight's Docker source has not been tried against it.

  ```bash
  sudo systemctl enable --now podman.socket
  ```

  ```toml
  [collector]
  docker_socket = "/run/podman/podman.sock"
  ```

### Check it

```bash
systemctl status daemonsight-collector daemonsight-web
daemonsight --version                          # version and installed commit
sudo daemonsight collect-once | less           # what each source sees right now
```

## Open the UI

The UI listens on `127.0.0.1:8466` and is never meant to face the internet.

**Over SSH,** from your own computer:

```bash
ssh -L 8466:127.0.0.1:8466 you@server
```

Then open http://localhost:8466.

**Through a reverse proxy on the same server.** Point it at
`127.0.0.1:8466` and limit the site to your LAN or VPN addresses. In Caddy:

```
daemonsight.example.com {
	@inside remote_ip 192.168.0.0/16 10.0.0.0/8
	handle @inside {
		reverse_proxy 127.0.0.1:8466
	}
	respond 403
}
```

Then set `secure_cookies = true` under `[web]`.

**Through a reverse proxy on another machine.** Set `listen` under `[web]` to
an address that machine can reach (a LAN or WireGuard address, never a public
one). Add the proxy's address to `trusted_proxies`, or every visitor looks
like the proxy to the login's rate limit and to fail2ban:

```toml
[web]
listen = "192.168.1.20"
trusted_proxies = ["192.168.1.1"]
secure_cookies = true
```

Restart the web UI after changing `[web]`:
`sudo systemctl restart daemonsight-web`.

## Configure

Settings live in `/etc/daemonsight/config.toml`. Every setting and its default
is in [packaging/config.example.toml](../packaging/config.example.toml).
After a change, restart both units:

```bash
sudo systemctl restart daemonsight-collector daemonsight-web
```

On a hub, a few settings can be changed in the browser instead; see "The
Settings page" next.

### The Settings page

The account button at the right of the header (a person icon, "Account and
settings") opens a menu with Settings, the theme (Light, Dark or Auto, which
follows your system), "Hide empty sections" and Log out. On a phone the same
items sit in the Menu panel.

**On a hub**, Settings lets you change these without editing a file or
restarting:

| Group | Settings |
|---|---|
| Outside view | Enabled, source (InternetDB or the Shodan API), extra addresses (`ip` or `ip=hostid`, one per line), check every N hours; and the Shodan API key (save, replace, remove, test; see "Outside checks") |
| CVE checks | Enabled, check every N hours, the EPSS probability that stands in for CISA's Automatable rating |
| Retention | Chart points (hours), Recent changes (days), cleared findings (days); 0 keeps for good |
| Backups | Hours between scheduled backups (blank is automatic, 0 is off), how many to keep |
| Remote systems | Whether the hub reads Unraid and OPNsense systems at all |

Each setting shows its default, the range it accepts and where its current
value comes from:

- **Set here**: saved on the page. It wins over the file.
- **Config file**: set in `config.toml`.
- **Default**: neither is set.

A setting saved here is kept in the hub's database (`settings` table), so it is
part of the hub's backups. The config file is never rewritten. "Reset" on a
setting deletes what was saved, and the file's value (or the default) applies
again. A change takes effect the next time the job that uses it runs, within
about a minute; turning the outside view or CVE checks off also closes their
findings then. Every change is listed under "Recent hub changes" on the Hosts
page and the Settings page, for example "Setting changed: Outside view,
enabled: off → on".

**Config file only.** The page lists, without a form, what is never editable
in the browser: the web listen address and port, trusted proxies, cookie and
session settings, the password and secret files, the data, database and backup
folders, the log file, where the Shodan key file is kept (`[outside] key_file`),
whether this install is a hub, the upload limits and the upload settings. A mistake in any of them could lock you out of the page
you would use to fix it, or stop the server starting. Change them in
`config.toml` and restart.

**On a host without a hub**, the page shows the values this install is running
with, read-only, because its web process opens the database read-only by design.
Edit `/etc/daemonsight/config.toml` and restart the two units, as above.
Settings that only a hub uses are labelled "Hub only".

### Updates and reboots

The Packages page needs nothing extra on Debian or Ubuntu. DaemonSight runs
`apt-get -s dist-upgrade`, a simulation that changes nothing, once an hour
(`interval_packages`, in seconds). It never runs `apt update`; keep apt's daily
timer on so the lists stay current. The page shows the lists' age.

On Fedora the page uses dnf5 and reads only what is cached on the host:
`dnf check-upgrade -C` (and `--security`), `rpm -q`, `dnf versionlock list`
and `dnf needs-restarting -C`. `-C` means "use only cached data", so it
never downloads or installs anything. A package counts as a security update
when a security advisory covers it. DaemonSight never runs `dnf makecache`;
Fedora's `dnf5-makecache.timer` does, and the page shows the cache's age. On
a new host with no cache yet, the page says so until the timer or a `sudo
dnf makecache` has run. "Reboot needed" needs file lists in that cache; if
they are missing the page falls back to `/run/reboot-required` and the
installed kernel against the running one. "Services on old libraries" needs the
`dnf5-plugins` package (installed by default on Fedora).

The page also shows whether security updates install themselves, and a low
finding appears when they don't. On Debian and Ubuntu that means
`unattended-upgrades` is installed and `APT::Periodic::Unattended-Upgrade` is
not 0 (`sudo apt install unattended-upgrades` sets both on Debian; if it doesn't,
`sudo dpkg-reconfigure -plow unattended-upgrades`). On Fedora it means
`dnf5-plugin-automatic` is installed, `dnf5-automatic.timer` is enabled and
`apply_updates = yes` is set under `[commands]` in `/etc/dnf/automatic.conf`;
the packaged default only downloads. A host with `role = "workstation"` skips
the finding.

On Debian and Ubuntu, `needrestart` is optional. With it installed (`sudo apt install needrestart`)
the page also lists services still running old libraries after an upgrade.
Without it, that card says so. DaemonSight only lists; it never restarts a
service.

### Laptops and desktops

Set `role = "workstation"` on a host that is often off, asleep or away from
the network:

```toml
role = "workstation"
```

It goes at the top of `/etc/daemonsight/config.toml`, before any `[section]`.
Restart the collector afterwards. The default is `"server"`; any other value
is treated as `"server"` and logged as a warning.

A workstation that stops uploading is "Offline" on the hub's Hosts page, with
a low "Offline since <time>" finding, not a red "Not reporting". The Hosts page
and the host's Overview show its role.

While the laptop is away from the hub's network, its uploads queue on the
laptop and go out in order when it is back. If the hub is only reachable from
your LAN, connect the laptop through your VPN to catch up.

### Which ports should be public

Two lists in `[exposure]` tell DaemonSight what you meant to expose. They
answer different questions.

**`expected_public`:** ports this server itself is meant to serve to the
internet. A port listening on a public address that isn't in this list is a
finding. The default is `22/tcp`, `80/tcp`, `443/tcp` and `443/udp`.

**`upstream_allow`:** ports a firewall in front of the server lets through,
such as a cloud provider's firewall policy. Leave it empty when there is
none. When it's set, a port the provider blocks isn't reported as reachable,
and the findings about the server's own firewall are lowered, since the
provider's firewall is doing that job.

A port can be in `upstream_allow` but not in `expected_public`. One example
is a port the provider lets through so it can be forwarded on to another
machine. Ports forwarded on that way are left out of the check, because
nothing on this server answers them.

So for each port the provider allows, ask whether a program on this server
should answer it from the internet. If yes, add it to `expected_public`. If
no, it's either forwarded elsewhere or shouldn't be listening on a public
address. The Exposure page shows which program owns each port.

```toml
[exposure]
expected_public = ["22/tcp", "80/tcp", "443/tcp", "443/udp", "51820/udp"]
upstream_allow = ["22/tcp", "80/tcp", "443/tcp", "51820/udp", "8000/tcp"]
```

### Jails that don't name their service

DaemonSight matches a fail2ban jail to the service it protects by the jail's
journal match or log path. When it can't, the service shows "no jail". Link
them by hand:

```toml
[exposure.jail_covers]
nginx-http-auth = ["nginx.service"]
```

### How long history is kept

On a hub, use Settings, Retention (see "The Settings page"). In the config
file:

```toml
[retention]
metrics_hours = 48            # chart points, about one a second per host
events_days = 0               # "Recent changes"; 0 keeps them for good
resolved_findings_days = 0    # findings that have cleared; open ones always stay
```

On a host the collector prunes its own rows every hour. On a hub, the hub's
settings apply to every host, whatever each host keeps itself. Raw metric
points add up: 48 hours is roughly 200,000 rows per host.

### Web UI links

Each card has an (i) button saying where its data came from. To add a link to
another web UI there, such as a firewall's own page:

```toml
[links]
caddy = "https://router.example.lan/ui/caddy/reverse_proxy"
```

Sources: `system`, `systemd`, `ports`, `docker`, `caddy`, `fail2ban`,
`firewall`, `packages`.

## Back up and restore

A backup is one `.tar.gz` holding a consistent copy of the database (taken
while the collector or hub keeps running), the config file, the password
hash, the session secret, any upload token, the API key of each remote system
and the Shodan API key. Only its owner can read it. Keep copies as private as
the server: the secret, the token and the API keys are live.

**Scheduled:** the hub, and the collector on a host that keeps its own
data, write one every 24 hours to `backups` in the data folder and keep the
newest seven. A host that uploads to a hub skips them, since the hub's
backups hold its history; set `interval_hours` to turn them back on.

On a hub, the interval and the number kept are on the Settings page (Backups);
the folder is set in the config file only. In the config file:

```toml
[backup]
dir = ""             # default: <data_dir>/backups
interval_hours = 24  # 0 turns them off; unset, a host that uploads skips them
keep = 7
```

A host that uploads keeps only its token and config locally. If it's
rebuilt, reinstall, then `hub revoke` and `hub add-host` it again for a new
token, or restore one of its own manual backups.

On Unraid that folder is inside appdata, so an appdata backup copies it off
the server. On a host, copy `/var/lib/daemonsight/backups` somewhere else
the same way you back up the rest of the server.

**Now:**

```bash
sudo daemonsight backup                         # on a host
docker exec daemonsight daemonsight backup      # on the hub
```

**Restore.** Stop the collector or the hub first; the restore refuses
while either holds the database. It checks the archive and the database
before replacing anything, and keeps each file it replaces as
`<name>.before-restore`.

On a host:

```bash
sudo systemctl stop daemonsight-collector
sudo daemonsight restore /var/lib/daemonsight/backups/daemonsight-vps-20261117-030000.tar.gz
sudo systemctl start daemonsight-collector
sudo systemctl restart daemonsight-web
```

On the hub:

```bash
docker stop daemonsight
docker run --rm -v /mnt/user/appdata/daemonsight:/data ghcr.io/bradbrownjr/daemonsight:edge \
  restore /data/backups/daemonsight-hub-20261117-030000.tar.gz
docker start daemonsight
```

Add `--db-only` to bring back the history but keep the current config,
password and secret.

## Run a hub

A hub is one more install that shows every host on one page. Each host
keeps its collector and uploads to the hub over HTTPS; nothing connects to
the hosts. The hub runs as a container. [SECURITY.md](../SECURITY.md#the-hub)
lists what protects it.

### Start the container

The container runs as uid 10001 with a read-only filesystem, and keeps
everything that changes in `/data`: its config, password, session secret,
database (every host's history) and log file (`daemonsight.log`). All of it
survives restarts, rebuilds and image updates. Retention (Settings page or `[retention]`) sets how
long history stays, and the hub writes a backup to `/data/backups` every
day (see "Back up and restore").

Create the folder with the right owner first, then start the container.

**On Unraid**, use the template so the Docker tab manages the container like
any other app: icon, web UI link, autostart (from Unraid's autostart list),
"Check for updates" and Edit. A container started with `docker run` instead
shows on the Docker tab but can't be updated or edited there.

```bash
mkdir -p /mnt/user/appdata/daemonsight
chown 10001:10001 /mnt/user/appdata/daemonsight
cp deploy/unraid/daemonsight.xml /boot/config/plugins/dockerMan/templates-user/my-daemonsight.xml
```

Then add the container from Docker → Add Container → Template, and set the
password once it runs:

```bash
docker exec -it daemonsight daemonsight set-password
```

**Anywhere else**, this command sets the same options:

```bash
mkdir -p /mnt/user/appdata/daemonsight
chown 10001:10001 /mnt/user/appdata/daemonsight
docker run -d --name daemonsight --restart unless-stopped \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 8466:8466 \
  -v /mnt/user/appdata/daemonsight:/data \
  ghcr.io/bradbrownjr/daemonsight:edge
docker exec -it daemonsight daemonsight set-password
```

`edge` follows `main`. Once releases are tagged, use a version such as
`:0.2.0`, or `:latest` for the newest release. To update on Unraid, see
"Updating: hub first, then hosts". Elsewhere, `docker pull` and start a new
container. Pulling alone doesn't change the running container. The data
stays in `/data` either way.

On its first start the container writes `/data/config.toml`. Edit it to set
your reverse proxy's address, then restart the container:

```toml
[web]
trusted_proxies = ["192.168.1.1"]
secure_cookies = true
```

Map port 8466 on a LAN address only. The page and the upload route share
that port.

### Put it behind a reverse proxy

Give the dashboard a name only your LAN can reach. If a host outside your
LAN uploads, give it a second name that accepts only that host's address and
only the upload path. In Caddy:

```
daemonsight.example.lan {
	@inside remote_ip 192.168.0.0/16
	handle @inside {
		reverse_proxy 192.168.1.20:8466
	}
	respond 403
}

upload.example.com {
	@vps {
		remote_ip 203.0.113.10
		path /api/v1/ingest
	}
	handle @vps {
		reverse_proxy 192.168.1.20:8466
	}
	respond 403
}
```

Hosts on the LAN upload through the dashboard's name. Uploads need HTTPS, so
both names need certificates.

**The hub's address for collectors.** A collector uploads only over HTTPS
(plain http is accepted only for a hub on the same machine) and checks the
hub's certificate against the system's CA store. So put the hub behind a
reverse proxy with a certificate a CA in that store signed, as in the Caddy
example above, or install your private CA's certificate on each host. The
upload path can have its own hostname that allows only `/api/v1/ingest`, as
`upload.example.com` does above. [SECURITY.md](../SECURITY.md#the-hub) and
[DESIGN.md](DESIGN.md) give the reasons.

### Add a host

On the hub, create the host and copy the token it prints. The token is shown
once; the hub keeps only its hash.

```bash
docker exec -it daemonsight daemonsight hub add-host vps
```

The name uses letters, digits, `.`, `_` and `-`, no spaces, starting with a
letter or digit, 63 characters at most. It is part of the host's page address
and can't be changed later.

On the host, with DaemonSight installed, save the token and the hub's
address. `--url` sets `[upload] url` in `/etc/daemonsight/config.toml` and
leaves the rest of the file alone:

```bash
sudo daemonsight set-upload-token --url https://upload.example.com/api/v1/ingest
```

Paste the token at the prompt. The host's `host_id` (its hostname unless the
config sets one) must match the name you gave the hub; the command prints
it.

If a machine can reach both the hub and the host, pipe the token across so
it's never on screen or in a terminal's scrollback. `--quiet` prints only
the token:

```bash
ssh unraid docker exec daemonsight daemonsight hub add-host vps --quiet \
  | ssh vps 'cat > ~/ds.token && chmod 600 ~/ds.token'
# then on the host:
sudo daemonsight set-upload-token --url https://upload.example.com/api/v1/ingest < ~/ds.token && rm ~/ds.token
```

Then restart the collector:

```bash
sudo systemctl restart daemonsight-collector
journalctl -u daemonsight-collector -n 20
```

Within a minute the host shows as "Reporting" on the hub's Hosts page.
The host's own web UI keeps working; stop it with
`sudo systemctl disable --now daemonsight-web` if the hub is all you need.

### Manage hosts in the web UI

The command line above is one way to do it; the hub's web UI is the other.
On the Hosts page, **Add a Linux host** asks for a name (same rule as above),
makes the host and shows its token once with the two commands to run on the
host. The address in the command is the one you opened the page with; if
hosts upload through another hostname, use that one.

The **Manage** button at the end of each row opens the host's page:

- **Update now** is `hub update NAME`. It is greyed out, with the reason, when
  the host runs the hub's version, has not reported, or has turned updates off.
- **Replace upload token** is `hub revoke` then `hub add-host`, but it keeps
  the host's history. The new token is shown once; the old one stops working
  at once, so the host stops uploading until you run
  `set-upload-token` with the new one and restart its collector.
- **Revoke** is `hub revoke NAME`. The host leaves the list and its history
  stays. To allow it again, add the same name as a new Linux host.
- **Remove from hub** is `hub revoke NAME --purge`. The confirmation page lists
  what is deleted (snapshots, metric points, findings, events, accepted
  findings, CVE matches and the token) and asks you to type the name. Nothing
  changes on the host; stop its collector there.

For an Unraid or OPNsense system, Manage opens its edit page, where it can be
changed, disabled or removed.

### CVE matching

The hub matches each host's installed packages against Debian's security
tracker. It needs outbound HTTPS, nothing inbound, to:

| Host | What | Size |
|---|---|---|
| `security-tracker.debian.org` | Debian security tracker (JSON) | 15 MB as sent |
| `epss.empiricalsecurity.com` | EPSS scores, from FIRST | 3 MB |
| `www.cisa.gov` | CISA's Known Exploited Vulnerabilities list | 0.2 MB |
| `cveawg.mitre.org` | CISA's SSVC rating of each CVE a host or image matches (the CVE Services record), one request per CVE, asked again after 7 days | 5 to 100 KB each |
| `codeload.github.com` | The OPNsense project's changelog (a tarball of github.com/opnsense/changelog), only while an OPNsense firewall is enabled | 0.6 MB |
| `www.freebsd.org` | The CVE ids of a FreeBSD security advisory the changelog names (one small file each, asked for once), only for a release a firewall needs | 6 KB each |
| `raw.githubusercontent.com` | The prioritisation table the DaemonSight repository publishes (two small JSON files, once a day; Settings, CVE checks, "Fetch prioritisation table updates from the DaemonSight repository") | 20 KB |
| `api.github.com` | The CVE id and rating of an OPNsense security advisory the changelog names (one request each, asked for once; no token, 60 requests an hour allowed) | 20 KB each |

It fetches each every 24 hours, asking only for what changed, keeps them in
`/data/cve/` and loads them into `/data/cve.db` (about 60 MB on disk, not
backed up). Parsing the tracker takes about 6 seconds and 60 MB of memory.
The first matching result shows a minute or so after the first host reports.
Requests identify themselves as `DaemonSight/<version>` and send nothing else.

Change these on the Settings page (CVE checks), or in the config file:

```toml
[cve]
enabled = true       # false: no downloads and no cve.* findings
refresh_hours = 24
epss_automatable = 0.04   # where CISA has not rated a CVE, an EPSS probability at or above this counts as "automatable"
priority_updates = true   # false: use only the prioritisation table bundled with this version
```

A config file that still has `epss_high` is read as `epss_automatable` and logs a warning; a value saved on the Settings page
under the old name is read the same way until the new one is saved.

**How a CVE finding gets its severity.** The hub follows the timelines of CISA BOD 26-04 (Table 1): whether the system is exposed
to the internet, whether the CVE is on CISA's KEV list, whether an attacker can automate it and how bad the impact is. 3 days is
Critical, 14 days High, 60 days Medium and "fix at the next upgrade" Low. CISA's answers for the last two questions come from the
CVE record at `cveawg.mitre.org`. Where CISA has not rated a CVE, the hub estimates them (an EPSS probability at or above
`epss_automatable` counts as automatable, the impact as partial) and the page says "estimated by DaemonSight". CVSS is shown for
information and decides nothing.

When CISA replaces the directive, the project publishes the new table in its repository and the hub fetches it once a day
(`raw.githubusercontent.com`, two small JSON files, checked before use), so the new deadlines arrive without a release. The Data
feeds card on the Vulnerabilities page shows which table is in force and where it came from, and any error. Turn this off with
the Settings page ("Fetch prioritisation table updates from the DaemonSight repository") or `priority_updates = false`; a fetched
table is then removed and the bundled one is used. A table you place yourself, as below, is never replaced by a fetched one.

The table is a data file. To use a different one (for example when CISA replaces the directive), put a file in the format described
in DESIGN.md ("The table is a data file") at `<data_dir>/priority/override.json` (`/data/priority/override.json` in the
container). The hub reads it when it changes. A file that fails the check is ignored, the reason goes to the log and the bundled
table is used.

Hosts send their package list (13 KB compressed for a desktop with 1,300
packages) when it changes, and once a day. It needs no setting on the host.
**Update the hub first, then the hosts.** An older hub ignores the list; an
older host sends none, and its Vulnerabilities page says so. Debian and
Raspberry Pi OS hosts are matched against Debian's tracker and Ubuntu hosts
against Canonical's OVAL data (the hub downloads one file of about 12 MB for each
Ubuntu release it sees, once a day at most); on Fedora the page lists pending
security advisories. A derivative with its own name (Linux Mint, Pop!_OS) isn't
matched. If the hub can't reach a feed for 3
days, a low "feed is stale" finding appears on each host.

### Outside checks

The hub can ask Shodan what the internet sees of each host's public
addresses: open ports, software names, hostnames, tags and CVEs, from
Shodan's own scans. DaemonSight compares that with what it knows from inside
the host. It is **off by default**, on the hub only. There are two sources;
you choose one under Settings, Outside view, Source.

| Source | Needs | Terms | What you get |
|---|---|---|---|
| InternetDB (default) | nothing: no account, no key | Free for non-commercial use only | Ports, CPEs, hostnames, tags, CVEs; updated about weekly; no banners |
| Shodan API | your own Shodan API key | The terms of the plan the key belongs to | The same, plus each port's transport (TCP or UDP), the software name and version Shodan saw, and when it last saw it |

**Licence.** InternetDB is free for non-commercial use. Shodan's page says:
"If you're using the InternetDB API to make money then you need an
enterprise license." InternetDB takes no key, so a key does not change that. If
you run DaemonSight for clients or inside a for-profit business, use the
Shodan API source with a key on a plan that allows your use. Shodan's pricing
page (https://developer.shodan.io/pricing) lists "Commercial Use" on its
Freelancer, Small Business and Corporate API plans, and its FAQ says the API
may be used in products "as long as the data is attributed to Shodan"
(DaemonSight says the data is from Shodan wherever it shows it). The Enterprise
Data License covers commercial use without attribution. That page does not say
whether the one-time Membership allows commercial use, and no Shodan terms
page was found that does, so ask Shodan before relying on it. DaemonSight does
not turn any of this on for you.

**Getting a Shodan API key.**

1. Create an account at https://account.shodan.io/. A free account is enough
   to get a key, but not to use it: looking up IPs through the API needs at
   least a Membership (a one-time payment), and a free account's key is
   refused.
2. Choose a plan that allows your use on https://developer.shodan.io/pricing.
   For commercial use, a plan that lists Commercial Use (above).
3. Copy the API key from your account page.
4. On the hub's Settings page, Outside view, set Source to Shodan API (your
   key). The API key box opens under it. Paste the key.
5. Press Test key. It asks Shodan's `api-info` page and shows your plan name
   and your credits, or the reason Shodan refused the key. (Test key does not
   say whether the plan allows your use: that is Shodan's terms, under the (i)
   beside Outside view.)
6. Press Save outside view. The key and the source are saved together; the key
   goes to a file only the hub can read, and is never shown again. To replace
   it, paste a new one and save; Remove key is beside the box. The page refuses
   the Shodan API with no key, and refuses to remove the key while the Shodan
   API is the source.

To turn it on, open Settings (account menu), choose Outside view, set Enabled
to On and save. It starts at the next pass, with no restart. Or add this to
the hub's `config.toml` and restart the hub:

```toml
[outside]
enabled = true
source = "internetdb"         # or "shodan": the key is saved on the Settings page
refresh_hours = 24            # each address is asked at most this often
addresses = []                # extra addresses, see below
# key_file = ""               # where the Shodan key is kept; blank: shodan.key in the data folder
```

- It checks every public address each host reports in its ports snapshot
  (scope "public"), IPv4 and IPv6. Private, loopback and link-local addresses
  are never sent.
- `addresses` adds more. `"203.0.113.9"` is checked for the host that reports
  it; `"203.0.113.9=vps"` attaches it to the host named `vps`, for an address
  no collector reports (a router's, for instance). Findings and the Exposure
  section belong to that host, and its `exposure.expected_public` decides what
  is expected.
- It sends one request per address per refresh, from the hub, in the
  background, with the User-Agent `DaemonSight/<version>`. InternetDB:
  `GET https://internetdb.shodan.io/<ip>`, a second apart; nothing else leaves
  the hub, and if it answers HTTP 429 the hub stops for the time it asks. Shodan
  API: `GET https://api.shodan.io/shodan/host/<ip>?key=<your key>`, 1.2
  seconds apart (Shodan's plans allow one request a second). A host lookup
  uses no query credits, according to Shodan's API book. The hub needs
  outbound HTTPS to the host of the source you chose.
- The key goes only to `api.shodan.io`, as the `key` query parameter (the
  only way Shodan documents). The hub removes it from every error message and
  log line, never shows it again, and does not follow redirects. It is in a
  file, `shodan.key` in the data folder, mode 0600, and in backups; see
  SECURITY.md.
- If Shodan refuses the key (HTTP 401 or 403), or has no credits, the hub
  says so at once with a medium `outside.key` finding and a message beside the
  address on the Exposure page. It does not fall back to InternetDB. Fix the
  key, or set Source back to InternetDB. A new key is tried at the next pass.
- Shodan updates InternetDB about once a week, and crawls the internet at least
  weekly, so a fixed port can stay in its data for days. A finding clears at
  the first refresh after Shodan stops listing the port.
- The Exposure page gets a "Seen from outside" section: for each address,
  when it was fetched, then each port Shodan lists with its status and what
  DaemonSight knows about it, plus hostnames, CPEs and tags. With the Shodan
  API source it also shows each port's transport, the software Shodan named
  and when it last saw it. Its source panel has the request and a `curl`
  command to repeat it yourself (for the API it says `key=YOUR_KEY`: put your
  own key there; the page never shows it).
- Findings: `outside.unexpected_port` (high), `outside.not_seen` (low),
  `outside.tagged` (critical), `outside.vulns` (medium), `outside.stale`
  (low) and, with the Shodan API, `outside.key` (medium). Accept them with a
  note like any other; see docs/DESIGN.md, "The outside view".
- Turn Enabled off again (Settings page, or `enabled = false` and a restart) and
  the hub makes no requests and closes the `outside.*` findings at its next
  pass, about a minute later. Remove the key from the Settings page (with
  Source on InternetDB) to delete the key file.

### Hosts that stop reporting

A host that misses three of its longest intervals gets a high "Stopped
reporting" finding (a low "Offline since <time>" one if it is a workstation, see
"Laptops and desktops"), and one added but never heard from gets "Never
reported" after ten minutes. A host whose clock is more than five minutes
off the hub's gets "Clock is off".

When the hub is down, each collector keeps its data and sends the backlog
once the hub is back.

### Add an Unraid server

An Unraid server needs no collector. The hub reads its GraphQL API with a key
that can only read. The Add a system form has these steps in a folded guide,
with links to Unraid's own docs on API keys
(https://docs.unraid.net/API/programmatic-api-key-management/).

1. In Unraid, open Settings → Management Access → API Keys and add a key.
   Give it the Viewer role and nothing else: no other role, no extra
   permissions. Copy it; Unraid shows it once.
2. On the hub, press the + in the header ("Add a system"). Choose Unraid and give
   it a name:
   letters, digits, `.`, `_` and `-`, no spaces, starting with a letter or
   digit, 63 characters at most. It is part of the system's page address and
   can't be changed later.
   Then enter the server's web address (for example
   `https://tower.example.lan`, the address you use for its web UI; HTTPS only)
   and paste the key. If Unraid's Settings → Management Access → Use SSL/TLS is
   Strict, use the myunraid.net address shown there.
3. Press Test connection. It shows the server's name, Unraid version, array
   state, the number of disks and containers, and the key's roles. A key with
   more than Viewer is refused with a message saying so; make a new one.
4. If Unraid uses its own self-signed certificate, the test says so and shows
   the certificate's SHA-256 fingerprint. Compare it with the one in Unraid
   (Settings → Management Access, certificate details), then choose "Pin this
   certificate". Nothing is sent until you do. A pinned certificate's dates are
   ignored (the pin names that one certificate; SECURITY.md has the reason). If
   Unraid has a certificate your browser trusts, leave verification on.
5. Save. The first read happens within a few seconds, and the server appears on
   the Hosts page as "Unraid · API" with its own pages.

The hub reads every minute by default (the Interval box: 30 to 3600
seconds). Disk SMART status and notifications are slower to ask for, so they
are read every 5 minutes, or at the interval if that is longer. Edit
changes the address, interval or certificate pin, replaces the key (type a new
one; the saved one is never shown) or turns reading off. Remove asks you to type
the name, deletes the key file and the server's history. Revoke the key in
Unraid as well.

If the hub runs as an Unraid container, it has to be able to reach Unraid's own
address. On the default bridge network it can. On a custom network with its own
IP address (macvlan or ipvlan), a container can't reach the Unraid host
itself: use the bridge network, or turn on "Host access to custom networks" in
Settings → Docker, or point the hub at a different address that reaches the
server. If Test connection says the server did not answer, check this first.

### Add the Docker reader to an Unraid server

Unraid's API lists containers but not Docker's images, volumes or build cache. To see which images and volumes nothing uses,
and where they probably came from, run the Docker reader on the server: a second container from the same image that
answers the hub and nothing else. It holds the Docker socket, which is root on the server, so read "The Docker reader" in
[SECURITY.md](../SECURITY.md) first. It is optional; the hub works without it.

The steps below are run by you, on the Unraid server and on the hub. DaemonSight does not change containers or networks.

1. **Make a network the two containers share.** On the server's terminal, once:

   ```
   docker network create daemonsight
   ```

   Then open Settings → Docker and set "Preserve user defined networks" to Yes. Unraid's help text says that by default
   networks made outside its GUI are removed from Docker
   (webgui `emhttp/languages/en_US/helptext.txt`, `docker_user_defined_network_help`), so without this the network goes
   away when Docker restarts and the hub can no longer find the reader.

2. **Make the token file.** The hub sends this token with every request; the reader refuses anything else. On the server:

   ```
   mkdir -p /mnt/user/appdata/daemonsight-docker-reader
   openssl rand -hex 32 > /mnt/user/appdata/daemonsight-docker-reader/token
   chown 10001:10001 /mnt/user/appdata/daemonsight-docker-reader/token
   chmod 600 /mnt/user/appdata/daemonsight-docker-reader/token
   cat /mnt/user/appdata/daemonsight-docker-reader/token
   ```

   The reader runs as uid 10001 and refuses to start unless the file is a regular file that only its owner can read
   (mode 0600). Copy the printed token for step 5.

3. **Find the Docker socket's group.** The reader runs as a user that is not root, so it needs the socket's group:

   ```
   ls -ln /var/run/docker.sock
   ```

   The fourth column is the group id. If it is `0` (root), gid 0 means the reader runs with root's group, which is wider than
   a docker group; continue only if you accept that. (What Unraid shows here was not checked.)

4. **Add the reader's template.** Copy `deploy/unraid/daemonsight-docker-reader.xml` from this repository to
   `/boot/config/plugins/dockerMan/templates-user/` on the server (Unraid reads user templates from that folder: webgui
   `DockerClient.php`, `templates-user`). On the Docker tab, Add Container, pick `daemonsight-docker-reader` from the
   template list, and before you press Apply:

   - In Extra Parameters, replace `REPLACE_WITH_SOCKET_GID` with the group id from step 3. Until you do, the container will
     not start, on purpose.
   - Check that Network Type is "Custom : daemonsight" (Unraid lists a network made with `docker network create` that way:
     webgui `CreateDocker.php`).
   - Check the two paths: the Docker socket and the token file from step 2.

   There is no port to publish. Apply, and look at the container's log: a wrong token file mode or a missing socket is
   named there. The log never holds the token.

5. **Move the hub to the same network.** Edit the hub's container (Docker tab, `daemonsight`, Edit) and set Network Type to
   "Custom : daemonsight". The published port keeps working on a user-defined bridge: Docker's bridge driver "supports port
   publishing" (https://docs.docker.com/engine/network/drivers/bridge/), so the dashboard stays at the same address. Newer
   Unraid versions also have "Additional Networks" under Network Type, which attaches the hub to `daemonsight` and leaves it
   where it is (webgui `CreateDocker.php`; whether your version has it was not checked). Apply.

6. **Attach the reader to the Unraid system.** On the hub, open Hosts, Edit the Unraid server, tick "Read images and volumes"
   and enter `http://daemonsight-docker-reader:8467` and the token from step 2. Press Test reader: it shows the Docker
   version and API version. Save.

7. **Wait for the first read.** The hub reads the reader every 10 minutes at most. Docker works out volume sizes slowly (more
   than 15 minutes on a busy server), so the page first shows the unused volumes with unknown sizes and fills them in later.
   Then open the Docker storage tab, and Container images for what is inside each image.

**Update the reader to the newest image before using Container images.** The page needs a reader from this version: it
reads each running image's package list, which earlier readers do not send. Until you update, the page says the reader sends
no package lists. Update the reader's container the same way as the hub (Docker tab, Check for Updates, apply) and restart
it; the template and the token stay as they are. The first pass reads 10 images a minute, so a server with many images
takes a few minutes to fill the page. Debian CVE matching also needs `[cve]` switched on (Settings) and the Debian tracker
downloaded; the hub loads the releases the images use by itself.

To change the token, write a new one to the file (step 2), restart the reader, and type it in the hub's Edit form. To stop
reading, untick the box and Save (this deletes the hub's copy of the token), then remove the reader's container and
`docker network rm daemonsight` if nothing else uses it.

### Add an OPNsense firewall

The hub reads the firewall's REST API with an API key and secret. No agent runs
on the firewall. OPNsense has no read-only privilege: each privilege covers a
whole page, read and write alike. DaemonSight only sends GET requests, but the
key could do more than that, so give it a dedicated user with only the
privileges below. The Add a system form has these steps in a folded guide, with
links to OPNsense's docs on API keys and users
(https://docs.opnsense.org/development/how-tos/api.html,
https://docs.opnsense.org/manual/how-tos/user-local.html).

1. In OPNsense, open System, Access, Users and add a user such as `daemonsight`.
   Leave it out of every group (admins in particular) and give it a password
   nobody will use.
2. In that user's Effective Privileges, add only these (A to Z, the order
   OPNsense lists them in):
   - Firewall: NAT: Destination NAT
   - Firewall: Rules [new] (also lists the classic rules)
   - Lobby: Dashboard (CPU, memory, disk, temperature)
   - Services: Caddy (only with the os-caddy plugin)
   - Status: Interfaces
   - Status: Services
   - System: Firmware (pending updates; it is the broadest, since it also covers
     installing updates, so leave it out if you'd rather the key could not)
   - System: Gateways
   - Tailscale (only with the os-tailscale plugin)
   - VPN: WireGuard: Status

   A privilege you leave out turns off only the page it feeds; the others work.
3. Save, edit the user again and create an API key (the + in API keys). OPNsense
   downloads a text file once with two lines: `key=...` and `secret=...`.
4. On the hub, press the + in the header ("Add a system"), choose OPNsense and give
   it a name:
   letters, digits, `.`, `_` and `-`, no spaces, starting with a letter or
   digit, 63 characters at most. It is part of the system's page address and
   can't be changed later.
   Then enter the web GUI's address with its port (for example
   `https://fw.example.lan:8443`, HTTPS only) and paste the key and the secret.
5. Press Test connection. It lists every source as Readable, "Needs privilege X"
   or "Plugin not installed". A user that can read none of them is refused.
6. If the firewall uses its own self-signed certificate, the test shows its
   SHA-256 fingerprint. Compare it with the firewall's (System, Settings,
   Administration shows the certificate; or run `openssl s_client` from another
   machine), then choose to trust it. Nothing is sent until you do.
7. Save. The first read happens within a few seconds, and the firewall appears on
   the Hosts page as "OPNsense · API" with Overview, Firewall, VPN, Gateways &
   interfaces and Report pages.

The hub reads every minute by default (30 to 3600 seconds). Firmware, rules,
port forwards and Caddy are read every 5 minutes, or at the interval if that is
longer. On the Gateways & interfaces page you can correct an interface's role
(WAN, LAN, VPN, other); the findings about "internet-facing" rules and forwards
follow the roles, not the interface names. Roles are saved in the hub, not on
the firewall. Edit, Remove and the certificate pin (dates ignored, as for Unraid) work as for Unraid; delete the
user's API key in OPNsense as well when you remove the system.

If the hub is an Unraid container and Test connection can't reach the firewall,
see the network note under "Add an Unraid server".

The poller runs with the hub. To stop all remote reading, turn off "Read remote
systems" on the Settings page, or set `[remote] enabled = false` in
`config.toml` and restart.

### Read CrowdSec bans from an OPNsense firewall

If the firewall runs CrowdSec, the hub can show when CrowdSec bans an address that must never be banned: the firewall's own
addresses, a host the hub knows, or an address you list. It is optional and needs the firewall added first (above). It was checked against os-crowdsec 1.0.12 and CrowdSec 1.8.2. Read
"CrowdSec bans" in [SECURITY.md](../SECURITY.md) before you start; the Local API is plain http on your LAN by default.

1. Find the Local API's address. The plugin's Local API listens on the firewall's LAN address, port 8180. To find it, read
   `api_url` in `/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml` on the firewall, for example
   `http://192.168.1.1:8180/`. The hub has to be able to reach that port: check the firewall's rules for the LAN
   interface.
2. On the firewall, in a shell, make a key for the hub:

   ```
   cscli bouncers add daemonsight-hub -o raw
   ```

   It prints only the key, once; copy it. A bouncer can only read decisions. Give the hub its own key: CrowdSec ties a key to the
   first address that uses it.
3. On the hub, open Hosts, Edit the firewall, tick "Read CrowdSec bans" and enter the address and the key.
4. Under "Addresses that must never be banned", list the addresses you depend on, one address or network per line (50 at
   most): the services whose loss would hurt, such as the range of an AI provider or a backup target. DaemonSight lists none
   of its own. A public network wider than /16 (IPv6: /48) is refused.
5. Press Test CrowdSec: it asks for one local decision, which proves the address and the key. Then Save.
6. `cscli bouncers list` on the firewall now shows the bouncer as validated, with the hub's source address. A hub in a
   bridge-mode container shows as the Unraid server's address.
7. Within a few minutes the Firewall page has a CrowdSec card: every address and network checked, with a status label, and the
   count of local bans by scenario.

To stop, untick the option and save: the key file, the list and the readings are deleted. Remove the bouncer on the firewall as
well (`cscli bouncers delete daemonsight-hub`). If you turn on TLS for CrowdSec's Local API, change the address to `https://`;
the certificate is checked against the usual authorities, and pinning a self-signed one is not available yet.

When a finding opens, its "What to do" steps give the command that ends the ban (`cscli decisions delete -i <address>`), how to
see why it happened, and how to add the address to a CrowdSec allowlist so it does not return.

### Remove a host

```bash
docker exec daemonsight daemonsight hub list
docker exec daemonsight daemonsight hub revoke vps            # its token stops working
docker exec daemonsight daemonsight hub revoke vps --purge    # and its data is deleted
```

For an Unraid server or OPNsense firewall added by API, the same commands list it and remove it
(`revoke` deletes its key file; the history goes with `--purge`). The web UI's
Remove does both.

## Update

```bash
sudo daemonsight-update
```

This fetches the latest `main` from GitHub into a root-owned copy in
`/opt/daemonsight/src`, lists the new commits, reinstalls with the saved
options, and restarts both units. Your config, password and database stay as
they are.

To go back, name the commit (the update prints the old one first):

```bash
sudo daemonsight-update 80ef9c1
```

After an update, `daemonsight-update` waits 20 seconds and checks the
collector is still running. If it isn't, it reinstalls the commit it
replaced.

An install made before `daemonsight-update` existed needs one manual update
first, from the folder you installed from:

```bash
git pull && sudo ./install.sh
```

### Updating without a password

On a development server, an account can be allowed to run the update without
a password, so a script or a coding assistant can deploy after each push. Add
a sudoers rule for that one command, checked by `visudo` before it's
installed:

```bash
echo 'youruser ALL=(root) NOPASSWD: /usr/local/sbin/daemonsight-update' > /tmp/daemonsight-update.sudoers
sudo visudo -cf /tmp/daemonsight-update.sudoers \
  && sudo install -m 0440 /tmp/daemonsight-update.sudoers /etc/sudoers.d/daemonsight-update
rm /tmp/daemonsight-update.sudoers
```

That account can then install whatever is on GitHub's `main` as root, but
nothing from its own files. Don't add this rule on a production server.

### Updating from the hub

A host that uploads to a hub can be updated from the hub's Hosts page. A
host on a different commit from the hub gets an "Update to <commit>"
button, and "Update N hosts" does them all. The host picks the request up
with its next upload, installs that commit, and reports back. The page shows
"Updating to …" until it's done, then the Recent changes list says
"Updated to …", or why it failed.

The target is always the hub's own version, so update the hub first, then
its hosts. On Unraid, "Updating: hub first, then hosts" below has a script
for both.

Update the hub first. The hub's database migrates when the hub starts, with
no action from you. A hub ignores top-level fields it doesn't know, but it
checks everything inside an upload strictly: a collector that sends a field
or value an older hub doesn't know gets a 422 and the whole upload is
refused. The collector keeps its data and sends it once the hub is updated.
A hub also won't start on a database from a newer version, so never go back
to an older image after an update without restoring a backup (see "Back up
and restore").

From the command line, on the hub:

```bash
docker exec daemonsight daemonsight hub update vps     # one host
docker exec daemonsight daemonsight hub update --all   # every host that's behind
```

On the host, the update runs as `daemonsight-update.service`:

```bash
journalctl -u daemonsight-update -n 50
```

Hub updates are on unless a host turns them off in its own config:

```toml
[upload]
remote_update = false
```

What a hub can and can't make a host do is in
[SECURITY.md](../SECURITY.md), "The hub".

### Updating: hub first, then hosts

The order is always the same: hub, then the Docker reader if you run one, then
the hosts. `deploy/unraid/update-hub.sh` does all of it for a hub that runs as
an Unraid container from the template. Run it on the Unraid server as root.

1. Push to `main`, then wait for CI to publish the `:edge` image. Watch the run
   with `gh run watch`, or on the repository's Actions page. The script can't
   tell a stale `:edge` from a new one unless you give it the commit.
2. Run the script, with the commit's sha if you want it checked:

   ```bash
   bash deploy/unraid/update-hub.sh            # whatever :edge is now
   bash deploy/unraid/update-hub.sh 1165709    # stop unless :edge is that commit
   ```

3. Open each host's Recent changes and look for "Updated to …". A host that
   failed says why.

What the script does:

- Takes the lock `/tmp/daemonsight-update.lock`, so two runs can't overlap.
  Overlapping runs once left the container dead.
- Pulls `ghcr.io/bradbrownjr/daemonsight:edge`. With a sha, it checks the
  image's `org.opencontainers.image.revision` label starts with it. If not, it
  stops and leaves every container as it was.
- Builds the `docker run` command from the container's Unraid template with
  Unraid's own PHP, and checks it contains `--name='daemonsight'` before
  anything is stopped. It doesn't call Unraid's `rebuild_container` or
  `update_container` scripts, which once failed silently and left no container.
- Stops the hub with a 20 second grace period, removes it and runs the new
  command.
- Waits up to five minutes for the container to be healthy, then prints
  `daemonsight --version`.
- If a container named `daemonsight-docker-reader` exists, recreates it the same
  way from its own template.
- Runs `daemonsight hub update --all`, which asks every host that is behind to
  install the hub's version.

It never deletes data: `/data` is a folder on the server and `docker rm` leaves
it alone. Each failure ends the script with its own exit code and a message
(listed in the script's header). The script includes Unraid's webgui PHP, so it
depends on Unraid's file layout; it was tested on Unraid 7.x.

## Remove

```bash
sudo systemctl disable --now daemonsight-web daemonsight-collector daemonsight-update.path
sudo rm /etc/systemd/system/daemonsight-{collector,web,update}.service /etc/systemd/system/daemonsight-update.path
sudo systemctl daemon-reload
sudo rm -rf /opt/daemonsight /var/lib/daemonsight /etc/daemonsight
sudo rm -f /usr/local/bin/daemonsight /usr/local/sbin/daemonsight-update
sudo rm -f /etc/fail2ban/filter.d/daemonsight.conf /etc/fail2ban/jail.d/daemonsight.conf
sudo rm -f /etc/sudoers.d/daemonsight-update   # only if you created it (see "Updating without a password")
sudo systemctl reload fail2ban                 # only if you had the jail
sudo userdel daemonsight
```
