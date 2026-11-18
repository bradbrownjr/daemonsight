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
hash, the session secret and any upload token. Only its owner can read it.
Keep copies as private as the server: the secret and token are live.

**Scheduled:** the hub, and the collector on a host that keeps its own
data, write one every 24 hours to `backups` in the data folder and keep the
newest seven. A host that uploads to a hub skips them, since the hub's
backups hold its history; set `interval_hours` to turn them back on.

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
survives restarts, rebuilds and image updates. `[retention]` sets how
long history stays, and the hub writes a backup to `/data/backups` every
day (see "Back up and restore").

Create the folder with the right owner first, then start the container.

On Unraid, use the template so the Docker tab manages the container like any
other app: icon, web UI link, autostart (from Unraid's autostart list), "Check for updates" and Edit. Copy
`deploy/unraid/daemonsight.xml` to
`/boot/config/plugins/dockerMan/templates-user/my-daemonsight.xml`, then add
the container from Docker → Add Container → Template. A container started
with `docker run` instead shows on the Docker tab but can't be updated or
edited there.

Anywhere else, this command sets the same options:

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
`:0.2.0`, or `:latest` for the newest release. On Unraid, update from the
Docker tab; Unraid pulls the image and recreates the container. Elsewhere,
`docker pull` and start a new container. Pulling alone doesn't change the
running container. The data stays in `/data` either way.

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

### Add a host

On the hub, create the host and copy the token it prints. The token is shown
once; the hub keeps only its hash.

```bash
docker exec -it daemonsight daemonsight hub add-host vps
```

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

### CVE matching

The hub matches each host's installed packages against Debian's security
tracker. It needs outbound HTTPS, nothing inbound, to:

| Host | What | Size |
|---|---|---|
| `security-tracker.debian.org` | Debian security tracker (JSON) | 15 MB as sent |
| `epss.empiricalsecurity.com` | EPSS scores, from FIRST | 3 MB |
| `www.cisa.gov` | CISA's Known Exploited Vulnerabilities list | 0.2 MB |

It fetches each every 24 hours, asking only for what changed, keeps them in
`/data/cve/` and loads them into `/data/cve.db` (about 60 MB on disk, not
backed up). Parsing the tracker takes about 6 seconds and 60 MB of memory.
The first matching result shows a minute or so after the first host reports.
Requests identify themselves as `DaemonSight/<version>` and send nothing else.

```toml
[cve]
enabled = true       # false: no downloads and no cve.* findings
refresh_hours = 24
epss_high = 0.10     # a fixable CVE with an EPSS score at or above this is a high finding
```

Hosts send their package list (13 KB compressed for a desktop with 1,300
packages) when it changes, and once a day. It needs no setting on the host.
**Update the hub first, then the hosts.** An older hub ignores the list; an
older host sends none, and its Vulnerabilities page says so. Debian and
Raspberry Pi OS hosts are matched; on Fedora the page lists pending security
advisories; Ubuntu isn't matched yet. If the hub can't reach a feed for 3
days, a low "feed is stale" finding appears on each host.

### Hosts that stop reporting

A host that misses three of its longest intervals gets a high "Stopped
reporting" finding (a low "Offline since <time>" one if it is a workstation, see
"Laptops and desktops"), and one added but never heard from gets "Never
reported" after ten minutes. A host whose clock is more than five minutes
off the hub's gets "Clock is off".

When the hub is down, each collector keeps its data and sends the backlog
once the hub is back.

### Remove a host

```bash
docker exec daemonsight daemonsight hub list
docker exec daemonsight daemonsight hub revoke vps            # its token stops working
docker exec daemonsight daemonsight hub revoke vps --purge    # and its data is deleted
```

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
its hosts. On Unraid, update the container from the Docker tab.

The order matters from this version on. A collector now sends a fix command
and a basis with some findings, and a hub from before that refuses the upload
until the hub is updated. The hub's database moves to schema 4 on its first
start; no action is needed.

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

## Remove

```bash
sudo systemctl disable --now daemonsight-web daemonsight-collector daemonsight-update.path
sudo rm /etc/systemd/system/daemonsight-{collector,web,update}.service /etc/systemd/system/daemonsight-update.path
sudo systemctl daemon-reload
sudo rm -rf /opt/daemonsight /var/lib/daemonsight /etc/daemonsight
sudo rm -f /usr/local/bin/daemonsight /usr/local/sbin/daemonsight-update
sudo rm -f /etc/fail2ban/filter.d/daemonsight.conf /etc/fail2ban/jail.d/daemonsight.conf
sudo systemctl reload fail2ban                 # only if you had the jail
sudo userdel daemonsight
```
