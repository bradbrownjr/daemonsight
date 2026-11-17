# Install, configure and update

DaemonSight runs on Debian 12 or 13 with Python 3.11 or newer. Every command
here runs on the server being watched.

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
`/var/lib/daemonsight`, and two systemd units:

| Unit | Runs as | Does |
|---|---|---|
| `daemonsight-collector` | root | Reads every source and writes the database |
| `daemonsight-web` | `daemonsight` | Shows the pages |

Options:

| Option | Installs |
|---|---|
| (none) | Collector and web UI, or the options used last time |
| `--collector` | The collector only, for a host that doesn't need its own UI |
| `--web` | Collector and web UI again, after `--collector` |
| `--fail2ban` | Also a jail that bans addresses failing the login (see [SECURITY.md](../SECURITY.md#fail2ban)) |

The options are saved in `/etc/daemonsight/install.options`, so updates keep
them.

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

### Web UI links

Each card has an (i) button saying where its data came from. To add a link to
another web UI there, such as a firewall's own page:

```toml
[links]
caddy = "https://router.example.lan/ui/caddy/reverse_proxy"
```

Sources: `system`, `systemd`, `ports`, `docker`, `caddy`, `fail2ban`,
`firewall`.

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

## Remove

```bash
sudo systemctl disable --now daemonsight-web daemonsight-collector
sudo rm /etc/systemd/system/daemonsight-{collector,web}.service
sudo systemctl daemon-reload
sudo rm -rf /opt/daemonsight /var/lib/daemonsight /etc/daemonsight
sudo rm -f /usr/local/bin/daemonsight /usr/local/sbin/daemonsight-update
sudo rm -f /etc/fail2ban/filter.d/daemonsight.conf /etc/fail2ban/jail.d/daemonsight.conf
sudo systemctl reload fail2ban                 # only if you had the jail
sudo userdel daemonsight
```
