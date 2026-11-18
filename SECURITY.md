# Security

DaemonSight runs as root on the servers it watches and shows what it finds
on a web page. The main risk is DaemonSight itself becoming a way in. This
page lists the rules that prevent that, what is planned, and what is left to
you.

Rules marked **(planned)** describe work that hasn't shipped. Everything else
is in the code today.

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab, then
**Report a vulnerability**. Please don't open a public issue.

DaemonSight is pre-1.0. Only the latest commit on `main` gets fixes.

## The collector

The collector runs as root, because reading other users' sockets, the Docker
socket, the fail2ban socket and the firewall needs it.

- **Read only.** Every source reads; none changes anything.

  | Source | What it calls |
  |---|---|
  | systemd | D-Bus `ListUnitsByPatterns` and `Properties.GetAll` |
  | Docker | Docker API `GET` requests only |
  | Caddy | Admin API `GET /config/` and `GET /reverse_proxy/upstreams` |
  | fail2ban | Socket commands `version`, `status` and `get` |
  | Firewall | `iptables-save`, `ip6tables-save`, `nft -j list ruleset` |
  | Ports, system | psutil, which reads `/proc` |

- **No commands from anywhere.** The collector takes no input from the web UI
  or the network. Its one outbound connection is the upload to a hub, when
  `[upload]` is set, and it reads nothing from the reply but a sequence
  number. Actions such as ban or restart would need their own design.
- **fail2ban replies are unpickled safely.** fail2ban's socket speaks Python
  pickle. The collector's unpickler accepts builtin data types and exception
  names only, so a reply can't run code.
- **Secrets in container logs and command lines are masked** before
  they're stored: `password=`, `token=`, `api_key=` and similar values,
  `Authorization` headers, and passwords inside URLs. The command line of
  each listening process is kept for its port's source panel, cut to 400
  characters. A secret passed some other way, such as a bare positional
  argument, can't be recognized; prefer config files or environment
  variables for secrets.
- **New files are private.** The unit sets `UMask=0027`, so the database is
  readable by root and the `daemonsight` group only.
- **systemd hardening:** `NoNewPrivileges`, `ProtectSystem=full`,
  `PrivateTmp`, and no access to kernel modules, kernel logs, the clock or the
  hostname.

## The web UI

The web UI runs as the unprivileged `daemonsight` user. It reads the
database and its own config, and nothing else.

- **Not on a public address by default.** It listens on `127.0.0.1:8466`.
  Reach it through a reverse proxy on a LAN-only route, or over a VPN. Don't
  publish it to the internet.
- **Login:** one admin password of at least 12 characters, stored as an
  Argon2 hash in `/etc/daemonsight/password`. The web process can read that
  file but not change it.
- **Rate limit:** five failed logins from one address in five minutes blocks
  that address for the rest of the window. Every failure is logged as
  `Failed login from <address>` for fail2ban.
- **Session cookie:** signed, `HttpOnly`, `SameSite=Strict`, 12 hours, and
  tied to the current password.
  Set `web.secure_cookies = true` when the UI is served over HTTPS.
- **Headers on every response:** a Content Security Policy that allows only
  the app's own scripts, styles and connections (no inline script, no
  framing), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, and `Cache-Control: no-store` on pages.
- **No outside code at runtime.** HTMX and Tabler are pinned and served from
  the app itself; no CDN, no Node build step.
- **Escaping:** pages are Jinja2 templates with autoescaping, so text from a
  server (a container name, a log line) can't become markup.
- **Redirects stay on the site.** The `next` value after login must be a
  local path.
- **No API docs pages.** FastAPI's `/docs`, `/redoc` and `/openapi.json` are
  turned off.
- **systemd hardening:** `ProtectSystem=strict`, `ProtectHome`,
  `PrivateDevices`, no capabilities, only IPv4, IPv6 and Unix sockets,
  `SystemCallFilter=@system-service`, and the rest of the usual set.

### Behind a reverse proxy

The web UI trusts `X-Forwarded-For` only from addresses in
`web.trusted_proxies` (default `127.0.0.1` and `::1`). When the proxy is on
another machine, add its address there. If you don't, every visitor looks
like the proxy: the log names the proxy instead of the attacker, and five bad
passwords from anyone lock everyone out for five minutes.

### Ending sessions

Each session is tied to the password it logged in with. Changing the
password (`sudo daemonsight set-password`) ends every session at once.
Logging out clears the cookie in that browser; a copy of the cookie taken
earlier stays valid until it expires or the password changes. To end every
session without changing the password, delete `/etc/daemonsight/secret`, run
`sudo daemonsight init` to make a new one, and restart `daemonsight-web`.

## fail2ban

`sudo ./install.sh --fail2ban` adds a jail that bans an address after five
failed logins in ten minutes, for one hour. It reads `daemonsight-web`'s
journal with the filter in `packaging/fail2ban/`. The filter has been tested
with `fail2ban-regex` on fail2ban 1.1.0.

Whether you need it depends on where the login can be reached from:

| Setup | fail2ban |
|---|---|
| UI on the same host as its reverse proxy, reachable from outside | Install the jail. It bans at the host's firewall, in front of the proxy. |
| UI reachable only from a LAN or VPN | Optional. The rate limit already covers it. |
| UI in a container behind a proxy on another machine (the hub) | Not on the hub. A ban there would block the proxy, and a container has no firewall of its own. Limit who reaches the proxy with access lists instead, and ban at the firewall if you want bans at all. |

DaemonSight's own fail2ban page shows this jail like any other.

## Config files and permissions

| Path | Owner | Mode |
|---|---|---|
| `/etc/daemonsight/` | root:daemonsight | 0750 |
| `/etc/daemonsight/config.toml` | root:daemonsight | 0640 |
| `/etc/daemonsight/password`, `secret` | root:daemonsight | 0640 |
| `/var/lib/daemonsight/` (database) | root:daemonsight | 2750 |
| `/var/lib/daemonsight/backups/` | root | 0700, each backup 0600 |

A backup holds the session secret and any upload token as well as the
database, so keep copies as private as the server. Restoring one brings back
the password and secret it was made with.

## Remote sources (planned)

OPNsense, Unraid and a cloud provider's firewall are read through their own
APIs.

- **A dedicated key for each,** never an admin login. Use Unraid's `VIEWER`
  role. OPNsense privileges cover reading and writing together, so grant only
  the pages DaemonSight reads; the list is in [docs/DESIGN.md](docs/DESIGN.md).
- **Keys live in root-only files** under `/etc/daemonsight/`, never in
  `config.toml`.
- **Read requests only.** The client sends no request that changes
  anything.

## The hub

One install, the hub, shows every host. Collectors push to it over HTTPS,
the way RMM and Wazuh agents report in. Nothing connects to a collector, so no
host needs a VPN or an open inbound port for DaemonSight. The design is in
[docs/DESIGN.md](docs/DESIGN.md), "Hub".

- **One token per host.** It can only write that host's data and gives no
  access to the hub's network or to other hosts. The hub stores only a
  SHA-256 of each token. `daemonsight hub revoke <host>` deletes it. On the
  host, `daemonsight set-upload-token` saves it readable by root only.
- **HTTPS only.** The collector refuses an upload address that isn't
  `https://` (except a hub on the same machine) and always checks the hub's
  certificate, with no setting to turn that off.
- **No replays.** Each upload has a sequence number that must go up.
- **Every upload is checked before anything is stored:**
  - gzip or plain JSON only, at most 8 MiB as sent and 48 MiB unpacked
  - every field's type and length, and the shape of each source's data.
    Unknown top-level fields are ignored, so a host updated before its hub
    can still report; anything inside a known field must match exactly.
  - links must be paths on the hub's own site
  - a collector can't open or close the hub's own `host.*` findings
  - ten bad tokens from one address in five minutes block that address,
    and one host may upload at most 120 times a minute
- **Refusals are logged** as `Refused upload from <address>: <reason>`.
  The fail2ban filter counts only bad tokens.
- **The hub can ask for one thing: an update.** Its reply carries the last
  sequence number it accepted and, when you've asked from the Hosts page, a
  commit for the host to install. Nothing else it says is acted on.
  - The hub names a commit, never a source. The host fetches from the
    GitHub URL in its own `daemonsight-update` and installs the commit only
    if it is on `main` or in a `v*` release tag.
  - The collector doesn't install anything. It writes the commit to
    `update.request` in its data folder; a systemd path unit starts
    `daemonsight-update.service`, which checks the commit and installs it.
  - If the collector isn't running 20 seconds after an update, the previous
    commit goes back on.
  - The worst a compromised hub can do is move hosts to another published
    version of DaemonSight. That's the same trust you place in the GitHub
    repo every time you update.
  - It's on by default, as with UniFi or FortiGate controllers. A host turns
    it off with `[upload] remote_update = false` in its own config; the hub
    can't change that.
- **The container runs as a non-root user** (uid 10001). Its config,
  password, session secret and database are in its `/data` volume.
- **Silence is a finding.** A host that misses three of its longest
  intervals raises `host.silent`.

Your part on the hub:

- Publish the container's port to a LAN address only.
- Keep the dashboard behind a LAN-only access list at the proxy.
- Give uploads from outside their own hostname, open only to each remote
  collector's fixed address and only for `/api/v1/ingest`.
- Set `web.trusted_proxies` to the proxy's address.

## What DaemonSight can't protect against

- **A compromised host can report false data about itself.** That's true of
  every monitoring agent. A host that goes quiet, and a provider's own
  alarms (CPU, traffic), are the checks it can't forge.
- **Root on a watched host can read everything DaemonSight collected there.**
- **The pages show a map of your systems:** open ports, addresses, bans,
  container logs. Treat access to the UI like admin access.

## Your part

- Use a long, unique password: `sudo daemonsight set-password`.
- Keep the UI on a LAN or VPN, behind a reverse proxy with an access list.
- Set `web.trusted_proxies` when the proxy is on another machine.
- Set `web.secure_cookies = true` when serving over HTTPS.
- Install the fail2ban jail where the login can be reached from outside.
- Update with `git pull` and `sudo ./install.sh`.
