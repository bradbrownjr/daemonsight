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
  | Packages | `apt-get -s dist-upgrade`, `apt-config shell`, `dpkg-query -W`, `dnf check-upgrade -C`, `dnf advisory list` and `info -C`, `rpm -q`, `systemctl is-enabled` |

- **No commands from anywhere.** The collector takes no input from the web UI
  or the network. Its one outbound connection is the upload to a hub, when
  `[upload]` is set, and it reads nothing from the reply but a sequence
  number and an update commit (see "The hub"). Actions such as ban or restart
  would need their own design.
- **fail2ban replies are unpickled safely.** fail2ban's socket speaks Python
  pickle. The collector's unpickler accepts builtin data types and exception
  names only, so a reply can't run code.
- **What it sends about packages.** With `[upload]` set, the list of
  installed packages (source name, version and binary package names) and the
  release name from `/etc/os-release`; on Fedora, the pending security
  advisories instead. That tells the hub, and anyone who reads its database,
  which versions of what the host runs. The collector downloads no
  vulnerability data.
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
- **Redirects stay on the site.** The `next` value after login, and after
  accepting a finding, must be a local path.
- **Accepting findings (hub only).** `POST /h/<host>/findings/accept` and
  `.../unaccept` need the login, refuse a request whose `Sec-Fetch-Site` is not
  `same-origin` or `none` (the same check as `/hosts/update`, on top of the
  `SameSite=Strict` cookie), and 404 for an unknown host. The note is 1 to 500
  characters with no control or format characters. A host's web process on a
  single host stays read-only, so it has no such routes. An acceptance hides
  a finding from the counts, so it is logged (user and address) and written to
  Recent changes with its note.
- **The Settings page (every install; changes on a hub only).**
  `GET /settings` needs the login. On a hub, `POST /settings` needs it too,
  refuses a request whose `Sec-Fetch-Site` is not `same-origin` or `none` (on
  top of the `SameSite=Strict` cookie), validates every value on the server
  (type, range, and for extra addresses that each one is a public IP address
  and the host id is well formed) and writes nothing unless all of it is
  valid. A posted name that is not one of the editable settings refuses the
  whole request, so a hand-made POST can't reach a read-only setting. Every
  change is logged (user and address) and written to Recent changes. A
  single host's web process opens the database read-only, so it has no
  `POST /settings` route.
- **The report is authenticated.** `/h/<host>/report` and `report.md` need
  the login like every other page. The Markdown escapes text from hosts, and
  puts commands in a code fence that the text can't close.
- **Fix commands are text from the host.** A finding's `fix` comes from the
  collector. The hub drops a fix with control or format characters (so an
  escape sequence or a right-to-left override can't make it show as something
  else) or over 2,000 characters, and shows the rest as escaped text. DaemonSight never runs it.
  Read it before pasting it into a terminal, as with any command from a
  website.
- **No API docs pages.** FastAPI's `/docs`, `/redoc` and `/openapi.json` are
  turned off.
- **systemd hardening:** `ProtectSystem=strict`, `ProtectHome`,
  `PrivateDevices`, no capabilities, only IPv4, IPv6 and Unix sockets,
  `SystemCallFilter=@system-service`, and the rest of the usual set.

### What can be changed in the browser

Only on a hub, and only by someone logged in, these settings can be saved from
the Settings page: the outside view (on or off, extra addresses, refresh
hours), CVE checks (on or off, refresh hours, the EPSS threshold), retention,
the backup interval and count, and whether remote systems are read. Each is a
row in the `settings` table of the hub's database, over the config file's
value, and "Reset" deletes it. No code in the web process writes the config file.

**Never editable in the browser:** the listen address and port, trusted
proxies, `secure_cookies`, `session_hours`, the password and secret files, the
data, database and backup folders, the log file, the hub flag and upload
limits, and the upload address and token file. The page shows them read-only,
with the reason. A wrong value in any of these could lock the administrator
out of the page needed to fix it (a bad listen address, a changed password
file), expose the interface (a public listen address, a wrong trusted
proxy), or send data somewhere else (the upload address). Someone with the
login could otherwise change them from one stolen session. They stay behind
file access on the server.

What a person with the login can change in the browser is limited to settings
that change what the hub does for you. The outside view is the one that sends
anything out: with it on, the hub sends public IP addresses to Shodan. The
page shows the licence terms beside that switch, and the change is logged and
shown under Recent hub changes. A stolen session could turn it on; it could
not change where the hub listens, who may log in, or where it uploads.

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

## Remote sources

The hub reads an Unraid server over its GraphQL API. The hub makes these
connections, which is the one exception to "nothing connects to a host". OPNsense
and a cloud provider's firewall are planned and will follow the same rules.

- **What the key can do.** An Unraid API key with the Admin role can start and
  stop the array, containers and VMs. DaemonSight only needs to read, so the
  hub accepts a key only if it has the `VIEWER` role and no permission that
  changes anything. It asks Unraid what the key can do (`me` returns the key's
  roles and permissions) when you press Test connection, when you save, and at
  the start of every poll, and it stops using a key that has gained more
  power. Make the key in Unraid under Settings → Management Access → API Keys:
  Viewer role only, nothing else. Revoke it there when you remove the system.
- **Where the key is stored.** In a file, `<data>/remotes/<id>.key`, mode 0600
  in a 0700 folder, written atomically. It is never in the database,
  `config.toml`, a page, a log line or an event. The form shows no saved key
  (leave the field empty to keep it, or type a new one to replace it), and
  errors are scrubbed of it. Backups include the file, so they are as private
  as the key; the archive is 0600. Removing the system deletes the file.
  A hub that is compromised leaks the keys it holds, which is why they must
  be Viewer keys.
- **Read requests only, enforced on both sides.** Unraid refuses a write from a
  Viewer key. The hub's client sends `{"query": ...}` through one method and
  refuses any document that isn't a query (it must begin with `{` or
  `query` and must not contain `mutation` or `subscription`) before anything
  is sent. A test asserts that no request body contains "mutation". Redirects
  are not followed, so the key can't be sent somewhere else, and a reply
  larger than 8 MiB is refused.
- **One subscription, and why it is read-only.** Unraid offers container CPU
  and memory only as a subscription, so the hub has one other method that opens
  a WebSocket to `/graphql` and sends exactly this document and no other:
  `subscription { dockerContainerStats { id cpuPercent memUsage memPercent } }`.
  The document is compared as a whole string, so any other subscription, any
  text added to it and any mutation is refused before the hub connects. It
  asks the server to report figures that Docker already prints (`docker stats`);
  it changes nothing, and it needs only the read permission on Docker, which the
  Viewer role has (the server's own Viewer policy, read from its source; not yet
  tried with a Viewer key). It is sampled for a few seconds each poll, with
  at most 5 seconds of collection, 5000 messages of 16 KiB each, and then the
  hub completes the subscription and closes the socket. The WebSocket uses
  the same certificate check as queries (the CA store, or the one pinned
  certificate, so a changed certificate is refused before the key is sent), the
  key goes in the first message after the TLS handshake and in no URL or header,
  redirects are not followed, no proxy from the environment is used, and the
  WebSocket library's logging, which would print that message at debug
  level, is switched off. Tests cover each of these. The library is
  `websockets`, pinned in `requirements.txt`.
- **TLS.** Certificates are verified by default. Unraid's own certificate is
  self-signed unless you installed a real one, so you may pin it: Test
  connection fetches the certificate, shows its SHA-256 fingerprint and the
  hub saves it only after you confirm that fingerprint (compare it with
  Unraid's certificate page). The key is not sent until then. A pinned system
  trusts that one certificate and no other, and a changed certificate stops
  the connection before any request, so the key goes nowhere new. There is no
  "don't verify" setting. A pinned certificate that Unraid renews has to be
  pinned again.
- **Add and edit pages** need the login and refuse cross-site requests
  (`Sec-Fetch-Site`). Removing a system asks you to type its name. A key
  waiting between Test connection and Save is held in the hub's memory for ten
  minutes, never in the page, and is used once.
- **Text from the server is untrusted.** Container names, Docker folder names
  and notification titles, subjects, descriptions and links are cut to a length
  (title 120, subject 200, description 300, link 100 characters; at most 400
  notifications are kept), stripped of control characters (and, in descriptions,
  of HTML tags), and escaped by the templates and, in the Markdown report, by the report's own
  escaping. A notification's link is shown as text, never as a link. A finding
  made from a notification repeats that text in its detail, cut again to 900
  characters. A remote system can't send rules or "What to do" steps; the hub
  makes them, and a collector's upload has no field for them.
- **One request that is not to your server.** Once a day the hub reads Unraid's
  public release page, `https://releases.unraid.net/os?branch=stable`, to learn
  the newest stable version. The request is the same for every server: no key,
  no address, no server name, no version, no license date (Unraid's own check
  sends the version and the license expiry; DaemonSight does not), and only a
  generic `User-Agent: DaemonSight/<version>`. The reply is size-limited and
  only a stable version number and a release-notes address on `docs.unraid.net`
  or `releases.unraid.net` are used. It runs only while an Unraid system is
  enabled.
- **The address is yours to choose.** The hub connects to the address an
  administrator typed, over HTTPS only. Anyone who can add a system can make
  the hub connect to an address on its own network; that is the same trust
  as the login.

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
  - a collector can't open or close the hub's own `host.*`, `cve.*`,
    `remote.*`, `unraid.*` or `outside.*` findings
  - ten bad tokens from one address in five minutes block that address,
    and one host may upload at most 120 times a minute
- **CVE matching downloads three public files.** The hub fetches the Debian
  security tracker, FIRST's EPSS scores and CISA's KEV list over HTTPS, with
  the User-Agent `DaemonSight/<version>` and nothing about your hosts. A
  redirect may only stay on the feed's own host, each download has a size
  cap, files are written atomically and parsed with the standard library
  (no code is run from them). A failed download keeps the last good data.
- **Outside checks send one thing to Shodan: an IP address.** Off by default
  (Settings page, or `[outside] enabled`). When on, the hub asks Shodan's InternetDB,
  `GET https://internetdb.shodan.io/<ip>`, for each public address of each
  host. The request carries the IP in the path and the User-Agent
  `DaemonSight/<version>`: no host name, host id, token, key, cookie, port
  or anything else. An address must parse as an IP and not be private,
  loopback, link-local or multicast, or it is never sent (a collector's
  report of its own addresses is checked again on the hub). Redirects are not
  followed, so an answer can't send the hub elsewhere. This tells Shodan that
  your hub exists and which addresses it watches. InternetDB is free for
  non-commercial use only; see INSTALL.md.
- **Shodan's reply is untrusted text.** It is capped at 1 MiB, parsed as
  JSON and cut down to ports (integers 1 to 65535), CPEs, hostnames, tags
  (a strict pattern) and CVE ids (a strict pattern), each with a count and
  length limit. It is stored as data and shown only through autoescaped
  templates; the links it produces go to `nvd.nist.gov`, built from a CVE id
  that matched the pattern. A wrong reply, or Shodan being down, can give
  wrong or missing findings but can't run anything. Its tags and CVE lists
  are Shodan's own guesses from scanning; the findings say so.
- **Feed text is untrusted.** CVE descriptions and names come from other
  people's files. They are cut to a fixed length when stored and shown only
  through autoescaped templates, and the links they produce go to
  `security-tracker.debian.org`, built from a CVE id that matched a strict
  pattern. A bad feed can give wrong findings but can't run anything.
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
- Update with `sudo daemonsight-update`.
