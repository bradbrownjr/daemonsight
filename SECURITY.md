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
  number, an update commit and an uninstall request (see "The hub"). Actions
  such as ban or restart would need their own design.
- **fail2ban replies are unpickled safely.** fail2ban's socket speaks Python
  pickle. The collector's unpickler accepts builtin data types and exception
  names only, so a reply can't run code.
- **What it sends about packages.** With `[upload]` set, the list of
  installed packages (source name, version and binary package names) and the
  release name from `/etc/os-release` (on Ubuntu, also which Ubuntu Pro ESM
  services are on, read from the apt source files they write); on Fedora, the
  pending security advisories instead. That tells the hub, and anyone who reads its database,
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
the Settings page: the outside view (on or off, its source, extra addresses,
refresh hours, and the Shodan API key, which is not a setting: see below), CVE checks (on or off, refresh hours, the EPSS probability that stands in for CISA's Automatable rating), retention,
the backup interval and count, whether remote systems are read, and the address alert links use. Alert channels have their own pages (see "Alert channels"). Each is a
row in the `settings` table of the hub's database, over the config file's
value, and "Reset" deletes it. No code in the web process writes the config file.

**Never editable in the browser:** the listen address and port, trusted
proxies, `secure_cookies`, `session_hours`, the password and secret files, the
data, database and backup folders, the Shodan key file's path, the log file, the hub flag and upload
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
| `/var/lib/daemonsight/shodan.key` (when saved) | the hub's user | 0600 |
| `/var/lib/daemonsight/remotes/*.key` | the hub's user | 0600, in a 0700 folder |

A backup holds the session secret, any upload token, the API keys of remote
systems and the Shodan API key as well as the database, so keep copies as
private as the server. Restoring one brings back
the password and secret it was made with.

## Remote sources

The hub reads an Unraid server over its GraphQL API, an OPNsense firewall
over its REST API and a UniFi Network controller over its Integration API. The hub makes these connections, which is the one exception to
"nothing connects to a host". A cloud provider's firewall is planned and will
follow the same rules.

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
  pinned again. A pinned certificate's dates are not checked: the pin already
  names the one certificate trusted, and appliances' self-signed certificates
  often expire unnoticed (OPNsense's web GUI one does). Everything else is
  still checked, including that the server holds the certificate's key.
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
- **OPNsense keys are not read-only.** OPNsense has no read-only privilege: each
  privilege covers a whole page, read and write alike (the `ACL.xml` files in
  github.com/opnsense/core list patterns such as `api/firewall/d_nat/*` with no
  split by method). A key with the privileges DaemonSight needs can also change
  the firewall rules, port forwards, Caddy sites and firmware those pages
  control, and nothing on the firewall limits it to reading. Protection is in
  two places. The hub's client has no way to send anything but GET: one method
  asks for a GET with no body, and it refuses any path that is not on a fixed
  list of 14 endpoints (a whole-string compare, so a query string or another
  endpoint is refused before anything is sent), follows no redirects and caps a
  reply at 8 MiB. Tests fail on any other method and on any path outside the
  list. And the key belongs to a dedicated user in no group with only the listed
  privileges. DaemonSight cannot check what a key may do (there is no `me`
  call), so that is on you. The most powerful of the privileges is System:
  Firmware (it covers installing updates and rebooting); leaving it out costs
  only the pending-updates finding. A hub that is compromised leaks the keys it
  holds, and an OPNsense key can change the firewall, so keep the hub's data
  folder and backups private and give the hub's user nothing else.
- **OPNsense key and secret.** Both are stored as two lines of
  `<data>/remotes/<id>.key`, mode 0600, with the same rules as an Unraid key:
  never in the database, a page, a log line, an event, a request URL or a
  curl command shown on a page (panels show `$KEY` and `$SECRET` placeholders).
  They go only in the Authorization header. The hub keeps from each reply only
  the fields it names: Caddy's reply includes the DNS provider API key and the
  ACME e-mail, WireGuard's includes public keys (cut to 8 characters), and
  Tailscale's lists peer names (only a count is kept).

- **UniFi keys are not read-only, and the hub cannot check.** A UniFi API key has the
  power of the admin who made it, and the Integration API has no call that
  reports it (the only call that is not about a site, a device or a client is
  `GET /v1/info`, which gives the version). So Test connection does not and
  cannot show the key's role; it says so on the page, and DaemonSight never
  tries a write to find out. Make the key as a dedicated local admin with the
  View Only role. Protection is in two places. The hub's client sends GET only
  (the same class as for OPNsense), to a fixed list of path patterns: the list
  endpoints for sites, devices, pending devices, Wi-Fi networks, firewall zones
  and policies, a device's statistics, and a client list asked only for its
  count (`limit=0`). It refuses any other path before anything is sent, so no
  detail, action, voucher or client-identity path can be requested; it follows
  no redirects and caps a reply at 8 MiB. Tests fail on any other method and
  any path outside the list. And the key's admin can only view. Whether a View
  Only admin can make a key at all, and what that key can do, was not checked
  against a controller; see the unverified list in docs/DESIGN.md, "UniFi
  Network".
- **UniFi key.** Stored as one line in `<data>/remotes/<id>.key`, mode 0600, with
  the same rules as the other keys: never in the database, a page, a log line, an
  event or a request URL, and panels show a `$KEY` placeholder. It goes only in
  the `X-API-KEY` header. A Wi-Fi network's passphrase is never read: the hub asks
  for the list of networks, which carries only the security type, never for one
  network's detail, which carries the passphrase. The parsers copy named fields
  only, so a passphrase that did arrive would be dropped. Clients are counted
  and never named. The key is in a backup of the data folder like the others.

## The Docker reader

The Docker reader (`daemonsight docker-reader`) lets the hub see an Unraid server's Docker images, volumes and build cache,
which Unraid's API does not list, and the package list of each image a container runs. It is the most privileged piece of DaemonSight. It runs as its own container and mounts
`/var/run/docker.sock`, and **access to the Docker socket is root-equivalent on the host**: anything that can send requests
to it can start a privileged container that mounts the host's disks. Install it only if the images and volumes list is worth
that. The rest of this section says what limits it and what does not.

**What limits it.**

- **It is not a proxy.** It has two routes, `GET /v1/summary` and `GET /v1/health`. It never forwards a path, query or body
  to Docker. The summary is computed inside the reader and cut to named fields, so the hub (or anyone holding the token)
  can't ask Docker anything else. There are no docs or OpenAPI routes and no request log.
- **GET, from a fixed list.** The reader's Docker client has one method, which sends GET over the unix socket and refuses
  any target that is not in a fixed list compared as a whole string: `/_ping`, `/version`, `/containers/json?all=1`,
  `/images/json?all=0&digests=1`, `/images/sha256:<64 hex>/json`, `/volumes`, `/system/df?verbose=1` and the container
  archive read described in the next item. Tests send about 25 near misses and check that each is refused before anything is
  sent, and that the fake engine received only GETs from the list.
- **One more endpoint: a container's archive, for four fixed paths.** `GET /containers/{id}/archive?path=<p>` is Docker's
  "Get an archive of a filesystem resource in a container" (operationId ContainerArchive in the Engine API v1.54 swagger,
  https://docs.docker.com/reference/api/engine/version/v1.54.yaml). The reader sends it only for `/usr/lib/os-release`,
  `/etc/os-release`, `/var/lib/dpkg/status` and `/lib/apk/db/installed`, URL-encoded exactly, and only with a container's
  64-digit hex id (a name is refused). So it can read an image's operating system name and its installed package names and
  versions, and no other file: not environment files, keys, configuration or data. A path that is not one of the four, a
  `..`, a differently encoded form, an extra query parameter or a trailing newline is refused before anything is sent.
  - **Why PutContainerArchive is never sent.** The same URL with PUT is "Extract an archive of files or folders to a directory
    in a container" (PutContainerArchive): it writes files into a container, which is code execution inside it. The client
    sends GET only and `check_allowed` refuses any other method, so a PUT (or a HEAD, ContainerArchiveInfo) is not built even by
    mistake. A test checks that the fake engine saw only GETs.
  - **What is read from the tar stream.** The reply is a tar stream, held in memory up to the file's cap plus 32 KiB and read
    with `tarfile` in streaming mode (`r|`: no seeking, no decompression, so a gzip or bzip2 bomb is not unpacked). It must
    hold exactly one member, and that member must be a regular file no bigger than the cap: 64 KB for os-release, 16 MB for
    dpkg's status file, 4 MB for apk's installed database. A symlink (`/etc/os-release` usually is one) is not followed, which
    is why `/usr/lib/os-release` is read first; a hard link, directory, device, a second member or a stream cut short is
    refused. Nothing is written to disk and no member name is used as a path. Lines of the files are parsed for the named
    fields only (`ID`, `ID_LIKE`, `VERSION_ID`, `VERSION_CODENAME`, `PRETTY_NAME`; `Package`, `Status`, `Version`, `Source`,
    `Architecture`; `P`, `V`, `o`), cut to 100 characters each and 4,000 packages per image, and the rest is dropped.
  - **How often.** One running container per image is read, once, and the result is kept by image id in the reader's memory, so
    it is read again only after the image changes. At most 10 images are read per minute, one after another, so a server under
    load is not asked for much. Stopped containers are never read.
  - **The template needs no change.** The reader's container already has the socket and the network the archive read uses.
    Read access to those four files is not a new permission on the socket.
- **No inspect of containers.** `/containers/{id}/json` is never called, because it returns each container's environment,
  where passwords are. The image inspect reply has `Env`, `Cmd` and `Entrypoint`; they are dropped as it arrives. A test puts
  a secret in each place Docker would and checks it is absent from the output. Image labels are kept only for
  `org.opencontainers.image.*` and `net.unraid.*` (cut to 200 characters), volume labels only for `com.docker.compose.*`.
- **A token, required, in constant time.** Both routes need `Authorization: Bearer <token>`, compared with
  `hmac.compare_digest` over the SHA-256 of each side. A wrong guess waits a quarter second and gets a 401, and a refused
  request never reaches Docker. The token is read from a file (`--token-file`) that must be a regular file with mode 0600,
  not a symlink, at least 32 characters. It is never an environment variable or a command-line argument, and it is in no
  log line, error, page or event (tests check each). The hub keeps its copy in `<data>/remotes/<id>.reader-token` (0600 in
  a 0700 folder; backed up with the keys, so the backup is as private as the token), never shows it back and deletes it
  with the system or when reading is switched off.
- **No published port.** The reader listens only on a user-defined Docker network shared with the hub
  (`docker network create daemonsight`) and the hub reaches it by container name. Nothing on the LAN can connect to it. The
  link is plain http, so the token is not encrypted on that network: only the two containers should be on it, and the hub
  runs with all capabilities dropped, so it can't sniff or spoof. Do not attach other containers to it.
- **A read-only container.** The template runs it with `--read-only` and a small `noexec` tmpfs, `--cap-drop ALL`,
  `no-new-privileges`, `--pids-limit 64`, `--memory 256m` and no healthcheck process. It writes nothing.
- **Not root.** It runs as uid 10001 with the socket's group added (`--group-add`, the group id from
  `ls -ln /var/run/docker.sock`), so a bug in it does not start as root inside the container. If the socket's group is root's
  (0), the reader runs with root's group; that does not make it root, but it is wider than a `docker` group.
- **The socket is mounted `:ro`, and that does not make the API read-only.** The `ro` flag only stops the container from
  replacing or deleting the socket file. A write to a unix socket is still a write, and Docker accepts POST requests over it.
  The reader is read-only because its own code sends only GET to a fixed list, not because of the mount. This is the weak
  point, and the reason the code is small and tested.
- **Untrusted replies.** The hub treats the reader's reply like any server's: re-checked for shape, cut to size (8 MiB at most)
  and shown escaped. Redirects are not followed and the hub ignores proxy settings from the environment for this call, so the
  token goes only to the address you entered.

**What remains.** A bug in the reader that lets someone make it send a request of their choosing to the Docker socket
(through a flaw in the allow-list, the web framework or the HTTP client) is root on the host. So is anything that gets code
running in the reader's container and can reach the socket: the read-only filesystem and dropped capabilities make that
harder, but the socket needs none of them. A stolen token alone cannot do that, since the reader never forwards a request;
it lets the holder read the summary (image, container and volume names, which is information about what runs on the server).
The token is stored on the hub and in its backups, and a hub that is compromised leaks it. Keep the reader's image
up to date with the hub's (they are the same image), keep the network to the two containers, and remove the reader when you
no longer use the page.

## CrowdSec bans

An OPNsense system can have the hub read CrowdSec's Local API on the firewall (Edit, "Read CrowdSec bans"), so a ban on an address
that must never be banned shows up as a finding. What the hub asks and why is in [docs/DESIGN.md](docs/DESIGN.md), "CrowdSec bans on
an OPNsense firewall".

- **A bouncer key, which only reads.** The credential is a CrowdSec bouncer key (`cscli bouncers add daemonsight-hub`). CrowdSec's
  docs say a bouncer's key "can only read decisions"; machine credentials can also create and delete them, so DaemonSight never takes
  those. The key reaches only `GET /v1/decisions`.
- **GET, filtered, nothing else.** The client has one method, which sends GET of `/v1/decisions` with an address, a network or
  `origins=crowdsec`, always with a `limit`. A read with no such filter would return all of CrowdSec's decisions, community blocklist
  included, so it is refused before it is sent, as is `/v1/decisions/stream` (the bouncer sync call) and every other parameter. Tests check
  this against a fake Local API that answers an unfiltered read with the whole list.
- **Plain http on the LAN.** CrowdSec's Local API listens on plain http unless you set up TLS, and the bouncer config shows
  `api_url: http://<firewall address>:<port>/`. The hub follows that: the key travels in clear on the LAN between the hub and the
  firewall, so anyone who can read that traffic can read decisions with it (and nothing else). Keep the hub and the firewall on a
  network you trust. To use TLS, enable it in CrowdSec's Local API config and change the address in the form to `https://`: the
  certificate is then checked against the usual authorities. A self-signed Local API certificate cannot be pinned yet.
- **Where the key is kept.** `<data>/remotes/<id>.crowdsec-key`, mode 0600 in a 0700 folder, written atomically. Never in the
  database, `config.toml`, a page, a log line or an event, and never shown back (a badge says a key is saved). Tests check each.
  Backups include the file and a restore puts it back, so the archive is as private as the key. Unticking the option or removing the
  system deletes it. If the hub is compromised the key leaks: delete the bouncer on the firewall (`cscli bouncers delete daemonsight-hub`).
- **Untrusted replies.** Whatever the Local API sends is cut to named fields and lengths, checked against the address that was asked
  about, capped in size and count, and shown escaped. A value that is not an address or a network is never put into a command.
- **Your never-ban list** holds addresses and networks you choose, validated and limited to 50. The hub asks CrowdSec about each, so
  the list is sent to CrowdSec on the firewall only.

## Alert channels

The hub can send alerts and digests to Ntfy, Slack, Discord and email. These are the only places the hub sends findings to. They are
off until an administrator adds a channel on the Settings page (Notifications), and only the hub sends: collectors never do.

- **New outbound destinations.** Each channel is one address the hub connects to: the webhook URL (Slack only
  `https://hooks.slack.com/`, Discord only `https://discord.com/api/webhooks/`), the Ntfy server the administrator names (any
  `https://` address, or `http://` to this machine), or the SMTP server the administrator names (implicit TLS or STARTTLS only, with the
  certificate and name checked; the password is sent only after encryption; there is no unencrypted option). The Ntfy and SMTP addresses
  are the administrator's own choice, so someone with the login can make the hub contact any host on those ports, as the remote
  systems' addresses already allow. No redirect is followed, a reply is read to at most 64 KB, and a request times out after 20 seconds.
- **What is sent.** Finding titles, host names, severities, deadlines and links to the hub, which can name packages, containers, ports
  and addresses. That is a map of your systems: send it only to channels you control. A public Ntfy server shows a topic's messages to
  anyone who knows its name.
- **Secrets.** A webhook URL, an Ntfy token or password and an SMTP password are stored like the remote systems' keys: a file
  `<data>/notify/<channel id>.secret`, mode 0600 in a 0700 folder, written atomically, never in the database, a page, a log line, an
  event or an error text (an error from a service is passed through a redaction of the channel's secrets first). The Settings page shows
  only that one is saved, with a blank box to replace it. The backups include these files, so keep backups as private as the data
  folder.
- **What a leaked webhook or token allows.** Slack and Discord webhook URLs are the whole credential: whoever has one can post
  messages to that one channel as the integration (fake alerts, links to a hostile site) but cannot read the channel, and no mentions
  work in what DaemonSight sends. Delete the webhook in Slack or Discord and make a new one. An Ntfy token or password lets its holder
  publish to, and read, whatever that account may; revoke the token on the Ntfy server. An SMTP password lets its holder send mail as
  that account, which is the larger risk: use an app password or a mailbox that can only send, and change it if it leaks.
- **Hostile text.** A finding's text can come from a package name, a container image or a remote system. Each message format
  neutralises it (entities in Slack, backslashes in Discord, `html.escape` in email, plain text in Ntfy; Discord's `allowed_mentions`
  names nobody; Slack's special mentions and links can't form), and links in a message are only ever the hub's own address.
- **Who can change channels.** Anyone with the login, with the same protections as other settings (the cross-site check and the
  strict cookie). Changes are listed under Recent hub changes without the secret. Someone with the login can read none of the saved
  secrets back, but can point a channel at a destination they control by replacing its secret, and so receive alerts there.

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
- **CVE matching downloads public files.** The hub fetches the Debian
  security tracker, FIRST's EPSS scores and CISA's KEV list over HTTPS, and
  CISA's SSVC rating of each CVE a host or image matches from the CVE Services
  API (`https://cveawg.mitre.org/api/cve/<CVE id>`, public, no key, one small
  request per CVE, asked again after 7 days; the hub obeys its `RateLimit-*`
  headers, accepts only that host, follows no redirect and refuses an answer
  over 1 MB; the request names a public CVE id and nothing about your
  hosts), and, when a container image on an Unraid server is Alpine, that release's
  `main.json` and `community.json` from `secdb.alpinelinux.org`, and, for each
  Ubuntu release a host or an image runs, Canonical's CVE OVAL file
  (`https://security-metadata.canonical.com/oval/com.ubuntu.<release>.cve.oval.xml.bz2`,
  about 12 MB, Creative Commons Attribution-ShareAlike 4.0), and, while an
  OPNsense firewall is enabled, the OPNsense project's
  changelog: one 0.6 MB tarball of its repository from `codeload.github.com`
  (`/opnsense/changelog/tar.gz/refs/heads/master`, BSD 2-Clause), read for the
  CVE ids in the release notes between the installed and the offered version.
  Release notes that name only a security advisory are looked up, one request
  each and only for the releases a firewall needs, on two more hosts:
  `www.freebsd.org` (`/security/advisories/FreeBSD-SA-<id>.asc`, a FreeBSD
  advisory, read for its `CVE Name:` line; `security.freebsd.org` redirects
  there, so the hub asks `www.freebsd.org` directly) and `api.github.com`
  (`/repos/opnsense/core/security-advisories/<GHSA id>`, OPNsense's own
  advisory, read for its CVE id and rating; no token, so GitHub's limit of 60
  requests an hour applies and the hub stops on a 403 or 429 until the time the
  answer gives). Each answer is kept and not asked for twice (a failed one is
  tried again after `refresh_hours`; a GitHub advisory that named no CVE is
  asked again after 7 days while a firewall still needs it). Nothing about your hosts is
  sent: the path names a public advisory. Requests carry
  the User-Agent `DaemonSight/<version>` and nothing about your hosts. A
  redirect may only stay on the feed's own host, each download has a size
  cap (the bzip2 files are also capped once decoded), files are written atomically and parsed with the standard library
  (no code is run from them). The changelog tarball is never extracted: it is
  read as a stream and only plain files named `community/<series>/<release>`
  are read, each capped. A failed download keeps the last good data. An
  advisory answer is HTTPS only, from the host asked, never redirected, capped
  (128 KB FreeBSD, 512 KB GitHub), and only CVE ids, GitHub's rating and a
  short title are kept.
- **The prioritisation table can be updated from the DaemonSight repository.** Once a week the hub asks `raw.githubusercontent.com`
  (a new outbound source) for two small JSON files in this project's repository,
  `/bradbrownjr/daemonsight/main/src/daemonsight/data/priority/current.json` (the name of the active table file) and that table, so
  that a directive replacing CISA BOD 26-04 reaches the hub without a release. The files are data only and nothing in them is
  executed, expanded or used as a template. Each is capped at 256 KB, fetched over HTTPS with a conditional request, and a redirect
  may only stay on `raw.githubusercontent.com`. The table goes through the same strict check as any table file (exact keys, types, all
  16 rows, allowed severities, https addresses), and only a `version` greater than the bundled table's (and the installed one's) is
  accepted, so a table cannot be rolled back. An invalid, oversized or unreachable answer changes nothing and is shown on the Data
  feeds card. A table you place at `<data folder>/priority/override.json` is never replaced. The request carries the User-Agent
  `DaemonSight/<version>` and nothing about your hosts. Settings, CVE checks, "Fetch prioritisation table updates from the DaemonSight
  repository" (`[cve] priority_updates = false`) turns it off. Trust placed in it: whoever can push to the repository's `main` branch
  can change the severities and deadlines your hub shows (never what runs); protect that branch accordingly.
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
- **The Shodan API key (optional).** The outside view can use Shodan's REST
  API instead of InternetDB, with the owner's key (Settings, Outside view). The
  key gets Shodan's data and your account's plan; treat it like a password.
  - *Where it is stored.* In a file, `<data>/shodan.key` (or `[outside]
    key_file`), mode 0600, written atomically. It is never in the `settings`
    table, an event, a page, a log line or an error, and it is not shown
    again once saved: the page shows only "A key is saved", with Replace and
    Remove. Backups include the file (the archive is 0600), so they are as
    private as the key.
  - *Who can change it.* Only someone logged in, on a hub, through `POST
    /settings/shodan-key` (save, remove, test). It needs the login and refuses
    a cross-site request, like every hub action. Saving and removing write the
    hub events "Shodan API key saved" and "Shodan API key removed", with who
    and no key material. The key's path and the source's default are not
    editable in the browser except the source itself, which is refused unless a
    key is saved.
  - *Where it goes.* Only to `api.shodan.io` over HTTPS, in the `key` query
    parameter: Shodan documents no other way, so there is no header to use.
    Redirects are not followed, so it can't be handed to another host. The
    InternetDB source never sends it.
  - *Redaction.* `key=...` is stripped from every error text the hub stores or
    shows, and from httpx's own request log lines (a filter on the `httpx`
    and `httpcore` loggers, which would otherwise print the full URL at INFO
    and DEBUG, and with `-v`). Tests assert the key is on no page, event, log
    line, finding or database page, and only in its file. The Exposure
    page's `curl` command says `key=YOUR_KEY`.
  - *If Shodan refuses it.* One `outside.key` finding says so at once and the
    hub asks nothing more for an hour, or until the key changes. It never falls
    back to InternetDB. A hub that is compromised leaks the key it holds: use
    a key you can revoke on your Shodan account page.
  - *What it tells Shodan.* The IP addresses, and that your account owns this
    hub. Its terms are your plan's; see INSTALL.md, "Outside checks".
- **Shodan's reply is untrusted text.** It is capped at 1 MiB (4 MiB for a full
  Shodan API host lookup, which carries every banner), parsed as
  JSON and cut down to ports (integers 1 to 65535), per port a transport (a
  strict pattern), product and version (length-limited text) and a time, CPEs,
  hostnames, tags
  (a strict pattern) and CVE ids (a strict pattern), each with a count and
  length limit. It is stored as data and shown only through autoescaped
  templates; the links it produces go to `nvd.nist.gov`, built from a CVE id
  that matched the pattern. A wrong reply, or Shodan being down, can give
  wrong or missing findings but can't run anything. Its tags and CVE lists
  are Shodan's own guesses from scanning; the findings say so.
- **Feed text is untrusted.** CVE descriptions and names come from other
  people's files. They are cut to a fixed length when stored and shown only
  through autoescaped templates, and the links they produce go to
  `security-tracker.debian.org` (Alpine images: `security.alpinelinux.org`; Ubuntu: `ubuntu.com/security`),
  built from a CVE id that matched a strict pattern. A bad feed can give wrong findings but can't run anything.
- **Refusals are logged** as `Refused upload from <address>: <reason>`.
  The fail2ban filter counts only bad tokens.
- **The hub can ask for two things: an update, and an uninstall.** Its reply
  carries the last sequence number it accepted and, when you've asked from the
  Hosts page, a commit for the host to install, or `uninstall`. Nothing else it
  says is acted on. The uninstall is described after the update.
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
  - **Uninstall.** An admin who picks "Uninstall the collector first" on
    Remove from hub makes the hub put `uninstall: true` in the reply to that
    host's next upload. That removes DaemonSight from the host, as root:
    `daemonsight uninstall` stops its services and deletes its units, program,
    config, upload token, database and backups, the fail2ban jail and sudoers
    rule if present, and the `daemonsight` user. Only DaemonSight's own files
    are named in it; the hub names nothing, only the request.
  - The collector acts only when all of these hold: the reply is a 2xx to an
    upload it sent with its own token; it went to the URL in `[upload] url`,
    over HTTPS with the certificate checked (or to this machine); the reply
    names the sequence number of that upload; and `uninstall` is exactly
    `true`. A 401, 403 or 404, a certificate error, an unreachable hub, a
    redirect or any other reply never uninstalls anything. A refused token
    only slows the collector to one try an hour.
  - It sends the hub a last upload saying it started, then hands the work to
    systemd: it writes `uninstall.request` (root, 0600) in its data folder,
    and a path unit starts `daemonsight-uninstall.service`, which runs
    `daemonsight uninstall --hub-request` as root. The collector's own
    sandboxing is unchanged. The service does nothing without that file, and
    re-reads `allow_remote_uninstall` from the host's own config first. The web
    UI cannot write the file: it runs as `daemonsight`, and the data folder is
    not writable by that group.
  - **The lock.** `[collector] allow_remote_uninstall = false` in the host's
    own config makes the collector answer "refused". The hub can't change it.
    Besides moving hosts to another published version (above), the worst a
    compromised hub can do with this switch on is delete DaemonSight, and with
    it the monitoring, from each host that uploads to it. It can't touch the
    host's other software or data, or run anything else. Lock a host where
    that matters more than removing it from the hub.
  - The hub sends `uninstall` only to a host an admin marked, and a host can
    only answer for itself. Starting, cancelling and "Remove anyway" are
    login-protected and refuse cross-site requests, like the other Manage
    actions.
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
