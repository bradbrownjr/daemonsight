# DaemonSight features

What each part does. For the plan and the data model see [DESIGN.md](DESIGN.md); for
setup see [INSTALL.md](INSTALL.md); for how it protects the hosts it runs on see
[SECURITY.md](../SECURITY.md).

## Hosts and collectors

- **What a collector reads.** System health, systemd services (over D-Bus),
  listening sockets, Docker, Caddy, fail2ban, the firewall and pending package
  updates. A small root collector writes snapshots; the web UI runs unprivileged
  and only reads them.
- **Findings link to the row they are about.** A port's panel shows the process
  behind it.
- **Fixes on findings.** A finding with one command to resolve it shows the
  command in a block with a Copy button. Findings with no single command, such
  as an exposed port, are decisions.
- **Per-host report.** `/h/<host>/report` (or `/report` on a single host) puts
  the open findings in order: install updates, restart services, reboot,
  automatic updates, then the rest. Each step has its commands merged and a Copy
  button. Copy it as text, download it as Markdown, or print it.

## Exposure

- **What the internet can reach.** The Exposure page checks listening sockets
  against the firewall rules, Docker's published ports and port forwards. The
  Routes page shows Caddy sites and whether their upstreams answer.
- **Seen from outside (Shodan).** Off by default. The hub can ask Shodan what
  the internet sees of each host's public addresses, once a day, sending only the
  IP address. Choose the source on the Settings page: InternetDB (free, no key,
  non-commercial use only) or the Shodan API with your own key (the route for
  commercial use; Test key shows your plan and credits, and the key is kept in a
  file and never shown again). The page lists each port Shodan sees with a status
  and what DaemonSight knows about it. With the API it also gives each port's
  transport, the software Shodan named and when it last saw it. Findings flag a
  port nobody expected, an expected port Shodan does not see, Shodan's
  compromise tags and CVE guesses, and a refused key. See
  [INSTALL.md](INSTALL.md), "Outside checks".
- **Status labels.** Every list says where each item stands: Unexpected, Accepted,
  Changed (accepted, but what it was about has changed) or Expected (listed in
  `exposure.expected_public`). Only Unexpected and Changed count as needing
  attention. Nothing is hidden: the Exposure page has a Status column on every
  listener and port forward, with a dash for what the internet cannot reach.
- **Accept with a note.** On a hub, an open finding can be accepted with a note.
  It leaves the counts, badges and report steps but stays in the list, in place,
  with an Accepted label and its note. It comes back, labelled Changed and
  counted again, when what you accepted changes, such as a new CVE in the same
  package. It is deleted when the finding resolves. The Overview list has an
  "All" and a "Needs attention" filter, and the report keeps its own Accepted
  section.

## Packages and CVEs

- **Updates.** Pending updates, reboots and services running on old libraries,
  for apt and dnf5.
- **Automatic updates.** The Packages page shows whether unattended-upgrades
  (apt) or dnf5-automatic (Fedora) will install security updates. A low finding
  says how to turn it on.
- **CVE matching on the hub.** Hosts report which packages they have. The hub
  matches them against the Debian security tracker or Canonical's Ubuntu
  OVAL data and rates each CVE with the timelines of CISA BOD 26-04: whether
  the system is reachable from the internet, whether the CVE is on CISA's
  known-exploited list, and CISA's rating of whether an attacker can automate
  it and how bad the impact is. Every finding says its deadline ("Fix within 3
  days", "Fix at the next upgrade") and which CVE sets it. One finding per
  package, and a Vulnerabilities page with the CVEs behind it. Debian, Raspberry Pi OS and Ubuntu hosts get the full list;
  Fedora hosts report their pending security advisories. On Ubuntu, a fix that
  only Ubuntu Pro's ESM archives carry is shown as "Fix needs Ubuntu Pro" and
  is not counted as one `apt upgrade` takes unless the host has Pro on. Hosts
  download nothing and run no scanner.

## Containers

- **Docker on a collector host.** Containers, health, restarts and logs, and
  the published ports that bypass the host firewall.
- **Docker images and volumes on Unraid.** Unraid's API does not list them, so
  an optional second container, the Docker reader, reads them from Docker and
  answers the hub. The Docker storage page lists the images and volumes no
  container uses, the build cache, and a guess at where each image came from
  (an old version left by an update, a removed app, its source label, a base
  image), with the `docker` command for each. Findings: old image versions,
  unused images, unused volumes (with a data-loss warning) and a build cache
  over 5 GB. DaemonSight never deletes anything. The reader holds the Docker
  socket, which is root on the server: read [SECURITY.md](../SECURITY.md) first.
- **Container images.** The reader also reads each running image's package list
  (four fixed files, through Docker's container archive call). The Container
  images page shows each image's base OS and whether it still gets security
  updates (finding: images on an end-of-life base). Debian images' packages are
  matched against Debian's security tracker and rated like a host's packages
  (finding: one per image, with the fixable CVEs and the deadline). An image
  counts as exposed when a container publishes a port that the firewall forwards. Alpine images are matched
  against Alpine's security database and Ubuntu images against Canonical's
  OVAL data in the same way; an Ubuntu fix that needs Ubuntu Pro is shown, not
  raised, since an image has no Pro.

## Unraid

- **Read over its API.** The hub polls an Unraid server with a Viewer-only API
  key, with no agent on the server. Add it with the + in the header ("Add a
  system"): Test connection shows the server, version, array state and the key's
  roles, and a key that could change anything is refused. Certificates are
  verified, or you pin one after confirming its fingerprint.
- **Pages.** Array and disks, containers grouped by your Docker folders, VMs, and
  notifications with the date and text of every unread alert. Each container shows
  its CPU and memory, sampled for a few seconds every minute; the Overview lists
  the five busiest by CPU and by memory.
- **Findings.** Full or hot disks, disk errors, a stopped array, an old parity
  check (with what it found, and when one was cancelled), unclean shutdowns
  (counted and dated), one finding for all container updates, a newer Unraid
  release, unread alerts grouped by title, and the UPS. Each finding from the
  hub's own rules has a "What to do" list. Notices DaemonSight already checks
  live (disk usage, temperature, parity checks) are not repeated as findings but
  stay listed on the Notifications page.

## OPNsense and CrowdSec

- **Read over its API.** The hub polls an OPNsense firewall with a dedicated
  user's API key and secret, with no agent. OPNsense has no read-only
  privilege, so the hub's client sends GET only and the key's user should hold
  only the listed privileges.
- **Pages.** Pass rules on internet-facing interfaces, port forwards, Caddy
  sites, WireGuard peers, Tailscale, gateways, interfaces and services.
  Interface roles (WAN, LAN, VPN, other) decide what is "internet-facing", and
  you can correct them. A forward that reaches a host also shows on that host's
  Exposure page.
- **CVEs a pending update fixes.** When the firewall offers a new OPNsense
  release, the hub reads the project's own changelog for every release and
  hotfix between the installed and the offered version, rates the CVE ids in it
  with CISA BOD 26-04's table (a firewall always counts as exposed), and shows "Fixes N CVEs (K known
  exploited)" on the Updates card with the release and the changelog line for
  each. The finding gains the count and the worst CVEs, and takes the deadline of the
  worst one. The changelog names many fixes only as
  a FreeBSD or GitHub security advisory. The hub looks each one up once and the
  CVE ids it lists join the ranking, with "via FreeBSD-SA-26:74.ktls" as the
  evidence. An advisory that lists none (or has not been looked up yet) is
  listed as "no CVE published", counted in the title ("fixes 27 CVEs and 2
  other security advisories"), and makes the finding at least Medium, or High
  when GitHub rates it High or Critical. Errata notices and plugin notes are not
  counted. Treat the CVE count as a floor.
- **A release the firewall has not seen.** The hub reads the changelog for every
  OPNsense firewall, not only one with an update pending. When it lists a
  newer release or hotfix in the firewall's series than the firewall runs or
  last saw, and the firewall has not checked for updates in 2 days or more (or
  its check time is missing), it raises a finding such as "26.7.10 is out
  (fixes 25 CVEs and 2 other security advisories); the firewall hasn't checked
  since Nov 18". It names the CVEs
  with the same ranking, tells you how to check now and how to add the
  firmware check to cron, and clears when the firewall checks. The Updates card
  shows the same sentence and CVE table. A major upgrade alone (a newer series)
  gets one line on the card, no finding.
- **Findings.** Pending firmware, a gateway down or lossy, a WireGuard peer that
  has not connected for a day or an instance with no peer, any-to-any and
  floating pass rules, forwards with no port, forwards and Caddy sites pointing
  at a host where nothing listens, a stopped service, and a full disk or hot
  sensor.
- **CrowdSec bans.** An optional read of CrowdSec's Local API on the firewall,
  with a bouncer key that can only read. DaemonSight asks about the firewall's
  own addresses and networks, every host the hub knows and a never-ban list you
  keep. It opens a High finding, with the command that ends it, when CrowdSec
  bans one of them. The Firewall page has a CrowdSec card with each address
  checked and the local bans by scenario.

## Hub

- **One page for every host.** The hub is a container image (with an Unraid
  template). Each host's collector uploads to it over HTTPS.
- **Host management in the web UI.** Every row of the Hosts table has a
  Manage button. A Linux host's page shows its version with Update now, and
  replaces its upload token, revokes it or removes it and its stored data,
  each behind a confirmation. Add a Linux host shows the token once with the
  command that installs it. The command line (`hub add-host`, `update`,
  `revoke`, `uninstall`) stays as an alternative.
- **Uninstall from the hub.** Remove from hub can uninstall the collector on
  the host first, like an RMM tool: the host is told with its next upload,
  runs `daemonsight uninstall`, and the hub then removes it and its data. Cancel
  or Remove anyway while it waits. A host can lock itself against this with
  `allow_remote_uninstall = false`. `daemonsight uninstall --yes` does the
  same by hand, and `daemonsight status` shows when the hub refuses a host's
  token.
- **Updates from the hub.** The Hosts page, or `daemonsight hub update`, moves
  hosts to the hub's own commit. A host can turn this off.
- **Retention and backups.** Retention sets how long history stays. Scheduled
  backups and `daemonsight restore` cover the database, config and secrets.

## Navigation and UI

- **Section menus.** Each page with sections has a section menu in its tab. The
  Hosts menu lists every host, A to Z, with its status. On a phone, one menu
  button opens the whole list of pages.
- **Settings page and account menu.** The button at the right of the header
  opens one menu with Settings, the theme (Light, Dark or Auto), "Hide empty
  sections" and Log out. On a hub the Settings page changes the outside view,
  CVE checks, retention, backups and remote polling without a restart. Each
  setting shows whether it comes from the Default, the Config file or "Set
  here", and can be reset. What controls login or where the server listens stays
  in the config file. On a host without a hub the page shows the running values
  read-only. See [INSTALL.md](INSTALL.md#the-settings-page).
- **Layout rules.** [UI.md](UI.md).

## How it compares

DaemonSight checks one question: what is exposed or out of date, and what do I do about it. Other tools answer different ones.

| | Metrics and uptime monitors (Netdata, Uptime Kuma) | SIEMs and host agents (Wazuh) | DaemonSight |
|---|---|---|---|
| Main job | Health, load, availability | Log analysis, intrusion detection, compliance | Exposure, patching and change findings |
| Needs an agent on every system | Often | Yes | A collector on Linux hosts only; none on Unraid or OPNsense |
| Cross-checks (a public port with no firewall rule or jail, a route with a dead upstream) | No | Not as one finding | Yes |
| Logs and alerts | Yes | Yes | Not yet: planned (see [DESIGN.md](DESIGN.md#phases)) |

It does not scan networks, read logs yet, or act on a server: it never changes anything it reads.
