# Planned sources

Designs for API systems DaemonSight does not read yet. UniFi was built from this design and has moved to docs/DESIGN.md, "UniFi Network"; everything else here is not built. Researched 2026-11-24; verify each fact again before building.

Scope to confirm with the owner: "Proxmox and its addons" is read here as Proxmox VE (PVE), Proxmox Backup Server (PBS), Proxmox Mail Gateway (PMG) and Proxmox Datacenter Manager (PDM), plus the community Helper-Scripts. The owner confirmed the helper scripts. PMG and PDM are still a scope guess.

## Summary and build order

| Order | Source | Why | Estimate (my guess, from the size of the Unraid and OPNsense work) |
|-------|--------|-----|------|
| Built | UniFi | See docs/DESIGN.md, "UniFi Network" | done |
| 2 | Proxmox VE, with the helper-script overlay | Most used; most of the findings people care about | 6 to 8 days, plus 2 to 3 for the helper scripts |
| 3 | PBS | Pairs with PVE; the Audit role is read-only and covers everything needed | 3 days |
| 4 | XCP-ng through Xen Orchestra | Only worth it once someone runs it | 5 to 6 days |
| 5 | FortiGate, Meraki, Aruba | Roadmap only | 5, 5 and 6 to 8 days |
| Later or never | PMG, PDM | PMG has no confirmed API tokens; PDM mostly repeats PVE and PBS | see below |

Shared work for the Proxmox and XCP-ng sources (the header form and path templates were done for UniFi in `remote/client.py`; the cookie and the reply cutting are still to do):

- `Rest` today sends HTTP basic auth and checks a path against a fixed set of whole strings. These APIs need three more things: a token header (`Authorization: PVEAPIToken=...`, `PBSAPIToken=...`, `X-API-KEY`), a cookie for Xen Orchestra, and paths with a variable part (node name, VM id). Proposal: a `Rest` option for the header form, and a whitelist of path templates where each variable part has a strict pattern (node: `[A-Za-z0-9-]+`, vmid: digits, uuid: hex and dashes), still compared as a whole and still GET only. Query strings are listed per template, not free.
- The certificate pin already covers a self-signed certificate. For the appliance's own certificate expiry, read it from the TLS handshake (the hub already fetches it for pinning) instead of from an API call. This avoids privileges that some products ask for (PBS needs Sys.Modify for its certificate call, see below).
- Reply fields are cut to a list in the hub, as for the Docker reader. This matters for PVE: a guest config can hold `cipassword`, `sshkeys`, `cicustom`, `args` and `hookscript`. The hub keeps only the fields it uses and never stores or logs the rest.

---

## Proxmox VE

### How the hub signs in

An API token on a dedicated user, with privilege separation on. Header: `Authorization: PVEAPIToken=USER@REALM!TOKENID=UUID`. The token secret is shown once. With privilege separation (the default for new tokens), the effective permissions are the intersection of the user's and the token's, so both the user and the token need the ACL. Tokens can carry an expiry. Source: https://pve.proxmox.com/pve-docs/chapter-pveum.html (API Tokens section; I read the page text).

PVEAuditor is described as "has read only access" in the same page. The exact privileges are in the source, `src/PVE/AccessControl.pm` in pve-access-control, where PVEAuditor is built from each group's audit list: `VM.Audit`, `VM.GuestAgent.Audit`, `Sys.Audit`, `Datastore.Audit`, `SDN.Audit`, `Pool.Audit`, `Mapping.Audit` (https://git.proxmox.com/?p=pve-access-control.git;a=blob_plain;f=src/PVE/AccessControl.pm;hb=HEAD, read 2026-11-24). It has no write privilege and no `Sys.Modify`, `Sys.Syslog`, `VM.GuestAgent.FileRead` or `VM.Console`.

Commands for the owner (user create, token create and ACL syntax from the same page; the page's example of a monitoring token is `pveum user token add joe@pve monitoring -privsep 1` then `pveum acl modify /vms -token 'joe@pve!monitoring' -role PVEAuditor`):

```
pveum user add daemonsight@pve --comment "DaemonSight read-only"
pveum user token add daemonsight@pve hub --privsep 1 --expire <unix-time>
pveum acl modify / --users daemonsight@pve --roles PVEAuditor
pveum acl modify / --tokens 'daemonsight@pve!hub' --roles PVEAuditor
pveum user token permissions daemonsight@pve hub
```

The `--users`/`--tokens`/`--roles` spelling is from `pveum acl modify` and is unverified here; the page's own examples use `-user`, `-token` and `-role`. Use the page's form.

### The one catch: pending updates

`GET /nodes/{node}/apt/update` ("List available updates") requires `Sys.Modify` on `/nodes/{node}`, which PVEAuditor does not have (PVE API viewer data, https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js). The same path with POST runs `apt-get update`, so Sys.Modify here is the privilege that guards a write on the same path. `GET /nodes/{node}/apt/versions` needs only Sys.Audit but lists the important Proxmox packages (installed version, running kernel), not the pending list.

**Decided (owner, 2026-11-24): updates and their CVEs are a key feature, and the token stays PVEAuditor.**
PVE nodes run Debian, so the collector installed on each node reports pending updates and the hub matches them
against Debian's security tracker, as for any Debian host. The custom role below is not built. Proxmox's own
packages (`pve-*`, `proxmox-*`) are not in Debian's tracker; whether Proxmox publishes advisories for them is
unverified and must be researched before building.

The rejected alternative, kept for the record: two tiers, chosen on the add form:

1. Default: PVEAuditor. Findings on installed versions only (see rules). No pending-update finding.
2. Optional "Read pending updates": a custom role, PVEAuditor plus Sys.Modify:

```
pveum role add DaemonSightUpdates --privs "Sys.Audit Sys.Modify VM.Audit VM.GuestAgent.Audit Datastore.Audit Pool.Audit SDN.Audit Mapping.Audit"
pveum acl modify / --users daemonsight@pve --roles DaemonSightUpdates
pveum acl modify / --tokens 'daemonsight@pve!hub' --roles DaemonSightUpdates
```

Sys.Modify is described as "create/modify/remove node network parameters" (pveum chapter). A stolen token could therefore change node network settings. That breaks "the server's own role is read-only too", which Unraid has. The form must say so, and the SECURITY.md paragraph must say the hub's GET-only client is the only limit in tier 2. Whether the GET lists the cache of the last `apt update` (refreshed by PVE's own job) is unverified; I assume yes. `role add` syntax is from the page (`pveum role add VM_Power-only --privs "VM.PowerMgmt VM.Console"`). Roles starting with PVE are reserved, hence the name.

Open question 1 is whether the owner accepts tier 2.

### TLS

Each node has a certificate signed by the cluster's own CA, used by pveproxy, "not automatically trusted by browsers" unless an external or ACME certificate is set (https://pve.proxmox.com/pve-docs/chapter-sysadmin.html, "Certificates for API and Web GUI"). So the pin applies, as for Unraid. Default port 8006 (unverified here; it is the web UI port in PVE docs). In a cluster, each node has its own certificate; the hub talks to one address, so a pinned node's replacement means a re-pin.

### GET-only whitelist

All entries are GET. "Priv" is the permission from the API viewer; all are within PVEAuditor unless marked. The path base is `/api2/json`.

| Template | Gives | Priv |
|----------|-------|------|
| `/version` | PVE version | any user |
| `/cluster/status` | quorum, node online, per-node subscription level | Sys.Audit on `/` |
| `/cluster/resources` | every node, guest and storage in one call: status, `template`, `tags`, `lock`, `hastate`, `disk`/`maxdisk`, uptime, `pool` | filtered to what the token can see |
| `/nodes` | node list, status, uptime | any user |
| `/nodes/{node}/status` | node CPU, memory, boot info | Sys.Audit |
| `/nodes/{node}/apt/versions` | installed Proxmox packages, running kernel | Sys.Audit |
| `/nodes/{node}/apt/update` | pending updates (tier 2 only) | Sys.Modify |
| `/nodes/{node}/apt/repositories` | repository files, `errors`, `infos`, `standard-repos` with enabled flags | Sys.Audit |
| `/nodes/{node}/subscription` | `status` (new, notfound, active, invalid, expired, suspended), `level`, `nextduedate`, `checktime` | any user (the key is shown only if permitted; the hub drops `key` and `serverid`) |
| `/nodes/{node}/certificates/info` | certificate files with `notafter`, `fingerprint`, `san` (the hub drops `pem`) | any user |
| `/nodes/{node}/storage` | per-storage `used`, `total`, `avail`, `active`, `enabled`, `content`, `shared` | Datastore.Audit per storage |
| `/nodes/{node}/storage/{storage}/content?content=backup` | backup volumes with `vmid`, `ctime`, `verification`, `protected` | Datastore.Audit |
| `/nodes/{node}/qemu`, `/nodes/{node}/lxc` | guest index | VM.Audit per guest |
| `/nodes/{node}/qemu/{vmid}/config`, `/nodes/{node}/lxc/{vmid}/config` | `tags`, `description`, `template`, `ostype`, `onboot`, `protection`, `lock` (cut to a field list, see above) | VM.Audit |
| `/nodes/{node}/qemu/{vmid}/status/current`, `/nodes/{node}/lxc/{vmid}/status/current` | running state, uptime | VM.Audit |
| `/nodes/{node}/qemu/{vmid}/snapshot`, `/nodes/{node}/lxc/{vmid}/snapshot` | snapshot names and times | VM.Audit |
| `/cluster/backup` | vzdump schedule jobs | Sys.Audit |
| `/cluster/backup/{id}/included_volumes` | guests a job covers | Sys.Audit |
| `/cluster/backup-info/not-backed-up` | "all guests which are not covered by any backup job" | Sys.Audit |
| `/nodes/{node}/tasks?typefilter=vzdump&errors=1&since=<t>&limit=<n>` | failed backup tasks (`status`, `vmid` in `id`, `endtime`) | Sys.Audit on the node |
| `/cluster/ha/status/current`, `/cluster/ha/resources` | quorum, master, LRM, service states, fencing | Sys.Audit |
| `/cluster/firewall/options` | `enable`, `policy_in`, `policy_out`, `policy_forward` | Sys.Audit |
| `/cluster/firewall/rules`, `/nodes/{node}/firewall/options`, `/nodes/{node}/firewall/rules`, `/nodes/{node}/qemu/{vmid}/firewall/options`, `/nodes/{node}/qemu/{vmid}/firewall/rules`, and the `lxc` versions | whether each level's firewall is on, and its rules | Sys.Audit or VM.Audit |
| `/cluster/ceph/status` | raw `ceph status`, with `health.status` | Sys.Audit or Datastore.Audit |
| `/nodes/{node}/disks/list`, `/nodes/{node}/disks/smart` | disk health (optional) | Sys.Audit |

Source for the table: the PVE API viewer data file (https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js, parsed 2026-11-24, which is the current docs and may be ahead of the owner's PVE version; the hub treats a 404 as "not in this version", as for an OPNsense plugin). `allowtoken` is 1 on all of them.

Not requested: any POST, PUT or DELETE; `/nodes/{node}/apt/update` POST; `/nodes/{node}/qemu/{vmid}/agent/*` (the file-read call needs a privilege PVEAuditor lacks); `/access/*`; storage `download-url`.

### Findings (rule, severity, one line, fix and how-to)

Severity follows the OPNsense rules: low, medium, high. "Accept basis" is what stays constant when accepted.

| Rule | Sev | Raised when | Fix or how-to | Accept basis |
|------|-----|-------------|---------------|--------------|
| `pve.updates` | low, medium if the hub has seen updates waiting over 14 days, high with a security-origin package waiting over 7 days (tier 2) | updates pending | `apt update && apt dist-upgrade` on the node, or Node, Updates in the GUI; steps say to read the changelog and migrate guests off first in a cluster | the set of package names |
| `pve.reboot` | medium | running kernel in `apt/versions` differs from the installed one | `reboot` on the node, after moving guests | the installed kernel version |
| `pve.repo_no_subscription` | medium | `subscription.status` is `notfound` while `apt/repositories` shows the enterprise repository enabled (updates fail with an error) | disable the enterprise repo or add the no-subscription one, or enter the key; howto only | constant |
| `pve.subscription` | low | status `expired`, `invalid` or `suspended`, or `nextduedate` within 30 days | howto: renew in the Proxmox customer portal | status |
| `pve.repo_errors` | medium | `apt/repositories` `errors` not empty | howto | the file names |
| `pve.cert_expiring` | medium at 14 days, high when expired | TLS certificate or `certificates/info` `notafter` | howto: Node, System, Certificates, renew (ACME if set) | constant |
| `pve.backup_missing` | high | a running, non-template guest appears in `backup-info/not-backed-up`, or has no backup volume newer than N days (default 3) on any storage that holds backups | howto: Datacenter, Backup, Add; for a deliberately unbacked guest (test VM), accept it | the guest id |
| `pve.backup_failed` | medium | a vzdump task for a guest ended in error in the last N days and no later success | howto: open the task log in Node, Tasks | guest id |
| `pve.backup_old` | medium | newest backup for the guest older than N days (default 7) | same | guest id |
| `pve.storage_full` | medium at 85%, high at 95% | `used/total` of an active storage | howto: prune old backups or add space | storage name and severity |
| `pve.storage_inactive` | medium | storage enabled but not `active` | howto | storage name |
| `pve.firewall_off` | medium | `/cluster/firewall/options` `enable` is 0 (also reports when a node's firewall is off while the cluster's is on) | `pve-firewall` howto; fix lines: `pvesh set /cluster/firewall/options --enable 1`, with a warning to add an allow rule for the web UI and SSH first, so a lockout is not caused by the fix | constant |
| `pve.guest_firewall_off` | low | a guest has its own firewall off while the cluster's is on | howto | guest id |
| `pve.ha_quorum` | high | cluster not quorate, or a node offline | howto | node |
| `pve.ha_service_error` | high | an HA service state `error` or `fence` | howto | service id |
| `pve.ceph_health` | medium for HEALTH_WARN, high for HEALTH_ERR | `health.status` | howto: `ceph health detail` on a node | the health check names |
| `pve.guest_lock` | low | a guest `lock` held over 1 day | howto: `qm unlock <id>` after checking its task | guest id |
| `pve.snapshot_old` | low | a guest snapshot older than 30 days | howto | guest id |
| `pve.disk_smart` | high | SMART health not PASSED (optional) | howto | disk |

Reasons for the numbers: they are defaults in Settings (GUI-first), the same way OPNsense thresholds are constants in its rules file.

### Pages and cards

Follow docs/UI.md: one sentence per card, details behind the (i), same column width top to bottom, steps folded. A host kind `proxmox` in `web/sections.py`, mirroring `opnsense`:

- Overview: Findings, At a glance (nodes online, quorum, guests running of total, backups newest, storage worst), Recent changes.
- Guests: one table of VMs and containers (name, id, node, state, tags, last backup, protected, snapshot count). Helper-script column (see below).
- Storage and backups: storages with a usage bar; backup jobs; guests with no job.
- Cluster: nodes, HA, Ceph, firewall, subscription and repositories.
- Report: Steps, Decide, All findings, Accepted (as the other hosts).

Polling: `interval` for status and resources; 5 minutes for backups, repositories, subscription and updates (same split as OPNsense). `/cluster/resources` makes the guest list one call per poll.

---

## Proxmox Helper-Scripts (community) overlay

Project: https://github.com/community-scripts/ProxmoxVE ("Proxmox VE Helper-Scripts (Community Edition)", MIT, about 30,000 stars, last push 2026-11-24 per the GitHub API). The shared build engine now lives in a second repository, https://github.com/community-scripts/core (build.func, update helper, docs). Website: https://community-scripts.org.

### How to recognise a guest a script created

Read from the repository's own code (core `ui/advanced.func` and `ui/defaults.func`, read 2026-11-24):

| Signal | What the code does | Readable with PVEAuditor? | How reliable |
|--------|-------------------|--------------------------|--------------|
| Tag `community-script` | Containers get `TAGS="community-script"` plus the script's `var_tags` (for example `adblock`), set with `pct create -tags` | Yes: `tags` in `/cluster/resources` and in the guest config | Good, but a person can remove or rename a tag in the GUI |
| Notes (description) | `description()` runs `pct set $CTID -description` with a block of HTML: a Community-Scripts logo, "<App> LXC", and a link `https://community-scripts.org/scripts/<slug>` (core `pve/backend.func`) | Yes: `description` in the LXC config (VM.Audit) | Good for the slug; the slug is the only machine-readable app name on the guest. A person can edit the notes |
| `/usr/bin/update` inside the guest | Generated by `write_update_entrypoint()` (core `core/core.func`, described in core `docs/updates.md`) | No | n/a |
| `~/.<app>` and `/opt/<app>_version.txt` | Example: ct/actualbudget.sh tests `~/.actualbudget` and `/opt/actualbudget_version.txt` (ProxmoxVE `ct/actualbudget.sh`) | No | n/a |

Not possible: reading any file in a container. The PVE API has no exec call for LXC, and the guest-agent file read (QEMU only) needs `VM.GuestAgent.FileRead`, which PVEAuditor does not have. PVEAuditor has `VM.GuestAgent.Audit` only, which is not a file read. So `/usr/bin/update`, the version files and the installed app version stay unreadable. Combine tag and notes: tag present and notes link present gives a "built by a helper script" guess with the app slug.

### Machine-readable metadata

The repository used to carry `json/*.json` per app. It no longer has a `json` folder on `main`; a workflow, `push-json-to-pocketbase.yml`, still pushes changed `json/**` files to a PocketBase database. The catalog is public:

- `GET https://community-scripts.org/api/update-info?slug=<slug>` returned, for `adguard`: `found`, `state` (active, disabled, deleted, unknown), `name`, `type` (lxc), `updateable`, `install_command`, `script_path`, `breaking_changes` (tested 2026-11-24). Documented in core `docs/updates.md`.
- `GET https://db.community-scripts.org/api/collections/script_scripts/records?filter=(slug='adguard')&perPage=1` returned a full record: `install_methods` with `resources.os` and `resources.version` (Debian 13 or Alpine 3.24 for AdGuard), `updateable`, `notes` (such as "can only be updated via the user interface"), `documentation`, `repository`, `is_disabled`, `is_deleted`, `pinned_version`. The scripts themselves call this endpoint (core `ui/menu.func`, `runtime_script_status_guard`).

Neither endpoint is described as a supported public API by the project. I did not find a published schema or rate limit: unverified. The hub should fetch the catalog once a day, cache it, send only slugs it already sees (no host data), and have a Settings switch (default off, since it is an outbound call to a third party).

What the hub can do with it:

- Show app name, default base OS and the "update" how-to link per guest.
- Base-OS end of life: ostype from the guest config says debian, ubuntu or alpine; the catalog says the script's default version. DaemonSight already holds endoflife.date data for Alpine and CentOS and distro-info for Debian and Ubuntu (DESIGN.md "Container images" and "Operating system"). The finding must say "default version per the script; the container may differ", because the real version is not readable. The catalog also tells when a script was removed or disabled (`state`), which is a finding in itself.
- The how-to: "Open the container's console and run `update`" (core docs).

### Findings

| Rule | Sev | Raised when | Note |
|------|-----|-------------|------|
| `pve.helper_scripts` | info (listed, not counted) | guests carry the tag and notes link | factual text, see below |
| `pve.helper_script_removed` | medium | catalog `state` is `deleted` or `disabled` for a guest's slug | the app can no longer be updated by `update`; core docs say a deleted script is not pulled |
| `pve.helper_os_eol` | medium, high once EOL | script's default OS release (matching the guest's ostype) past end of life | wording says "default"; accept basis the slug and OS |
| `pve.helper_breaking` | low | catalog `breaking_changes` not empty for the slug | link to the advisory |

### Security angle, stated plainly

These are facts from the project's own code and policy; the project is popular and widely used, and its README tells users to read a script before running it ("These commands run as root on your host. Every script is readable in this repository", https://github.com/community-scripts/ProxmoxVE README).

- Run-time fetch: ct scripts begin by sourcing `build.func` from `raw.githubusercontent.com/community-scripts/core/main` (ProxmoxVE `ct/adguard.sh`, core `core/build.func`), and the in-guest `/usr/bin/update` pulls the app's `ct/<name>.sh` from `main` each time (core `docs/updates.md`). Both follow the branch tip, not a fixed commit. The catalog has a `pinned_version` field; what it pins is unverified.
- Signing: I found no sign of signed releases or script checksums in the files I read. Unverified; I did not check commit signing or branch protection.
- Incidents and notices: GitHub's repository security advisories list was empty when queried (https://api.github.com/repos/community-scripts/ProxmoxVE/security-advisories, 2026-11-24). A security policy exists with private reporting (https://github.com/community-scripts/ProxmoxVE/blob/main/SECURITY.md). Fixes are public as pull requests, for example #15007, "Fix MITM RCE vulnerability in microcode scripts", merged 2026-06-08, where two host scripts downloaded Intel microcode over HTTP and installed it with `dpkg -i` (https://github.com/community-scripts/ProxmoxVE/pull/15007; severity and CVSS 6.5 are the author's text), and #15009, HTTP to HTTPS for downloads. Third-party issues #15298 and #15669 claim a "self-hosted runner risk"; they are scanner reports, unverified.
- Wording for `pve.helper_scripts`: "N guests were built by Proxmox VE Helper-Scripts (community project). Their `update` command downloads and runs the current script from GitHub as root, so the update is as trustworthy as that repository at that moment. This is how the project works, not a fault. Read a script before first use; to hold a version, take a Proxmox backup before updating." No fix command; accept basis is the list of slugs.

The overlay needs only the guest list and config the PVE source already reads, so it ships with PVE.

---

## Proxmox Backup Server

### Sign in and role

API token, header `Authorization: PBSAPIToken=TOKENID:TOKENSECRET`; made with `proxmox-backup-manager user generate-token john@pbs client1` (https://pbs.proxmox.com/docs/user-management.html). Token permissions come from ACLs naming the token and are intersected with the user's, so the token needs its own entries and "can never do more than their corresponding user" (same page). PBS has only built-in roles, "you cannot create your own, custom role". The role `Audit` "can view the status and configuration of things, but is not allowed to change settings"; `DatastoreAudit` "can view datastore metrics, settings and list content. But is not allowed to read the actual data" (same page). So no custom role is needed, and unlike PVE, pending updates need only Sys.Audit.

```
proxmox-backup-manager user create daemonsight@pbs
proxmox-backup-manager user generate-token daemonsight@pbs hub
proxmox-backup-manager acl update / Audit --auth-id daemonsight@pbs
proxmox-backup-manager acl update / Audit --auth-id 'daemonsight@pbs!hub'
proxmox-backup-manager user permissions 'daemonsight@pbs!hub' --path /datastore
```

(Command forms from the user-management page: `user create`, `generate-token`, `acl update /datastore/store1 DatastoreAdmin --auth-id ...`, `user permissions ... --path ...`.) `user permissions` is a CLI command. Over the API, PBS has `GET /access/permissions` (Sys.Audit on `/access` or own privileges), which can report the token's own privileges, so the hub can refuse a token that holds anything but audit privileges, as it does for Unraid. Reply shape is unverified; plan to read it on a test system.

TLS: PBS uses its own self-signed certificate by default (unverified here; PBS docs say so in certificate management, which I did not read), so the pin applies. Port 8007 (PBS client docs use `...:8007`, seen in the PMG guide example).

### Whitelist (GET; from https://pbs.proxmox.com/docs/api-viewer/apidoc.js, parsed 2026-11-24)

| Template | Gives | Priv |
|----------|-------|------|
| `/version` | version | any |
| `/status/datastore-usage` | per datastore `used`, `total`, `avail`, `estimated-full-date`, `gc-status`, `error`, `mount-status` | filtered by access |
| `/admin/datastore/{store}/status` | usage, counts per backup type, `gc-status` | Datastore.Audit |
| `/admin/datastore/{store}/groups?ns=...` | each backup group: `backup-type`, `backup-id`, `last-backup`, `backup-count`, `owner` | Datastore.Audit |
| `/admin/datastore/{store}/namespace` | namespaces | Datastore.Audit |
| `/admin/gc` | GC jobs: `last-run-state`, `last-run-endtime`, `next-run`, `schedule` | Datastore.Audit |
| `/admin/verify` | verify jobs with `last-run-state`, `last-run-endtime`, `outdated-after`, `ignore-verified` | Datastore.Audit |
| `/admin/prune` | prune jobs with `last-run-state`, `next-run` | Datastore.Audit |
| `/admin/sync` | sync jobs with `last-run-state` | Datastore.Audit |
| `/nodes/localhost/status` (node name `localhost` is used by PBS; unverified) | CPU, memory, root disk, `current-kernel` | Sys.Audit |
| `/nodes/{node}/apt/update` | pending updates with `Origin` | Sys.Audit |
| `/nodes/{node}/apt/versions`, `/nodes/{node}/apt/repositories` | installed packages, repo errors and `standard-repos` | Sys.Audit |
| `/nodes/{node}/subscription` | `status`, `nextduedate` | any |
| `/nodes/{node}/tasks?errors=1&limit=...` | failed tasks (`worker_type`, `worker_id`, `status`) | Sys.Audit on `/system/tasks` |
| `/nodes/{node}/disks/smart`, `/nodes/{node}/disks/zfs` (optional) | disk and pool health | Sys.Audit |

Not used: `/nodes/{node}/certificates/info` (needs Sys.Modify; the hub reads the TLS certificate instead), `/admin/datastore/{store}/download*`, `catalog`, `pxar-file-download` (they read backup data), `/nodes/{node}/journal` and `syslog` (logs may hold names).

### Findings

| Rule | Sev | Raised when | Fix or how-to |
|------|-----|-------------|---------------|
| `pbs.datastore_full` | medium 85%, high 95% | `used/total`; also when `estimated-full-date` is within 30 days (low) | howto: prune, run GC, add space; GC only frees space after prune |
| `pbs.gc_failed` | high | a datastore's GC `last-run-state` is not `OK` | howto: Datastore, Garbage collect task log |
| `pbs.gc_never` | medium | no GC job and no run for 30 days | howto: add a GC schedule |
| `pbs.verify_failed` | high | verify job `last-run-state` not `OK` (corrupt chunks are possible) | howto: open the task log; re-verify |
| `pbs.verify_missing` | medium | datastore has no verify job | howto |
| `pbs.verify_old` | low | last verify over N days (default 35) | howto |
| `pbs.prune_failed` | medium | prune job failed | howto |
| `pbs.sync_failed` | medium | sync job failed (an offsite copy is not updating) | howto |
| `pbs.group_stale` | high | a backup group (VM or CT) has `last-backup` older than N days (default 3) | howto: check the PVE job that writes to it; accept when decommissioned |
| `pbs.updates` | as `pve.updates` | pending updates | `apt update && apt full-upgrade` |
| `pbs.repo_no_subscription` | medium | as PVE | howto |
| `pbs.subscription` | low | as PVE | howto |
| `pbs.cert_expiring` | as PVE | TLS certificate | howto |
| `pbs.task_failed` | low | failed tasks in the last day not covered above | detail only |

Pages: a kind `pbs` with Overview, Datastores (usage, jobs, newest backup per group), Report. The group list is the place to answer "last backup per guest" across PVE and PBS.

---

## Proxmox Mail Gateway: brief, recommend later

- Roles: Superuser, Administrator, Quarantine Manager, Auditor ("read-only access to the whole configuration, can access logs and view statistics"), Helpdesk (https://pmg.proxmox.com/pmg-docs/pmg-admin-guide.html). The Auditor role would be right.
- Sign in is the problem. The PMG API viewer marks calls `allowtoken: 1`, but a Proxmox staff member said in the forum on 2024-11-04 that API tokens "are simply not implemented in PMG yet" (https://forum.proxmox.com/threads/why-are-there-no-api-tokens.156802/); I found no token text in the current admin guide. Unverified whether that changed. Without tokens, the hub would store a user's password and log in with `POST /access/ticket` ("You need to pass valid credentials", from the PMG API viewer, https://pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js). That is a POST and a password, which breaks the GET-only client and the "key, not password" rule.
- Worth reading if it is built: `/nodes/{node}/apt/update` and `versions` (admin or audit), `/nodes/{node}/subscription`, `/nodes/{node}/status`, `/nodes/{node}/clamav/database` (virus database build time), `/nodes/{node}/spamassassin/rules`, `/statistics/mail` (counts: spam, virus, bounces, RBL rejects), `/quarantine/spamstatus`, `/quarantine/virusstatus`, `/config/cluster/status`. The Postfix queue size is under `/nodes/{node}/postfix/queue`; fields unverified.
- Findings if built: updates pending, ClamAV database older than 2 days, quarantine growing, cluster node out of sync, subscription.
- Recommendation: do not build now. Revisit when PMG gets tokens or the owner runs one. Value is low compared with the sign-in cost.

## Proxmox Datacenter Manager: recommend not supporting

- Status: version 1.0 stable announced 2025-12-04, built on Debian 13, AGPLv3, needs PVE 8.4 or PBS 3.4 or newer remotes (https://proxmox.com/en/about/company-details/press-releases/proxmox-datacenter-manager-1-0, and https://forum.proxmox.com/threads/proxmox-datacenter-manager-1-0-stable.177320/). Its current docs are for version 1.1.10, dated 2026-11-14 (https://pdm.proxmox.com/docs/).
- What it does: one inventory of PVE and PBS "remotes", a dashboard, aggregated tasks, an update overview, and actions such as power and migration (https://pdm.proxmox.com/docs/introduction.html, https://pdm.proxmox.com/docs/remotes.html). It has API tokens and its own access-control and API viewer (page headings only; details unverified).
- It adds nothing DaemonSight cannot read directly from PVE and PBS, except a single pane across many clusters and the update overview without Sys.Modify (unverified: depends on how PDM reads updates). Against that, PDM holds credentials to every remote and can act on them; reading it does not remove the need for per-product findings (backup age, datastore usage).
- Recommendation: skip. Read PVE and PBS directly. Reconsider only if the owner has many clusters behind PDM and wants one key to read them all; check then that a PDM token can be limited to audit.

---

## XCP-ng

### Two ways in

| | XAPI directly | Xen Orchestra (XO) REST API |
|---|---|---|
| Protocol | XML-RPC or JSON-RPC, POST, on the pool master; a non-master answers `HOST_IS_SLAVE` with the master's address (https://xapi-project.github.io/xen-api/usage.html) | HTTP REST, `/rest/v0`, GET for reads (https://docs.xen-orchestra.com/automation/restapi, source https://raw.githubusercontent.com/vatesfr/xen-orchestra/master/docs/docs/automation/restapi.md) |
| Sign in | `session.login_with_password` with a user name and password | token, sent as the `authenticationToken` cookie; created for a user and expiring (`maxTokenValidity`) |
| Read-only role | XenServer's RBAC has "Read Only: can view resource pool and performance data" (https://docs.xenserver.com/en-us/xenserver/8/users/rbac-roles-permissions), but "RBAC depends on Active Directory" and local root has everything (https://docs.xenserver.com/en-us/xenserver/8/users/rbac-overview). XCP-ng calls host-level AD "deprecated" and recommends managing users in XO (https://docs.xcp-ng.org/management/users-permissions/). So in practice the hub would hold the root password | XO RBAC: a template role "Read only" ("Read access to the entire infrastructure and all XO objects. Cannot modify anything."), and custom roles built from resource and action pairs (https://raw.githubusercontent.com/vatesfr/xen-orchestra/master/docs/docs/security/user-management/rbac.md). On XOA, RBAC is in the Essential+, Pro and Enterprise bundles; installs from source are not restricted (same page) |
| Reads | `get_all_records` and `get_*` calls; the same endpoint also takes writes, so a GET-only client does not fit; a method whitelist would be needed | plain GET, filter and `fields` parameters, NDJSON; the API documents itself at `/rest/v0/docs` and `/rest/v0/docs/swagger.json` |
| Backups | not in XAPI (XO's own jobs) | `backup-jobs`, `backup-logs` (below) |

Recommendation: Xen Orchestra's REST API. Reasons: a real read-only role, a token instead of a root password, GET only, XO's backup data (which XAPI does not have), and one address for many pools. Cost: it needs XO (XOA or from source) to exist. If the owner has XCP-ng with no XO, say so on the add form: XAPI direct would need the root password, which this project refuses to store as a key. Do not build XAPI direct.

### Role

Do not rely on the "Read only" template as is: it covers "all XO objects", which on the RBAC page's resource list includes users, groups, roles, servers (the stored XCP-ng credentials) and tokens; I did not read what each read returns, so treat it as wider than needed (unverified). Copy the template and remove those, or build a custom role from the resource and action pairs: `read` on `vm`, `vm-snapshot`, `vm-template`, `host`, `pool`, `sr`, `pbd`, `network`, `alarm`, `message`, `task`, `backup-job`, `backup-log`, `backup-repository`, `schedule`. A role is a container of privileges, made with `POST /rest/v0/acl-roles`, `POST /rest/v0/acl-privileges` and `PUT /rest/v0/acl-roles/<id>/users/<userId>`; a template must be copied first with `POST /acl-roles/<template-id>/actions/copy` (same RBAC page). The hub's own check: `GET /rest/v0/users/me/acl-privileges` ("List your own privileges", always allowed) lets it refuse a token whose user holds any action other than `read`, as for Unraid.

Create the token: `xo-cli create-token xo.example.org <user>` or `POST /rest/v0/users/me/authentication_tokens` (restapi page). A token acts "within the limits of" the user's privileges (RBAC page).

TLS: XO serves HTTPS on its own, often self-signed (unverified); the pin applies. Hosts' own certificates are not visible through XO's REST routes I found (unverified), so no host certificate finding.

### GET-only whitelist (routes from the XO source, https://github.com/vatesfr/xen-orchestra/tree/master/@xen-orchestra/rest-api/src, read 2026-11-24)

| Template | Gives |
|----------|-------|
| `/rest/v0/pools`, `/pools/{id}`, `/pools/{id}/missing_patches`, `/pools/{id}/alarms`, `/pools/{id}/dashboard` | pool, patches the pool lacks, alarms |
| `/rest/v0/hosts`, `/hosts/{id}`, `/hosts/{id}/missing_patches`, `/hosts/{id}/alarms` | host, version, patches missing (the reply has a `hasAuthorization` field; whether patch data needs a paid XOA is unverified) |
| `/rest/v0/vms`, `/vms/{id}`, `/vms/{id}/alarms`, `/vms/{id}/backup-jobs`, `/vms/{id}/vdis` | power state, tools (the VM object's guest tools fields, names unverified), which backup jobs cover the VM |
| `/rest/v0/vm-snapshots`, `/vm-snapshots/{id}` | snapshots (age field name unverified; read the swagger file) |
| `/rest/v0/srs`, `/srs/{id}`, `/srs/{id}/alarms` | SR usage (field names unverified) |
| `/rest/v0/backup-jobs`, `/backup/jobs/vm`, `/backup/jobs/vm/{id}`, `/backup/jobs/mirror`, `/backup/jobs/metadata` | backup job definitions |
| `/rest/v0/backup-logs`, `/backup/logs`, `/backup-logs/{id}` | job runs and results |
| `/rest/v0/backup-repositories` | backup targets |
| `/rest/v0/alarms`, `/rest/v0/messages`, `/rest/v0/tasks` | XO and XAPI alarms (for example low SR space), messages, tasks |
| `/rest/v0/users/me/acl-privileges` | the key check |

Exclude: every `/actions/` POST; `GET /hosts/{id}/audit.txt` and `/hosts/{id}/logs.tgz` (exports, likely hold logs); `GET /vms/{id}.{format}` (VM export). XO's collections accept `fields`, `filter` and `limit` (restapi page), so the hub requests only the fields it uses.

First step when building: on Test connection, fetch `/rest/v0/docs/swagger.json` and confirm each route and field the hub uses is in it, then freeze the field list in a constant. HA state: XAPI has a pool-level HA setting; whether the XO REST pool object exposes it is unverified.

### Findings

| Rule | Sev | Raised when | Fix or how-to |
|------|-----|-------------|---------------|
| `xcp.patches` | medium, high after 14 days or when several | `missing_patches` not empty on a host or pool | howto: Pool, Patches, Install pool patches (https://docs.xcp-ng.org/management/updates/); rolling pool update |
| `xcp.reboot` | medium | host needs a restart after updates (XO shows "Reboot to apply updates"; the field is unverified) | howto |
| `xcp.sr_full` | medium 85%, high 95% | SR `physical_usage` over `physical_size` (names unverified) | howto: move or delete disks, add space |
| `xcp.sr_unplugged` | high | a PBD not attached | howto |
| `xcp.backup_missing` | high | a running VM has no backup job (from `/vms/{id}/backup-jobs`) | howto |
| `xcp.backup_failed` | high | a backup log shows failure and no later success; or older than N days | howto |
| `xcp.snapshot_old` | low | a VM snapshot older than 30 days (long snapshot chains cost space and slow the disk) | howto |
| `xcp.tools_old` | low | guest tools missing or not running on a running VM | howto |
| `xcp.alarm` | per alarm | open XO alarms | detail |
| `xcp.cert_expiring` | as PVE | the XO TLS certificate | howto |
| `xcp.ha_off` | low | pool HA disabled where the owner expects it (opt-in) | howto; unverified field |

Pages: kind `xcp`: Overview, Hosts and pools, VMs (power, tools, snapshots, backup coverage), Storage (SRs), Backups, Report. Effort is higher than PVE because the field names are not yet verified.

---

## UniFi

Built. See docs/DESIGN.md, "UniFi Network", for the source, the whitelist, the findings and what is unverified.

---

## Roadmap-level designs

Estimates assume the shared client work above is done. Everything here is research from documentation only; none is tested.

### FortiGate (Fortinet)

- Auth and least privilege: a "REST API Admin" (System, Administrators, Create New; only a super_admin can create it) with an access profile and trusted hosts; `0.0.0.0/0` is not allowed as a trusted host; the token is shown once; sent as `Authorization: Bearer <token>` (https://docs.fortinet.com/document/fortigate/7.4.6/administration-guide/940602 and /7.4.0/administration-guide/399023, via search snippets; the pages are large and my fetch read only the navigation). CLI object `config system api-user`, key by `execute api-user generate-key <name>` (community post: https://community.fortinet.com/fortigate-3/technical-tip-how-to-create-a-rest-api-admin-user-and-assign-it-to-an-admin-profile-130221). Read-only means an access profile with Read on the items needed, not Read/Write. I found no official page that builds such a profile: unverified. A trusted-host list holding only the hub's address is the second limit; a community tip says the client IP must be in the trusted hosts of both the API user and the admin (same post). Self-signed certificate by default (unverified here), so the pin applies.
- Key GET endpoints (two families: `/api/v2/cmdb/...` for configuration and `/api/v2/monitor/...` for state, as in the reference; per-VDOM with `?vdom=`): `/api/v2/monitor/system/status` (version, serial; confirmed to exist in a client library's status call), `/api/v2/cmdb/firewall/policy` (rules; path appears in copies of Fortinet's reference), `/api/v2/monitor/firewall/policy/` (hit counts; seen in a community post), `/api/v2/cmdb/system/interface`, `/api/v2/cmdb/firewall/vip` (port forwards, from memory; unverified), `/api/v2/monitor/system/firmware` (available firmware, unverified), `/api/v2/monitor/license/status` (FortiGuard licences, unverified), `/api/v2/monitor/system/ha-peer` (HA, unverified). The reference is behind a Fortinet developer login, so every path must be confirmed on a real unit.
- Findings: firmware update available; FortiGuard licence expiring or expired; a policy that allows `all` to `all` (like `firewall.default_accept`); a virtual IP forwarding the internet to inside (like `opnsense.nat`); admin interface reachable from the WAN (`allowaccess` on a WAN interface); HA out of sync; certificate expiring.
- Testing without the hardware: FortiGate-VM has a permanent trial licence from FortiOS 7.2.1: maximum 1 CPU and 2 GiB memory, low-encryption only, one per FortiCare account, no support; the older evaluation was 15 days (https://docs.fortinet.com/document/fortigate-private-cloud/7.2.0/kvm-administration-guide/504166/fortigate-vm-evaluation-license, as summarised by a search; read the page before relying on the numbers). It runs on Proxmox or Unraid KVM, and the REST admin and token work on it (assumed; unverified). Effort 5 days.

### Meraki (Cisco)

- Auth: Dashboard API key tied to an administrator and inheriting that account's permissions; no read-only key type was found, so use a read-only organization administrator (https://documentation.meraki.com/General_Administration/Other_Topics/Cisco_Meraki_Dashboard_API, via search). The spec declares `X-Cisco-Meraki-API-Key` and bearer auth (https://github.com/meraki/openapi, `openapi/spec3.json`, version 1.76.0, parsed 2026-11-24). Rate limit: 10 calls per second per organization, HTTP 429 with `Retry-After` (same documentation). The hub must pace and honour `Retry-After`. A cloud API, so no certificate pin: the normal CA check.
- Key GET endpoints (all present in spec3.json): `/organizations`, `/organizations/{id}/networks`, `/organizations/{id}/devices/availabilities`, `/organizations/{id}/devices/statuses`, `/organizations/{id}/firmware/upgrades`, `/organizations/{id}/licenses/overview`, `/organizations/{id}/inventory/devices`, `/networks/{id}/wireless/ssids` (per-SSID auth mode), `/networks/{id}/appliance/firewall/l3FirewallRules`, `/networks/{id}/appliance/firewall/portForwardingRules`, `/networks/{id}/appliance/security/intrusion`, `/organizations/{id}/admins`, `/organizations/{id}/configurationChanges`. Field names not read; confirm in the spec.
- Findings: licence expired or expiring; device offline; firmware behind or upgrade stuck; open or WPA-only SSID that is not guest; port forward to inside; `allow any any` rule; intrusion prevention off on an MX; an administrator without two-step (field unverified).
- Testing: the DevNet always-on sandbox is described as a working Meraki organisation with read-only GET examples and a shared read-only demo key (https://blogs.cisco.com/cisco-devnet/handsonmerakiapi01/, https://developer.cisco.com/meraki). Reports from 2021 to 2023 say the key's organisations differed from the dashboard's and reservable sandboxes sometimes rejected keys (https://community.meraki.com/t5/Dashboard-Administration/API-access-and-Dashboard-GUI-access-don-t-match-for-always-on/m-p/90682). Whether it is still up is unverified. Effort 5 days.

### Aruba (HPE Aruba Networking)

- Three products; target order: Aruba Central (cloud) first, because it has one API for many access points and switches. AOS-CX switches have their own REST API and Instant On a separate one; neither was researched (unverified).
- Auth for New Central: tokens come from HPE GreenLake, work only with Central, and carry the rights of the user's role; Classic Central tokens are a separate thing; an OAuth scope of `read` gives read-only access; access tokens last 2 hours (https://developer.arubanetworks.com/new-central/docs/generating-and-managing-access-tokens, https://developer.arubanetworks.com/central/docs/api-oauth-access-token, via search; the refresh limits conflict between pages). A built-in role "Aruba Central View Only" exists (https://arubanetworking.hpe.com/techdocs/new-central/content/get-started/rbac.htm). Refreshing a token is a POST to an OAuth endpoint, so the hub needs one narrow, documented exception to GET only, or the owner pastes a token each 2 hours, which is not workable. This is the hardest part and needs a decision.
- Key GET endpoints: not researched; the developer pages are the starting point. Unverified.
- Findings (design intent): AP or switch offline; firmware behind the recommended version; open SSID; WPA2-only; licence or subscription expiring; rogue AP count.
- Testing: I found no Central sandbox (unverified). Aruba offers trials; unverified. Effort 6 to 8 days, largest because of the token refresh.

---

## Open questions (to settle before building)

1. ~~PVE updates (tier 2)~~ Decided: the collector on each node reads updates; the token stays PVEAuditor.
2. Confirm scope: PMG and PDM. My recommendation is skip PDM, defer PMG.
3. Helper-scripts catalog: is an outbound daily call to community-scripts.org acceptable (Settings switch, default off)? The alternative is no app names or OS end-of-life, only the tag count.
4. Does the owner run Xen Orchestra with XCP-ng? If not, XCP-ng is not worth building (XAPI direct needs root).
5. ~~UniFi~~ Built. Open: whether a View Only admin can make a key and what it can do (needs a live controller); the legacy API may show a latest controller version (not probed).
6. Aruba: is a documented POST for token refresh acceptable?
7. Thresholds: are 85% and 95% for storage, 3 and 7 days for backups, and 2 hours for an offline AP the right defaults?

---

## Source list

- PVE user management, API tokens, roles: https://pve.proxmox.com/pve-docs/chapter-pveum.html
- PVEAuditor privilege groups: https://git.proxmox.com/?p=pve-access-control.git;a=blob_plain;f=src/PVE/AccessControl.pm;hb=HEAD
- PVE API viewer data: https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js
- PVE certificates: https://pve.proxmox.com/pve-docs/chapter-sysadmin.html
- PBS user management and roles: https://pbs.proxmox.com/docs/user-management.html
- PBS API viewer data: https://pbs.proxmox.com/docs/api-viewer/apidoc.js
- PMG guide and API viewer data: https://pmg.proxmox.com/pmg-docs/pmg-admin-guide.html, https://pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js
- PMG tokens: https://forum.proxmox.com/threads/why-are-there-no-api-tokens.156802/
- PDM: https://proxmox.com/en/about/company-details/press-releases/proxmox-datacenter-manager-1-0, https://forum.proxmox.com/threads/proxmox-datacenter-manager-1-0-stable.177320/, https://pdm.proxmox.com/docs/, https://pdm.proxmox.com/docs/introduction.html, https://pdm.proxmox.com/docs/remotes.html
- Helper-Scripts: https://github.com/community-scripts/ProxmoxVE (README, SECURITY.md, ct scripts, PR 15007, PR 15009), https://github.com/community-scripts/core (core/build.func, ui/advanced.func, ui/defaults.func, ui/menu.func, pve/backend.func, docs/updates.md), https://community-scripts.org/api/update-info?slug=adguard, https://db.community-scripts.org/api/collections/script_scripts/records
- XCP-ng and XO: https://docs.xcp-ng.org/management/users-permissions/, https://docs.xcp-ng.org/management/updates/, https://docs.xen-orchestra.com/automation/restapi, https://github.com/vatesfr/xen-orchestra (docs/docs/automation/restapi.md, docs/docs/security/user-management/rbac.md, @xen-orchestra/rest-api/src)
- XAPI and XenServer RBAC: https://xapi-project.github.io/xen-api/usage.html, https://docs.xenserver.com/en-us/xenserver/8/users/rbac-roles-permissions, https://docs.xenserver.com/en-us/xenserver/8/users/rbac-overview
- UniFi: moved to docs/DESIGN.md, "UniFi Network"
- FortiGate: https://docs.fortinet.com/document/fortigate/7.4.6/administration-guide/940602, https://community.fortinet.com/fortigate-3/technical-tip-how-to-create-a-rest-api-admin-user-and-assign-it-to-an-admin-profile-130221, https://docs.fortinet.com/document/fortigate-private-cloud/7.2.0/kvm-administration-guide/504166/fortigate-vm-evaluation-license
- Meraki: https://github.com/meraki/openapi (openapi/spec3.json), https://documentation.meraki.com/General_Administration/Other_Topics/Cisco_Meraki_Dashboard_API, https://developer.cisco.com/meraki/api-v1/rate-limit/, https://blogs.cisco.com/cisco-devnet/handsonmerakiapi01/, https://developer.cisco.com/meraki
- Aruba: https://developer.arubanetworks.com/new-central/docs/generating-and-managing-access-tokens, https://developer.arubanetworks.com/central/docs/api-oauth-access-token, https://arubanetworking.hpe.com/techdocs/new-central/content/get-started/rbac.htm
