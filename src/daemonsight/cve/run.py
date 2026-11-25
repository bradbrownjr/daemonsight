"""The hub's CVE chore: refresh the feeds when they are due, match the hosts
whose package list or the data changed, and keep each host's `cve.*` findings
current. It runs on the hub's event loop, but downloads are async and the
parsing and matching happen in worker threads, so a page request never waits
for it. A failure is logged and tried again on the next pass.

Only this module writes cve.db; the state.db connection is used from the
event loop thread only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from functools import partial

from .. import db, hub, settings
from ..config import Config
from ..findings import Finding
from . import advisories, alpine, exposure, feeds, match, opnsense, priority, priority_fetch, records, store, ubuntu

log = logging.getLogger("daemonsight.cve")

EXPOSURE_EVERY = 600      # seconds between two looks at each host's exposure (a change makes the findings dirty)


def _inventories(conn) -> dict[str, dict]:
    """host -> inventory (the data, with its taken_at) for every host that sent one."""
    out = {}
    for r in conn.execute("SELECT host, taken_at, data FROM snapshots WHERE source = 'inventory'"):
        try:
            d = json.loads(r["data"]) if r["data"] else None
        except ValueError:
            d = None
        if isinstance(d, dict):
            d["taken_at"] = r["taken_at"]
            out[r["host"]] = d
    return out


def _image_inventories(conn) -> dict[str, dict]:
    """pseudo-host -> inventory for every Debian, Ubuntu and Alpine container image an Unraid system's Docker reader listed or a
    collector host sent (see remote/docker_images.py). They are matched like hosts but never get findings under their pseudo-host id:
    poll.py raises `docker.image_cves` for an Unraid system, and `_docker_findings` below for a collector host, from the matches."""
    from ..remote import docker_images, docker_storage
    stored = {}
    for source in (docker_storage.SNAPSHOT, hub.DOCKER_IMAGES):
        for r in conn.execute("SELECT host, data FROM snapshots WHERE source = ?", (source,)):
            try:
                d = json.loads(r["data"]) if r["data"] else None
            except ValueError:
                d = None
            if isinstance(d, dict):
                stored[r["host"]] = d
    return docker_images.image_inventories(stored)


def _opnsense_plans(conn) -> tuple[dict[str, dict], dict[str, dict], set[str]]:
    """(pending, fws, series) for the enabled OPNsense systems. `pending`: pseudo-host -> plan (cve/opnsense.py `plan`) for each
    whose last firmware check found an update that brings a new OPNsense release. `fws`: system id -> firmware status, for the
    check of a release it has not been offered (`unseen_plan`). `series`: what the changelog must hold for both. Every enabled
    firewall needs the changelog, not only one with an update pending."""
    out, fws, series = {}, {}, set()
    for r in conn.execute("SELECT s.host, s.data FROM snapshots s JOIN remotes r ON r.id = s.host "
                          "WHERE s.source = 'opnsense_firmware' AND r.kind = 'opnsense' AND r.enabled = 1"):
        try:
            d = json.loads(r["data"]) if r["data"] else None
        except ValueError:
            d = None
        d = d if isinstance(d, dict) else None
        p = opnsense.plan(d)
        if p["ok"]:
            out[opnsense.pseudo_host(r["host"])] = p
            series.update(p["series"])
        w = opnsense.watch_series(d)
        if w:
            fws[r["host"]] = d
            series.update(w)
    return out, fws, series


def _pending_names(conn, host: str) -> set[str]:
    snap = db.get_snapshot(conn, host, "packages")
    ups = (snap.data or {}).get("updates", []) if snap and snap.data and snap.data.get("available") is not False else []
    return {u["name"] for u in ups if isinstance(u, dict) and u.get("name")}


def _reboot_pending(conn, host: str) -> bool:
    """A newer kernel is installed and waits for a reboot (pkg.reboot is open)."""
    return conn.execute("SELECT 1 FROM findings WHERE host = ? AND rule = 'pkg.reboot' AND resolved_at IS NULL",
                        (host,)).fetchone() is not None


def _set_cve_findings(conn, host: str, now: float, current: list[Finding], rules_prefix: str) -> None:
    """Make the host's open findings under one rule prefix match `current`,
    logging an event for each one that opens or clears."""
    changes = db.reconcile_findings(conn, host, now, current, only_prefix=rules_prefix)
    for change, f in changes:
        if change == "opened":
            db.add_event(conn, host, now, "finding_opened", f.title, severity=f.severity, detail=f.detail,
                         link=f.link)
        else:
            db.add_event(conn, host, now, "finding_resolved", f"Resolved: {f['title']}", link=f["link"])


def clear_findings(conn, now: float) -> None:
    """With [cve] off, close any cve.* finding left from when it was on, and a collector host's docker.* ones (an Unraid
    system's follow its own poll, which closes them when matching is off)."""
    for (host,) in conn.execute("SELECT DISTINCT host FROM findings WHERE rule LIKE 'cve.%' "
                                "AND resolved_at IS NULL").fetchall():
        db.reconcile_findings(conn, host, now, [], only_prefix="cve.")
    for (host,) in conn.execute("SELECT DISTINCT f.host FROM findings f JOIN hosts h ON h.id = f.host WHERE h.kind IS NULL "
                                "AND f.rule LIKE 'docker.%' AND f.resolved_at IS NULL").fetchall():
        _set_cve_findings(conn, host, now, [], "docker.")


class Chore:
    def __init__(self, cfg: Config, state_conn, client=None):
        self.base = cfg                # the config file's values; self.cfg adds the Settings page's, each pass
        self.cfg = cfg
        self.state = state_conn
        self.client = client           # an httpx client for tests
        self.factory = partial(store.connect, cfg.cve_db_path)
        self.dirty = True              # recompute findings (first pass, and whenever data changed)
        self.last_gen: str | None = None
        self._epss_auto: float | None = None
        self._table_sig: tuple | None = None
        self._rec_gen: str | None = None
        self._exposures: dict[str, exposure.Exposure] = {}
        self._exposure_at = 0.0

    async def run_once(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        # Read the settings afresh: a change on the Settings page applies on this pass.
        self.cfg = settings.effective(self.base, self.state)
        if not self.cfg.cve.enabled:
            clear_findings(self.state, now)
            self.dirty = True          # recompute everything when it is turned on again
            return
        if self.cfg.cve.epss_automatable != self._epss_auto:
            self._epss_auto = self.cfg.cve.epss_automatable
            self.dirty = True          # the Automatable estimate moved
        await self._fetch_priority(now)
        table = priority.use(self.cfg.data_dir)
        sig = (table.source, table.version, table.name)
        if sig != self._table_sig:
            self._table_sig = sig
            self.dirty = True          # another priority table (data/priority, or an override file)
        invs = _inventories(self.state)
        # Debian, Ubuntu and Alpine container images are matched like hosts, under pseudo-host ids, and their releases are loaded too.
        imgs = _image_inventories(self.state)
        every = {**invs, **imgs}
        opn, opn_fws, opn_series = _opnsense_plans(self.state)
        opn_series = sorted(opn_series)
        releases = {i["codename"] for i in every.values() if match.release_of(i)}
        alpine_releases = {i["release"] for i in imgs.values() if i.get("backend") == "apk" and i.get("release")}
        # Ubuntu: a file per release; kernel rows are kept only for the flavors the hub's own hosts run (see feeds.load_ubuntu).
        ubuntu_releases = {ubuntu.release_of(i) for i in every.values()} - {None}
        ubuntu_kernels = {r: {s for h, i in invs.items() if ubuntu.release_of(i) == r
                              for s, _v, _b in i.get("sources", []) if s.startswith("linux")} for r in ubuntu_releases}
        conn = await asyncio.to_thread(self.factory)
        try:
            changed = await self._refresh(conn, releases, now)
            changed = await self._refresh_alpine(conn, alpine_releases, now) or changed
            changed = await self._refresh_ubuntu(conn, ubuntu_kernels, now) or changed
            changed = await self._refresh_opnsense(conn, set(opn_series), now) or changed
            deb = conn.execute("SELECT changed_at FROM feed WHERE name = 'debian'").fetchone()
            gen = f"{match.MATCH_VERSION}:{(deb['changed_at'] if deb else None)}:{','.join(sorted(releases))}"
            # An Alpine image is matched again when any of the secdb files changed; a host never is for that.
            apk_gen = f"{match.MATCH_VERSION}:apk:" + ",".join(
                f"{r['name']}={r['changed_at']}" for r in conn.execute(
                    "SELECT name, changed_at FROM feed WHERE name LIKE ? ORDER BY name", (feeds.ALPINE_PREFIX + "%",)))
            # An Ubuntu host or image is matched again when any of the OVAL files changed.
            ubu_gen = f"{match.MATCH_VERSION}:ubu:" + ",".join(
                f"{r['name']}={r['changed_at']}" for r in conn.execute(
                    "SELECT name, changed_at FROM feed WHERE name LIKE ? ORDER BY name", (feeds.UBUNTU_PREFIX + "%",)))
            opn_row = conn.execute("SELECT changed_at FROM feed WHERE name = ?", (feeds.OPNSENSE_NAME,)).fetchone()
            opn_loaded = opnsense.loaded_series(conn)
            opn_ready = bool(opn_loaded) and set(opn_series) <= opn_loaded
            # The newest release in a firewall's series that it has not been offered, matched like a pending update.
            unseen = {}
            if opn_ready:
                for h, fw in opn_fws.items():
                    u = opnsense.unseen_plan(conn, fw)
                    if u["ok"]:
                        unseen[opnsense.unseen_host(h)] = u
                # The CVE ids of the advisories those two ranges name, asked for once each (advisories.py).
                await self._resolve_advisories(conn, [*opn.values(), *unseen.values()], now)
            opn_gen = (f"{match.MATCH_VERSION}:opn:{opn_row['changed_at'] if opn_row else None}:{','.join(sorted(opn_loaded))}:"
                       f"{advisories.generation(conn)}")
            matched = {r["host"]: r for r in conn.execute("SELECT * FROM matched")}
        finally:
            conn.close()
        gens = {h: apk_gen if inv.get("backend") == "apk" else ubu_gen if ubuntu.release_of(inv) or inv.get("os_id") == "ubuntu" else gen
                for h, inv in every.items()}
        todo = [h for h, inv in every.items()
                if h not in matched or matched[h]["inv_at"] != inv["taken_at"] or matched[h]["gen"] != gens[h]]
        if todo:
            await asyncio.to_thread(self._match, {h: every[h] for h in todo}, gens)
            self.dirty = True
        # A firewall is matched against the changelog once the series it needs are loaded, and again when its plan or the
        # loaded data changes.
        opn_todo = {h: p for h, p in {**opn, **unseen}.items() if opn_ready and (
            h not in matched or matched[h]["inv_hash"] != opnsense.plan_hash(p) or matched[h]["gen"] != opn_gen)}
        if opn_todo:
            await asyncio.to_thread(self._match_opnsense, opn_todo, opn_gen)
        if changed:
            self.dirty = True
        # Hosts that are gone (revoked) leave rows behind; drop them.
        await asyncio.to_thread(self._forget, set(every) | set(opn) | set(unseen))
        await self._fetch_records(now)
        await self._findings(invs, now)
        await self._docker_findings(now)

    async def _fetch_priority(self, now: float) -> None:
        """Once a day, ask the DaemonSight repository for a newer prioritisation table (priority_fetch.py). A table that was installed is
        logged, shown under Recent hub changes, and makes the next pass rate every finding again."""
        try:
            update = await priority_fetch.refresh(self.cfg.data_dir, now, self.cfg.cve.priority_updates, self.client)
        except Exception:
            log.exception("Prioritisation table update failed")
            return
        if update is None:
            return
        self.dirty = True
        if self.state is not None:
            db.add_event(self.state, db.HUB_HOST, now, "priority", f"Prioritisation table updated to {update.name} v{update.version}",
                         detail=f"Fetched {update.file} from the DaemonSight repository")

    async def _fetch_records(self, now: float) -> None:
        """CISA's SSVC rating of the CVEs the hub has matched (records.py): the ones due, up to a cap in one pass. A record that
        was read changes the ratings, so the findings are worked out again."""
        conn = await asyncio.to_thread(self.factory)
        try:
            try:
                got = await records.resolve(conn, now, self.client)
            except Exception:
                log.exception("CVE Services lookup failed")
                return
            gen = records.generation(conn)
        finally:
            conn.close()
        if gen != self._rec_gen:
            self._rec_gen = gen
            self.dirty = True
        if got["asked"]:
            log.info("CVE Services: asked %d, read %d, no record %d, failed %d, still due %d",
                     got["asked"], got["read"], got["absent"], got["failed"], got["waiting"])

    def _host_exposures(self, invs: dict[str, dict], now: float) -> dict[str, exposure.Exposure]:
        """Each host's exposure (cve/exposure.py), worked out again every `EXPOSURE_EVERY` seconds and whenever the findings are;
        a change makes the findings dirty. Reads state.db, so it runs on the event loop's thread."""
        if not self.dirty and now - self._exposure_at < EXPOSURE_EVERY and set(self._exposures) == set(invs):
            return self._exposures
        from ..web import views
        out = {}
        for host in invs:
            try:
                out[host] = exposure.host_exposure(self.state, views.host_config(self.state, self.cfg, host), host)
            except Exception:
                log.exception("Exposure check failed for %s", host)
                out[host] = self._exposures.get(host) or exposure.unknown([])
        self._exposure_at = now
        if {h: (e.exposed, e.why) for h, e in out.items()} != {h: (e.exposed, e.why) for h, e in self._exposures.items()}:
            self.dirty = True
        self._exposures = out
        return out

    async def _refresh_alpine(self, conn, releases: set[str], now: float) -> bool:
        """Alpine's security database: main and community for each release an image runs, each file asked again at most once
        per [cve] refresh_hours (an hour after an error). A release no image runs is forgotten."""
        any_changed = False
        for release in sorted(releases):
            for feed in feeds.alpine_feeds(release):
                if feeds.is_due(feeds.feed_row(conn, feed), now, self.cfg.cve.refresh_hours):
                    if await feeds.refresh(self.factory, self.cfg.data_dir, feed, set(), now, self.client):
                        any_changed = True
        if await asyncio.to_thread(feeds.drop_alpine, self.factory, self.cfg.data_dir, releases):
            any_changed = True
        return any_changed

    async def _refresh_ubuntu(self, conn, kernels: dict[str, set[str]], now: float) -> bool:
        """Canonical's CVE OVAL: one file for each Ubuntu release a host or image runs, asked again at most once per [cve]
        refresh_hours (an hour after an error). A release nothing runs any more is forgotten. When a host reports a kernel flavor the
        saved file was not loaded for, the saved file is read again without a download."""
        any_changed = False
        for release in sorted(kernels):
            feed = feeds.ubuntu_feed(release)
            if feeds.is_due(feeds.feed_row(conn, feed), now, self.cfg.cve.refresh_hours):
                if await feeds.refresh(self.factory, self.cfg.data_dir, feed, kernels[release], now, self.client):
                    any_changed = True
                    continue
            row = feeds.feed_row(conn, feed)
            loaded = set(json.loads(store.get_meta(conn, f"ubu_kernels_{release}", "[]")))
            if row["status"] in ("ok", "not modified") and loaded != kernels[release] and feeds.raw_path(self.cfg.data_dir, feed).exists():
                if await asyncio.to_thread(feeds.reload_ubuntu, self.factory, self.cfg.data_dir, release, kernels[release]) is not None:
                    any_changed = True
        if await asyncio.to_thread(feeds.drop_ubuntu, self.factory, self.cfg.data_dir, set(kernels)):
            any_changed = True
        return any_changed

    async def _refresh_opnsense(self, conn, series: set[str], now: float) -> bool:
        """OPNsense's changelog: one tarball, asked again at most once per [cve] refresh_hours (an hour after an error) and only
        while an enabled firewall exists (it needs the changelog to know of a release it was not offered). The rows kept are those of the series the firewalls need; another set
        is read from the saved file without a new download. With no firewall waiting, the file and its rows are dropped."""
        if not series:
            return await asyncio.to_thread(feeds.drop_opnsense, self.factory, self.cfg.data_dir)
        feed = feeds.OPNSENSE_FEED
        changed = False
        if feeds.is_due(feeds.feed_row(conn, feed), now, self.cfg.cve.refresh_hours):
            changed = await feeds.refresh(self.factory, self.cfg.data_dir, feed, series, now, self.client)
        if not changed and (opnsense.loaded_series(conn) != series or opnsense.versions_missing(conn)) and feeds.raw_path(self.cfg.data_dir, feed).exists():
            changed = await asyncio.to_thread(feeds.reload_opnsense, self.factory, self.cfg.data_dir, series) is not None
        return changed

    async def _resolve_advisories(self, conn, plans: list[dict], now: float) -> None:
        """Look up the CVE ids of the FreeBSD and GitHub advisories in the pending and unseen ranges. Only those: an advisory
        in a release no firewall needs is not asked for. Answers are kept for good; a failure is asked again after
        `[cve] refresh_hours`, and GitHub is not asked while its rate limit holds."""
        refs: set[str] = set()
        for p in plans:
            refs.update(r["ref"] for r in opnsense.fixes_between(conn, p["installed"], p["offered"], "adv"))
        if not refs:
            return
        try:
            await advisories.resolve(conn, refs, now, self.cfg.cve.refresh_hours, self.client)
        except Exception:
            log.exception("OPNsense advisory lookup failed")

    def _match_opnsense(self, plans: dict[str, dict], gen: str) -> None:
        conn = self.factory()
        try:
            for host, p in plans.items():
                try:
                    opnsense.match_host(conn, host, p, gen)
                except Exception:
                    log.exception("CVE matching failed for %s", host)
        finally:
            conn.close()

    async def _refresh(self, conn, releases: set[str], now: float) -> bool:
        any_changed = False
        for feed in feeds.FEEDS.values():
            row = feeds.feed_row(conn, feed)
            if feeds.is_due(row, now, self.cfg.cve.refresh_hours):
                if await feeds.refresh(self.factory, self.cfg.data_dir, feed, releases, now, self.client):
                    any_changed = True
        # A host on a release the saved tracker file wasn't loaded for: parse it again.
        loaded = set(json.loads(store.get_meta(conn, "deb_releases", "[]")))
        if releases and releases != loaded and feeds.raw_path(self.cfg.data_dir, feeds.FEEDS["debian"]).exists():
            rows = await asyncio.to_thread(feeds.reload_debian, self.factory, self.cfg.data_dir, releases)
            if rows is not None:
                any_changed = True
        return any_changed

    def _match(self, invs: dict[str, dict], gens: dict[str, str]) -> None:
        conn = self.factory()
        try:
            for host, inv in invs.items():
                try:
                    if inv.get("backend") == "dnf":
                        match.set_advisories(conn, host, inv, gens[host])
                    elif inv.get("backend") == "apk":
                        alpine.match_host(conn, host, inv, gens[host])
                    elif inv.get("os_id") == "ubuntu":
                        ubuntu.match_host(conn, host, inv, gens[host])
                    else:
                        match.match_host(conn, host, inv, gens[host])
                except Exception:
                    log.exception("CVE matching failed for %s", host)
        finally:
            conn.close()

    def _forget(self, hosts: set[str]) -> None:
        conn = self.factory()
        try:
            for (h,) in conn.execute("SELECT host FROM matched").fetchall():
                if h not in hosts:
                    conn.execute("DELETE FROM match WHERE host = ?", (h,))
                    conn.execute("DELETE FROM matched WHERE host = ?", (h,))
        finally:
            conn.close()

    async def _findings(self, invs: dict[str, dict], now: float) -> None:
        conn = await asyncio.to_thread(self.factory)
        try:
            stale = feeds.stale_feeds(conn, now)
            titles = {n: f.title for n, f in feeds.FEEDS.items()}
            titles[feeds.OPNSENSE_NAME] = feeds.OPNSENSE_FEED.title
            for name, _age in stale:
                if name.startswith(feeds.ALPINE_PREFIX):
                    titles[name] = feeds.alpine_title(name)
                elif name.startswith(feeds.UBUNTU_PREFIX):
                    titles[name] = feeds.ubuntu_title(name)
            matched = {r["host"] for r in conn.execute("SELECT host FROM matched")}
        finally:
            conn.close()
        stale_f = match.stale_finding(stale, titles)
        packages: dict[str, list[Finding]] = {}
        exposures = self._host_exposures(invs, now)
        if self.dirty:
            packages = await asyncio.to_thread(self._package_findings, {h: i for h, i in invs.items() if h in matched},
                                               {h: _pending_names(self.state, h) for h in invs},
                                               {h for h in invs if _reboot_pending(self.state, h)}, dict(exposures))
        for host in invs:
            # A host with no match made yet (its rows were forgotten or never made) says nothing about its CVEs: its findings stay as
            # they are until the matching runs, which makes the findings dirty again.
            if self.dirty and host in matched:
                _set_cve_findings(self.state, host, now, packages.get(host, []), "cve.package")
            db.set_finding(self.state, host, now, stale_f, rule="cve.feed_stale", key="feeds")
        self.dirty = False

    async def _docker_findings(self, now: float) -> None:
        """`docker.image_cves` and `docker.eol_base` for each collector host that sent its container images (docs/DESIGN.md,
        "Collector hosts: image CVEs"): the same rules, wording and holds as for an Unraid system (remote/docker_images.py), run on the
        stored image data and the matches made above. Each pass, because the inputs (the matches, the host's exposure, the
        prioritisation table) change on their own; reconciling the same findings again changes nothing. A host that has sent no image
        data keeps whatever findings it has: nothing says they no longer hold."""
        from ..remote import docker_images, poll
        for r in self.state.execute("SELECT s.host, s.data FROM snapshots s JOIN hosts h ON h.id = s.host "
                                    "WHERE s.source = ? AND h.kind IS NULL", (hub.DOCKER_IMAGES,)).fetchall():
            try:
                data = json.loads(r["data"]) if r["data"] else None
                if not isinstance(data, dict) or data.get("available") is False:
                    continue
                cves = docker_images.load_cves(self.cfg, self.state, r["host"], data)
                current = docker_images.evaluate(data, None, cves, None, poll.open_findings(self.state, r["host"], ("docker.image_cves",)),
                                                 platform="host")
                _set_cve_findings(self.state, r["host"], now, current, "docker.")
            except Exception:
                log.exception("Container image findings failed for %s", r["host"])

    def _package_findings(self, invs: dict[str, dict], pending: dict[str, set[str]],
                          rebooting: set[str] = frozenset(), exposures: dict | None = None) -> dict[str, list[Finding]]:
        conn = self.factory()
        out = {}
        try:
            for host, inv in invs.items():
                bins = {s: b for s, _v, b in inv.get("sources", [])}
                out[host] = match.package_findings(
                    match.host_cves(conn, host, ("fix", "esm", "nofix")), bins, pending.get(host, set()),
                    (exposures or {}).get(host) or exposure.unknown([]),
                    self.cfg.cve.epss_automatable, inv.get("backend", "apt"), host in rebooting,
                    "ubuntu" if inv.get("os_id") == "ubuntu" else "debian")
        finally:
            conn.close()
        return out


async def loop(cfg: Config, state_conn, client=None) -> None:
    chore = Chore(cfg, state_conn, client)
    # Let the web server finish starting before the first download.
    await asyncio.sleep(5)
    while True:
        try:
            await chore.run_once()
        except Exception:
            log.exception("CVE chore failed")
        await asyncio.sleep(60)
