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

from .. import db, settings
from ..config import Config
from ..findings import Finding
from . import feeds, match, store

log = logging.getLogger("daemonsight.cve")


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
    """pseudo-host -> inventory for every Debian container image an Unraid system's Docker reader listed (see
    remote/docker_images.py). They are matched like hosts but never get findings here: poll.py raises
    `docker.image_cves` from the matches."""
    from ..remote import docker_images, docker_storage
    stored = {}
    for r in conn.execute("SELECT host, data FROM snapshots WHERE source = ?", (docker_storage.SNAPSHOT,)):
        try:
            d = json.loads(r["data"]) if r["data"] else None
        except ValueError:
            d = None
        if isinstance(d, dict):
            stored[r["host"]] = d
    return docker_images.image_inventories(stored)


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
    """With [cve] off, close any cve.* finding left from when it was on."""
    for (host,) in conn.execute("SELECT DISTINCT host FROM findings WHERE rule LIKE 'cve.%' "
                                "AND resolved_at IS NULL").fetchall():
        db.reconcile_findings(conn, host, now, [], only_prefix="cve.")


class Chore:
    def __init__(self, cfg: Config, state_conn, client=None):
        self.base = cfg                # the config file's values; self.cfg adds the Settings page's, each pass
        self.cfg = cfg
        self.state = state_conn
        self.client = client           # an httpx client for tests
        self.factory = partial(store.connect, cfg.cve_db_path)
        self.dirty = True              # recompute findings (first pass, and whenever data changed)
        self.last_gen: str | None = None
        self._epss_high: float | None = None

    async def run_once(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        # Read the settings afresh: a change on the Settings page applies on this pass.
        self.cfg = settings.effective(self.base, self.state)
        if not self.cfg.cve.enabled:
            clear_findings(self.state, now)
            self.dirty = True          # recompute everything when it is turned on again
            return
        if self.cfg.cve.epss_high != self._epss_high:
            self._epss_high = self.cfg.cve.epss_high
            self.dirty = True          # the High threshold moved
        invs = _inventories(self.state)
        # Debian container images are matched like hosts, under pseudo-host ids, and their releases are loaded too.
        imgs = _image_inventories(self.state)
        every = {**invs, **imgs}
        releases = {i["codename"] for i in every.values() if match.release_of(i)}
        conn = await asyncio.to_thread(self.factory)
        try:
            changed = await self._refresh(conn, releases, now)
            deb = conn.execute("SELECT changed_at FROM feed WHERE name = 'debian'").fetchone()
            gen = f"{match.MATCH_VERSION}:{(deb['changed_at'] if deb else None)}:{','.join(sorted(releases))}"
            matched = {r["host"]: r for r in conn.execute("SELECT * FROM matched")}
        finally:
            conn.close()
        todo = [h for h, inv in every.items()
                if h not in matched or matched[h]["inv_at"] != inv["taken_at"] or matched[h]["gen"] != gen]
        if todo:
            await asyncio.to_thread(self._match, {h: every[h] for h in todo}, gen)
            self.dirty = True
        if changed:
            self.dirty = True
        # Hosts that are gone (revoked) leave rows behind; drop them.
        await asyncio.to_thread(self._forget, set(every))
        await self._findings(invs, now)

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

    def _match(self, invs: dict[str, dict], gen: str) -> None:
        conn = self.factory()
        try:
            for host, inv in invs.items():
                try:
                    if inv.get("backend") == "dnf":
                        match.set_advisories(conn, host, inv, gen)
                    else:
                        match.match_host(conn, host, inv, gen)
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
        finally:
            conn.close()
        stale_f = match.stale_finding(stale, titles)
        packages: dict[str, list[Finding]] = {}
        if self.dirty:
            packages = await asyncio.to_thread(self._package_findings, invs,
                                               {h: _pending_names(self.state, h) for h in invs},
                                               {h for h in invs if _reboot_pending(self.state, h)})
        for host in invs:
            if self.dirty:
                _set_cve_findings(self.state, host, now, packages.get(host, []), "cve.package")
            db.set_finding(self.state, host, now, stale_f, rule="cve.feed_stale", key="feeds")
        self.dirty = False

    def _package_findings(self, invs: dict[str, dict], pending: dict[str, set[str]],
                          rebooting: set[str] = frozenset()) -> dict[str, list[Finding]]:
        conn = self.factory()
        out = {}
        try:
            for host, inv in invs.items():
                bins = {s: b for s, _v, b in inv.get("sources", [])}
                out[host] = match.package_findings(
                    match.host_cves(conn, host, ("fix", "nofix")), bins, pending.get(host, set()),
                    self.cfg.cve.epss_high, inv.get("backend", "apt"), host in rebooting)
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
