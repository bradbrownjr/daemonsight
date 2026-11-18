"""Download the public vulnerability data and load it into cve.db.

Three feeds, each fetched with If-None-Match / If-Modified-Since so an
unchanged file costs one small request, by default every 24 hours:

* Debian security tracker, https://security-tracker.debian.org/tracker/data/json
  (about 15 MB gzipped, 90 MB of JSON). Parsed a CVE at a time (tracker.py).
* EPSS scores from FIRST, https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  (the URL on https://www.first.org/epss/data; it redirects to the day's file).
  Free, no registration; FIRST asks for attribution.
* CISA Known Exploited Vulnerabilities,
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  (CC0 1.0, see https://www.cisa.gov/sites/default/files/licenses/kev/license.txt).

Requests carry only a generic User-Agent, "DaemonSight/<version>". Everything
downloaded is untrusted text: it is size-capped, parsed with the standard
library, stored as data, and escaped when shown. A download goes to a
temporary file and replaces the old copy only once it has loaded.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .. import __version__
from . import store, tracker

log = logging.getLogger("daemonsight.cve")

USER_AGENT = f"DaemonSight/{__version__}"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")
RETRY_AFTER_ERROR = 3600
DESCR_MAX = 200


@dataclass(frozen=True)
class Feed:
    name: str
    title: str
    url: str
    hosts: tuple[str, ...]   # a redirect may only go to these
    max_bytes: int           # largest download accepted, after decoding
    gz_source: bool          # the download is itself a .gz file (EPSS); else it is JSON we gzip
    terms: str
    docs: str


FEEDS = {
    "debian": Feed("debian", "Debian security tracker", "https://security-tracker.debian.org/tracker/data/json",
                   ("security-tracker.debian.org",), 400 << 20, False,
                   "Debian security tracker data, https://security-tracker.debian.org/",
                   "https://security-tracker.debian.org/tracker/"),
    "epss": Feed("epss", "EPSS scores (FIRST)", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                 ("epss.empiricalsecurity.com",), 100 << 20, True,
                 "Free to use, no registration; FIRST asks for attribution: https://www.first.org/epss/",
                 "https://www.first.org/epss/data"),
    "kev": Feed("kev", "CISA Known Exploited Vulnerabilities",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                ("www.cisa.gov",), 50 << 20, False,
                "CC0 1.0: https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
}


def cve_dir(data_dir: str) -> Path:
    return Path(data_dir) / "cve"


def raw_path(data_dir: str, feed: Feed) -> Path:
    return cve_dir(data_dir) / f"{feed.name}.{'csv' if feed.gz_source else 'json'}.gz"


# ---- feed status ------------------------------------------------------------

def feed_row(conn, feed: Feed):
    conn.execute("INSERT OR IGNORE INTO feed (name, url, first_try) VALUES (?, ?, ?)",
                 (feed.name, feed.url, time.time()))
    return conn.execute("SELECT * FROM feed WHERE name = ?", (feed.name,)).fetchone()


def is_due(row, now: float, refresh_hours: float) -> bool:
    """Whether to ask this feed again: never tried, or the refresh time has
    passed since the last attempt (an hour after an error, if that is sooner)."""
    if row["checked_at"] is None:
        return True
    wait = refresh_hours * 3600
    if row["status"] == "error":
        wait = min(wait, RETRY_AFTER_ERROR)
    return now - row["checked_at"] >= wait


def stale_feeds(conn, now: float, days: float = 3) -> list[tuple[str, float | None]]:
    """(feed name, seconds since its last success) for every feed over `days`
    without a success. A feed that never succeeded counts from its first try."""
    out = []
    for r in conn.execute("SELECT * FROM feed"):
        since = r["ok_at"] if r["ok_at"] is not None else r["first_try"]
        if since is not None and now - since > days * 86400:
            out.append((r["name"], now - r["ok_at"] if r["ok_at"] is not None else None))
    return sorted(out)


# ---- download ---------------------------------------------------------------

class FetchError(Exception):
    pass


def _allow_hosts(feed: Feed):
    async def check(response: httpx.Response) -> None:
        url = response.request.url
        if url.scheme != "https" or url.host not in feed.hosts:
            raise FetchError(f"redirected to {url.host}, which is not a source for this feed")
    return check


async def download(feed: Feed, row, dest: Path, client: httpx.AsyncClient | None = None) -> dict | None:
    """Fetch the feed to `dest` (replaced only on success). Returns the new
    validators and size, or None when the server says it hasn't changed."""
    headers = {"User-Agent": USER_AGENT}
    if row["etag"]:
        headers["If-None-Match"] = row["etag"]
    if row["last_modified"]:
        headers["If-Modified-Since"] = row["last_modified"]
    if not dest.exists():
        headers.pop("If-None-Match", None)
        headers.pop("If-Modified-Since", None)
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, read=120.0), follow_redirects=True,
                                   max_redirects=3, headers={"User-Agent": USER_AGENT},
                                   event_hooks={"response": [_allow_hosts(feed)]})
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        async with client.stream("GET", feed.url, headers=headers) as r:
            for hop in [*r.history, r]:  # a client without the hook above still gets checked
                if hop.request.url.scheme != "https" or hop.request.url.host not in feed.hosts:
                    raise FetchError(f"answered by {hop.request.url.host}, which is not a source for this feed")
            if r.status_code == 304:
                return None
            if r.status_code != 200:
                raise FetchError(f"HTTP {r.status_code}")
            size = 0
            opener = open if feed.gz_source else gzip.open
            with opener(tmp, "wb") as out:
                async for chunk in r.aiter_bytes(1 << 16):
                    size += len(chunk)
                    if size > feed.max_bytes:
                        raise FetchError("download is larger than the limit")
                    out.write(chunk)
            if feed.gz_source:
                with open(tmp, "rb") as fh:
                    if fh.read(2) != b"\x1f\x8b":
                        raise FetchError("expected a gzip file")
            info = {"etag": r.headers.get("etag"), "last_modified": r.headers.get("last-modified"), "size": size}
        os.replace(tmp, dest)
        return info
    except httpx.HTTPError as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}"[:200]) from None
    finally:
        tmp.unlink(missing_ok=True)
        if own:
            await client.aclose()


# ---- loaders ----------------------------------------------------------------

def _short(text, limit: int = DESCR_MAX) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= limit else t[:limit - 1].rstrip() + "…"


NODSA_SHORT = 100


def load_debian(conn: sqlite3.Connection, path: Path, releases: set[str]) -> int:
    """Replace the `deb` and `cve` tables with the tracker's rows for these
    releases. Returns the number of rows kept."""
    rows = kept = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM deb")
        conn.execute("DELETE FROM cve")
        batch: list[tuple] = []
        descs: list[tuple] = []
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for source, cve, entry in tracker.iter_entries(fh):
                rel = entry.get("releases")
                if not isinstance(rel, dict) or not CVE_RE.match(cve):
                    continue
                for codename in releases:
                    x = rel.get(codename)
                    if not isinstance(x, dict):
                        continue
                    status = x.get("status")
                    fixed = x.get("fixed_version")
                    if status not in ("open", "resolved", "undetermined"):
                        continue
                    if status == "resolved" and (not isinstance(fixed, str) or fixed in ("", "0")):
                        continue  # not affected
                    nodsa = x.get("nodsa")
                    batch.append((codename, source, cve, status, fixed if isinstance(fixed, str) else None,
                                  str(x.get("urgency") or "")[:30],
                                  _short(nodsa, NODSA_SHORT) if nodsa is not None else None))
                    kept += 1
                    descs.append((cve, _short(entry.get("description"))))
                if len(batch) >= 20_000:
                    _flush_deb(conn, batch, descs)
                rows += 1
        _flush_deb(conn, batch, descs)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return kept


def _flush_deb(conn, batch: list, descs: list) -> None:
    conn.executemany("INSERT OR REPLACE INTO deb VALUES (?, ?, ?, ?, ?, ?, ?)", batch)
    conn.executemany("INSERT OR IGNORE INTO cve VALUES (?, ?)", descs)
    batch.clear()
    descs.clear()


def load_epss(conn: sqlite3.Connection, path: Path) -> tuple[int, str]:
    """All scores. The file starts with `#model_version:...,score_date:...`, then
    a `cve,epss,percentile` header. Returns (rows, note about the model and date)."""
    note = ""
    n = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM epss")
        batch = []
        with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
            for line in fh:
                if line.startswith("#"):
                    note = line[1:].strip()[:120]
                    continue
                parts = line.rstrip("\r\n").split(",")
                if len(parts) < 3 or not CVE_RE.match(parts[0]):
                    continue  # the header, or junk
                try:
                    score, pct = float(parts[1]), float(parts[2])
                except ValueError:
                    continue
                if not (0 <= score <= 1 and 0 <= pct <= 1):
                    continue
                batch.append((parts[0], score, pct))
                if len(batch) >= 50_000:
                    conn.executemany("INSERT OR REPLACE INTO epss VALUES (?, ?, ?)", batch)
                    n += len(batch)
                    batch.clear()
        conn.executemany("INSERT OR REPLACE INTO epss VALUES (?, ?, ?)", batch)
        n += len(batch)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return n, note


def load_kev(conn: sqlite3.Connection, path: Path) -> tuple[int, str]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        doc = json.load(fh)
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError("no vulnerabilities list in the KEV file")
    batch = []
    for v in items:
        if not isinstance(v, dict) or not CVE_RE.match(str(v.get("cveID", ""))):
            continue
        batch.append((v["cveID"], _short(v.get("vendorProject"), 80), _short(v.get("product"), 80),
                      _short(v.get("vulnerabilityName"), 160), _short(v.get("dateAdded"), 10),
                      _short(v.get("knownRansomwareCampaignUse"), 20)))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM kev")
        conn.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?, ?, ?, ?)", batch)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    note = f"catalog {_short(doc.get('catalogVersion'), 20)}" if isinstance(doc, dict) else ""
    return len(batch), note


# ---- refresh ----------------------------------------------------------------

def _record(conn, feed: Feed, **fields) -> None:
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE feed SET {sets} WHERE name = ?", (*fields.values(), feed.name))


def load_one(conn, feed: Feed, path: Path, releases: set[str]) -> tuple[int, str]:
    if feed.name == "debian":
        if not releases:
            return 0, "no host runs Debian yet"
        rows = load_debian(conn, path, releases)
        store.set_meta(conn, "deb_releases", json.dumps(sorted(releases)))
        return rows, "releases: " + ", ".join(sorted(releases))
    if feed.name == "epss":
        return load_epss(conn, path)
    return load_kev(conn, path)


async def refresh(conn_factory, data_dir: str, feed: Feed, releases: set[str], now: float,
                  client: httpx.AsyncClient | None = None) -> bool:
    """Ask one feed for changes and load what comes. Returns True when new
    data was loaded. Never raises: a failure is recorded on the feed's row.
    `conn_factory()` opens a cve.db connection for the thread doing the loading."""
    import asyncio
    conn = conn_factory()
    try:
        row = feed_row(conn, feed)
        dest = raw_path(data_dir, feed)
        try:
            info = await download(feed, row, dest, client)
        except FetchError as exc:
            log.warning("CVE feed %s: %s", feed.name, exc)
            _record(conn, feed, checked_at=now, status="error", detail=str(exc)[:200])
            return False
        if info is None:
            _record(conn, feed, checked_at=now, ok_at=now, status="not modified", detail=None)
            return False
        rows, note = await asyncio.to_thread(_load_in_thread, conn_factory, feed, dest, releases)
        _record(conn, feed, checked_at=now, ok_at=now, changed_at=now, status="ok", detail=None,
                etag=info["etag"], last_modified=info["last_modified"], size=info["size"], rows=rows, note=note)
        log.info("CVE feed %s: loaded %d rows (%d bytes)", feed.name, rows, info["size"])
        return True
    except Exception as exc:  # a bad file must not stop the chore
        log.exception("CVE feed %s failed to load", feed.name)
        try:
            _record(conn, feed, checked_at=now, status="error", detail=f"{type(exc).__name__}: {exc}"[:200],
                    etag=None, last_modified=None)
        except sqlite3.Error:
            pass
        return False
    finally:
        conn.close()


def _load_in_thread(conn_factory, feed, path, releases):
    conn = conn_factory()
    try:
        return load_one(conn, feed, path, releases)
    finally:
        conn.close()


def reload_debian(conn_factory, data_dir: str, releases: set[str]) -> int | None:
    """Parse the saved tracker file again, for another set of releases (a host
    on a new release reported). Returns the rows kept, or None if no file."""
    feed = FEEDS["debian"]
    path = raw_path(data_dir, feed)
    if not path.exists():
        return None
    conn = conn_factory()
    try:
        rows = load_debian(conn, path, releases)
        store.set_meta(conn, "deb_releases", json.dumps(sorted(releases)))
        _record(conn, feed, rows=rows, note="releases: " + ", ".join(sorted(releases)))
        return rows
    finally:
        conn.close()
