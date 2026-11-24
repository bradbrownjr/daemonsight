"""The hub's CVE database, <data_dir>/cve.db: a separate file from state.db so
feed data, which can always be downloaded again, stays out of the hub's
backups and its schema version. The chore thread writes it; the pages open it
read-only."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import quote

SCHEMA_VERSION = 4

SCHEMA = """
-- One row per feed: when it was tried, when it last answered, and what it said.
CREATE TABLE IF NOT EXISTS feed (
    name          TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    first_try     REAL,
    checked_at    REAL,      -- last attempt
    ok_at         REAL,      -- last 200 or 304
    changed_at    REAL,      -- last 200
    status        TEXT,      -- "ok", "not modified", "error"
    detail        TEXT,
    etag          TEXT,
    last_modified TEXT,
    size          INTEGER,   -- bytes downloaded the last time it changed
    rows          INTEGER,   -- rows kept in the tables below
    note          TEXT       -- e.g. EPSS model version and score date
);

-- Debian security tracker, only the releases hosts run. "not affected" rows
-- (resolved with fixed version 0) are not kept.
CREATE TABLE IF NOT EXISTS deb (
    release TEXT NOT NULL,
    source  TEXT NOT NULL,
    cve     TEXT NOT NULL,
    status  TEXT NOT NULL,   -- open, resolved, undetermined
    fixed   TEXT,
    urgency TEXT,
    nodsa   TEXT,            -- the tracker's reason for not issuing an advisory, if any
    PRIMARY KEY (release, source, cve)
) WITHOUT ROWID;

-- Alpine's security database (secdb), only the releases the hub's container images run. One row per origin package, CVE and
-- fixed version: `fixed` is a version from the package's secfixes list, never "0" (that key lists CVEs that never
-- affected the package). A CVE fixed in two versions has two rows.
CREATE TABLE IF NOT EXISTS apk (
    release TEXT NOT NULL,   -- "v3.23"
    repo    TEXT NOT NULL,   -- "main" or "community": the file the row came from
    origin  TEXT NOT NULL,
    cve     TEXT NOT NULL,
    fixed   TEXT NOT NULL,
    PRIMARY KEY (release, origin, cve, fixed)
) WITHOUT ROWID;

-- Canonical's CVE OVAL (security-metadata.canonical.com/oval), only the Ubuntu releases the hub's hosts and container images run
-- (see cve/ubuntu.py). One row per source package, CVE and pocket: `pocket` is "" for the standard archives and
-- "esm-infra" or "esm-apps" for the Ubuntu Pro (ESM) ones; `state` is "fixed" (`fixed` is the fixed source version) or "open"
-- (the file's "might be affected and may need fixing": it does not separate needed, deferred and the rest); `kernel` is 1 for a
-- kernel flavor's row (`source` is then the flavor's source package: linux, linux-aws); `priority` is Ubuntu's.
CREATE TABLE IF NOT EXISTS ubu (
    release  TEXT NOT NULL,
    source   TEXT NOT NULL,
    cve      TEXT NOT NULL,
    pocket   TEXT NOT NULL,
    kernel   INTEGER NOT NULL,
    state    TEXT NOT NULL,
    fixed    TEXT,
    priority TEXT,
    PRIMARY KEY (release, source, cve, pocket)
) WITHOUT ROWID;

-- The CVE text from Canonical's file (the Debian tracker's `cve` table is replaced whole whenever it loads).
CREATE TABLE IF NOT EXISTS ubu_cve (
    cve   TEXT PRIMARY KEY,
    descr TEXT NOT NULL
) WITHOUT ROWID;

-- OPNsense's changelog (github.com/opnsense/changelog, community/), only the series the hub's firewalls need (see
-- cve/opnsense.py). `opn_release` is one row per release file; `opn_fix` is one row per security issue a section names.
-- `version` is the section's: the release (26.1.11) or a hotfix under it (26.1.11_3). `kind` is `cve`, or `adv` for a GitHub
-- or FreeBSD advisory with no CVE id (`ref` is then `GHSA:...` or `FREEBSD-SA:...`). `line` is the changelog bullet.
CREATE TABLE IF NOT EXISTS opn_release (
    version TEXT PRIMARY KEY,
    series  TEXT NOT NULL,
    date    TEXT             -- ISO date of the announcement
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS opn_fix (
    version TEXT NOT NULL,
    release TEXT NOT NULL,   -- the file the section is in
    kind    TEXT NOT NULL,
    ref     TEXT NOT NULL,
    line    TEXT NOT NULL,
    PRIMARY KEY (version, kind, ref)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS cve (
    id    TEXT PRIMARY KEY,
    descr TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS epss (
    cve   TEXT PRIMARY KEY,
    score REAL NOT NULL,
    pct   REAL NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS kev (
    cve        TEXT PRIMARY KEY,
    vendor     TEXT,
    product    TEXT,
    name       TEXT,
    added      TEXT,
    ransomware TEXT
) WITHOUT ROWID;

-- What matching found for each host: only CVEs that still apply.
CREATE TABLE IF NOT EXISTS match (
    host      TEXT NOT NULL,
    source    TEXT NOT NULL,
    cve       TEXT NOT NULL,
    state     TEXT NOT NULL,  -- fix, esm (Ubuntu: fixed only through Ubuntu Pro), nofix, minor, undetermined
    installed TEXT,
    fixed     TEXT,           -- Debian: fixed source version. Fedora: advisory id. OPNsense: the changelog section
    urgency   TEXT,           -- Debian's urgency, or Ubuntu's priority
    PRIMARY KEY (host, source, cve)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS matched (
    host       TEXT PRIMARY KEY,
    inv_hash   TEXT,
    inv_at     REAL,
    gen        TEXT,         -- which feed data the matches were made with
    matched_at REAL,
    packages   INTEGER,
    note       TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def connect(path: Path) -> sqlite3.Connection:
    """Open for writing, creating the file and tables."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(f"cve.db schema {version} is newer than this DaemonSight ({SCHEMA_VERSION})")
    if version < SCHEMA_VERSION:
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    return conn


def connect_reader(path: Path) -> sqlite3.Connection | None:
    """Open read-only, or None when there is no CVE database yet."""
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("SELECT 1 FROM feed LIMIT 1").fetchall()
    except sqlite3.OperationalError:
        return None
    return conn


def get_meta(conn, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                 (key, value))
