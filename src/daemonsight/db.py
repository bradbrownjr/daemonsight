"""SQLite storage.

On a host, the collector is the only writer and the web process opens the
file read-only. On a hub, the hub's web process is the only writer: it stores
what collectors upload. Every table carries a `host` column, so one database
holds every host.

Read-only access to a WAL database works when the -wal and -shm files exist
and are readable (https://www.sqlite.org/wal.html, section 5). The collector
keeps its connection open, and the data directory is setgid to the
daemonsight group with umask 027, so those files are group-readable.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    host     TEXT NOT NULL,
    source   TEXT NOT NULL,
    taken_at REAL NOT NULL,
    ok       INTEGER NOT NULL,
    error    TEXT,
    data     TEXT,
    PRIMARY KEY (host, source)
);

CREATE TABLE IF NOT EXISTS metrics (
    host  TEXT NOT NULL,
    ts    REAL NOT NULL,
    name  TEXT NOT NULL,
    value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_by_name ON metrics (host, name, ts);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    host        TEXT NOT NULL,
    rule        TEXT NOT NULL,
    key         TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL,
    link        TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    resolved_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_open
    ON findings (host, rule, key) WHERE resolved_at IS NULL;

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY,
    host     TEXT NOT NULL,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT,
    title    TEXT NOT NULL,
    detail   TEXT,
    link     TEXT,
    src_id   INTEGER  -- hub: the event's id on its collector, so a resent upload adds nothing
);
CREATE INDEX IF NOT EXISTS events_by_time ON events (host, ts);

-- Collector: upload cursors. Hub: nothing yet.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Hub: hosts allowed to upload, by the SHA-256 of their token.
CREATE TABLE IF NOT EXISTS hosts (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   REAL NOT NULL,
    last_seq     INTEGER NOT NULL DEFAULT 0,
    last_seen    REAL,
    last_sent_at REAL,
    max_interval REAL,
    version      TEXT,
    address      TEXT
);
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Snapshot:
    source: str
    taken_at: float
    ok: bool
    error: str | None
    data: dict | None


def connect_writer(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    migrate(conn)
    return conn


def connect_reader(path: Path) -> sqlite3.Connection:
    """Open read-only. Falls back to immutable mode when the collector is
    stopped and the WAL side files are gone."""
    if not path.exists():
        raise FileNotFoundError(path)
    base = f"file:{quote(str(path))}?mode=ro"
    try:
        conn = sqlite3.connect(base, uri=True)
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
    except sqlite3.OperationalError:
        conn = sqlite3.connect(base + "&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError(f"database schema {version} is newer than this DaemonSight ({SCHEMA_VERSION})")
    if version < SCHEMA_VERSION:
        conn.executescript(SCHEMA)
        # Version 1 databases have events without src_id.
        if "src_id" not in {r[1] for r in conn.execute("PRAGMA table_info(events)")}:
            conn.execute("ALTER TABLE events ADD COLUMN src_id INTEGER")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS events_by_source "
                     "ON events (host, src_id) WHERE src_id IS NOT NULL")
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


# --- writes (collector) ---------------------------------------------------

def put_snapshot(conn, host: str, source: str, taken_at: float, ok: bool,
                 error: str | None, data: dict | None) -> None:
    conn.execute(
        "INSERT INTO snapshots (host, source, taken_at, ok, error, data) VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (host, source) DO UPDATE SET taken_at=excluded.taken_at, ok=excluded.ok, "
        "error=excluded.error, data=excluded.data",
        (host, source, taken_at, int(ok), error, json.dumps(data) if data is not None else None),
    )


def add_metrics(conn, host: str, ts: float, values: dict[str, float]) -> None:
    conn.executemany(
        "INSERT INTO metrics (host, ts, name, value) VALUES (?, ?, ?, ?)",
        [(host, ts, name, float(v)) for name, v in values.items() if v is not None],
    )


def prune_metrics(conn, host: str, before: float) -> None:
    conn.execute("DELETE FROM metrics WHERE host = ? AND ts < ?", (host, before))


def add_event(conn, host: str, ts: float, kind: str, title: str, *, severity: str | None = None,
              detail: str | None = None, link: str | None = None) -> None:
    conn.execute(
        "INSERT INTO events (host, ts, kind, severity, title, detail, link) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (host, ts, kind, severity, title, detail, link),
    )


def reconcile_findings(conn, host: str, ts: float, current: list,
                       keep_prefix: str | None = None) -> list[tuple[str, object]]:
    """Make the open findings match `current` (a list of findings.Finding).
    Rules starting with `keep_prefix` are left alone (the hub's own rules).

    Returns (change, finding) pairs where change is "opened" or "resolved".
    """
    changes: list[tuple[str, object]] = []
    open_rows = {
        (r["rule"], r["key"]): r
        for r in conn.execute("SELECT * FROM findings WHERE host = ? AND resolved_at IS NULL", (host,))
        if not (keep_prefix and r["rule"].startswith(keep_prefix))
    }
    seen = set()
    conn.execute("BEGIN")
    try:
        for f in current:
            ident = (f.rule, f.key)
            seen.add(ident)
            if ident in open_rows:
                conn.execute(
                    "UPDATE findings SET severity=?, title=?, detail=?, link=?, last_seen=? WHERE id=?",
                    (f.severity, f.title, f.detail, f.link, ts, open_rows[ident]["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO findings (host, rule, key, severity, title, detail, link, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (host, f.rule, f.key, f.severity, f.title, f.detail, f.link, ts, ts),
                )
                changes.append(("opened", f))
        for ident, row in open_rows.items():
            if ident not in seen:
                conn.execute("UPDATE findings SET resolved_at=? WHERE id=?", (ts, row["id"]))
                changes.append(("resolved", row))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return changes


def set_finding(conn, host: str, ts: float, f, *, rule: str, key: str) -> str | None:
    """Open, update or resolve one finding without touching the others.
    `f` is a findings.Finding, or None to resolve. Returns "opened",
    "resolved" or None."""
    row = conn.execute("SELECT id FROM findings WHERE host = ? AND rule = ? AND key = ? AND resolved_at IS NULL",
                       (host, rule, key)).fetchone()
    if f is None:
        if row:
            conn.execute("UPDATE findings SET resolved_at = ? WHERE id = ?", (ts, row["id"]))
            return "resolved"
        return None
    if row:
        conn.execute("UPDATE findings SET severity=?, title=?, detail=?, link=?, last_seen=? WHERE id=?",
                     (f.severity, f.title, f.detail, f.link, ts, row["id"]))
        return None
    conn.execute("INSERT INTO findings (host, rule, key, severity, title, detail, link, first_seen, last_seen) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (host, rule, key, f.severity, f.title, f.detail, f.link, ts, ts))
    return "opened"


def get_meta(conn, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, values: dict[str, object]) -> None:
    conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?) "
                     "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                     [(k, str(v)) for k, v in values.items()])


# --- reads (collector and web) --------------------------------------------

def get_snapshot(conn, host: str, source: str) -> Snapshot | None:
    row = conn.execute("SELECT * FROM snapshots WHERE host = ? AND source = ?", (host, source)).fetchone()
    if row is None:
        return None
    return Snapshot(row["source"], row["taken_at"], bool(row["ok"]), row["error"],
                    json.loads(row["data"]) if row["data"] else None)


def get_snapshots(conn, host: str) -> dict[str, Snapshot]:
    out = {}
    for row in conn.execute("SELECT * FROM snapshots WHERE host = ?", (host,)):
        out[row["source"]] = Snapshot(row["source"], row["taken_at"], bool(row["ok"]), row["error"],
                                      json.loads(row["data"]) if row["data"] else None)
    return out


def open_findings(conn, host: str) -> list[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE host = ? AND resolved_at IS NULL", (host,)
    ).fetchall()
    return sorted(rows, key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["first_seen"]))


def recent_events(conn, host: str, limit: int = 8) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE host = ? ORDER BY ts DESC LIMIT ?", (host, limit)
    ).fetchall()


def metric_series(conn, host: str, name: str, since: float) -> list[tuple[float, float]]:
    return [
        (r["ts"], r["value"])
        for r in conn.execute(
            "SELECT ts, value FROM metrics WHERE host = ? AND name = ? AND ts >= ? ORDER BY ts",
            (host, name, since),
        )
    ]


def metric_average(conn, host: str, name: str, since: float) -> tuple[float | None, int]:
    row = conn.execute(
        "SELECT AVG(value) AS avg, COUNT(*) AS n FROM metrics WHERE host = ? AND name = ? AND ts >= ?",
        (host, name, since),
    ).fetchone()
    return row["avg"], row["n"]


def now() -> float:
    return time.time()
