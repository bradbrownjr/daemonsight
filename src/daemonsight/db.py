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

from .findings import fingerprint

SCHEMA_VERSION = 9

# Events that belong to no host (a setting changed on the hub) use this as their
# host. No host id can be empty (hub.HOST_RE), so a row never shows up under a host.
HUB_HOST = ""

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
    resolved_at REAL,
    fix         TEXT,   -- command(s) that resolve it, one per line; NULL when none does
    basis       TEXT,   -- what an acceptance is tied to; NULL means the title
    howto       TEXT    -- plain-language steps, one per line (hub rules only); NULL when none
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_open
    ON findings (host, rule, key) WHERE resolved_at IS NULL;

-- Findings someone accepted, with a note. Written by the hub's web process
-- (the collector never touches it). Deleted when the finding resolves. The
-- fingerprint hashes the finding's basis: when it differs from the open
-- finding's, the acceptance no longer applies.
CREATE TABLE IF NOT EXISTS accepted (
    host        TEXT NOT NULL,
    rule        TEXT NOT NULL,
    key         TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    note        TEXT NOT NULL,
    accepted_at REAL NOT NULL,
    accepted_by TEXT NOT NULL,
    PRIMARY KEY (host, rule, key)
);

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
    address      TEXT,
    update_to    TEXT,      -- commit the hub asked this host to install
    update_asked REAL,
    update_state TEXT,      -- JSON: the host's last update result
    remote_update INTEGER,  -- 0 when the host turned hub updates off
    kind         TEXT       -- NULL: a collector uploads for it. "unraid": the hub reads it over its API (see remotes)
);

-- Hub: what Shodan's InternetDB last said about each public address (see
-- outside.py). data is the cleaned answer as JSON; status says what it was:
-- "ok" (a record), "none" (404: Shodan has nothing on the address), or
-- "error" (no answer yet). A failed refresh keeps the old data and sets error.
CREATE TABLE IF NOT EXISTS outside (
    ip         TEXT PRIMARY KEY,
    first_try  REAL NOT NULL,
    checked_at REAL NOT NULL,   -- last attempt
    fetched_at REAL,            -- last good answer (a 404 counts)
    status     TEXT NOT NULL,
    data       TEXT,
    error      TEXT
);

-- Hub: settings changed on the Settings page (see settings.py). value is JSON.
-- They sit over the config file and under nothing; deleting a row brings the
-- file's value (or the default) back. Written by the hub's web process only.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    changed_at REAL NOT NULL,
    changed_by TEXT NOT NULL
);

-- Hub: systems the hub reads over their own API (no collector). One row per
-- system, with the same id as its hosts row. The API key is not here: it is
-- a file under <data_dir>/remotes/ (see remote/store.py).
CREATE TABLE IF NOT EXISTS remotes (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    url        TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    tls        TEXT NOT NULL DEFAULT 'verify',   -- 'verify' (CA store) or 'pin' (one certificate)
    tls_pin    TEXT,                             -- SHA-256 of the pinned certificate (DER), hex
    tls_cert   TEXT,                             -- the pinned certificate, PEM (public)
    interval   INTEGER NOT NULL DEFAULT 60,      -- seconds between polls
    created_at REAL NOT NULL,
    last_poll  REAL,                             -- last attempt
    last_ok    REAL,                             -- last attempt that worked
    last_error TEXT,
    fails      INTEGER NOT NULL DEFAULT 0,       -- polls in a row that failed
    reader_url TEXT                              -- an Unraid server's Docker reader (its token is a file); NULL: none
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


def connect_writer(path: Path, busy_ms: int = 5000) -> sqlite3.Connection:
    """`busy_ms`: how long a write waits for another writer. The services keep
    5 s, since they wait on their own event loop; a CLI command can wait longer
    for a hub that is busy just after it starts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA busy_timeout={int(busy_ms)}")
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
        # Version 2 hosts rows have no update columns.
        have = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
        for col, kind in (("update_to", "TEXT"), ("update_asked", "REAL"), ("update_state", "TEXT"),
                          ("remote_update", "INTEGER"), ("kind", "TEXT")):
            if col not in have:
                conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {kind}")
        # Version 4 databases have no remotes table (the script above created it) and no hosts.kind.
        # Version 3 findings have no fix or basis; old rows keep NULL until the next run rewrites them.
        have = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        # Version 5 findings have no howto.
        for col in ("fix", "basis", "howto"):
            if col not in have:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
        # Version 8 remotes have no reader_url (the Docker reader, schema 9).
        if "reader_url" not in {r[1] for r in conn.execute("PRAGMA table_info(remotes)")}:
            conn.execute("ALTER TABLE remotes ADD COLUMN reader_url TEXT")
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


def prune(conn, now: float, metrics_hours: float, events_days: float, resolved_findings_days: float,
          host: str | None = None) -> None:
    """Apply the retention settings, for one host or (host=None, on a hub)
    every host. A value of 0 keeps that kind of row for good. Open findings
    are never pruned."""
    where, args = ("host = ? AND ", [host]) if host is not None else ("", [])
    if metrics_hours > 0:
        conn.execute(f"DELETE FROM metrics WHERE {where}ts < ?", (*args, now - metrics_hours * 3600))
    if events_days > 0:
        conn.execute(f"DELETE FROM events WHERE {where}ts < ?", (*args, now - events_days * 86400))
    if resolved_findings_days > 0:
        conn.execute(f"DELETE FROM findings WHERE {where}resolved_at IS NOT NULL AND resolved_at < ?",
                     (*args, now - resolved_findings_days * 86400))


def add_event(conn, host: str, ts: float, kind: str, title: str, *, severity: str | None = None,
              detail: str | None = None, link: str | None = None) -> None:
    conn.execute(
        "INSERT INTO events (host, ts, kind, severity, title, detail, link) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (host, ts, kind, severity, title, detail, link),
    )


def reconcile_findings(conn, host: str, ts: float, current: list,
                       keep_prefix: str | tuple[str, ...] | None = None,
                       only_prefix: str | tuple[str, ...] | None = None) -> list[tuple[str, object]]:
    """Make the open findings match `current` (a list of findings.Finding).
    Rules starting with `keep_prefix` are left alone (the hub's own rules).
    With `only_prefix`, only the open findings of rules starting with it are
    compared, and `current` should hold only those.

    Returns (change, finding) pairs where change is "opened" or "resolved".
    """
    changes: list[tuple[str, object]] = []
    open_rows = {
        (r["rule"], r["key"]): r
        for r in conn.execute("SELECT * FROM findings WHERE host = ? AND resolved_at IS NULL", (host,))
        if not (keep_prefix and r["rule"].startswith(keep_prefix))
        and (only_prefix is None or r["rule"].startswith(only_prefix))
    }
    seen = set()
    conn.execute("BEGIN")
    try:
        for f in current:
            ident = (f.rule, f.key)
            seen.add(ident)
            if ident in open_rows:
                conn.execute(
                    "UPDATE findings SET severity=?, title=?, detail=?, link=?, fix=?, basis=?, howto=?, last_seen=? "
                    "WHERE id=?",
                    (f.severity, f.title, f.detail, f.link, f.fix, f.basis, f.howto, ts, open_rows[ident]["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO findings (host, rule, key, severity, title, detail, link, fix, basis, howto, "
                    "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (host, f.rule, f.key, f.severity, f.title, f.detail, f.link, f.fix, f.basis, f.howto, ts, ts),
                )
                changes.append(("opened", f))
        for ident, row in open_rows.items():
            if ident not in seen:
                conn.execute("UPDATE findings SET resolved_at=? WHERE id=?", (ts, row["id"]))
                conn.execute("DELETE FROM accepted WHERE host=? AND rule=? AND key=?", (host, *ident))
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
            conn.execute("DELETE FROM accepted WHERE host=? AND rule=? AND key=?", (host, rule, key))
            return "resolved"
        return None
    if row:
        conn.execute("UPDATE findings SET severity=?, title=?, detail=?, link=?, fix=?, basis=?, howto=?, last_seen=? "
                     "WHERE id=?", (f.severity, f.title, f.detail, f.link, f.fix, f.basis, f.howto, ts, row["id"]))
        return None
    conn.execute("INSERT INTO findings (host, rule, key, severity, title, detail, link, fix, basis, howto, "
                 "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (host, rule, key, f.severity, f.title, f.detail, f.link, f.fix, f.basis, f.howto, ts, ts))
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


def _finding_dict(r: sqlite3.Row) -> dict:
    """A findings row as a dict. A database the collector hasn't migrated yet
    (the web process only reads it) lacks the fix, basis and howto columns."""
    d = dict(r)
    d.setdefault("fix", None)
    d.setdefault("basis", None)
    d.setdefault("howto", None)
    return d


def _accepted_rows(conn, host: str | None = None) -> dict[tuple[str, str, str], dict]:
    sql, args = "SELECT * FROM accepted", ()
    if host is not None:
        sql, args = sql + " WHERE host = ?", (host,)
    try:
        return {(r["host"], r["rule"], r["key"]): dict(r) for r in conn.execute(sql, args)}
    except sqlite3.OperationalError:  # table not created yet
        return {}


def _split(rows: list[dict], accepted: dict) -> tuple[list[dict], list[dict]]:
    """(active, accepted). Each finding dict gains "accepted": None, or the
    acceptance with "changed" set when the finding's basis is no longer the one
    that was accepted. A changed one counts as active again."""
    active, held = [], []
    for d in rows:
        a = accepted.get((d["host"], d["rule"], d["key"]))
        d["accepted"] = None
        if a is None:
            active.append(d)
            continue
        a = dict(a)
        a["changed"] = a["fingerprint"] != fingerprint(d["rule"], d["key"], d["basis"], d["title"])
        d["accepted"] = a
        (active if a["changed"] else held).append(d)
    return active, held


def findings_state(conn, host: str) -> tuple[list[dict], list[dict]]:
    """The host's open findings as (active, accepted), worst first. Counts,
    badges and lists of what needs attention use the active ones."""
    return _split([_finding_dict(r) for r in open_findings(conn, host)], _accepted_rows(conn, host))


def active_findings_by_host(conn) -> dict[str, list[dict]]:
    """Every host's active findings (open and not accepted), for the hub's host list."""
    rows = [_finding_dict(r) for r in conn.execute("SELECT * FROM findings WHERE resolved_at IS NULL")]
    active, _held = _split(rows, _accepted_rows(conn))
    out: dict[str, list[dict]] = {}
    for d in active:
        out.setdefault(d["host"], []).append(d)
    return out


def accept_finding(conn, host: str, rule: str, key: str, note: str, by: str, ts: float) -> dict | None:
    """Accept an open finding with a note (accepting again replaces the old
    acceptance, which is how a changed one is re-accepted). Returns the
    finding, or None when it isn't open."""
    row = conn.execute("SELECT * FROM findings WHERE host = ? AND rule = ? AND key = ? AND resolved_at IS NULL",
                       (host, rule, key)).fetchone()
    if row is None:
        return None
    d = _finding_dict(row)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO accepted (host, rule, key, fingerprint, note, accepted_at, accepted_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (host, rule, key) DO UPDATE SET "
            "fingerprint=excluded.fingerprint, note=excluded.note, accepted_at=excluded.accepted_at, "
            "accepted_by=excluded.accepted_by",
            (host, rule, key, fingerprint(rule, key, d["basis"], d["title"]), note, ts, by))
        add_event(conn, host, ts, "finding_accepted", f"Accepted: {d['title']}", detail=note, link=d["link"])
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return d


def unaccept_finding(conn, host: str, rule: str, key: str, ts: float) -> dict | None:
    """Revoke an acceptance. Returns the finding as it was, with its old note
    under "note", or None when nothing was accepted."""
    old = conn.execute("SELECT * FROM accepted WHERE host = ? AND rule = ? AND key = ?",
                       (host, rule, key)).fetchone()
    if old is None:
        return None
    row = conn.execute("SELECT title, link FROM findings WHERE host = ? AND rule = ? AND key = ? "
                       "AND resolved_at IS NULL", (host, rule, key)).fetchone()
    title, link = (row["title"], row["link"]) if row else (f"{rule} {key}", None)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM accepted WHERE host = ? AND rule = ? AND key = ?", (host, rule, key))
        add_event(conn, host, ts, "finding_unaccepted", f"Un-accepted: {title}",
                  detail=f"Note was: {old['note']}", link=link)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return {"title": title, "note": old["note"]}


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
