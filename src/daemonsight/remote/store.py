"""Remote systems in the hub's database, and their API keys.

A key is a file, `<data_dir>/remotes/<id>.key`, mode 0600 in a 0700 folder,
written atomically. It is never in the database, never in a page, a log or an
event, and never shown again once saved; saving a new one replaces the file.
Removing a system deletes the file.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path


KINDS = {"unraid": "Unraid"}
KEY_RE = re.compile(r"^[\x21-\x7e]{8,200}$")      # printable ASCII, no spaces
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")   # the same rule as hub.HOST_RE
KEY_FILE_RE = re.compile(r"^remotes/([A-Za-z0-9][A-Za-z0-9._-]{0,62})\.key$")
MIN_INTERVAL, MAX_INTERVAL, DEFAULT_INTERVAL = 30, 3600, 60


# --- key files ----------------------------------------------------------------

def key_dir(data_dir: str | os.PathLike) -> Path:
    return Path(data_dir) / "remotes"


def key_path(data_dir: str | os.PathLike, remote_id: str) -> Path:
    if not ID_RE.match(remote_id):
        raise ValueError(f"not a valid system name: {remote_id!r}")
    return key_dir(data_dir) / f"{remote_id}.key"


def clean_key(raw: str | None) -> str:
    key = (raw or "").strip()
    if not KEY_RE.match(key):
        raise ValueError("The API key is missing or has characters an Unraid key doesn't have.")
    return key


def write_key(data_dir, remote_id: str, key: str) -> Path:
    """Save or replace the key. The new file is complete and 0600 before it takes the old one's place."""
    key = clean_key(key)
    folder = key_dir(data_dir)
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    path = key_path(data_dir, remote_id)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(key + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return path


def read_key(data_dir, remote_id: str) -> str | None:
    try:
        key = key_path(data_dir, remote_id).read_text().strip()
    except (OSError, ValueError):
        return None
    return key if KEY_RE.match(key) else None


def delete_key(data_dir, remote_id: str) -> bool:
    try:
        key_path(data_dir, remote_id).unlink()
        return True
    except (OSError, ValueError):
        return False


def key_files(data_dir) -> dict[str, Path]:
    """Every saved key as the name a backup archive stores it under."""
    out = {}
    for p in sorted(key_dir(data_dir).glob("*.key")):
        if p.is_file() and ID_RE.match(p.name[:-4]):
            out[f"remotes/{p.name}"] = p
    return out


# --- rows ---------------------------------------------------------------------

def get(conn, remote_id: str):
    return conn.execute("SELECT * FROM remotes WHERE id = ?", (remote_id,)).fetchone()


def all_rows(conn) -> list:
    return conn.execute("SELECT * FROM remotes ORDER BY id").fetchall()


def host_kind(conn, host_id: str) -> str | None:
    row = conn.execute("SELECT kind FROM hosts WHERE id = ?", (host_id,)).fetchone()
    return row["kind"] if row else None


def valid_interval(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"The interval is a number of seconds, {MIN_INTERVAL} to {MAX_INTERVAL}.") from None
    if not MIN_INTERVAL <= n <= MAX_INTERVAL:
        raise ValueError(f"The interval is a number of seconds, {MIN_INTERVAL} to {MAX_INTERVAL}.")
    return n


def add(conn, data_dir, remote_id: str, kind: str, url: str, key: str, *, tls: str = "verify",
        pin: str | None = None, cert: str | None = None, interval: int = DEFAULT_INTERVAL,
        now: float | None = None) -> None:
    """Create the system: a hosts row marked with its kind (no upload token
    exists for it and `hub update` skips it), the remotes row and the key file."""
    if kind not in KINDS:
        raise ValueError("Unknown kind of system.")
    if not ID_RE.match(remote_id):
        raise ValueError("Use letters, digits, '.', '_' and '-', starting with a letter or digit (63 at most).")
    if tls not in ("verify", "pin") or (tls == "pin" and not (pin and cert)):
        raise ValueError("TLS mode needs a confirmed certificate.")
    interval = valid_interval(interval)
    now = time.time() if now is None else now
    if conn.execute("SELECT 1 FROM hosts WHERE id = ?", (remote_id,)).fetchone():
        raise ValueError(f"{remote_id} already exists. Pick another name.")
    write_key(data_dir, remote_id, key)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # The sentinel can never equal a SHA-256 hex digest, so no token matches this host.
            conn.execute("INSERT INTO hosts (id, token_hash, created_at, kind) VALUES (?, ?, ?, ?)",
                         (remote_id, f"remote:{remote_id}", now, kind))
            conn.execute("INSERT INTO remotes (id, kind, url, enabled, tls, tls_pin, tls_cert, interval, created_at) "
                         "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)", (remote_id, kind, url, tls, pin, cert, interval, now))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    except Exception:
        delete_key(data_dir, remote_id)
        raise


def update(conn, data_dir, remote_id: str, *, url: str, tls: str, pin: str | None, cert: str | None,
           interval: int, enabled: bool, key: str | None = None) -> None:
    if tls not in ("verify", "pin") or (tls == "pin" and not (pin and cert)):
        raise ValueError("TLS mode needs a confirmed certificate.")
    interval = valid_interval(interval)
    if key:
        write_key(data_dir, remote_id, key)
    conn.execute("UPDATE remotes SET url=?, tls=?, tls_pin=?, tls_cert=?, interval=?, enabled=?, "
                 "last_poll=NULL, fails=0 WHERE id=?",
                 (url, tls, pin if tls == "pin" else None, cert if tls == "pin" else None, interval,
                  int(enabled), remote_id))


def set_enabled(conn, remote_id: str, enabled: bool) -> bool:
    return conn.execute("UPDATE remotes SET enabled=?, last_poll=NULL, fails=0 WHERE id=?",
                        (int(enabled), remote_id)).rowcount == 1


def remove(conn, data_dir, remote_id: str, purge: bool = True) -> bool:
    """Delete the system: its remotes and hosts rows and its key file, and
    (by default) every row of history it has (snapshots, metrics, findings,
    events, acceptances)."""
    row = get(conn, remote_id)
    if row is None:
        return False
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM remotes WHERE id = ?", (remote_id,))
        conn.execute("DELETE FROM hosts WHERE id = ? AND kind IS NOT NULL", (remote_id,))
        if purge:
            for table in ("snapshots", "metrics", "findings", "events", "accepted"):
                conn.execute(f"DELETE FROM {table} WHERE host = ?", (remote_id,))  # noqa: S608 (fixed names)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    if data_dir:
        delete_key(data_dir, remote_id)
    return True
