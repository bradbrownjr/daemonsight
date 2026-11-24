"""Backups and restores.

A backup is one .tar.gz, readable by its owner only, holding:
  state.db       a consistent copy of the live database (SQLite's online
                 backup API, so the collector or hub can keep writing)
  config.toml    the config file the install runs with
  password, secret, hub.token   when they exist and can be read
  remotes/<name>.key   the API key of each system the hub reads (a hub only); <name>.reader-token the Docker reader's token; <name>.crowdsec-key a CrowdSec bouncer key
  shodan.key   the Shodan API key for the outside view, when one is saved (a hub only)
  notify/<id>.secret   an alert channel's webhook URL, token or password (a hub only)
  manifest.json  version, schema, host and what's inside

The password file holds an Argon2 hash, but the session secret, an upload
token, the API keys of remote systems and the Shodan API key are live
credentials. Store backups like the server itself.

A restore refuses while the collector or hub holds the database (see
`hold`), checks the archive's names, the database's integrity and its schema
version, keeps each current file as <name>.before-restore, then swaps the
backup in.
"""

from __future__ import annotations

import fcntl
import io
import json
import os
import shutil
import sqlite3
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path

import re

from . import db, full_version
from .config import Config
from .notify import channels as notify_channels
from .remote import store as remote_store

PREFIX = "daemonsight-"
SUFFIX = ".tar.gz"
MAX_MEMBER = 4 * 2**30


class BackupError(Exception):
    pass


# --- the lock that keeps a restore away from a running writer ---------------

def _lock_path(cfg: Config) -> Path:
    return Path(cfg.data_dir) / "daemonsight.lock"


@contextmanager
def hold(cfg: Config):
    """Held by the collector, or the hub, for as long as it runs."""
    path = _lock_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError(f"another DaemonSight process holds {path}") from None
        yield
    finally:
        os.close(fd)


# --- making a backup ----------------------------------------------------------

def _files(cfg: Config, config_file: Path) -> dict[str, Path]:
    return {"config.toml": config_file, "password": Path(cfg.web.password_file),
            "secret": Path(cfg.web.secret_file), "hub.token": Path(cfg.upload.token_file),
            "shodan.key": cfg.shodan_key_path, **remote_store.key_files(cfg.data_dir),
            **notify_channels.key_files(cfg.data_dir)}


def create(cfg: Config, config_file: Path, dest_dir: Path | None = None, now: float | None = None) -> Path:
    """Write a backup and return its path."""
    now = now or time.time()
    dest_dir = Path(dest_dir or cfg.backup_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    final = dest_dir / f"{PREFIX}{cfg.host_id}-{stamp}{SUFFIX}"
    tmp_db = dest_dir / f".{final.name}.db"
    tmp_tar = dest_dir / f".{final.name}.part"
    try:
        if not cfg.db_path.exists():
            raise BackupError(f"no database at {cfg.db_path}")
        src = sqlite3.connect(f"file:{cfg.db_path}?mode=ro", uri=True, timeout=30)
        dst = sqlite3.connect(tmp_db)
        try:
            src.backup(dst)
            schema = dst.execute("PRAGMA user_version").fetchone()[0]
        finally:
            dst.close()
            src.close()
        included = ["state.db"]
        fd = os.open(tmp_tar, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
            tar.add(tmp_db, arcname="state.db")
            for name, path in _files(cfg, config_file).items():
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                _add_bytes(tar, name, data)
                included.append(name)
            manifest = {"format": 1, "created": now, "version": full_version(), "schema": schema,
                        "host": cfg.host_id, "files": included}
            _add_bytes(tar, "manifest.json", json.dumps(manifest, indent=2).encode())
        os.replace(tmp_tar, final)
    finally:
        for p in (tmp_db, tmp_tar):
            p.unlink(missing_ok=True)
    return final


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def prune(dest_dir: Path, keep: int) -> list[Path]:
    """Keep the newest `keep` backups in dest_dir; return what was removed."""
    if keep <= 0:
        return []
    found = sorted((p for p in Path(dest_dir).glob(f"{PREFIX}*{SUFFIX}") if p.is_file()),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    gone = found[keep:]
    for p in gone:
        p.unlink(missing_ok=True)
    return gone


def due(cfg: Config, now: float) -> bool:
    """True when the newest backup is older than interval_hours."""
    hours = cfg.backup_interval_hours
    if hours <= 0:
        return False
    newest = max((p.stat().st_mtime for p in cfg.backup_dir.glob(f"{PREFIX}*{SUFFIX}")), default=0)
    return now - newest >= hours * 3600


def scheduled(cfg: Config, config_file: Path) -> Path | None:
    """Make a backup if one is due and prune old ones. Blocking: run it in a
    thread."""
    now = time.time()
    if not due(cfg, now):
        return None
    path = create(cfg, config_file, now=now)
    prune(cfg.backup_dir, cfg.backup.keep)
    return path


# --- restoring ------------------------------------------------------------------

ALLOWED = {"state.db", "manifest.json", "config.toml", "password", "secret", "hub.token", "shodan.key"}


def _allowed(name: str) -> bool:
    return name in ALLOWED or remote_store.KEY_FILE_RE.match(name) is not None or notify_channels.SECRET_FILE_RE.match(name) is not None


def _read(archive: Path) -> tuple[dict, dict[str, bytes] | None, tarfile.TarFile]:
    try:
        tar = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise BackupError(f"can't open {archive}: {exc}") from None
    members = {}
    for m in tar.getmembers():
        if not _allowed(m.name) or not m.isfile() or m.size > MAX_MEMBER:
            raise BackupError(f"unexpected entry in the archive: {m.name!r}")
        if m.name in members:
            raise BackupError(f"{m.name} appears twice in the archive")
        members[m.name] = m
    if "state.db" not in members or "manifest.json" not in members:
        raise BackupError("not a DaemonSight backup (no state.db or manifest.json)")
    manifest = json.loads(tar.extractfile(members["manifest.json"]).read())
    return manifest, members, tar


def inspect(archive: Path) -> dict:
    manifest, _, tar = _read(archive)
    tar.close()
    return manifest


def restore(cfg: Config, archive: Path, config_file: Path, db_only: bool = False) -> list[str]:
    """Put a backup back. The collector or hub must be stopped. Returns what
    was restored."""
    manifest, members, tar = _read(Path(archive))
    with tar, hold(cfg):
        if manifest.get("schema", 0) > db.SCHEMA_VERSION:
            raise BackupError(f"the backup's database (schema {manifest.get('schema')}) is newer than "
                              f"this DaemonSight (schema {db.SCHEMA_VERSION}); update first")
        target = cfg.db_path
        target.parent.mkdir(parents=True, exist_ok=True)
        staged = target.with_name(target.name + ".restoring")
        with tar.extractfile(members["state.db"]) as src, open(staged, "wb") as out:
            shutil.copyfileobj(src, out)
        try:
            check = sqlite3.connect(staged)
            try:
                ok = check.execute("PRAGMA integrity_check").fetchone()[0]
                schema = check.execute("PRAGMA user_version").fetchone()[0]
            finally:
                check.close()
            if ok != "ok":
                raise BackupError(f"the backup's database fails its integrity check: {ok}")
            if schema > db.SCHEMA_VERSION:
                raise BackupError(f"the backup's database is schema {schema}, newer than this DaemonSight")
            done = []
            _swap(staged, target)
            for side in ("-wal", "-shm"):
                Path(str(target) + side).unlink(missing_ok=True)
            done.append(f"database -> {target}")
        finally:
            staged.unlink(missing_ok=True)
        if not db_only:
            wanted = {**_files(cfg, config_file),
                      **{n: path for n in members
                         if (path := remote_store.member_path(cfg.data_dir, n) or notify_channels.member_path(cfg.data_dir, n)) is not None}}
            for name, path in wanted.items():
                if name in members:
                    data = tar.extractfile(members[name]).read()
                    tmp = path.with_name(path.name + ".restoring")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if name.startswith(("remotes/", "notify/")):
                        os.chmod(path.parent, 0o700)
                    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(data)
                    _swap(tmp, path)
                    done.append(f"{name} -> {path}")
    return done


def _swap(new: Path, target: Path) -> None:
    """Move `target` aside as <name>.before-restore, then put `new` in its
    place with the old file's owner and mode."""
    st = None
    if target.exists():
        st = target.stat()
        shutil.copy2(target, target.with_name(target.name + ".before-restore"))
        wal = Path(str(target) + "-wal")
        if wal.exists():
            shutil.copy2(wal, target.with_name(target.name + ".before-restore-wal"))
    if st is not None:
        os.chmod(new, st.st_mode & 0o777)
        if os.geteuid() == 0:
            os.chown(new, st.st_uid, st.st_gid)
    os.replace(new, target)
