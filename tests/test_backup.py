"""Backups and restores."""

import io
import json
import os
import sqlite3
import tarfile
import time

import pytest

from daemonsight import backup, db


@pytest.fixture
def live(cfg, tmp_path):
    """An install with a config file, an upload token and a database that a
    writer keeps open, as the collector does."""
    conf = tmp_path / "config.toml"
    conf.write_text('host_id = "testhost"\n')
    cfg.upload.token_file = str(tmp_path / "hub.token")
    (tmp_path / "hub.token").write_text("tok\n")
    conn = db.connect_writer(cfg.db_path)
    db.add_event(conn, "testhost", time.time(), "port_new", "before the backup")
    yield cfg, conf, conn
    conn.close()


def titles(conn):
    return [r["title"] for r in db.recent_events(conn, "testhost")]


def test_round_trip(live, tmp_path):
    cfg, conf, conn = live
    path = backup.create(cfg, conf)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert backup.inspect(path)["files"] == ["state.db", "config.toml", "password", "secret", "hub.token"]

    db.add_event(conn, "testhost", time.time(), "port_new", "after the backup")
    (tmp_path / "secret").write_text("changed")
    conn.close()  # the collector is stopped for a restore

    done = backup.restore(cfg, path, conf)
    assert any(d.startswith("database") for d in done)
    fresh = db.connect_writer(cfg.db_path)
    assert titles(fresh) == ["before the backup"]
    fresh.close()
    assert (tmp_path / "secret").read_text() == "x" * 64
    assert (tmp_path / "secret.before-restore").read_text() == "changed"


def test_restore_refused_while_running(live):
    cfg, conf, _ = live
    path = backup.create(cfg, conf)
    with backup.hold(cfg):  # the collector or hub is running
        with pytest.raises(backup.BackupError, match="holds"):
            backup.restore(cfg, path, conf)


def test_db_only(live, tmp_path):
    cfg, conf, conn = live
    path = backup.create(cfg, conf)
    conn.close()
    (tmp_path / "secret").write_text("keep me")
    backup.restore(cfg, path, conf, db_only=True)
    assert (tmp_path / "secret").read_text() == "keep me"


def _archive(tmp_path, members: dict[str, bytes]):
    p = tmp_path / "evil.tar.gz"
    with tarfile.open(p, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return p


def test_bad_archives_refused(live, tmp_path):
    cfg, conf, conn = live
    conn.close()
    manifest = json.dumps({"schema": 1}).encode()
    with pytest.raises(backup.BackupError, match="unexpected"):
        backup.restore(cfg, _archive(tmp_path, {"../../etc/passwd": b"x", "manifest.json": manifest}), conf)
    with pytest.raises(backup.BackupError, match="not a DaemonSight backup"):
        backup.restore(cfg, _archive(tmp_path, {"manifest.json": manifest}), conf)
    with pytest.raises(backup.BackupError, match="newer"):
        backup.restore(cfg, _archive(tmp_path, {"state.db": b"", "manifest.json": json.dumps({"schema": 99}).encode()}), conf)
    junk = _archive(tmp_path, {"state.db": b"not a database" * 100, "manifest.json": manifest})
    with pytest.raises((backup.BackupError, sqlite3.DatabaseError)):
        backup.restore(cfg, junk, conf)
    # Nothing was replaced.
    assert titles(db.connect_writer(cfg.db_path)) == ["before the backup"]


def test_schedule_and_prune(live):
    cfg, conf, _ = live
    cfg.backup.interval_hours = 24
    cfg.backup.keep = 2
    assert backup.due(cfg, time.time())
    first = backup.scheduled(cfg, conf)
    assert first and backup.scheduled(cfg, conf) is None  # not due again yet
    for i in range(3):
        p = backup.create(cfg, conf, now=time.time() + i + 1)
        os.utime(p, (time.time() + i + 1, time.time() + i + 1))
    backup.prune(cfg.backup_dir, cfg.backup.keep)
    assert len(list(cfg.backup_dir.glob("daemonsight-*.tar.gz"))) == 2
    cfg.backup.interval_hours = 0
    assert not backup.due(cfg, time.time() + 10**6)
