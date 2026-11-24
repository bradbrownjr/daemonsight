"""Command line entry point: `daemonsight <command>`."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import grp
import json
import logging
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path

from . import config, db, full_version

GROUP = "daemonsight"


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    # httpx logs every request at INFO: one line per upload.
    logging.getLogger("httpx").setLevel(logging.DEBUG if verbose else logging.WARNING)
    # With -v that line carries the full URL, and a Shodan API request's URL carries the key: redact it.
    from . import shodan
    shodan.install_log_redaction()


def _group_id() -> int | None:
    try:
        return grp.getgrnam(GROUP).gr_gid
    except KeyError:
        return None


def _write_private(path: Path, text: str, group: bool = True) -> None:
    """Write a file readable by root and the daemonsight group only, or by
    root only when group is False."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640 if group else 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text + "\n")
    os.chmod(tmp, 0o640 if group else 0o600)
    gid = _group_id()
    if group and gid is not None and os.geteuid() == 0:
        os.chown(tmp, 0, gid)
    os.replace(tmp, path)


def cmd_collector(args, cfg) -> int:
    from .backup import BackupError, hold
    from .collector.runner import Collector
    os.umask(0o027)
    try:
        with hold(cfg):
            asyncio.run(Collector(cfg, config_file=config.config_path(args.config)).run())
    except BackupError as exc:
        print(f"Not starting: {exc}. Is the collector already running?", file=sys.stderr)
        return 1
    return 0


def cmd_web(args, cfg) -> int:
    import uvicorn
    from .backup import BackupError, hold
    from .web.app import create_app

    def serve():
        # The path is for backups on a hub and for the Settings page, which names the file to edit.
        app = create_app(cfg, config_file=config.config_path(args.config))
        uvicorn.run(app, host=cfg.web.listen, port=cfg.web.port, proxy_headers=True,
                    forwarded_allow_ips=",".join(cfg.web.trusted_proxies), server_header=False,
                    access_log=False)

    if not cfg.hub.enabled:
        serve()  # reads only; the collector holds the database
        return 0
    try:
        with hold(cfg):
            serve()
    except BackupError as exc:
        print(f"Not starting: {exc}. Is the hub already running?", file=sys.stderr)
        return 1
    return 0


def cmd_docker_reader(args, cfg) -> int:
    """Serve the Docker reader (docs/DESIGN.md, Docker reader). Needs the Docker socket and a token file."""
    from . import docker_reader
    return docker_reader.serve(args.socket, args.token_file, args.listen, args.port)


def cmd_backup(args, cfg) -> int:
    from . import backup
    try:
        path = backup.create(cfg, config.config_path(args.config), Path(args.to) if args.to else None)
    except (backup.BackupError, OSError, sqlite3.Error) as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {path}")
    print("It holds the session secret and any upload token: keep it as private as the server.")
    return 0


def cmd_restore(args, cfg) -> int:
    from . import backup
    archive = Path(args.archive)
    try:
        m = backup.inspect(archive)
    except backup.BackupError as exc:
        print(exc, file=sys.stderr)
        return 1
    made = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m.get("created", 0)))
    print(f"Backup of {m.get('host')} from {made}, DaemonSight {m.get('version')}, holding "
          f"{', '.join(m.get('files', []))}.")
    if m.get("host") != cfg.host_id:
        print(f"Note: this install's host_id is {cfg.host_id}, not {m.get('host')}.")
    try:
        done = backup.restore(cfg, archive, config.config_path(args.config), db_only=args.db_only)
    except backup.BackupError as exc:
        print(f"Not restored: {exc}.", file=sys.stderr)
        if "holds" in str(exc):
            print("Stop the collector (sudo systemctl stop daemonsight-collector) or the hub container "
                  "first.", file=sys.stderr)
        return 1
    for line in done:
        print(f"Restored {line}")
    print("Each replaced file was kept as <name>.before-restore. Start the collector or hub again.")
    return 0


def cmd_set_password(args, cfg) -> int:
    from .web.auth import hash_password
    first = getpass.getpass("New password: ")
    if len(first) < 12:
        print("Use at least 12 characters.", file=sys.stderr)
        return 1
    if getpass.getpass("Again: ") != first:
        print("The two entries don't match.", file=sys.stderr)
        return 1
    _write_private(Path(cfg.web.password_file), hash_password(first))
    print(f"Saved to {cfg.web.password_file}. Anyone logged in has to log in again.")
    return 0


def cmd_init(args, cfg) -> int:
    """Create the session secret and database. Safe to run again."""
    secret = Path(cfg.web.secret_file)
    if not secret.exists():
        _write_private(secret, secrets.token_hex(32))
        print(f"Created {secret}")
    os.umask(0o027)
    conn = db.connect_writer(cfg.db_path, busy_ms=60_000)
    conn.close()
    print(f"Database ready at {cfg.db_path}")
    return 0


def cmd_collect_once(args, cfg) -> int:
    """Run sources once and print what they return. Writes nothing."""
    from .collector.runner import build_sources, collect_once

    async def run():
        out = {}
        for source in build_sources(cfg):
            if args.source and source.name not in args.source:
                continue
            ok, error, data = await collect_once(source, timeout=30)
            out[source.name] = {"ok": ok, "error": error, "data": data}
            await source.close()
        return out

    print(json.dumps(asyncio.run(run()), indent=2, default=str))
    return 0


def cmd_set_upload_token(args, cfg) -> int:
    """Save the upload token: typed at a prompt, or piped in so it never
    shows on screen, e.g. ssh hub 'daemonsight hub add-host web1 --quiet' |
    sudo daemonsight set-upload-token --url https://hub/api/v1/ingest"""
    from .collector.upload import UploadError, check_url
    if args.url:
        try:
            check_url(args.url)
        except UploadError as exc:
            print(exc, file=sys.stderr)
            return 1
    if sys.stdin.isatty():
        token = getpass.getpass("Token from the hub: ").strip()
    else:
        token = sys.stdin.readline().strip()
    if len(token) < 32 or not token.isascii() or any(c.isspace() for c in token):
        print("That doesn't look like a hub token (run 'daemonsight hub add-host' on the hub).", file=sys.stderr)
        return 1
    _write_private(Path(cfg.upload.token_file), token, group=False)
    print(f"Token saved to {cfg.upload.token_file}.")
    if args.url:
        path = config.config_path(args.config)
        try:
            config.set_upload_url(path, args.url)
        except (ValueError, OSError) as exc:
            print(f"Couldn't set the url in {path}: {exc}", file=sys.stderr)
            return 1
        print(f"Set [upload] url in {path}.")
    elif not cfg.upload.url:
        print("Set url under [upload] in the config (or rerun with --url).")
    print(f"This host uploads as {cfg.host_id!r}; the hub's name for it must match.")
    print("Restart the collector: sudo systemctl restart daemonsight-collector")
    return 0


def cmd_status(args, cfg) -> int:
    """What this host's uploads are doing, from the collector's database. Read-only."""
    from .collector import upload
    print(f"Host:        {cfg.host_id}")
    if not cfg.upload.url:
        print("Hub:         none; this host keeps its data to itself")
        return 0
    print(f"Hub:         {cfg.upload.url}")
    try:
        conn = db.connect_reader(cfg.db_path)
    except (FileNotFoundError, sqlite3.OperationalError):
        print("Last upload: unknown (no database yet; start the collector)")
        return 0
    try:
        ok = db.get_meta(conn, "upload.last_ok")
        bad = upload.rejection(conn)
    except sqlite3.Error:
        ok, bad = None, None
    finally:
        conn.close()
    when = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t)))  # noqa: E731
    print(f"Last upload: {when(ok) if ok else 'never accepted'}")
    if bad:
        print(f"Problem:     {upload.REJECTED_MESSAGE} (HTTP {bad['status']} at {when(bad['at'])}).")
        print("             The collector asks again every hour. On the hub, Manage, Replace upload token; then here:")
        print("             sudo daemonsight set-upload-token && sudo systemctl restart daemonsight-collector")
    return 0


def cmd_uninstall(args, cfg) -> int:
    """Remove DaemonSight from this host (see uninstall.py). The hub's request comes through here too."""
    from . import uninstall
    allowed = cfg is not None and cfg.collector.allow_remote_uninstall
    return uninstall.main(args.yes, hub_request=args.hub_request, allowed=allowed)


def cmd_hub(args, cfg) -> int:
    from . import hub
    if not cfg.hub.enabled:
        print("This install isn't a hub. Set enabled = true under [hub] first.", file=sys.stderr)
        return 1
    conn = db.connect_writer(cfg.db_path, busy_ms=60_000)
    if args.hub_command == "add-host":
        try:
            token = hub.add_host(conn, args.name)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        if args.quiet:
            print(token)
            return 0
        print(f"Token for {args.name}. It is shown once; the hub keeps only its hash.\n")
        print(f"  {token}\n")
        print(f"On {args.name}, with DaemonSight installed:")
        print("  1. sudo daemonsight set-upload-token --url https://<this hub>/api/v1/ingest")
        print("     (paste the token), and make sure host_id in its config is", repr(args.name))
        print("  2. sudo systemctl restart daemonsight-collector")
    elif args.hub_command == "update":
        target = hub.hub_revision()
        if not target:
            print("This hub's own commit isn't known, so there's nothing to update hosts to.", file=sys.stderr)
            return 1
        if args.all:
            ids = hub.request_update_all(conn, target, time.time())
        elif args.name and hub.request_update(conn, args.name, target, time.time()):
            ids = [args.name]
        else:
            print("Name a host the hub knows, or use --all.", file=sys.stderr)
            return 1
        print(f"Asked {', '.join(ids) or 'no hosts'} to update to {target}. Each picks it up with its next upload.")
    elif args.hub_command == "list":
        rows = conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        if not rows:
            print("No hosts. Add one: daemonsight hub add-host <name>")
        for h in rows:
            seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["last_seen"])) if h["last_seen"] else "never"
            what = "last poll  " if h["kind"] else "last upload"
            where = f"{h['kind']} (API)" if h["kind"] else (h["address"] or "")
            print(f"{h['id']:<24} {what} {seen:<20} {where:<40} {h['version'] or ''}")
    elif args.hub_command == "revoke":
        if not hub.revoke_host(conn, args.name, purge=args.purge, data_dir=cfg.data_dir,
                                cve_path=cfg.cve_db_path):
            print(f"No host named {args.name}.", file=sys.stderr)
            return 1
        print(f"Revoked {args.name}: its token or API key no longer works." +
              (" Its data is deleted." if args.purge else " Its data stays until you run this with --purge."))
    elif args.hub_command == "uninstall":
        if args.cancel:
            done = hub.cancel_uninstall(conn, args.name)
            print(f"Cancelled the uninstall of {args.name}." if done else f"{args.name} has no uninstall waiting.")
            return 0 if done else 1
        if not hub.request_uninstall(conn, args.name, time.time()):
            print(f"No collector host named {args.name}.", file=sys.stderr)
            return 1
        print(f"Asked {args.name} to uninstall its collector with its next upload. When it says it started, the hub "
              f"removes it and deletes its data. Cancel: daemonsight hub uninstall {args.name} --cancel")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="daemonsight", description="DaemonSight server monitor")
    parser.add_argument("-c", "--config", help="config file (default /etc/daemonsight/config.toml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"daemonsight {full_version()}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("collector", help="run the collector (root)")
    sub.add_parser("web", help="run the web UI")
    rd = sub.add_parser("docker-reader", help="serve a summary of Docker's images, volumes and build cache to the hub")
    rd.add_argument("--token-file", required=True, help="file holding the bearer token the hub sends (mode 0600)")
    rd.add_argument("--socket", default="/var/run/docker.sock", help="Docker's unix socket")
    rd.add_argument("--listen", default="0.0.0.0", help="address to listen on (inside the container)")
    rd.add_argument("--port", type=int, default=8467)
    sub.add_parser("status", help="show what this host's uploads to the hub are doing")
    un = sub.add_parser("uninstall", help="remove DaemonSight from this host (root)")
    un.add_argument("--yes", action="store_true", help="really remove it; without this, only list what would go")
    un.add_argument("--hub-request", action="store_true", help=argparse.SUPPRESS)  # daemonsight-uninstall.service
    sub.add_parser("set-password", help="set the web login password")
    sub.add_parser("init", help="create the session secret and database")
    once = sub.add_parser("collect-once", help="run sources once and print JSON")
    once.add_argument("source", nargs="*", help="limit to these sources")
    tok = sub.add_parser("set-upload-token", help="save the token this host uses to upload to a hub (root)")
    tok.add_argument("--url", help="also set [upload] url in the config, e.g. https://hub.example.com/api/v1/ingest")
    bk = sub.add_parser("backup", help="write a backup of the database, config and secrets")
    bk.add_argument("--to", help="folder for the backup (default: [backup] dir)")
    rs = sub.add_parser("restore", help="restore a backup (stop the collector or hub first)")
    rs.add_argument("archive")
    rs.add_argument("--db-only", action="store_true", help="restore only the database")
    hubp = sub.add_parser("hub", help="manage the hosts that upload to this hub")
    hubsub = hubp.add_subparsers(dest="hub_command", required=True)
    add = hubsub.add_parser("add-host", help="create a host and print its token")
    add.add_argument("name")
    add.add_argument("--quiet", action="store_true", help="print only the token, for piping to set-upload-token")
    hubsub.add_parser("list", help="list hosts and when each last uploaded")
    upd = hubsub.add_parser("update", help="ask a host, or every host that's behind, to install the hub's version")
    upd.add_argument("name", nargs="?")
    upd.add_argument("--all", action="store_true")
    rev = hubsub.add_parser("revoke", help="stop accepting a host's uploads")
    rev.add_argument("name")
    rev.add_argument("--purge", action="store_true", help="also delete the host's data")
    uni = hubsub.add_parser("uninstall", help="ask a host to uninstall its collector; the hub then removes the host")
    uni.add_argument("name")
    uni.add_argument("--cancel", action="store_true", help="withdraw the request")
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    try:
        cfg = config.load(args.config)
    except (ValueError, OSError):
        if args.command != "uninstall":
            raise
        cfg = None  # a host whose config no longer loads can still be uninstalled by hand
    if cfg is not None and cfg.log_file and args.command in ("web", "collector"):
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(cfg.log_file, maxBytes=5 * 2**20, backupCount=3)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        from . import shodan
        shodan.filter_handler(fh)
        logging.getLogger().addHandler(fh)
    handler = {
        "collector": cmd_collector, "web": cmd_web, "set-password": cmd_set_password,
        "init": cmd_init, "collect-once": cmd_collect_once,
        "set-upload-token": cmd_set_upload_token, "hub": cmd_hub,
        "docker-reader": cmd_docker_reader, "backup": cmd_backup, "restore": cmd_restore,
        "status": cmd_status, "uninstall": cmd_uninstall,
    }[args.command]
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
