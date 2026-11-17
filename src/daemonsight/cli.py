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
import sys
import time
from pathlib import Path

from . import config, db, full_version

GROUP = "daemonsight"


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")


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
    from .collector.runner import Collector
    os.umask(0o027)
    asyncio.run(Collector(cfg).run())
    return 0


def cmd_web(args, cfg) -> int:
    import uvicorn
    from .web.app import create_app
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.web.listen, port=cfg.web.port, proxy_headers=True,
                forwarded_allow_ips=",".join(cfg.web.trusted_proxies), server_header=False,
                access_log=False)
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
    conn = db.connect_writer(cfg.db_path)
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
    token = getpass.getpass("Token from the hub: ").strip()
    if len(token) < 32:
        print("That doesn't look like a hub token (run 'daemonsight hub add-host' on the hub).", file=sys.stderr)
        return 1
    _write_private(Path(cfg.upload.token_file), token, group=False)
    print(f"Saved to {cfg.upload.token_file}.")
    if not cfg.upload.url:
        print("Set url under [upload] in the config, then: sudo systemctl restart daemonsight-collector")
    else:
        print("Restart the collector: sudo systemctl restart daemonsight-collector")
    return 0


def cmd_hub(args, cfg) -> int:
    from . import hub
    if not cfg.hub.enabled:
        print("This install isn't a hub. Set enabled = true under [hub] first.", file=sys.stderr)
        return 1
    conn = db.connect_writer(cfg.db_path)
    if args.hub_command == "add-host":
        try:
            token = hub.add_host(conn, args.name)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(f"Token for {args.name}. It is shown once; the hub keeps only its hash.\n")
        print(f"  {token}\n")
        print(f"On {args.name}, with DaemonSight installed:")
        print("  1. sudo daemonsight set-upload-token        (paste the token)")
        print("  2. In /etc/daemonsight/config.toml:")
        print("       [upload]")
        print('       url = "https://<this hub>/api/v1/ingest"')
        print(f'     and make sure host_id is "{args.name}".')
        print("  3. sudo systemctl restart daemonsight-collector")
    elif args.hub_command == "list":
        rows = conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
        if not rows:
            print("No hosts. Add one: daemonsight hub add-host <name>")
        for h in rows:
            seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["last_seen"])) if h["last_seen"] else "never"
            print(f"{h['id']:<24} last upload {seen:<20} {h['address'] or '':<40} {h['version'] or ''}")
    elif args.hub_command == "revoke":
        if not hub.revoke_host(conn, args.name, purge=args.purge):
            print(f"No host named {args.name}.", file=sys.stderr)
            return 1
        print(f"Revoked {args.name}: its token no longer works." +
              (" Its data is deleted." if args.purge else " Its data stays until you run this with --purge."))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="daemonsight", description="DaemonSight server monitor")
    parser.add_argument("-c", "--config", help="config file (default /etc/daemonsight/config.toml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"daemonsight {full_version()}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("collector", help="run the collector (root)")
    sub.add_parser("web", help="run the web UI")
    sub.add_parser("set-password", help="set the web login password")
    sub.add_parser("init", help="create the session secret and database")
    once = sub.add_parser("collect-once", help="run sources once and print JSON")
    once.add_argument("source", nargs="*", help="limit to these sources")
    sub.add_parser("set-upload-token", help="save the token this host uses to upload to a hub (root)")
    hubp = sub.add_parser("hub", help="manage the hosts that upload to this hub")
    hubsub = hubp.add_subparsers(dest="hub_command", required=True)
    add = hubsub.add_parser("add-host", help="create a host and print its token")
    add.add_argument("name")
    hubsub.add_parser("list", help="list hosts and when each last uploaded")
    rev = hubsub.add_parser("revoke", help="stop accepting a host's uploads")
    rev.add_argument("name")
    rev.add_argument("--purge", action="store_true", help="also delete the host's data")
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    cfg = config.load(args.config)
    handler = {
        "collector": cmd_collector, "web": cmd_web, "set-password": cmd_set_password,
        "init": cmd_init, "collect-once": cmd_collect_once,
        "set-upload-token": cmd_set_upload_token, "hub": cmd_hub,
    }[args.command]
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
