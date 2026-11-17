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
from pathlib import Path

from . import __version__, config, db

GROUP = "daemonsight"


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")


def _group_id() -> int | None:
    try:
        return grp.getgrnam(GROUP).gr_gid
    except KeyError:
        return None


def _write_private(path: Path, text: str) -> None:
    """Write a file readable by root and the daemonsight group only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as fh:
        fh.write(text + "\n")
    gid = _group_id()
    if gid is not None and os.geteuid() == 0:
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
    print(f"Saved to {cfg.web.password_file}. Restart daemonsight-web if it is running.")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="daemonsight", description="DaemonSight server monitor")
    parser.add_argument("-c", "--config", help="config file (default /etc/daemonsight/config.toml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"daemonsight {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("collector", help="run the collector (root)")
    sub.add_parser("web", help="run the web UI")
    sub.add_parser("set-password", help="set the web login password")
    sub.add_parser("init", help="create the session secret and database")
    once = sub.add_parser("collect-once", help="run sources once and print JSON")
    once.add_argument("source", nargs="*", help="limit to these sources")
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    cfg = config.load(args.config)
    handler = {
        "collector": cmd_collector, "web": cmd_web, "set-password": cmd_set_password,
        "init": cmd_init, "collect-once": cmd_collect_once,
    }[args.command]
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
