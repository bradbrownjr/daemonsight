"""Configuration loaded from a TOML file.

Lookup order: the path given on the command line, $DAEMONSIGHT_CONFIG,
then /etc/daemonsight/config.toml. A missing file means all defaults.
"""

from __future__ import annotations

import os
import socket
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

DEFAULT_PATH = Path("/etc/daemonsight/config.toml")


@dataclass
class WebConfig:
    listen: str = "127.0.0.1"
    port: int = 8466
    # Proxies whose X-Forwarded-For header is trusted (Caddy on the same host).
    trusted_proxies: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    # Set true when the UI is only reached over HTTPS (for example through Caddy).
    secure_cookies: bool = False
    session_hours: int = 12
    password_file: str = "/etc/daemonsight/password"
    secret_file: str = "/etc/daemonsight/secret"


@dataclass
class CollectorConfig:
    interval_system: int = 15
    interval_systemd: int = 30
    interval_ports: int = 60
    interval_docker: int = 30
    interval_caddy: int = 60
    interval_fail2ban: int = 60
    interval_firewall: int = 300
    docker_socket: str = "/var/run/docker.sock"
    # Caddy's admin address as Caddy writes it: "localhost:2019" or
    # "unix//run/caddy/admin.sock".
    caddy_admin: str = "localhost:2019"
    fail2ban_socket: str = "/var/run/fail2ban/fail2ban.sock"
    nft: str = "nft"
    service_patterns: list[str] = field(default_factory=lambda: ["*.service"])
    log_tail_lines: int = 100
    metrics_retention_hours: int = 48


@dataclass
class ExposureConfig:
    # Ports meant to be reachable from the internet. Anything else listening
    # on a public address is a finding.
    expected_public: list[str] = field(default_factory=lambda: ["22/tcp", "80/tcp", "443/tcp", "443/udp"])
    # Extra jail -> systemd units links, for jails DaemonSight can't match by
    # name, journal match or log path. Example: {"nginx-http-auth" = ["nginx.service"]}
    jail_covers: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Thresholds:
    disk_percent: float = 90.0
    memory_percent: float = 90.0
    memory_minutes: int = 15


@dataclass
class Config:
    host_id: str = field(default_factory=socket.gethostname)
    data_dir: str = "/var/lib/daemonsight"
    web: WebConfig = field(default_factory=WebConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    thresholds: Thresholds = field(default_factory=Thresholds)
    exposure: ExposureConfig = field(default_factory=ExposureConfig)

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "state.db"


def _apply(obj, values: dict, section: str) -> None:
    known = {f.name: f for f in fields(obj)}
    for key, value in values.items():
        if key not in known:
            raise ValueError(f"unknown setting {section}{key}")
        current = getattr(obj, key)
        if hasattr(current, "__dataclass_fields__"):
            if not isinstance(value, dict):
                raise ValueError(f"[{section}{key}] must be a table")
            _apply(current, value, f"{section}{key}.")
        else:
            setattr(obj, key, value)


def load(path: str | os.PathLike | None = None) -> Config:
    cfg = Config()
    candidate = Path(path or os.environ.get("DAEMONSIGHT_CONFIG") or DEFAULT_PATH)
    if candidate.exists():
        with candidate.open("rb") as fh:
            _apply(cfg, tomllib.load(fh), "")
    elif path:
        raise FileNotFoundError(candidate)
    return cfg
