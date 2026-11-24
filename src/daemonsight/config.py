"""Configuration loaded from a TOML file.

Lookup order: the path given on the command line, $DAEMONSIGHT_CONFIG,
then /etc/daemonsight/config.toml. A missing file means all defaults.
"""

from __future__ import annotations

import os
import logging
import re
import socket
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import ClassVar

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
    interval_packages: int = 3600
    docker_socket: str = "/var/run/docker.sock"
    # Caddy's admin address as Caddy writes it: "localhost:2019" or
    # "unix//run/caddy/admin.sock".
    caddy_admin: str = "localhost:2019"
    fail2ban_socket: str = "/var/run/fail2ban/fail2ban.sock"
    nft: str = "nft"
    service_patterns: list[str] = field(default_factory=lambda: ["*.service"])
    log_tail_lines: int = 100
    # Old name for [retention] metrics_hours; still read when set.
    metrics_retention_hours: int | None = None
    # Let the hub uninstall DaemonSight from this host when an admin asks it to (Remove from hub, "Uninstall the
    # collector first"). false locks the host against it: the collector answers "refused". The hub can't change this.
    allow_remote_uninstall: bool = True


@dataclass
class ExposureConfig:
    # Ports meant to be reachable from the internet. Anything else listening
    # on a public address is a finding.
    expected_public: list[str] = field(default_factory=lambda: ["22/tcp", "80/tcp", "443/tcp", "443/udp"])
    # Ports a provider's firewall in front of this host lets in (a cloud
    # firewall policy, for example). Empty means no such firewall is known.
    # Ports outside it can't be reached from the internet whatever the host does.
    upstream_allow: list[str] = field(default_factory=list)
    # Extra jail -> systemd units links, for jails DaemonSight can't match by
    # name, journal match or log path. Example: {"nginx-http-auth" = ["nginx.service"]}
    jail_covers: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class UploadConfig:
    """On a collector: send everything it collects to a hub."""
    # The hub's upload address, e.g. "https://hub.example.com/api/v1/ingest".
    # Empty means this host keeps its data to itself.
    url: str = ""
    # The host's token from `daemonsight hub add-host` (root-only file).
    token_file: str = "/etc/daemonsight/hub.token"
    # Seconds between uploads.
    interval: int = 30
    # Install updates the hub asks for (a commit on main or a release tag of
    # the GitHub repo, checked on this host). The hub can't change this.
    remote_update: bool = True


@dataclass
class HubConfig:
    """On the hub: receive uploads from collectors."""
    enabled: bool = False
    # Largest upload accepted, before and after gzip.
    max_upload_mb: int = 8
    max_unpacked_mb: int = 48


@dataclass
class CveConfig:
    """On the hub: download public vulnerability data and match each host's
    installed packages against it. Needs outbound HTTPS to the Debian
    security tracker, FIRST's EPSS files and CISA's KEV list."""
    enabled: bool = True
    # Hours between checks of each feed. Each check sends If-None-Match /
    # If-Modified-Since, so an unchanged file costs one small request.
    refresh_hours: float = 24
    # Where CISA has not rated a CVE's "Automatable" (its SSVC decision point), DaemonSight estimates it: yes when the CVE's
    # EPSS probability is at or above this. FIRST (https://www.first.org/epss/using-epss): the threshold is "a very
    # localized effort"; for the effort of patching every CVSS Critical, the "EPSS equivalent effort level is approximately
    # the 90th percentile (>=0.04)". Replaces the old `epss_high`, which a config file may still name (it is read as this).
    epss_automatable: float = 0.04
    # Once a day, fetch the prioritisation table the DaemonSight repository publishes (cve/priority_fetch.py), so a directive that
    # replaces BOD 26-04 reaches this hub without a release. Data only, checked strictly. Off: only the bundled table is used.
    priority_updates: bool = True


@dataclass
class OutsideConfig:
    """On the hub: ask Shodan what the internet sees of each host's public
    addresses. Off by default: InternetDB is free for non-commercial use only
    ("If you're using the InternetDB API to make money then you need an
    enterprise license", https://internetdb.shodan.io/). Only the IP address is
    sent (the Shodan API source also sends your key)."""
    enabled: bool = False
    # Extra addresses to check, besides every host's own public addresses.
    # "203.0.113.9" is checked for the host that reports it; "203.0.113.9=vps"
    # attaches it to the host named vps, for an address no collector reports
    # (a router's, say). Private addresses are refused.
    addresses: list[str] = field(default_factory=list)
    # Hours between checks of each address. InternetDB updates weekly.
    refresh_hours: float = 24
    # Where the addresses come from: "internetdb" (free for non-commercial use, no key) or "shodan" (Shodan's
    # REST API with your own key, for use its plan allows, commercial included). The key is never in this file:
    # it is saved from the Settings page into key_file.
    source: str = "internetdb"
    # The file holding the Shodan API key (one line, mode 0600). Blank: shodan.key in data_dir.
    key_file: str = ""


@dataclass
class RemoteConfig:
    """On the hub: read systems that have no collector (Unraid) over their
    own API. The systems are added in the web UI (Hosts, Add a system); this
    only switches the polling on or off."""
    enabled: bool = True


@dataclass
class RetentionConfig:
    """How long the database keeps history: on a host its collector prunes,
    on a hub the hub prunes every host's rows. 0 keeps for good."""
    metrics_hours: int = 48          # chart points: about 1 a second per host
    events_days: int = 0             # "Recent changes"
    resolved_findings_days: int = 0  # findings that have cleared


@dataclass
class BackupConfig:
    """Scheduled backups, made by the collector on a host and by the hub."""
    dir: str = ""                    # default: <data_dir>/backups
    # 0 turns scheduled backups off. Unset: every 24 hours, except on a host
    # that uploads to a hub, whose history the hub's backups already hold.
    interval_hours: int | None = None
    keep: int = 7


@dataclass
class Thresholds:
    disk_percent: float = 90.0
    memory_percent: float = 90.0
    memory_minutes: int = 15


@dataclass
class Config:
    host_id: str = field(default_factory=socket.gethostname)
    # "server" (always on) or "workstation" (a laptop or desktop that is often
    # off or asleep). A workstation that stops uploading is "Offline", a low
    # finding, not a high "Not reporting". Anything else counts as "server".
    role: str = "server"
    # Set by the hub for a system it reads over an API ("unraid"); not a config key.
    kind: str = ""
    data_dir: str = "/var/lib/daemonsight"
    # Also write the collector's and web UI's log lines to this file, kept
    # to four files of 5 MB. On a host the journal already has them; the hub
    # container sets /data/daemonsight.log so they outlive the container.
    log_file: str = ""
    web: WebConfig = field(default_factory=WebConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    thresholds: Thresholds = field(default_factory=Thresholds)
    exposure: ExposureConfig = field(default_factory=ExposureConfig)
    upload: UploadConfig = field(default_factory=UploadConfig)
    hub: HubConfig = field(default_factory=HubConfig)
    cve: CveConfig = field(default_factory=CveConfig)
    outside: OutsideConfig = field(default_factory=OutsideConfig)
    remote: RemoteConfig = field(default_factory=RemoteConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    # Web UIs to link from each source's panel, e.g. {caddy = "https://...",
    # fail2ban = "..."}; later also opnsense, unraid and ionos.
    links: dict[str, str] = field(default_factory=dict)
    # Dotted names of the keys the config file set ("outside.enabled"), so the
    # Settings page can tell "Config file" from "Default". Not a config key.
    file_keys: ClassVar[frozenset[str]] = frozenset()

    @property
    def metrics_hours(self) -> int:
        old = self.collector.metrics_retention_hours
        return old if old is not None else self.retention.metrics_hours

    @property
    def backup_interval_hours(self) -> int:
        if self.backup.interval_hours is not None:
            return self.backup.interval_hours
        return 0 if self.upload.url and not self.hub.enabled else 24

    @property
    def backup_dir(self) -> Path:
        return Path(self.backup.dir) if self.backup.dir else Path(self.data_dir) / "backups"

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "state.db"

    @property
    def cve_db_path(self) -> Path:
        return Path(self.data_dir) / "cve.db"

    @property
    def shodan_key_path(self) -> Path:
        return Path(self.outside.key_file) if self.outside.key_file else Path(self.data_dir) / "shodan.key"


def _apply(obj, values: dict, section: str, seen: set[str] | None = None) -> None:
    known = {f.name: f for f in fields(obj)}
    for key, value in values.items():
        if key not in known:
            raise ValueError(f"unknown setting {section}{key}")
        current = getattr(obj, key)
        if hasattr(current, "__dataclass_fields__"):
            if not isinstance(value, dict):
                raise ValueError(f"[{section}{key}] must be a table")
            _apply(current, value, f"{section}{key}.", seen)
        else:
            setattr(obj, key, value)
            if seen is not None:
                seen.add(f"{section}{key}")


ROLES = ("server", "workstation")


def valid_role(value, warn: bool = False) -> str:
    """The role if it is a known one, else "server"."""
    role = value.strip().lower() if isinstance(value, str) else value
    if role in ROLES:
        return role
    if warn:
        logging.getLogger("daemonsight").warning(
            "unknown role %r in the config; using \"server\" (known: %s)", value, ", ".join(ROLES))
    return "server"


def _migrate(values: dict) -> dict:
    """Old names a config file may still use. `[cve] epss_high` (the EPSS score that made a finding High) is now
    `epss_automatable` (the EPSS probability above which a CVE CISA has not rated is estimated as automatable): both are an
    EPSS probability above which a CVE counts as likely to be exploited, so the old value carries over, unless the file
    also sets the new name."""
    cve = values.get("cve")
    if isinstance(cve, dict) and "epss_high" in cve:
        cve = dict(cve)
        old = cve.pop("epss_high")
        if "epss_automatable" not in cve:
            cve["epss_automatable"] = old
        logging.getLogger("daemonsight").warning(
            "[cve] epss_high is renamed epss_automatable (it now sets when a CVE CISA has not rated counts as automatable); "
            "the value %r is used for it", old)
        values = {**values, "cve": cve}
    return values


def config_path(path: str | os.PathLike | None = None) -> Path:
    return Path(path or os.environ.get("DAEMONSIGHT_CONFIG") or DEFAULT_PATH)


def load(path: str | os.PathLike | None = None) -> Config:
    cfg = Config()
    candidate = config_path(path)
    seen: set[str] = set()
    if candidate.exists():
        with candidate.open("rb") as fh:
            _apply(cfg, _migrate(tomllib.load(fh)), "", seen)
    elif path:
        raise FileNotFoundError(candidate)
    if "collector.metrics_retention_hours" in seen:
        seen.add("retention.metrics_hours")   # the old name sets the same thing
    cfg.file_keys = frozenset(seen)
    cfg.role = valid_role(cfg.role, warn=True)
    if cfg.outside.source not in ("internetdb", "shodan"):
        logging.getLogger("daemonsight").warning(
            "unknown [outside] source %r; using \"internetdb\" (known: internetdb, shodan)", cfg.outside.source)
        cfg.outside.source = "internetdb"
    return cfg


_SECTION = re.compile(r"^\s*\[([^\[\]]+)\]\s*(#.*)?$")
_URL_LINE = re.compile(r"^\s*#?\s*url\s*=")


def set_upload_url(path: str | os.PathLike, url: str) -> None:
    """Set url under [upload] in a config file, keeping its comments, owner
    and mode. Replaces an existing (or commented-out) url line in [upload],
    or adds the section at the end."""
    if not re.fullmatch(r"[\x21-\x7e]+", url) or '"' in url or "\\" in url:
        raise ValueError(f"not a usable URL: {url!r}")
    path = Path(path)
    lines = path.read_text().splitlines() if path.exists() else []
    new = f'url = "{url}"'
    start = next((i for i, l in enumerate(lines)
                  if (m := _SECTION.match(l)) and m.group(1).strip() == "upload"), None)
    if start is None:
        lines += ["", "[upload]", new]
    else:
        end = next((i for i in range(start + 1, len(lines)) if _SECTION.match(lines[i])), len(lines))
        hit = next((i for i in range(start + 1, end) if _URL_LINE.match(lines[i])), None)
        if hit is None:
            lines.insert(start + 1, new)
        else:
            lines[hit] = new
    text = "\n".join(lines) + "\n"
    tomllib.loads(text)  # never leave a file that won't load
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    if path.exists():
        st = path.stat()
        os.chmod(tmp, st.st_mode & 0o777)
        if os.geteuid() == 0:
            os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)
