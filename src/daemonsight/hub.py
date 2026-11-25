"""The hub: host tokens, checking uploads, storing them, and noticing hosts
that stop reporting. See docs/DESIGN.md "Hub" and SECURITY.md "The hub".

Everything a collector sends is untrusted. The models below set the shape
and size of every field, internal links must be paths on this site, and a
collector can't open or close the hub's own `host.*` findings.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import time
import unicodedata
import zlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import db, full_version
from .findings import Finding

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
log = logging.getLogger("daemonsight.hub")
# Rules the hub opens and closes itself; a collector can't send these, and an
# upload never closes them: host.* (silence, clock), cve.* (CVE matching),
# remote.* (a system the hub reads over its API is unreachable), unraid.*
# opnsense.* and unifi.* (what the hub reads from an Unraid server, an OPNsense
# firewall or a UniFi controller), docker.* (an Unraid server's Docker reader), crowdsec.* (bans on a firewall's CrowdSec) and outside.*
# (what Shodan's InternetDB says the internet sees).
HUB_RULES = ("host.", "cve.", "remote.", "unraid.", "opnsense.", "unifi.", "outside.", "docker.", "crowdsec.")
# The package list is not a snapshot source: see InventoryIn. Nor is the container images' package lists: see DockerImagesIn.
INVENTORY = "inventory"
DOCKER_IMAGES = "docker_images"
SOURCES = ("system", "systemd", "ports", "docker", "caddy", "fail2ban", "firewall", "packages")
SILENT_AFTER_INTERVALS = 3
SKEW_SECONDS = 300

# Top-level fields each source's data must have, with their types. Deeper
# fields are left to the pages, which escape all text.
SOURCE_SHAPE: dict[str, dict[str, type]] = {
    "system": {"cpu": dict, "memory": dict},
    "systemd": {"units": list},
    "ports": {"listeners": list},
    "docker": {"containers": list},
    "caddy": {"sites": list, "servers": list},
    "fail2ban": {"jails": list},
    "firewall": {"input": list, "forwards": list},
    "packages": {"updates": list},
}

Severity = Literal["critical", "high", "medium", "low", "info"]
Text = Annotated[str, Field(max_length=4000)]
Short = Annotated[str, Field(max_length=300)]


class UploadRefused(Exception):
    """An upload the hub won't store. `status` is the HTTP status to send."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _site_path(value: str | None) -> str | None:
    """A link from a collector must be a path on this site, or nothing."""
    if value is None:
        return None
    if len(value) > 300 or not value.startswith("/") or value.startswith("//") or "\\" in value \
            or any(ord(ch) < 32 for ch in value):
        raise ValueError("link must be a path on this site")
    return value


class _Model(BaseModel):
    # NaN and Infinity are valid in Python's JSON but not in the database.
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class SnapshotIn(_Model):
    source: Literal[SOURCES]  # type: ignore[valid-type]
    taken_at: float
    ok: bool
    error: Text | None = None
    data: dict | None = None


class EventIn(_Model):
    id: int = Field(ge=1)
    ts: float
    kind: Annotated[str, Field(pattern=r"^[a-z0-9_]{1,40}$")]
    severity: Severity | None = None
    title: Short
    detail: Text | None = None
    link: str | None = None

    @field_validator("link")
    @classmethod
    def _link(cls, v: str | None) -> str | None:
        return _site_path(v)


class FindingIn(_Model):
    rule: Annotated[str, Field(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)+$", max_length=60)]
    key: Short
    severity: Severity
    title: Short
    detail: Text
    link: str | None = None
    # Both optional: collectors from before they existed send neither.
    fix: Annotated[str, Field(max_length=20_000)] | None = None
    basis: Short | None = None

    @field_validator("link")
    @classmethod
    def _link(cls, v: str | None) -> str | None:
        return _site_path(v)

    @field_validator("fix")
    @classmethod
    def _fix_is_plain_text(cls, v: str | None) -> str | None:
        """A fix is shown to be copied into a terminal. Newlines separate
        commands; other control and format characters (escape sequences,
        right-to-left overrides) could make the text show as something other
        than what pastes. Such a fix is dropped, not refused: refusing would
        reject the host's whole upload over one suggestion."""
        if v is None:
            return None
        if len(v) > 2000 or any(ch != "\n" and unicodedata.category(ch) in ("Cc", "Cf") for ch in v):
            return None
        return v.strip() or None

    @field_validator("rule")
    @classmethod
    def _not_hub_rule(cls, v: str) -> str:
        if v.startswith(HUB_RULES):
            raise ValueError("host.*, cve.*, remote.*, unraid.*, opnsense.*, unifi.*, docker.*, crowdsec.* and outside.* findings belong to the hub")
        return v


class ExposureIn(_Model):
    expected_public: list[Annotated[str, Field(max_length=20)]] = Field(default_factory=list, max_length=500)
    upstream_allow: list[Annotated[str, Field(max_length=20)]] = Field(default_factory=list, max_length=500)
    jail_covers: dict[Short, list[Short]] = Field(default_factory=dict)


class SettingsIn(_Model):
    """The collector's own settings the pages need: which ports it expects
    to be public, its ephemeral port range, and how often it reads."""
    exposure: ExposureIn = Field(default_factory=ExposureIn)
    links: dict[Annotated[str, Field(max_length=40)], Short] = Field(default_factory=dict)
    eph: tuple[int, int] = (32768, 60999)
    interval_system: int = Field(default=10, ge=1, le=86400)
    # "server" or "workstation". Older collectors send nothing: server.
    role: Literal["server", "workstation"] = "server"


PkgName = Annotated[str, Field(max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")]
PkgVersion = Annotated[str, Field(max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")]
CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,10}$", max_length=24)]


class AdvisoryIn(BaseModel):
    """One pending Fedora security advisory: its id, severity, the CVEs it
    names and the installed packages it would update."""
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    id: Annotated[str, Field(max_length=60, pattern=r"^[A-Za-z0-9._:-]+$")]
    severity: Annotated[str, Field(max_length=20)] = ""
    cves: list[CveId] = Field(default_factory=list, max_length=200)
    packages: list[PkgName] = Field(default_factory=list, max_length=100)


class InventoryIn(BaseModel):
    """What the host has installed, for CVE matching on the hub. Unlike the
    other models this one ignores unknown fields, so a newer collector can
    add to it. And `Upload.inventory` drops an inventory it can't read rather
    than refuse the whole upload; the earlier "packages" snapshot source
    broke an old hub with a 422, and that must not happen again."""
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    v: Literal[1]
    taken_at: float
    backend: Literal["apt", "dnf"]
    hash: Annotated[str, Field(max_length=64, pattern=r"^[0-9a-f]*$")] = ""
    os_id: Annotated[str, Field(max_length=40)] | None = None
    version_id: Annotated[str, Field(max_length=40)] | None = None
    codename: Annotated[str, Field(pattern=r"^[a-z0-9._-]{1,40}$")] | None = None
    # Ubuntu: the Ubuntu Pro ESM services the host has on ("infra", "apps"); None when the collector did not look
    esm: list[Literal["infra", "apps"]] | None = Field(default=None, max_length=2)
    # apt: [source package, source version, [binary packages]]
    sources: list[tuple[PkgName, PkgVersion, list[PkgName]]] = Field(default_factory=list, max_length=20_000)
    # dnf: pending security advisories
    advisories: list[AdvisoryIn] = Field(default_factory=list, max_length=2_000)


PkgOpt = Annotated[str, Field(max_length=100, pattern=r"^[^\x00-\x1f\x7f]*$")]
Printable = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]*$")]
ImageId = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
MAX_IMAGE_PACKAGES = 4_000           # per image, the cap the Docker reader and the collector apply
CARRY_ERRORS = ("not read yet", "not read: stopped")    # what the collector says of an image it has no read of (as the Docker reader does)
MAX_IMAGE_PACKAGES_TOTAL = 40_000    # across one host's upload, the same as the Docker reader's summary


class ImageOsIn(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    id: Annotated[str, Field(max_length=40, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    like: list[Annotated[str, Field(max_length=40, pattern=r"^[^\x00-\x1f\x7f]*$")]] = Field(default_factory=list, max_length=6)
    version_id: Annotated[str, Field(max_length=40, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    codename: Annotated[str, Field(max_length=40, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    pretty: Annotated[str, Field(max_length=80, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""


class ImageEntryIn(BaseModel):
    """One image's OS and packages, as the collector read them. `packages` is empty with a `hash` and a `count` when the hub is
    meant to have the list already (merge_docker_images)."""
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    image_id: ImageId
    container: Annotated[str, Field(max_length=80, pattern=r"^[^\x00-\x1f\x7f]*$")] | None = None
    read_at: int | None = Field(default=None, ge=0, le=10 ** 11)
    os: ImageOsIn | None = None
    manager: Literal["dpkg", "apk"] | None = None
    count: int = Field(default=0, ge=0, le=10 ** 6)
    hash: Annotated[str, Field(max_length=64, pattern=r"^[0-9a-f]*$")] = ""
    # [name, source package, version, source version]; the source fields are empty when they equal the package's own
    packages: list[tuple[PkgName, PkgOpt, PkgVersion, PkgOpt]] = Field(default_factory=list, max_length=MAX_IMAGE_PACKAGES)
    error: Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")] | None = None


class ContainerRefIn(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    name: Annotated[str, Field(max_length=80, pattern=r"^[^\x00-\x1f\x7f]*$")]
    image: Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    image_id: Annotated[str, Field(max_length=80, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    state: Annotated[str, Field(max_length=20, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""


class ImageRefIn(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    id: ImageId
    tags: list[Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")]] = Field(default_factory=list, max_length=40)
    digests: list[Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")]] = Field(default_factory=list, max_length=40)


class EngineIn(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    version: Annotated[str, Field(max_length=40, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    api: Annotated[str, Field(max_length=10, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""


class DockerImagesIn(BaseModel):
    """The OS and package list of each container image a collector host runs, for CVE matching (docs/DESIGN.md, "Collector hosts:
    image CVEs"). Like InventoryIn it ignores unknown fields and `Upload.docker_images` drops what it can't read instead of
    refusing the upload. `available` false says why the collector sends none (no Docker, or turned off)."""
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    v: Literal[1]
    taken_at: float
    available: bool = True
    reason: Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    engine: EngineIn = Field(default_factory=EngineIn)
    containers: list[ContainerRefIn] = Field(default_factory=list, max_length=2_000)
    images: list[ImageRefIn] = Field(default_factory=list, max_length=3_000)
    image_packages: list[ImageEntryIn] = Field(default_factory=list, max_length=1_000)

    @field_validator("image_packages")
    @classmethod
    def _within_the_total(cls, entries: list[ImageEntryIn]) -> list[ImageEntryIn]:
        if len({e.image_id for e in entries}) != len(entries):
            raise ValueError("an image sent twice")
        if sum(len(e.packages) for e in entries) > MAX_IMAGE_PACKAGES_TOTAL:
            raise ValueError("more packages than one host may send")
        return entries


UPDATE_STATES = ("running", "done", "failed", "refused", "rolled_back")


class UpdateStateIn(_Model):
    """The host's last update attempt, from daemonsight-update."""
    ref: Annotated[str, Field(pattern=r"^[0-9a-f]{7,40}$")]
    status: Literal[UPDATE_STATES]  # type: ignore[valid-type]
    at: float
    detail: Annotated[str, Field(max_length=300)] = ""

    @field_validator("detail")
    @classmethod
    def _printable(cls, v: str) -> str:
        if any(ord(ch) < 32 for ch in v):
            raise ValueError("control characters in detail")
        return v


UNINSTALL_ACKS = ("started", "refused", "failed")


class Upload(_Model):
    # Unknown top-level fields are ignored, so a host updated ahead of its
    # hub can still report. Everything inside stays strict.
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)

    v: Literal[1]
    host: Annotated[str, Field(pattern=HOST_RE.pattern)]
    seq: int = Field(ge=1)
    sent_at: float
    version: Annotated[str, Field(max_length=80)]
    max_interval: float = Field(ge=1, le=86400)
    settings: SettingsIn = Field(default_factory=SettingsIn)
    snapshots: list[SnapshotIn] = Field(default_factory=list, max_length=len(SOURCES))
    metrics: list[tuple[float, Annotated[str, Field(max_length=120)], float]] = \
        Field(default_factory=list, max_length=50_000)
    events: list[EventIn] = Field(default_factory=list, max_length=2_000)
    findings: list[FindingIn] = Field(default_factory=list, max_length=2_000)
    remote_update: bool | None = None
    update: UpdateStateIn | None = None
    inventory: InventoryIn | None = None
    docker_images: DockerImagesIn | None = None
    # Seconds between this host's uploads. A top-level field, not in `settings` (which is strict), so an older hub ignores it.
    upload_interval: float | None = Field(default=None, ge=1, le=86400)
    # The collector's answer to the hub's `uninstall: true`; see "Uninstall from the hub" below.
    uninstall: Literal[UNINSTALL_ACKS] | None = None  # type: ignore[valid-type]
    uninstall_detail: Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")] | None = None

    @field_validator("inventory", mode="wrap")
    @classmethod
    def _inventory_optional(cls, v, handler):
        """A package list this hub can't read is dropped, not a reason to refuse the upload."""
        try:
            return handler(v)
        except ValidationError as exc:
            log.warning("Ignoring an unreadable inventory: %s", exc.errors()[0]["msg"])
            return None

    @field_validator("docker_images", mode="wrap")
    @classmethod
    def _docker_images_optional(cls, v, handler):
        """Image package lists this hub can't read are dropped, not a reason to refuse the upload."""
        try:
            return handler(v)
        except ValidationError as exc:
            log.warning("Ignoring unreadable image package lists: %s", exc.errors()[0]["msg"])
            return None

    @field_validator("snapshots")
    @classmethod
    def _shapes(cls, snaps: list[SnapshotIn]) -> list[SnapshotIn]:
        seen = set()
        for s in snaps:
            if s.source in seen:
                raise ValueError(f"{s.source} sent twice")
            seen.add(s.source)
            if s.data is None or s.data.get("available") is False:
                continue
            for key, kind in SOURCE_SHAPE[s.source].items():
                if not isinstance(s.data.get(key), kind):
                    raise ValueError(f"{s.source}.{key} must be a {kind.__name__}")
                if kind is list and not all(isinstance(x, dict) for x in s.data[key]):
                    raise ValueError(f"{s.source}.{key} must hold objects")
        return snaps


# --- tokens -----------------------------------------------------------------

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def add_host(conn, host_id: str) -> str:
    """Create a host and return its token. The token is shown once; only its
    SHA-256 is stored."""
    if not HOST_RE.match(host_id):
        raise ValueError("Use letters, digits, '.', '_' and '-', starting with a letter or digit (63 at most).")
    if conn.execute("SELECT 1 FROM hosts WHERE id = ?", (host_id,)).fetchone():
        raise ValueError(f"{host_id} already exists. Revoke it first to issue a new token.")
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES (?, ?, ?)",
                 (host_id, hash_token(token), time.time()))
    return token


# Tables with a `host` column in the hub's database; removing a host deletes its rows from each.
PURGE_TABLES = ("snapshots", "metrics", "findings", "events", "accepted")


def revoke_host(conn, host_id: str, purge: bool = False, data_dir=None, cve_path=None) -> bool:
    """Stop accepting a host. A system the hub reads over its API is removed
    whole instead (its remotes row and key file too); `purge` decides whether
    its history goes."""
    from .remote import store as remote_store
    if remote_store.get(conn, host_id) is not None:
        return remote_store.remove(conn, data_dir, host_id, purge=purge)
    gone = conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,)).rowcount > 0
    if purge:
        for table in PURGE_TABLES:
            conn.execute(f"DELETE FROM {table} WHERE host = ?", (host_id,))  # noqa: S608 (fixed names)
        forget_cves(cve_path, host_id)
    return gone


def forget_cves(cve_path, host_id: str) -> int:
    """Delete a host's CVE matches (they live in cve.db, apart from the hub's database). Returns the rows
    deleted. A hub that never fetched feeds has no cve.db, and this doesn't make one."""
    if cve_path is None or not Path(cve_path).exists():
        return 0
    from .cve import store as cve_store
    cve = cve_store.connect(Path(cve_path))
    try:
        n = cve.execute("DELETE FROM match WHERE host = ?", (host_id,)).rowcount
        cve.execute("DELETE FROM matched WHERE host = ?", (host_id,))
        return n
    finally:
        cve.close()


def data_counts(conn, host_id: str, cve_path=None) -> list[tuple[str, int]]:
    """What removing a host deletes, as (label, rows): the tables `revoke_host(purge=True)` clears."""
    labels = {"snapshots": "Snapshots", "metrics": "Metric points", "findings": "Findings",
              "events": "Events", "accepted": "Accepted findings"}
    out = [(labels[t], conn.execute(f"SELECT COUNT(*) FROM {t} WHERE host = ?", (host_id,)).fetchone()[0])  # noqa: S608
           for t in PURGE_TABLES]
    n = 0
    if cve_path is not None and Path(cve_path).exists():
        from .cve import store as cve_store
        cve = cve_store.connect(Path(cve_path))
        try:
            n = cve.execute("SELECT COUNT(*) FROM match WHERE host = ?", (host_id,)).fetchone()[0]
        finally:
            cve.close()
    return out + [("CVE matches", n)]


def replace_token(conn, host_id: str) -> str | None:
    """Give a collector host a new token and return it (shown once). The old token stops working at once.
    The host's history and settings stay. None when no collector host has that name."""
    token = secrets.token_urlsafe(32)
    cur = conn.execute("UPDATE hosts SET token_hash = ? WHERE id = ? AND kind IS NULL", (hash_token(token), host_id))
    return token if cur.rowcount == 1 else None


def host_for_token(conn, token: str):
    """Look a token up by its SHA-256. The lookup's timing depends on the
    hash, which says nothing useful about the token itself."""
    if not token or len(token) > 200:
        return None
    return conn.execute("SELECT * FROM hosts WHERE token_hash = ? AND kind IS NULL", (hash_token(token),)).fetchone()


# --- reading an upload ------------------------------------------------------

def unpack(body: bytes, gzipped: bool, max_unpacked: int) -> Upload:
    """Decompress with a hard size cap (a small gzip can expand to gigabytes),
    parse, and check every field."""
    if gzipped:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            raw = d.decompress(body, max_unpacked + 1)
        except zlib.error as exc:
            raise UploadRefused(400, f"bad gzip: {exc}") from None
        if len(raw) > max_unpacked or d.unconsumed_tail:
            raise UploadRefused(413, "too large once unpacked")
        if not d.eof:
            raise UploadRefused(400, "gzip stream incomplete")
    else:
        raw = body
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise UploadRefused(400, f"not JSON: {type(exc).__name__}") from None
    try:
        return Upload.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise UploadRefused(422, f"{where}: {first['msg']}") from None


# --- storing ----------------------------------------------------------------

def merge_docker_images(new: DockerImagesIn, prev: dict | None) -> tuple[dict, list[str]]:
    """What is stored for a collector host's images: the upload, with each image's package list carried forward from the last stored
    one when the collector sent only its hash. An image id is a content hash, so the list read from it does not change; a list is
    carried only for the same image id AND the same `hash`. A hash-only entry the hub has no list for is stored as "not read yet"
    and its id is returned, so the reply can ask the collector for it (`docker_images_resend`, collector/upload.py). The shape is
    the one the Unraid Docker reader's summary has (remote/docker_storage.py), so remote/docker_images.py analyses both."""
    old = {e["image_id"]: e for e in (prev or {}).get("image_packages") or [] if e.get("manager") and e.get("packages") and e.get("hash")}
    entries, missing = [], []
    for e in new.image_packages:
        d = e.model_dump()
        d["packages"] = [list(p) for p in d["packages"]]
        d["os"] = e.os.model_dump() if e.os else None
        o = old.get(e.image_id)
        if d["manager"] and not d["packages"] and d["count"] > 0:      # the hash stands for a list the hub should have
            if o is not None and o["hash"] == e.hash:
                d["packages"] = o["packages"]
            else:
                d.update(manager=None, count=0, error="not read yet", need_list=True)
                missing.append(e.image_id)
        elif not d["manager"] and o is not None and d["error"] in CARRY_ERRORS:
            # Not read (the collector restarted, or only stopped containers use the image): the last good read of the same image id
            # stands, marked carried and with its own read time, as for the Unraid reader (remote/docker_storage._carry_packages).
            d = {**o, "carried": True}
        entries.append(d)
    data = {"generated": new.taken_at, "source": "collector", "available": new.available, "reason": new.reason or None,
            "docker": {"version": new.engine.version, "api": new.engine.api},
            "images": [{"id": i.id, "tags": i.tags, "digests": i.digests} for i in new.images],
            "containers": [c.model_dump() for c in new.containers], "image_packages": entries}
    if not new.available:                 # no Docker, or turned off: nothing to carry over
        data["image_packages"], data["images"], data["containers"] = [], [], []
    return data, missing


def docker_images_missing(conn, host: str) -> list[str]:
    """The image ids whose package list the hub is waiting for (hash-only entries it could not carry), for the upload reply."""
    snap = db.get_snapshot(conn, host, DOCKER_IMAGES)
    return [e["image_id"] for e in (snap.data or {}).get("image_packages", []) if e.get("need_list")][:100] if snap and snap.data else []


def store(conn, host_row, up: Upload, now: float, address: str | None) -> str | None:
    """Write one accepted upload. Safe to repeat: snapshots only move
    forward, metric points with the same time and name are replaced, and
    events are keyed by their collector id. Returns the commit the host
    should update to, if the hub has asked for one and it isn't done."""
    host = host_row["id"]
    conn.execute("BEGIN IMMEDIATE")
    try:
        for s in up.snapshots:
            conn.execute(
                "INSERT INTO snapshots (host, source, taken_at, ok, error, data) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (host, source) DO UPDATE SET taken_at=excluded.taken_at, ok=excluded.ok, "
                "error=excluded.error, data=excluded.data WHERE excluded.taken_at >= snapshots.taken_at",
                (host, s.source, s.taken_at, int(s.ok), s.error, json.dumps(s.data) if s.data is not None else None))
        if up.inventory is not None:
            conn.execute(
                "INSERT INTO snapshots (host, source, taken_at, ok, error, data) VALUES (?, ?, ?, 1, NULL, ?) "
                "ON CONFLICT (host, source) DO UPDATE SET taken_at=excluded.taken_at, data=excluded.data "
                "WHERE excluded.taken_at >= snapshots.taken_at",
                (host, INVENTORY, up.inventory.taken_at, up.inventory.model_dump_json(exclude_defaults=True)))
        if up.docker_images is not None:
            prev = db.get_snapshot(conn, host, DOCKER_IMAGES)
            stored, _ = merge_docker_images(up.docker_images, prev.data if prev else None)
            conn.execute(
                "INSERT INTO snapshots (host, source, taken_at, ok, error, data) VALUES (?, ?, ?, 1, NULL, ?) "
                "ON CONFLICT (host, source) DO UPDATE SET taken_at=excluded.taken_at, data=excluded.data "
                "WHERE excluded.taken_at >= snapshots.taken_at",
                (host, DOCKER_IMAGES, up.docker_images.taken_at, json.dumps(stored)))
        conn.execute(
            "INSERT INTO snapshots (host, source, taken_at, ok, error, data) VALUES (?, 'settings', ?, 1, NULL, ?) "
            "ON CONFLICT (host, source) DO UPDATE SET taken_at=excluded.taken_at, data=excluded.data",
            (host, up.sent_at, up.settings.model_dump_json()))
        if up.metrics:
            conn.executemany("DELETE FROM metrics WHERE host = ? AND name = ? AND ts = ?",
                             [(host, name, ts) for ts, name, _ in up.metrics])
            conn.executemany("INSERT INTO metrics (host, ts, name, value) VALUES (?, ?, ?, ?)",
                             [(host, ts, name, value) for ts, name, value in up.metrics])
        conn.executemany(
            "INSERT OR IGNORE INTO events (host, ts, kind, severity, title, detail, link, src_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(host, e.ts, e.kind, e.severity, e.title, e.detail, e.link, e.id) for e in up.events])
        conn.execute(
            "UPDATE hosts SET last_seq=?, last_seen=?, last_sent_at=?, max_interval=?, version=?, address=?, "
            "remote_update=?, update_state=COALESCE(?, update_state), upload_interval=COALESCE(?, upload_interval) "
            "WHERE id=?",
            (up.seq, now, up.sent_at, up.max_interval, up.version, address,
             None if up.remote_update is None else int(up.remote_update),
             up.update.model_dump_json() if up.update else None, up.upload_interval, host))
        pending = _pending_update(conn, host, up, now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    current = [Finding(f.rule, f.key, f.severity, f.title, f.detail, f.link, f.fix, f.basis) for f in up.findings]
    db.reconcile_findings(conn, host, now, current, keep_prefix=HUB_RULES)
    _silent(conn, host, now, None)
    skew = up.sent_at - now
    f = None
    if abs(skew) > SKEW_SECONDS:
        f = Finding("host.clock_skew", "clock", "low", "Clock is off",
                    f"This host's clock is {abs(skew):.0f} seconds {'ahead of' if skew > 0 else 'behind'} the hub's. "
                    "Times on its pages may be wrong. Check NTP on the host (timedatectl).", "/")
    db.set_finding(conn, host, now, f, rule="host.clock_skew", key="clock")
    return pending


# --- updates from the hub ---------------------------------------------------
# The hub can only name a commit. The host installs it from its own clone of
# the GitHub repo, and only if the commit is on main or in a v* tag
# (packaging/daemonsight-update). Hosts turn this off with
# [upload] remote_update = false.

REV_RE = re.compile(r"^[0-9a-f]{7,40}$")


def revision(version: str | None) -> str | None:
    """The commit in a version string like "0.1.0 (b41c588)"."""
    m = re.search(r"\(([0-9a-f]{7,40})\)\s*$", version or "")
    return m.group(1) if m else None


def same_rev(a: str | None, b: str | None) -> bool:
    return bool(a and b) and (a.startswith(b) or b.startswith(a))


def hub_revision() -> str | None:
    return revision(full_version())


def request_update(conn, host_id: str, target: str, now: float) -> bool:
    if not REV_RE.match(target or ""):
        raise ValueError(f"not a commit: {target!r}")
    cur = conn.execute("UPDATE hosts SET update_to=?, update_asked=? WHERE id=? AND kind IS NULL", (target, now, host_id))
    return cur.rowcount == 1


def cancel_update(conn, host_id: str) -> bool:
    return conn.execute("UPDATE hosts SET update_to=NULL WHERE id=? AND update_to IS NOT NULL",
                        (host_id,)).rowcount == 1


def behind(row, target: str | None) -> bool:
    """A host that has reported, accepts updates, and runs another commit."""
    return bool(target) and row["kind"] is None and row["last_seen"] is not None and row["remote_update"] != 0 \
        and not same_rev(revision(row["version"]), target)


def request_update_all(conn, target: str, now: float) -> list[str]:
    ids = [r["id"] for r in conn.execute("SELECT * FROM hosts ORDER BY id") if behind(r, target)]
    for i in ids:
        request_update(conn, i, target, now)
    return ids


def _pending_update(conn, host: str, up: Upload, now: float) -> str | None:
    row = conn.execute("SELECT update_to, update_asked FROM hosts WHERE id=?", (host,)).fetchone()
    target = row["update_to"]
    if not target:
        return None
    short = target[:7]
    if same_rev(revision(up.version), target):
        conn.execute("UPDATE hosts SET update_to=NULL WHERE id=?", (host,))
        _event(conn, host, now, None, f"Updated to {short}")
        return None
    u = up.update
    if u and same_rev(u.ref, target) and u.at >= (row["update_asked"] or 0) \
            and u.status in ("failed", "refused", "rolled_back"):
        conn.execute("UPDATE hosts SET update_to=NULL WHERE id=?", (host,))
        word = {"failed": "failed", "refused": "was refused", "rolled_back": "failed and was rolled back"}[u.status]
        _event(conn, host, now, "medium", f"Update to {short} {word}", u.detail or None)
        return None
    if up.remote_update is False:
        return None
    return target


# --- uninstall from the hub -------------------------------------------------
# "Remove from hub" can first ask the host to uninstall its collector, like an RMM tool removing its agent. The
# hub marks the host "pending" (kept in the hosts row, so a restart keeps it). On the host's next authenticated
# upload the reply carries `uninstall: true`. The collector acts only on a 2xx reply to an upload made with its
# token (collector/upload.py) and only while `[collector] allow_remote_uninstall` is on. It answers in a later
# upload: "started" (the hub then revokes and purges, as Remove does), or "refused" / "failed" (the hub stops
# asking and shows why; the admin can cancel, or remove the host anyway and uninstall by hand).

UNINSTALL_STATES = ("pending", "refused", "failed")


def request_uninstall(conn, host_id: str, now: float) -> bool:
    """Mark a collector host "uninstall pending". False when there is no such host."""
    return conn.execute("UPDATE hosts SET uninstall_state='pending', uninstall_asked=?, uninstall_detail=NULL "
                        "WHERE id=? AND kind IS NULL", (now, host_id)).rowcount == 1


def cancel_uninstall(conn, host_id: str) -> bool:
    return conn.execute("UPDATE hosts SET uninstall_state=NULL, uninstall_asked=NULL, uninstall_detail=NULL "
                        "WHERE id=? AND uninstall_state IS NOT NULL", (host_id,)).rowcount == 1


def uninstall_wanted(conn, host_id: str) -> bool:
    """True while this host is pending: the only case in which an upload's reply says `uninstall`."""
    row = conn.execute("SELECT uninstall_state FROM hosts WHERE id=? AND kind IS NULL", (host_id,)).fetchone()
    return bool(row) and row["uninstall_state"] == "pending"


def remove_host(conn, host_id: str, data_dir=None, cve_path=None) -> None:
    """Revoke a host and delete its stored data, in one transaction (what the Remove button does)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        revoke_host(conn, host_id, purge=True, data_dir=data_dir, cve_path=cve_path)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def hub_event(conn, ts: float, title: str, detail: str | None = None) -> None:
    db.add_event(conn, db.HUB_HOST, ts, "setting", title, detail=detail)


def handle_uninstall_ack(conn, host_id: str, up: Upload, now: float, data_dir=None, cve_path=None) -> bool:
    """Act on what the host said about an uninstall, after its upload is stored. Only a host that is pending
    counts. "started": revoke and purge it and record an event; True is returned. "refused" or "failed": keep
    the host, stop asking and keep the reason."""
    if up.uninstall is None or not uninstall_wanted(conn, host_id):
        return False
    detail = up.uninstall_detail or None
    if up.uninstall == "started":
        remove_host(conn, host_id, data_dir, cve_path)
        hub_event(conn, now, f"Host uninstalled and removed: {host_id}",
                  "the collector reported that its uninstall started; its token and stored data are deleted")
        log.info("Host %s reported its uninstall started; removed", host_id)
        return True
    conn.execute("UPDATE hosts SET uninstall_state=?, uninstall_detail=? WHERE id=?", (up.uninstall, detail, host_id))
    word = "refused" if up.uninstall == "refused" else "failed"
    hub_event(conn, now, f"Uninstall {word} by {host_id}", detail)
    log.warning("Host %s %s the uninstall: %s", host_id, word, detail or "no reason given")
    return False


def _event(conn, host: str, ts: float, severity: str | None, title: str, detail: str | None = None) -> None:
    conn.execute("INSERT INTO events (host, ts, kind, severity, title, detail) VALUES (?, ?, 'update', ?, ?, ?)",
                 (host, ts, severity, title, detail))


def _silent(conn, host: str, now: float, f: Finding | None) -> None:
    change = db.set_finding(conn, host, now, f, rule="host.silent", key="silent")
    if change == "opened":
        db.add_event(conn, host, now, "host_silent", f.title, severity=f.severity, detail=f.detail, link="/")
    elif change == "resolved":
        db.add_event(conn, host, now, "host_back", "Reporting again", link="/")


def host_role(conn, host: str) -> str:
    """"server" or "workstation", from the host's last uploaded settings."""
    snap = db.get_snapshot(conn, host, "settings")
    role = (snap.data or {}).get("role") if snap and snap.data else None
    return role if role == "workstation" else "server"


def check_silent(conn, now: float, default_interval: float = 60) -> None:
    """Open host.silent for every host that has missed three of its longest
    intervals, or never reported within ten minutes of being added."""
    for h in conn.execute("SELECT * FROM hosts WHERE kind IS NULL").fetchall():
        limit = SILENT_AFTER_INTERVALS * (h["max_interval"] or default_interval)
        if h["last_seen"] is None:
            if now - h["created_at"] > 600:
                _silent(conn, h["id"], now, Finding(
                    "host.silent", "silent", "high", "Never reported",
                    "This host was added but has not uploaded anything. Check [upload] in its config and "
                    "journalctl -u daemonsight-collector on the host.", "/"))
            continue
        if now - h["last_seen"] > limit and host_role(conn, h["id"]) == "workstation":
            since = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(h["last_seen"]))
            _silent(conn, h["id"], now, Finding(
                "host.silent", "silent", "low", f"Offline since {since}",
                "This host is set as a workstation, which is often off, asleep or away from the hub's "
                "network. It uploads again when it's back.", "/"))
        elif now - h["last_seen"] > limit:
            _silent(conn, h["id"], now, Finding(
                "host.silent", "silent", "high", "Stopped reporting",
                f"No upload for {int(now - h['last_seen'])} seconds. The host may be down, its network cut, or "
                "its collector stopped. A collector stopped on purpose by an intruder looks the same.", "/"))
