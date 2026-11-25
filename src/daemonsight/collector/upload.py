"""Send this host's data to a hub over HTTPS. See docs/DESIGN.md "Hub".

Each upload carries the latest snapshot of every source that changed, the
metrics and events the hub hasn't confirmed, and the current findings. The
cursors only move forward when the hub answers 200, so nothing is lost while
the hub is down. Sending the same data twice is harmless: the hub keys
events by their id here and replaces metric points by time and name.

Cursors follow write order, not timestamps: a source stamps its reading when
it starts and writes it when it finishes, so a slow source can write an
older timestamp after a faster one has written a newer one.

`seq` grows with the clock (milliseconds), so a reinstalled collector with a
fresh database still sends numbers higher than the hub has seen.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import re
import time
from dataclasses import asdict
from pathlib import Path

import httpx

from .. import db, full_version
from ..config import Config
from . import remote_uninstall, remote_update

log = logging.getLogger("daemonsight.upload")

MAX_METRICS = 20_000
MAX_EVENTS = 1_000
MAX_BACKOFF = 300
# The hub refused this host's token (401, 403): asking again every interval only fills its logs and trips its
# rate limit, so ask once an hour. `systemctl restart daemonsight-collector` asks at once.
REJECTED_RETRY = 3600
REJECTED_MESSAGE = "the hub rejected this host's upload token"
INVENTORY = "inventory"
INVENTORY_RESEND = 86400  # send the package list again after a day even when unchanged
DOCKER_IMAGES = "docker_images"
DOCKER_IMAGES_RESEND = 86400   # send every image's package list again after a day, so a hub that lost one recovers
RESEND_ASKED_EVERY = 600       # a package list the hub asks for again is sent at most this often per image
# Sources that have a top-level field of their own in the upload instead of a snapshot (see _inventory, _docker_images).
OWN_FIELD = (INVENTORY, DOCKER_IMAGES)


class UploadError(Exception):
    pass


class TokenRejected(UploadError):
    """The hub answered 401 or 403: it doesn't accept this host's token."""


def rejection(conn) -> dict | None:
    """When the hub last rejected this host's token, as {"at", "status"}, or None while uploads are accepted.
    Kept in the database so `daemonsight status` and the local web page can show it."""
    at = db.get_meta(conn, "upload.rejected_at")
    if at is None:
        return None
    try:
        return {"at": float(at), "status": int(db.get_meta(conn, "upload.rejected_status", "0"))}
    except ValueError:
        return None


def check_url(url: str) -> None:
    """The token travels in every upload, so it must go over HTTPS, except
    to a hub on this same machine."""
    u = httpx.URL(url)
    if u.scheme == "https" and u.host:
        return
    if u.scheme == "http" and u.host in ("127.0.0.1", "localhost", "::1"):
        return
    raise UploadError(f"[upload] url must start with https:// (got {url!r})")


def _meta_float(conn, key: str) -> float:
    try:
        return float(db.get_meta(conn, key, "0"))
    except ValueError:
        return 0.0


def _inventory(conn, snapshot_rows) -> tuple[dict | None, dict]:
    """The installed-package list for the hub, and the cursors to save when
    it accepts it. It is its own top-level upload field, not a snapshot, so
    an older hub, which ignores fields it doesn't know, still takes the rest
    of the upload (a snapshot from an unknown source would be refused whole).
    It is sent when its hash changed, and again after a day, so a hub that
    lost it recovers."""
    row = next((r for r in snapshot_rows if r["source"] == INVENTORY), None)
    if row is None or not row["ok"] or not row["data"]:
        return None, {}
    data = json.loads(row["data"])
    if data.get("available") is False or not data.get("hash"):
        return None, {}
    now = time.time()
    unchanged = db.get_meta(conn, "upload.inv_hash") == data["hash"]
    if unchanged and now - _meta_float(conn, "upload.inv_at") < INVENTORY_RESEND:
        return None, {}
    body = {k: v for k, v in data.items() if k not in ("available", "count")}
    body["v"] = 1
    body["taken_at"] = row["taken_at"]
    return body, {"upload.inv_hash": data["hash"], "upload.inv_at": now}


def _docker_images(conn, snapshot_rows, resend: frozenset[str] = frozenset()) -> tuple[dict | None, dict]:
    """The container images' OS and package lists for the hub, and the cursors to save when it accepts them. Its own top-level
    upload field, like the inventory (an older hub ignores it). A list is sent in full only when the hub does not have it: the
    image's `hash` is not what the hub last accepted from this host, or the hub asked for it (`resend`, from its reply), or a day
    has passed. Otherwise the entry carries the hash and the count and no packages, and the hub keeps the list it has per image id
    (hub.merge_docker_images). When nothing changed at all, the field is left out of the upload. See docs/DESIGN.md "Collector
    hosts: image CVEs" for the sizes."""
    row = next((r for r in snapshot_rows if r["source"] == DOCKER_IMAGES), None)
    if row is None or not row["ok"] or not row["data"]:
        return None, {}
    data = json.loads(row["data"])
    now = time.time()
    full_at = _meta_float(conn, "upload.dimg_full_at")
    full_all = now - full_at >= DOCKER_IMAGES_RESEND
    held: dict[str, str] = {}
    try:
        held = {k: v for k, v in json.loads(db.get_meta(conn, "upload.dimg_sent") or "{}").items() if isinstance(v, str)}
    except ValueError:
        pass
    if data.get("available") is False:
        body = {"v": 1, "available": False, "reason": str(data.get("reason") or "")[:200]}
        hashes: dict[str, str] = {}
    else:
        entries = []
        for e in data.get("image_packages") or []:
            e = dict(e)
            if e.get("hash") and not (full_all or held.get(e["image_id"]) != e["hash"] or e["image_id"] in resend):
                e["packages"] = []                   # the hub has this list: the hash says which
            entries.append(e)
        body = {"v": 1, "engine": data.get("engine") or {}, "containers": data.get("containers") or [],
                "images": data.get("images") or [], "image_packages": entries}
        hashes = {e["image_id"]: e["hash"] for e in data.get("image_packages") or [] if e.get("hash")}
    # What the hub would learn from this upload: the entries without their lists (the hashes stand for them).
    shape = json.dumps({**body, "image_packages": [{**e, "packages": None} for e in body.get("image_packages", [])]},
                       sort_keys=True, separators=(",", ":"))
    fp = hashlib.sha256(shape.encode()).hexdigest()[:32]
    if db.get_meta(conn, "upload.dimg_fp") == fp and not full_all and not resend:
        return None, {}
    body["taken_at"] = row["taken_at"]
    return body, {"upload.dimg_fp": fp, "upload.dimg_sent": json.dumps(hashes, separators=(",", ":")),
                  "upload.dimg_full_at": now if full_all else full_at}


def _finding_payload(f) -> dict:
    """fix and basis are sent only when set, so a host updated ahead of its hub
    still reports when it has nothing to say there."""
    out = {"rule": f["rule"], "key": f["key"], "severity": f["severity"], "title": f["title"],
           "detail": f["detail"], "link": f["link"]}
    for field in ("fix", "basis"):
        if f[field] is not None:
            out[field] = f[field]
    return out


def build(conn, cfg: Config, eph: tuple[int, int], max_interval: float,
          resend: frozenset[str] = frozenset()) -> tuple[dict, dict, bool]:
    """The next upload, the cursors to save once the hub accepts it, and
    whether more is waiting after it."""
    host = cfg.host_id
    metric_row = int(_meta_float(conn, "upload.metric_row"))
    event_id = int(_meta_float(conn, "upload.event_id"))

    rows_all = conn.execute("SELECT * FROM snapshots WHERE host = ?", (host,)).fetchall()
    snaps = [s for s in rows_all
             if s["source"] not in OWN_FIELD and s["taken_at"] != _meta_float(conn, f"upload.snap.{s['source']}")]
    rows = conn.execute("SELECT rowid, ts, name, value FROM metrics WHERE host = ? AND rowid > ? "
                        "ORDER BY rowid LIMIT ?", (host, metric_row, MAX_METRICS + 1)).fetchall()
    more = len(rows) > MAX_METRICS
    rows = rows[:MAX_METRICS]
    events = conn.execute("SELECT * FROM events WHERE host = ? AND id > ? ORDER BY id LIMIT ?",
                          (host, event_id, MAX_EVENTS + 1)).fetchall()
    more = more or len(events) > MAX_EVENTS
    events = events[:MAX_EVENTS]
    findings = db.open_findings(conn, host)
    inventory, inv_cursors = _inventory(conn, rows_all)
    images, img_cursors = _docker_images(conn, rows_all, resend)

    payload = {
        "v": 1,
        "host": host,
        "version": full_version()[:80],
        "max_interval": max_interval,
        "settings": {
            "exposure": asdict(cfg.exposure),
            "links": cfg.links,
            "eph": list(eph),
            "interval_system": cfg.collector.interval_system,
            "role": cfg.role,
        },
        "snapshots": [{"source": s["source"], "taken_at": s["taken_at"], "ok": bool(s["ok"]),
                       "error": s["error"], "data": json.loads(s["data"]) if s["data"] else None} for s in snaps],
        "metrics": [[r["ts"], r["name"], r["value"]] for r in rows],
        "events": [{"id": e["id"], "ts": e["ts"], "kind": e["kind"], "severity": e["severity"],
                    "title": e["title"], "detail": e["detail"], "link": e["link"]} for e in events],
        "findings": [_finding_payload(f) for f in findings],
    }
    if inventory is not None:
        payload["inventory"] = inventory
    if images is not None:
        payload["docker_images"] = images
    cursors = {
        **inv_cursors,
        **img_cursors,
        **{f"upload.snap.{s['source']}": s["taken_at"] for s in snaps},
        "upload.metric_row": rows[-1]["rowid"] if rows else metric_row,
        "upload.event_id": events[-1]["id"] if events else event_id,
    }
    return payload, cursors, more


class Uploader:
    def __init__(self, cfg: Config, conn, lock: asyncio.Lock, eph: tuple[int, int], max_interval: float):
        self.cfg = cfg
        self.conn = conn
        self.lock = lock
        self.eph = eph
        self.max_interval = max(max_interval, cfg.upload.interval)
        self.client = httpx.AsyncClient(timeout=30.0, verify=True, follow_redirects=False,
                                        headers={"User-Agent": f"daemonsight/{full_version()}"})
        self._update_seen: tuple[str, str] | None = None
        # What to tell the hub about an uninstall it asked for, sent with the next upload (see _hub_uninstall).
        self._uninstall_ack: tuple[str, str] | None = None
        self._uninstalling = False
        # Image ids whose package lists the hub's last reply asked for again, and when each was last asked for.
        self._resend: frozenset[str] = frozenset()
        self._asked_at: dict[str, float] = {}

    def _hub_wants_lists(self, reply) -> None:
        """Note the image package lists the hub says it is missing (`docker_images_resend`, a short list of image ids), to send in
        full with the next upload. An id is honoured at most once per RESEND_ASKED_EVERY, so a hub that keeps refusing a list
        is not sent it every upload."""
        try:
            ids = reply.json().get("docker_images_resend")
        except (ValueError, AttributeError):
            ids = None
        now = time.time()
        asked = set()
        for i in (ids if isinstance(ids, list) else [])[:100]:
            if isinstance(i, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", i) and now - self._asked_at.get(i, 0) >= RESEND_ASKED_EVERY:
                asked.add(i)
                self._asked_at[i] = now
        self._resend = frozenset(asked)
        self._asked_at = {k: v for k, v in self._asked_at.items() if now - v < 3600}

    def _hub_asks(self, reply) -> None:
        """Act on an update the hub's reply asks for, logging each change."""
        try:
            target = reply.json().get("update_to")
        except (ValueError, AttributeError):
            return
        if not target:
            self._update_seen = None
            return
        outcome = remote_update.handle(self.cfg, target)
        if (target, outcome) != self._update_seen:
            self._update_seen = (target, outcome)
            msg = {"requested": "the hub asked for an update to %s; requested it",
                   "off": "the hub asked for an update to %s, but remote_update is off here",
                   "invalid": "the hub sent an update target that isn't a commit: %r"}.get(outcome)
            if msg:
                (log.warning if outcome == "invalid" else log.info)(msg, target)

    async def _hub_uninstall(self, r, seq: int) -> None:
        """Act on `uninstall: true` in the reply. Called only for a successful reply to an upload sent with this
        host's token to the configured URL, and never from any other response. The hub is told with a final upload
        before anything is removed; the removal itself is handed to systemd (remote_uninstall.py)."""
        if self._uninstalling:
            return
        try:
            reply = r.json()
        except (ValueError, AttributeError):
            reply = None
        try:
            check_url(self.cfg.upload.url)  # HTTPS (or this machine), as for every upload
        except UploadError:
            reply = None
        asked = isinstance(reply, dict) and reply.get("uninstall") is True and reply.get("last_seq") == seq
        if not asked or not r.is_success or r.request.url != httpx.URL(self.cfg.upload.url):
            self._uninstall_ack = None
            return
        ok, why = remote_uninstall.check(self.cfg)
        if not ok:
            if self._uninstall_ack is None:
                log.warning("the hub asked this host to uninstall DaemonSight; refused: %s", why)
            self._uninstall_ack = ("refused", why)
            return
        log.warning("the hub asked this host to uninstall DaemonSight (Remove from hub, \"Uninstall the collector "
                    "first\"); uninstalling")
        self._uninstalling = True
        self._uninstall_ack = ("started", "")
        try:
            await self.upload_once()  # tell the hub, if it can be reached; the uninstall goes ahead either way
        except UploadError as exc:
            log.warning("could not tell the hub the uninstall started: %s", exc)
        try:
            remote_uninstall.request(self.cfg)
        except OSError as exc:
            log.error("could not start the uninstall: %s", exc.strerror)
            self._uninstalling = False
            self._uninstall_ack = ("failed", "the collector could not write the uninstall request")

    def _token(self) -> str:
        try:
            token = Path(self.cfg.upload.token_file).read_text().strip()
        except OSError as exc:
            raise UploadError(f"can't read the token file {self.cfg.upload.token_file}: {exc.strerror}") from None
        if not token:
            raise UploadError(f"the token file {self.cfg.upload.token_file} is empty")
        return token

    def _next_seq(self) -> int:
        last = int(_meta_float(self.conn, "upload.seq"))
        return max(last + 1, int(time.time() * 1000))

    async def upload_once(self) -> bool:
        """Send one upload. Returns True when more data is waiting."""
        token = self._token()
        async with self.lock:
            payload, cursors, more = build(self.conn, self.cfg, self.eph, self.max_interval, self._resend)
            seq = self._next_seq()
            db.set_meta(self.conn, {"upload.seq": seq})
        payload["seq"] = seq
        payload["sent_at"] = time.time()
        payload["remote_update"] = self.cfg.upload.remote_update
        payload["upload_interval"] = self.cfg.upload.interval
        if self._uninstall_ack:
            payload["uninstall"] = self._uninstall_ack[0]
            if self._uninstall_ack[1]:
                payload["uninstall_detail"] = self._uninstall_ack[1]
        last = remote_update.read_result(self.cfg.data_dir)
        if last:
            payload["update"] = last
        body = gzip.compress(json.dumps(payload, separators=(",", ":")).encode(), compresslevel=6)
        try:
            r = await self.client.post(self.cfg.upload.url, content=body, headers={
                "Authorization": f"Bearer {token}", "Content-Type": "application/json",
                "Content-Encoding": "gzip"})
        except httpx.HTTPError as exc:
            raise UploadError(f"{type(exc).__name__}: {exc}") from None
        if r.status_code == 200:
            async with self.lock:
                db.set_meta(self.conn, {**cursors, "upload.last_ok": time.time()})
                db.delete_meta(self.conn, "upload.rejected_at", "upload.rejected_status")
            log.debug("uploaded seq %d (%d bytes, %d metrics, %d events)", seq, len(body),
                      len(payload["metrics"]), len(payload["events"]))
            self._hub_asks(r)
            self._hub_wants_lists(r)
            await self._hub_uninstall(r, seq)
            return more
        if r.status_code == 409:
            # The hub has seen a higher number (our clock went back): jump past it.
            try:
                last = int(r.json().get("last_seq", 0))
            except ValueError:
                last = 0
            async with self.lock:
                db.set_meta(self.conn, {"upload.seq": max(last, seq)})
            raise UploadError(f"hub expects a sequence number above {last}; retrying")
        if r.status_code in (401, 403):
            async with self.lock:
                db.set_meta(self.conn, {"upload.rejected_at": time.time(), "upload.rejected_status": r.status_code})
            raise TokenRejected(f"{REJECTED_MESSAGE} (HTTP {r.status_code})")
        reason = r.text[:200].strip() if r.headers.get("content-type", "").startswith("text/") else ""
        raise UploadError(f"HTTP {r.status_code}{': ' + reason if reason else ''}")

    async def run(self, stop: asyncio.Event) -> None:
        try:
            check_url(self.cfg.upload.url)
        except UploadError as exc:
            log.error("not uploading: %s", exc)
            await self.client.aclose()
            return
        log.info("uploading to %s every %d s", self.cfg.upload.url, self.cfg.upload.interval)
        backoff = 0
        failing = False
        while not stop.is_set():
            delay = self.cfg.upload.interval
            try:
                more = await self.upload_once()
                if failing:
                    log.info("upload working again")
                failing, backoff = False, 0
                if more:
                    delay = 1
            except TokenRejected as exc:
                delay, backoff = REJECTED_RETRY, 0
                (log.warning if not failing else log.debug)("upload failed: %s (next try in %d s)", exc, delay)
                failing = True
            except UploadError as exc:
                backoff = min(max(backoff * 2, self.cfg.upload.interval), MAX_BACKOFF)
                delay = backoff
                (log.warning if not failing else log.debug)("upload failed: %s (next try in %d s)", exc, delay)
                failing = True
            except Exception:
                log.exception("upload failed")
                delay = MAX_BACKOFF
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        await self.client.aclose()
