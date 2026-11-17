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
import json
import logging
import time
from dataclasses import asdict
from pathlib import Path

import httpx

from .. import db, full_version
from ..config import Config
from . import remote_update

log = logging.getLogger("daemonsight.upload")

MAX_METRICS = 20_000
MAX_EVENTS = 1_000
MAX_BACKOFF = 300


class UploadError(Exception):
    pass


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


def build(conn, cfg: Config, eph: tuple[int, int], max_interval: float) -> tuple[dict, dict, bool]:
    """The next upload, the cursors to save once the hub accepts it, and
    whether more is waiting after it."""
    host = cfg.host_id
    metric_row = int(_meta_float(conn, "upload.metric_row"))
    event_id = int(_meta_float(conn, "upload.event_id"))

    snaps = [s for s in conn.execute("SELECT * FROM snapshots WHERE host = ?", (host,)).fetchall()
             if s["taken_at"] != _meta_float(conn, f"upload.snap.{s['source']}")]
    rows = conn.execute("SELECT rowid, ts, name, value FROM metrics WHERE host = ? AND rowid > ? "
                        "ORDER BY rowid LIMIT ?", (host, metric_row, MAX_METRICS + 1)).fetchall()
    more = len(rows) > MAX_METRICS
    rows = rows[:MAX_METRICS]
    events = conn.execute("SELECT * FROM events WHERE host = ? AND id > ? ORDER BY id LIMIT ?",
                          (host, event_id, MAX_EVENTS + 1)).fetchall()
    more = more or len(events) > MAX_EVENTS
    events = events[:MAX_EVENTS]
    findings = db.open_findings(conn, host)

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
        },
        "snapshots": [{"source": s["source"], "taken_at": s["taken_at"], "ok": bool(s["ok"]),
                       "error": s["error"], "data": json.loads(s["data"]) if s["data"] else None} for s in snaps],
        "metrics": [[r["ts"], r["name"], r["value"]] for r in rows],
        "events": [{"id": e["id"], "ts": e["ts"], "kind": e["kind"], "severity": e["severity"],
                    "title": e["title"], "detail": e["detail"], "link": e["link"]} for e in events],
        "findings": [{"rule": f["rule"], "key": f["key"], "severity": f["severity"], "title": f["title"],
                      "detail": f["detail"], "link": f["link"]} for f in findings],
    }
    cursors = {
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
            payload, cursors, more = build(self.conn, self.cfg, self.eph, self.max_interval)
            seq = self._next_seq()
            db.set_meta(self.conn, {"upload.seq": seq})
        payload["seq"] = seq
        payload["sent_at"] = time.time()
        payload["remote_update"] = self.cfg.upload.remote_update
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
            log.debug("uploaded seq %d (%d bytes, %d metrics, %d events)", seq, len(body),
                      len(payload["metrics"]), len(payload["events"]))
            self._hub_asks(r)
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
