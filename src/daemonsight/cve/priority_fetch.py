"""Keep the prioritisation table current without a release: fetch the one the DaemonSight repository publishes.

When CISA replaces BOD 26-04, a person transcribes the new table into a file under data/priority/ in the repository and points
`current.json` at it (docs/DESIGN.md, "When the directive changes"). Once a week the hub's CVE chore asks for two small files:

  https://raw.githubusercontent.com/bradbrownjr/daemonsight/main/src/daemonsight/data/priority/current.json    {"table": "<file>.json"}
  https://raw.githubusercontent.com/bradbrownjr/daemonsight/main/src/daemonsight/data/priority/<file>.json    the table

It is data only and nothing in it is executed. Both files are fetched with a conditional GET, over HTTPS from
raw.githubusercontent.com only (a redirect to any other host is refused before it is followed), capped at 256 KB each. The table
goes through the strict check of priority.parse and is accepted only when its `version` is greater than the bundled table's
(and than the fetched one already installed). Accepted, it is written atomically to `<data_dir>/priority/override.json`, which
priority.load already prefers. Invalid, too big or unreachable: whatever is in force stays, and the reason is kept for the
Vulnerabilities page's data feeds card.

An override.json this module did not write (an administrator's own table) is never touched: it keeps winning, and the fetched
table is not installed. The module knows its own file by the SHA-256 it recorded. State is in `<data_dir>/priority/fetch.json`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import priority
from .feeds import USER_AGENT

log = logging.getLogger("daemonsight.priority")

HOST = "raw.githubusercontent.com"
BASE = f"https://{HOST}/bradbrownjr/daemonsight/main/src/daemonsight/data/priority/"
POINTER = "current.json"
MAX_BYTES = 256 << 10
EVERY = 7 * 24 * 3600   # CISA replaces this directive every few years; weekly is plenty
RETRY_AFTER_ERROR = 3600
MAX_HOPS = 3
STATE = Path("priority") / "fetch.json"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.json")


class FetchError(Exception):
    pass


@dataclass(frozen=True)
class Update:
    """A newer table was installed."""
    name: str          # the directive's name, "CISA BOD 27-01"
    version: int
    file: str


# --- state ---------------------------------------------------------------------------------------------------------------

def _state_path(data_dir) -> Path:
    return Path(data_dir) / STATE


def read_state(data_dir) -> dict:
    try:
        d = json.loads(_state_path(data_dir).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(path: Path, data: bytes) -> None:
    """Replace `path` with `data` in one step."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def write_state(data_dir, state: dict) -> None:
    try:
        _write(_state_path(data_dir), json.dumps(state, indent=1, sort_keys=True).encode())
    except OSError as exc:
        log.warning("Cannot save %s: %s", _state_path(data_dir), type(exc).__name__)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _override_sha(data_dir) -> str | None:
    """SHA-256 of override.json, or None when there is none."""
    try:
        return _sha((Path(data_dir) / priority.OVERRIDE).read_bytes())
    except OSError:
        return None


def _ours(data_dir, state: dict) -> bool:
    sha = _override_sha(data_dir)
    return sha is not None and sha == state.get("override_sha256")


STATE_KEYS = ("override_sha256", "table_file", "pointer_etag", "pointer_modified", "table_etag", "table_modified", "version", "name",
              "fetched_at", "held")


def _forget(state: dict) -> None:
    for k in STATE_KEYS:
        state.pop(k, None)


def _drop_ours(data_dir, state: dict) -> None:
    (Path(data_dir) / priority.OVERRIDE).unlink(missing_ok=True)
    _forget(state)


# --- fetching ------------------------------------------------------------------------------------------------------------

def _ok_url(url) -> bool:
    p = urlsplit(str(url))
    return p.scheme == "https" and p.hostname == HOST and not p.username and p.port in (None, 443)


async def _get(client: httpx.AsyncClient, url: str, etag: str | None, modified: str | None):
    """(body, etag, last_modified) of `url`, or None when the server answers 304. Follows at most MAX_HOPS redirects and only to
    https on raw.githubusercontent.com, checking each address before asking for it. Raises FetchError."""
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if modified:
        headers["If-Modified-Since"] = modified
    try:
        for _ in range(MAX_HOPS + 1):
            if not _ok_url(url):
                raise FetchError(f"{urlsplit(url).hostname} is not a source for this file")
            async with client.stream("GET", url, headers=headers, follow_redirects=False) as r:
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                    url = urljoin(url, r.headers["location"])
                    continue
                if r.status_code == 304:
                    return None
                if r.status_code != 200:
                    raise FetchError(f"HTTP {r.status_code}")
                try:
                    declared = int(r.headers.get("content-length", "0"))
                except ValueError:
                    declared = 0
                if declared > MAX_BYTES:
                    raise FetchError(f"larger than {MAX_BYTES >> 10} KB")
                body = bytearray()
                async for chunk in r.aiter_bytes(1 << 14):
                    body += chunk
                    if len(body) > MAX_BYTES:
                        raise FetchError(f"larger than {MAX_BYTES >> 10} KB")
                return bytes(body), r.headers.get("etag"), r.headers.get("last-modified")
        raise FetchError("too many redirects")
    except httpx.HTTPError as exc:
        raise FetchError(f"{type(exc).__name__}"[:100]) from None


def _pointer(body: bytes) -> str:
    try:
        doc = json.loads(body)
    except ValueError:
        raise FetchError("current.json is not valid JSON") from None
    name = doc.get("table") if isinstance(doc, dict) and set(doc) == {"table"} else None
    if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name == POINTER:
        raise FetchError("current.json must be {\"table\": \"<file>.json\"}")
    return name


# --- the daily step ------------------------------------------------------------------------------------------------------

def is_due(state: dict, now: float) -> bool:
    last = state.get("checked_at")
    if last is None:
        return True
    return now - last >= (RETRY_AFTER_ERROR if state.get("status") == "error" else EVERY)


async def refresh(data_dir, now: float | None = None, enabled: bool = True,
                  client: httpx.AsyncClient | None = None) -> Update | None:
    """The chore's daily step. Returns an Update when a newer table was installed, else None. Never raises: a failure is kept in
    the state for the page and the table in force stays."""
    now = time.time() if now is None else now
    state = read_state(data_dir)
    changed = False
    if _override_sha(data_dir) != state.get("override_sha256") and state.get("override_sha256"):
        _forget(state)       # the file we wrote is gone or replaced: forget it
        changed = True
    if not enabled:
        if _ours(data_dir, state):
            log.info("Prioritisation updates are off: removing the fetched table, using the bundled %s", priority.BUNDLED)
            _drop_ours(data_dir, state)
        if changed or state.get("status") != "off":
            state.update(status="off", detail=None)
            write_state(data_dir, state)
        return None
    if state.get("status") == "off":
        state.pop("checked_at", None)         # turned on again: ask now
    # A fetched table the bundled one has caught up with (an upgrade) is no longer wanted.
    if _ours(data_dir, state) and state.get("version", 0) <= priority.bundled().version:
        log.info("The bundled prioritisation table (version %d) is as new as the fetched one: dropping the fetched one",
                 priority.bundled().version)
        _drop_ours(data_dir, state)
        changed = True
    if not is_due(state, now):
        if changed:
            write_state(data_dir, state)
        return None
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=False, headers={"User-Agent": USER_AGENT})
    state["checked_at"] = now
    try:
        update = await _step(client, data_dir, state, now)
        state["ok_at"] = now
        state["detail"] = state.pop("note", None)
        return update
    except FetchError as exc:
        log.warning("Prioritisation table: %s", exc)
        state["status"], state["detail"] = "error", str(exc)[:200]
        return None
    except Exception as exc:       # nothing here may stop the chore
        log.exception("Prioritisation table update failed")
        state["status"], state["detail"] = "error", f"{type(exc).__name__}: {exc}"[:200]
        return None
    finally:
        write_state(data_dir, state)
        if own:
            await client.aclose()


async def _step(client, data_dir, state: dict, now: float) -> Update | None:
    path = Path(data_dir) / priority.OVERRIDE
    state["status"] = "ok"
    # Validators are only worth sending while the answer would change nothing here: a table is installed, or the published
    # one was seen and judged not newer. Otherwise (never fetched, a table of the administrator's in the way) the full file is wanted.
    held = bool(state.get("held"))
    got = await _get(client, BASE + POINTER, state.get("pointer_etag") if held else None,
                     state.get("pointer_modified") if held else None)
    if got is None:
        name = state.get("table_file")
        if not name:
            raise FetchError("current.json: HTTP 304 with nothing kept")
    else:
        body, state["pointer_etag"], state["pointer_modified"] = got
        name = _pointer(body)
    same = name == state.get("table_file")
    got = await _get(client, BASE + name, state.get("table_etag") if held and same else None,
                     state.get("table_modified") if held and same else None)
    if got is None:
        state["status"] = "not modified"
        return None
    body, etag, modified = got
    state["table_file"] = name
    if len(body) > priority.MAX_FILE_BYTES:
        raise FetchError(f"{name} is larger than {priority.MAX_FILE_BYTES >> 10} KB")
    try:
        table = priority.parse(json.loads(body), str(path))
    except ValueError as exc:       # json.JSONDecodeError and priority.TableError are both ValueErrors
        state.pop("table_etag", None)
        raise FetchError(f"{name} refused: {str(exc)[:150]}") from None
    state["table_etag"], state["table_modified"] = etag, modified
    bundled = priority.bundled()
    if path.exists() and not _ours(data_dir, state):
        state.pop("held", None)          # ask for the full file next time: the file in the way may be gone by then
        state["note"] = f"{name} (version {table.version}) not installed: a table you placed at {path} is in use"
        return None
    have = state.get("version", 0) if _ours(data_dir, state) else 0
    if table.version <= max(bundled.version, have):
        state["held"] = True
        return None
    _write(path, body)
    state.update(override_sha256=_sha(body), version=table.version, name=table.name, fetched_at=now, held=True)
    log.info("Prioritisation table updated to %s version %d (%s)", table.name, table.version, name)
    return Update(table.name, table.version, name)


# --- for the page --------------------------------------------------------------------------------------------------------

def describe(data_dir, enabled: bool = True) -> dict:
    """What the data feeds card shows of the table in force: the Table, where it came from ("bundled", "fetched" or "file": a
    table placed at override.json by hand), when it was fetched, and the last fetch's outcome."""
    table = priority.load(data_dir)
    state = read_state(data_dir)
    origin = "bundled"
    if table.source != "bundled":
        origin = "fetched" if _ours(data_dir, state) else "file"
    return {"table": table, "origin": origin, "when": state.get("fetched_at") if origin == "fetched" else None,
            "enabled": enabled, "checked_at": state.get("checked_at"),
            "error": (state.get("detail") or "") if state.get("status") == "error" else "",
            "note": (state.get("detail") or "") if state.get("status") not in ("error", "off") else ""}
