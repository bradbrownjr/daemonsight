"""The newest stable Unraid release, for the `unraid.os_update` rule.

The Unraid GraphQL API has no field for it (checked against
`api/generated-schema.graphql` in https://github.com/unraid/api: there is no
update or release field on `Query`, `Info` or `Vars`). The server's own
"Update OS" check reads a public page, `https://releases.unraid.net/os`:
`UnraidCheck.php` in https://github.com/unraid/api, under
`plugin/source/dynamix.unraid.net/usr/local/emhttp/plugins/dynamix.plugin.manager/include/`,
builds `BASE_RELEASES_URL = 'https://releases.unraid.net/os'` plus the query
`branch` (the plugin's category, `stable` by default), `current_version` and, for a
registered server, `update_exp` (its license expiry date), and the page answers
with the newest release for that branch and an `isNewer` flag.

DaemonSight sends none of the server's details. It asks for the page with
`branch=stable` only: the same request for every server, answered with the
newest stable release (`version`, `name`, `date`, `changelogPretty`;
checked live, read-only, no account needed) and compares it with the version
the API reports. The request goes out from the hub at most once a day, with the
generic User-Agent `DaemonSight/<version>`, and only while at least one Unraid
system is enabled. A failed fetch is tried again after six hours.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit

from .. import db
from . import store
from .client import RemoteError

URL = "https://releases.unraid.net/os?branch=stable"
EVERY = 24 * 3600
RETRY = 6 * 3600
MAX_BYTES = 64 * 1024
META_RELEASE, META_TRIED, META_OK = "unraid_release", "unraid_release_tried", "unraid_release_ok"
NOTES_HOSTS = ("docs.unraid.net", "releases.unraid.net")
_VERSION = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:[-.]([0-9A-Za-z.-]{1,20}))?$")


def parse_version(v) -> tuple[int, int, int, int] | None:
    """(major, minor, patch, 1) for 7.3.2; the last number is 0 for a pre-release such as 7.4.0-rc.1, so the
    release sorts after its candidates."""
    m = _VERSION.match(str(v or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if m.group(4) else 1) if m else None


def valid(reply) -> dict | None:
    """The fields kept from the page's answer, or None when it isn't a stable release we understand."""
    if not isinstance(reply, dict) or reply.get("error"):
        return None
    v = parse_version(reply.get("version"))
    if v is None or not v[3]:
        return None
    notes = str(reply.get("changelogPretty") or "")
    parts = urlsplit(notes)
    if parts.scheme != "https" or parts.hostname not in NOTES_HOSTS or len(notes) > 300 or any(c.isspace() for c in notes):
        notes = f"https://docs.unraid.net/unraid-os/release-notes/{reply['version']}/"
    date = str(reply.get("date") or "")
    return {"version": str(reply["version"]), "date": date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else "",
            "notes": notes}


def stored(conn) -> dict | None:
    raw = db.get_meta(conn, META_RELEASE)
    try:
        d = json.loads(raw) if raw else None
    except ValueError:
        return None
    return d if isinstance(d, dict) and parse_version(d.get("version")) else None


def due(conn, now: float) -> bool:
    tried = float(db.get_meta(conn, META_TRIED, "0") or 0)
    ok = float(db.get_meta(conn, META_OK, "0") or 0)
    return now - tried >= (EVERY if ok >= tried else RETRY)


async def refresh(conn, net, now: float | None = None) -> bool:
    """Fetch the release page when it is due and a system needs it. Returns True when a request was made."""
    now = time.time() if now is None else now
    if not any(r["enabled"] for r in store.all_rows(conn)) or not due(conn, now):
        return False
    db.set_meta(conn, {META_TRIED: now})
    http = net.public()
    try:
        async with http.stream("GET", URL, headers={"User-Agent": _agent(), "Accept": "application/json"}) as r:
            body = bytearray()
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    raise RemoteError("http", "The release page's reply was too large.")
            status = r.status_code
        if status != 200:
            raise RemoteError("http", f"HTTP {status}")
        rel = valid(json.loads(body))
    except Exception as exc:      # a failed check never stops a poll
        db.set_meta(conn, {"unraid_release_error": type(exc).__name__})
        return True
    finally:
        await http.aclose()
    if rel:
        db.set_meta(conn, {META_RELEASE: json.dumps(rel), META_OK: now, "unraid_release_error": ""})
    else:
        db.set_meta(conn, {"unraid_release_error": "unreadable"})
    return True


def _agent() -> str:
    from .client import USER_AGENT
    return USER_AGENT


def newer(latest: dict | None, running: str | None) -> bool:
    a, b = parse_version((latest or {}).get("version")), parse_version(running)
    return bool(a and b and a > b)
