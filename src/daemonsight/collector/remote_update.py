"""Updates the hub asks for.

The hub's upload reply can carry `update_to`, a commit. The collector does
not install anything itself: installing restarts the collector, and the
collector runs with systemd's sandboxing. It writes the commit to
<data_dir>/update.request, and the daemonsight-update.path unit starts
daemonsight-update.service, which checks the commit is on main or in a v*
tag of the GitHub repo before installing it (packaging/daemonsight-update).

That script writes <data_dir>/update.result (ref, status, at, detail),
which the collector sends with each upload so the hub can show it.

On by default, like a UniFi or FortiGate controller updating its devices.
A host turns it off with [upload] remote_update = false; the hub can't
change that setting.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .. import full_version
from ..hub import REV_RE, UPDATE_STATES, revision, same_rev

REQUEST = "update.request"
RESULT = "update.result"
# After an attempt at a commit, don't ask for the same one again for this
# long, so a failing update isn't retried every 30 seconds.
RETRY_AFTER = 3600


def read_result(data_dir: str | os.PathLike) -> dict | None:
    """The last update result, cleaned up for the upload, or None."""
    path = Path(data_dir) / RESULT
    try:
        raw = path.read_bytes()[:4096]
        r = json.loads(raw)
    except (OSError, ValueError):
        return None
    if not isinstance(r, dict) or not REV_RE.match(str(r.get("ref", ""))) \
            or r.get("status") not in UPDATE_STATES or not isinstance(r.get("at"), (int, float)):
        return None
    detail = "".join(ch for ch in str(r.get("detail") or "") if ord(ch) >= 32)[:300]
    return {"ref": r["ref"], "status": r["status"], "at": float(r["at"]), "detail": detail}


def handle(cfg, target: str, now: float | None = None) -> str:
    """Act on the hub's `update_to`. Returns what happened: requested,
    current, off, waiting or invalid."""
    now = now or time.time()
    if not isinstance(target, str) or not REV_RE.match(target):
        return "invalid"
    if same_rev(revision(full_version()), target):
        return "current"
    if not cfg.upload.remote_update:
        return "off"
    data = Path(cfg.data_dir)
    request = data / REQUEST
    if request.exists():
        return "waiting"
    last = read_result(data)
    if last and same_rev(last["ref"], target) and (last["status"] == "running" or now - last["at"] < RETRY_AFTER):
        return "waiting"
    tmp = data / (REQUEST + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(target + "\n")
    os.replace(tmp, request)
    return "requested"
