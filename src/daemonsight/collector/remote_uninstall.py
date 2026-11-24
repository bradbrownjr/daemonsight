"""An uninstall the hub asks for. See docs/DESIGN.md "Uninstall from the hub".

The collector never removes anything itself: it runs under systemd's sandboxing, and removing itself would stop
the upload that tells the hub it started. After the final upload it writes <data_dir>/uninstall.request (0600),
and `daemonsight-uninstall.path` starts `daemonsight-uninstall.service`, which runs `daemonsight uninstall`
as root, outside the sandbox. It is the way an update is handed to `daemonsight-update.path` (remote_update.py).

upload.py calls this only for a 2xx reply to an upload made with this host's token, to the configured hub URL,
over HTTPS with the certificate checked. A 401, 403 or 404, a TLS error or an unreachable hub raise before any
reply is read, so none of them can reach this.

[collector] allow_remote_uninstall = false locks the host: the answer is "refused". The hub can't change it.
"""

from __future__ import annotations

import os
from pathlib import Path

REQUEST = "uninstall.request"
# install.sh installs this path unit. A host installed before this feature has none until `daemonsight-update`
# (or an update from the hub) reinstalls, and can't be uninstalled from the hub until then.
UNIT = Path("/etc/systemd/system/daemonsight-uninstall.path")

# Fixed phrases sent to the hub as the reason, never command output.
OFF = "allow_remote_uninstall is off on this host"
NO_UNIT = "this host has no daemonsight-uninstall.path unit; update it first, or uninstall it by hand"


def check(cfg) -> tuple[bool, str]:
    """May this host be uninstalled by the hub now? (yes/no, the reason when no)."""
    if not cfg.collector.allow_remote_uninstall:
        return False, OFF
    if not UNIT.exists():
        return False, NO_UNIT
    return True, ""


def request(cfg) -> None:
    """Hand the uninstall to systemd. Call this after the final upload."""
    data = Path(cfg.data_dir)
    tmp = data / (REQUEST + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("uninstall\n")
    os.replace(tmp, data / REQUEST)
