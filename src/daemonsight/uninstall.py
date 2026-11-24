"""`daemonsight uninstall`: take DaemonSight off this host.

It removes what install.sh installed, and nothing else. The list below comes from install.sh (the `install`,
`ln`, `useradd` and `systemctl enable` lines) plus the two things an admin may have added later, which docs/INSTALL.md
names under "Remove": the sudoers rule for daemonsight-update and the fail2ban jail. Run it by hand
(`sudo daemonsight uninstall --yes`) or let the hub ask for it: the collector writes <data_dir>/uninstall.request,
`daemonsight-uninstall.path` starts `daemonsight-uninstall.service`, and that runs this command as root, outside the
collector's sandbox. See docs/DESIGN.md "Uninstall from the hub".

Only the standard locations are touched: a data folder, token file or config the admin moved elsewhere is left
alone. Running it again after it finished removes nothing and succeeds.

It uses the standard library only and imports nothing from the package, because it deletes the package it runs from.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

SYSTEMD = "/etc/systemd/system"
# install.sh: the collector, the web UI (unless --collector), the update path and service, and (new with this
# command) the uninstall path and service. Paths first, so nothing restarts a service that is being removed.
PATH_UNITS = ("daemonsight-update.path", "daemonsight-uninstall.path")
SERVICE_UNITS = ("daemonsight-collector.service", "daemonsight-web.service")
# Services started by a path unit. They are removed, but never stopped here: the uninstall service is this very
# process, and an update in progress is left to its own end.
ONESHOT_UNITS = ("daemonsight-update.service", "daemonsight-uninstall.service")
UNIT_FILES = tuple(f"{SYSTEMD}/{u}" for u in (*SERVICE_UNITS, *PATH_UNITS, *ONESHOT_UNITS))
# install.sh: `ln -sf ... /usr/local/bin/daemonsight` and `install ... /usr/local/sbin/daemonsight-update`.
COMMANDS = ("/usr/local/bin/daemonsight", "/usr/local/sbin/daemonsight-update")
# install.sh --fail2ban, and the sudoers rule INSTALL.md "Updating without a password" has the admin add.
FAIL2BAN = ("/etc/fail2ban/filter.d/daemonsight.conf", "/etc/fail2ban/jail.d/daemonsight.conf")
SUDOERS = ("/etc/sudoers.d/daemonsight-update",)
# install.sh: PREFIX (the venv, REVISION and the update clone), ETC (config.toml, install.options, hub.token,
# password, secret) and DATA (state.db, update.request and result, backups).
TREES = ("/opt/daemonsight", "/etc/daemonsight", "/var/lib/daemonsight")
DATA = "/var/lib/daemonsight"
REQUEST = "uninstall.request"
USER = "daemonsight"  # install.sh: useradd --system --user-group --home-dir $DATA --shell /usr/sbin/nologin


def _under(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def _run(cmd: list[str]) -> int:
    try:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=120, check=False).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 127


def _exists(p: Path) -> bool:
    return p.is_symlink() or p.exists()


def _created_user(lookup: Callable[[str], object]) -> bool:
    """True when the account is the one install.sh makes: its home is the data folder and it can't log in. An
    account that happened to have this name already is left alone."""
    try:
        pw = lookup(USER)
    except KeyError:
        return False
    return pw.pw_dir == DATA and str(pw.pw_shell).endswith("nologin")  # type: ignore[attr-defined]


def plan(root: Path = Path("/"), lookup: Callable[[str], object] = pwd.getpwnam) -> dict:
    """What is installed here: units, files, folders, whether the user is ours."""
    units = [u for u in (*PATH_UNITS, *SERVICE_UNITS, *ONESHOT_UNITS) if _exists(_under(root, f"{SYSTEMD}/{u}"))]
    files = [p for p in (*UNIT_FILES, *COMMANDS, *FAIL2BAN, *SUDOERS) if _exists(_under(root, p))]
    trees = [p for p in TREES if _exists(_under(root, p))]
    return {"units": units, "files": files, "trees": trees, "user": _created_user(lookup)}


def describe(p: dict) -> list[str]:
    lines = []
    if p["units"]:
        lines.append("Stop and disable: " + ", ".join(u for u in p["units"] if u not in ONESHOT_UNITS))
    lines += [f"Remove file:   {f}" for f in p["files"]]
    lines += [f"Remove folder: {t}" for t in p["trees"]]
    if p["user"]:
        lines.append(f"Remove the {USER} user and group")
    return lines


def run(root: Path = Path("/"), runner: Callable[[list[str]], int] = _run,
        lookup: Callable[[str], object] = pwd.getpwnam, out: Callable[[str], None] = print) -> int:
    """Remove everything `plan` lists. Returns 0 when it all went, 1 when something couldn't be removed.
    `root` re-bases every path (tests); `runner` runs systemctl and userdel; `lookup` finds the user."""
    p = plan(root, lookup)
    errors = 0
    # A request left behind would make the path unit start this again as soon as it is started.
    _under(root, f"{DATA}/{REQUEST}").unlink(missing_ok=True)
    for unit in p["units"]:
        if unit in ONESHOT_UNITS:
            continue
        runner(["systemctl", "disable", "--now", unit])
        out(f"Stopped and disabled {unit}")
    had_jail = any(_exists(_under(root, f)) for f in FAIL2BAN)
    for f in p["files"]:
        try:
            _under(root, f).unlink()
            out(f"Removed {f}")
        except OSError as exc:
            errors += 1
            out(f"Could not remove {f}: {exc.strerror}")
    if p["units"]:
        runner(["systemctl", "daemon-reload"])
        runner(["systemctl", "reset-failed"])
    if had_jail:
        runner(["systemctl", "reload", "fail2ban"])
    if p["user"]:
        if runner(["userdel", USER]) == 0:
            out(f"Removed the {USER} user")
        else:
            errors += 1
            out(f"Could not remove the {USER} user: run userdel {USER}")
    # The folders last: the running program is in /opt/daemonsight.
    for t in p["trees"]:
        path = _under(root, t)
        if path.is_symlink():
            path.unlink()
        else:
            failed: list[str] = []
            shutil.rmtree(path, onerror=lambda _f, name, _e: failed.append(name))
            if failed:
                errors += 1
                out(f"Could not remove everything in {t}")
                continue
        out(f"Removed {t}")
    if not any(p.values()):
        out("Nothing to remove: DaemonSight is not installed here.")
    return 1 if errors else 0


def main(yes: bool, hub_request: bool = False, allowed: bool = False, root: Path = Path("/"),
         runner: Callable[[list[str]], int] = _run) -> int:
    """The command. Without --yes it only lists what it would remove."""
    if hub_request:
        # Started by daemonsight-uninstall.path. Only with a request the root collector wrote, and only when this
        # host's own config still allows it: the request file alone is not enough.
        request = _under(root, f"{DATA}/{REQUEST}")
        if not request.exists():
            return 0
        if not allowed:
            request.unlink(missing_ok=True)
            print("The hub asked this host to uninstall, but allow_remote_uninstall is off or unreadable.",
                  file=sys.stderr)
            return 0
        yes = True
    if root == Path("/") and os.geteuid() != 0:
        print("Run as root: sudo daemonsight uninstall --yes", file=sys.stderr)
        return 1
    p = plan(root)
    if not yes:
        for line in describe(p) or ["Nothing to remove: DaemonSight is not installed here."]:
            print(line)
        if any(p.values()):
            print("\nNothing was changed. Run it again with --yes to remove these.")
        return 0
    if any(p.values()):
        print("Removing:")
        for line in describe(p):
            print("  " + line)
    return run(root, runner)
