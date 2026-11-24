"""Findings from what the hub has read from an Unraid server.

Pure functions of the stored snapshots, like findings.py: `evaluate` takes
each source's latest data and returns the findings that hold now; the poller
makes the open `unraid.*` findings match. Links are paths on the host's own
pages (`/disks#disk-disk1`); the page code adds the `/h/<host>` prefix.

Thresholds and where they come from:

* Disk usage: 90% medium, 95% high, as agreed for DaemonSight. (Unraid's own
  default usage thresholds are 70% and 90%: Settings \u2192 Disk Settings.)
* Disk temperature: Unraid's own thresholds, read through `display { hot max }`
  (Settings \u2192 Disk Settings, "Default warning/critical disk temperature
  threshold", stored in degrees C). The API doesn't expose the SSD thresholds
  (`hotssd`, `maxssd`), so SSDs and NVMe disks use Unraid's shipped defaults,
  60 and 70 C, and HDDs fall back to 45 and 55 C if `display` is unreadable.
  Source: emhttp/plugins/dynamix/default.cfg and DiskSettings.page in
  https://github.com/unraid/webgui. A disk with its own threshold set in
  Unraid isn't seen; the API has no field for it.
* Last parity check older than 100 days. Unraid's docs: "It's advisable to
  perform automated, correcting checks on a monthly or quarterly basis"
  (https://docs.unraid.net/unraid-os/using-unraid-to/manage-storage/array/array-health-and-maintenance/).
* The API's `numReads` and `numWrites` count I/O requests, not failures
  (schema: "Count of I/O read requests sent to the device I/O drivers"), so
  only `numErrors` counts as an error.
* `smartStatus` is OK or UNKNOWN only: the API maps anything else, including
  a failing disk's "Predicted Failure", to UNKNOWN (disks.service.ts).

Where the "What to do" steps get their menu paths (Unraid docs, https://docs.unraid.net/unraid-os/):

* Main, Array Operation, Check, and "Write corrections to parity"; sync errors counted in 4 KiB blocks, only the
  first 100 addresses logged; the automatic check after an unsafe shutdown set under Settings, Scheduler, Parity
  Check: using-unraid-to/manage-storage/array/array-health-and-maintenance/
* Settings, Syslog Server ("Mirror syslog to boot drive", remote and local syslog server); Settings, UPS Settings;
  Memtest86+ in the boot menu: troubleshooting/diagnostics/capture-diagnostics-and-logs/,
  troubleshooting/common-issues/unclean-shutdowns/ and troubleshooting/common-issues/system-crashes-and-stability/
* Shares, click a share: Allocation method, Split level, Minimum free space; existing files don't move when they
  change; split level beats free space: using-unraid-to/manage-storage/shares/
* SMART report from Main (click the disk's name), what the attributes mean: system-administration/monitor-performance/
  smart-reports-and-disk-health/
* Replacing a disk: using-unraid-to/manage-storage/array/replacing-disks-in-array/; "check SMART before a rebuild":
  the array health page above
* Docker tab buttons "Check for Updates", "Update All" and "Container Size": webgui
  emhttp/plugins/dynamix.docker.manager/DockerContainers.page; "Docker vDisk size": DockerSettings.page
* Settings, Disk Settings (temperature thresholds): webgui DiskSettings.page
* Tools, Update OS (the page is `Update.page`, title "Update OS", notice link `/Tools/Update`), and the release source:
  release.py. Boot device backup: system-administration/secure-your-server/secure-your-boot-drive/
"""

from __future__ import annotations

import time

from ..findings import Finding, anchor
from . import docker_images, docker_storage, release, unraid_notify

DISK_FULL_MEDIUM, DISK_FULL_HIGH = 90.0, 95.0
HDD_TEMP_DEFAULT = (45, 55)
SSD_TEMP_DEFAULT = (60, 70)
PARITY_MAX_AGE_DAYS = 100
UPS_LOW_CHARGE = 50
UPS_CRITICAL_CHARGE = 30

SERVER_HINT = "the Unraid web UI"

# ArrayDiskStatus values that mean something is wrong (schema enum ArrayDiskStatus).
DISK_STATE_TEXT = {
    "DISK_DSBL": "is disabled. Unraid emulates its contents from parity until it is replaced or rebuilt",
    "DISK_NP_DSBL": "is disabled and not present. Unraid emulates its contents from parity",
    "DISK_DSBL_NEW": "is a new disk in a disabled slot",
    "DISK_NP_MISSING": "is missing. Unraid emulates its contents from parity",
    "DISK_INVALID": "has invalid contents",
    "DISK_WRONG": "is not the disk assigned to this slot",
}
ARRAY_STATE_TEXT = {
    "STOPPED": "The array is stopped. Shares, Docker containers and VMs that use it are offline.",
    "RECON_DISK": "The array is reconstructing a disk (a rebuild or a parity sync).",
    "DISABLE_DISK": "The array has a disabled disk.",
    "NEW_ARRAY": "The array is new and has not been started.",
    "INVALID_EXPANSION": "The array's disk assignments are not valid.",
    "PARITY_NOT_BIGGEST": "The parity disk is not the largest disk.",
    "TOO_MANY_MISSING_DISKS": "More disks are missing than parity can cover.",
    "NEW_DISK_TOO_SMALL": "A new disk is smaller than the disk it replaces.",
    "NO_DATA_DISKS": "The array has no data disks.",
}


def steps(*lines: str) -> str:
    """A howto: one step per line."""
    return "\n".join(lines)



def _pct(v: float) -> str:
    return f"{v:.0f}%"


def fmt_kb(v) -> str:
    if v is None:
        return "?"
    n = float(v) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def _models(disks: dict | None) -> dict[str, dict]:
    return {d["device"]: d for d in (disks or {}).get("disks", []) if d.get("device")}


def _label(d: dict, models: dict[str, dict]) -> str:
    m = models.get(d.get("device") or "")
    extra = " ".join(x for x in (d.get("device"), (m or {}).get("model")) if x)
    return f"{d['name']} ({extra})" if extra else d["name"]


def temp_limits(d: dict, thresholds: dict | None) -> tuple[int, int]:
    """(warning, critical) in degrees C for one disk: see the module doc."""
    if d.get("rotational") is False:
        return SSD_TEMP_DEFAULT
    thr = thresholds or {}
    return (thr.get("hot") or HDD_TEMP_DEFAULT[0], thr.get("max") or HDD_TEMP_DEFAULT[1])


HOWTO_ARRAY = {
    "STOPPED": steps(
        "Start the array in Main → Array Operation, if it should be running",
        "If it won't start, the messages under Main → Array Operation say why (a missing disk, a license problem)",
        "Shares, Docker containers and VMs that use the array stay offline until it starts"),
    "RECON_DISK": steps(
        "Let it finish: Main → Array Operation shows the progress",
        "Don't reboot or stop the array while it runs",
        "The finding goes away when the reconstruction ends"),
}
HOWTO_ARRAY_OTHER = steps(
    "Open Main → Array Operation and read the message there",
    "A disabled or missing disk is the usual cause: see the finding for that disk",
    "If you are unsure, ask on the Unraid forums before starting or stopping anything")

HOWTO_DISK_STATE = steps(
    "Unraid is emulating this disk from parity, or it can't read it. The data is still there if parity is good, but is not protected until this is fixed",
    "Check the disk's SMART report and its cables first (Main, then click the disk's name); also check the other disks' SMART reports, since a rebuild stresses every disk",
    "Then re-seat or replace the disk and rebuild it, following Unraid's guide: Replacing disks in array",
    "Don't stop the array or reboot mid-rebuild")

HOWTO_DISK_ERRORS = steps(
    "Open the disk's SMART report (Main, then click the disk's name)",
    "Check the disk's data and power cables and re-seat them",
    "If the error count keeps growing, or the SMART reallocated, pending or uncorrectable counts rise, back up the disk and plan to replace it")

HOWTO_DISK_TEMP = steps(
    "Check airflow: fans running, filters and the disk's cage free of dust, nothing blocking the case",
    "A hot disk is worse in a long parity check or rebuild; let it cool before starting one",
    "The warning and critical levels are set in Settings → Disk Settings")

HOWTO_DISK_SMART = steps(
    "Open the disk's SMART report (Main, then click the disk's name)",
    "If reallocated, pending or uncorrectable sector counts are rising, back up the disk and plan to replace it",
    "If the disk has no SMART data (some controllers and enclosures give none), accept this finding with a note")

HOWTO_DISK_FULL = steps(
    "Where new files go is decided by each share's settings: Shares, click a share, then Allocation method, Split level and Minimum free space",
    "Set Minimum free space above your largest file, so Unraid stops writing to a disk that is nearly full",
    "A strict Split level can keep writing to a full disk, because Unraid follows the split level before the free space setting",
    "Changing a setting affects only new files. Move or delete data already on the disk, or add capacity")
HOWTO_ARRAY_FULL = steps(
    "Delete or move data you no longer need, or add a disk (Unraid's guide: Adding disks to array)",
    "Check which shares hold the most data on the Shares tab")

HOWTO_PARITY_ERRORS = steps(
    "If this check came after an unclean shutdown (a crash or a power loss), a few corrected errors are expected",
    "To confirm parity is good now, run a check without corrections: Main → Array Operation, untick Write corrections to parity, press Check. Zero errors means it is",
    "If errors come back with no crash or power loss in between, check the SMART report and the cables of every array disk, then check again")

HOWTO_PARITY_OLD = steps(
    "Start a check now: Main → Array Operation → Check (leave Write corrections to parity ticked for a correcting check)",
    "Schedule one every month or quarter in Settings → Scheduler → Parity Check",
    "If a started check stops early, find out why: a reboot, a stopped array or a schedule setting")

HOWTO_UPS_POWER = steps(
    "Check mains power to the UPS and the cable from the UPS to the server",
    "Make sure Unraid shuts down cleanly before the battery runs out: Settings → UPS Settings has the battery runtime and charge thresholds",
    "If the power is back, the finding goes away once the UPS reports online and charged")
HOWTO_UPS_BATTERY = steps(
    "Replace the UPS battery with one the UPS maker lists for the model",
    "Until then the server may not survive a power cut: Settings → UPS Settings has the shutdown thresholds")

HOWTO_CONTAINER_UPDATES = steps(
    "In the Unraid web UI, open the Docker tab and press Check for Updates",
    "Update the containers you want one at a time, or press Update All",
    "Images tagged :latest or :edge change often, so some of these come back soon. A container pinned to a version tag never shows an update here: check those by hand")


def array_rules(a: dict, disks: dict | None, crashes: list[float] = ()) -> list[Finding]:
    out: list[Finding] = []
    models = _models(disks)
    state = a.get("state") or ""
    if state and state != "STARTED":
        sev = "medium" if state == "RECON_DISK" else "high"
        out.append(Finding("unraid.array_state", "array", sev, f"Array state: {state.replace('_', ' ').lower()}",
                           ARRAY_STATE_TEXT.get(state, f"The array's state is {state}, not STARTED.") +
                           f" Change it in {SERVER_HINT}: Main → Array Operation.",
                           "/disks#array", None, f"state:{state}", HOWTO_ARRAY.get(state, HOWTO_ARRAY_OTHER)))
    thr = a.get("thresholds") or {}
    for d in a.get("disks", []):
        name, link = d["name"], "/disks#" + anchor("disk", d["name"])
        if d["status"] in DISK_STATE_TEXT:
            out.append(Finding("unraid.disk_state", name, "high", f"{name} {DISK_STATE_TEXT[d['status']].split('.')[0]}",
                               f"{_label(d, models)} {DISK_STATE_TEXT[d['status']]}. Status {d['status']}.",
                               link, None, f"{name}:{d['status']}", HOWTO_DISK_STATE))
        if (d.get("errors") or 0) > 0 and d["kind"] in ("parity", "data", "cache"):
            n = int(d["errors"])
            out.append(Finding("unraid.disk_errors", name, "high", f"{name} has {n} read or write error{'s' if n != 1 else ''}",
                               f"{_label(d, models)} reported {n} unrecoverable error{'s' if n != 1 else ''} to Unraid.",
                               link, None, f"{name}:{n}", HOWTO_DISK_ERRORS))
        t = d.get("temp")
        if t is not None and d["kind"] in ("parity", "data", "cache"):
            ssd = d.get("rotational") is False
            warn, crit = temp_limits(d, thr)
            if t >= warn:
                high = t >= crit
                src = ("Unraid's default for SSDs (the API doesn't expose it)" if ssd
                       else "Unraid's threshold (Settings → Disk Settings)")
                out.append(Finding("unraid.disk_temp", name, "high" if high else "medium",
                                   f"{name} is {t:.0f} °C",
                                   f"{_label(d, models)} is at {t:.0f} °C; the {'critical' if high else 'warning'} "
                                   f"level is {crit if high else warn} °C, {src}.",
                                   link, None, f"{name}:{'critical' if high else 'warning'}", HOWTO_DISK_TEMP))
        pct = d.get("percent")
        if pct is not None and pct >= DISK_FULL_MEDIUM:
            band = "high" if pct >= DISK_FULL_HIGH else "medium"
            out.append(Finding("unraid.disk_full", name, band, f"{name} is {_pct(pct)} full",
                               f"{name} has {fmt_kb(d.get('fs_free_kb'))} free of {fmt_kb(d.get('fs_size_kb'))}.",
                               link, None, f"{name}:{band}", HOWTO_DISK_FULL))
    cap = a.get("capacity") or {}
    if cap.get("percent") is not None and cap["percent"] >= DISK_FULL_MEDIUM:
        band = "high" if cap["percent"] >= DISK_FULL_HIGH else "medium"
        out.append(Finding("unraid.disk_full", "array", band, f"The array is {_pct(cap['percent'])} full",
                           f"{fmt_kb(cap.get('free_kb'))} free of {fmt_kb(cap.get('total_kb'))} across the array's data disks.",
                           "/disks#array", None, f"array:{band}", HOWTO_ARRAY_FULL))
    out += parity_rules(a, crashes)
    return out


def _span(seconds) -> str:
    s = int(seconds or 0)
    if s < 120:
        return f"{s} seconds"
    if s < 7200:
        return f"{s // 60} minutes"
    if s < 172800:
        return f"{s // 3600} hours"
    return f"{s // 86400} days"


def _utc(ts: float, minutes: bool = False) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC" if minutes else "%Y-%m-%d", time.gmtime(ts))


def _stopped_after(a: dict, after: float) -> list[dict]:
    """Checks in the history that were cancelled or failed after `after`, newest first. A history entry's
    `date` is when the check ended (it matches the finish notice within seconds on the server read)."""
    return [h for h in a.get("parity_history", []) if h.get("status") in ("CANCELLED", "FAILED") and (h.get("date") or 0) > after]


def _stopped_text(h: dict) -> str:
    ended, dur = h["date"], h.get("duration")
    how = "failed" if h.get("status") == "FAILED" else "was cancelled"
    after = f" after {_span(dur)}" if dur is not None else ""
    if dur is not None and dur < 86400:
        return f"A check started {_utc(ended - dur, True)} and {how}{after}, so it doesn't count."
    return f"A check {how}{after} on {_utc(ended)}, so it doesn't count."


def parity_rules(a: dict, crashes: list[float] = ()) -> list[Finding]:
    if not any(d["kind"] == "parity" for d in a.get("disks", [])) or a.get("state") != "STARTED":
        return []
    out = []
    pc = a.get("parity_check") or {}
    runs = [h for h in a.get("parity_history", []) if h.get("status") == "COMPLETED" and h.get("date")]
    if pc.get("status") == "COMPLETED" and pc.get("date") and pc["date"] not in {h["date"] for h in runs}:
        runs.append(pc)
    last = max(runs, key=lambda h: h["date"], default=None)
    if last and (last.get("errors") or 0) > 0:
        n = int(last["errors"])
        start = last["date"] - (last.get("duration") or 0)
        crash = max((t for t in crashes if start - 7 * 86400 <= t <= last["date"]), default=None)
        stopped = _stopped_after(a, last["date"])
        parts = [f"The check that ended on {_utc(last['date'])} found {n} sync error{'s' if n != 1 else ''}. "
                 "A sync error means the parity disk and the data disks disagreed in one 4 KiB block. A correcting check "
                 "rewrites parity to match the data; a non-correcting one only counts them."]
        if crash:
            parts.append(f"Unraid recorded an unclean shutdown on {_utc(crash)}, shortly before this check; that is the usual cause.")
        parts.append(_stopped_text(stopped[0]) if stopped else "No check has finished since.")
        parts.append("Unraid logs the sector numbers of only the first 100 errors, and only in its syslog for the boot the check ran in. "
                     "A crash loses that log unless it was mirrored to the boot drive or sent to a syslog server.")
        out.append(Finding("unraid.parity_errors", "parity", "high",
                           f"The last parity check found {n} error{'s' if n != 1 else ''}", " ".join(parts),
                           "/disks#parity", None, f"errors:{int(last['date'])}:{n}", HOWTO_PARITY_ERRORS))
    return out


def parity_age_rule(a: dict, now: float) -> list[Finding]:
    if not any(d["kind"] == "parity" for d in a.get("disks", [])) or a.get("state") != "STARTED":
        return []
    pc = a.get("parity_check") or {}
    if pc.get("running"):
        return []
    runs = [h["date"] for h in a.get("parity_history", []) if h.get("status") == "COMPLETED" and h.get("date")]
    if pc.get("status") == "COMPLETED" and pc.get("date"):
        runs.append(pc["date"])
    stopped = _stopped_after(a, max(runs, default=0))
    note = (" " + _stopped_text(stopped[0])) if stopped else ""
    if not runs:
        return [Finding("unraid.parity_old", "parity", "low", "No completed parity check on record",
                        "Unraid has no finished parity check in its history." + note, "/disks#parity", None, "never",
                        HOWTO_PARITY_OLD)]
    age = (now - max(runs)) / 86400
    if age > PARITY_MAX_AGE_DAYS:
        return [Finding("unraid.parity_old", "parity", "low", f"The last parity check was {age:.0f} days ago",
                        f"The last check that finished ended on {_utc(max(runs))}. Unraid's docs advise a correcting check "
                        "every month or quarter." + note, "/disks#parity", None, "old", HOWTO_PARITY_OLD)]
    return []


def smart_rules(a: dict | None, disks: dict | None) -> list[Finding]:
    """A disk in the array whose SMART status isn't OK. The API can't tell
    "failing" from "no SMART data": both are UNKNOWN."""
    out = []
    models = _models(disks)
    for d in (a or {}).get("disks", []):
        m = models.get(d.get("device") or "")
        if not m or d["kind"] not in ("parity", "data", "cache") or m["interface"] == "USB" or m["smart"] == "OK":
            continue
        out.append(Finding("unraid.disk_smart", d["name"], "medium", f"{d['name']}: SMART status is not OK",
                           f"{_label(d, models)} reports SMART status {m['smart'] or 'UNKNOWN'}. Unraid's API reports only OK or "
                           "UNKNOWN, and a disk that predicts its own failure also shows as UNKNOWN.",
                           "/disks#" + anchor("disk", d["name"]), None, d["name"], HOWTO_DISK_SMART))
    return out


CONTAINERS_LISTED = 40


def container_rules(dk: dict | None) -> list[Finding]:
    """One finding for every container Unraid says has a newer image. The old rule made one per container."""
    names = sorted((c["name"] for c in (dk or {}).get("containers", []) if c.get("update") is True and c["name"]),
                   key=str.lower)
    if not names:
        return []
    n = len(names)
    listed = ", ".join(names[:CONTAINERS_LISTED]) + (f" and {n - CONTAINERS_LISTED} more" if n > CONTAINERS_LISTED else "")
    return [Finding("unraid.container_updates", "all", "low",
                    f"{n} containers have updates" if n != 1 else "1 container has an update",
                    f"Unraid says a newer image exists for: {listed}. DaemonSight only reads; update them in {SERVER_HINT}.",
                    "/containers", None, ",".join(names), HOWTO_CONTAINER_UPDATES)]


def notification_rules(n: dict | None) -> list[Finding]:
    return unraid_notify.notification_findings(n)


def _ups_state(status: str) -> str:
    return "".join(ch for ch in status.upper() if ch.isalpha())


def ups_rules(u: dict | None) -> list[Finding]:
    out = []
    for d in (u or {}).get("devices", []):
        state, charge = _ups_state(d["status"]), d.get("charge")
        name = d["name"] or d["id"] or "UPS"
        on_batt = "ONBATT" in state or "ONBATTERY" in state
        low = "LOWBATT" in state or "LOWBATTERY" in state
        if low or (on_batt and charge is not None and charge <= UPS_CRITICAL_CHARGE):
            sev, title = "high", f"{name} is on battery and low"
        elif on_batt:
            sev, title = "medium", f"{name} is running on battery"
        elif charge is not None and charge < UPS_LOW_CHARGE:
            sev, title = "medium", f"{name} battery is at {charge}%"
        else:
            sev = None
        if sev:
            out.append(Finding("unraid.ups", d["id"] or name, sev, title,
                               f"UPS status {d['status'] or 'unknown'}, charge {charge if charge is not None else '?'}%"
                               + (f", about {int(d['runtime'] // 60)} min left" if d.get("runtime") else "") + ".",
                               "/#ups", None, f"{d['id'] or name}:power", HOWTO_UPS_POWER))
        if state == "REPLACEBATT" or d.get("health") == "Replace":
            out.append(Finding("unraid.ups", f"{d['id'] or name}:battery", "low", f"{name} battery needs replacing",
                               "The UPS reports its battery should be replaced.", "/#ups", None,
                               f"{d['id'] or name}:battery", HOWTO_UPS_BATTERY))
    return out


def os_update_rule(system: dict | None, rel: dict | None) -> list[Finding]:
    """unraid.os_update (Low): the newest stable release is newer than the version the API reports.
    The release comes from release.py (a public page, once a day)."""
    cur = (system or {}).get("version")
    if not release.newer(rel, cur):
        return []
    new = rel["version"]
    notes = rel.get("notes") or f"https://docs.unraid.net/unraid-os/release-notes/{new}/"
    when = f" on {rel['date']}" if rel.get("date") else ""
    return [Finding("unraid.os_update", "os", "low", f"Unraid {new} is available (running {cur})",
                    f"Unraid {new} was released{when}. This server runs {cur}. Release notes: {notes}",
                    "/#os", None, new, steps(
                        f"Read the release notes first: {notes}",
                        "Back up the boot device: Main, then Boot Device (called Flash before Unraid 7.3.0), then Boot Device Backup",
                        "Open Tools \u2192 Update OS and install the update",
                        "The update takes effect after a reboot: pick a time when VMs and containers can stop"))]


def evaluate(data: dict[str, dict | None], now: float) -> list[Finding]:
    """`data` maps short source names (system, array, disks, docker, vms,
    notifications, ups, docker_storage) to their latest stored data, or None."""
    a = data.get("array")
    out: list[Finding] = []
    if a:
        out += array_rules(a, data.get("disks"), unraid_notify.unclean_times(data.get("notifications")))
        out += parity_age_rule(a, now)
        out += smart_rules(a, data.get("disks"))
    out += container_rules(data.get("docker"))
    out += notification_rules(data.get("notifications"))
    out += ups_rules(data.get("ups"))
    out += os_update_rule(data.get("system"), data.get("release"))
    out += docker_storage.evaluate(data.get("docker_storage"), data.get("docker"))
    out += docker_images.evaluate(data.get("docker_storage"), data.get("docker"), data.get("image_cves"), prior=data.get("prior"))
    return out
