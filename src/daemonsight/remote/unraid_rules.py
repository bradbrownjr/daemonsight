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
"""

from __future__ import annotations

from ..findings import Finding, anchor

DISK_FULL_MEDIUM, DISK_FULL_HIGH = 90.0, 95.0
HDD_TEMP_DEFAULT = (45, 55)
SSD_TEMP_DEFAULT = (60, 70)
PARITY_MAX_AGE_DAYS = 100
NOTIFICATIONS_MAX = 10          # findings made from unread warnings and alerts; the rest are one summary
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


def array_rules(a: dict, disks: dict | None) -> list[Finding]:
    out: list[Finding] = []
    models = _models(disks)
    state = a.get("state") or ""
    if state and state != "STARTED":
        sev = "medium" if state == "RECON_DISK" else "high"
        out.append(Finding("unraid.array_state", "array", sev, f"Array state: {state.replace('_', ' ').lower()}",
                           ARRAY_STATE_TEXT.get(state, f"The array's state is {state}, not STARTED.") +
                           f" Change it in {SERVER_HINT}: Main \u2192 Array Operation.",
                           "/disks#array", None, f"state:{state}"))
    thr = a.get("thresholds") or {}
    for d in a.get("disks", []):
        name, link = d["name"], "/disks#" + anchor("disk", d["name"])
        if d["status"] in DISK_STATE_TEXT:
            out.append(Finding("unraid.disk_state", name, "high", f"{name} {DISK_STATE_TEXT[d['status']].split('.')[0]}",
                               f"{_label(d, models)} {DISK_STATE_TEXT[d['status']]}. Status {d['status']}. "
                               "Replace or re-seat the disk in the Unraid web UI (Main).", link, None, f"{name}:{d['status']}"))
        if (d.get("errors") or 0) > 0 and d["kind"] in ("parity", "data", "cache"):
            n = int(d["errors"])
            out.append(Finding("unraid.disk_errors", name, "high", f"{name} has {n} read or write error{'s' if n != 1 else ''}",
                               f"{_label(d, models)} reported {n} unrecoverable error{'s' if n != 1 else ''} to Unraid. "
                               "Check its SMART report (Main \u2192 click the disk) and the cabling.", link, None, f"{name}:{n}"))
        t = d.get("temp")
        if t is not None and d["kind"] in ("parity", "data", "cache"):
            ssd = d.get("rotational") is False
            warn, crit = temp_limits(d, thr)
            if t >= warn:
                high = t >= crit
                src = ("Unraid's default for SSDs (the API doesn't expose it)" if ssd
                       else "Unraid's threshold (Settings \u2192 Disk Settings)")
                out.append(Finding("unraid.disk_temp", name, "high" if high else "medium",
                                   f"{name} is {t:.0f} °C",
                                   f"{_label(d, models)} is at {t:.0f} °C; the {'critical' if high else 'warning'} "
                                   f"level is {crit if high else warn} °C, {src}. Check airflow and fans.",
                                   link, None, f"{name}:{'critical' if high else 'warning'}"))
        pct = d.get("percent")
        if pct is not None and pct >= DISK_FULL_MEDIUM:
            band = "high" if pct >= DISK_FULL_HIGH else "medium"
            out.append(Finding("unraid.disk_full", name, band, f"{name} is {_pct(pct)} full",
                               f"{name} has {fmt_kb(d.get('fs_free_kb'))} free of {fmt_kb(d.get('fs_size_kb'))}. "
                               "Move or delete data, or add capacity. Unraid's mover and split-level settings decide where new files go.",
                               link, None, f"{name}:{band}"))
    cap = a.get("capacity") or {}
    if cap.get("percent") is not None and cap["percent"] >= DISK_FULL_MEDIUM:
        band = "high" if cap["percent"] >= DISK_FULL_HIGH else "medium"
        out.append(Finding("unraid.disk_full", "array", band, f"The array is {_pct(cap['percent'])} full",
                           f"{fmt_kb(cap.get('free_kb'))} free of {fmt_kb(cap.get('total_kb'))} across the array's data disks.",
                           "/disks#array", None, f"array:{band}"))
    out += parity_rules(a)
    return out


def parity_rules(a: dict) -> list[Finding]:
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
        out.append(Finding("unraid.parity_errors", "parity", "high",
                           f"The last parity check found {n} error{'s' if n != 1 else ''}",
                           "Parity didn't match the data in that many 4 KiB blocks. Check the disks' SMART reports and cables, "
                           "then run another check (Main \u2192 Array Operation \u2192 Check).",
                           "/disks#parity", None, f"errors:{int(last['date'])}:{n}"))
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
    if not runs:
        return [Finding("unraid.parity_old", "parity", "low", "No completed parity check on record",
                        "Unraid has no finished parity check in its history. Run one (Main \u2192 Array Operation \u2192 Check) "
                        "and schedule them under Settings \u2192 Scheduler.", "/disks#parity", None, "never")]
    age = (now - max(runs)) / 86400
    if age > PARITY_MAX_AGE_DAYS:
        return [Finding("unraid.parity_old", "parity", "low", f"The last parity check was {age:.0f} days ago",
                        f"Unraid's docs advise a correcting check every month or quarter. Run one (Main, Array Operation, "
                        "Check) and schedule them under Settings \u2192 Scheduler.", "/disks#parity", None, "old")]
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
                           "UNKNOWN, and a disk that predicts its own failure also shows as UNKNOWN. Open its SMART report "
                           "(Main \u2192 click the disk). If the disk simply has no SMART data, accept this finding with a note.",
                           "/disks#" + anchor("disk", d["name"]), None, d["name"]))
    return out


def container_rules(dk: dict | None) -> list[Finding]:
    out = []
    for c in (dk or {}).get("containers", []):
        if c.get("update") is True and c["name"]:
            out.append(Finding("unraid.container_update", c["name"], "low", f"An update is available for {c['name']}",
                               f"Unraid says a newer image of {c['image']} exists. Update it from the Docker tab in "
                               f"{SERVER_HINT}; DaemonSight only reads.", "/containers#" + anchor("ctr", c["name"]),
                               None, c["name"]))
    return out


def notification_rules(n: dict | None) -> list[Finding]:
    if not n:
        return []
    items = sorted(n.get("items", []), key=lambda i: (i["importance"] != "ALERT", -(i["time"] or 0)))
    out = []
    for i in items[:NOTIFICATIONS_MAX]:
        sev = "medium" if i["importance"] == "ALERT" else "low"
        out.append(Finding("unraid.notification", i["id"][:200], sev,
                           f"Unraid {i['importance'].lower()}: {i['title'] or 'notification'}",
                           i["subject"] or "Unraid raised an unread notification. Read it in the Unraid web UI.",
                           "/notifications#" + anchor("notif", i["id"][:60]), None, i["id"][:200]))
    more = len(items) - NOTIFICATIONS_MAX
    if more > 0:
        out.append(Finding("unraid.notification", "more", "low", f"{more} more unread warnings and alerts",
                           "Unraid has more unread warnings and alerts than are listed as findings here. Read and archive "
                           "them in the Unraid web UI.", "/notifications", None, "more"))
    return out


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
                               + (f", about {int(d['runtime'] // 60)} min left" if d.get("runtime") else "") +
                               ". Check mains power to the UPS.", "/#ups", None, f"{d['id'] or name}:power"))
        if state == "REPLACEBATT" or d.get("health") == "Replace":
            out.append(Finding("unraid.ups", f"{d['id'] or name}:battery", "low", f"{name} battery needs replacing",
                               "The UPS reports its battery should be replaced.", "/#ups", None, f"{d['id'] or name}:battery"))
    return out


def evaluate(data: dict[str, dict | None], now: float) -> list[Finding]:
    """`data` maps short source names (system, array, disks, docker, vms,
    notifications, ups) to their latest stored data, or None."""
    a = data.get("array")
    out: list[Finding] = []
    if a:
        out += array_rules(a, data.get("disks"))
        out += parity_age_rule(a, now)
        out += smart_rules(a, data.get("disks"))
    out += container_rules(data.get("docker"))
    out += notification_rules(data.get("notifications"))
    out += ups_rules(data.get("ups"))
    return out
