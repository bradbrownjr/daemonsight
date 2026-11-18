"""What DaemonSight does with Unraid's unread warnings and alerts.

Unraid's inbox mixes three things: notices about conditions DaemonSight
already checks live (disk usage, temperature, parity checks), notices about
one event (an unclean shutdown), and everything else. Each notification is
classified once, by `classify`, from the table below; the findings and the
Notifications page both use the result, so they cannot disagree.

Where the title and subject formats come from (read, not guessed):

* Unraid's own monitor script, `emhttp/plugins/dynamix/scripts/monitor` in
  https://github.com/unraid/webgui: "Unraid <disk> disk utilization",
  "Unraid <disk> temperature", "Unraid <disk> SMART health [<id>]",
  "Unraid <disk> error", "Unraid array errors", and for array operations
  "Unraid <Parity-Check|Parity-Sync|Read-Check|Data-Rebuild|Disk-Clear>"
  with the subject "Notice [server] - <operation> started|finished (N errors)";
  "Docker high|critical image disk utilization".
* The Docker update script, `dynamix.docker.manager/scripts/dockerupdate`:
  title "Docker - <container> [<new version>]", subject "Notice [server] -
  Version update ...", importance normal (so it is not in the unread
  warnings and alerts; the pattern is here so it is covered if a version sends
  it as one).
* The Parity Check Tuning plugin, `parity.check.tuning.php` in
  https://github.com/itimpi/parity.check.tuning: title "Parity Check Tuning" (or
  "Parity Problem Assistant"), subject "[server] <Automatic|Manual> <Correcting|
  Non-Correcting> Parity-Check finished|canceled (N errors)" and, for a crash,
  "[server] Unclean shutdown detected" with the description "System crashed" or
  "Unable to stop array".
* Fix Common Problems, `scripts/scan.php` in
  https://github.com/Squidly271/fix.common.problems: title "Fix Common
  Problems - <server>", description "Investigate at Settings / User Utilities /
  Fix Common Problems".

Every pattern was also checked against the unread inbox of a real Unraid 7.3
server (235 warnings and alerts, read-only). The text of a notification is the
server's and untrusted: parse_notifications cuts it, and it is shown only
through escaped templates.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from ..findings import Finding, anchor

SEE_SYSLOG = ("Open Settings → Syslog Server and turn on Mirror syslog to boot drive, or send the log to a syslog "
              "server or a share. Unraid keeps its log in RAM, so a crash loses it")


@dataclass(frozen=True)
class Kind:
    """A class of notification. `covered_by` names the live check that makes a
    finding from it unnecessary (the notification is not listed as a finding);
    None means the notification is part of a finding."""
    key: str
    label: str                       # shown on the Notifications page
    covered_by: str | None = None
    howto: tuple[str, ...] = ()


ARCHIVE = "Archive the alert in Unraid once you have dealt with it (the bell icon); it then drops out of this finding"
READ_IT = "Read it in Unraid (the bell icon) and archive it once it is handled"

KINDS = {k.key: k for k in (
    # --- covered by a live check: not a finding ---
    Kind("disk_usage", "Disk usage alert", "unraid.disk_full"),
    Kind("disk_temp", "Disk temperature alert", "unraid.disk_temp"),
    Kind("parity_run", "Parity check or sync notice", "unraid.parity_errors, unraid.parity_old"),
    Kind("array_job", "Rebuild or disk clear notice", "unraid.array_state"),
    Kind("container_update", "Docker update notice", "unraid.container_updates"),
    # --- its own rule ---
    Kind("unclean_shutdown", "Unclean shutdown", None),
    # --- findings, one per distinct title ---
    Kind("fcp", "Fix Common Problems", None, (
        "Open Settings → User Utilities → Fix Common Problems. It lists each error and warning it found",
        "Fix each item there, or mark the ones you accept as ignored in that plugin",
        ARCHIVE)),
    Kind("smart", "Disk SMART attribute", None, (
        "Open the disk's SMART report (Main, then click the disk's name)",
        "If the reallocated, pending or uncorrectable counts keep rising, back up the disk's data and plan to replace it",
        "For a CRC error count, re-seat the disk's data cable",
        "Acknowledge the change on the Dashboard (the orange icon beside the disk); Unraid warns again only if the value changes",
        ARCHIVE)),
    Kind("disk_error", "Disk in error state", None, (
        "Open Main and look at the disk's status. A disabled disk is emulated from parity until it is replaced or rebuilt",
        "Check its SMART report and cables before rebuilding (Unraid's advice: check drive health before any rebuild)",
        ARCHIVE)),
    Kind("array_errors", "Array read errors", None, (
        "Open Main and look at the Errors column to find the disk with read or write errors",
        "Check that disk's SMART report and its cables; a disk whose errors keep growing should be replaced",
        ARCHIVE)),
    Kind("docker_image", "Docker image disk", None, (
        "Open the Docker tab and press Container Size to see which containers are largest",
        "Check that containers keep their data in appdata, not inside the image",
        "If the image is simply too small, raise Docker vDisk size in Settings → Docker (stop Docker first)",
        ARCHIVE)),
    Kind("parity_tuning", "Parity Check Tuning", None, (
        "Open Settings → Scheduler → Parity Check to see how the plugin is set up",
        READ_IT)),
    Kind("other", "Other notification", None, (READ_IT,)),
)}

# First match wins: (kind, title pattern, subject pattern or None).
PATTERNS = (
    ("disk_usage", r"^Unraid .+ disk utilization$", None),
    ("disk_temp", r"^Unraid .+ temperature$", None),
    ("parity_run", r"^Unraid (Parity[ -][Cc]heck|Parity-Sync|Read-Check)$", None),
    ("array_job", r"^Unraid (Data-Rebuild|Disk-Clear)$", None),
    ("parity_run", r"^Parity (Check Tuning|Problem Assistant)$",
     r"\b(Parity-Check|Parity-Sync|Read-Check|Data-Rebuild)\s+(finished|canceled|cancelled|aborted)\b"),
    ("container_update", r"^Docker - .+ \[.+\]$", r"Version update"),
    ("unclean_shutdown", r".", r"Unclean shutdown detected\s*$"),
    ("fcp", r"^Fix Common Problems\b", None),
    ("smart", r"^Unraid .+ SMART health \[\d+\]$", None),
    ("array_errors", r"^Unraid array errors$", None),
    ("disk_error", r"^Unraid .+ error$", None),
    ("docker_image", r"^Docker (high|critical) image disk utilization$", None),
    ("parity_tuning", r"^Parity (Check Tuning|Problem Assistant)$", None),
)
_COMPILED = tuple((k, re.compile(t), re.compile(s) if s else None) for k, t, s in PATTERNS)


def classify(item: dict) -> Kind:
    title, subject = item.get("title") or "", item.get("subject") or ""
    for key, tre, sre in _COMPILED:
        if tre.search(title) and (sre is None or sre.search(subject)):
            return KINDS[key]
    return KINDS["other"]


def day(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "an unknown date"


def _sentence(s: str) -> str:
    s = (s or "").strip()
    return s if not s or s[-1] in ".!?" else s + "."


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def disposition(item: dict) -> tuple[str, str]:
    """(state, text) for the Notifications page: "finding" or "covered"."""
    k = classify(item)
    if k.covered_by:
        return "covered", f"Covered by a live check ({k.covered_by}); not a finding"
    if k.key == "unclean_shutdown":
        return "finding", "In the finding about unclean shutdowns"
    return "finding", "In a finding, grouped with others of the same title"


# --- findings ---------------------------------------------------------------------------------------------------

def unclean_times(n: dict | None) -> list[float]:
    """When Unraid recorded an unclean shutdown (the parity rules use it as a cause)."""
    return sorted(i["time"] for i in (n or {}).get("items", []) if i.get("time") and classify(i).key == "unclean_shutdown")


UNCLEAN_HOWTO = (
    "An unclean shutdown means Unraid was not stopped properly: a crash, a power loss or a forced power-off",
    "Unraid starts a parity check on the next boot. If it finds and corrects a few sync errors after a crash, that is expected",
    SEE_SYSLOG + ". Next time the log that explains the crash is still there",
    "Check the UPS (Settings → UPS Settings) and the power feeding the server; power loss is the most common cause. "
    "If crashes repeat with steady power, test the RAM with Memtest86+ from the boot menu",
    ARCHIVE,
)


def unclean_finding(items: list[dict]) -> Finding | None:
    if not items:
        return None
    n = len(items)
    times = sorted(i["time"] for i in items if i.get("time"))
    first = day(times[0]) if times else None
    title = f"Unraid shut down uncleanly {n} time{'s' if n != 1 else ''}" + (f" since {first}" if first else "")
    shown = [day(t) for t in reversed(times)]
    listed = ", ".join(shown[:20]) + (f" and {len(shown) - 20} more" if len(shown) > 20 else "")
    newest = max(items, key=lambda i: i.get("time") or 0)
    why = _sentence(newest.get("description") or "")
    detail = (f"Unraid recorded {n} unclean shutdown alert{'s' if n != 1 else ''}"
              + (f", from {first} to {day(times[-1])}" if len(times) > 1 else (f", from {first}" if first else ""))
              + (f": {listed}." if listed else ".")
              + (f" The newest says: {why}" if why else ""))
    basis = ",".join(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) for t in times) or f"count:{n}"
    link = "/notifications#" + anchor("notif", newest["id"][:60])
    return Finding("unraid.unclean_shutdown", "unclean", "medium", title, detail[:900], link, None, basis[:1500],
                   "\n".join(UNCLEAN_HOWTO))


def _group_finding(entries: list[dict], kind: Kind) -> Finding:
    entries = sorted(entries, key=lambda i: -(i.get("time") or 0))
    new = entries[0]
    alert = next((i for i in entries if i["importance"] == "ALERT"), None)
    level = "alert" if alert else "warning"
    title = new["title"] or "notification"
    body = _sentence(new["subject"]) or "Unraid raised an unread notification."
    if new.get("description"):
        body += " " + _sentence(new["description"])
    n = len(entries)
    if n == 1:
        body += f" From {day(new.get('time'))}."
    else:
        body += (f" {n} unread with this title; newest from {day(new.get('time'))}, "
                 f"oldest from {day(entries[-1].get('time'))}.")
        if alert and alert is not new and alert["subject"] != new["subject"]:
            body += f" The most serious: {_sentence(alert['subject'])[:150]} (from {day(alert.get('time'))})."
    basis = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(new["time"])) if new.get("time") else new["id"][:200]
    return Finding("unraid.notification", title[:200], "medium" if alert else "low", f"Unraid {level}: {title}",
                   body[:900], "/notifications#" + anchor("notif", new["id"][:60]), None, basis,
                   "\n".join(kind.howto))


def notification_findings(n: dict | None) -> list[Finding]:
    if not n:
        return []
    items = n.get("items", [])
    unread = n.get("unread") or {}
    alerts, warnings = unread.get("alert") or 0, unread.get("warning") or 0
    total = alerts + warnings or len(items)
    out: list[Finding] = []
    covered, groups, crashes = 0, {}, []
    for i in items:
        k = classify(i)
        if k.covered_by:
            covered += 1
        elif k.key == "unclean_shutdown":
            crashes.append(i)
        else:
            groups.setdefault(i["title"] or "(no title)", ([], k))[0].append(i)
    unclean = unclean_finding(crashes)
    if unclean:
        out.append(unclean)
    out += [_group_finding(entries, k) for entries, k in groups.values()]
    if total:
        listed = len(groups)
        bits = []
        if alerts or warnings:
            bits.append(f"{alerts} alert{'s' if alerts != 1 else ''} and {warnings} warning{'s' if warnings != 1 else ''}")
        detail = (f"Unraid has {total} unread {_plural(total, 'alert or warning', 'alerts and warnings')}"
                  + (f" ({bits[0]})" if bits else "") + ". "
                  + (f"{covered} of them are about disk usage, temperature, parity checks or container updates, which "
                     "DaemonSight checks live, so they are not findings of their own. " if covered else "")
                  + (f"The rest are findings of their own, one per kind of alert ({listed + (1 if unclean else 0)}). "
                     if listed or unclean else "")
                  + "Archived alerts drop out of this count and these findings.")
        if n.get("truncated"):
            detail += " Unraid has more unread notifications than DaemonSight reads, so older ones may be missing."
        out.append(Finding("unraid.notification", "inbox", "low",
                           f"{total} unread Unraid {_plural(total, 'alert or warning', 'alerts and warnings')}",
                           detail, "/notifications", None, "inbox",
                           "Read and archive them in the Unraid web UI (bell icon, Archive all)"))
    return out
