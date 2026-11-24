"""When a channel's digest is next due, in the hub's time zone.

The hub knows its zone from the `TZ` environment variable (the container image and Unraid's template set it), else
`/etc/timezone`, else the zone `/etc/localtime` points to, else UTC. Python's `zoneinfo` needs the IANA database, which
the `tzdata` package supplies when the system has none.

A schedule is a wall-clock time (08:00), so the gap between two runs is 23 hours when the clocks go forward and 25 when
they go back. A wall-clock time that does not exist (02:30 the night the clocks go forward) runs at 03:30, the same
instant the clock would show if it had kept running; one that happens twice (01:30 the night they go back) runs at the
first.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger("daemonsight.notify")

FREQS = (("daily", "Daily"), ("weekly", "Weekly"), ("monthly", "Monthly"))
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def _zone(name: str) -> ZoneInfo | None:
    name = (name or "").strip().lstrip(":")
    if not name or not re.fullmatch(r"[A-Za-z0-9_+./-]{1,64}", name) or ".." in name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def hub_zone() -> tuple[tzinfo, str]:
    """The hub's time zone and its name (UTC when nothing says otherwise)."""
    z = _zone(os.environ.get("TZ", ""))
    if z:
        return z, z.key
    try:
        z = _zone(Path("/etc/timezone").read_text().strip())
        if z:
            return z, z.key
    except OSError:
        pass
    try:
        target = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in target:
            z = _zone(target.split("zoneinfo/", 1)[1])
            if z:
                return z, z.key
    except OSError:
        pass
    return timezone.utc, "UTC"


def _at(day, hh: int, mm: int, tz: tzinfo) -> datetime:
    """The wall-clock time on `day` in `tz`, normalised so a time inside a clock change lands on a real instant."""
    local = datetime(day.year, day.month, day.day, hh, mm, tzinfo=tz)
    return local.astimezone(timezone.utc).astimezone(tz)


def next_run(freq: str, hhmm: str, weekday: int, day: int, after: float, tz: tzinfo) -> float:
    """The first scheduled time strictly after `after` (a timestamp). `weekday` is 0 for Monday; `day` is 1 to 28."""
    m = TIME_RE.match(hhmm)
    if not m:
        raise ValueError(f"not a time of day: {hhmm!r}")
    hh, mm = int(m.group(1)), int(m.group(2))
    now = datetime.fromtimestamp(after, tz)
    today = now.date()
    if freq == "daily":
        days = (today + timedelta(days=i) for i in range(0, 3))
    elif freq == "weekly":
        if not 0 <= weekday <= 6:
            raise ValueError("weekday must be 0 to 6")
        start = today + timedelta(days=(weekday - today.weekday()) % 7)
        days = (start + timedelta(days=7 * i) for i in range(0, 3))
    elif freq == "monthly":
        if not 1 <= day <= 28:
            raise ValueError("day of month must be 1 to 28")

        def months():
            y, mo = today.year, today.month
            for _ in range(3):
                yield today.replace(year=y, month=mo, day=day)
                y, mo = (y + 1, 1) if mo == 12 else (y, mo + 1)
        days = months()
    else:
        raise ValueError(f"unknown frequency: {freq!r}")
    for d in days:
        t = _at(d, hh, mm, tz)
        if t.timestamp() > after:
            return t.timestamp()
    raise ValueError("no next run found")   # unreachable: three candidates always include one in the future


def describe(freq: str, hhmm: str, weekday: int, day: int) -> str:
    """"Daily at 08:00", "Weekly on Monday at 08:00", "Monthly on day 5 at 08:00"."""
    if freq == "weekly":
        return f"Weekly on {WEEKDAYS[weekday]} at {hhmm}"
    if freq == "monthly":
        return f"Monthly on day {day} at {hhmm}"
    return f"Daily at {hhmm}"
