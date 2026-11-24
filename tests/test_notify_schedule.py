"""When a digest is next due: daily, weekly and monthly, across the clock changes in America/New_York (2026: forward on
March 8 at 02:00, back on November 1 at 02:00), and how the hub learns its time zone."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from daemonsight.notify import schedule

NY = ZoneInfo("America/New_York")


def ts(y, mo, d, h=0, mi=0, tz=NY):
    return datetime(y, mo, d, h, mi, tzinfo=tz).timestamp()


def local(t):
    return datetime.fromtimestamp(t, NY).strftime("%Y-%m-%d %H:%M %Z")


def test_daily_before_and_after_today_s_time():
    assert local(schedule.next_run("daily", "08:00", 0, 1, ts(2026, 5, 4, 7, 0), NY)) == "2026-05-04 08:00 EDT"
    assert local(schedule.next_run("daily", "08:00", 0, 1, ts(2026, 5, 4, 8, 0), NY)) == "2026-05-05 08:00 EDT"   # strictly after
    assert local(schedule.next_run("daily", "08:00", 0, 1, ts(2026, 5, 4, 23, 59), NY)) == "2026-05-05 08:00 EDT"


def test_daily_across_spring_forward_keeps_the_wall_clock():
    first = schedule.next_run("daily", "08:00", 0, 1, ts(2026, 3, 7, 9, 0), NY)       # Sat 7 Mar, after 08:00
    assert local(first) == "2026-03-08 08:00 EDT"
    assert first - ts(2026, 3, 7, 8, 0) == 23 * 3600                                  # the night has 23 hours
    assert local(schedule.next_run("daily", "08:00", 0, 1, first, NY)) == "2026-03-09 08:00 EDT"


def test_daily_across_fall_back_keeps_the_wall_clock():
    first = schedule.next_run("daily", "08:00", 0, 1, ts(2026, 10, 31, 9, 0), NY)
    assert local(first) == "2026-11-01 08:00 EST"
    assert first - ts(2026, 10, 31, 8, 0) == 25 * 3600


def test_a_time_that_does_not_exist_runs_an_hour_later():
    t = schedule.next_run("daily", "02:30", 0, 1, ts(2026, 3, 7, 12, 0), NY)
    assert local(t) == "2026-03-08 03:30 EDT"          # 02:30 never happened that night
    assert local(schedule.next_run("daily", "02:30", 0, 1, t, NY)) == "2026-03-09 02:30 EDT"


def test_a_time_that_happens_twice_runs_at_the_first():
    t = schedule.next_run("daily", "01:30", 0, 1, ts(2026, 10, 31, 12, 0), NY)
    assert t == datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc).timestamp()          # 01:30 EDT, the first one
    nxt = schedule.next_run("daily", "01:30", 0, 1, t, NY)
    assert local(nxt) == "2026-11-02 01:30 EST"


@pytest.mark.parametrize("now, want", [
    (ts(2026, 3, 4, 12), "2026-03-09 06:00 EDT"),      # Wed 4 Mar: next Monday is the 9th, after the clocks moved
    (ts(2026, 3, 9, 6, 0), "2026-03-16 06:00 EDT"),    # exactly on the time: the next one
    (ts(2026, 3, 9, 5, 59), "2026-03-09 06:00 EDT"),
    (ts(2026, 10, 28, 12), "2026-11-02 06:00 EST"),    # the Monday after the clocks went back
])
def test_weekly_monday(now, want):
    assert local(schedule.next_run("weekly", "06:00", 0, 1, now, NY)) == want


def test_weekly_every_weekday_lands_on_that_weekday():
    start = ts(2026, 11, 1, 12)
    for wd in range(7):
        t = datetime.fromtimestamp(schedule.next_run("weekly", "09:15", wd, 1, start, NY), NY)
        assert t.weekday() == wd and (t.hour, t.minute) == (9, 15)


@pytest.mark.parametrize("now, day, want", [
    (ts(2026, 3, 1, 12), 8, "2026-03-08 08:00 EDT"),      # the day the clocks go forward
    (ts(2026, 3, 8, 8, 0), 8, "2026-04-08 08:00 EDT"),
    (ts(2026, 10, 15, 12), 1, "2026-11-01 08:00 EST"),    # the day they go back
    (ts(2026, 12, 29, 12), 5, "2027-01-05 08:00 EST"),    # over a year end
    (ts(2026, 1, 30, 12), 28, "2026-02-28 08:00 EST"),    # day 28 exists in February
    (ts(2026, 2, 28, 8, 1), 28, "2026-03-28 08:00 EDT"),
])
def test_monthly(now, day, want):
    assert local(schedule.next_run("monthly", "08:00", 0, day, now, NY)) == want


def test_bad_input_is_refused():
    for args in (("daily", "8:00", 0, 1), ("weekly", "08:00", 7, 1), ("monthly", "08:00", 0, 29), ("yearly", "08:00", 0, 1)):
        with pytest.raises(ValueError):
            schedule.next_run(*args, 0, NY)


def test_describe():
    assert schedule.describe("daily", "08:00", 0, 1) == "Daily at 08:00"
    assert schedule.describe("weekly", "08:00", 3, 1) == "Weekly on Thursday at 08:00"
    assert schedule.describe("monthly", "08:00", 0, 5) == "Monthly on day 5 at 08:00"


def test_the_hub_zone_comes_from_TZ(monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")
    tz, name = schedule.hub_zone()
    assert name == "America/New_York" and tz.key == "America/New_York"
    monkeypatch.setenv("TZ", "Not/AZone")
    _tz, name = schedule.hub_zone()
    assert name != "Not/AZone"                       # falls back to the system's zone, or UTC
    monkeypatch.setenv("TZ", "../../etc/passwd")
    assert schedule.hub_zone()[1] != "../../etc/passwd"
