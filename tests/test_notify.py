"""Alert channels: what triggers a message, the outbox (no repeats, retry, give up), grouping, digests, each service's payload and
limits, neutralising of finding text, and that no secret reaches a log, an event, an error or a page."""

import asyncio
import json
import logging
import sqlite3
from email import message_from_bytes, policy
from zoneinfo import ZoneInfo

import httpx
import pytest

from daemonsight import __version__, db
from daemonsight.config import Config
from daemonsight.findings import Finding
from daemonsight.notify import channels, engine, render, schedule, send

from .fake_notify import DISCORD_URL, NTFY_TOKEN, SLACK_URL, Fake, FakeNet

NY = ZoneInfo("America/New_York")
HUB = "https://hub.example.com"
DAY = 86400.0
T0 = 1_800_000_000.0          # a fixed "now" (2027-01-15), so nothing here depends on the clock


class Form(dict):
    def getlist(self, key):
        v = self.get(key, [])
        return v if isinstance(v, list) else [v]


DEFAULTS = {
    "slack": {"name": "Slack ops", "secret": SLACK_URL},
    "discord": {"name": "Discord ops", "secret": DISCORD_URL},
    "ntfy": {"name": "Phone", "ntfy_server": "https://ntfy.example.org", "ntfy_topic": "ds-alerts", "ntfy_auth": "none"},
    "email": {"name": "Mail", "email_host": "localhost", "email_security": "tls", "email_port": "465", "email_user": "bot",
              "email_from": "daemonsight@example.com", "email_to": "a@example.com\nb@example.com", "secret": "pw-secret-1"},
}


def form(kind="slack", **over) -> Form:
    f = Form(DEFAULTS[kind])
    f.update({"kind": kind, "severity": ["critical", "high"], "mode": "immediate", "deadline_reminders": "on",
              "skip_empty": "on", "digest_freq": "daily", "digest_time": "08:00", "digest_weekday": "0", "digest_day": "1"})
    f.update(over)
    return f


def add_channel(conn, cfg, kind="slack", now=1000.0, **over) -> int:
    values, secret, _drop, errors = channels.parse_form(form(kind, **over), None, secret_saved_now=False)
    assert not errors, errors
    return channels.create(conn, cfg.data_dir, values, secret, "admin", now)


def F(key, sev="high", title=None, days=None, rule="cve.package") -> Finding:
    return Finding(rule, key, sev, title or f"{key}: CVE fixed in an update", "detail", f"/vulnerabilities#cve-{key}", deadline_days=days)


def put(conn, findings, ts, host="web1"):
    db.reconcile_findings(conn, host, ts, findings)


@pytest.fixture
def cfg(tmp_path):
    c = Config(host_id="hub", data_dir=str(tmp_path / "data"))
    c.hub.enabled = True
    c.notify.hub_url = HUB
    return c


@pytest.fixture
def conn(cfg):
    c = db.connect_writer(cfg.db_path)
    yield c
    c.close()


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(send, "SLACK_GAP", 0.0)
    monkeypatch.setenv("TZ", "America/New_York")        # the hub's zone, which the digest schedule uses


async def tick(conn, cfg, now, fake, *, settle=True):
    """One pass of the chore at `now`: scan, queue digests, deliver. With `settle` the pass is 20 s later, so rows the scan just
    queued are old enough to send (they wait COALESCE_SECONDS so one poll's changes go together)."""
    engine.scan(conn, now)
    engine.schedule_digests(conn, now, NY)
    return await engine.deliver(conn, cfg, now + (engine.COALESCE_SECONDS + 5 if settle else 0), FakeNet(fake), NY)


def events(conn, **where):
    sql = "SELECT * FROM notify_events"
    if where:
        sql += " WHERE " + " AND ".join(f"{k}=?" for k in where)
    return conn.execute(sql + " ORDER BY id", tuple(where.values())).fetchall()


def slack_text(fake, i=-1) -> str:
    return "\n".join(b["text"]["text"] for b in fake.json(i)["blocks"] if b["type"] == "section")


# --- the triggers ----------------------------------------------------------------------------

async def test_a_new_finding_at_a_selected_severity_alerts_once(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("openssl", "critical", days=3), F("curl", "low")], T0)
    assert await tick(conn, cfg, T0, fake) == 1
    assert len(fake.requests) == 1
    text = slack_text(fake)
    assert "openssl" in text and "curl" not in text                   # low is not selected
    assert "New" in text and "Critical" in text
    assert f"{HUB}/h/web1/vulnerabilities#cve-openssl" in text      # a link to the finding on the hub
    assert await tick(conn, cfg, T0 + 60, fake) == 0                  # nothing repeats
    assert len(fake.requests) == 1


async def test_a_severity_rise_into_a_selected_one_alerts_and_only_a_further_rise_alerts_again(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("zlib", "low")], T0)
    assert await tick(conn, cfg, T0, fake) == 0                       # low: not selected
    put(conn, [F("zlib", "high")], T0 + 100)
    assert await tick(conn, cfg, T0 + 100, fake) == 1
    assert "Worse" in slack_text(fake) and "was low" in slack_text(fake)
    put(conn, [F("zlib", "medium")], T0 + 200)                         # falls out of the set: no message
    assert await tick(conn, cfg, T0 + 200, fake) == 0
    put(conn, [F("zlib", "high")], T0 + 300)                           # back to what was already announced
    assert await tick(conn, cfg, T0 + 300, fake) == 0
    put(conn, [F("zlib", "critical")], T0 + 400)                       # a real further rise
    assert await tick(conn, cfg, T0 + 400, fake) == 1
    assert "was high" in slack_text(fake)
    assert len(fake.requests) == 2


async def test_a_resolved_alert_only_when_enabled(conn, cfg):
    add_channel(conn, cfg, "slack", name="quiet")
    add_channel(conn, cfg, "discord", name="loud", send_resolved="on")
    fake = Fake()
    put(conn, [F("openssl", "critical")], T0)
    await tick(conn, cfg, T0, fake)
    fake.requests.clear()
    put(conn, [], T0 + 100)
    await tick(conn, cfg, T0 + 100, fake)
    assert len(fake.requests) == 1 and fake.requests[0]["url"] == DISCORD_URL
    desc = fake.json()["embeds"][0]["description"]
    assert "Resolved" in desc and "openssl" in desc
    assert fake.json()["embeds"][0]["color"] == render.GOOD_COLOR       # only resolutions: green, not red


@pytest.mark.parametrize("days, lead_hours", [(3, 12), (14, 24), (60, 24)])
async def test_deadline_reminders_come_once_before_and_once_after(conn, cfg, days, lead_hours):
    add_channel(conn, cfg)
    fake = Fake()
    sev = "critical" if days == 3 else "high"
    put(conn, [F("pkg", sev, days=days)], T0)
    await tick(conn, cfg, T0, fake)
    fake.requests.clear()
    due = T0 + days * DAY
    await tick(conn, cfg, due - (lead_hours + 1) * 3600, fake)
    assert not fake.requests                                            # not yet inside the window
    await tick(conn, cfg, due - (lead_hours - 1) * 3600, fake)
    assert len(fake.requests) == 1 and "Deadline soon" in slack_text(fake) and "due " in slack_text(fake)
    await tick(conn, cfg, due - 600, fake)
    assert len(fake.requests) == 1                                      # once
    await tick(conn, cfg, due + 3600, fake)
    assert len(fake.requests) == 2 and "Past deadline" in slack_text(fake) and "overdue since" in slack_text(fake)
    await tick(conn, cfg, due + 7 * DAY, fake)
    assert len(fake.requests) == 2                                      # once


async def test_a_deadline_already_gone_when_first_noticed_sends_only_the_passed_message(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("pkg", "critical", days=3)], T0)
    await tick(conn, cfg, T0 + 5 * DAY, fake)                           # the hub was off for five days
    kinds = [e["kind"] for e in events(conn)]
    assert "deadline_passed" in kinds and "deadline_soon" not in kinds


async def test_deadline_reminders_can_be_switched_off_and_never_apply_to_findings_without_one(conn, cfg):
    add_channel(conn, cfg, name="off", deadline_reminders="")
    put(conn, [F("a", "critical", days=3), F("b", "critical", days=None)], T0)
    fake = Fake()
    await tick(conn, cfg, T0, fake)
    fake.requests.clear()
    await tick(conn, cfg, T0 + 10 * DAY, fake)
    assert not fake.requests
    add_channel(conn, cfg, "discord", now=T0 + 10 * DAY - 1)             # a second channel with reminders on (default)
    put(conn, [F("a", "critical", days=3), F("b", "critical", days=None), F("c", "critical", days=3)], T0 + 10 * DAY)
    await tick(conn, cfg, T0 + 10 * DAY, fake)
    fake.requests.clear()
    await tick(conn, cfg, T0 + 14 * DAY, fake)
    assert [e["key"] for e in events(conn, kind="deadline_passed")] == ["c"]


async def test_accepted_findings_never_alert(conn, cfg):
    add_channel(conn, cfg, send_resolved="on")
    fake = Fake()
    put(conn, [F("openssl", "critical", days=3)], T0)
    db.accept_finding(conn, "web1", "cve.package", "openssl", "known", "admin", T0 + 1)
    await tick(conn, cfg, T0 + 2, fake)
    assert not fake.requests and not events(conn)                       # accepted before it was ever sent
    await tick(conn, cfg, T0 + 5 * DAY, fake)
    assert not fake.requests                                            # not even its deadline
    put(conn, [], T0 + 6 * DAY)
    await tick(conn, cfg, T0 + 6 * DAY, fake)
    assert not fake.requests                                            # nor its resolution


async def test_accepting_after_the_alert_silences_the_deadline_and_the_resolution(conn, cfg):
    add_channel(conn, cfg, send_resolved="on")
    fake = Fake()
    put(conn, [F("openssl", "critical", days=3)], T0)
    await tick(conn, cfg, T0, fake)
    assert len(fake.requests) == 1
    db.accept_finding(conn, "web1", "cve.package", "openssl", "known", "admin", T0 + 60)
    await tick(conn, cfg, T0 + 3 * DAY + 60, fake)
    put(conn, [], T0 + 4 * DAY)
    await tick(conn, cfg, T0 + 4 * DAY, fake)
    assert len(fake.requests) == 1


async def test_a_finding_that_was_accepted_and_then_comes_back_is_announced(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("openssl", "high")], T0)
    db.accept_finding(conn, "web1", "cve.package", "openssl", "known", "admin", T0 + 1)
    await tick(conn, cfg, T0 + 2, fake)
    assert not fake.requests
    db.unaccept_finding(conn, "web1", "cve.package", "openssl", T0 + 100)
    await tick(conn, cfg, T0 + 100, fake)
    assert len(fake.requests) == 1 and "openssl" in slack_text(fake)


async def test_what_was_open_before_the_channel_is_not_announced(conn, cfg):
    put(conn, [F("old1", "critical", days=3), F("old2", "high")], T0 - 10 * DAY)    # its 3-day deadline passed a week ago
    add_channel(conn, cfg, now=T0, send_resolved="on")
    fake = Fake()
    await tick(conn, cfg, T0 + 10, fake)
    assert not fake.requests
    await tick(conn, cfg, T0 + 5 * DAY, fake)                           # nor does a long-past deadline of an old finding
    assert not fake.requests
    put(conn, [F("old1", "critical", days=3), F("old2", "high"), F("new1", "critical")], T0 + 6 * DAY)
    await tick(conn, cfg, T0 + 6 * DAY, fake)
    assert len(fake.requests) == 1 and "new1" in slack_text(fake) and "old" not in slack_text(fake)
    put(conn, [F("old1", "critical", days=3), F("new1", "critical")], T0 + 7 * DAY)
    await tick(conn, cfg, T0 + 7 * DAY, fake)                           # an old one resolving is still news to a channel that wants it
    assert "old2" in slack_text(fake) and "Resolved" in slack_text(fake)


async def test_a_finding_that_resolves_and_returns_is_a_new_alert(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("openssl", "critical")], T0)
    await tick(conn, cfg, T0, fake)
    put(conn, [], T0 + 100)
    await tick(conn, cfg, T0 + 100, fake)
    put(conn, [F("openssl", "critical")], T0 + 200)
    await tick(conn, cfg, T0 + 200, fake)
    assert len(fake.requests) == 2


# --- grouping ------------------------------------------------------------------------------

async def test_everything_found_in_one_poll_goes_out_as_one_message_per_channel(conn, cfg):
    add_channel(conn, cfg, "slack")
    add_channel(conn, cfg, "discord")
    add_channel(conn, cfg, "ntfy")
    fake = Fake()
    put(conn, [F(f"pkg{i}", "critical" if i % 2 else "high", days=3) for i in range(12)], T0)
    put(conn, [F("openssl", "critical")], T0, host="web2")
    assert await tick(conn, cfg, T0, fake) == 3
    assert len(fake.requests) == 3
    assert sorted(r["url"].split("/")[2] for r in fake.requests) == ["discord.com", "hooks.slack.com", "ntfy.example.org"]
    assert all("13 new" in r["body"].decode() for r in fake.requests)         # all 13 findings, in each channel's one message


async def test_a_poll_s_changes_wait_a_few_seconds_so_they_arrive_together(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("a", "critical")], T0)
    engine.scan(conn, T0)
    assert await engine.deliver(conn, cfg, T0 + 2, FakeNet(fake), NY) == 0      # too fresh: held back
    put(conn, [F("a", "critical"), F("b", "critical")], T0 + 3)
    engine.scan(conn, T0 + 3)
    assert await engine.deliver(conn, cfg, T0 + 25, FakeNet(fake), NY) == 1
    assert len(fake.requests) == 1 and "a: CVE" in slack_text(fake) and "b: CVE" in slack_text(fake)


# --- the outbox -------------------------------------------------------------------------------

async def test_nothing_repeats_after_a_restart_even_if_the_state_is_lost(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake()
    put(conn, [F("openssl", "critical")], T0)
    await tick(conn, cfg, T0, fake)
    conn2 = db.connect_writer(cfg.db_path)                               # a new process, the same database
    try:
        n = await engine.Notifier(cfg, conn2, FakeNet(fake)).run_once(T0 + 100)
        assert n == 0 and len(fake.requests) == 1
        conn2.execute("DELETE FROM notify_seen")                          # even with the seen table wiped, the outbox's unique index holds
        engine.scan(conn2, T0 + 200)
        assert await engine.deliver(conn2, cfg, T0 + 300, FakeNet(fake), NY) == 0
    finally:
        conn2.close()
    assert len(fake.requests) == 1


async def test_pending_rows_survive_a_restart_and_go_out_once(conn, cfg):
    add_channel(conn, cfg)
    put(conn, [F("openssl", "critical")], T0)
    engine.scan(conn, T0)                                                 # queued; the process dies before delivering
    conn2 = db.connect_writer(cfg.db_path)
    fake = Fake()
    try:
        assert await engine.Notifier(cfg, conn2, FakeNet(fake)).run_once(T0 + 60) == 1
        assert await engine.Notifier(cfg, conn2, FakeNet(fake)).run_once(T0 + 120) == 0
    finally:
        conn2.close()
    assert len(fake.requests) == 1


async def test_a_failure_retries_with_growing_delays_then_succeeds(conn, cfg):
    cid = add_channel(conn, cfg)
    fake = Fake(script=[(500, {}, b"oops"), (503, {}, b"oops")])
    put(conn, [F("openssl", "critical")], T0)
    engine.scan(conn, T0)
    now = T0 + 20
    assert await engine.deliver(conn, cfg, now, FakeNet(fake), NY) == 0
    row = events(conn)[0]
    assert row["attempts"] == 1 and row["next_try"] == pytest.approx(now + 30)
    ch = channels.get(conn, cid)
    assert "HTTP 500" in ch["last_error"] and ch["last_ok"] is None
    assert await engine.deliver(conn, cfg, now + 10, FakeNet(fake), NY) == 0      # too early: no request
    assert len(fake.requests) == 1
    assert await engine.deliver(conn, cfg, now + 31, FakeNet(fake), NY) == 0
    row = events(conn)[0]
    assert row["attempts"] == 2 and row["next_try"] == pytest.approx(now + 31 + 60)
    assert await engine.deliver(conn, cfg, now + 31 + 61, FakeNet(fake), NY) == 1
    assert len(fake.requests) == 3
    row, ch = events(conn)[0], channels.get(conn, cid)
    assert row["state"] == "sent" and ch["last_error"] is None and ch["last_ok"] is not None


async def test_the_backoff_grows_and_stops_at_an_hour():
    assert [engine.backoff(n) for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 30)] == [30, 60, 120, 300, 600, 1200, 1800, 3600, 3600, 3600]


async def test_it_gives_up_after_a_day_and_says_so(conn, cfg):
    cid = add_channel(conn, cfg)
    fake = Fake(script=[(500, {}, b"down")] * 500)
    put(conn, [F("openssl", "critical")], T0)
    engine.scan(conn, T0)
    now = T0 + 20
    while now < T0 + DAY + 7200:
        await engine.deliver(conn, cfg, now, FakeNet(fake), NY)
        now += 600
    row = events(conn)[0]
    assert row["state"] == "gave_up"
    ch = channels.get(conn, cid)
    assert ch["gave_up_count"] == 1 and ch["gave_up_at"] and "HTTP 500" in ch["last_error"]
    n = len(fake.requests)
    await engine.deliver(conn, cfg, now + 100000, FakeNet(fake), NY)
    assert len(fake.requests) == n                                        # no more tries
    assert any(e["title"].startswith("Gave up sending to") for e in conn.execute("SELECT * FROM events WHERE host=''"))
    from daemonsight.web import notify_routes
    row = notify_routes.channel_rows(conn, cfg)[0]
    assert "Gave up on 1 message" in row["gave_up"] and row["status"]["state"] == "error"


async def test_a_refusal_the_service_will_not_change_is_given_up_sooner(conn, cfg):
    cid = add_channel(conn, cfg)
    fake = Fake(script=[(404, {}, b"no_service")] * 20)
    put(conn, [F("openssl", "critical")], T0)
    engine.scan(conn, T0)
    now = T0 + 20
    for _ in range(engine.PERMANENT_ATTEMPTS + 2):
        await engine.deliver(conn, cfg, now, FakeNet(fake), NY)
        now += 4000
    assert events(conn)[0]["state"] == "gave_up" and len(fake.requests) == engine.PERMANENT_ATTEMPTS
    assert "no_service" in channels.get(conn, cid)["last_error"]


async def test_a_429_waits_as_long_as_the_service_asks(conn, cfg):
    add_channel(conn, cfg, "discord")
    fake = Fake(script=[(429, {"retry-after": "120"}, json.dumps({"message": "slow down", "retry_after": 120.0, "global": False}).encode())])
    put(conn, [F("openssl", "critical")], T0)
    engine.scan(conn, T0)
    now = T0 + 20
    await engine.deliver(conn, cfg, now, FakeNet(fake), NY)
    assert events(conn)[0]["next_try"] == pytest.approx(now + 120)
    assert await engine.deliver(conn, cfg, now + 60, FakeNet(fake), NY) == 0 and len(fake.requests) == 1
    assert await engine.deliver(conn, cfg, now + 121, FakeNet(fake), NY) == 1


async def test_late_changes_join_the_retry_in_one_message(conn, cfg):
    add_channel(conn, cfg)
    fake = Fake(script=[(500, {}, b"x")])
    put(conn, [F("a", "critical")], T0)
    engine.scan(conn, T0)
    await engine.deliver(conn, cfg, T0 + 20, FakeNet(fake), NY)
    put(conn, [F("a", "critical"), F("b", "critical")], T0 + 40)
    engine.scan(conn, T0 + 40)
    assert await engine.deliver(conn, cfg, T0 + 60, FakeNet(fake), NY) == 1
    assert "a: CVE" in slack_text(fake) and "b: CVE" in slack_text(fake) and len(fake.requests) == 2


# --- digests ----------------------------------------------------------------------------------

def digest_channel(conn, cfg, now, **over):
    return add_channel(conn, cfg, "discord", now=now, mode="digest", digest_freq="daily", digest_time="08:00", **over)


def next_due(conn, cid):
    return channels.get(conn, cid)["next_digest_at"]


async def test_a_digest_lists_what_opened_got_worse_and_resolved_with_the_counts(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    cid = digest_channel(conn, cfg, start)
    fake = Fake()
    put(conn, [F("keep", "high"), F("gone", "high"), F("rising", "low")], start - 100)     # open before the channel
    put(conn, [F("keep", "high"), F("gone", "high"), F("rising", "low"), F("fresh", "critical", days=3)], start + 100)
    await tick(conn, cfg, start + 100, fake)
    put(conn, [F("keep", "high"), F("rising", "high"), F("fresh", "critical", days=3)], start + 200)       # gone resolves; rising rises
    await tick(conn, cfg, start + 200, fake)
    assert not fake.requests                                              # digest-only: nothing immediate
    due = next_due(conn, cid)
    assert due == ts_ny(2027, 1, 15, 8)
    await tick(conn, cfg, due + 5, fake)
    assert len(fake.requests) == 1
    emb = fake.json()["embeds"][0]
    d = emb["description"]
    assert "daily digest" in emb["title"]
    assert "New" in d and "fresh" in d and "Worse" in d and "rising" in d and "Resolved" in d and "gone" in d
    assert "keep" not in d
    assert "3 open (critical, high)" in d                                 # fresh (critical), keep and rising (high)
    assert next_due(conn, cid) == ts_ny(2027, 1, 16, 8)


def ts_ny(y, mo, d, h=0, mi=0):
    from datetime import datetime
    return datetime(y, mo, d, h, mi, tzinfo=NY).timestamp()


async def test_the_open_count_by_severity_is_in_the_digest(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    cid = digest_channel(conn, cfg, start, skip_empty="")
    put(conn, [F("a", "critical"), F("b", "high"), F("c", "high"), F("d", "low")], start - 10)
    fake = Fake()
    await tick(conn, cfg, next_due(conn, cid) + 5, fake)
    emb = fake.json()["embeds"][0]
    counts = {f["name"]: f["value"] for f in emb["fields"]}
    assert counts == {"Critical": "1", "High": "2"}                       # low is not a selected severity
    assert "No changes; 3 open (critical, high)" in emb["description"]


async def test_an_empty_digest_is_skipped_by_default_and_sent_when_asked(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    skip = digest_channel(conn, cfg, start, name="skips")
    keep = add_channel(conn, cfg, "slack", now=start, name="keeps", mode="digest", skip_empty="")
    put(conn, [F("a", "critical")], start - 10)                          # open, unchanged
    fake = Fake()
    await tick(conn, cfg, next_due(conn, skip) + 5, fake)
    assert [r["url"] for r in fake.requests] == [SLACK_URL]               # only the channel that wants empty digests
    assert "No changes; 1 open" in slack_text(fake)
    assert [e["state"] for e in events(conn, channel_id=skip, kind="digest")] == ["none"]
    assert next_due(conn, skip) > next_due(conn, keep) - DAY              # and its next run is set either way
    await tick(conn, cfg, next_due(conn, skip) + 5, fake)


async def test_an_overdue_finding_makes_a_digest_worth_sending(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    cid = digest_channel(conn, cfg, start)
    put(conn, [F("late", "critical", days=3)], start - 5 * DAY)
    fake = Fake()
    await tick(conn, cfg, next_due(conn, cid) + 5, fake)
    emb = fake.json()["embeds"][0]
    assert "Overdue" in emb["description"] and "late" in emb["description"] and "overdue since" in emb["description"]


async def test_something_that_opened_and_resolved_between_digests_is_not_reported(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    cid = digest_channel(conn, cfg, start, skip_empty="")
    put(conn, [F("blip", "critical")], start + 10)
    await tick(conn, cfg, start + 10, Fake())
    put(conn, [], start + 100)
    await tick(conn, cfg, start + 100, Fake())
    fake = Fake()
    await tick(conn, cfg, next_due(conn, cid) + 5, fake)
    assert "blip" not in fake.json()["embeds"][0]["description"]


async def test_both_sends_at_once_and_in_the_digest(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    cid = add_channel(conn, cfg, "slack", now=start, mode="both")
    fake = Fake()
    put(conn, [F("openssl", "critical")], start + 10)
    await tick(conn, cfg, start + 10, fake)
    assert len(fake.requests) == 1 and "New" in slack_text(fake)
    await tick(conn, cfg, next_due(conn, cid) + 5, fake)
    assert len(fake.requests) == 2 and "daily digest" in fake.json()["blocks"][0]["text"]["text"] and "openssl" in slack_text(fake)


async def test_a_digest_that_fails_is_retried_and_keeps_its_changes(conn, cfg):
    start = ts_ny(2027, 1, 14, 12)
    cid = digest_channel(conn, cfg, start)
    put(conn, [F("fresh", "critical")], start + 10)
    engine.scan(conn, start + 10)
    due = next_due(conn, cid) + 5
    fake = Fake(script=[(500, {}, b"x")])
    engine.scan(conn, due)
    engine.schedule_digests(conn, due, NY)
    assert await engine.deliver(conn, cfg, due, FakeNet(fake), NY) == 0
    assert await engine.deliver(conn, cfg, due + 40, FakeNet(fake), NY) == 1
    assert "fresh" in fake.json()["embeds"][0]["description"]


# --- payloads and limits ---------------------------------------------------------------------

def many(n, title_len=120):
    return [F(f"pkg{i}", ["critical", "high"][i % 2], title="x" * title_len + str(i), days=3) for i in range(n)]


def alert_note(findings, now=T0, sections=None):
    put_conn = sqlite3.connect(":memory:")
    put_conn.row_factory = sqlite3.Row
    rows = []
    for f in findings:
        rows.append({"kind": "opened", "severity": f.severity, "title": f.title, "host": "web1", "link": f.link,
                     "deadline_ts": now + 3 * DAY if f.deadline_days else None, "prev_severity": None})
    return engine.build_alert_note(rows, {"mode": "immediate"}, HUB, now, NY)


@pytest.mark.parametrize("n", [1, 30, 500])
async def test_ntfy_payload_stays_inside_ntfy_s_limits(n):
    fake = Fake()
    ch = {"id": 1, "kind": "ntfy", "config": {"server": "https://ntfy.example.org", "topic": "t", "auth": "none"}}
    await send.send(ch, None, alert_note(many(n)), FakeNet(fake))
    body = fake.json()
    assert body["topic"] == "t" and body["priority"] == 5 and "rotating_light" in body["tags"]
    assert len(body["message"].encode()) <= 4096 and len(body["title"].encode()) <= 1024
    assert fake.requests[0]["url"] == "https://ntfy.example.org"            # the server root, as the JSON publish API wants
    assert f"DaemonSight {engine.full_version()}" in body["message"] and HUB in body["message"]
    assert "markdown" not in body                                           # plain text only
    if n > 30:
        assert " more" in body["message"]
    if n == 1:
        assert body["click"].startswith(f"{HUB}/h/web1/")


async def test_ntfy_authentication_forms():
    fake = Fake(ntfy_token=NTFY_TOKEN)
    ch = {"id": 1, "kind": "ntfy", "config": {"server": "https://ntfy.example.org", "topic": "t", "auth": "token"}}
    await send.send(ch, NTFY_TOKEN, alert_note(many(1)), FakeNet(fake))
    assert fake.requests[0]["headers"]["authorization"] == f"Bearer {NTFY_TOKEN}"
    with pytest.raises(send.SendError) as e:
        await send.send(ch, "tk_wrongwrongwrong", alert_note(many(1)), FakeNet(fake))
    assert "HTTP 401" in e.value.message and e.value.permanent and "tk_wrong" not in e.value.message
    basic = Fake(ntfy_basic=("alice", "p4ss word"))
    ch = {"id": 1, "kind": "ntfy", "config": {"server": "https://ntfy.example.org", "topic": "t", "auth": "basic", "user": "alice"}}
    await send.send(ch, "p4ss word", alert_note(many(1)), FakeNet(basic))
    assert basic.requests[0]["headers"]["authorization"].startswith("Basic ")


@pytest.mark.parametrize("n", [1, 30, 500, 1500])
async def test_slack_payload_stays_inside_slack_s_limits(n):
    fake = Fake()
    ch = {"id": 1, "kind": "slack", "config": {}}
    await send.send(ch, SLACK_URL, alert_note(many(n)), FakeNet(fake))
    data = fake.json()
    assert data["text"] and len(data["blocks"]) <= 50
    assert data["blocks"][0]["type"] == "header" and len(data["blocks"][0]["text"]["text"]) <= 150
    for b in data["blocks"]:
        if b["type"] == "section":
            assert 0 < len(b["text"]["text"]) <= 3000
    last = data["blocks"][-1]
    assert last["type"] == "context" and f"DaemonSight {engine.full_version()}" in last["elements"][0]["text"] and HUB in last["elements"][0]["text"]
    if n == 1500:
        assert "more" in slack_text(fake) and f"<{HUB}|Open DaemonSight>" in slack_text(fake) and len(data["blocks"]) == 50


@pytest.mark.parametrize("n", [1, 30, 500])
async def test_discord_payload_stays_inside_discord_s_limits(n):
    fake = Fake()
    ch = {"id": 1, "kind": "discord", "config": {}}
    await send.send(ch, DISCORD_URL, alert_note(many(n)), FakeNet(fake))
    data = fake.json()
    assert data["allowed_mentions"] == {"parse": []}
    (emb,) = data["embeds"]
    assert isinstance(emb["color"], int) and render.discord_embed_size(data) <= 6000
    assert len(emb["description"]) <= 4096 and len(emb["title"]) <= 256
    assert f"DaemonSight {engine.full_version()}" in emb["footer"]["text"] and HUB in emb["footer"]["text"]
    if n == 500:
        assert "more" in emb["description"]


async def test_a_very_long_title_is_cut_not_sent_whole():
    fake = Fake()
    long = [F("p", "critical", title="y" * 5000)]
    for kind, url in (("slack", SLACK_URL), ("discord", DISCORD_URL), ("ntfy", None)):
        ch = {"id": 1, "kind": kind, "config": {"server": "https://ntfy.example.org", "topic": "t", "auth": "none"}}
        await send.send(ch, url, alert_note(long), FakeNet(fake))        # the fake servers reject anything over the documented limits


async def test_severity_sets_the_colour_and_priority():
    for sev, prio in (("critical", 5), ("high", 4), ("medium", 3), ("low", 2)):
        p = render.ntfy_payload(alert_note([F("a", sev)]), "t")
        assert p["priority"] == prio
        assert render.discord_payload(alert_note([F("a", sev)]))["embeds"][0]["color"] == render.SEV_COLOR[sev]
    assert len({render.SEV_COLOR[s] for s in render.SEV_COLOR}) == 5


# --- neutralising ------------------------------------------------------------------------------

NASTY = "<!channel> @everyone <@U123> <https://evil.example|click> *bold* _it_ ~x~ `code` [a](https://evil.example) &amp; @here"


def nasty_note():
    return alert_note([F("p", "critical", title=NASTY)])


def test_slack_text_cannot_mention_or_link_or_format():
    out = json.dumps(render.slack_payload(nasty_note()))
    assert "<!channel>" not in out and "<@U123>" not in out and "<https://evil.example|click>" not in out
    assert "&lt;!channel&gt;" in out and "&amp;amp;" in out
    assert "@everyone" not in out and "@here" not in out                    # an @ is followed by a zero-width space
    assert "*bold*" not in out and "_it_" not in out and "`code`" not in out
    first = slack_text_of(render.slack_payload(nasty_note()))
    assert first.count("<") == first.count(">") == 1                        # the one link is DaemonSight's own: <hub-url|title>


def slack_text_of(payload) -> str:
    return "\n".join(b["text"]["text"] for b in payload["blocks"] if b["type"] == "section")


def test_discord_text_cannot_mention_or_link_or_format():
    p = render.discord_payload(nasty_note())
    assert p["allowed_mentions"] == {"parse": []}
    d = p["embeds"][0]["description"]
    assert "@everyone" not in d and "@here" not in d and "<@U123>" not in d and "<!channel>" not in d
    assert "\\<" in d and "\\*bold\\*" in d and "\\[a\\](https://evil.example)" in d
    import re
    assert len(re.findall(r"(?<!\\)\]\(", d)) == 1                           # the only link is the one DaemonSight builds


def test_ntfy_is_plain_text_and_email_is_escaped():
    p = render.ntfy_payload(nasty_note(), "t")
    assert "markdown" not in p and "\n" not in p["title"]
    html = render.email_html(nasty_note(), None)
    assert "<!channel>" not in html and "&lt;!channel&gt;" in html and "<@U123>" not in html
    assert "<script" not in html and "&lt;https://evil.example|click&gt;" in html


def test_control_characters_and_newlines_never_reach_a_header_or_title():
    n = alert_note([F("p", "critical", title="line one\r\nBcc: attacker@example.com\x00\x1b[31mred")])
    msg = render.build_email(n, "ds@example.com", ["a@example.com"])
    assert "Bcc" not in "".join(f"{k}" for k in msg.keys())
    assert "\n" not in msg["Subject"] and "\r" not in msg["Subject"]
    for p in (render.ntfy_payload(n, "t"), render.slack_payload(n), render.discord_payload(n)):
        assert "\x00" not in json.dumps(p) and "\\u001b" not in json.dumps(p)


def test_links_are_only_the_hubs_own():
    assert render.finding_url(HUB, "web1", "/vulnerabilities#cve-x") == f"{HUB}/h/web1/vulnerabilities#cve-x"
    assert render.finding_url(HUB, "web1", "//evil.example/x") == f"{HUB}/h/web1/"
    assert render.finding_url(HUB, "web1", "https://evil.example/x") == f"{HUB}/h/web1/"
    assert render.finding_url(None, "web1", "/x") is None
    assert render.finding_url(HUB, "we b", "/x").startswith(f"{HUB}/h/we%20b/")


# --- email ---------------------------------------------------------------------------------------

def test_email_has_text_html_and_the_logo_inline_by_content_id():
    note = alert_note(many(3))
    msg = render.build_email(note, "ds@example.com", ["a@example.com", "b@example.com"], render.load_logo())
    parsed = message_from_bytes(bytes(msg), policy=policy.default)
    assert parsed["To"] == "a@example.com, b@example.com" and parsed["Subject"].startswith("DaemonSight: 3 new")
    assert parsed.get_content_type() == "multipart/alternative"
    text, html_part = parsed.get_payload()
    assert text.get_content_type() == "text/plain" and html_part.get_content_type() == "multipart/related"
    html_body, image = html_part.get_payload()
    assert html_body.get_content_type() == "text/html" and image.get_content_type() == "image/png"
    cid = image["Content-ID"].strip("<>")
    body = html_body.get_content()
    assert f'src="cid:{cid}"' in body
    assert image["Content-Disposition"].startswith("inline") and image.get_content().startswith(b"\x89PNG")
    assert f"DaemonSight {engine.full_version()}" in body and HUB in body
    assert f"DaemonSight {engine.full_version()}" in text.get_content() and HUB in text.get_content()
    assert 'src="http' not in body                                           # never a remote image


def test_the_email_logo_is_the_one_in_assets():
    from pathlib import Path
    assets = Path(__file__).resolve().parent.parent / "assets" / "logo-256.png"
    assert render.load_logo() == assets.read_bytes()


# --- what a channel is allowed to point at -------------------------------------------------------

@pytest.mark.parametrize("kind, url, ok", [
    ("slack", SLACK_URL, True),
    ("slack", "http://hooks.slack.com/services/T0/B0/xxxx", False),
    ("slack", "https://hooks.slack.com.evil.example/services/T0/B0/xxxx", False),
    ("slack", "https://evil.example/hooks.slack.com/services/T0/B0/xxxx", False),
    ("slack", "https://user@hooks.slack.com/services/T0/B0/xxxx", False),
    ("slack", "https://hooks.slack.com/services/T0/B0/xxxx?x=1", False),
    ("slack", "https://hooks.slack.com:8443/services/T0/B0/xxxx", False),
    ("slack", "https://hooks.slack.com/triggers/T0/B0/xxxx", False),
    ("slack", DISCORD_URL, False),
    ("discord", DISCORD_URL, True),
    ("discord", "https://discordapp.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789", False),
    ("discord", "https://discord.com.evil.example/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz", False),
    ("discord", "https://discord.com/api/webhooks/abc/abcdefghijklmnopqrstuvwxyz0123456789", False),
    ("discord", "http://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789", False),
    ("discord", SLACK_URL, False),
])
def test_webhook_urls(kind, url, ok):
    if ok:
        assert channels.clean_webhook(kind, url) == url
    else:
        with pytest.raises(channels.Invalid):
            channels.clean_webhook(kind, url)


@pytest.mark.parametrize("url, ok", [
    ("https://ntfy.sh", True), ("ntfy.sh", True), ("https://ntfy.example.org/prefix/", True),
    ("http://localhost:2586", True), ("http://127.0.0.1:2586", True), ("http://[::1]:2586", True),
    ("http://ntfy.example.org", False), ("http://192.168.1.5", False), ("ftp://ntfy.sh", False),
    ("https://user:pw@ntfy.sh", False), ("https://ntfy.sh/?x=1", False), ("", False),
])
def test_ntfy_server(url, ok):
    if ok:
        assert channels.clean_ntfy_server(url).startswith(("http://", "https://"))
    else:
        with pytest.raises(channels.Invalid):
            channels.clean_ntfy_server(url)


def test_a_form_for_each_kind_is_checked_for_what_it_needs():
    for kind, field in (("slack", "secret"), ("discord", "secret"), ("ntfy", "ntfy_topic"), ("email", "email_to")):
        f = form(kind)
        f.pop(field)
        _v, _s, _d, errors = channels.parse_form(f, None, secret_saved_now=False)
        assert field in errors, kind
    assert "severity" in channels.parse_form(form(severity=[]), None, secret_saved_now=False)[3]
    assert "email_security" in channels.parse_form(form("email", email_security="none"), None, secret_saved_now=False)[3]
    assert "secret" in channels.parse_form(form("ntfy", ntfy_auth="token"), None, secret_saved_now=False)[3]
    assert "digest_day" in channels.parse_form(form(digest_day="29"), None, secret_saved_now=False)[3]
    assert "digest_time" in channels.parse_form(form(digest_time="25:00"), None, secret_saved_now=False)[3]


# --- secrets ---------------------------------------------------------------------------------------

async def test_secrets_are_files_with_mode_0600_and_never_in_the_database(conn, cfg, tmp_path):
    import os
    cid = add_channel(conn, cfg)
    path = channels.secret_path(cfg.data_dir, cid)
    assert path.read_text().strip() == SLACK_URL
    assert oct(path.stat().st_mode & 0o777) == "0o600" and oct(path.parent.stat().st_mode & 0o777) == "0o700"
    dump = "\n".join(conn.iterdump())
    assert SLACK_URL not in dump and "abcdefghijklmnopqrstuvwx" not in dump
    assert not os.path.exists(str(path) + ".tmp")
    channels.remove(conn, cfg.data_dir, cid, "admin")
    assert not path.exists()


async def test_no_secret_reaches_a_log_an_event_or_an_error(conn, cfg, caplog):
    caplog.set_level(logging.DEBUG)
    add_channel(conn, cfg, "slack")
    add_channel(conn, cfg, "discord")
    add_channel(conn, cfg, "ntfy", ntfy_auth="token", secret=NTFY_TOKEN, name="n")
    secrets = [SLACK_URL, DISCORD_URL, NTFY_TOKEN, "abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwxyz0123456789"]

    def boom(request):                                    # a transport whose own error text holds the URL and the token
        raise httpx.ConnectError(f"cannot connect to {request.url} with {request.headers.get('authorization')}")
    net = FakeNet(Fake())
    net.transport = httpx.MockTransport(boom)
    put(conn, [F("openssl", "critical")], T0)
    engine.scan(conn, T0)
    await engine.deliver(conn, cfg, T0 + 20, net, NY)
    for r in conn.execute("SELECT last_error FROM notify_channels"):
        assert r["last_error"] == "could not connect"
    haystack = caplog.text + json.dumps([dict(r) for r in conn.execute("SELECT * FROM events")]) \
        + json.dumps([dict(r) for r in conn.execute("SELECT * FROM notify_channels")]) \
        + json.dumps([dict(r) for r in conn.execute("SELECT * FROM notify_events")])
    for s in secrets:
        assert s not in haystack
    assert any("Sending to channel" in r.getMessage() for r in caplog.records)   # it did log the failure, without the secret


async def test_error_text_from_a_service_is_cleaned_and_secret_free(conn, cfg):
    fake = Fake(script=[(400, {}, f"invalid_payload {SLACK_URL} \x1b[31m<script>".encode())])
    ch = {"id": 1, "kind": "slack", "config": {}}
    with pytest.raises(send.SendError) as e:
        await send.send(ch, SLACK_URL, alert_note(many(1)), FakeNet(fake))
    assert "invalid_payload" in e.value.message and SLACK_URL not in e.value.message and "\x1b" not in e.value.message
    assert "<" not in e.value.message


async def test_a_redirect_is_never_followed(conn, cfg):
    fake = Fake(script=[(302, {"location": "https://evil.example/steal"}, b"")])
    ch = {"id": 1, "kind": "ntfy", "config": {"server": "https://ntfy.example.org", "topic": "t", "auth": "token"}}
    with pytest.raises(send.SendError) as e:
        await send.send(ch, NTFY_TOKEN, alert_note(many(1)), FakeNet(fake))
    assert "redirect" in e.value.message and len(fake.requests) == 1 and NTFY_TOKEN not in e.value.message


async def test_the_request_names_the_product_and_carries_no_other_identity(conn, cfg):
    fake = Fake()
    ch = {"id": 1, "kind": "discord", "config": {}}
    await send.send(ch, DISCORD_URL, alert_note(many(1)), FakeNet(fake))
    assert fake.requests[0]["headers"]["user-agent"] == f"DaemonSight/{__version__}"
    assert fake.requests[0]["headers"]["content-type"] == "application/json"


# --- the schema ---------------------------------------------------------------------------------------

def test_an_older_database_gets_the_new_column_and_tables(tmp_path):
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript("""CREATE TABLE findings (id INTEGER PRIMARY KEY, host TEXT NOT NULL, rule TEXT NOT NULL, key TEXT NOT NULL,
        severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, link TEXT, first_seen REAL NOT NULL,
        last_seen REAL NOT NULL, resolved_at REAL, fix TEXT, basis TEXT, howto TEXT);
        INSERT INTO findings (host, rule, key, severity, title, detail, first_seen, last_seen) VALUES ('h','r','k','high','t','d',1,1);
        PRAGMA user_version=11;""")
    c.commit()
    c.close()
    conn = db.connect_writer(path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "deadline_days" in cols and {"notify_channels", "notify_seen", "notify_events"} <= tables
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION == 12
    assert conn.execute("SELECT deadline_days FROM findings").fetchone()[0] is None
    conn.close()


def test_the_deadline_is_stored_updated_and_held(tmp_path):
    c = db.connect_writer(tmp_path / "d.db")
    try:
        put(c, [F("a", "high", days=14)], 100)
        assert c.execute("SELECT deadline_days FROM findings").fetchone()[0] == 14
        put(c, [F("a", "critical", days=3)], 200)
        row = c.execute("SELECT * FROM findings").fetchone()
        assert row["deadline_days"] == 3 and row["first_seen"] == 100          # the clock keeps running from when it was first seen
        from daemonsight import findings
        held = findings.held({("cve.package", "a"): row}, "cve.package", "a")
        assert held.deadline_days == 3
    finally:
        c.close()
