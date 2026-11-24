"""Finding changes in, messages out: the hub's alert chore.

How a change reaches a channel, and why it can't repeat:

1. **Scan.** Every pass compares the open findings (accepted ones left out) with what each channel was last told
   (`notify_seen`, one row per channel and open finding). A finding that is new, more severe than what was announced, gone,
   or near or past its deadline becomes a row in the outbox (`notify_events`). A unique index on (channel, finding, kind,
   severity) means a change is queued once, however often the scan runs or the hub restarts. Findings that were already open
   when a channel was created are noted silently (`first_seen` at or before the channel's `created_at`): a new channel does
   not announce what the hub already knew.
2. **Deliver.** Pending rows older than a few seconds (so one poll's changes arrive together) go out as ONE message per
   channel, however many findings. A failure keeps the rows pending with a growing delay (30 s doubling to an hour; what
   a 429 asks for, if longer). After a day without success, or five refusals the service won't change its mind about
   (a webhook that no longer exists, a refused login), a row is given up and the channel shows it on the Settings page.
3. **Digests.** On the channel's schedule (the hub's time zone) a digest row is queued with the window since the last one.
   It is built when it is sent, from the changes that were recorded for the digest, and the current open counts.

Nothing here reads a secret except to send with it, and no text it stores or logs contains one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, tzinfo

from .. import db, full_version, settings
from ..config import Config
from . import channels as ch_mod
from . import render, schedule, send
from .channels import SEV_RANK

log = logging.getLogger("daemonsight.notify")

COALESCE_SECONDS = 15.0                    # a poll's changes are sent together: rows younger than this wait
GIVE_UP_SECONDS = 86400.0                  # a day of failures, then give up
BACKOFF = (30, 60, 120, 300, 600, 1200, 1800, 3600)
PERMANENT_ATTEMPTS = 5
PASS_SECONDS = 20.0
KEEP_SECONDS = 60 * 86400.0                # sent and given-up outbox rows are kept this long
LEAD_SHORT, LEAD_LONG = 12 * 3600.0, 24 * 3600.0     # reminder before a deadline: 12 hours for 3-day items, else 1 day
DEADLINE_KINDS = ("deadline_soon", "deadline_passed")
SECTIONS = (("deadline_passed", "Past deadline"), ("deadline_soon", "Deadline soon"), ("opened", "New"),
            ("worse", "Worse"), ("resolved", "Resolved"))
HEAD_WORDS = {"deadline_passed": "past deadline", "deadline_soon": "due soon", "opened": "new", "worse": "worse",
              "resolved": "resolved"}


def rank(sev: str) -> int:
    return SEV_RANK.get(sev, 99)


def backoff(failures: int) -> float:
    return float(BACKOFF[min(max(failures, 1), len(BACKOFF)) - 1])


def lead_for(days: int) -> float:
    return LEAD_SHORT if days <= 3 else LEAD_LONG


# --- what is open ---------------------------------------------------------------------

def open_state(conn) -> list[dict]:
    """Every open finding, each with `active`: False when someone accepted it and nothing about it has changed since."""
    rows = [db._finding_dict(r) for r in conn.execute("SELECT * FROM findings WHERE resolved_at IS NULL")]
    active, held = db._split(rows, db._accepted_rows(conn))
    for d in active:
        d["active"] = True
    for d in held:
        d["active"] = False
    return active + held


def deadline_of(f) -> float | None:
    days = f.get("deadline_days") if isinstance(f, dict) else f["deadline_days"]
    return f["first_seen"] + days * 86400 if days else None


def _flags(f: dict, now: float) -> tuple[int, int]:
    """(soon_sent, passed_sent) for a finding already open when its channel was made: what has already happened counts as done."""
    dl = deadline_of(f)
    if dl is None:
        return 0, 0
    if now >= dl:
        return 1, 1
    return (1 if now >= dl - lead_for(f["deadline_days"]) else 0), 0


# --- the scan ---------------------------------------------------------------------------

def _queue(conn, ch: dict, kind: str, now: float, *, host: str, rule: str, key: str, first_seen: float, severity: str,
           title: str, link: str | None, prev: str | None = None, deadline_ts: float | None = None) -> int:
    mode = ch["mode"]
    now_ok = mode != "digest" and (kind != "resolved" or ch["send_resolved"])
    digest_ok = mode != "immediate" and kind not in DEADLINE_KINDS
    if not now_ok and not digest_ok:
        return 0
    cur = conn.execute(
        "INSERT OR IGNORE INTO notify_events (channel_id, ts, kind, host, rule, key, first_seen, severity, prev_severity, title, "
        "link, deadline_ts, state, in_digest, next_try) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (ch["id"], now, kind, host, rule, key, first_seen, severity, prev, title[:300], link, deadline_ts,
         "pending" if now_ok else "none", int(digest_ok)))
    return cur.rowcount


def _resolve(conn, ch: dict, s, now: float) -> int:
    """A finding the channel knew is gone (or has come back as a new one)."""
    n = 0
    if s["announced"] and not s["accepted"]:
        n = _queue(conn, ch, "resolved", now, host=s["host"], rule=s["rule"], key=s["key"], first_seen=s["first_seen"],
                   severity=s["severity"], title=s["title"], link=s["link"])
    conn.execute("DELETE FROM notify_seen WHERE channel_id=? AND host=? AND rule=? AND key=?",
                 (ch["id"], s["host"], s["rule"], s["key"]))
    return n


def _scan_channel(conn, ch: dict, findings: list[dict], now: float) -> int:
    cid, wanted_sev = ch["id"], set(ch["severities"])
    seen = {(r["host"], r["rule"], r["key"]): r for r in conn.execute("SELECT * FROM notify_seen WHERE channel_id=?", (cid,))}
    queued = 0
    current = set()
    for f in findings:
        ident = (f["host"], f["rule"], f["key"])
        current.add(ident)
        s = seen.get(ident)
        if s is not None and s["first_seen"] != f["first_seen"]:
            queued += _resolve(conn, ch, s, now)             # the old one ended; this is a new one
            s = None
        sev, days = f["severity"], f.get("deadline_days")
        want = f["active"] and sev in wanted_sev
        dl = deadline_of(f)
        if s is None:
            silent = f["first_seen"] <= ch["created_at"]
            announced = sev if (silent and want) else None
            soon, passed = _flags(f, now) if silent else (0, 0)
            was, new = sev, True
        else:
            announced, soon, passed, was, new = s["announced"], s["soon_sent"], s["passed_sent"], s["severity"], False
        common = dict(host=f["host"], rule=f["rule"], key=f["key"], first_seen=f["first_seen"], title=f["title"], link=f["link"],
                      deadline_ts=dl)
        if want:
            if announced is None:
                kind = "opened" if (new or was == sev) else "worse"
                queued += _queue(conn, ch, kind, now, severity=sev, prev=None if kind == "opened" else was, **common)
                announced = sev
            elif rank(sev) < rank(announced):
                queued += _queue(conn, ch, "worse", now, severity=sev, prev=announced, **common)
                announced = sev
            if ch["deadline_reminders"] and dl is not None:
                if not passed and now >= dl:
                    queued += _queue(conn, ch, "deadline_passed", now, severity=sev, **common)
                    soon = passed = 1
                elif not soon and now >= dl - lead_for(days):
                    queued += _queue(conn, ch, "deadline_soon", now, severity=sev, **common)
                    soon = 1
        conn.execute(
            "INSERT OR REPLACE INTO notify_seen (channel_id, host, rule, key, first_seen, severity, announced, accepted, title, "
            "link, deadline_days, soon_sent, passed_sent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cid, f["host"], f["rule"], f["key"], f["first_seen"], sev, announced, int(not f["active"]), f["title"][:300],
             f["link"], days, soon, passed))
    for ident, s in seen.items():
        if ident not in current:
            queued += _resolve(conn, ch, s, now)
    return queued


def scan(conn, now: float) -> int:
    """Queue what changed since the last pass, for every channel. Returns how many outbox rows were added."""
    chans = ch_mod.all_channels(conn)
    if not chans:
        return 0
    findings = open_state(conn)
    queued = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        for ch in chans:
            queued += _scan_channel(conn, ch, findings, now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return queued


def schedule_digests(conn, now: float, tz: tzinfo | None = None) -> int:
    """Queue a digest for each channel whose time has come, and set its next time."""
    tz = tz or schedule.hub_zone()[0]
    n = 0
    for ch in ch_mod.all_channels(conn):
        if ch["mode"] == "immediate":
            continue
        due = ch["next_digest_at"]
        if due is None:
            conn.execute("UPDATE notify_channels SET next_digest_at=? WHERE id=?", (
                schedule.next_run(ch["digest_freq"], ch["digest_time"], ch["digest_weekday"], ch["digest_day"], now, tz), ch["id"]))
            continue
        if due > now:
            continue
        since = ch["last_digest_at"] or ch["created_at"]
        nxt = schedule.next_run(ch["digest_freq"], ch["digest_time"], ch["digest_weekday"], ch["digest_day"], now, tz)
        conn.execute("BEGIN IMMEDIATE")
        try:
            n += conn.execute(
                "INSERT OR IGNORE INTO notify_events (channel_id, ts, kind, host, rule, key, first_seen, severity, title, info, "
                "state, next_try) VALUES (?, ?, 'digest', '', '', 'digest', ?, '', 'digest', ?, 'pending', 0)",
                (ch["id"], now, now, json.dumps({"since": since, "until": now}))).rowcount
            conn.execute("UPDATE notify_channels SET last_digest_at=?, next_digest_at=? WHERE id=?", (now, nxt, ch["id"]))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return n


# --- building a message -----------------------------------------------------------------

def fmt_when(ts: float, tz: tzinfo) -> str:
    return datetime.fromtimestamp(ts, tz).strftime("%a %d %b %H:%M %Z").strip()


def deadline_text(dl: float | None, now: float, tz: tzinfo, passed: bool = False) -> str | None:
    if dl is None:
        return None
    return f"overdue since {fmt_when(dl, tz)}" if (passed or now >= dl) else f"due {fmt_when(dl, tz)}"


def footer(hub_url: str | None) -> str:
    return f"DaemonSight {full_version()}" + (f" · {hub_url}" if hub_url else "")


def _item(r, hub_url: str | None, now: float, tz: tzinfo) -> render.Item:
    return render.Item(r["severity"], r["title"], r["host"], render.finding_url(hub_url, r["host"], r["link"]),
                       deadline_text(r["deadline_ts"], now, tz, r["kind"] == "deadline_passed") if r["kind"] != "resolved" else None,
                       r["prev_severity"])


def _head(counts: dict[str, int]) -> str:
    return ", ".join(f"{counts[k]} {HEAD_WORDS[k]}" for k, _l in SECTIONS if counts.get(k))


def build_alert_note(rows: list, ch: dict, hub_url: str | None, now: float, tz: tzinfo) -> render.Note:
    secs, counts = [], {}
    for kind, label in SECTIONS:
        items = [_item(r, hub_url, now, tz) for r in rows if r["kind"] == kind]
        if items:
            items.sort(key=lambda i: rank(i.severity))
            secs.append(render.Section(label, items))
            counts[kind] = len(items)
    return render.Note("alert", f"DaemonSight: {_head(counts)}", secs, footer(hub_url), hub_url,
                       good=set(counts) == {"resolved"})


def sample_note(hub_url: str | None) -> render.Note:
    return render.Note("test", "DaemonSight: test message", [], footer(hub_url), hub_url,
                       summary="This is a test from DaemonSight. If you can read it, this channel works. Nothing is wrong.")


def build_digest_note(conn, ch: dict, info: dict, hub_url: str | None, tz: tzinfo, now: float) -> render.Note | None:
    """The digest for the window in `info`, or None when it is empty and the channel skips empty ones."""
    until = info["until"]
    rows = conn.execute("SELECT * FROM notify_events WHERE channel_id=? AND in_digest=1 AND ts<=? AND kind IN "
                        "('opened','worse','resolved') ORDER BY ts, id", (ch["id"], until)).fetchall()
    ended = {(r["host"], r["rule"], r["key"], r["first_seen"]) for r in rows if r["kind"] == "resolved"}
    began = {(r["host"], r["rule"], r["key"], r["first_seen"]) for r in rows if r["kind"] == "opened"}
    gone = ended & began          # opened and resolved inside the window: nothing to report
    rows = [r for r in rows if (r["host"], r["rule"], r["key"], r["first_seen"]) not in gone]
    sevs = [s for s in ch_mod.SEVERITIES if s in ch["severities"]]
    open_now = [f for f in open_state(conn) if f["active"] and f["severity"] in sevs]
    counts = [(s, sum(1 for f in open_now if f["severity"] == s)) for s in sevs]
    overdue = []
    for f in open_now:
        dl = deadline_of(f)
        if dl is not None and dl < until:
            overdue.append(render.Item(f["severity"], f["title"], f["host"], render.finding_url(hub_url, f["host"], f["link"]),
                                       deadline_text(dl, now, tz, True)))
    overdue.sort(key=lambda i: (rank(i.severity), i.title))
    secs, tally = [], {}
    if overdue:
        secs.append(render.Section("Overdue", overdue))
    for kind, label in SECTIONS:
        if kind in DEADLINE_KINDS:
            continue
        items = [_item(r, hub_url, now, tz) for r in rows if r["kind"] == kind]
        if items:
            items.sort(key=lambda i: rank(i.severity))
            secs.append(render.Section(label, items))
            tally[kind] = len(items)
    changes = bool(tally)
    if not changes and not overdue and ch["skip_empty"]:
        return None
    total = sum(n for _s, n in counts)
    scope = f"{total} open ({', '.join(sevs)})"
    what = _head(tally) if changes else "no changes"
    summary = (what[0].upper() + what[1:] if what else "No changes") + "; " + scope + (f"; {len(overdue)} overdue" if overdue else "")
    freq = dict(schedule.FREQS)[ch["digest_freq"]].lower()
    return render.Note("digest", f"DaemonSight {freq} digest: {what}" + (f"; {len(overdue)} overdue" if overdue else ""), secs,
                       footer(hub_url), hub_url, summary=summary, counts=counts,
                       good=False)


# --- delivery ---------------------------------------------------------------------------

def _fail(conn, ch: dict, rows: list, exc: send.SendError, now: float) -> int:
    """Record a failed send: push each row's next try out, or give it up. Returns how many were given up."""
    gave_up = 0
    for r in rows:
        attempts = r["attempts"] + 1
        old_enough = now - r["ts"] >= GIVE_UP_SECONDS
        if old_enough or (exc.permanent and attempts >= PERMANENT_ATTEMPTS):
            conn.execute("UPDATE notify_events SET state='gave_up', attempts=? WHERE id=?", (attempts, r["id"]))
            gave_up += 1
        else:
            delay = max(backoff(attempts), exc.retry_after or 0)
            conn.execute("UPDATE notify_events SET attempts=?, next_try=? WHERE id=?", (attempts, now + delay, r["id"]))
    ch_mod.record_result(conn, ch["id"], False, exc.message, now)
    if gave_up:
        conn.execute("UPDATE notify_channels SET gave_up_at=?, gave_up_count=gave_up_count+? WHERE id=?", (now, gave_up, ch["id"]))
        db.add_event(conn, db.HUB_HOST, now, "setting", f"Gave up sending to {ch['name']}"[:300],
                     detail=f"{gave_up} message{'s' if gave_up != 1 else ''} could not be sent for a day: {exc.message}"[:300])
        log.warning("Gave up on %d notification(s) for channel %s: %s", gave_up, ch["name"], exc.message)
    else:
        log.warning("Sending to channel %s failed: %s", ch["name"], exc.message)
    return gave_up


async def _attempt(conn, ch: dict, rows: list, note: render.Note, secret: str | None, net, now: float, on_sent=None) -> bool:
    try:
        await send.send(ch, secret, note, net)
    except send.SendError as exc:
        _fail(conn, ch, rows, exc, now)
        return False
    except Exception as exc:           # a bug must not lose the rows: they stay pending and retry
        log.exception("Unexpected error sending to channel %s", ch["name"])
        _fail(conn, ch, rows, send.SendError(f"internal error ({type(exc).__name__})"), now)
        return False
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany("UPDATE notify_events SET state='sent', sent_at=?, attempts=attempts+1 WHERE id=?",
                         [(now, r["id"]) for r in rows])
        if on_sent:
            on_sent()
        ch_mod.record_result(conn, ch["id"], True, None, now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return True


async def deliver(conn, cfg: Config, now: float, net=None, tz: tzinfo | None = None) -> int:
    """Send what is pending, one message per channel for alerts and one per due digest. Returns the number of messages sent."""
    tz = tz or schedule.hub_zone()[0]
    live = settings.effective(cfg, conn)
    hub_url = live.notify.hub_url or None
    sent = 0
    for ch in ch_mod.all_channels(conn):
        secret = ch_mod.read_secret(cfg.data_dir, ch["id"])
        rows = conn.execute(
            "SELECT * FROM notify_events WHERE channel_id=? AND state='pending' AND kind!='digest' AND next_try<=? AND ts<=? "
            "ORDER BY ts, id", (ch["id"], now, now - COALESCE_SECONDS)).fetchall()
        if rows:
            note = build_alert_note(rows, ch, hub_url, now, tz)
            if await _attempt(conn, ch, rows, note, secret, net, now):
                sent += 1
        for d in conn.execute("SELECT * FROM notify_events WHERE channel_id=? AND state='pending' AND kind='digest' AND next_try<=? "
                              "ORDER BY id", (ch["id"], now)).fetchall():
            info = json.loads(d["info"] or "{}")
            note = build_digest_note(conn, ch, info, hub_url, tz, now)
            until = info.get("until", now)

            def clear(until=until, cid=ch["id"]):
                conn.execute("UPDATE notify_events SET in_digest=0 WHERE channel_id=? AND in_digest=1 AND ts<=?", (cid, until))
            if note is None:               # nothing to say and the channel skips empty digests
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE notify_events SET state='none' WHERE id=?", (d["id"],))
                clear()
                conn.execute("COMMIT")
                continue
            if await _attempt(conn, ch, [d], note, secret, net, now, on_sent=clear):
                sent += 1
    return sent


def prune(conn, now: float) -> None:
    conn.execute("DELETE FROM notify_events WHERE state IN ('sent', 'gave_up', 'none') AND in_digest=0 AND ts < ?",
                 (now - KEEP_SECONDS,))


async def send_test(conn, cfg: Config, ch: dict, secret: str | None, hub_url: str | None, net=None) -> str | None:
    """Send the test message. Returns None when it went out, else the reason (safe to show). Records the result on a saved channel."""
    now = time.time()
    try:
        await send.send(ch, secret, sample_note(hub_url), net)
    except send.SendError as exc:
        if ch.get("id"):
            ch_mod.record_result(conn, ch["id"], False, exc.message, now)
        return exc.message
    if ch.get("id"):
        ch_mod.record_result(conn, ch["id"], True, None, now)
    return None


class Notifier:
    def __init__(self, cfg: Config, conn, net=None):
        self.cfg, self.conn, self.net = cfg, conn, net
        self.last_prune = 0.0

    async def run_once(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        scan(self.conn, now)
        schedule_digests(self.conn, now)
        sent = await deliver(self.conn, self.cfg, now, self.net)
        if now - self.last_prune > 3600:
            prune(self.conn, now)
            self.last_prune = now
        return sent


async def loop(cfg: Config, conn, net=None) -> None:
    notifier = Notifier(cfg, conn, net)
    await asyncio.sleep(10)
    while True:
        try:
            await notifier.run_once()
        except Exception:
            log.exception("Notification chore failed")
        await asyncio.sleep(PASS_SECONDS)
