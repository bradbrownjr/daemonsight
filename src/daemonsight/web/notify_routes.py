"""The Settings page's alert channels: add, edit, Send test and remove. Hub only. Every page needs the login and every POST
refuses a cross-site request (the `Sec-Fetch-Site` check the other hub actions use, on top of the SameSite=strict cookie).

A channel's secret (a webhook URL, a token, an SMTP password) is typed into a password box, written to a 0600 file by
notify/channels.py and never put back into a page, an event, a log line or an error. A blank box on the edit page keeps the
saved one.
"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import settings
from ..config import Config
from ..notify import channels, engine, schedule
from . import views

log = logging.getLogger("daemonsight.notify")

HELP = {
    "slack": "Create an incoming webhook in your Slack workspace (Apps, Incoming Webhooks) for the channel the messages should go to, "
             "and paste its URL. The URL is the credential: anyone who has it can post to that channel.",
    "discord": "In Discord open the channel's settings, Integrations, Webhooks, make one and copy its URL. The URL is the credential: "
               "anyone who has it can post to that channel.",
    "ntfy": "Messages go to a topic on an Ntfy server. On a public server anyone who knows the topic name can read it, so pick a long "
            "one, or use a server with logins and an access token.",
    "email": "DaemonSight logs in to your mail provider's SMTP server over an encrypted connection (never unencrypted) and checks "
             "its certificate. Gmail and Microsoft 365 need an app password or SMTP AUTH; see the install guide.",
}


def blank_form(kind: str = "slack") -> dict:
    return {"name": "", "kind": kind, "severity": list(channels.DEFAULT_SEVERITIES), "mode": "immediate",
            "send_resolved": False, "deadline_reminders": True, "skip_empty": True, "digest_freq": "daily",
            "digest_time": "08:00", "digest_weekday": 0, "digest_day": 1, "ntfy_server": "https://ntfy.sh", "ntfy_topic": "",
            "ntfy_auth": "none", "ntfy_user": "", "email_host": "", "email_security": "tls", "email_port": "",
            "email_user": "", "email_from": "", "email_to": ""}


def form_from_channel(ch: dict) -> dict:
    c = ch["config"]
    f = blank_form(ch["kind"])
    f.update(name=ch["name"], severity=ch["severities"], mode=ch["mode"], send_resolved=ch["send_resolved"],
             deadline_reminders=ch["deadline_reminders"], skip_empty=ch["skip_empty"], digest_freq=ch["digest_freq"],
             digest_time=ch["digest_time"], digest_weekday=ch["digest_weekday"], digest_day=ch["digest_day"])
    if ch["kind"] == "ntfy":
        f.update(ntfy_server=c.get("server", ""), ntfy_topic=c.get("topic", ""), ntfy_auth=c.get("auth", "none"),
                 ntfy_user=c.get("user", ""))
    elif ch["kind"] == "email":
        f.update(email_host=c.get("host", ""), email_security=c.get("security", "tls"), email_port=c.get("port", 465),
                 email_user=c.get("user", ""), email_from=c.get("from", ""), email_to="\n".join(c.get("to", [])))
    return f


def form_from_post(form, kind: str) -> dict:
    f = blank_form(kind)
    for k in ("name", "mode", "digest_freq", "digest_time", "ntfy_server", "ntfy_topic", "ntfy_auth", "ntfy_user", "email_host",
              "email_security", "email_user", "email_from", "email_to", "digest_weekday", "digest_day", "email_port"):
        if k in form:
            f[k] = str(form.get(k))[:2000]
    f["severity"] = [s for s in form.getlist("severity") if s in channels.SEVERITIES]
    for k in ("send_resolved", "deadline_reminders", "skip_empty"):
        f[k] = str(form.get(k, "")).strip().lower() in ("on", "1", "true", "yes")
    return f


def _ago(ts) -> str:
    return views.fmt_ago(ts) if ts else "never"


def channel_rows(conn, cfg: Config) -> list[dict]:
    """What the Settings page lists for each channel. Never holds a secret."""
    tz, _name = schedule.hub_zone()
    out = []
    for ch in channels.all_channels(conn):
        pending = conn.execute("SELECT COUNT(*) FROM notify_events WHERE channel_id=? AND state='pending'", (ch["id"],)).fetchone()[0]
        recv = f"{', '.join(ch['severities'])}"
        when = dict(channels.MODES)[ch["mode"]]
        if ch["mode"] != "immediate":
            when += ": " + schedule.describe(ch["digest_freq"], ch["digest_time"], ch["digest_weekday"], ch["digest_day"]).lower()
        nxt = engine.fmt_when(ch["next_digest_at"], tz) if ch["next_digest_at"] else None
        status = {"state": "new", "text": "Nothing sent yet"}
        if ch["last_error"]:
            status = {"state": "error", "text": f"Failing: {ch['last_error']} ({_ago(ch['last_error_at'])})"}
        elif ch["last_ok"]:
            status = {"state": "ok", "text": f"Last sent {_ago(ch['last_ok'])}"}
        out.append({"id": ch["id"], "name": ch["name"], "kind": channels.KINDS[ch["kind"]], "receives": recv, "when": when,
                    "next_digest": nxt, "status": status, "pending": pending,
                    "gave_up": (f"Gave up on {ch['gave_up_count']} message{'s' if ch['gave_up_count'] != 1 else ''} "
                                f"({_ago(ch['gave_up_at'])}): they could not be sent for a day.") if ch["gave_up_at"] else None,
                    "secret_saved": channels.secret_saved(cfg.data_dir, ch["id"])})
    return out


def add_notify_routes(app: FastAPI, cfg: Config, conn, *, render, require_login, flash, reader, net) -> None:
    def guard(request: Request) -> str:
        require_login(request)
        if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            raise HTTPException(403, "cross-site request refused")
        return str(request.session.get("user") or "admin")

    def client(request: Request) -> str:
        return request.client.host if request.client else "?"

    def hub_url_for(request: Request, by: str, save: bool) -> str | None:
        """The address links use: the setting, else the one the administrator is using now (saved as the setting when `save`)."""
        live = settings.effective(cfg, conn)
        if live.notify.hub_url:
            return live.notify.hub_url
        origin = channels.origin_of(request.url.scheme, request.headers.get("host"))
        if origin and save:
            settings.save(conn, cfg, {"notify.hub_url": origin}, by)
        return origin or None

    def page(request: Request, ctx: dict, status: int = 200):
        return render(request, "notify_form.html", {"page": "settings", "v": {"host": None}, "kinds": channels.KINDS,
                                                    "severities": channels.SEVERITIES, "modes": channels.MODES,
                                                    "freqs": schedule.FREQS, "weekdays": schedule.WEEKDAYS,
                                                    "security": channels.EMAIL_SECURITY, "ntfy_auth": channels.NTFY_AUTH,
                                                    "help": HELP, "tz": schedule.hub_zone()[1], "errors": {}, "result": None,
                                                    "existing": None, **ctx}, status)

    def existing_or_404(cid: int) -> dict:
        with reader() as rc:
            ch = channels.get(rc, cid) if rc is not None else None
        if ch is None:
            raise HTTPException(404)
        return ch

    @app.get("/settings/notify/new")
    async def new_get(request: Request, kind: str = "slack"):
        require_login(request)
        return page(request, {"f": blank_form(kind if kind in channels.KINDS else "slack"), "secret_saved": False})

    @app.post("/settings/notify/new")
    async def new_post(request: Request):
        by = guard(request)
        form = await request.form()
        values, secret, _drop, errors = channels.parse_form(form, None, secret_saved_now=False)
        if not errors and channels.name_taken(conn, values["name"]):
            errors["name"] = "A channel with that name already exists."
        if errors:
            return page(request, {"f": form_from_post(form, values["kind"]), "errors": errors, "secret_saved": False}, 400)
        try:
            cid = channels.create(conn, cfg.data_dir, values, secret, by)
        except channels.Invalid as exc:
            return page(request, {"f": form_from_post(form, values["kind"]), "errors": {"name": str(exc)}, "secret_saved": False}, 400)
        except OSError as exc:
            log.error("Could not save a channel's secret: %s", exc.strerror or type(exc).__name__)
            return page(request, {"f": form_from_post(form, values["kind"]), "secret_saved": False,
                                  "errors": {"secret": "The secret could not be written. Check the data folder's permissions."}}, 500)
        hub_url_for(request, by, True)
        log.info("Notification channel %s (%s) added by %s from %s", values["name"], values["kind"], by, client(request))
        flash(request, f"Channel {values['name']} saved. Press Send test to check it.")
        return RedirectResponse("/settings/notifications#notify-channels", status_code=303)

    @app.get("/settings/notify/{cid}")
    async def edit_get(request: Request, cid: int):
        require_login(request)
        ch = existing_or_404(cid)
        return page(request, {"f": form_from_channel(ch), "existing": ch, "secret_saved": channels.secret_saved(cfg.data_dir, cid)})

    @app.post("/settings/notify/{cid}")
    async def edit_post(request: Request, cid: int):
        by = guard(request)
        ch = existing_or_404(cid)
        form = await request.form()
        saved = channels.secret_saved(cfg.data_dir, cid)
        values, secret, drop, errors = channels.parse_form(form, ch, secret_saved_now=saved)
        if not errors and channels.name_taken(conn, values["name"], cid):
            errors["name"] = "A channel with that name already exists."
        if errors:
            return page(request, {"f": form_from_post(form, ch["kind"]), "errors": errors, "existing": ch, "secret_saved": saved}, 400)
        try:
            changed = channels.update(conn, cfg.data_dir, cid, values, secret, drop, by)
        except channels.Invalid as exc:
            return page(request, {"f": form_from_post(form, ch["kind"]), "errors": {"name": str(exc)}, "existing": ch,
                                  "secret_saved": saved}, 400)
        except OSError as exc:
            log.error("Could not save a channel's secret: %s", exc.strerror or type(exc).__name__)
            return page(request, {"f": form_from_post(form, ch["kind"]), "existing": ch, "secret_saved": saved,
                                  "errors": {"secret": "The secret could not be written. Check the data folder's permissions."}}, 500)
        hub_url_for(request, by, True)
        log.info("Notification channel %s changed by %s from %s", values["name"], by, client(request))
        flash(request, f"Channel {values['name']} saved." if changed else "No changes: those values are already saved.")
        return RedirectResponse("/settings/notifications#notify-channels", status_code=303)

    @app.post("/settings/notify-test")
    async def test_post(request: Request):
        """Send the test message with the form as typed (a newly typed secret if there is one, else the saved one). Saves nothing."""
        by = guard(request)
        form = await request.form()
        raw = str(form.get("id", "")).strip()
        cid = int(raw) if raw.isdigit() else None
        saved_ch = channels.get(conn, cid) if cid else None
        if cid and saved_ch is None:
            raise HTTPException(404)
        hub_url = hub_url_for(request, by, False)
        saved = bool(saved_ch and channels.secret_saved(cfg.data_dir, cid))
        values, typed, drop, errors = channels.parse_form(form, saved_ch, secret_saved_now=saved)
        kind = saved_ch["kind"] if saved_ch else values["kind"]
        if errors:
            return page(request, {"f": form_from_post(form, kind), "errors": errors, "existing": saved_ch, "secret_saved": saved,
                                  "result": {"ok": False, "text": "Fix the marked fields before sending a test."}}, 400)
        secret = typed or (None if drop else (channels.read_secret(cfg.data_dir, cid) if saved_ch else None))
        probe = {"id": 0, "name": values["name"], "kind": values["kind"], "config": values["config"]}   # id 0: nothing is recorded
        reason = await engine.send_test(conn, cfg, probe, secret, hub_url, net)
        text = f"The test failed: {reason}." if reason else "The test message was sent with the settings on this page. Save to keep them."
        log.info("Test sent from the form of channel %s by %s from %s: %s", values["name"], by, client(request),
                 "failed" if reason else "ok")
        return page(request, {"f": form_from_post(form, kind), "existing": saved_ch, "secret_saved": saved,
                              "result": {"ok": reason is None, "text": text}})

    @app.get("/settings/notify/{cid}/remove")
    async def remove_get(request: Request, cid: int):
        require_login(request)
        ch = existing_or_404(cid)
        with reader() as rc:
            pending = rc.execute("SELECT COUNT(*) FROM notify_events WHERE channel_id=? AND state='pending'", (cid,)).fetchone()[0]
        return render(request, "notify_remove.html", {"page": "settings", "v": {"host": None}, "ch": ch, "pending": pending,
                                                      "kind": channels.KINDS[ch["kind"]],
                                                      "secret_saved": channels.secret_saved(cfg.data_dir, cid), "error": None})

    @app.post("/settings/notify/{cid}/remove")
    async def remove_post(request: Request, cid: int):
        by = guard(request)
        ch = existing_or_404(cid)
        form = await request.form()
        if str(form.get("confirm", "")).strip() != ch["name"]:
            return render(request, "notify_remove.html", {"page": "settings", "v": {"host": None}, "ch": ch,
                                                          "kind": channels.KINDS[ch["kind"]], "pending": 0,
                                                          "secret_saved": channels.secret_saved(cfg.data_dir, cid),
                                                          "error": "Type the channel's name exactly to remove it."}, 400)
        channels.remove(conn, cfg.data_dir, cid, by)
        log.info("Notification channel %s removed by %s from %s", ch["name"], by, client(request))
        flash(request, f"Channel {ch['name']} removed, with its saved secret and anything still waiting to be sent.")
        return RedirectResponse("/settings/notifications#notify-channels", status_code=303)
