"""Alert channels: what an administrator may set, how it is checked, and where it is kept.

A channel is a row in `notify_channels` (the name, the settings that are not secret, what it receives and when) and, when it
has one, a secret in `<data_dir>/notify/<id>.secret`, mode 0600 in a 0700 folder, written atomically. The secret is what
would let anyone send as the channel: a Slack or Discord webhook URL (the URL is the credential), an Ntfy access token or
password, or the SMTP password. It is never in the database, a page, an event or a log line, and is never shown again once
saved: a blank box on the edit page keeps it, a typed value replaces it. Removing the channel deletes the file.

Allowed destinations (docs/DESIGN.md, "Alert channels"):
  Slack    https://hooks.slack.com/services/...                  (Slack's incoming-webhook form)
  Discord  https://discord.com/api/webhooks/<id>/<token>         (Discord's docs name no other host)
  Ntfy     any https:// server, or http:// to this machine (loopback) only
  Email    an SMTP server over implicit TLS (465) or STARTTLS (587), never unencrypted
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from .. import db
from ..remote import store as remote_store
from . import schedule

KINDS = {"ntfy": "Ntfy", "slack": "Slack", "discord": "Discord", "email": "Email"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
DEFAULT_SEVERITIES = ("critical", "high")
MODES = (("immediate", "Immediately"), ("digest", "In a digest"), ("both", "Both"))
EMAIL_SECURITY = (("tls", "Implicit TLS (port 465)"), ("starttls", "STARTTLS (port 587)"))
EMAIL_DEFAULT_PORT = {"tls": 465, "starttls": 587}
NTFY_AUTH = (("none", "None"), ("token", "Access token"), ("basic", "User name and password"))
MAX_RECIPIENTS = 20
MAX_CHANNELS = 50

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TOKEN_RE = re.compile(r"^[\x21-\x7e]{8,200}$")
USER_RE = re.compile(r"^[\x21-\x7e]{1,100}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
ADDR_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
SLACK_PATH_RE = re.compile(r"^/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+$")
DISCORD_PATH_RE = re.compile(r"^/api/webhooks/(\d{5,25})/([A-Za-z0-9._-]{20,200})$")
SECRET_FILE_RE = re.compile(r"^notify/(\d{1,9})\.secret$")


class Invalid(ValueError):
    pass


# --- the secret files -----------------------------------------------------------------

def secret_dir(data_dir) -> Path:
    return Path(data_dir) / "notify"


def secret_path(data_dir, channel_id: int) -> Path:
    return secret_dir(data_dir) / f"{int(channel_id)}.secret"


def write_secret(data_dir, channel_id: int, text: str) -> Path:
    path = secret_path(data_dir, channel_id)
    remote_store.write_secret(path, text.strip() + "\n")
    return path


def read_secret(data_dir, channel_id: int) -> str | None:
    try:
        text = secret_path(data_dir, channel_id).read_text().strip()
    except OSError:
        return None
    return text or None


def secret_saved(data_dir, channel_id: int) -> bool:
    return read_secret(data_dir, channel_id) is not None


def delete_secret(data_dir, channel_id: int) -> bool:
    try:
        secret_path(data_dir, channel_id).unlink()
        return True
    except OSError:
        return False


def key_files(data_dir) -> dict[str, Path]:
    """Every saved secret as the name a backup archive stores it under."""
    out = {}
    for p in sorted(secret_dir(data_dir).glob("*.secret")):
        if p.is_file() and SECRET_FILE_RE.match(f"notify/{p.name}"):
            out[f"notify/{p.name}"] = p
    return out


def member_path(data_dir, member: str) -> Path | None:
    m = SECRET_FILE_RE.match(member)
    return secret_path(data_dir, int(m.group(1))) if m else None


# --- checking what was typed ----------------------------------------------------------

def clean_name(raw: str | None) -> str:
    name = " ".join((raw or "").split())
    if not NAME_RE.match(name):
        raise Invalid("The name is 1 to 40 characters: letters, digits, spaces, dots, dashes and underscores, "
                      "starting with a letter or digit.")
    return name


def _no_extras(parts, what: str) -> None:
    if parts.username or parts.password or parts.query or parts.fragment:
        raise Invalid(f"Leave out any user name, password, query or fragment in the {what}.")


def clean_webhook(kind: str, raw: str | None) -> str:
    """A Slack or Discord webhook URL, or an error saying what is wrong. The check is on the whole URL, so a look-alike host
    (hooks.slack.com.example.org, a user name before the host) is refused."""
    url = (raw or "").strip()
    if not url or len(url) > 300 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise Invalid("Paste the webhook URL.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise Invalid("That is not a valid URL.") from None
    if kind == "slack":
        host, ok_path, example = "hooks.slack.com", SLACK_PATH_RE, "https://hooks.slack.com/services/T000/B000/XXXX"
    else:
        host, ok_path, example = "discord.com", DISCORD_PATH_RE, "https://discord.com/api/webhooks/123456789/abcdef"
    if parts.scheme != "https" or parts.hostname != host or port not in (None, 443) or parts.username or parts.password \
            or parts.query or parts.fragment or not ok_path.match(parts.path):
        raise Invalid(f"A {KINDS[kind]} webhook URL looks like {example}.")
    return url


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def clean_ntfy_server(raw: str | None) -> str:
    """An Ntfy server's address: https anywhere, or http to this machine. A path may follow (a server behind a prefix)."""
    url = (raw or "").strip()
    if not url or len(url) > 200 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise Invalid("Enter the Ntfy server's address, for example https://ntfy.sh.")
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError:
        raise Invalid("That is not a valid address.") from None
    if not parts.hostname:
        raise Invalid("Enter the Ntfy server's address, for example https://ntfy.sh.")
    _no_extras(parts, "address")
    if parts.scheme == "http":
        if not _loopback(parts.hostname):
            raise Invalid("Use an https:// address. Plain http is only allowed to this machine (localhost), because the "
                          "access token and the findings would travel in the clear.")
    elif parts.scheme != "https":
        raise Invalid("The address must start with https://.")
    return url.rstrip("/")


def clean_topic(raw: str | None) -> str:
    topic = (raw or "").strip()
    if not TOPIC_RE.match(topic):
        raise Invalid("The topic is 1 to 64 characters: letters, digits, dashes and underscores. "
                      "Anyone who knows a topic on a public server can read it, so make it hard to guess.")
    return topic


def clean_token(raw: str | None) -> str:
    token = (raw or "").strip()
    if not TOKEN_RE.match(token):
        raise Invalid("An access token is 8 to 200 printable characters with no spaces (Ntfy's start with tk_).")
    return token


def clean_password(raw: str | None) -> str:
    pw = (raw or "").strip()
    if not 1 <= len(pw) <= 200 or any(ord(c) < 32 or ord(c) == 127 for c in pw):
        raise Invalid("The password is 1 to 200 characters, with no line breaks.")
    return pw


def clean_address(raw: str | None, what: str = "address") -> str:
    addr = (raw or "").strip()
    if len(addr) > 254 or not ADDR_RE.match(addr):
        raise Invalid(f"{addr[:60] or 'Empty'!r} is not an email {what}.")
    return addr


def clean_recipients(raw: str | None) -> list[str]:
    items = [x for x in re.split(r"[\s,;]+", (raw or "").strip()) if x]
    if not items:
        raise Invalid("Enter at least one recipient.")
    out: list[str] = []
    for item in items:
        a = clean_address(item, "address")
        if a.lower() not in [x.lower() for x in out]:
            out.append(a)
    if len(out) > MAX_RECIPIENTS:
        raise Invalid(f"At most {MAX_RECIPIENTS} recipients.")
    return out


def clean_mail_host(raw: str | None) -> str:
    host = (raw or "").strip().lower()
    if not HOST_RE.match(host):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise Invalid("Enter the mail server's name, for example smtp.example.com.") from None
    return host


def clean_hub_url(raw: str | None) -> str:
    """The address links point at: http or https, a host, an optional port and path. Blank is allowed (links are left out until
    one is set)."""
    url = (raw or "").strip()
    if not url:
        return ""
    if len(url) > 200 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise Invalid("Enter the hub's address, for example https://daemonsight.example.com.")
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError:
        raise Invalid("That is not a valid address.") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Invalid("Enter the hub's address, for example https://daemonsight.example.com.")
    _no_extras(parts, "address")
    return url.rstrip("/")


def origin_of(scheme: str, host_header: str | None) -> str:
    """The address the administrator used, from the request, or "" when it can't be used."""
    try:
        return clean_hub_url(f"{scheme}://{(host_header or '').strip()}")
    except Invalid:
        return ""


# --- reading a form ------------------------------------------------------------------

def _flag(form, name: str) -> bool:
    return str(form.get(name, "")).strip().lower() in ("on", "1", "true", "yes")


def _int(form, name: str, lo: int, hi: int, label: str, errors: dict, default: int) -> int:
    raw = str(form.get(name, "")).strip()
    if raw == "":
        return default
    try:
        n = int(raw)
    except ValueError:
        errors[name] = f"{label} must be a whole number from {lo} to {hi}."
        return default
    if not lo <= n <= hi:
        errors[name] = f"{label} must be from {lo} to {hi}."
    return n


def parse_form(form, existing: dict | None, *, secret_saved_now: bool) -> tuple[dict, str | None, bool, dict]:
    """(values, new secret or None, delete the saved secret, errors) from a posted form. `form` has `.get` and, for the
    severities, `.getlist`. `existing` is the channel being edited (its kind and type of login can't change under a saved
    secret without a new one). Nothing is stored here."""
    errors: dict[str, str] = {}
    kind = existing["kind"] if existing else str(form.get("kind", "")).strip()
    if kind not in KINDS:
        errors["kind"] = "Choose a type."
        kind = "slack"
    values: dict = {"kind": kind}

    def attempt(field: str, fn, *args, default=""):
        try:
            return fn(*args)
        except Invalid as exc:
            errors[field] = str(exc)
            return default

    values["name"] = attempt("name", clean_name, form.get("name"))
    sev = [s for s in form.getlist("severity") if s in SEVERITIES] if hasattr(form, "getlist") else \
        [s for s in (form.get("severity") or []) if s in SEVERITIES]
    values["severities"] = [s for s in SEVERITIES if s in sev]
    if not values["severities"]:
        errors["severity"] = "Choose at least one severity."
    mode = str(form.get("mode", "immediate")).strip()
    if mode not in dict(MODES):
        errors["mode"] = "Choose when to send."
        mode = "immediate"
    values["mode"] = mode
    values["send_resolved"] = _flag(form, "send_resolved")
    values["deadline_reminders"] = _flag(form, "deadline_reminders")
    values["skip_empty"] = _flag(form, "skip_empty")
    freq = str(form.get("digest_freq", "daily")).strip()
    if freq not in dict(schedule.FREQS):
        errors["digest_freq"] = "Choose daily, weekly or monthly."
        freq = "daily"
    values["digest_freq"] = freq
    t = str(form.get("digest_time", "08:00")).strip() or "08:00"
    if not schedule.TIME_RE.match(t):
        errors["digest_time"] = "Enter a time like 08:00 (24-hour)."
        t = "08:00"
    values["digest_time"] = t
    values["digest_weekday"] = _int(form, "digest_weekday", 0, 6, "The weekday", errors, 0)
    values["digest_day"] = _int(form, "digest_day", 1, 28, "The day of the month", errors, 1)

    typed = str(form.get("secret", "") or "").strip()
    old_cfg = (existing or {}).get("config") or {}
    config: dict = {}
    secret: str | None = None
    need_secret = False
    drop_secret = False
    if kind in ("slack", "discord"):
        need_secret = True
        if typed:
            secret = attempt("secret", clean_webhook, kind, typed, default=None)
    elif kind == "ntfy":
        config["server"] = attempt("ntfy_server", clean_ntfy_server, form.get("ntfy_server"))
        config["topic"] = attempt("ntfy_topic", clean_topic, form.get("ntfy_topic"))
        auth = str(form.get("ntfy_auth", "none")).strip()
        if auth not in dict(NTFY_AUTH):
            errors["ntfy_auth"] = "Choose how to log in."
            auth = "none"
        config["auth"] = auth
        if auth == "basic":
            user = str(form.get("ntfy_user", "")).strip()
            if not USER_RE.match(user) or ":" in user:
                errors["ntfy_user"] = "Enter the user name (no spaces or colons)."
            config["user"] = user
        if auth == "none":
            drop_secret = True
        else:
            need_secret = True
            changed = old_cfg.get("auth") != auth
            if typed:
                secret = attempt("secret", clean_token if auth == "token" else clean_password, typed, default=None)
            elif changed:
                errors["secret"] = "Enter the access token." if auth == "token" else "Enter the password."
    else:
        config["host"] = attempt("email_host", clean_mail_host, form.get("email_host"))
        sec = str(form.get("email_security", "tls")).strip()
        if sec not in dict(EMAIL_SECURITY):
            errors["email_security"] = "Choose implicit TLS or STARTTLS. Unencrypted mail is not offered."
            sec = "tls"
        config["security"] = sec
        config["port"] = _int(form, "email_port", 1, 65535, "The port", errors, EMAIL_DEFAULT_PORT[sec])
        user = str(form.get("email_user", "")).strip()
        if user and (len(user) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in user)):
            errors["email_user"] = "The user name is up to 200 characters, with no line breaks."
        config["user"] = user
        config["from"] = attempt("email_from", clean_address, form.get("email_from"), "address")
        config["to"] = attempt("email_to", clean_recipients, form.get("email_to"), default=[])
        if user:
            need_secret = True
            if typed:
                secret = attempt("secret", clean_password, typed, default=None)
        else:
            drop_secret = True
    values["config"] = config
    if need_secret and secret is None and "secret" not in errors and not secret_saved_now:
        errors["secret"] = {"slack": "Paste the webhook URL.", "discord": "Paste the webhook URL.",
                            "ntfy": "Enter the access token." if config.get("auth") == "token" else "Enter the password.",
                            "email": "Enter the password for that user name."}[kind]
    return values, secret, drop_secret, errors


# --- the rows ------------------------------------------------------------------------

def _row(r) -> dict:
    d = dict(r)
    d["config"] = json.loads(d["config"] or "{}")
    d["severities"] = [s for s in json.loads(d["severities"] or "[]") if s in SEV_RANK]
    for k in ("send_resolved", "deadline_reminders", "skip_empty"):
        d[k] = bool(d[k])
    return d


def get(conn, channel_id: int) -> dict | None:
    r = conn.execute("SELECT * FROM notify_channels WHERE id = ?", (channel_id,)).fetchone()
    return _row(r) if r else None


def all_channels(conn) -> list[dict]:
    try:
        return [_row(r) for r in conn.execute("SELECT * FROM notify_channels ORDER BY name COLLATE NOCASE")]
    except Exception:
        return []


def name_taken(conn, name: str, except_id: int | None = None) -> bool:
    r = conn.execute("SELECT id FROM notify_channels WHERE lower(name) = lower(?)", (name,)).fetchone()
    return bool(r) and r["id"] != except_id


def _event(conn, ts: float, title: str, by: str, detail: str | None = None) -> None:
    db.add_event(conn, db.HUB_HOST, ts, "setting", title[:300], detail=detail or f"by {by}")


def summary(ch: dict) -> str:
    """What a channel receives, for the event log and the list: "critical, high; immediately"."""
    mode = dict(MODES)[ch["mode"]].lower()
    return f"{', '.join(ch['severities'])}; {mode}"


def _next_digest(values: dict, now: float) -> float | None:
    if values["mode"] == "immediate":
        return None
    tz, _name = schedule.hub_zone()
    return schedule.next_run(values["digest_freq"], values["digest_time"], values["digest_weekday"],
                             values["digest_day"], now, tz)


def create(conn, data_dir, values: dict, secret: str | None, by: str, now: float | None = None) -> int:
    """Add a channel (values already checked by parse_form) and log it. Returns its id."""
    now = time.time() if now is None else now
    if conn.execute("SELECT COUNT(*) FROM notify_channels").fetchone()[0] >= MAX_CHANNELS:
        raise Invalid(f"At most {MAX_CHANNELS} channels.")
    if name_taken(conn, values["name"]):
        raise Invalid("A channel with that name already exists.")
    cid = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO notify_channels (name, kind, config, severities, mode, send_resolved, deadline_reminders, "
            "digest_freq, digest_time, digest_weekday, digest_day, skip_empty, created_at, last_digest_at, next_digest_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (values["name"], values["kind"], json.dumps(values["config"]), json.dumps(values["severities"]), values["mode"],
             int(values["send_resolved"]), int(values["deadline_reminders"]), values["digest_freq"], values["digest_time"],
             values["digest_weekday"], values["digest_day"], int(values["skip_empty"]), now, now, _next_digest(values, now)))
        cid = cur.lastrowid
        if secret:
            write_secret(data_dir, cid, secret)
        _event(conn, now, f"Notification channel added: {values['name']} ({KINDS[values['kind']]})", by,
               f"by {by}; {summary({**values})}")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        if cid is not None:
            delete_secret(data_dir, cid)
        raise
    return cid


def update(conn, data_dir, channel_id: int, values: dict, secret: str | None, drop_secret: bool, by: str,
           now: float | None = None) -> list[str]:
    """Save an edited channel and log what changed (never the secret's value). Returns the names of what changed."""
    now = time.time() if now is None else now
    old = get(conn, channel_id)
    if old is None:
        raise Invalid("That channel no longer exists.")
    if name_taken(conn, values["name"], channel_id):
        raise Invalid("A channel with that name already exists.")
    labels = {"name": "name", "severities": "severities", "mode": "when it sends", "send_resolved": "resolved alerts",
              "deadline_reminders": "deadline reminders", "digest_freq": "digest frequency", "digest_time": "digest time",
              "digest_weekday": "digest weekday", "digest_day": "digest day", "skip_empty": "skip empty digests",
              "config": "settings"}
    changed = [labels[k] for k in labels if values[k] != old[k]]
    if secret:
        changed.append("login" if old["kind"] == "ntfy" else "password" if old["kind"] == "email" else "webhook URL")
    if drop_secret and secret_saved(data_dir, channel_id):
        changed.append("saved secret removed")
    schedule_changed = any(values[k] != old[k] for k in ("mode", "digest_freq", "digest_time", "digest_weekday", "digest_day"))
    conn.execute("BEGIN IMMEDIATE")
    try:
        nxt = _next_digest(values, now) if schedule_changed or old["next_digest_at"] is None else old["next_digest_at"]
        if values["mode"] == "immediate":
            nxt = None
        last = old["last_digest_at"] if values["mode"] != "immediate" and old["mode"] != "immediate" else now
        conn.execute(
            "UPDATE notify_channels SET name=?, config=?, severities=?, mode=?, send_resolved=?, deadline_reminders=?, "
            "digest_freq=?, digest_time=?, digest_weekday=?, digest_day=?, skip_empty=?, next_digest_at=?, last_digest_at=? "
            "WHERE id=?",
            (values["name"], json.dumps(values["config"]), json.dumps(values["severities"]), values["mode"],
             int(values["send_resolved"]), int(values["deadline_reminders"]), values["digest_freq"], values["digest_time"],
             values["digest_weekday"], values["digest_day"], int(values["skip_empty"]), nxt, last, channel_id))
        if secret:
            write_secret(data_dir, channel_id, secret)
        elif drop_secret:
            delete_secret(data_dir, channel_id)
        if changed:
            _event(conn, now, f"Notification channel changed: {values['name']}", by,
                   f"by {by}; changed: {', '.join(changed)}")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return changed


def remove(conn, data_dir, channel_id: int, by: str, now: float | None = None) -> dict | None:
    now = time.time() if now is None else now
    old = get(conn, channel_id)
    if old is None:
        return None
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM notify_events WHERE channel_id = ?", (channel_id,))
        conn.execute("DELETE FROM notify_seen WHERE channel_id = ?", (channel_id,))
        conn.execute("DELETE FROM notify_channels WHERE id = ?", (channel_id,))
        _event(conn, now, f"Notification channel removed: {old['name']} ({KINDS[old['kind']]})", by)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    delete_secret(data_dir, channel_id)
    return old


def record_result(conn, channel_id: int, ok: bool, error: str | None, now: float) -> None:
    """After a send (or a test): when it last worked, or what went wrong. A working send clears the error, and the
    "gave up" note (a person has seen it work again)."""
    if ok:
        conn.execute("UPDATE notify_channels SET last_ok=?, last_error=NULL, last_error_at=NULL, gave_up_at=NULL, "
                     "gave_up_count=0 WHERE id=?", (now, channel_id))
    else:
        conn.execute("UPDATE notify_channels SET last_error=?, last_error_at=? WHERE id=?",
                     ((error or "")[:300], now, channel_id))
