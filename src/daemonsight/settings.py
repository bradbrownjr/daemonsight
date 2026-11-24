"""Settings that can be changed in the web UI, and how they combine with the
config file.

The effective value of a setting is, in this order:
  1. a value set on the Settings page (a row in the `settings` table of
     state.db, written only by the hub's web process),
  2. the value in the config file,
  3. the default in config.py.

The config file is never rewritten. Only the settings listed in FIELDS can be
set from the browser. What controls login, where the server listens or where
it keeps its files is not in the list, so a wrong value there can never lock
anyone out of the page that would fix it (see READ_ONLY, shown on the page).

Chores call `effective()` at the start of every pass, so a change applies at
their next pass with no restart.
"""

from __future__ import annotations

import copy
import json
import logging
import math
import sqlite3
import time
from dataclasses import dataclass

from .config import Config

log = logging.getLogger("daemonsight.settings")

DEFAULT = "Default"
FILE = "Config file"
HERE = "Set here"


@dataclass(frozen=True)
class Field:
    key: str                    # "outside.enabled": the config file's [section] and name
    label: str
    group: str
    kind: str                   # "bool", "int", "float", "addresses", "choice"
    help: str
    lo: float | None = None
    hi: float | None = None
    nullable: bool = False      # blank means "automatic" (stored as null)
    unit: str = ""
    choices: tuple[tuple[str, str], ...] = ()    # kind "choice": (stored value, label shown)

    @property
    def section(self) -> str:
        return self.key.split(".", 1)[0]

    @property
    def attr(self) -> str:
        return self.key.split(".", 1)[1]

    @property
    def name(self) -> str:
        """Name shown in Recent changes: "Outside view, enabled"."""
        return f"{GROUPS[self.group]['title']}, {self.attr.replace('_', ' ')}"


GROUPS = {
    "outside": {"title": "Outside view", "hub_only": True,
                "intro": "Asks Shodan what the internet sees of each host's public addresses. Only the IP address "
                         "is sent.",
                "note_title": "Shodan's terms",
                "note": "InternetDB is free for non-commercial use only. Shodan: \"If you're using the InternetDB "
                        "API to make money then you need an enterprise license.\" A key doesn't change that. "
                        "For commercial use, choose the Shodan API on a plan that lists Commercial Use "
                        "(Freelancer, Small Business or Corporate). Shodan allows its API in products \"as long as the "
                        "data is attributed to Shodan\"; DaemonSight names Shodan wherever it shows it. Shodan doesn't say whether the "
                        "one-time Membership allows commercial use, so ask them. The Enterprise Data License "
                        "allows it without attribution.",
                "note_links": (("Shodan plans and pricing", "https://developer.shodan.io/pricing"),
                               ("InternetDB and its terms", "https://internetdb.shodan.io/"))},
    "cve": {"title": "CVE checks", "hub_only": True,
            "intro": "Downloads the Debian security tracker, FIRST's EPSS scores and CISA's KEV list, and matches "
                     "each host's packages against them.", "note": ""},
    "retention": {"title": "Retention", "hub_only": False,
                  "intro": "How long the database keeps history. On a hub this applies to every host's rows. "
                           "0 keeps it for good.", "note": ""},
    "backup": {"title": "Backups", "hub_only": False,
               "intro": "Scheduled backups of the database, config file and secrets. The folder is set in the "
                        "config file only.", "note": ""},
    "remote": {"title": "Remote systems", "hub_only": True,
               "intro": "Reading systems that have no collector (Unraid and OPNsense) over their API. Systems are added "
                        "under Hosts, Add a system; each one sets its own read interval there.", "note": ""},
}

# Beside a group: how to get what it needs. Steps follow Shodan's own pages (linked); check them when Shodan
# changes its site.
GUIDES = {
    "outside": {
        "title": "Getting a Shodan API key",
        "steps": [
            "Create a Shodan account at account.shodan.io and pick a plan. IP lookups need at least a "
            "Membership; a free account's key is refused. For commercial use, see Shodan's terms (the i button).",
            "Copy the API key from your account page.",
            "Choose Shodan API (your key) as the Source and paste the key.",
            "Press Test key to see your plan and credits, then Save outside view. Lookups use no query credits.",
        ],
        "links": [
            ("Your Shodan account and API key", "https://account.shodan.io/"),
            ("Shodan plans and pricing", "https://developer.shodan.io/pricing"),
            ("Shodan REST API reference", "https://developer.shodan.io/api"),
            ("How Shodan counts credits", "https://book.shodan.io/developer-apis/shodan-api/"),
            ("InternetDB and its terms", "https://internetdb.shodan.io/"),
        ],
    },
}

FIELDS: tuple[Field, ...] = (
    Field("outside.enabled", "Enabled", "outside", "bool",
          "Ask Shodan about each host's public addresses. Off makes no requests and closes any outside.* finding at the next pass."),
    Field("outside.source", "Source", "outside", "choice",
          "InternetDB needs no key. The Shodan API adds each port's protocol, product, version and last-seen "
          "time, and needs your key.",
          choices=(("internetdb", "InternetDB (free, non-commercial)"), ("shodan", "Shodan API (your key)"))),
    Field("outside.addresses", "Extra addresses", "outside", "addresses",
          "One per line: an IP address, or ip=hostid to attach an address no collector reports (a router's, "
          "say) to that host. Private addresses are refused."),
    Field("outside.refresh_hours", "Check every", "outside", "float",
          "Hours between checks of each address. InternetDB updates about weekly; Shodan crawls the internet at least weekly.", 1, 720, unit="hours"),
    Field("cve.enabled", "Enabled", "cve", "bool",
          "Download the feeds and match packages. Off makes no downloads and closes any cve.* finding at the "
          "next pass."),
    Field("cve.refresh_hours", "Check every", "cve", "float",
          "Hours between checks of each feed. An unchanged file costs one small request.", 1, 720, unit="hours"),
    Field("cve.epss_high", "EPSS score for High", "cve", "float",
          "A fixable CVE with an EPSS score at or above this makes its package's finding High. FIRST: "
          "\"There is no universal threshold\"; 0.10 is the figure it says is commonly cited.", 0.01, 1.0),
    Field("retention.metrics_hours", "Keep chart points for", "retention", "int",
          "Chart points, about one a second per host. 0 keeps them for good.", 0, 87600, unit="hours"),
    Field("retention.events_days", "Keep Recent changes for", "retention", "int",
          "Events under Recent changes. 0 keeps them for good.", 0, 36500, unit="days"),
    Field("retention.resolved_findings_days", "Keep cleared findings for", "retention", "int",
          "Findings that have cleared. Open findings are never removed. 0 keeps them for good.", 0, 36500,
          unit="days"),
    Field("backup.interval_hours", "Back up every", "backup", "int",
          "Hours between scheduled backups; 0 turns them off. Blank is automatic: every 24 hours here.",
          0, 8760, nullable=True, unit="hours"),
    Field("backup.keep", "Keep the newest", "backup", "int",
          "How many backups to keep; older ones are deleted.", 1, 365, unit="backups"),
    Field("remote.enabled", "Read remote systems", "remote", "bool",
          "Off stops all reading of Unraid systems. Their last data stays on the pages."),
)
BY_KEY = {f.key: f for f in FIELDS}

# Never editable in the browser: a mistake in any of these could cut off the page needed to fix it, or
# change what the server exposes. (key, label, why)
LISTEN = "Where the server listens. A wrong value makes this page unreachable."
AUTH = "Controls who can log in. A mistake could lock you out of this page."
FILES = "A path the server needs to start. A wrong value stops it starting."
READ_ONLY: tuple[tuple[str, str, str], ...] = (
    ("web.listen", "Web listen address", LISTEN),
    ("web.port", "Web port", LISTEN),
    ("web.trusted_proxies", "Trusted proxies", "Decides which address a login attempt is blamed on. " + AUTH),
    ("web.secure_cookies", "Secure cookies", AUTH),
    ("web.session_hours", "Session length", AUTH),
    ("web.password_file", "Password file", AUTH),
    ("web.secret_file", "Session secret file", AUTH),
    ("data_dir", "Data folder", FILES),
    ("@db_path", "Database", FILES),
    ("@shodan_key_path", "Shodan key file", "Where the Shodan API key is saved (mode 0600). The key itself is "
                                           "never shown, and is saved from this page. Set as key_file under [outside]; blank means "
                                           "shodan.key in the data folder. " + FILES),
    ("@backup_dir", "Backup folder", "Where backups are written, which hold the secrets. " + FILES),
    ("log_file", "Log file", FILES),
    ("hub.enabled", "Hub enabled", "Turns this install into a hub. Turning it off from here would remove this page."),
    ("hub.max_upload_mb", "Largest upload", "Limits what the open upload address accepts."),
    ("hub.max_unpacked_mb", "Largest upload, unpacked", "Limits what the open upload address accepts."),
    ("upload.url", "Upload address", "Where this install sends its data. Changing it elsewhere sends data there."),
    ("upload.token_file", "Upload token file", "The secret this install uploads with. It is set with the set-upload-token command."),
    ("upload.interval", "Upload interval", "Set in the config file with the upload address."),
    ("upload.remote_update", "Install updates the hub asks for", "A host decides this for itself; a hub can't "
                                                              "change it."),
)

MAX_ADDRESSES = 100


# --- reading values ---------------------------------------------------------------------

def _defaults() -> Config:
    return Config()


def default_of(f: Field):
    return getattr(getattr(_defaults(), f.section), f.attr)


def get(cfg: Config, f: Field):
    """The value a Config holds for a field. [retention] metrics_hours may
    come from its old name, [collector] metrics_retention_hours."""
    if f.key == "retention.metrics_hours":
        return cfg.metrics_hours
    return getattr(getattr(cfg, f.section), f.attr)


def _set(cfg: Config, f: Field, value) -> None:
    if f.key == "retention.metrics_hours":
        cfg.collector.metrics_retention_hours = None   # the old name would win over this
    target = getattr(cfg, f.section)
    setattr(target, f.attr, list(value) if isinstance(value, list) else value)


def file_value(base: Config, f: Field):
    """What the config file and defaults give, ignoring anything set here."""
    return get(base, f)


# --- validation -------------------------------------------------------------------------

class Invalid(ValueError):
    pass


def _range_text(f: Field) -> str:
    lo, hi = f.lo, f.hi
    return f"{lo:g} to {hi:g}"


def check_address(entry: str) -> str:
    """One extra address, "ip" or "ip=hostid", in the form that is stored."""
    from . import hub, outside
    ip_text, eq, host = entry.partition("=")
    ip = outside.sendable(ip_text.strip())
    if ip is None:
        raise Invalid(f"{ip_text.strip()[:60]!r} is not a public IP address.")
    host = host.strip()
    if eq and not hub.HOST_RE.match(host):
        raise Invalid(f"{host[:60]!r} is not a host id (letters, digits, dot, dash and underscore).")
    return f"{ip}={host}" if host else ip


def parse(f: Field, raw) -> object:
    """Turn what a form posted (text) into a value, or raise Invalid with a message a person can act on."""
    text = raw if isinstance(raw, str) else str(raw)
    if f.kind == "bool":
        t = text.strip().lower()
        if t in ("on", "true", "1", "yes"):
            return True
        if t in ("off", "false", "0", "no"):
            return False
        raise Invalid("Choose On or Off.")
    if f.kind == "choice":
        t = text.strip()
        if t not in dict(f.choices):
            raise Invalid("Choose one of: " + ", ".join(label for _v, label in f.choices) + ".")
        return t
    if f.kind == "addresses":
        out: list[str] = []
        for line in text.replace("\r", "").split("\n"):
            line = line.strip()
            if not line:
                continue
            item = check_address(line)
            if item not in out:
                out.append(item)
        if len(out) > MAX_ADDRESSES:
            raise Invalid(f"At most {MAX_ADDRESSES} addresses.")
        return out
    t = text.strip()
    if t == "" and f.nullable:
        return None
    try:
        if f.kind == "int":
            if not t.lstrip("+-").isdigit():
                raise ValueError
            n: float = int(t)
        else:
            n = float(t)
            if not math.isfinite(n):
                raise ValueError
    except ValueError:
        raise Invalid(f"Enter a number, {_range_text(f)}.") from None
    return _check_range(f, n)


def _check_range(f: Field, n):
    if (f.lo is not None and n < f.lo) or (f.hi is not None and n > f.hi):
        raise Invalid(f"Enter a number from {_range_text(f)}.")
    return n


def valid_stored(f: Field, value) -> object:
    """A value read back from the database, checked again: a row that
    doesn't fit its field is ignored, never applied."""
    if f.kind == "bool":
        if isinstance(value, bool):
            return value
        raise Invalid("not a boolean")
    if f.kind == "choice":
        if isinstance(value, str) and value in dict(f.choices):
            return value
        raise Invalid("not one of the choices")
    if f.kind == "addresses":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise Invalid("not a list of text")
        return [check_address(v) for v in value]
    if value is None and f.nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Invalid("not a number")
    if f.kind == "int" and not isinstance(value, int):
        raise Invalid("not a whole number")
    if isinstance(value, float) and not math.isfinite(value):
        raise Invalid("not finite")
    return _check_range(f, value)


# --- the overrides table ---------------------------------------------------------------

def overrides(conn) -> dict[str, object]:
    """Every valid override in the settings table, key -> value."""
    if conn is None:
        return {}
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    except sqlite3.Error:        # no table yet (a database no hub has migrated)
        return {}
    out = {}
    for r in rows:
        f = BY_KEY.get(r["key"])
        if f is None:
            log.warning("Ignoring unknown setting %r in the database", r["key"])
            continue
        try:
            out[f.key] = valid_stored(f, json.loads(r["value"]))
        except (ValueError, TypeError) as exc:
            log.warning("Ignoring setting %s in the database: %s", f.key, exc)
    return out


def rows(conn) -> dict[str, dict]:
    """key -> {changed_at, changed_by} for each stored override."""
    if conn is None:
        return {}
    try:
        return {r["key"]: {"changed_at": r["changed_at"], "changed_by": r["changed_by"]}
                for r in conn.execute("SELECT key, changed_at, changed_by FROM settings")}
    except sqlite3.Error:
        return {}


def effective(base: Config, conn=None) -> Config:
    """The config with the Settings page's overrides applied. `base` (the
    config file over the defaults) is returned itself when nothing is set
    here; callers never change what they get back."""
    found = overrides(conn)
    if not found:
        return base
    cfg = copy.deepcopy(base)
    for key, value in found.items():
        _set(cfg, BY_KEY[key], value)
    return cfg


def source_of(base: Config, f: Field, found: dict) -> str:
    if f.key in found:
        return HERE
    if f.key in getattr(base, "file_keys", ()) or file_value(base, f) != default_of(f):
        return FILE
    return DEFAULT


# --- changing them ---------------------------------------------------------------------

def show(f: Field, value) -> str:
    """A value as text, for the page and for Recent changes."""
    if f.kind == "bool":
        return "on" if value else "off"
    if f.kind == "addresses":
        return ", ".join(value) if value else "none"
    if f.kind == "choice":
        return dict(f.choices).get(value, str(value))
    if value is None:
        return "automatic"
    return f"{value:g}" if isinstance(value, float) else str(value)


def _event(conn, ts: float, title: str, by: str, detail: str | None = None) -> None:
    from . import db
    db.add_event(conn, db.HUB_HOST, ts, "setting", title, detail=detail or f"by {by}")


def save(conn, base: Config, changes: dict[str, object], by: str, now: float | None = None) -> list[str]:
    """Store overrides and log each as a hub-wide event, in one transaction.
    `changes` holds validated values. A value equal to the one already in
    effect is skipped. Returns the keys that changed."""
    now = time.time() if now is None else now
    current = effective(base, conn)
    changed = []
    conn.execute("BEGIN IMMEDIATE")
    try:
        for key, value in changes.items():
            f = BY_KEY[key]
            old = get(current, f)
            if value == old:
                continue
            conn.execute("INSERT INTO settings (key, value, changed_at, changed_by) VALUES (?, ?, ?, ?) "
                         "ON CONFLICT (key) DO UPDATE SET value = excluded.value, "
                         "changed_at = excluded.changed_at, changed_by = excluded.changed_by",
                         (key, json.dumps(value), now, by))
            _event(conn, now, f"Setting changed: {f.name}: {show(f, old)} → {show(f, value)}"[:300], by)
            changed.append(key)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return changed


def reset(conn, base: Config, key: str, by: str, now: float | None = None) -> bool:
    """Delete an override, so the config file's value (or the default) applies
    again. Returns False when nothing was set."""
    now = time.time() if now is None else now
    f = BY_KEY[key]
    old = get(effective(base, conn), f)
    conn.execute("BEGIN IMMEDIATE")
    try:
        gone = conn.execute("DELETE FROM settings WHERE key = ?", (key,)).rowcount > 0
        if gone:
            new = file_value(base, f)
            origin = "config file" if source_of(base, f, {}) == FILE else "default"
            _event(conn, now, f"Setting reset: {f.name}: {show(f, old)} → {show(f, new)} ({origin})"[:300], by)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return gone


# --- what the page shows ---------------------------------------------------------------

def describe(base: Config, conn, hub: bool) -> list[dict]:
    """The editable settings grouped for the page: per group, a title and
    each field with its effective value, default, file value and source."""
    found = overrides(conn) if hub else {}
    stored = rows(conn) if hub else {}
    cfg = effective(base, conn) if hub else base
    out = []
    for gid, g in GROUPS.items():
        items = []
        for f in (x for x in FIELDS if x.group == gid):
            value = get(cfg, f)
            src = source_of(base, f, found)
            items.append({
                "field": f, "key": f.key, "value": value, "text": show(f, value),
                "default": show(f, default_of(f)), "file": show(f, file_value(base, f)),
                "source": src, "base_source": source_of(base, f, {}), "set": f.key in found, "meta": stored.get(f.key),
                "range": _range_text(f) if f.lo is not None else "",
            })
        out.append({"id": gid, "hub_only": g["hub_only"], "title": g["title"], "intro": g["intro"],
                    "note": g["note"], "note_title": g.get("note_title", ""), "note_links": g.get("note_links", ()),
                    "fields": items, "guide": GUIDES.get(gid)})
    return out


def read_only(cfg: Config) -> list[dict]:
    """The settings that can only be changed in the config file, with their values."""
    out = []
    for key, label, why in READ_ONLY:
        if key.startswith("@"):
            value = str(getattr(cfg, key[1:]))
            name = key[1:]
        else:
            obj, _, attr = key.rpartition(".")
            value = getattr(getattr(cfg, obj) if obj else cfg, attr)
            name = key
        if isinstance(value, list):
            value = ", ".join(map(str, value)) or "none"
        elif isinstance(value, bool):
            value = "on" if value else "off"
        elif value == "":
            value = "not set"
        out.append({"key": name, "label": label, "value": str(value), "why": why})
    return out
