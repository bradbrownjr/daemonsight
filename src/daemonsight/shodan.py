"""The optional Shodan API key for the outside view, and the one call that tests it.

The outside view (outside.py) can ask Shodan's InternetDB, which needs no key
and is free for non-commercial use, or Shodan's own REST API with the owner's
key. This module holds what is specific to the key:

  - the key file: `<data_dir>/shodan.key` (or `[outside] key_file`), mode 0600,
    written atomically. The key is never in the database, a page, an event or a
    log line, and is never shown again once saved. Saving a new one replaces
    the file; removing it deletes the file. A backup carries the file, like the
    other secrets.
  - redaction: Shodan documents one way to send the key, the `key` query
    parameter (https://developer.shodan.io/api shows every request as
    `...?key={YOUR_API_KEY}`, and the official Python client sends it the same
    way, shodan/client.py `params['key'] = self.api_key`). No header is
    documented, so the key does travel in a URL. `redact` strips it from every
    error text, and a logging filter strips it from httpx's own "HTTP Request"
    lines, which print the whole URL.
  - `api_info`: GET https://api.shodan.io/api-info?key=..., which "Returns
    information about the API plan belonging to the given API key." Test key
    uses it: it shows the plan name and the credits, or why the key failed.

The key goes only to api.shodan.io over HTTPS. Redirects are never followed.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

import httpx

API = "https://api.shodan.io"
HOST_URL = API + "/shodan/host/"
INFO_URL = API + "/api-info"

# Shodan's own pages, linked from the Settings page and the source panels.
DOCS = "https://developer.shodan.io/api"
ACCOUNT = "https://account.shodan.io/"
PRICING = "https://developer.shodan.io/pricing"
MEMBERSHIP = "https://help.shodan.io/the-basics/account-faq"
CREDITS_DOC = "https://book.shodan.io/developer-apis/shodan-api/"
INTERNETDB = "https://internetdb.shodan.io/"
ENTERPRISE = "https://enterprise.shodan.io/"

# Shodan's pricing page: "All API plans are subject to a rate limit of 1 request per second".
RATE_LIMIT_GAP = 1.2         # seconds between two requests, a little over the documented limit

# Prefixes of the error text kept on an address when the key is the problem. outside.py turns them into an
# `outside.key` finding at once, instead of waiting for the "stale" rule's 72 hours.
KEY_REFUSED = "Shodan refused the API key"
KEY_MISSING = "No Shodan API key is saved"
NO_CREDITS = "Shodan says there are no query credits left"
KEY_PROBLEMS = {KEY_REFUSED: "refused", KEY_MISSING: "missing", NO_CREDITS: "credits"}

KEY_RE = re.compile(r"^[A-Za-z0-9._~-]{8,128}$")     # URL-safe characters only, so it can never alter a URL
_KEY_PARAM = re.compile(r"(?i)\b(key=)[^&\s'\"<>]+")


# ---- the key file ----------------------------------------------------------------

def key_path(cfg) -> Path:
    return Path(cfg.shodan_key_path)


def clean_key(raw: str | None) -> str:
    key = (raw or "").strip()
    if not KEY_RE.match(key):
        raise ValueError("That does not look like a Shodan API key. Copy it from your account page "
                         "(account.shodan.io): letters and digits only, no spaces.")
    return key


def read_key(cfg) -> str | None:
    try:
        key = key_path(cfg).read_text().strip()
    except OSError:
        return None
    return key if KEY_RE.match(key) else None


def key_saved(cfg) -> bool:
    return read_key(cfg) is not None


def write_key(cfg, raw: str) -> Path:
    """Save or replace the key. The new file is complete and 0600 before it takes the old one's place."""
    key = clean_key(raw)
    path = key_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(key + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return path


def delete_key(cfg) -> bool:
    try:
        key_path(cfg).unlink()
        return True
    except OSError:
        return False


# ---- redaction ---------------------------------------------------------------------

def redact(text, *secrets: str | None) -> str:
    """The text with any `key=...` query value, and any given secret, replaced. Applied to every error message
    and log line that could contain a Shodan URL."""
    out = _KEY_PARAM.sub(r"\1REDACTED", str(text))
    for s in secrets:
        if s:
            out = out.replace(s, "REDACTED")
    return out


class _RedactFilter(logging.Filter):
    """httpx logs "HTTP Request: GET https://api.shodan.io/...?key=... "HTTP/1.1 200 OK"" at INFO, with the full URL."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        if "key=" in message.lower():
            record.msg, record.args = redact(message), ()
        return True


_FILTER = _RedactFilter()


def install_log_redaction() -> None:
    """Put the filter on every logger that can print a request URL. A logger's filter runs before any handler
    sees the record, so every handler (journal, log file, a test's) gets the redacted line. Safe to call again."""
    for name in ("httpx", "httpcore"):
        lg = logging.getLogger(name)
        if _FILTER not in lg.filters:
            lg.addFilter(_FILTER)


def filter_handler(handler: logging.Handler) -> None:
    """Also filter a handler, for a log line some other logger might write about a URL."""
    if _FILTER not in handler.filters:
        handler.addFilter(_FILTER)


install_log_redaction()


# ---- reading an answer --------------------------------------------------------------

def _message(body: bytes) -> str | None:
    """The reason in Shodan's error body, {"error": "..."}, trimmed and checked; None when there is none."""
    import json
    try:
        data = json.loads(body[:65536])
    except (ValueError, RecursionError):
        return None
    msg = data.get("error") if isinstance(data, dict) else None
    if not isinstance(msg, str) or not msg.strip():
        return None
    msg = "".join(c for c in msg if c.isprintable())[:150].strip()
    return msg or None


def error_text(code: int, body: bytes, key: str | None = None) -> str:
    """One line for an error answer, with the key (if it echoes it) redacted."""
    msg = _message(body)
    if code in (401, 403):
        why = msg or ("Invalid API key" if code == 401 else "Access denied")
        extra = (" Check the key on your account page. Looking up IPs through the Shodan API needs at least a "
                 "Membership, so a free account's key is refused too.")
        return redact(f"{KEY_REFUSED} (HTTP {code}): {why}.{extra}", key)
    if code == 402 or (msg and "credit" in msg.lower()):
        return redact(f"{NO_CREDITS} (HTTP {code}): {msg or 'payment required'}.", key)
    return redact(f"HTTP {code}" + (f": {msg}" if msg else ""), key)


@dataclass
class Info:
    ok: bool
    plan: str | None = None
    query_credits: int | None = None
    scan_credits: int | None = None
    error: str | None = None


def _count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and -1 <= value < 10**12 else None


async def api_info(client: httpx.AsyncClient, key: str) -> Info:
    """Ask Shodan what plan a key belongs to. One request; never raises; no credit is used by it as far as
    the documentation says (it lists none)."""
    import json
    try:
        async with client.stream("GET", INFO_URL, params={"key": key},
                                 headers={"Accept": "application/json"}) as r:
            code = r.status_code
            body = b""
            async for chunk in r.aiter_bytes(1 << 14):
                body += chunk
                if len(body) > 1 << 20:
                    return Info(False, error="The answer is larger than the limit.")
    except httpx.HTTPError as exc:
        return Info(False, error=redact(f"Could not reach api.shodan.io: {type(exc).__name__}", key))
    if code != 200:
        text = error_text(code, body, key)
        if code == 429:
            text = "Shodan says to slow down (HTTP 429). Try again in a minute."
        return Info(False, error=text)
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        data = None
    if not isinstance(data, dict):
        return Info(False, error="The answer is not the documented shape.")
    plan = data.get("plan")
    if not isinstance(plan, str) or not re.fullmatch(r"[A-Za-z0-9 ._+-]{1,40}", plan):
        plan = None
    return Info(True, plan, _count(data.get("query_credits")), _count(data.get("scan_credits")))


def describe_info(info: Info) -> str:
    """The Test key result as one sentence. Plan names are shown as Shodan gives them: this module does not map
    them to what a plan may be used for."""
    if not info.ok:
        return info.error or "The key was not accepted."
    parts = [f"Plan: {info.plan or 'not named in the answer'}."]
    if info.query_credits is not None:
        parts.append(f"Query credits left: {info.query_credits}.")
    if info.scan_credits is not None:
        parts.append(f"Scan credits left: {info.scan_credits}.")
    return "Shodan accepted the key. " + " ".join(parts)
