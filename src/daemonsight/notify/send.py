"""Sending one rendered message to one channel.

Outbound conventions follow the hub's other calls (remote/client.py): HTTPS with the normal CA check, no redirect followed
(a credential in a header or in the URL path must not go to a new address), no proxy from the environment, a short timeout,
a body read of at most 64 KB, and a generic `DaemonSight/<version>` User-Agent (Discord asks API clients for one that
identifies them, and says requests without a valid one may be blocked).

Nothing here ever puts a secret into an error. A failure becomes a `SendError` with a short plain text that names the
service's own error word where the service gives one (Slack: `invalid_payload`, `no_service`), the HTTP status, or what
failed on the way (timed out, could not connect, certificate not trusted), and every message is passed through `redact`
with the channel's secrets.

Email: implicit TLS (465) or STARTTLS (587) under `ssl.create_default_context()` (certificate and host name verified);
AUTH is only attempted on an encrypted connection, and a server that doesn't offer STARTTLS is refused, so nothing is sent
in the clear. Tests replace `tls_context` to trust their own CA.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import smtplib
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from .. import __version__
from . import render

log = logging.getLogger("daemonsight.notify")
USER_AGENT = f"DaemonSight/{__version__}"
TIMEOUT = httpx.Timeout(20.0, connect=8.0)
MAX_BODY = 64 << 10
MAX_RETRY_AFTER = 3600.0
SMTP_TIMEOUT = 25
SLACK_GAP = 1.1          # Slack: "no more than one message per second per channel" for incoming webhooks


@dataclass
class Reply:
    status: int
    headers: httpx.Headers
    content: bytes


class SendError(Exception):
    """A send that failed. `message` is safe to show and store: it never holds a secret. `permanent` means retrying the same
    request is pointless (a refused login, a webhook that no longer exists); `retry_after` is what a 429 asked for."""

    def __init__(self, message: str, permanent: bool = False, retry_after: float | None = None):
        super().__init__(message)
        self.message = message
        self.permanent = permanent
        self.retry_after = retry_after


def redact(text: object, *secrets: str | None) -> str:
    out = str(text)
    for s in secrets:
        if s and len(s) >= 4:
            out = out.replace(s, "[secret]")
    return out


def tls_context() -> ssl.SSLContext:
    """The context for SMTP: the system's CAs, certificate required, host name checked. Tests replace this function."""
    return ssl.create_default_context()


def http_client(net=None) -> httpx.AsyncClient:
    """A client for a webhook or a notification server. With a `Net` (tests, or the hub's own) its transport is used."""
    transport = getattr(net, "transport", None)
    headers = {"User-Agent": USER_AGENT}
    if transport is not None:
        return httpx.AsyncClient(transport=transport, timeout=TIMEOUT, follow_redirects=False, headers=headers)
    return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, trust_env=False, headers=headers)


_WORD = re.compile(r"[^A-Za-z0-9_ .,:;/-]")


def _service_word(body: bytes) -> str:
    """The service's own short error (Slack answers with a word such as `invalid_payload`; Discord and Ntfy with JSON that has a
    message), cut and cleaned, or ""."""
    text = body[:400].decode("utf-8", "replace").strip()
    if text.startswith("{"):
        m = re.search(r'"(?:message|error)"\s*:\s*"([^"]{1,150})"', text)
        text = m.group(1) if m else ""
    return _WORD.sub("", text)[:100].strip()


async def _post(client: httpx.AsyncClient, url: str, *, json=None, headers=None, secrets=()) -> Reply:
    try:
        async with client.stream("POST", url, json=json, headers=headers) as resp:
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > MAX_BODY:
                    break
            reply = Reply(resp.status_code, resp.headers, bytes(body[:MAX_BODY]))
    except httpx.TimeoutException:
        raise SendError("timed out") from None
    except httpx.ConnectError as exc:
        text = redact(exc, *secrets)
        if "CERTIFICATE_VERIFY_FAILED" in text or "certificate" in text.lower():
            raise SendError("the server's certificate could not be verified") from None
        raise SendError("could not connect") from None
    except httpx.HTTPError as exc:
        raise SendError(f"request failed ({type(exc).__name__})") from None
    return reply


def _retry_after(resp: Reply) -> float | None:
    """Seconds to wait: Retry-After (Slack, Discord, Ntfy proxies) or Discord's `retry_after` in the body."""
    raw = resp.headers.get("retry-after")
    try:
        if raw is not None:
            return min(max(float(raw), 0.0), MAX_RETRY_AFTER)
        m = re.search(rb'"retry_after"\s*:\s*([0-9.]+)', resp.content)
        if m:
            return min(max(float(m.group(1)), 0.0), MAX_RETRY_AFTER)
    except ValueError:
        pass
    return None


def _check(resp: Reply, what: str, secrets=()) -> None:
    code = resp.status
    if 200 <= code < 300:
        return
    word = redact(_service_word(resp.content), *secrets)
    detail = f": {word}" if word else ""
    if 300 <= code < 400:
        raise SendError(f"{what} answered with a redirect (HTTP {code}); redirects are not followed", permanent=True)
    if code == 429:
        raise SendError(f"{what} is rate limiting (HTTP 429){detail}", retry_after=_retry_after(resp) or 60.0)
    permanent = code in (400, 401, 403, 404, 410, 413)
    raise SendError(f"{what} refused it (HTTP {code}){detail}" if permanent else f"{what} had a problem (HTTP {code}){detail}",
                    permanent=permanent)


# --- one function per service -------------------------------------------------------

async def send_ntfy(cfg: dict, secret: str | None, note: render.Note, client: httpx.AsyncClient) -> None:
    payload = render.ntfy_payload(note, cfg["topic"])
    headers = {}
    if cfg.get("auth") == "token" and secret:
        headers["Authorization"] = f"Bearer {secret}"
    elif cfg.get("auth") == "basic" and secret:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{cfg.get('user', '')}:{secret}".encode()).decode()
    resp = await _post(client, cfg["server"], json=payload, headers=headers, secrets=(secret,))
    _check(resp, "Ntfy", (secret,))


async def send_slack(secret: str, note: render.Note, client: httpx.AsyncClient) -> None:
    resp = await _post(client, secret, json=render.slack_payload(note), secrets=(secret,))
    _check(resp, "Slack", (secret,))


async def send_discord(secret: str, note: render.Note, client: httpx.AsyncClient) -> float | None:
    """Returns the seconds to leave before the next message to this webhook (Discord's bucket is used up), or None."""
    payload = render.discord_payload(note, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    assert render.discord_embed_size(payload) <= render.DISCORD_TOTAL
    resp = await _post(client, secret, json=payload, secrets=(secret,))
    _check(resp, "Discord", (secret,))
    # Discord's bucket headers: when none is left, wait until it resets before the next message to this webhook.
    if resp.headers.get("x-ratelimit-remaining") == "0":
        try:
            return min(float(resp.headers.get("x-ratelimit-reset-after", "1")), MAX_RETRY_AFTER)
        except ValueError:
            return None
    return None


def _smtp_send(cfg: dict, password: str | None, msg, context: ssl.SSLContext) -> None:
    host, port, security = cfg["host"], int(cfg["port"]), cfg["security"]
    user = cfg.get("user") or ""
    try:
        if security == "tls":
            smtp = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT)
        with smtp:
            if security != "tls":
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise SendError("the server doesn't offer STARTTLS; nothing was sent unencrypted", permanent=True)
                smtp.starttls(context=context)
                smtp.ehlo()
            if not isinstance(smtp.sock, ssl.SSLSocket):      # never AUTH or send on a link that is not encrypted
                raise SendError("the connection is not encrypted; nothing was sent", permanent=True)
            if user:
                smtp.login(user, password or "")
            smtp.send_message(msg)
    except SendError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise SendError("the server's certificate could not be verified: "
                        + redact(getattr(exc, "verify_message", "") or "not trusted", password), permanent=True) from None
    except ssl.SSLError as exc:
        raise SendError("TLS failed: " + redact((exc.reason or type(exc).__name__), password)) from None
    except smtplib.SMTPAuthenticationError as exc:
        raise SendError(f"the server refused the login (code {exc.smtp_code})", permanent=True) from None
    except smtplib.SMTPRecipientsRefused:
        raise SendError("the server refused every recipient", permanent=True) from None
    except smtplib.SMTPSenderRefused as exc:
        raise SendError(f"the server refused the From address (code {exc.smtp_code})", permanent=True) from None
    except smtplib.SMTPResponseException as exc:
        raise SendError(f"the server answered {exc.smtp_code}", permanent=exc.smtp_code >= 550) from None
    except smtplib.SMTPException as exc:
        raise SendError("SMTP failed: " + redact(type(exc).__name__, password)) from None
    except TimeoutError:
        raise SendError("timed out") from None
    except OSError as exc:
        raise SendError("could not connect" if not isinstance(exc, ssl.SSLError) else "TLS failed") from None


# --- the one entry point -------------------------------------------------------------

_last_sent: dict[int, float] = {}       # per channel: when the last message went out (Slack's one-per-second)
_not_before: dict[int, float] = {}      # per channel: Discord asked us to wait until then


async def send(channel: dict, secret: str | None, note: render.Note, net=None) -> None:
    """Send `note` through `channel` (a dict from channels.get). Raises SendError."""
    kind, cfg, cid = channel["kind"], channel["config"], channel["id"]
    wait = _not_before.get(cid, 0) - time.monotonic()
    if wait > 0:
        await asyncio.sleep(min(wait, 30))
    if kind == "slack":
        gap = SLACK_GAP - (time.monotonic() - _last_sent.get(cid, 0))
        if gap > 0:
            await asyncio.sleep(gap)
    try:
        if kind == "email":
            msg = render.build_email(note, cfg["from"], cfg["to"], render.load_logo())
            await asyncio.to_thread(_smtp_send, cfg, secret, msg, tls_context())
            return
        if not secret and (kind in ("slack", "discord") or cfg.get("auth") in ("token", "basic")):
            raise SendError("no secret is saved for this channel", permanent=True)
        async with http_client(net) as client:
            if kind == "ntfy":
                await send_ntfy(cfg, secret, note, client)
            elif kind == "slack":
                await send_slack(secret, note, client)
            elif kind == "discord":
                pause = await send_discord(secret, note, client)
                if pause:
                    _not_before[cid] = time.monotonic() + pause
            else:
                raise SendError(f"unknown channel type {kind!r}", permanent=True)
    finally:
        _last_sent[cid] = time.monotonic()
