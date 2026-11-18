"""Talking to a remote system: a GraphQL client that can only read, and TLS
that is either the normal CA check or one pinned certificate.

Read-only, on this side: `Graph.query` sends one query document and refuses
anything that is not a query (no `mutation`, no `subscription`). The one
exception is `Graph.sample`, which opens a WebSocket and sends exactly one
subscription document, `STATS_SUBSCRIPTION`, compared as a whole string (see
the class doc). The key itself is the other half: the hub requires a Viewer
key (see unraid.py).

TLS, two modes, never "don't verify":

* `verify`: the CA store httpx uses by default (certifi). Fits Unraid's
  myunraid.net certificate or one from your own CA.
* `pin`: only one certificate is trusted, the one whose SHA-256 fingerprint
  you confirmed when you tested the connection. httpx has no fingerprint
  option, but its docs say `verify` takes an `ssl.SSLContext`
  (https://www.python-httpx.org/advanced/ssl/). The pinned certificate is
  loaded as the context's only trust anchor (`SSLContext.load_verify_locations`
  with `cadata`, https://docs.python.org/3/library/ssl.html), with
  `VERIFY_X509_PARTIAL_CHAIN` so a certificate that is itself the anchor is
  accepted. The handshake then proves the server holds that certificate's
  private key; a different certificate, even one for the same name, fails
  verification before any request (and so the key) is sent. The host name is
  not checked in this mode: Unraid's own certificate names `<server>.local`
  while you reach it by IP, and the pin already says which server it is.
  The expiry date is still checked.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import websockets
from websockets.asyncio.client import connect as _ws_connect

from .. import __version__

USER_AGENT = f"DaemonSight/{__version__}"
MAX_RESPONSE = 8 << 20          # bytes of JSON accepted per query
TIMEOUT = httpx.Timeout(20.0, connect=5.0)
_WRITE_WORDS = re.compile(r"\b(mutation|subscription)\b", re.I)

# The one subscription the hub may send. Unraid has container CPU and memory only as a subscription
# (`Subscription.dockerContainerStats: DockerContainerStats!`, api/generated-schema.graphql); there is no query.
# `Graph.sample` refuses any other document, by exact comparison.
STATS_SUBSCRIPTION = "subscription { dockerContainerStats { id cpuPercent memUsage memPercent } }"
WS_SUBPROTOCOL = "graphql-transport-ws"     # https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md
WS_MAX_MESSAGE = 16 << 10                   # bytes per message (a real one is about 300)
WS_MAX_MESSAGES = 5000                      # messages kept per sample
SAMPLE_SECONDS = 5.0                        # longest a sample lasts
ACK_SECONDS = 5.0                           # longest to wait for connection_ack
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_CONTAINER_ID = re.compile(r"([0-9a-f]{64})$")

# websockets logs every frame at DEBUG, and the first frame holds the key: give it a logger that never emits.
_WS_LOG = logging.getLogger("daemonsight.remote.ws")
_WS_LOG.setLevel(logging.CRITICAL + 1)
_WS_LOG.propagate = False


class RemoteError(Exception):
    """A failed read. `kind` is one of: unreachable, tls, auth, http,
    graphql, key (the key is allowed more than read), config, forbidden (the
    key is good but may not read `path`: OPNsense answers 403), missing (404: no such endpoint, a plugin that
    isn't installed). The message is
    safe to show: it never holds the key."""

    def __init__(self, kind: str, message: str, path: str | None = None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.path = path


# --- addresses ---------------------------------------------------------------

def normalize_url(raw: str, kind: str = "unraid") -> str:
    """The server's origin, `https://host[:port]`. Only https: the key travels
    in a header, and Unraid can serve the API over a self-signed certificate
    (Settings, Management Access, Use SSL/TLS). `kind` only picks the wording
    of the messages and the one path that may follow the address."""
    opn = kind == "opnsense"
    raw = (raw or "").strip()
    if not raw or len(raw) > 300 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        raise ValueError("Enter the firewall's address, for example https://fw.example.lan:8443 or https://192.0.2.1:8443."
                         if opn else
                         "Enter the server's address, for example https://tower.example.lan or https://192.0.2.10:4443.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ValueError("That address isn't valid.") from None
    if parts.scheme == "http":
        raise ValueError("Use an https:// address. The API key and secret are sent in a header, so they must not travel "
                         "in plain text. In OPNsense, System, Settings, Administration, set the web GUI protocol to HTTPS."
                         if opn else
                         "Use an https:// address. The API key is sent in a header, so it must not travel in "
                         "plain text. In Unraid, Settings, Management Access, set Use SSL/TLS to Yes.")
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("The address must start with https://.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Leave out any user name, password, query or fragment.")
    if parts.path not in ("", "/") + (() if opn else ("/graphql",)):
        raise ValueError("Give only the firewall's address; DaemonSight adds /api/..." if opn else
                         "Give only the server's address; DaemonSight adds /graphql.")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"https://{host}" + (f":{port}" if port else "")


def host_port(url: str) -> tuple[str, int]:
    p = urlsplit(url)
    return p.hostname or "", p.port or 443


# --- certificates ------------------------------------------------------------

def fingerprint(pem: str) -> str:
    """SHA-256 of the certificate's DER bytes, lowercase hex."""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def fmt_fingerprint(hexstr: str) -> str:
    """AA:BB:... as `openssl x509 -fingerprint -sha256` and browsers print it."""
    h = hexstr.upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def clean_fingerprint(text: str | None) -> str | None:
    """A fingerprint typed or pasted with colons, spaces or any case, as 64 hex digits; or None."""
    h = re.sub(r"[\s:]", "", text or "").lower()
    return h if re.fullmatch(r"[0-9a-f]{64}", h) else None


def pinned_context(pem: str) -> ssl.SSLContext:
    """A TLS context that trusts exactly the certificate `pem` (see the module doc)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cadata=pem)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


def _fetch_certificate(host: str, port: int) -> str:
    # ssl.get_server_certificate does not verify (it only does with ca_certs):
    # it exists to look at a certificate. Trusting it is the user's step.
    return ssl.get_server_certificate((host, port), timeout=8)


class Net:
    """How the hub reaches remote systems. One place, so tests can replace
    the transport and the certificate fetch."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, fetch_cert=None, websocket=None):
        self.transport = transport
        self._fetch_cert = fetch_cert or _fetch_certificate
        self._websocket = websocket      # tests: replaces the WebSocket connection (see `websocket`)

    @staticmethod
    def _verify(tls: str, pem: str | None) -> bool | ssl.SSLContext:
        """The TLS check for a connection, the same for HTTP and WebSocket: the CA store, or one pinned certificate."""
        if tls == "pin":
            if not pem:
                raise RemoteError("config", "No pinned certificate is stored for this system.")
            return pinned_context(pem)
        return True

    def http(self, tls: str = "verify", pem: str | None = None) -> httpx.AsyncClient:
        if self.transport is not None:
            return httpx.AsyncClient(transport=self.transport, timeout=TIMEOUT, follow_redirects=False)
        return httpx.AsyncClient(verify=self._verify(tls, pem), timeout=TIMEOUT, follow_redirects=False)

    def websocket(self, url: str, tls: str = "verify", pem: str | None = None):
        """An async context manager for a graphql-transport-ws connection to `url` (wss://...), yielding an object
        with `send(str)`, `recv() -> str` and `close()`. Same TLS check as `http` (CA store or the pinned
        certificate, never "don't verify"), no proxy, no compression, no redirects (the key is sent after the
        handshake, and a redirect would send it to a new address), and messages over WS_MAX_MESSAGE are refused."""
        if self._websocket is not None:
            return self._websocket(url, tls, pem)
        verify = self._verify(tls, pem)
        ctx = verify if isinstance(verify, ssl.SSLContext) else ssl.create_default_context()
        return _NoRedirectConnect(url, ssl=ctx, subprotocols=[WS_SUBPROTOCOL], proxy=None, compression=None,
                                  max_size=WS_MAX_MESSAGE, max_queue=64, open_timeout=TIMEOUT.connect,
                                  close_timeout=2, ping_interval=None, user_agent_header=USER_AGENT, logger=_WS_LOG)

    def public(self) -> httpx.AsyncClient:
        """A client for a public page (no key, normal CA check, no redirects)."""
        if self.transport is not None:
            return httpx.AsyncClient(transport=self.transport, timeout=TIMEOUT, follow_redirects=False)
        return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)

    async def certificate(self, url: str) -> str:
        host, port = host_port(url)
        try:
            return await asyncio.to_thread(self._fetch_cert, host, port)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise RemoteError("unreachable", f"Could not read the server's certificate: {exc}") from None


class _NoRedirectConnect(_ws_connect):
    """websockets' `connect` follows redirects on its own. The key is not sent until after the handshake, but a
    redirect to another address is still not something to follow: the 3xx comes back as the error."""

    def process_redirect(self, exc):
        return exc


# --- GraphQL -----------------------------------------------------------------

@dataclass
class Reply:
    data: dict
    warnings: list[str]


@dataclass
class Sample:
    """What one run of the statistics subscription collected. `items` maps a container's Docker id (64 hex digits,
    the part of Unraid's PrefixedID after the colon) to its last report: {"cpu", "mem_usage", "mem_percent"}."""
    items: dict[str, dict]
    messages: int
    seconds: float
    covered: bool       # every expected container reported before the time ran out


def scrub(text: str, key: str | None, *more: str | None) -> str:
    """Never let the key (or, for OPNsense, the secret too) into a message, even by accident."""
    for k in (key, *more):
        if k and len(k) >= 8:
            text = text.replace(k, "***")
    return text


class Graph:
    """One GraphQL endpoint. `query` sends only queries. `sample` is the one other way to talk to the server: it
    sends the single allow-listed subscription `STATS_SUBSCRIPTION` over a WebSocket and nothing else; there is no
    way to send a mutation, or any other subscription, through this class."""

    def __init__(self, base_url: str, key: str, http: httpx.AsyncClient, ws: Callable | None = None):
        self.url = base_url.rstrip("/") + "/graphql"
        self._key = key
        self._http = http
        self._ws = ws          # (wss url) -> async context manager, see Net.websocket

    async def aclose(self) -> None:
        await self._http.aclose()

    @staticmethod
    def check_read_only(document: str) -> None:
        text = document.lstrip()
        if not (text.startswith("{") or text.startswith("query")) or _WRITE_WORDS.search(document):
            raise ValueError("only read queries may be sent")

    async def query(self, document: str, require: tuple[str, ...] = ()) -> Reply:
        """Run a query. `require` names root fields that must come back (not
        null); other fields may fail and show up in `warnings`."""
        self.check_read_only(document)
        headers = {"x-api-key": self._key, "Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": USER_AGENT}
        try:
            async with self._http.stream("POST", self.url, json={"query": document}, headers=headers) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE:
                        raise RemoteError("http", "The server's reply was larger than 8 MiB; ignored.")
                status = r.status_code
        except RemoteError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from None
        if 300 <= status < 400:
            raise RemoteError("http", "The server redirected the request. Redirects are not followed (the key "
                                      "would go to the new address). Use the address Unraid serves the API from; "
                                      "with Use SSL/TLS set to Strict, that is the myunraid.net address.")
        if status in (401, 403):
            raise RemoteError("auth", f"The server refused the key (HTTP {status}).")
        if status != 200:
            raise RemoteError("http", f"The server answered HTTP {status}.")
        try:
            payload = json.loads(body)
        except ValueError:
            raise RemoteError("http", "The server's reply was not JSON.") from None
        if not isinstance(payload, dict):
            raise RemoteError("http", "The server's reply was not a GraphQL response.")
        data = payload.get("data")
        errors = payload.get("errors") or []
        messages = [self._clip(e.get("message")) for e in errors if isinstance(e, dict)][:3]
        if not isinstance(data, dict) or any(data.get(f) is None for f in require):
            why = messages[0] if messages else "no data"
            if any(w in why.lower() for w in ("forbidden", "unauthorized", "unauthenticated", "invalid api key")):
                raise RemoteError("auth", f"The server refused the key: {why}")
            raise RemoteError("graphql", f"The server could not answer the query: {why}")
        return Reply(data, messages)

    @staticmethod
    def _clip(msg) -> str:
        return "".join(c for c in str(msg or "")[:200] if c.isprintable())

    def _transport_error(self, exc: httpx.HTTPError) -> RemoteError:
        text = scrub(str(exc), self._key)
        if isinstance(exc, httpx.ConnectError) and ("CERTIFICATE_VERIFY_FAILED" in text or "certificate" in text.lower()):
            return RemoteError("tls", "The server's certificate was not accepted: " + self._clip(text) +
                               " If you pinned a certificate and the server's has changed, test the connection "
                               "again and confirm the new fingerprint.")
        if isinstance(exc, httpx.TimeoutException):
            return RemoteError("unreachable", "The server did not answer in time.")
        if isinstance(exc, httpx.ConnectError):
            return RemoteError("unreachable", "Could not connect: " + self._clip(text))
        return RemoteError("unreachable", f"{type(exc).__name__}: {self._clip(text)}")


    # --- the one subscription ---------------------------------------------------

    @staticmethod
    def check_allowed_subscription(document: str) -> None:
        if document != STATS_SUBSCRIPTION:
            raise ValueError("only the container statistics subscription may be sent")

    async def sample(self, document: str = STATS_SUBSCRIPTION, expected: frozenset[str] | set[str] = frozenset(),
                     seconds: float | None = None) -> Sample:
        """Subscribe to `document` (only `STATS_SUBSCRIPTION` is accepted), collect reports for at most `seconds`
        or until every id in `expected` has reported, then complete the subscription and close the socket.
        Unraid's own client does the same handshake (graphql-ws: connection_init with the key in its payload,
        subscribe, next ..., complete). At most WS_MAX_MESSAGES messages are read, each at most WS_MAX_MESSAGE bytes."""
        self.check_allowed_subscription(document)
        seconds = SAMPLE_SECONDS if seconds is None else seconds
        if self._ws is None:
            raise RemoteError("config", "No WebSocket connection is set up for this client.")
        url = "wss://" + self.url.removeprefix("https://")
        started = time.monotonic()
        items: dict[str, dict] = {}
        count = 0
        try:
            # The overall limit is a backstop; each step below has its own, tighter one.
            async with asyncio.timeout(TIMEOUT.connect + ACK_SECONDS + seconds + 5):
                async with self._ws(url) as sock:
                    await sock.send(json.dumps({"type": "connection_init", "payload": {"x-api-key": self._key}}))
                    while True:
                        msg = await self._receive(sock, ACK_SECONDS)
                        if msg.get("type") == "connection_ack":
                            break
                        await self._housekeeping(sock, msg)
                    await sock.send(json.dumps({"id": "1", "type": "subscribe", "payload": {"query": document}}))
                    deadline = time.monotonic() + seconds
                    try:
                        while count < WS_MAX_MESSAGES and (left := deadline - time.monotonic()) > 0:
                            try:
                                msg = await self._receive(sock, left)
                            except TimeoutError:
                                break
                            count += 1
                            kind = msg.get("type")
                            if kind == "complete":
                                break
                            if kind == "next":
                                self._take(msg, items)
                                if expected and expected <= items.keys():
                                    break
                            else:
                                await self._housekeeping(sock, msg)
                    finally:
                        with contextlib.suppress(Exception):
                            await sock.send(json.dumps({"id": "1", "type": "complete"}))
        except RemoteError:
            raise
        except Exception as exc:
            raise self._ws_error(exc) from None
        return Sample(items, count, round(time.monotonic() - started, 2), bool(expected) and expected <= items.keys())

    async def _receive(self, sock, timeout: float) -> dict:
        raw = await asyncio.wait_for(sock.recv(), timeout)
        if not isinstance(raw, str) or len(raw) > WS_MAX_MESSAGE:
            raise RemoteError("http", "The server sent a message that was too large or not text; ignored.")
        try:
            msg = json.loads(raw)
        except ValueError:
            raise RemoteError("http", "The server sent a message that was not JSON.") from None
        if not isinstance(msg, dict):
            raise RemoteError("http", "The server sent a message that was not a GraphQL message.")
        return msg

    async def _housekeeping(self, sock, msg: dict) -> None:
        kind = msg.get("type")
        if kind == "ping":
            await sock.send(json.dumps({"type": "pong"}))
        elif kind == "error":
            errors = msg.get("payload")
            why = self._clip(errors[0].get("message") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else "")
            raise RemoteError(*self._classify(why or "no reason given", "The server could not run the subscription"))

    @staticmethod
    def _classify(why: str, lead: str) -> tuple[str, str]:
        if any(w in why.lower() for w in ("forbidden", "unauthorized", "unauthenticated", "invalid api key", "user not found")):
            return "auth", f"The server refused the key: {why}"
        return "graphql", f"{lead}: {why}"

    def _take(self, msg: dict, items: dict[str, dict]) -> None:
        payload = msg.get("payload")
        if not isinstance(payload, dict):
            return
        errors = payload.get("errors")
        if errors and not isinstance(payload.get("data"), dict):
            why = self._clip(errors[0].get("message") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else "")
            raise RemoteError(*self._classify(why or "no data", "The server could not answer the subscription"))
        d = (payload.get("data") or {}).get("dockerContainerStats")
        if not isinstance(d, dict) or not isinstance(d.get("id"), str):
            return
        # Unraid builds these from `docker stats` output, and the first line of each refresh carries a terminal
        # control sequence (observed live: "\x1b[H" and "\x1b[J\x1b[H" before the id). Strip those; the id is the
        # 64 hex digits after the "<server>:" prefix.
        found = _CONTAINER_ID.search(_ANSI.sub("", d["id"]))
        if found:
            items[found.group(1)] = {"cpu": d.get("cpuPercent"), "mem_usage": self._clip(d.get("memUsage")),
                                     "mem_percent": d.get("memPercent")}

    def _ws_error(self, exc: Exception) -> RemoteError:
        text = scrub(str(exc), self._key)
        if isinstance(exc, ssl.SSLError):
            return RemoteError("tls", "The server's certificate was not accepted: " + self._clip(text) +
                               " If you pinned a certificate and the server's has changed, test the connection "
                               "again and confirm the new fingerprint.")
        if isinstance(exc, websockets.exceptions.InvalidStatus):
            status = exc.response.status_code
            if 300 <= status < 400:
                return RemoteError("http", "The server redirected the WebSocket request. Redirects are not followed "
                                           "(the key would go to the new address).")
            if status in (401, 403):
                return RemoteError("auth", f"The server refused the key (HTTP {status}).")
            return RemoteError("http", f"The server answered the WebSocket request with HTTP {status}.")
        if isinstance(exc, websockets.exceptions.ConnectionClosed):
            code = exc.rcvd.code if exc.rcvd else None
            if code in (4401, 4403):
                return RemoteError("auth", f"The server refused the key (WebSocket close code {code}).")
            return RemoteError("unreachable", f"The server closed the WebSocket (code {code}).")
        if isinstance(exc, TimeoutError):
            return RemoteError("unreachable", "The server did not answer in time.")
        if isinstance(exc, OSError):
            return RemoteError("unreachable", "Could not connect: " + self._clip(text))
        if isinstance(exc, websockets.exceptions.WebSocketException):
            return RemoteError("http", f"The WebSocket handshake failed: {type(exc).__name__}.")
        return RemoteError("unreachable", f"{type(exc).__name__}: {self._clip(text)}")


# --- REST, GET only (OPNsense) -------------------------------------------------

class Rest:
    """One firewall's REST API, read-only on this side. There is no method here that sends anything but GET: `get`
    asks httpx for a GET and nothing else, with no request body and no Content-Type header (OPNsense answers an
    empty body that claims to be JSON with 400 "Invalid JSON syntax": ApiControllerBase.parseJsonBodyData). It also
    refuses any path that is not in `allowed`, compared as a whole string, so a bug elsewhere can't make it call an
    endpoint that acts (OPNsense has GET endpoints that do something, such as `/api/core/firmware/check` or
    `/api/tailscale/status/net`). No redirects are followed (the key would go to the new address), a reply is capped
    at MAX_RESPONSE, and the key and secret are scrubbed from every message."""

    def __init__(self, base_url: str, key: str, secret: str, http: httpx.AsyncClient, allowed: frozenset[str]):
        self.base = base_url.rstrip("/")
        self._key, self._secret = key, secret
        self._http = http
        self._allowed = frozenset(allowed)
        cred = base64.b64encode(f"{key}:{secret}".encode()).decode()
        self._headers = {"Authorization": "Basic " + cred, "Accept": "application/json", "User-Agent": USER_AGENT}

    async def aclose(self) -> None:
        await self._http.aclose()

    def check_allowed(self, path: str) -> None:
        if path not in self._allowed:
            raise ValueError("only the listed read-only endpoints may be requested")

    async def get(self, path: str):
        """GET `path` and return the parsed JSON. Raises RemoteError: auth (401), forbidden (403: the key is good
        but the user lacks the privilege for this page), http, unreachable, tls."""
        self.check_allowed(path)
        try:
            async with self._http.stream("GET", self.base + path, headers=self._headers) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE:
                        raise RemoteError("http", "The firewall's reply was larger than 8 MiB; ignored.", path)
                status = r.status_code
        except RemoteError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc, path) from None
        if 300 <= status < 400:
            raise RemoteError("http", "The firewall redirected the request. Redirects are not followed (the key "
                                      "would go to the new address). Use the address the web GUI answers on.", path)
        if status == 401:
            raise RemoteError("auth", "The firewall refused the API key or secret (HTTP 401).", path)
        if status == 403:
            raise RemoteError("forbidden", f"The user may not read {path} (HTTP 403).", path)
        if status == 404:
            raise RemoteError("missing", f"The firewall has no {path} (HTTP 404). The plugin is not installed, or this "
                                         "version of it is too old.", path)
        if status != 200:
            raise RemoteError("http", f"The firewall answered HTTP {status} for {path}.", path)
        try:
            return json.loads(body)
        except ValueError:
            raise RemoteError("http", f"The reply for {path} was not JSON.", path) from None

    def _transport_error(self, exc: httpx.HTTPError, path: str) -> RemoteError:
        text = scrub(str(exc), self._key, self._secret)
        clip = "".join(c for c in text[:200] if c.isprintable())
        if isinstance(exc, httpx.ConnectError) and ("CERTIFICATE_VERIFY_FAILED" in text or "certificate" in text.lower()):
            return RemoteError("tls", "The firewall's certificate was not accepted: " + clip +
                               " If you pinned a certificate and the firewall's has changed, test the connection "
                               "again and confirm the new fingerprint.", path)
        if isinstance(exc, httpx.TimeoutException):
            return RemoteError("unreachable", "The firewall did not answer in time.", path)
        if isinstance(exc, httpx.ConnectError):
            return RemoteError("unreachable", "Could not connect: " + clip, path)
        return RemoteError("unreachable", f"{type(exc).__name__}: {clip}", path)
