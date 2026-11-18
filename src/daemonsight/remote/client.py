"""Talking to a remote system: a GraphQL client that can only read, and TLS
that is either the normal CA check or one pinned certificate.

Read-only, on this side: `Graph.query` sends one query document and refuses
anything that is not a query (no `mutation`, no `subscription`). The key
itself is the other half: the hub requires a Viewer key (see unraid.py).

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
import hashlib
import json
import re
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .. import __version__

USER_AGENT = f"DaemonSight/{__version__}"
MAX_RESPONSE = 8 << 20          # bytes of JSON accepted per query
TIMEOUT = httpx.Timeout(20.0, connect=5.0)
_WRITE_WORDS = re.compile(r"\b(mutation|subscription)\b", re.I)


class RemoteError(Exception):
    """A failed read. `kind` is one of: unreachable, tls, auth, http,
    graphql, key (the key is allowed more than read), config. The message is
    safe to show: it never holds the key."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


# --- addresses ---------------------------------------------------------------

def normalize_url(raw: str) -> str:
    """The server's origin, `https://host[:port]`. Only https: the key travels
    in a header, and Unraid can serve the API over a self-signed certificate
    (Settings, Management Access, Use SSL/TLS)."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 300 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        raise ValueError("Enter the server's address, for example https://tower.example.lan or https://192.0.2.10:4443.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ValueError("That address isn't valid.") from None
    if parts.scheme == "http":
        raise ValueError("Use an https:// address. The API key is sent in a header, so it must not travel in "
                         "plain text. In Unraid, Settings, Management Access, set Use SSL/TLS to Yes.")
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("The address must start with https://.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Leave out any user name, password, query or fragment.")
    if parts.path not in ("", "/", "/graphql"):
        raise ValueError("Give only the server's address; DaemonSight adds /graphql.")
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

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None, fetch_cert=None):
        self.transport = transport
        self._fetch_cert = fetch_cert or _fetch_certificate

    def http(self, tls: str = "verify", pem: str | None = None) -> httpx.AsyncClient:
        if self.transport is not None:
            return httpx.AsyncClient(transport=self.transport, timeout=TIMEOUT, follow_redirects=False)
        verify: bool | ssl.SSLContext = True
        if tls == "pin":
            if not pem:
                raise RemoteError("config", "No pinned certificate is stored for this system.")
            verify = pinned_context(pem)
        return httpx.AsyncClient(verify=verify, timeout=TIMEOUT, follow_redirects=False)

    async def certificate(self, url: str) -> str:
        host, port = host_port(url)
        try:
            return await asyncio.to_thread(self._fetch_cert, host, port)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise RemoteError("unreachable", f"Could not read the server's certificate: {exc}") from None


# --- GraphQL -----------------------------------------------------------------

@dataclass
class Reply:
    data: dict
    warnings: list[str]


def scrub(text: str, key: str | None) -> str:
    """Never let the key into a message, even by accident."""
    return text.replace(key, "***") if key and len(key) >= 8 else text


class Graph:
    """One GraphQL endpoint. Only `query` exists; there is no way to send a
    mutation through this class."""

    def __init__(self, base_url: str, key: str, http: httpx.AsyncClient):
        self.url = base_url.rstrip("/") + "/graphql"
        self._key = key
        self._http = http

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
