"""TLS for remote systems, with a real handshake: a certificate that is pinned is accepted, any other
certificate is refused before a single request (and so the API key) is sent, and the normal CA check
refuses a self-signed certificate."""

import asyncio
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from daemonsight.remote import unraid
from daemonsight.remote.client import Graph, Net, RemoteError, fingerprint, pinned_context

from .fake_unraid import KEY, load, make_cert


@pytest.fixture
def tls_server(tmp_path):
    """An HTTPS server with a self-signed certificate; `seen` lists the requests it got."""
    pem, crt, key = make_cert(tmp_path / "server", "tower.test")
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            seen.append((self.headers.get("x-api-key"), json.loads(body)["query"]))
            out = json.dumps(load("me_viewer")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"https://127.0.0.1:{srv.server_port}", pem, seen
    srv.shutdown()
    srv.server_close()


def ask(url, tls, pem):
    async def go():
        g = Graph(url, KEY, Net().http(tls, pem))
        try:
            return await g.query(unraid.Q_ME, ("me",))
        finally:
            await g.aclose()
    return asyncio.run(go())


def test_the_pinned_certificate_is_accepted(tls_server):
    url, pem, seen = tls_server
    # The host name (127.0.0.1) isn't in the certificate: the pin, not the name, says which server this is.
    assert ask(url, "pin", pem).data["me"]["roles"] == ["VIEWER"]
    assert seen == [(KEY, unraid.Q_ME)]


def test_a_different_certificate_is_refused_before_the_key_is_sent(tls_server, tmp_path):
    url, pem, seen = tls_server
    other, _, _ = make_cert(tmp_path / "other", "tower.test")       # same name, different key pair
    assert fingerprint(other) != fingerprint(pem)
    with pytest.raises(RemoteError) as e:
        ask(url, "pin", other)
    assert e.value.kind == "tls" and "certificate" in e.value.message and KEY not in e.value.message
    assert seen == []        # the server never saw a request, so never saw the key


def test_the_normal_check_refuses_a_self_signed_certificate(tls_server):
    url, _, seen = tls_server
    with pytest.raises(RemoteError) as e:
        ask(url, "verify", None)
    assert e.value.kind == "tls" and seen == []


def test_the_certificate_fetch_returns_what_the_server_presents(tls_server):
    url, pem, _ = tls_server
    got = asyncio.run(Net().certificate(url))
    assert fingerprint(got) == fingerprint(pem)


def test_the_pinned_context_is_never_unverified():
    ctx = pinned_context(make_cert_pem())
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    with pytest.raises(RemoteError):
        Net().http("pin", None)


def make_cert_pem():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        return make_cert(Path(d), "x.test")[0]
