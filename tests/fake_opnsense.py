"""A fake OPNsense firewall for tests: an httpx MockTransport that serves the synthetic responses in
tests/fixtures/opnsense/ (made from the real response shapes, with documentation addresses and made-up names),
checks the basic-auth credentials, and records every request. A request that is not a GET is a test failure."""

import base64
import copy
import json
from pathlib import Path

import httpx

from daemonsight.remote import opnsense
from daemonsight.remote.client import Net

FIX = Path(__file__).parent / "fixtures" / "opnsense"
KEY = "SYNTHETICKEY0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR"
SECRET = "SYNTHETICSECRET0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM"


def load(name: str):
    return json.loads((FIX / f"{name}.json").read_text())


class FakeOpnsense:
    """`replies` maps an API path to the JSON it returns; `deny` is a set of paths that answer 403 (the user lacks the
    privilege) and `absent` a set that answer 404 (a plugin that isn't installed)."""

    def __init__(self, key: str = KEY, secret: str = SECRET):
        self.key, self.secret = key, secret
        self.requests: list[httpx.Request] = []
        self.fail: Exception | None = None
        self.status: int | None = None
        self.deny: set[str] = set()
        self.absent: set[str] = set()
        self.server_cert: str | None = None
        p = opnsense.PATHS
        self.replies = {
            p["firmware"]: load("firmware"), p["gateways"]: load("gateways"), p["wireguard"]: load("wireguard"),
            p["interfaces"]: load("interfaces"), p["services"]: load("services"), p["rules"]: load("rules"),
            p["nat"]: load("nat"), p["caddy"]: load("caddy"), p["caddy_status"]: load("caddy_status"),
            p["tailscale"]: load("tailscale"), p["tailscale_settings"]: load("tailscale_settings"),
            p["resources"]: load("resources"), p["disk"]: load("disk"), p["temperature"]: load("temperature"),
        }

    def deny_source(self, source: str) -> None:
        self.deny |= {opnsense.PATHS[k] for k in opnsense.SOURCES[source].paths}

    def absent_source(self, source: str) -> None:
        self.absent |= {opnsense.PATHS[k] for k in opnsense.SOURCES[source].paths}

    def edit(self, path_key: str, fn) -> None:
        fn(self.replies[opnsense.PATHS[path_key]])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.method == "GET", f"the hub sent {request.method} {request.url.path}"
        assert not request.content, "a GET to the firewall carried a body"
        assert "content-type" not in request.headers, "a GET to the firewall carried a Content-Type"
        if self.fail:
            raise self.fail
        if self.status:
            return httpx.Response(self.status, text="nope")
        want = "Basic " + base64.b64encode(f"{self.key}:{self.secret}".encode()).decode()
        if request.headers.get("authorization") != want:
            return httpx.Response(401, json={"status": 401, "message": "Authentication Failed"})
        path = request.url.path
        if path in self.deny:
            return httpx.Response(403, json={"status": 403, "message": "Forbidden"})
        if path in self.absent or path not in self.replies:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        return httpx.Response(200, json=copy.deepcopy(self.replies[path]))

    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]

    def net(self) -> Net:
        fake = self

        class FakeNet(Net):
            def http(self_, tls="verify", pem=None):
                def handler(request):
                    if fake.server_cert is not None and (tls == "verify" or pem != fake.server_cert):
                        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                                                 "self-signed certificate (_ssl.c:1029)")
                    return fake.handler(request)
                return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5, follow_redirects=False)

            async def certificate(self_, url):
                from daemonsight.remote.client import RemoteError
                if fake.server_cert is None:
                    raise RemoteError("unreachable", "no certificate")
                return fake.server_cert

        return FakeNet()
