"""A fake Unraid GraphQL server for tests: an httpx MockTransport that serves
the trimmed real responses in tests/fixtures/unraid/, checks the x-api-key
header, and records every request body."""

import copy
import json
from pathlib import Path

import httpx

from daemonsight.remote import unraid
from daemonsight.remote.client import Net

FIX = Path(__file__).parent / "fixtures" / "unraid"
KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


def load(name: str) -> dict:
    return json.loads((FIX / f"{name}.json").read_text())


class FakeUnraid:
    """`replies` maps a query to the {"data": ...} body it returns; change them to stage a situation."""

    def __init__(self, key: str = KEY, role: str = "viewer"):
        self.key = key
        self.requests: list[dict] = []        # the JSON bodies received
        self.headers: list[dict] = []
        self.fail: Exception | None = None     # raised for every request
        self.status: int | None = None         # answered for every request
        self.replies = {
            unraid.Q_ME: load(f"me_{role}"), unraid.Q_PROBE: load("probe"), unraid.Q_SYSTEM: load("system"),
            unraid.Q_ARRAY: load("array"), unraid.Q_DOCKER: load("docker"), unraid.Q_VMS: load("vms"),
            unraid.Q_UPS: load("ups"), unraid.Q_DISKS: load("disks"), unraid.Q_NOTIFICATIONS: load("notifications"),
        }
        self.errors: dict[str, list] = {}      # query -> GraphQL errors to add

    def set(self, query: str, fn) -> None:
        """Change a reply in place: fn receives the data dict."""
        fn(self.replies[query]["data"])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.headers.append(dict(request.headers))
        body = json.loads(request.content)
        self.requests.append(body)
        if self.fail:
            raise self.fail
        if self.status:
            return httpx.Response(self.status, text="nope")
        if request.headers.get("x-api-key") != self.key:
            return httpx.Response(401, json={"errors": [{"message": "Invalid API key"}]})
        q = body["query"]
        if q not in self.replies:
            return httpx.Response(400, json={"errors": [{"message": "unknown query"}]})
        reply = copy.deepcopy(self.replies[q])
        if q in self.errors:
            reply["errors"] = self.errors[q]
        return httpx.Response(200, json=reply)

    server_cert: str | None = None   # set: the fake server has this self-signed certificate

    def net(self) -> Net:
        """A Net that answers from this fake. With `server_cert` set it also acts like a server with that
        self-signed certificate: the normal CA check fails, a pin on a different certificate fails, and a pin
        on this one works. (The real handshake is tested in test_remote_tls.py.)"""
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
                if fake.server_cert is None:
                    from daemonsight.remote.client import RemoteError
                    raise RemoteError("unreachable", "no certificate")
                return fake.server_cert

        return FakeNet()

    def queries(self) -> list[str]:
        return [r["query"] for r in self.requests]


def make_cert(directory: Path, cn: str = "tower.test") -> tuple[str, Path, Path]:
    """A throwaway self-signed certificate with openssl: (PEM text, cert path, key path)."""
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        import pytest
        pytest.skip("openssl is not installed")
    directory.mkdir(parents=True, exist_ok=True)
    crt, key = directory / f"{cn}.crt", directory / f"{cn}.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", f"/O=Test/CN={cn}"],
                   check=True, capture_output=True)
    return crt.read_text(), crt, key
