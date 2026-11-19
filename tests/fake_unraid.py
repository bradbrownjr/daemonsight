"""A fake Unraid GraphQL server for tests: an httpx MockTransport that serves
the trimmed real responses in tests/fixtures/unraid/, checks the x-api-key
header, and records every request body."""

import asyncio
import contextlib
import copy
import json
import ssl
from pathlib import Path

import httpx
import websockets

from daemonsight.remote import unraid
from daemonsight.remote.client import STATS_SUBSCRIPTION, Net

FIX = Path(__file__).parent / "fixtures" / "unraid"
KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


def load(name: str) -> dict:
    return json.loads((FIX / f"{name}.json").read_text())


def stat(container_id: str, cpu: float, mem_usage: str, mem_percent: float) -> dict:
    """One `dockerContainerStats` payload, as Unraid sends it."""
    return {"id": container_id, "cpuPercent": cpu, "memUsage": mem_usage, "memPercent": mem_percent}


class FakeSocket:
    """The server side of one graphql-transport-ws connection (https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md),
    as the object `Net.websocket` yields: `send(str)`, `recv() -> str`. It answers connection_init with
    connection_ack (or closes with 4403 for a wrong key), answers subscribe with the staged `next` messages and then
    stays quiet, as the real stream does until the client completes."""

    def __init__(self, owner: "FakeUnraid"):
        self.owner = owner
        self.sent: list[dict] = []          # what the client sent, parsed
        self.inbox: list[str | Exception] = []
        self.closed = False
        self.completed = False

    async def send(self, raw: str) -> None:
        msg = json.loads(raw)
        self.sent.append(msg)
        owner = self.owner
        if msg["type"] == "connection_init":
            if (msg.get("payload") or {}).get("x-api-key") != owner.key:
                self.inbox.append(websockets.exceptions.ConnectionClosed(
                    websockets.frames.Close(4403, "Forbidden"), None))
            elif owner.ws_silent:
                pass
            else:
                self.inbox += owner.ws_before_ack + [json.dumps({"type": "connection_ack"})]
        elif msg["type"] == "subscribe":
            query = msg["payload"]["query"]
            if query != STATS_SUBSCRIPTION:
                self.inbox.append(json.dumps({"id": msg["id"], "type": "error",
                                              "payload": [{"message": "Cannot query field"}]}))
            else:
                self.inbox += owner.ws_script(msg["id"])
        elif msg["type"] == "complete":
            self.completed = True

    async def recv(self) -> str:
        while not self.inbox:
            await asyncio.sleep(0.005)
        item = self.inbox.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


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
            unraid.Q_ARRAY: load("array"), unraid.Q_DOCKER: load("docker"), unraid.Q_FOLDERS: load("folders"), unraid.Q_VMS: load("vms"),
            unraid.Q_UPS: load("ups"), unraid.Q_DISKS: load("disks"), unraid.Q_NOTIFICATIONS: load("notifications"),
        }
        self.errors: dict[str, list] = {}      # query -> GraphQL errors to add
        # The statistics subscription (WebSocket). `stats` is the list of `dockerContainerStats` payloads one tick
        # sends; by default every container in docker.json reports once.
        self.stats = [stat(c["id"], 1.5 + n, f"{100 + n}MiB / 2GiB", round((100 + n) / 2048 * 100, 2))
                      for n, c in enumerate(load("docker")["data"]["docker"]["containers"])]
        self.stats_ticks = 1
        self.ws_before_ack: list[str] = []     # messages sent before connection_ack (a ping, say)
        self.ws_silent = False                 # never answer connection_init
        self.ws_fail: Exception | None = None  # raised when connecting
        self.sockets: list[FakeSocket] = []
        self.release = load("release")         # what releases.unraid.net answers
        self.release_requests: list[httpx.Request] = []
        self.release_status = 200

    def ws_script(self, op_id: str) -> list[str]:
        return [json.dumps({"id": op_id, "type": "next", "payload": {"data": {"dockerContainerStats": s}}})
                for _ in range(self.stats_ticks) for s in self.stats]

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

            def websocket(self_, url, tls="verify", pem=None):
                @contextlib.asynccontextmanager
                async def connect():
                    if fake.ws_fail:
                        raise fake.ws_fail
                    if fake.server_cert is not None and (tls == "verify" or pem != fake.server_cert):
                        raise ssl.SSLCertVerificationError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                                                           "self-signed certificate (_ssl.c:1029)")
                    sock = FakeSocket(fake)
                    sock.url = url
                    fake.sockets.append(sock)
                    try:
                        yield sock
                    finally:
                        sock.closed = True
                return connect()

            async def certificate(self_, url):
                if fake.server_cert is None:
                    from daemonsight.remote.client import RemoteError
                    raise RemoteError("unreachable", "no certificate")
                return fake.server_cert

            def public(self_):
                def handler(request):
                    fake.release_requests.append(request)
                    if fake.fail:
                        raise fake.fail
                    if request.url.host != "releases.unraid.net":
                        return httpx.Response(404, text="unknown host")
                    return httpx.Response(fake.release_status, json=fake.release)
                return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5, follow_redirects=False)

        return FakeNet()

    def queries(self) -> list[str]:
        return [r["query"] for r in self.requests]


def make_cert(directory: Path, cn: str = "tower.test", expired: bool = False) -> tuple[str, Path, Path]:
    """A throwaway self-signed certificate with openssl: (PEM text, cert path, key path). `expired` dates it
    2020-01-01 to 2020-01-02."""
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        import pytest
        pytest.skip("openssl is not installed")
    directory.mkdir(parents=True, exist_ok=True)
    crt, key = directory / f"{cn}.crt", directory / f"{cn}.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(key), "-out", str(crt), "-subj", f"/O=Test/CN={cn}",
                    *(["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"] if expired else ["-days", "2"])],
                   check=True, capture_output=True)
    return crt.read_text(), crt, key
