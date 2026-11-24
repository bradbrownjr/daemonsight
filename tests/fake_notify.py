"""Fake Ntfy, Slack and Discord servers (an httpx transport, so nothing leaves the process) and a fake SMTP server (a real
socket on 127.0.0.1, with implicit TLS or STARTTLS from a throwaway certificate), for the alert channel tests.

The HTTP fakes check what each service's documentation says it checks: Slack answers 400 `invalid_payload` for a body that is
not JSON or has neither `text` nor `blocks`, 404 `no_service` for an unknown path, 429 with Retry-After; Discord answers 400
for an embed over its limits (title 256, description 4096, 25 fields, field name 256 and value 1024, footer 2048, 6000 in
all, 10 embeds) and 429 with `retry_after`; Ntfy answers 400 for a message over 4096 bytes or a title over 1 KB, 401 without
the right Authorization header when a token is required.
"""

from __future__ import annotations

import base64
import json
import shutil
import socket
import ssl
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

import httpx

SLACK_URL = "https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx"
DISCORD_URL = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEF"
NTFY_TOKEN = "tk_abcdefghijklmnopqrstuvwxyz012"


@dataclass
class Fake:
    """Records every request, and answers from `script` (a list of (status, headers, body) consumed first) or by service rules."""
    requests: list = field(default_factory=list)
    script: list = field(default_factory=list)
    ntfy_token: str | None = None
    ntfy_basic: tuple[str, str] | None = None

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = request.content
        self.requests.append({"url": str(request.url), "method": request.method, "headers": dict(request.headers), "body": body})
        if self.script:
            status, headers, content = self.script.pop(0)
            return httpx.Response(status, headers=headers, content=content)
        host = request.url.host
        if host == "hooks.slack.com":
            return self._slack(request)
        if host == "discord.com":
            return self._discord(request)
        return self._ntfy(request)

    def _slack(self, request):
        try:
            data = json.loads(request.content)
        except ValueError:
            return httpx.Response(400, content=b"invalid_payload")
        if not isinstance(data, dict) or ("text" not in data and "blocks" not in data):
            return httpx.Response(400, content=b"no_text")
        if request.url.path != "/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx":
            return httpx.Response(404, content=b"no_service")
        if len(data.get("blocks", [])) > 50:
            return httpx.Response(400, content=b"invalid_blocks")
        for b in data.get("blocks", []):
            t = b.get("text", {})
            if b["type"] == "section" and len(t.get("text", "")) > 3000:
                return httpx.Response(400, content=b"invalid_blocks")
            if b["type"] == "header" and len(t.get("text", "")) > 150:
                return httpx.Response(400, content=b"invalid_blocks")
            if b["type"] == "context" and len(b.get("elements", [])) > 10:
                return httpx.Response(400, content=b"invalid_blocks")
        return httpx.Response(200, content=b"ok")

    def _discord(self, request):
        try:
            data = json.loads(request.content)
        except ValueError:
            return httpx.Response(400, json={"message": "Cannot send an empty message", "code": 50006})
        embeds = data.get("embeds", [])
        if not embeds and not data.get("content"):
            return httpx.Response(400, json={"message": "Cannot send an empty message", "code": 50006})
        if len(embeds) > 10 or len(data.get("content", "")) > 2000:
            return httpx.Response(400, json={"message": "Invalid Form Body", "code": 50035})
        total = 0
        for e in embeds:
            fields = e.get("fields", [])
            parts = [e.get("title", ""), e.get("description", ""), e.get("footer", {}).get("text", ""), e.get("author", {}).get("name", "")]
            parts += [x for f in fields for x in (f["name"], f["value"])]
            total += sum(len(p) for p in parts)
            if (len(e.get("title", "")) > 256 or len(e.get("description", "")) > 4096 or len(fields) > 25
                    or any(len(f["name"]) > 256 or len(f["value"]) > 1024 for f in fields)
                    or len(e.get("footer", {}).get("text", "")) > 2048 or not isinstance(e.get("color", 0), int)):
                return httpx.Response(400, json={"message": "Invalid Form Body", "code": 50035})
        if total > 6000:
            return httpx.Response(400, json={"message": "Invalid Form Body", "code": 50035})
        return httpx.Response(204, headers={"x-ratelimit-remaining": "4", "x-ratelimit-reset-after": "1.0"})

    def _ntfy(self, request):
        auth = request.headers.get("authorization")
        if self.ntfy_token and auth != f"Bearer {self.ntfy_token}":
            return httpx.Response(401, json={"code": 40101, "http": 401, "error": "unauthorized"})
        if self.ntfy_basic:
            want = "Basic " + base64.b64encode(":".join(self.ntfy_basic).encode()).decode()
            if auth != want:
                return httpx.Response(401, json={"code": 40101, "http": 401, "error": "unauthorized"})
        if request.url.path not in ("", "/"):
            return httpx.Response(404, json={"code": 40401, "http": 404, "error": "page not found"})
        try:
            data = json.loads(request.content)
        except ValueError:
            return httpx.Response(400, json={"code": 40001, "http": 400, "error": "invalid JSON"})
        if not data.get("topic"):
            return httpx.Response(400, json={"code": 40001, "http": 400, "error": "topic missing"})
        if len(data.get("message", "").encode()) > 4096 or len(data.get("title", "").encode()) > 1024:
            return httpx.Response(400, json={"code": 40013, "http": 400, "error": "message or title too long"})
        if not 1 <= data.get("priority", 3) <= 5:
            return httpx.Response(400, json={"code": 40007, "http": 400, "error": "invalid priority"})
        return httpx.Response(200, json={"id": "abc", "time": 1, "event": "message", "topic": data["topic"]})

    def json(self, i: int = -1) -> dict:
        return json.loads(self.requests[i]["body"])


class FakeNet:
    """The bit of remote.client.Net the sender uses: a transport."""

    def __init__(self, fake: Fake):
        self.transport = fake.transport()


# --- SMTP ------------------------------------------------------------------------------

def make_cert(folder: Path) -> tuple[Path, Path] | None:
    """A throwaway self-signed certificate for localhost and 127.0.0.1 (None when openssl is not installed)."""
    if not shutil.which("openssl"):
        return None
    key, crt = folder / "smtp.key", folder / "smtp.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    return key, crt


class FakeSMTP:
    """A minimal SMTP server: EHLO, STARTTLS (when `mode` is "starttls"), AUTH PLAIN and LOGIN (only advertised once the link is
    encrypted, unless `auth_in_clear`), MAIL, RCPT, DATA, QUIT. `mode` "tls" is implicit TLS, "plain" has no TLS at all."""

    def __init__(self, mode: str, cert: tuple[Path, Path] | None = None, user: str = "bot", password: str = "pw-secret-1",
                 offer_starttls: bool = True):
        self.mode, self.user, self.password, self.offer_starttls = mode, user, password, offer_starttls
        self.messages: list[bytes] = []
        self.recipients: list[list[str]] = []
        self.auth_log: list[tuple[str, bool, bool]] = []     # (user, ok, over TLS)
        self.clear_commands: list[str] = []
        self.ctx = None
        if cert:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(str(cert[1]), str(cert[0]))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        self._stop = True
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        except OSError:
            pass
        self.sock.close()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            if self._stop:
                conn.close()
                return
            try:
                self._session(conn)
            except (OSError, ssl.SSLError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _session(self, conn):
        conn.settimeout(10)
        tls = False
        if self.mode == "tls":
            conn = self.ctx.wrap_socket(conn, server_side=True)
            tls = True
        f = conn.makefile("rwb", buffering=0)

        def send(line: str):
            f.write(line.encode() + b"\r\n")

        def readline() -> str:
            return f.readline().decode("utf-8", "replace").rstrip("\r\n")

        send("220 fake ESMTP")
        sender, rcpts = "", []
        while True:
            line = readline()
            if not line:
                return
            cmd = line.split(" ", 1)[0].upper()
            if not tls:
                self.clear_commands.append(cmd)
            if cmd in ("EHLO", "HELO"):
                caps = ["250-fake", "250-8BITMIME"]
                if self.mode == "starttls" and not tls and self.offer_starttls:
                    caps.append("250-STARTTLS")
                if tls or self.mode == "plain":
                    caps.append("250-AUTH PLAIN LOGIN")
                caps.append("250 SIZE 10485760")
                for c in caps:
                    send(c)
            elif cmd == "STARTTLS":
                send("220 ready")
                conn = self.ctx.wrap_socket(conn, server_side=True)
                f = conn.makefile("rwb", buffering=0)
                tls = True
            elif cmd == "AUTH":
                parts = line.split()
                user = pw = ""
                if parts[1].upper() == "PLAIN":
                    raw = parts[2] if len(parts) > 2 else (send("334 ") or readline())
                    _a, user, pw = base64.b64decode(raw).decode().split("\x00")
                else:
                    send("334 " + base64.b64encode(b"Username:").decode())
                    user = base64.b64decode(readline()).decode()
                    send("334 " + base64.b64encode(b"Password:").decode())
                    pw = base64.b64decode(readline()).decode()
                ok = user == self.user and pw == self.password
                self.auth_log.append((user, ok, tls))
                send("235 ok" if ok else "535 5.7.8 bad credentials")
            elif cmd == "MAIL":
                sender = line
                rcpts = []
                send("250 ok")
            elif cmd == "RCPT":
                rcpts.append(line.split(":", 1)[1].strip().strip("<>"))
                send("250 ok")
            elif cmd == "DATA":
                send("354 go")
                data = bytearray()
                while True:
                    chunk = readline()
                    if chunk == ".":
                        break
                    data += (chunk[1:] if chunk.startswith("..") else chunk).encode("utf-8", "replace") + b"\r\n"
                self.messages.append(bytes(data))
                self.recipients.append(rcpts)
                send("250 queued")
            elif cmd == "QUIT":
                send("221 bye")
                return
            else:
                send("250 ok")
