"""A fake Docker Engine on a unix socket, and a fake Docker reader for the hub's side. Everything here is made up:
the names are invented (acme, widget, nginx, debian are public or fictional), and the ids are hashes of those names.

`FakeEngine` speaks just enough HTTP/1.1 to answer httpx over a unix socket, records every request as
(method, target), and answers from `replies`, a dict of target (without the /v1.54 prefix) to a JSON-able body,
a (status, body) pair, or a function of the target. A target it has no reply for is a 404. It also puts secrets
(Env, Cmd) where the real Docker does, so the tests can prove they never come out of the reader."""

import asyncio
import contextlib
import copy
import hashlib
import io
import json
import re
import tarfile

import httpx

SECRET = "hunter2-the-database-password"


def hid(name: str) -> str:
    """A made-up image id from a name: sha256:<64 hex>."""
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def vol_name(name: str) -> str:
    """A made-up anonymous volume name (64 hex digits)."""
    return hashlib.sha256(("vol" + name).encode()).hexdigest()


IDS = {n: hid(n) for n in ("nginx", "postgres", "widget-new", "widget-old", "debian", "gadget", "oldapp", "mystery", "tool", "inuse2")}
CREATED = {"nginx": 1_760_000_000, "postgres": 1_760_000_100, "widget-new": 1_762_000_000, "widget-old": 1_750_000_000,
           "debian": 1_755_000_000, "gadget": 1_740_000_000, "oldapp": 1_730_000_000, "mystery": 1_720_000_000,
           "tool": 1_735_000_000, "inuse2": 1_761_000_000}
SIZES = {"nginx": 190_000_000, "postgres": 430_000_000, "widget-new": 300_000_000, "widget-old": 290_000_000,
         "debian": 117_000_000, "gadget": 500_000_000, "oldapp": 700_000_000, "mystery": 50_000_000, "tool": 80_000_000,
         "inuse2": 60_000_000}


def image(name: str, tags=(), digests=(), labels=None, **extra) -> dict:
    """An /images/json entry."""
    return {"Id": IDS[name], "ParentId": "", "RepoTags": list(tags) or None, "RepoDigests": list(digests) or None,
            "Created": CREATED[name], "Size": SIZES[name], "SharedSize": -1, "Labels": labels, "Containers": -1, **extra}


def container(name: str, image_name: str, image_ref: str, state="running", volumes=()) -> dict:
    return {"Id": hashlib.sha256(name.encode()).hexdigest(), "Names": ["/" + name], "Image": image_ref,
            "ImageID": IDS[image_name], "Command": "run --secret", "State": state, "Status": "Up 2 hours",
            "Env": [f"PASSWORD={SECRET}"],      # not a real field of the summary; here to prove nothing copies it
            "Mounts": [{"Type": "volume", "Name": v, "Source": "/var/lib/docker/volumes/x/_data", "Destination": "/data"}
                       for v in volumes] + [{"Type": "bind", "Source": "/mnt/user/appdata/x", "Destination": "/cfg"}],
            "Labels": {"com.example.secret": SECRET}}


def inspect_of(name: str, labels=None, last_tag="0001-01-01T00:00:00Z") -> dict:
    return {"Id": IDS[name], "RepoTags": [], "Created": "2025-01-01T00:00:00Z", "Size": SIZES[name],
            "Config": {"Env": [f"PASSWORD={SECRET}", "PATH=/usr/bin"], "Cmd": ["serve", f"--token={SECRET}"],
                       "Entrypoint": ["/entry.sh"], "Labels": labels},
            "Metadata": {"LastTagTime": last_tag}}


ANON_A, ANON_B, ANON_USED = vol_name("a"), vol_name("b"), vol_name("used")


def standard_replies(df_shape: str = "new") -> dict:
    """A small server: nginx and postgres and the new widget run; the old widget (untagged), debian, gadget (with a source
    label), oldapp (an app that was removed), mystery (nothing to go on) and tool (a multi-tag image) are unused."""
    long_label = "x" * 500
    containers = [
        container("web", "nginx", "nginx:1.27", volumes=["webdata"]),
        container("db", "postgres", "postgres:17", volumes=[ANON_USED]),
        container("widget", "widget-new", "ghcr.io/acme/widget:latest"),
        container("sleeper", "inuse2", "acme/sleeper:1", state="exited"),
    ]
    images = [
        image("nginx", ["nginx:1.27"], ["nginx@sha256:" + "1" * 64], {"org.opencontainers.image.title": "nginx", "other.label": "dropped"}),
        image("postgres", ["postgres:17"], ["postgres@sha256:" + "2" * 64]),
        image("widget-new", ["ghcr.io/acme/widget:latest"], ["ghcr.io/acme/widget@sha256:" + "3" * 64],
              {"org.opencontainers.image.source": "https://github.com/acme/widget"}),
        image("widget-old", [], ["ghcr.io/acme/widget@sha256:" + "4" * 64], {"org.opencontainers.image.source": "https://github.com/acme/widget"}),
        image("debian", ["debian:12"], ["debian@sha256:" + "5" * 64]),
        image("gadget", ["acme/gadget:2"], [], {"org.opencontainers.image.source": "https://example.test/acme/gadget", "net.unraid.docker.icon": "https://example.test/i.png"}),
        image("oldapp", ["acme/oldapp:latest"], ["acme/oldapp@sha256:" + "6" * 64]),
        image("mystery", ["someone/mystery:1"], []),
        image("tool", ["acme/tool:1", "acme/tool:stable"], []),
        image("inuse2", ["acme/sleeper:1"], []),
    ]
    inspects = {
        "widget-old": inspect_of("widget-old", {"org.opencontainers.image.source": "https://github.com/acme/widget", "org.opencontainers.image.description": long_label, "evil": "x"}),
        "debian": inspect_of("debian", None, "2025-06-01T12:00:00.123456789Z"),
        "gadget": inspect_of("gadget", {"org.opencontainers.image.source": "https://example.test/acme/gadget"}),
        "oldapp": inspect_of("oldapp", None), "mystery": inspect_of("mystery", None), "tool": inspect_of("tool", None),
    }
    volumes = {"Volumes": [
        {"Name": ANON_A, "Driver": "local", "CreatedAt": "2025-03-01T10:00:00Z", "Labels": {"com.docker.volume.anonymous": ""}, "Mountpoint": "/x"},
        {"Name": ANON_B, "Driver": "local", "CreatedAt": "2025-03-02T10:00:00Z", "Labels": {"com.docker.volume.anonymous": ""}, "Mountpoint": "/x"},
        {"Name": "shop_db", "Driver": "local", "CreatedAt": "2025-04-01T10:00:00Z",
         "Labels": {"com.docker.compose.project": "shop", "com.docker.compose.volume": "db", "secret.label": SECRET}, "Mountpoint": "/x"},
        {"Name": "webdata", "Driver": "local", "CreatedAt": "2025-05-01T10:00:00Z", "Labels": None, "Mountpoint": "/x"},
        {"Name": ANON_USED, "Driver": "local", "CreatedAt": "2025-05-02T10:00:00Z", "Labels": {"com.docker.volume.anonymous": ""}, "Mountpoint": "/x"},
    ], "Warnings": []}
    usage = {ANON_A: (4_000_000, 0), ANON_B: (30_000_000, 0), "shop_db": (900_000_000, 0), "webdata": (5_000_000, 1), ANON_USED: (7_000_000, 1)}
    vol_usage = [{**v, "UsageData": {"Size": usage[v["Name"]][0], "RefCount": usage[v["Name"]][1]}} for v in volumes["Volumes"]]
    if df_shape == "new":
        df = {"ImageUsage": {"ActiveCount": 4, "TotalCount": 10, "Reclaimable": 1_000_000_000, "TotalSize": 3_000_000_000},
              "VolumeUsage": {"ActiveCount": 2, "TotalCount": 5, "Reclaimable": 934_000_000, "TotalSize": 946_000_000, "Items": vol_usage},
              "BuildCacheUsage": {"ActiveCount": 0, "TotalCount": 12, "Reclaimable": 6_100_000_000, "TotalSize": 6_100_000_000}}
    else:
        df = {"LayersSize": 1, "Images": [], "Containers": [], "Volumes": vol_usage,
              "BuildCache": [{"ID": f"c{i}", "Size": 500_000_000, "InUse": False} for i in range(12)]}
    replies = {
        "/_ping": (200, "OK"), "/version": {"ApiVersion": "1.54", "MinAPIVersion": "1.24", "Version": "29.0.0"},
        "/containers/json?all=1": containers, "/images/json?all=0&digests=1": images, "/volumes": volumes,
        "/system/df?verbose=1": df,
    }
    for n, body in inspects.items():
        replies[f"/images/{IDS[n]}/json"] = body
    return replies


def tar_of(name: str, data: bytes = b"", kind: bytes = tarfile.REGTYPE, link: str = "", extra: tuple = ()) -> bytes:
    """A tar stream as ContainerArchive answers: one member (plus `extra` (name, data) regular members), uncompressed."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.linkname = link
        info.size = len(data) if kind == tarfile.REGTYPE else 0
        tf.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        for n, d in extra:
            i2 = tarfile.TarInfo(n)
            i2.size = len(d)
            tf.addfile(i2, io.BytesIO(d))
    return buf.getvalue()


def archive_key(container_name: str, path: str) -> str:
    """The engine's reply key (without the /v1.54 prefix) for one archive read of the container called `container_name`."""
    from urllib.parse import quote
    return f"/containers/{hashlib.sha256(container_name.encode()).hexdigest()}/archive?path={quote(path, safe='')}"


def serve_files(replies: dict, container_name: str, files: dict) -> None:
    """Make `replies` answer archive reads for a container. A value that is bytes becomes a one-file tar of that
    content; a ("tar", raw) pair is sent as the raw tar stream given. A path not listed stays a 404."""
    for path, content in files.items():
        raw = content[1] if isinstance(content, tuple) else tar_of(path.rsplit("/", 1)[1], content)
        replies[archive_key(container_name, path)] = raw


class FakeEngine:
    def __init__(self, path, replies=None):
        self.path = str(path)
        self.replies = copy.deepcopy(replies if replies is not None else standard_replies())
        self.requests: list[tuple[str, str]] = []      # (method, target as sent)
        self.delay: dict[str, float] = {}              # target (without prefix) -> seconds to wait before answering
        self._server = None

    @staticmethod
    def strip(target: str) -> str:
        return re.sub(r"^/v\d+\.\d+", "", target)

    def targets(self) -> list[str]:
        return [t for _m, t in self.requests]

    async def _handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return
        method, target, _v = head.split(b"\r\n", 1)[0].decode().split(" ")
        self.requests.append((method, target))
        bare = self.strip(target)
        if bare in self.delay:
            await asyncio.sleep(self.delay[bare])
        reply = self.replies.get(bare)
        if callable(reply):
            reply = reply(bare)
        status, body = (reply if isinstance(reply, tuple) else (200, reply)) if reply is not None else (404, {"message": "page not found"})
        raw = body if isinstance(body, bytes) else body.encode() if isinstance(body, str) else json.dumps(body).encode()
        ctype = "application/x-tar" if isinstance(body, bytes) else "text/plain" if isinstance(body, str) else "application/json"
        writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode() + raw)
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        writer.close()

    async def __aenter__(self):
        self._server = await asyncio.start_unix_server(self._handle, path=self.path)
        return self

    async def __aexit__(self, *exc):
        self._server.close()
        await self._server.wait_closed()


class FakeReader:
    """The hub's view of a Docker reader: an httpx MockTransport that checks the bearer token and answers
    /v1/summary and /v1/health. `summary` is the JSON the reader would send."""

    def __init__(self, token: str, summary: dict | None = None):
        self.token = token
        self.summary = summary if summary is not None else standard_summary()
        self.requests: list[httpx.Request] = []
        self.status: int | None = None
        self.fail: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            raise self.fail
        if request.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(401, json={"error": "A valid bearer token is required."})
        if self.status:
            return httpx.Response(self.status, json={"error": "Docker did not answer in time."})
        if request.method != "GET" or request.url.path not in ("/v1/summary", "/v1/health"):
            return httpx.Response(404, json={"error": "no"})
        if request.url.path == "/v1/health":
            return httpx.Response(200, json={"ok": True, "version": "29.0.0", "api": "1.54"})
        return httpx.Response(200, json=copy.deepcopy(self.summary))

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler), timeout=5, follow_redirects=False)

    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]


def standard_summary() -> dict:
    """What the reader sends for standard_replies(): built with the reader's own trimming, without a socket."""
    from daemonsight import docker_reader as dr
    r = standard_replies()
    containers = dr.trim_containers(r["/containers/json?all=1"])
    used = {c["image_id"] for c in containers}
    mounted: dict[str, int] = {}
    for c in containers:
        for v in c["volumes"]:
            mounted[v] = mounted.get(v, 0) + 1
    df = dr.parse_df(r["/system/df?verbose=1"])
    images = []
    for s in r["/images/json?all=0&digests=1"]:
        n = next(k for k, v in IDS.items() if v == s["Id"])
        ins = None
        if s["Id"] not in used:
            data = r.get(f"/images/{s['Id']}/json")
            ins = {"Config": {"Labels": data["Config"]["Labels"]}, "Metadata": data["Metadata"]} if data else None
        images.append(dr.trim_image(s, s["Id"] in used, ins))
    for c in containers:
        c.pop("volumes")
        c.pop("id")
    return {"v": 1, "generated": 1_800_000_000, "docker": {"version": "29.0.0", "api": "1.54"}, "df_at": 1_800_000_000,
            "df_error": None, "df_running": False, "containers": containers, "images": images,
            "images_reclaimable": df["images_reclaimable"], "volumes": dr.trim_volumes(r["/volumes"], df["volumes"], mounted),
            "build_cache": df["build_cache"]}
