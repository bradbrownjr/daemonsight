"""The Docker reader: a small second process (`daemonsight docker-reader`) that tells the hub what Docker is holding
on a server, because Unraid's GraphQL API lists containers but not images, volumes or build cache.

It is not a proxy. It has two routes, `GET /v1/summary` and `GET /v1/health`, both behind a bearer token. The summary
is computed here from a fixed list of Docker Engine API reads and trimmed to the fields below; no path or query of
the caller's ever reaches Docker, so the hub can't ask Docker anything else.

Talking to Docker (https://docs.docker.com/reference/api/engine/): GET only, over the unix socket, to exactly these
targets. `/_ping` and `/version` are unversioned; every other path carries the version prefix (`/v1.54/volumes`), which
is the lower of the daemon's `ApiVersion` (from `/version`) and `MAX_API`, the newest version whose reference was read
for this file (https://docs.docker.com/reference/api/engine/version/v1.54/).

* `GET /_ping`: "Ping": the daemon answers `OK` (swagger operation SystemPing). Used by the health route.
* `GET /version`: "Get version" (SystemVersion): `ApiVersion`, `MinAPIVersion`, `Version`. Kept: the first and the last.
* `GET /containers/json?all=1`: "List containers" (ContainerList), `all` = "Return all containers. By default, only
  running containers are shown". The summary has `Names`, `Image`, `ImageID`, `State` and `Mounts` (of which only the names of `volume` mounts are kept: a
  volume is "in use" while a container, running or not, mounts it, which is what `/system/df`'s `RefCount` counts too,
  and this way it is known before the slow df read ends). Not `/containers/{id}/json`
  (inspect): that holds each container's `Config.Env`, where passwords live.
* `GET /images/json?all=0&digests=1`: "List Images" (ImageList). `all=0` is the default: "Only images from a final layer
  (no children) are shown". That already includes dangling images (untagged leaves, which is what `docker image prune`
  removes), and leaves out the intermediate layers of a build, which nobody can remove on their own and which
  `all=1` would add as noise. `digests=1` adds `RepoDigests` to each summary, which the hub reads for the image's
  repository name. Per image: `Id`, `RepoTags`, `RepoDigests`, `Created` (Unix time), `Size` (all layers, shared ones
  included), `Labels` (the image's config labels).
* `GET /images/{id}/json`: "Inspect an image" (ImageInspect), only for an image no container uses and only with
  `sha256:<64 hex>` as the id. Kept: `Metadata.LastTagTime` ("Additional metadata of the image in the local cache";
  `0001-01-01T00:00:00Z` for an image that was pulled and never tagged by hand: seen live), `Config.Labels`,
  `RepoDigests`, `RepoTags`, `Created`, `Size`. Never `Config.Env`, `Config.Cmd` or `Config.Entrypoint`.
* `GET /volumes`: "List volumes" (VolumeList): `Name`, `Driver`, `CreatedAt`, `Labels`.
* `GET /system/df?verbose=1`: "Get data usage information" (SystemDataUsage), "verbose: Show detailed information on
  space usage". It is very slow on a busy server (it walks every volume: more than 15 minutes on the first server this
  was built for), so it runs in the background, never inside a request: the summary is answered at once from what is
  cached and carries `df_at` (when the sizes were read, null until the first read ends) and `df_running`. A new read
  starts DF_SECONDS after the last one ended. From API 1.52 the answer is `ImageUsage`, `VolumeUsage` (with `Items`, each volume carrying `UsageData`
  `{Size, RefCount}`), `BuildCacheUsage` (`TotalCount`, `TotalSize`); before it, `Volumes` and `BuildCache` arrays.
  Both are read.

Nothing else is sent: `Docker.get` refuses any other target, and has no method that sends anything but GET.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__

log = logging.getLogger("daemonsight.docker_reader")

MAX_API = (1, 54)                  # the newest Engine API version whose reference was read (see the module doc)
DF_SECONDS = 30 * 60               # /system/df at most this often
INSPECT_SECONDS = 30 * 60          # an image's inspect is reused this long
SUMMARY_SECONDS = 60               # the whole summary is reused this long
MAX_BODY = 64 << 20                # bytes accepted from Docker per request
TIMEOUT = httpx.Timeout(60.0, connect=5.0)
DF_TIMEOUT = httpx.Timeout(3600.0, connect=5.0)
TOKEN_MIN = 32
MAX_CONTAINERS, MAX_IMAGES, MAX_VOLUMES = 2000, 3000, 10000
LABEL_PREFIXES = ("org.opencontainers.image.", "net.unraid.")       # image labels kept
VOLUME_LABEL_PREFIX = "com.docker.compose."                          # volume labels kept
ANON_LABEL = "com.docker.volume.anonymous"                           # set by Docker on an anonymous volume (seen live)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")

UNVERSIONED = frozenset({"/_ping", "/version"})
VERSIONED = frozenset({"/containers/json?all=1", "/images/json?all=0&digests=1", "/volumes", "/system/df?verbose=1"})
_INSPECT = re.compile(r"^/images/sha256:[0-9a-f]{64}/json$")


class DockerError(Exception):
    """A failed read of Docker. The message is short and holds nothing from Docker's replies."""


def clean(v, n: int = 200) -> str:
    return "".join(c for c in str(v if v is not None else "")[:n] if c.isprintable()).strip()


def num(v) -> int | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return int(v)


def api_tuple(v: str) -> tuple[int, int] | None:
    m = re.fullmatch(r"(\d{1,3})\.(\d{1,4})", str(v or "").strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


class Docker:
    """Docker's Engine API, read-only. `get` sends GET and nothing else, to a target in the fixed list, and returns
    the parsed JSON (the text for `/_ping`). Redirects are not followed; a reply is capped at MAX_BODY."""

    def __init__(self, http: httpx.AsyncClient):
        self._http = http
        self.api: tuple[int, int] | None = None     # set by `negotiate`

    @classmethod
    def over_socket(cls, path: str) -> "Docker":
        transport = httpx.AsyncHTTPTransport(uds=path)
        return cls(httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=TIMEOUT,
                                     follow_redirects=False, trust_env=False,
                                     headers={"User-Agent": f"DaemonSight-docker-reader/{__version__}"}))

    async def aclose(self) -> None:
        await self._http.aclose()

    @staticmethod
    def check_allowed(target: str) -> None:
        if target not in UNVERSIONED and target not in VERSIONED and not _INSPECT.match(target):
            raise ValueError("only the listed read-only Docker endpoints may be requested")

    def _url(self, target: str) -> str:
        if target in UNVERSIONED:
            return target
        if self.api is None:
            raise DockerError("Docker's API version is not known yet.")
        return f"/v{self.api[0]}.{self.api[1]}{target}"

    async def get(self, target: str, timeout: httpx.Timeout | None = None):
        self.check_allowed(target)
        url = self._url(target)
        try:
            async with self._http.stream("GET", url, **({"timeout": timeout} if timeout else {})) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BODY:
                        raise DockerError("Docker's reply was too large; ignored.")
                status = r.status_code
        except DockerError:
            raise
        except httpx.TimeoutException:
            raise DockerError("Docker did not answer in time.") from None
        except httpx.HTTPError as exc:
            raise DockerError(f"Could not reach Docker's socket ({type(exc).__name__}).") from None
        if status != 200:
            raise DockerError(f"Docker answered HTTP {status}.")
        if target == "/_ping":
            return bytes(body).decode("ascii", "replace").strip()[:20]
        try:
            return json.loads(body)
        except ValueError:
            raise DockerError("Docker's reply was not JSON.") from None

    async def negotiate(self) -> dict:
        """Read `/version` and fix the API version to use. Returns {"version", "api"} (what the daemon says)."""
        v = await self.get("/version")
        if not isinstance(v, dict):
            raise DockerError("Docker's version reply was not what was expected.")
        top, low = api_tuple(v.get("ApiVersion")), api_tuple(v.get("MinAPIVersion"))
        if top is None:
            raise DockerError("Docker did not say which API version it speaks.")
        use = min(top, MAX_API)
        if low is not None and use < low:
            use = top
        self.api = use
        return {"version": clean(v.get("Version"), 40), "api": f"{top[0]}.{top[1]}"}


# --- trimming ---------------------------------------------------------------------------------------------------

def keep_labels(labels, prefixes: tuple[str, ...], n: int = 200) -> dict[str, str]:
    """Only labels whose key starts with one of `prefixes`, values cut to `n` characters. A null (an image with no
    labels: seen live) is an empty dict."""
    if not isinstance(labels, dict):
        return {}
    out = {}
    for k, v in labels.items():
        if isinstance(k, str) and k.startswith(prefixes) and len(out) < 40:
            out[clean(k, 100)] = clean(v, n)
    return out


def epoch(v) -> int | None:
    """Unix time from an RFC 3339 string; None for the zero time Docker uses for "never"."""
    s = str(v or "").strip()
    if not s or s.startswith("0001-"):
        return None
    try:
        from datetime import datetime
        s = re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00"))
        return int(datetime.fromisoformat(s).timestamp())
    except ValueError:
        return None


def trim_containers(raw) -> list[dict]:
    out = []
    for c in (raw if isinstance(raw, list) else [])[:MAX_CONTAINERS]:
        if not isinstance(c, dict):
            continue
        names = c.get("Names") or []
        mounts = c.get("Mounts") if isinstance(c.get("Mounts"), list) else []
        vols = sorted({clean(m.get("Name"), 100) for m in mounts[:200]
                       if isinstance(m, dict) and m.get("Type") == "volume" and m.get("Name")})
        out.append({"name": clean(names[0] if names else "", 80).lstrip("/"), "image": clean(c.get("Image"), 200),
                    "image_id": clean(c.get("ImageID"), 80), "state": clean(c.get("State"), 20).lower(),
                    "volumes": vols})
    out.sort(key=lambda c: c["name"].lower())
    return out


def _strs(v, n: int = 60, each: int = 200) -> list[str]:
    return [clean(x, each) for x in (v if isinstance(v, list) else [])[:n] if isinstance(x, str)]


def trim_image(summary: dict, in_use: bool, inspected: dict | None) -> dict:
    """One image as sent. `summary` is a list entry; `inspected` (unused images only) is the inspect reply."""
    ins = inspected or {}
    cfg = ins.get("Config") if isinstance(ins.get("Config"), dict) else {}
    meta = ins.get("Metadata") if isinstance(ins.get("Metadata"), dict) else {}
    labels = keep_labels(cfg.get("Labels") if inspected else summary.get("Labels"), LABEL_PREFIXES)
    return {"id": clean(summary.get("Id"), 80), "tags": [t for t in _strs(summary.get("RepoTags")) if t != "<none>:<none>"],
            "digests": [d for d in _strs(summary.get("RepoDigests")) if d != "<none>@<none>"],
            "created": num(summary.get("Created")), "size": num(summary.get("Size")),
            "last_tag": epoch(meta.get("LastTagTime")) if inspected else None, "labels": labels, "in_use": in_use}


def parse_df(df) -> dict:
    """{"volumes": {name: {"size", "refs"}}, "build_cache": {"count", "size"} | None, "images_reclaimable"} from either
    shape of /system/df (see the module doc)."""
    if not isinstance(df, dict):
        return {"volumes": {}, "build_cache": None, "images_reclaimable": None}
    vol_items, cache = None, None
    vu = df.get("VolumeUsage")
    if isinstance(vu, dict):
        vol_items = vu.get("Items")
    elif isinstance(df.get("Volumes"), list):
        vol_items = df["Volumes"]
    volumes = {}
    for v in (vol_items if isinstance(vol_items, list) else [])[:MAX_VOLUMES]:
        if isinstance(v, dict) and isinstance(v.get("UsageData"), dict):
            u = v["UsageData"]
            size, refs = num(u.get("Size")), num(u.get("RefCount"))
            volumes[clean(v.get("Name"), 100)] = {"size": size if size is not None and size >= 0 else None,
                                                  "refs": refs if refs is not None and refs >= 0 else None}
    bu = df.get("BuildCacheUsage")
    if isinstance(bu, dict):
        cache = {"count": num(bu.get("TotalCount")), "size": num(bu.get("TotalSize"))}
    elif isinstance(df.get("BuildCache"), list):
        recs = [r for r in df["BuildCache"] if isinstance(r, dict)]
        cache = {"count": len(recs), "size": sum(num(r.get("Size")) or 0 for r in recs)}
    iu = df.get("ImageUsage")
    return {"volumes": volumes, "build_cache": cache,
            "images_reclaimable": num(iu.get("Reclaimable")) if isinstance(iu, dict) else None}


def trim_volumes(raw, usage: dict[str, dict], mounted: dict[str, int]) -> list[dict]:
    """Volumes as sent. `usage` is from /system/df (empty until its first read ends); `mounted` counts the containers
    that mount each volume, used for the reference count when df has none."""
    items = raw.get("Volumes") if isinstance(raw, dict) else None
    out = []
    for v in (items if isinstance(items, list) else [])[:MAX_VOLUMES]:
        if not isinstance(v, dict):
            continue
        name = clean(v.get("Name"), 100)
        labels = v.get("Labels") if isinstance(v.get("Labels"), dict) else {}
        u = usage.get(name) or {}
        out.append({"name": name, "created": clean(v.get("CreatedAt"), 40), "driver": clean(v.get("Driver"), 40),
                    "labels": keep_labels(labels, (VOLUME_LABEL_PREFIX,)),
                    "anonymous": ANON_LABEL in labels or bool(_HEX64.match(name)),
                    "size": u.get("size"), "refs": u["refs"] if u.get("refs") is not None else mounted.get(name, 0)})
    out.sort(key=lambda v: v["name"])
    return out


# --- the summary --------------------------------------------------------------------------------------------------

@dataclass
class Summarizer:
    """Builds the summary. The cheap reads (containers, images, volumes) happen at most every SUMMARY_SECONDS, an
    unused image's inspect is reused for INSPECT_SECONDS, and `/system/df` runs in a background task (see the module
    doc) that keeps the last good result when a read fails."""
    docker: Docker
    clock: object = time.time
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _summary: dict | None = None
    _built: float = 0.0
    _df: dict | None = None
    _df_at: float | None = None
    _df_ended: float | None = None
    _df_error: str | None = None
    df_task: asyncio.Task | None = None
    _inspect: dict[str, tuple[float, dict]] = field(default_factory=dict)
    _info: dict | None = None

    async def health(self) -> dict:
        reply = await self.docker.get("/_ping")
        if reply != "OK":
            raise DockerError("Docker did not answer the ping as expected.")
        if self._info is None or self.docker.api is None:
            self._info = await self.docker.negotiate()
        return {"ok": True, **self._info}

    async def get(self) -> dict:
        async with self._lock:
            now = self.clock()
            self._maybe_start_df(now)
            if self._summary is not None and now - self._built < SUMMARY_SECONDS:
                return {**self._summary, **self._df_state()}
            self._summary = await self._build(now)
            self._built = now
            return {**self._summary, **self._df_state()}

    def _maybe_start_df(self, now: float) -> None:
        running = self.df_task is not None and not self.df_task.done()
        due = self._df_ended is None or now - self._df_ended >= DF_SECONDS
        if not running and due and self.docker.api is not None:
            self.df_task = asyncio.create_task(self._refresh_df())

    async def _refresh_df(self) -> None:
        try:
            self._df = parse_df(await self.docker.get("/system/df?verbose=1", DF_TIMEOUT))
            self._df_at = self.clock()
            self._df_error = None
        except DockerError as exc:
            self._df_error = str(exc)
        except Exception:
            log.exception("Reading Docker's data usage failed")
            self._df_error = "The reader failed to read Docker's data usage."
        finally:
            self._df_ended = self.clock()

    def _df_state(self) -> dict:
        """What changes with the background read, so a cached summary still reports it."""
        df = self._df or parse_df(None)
        sizes = df["volumes"]
        vols = [{**v, "size": (sizes.get(v["name"]) or {}).get("size", v["size"])} for v in self._summary["volumes"]]
        return {"df_at": int(self._df_at) if self._df_at else None, "df_error": self._df_error,
                "df_running": self.df_task is not None and not self.df_task.done(),
                "images_reclaimable": df["images_reclaimable"], "volumes": vols, "build_cache": df["build_cache"]}

    async def _build(self, now: float) -> dict:
        if self._info is None or self.docker.api is None:
            self._info = await self.docker.negotiate()
        self._maybe_start_df(now)
        containers = trim_containers(await self.docker.get("/containers/json?all=1"))
        listed = await self.docker.get("/images/json?all=0&digests=1")
        volumes_raw = await self.docker.get("/volumes")
        used_ids = {c["image_id"] for c in containers if c["image_id"]}
        mounted: dict[str, int] = {}
        for c in containers:
            for name in c["volumes"]:
                mounted[name] = mounted.get(name, 0) + 1
        todo = []
        for s in (listed if isinstance(listed, list) else [])[:MAX_IMAGES]:
            if isinstance(s, dict) and _IMAGE_ID.match(str(s.get("Id") or "")):
                todo.append((s, s["Id"] in used_ids))
        live = {s["Id"] for s, in_use in todo if not in_use}
        sem = asyncio.Semaphore(6)

        async def inspect(iid: str):
            async with sem:
                return await self._inspected(iid, now)

        results = await asyncio.gather(*(inspect(s["Id"]) if not in_use else asyncio.sleep(0, None) for s, in_use in todo))
        images = [trim_image(s, in_use, ins) for (s, in_use), ins in zip(todo, results)]
        for iid in set(self._inspect) - live:
            del self._inspect[iid]
        for c in containers:     # the reader sends which volumes a container uses, not the mounts themselves
            c.pop("volumes", None)
        return {"v": 1, "generated": int(now), "docker": dict(self._info), "containers": containers, "images": images,
                "volumes": trim_volumes(volumes_raw, (self._df or parse_df(None))["volumes"], mounted)}

    async def _inspected(self, iid: str, now: float) -> dict | None:
        hit = self._inspect.get(iid)
        if hit and now - hit[0] < INSPECT_SECONDS:
            return hit[1]
        try:
            data = await self.docker.get(f"/images/{iid}/json")
        except DockerError:
            return hit[1] if hit else None
        if not isinstance(data, dict):
            return None
        # Keep only what is used, so Env, Cmd and Entrypoint are dropped as soon as they arrive.
        cfg = data.get("Config") if isinstance(data.get("Config"), dict) else {}
        meta = data.get("Metadata") if isinstance(data.get("Metadata"), dict) else {}
        kept = {"Config": {"Labels": cfg.get("Labels")}, "Metadata": {"LastTagTime": meta.get("LastTagTime")}}
        self._inspect[iid] = (now, kept)
        return kept


# --- token ----------------------------------------------------------------------------------------------------------

class TokenError(Exception):
    pass


def read_token_file(path: str) -> str:
    """The token in `path`. The file must be a regular file with no access for group or others (mode 0600), and the
    token at least TOKEN_MIN printable characters with no spaces. The token is never part of an error message."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise TokenError(f"Can't open the token file {path}: {exc.strerror}.") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise TokenError(f"{path} is not a regular file.")
        if st.st_mode & 0o077:
            raise TokenError(f"{path} must be readable by its owner only (mode 0600): chmod 600 {path}")
        with os.fdopen(fd) as fh:
            fd = -1
            token = fh.read(4096).strip()
    finally:
        if fd >= 0:
            os.close(fd)
    if len(token) < TOKEN_MIN or not re.fullmatch(r"[\x21-\x7e]+", token):
        raise TokenError(f"The token in {path} must be at least {TOKEN_MIN} printable characters with no spaces. "
                         "Make one with: openssl rand -hex 32")
    return token


def token_matches(expected: str, header: str | None) -> bool:
    """Constant-time check of `Authorization: Bearer <token>`. Both sides are hashed first, so the comparison is
    over equal lengths whatever was sent."""
    scheme, _, given = (header or "").partition(" ")
    if scheme.lower() != "bearer":
        given = ""
    a = hashlib.sha256(expected.encode()).digest()
    b = hashlib.sha256(given.strip().encode("utf-8", "replace")).digest()
    return hmac.compare_digest(a, b) and scheme.lower() == "bearer"


# --- the web app ----------------------------------------------------------------------------------------------------

def create_app(token: str, docker: Docker):
    """The reader's app: `GET /v1/summary` and `GET /v1/health` and nothing else. No OpenAPI or docs pages, no
    request logging (so nothing that came in a header can reach a log)."""
    @contextlib.asynccontextmanager
    async def lifespan(_app):
        yield
        with contextlib.suppress(Exception):
            await docker.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    summarizer = Summarizer(docker)

    async def guard(request: Request) -> JSONResponse | None:
        if token_matches(token, request.headers.get("authorization")):
            return None
        await asyncio.sleep(0.25)     # a wrong guess costs a quarter second
        return JSONResponse({"error": "A valid bearer token is required."}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})

    @app.get("/v1/health")
    async def health(request: Request):
        if (denied := await guard(request)) is not None:
            return denied
        try:
            return await summarizer.health()
        except DockerError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)

    @app.get("/v1/summary")
    async def summary(request: Request):
        if (denied := await guard(request)) is not None:
            return denied
        try:
            return await summarizer.get()
        except DockerError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        except Exception:
            log.exception("Building the summary failed")
            return JSONResponse({"error": "The reader failed to build the summary."}, status_code=500)

    return app


def serve(socket_path: str, token_file: str, listen: str, port: int) -> int:
    import sys

    import uvicorn
    try:
        token = read_token_file(token_file)
    except TokenError as exc:
        print(exc, file=sys.stderr)
        return 1
    if not os.path.exists(socket_path):
        print(f"No Docker socket at {socket_path}. Mount /var/run/docker.sock into the container.", file=sys.stderr)
        return 1
    app = create_app(token, Docker.over_socket(socket_path))
    uvicorn.run(app, host=listen, port=port, server_header=False, access_log=False, log_level="warning")
    return 0
