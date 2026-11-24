"""Docker's images, volumes and build cache on an Unraid server, as the hub reads them from the Docker reader
(`daemonsight docker-reader`, see docs/DESIGN.md, "Docker reader"), plus what the hub works out from them: which
images and volumes nothing uses, where each probably came from, and the findings.

Unraid's GraphQL API lists containers and nothing else Docker holds, so the hub asks the reader, a second container
that holds the Docker socket and answers one read, `GET /v1/summary`, behind a bearer token.

This file has four parts: the client (`Reader`, GET only, two allowed paths), `parse_summary` (the hub does not
trust the reader's JSON more than any other server's), `analyze` (the origin hints and the unused sets, pure
functions of the stored data) and `evaluate` (the findings).

Where an image came from. Docker does not record who pulled an image or why, so the hint is an inference, shown as
text and never as a fact. In order, first match wins:

1. Superseded: the image has no tag (dangling) and an image from the same repository that a container uses is newer.
   The repository is the name in `RepoDigests` (an untagged image keeps its digest names), or the same
   `org.opencontainers.image.source` label.
2. Removed app: the hub once saw an Unraid-managed container (one with a template: `isOrphaned` false) running this
   repository, and none uses it now. The Unraid API lists a template only through a container that has it
   (`DockerContainer.templatePath`; api/generated-schema.graphql has no list of templates) and the reader cannot see
   `/boot`, so a template whose container is gone cannot be read. The hub remembers the apps it has seen instead
   (`apps_seen`, updated at each read) and says "removed" only for those.
3. Source label: `org.opencontainers.image.source`, shown as given.
4. Bare base image (debian, alpine, python...) that no container and no remembered app uses: probably pulled for a
   build or a test.
5. No hint.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .. import __version__
from ..findings import Finding, digest
from .client import MAX_RESPONSE, RemoteError, scrub

SNAPSHOT = "unraid_docker_storage"
READ_EVERY = 600                       # seconds: the hub reads the summary at most this often
CACHE_FINDING_MIN = 5 * 10 ** 9        # build cache over 5 GB is a finding (decimal GB, as Docker prints sizes)
APPS_KEPT = 300
ALLOWED = frozenset({"/v1/summary", "/v1/health"})
LABEL_PREFIXES = ("org.opencontainers.image.", "net.unraid.")
SOURCE_LABEL = "org.opencontainers.image.source"
PROJECT_LABEL = "com.docker.compose.project"
BASE_IMAGES = frozenset({
    "debian", "ubuntu", "fedora", "alpine", "busybox", "centos", "rockylinux", "almalinux", "archlinux", "opensuse/leap",
    "python", "node", "golang", "ruby", "php", "rust", "openjdk", "eclipse-temurin", "gcc", "dotnet/sdk", "dotnet/runtime",
    "buildpack-deps", "scratch"})
URL_HELP = "Give the reader's address, for example http://daemonsight-docker-reader:8467."


# --- the client -------------------------------------------------------------------------------------------------------

def normalize_url(raw: str) -> str:
    """The reader's origin, `http(s)://host[:port]`. http is allowed: the reader publishes no port and is reached by
    container name over a Docker network only the hub shares (docs/SECURITY.md)."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 300 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        raise ValueError(URL_HELP)
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ValueError("That address isn't valid.") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The address must start with http:// or https://.")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("Give only the address and port; leave out any path, user name, password or query.")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


class Reader:
    """The Docker reader's two routes, read-only on this side. `get` asks for a GET of `/v1/summary` or `/v1/health`
    and nothing else (compared as a whole string), with the token in an Authorization header. No redirects are
    followed (the token would go to the new address); a reply is capped at MAX_RESPONSE; the token is scrubbed from
    every message."""

    def __init__(self, base_url: str, token: str, http: httpx.AsyncClient):
        self.base = base_url.rstrip("/")
        self._token = token
        self._http = http
        self._headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
                         "User-Agent": f"DaemonSight/{__version__}"}

    async def aclose(self) -> None:
        await self._http.aclose()

    @staticmethod
    def check_allowed(path: str) -> None:
        if path not in ALLOWED:
            raise ValueError("only the reader's summary and health routes may be requested")

    async def get(self, path: str) -> dict:
        self.check_allowed(path)
        try:
            async with self._http.stream("GET", self.base + path, headers=self._headers) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE:
                        raise RemoteError("http", "The reader's reply was larger than 8 MiB; ignored.", path)
                status = r.status_code
        except RemoteError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc, path) from None
        if 300 <= status < 400:
            raise RemoteError("http", "The reader redirected the request. Redirects are not followed (the token "
                                      "would go to the new address).", path)
        if status in (401, 403):
            raise RemoteError("auth", f"The reader refused the token (HTTP {status}). Enter the token in the reader's "
                                      "token file again.", path)
        if status == 502:
            why = _reply_error(body)
            raise RemoteError("http", f"The reader could not read Docker: {why}" if why else "The reader could not read Docker.", path)
        if status != 200:
            raise RemoteError("http", f"The reader answered HTTP {status}.", path)
        try:
            data = json.loads(body)
        except ValueError:
            raise RemoteError("http", "The reader's reply was not JSON.", path) from None
        if not isinstance(data, dict):
            raise RemoteError("http", "The reader's reply was not what was expected.", path)
        return data

    def _transport_error(self, exc: httpx.HTTPError, path: str) -> RemoteError:
        clip = "".join(c for c in scrub(str(exc), self._token)[:200] if c.isprintable())
        if isinstance(exc, httpx.TimeoutException):
            return RemoteError("unreachable", "The reader did not answer in time.", path)
        if isinstance(exc, httpx.ConnectError):
            return RemoteError("unreachable", "Could not connect to the reader: " + clip, path)
        return RemoteError("unreachable", f"{type(exc).__name__}: {clip}", path)


def _reply_error(body) -> str:
    try:
        msg = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return ""
    return "".join(c for c in str(msg or "")[:200] if c.isprintable())


@dataclass
class Probe:
    docker: str
    api: str


async def probe(net, url: str, token: str) -> Probe:
    """Ask the reader for its health: proves the address, the token and that Docker answers. Raises RemoteError."""
    reader = Reader(url, token, net.reader())
    try:
        d = await reader.get("/v1/health")
    finally:
        await reader.aclose()
    if d.get("ok") is not True:
        raise RemoteError("http", "The reader says Docker is not answering.")
    return Probe(_text(d.get("version"), 40), _text(d.get("api"), 10))


async def fetch(net, url: str, token: str) -> dict:
    reader = Reader(url, token, net.reader())
    try:
        return await reader.get("/v1/summary")
    finally:
        await reader.aclose()


def error_text(exc: Exception, token: str | None) -> str:
    return scrub(exc.message if isinstance(exc, RemoteError) else f"{type(exc).__name__}: {exc}", token)[:300]


# --- what is stored -----------------------------------------------------------------------------------------------------

def _text(v, n: int = 200) -> str:
    return "".join(c for c in str(v if v is not None else "")[:n] if c.isprintable()).strip()


def _int(v) -> int | None:
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else None


def _strs(v, n: int = 40) -> list[str]:
    return [_text(x) for x in (v if isinstance(v, list) else [])[:n] if isinstance(x, str) and x]


def _labels(v, prefixes: tuple[str, ...]) -> dict[str, str]:
    return {_text(k, 100): _text(x) for k, x in list((v if isinstance(v, dict) else {}).items())[:40]
            if isinstance(k, str) and k.startswith(prefixes)}


PACKAGES_KEPT = 4000          # per image, the same cap the reader applies
IMAGES_WITH_PACKAGES_KEPT = 1000


def _os_info(v) -> dict | None:
    if not isinstance(v, dict):
        return None
    return {"id": _text(v.get("id"), 40).lower(), "like": [_text(x, 40).lower() for x in (v.get("like") if isinstance(v.get("like"), list) else [])[:6] if isinstance(x, str)],
            "version_id": _text(v.get("version_id"), 40), "codename": _text(v.get("codename"), 40).lower(),
            "pretty": _text(v.get("pretty"), 80)}


def _image_packages(raw) -> list[dict] | None:
    """The reader's `image_packages`, checked and cut again. None when the reader did not send the field (a reader
    from before package lists), which is not the same as an empty list."""
    if not isinstance(raw, list):
        return None
    out = []
    for e in raw[:IMAGES_WITH_PACKAGES_KEPT]:
        if not isinstance(e, dict) or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(e.get("image_id") or "")):
            continue
        pkgs = []
        for p in (e.get("packages") if isinstance(e.get("packages"), list) else [])[:PACKAGES_KEPT]:
            if isinstance(p, list) and len(p) >= 3 and all(isinstance(x, str) for x in p[:4]) and p[0] and p[2]:
                pkgs.append([_text(p[0], 100), _text(p[1], 100), _text(p[2], 100), _text(p[3], 100) if len(p) > 3 else ""])
        manager = e.get("manager") if e.get("manager") in ("dpkg", "apk") else None
        out.append({"image_id": e["image_id"], "container": _text(e.get("container"), 80) or None, "read_at": _int(e.get("read_at")),
                    "os": _os_info(e.get("os")), "manager": manager, "count": _int(e.get("count")) or 0, "packages": pkgs,
                    "error": _text(e.get("error"), 200) or None})
    return out


def parse_summary(raw: dict, prev: dict | None, unraid_docker: dict | None, now: float) -> dict:
    """What is stored for this server: the summary, re-checked and trimmed again, with the volumes cut down to the
    unused ones and a count of the rest. `prev` is the last stored value (the remembered apps), `unraid_docker`
    the container list the Unraid API gave."""
    images = []
    for i in (raw.get("images") if isinstance(raw.get("images"), list) else [])[:3000]:
        if not isinstance(i, dict) or not str(i.get("id") or "").startswith("sha256:"):
            continue
        images.append({"id": _text(i["id"], 80), "tags": _strs(i.get("tags")), "digests": _strs(i.get("digests")),
                       "created": _int(i.get("created")), "size": _int(i.get("size")), "last_tag": _int(i.get("last_tag")),
                       "labels": _labels(i.get("labels"), LABEL_PREFIXES), "in_use": i.get("in_use") is True})
    containers = [{"name": _text(c.get("name"), 80), "image": _text(c.get("image")), "image_id": _text(c.get("image_id"), 80),
                   "state": _text(c.get("state"), 20)}
                  for c in (raw.get("containers") if isinstance(raw.get("containers"), list) else [])[:2000] if isinstance(c, dict)]
    vols, unused, known_size = 0, [], 0
    in_use = unknown = 0
    for v in (raw.get("volumes") if isinstance(raw.get("volumes"), list) else [])[:10000]:
        if not isinstance(v, dict):
            continue
        vols += 1
        refs, size = _int(v.get("refs")), _int(v.get("size"))
        known_size += size or 0
        if refs is None:
            unknown += 1
        elif refs > 0:
            in_use += 1
        else:
            unused.append({"name": _text(v.get("name"), 100), "created": _text(v.get("created"), 40),
                           "driver": _text(v.get("driver"), 40), "anonymous": v.get("anonymous") is True,
                           "labels": _labels(v.get("labels"), ("com.docker.compose.",)), "size": size})
    bc = raw.get("build_cache") if isinstance(raw.get("build_cache"), dict) else None
    d = raw.get("docker") if isinstance(raw.get("docker"), dict) else {}
    return {"generated": now, "docker": {"version": _text(d.get("version"), 40), "api": _text(d.get("api"), 10)},
            "df_at": _int(raw.get("df_at")), "df_error": _text(raw.get("df_error"), 200) or None,
            "df_running": raw.get("df_running") is True,
            "image_packages": _image_packages(raw.get("image_packages")),
            "images": images, "containers": containers, "images_reclaimable": _int(raw.get("images_reclaimable")),
            "volumes": {"total": vols, "in_use": in_use, "unknown": unknown, "total_size": known_size, "unused": unused[:5000]},
            "build_cache": {"count": _int(bc.get("count")), "size": _int(bc.get("size"))} if bc else None,
            "apps_seen": remember_apps((prev or {}).get("apps_seen"), unraid_docker, now)}


def repo_of(ref: str) -> str:
    """The repository in an image reference: no tag, no digest, no docker.io/ or library/ prefix, lower case.
    `nginx:1.27`, `docker.io/library/nginx` and `nginx@sha256:...` are all `nginx`."""
    s = (ref or "").strip().lower().split("@", 1)[0]
    if s.startswith("sha256:"):
        return ""
    head, _, tail = s.rpartition("/")
    if ":" in tail:
        tail = tail.split(":", 1)[0]
    s = f"{head}/{tail}" if head else tail
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        s = s.removeprefix(prefix)
    return s.removeprefix("library/")


def remember_apps(old, unraid_docker: dict | None, now: float) -> dict[str, dict]:
    """{repository: {"name", "seen"}} for every repository an Unraid-managed container (one with a template) has used,
    refreshed from the container list now and capped at APPS_KEPT, oldest dropped first."""
    apps = {k: {"name": _text(v.get("name"), 80), "seen": _int(v.get("seen")) or 0}
            for k, v in (old if isinstance(old, dict) else {}).items() if isinstance(v, dict) and isinstance(k, str)}
    for c in (unraid_docker or {}).get("containers", []):
        repo = repo_of(c.get("image") or "")
        if repo and c.get("orphaned") is False and c.get("name"):
            apps[repo] = {"name": c["name"], "seen": int(now)}
    if len(apps) > APPS_KEPT:
        apps = dict(sorted(apps.items(), key=lambda kv: -kv[1]["seen"])[:APPS_KEPT])
    return apps


# --- what the hub works out ---------------------------------------------------------------------------------------------

def fmt_size(n) -> str:
    """Decimal units, the way `docker image ls` prints them (40.6GB)."""
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def short_id(image_id: str) -> str:
    return image_id.removeprefix("sha256:")[:12]


def image_repos(img: dict) -> set[str]:
    return {r for r in (repo_of(x) for x in img["tags"] + img["digests"]) if r}


def image_name(img: dict) -> str:
    if img["tags"]:
        return img["tags"][0]
    repos = sorted(image_repos(img))
    return f"{repos[0]} (untagged)" if repos else short_id(img["id"]) + " (untagged)"


def arrived(img: dict) -> tuple[int | None, str]:
    """When the image reached this server, as far as Docker says: when it was last tagged here (`LastTagTime`), else
    its build date, which can be long before it was pulled. Docker records neither who pulled it nor when it was
    pulled."""
    if img.get("last_tag"):
        return img["last_tag"], "tagged"
    return img.get("created"), "built"


def hint(img: dict, in_use: list[dict], current_repos: set[str], apps: dict[str, dict]) -> dict:
    """{"key", "text"} for one unused image: the first rule that matches (see the module doc)."""
    repos = image_repos(img)
    source = (img.get("labels") or {}).get(SOURCE_LABEL, "")
    if not img["tags"]:
        for other in in_use:
            same = bool(repos & image_repos(other)) or (source and (other.get("labels") or {}).get(SOURCE_LABEL) == source)
            newer = not (img.get("created") and other.get("created")) or other["created"] > img["created"]
            if same and newer:
                what = sorted(repos)[0] if repos else source
                return {"key": "superseded", "text": f"old version of {what} left by an update; safe to remove"}
    gone = [r for r in sorted(repos) if r in apps and r not in current_repos]
    if gone:
        return {"key": "removed_app", "text": f"app {apps[gone[0]]['name']} was removed from Unraid; its template may still be there"}
    if source:
        return {"key": "source", "text": f"from {source}"}
    if repos & BASE_IMAGES and not (repos & set(apps)):
        return {"key": "base", "text": "base image, probably pulled for a build or a test"}
    return {"key": "none", "text": "no hint"}


def analyze(data: dict | None, unraid_docker: dict | None = None) -> dict | None:
    """The unused images and volumes with their hints, from the stored summary. None without data."""
    if not data:
        return None
    images = data.get("images", [])
    in_use = [i for i in images if i["in_use"]]
    current = {r for i in in_use for r in image_repos(i)}
    current |= {r for c in data.get("containers", []) if (r := repo_of(c.get("image") or ""))}
    current |= {r for c in (unraid_docker or {}).get("containers", []) if (r := repo_of(c.get("image") or ""))}
    apps = data.get("apps_seen") or {}
    unused = []
    for img in images:
        if img["in_use"]:
            continue
        ts, how = arrived(img)
        h = hint(img, in_use, current, apps)
        unused.append({"id": img["id"], "short": short_id(img["id"]), "name": image_name(img), "tags": img["tags"],
                       "size": img.get("size"), "arrived": ts, "arrived_how": how, "hint": h,
                       "superseded": h["key"] == "superseded", "labels": img.get("labels") or {}})
    unused.sort(key=lambda i: -(i["size"] or 0))
    vols = data.get("volumes") or {}
    uv = []
    for v in vols.get("unused", []):
        project = (v.get("labels") or {}).get(PROJECT_LABEL, "")
        if v["anonymous"]:
            h = "left by a container that was removed"
        elif project:
            h = f"from compose project {project}"
        else:
            h = "named volume; no container uses it"
        uv.append({**v, "project": project, "hint": h})
    uv.sort(key=lambda v: (-(v["size"] or 0), v["name"]))
    sup = [i for i in unused if i["superseded"]]
    return {"unused_images": unused, "superseded": sup, "other_unused": [i for i in unused if not i["superseded"]],
            "images_total": len(images), "images_in_use": len(in_use), "images_reclaimable": data.get("images_reclaimable"),
            "unused_volumes": uv, "volumes_total": vols.get("total", 0), "volumes_in_use": vols.get("in_use", 0),
            "volumes_unknown": vols.get("unknown", 0), "build_cache": data.get("build_cache"),
            "docker": data.get("docker") or {}, "generated": data.get("generated"), "df_at": data.get("df_at"),
            "df_error": data.get("df_error"), "df_running": data.get("df_running", False)}


# --- findings -------------------------------------------------------------------------------------------------------------

LINK = "/docker"


def steps(*lines: str) -> str:
    return "\n".join(lines)


HOWTO_SUPERSEDED = steps(
    "These images have no tag and a newer image of the same app is in use: an update pulled the new one and left the old one behind",
    "On the server, run docker image prune. It removes dangling images, which are untagged ones; Docker's docs: \"Remove all dangling images\". An image a container uses is not removed",
    "Check the list on the Docker storage page first; each row says what its hint is based on",
    "DaemonSight only reads and never removes anything")
HOWTO_UNUSED_IMAGES = steps(
    "These images are tagged but no container uses them. Some are apps you removed, some were pulled for a test or a build, and some are kept on purpose for a later start",
    "Remove one with docker image rm followed by its id (or its tags, when it has more than one: Docker refuses to remove an image that several tags point to by its id alone)",
    "Do not use docker image prune -a unless you mean it: it removes every image no running container uses, including ones you meant to keep",
    "An app you start only now and then has no container while it is off, but its image can be needed again. Check the hint and the date first")
HOWTO_UNUSED_VOLUMES = steps(
    "WARNING: a volume can hold the only copy of data, such as a database. Removing one cannot be undone",
    "Check each volume before removing it. Anonymous volumes (a 64-character name) are usually left by a container that was removed, but one can still hold data you want",
    "To look inside one first, on the server: docker run --rm -v VOLUME:/v:ro alpine ls -la /v, with the volume's name in place of VOLUME",
    "Remove one volume at a time with docker volume rm followed by its name. Docker refuses to remove a volume a container uses",
    "Never run docker volume prune or docker system prune --volumes to clear them all: they remove every unused volume, including the ones you want")
HOWTO_BUILD_CACHE = steps(
    "Build cache is what Docker keeps so a build can reuse earlier steps. It is safe to remove: the next build is slower and fills it again",
    "docker builder prune removes the dangling build cache (Docker's docs: \"Remove build cache\"); add -a to remove all unused cache, or --filter until=168h to keep the last week",
    "If it keeps coming back, the builds are on this server: Unraid's Docker image builds and compose builds both fill it")


def _fix_images(items: list[dict]) -> str | None:
    lines, size = [], 0
    for i in items:
        target = " ".join(shlex.quote(t) for t in i["tags"]) if len(i["tags"]) > 1 else shlex.quote(i["short"])
        line = f"docker image rm {target}"
        if size + len(line) > 1700:
            lines.append(f"# {len(items) - len(lines)} more: see the Docker storage page")
            break
        lines.append(line)
        size += len(line) + 1
    return "\n".join(lines) if lines else None


def evaluate(data: dict | None, unraid_docker: dict | None = None) -> list[Finding]:
    a = analyze(data, unraid_docker)
    if not a:
        return []
    out: list[Finding] = []
    sup, other = a["superseded"], a["other_unused"]
    if sup:
        n, size = len(sup), sum(i["size"] or 0 for i in sup)
        out.append(Finding("docker.superseded_images", "all", "low",
                           f"{n} old image version{'s' if n != 1 else ''} left by updates, {fmt_size(size)}",
                           f"{n} untagged image{'s' if n != 1 else ''} on this server that no container uses, each with a newer image of the same app in use. "
                           "An update pulled the new version and left the old one behind. Sizes count layers an image shares with others, so removing them frees less than the total.",
                           f"{LINK}#images", "docker image prune", "superseded:" + digest(i["id"] for i in sup), HOWTO_SUPERSEDED))
    if other:
        n, size = len(other), sum(i["size"] or 0 for i in other)
        out.append(Finding("docker.unused_images", "all", "info",
                           f"{n} image{'s' if n != 1 else ''} no container uses, {fmt_size(size)}",
                           f"{n} image{'s' if n != 1 else ''} on this server that no container, running or stopped, uses. "
                           "Docker does not record who pulled an image, so each row on the Docker storage page gives a hint from what DaemonSight can see. "
                           "Sizes count layers an image shares with others, so removing them all frees less than the total.",
                           f"{LINK}#images", _fix_images(other), "unused:" + digest(i["id"] for i in other), HOWTO_UNUSED_IMAGES))
    vols = a["unused_volumes"]
    if vols:
        n, size = len(vols), sum(v["size"] or 0 for v in vols)
        anon = sum(1 for v in vols if v["anonymous"])
        out.append(Finding("docker.unused_volumes", "all", "info",
                           f"{n} volume{'s' if n != 1 else ''} no container uses, {fmt_size(size)}",
                           f"{n} volume{'s' if n != 1 else ''} that no container uses ({anon} anonymous). A volume can hold the only copy of a database, so check before removing one. "
                           "The Docker storage page gives the command for each volume.",
                           f"{LINK}#volumes", None, "unused:" + digest(v["name"] for v in vols), HOWTO_UNUSED_VOLUMES))
    bc = a["build_cache"]
    if bc and (bc.get("size") or 0) > CACHE_FINDING_MIN:
        out.append(Finding("docker.build_cache", "all", "info", f"Docker build cache is {fmt_size(bc['size'])}",
                           f"Docker is keeping {fmt_size(bc['size'])} of build cache ({bc.get('count') or '?'} records). It is only a speed-up for later builds and can be cleared.",
                           f"{LINK}#cache", "docker builder prune", "over-5GB", HOWTO_BUILD_CACHE))
    return out

