"""The OS and package list of each container image a running container uses, for the hub's CVE matching (the same matching the
Docker reader gives an Unraid server's images). See docs/DESIGN.md, "Collector hosts: image CVEs".

This is the Docker reader's reading (docker_reader.py, "Package lists") run inside the collector instead of in a second process:
the collector already runs as root with the Docker socket (collector/sources/docker.py), so it reuses `docker_reader.Docker` (GET
only, a fixed list of targets, a capped reply) and `docker_reader.read_image` (os-release, then dpkg's status file or apk's
installed database, through `GET /containers/{id}/archive?path=...`, parsed by `docker_packages`). No second extractor.

* GET only. Nothing is created, started or executed: an image is read through a container that is already running. An image
  that only stopped containers use is reported as "not read: stopped", the Docker reader's answer too. (Docker can archive a
  stopped container's files as well; that was not tried here, so it is not used.)
* The archive endpoint is only ever asked for the four paths in `docker_packages.ARCHIVE_PATHS`; `Docker.check_allowed` refuses
  any other target before anything is sent.
* Cost: an image is read once per image id (an image id is a content hash). It is read again only when the id changes (an update),
  or, after an error that may pass (the container just stopped, Docker was busy), 30 minutes later. At most `max_reads` images are
  read per look, so the first pass over a host with many images is spread over several looks. A look with nothing new costs two
  list requests. The reads are kept in the collector's database (the snapshot of this source), so a restart reads nothing again.
* What is kept per image is what the Unraid reader keeps: the OS, the package manager, and per package its name, source package,
  version and source version. Nothing else from inside the container, and never an environment variable.

`restore` gives the last snapshot back after a restart; `collect` returns the snapshot. Each image entry carries `hash`, a
fingerprint of its OS and packages, which collector/upload.py uses to send a package list only when the hub does not have it.
"""

from __future__ import annotations

import logging
import os
import time

from ... import docker_packages as pk
from ... import docker_reader as dr
from . import Source, SourceUnavailable

log = logging.getLogger("daemonsight.docker_images")

MAX_READS = dr.ARCHIVE_IMAGES_PER_CYCLE        # images read per look
RETRY_SECONDS = dr.PACKAGES_RETRY_SECONDS      # an image whose read failed is tried again after this long
MAX_PACKAGES_TOTAL = dr.MAX_PACKAGES_SENT      # across the whole snapshot; past it an image's list is left out (its count stays)
OFF_REASON = "reading image packages is turned off ([collector] docker_read_packages = false)"
PERMANENT_MARK = "does not use dpkg or apk"


def is_permanent(entry: dict) -> bool:
    """True when reading the image again would give the same answer: it was read, or its OS has no dpkg or apk."""
    return bool(entry.get("manager")) or PERMANENT_MARK in (entry.get("error") or "")


class DockerImagesSource(Source):
    name = "docker_images"

    def __init__(self, interval: int = 300, socket_path: str = "/var/run/docker.sock", enabled: bool = True,
                 max_reads: int = MAX_READS, clock=time.time, docker: dr.Docker | None = None):
        self.interval = interval
        self.socket_path = socket_path
        self.enabled = enabled
        self.max_reads = max_reads
        self.clock = clock
        self._docker = docker
        self._info: dict | None = None
        self._cache: dict[str, tuple[float | None, dict]] = {}     # image id -> (retry at, entry); None: never again

    def restore(self, data: dict | None) -> None:
        """Take the reads from the last stored snapshot, so a restart does not read every image again. Only an answer that
        would not change (an image that was read, or an OS with no dpkg or apk) comes back; an error is tried again."""
        for e in (data or {}).get("image_packages") or []:
            if isinstance(e, dict) and isinstance(e.get("image_id"), str) and pk.CONTAINER_ID.match(e["image_id"].removeprefix("sha256:")) \
                    and is_permanent(e):
                self._cache[e["image_id"]] = (None, {k: v for k, v in e.items() if k != "hash"})

    async def _client(self) -> dr.Docker:
        if self._docker is None:
            self._docker = dr.Docker.over_socket(self.socket_path)
        if self._info is None or self._docker.api is None:
            self._info = await self._docker.negotiate()
        return self._docker

    async def collect(self) -> dict:
        if not self.enabled:
            raise SourceUnavailable(OFF_REASON)
        if self._docker is None and not os.path.exists(self.socket_path):
            raise SourceUnavailable(f"no Docker socket at {self.socket_path}")
        docker = await self._client()
        try:
            containers = dr.trim_containers(await docker.get("/containers/json?all=1"))
            listed = await docker.get("/images/json?all=0&digests=1")
        except dr.DockerError:
            await self._reset()
            raise
        targets: dict[str, tuple[str, str]] = {}       # image id -> (container name, container id) to read: the first running one
        used: set[str] = set()
        for c in containers:                           # sorted by name
            if not c["image_id"]:
                continue
            used.add(c["image_id"])
            if c["state"] == "running" and c["id"] and c["image_id"] not in targets:
                targets[c["image_id"]] = (c["name"], c["id"])
        for iid in set(self._cache) - used:
            del self._cache[iid]                       # an image no container uses any more is forgotten
        now = self.clock()
        pending = sorted((i for i in targets if i not in self._cache or (self._cache[i][0] is not None and now >= self._cache[i][0])),
                         key=lambda i: targets[i][0])
        for iid in pending[: self.max_reads]:
            name, cid = targets[iid]
            try:
                entry, permanent = await dr.read_image(docker, iid, name, cid, self.clock())
            except Exception:
                log.exception("Reading the packages of image %s failed", iid[:19])
                entry, permanent = dr.blank_entry(iid, name, "packages not read: the collector failed to read it"), False
            self._cache[iid] = (None if permanent else self.clock() + RETRY_SECONDS, entry)
        stopped = used - set(targets)
        images = []
        for s in (listed if isinstance(listed, list) else [])[: dr.MAX_IMAGES]:
            if isinstance(s, dict) and s.get("Id") in used:
                im = dr.trim_image(s, True, None)
                images.append({"id": im["id"], "tags": im["tags"], "digests": im["digests"]})
        return {"v": 1, "engine": dict(self._info or {}),
                "containers": [{"name": c["name"], "image": c["image"], "image_id": c["image_id"], "state": c["state"]} for c in containers],
                "images": images, "image_packages": self._entries(targets, stopped)}

    def _entries(self, targets: dict, stopped: set[str]) -> list[dict]:
        out, total = [], 0
        for iid in sorted(targets.keys() | stopped):
            hit = self._cache.get(iid)
            entry = dict(hit[1]) if hit else dr.blank_entry(iid, None, "not read: stopped" if iid in stopped else "not read yet")
            if entry.get("manager"):
                if total + len(entry["packages"]) > MAX_PACKAGES_TOTAL:
                    entry["packages"], entry["error"] = [], "package list left out: the host's lists would be too large"
                    entry["manager"] = None
                else:
                    total += len(entry["packages"])
                    entry["hash"] = pk.fingerprint(entry)
            out.append(entry)
        return out

    async def _reset(self) -> None:
        """Forget the connection after a failed read, so the next look negotiates again."""
        if self._docker is not None:
            await self._docker.aclose()
        self._docker, self._info = None, None

    async def close(self) -> None:
        if self._docker is not None:
            await self._docker.aclose()
            self._docker = None
