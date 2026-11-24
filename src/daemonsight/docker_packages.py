"""Package lists out of a container, for the Docker reader (docker_reader.py): which four files may be asked for, how
the tar stream Docker answers with is read, and how the files are parsed.

Docker's "Get an archive of a filesystem resource in a container" (`GET /containers/{id}/archive?path=...`, swagger
operationId ContainerArchive, https://docs.docker.com/reference/api/engine/version/v1.54.yaml) answers with a tar
stream of the one path. Only these paths are ever asked for:

* `/usr/lib/os-release`, then `/etc/os-release` when the first is missing. `/etc/os-release` is normally a symlink to
  the first, and an archive of a symlink holds the link itself, which is not followed: that is why the first is tried
  first. os-release's format is https://www.freedesktop.org/software/systemd/man/latest/os-release.html.
* `/var/lib/dpkg/status` (Debian and Ubuntu): "Package", "Status", "Version", "Source" and "Architecture" fields in
  Debian control-file stanzas (deb-control(5), dpkg(1) "Source: name (version)" in deb-src-control(5)).
* `/lib/apk/db/installed` (Alpine): one record per package, a letter and a colon at the start of each line: `P:` name,
  `V:` version, `o:` origin (https://wiki.alpinelinux.org/wiki/Apk_spec).

The tar reply is held in memory, capped, and read with `tarfile` in streaming mode (`r|`, no seeking, no
decompression). It must hold exactly one member and that member must be a regular file within the cap. Nothing is ever
written to disk, and no member name is used as a path.
"""

from __future__ import annotations

import io
import re
import tarfile
from urllib.parse import quote

from . import distro

OS_RELEASE_PATHS = ("/usr/lib/os-release", "/etc/os-release")
DPKG_STATUS = "/var/lib/dpkg/status"
APK_INSTALLED = "/lib/apk/db/installed"
ARCHIVE_PATHS = (*OS_RELEASE_PATHS, DPKG_STATUS, APK_INSTALLED)

CAPS = {"/usr/lib/os-release": 64 << 10, "/etc/os-release": 64 << 10, DPKG_STATUS: 16 << 20, APK_INSTALLED: 4 << 20}
TAR_OVERHEAD = 32 << 10            # header blocks, padding and the end-of-archive blocks around the file's bytes
MAX_PACKAGES = 4000                # per image; more are counted, not listed
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")


class ArchiveError(Exception):
    """The archive is not one regular file within the cap. The message is short and holds nothing from the archive."""


class ArchiveSymlink(ArchiveError):
    """The one member is a link; it is not followed."""


def archive_target(container_id: str, path: str) -> str:
    """The request target (without the version prefix) for one of the four paths. Raises ValueError for anything
    else, so a caller can't build another."""
    if not CONTAINER_ID.match(container_id or "") or path not in ARCHIVE_PATHS:
        raise ValueError("only the four package-list paths of a container, by its 64-digit id, may be requested")
    return f"/containers/{container_id}/archive?path={quote(path, safe='')}"


ARCHIVE_TARGET = re.compile(
    r"^/containers/[0-9a-f]{64}/archive\?path=(?:" + "|".join(re.escape(quote(p, safe="")) for p in ARCHIVE_PATHS) + r")$")


def read_single_file(data: bytes, cap: int) -> bytes:
    """The bytes of the one regular file in a tar stream held in `data`. Refuses: a stream that is not tar, a link
    (ArchiveSymlink), any other kind of member, a size over `cap`, a second member, and a truncated file."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as tf:
            member = tf.next()
            if member is None:
                raise ArchiveError("The archive was empty.")
            if member.issym() or member.islnk():
                raise ArchiveSymlink("The path is a link, which is not followed.")
            if not member.isreg():
                raise ArchiveError("The archive's member is not a regular file.")
            if member.size > cap:
                raise ArchiveError("The file is larger than the limit; not read.")
            fh = tf.extractfile(member)
            content = fh.read(cap + 1) if fh is not None else b""
            if len(content) != member.size:
                raise ArchiveError("The archive ended inside the file.")
            if tf.next() is not None:
                raise ArchiveError("The archive held more than one member.")
            return content
    except ArchiveError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError):
        raise ArchiveError("The reply was not a readable tar archive.") from None


def clean(v, n: int = 120) -> str:
    return "".join(c for c in str(v if v is not None else "")[:n] if c.isprintable()).strip()


def parse_os_release(text: str) -> dict:
    """{"id", "like", "version_id", "codename", "pretty"} from os-release text; each is cut short and made printable."""
    f = distro.parse_os_release(text[:65536])
    return {"id": clean(f.get("ID"), 40).lower(), "like": [clean(x, 40).lower() for x in (f.get("ID_LIKE") or "").split()[:6]],
            "version_id": clean(f.get("VERSION_ID"), 40), "codename": clean(f.get("VERSION_CODENAME"), 40).lower(),
            "pretty": clean(f.get("PRETTY_NAME"), 80)}


_SOURCE = re.compile(r"^(\S+)(?:\s+\((\S+)\))?\s*$")


def parse_dpkg_status(text: str) -> tuple[list[list[str]], int]:
    """(packages, count) from dpkg's status file. Only a stanza whose Status is exactly "install ok installed" counts.
    Each package is [name, source, version, source_version] with `source` empty when it is the package's own name and
    `source_version` empty when it is the package's own version. "Source: name (version)" gives both a source name and
    the version of that source, which differs from the binary's after a rebuild (1.2-3+b1 from source 1.2-3); the
    Debian tracker is keyed by the source name and its version."""
    out: list[list[str]] = []
    seen: set[tuple[str, str]] = set()
    count = 0
    for stanza in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        for line in stanza.split("\n"):
            if not line or line[0] in " \t#":           # a continuation line (the description) or a comment
                continue
            key, sep, value = line.partition(":")
            if sep and key in ("Package", "Status", "Version", "Source", "Architecture"):
                fields[key] = value.strip()
        if not fields.get("Package") or not fields.get("Version"):
            continue
        if " ".join(fields.get("Status", "").split()) != "install ok installed":     # not "deinstall ok installed"
            continue
        name, version = clean(fields["Package"], 100), clean(fields["Version"], 100)
        source, src_version = name, version
        m = _SOURCE.match(fields.get("Source", ""))
        if m:
            source = clean(m.group(1), 100) or name
            src_version = clean(m.group(2), 100) or version
        key = (name, version)
        if not name or not version or key in seen:       # the same package for a second architecture is one entry
            continue
        seen.add(key)
        count += 1
        if len(out) < MAX_PACKAGES:
            out.append([name, "" if source == name else source, version, "" if src_version == version else src_version])
    return out, count


def parse_apk_installed(text: str) -> tuple[list[list[str]], int]:
    """(packages, count) from apk's installed database: [name, origin, version, ""] with `origin` empty when it is the
    package's own name. Records are separated by a blank line."""
    out: list[list[str]] = []
    count = 0
    for record in re.split(r"\n\s*\n", text):
        f: dict[str, str] = {}
        for line in record.split("\n"):
            if len(line) > 2 and line[1] == ":" and line[0] in "PVo":
                f.setdefault(line[0], line[2:].strip())
        name, version = clean(f.get("P"), 100), clean(f.get("V"), 100)
        if not name or not version:
            continue
        origin = clean(f.get("o"), 100)
        count += 1
        if len(out) < MAX_PACKAGES:
            out.append([name, "" if not origin or origin == name else origin, version, ""])
    return out, count


def os_kind(os_info: dict | None) -> str:
    """"dpkg", "apk", "other" (an OS with another package manager) or "unknown" (no os-release)."""
    if not os_info:
        return "unknown"
    ids = {os_info.get("id", "")} | set(os_info.get("like") or [])
    if "alpine" in ids:
        return "apk"
    if ids & {"debian", "ubuntu", "raspbian"}:
        return "dpkg"
    return "other" if os_info.get("id") else "unknown"
