"""The OPNsense changelog repository as codeload.github.com serves it, for tests: a gzipped tarball whose entries are
`changelog-master/<path>`. The files are real ones copied from the repository (tests/fixtures/opnsense/changelog/, see the
README there). `extra` adds or replaces entries as {name: bytes}; a value of None adds a symbolic link of that name."""

import gzip
import io
import tarfile
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "opnsense" / "changelog"
ROOT = "changelog-master"
PATH = "/opnsense/changelog/tar.gz/refs/heads/master"


def tarball_bytes(extra: dict | None = None, root: str = ROOT, skip: tuple[str, ...] = ()) -> bytes:
    files = {str(f.relative_to(FIX)): f.read_bytes() for f in sorted(FIX.rglob("*")) if f.is_file()}
    files = {k: v for k, v in files.items() if k not in skip}
    files.update(extra or {})
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        top = tarfile.TarInfo(root)
        top.type = tarfile.DIRTYPE
        tar.addfile(top)
        for name, data in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            if data is None:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
                continue
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def write_tarball(path: Path, **kw) -> Path:
    path.write_bytes(tarball_bytes(**kw))
    return path


def not_a_tarball() -> bytes:
    return gzip.compress(b"this is not a tar file" * 100)
