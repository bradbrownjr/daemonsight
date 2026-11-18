"""Whether the host's Debian or Ubuntu release still gets security updates.

Release dates come from the distro-info-data CSVs (ISC licence). A host with
the `distro-info-data` package has a newer copy in /usr/share/distro-info/;
that one wins when it has the release. The bundled copy in `data/distro-info/`
is the fallback. See data/distro-info/README.md.
"""

from __future__ import annotations

import csv
import io
import shlex
from dataclasses import dataclass
from datetime import date
from importlib import resources

SYSTEM_DIR = "/usr/share/distro-info"
SUPPORTED_DISTROS = ("debian", "ubuntu")
NAMES = {"debian": "Debian", "ubuntu": "Ubuntu"}
LTS_URL = "https://wiki.debian.org/LTS"


def parse_os_release(text: str) -> dict[str, str]:
    """KEY=value lines of /etc/os-release; values may be quoted."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        try:
            parts = shlex.split(raw)
        except ValueError:
            parts = [raw.strip("\"'")]
        out[key.strip()] = parts[0] if parts else ""
    return out


def os_ident(fields: dict[str, str]) -> dict:
    """The os-release fields the snapshot keeps."""
    return {"os_id": (fields.get("ID") or "").lower() or None,
            "os_like": (fields.get("ID_LIKE") or "").lower().split(),
            "version_id": fields.get("VERSION_ID") or None,
            "version_codename": (fields.get("VERSION_CODENAME") or "").lower() or None}


def _parse_date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def parse_csv(text: str) -> list[dict]:
    """Rows with dates parsed. Short rows (unreleased versions) leave the
    later columns as None."""
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        row = {k: (v or None) for k, v in r.items() if k}
        for k in row:
            if k not in ("version", "codename", "series"):
                row[k] = _parse_date(row[k])
        rows.append(row)
    return rows


def bundled_text(distro: str) -> str:
    return (resources.files("daemonsight.data") / "distro-info" / f"{distro}.csv").read_text(encoding="utf-8")


def _system_text(distro: str) -> str | None:
    try:
        with open(f"{SYSTEM_DIR}/{distro}.csv", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _bare_version(row: dict) -> str:
    return (row.get("version") or "").removesuffix(" LTS").strip()


def find_row(rows: list[dict], version_id: str | None, codename: str | None) -> dict | None:
    """The release named by its codename (series), else by version."""
    if codename:
        for r in rows:
            if (r.get("series") or "").lower() == codename:
                return r
    if version_id:
        for r in rows:
            if _bare_version(r) == version_id:
                return r
    return None


def load_rows(distro: str, version_id: str | None = None, codename: str | None = None) -> list[dict]:
    """The system copy when it has the release, otherwise the bundled copy."""
    text = _system_text(distro)
    if text:
        try:
            rows = parse_csv(text)
        except (csv.Error, ValueError):
            rows = []
        if rows and find_row(rows, version_id, codename):
            return rows
    return parse_csv(bundled_text(distro))


def distro_of(ident: dict) -> tuple[str, str | None, str | None] | None:
    """(distro, version_id, codename) to look up, or None when out of scope.
    Raspberry Pi OS (raspbian) is Debian with its own version numbering that
    matches Debian's; it is looked up by codename. Other derivatives are not
    judged: their support follows their own vendor."""
    os_id = ident.get("os_id")
    codename = ident.get("version_codename")
    if os_id in SUPPORTED_DISTROS:
        return os_id, ident.get("version_id"), codename
    if os_id == "raspbian" and codename:
        return "debian", None, codename
    return None


@dataclass(frozen=True)
class Support:
    status: str  # supported, extended, ended, eol, unknown
    label: str
    distro: str = ""
    version: str = ""
    codename: str = ""
    released: date | None = None
    eol: date | None = None
    until: date | None = None  # when the extended coverage (LTS or ESM) ends
    current_version: str = ""
    current_codename: str = ""

    @property
    def name(self) -> str:
        """e.g. "Debian 12"."""
        return f"{NAMES.get(self.distro, self.distro)} {self.version}".strip()

    @property
    def current(self) -> str:
        """e.g. "Debian 13 (trixie)"."""
        return f"{NAMES.get(self.distro, self.distro)} {self.current_version} ({self.current_codename})"

    @property
    def plain(self) -> bool:
        return self.status in ("supported", "unknown")


UNKNOWN = Support("unknown", "")


def _newest_release(rows: list[dict], distro: str, today: date) -> dict | None:
    """The newest release out today. For Ubuntu that is the newest LTS, since
    that is the one to upgrade to."""
    out = [r for r in rows if r.get("release") and r["release"] <= today
           and (distro != "ubuntu" or (r.get("version") or "").endswith(" LTS"))]
    return max(out, key=lambda r: r["release"], default=None)


def evaluate(ident: dict, today: date | None = None) -> Support:
    today = today or date.today()
    target = distro_of(ident or {})
    if not target:
        return UNKNOWN
    distro, version_id, codename = target
    rows = load_rows(distro, version_id, codename)
    row = find_row(rows, version_id, codename)
    if not row or not row.get("release") or row["release"] > today or not row.get("eol"):
        return UNKNOWN  # not found, not released yet, or a rolling branch such as sid
    cur = _newest_release(rows, distro, today)
    base = dict(distro=distro, version=_bare_version(row), codename=row.get("series") or "",
                released=row["release"], eol=row["eol"],
                current_version=_bare_version(cur) if cur else "", current_codename=(cur or {}).get("series") or "")
    eol = row["eol"]
    if today < eol:
        return Support("supported", "Supported", **base)
    if distro == "debian":
        lts, elts = row.get("eol-lts"), row.get("eol-elts")
        if lts and today < lts:
            return Support("extended", f"LTS until {lts.isoformat()}", until=lts, **base)
        if lts and elts and today < elts:
            return Support("ended", f"No free security updates (ELTS only, paid) since {lts.isoformat()}",
                           until=lts, **base)
        return Support("eol", "End of life", until=lts, **base)
    esm = row.get("eol-esm")
    if esm and today < esm:
        return Support("extended", f"ESM only (Ubuntu Pro) until {esm.isoformat()}", until=esm, **base)
    return Support("eol", "End of life", until=esm, **base)


STATUS_BADGE = {"supported": "bg-green-lt", "extended": "bg-yellow-lt", "ended": "bg-red-lt", "eol": "bg-red-lt"}
