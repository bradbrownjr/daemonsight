"""OPNsense version order, for choosing which changelogs a pending update brings in.

An OPNsense release is a FreeBSD package, so its versions follow pkg's ordering. Read for this: `libpkg/pkg_version.c`
in https://github.com/freebsd/pkg (master, read 2026-11-24). Its header says the syntax is
`${PORTVERSION}[_${PORTREVISION}][,${PORTEPOCH}]`, and `pkg_version_cmp` compares the epoch, then the dotted version part,
then the revision, in that order. Missing dotted components count as 0 (`10 = 10.0 = 10.0.0`), and the revision is a single
number compared last.

What OPNsense sends, checked against the changelog repository (github.com/opnsense/changelog, `community/`, 357 files read
on 2026-11-24) and a real firmware status:

* `26.7`, `26.7.1`, `26.7.10`: a release. `YY.M` is the series (a major release, named like the file `26.7`), then a
  patch number. A few old releases have four parts (`15.1.6.1`). 26.7.10 is above 26.7.9: the parts are numbers.
* `26.1.11_3`: a hotfix of 26.1.11. The `_3` is pkg's revision. There is no changelog file for it; the notes sit inside the
  file of the release, under "A hotfix release was issued as 26.1.11_3:" (see opnsense.py). So 26.1.11 < 26.1.11_3 <
  26.1.11_10 < 26.1.12, with `_10` above `_3` because the revision is a number.
* `26.7.r1`, `26.1.b`: release candidates and betas. They are files in the repository and the firewall's own changelog
  list skips them unless the firewall runs a development version (`FirmwareController.php`, `infoAction`), so they are
  not versions here (`parse` returns None).

The epoch (`,N`) is not used by OPNsense's core package and is refused as an unknown form rather than guessed at.

Only the ordering of valid versions is defined. A caller that gets None from `parse` has a version it must not compare.
"""

from __future__ import annotations

import re

VERSION_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})((?:\.\d{1,5}){0,2})(?:_(\d{1,5}))?$")
COMMUNITY_MONTHS = (1, 7)          # the community series are YY.1 and YY.7 (every directory under community/)
MAX_SERIES_STEPS = 12              # a sanity bound: six years of two series each


def parse(v: str | None) -> tuple[tuple[int, ...], int] | None:
    """((major, minor, patch, ...), revision) for a release or hotfix version, else None. Trailing zeros are dropped so
    that 26.7 and 26.7.0 are the same version, as pkg compares them."""
    m = VERSION_RE.match((v or "").strip())
    if not m:
        return None
    parts = [int(m.group(1)), int(m.group(2))]
    if m.group(3):
        parts += [int(x) for x in m.group(3).split(".")[1:]]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts), int(m.group(4) or 0)


def valid(v: str | None) -> bool:
    return parse(v) is not None


def key(v: str) -> tuple[tuple[int, ...], int]:
    p = parse(v)
    if p is None:
        raise ValueError(f"not an OPNsense version: {v!r}")
    return p


def compare(a: str, b: str) -> int:
    """-1, 0 or 1. Raises ValueError for a version `parse` refuses."""
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


def series_of(v: str | None) -> str | None:
    """"26.1" for 26.1.11_3, from the first two parts."""
    m = VERSION_RE.match((v or "").strip())
    return f"{int(m.group(1))}.{int(m.group(2))}" if m else None


def is_community_series(series: str | None) -> bool:
    m = re.match(r"^(\d{1,3})\.(\d{1,3})$", series or "")
    return bool(m) and int(m.group(2)) in COMMUNITY_MONTHS


def series_between(installed: str | None, offered: str | None) -> list[str] | None:
    """The community series from the installed version's to the offered one's, both included, oldest first: 26.1 and
    26.7 for an upgrade from 26.1.11 to 26.7. [installed's series] when the offered one is not newer. None when either
    version is not valid, or is a Business Edition series (YY.4, YY.10; those changelogs are in the repository's
    `business/` directory, not read), or the two are implausibly far apart."""
    a, b = series_of(installed), series_of(offered)
    if not (a and b and is_community_series(a) and is_community_series(b)):
        return None
    ya, ma = (int(x) for x in a.split("."))
    yb, mb = (int(x) for x in b.split("."))
    if (yb, mb) <= (ya, ma):
        return [a]
    out = []
    y, m = ya, ma
    while (y, m) <= (yb, mb):
        out.append(f"{y}.{m}")
        if len(out) > MAX_SERIES_STEPS:
            return None
        y, m = (y, 7) if m == 1 else (y + 1, 1)
    return out


def next_series(series: str | None, count: int = 2) -> list[str]:
    """The `count` community series after this one: ["27.1", "27.7"] after 26.7. [] when `series` is not a community series."""
    if not is_community_series(series):
        return []
    y, m = (int(x) for x in series.split("."))
    out = []
    for _ in range(count):
        y, m = (y, 7) if m == 1 else (y + 1, 1)
        out.append(f"{y}.{m}")
    return out
