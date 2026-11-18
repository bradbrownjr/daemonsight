"""Debian version comparison, written from Debian Policy section 5.6.12
(https://www.debian.org/doc/debian-policy/ch-controlfields.html#version).
python-debian does the same job but is GPL, so it is not used here.

A version is `[epoch:]upstream_version[-debian_revision]`:

* The epoch is an unsigned integer; no epoch means 0.
* The revision is what follows the LAST hyphen; no hyphen means no revision,
  which compares as "0".
* Upstream version and revision are compared the same way: alternately a
  run of non-digits, compared character by character, then a run of digits,
  compared as numbers (a missing digit run is 0).
* In the character comparison `~` sorts before everything, even the end of
  the string; then the end of the string; then letters; then every other
  character, in ASCII order.

dpkg's own function for this is verrevcmp() in lib/dpkg/version.c; the tests
compare this module with `dpkg --compare-versions` on real versions.
"""

from __future__ import annotations

import re
from functools import lru_cache

_PARSE = re.compile(r"^(?:(\d+):)?(.*?)(?:-([^-]*))?$")


def _order(ch: str) -> int:
    """Sort weight of one character, as dpkg's order()."""
    if ch == "~":
        return -1
    if ch.isdigit() and ch.isascii():
        return 0
    if ch.isalpha() and ch.isascii():
        return ord(ch)
    return ord(ch) + 256


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _cmp_part(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        # Non-digit run. A digit or the end counts as weight 0, which is
        # why "1.0" and "1.0~rc1" differ but "1.0" and "1.0a" sort as expected.
        while (i < la and not _is_digit(a[i])) or (j < lb and not _is_digit(b[j])):
            wa = _order(a[i]) if i < la and not _is_digit(a[i]) else 0
            wb = _order(b[j]) if j < lb and not _is_digit(b[j]) else 0
            if wa != wb:
                return -1 if wa < wb else 1
            if i < la and not _is_digit(a[i]):
                i += 1
            if j < lb and not _is_digit(b[j]):
                j += 1
        # Digit run.
        si = i
        while i < la and _is_digit(a[i]):
            i += 1
        sj = j
        while j < lb and _is_digit(b[j]):
            j += 1
        na = int(a[si:i]) if i > si else 0
        nb = int(b[sj:j]) if j > sj else 0
        if na != nb:
            return -1 if na < nb else 1
    return 0


@lru_cache(maxsize=65536)
def parse(version: str) -> tuple[int, str, str]:
    """(epoch, upstream, revision). Raises ValueError for text that is not a
    version (empty, or an epoch that is not a number)."""
    v = version.strip()
    if not v:
        raise ValueError("empty version")
    m = _PARSE.match(v)
    if not m:
        raise ValueError(f"not a Debian version: {version!r}")
    epoch, upstream, revision = m.groups()
    if ":" in v and epoch is None:
        raise ValueError(f"bad epoch in {version!r}")
    # dpkg refuses "1.0-" ("revision number is empty") and "-1" (empty upstream).
    if not upstream or revision == "":
        raise ValueError(f"not a Debian version: {version!r}")
    return int(epoch or 0), upstream, revision or "0"


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as `a` is older than, equal to or newer than `b`."""
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)


def lt(a: str, b: str) -> bool:
    return compare(a, b) < 0
