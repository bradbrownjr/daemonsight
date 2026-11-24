"""Alpine (apk) version comparison, written from apk-tools' own rules.

Read for this: `src/version.c` at apk-tools v3.0.9 (commit f419028ee18aabcfb405400f899572fb0a949331, 2026-11-02; Alpine
3.23 ships apk-tools 3.0.9, from main/apk-tools/APKBUILD on the 3.23-stable branch), with `apk_blob_pull_uint` and
`apk_blob_sort` from `src/blob.c` and the character classes from `src/ctype.c`, all in
https://gitlab.alpinelinux.org/alpine/apk-tools. `src/version.c` is identical at v3.0.9, v3.0.10 and master
(c7b05e07, 2026-11-23). The ordering is checked against that tree's own `test/unit/version.data`
(tests/fixtures/cve/apk-version.data).

A version is `digit{.digit}...{letter}{_suffix{digits}}...{~hash}{-r<digits>}`. It is read as a list of tokens:

* the first number, then each `.number`; a number that starts with `0` (`.01`, `.001`) is compared as a string, not as a
  number, when either side has the leading zero (`1.02` < `1.1` is a string comparison, `1.2` < `1.10` is numeric);
* one lowercase letter after a number (`2.5.1a`), and no digit or `.` straight after it;
* suffixes, each `_name` and optional digits: `_alpha` < `_beta` < `_pre` < `_rc` < (no suffix) < `_cvs` < `_svn` < `_git` <
  `_hg` < `_p`. The first four mark a pre-release, so `1.0_rc1` < `1.0` < `1.0_p1`;
* `~` and hex digits (a commit hash), compared as a string;
* `-r<digits>`, the package revision, last.

Anything else makes the version invalid: a number over 2**64-1, a letter followed by a letter or digit, an unknown suffix,
a token out of order. apk compares up to the point where either side is invalid and calls two invalid tails equal, so
`compare` follows that exactly; a caller that must not compare invalid versions checks `valid` first.

apk-tools 2.x has older code for the same job (`version.c` at v2.14.13 counts leading zeros as a negative number, and has no
`~hash` token). The 3.x rules are used here, as Alpine 3.23's own apk applies them. Whether 2.x orders any version
differently from 3.x beyond leading zeros was not checked.
"""

from __future__ import annotations

# The token kinds, in apk's order (the order matters: a version continues only with a later kind, and a longer version
# compares by its next token's kind).
INITIAL_DIGIT, DIGIT, LETTER, SUFFIX, SUFFIX_NO, COMMIT_HASH, REVISION_NO, END, INVALID = range(9)

# apk's suffix order: the four pre-release names, then no suffix, then the four post-release ones, then _p.
_SUFFIX = {"alpha": 1, "beta": 2, "pre": 3, "rc": 4, "cvs": 6, "svn": 7, "git": 8, "hg": 9, "p": 10}
_SUFFIX_NONE = 5
_UINT64_MAX = (1 << 64) - 1
_HEX = frozenset("0123456789abcdef")           # ctype.c: HEXDGT is 0-9 and lowercase a-f only


def _lower(c: str) -> bool:
    return "a" <= c <= "z"


def _digit(c: str) -> bool:
    return "0" <= c <= "9"


class _Token:
    __slots__ = ("kind", "suffix", "number", "value")

    def __init__(self) -> None:
        self.kind = INITIAL_DIGIT
        self.suffix = 0
        self.number = 0
        self.value = ""


def _parse_digits(t: _Token, s: str, pos: int) -> int:
    """token_parse_digits: a run of ASCII digits. No digits, or a value over 2**64-1, is an invalid token."""
    end = pos
    while end < len(s) and _digit(s[end]):
        end += 1
    number = int(s[pos:end]) if end > pos else 0
    if end == pos or number > _UINT64_MAX:
        t.kind = INVALID
        t.value = ""
        return end
    t.number = number
    t.value = s[pos:end]
    return end


def _first(t: _Token, s: str) -> int:
    t.kind = INITIAL_DIGIT
    return _parse_digits(t, s, 0)


def _next(t: _Token, s: str, pos: int) -> int:
    """token_next: the token that starts at `pos`; returns the position after it. The previous token (t.kind) decides
    which tokens may follow."""
    if pos >= len(s):
        t.kind = END
        return pos
    c = s[pos]
    if _lower(c):
        if t.kind > DIGIT:
            t.kind = INVALID
            return pos
        t.value = c
        t.kind = LETTER
        return pos + 1
    if c == "." or _digit(c):
        if c == ".":
            if t.kind > DIGIT:
                t.kind = INVALID
                return pos
            pos += 1
        if t.kind in (INITIAL_DIGIT, DIGIT):
            t.kind = DIGIT
        elif t.kind == SUFFIX:
            t.kind = SUFFIX_NO
        else:
            t.kind = INVALID
            return pos
        return _parse_digits(t, s, pos)
    if c == "_":
        if t.kind > SUFFIX_NO:
            t.kind = INVALID
            return pos
        pos += 1
        end = pos
        while end < len(s) and _lower(s[end]):
            end += 1
        t.value = s[pos:end]
        t.suffix = _SUFFIX.get(t.value, 0)             # 0 is apk's SUFFIX_INVALID; "" is not in the table either
        if not t.suffix:
            t.kind = INVALID
            return end
        t.kind = SUFFIX
        return end
    if c == "~":
        if t.kind >= COMMIT_HASH:
            t.kind = INVALID
            return pos
        pos += 1
        end = pos
        while end < len(s) and s[end] in _HEX:
            end += 1
        t.value = s[pos:end]
        if end == pos:
            t.kind = INVALID
            return end
        t.kind = COMMIT_HASH
        return end
    if c == "-":
        if t.kind >= REVISION_NO or not s.startswith("-r", pos):
            t.kind = INVALID
            return pos
        t.kind = REVISION_NO
        return _parse_digits(t, s, pos + 2)
    t.kind = INVALID
    return pos


def valid(version: str) -> bool:
    """apk_version_validate: the whole string parses (`apk version -c`)."""
    t = _Token()
    pos = _first(t, version)
    while t.kind < END:
        pos = _next(t, version, pos)
    return t.kind == END


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


def _token_cmp(ta: _Token, tb: _Token) -> int:
    """token_cmp: -1, 0 or 1 for two tokens of the same kind."""
    if ta.kind == DIGIT and (ta.value[0] == "0" or tb.value[0] == "0"):
        return _cmp(ta.value, tb.value)               # a leading zero: string order, as apk_blob_sort
    if ta.kind in (DIGIT, INITIAL_DIGIT, SUFFIX_NO, REVISION_NO):
        return _cmp(ta.number, tb.number)
    if ta.kind == LETTER:
        return _cmp(ta.value, tb.value)
    if ta.kind == SUFFIX:
        return _cmp(ta.suffix, tb.suffix)
    return _cmp(ta.value, tb.value)                   # COMMIT_HASH


def compare(a: str, b: str) -> int:
    """apk_version_compare: -1 if a is older than b, 0 if equal, 1 if newer. Versions that do not parse are compared as
    far as they do, as apk does (see the module text); use `valid` to refuse them."""
    ta, tb = _Token(), _Token()
    pa, pb = _first(ta, a), _first(tb, b)
    while ta.kind == tb.kind and ta.kind < END:
        r = _token_cmp(ta, tb)
        if r:
            return r
        pa, pb = _next(ta, a, pa), _next(tb, b, pb)
    if ta.kind == tb.kind:                             # both ended, or both are invalid from here
        return 0
    # The leading parts are equal. The version that goes on is newer, unless what follows is a pre-release suffix.
    if ta.kind == SUFFIX and ta.suffix < _SUFFIX_NONE:
        return -1
    if tb.kind == SUFFIX and tb.suffix < _SUFFIX_NONE:
        return 1
    if ta.kind > tb.kind:
        return -1
    if tb.kind > ta.kind:
        return 1
    return 0


def lt(a: str, b: str) -> bool:
    return compare(a, b) < 0
