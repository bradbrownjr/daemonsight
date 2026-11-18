"""Read the Debian security tracker's JSON export without loading it whole.

https://security-tracker.debian.org/tracker/data/json is one JSON object:

    {"<source package>": {"<CVE or other id>": {
        "description": "...", "scope": "local|remote", "debianbug": 123,
        "releases": {"<codename>": {
            "status": "open|resolved|undetermined",
            "repositories": {"<suite>": "<version there>"},
            "fixed_version": "<source version>" | "0",   (only when resolved)
            "urgency": "unimportant|low|medium|high|not yet assigned|end-of-life",
            "nodsa": "<reason>", "nodsa_reason": "", "ignored" or "postponed",
            "next_point_update": ...}}}}}

The format has no schema document; it is read from the file itself and from
the maintainers' own reader, bin/tracker_data.py in
https://salsa.debian.org/security-tracker-team/security-tracker (class Issue,
get_status): `resolved` with `fixed_version`; `nodsa_reason` "ignored";
`undetermined`; any `nodsa`; urgency `unimportant` or `end-of-life`.

The file is about 90 MB of JSON, and the single entry for `linux` is 35 MB.
json.load() peaked at 364 MB of memory on it, too much for a small
container, so this reads two levels at a time: one CVE entry is decoded,
handed on and dropped. Only the standard library is used.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import IO

CHUNK = 1 << 20
MAX_ENTRY = 64 << 20       # one CVE entry or key larger than this: refuse the feed
WS = " \t\r\n"
_dec = json.JSONDecoder()


class FeedFormatError(ValueError):
    pass


class _Reader:
    def __init__(self, fh: IO[str], limit: int):
        self.fh = fh
        self.buf = ""
        self.pos = 0
        self.read_total = 0
        self.limit = limit

    def fill(self, want: int = CHUNK) -> bool:
        data = self.fh.read(max(want, CHUNK))
        if not data:
            return False
        self.read_total += len(data)
        if self.read_total > self.limit:
            raise FeedFormatError("feed is larger than the limit")
        if self.pos > CHUNK:
            self.buf = self.buf[self.pos:]
            self.pos = 0
        self.buf += data
        return True

    def peek(self) -> str:
        """The next character that is not white space, left in place."""
        while True:
            while self.pos < len(self.buf) and self.buf[self.pos] in WS:
                self.pos += 1
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self.fill():
                return ""

    def expect(self, ch: str) -> None:
        got = self.peek()
        if got != ch:
            raise FeedFormatError(f"expected {ch!r}, found {got!r}")
        self.pos += 1

    def value(self):
        """Decode the next JSON value, reading more until it is complete."""
        self.peek()
        while True:
            try:
                obj, end = _dec.raw_decode(self.buf, self.pos)
                if end < len(self.buf) or not isinstance(obj, (int, float)):
                    self.pos = end
                    return obj
            except json.JSONDecodeError as exc:
                if len(self.buf) - self.pos > MAX_ENTRY:
                    raise FeedFormatError("a JSON value is larger than the limit") from exc
            # Incomplete: double what is buffered, so a huge value costs few retries.
            if not self.fill(len(self.buf) - self.pos):
                raise FeedFormatError("the feed ends in the middle of a value")


def _members(r: _Reader) -> Iterator[str]:
    """Walk an object's members: yield each key, leaving the reader at its
    value; the caller must read that value before asking for the next."""
    r.expect("{")
    if r.peek() == "}":
        r.pos += 1
        return
    while True:
        key = r.value()
        if not isinstance(key, str):
            raise FeedFormatError("object key is not a string")
        r.expect(":")
        yield key
        nxt = r.peek()
        r.pos += 1
        if nxt == "}":
            return
        if nxt != ",":
            raise FeedFormatError(f"expected ',' or '}}', found {nxt!r}")


def iter_entries(fh: IO[str], limit: int = 1 << 30) -> Iterator[tuple[str, str, dict]]:
    """(source package, CVE id, entry) for every entry of the file."""
    r = _Reader(fh, limit)
    for pkg in _members(r):
        for cve in _members(r):
            entry = r.value()
            if isinstance(entry, dict):
                yield pkg, cve, entry
