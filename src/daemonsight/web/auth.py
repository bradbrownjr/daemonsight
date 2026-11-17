"""Single-admin login.

The argon2 hash lives in a file the web process can read but not write
(set with `daemonsight set-password`). Failed logins are logged as
"Failed login from <ip>" so a fail2ban jail can watch them
(packaging/fail2ban/filter.d/daemonsight.conf), and are also rate-limited here.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

log = logging.getLogger("daemonsight.auth")
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


class PasswordStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def current_hash(self) -> str | None:
        try:
            value = self.path.read_text().strip()
        except OSError:
            return None
        return value or None

    def verify(self, password: str) -> bool:
        stored = self.current_hash()
        if not stored:
            return False
        try:
            return _hasher.verify(stored, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


class RateLimiter:
    """At most `limit` failures per `window` seconds per client address."""

    def __init__(self, limit: int = 5, window: int = 300):
        self.limit = limit
        self.window = window
        self._failures: dict[str, deque] = defaultdict(deque)

    def _trim(self, key: str, now: float) -> deque:
        q = self._failures[key]
        while q and q[0] < now - self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._trim(key, time.monotonic())) >= self.limit

    def fail(self, key: str) -> None:
        self._trim(key, time.monotonic()).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)
