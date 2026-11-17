"""Data sources. Each one gathers one kind of fact about the host."""

from __future__ import annotations


class SourceUnavailable(Exception):
    """The thing this source reads is not on this host (no Docker, for example).

    Not an error: the snapshot is stored with available=False and a reason.
    """


class Source:
    name: str = ""
    interval: int = 60

    async def collect(self) -> dict:
        raise NotImplementedError

    def metrics(self, data: dict) -> dict[str, float]:
        """Numbers from `data` worth keeping as a time series."""
        return {}

    async def close(self) -> None:
        pass
