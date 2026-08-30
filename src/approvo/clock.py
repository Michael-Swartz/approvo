"""Time sources.

All timestamps in approvo are RFC 3339 UTC strings with a ``Z`` suffix —
strings, not datetimes, so canonical hashing never depends on datetime
serialization quirks. The ``Clock`` protocol exists so tests can freeze
time and so a trusted external source (e.g. an RFC 3161 TSA) can be
swapped in later without touching call sites.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_rfc3339(value: str) -> datetime:
    # Python 3.11+ fromisoformat parses a trailing 'Z' directly.
    return datetime.fromisoformat(value)


class Clock(Protocol):
    def now(self) -> str:
        """Current time as an RFC 3339 UTC string."""
        ...


class SystemClock:
    def now(self) -> str:
        return to_rfc3339(datetime.now(UTC))


class FixedClock:
    """Deterministic clock for tests."""

    def __init__(self, value: str) -> None:
        self.value = value

    def now(self) -> str:
        return self.value
