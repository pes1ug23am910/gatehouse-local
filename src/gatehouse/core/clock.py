"""UTC millisecond clocks with explicit dependency-injection seams."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from time import time_ns
from typing import Protocol, runtime_checkable

MIN_UTC_MS = 0
MAX_UTC_MS = 253_402_300_799_999
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def require_utc_ms(value: int) -> int:
    """Validate an integer UTC Unix timestamp expressed in milliseconds."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("UTC milliseconds must be an integer")
    if not MIN_UTC_MS <= value <= MAX_UTC_MS:
        raise ValueError("UTC milliseconds are outside the supported range")
    return value


def utc_now_ms() -> int:
    """Return the current UTC Unix time in whole milliseconds."""

    return time_ns() // 1_000_000


def datetime_to_utc_ms(value: datetime) -> int:
    """Convert an aware datetime to UTC Unix milliseconds."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    delta = value.astimezone(UTC) - _UNIX_EPOCH
    milliseconds = delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000
    return require_utc_ms(milliseconds)


def datetime_from_utc_ms(value: int) -> datetime:
    """Convert UTC Unix milliseconds to an aware UTC datetime."""

    return datetime.fromtimestamp(require_utc_ms(value) / 1_000, tz=UTC)


@runtime_checkable
class UtcMsClock(Protocol):
    """Clock interface used by code that persists or compares timestamps."""

    def now_ms(self) -> int:
        """Return a validated UTC Unix timestamp in milliseconds."""


@dataclass(frozen=True, slots=True)
class SystemUtcClock:
    """Production clock backed by the operating system wall clock."""

    def now_ms(self) -> int:
        return utc_now_ms()


@dataclass(frozen=True, slots=True)
class FixedUtcClock:
    """Deterministic clock for tests and replayable workflows."""

    value_ms: int

    def __post_init__(self) -> None:
        require_utc_ms(self.value_ms)

    def now_ms(self) -> int:
        return self.value_ms


SYSTEM_UTC_CLOCK = SystemUtcClock()
