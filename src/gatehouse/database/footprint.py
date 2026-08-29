"""Bounded, path-sanitized SQLite footprint admission helpers."""

from __future__ import annotations

import os
import stat
from pathlib import Path

_DATABASE_FILE_SUFFIXES = ("", "-wal", "-shm", "-journal")
_MAXIMUM_PATH_CHARACTERS = 32_767


class DatabaseFootprintUnavailable(RuntimeError):
    """Raised when the bounded filesystem measurement cannot be trusted."""

    def __init__(self) -> None:
        super().__init__("database footprint is unavailable")


class DatabaseFootprintCapacityExceeded(RuntimeError):
    """Raised without path or byte details when a projected write exceeds the cap."""

    def __init__(self) -> None:
        super().__init__("database footprint capacity is exhausted")


def database_footprint(path: str | Path) -> int:
    """Measure the main SQLite file and its fixed set of possible journals.

    The operation performs at most four non-following ``stat`` calls. It never
    opens a database, reads file contents, or enumerates the containing
    directory. Files can change immediately after the calls, so the result is
    an admission-time observation rather than a filesystem quota guarantee.
    """

    raw_path = os.fspath(path)
    if raw_path == ":memory:":
        return 0
    if (
        not raw_path
        or len(raw_path) > _MAXIMUM_PATH_CHARACTERS
        or any(character in raw_path for character in ("\x00", "\n", "\r"))
    ):
        raise DatabaseFootprintUnavailable

    total_bytes = 0
    for suffix in _DATABASE_FILE_SUFFIXES:
        try:
            observed = os.stat(f"{raw_path}{suffix}", follow_symlinks=False)
        except FileNotFoundError:
            if not suffix:
                raise DatabaseFootprintUnavailable from None
            continue
        except OSError:
            raise DatabaseFootprintUnavailable from None
        if not stat.S_ISREG(observed.st_mode) or observed.st_size < 0:
            raise DatabaseFootprintUnavailable
        total_bytes += observed.st_size
    return total_bytes


class DatabaseFootprintGuard:
    """Reject writes whose logical projection exceeds an observed file cap.

    A single SQLite connection can serialize the database transaction but not
    filesystem allocation or writes from unrelated processes. SQLite also
    grows files in pages and WAL frames rather than logical payload bytes.
    Consequently this is a best-effort low-priority load-shedding boundary,
    not a race-free global disk quota.
    """

    __slots__ = ("_database_path", "_maximum_bytes")

    def __init__(self, path: str | Path, *, maximum_bytes: int) -> None:
        if type(maximum_bytes) is not int or maximum_bytes <= 0:
            raise ValueError("database footprint capacity must be positive")
        self._database_path = Path(path)
        self._maximum_bytes = maximum_bytes

    def assert_write_allowed(self, *, projected_write_bytes: int) -> None:
        """Fail closed when measurement or projected capacity is unavailable."""

        if type(projected_write_bytes) is not int or projected_write_bytes < 0:
            raise ValueError("projected database write size must be non-negative")
        try:
            observed_bytes = database_footprint(self._database_path)
        except DatabaseFootprintUnavailable:
            raise DatabaseFootprintCapacityExceeded from None
        if observed_bytes > self._maximum_bytes - projected_write_bytes:
            raise DatabaseFootprintCapacityExceeded
