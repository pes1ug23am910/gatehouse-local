"""Bounded, path-sanitized SQLite footprint admission helpers."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .connection import transaction

_DATABASE_FILE_SUFFIXES = ("", "-wal", "-shm", "-journal")
_MAXIMUM_PATH_CHARACTERS = 32_767
_RETENTION_PRESSURE_ALERT_ID = "alert_database_retention_pressure"
_RETENTION_PRESSURE_ALERT_TITLE = "Database retention pressure"
_PRESSURE_NUMERATOR = 9
_PRESSURE_DENOMINATOR = 10


class DatabaseFootprintUnavailable(RuntimeError):
    """Raised when the bounded filesystem measurement cannot be trusted."""

    def __init__(self) -> None:
        super().__init__("database footprint is unavailable")


class DatabaseFootprintCapacityExceeded(RuntimeError):
    """Raised without path or byte details when observed capacity is exhausted."""

    def __init__(self) -> None:
        super().__init__("database footprint capacity is exhausted")


class DatabaseFootprintStatus(StrEnum):
    """Typed result of one bounded global footprint observation."""

    HEALTHY = "HEALTHY"
    PRESSURE = "PRESSURE"
    CAPACITY_EXHAUSTED = "CAPACITY_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class DatabaseFootprintPolicy:
    """Exact warning and hard-cap policy for one configured capacity."""

    maximum_bytes: int

    def __post_init__(self) -> None:
        if type(self.maximum_bytes) is not int or self.maximum_bytes <= 0:
            raise ValueError("database footprint capacity must be positive")

    def status_for(self, observed_bytes: int) -> DatabaseFootprintStatus:
        """Classify a trusted byte observation without floating-point arithmetic."""

        if type(observed_bytes) is not int or observed_bytes < 0:
            raise ValueError("observed database footprint must be non-negative")
        if observed_bytes >= self.maximum_bytes:
            return DatabaseFootprintStatus.CAPACITY_EXHAUSTED
        if observed_bytes * _PRESSURE_DENOMINATOR >= self.maximum_bytes * _PRESSURE_NUMERATOR:
            return DatabaseFootprintStatus.PRESSURE
        return DatabaseFootprintStatus.HEALTHY


@dataclass(frozen=True, slots=True)
class DatabaseFootprintReport:
    """Path-free evidence returned to daemon maintenance composition."""

    status: DatabaseFootprintStatus
    observed_bytes: int
    maximum_bytes: int
    observed_at_ms: int
    alert_updated: bool

    @property
    def fatal(self) -> bool:
        """Whether stock composition must treat this observation as fail-closed."""

        return self.status is DatabaseFootprintStatus.CAPACITY_EXHAUSTED


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


def observe_database_footprint(
    connection: sqlite3.Connection,
    *,
    database_path: str | Path,
    now_ms: int,
    maximum_bytes: int,
) -> DatabaseFootprintReport:
    """Observe the global SQLite footprint and transition its singleton alert.

    Measurement remains a fixed, stat-only observation. Alert evidence contains
    only a stable status band; it never includes the database path or byte counts.
    An unavailable observation propagates its sanitized typed exception without
    changing durable alert state.
    """

    if type(now_ms) is not int or now_ms < 0:
        raise ValueError("database footprint observation time must be non-negative")
    policy = DatabaseFootprintPolicy(maximum_bytes=maximum_bytes)
    observed_bytes = database_footprint(database_path)
    status = policy.status_for(observed_bytes)
    alert_updated = _transition_retention_pressure_alert(
        connection,
        status=status,
        now_ms=now_ms,
    )
    return DatabaseFootprintReport(
        status=status,
        observed_bytes=observed_bytes,
        maximum_bytes=policy.maximum_bytes,
        observed_at_ms=now_ms,
        alert_updated=alert_updated,
    )


def _transition_retention_pressure_alert(
    connection: sqlite3.Connection,
    *,
    status: DatabaseFootprintStatus,
    now_ms: int,
) -> bool:
    desired = _alert_values(status)
    existing = _alert_values_from_database(connection)
    if existing is None and status is DatabaseFootprintStatus.HEALTHY:
        return False
    if existing == desired:
        return False

    with transaction(connection, "IMMEDIATE"):
        existing = _alert_values_from_database(connection)
        if existing is None:
            if status is DatabaseFootprintStatus.HEALTHY:
                return False
            connection.execute(
                """
                INSERT INTO alerts(
                    alert_id, severity, category, state, title, summary,
                    created_at_ms, preserve, metadata_json
                ) VALUES (?, ?, 'DATABASE_RETENTION_PRESSURE', ?, ?, ?, ?, ?, ?)
                """,
                (
                    _RETENTION_PRESSURE_ALERT_ID,
                    desired[0],
                    desired[1],
                    desired[2],
                    desired[3],
                    now_ms,
                    desired[4],
                    desired[5],
                ),
            )
            return True
        if existing == desired:
            return False
        connection.execute(
            """
            UPDATE alerts
               SET severity = ?, state = ?, title = ?, summary = ?,
                   preserve = ?, metadata_json = ?
             WHERE alert_id = ?
            """,
            (*desired, _RETENTION_PRESSURE_ALERT_ID),
        )
        return True


def _alert_values_from_database(
    connection: sqlite3.Connection,
) -> tuple[str, str, str, str, int, str] | None:
    row = connection.execute(
        """
        SELECT severity, state, title, summary, preserve, metadata_json
          FROM alerts WHERE alert_id = ?
        """,
        (_RETENTION_PRESSURE_ALERT_ID,),
    ).fetchone()
    if row is None:
        return None
    return (
        str(row[0]),
        str(row[1]),
        str(row[2]),
        str(row[3]),
        int(row[4]),
        str(row[5]),
    )


def _alert_values(status: DatabaseFootprintStatus) -> tuple[str, str, str, str, int, str]:
    severity: str
    state: str
    summary: str
    preserve: int
    if status is DatabaseFootprintStatus.HEALTHY:
        severity = "INFO"
        state = "RESOLVED"
        summary = "The observed database footprint is below the retention-pressure threshold."
        preserve = 0
    elif status is DatabaseFootprintStatus.PRESSURE:
        severity = "HIGH"
        state = "OPEN"
        summary = "The observed database footprint reached the retention-pressure threshold."
        preserve = 1
    else:
        severity = "CRITICAL"
        state = "OPEN"
        summary = "The observed database footprint reached its configured capacity."
        preserve = 1
    metadata_json = json.dumps(
        {"footprint_status": status.value},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        severity,
        state,
        _RETENTION_PRESSURE_ALERT_TITLE,
        summary,
        preserve,
        metadata_json,
    )


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
