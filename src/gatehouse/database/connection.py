"""SQLite connection, transaction, and integrity primitives for Gatehouse.

Connections use autocommit mode so every write transaction is visible in the
source.  Callers must opt into :func:`transaction`; this keeps provider I/O
from being accidentally wrapped in an implicit database transaction.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import quote

DEFAULT_BUSY_TIMEOUT_MS = 5_000
TransactionMode = Literal["DEFERRED", "IMMEDIATE", "EXCLUSIVE"]


class DatabaseError(RuntimeError):
    """Base class for Gatehouse persistence failures."""


class TransactionNestingError(DatabaseError):
    """Raised when code attempts an unsupported nested transaction."""


class DatabaseConfigurationError(DatabaseError):
    """Raised when SQLite cannot honor mandatory durability settings."""


def _apply_connection_security(connection: sqlite3.Connection) -> None:
    """Require defensive SQL, untrusted schema and disabled extension loading."""
    failed = False
    try:
        for name, enabled in (
            ("SQLITE_DBCONFIG_DEFENSIVE", True),
            ("SQLITE_DBCONFIG_TRUSTED_SCHEMA", False),
            ("SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION", False),
        ):
            option = getattr(sqlite3, name)
            connection.setconfig(option, enabled)
            if connection.getconfig(option) is not enabled:
                failed = True
                break
    except (AttributeError, sqlite3.Error, ValueError):
        failed = True
    if failed:
        raise DatabaseConfigurationError("SQLite defensive settings are unavailable") from None


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """Non-secret diagnostic summary for an opened Gatehouse database."""

    ok: bool
    integrity_messages: tuple[str, ...]
    foreign_key_violations: tuple[tuple[object, ...], ...]
    schema_version: int
    journal_mode: str
    synchronous: int
    foreign_keys_enabled: bool
    busy_timeout_ms: int


def connect_database(
    path: str | Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    read_only: bool = False,
    must_exist: bool = False,
    immutable: bool = False,
) -> sqlite3.Connection:
    """Open and configure a SQLite connection.

    File databases are required to enter WAL mode.  ``:memory:`` databases
    cannot use WAL and are accepted only for narrow unit tests.
    """

    if busy_timeout_ms < 0:
        raise ValueError("busy_timeout_ms must be non-negative")

    if type(read_only) is not bool or type(must_exist) is not bool or type(immutable) is not bool:
        raise ValueError("database open modes must be Boolean")
    if immutable and not read_only:
        raise ValueError("immutable mode requires a read-only connection")

    raw_path = str(path)
    if raw_path == ":memory:" and (read_only or must_exist):
        raise ValueError("an in-memory database cannot use an existing-file open mode")
    if read_only:
        resolved = Path(raw_path).resolve()
        immutable_query = "&immutable=1" if immutable else ""
        database_uri = f"file:{quote(resolved.as_posix(), safe='/:')}?mode=ro{immutable_query}"
        connection = sqlite3.connect(
            database_uri,
            uri=True,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )
    elif must_exist:
        resolved = Path(raw_path).resolve()
        database_uri = f"file:{quote(resolved.as_posix(), safe='/:')}?mode=rw"
        connection = sqlite3.connect(
            database_uri,
            uri=True,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )
    else:
        if raw_path != ":memory:":
            Path(raw_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            raw_path,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )

    connection.row_factory = sqlite3.Row
    try:
        _apply_connection_security(connection)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        connection.execute("PRAGMA temp_store = MEMORY")

        if not read_only:
            journal_mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0])
            if raw_path != ":memory:" and journal_mode.lower() != "wal":
                raise DatabaseConfigurationError(
                    f"SQLite refused WAL mode and returned {journal_mode!r}"
                )
            connection.execute("PRAGMA synchronous = FULL")

        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise DatabaseConfigurationError("SQLite foreign-key enforcement is unavailable")
        if not read_only and int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise DatabaseConfigurationError("SQLite synchronous=FULL was not applied")
    except BaseException:
        connection.close()
        raise

    return connection


def _connect_existing_database_without_write_configuration(
    path: str | Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> sqlite3.Connection:
    """Open an existing writable database without changing durable pragmas."""

    if busy_timeout_ms < 0:
        raise ValueError("busy_timeout_ms must be non-negative")
    raw_path = str(path)
    if raw_path == ":memory:":
        raise ValueError("an in-memory database cannot use an existing-file open mode")
    resolved = Path(raw_path).resolve()
    database_uri = f"file:{quote(resolved.as_posix(), safe='/:')}?mode=rw"
    connection = sqlite3.connect(
        database_uri,
        uri=True,
        timeout=busy_timeout_ms / 1_000,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    try:
        _apply_connection_security(connection)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        connection.execute("PRAGMA temp_store = MEMORY")
        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise DatabaseConfigurationError("SQLite foreign-key enforcement is unavailable")
    except BaseException:
        connection.close()
        raise
    return connection


def _configure_database_for_writes(
    connection: sqlite3.Connection,
) -> None:
    """Apply mandatory durable pragmas after compatibility has been proven."""

    _apply_connection_security(connection)
    journal_mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0])
    if journal_mode.lower() != "wal":
        raise DatabaseConfigurationError(f"SQLite refused WAL mode and returned {journal_mode!r}")
    connection.execute("PRAGMA synchronous = FULL")
    if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
        raise DatabaseConfigurationError("SQLite synchronous=FULL was not applied")


@contextmanager
def transaction(
    connection: sqlite3.Connection,
    mode: TransactionMode = "IMMEDIATE",
) -> Iterator[sqlite3.Connection]:
    """Run a short explicit transaction and reliably roll it back on error."""

    if mode not in {"DEFERRED", "IMMEDIATE", "EXCLUSIVE"}:
        raise ValueError(f"unsupported transaction mode: {mode!r}")
    if connection.in_transaction:
        raise TransactionNestingError("nested database transactions are not supported")

    connection.execute(f"BEGIN {mode}")
    try:
        yield connection
    except BaseException:
        _rollback_or_quarantine(connection)
        raise
    else:
        try:
            connection.commit()
        except BaseException:
            _rollback_or_quarantine(connection)
            raise


def _rollback_or_quarantine(connection: sqlite3.Connection) -> None:
    """Restore a failed transaction or close an unusable connection.

    Cleanup failures must never replace the body or COMMIT exception that led
    here. A connection whose rollback fails, whose state cannot be inspected,
    or which remains in a transaction is no longer safe for shared admission
    and persistence work, so it is closed before the original error escapes.
    """

    try:
        connection.rollback()
    except BaseException:
        _close_quietly(connection)
        return
    try:
        still_active = connection.in_transaction
    except BaseException:
        _close_quietly(connection)
        return
    if still_active:
        _close_quietly(connection)


def _close_quietly(connection: sqlite3.Connection) -> None:
    with suppress(BaseException):
        connection.close()


def inspect_integrity(
    connection: sqlite3.Connection,
    *,
    full: bool = False,
) -> IntegrityReport:
    """Run SQLite integrity and foreign-key diagnostics without exposing rows."""

    check = "integrity_check" if full else "quick_check"
    integrity_messages = tuple(str(row[0]) for row in connection.execute(f"PRAGMA {check}"))
    foreign_key_violations = tuple(
        tuple(row) for row in connection.execute("PRAGMA foreign_key_check")
    )
    schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
    synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
    foreign_keys_enabled = bool(connection.execute("PRAGMA foreign_keys").fetchone()[0])
    busy_timeout_ms = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])

    return IntegrityReport(
        ok=integrity_messages == ("ok",) and not foreign_key_violations,
        integrity_messages=integrity_messages,
        foreign_key_violations=foreign_key_violations,
        schema_version=schema_version,
        journal_mode=journal_mode,
        synchronous=synchronous,
        foreign_keys_enabled=foreign_keys_enabled,
        busy_timeout_ms=busy_timeout_ms,
    )
