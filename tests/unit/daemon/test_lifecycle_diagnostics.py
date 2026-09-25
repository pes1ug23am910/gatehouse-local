from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatehouse.database import open_migrated_database
from gatehouse.database.connection import transaction
from gatehouse.database.lifecycle_diagnostics import (
    LifecycleConnectionUnavailable,
    LifecycleDiagnosticsUnavailable,
    LifecycleJournal,
    LifecyclePhase,
)


@pytest.fixture
def connection(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    database = open_migrated_database(tmp_path / "diagnostics.sqlite3")
    try:
        yield database
    finally:
        database.close()


def test_diagnostics_retain_bounded_metadata_across_runs(connection: sqlite3.Connection) -> None:
    first = LifecycleJournal(connection, now_ms=lambda: 1_000, run_id="a" * 32)
    second = LifecycleJournal(connection, now_ms=lambda: 2_000, run_id="b" * 32)
    assert first.record(LifecyclePhase.RECOVERING)
    assert first.record(LifecyclePhase.READY)
    assert second.record(LifecyclePhase.RECOVERING)
    rows = second.recent(limit=3)
    assert [row.phase for row in rows] == [
        LifecyclePhase.RECOVERING,
        LifecyclePhase.READY,
        LifecyclePhase.RECOVERING,
    ]
    assert [row.run_id for row in rows] == ["b" * 32, "a" * 32, "a" * 32]
    assert [row.occurred_at_ms for row in rows] == [2_000, 1_000, 1_000]


def test_retention_keeps_exact_latest_256_records(connection: sqlite3.Connection) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000, run_id="a" * 32)
    for _ in range(300):
        assert journal.record(LifecyclePhase.DRAINING)
    rows = journal.recent(limit=256)
    assert len(rows) == 256
    assert rows[0].sequence == 300 and rows[-1].sequence == 45
    assert connection.execute("SELECT COUNT(*) FROM lifecycle_diagnostics").fetchone()[0] == 256
    assert journal.dropped_count == 0


@pytest.mark.parametrize("phase", ("READY", "synthetic-secret-phase", None, 1, True))
def test_arbitrary_event_fields_refuse_before_database(
    connection: sqlite3.Connection,
    phase: object,
) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    with pytest.raises(ValueError, match="lifecycle phase is invalid"):
        journal.record(phase)  # type: ignore[arg-type]
    assert statements == []


@pytest.mark.parametrize("run_id", ("", "a" * 31, "a" * 33, "G" * 32, "synthetic-secret-run", 1))
def test_correlation_has_fixed_nonsecret_shape(
    connection: sqlite3.Connection,
    run_id: object,
) -> None:
    with pytest.raises(ValueError, match="lifecycle correlation is invalid"):
        LifecycleJournal(connection, now_ms=lambda: 1_000, run_id=run_id)  # type: ignore[arg-type]


def test_record_refusal_does_not_join_or_commit_caller_transaction(
    connection: sqlite3.Connection,
) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    with transaction(connection, "IMMEDIATE"):
        assert not journal.record(LifecyclePhase.READY)
        assert connection.in_transaction
    assert journal.dropped_count == 1
    assert journal.recent(limit=1) == ()


def test_failure_is_fixed_and_diagnostic_counter_is_bounded(
    connection: sqlite3.Connection,
) -> None:
    def failed_clock() -> int:
        raise ValueError("synthetic-private-clock-detail")

    journal = LifecycleJournal(connection, now_ms=failed_clock)
    for _ in range(300):
        assert not journal.record(LifecyclePhase.FAILED_CLOSED)
    assert journal.dropped_count == 256
    assert not journal.connection_unavailable
    connection.close()
    with pytest.raises(LifecycleDiagnosticsUnavailable) as failure:
        journal.recent(limit=1)
    assert str(failure.value) == "lifecycle diagnostics are unavailable"
    assert failure.value.__context__ is None


def test_closed_shared_connection_is_a_fixed_hard_failure(connection: sqlite3.Connection) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    connection.close()
    with pytest.raises(LifecycleConnectionUnavailable) as caught:
        journal.record(LifecyclePhase.READY)
    assert journal.connection_unavailable and journal.dropped_count == 1
    assert caught.value.args == ("lifecycle diagnostic connection is unavailable",)
    assert caught.value.__cause__ is caught.value.__context__ is None


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt, SystemExit))
def test_failed_commit_and_rollback_quarantine_connection_without_replacing_interrupt(
    failure: type[BaseException],
) -> None:
    signal = failure("synthetic-private-commit-detail")

    class FailedCommitConnection(sqlite3.Connection):
        def commit(self) -> None:
            raise signal

        def rollback(self) -> None:
            raise OSError("synthetic-private-rollback-detail")

    database = sqlite3.connect(":memory:", factory=FailedCommitConnection, isolation_level=None)
    database.execute(
        "CREATE TABLE lifecycle_diagnostics "
        "(sequence INTEGER PRIMARY KEY, run_id, occurred_at_ms, phase)"
    )
    journal = LifecycleJournal(database, now_ms=lambda: 1_000)
    expected = LifecycleConnectionUnavailable if failure is RuntimeError else failure
    try:
        with pytest.raises(expected) as caught:
            journal.record(LifecyclePhase.READY)
        assert journal.connection_unavailable
        if failure is RuntimeError:
            assert caught.value.args == ("lifecycle diagnostic connection is unavailable",)
            assert caught.value.__context__ is None
        else:
            assert caught.value is signal
        with pytest.raises(sqlite3.ProgrammingError):
            database.execute("SELECT 1")
    finally:
        database.close()


@pytest.mark.parametrize("limit", (0, 257, -1, True, "1"))
def test_read_limits_are_strict(connection: sqlite3.Connection, limit: object) -> None:
    with pytest.raises(ValueError, match="lifecycle read limit is invalid"):
        LifecycleJournal(connection, now_ms=lambda: 1_000).recent(
            limit=limit,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("failure", (KeyboardInterrupt, SystemExit))
def test_control_interruption_is_not_converted_to_diagnostic_loss(
    connection: sqlite3.Connection,
    failure: type[BaseException],
) -> None:
    def interrupted_clock() -> int:
        raise failure

    with pytest.raises(failure):
        LifecycleJournal(connection, now_ms=interrupted_clock).record(LifecyclePhase.DRAINING)
    assert not connection.in_transaction


def test_failed_insert_retains_existing_ring_atomically(connection: sqlite3.Connection) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    for _ in range(256):
        assert journal.record(LifecyclePhase.RECOVERING)
    before = journal.recent(limit=256)
    connection.execute("""CREATE TRIGGER reject_lifecycle_fixture BEFORE INSERT
                          ON lifecycle_diagnostics BEGIN
                          SELECT RAISE(ABORT, 'synthetic-secret-database-detail'); END""")
    assert not journal.record(LifecyclePhase.READY)
    assert journal.recent(limit=256) == before
    assert journal.dropped_count == 1


@pytest.mark.parametrize("defect", ("text", "blob", "real", "null", "negative", "overflow"))
def test_corrupted_timestamp_is_rejected_before_unbounded_python_materialization(
    defect: str,
) -> None:
    database = sqlite3.connect(":memory:", isolation_level=None)
    try:
        database.execute(
            "CREATE TABLE lifecycle_diagnostics "
            "(sequence INTEGER PRIMARY KEY, run_id, occurred_at_ms, phase)"
        )
        values = {
            "text": "synthetic-secret-timestamp" * 16_384,
            "blob": b"synthetic-secret-timestamp" * 16_384,
            "real": 1.5,
            "null": None,
            "negative": -1,
            "overflow": 2**62,
        }
        database.execute(
            "INSERT INTO lifecycle_diagnostics VALUES (1, ?, ?, 'READY')",
            ("a" * 32, values[defect]),
        )
        decoded: list[int] = []
        timestamp_bytes: list[int] = []

        def text_factory(value: bytes) -> str:
            decoded.append(len(value))
            raise AssertionError("unbounded timestamp reached Python")

        database.text_factory = text_factory

        def row_factory(_cursor: sqlite3.Cursor, row: tuple[object, ...]) -> tuple[object, ...]:
            value = row[2]
            timestamp_bytes.append(len(value) if isinstance(value, (bytes, str)) else 0)
            return row

        database.row_factory = row_factory
        with pytest.raises(LifecycleDiagnosticsUnavailable) as caught:
            LifecycleJournal(database, now_ms=lambda: 1_000).recent(limit=1)
        assert decoded == []
        assert timestamp_bytes == [0]
        assert caught.value.args == ("lifecycle diagnostics are unavailable",)
        assert caught.value.__context__ is caught.value.__cause__ is None
    finally:
        database.close()


@pytest.mark.parametrize("occurred", (0, 253_402_300_799_999))
def test_timestamp_exact_integer_limits_round_trip(
    connection: sqlite3.Connection,
    occurred: int,
) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: occurred)
    assert journal.record(LifecyclePhase.RECOVERING)
    assert journal.recent(limit=1)[0].occurred_at_ms == occurred


def test_schema_rejects_direct_overflow_and_updates(connection: sqlite3.Connection) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    for _ in range(256):
        assert journal.record(LifecyclePhase.RECOVERING)
    before = journal.recent(limit=256)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO lifecycle_diagnostics(run_id, occurred_at_ms, phase) "
            "VALUES (?, 1000, 'READY')",
            ("b" * 32,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE lifecycle_diagnostics SET phase = 'READY' WHERE sequence = 1")
    assert journal.recent(limit=256) == before
