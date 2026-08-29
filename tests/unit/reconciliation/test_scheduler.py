from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path

import pytest

from gatehouse.database import open_compatible_database, open_migrated_database
from gatehouse.reconciliation import (
    ReconciliationBatchReport,
    ReconciliationPolicy,
    await_scheduled_reconciliation_batch,
    run_scheduled_reconciliation_batch,
)
from gatehouse.reconciliation import scheduler as scheduler_module

POLICY = ReconciliationPolicy(
    absolute_tolerance_units=0,
    relative_tolerance=0.0,
    maximum_snapshot_age_ms=10_000,
)


def _database_with_scopes(path: Path, *, count: int) -> Path:
    connection = open_migrated_database(path)
    try:
        for ordinal in range(count):
            connection.execute(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms
                ) VALUES (?, 'firecrawl', ?, 0, 0)
                """,
                (f"principal-{ordinal}", f"principal-{ordinal}"),
            )
            connection.execute(
                """
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    last_known_remaining_units, configured_floor_units
                ) VALUES (?, ?, 'main', 'HEALTHY', 'credits', NULL, 0)
                """,
                (f"quota-{ordinal}", f"principal-{ordinal}"),
            )
    finally:
        connection.close()
    return path


def test_batch_stops_at_scope_bound_and_counts_unchanged_due_scopes(
    tmp_path: Path,
) -> None:
    database_path = _database_with_scopes(tmp_path / "scope-bound.db", count=3)

    report = run_scheduled_reconciliation_batch(
        database_path,
        policy=POLICY,
        now_ms=0,
        quick_interval_ms=10,
        full_interval_ms=20,
        maximum_scopes=2,
        maximum_wall_duration_ms=10_000,
    )

    assert report == ReconciliationBatchReport(
        processed_scopes=2,
        quick_scopes=0,
        full_scopes=2,
        scope_limit_reached=True,
        wall_limit_reached=False,
        cancellation_requested=False,
    )
    connection = open_migrated_database(database_path)
    try:
        assert (
            connection.execute(
                """
                SELECT COUNT(*) FROM reconciliation_scope_schedules
                 WHERE full_last_checked_at_ms = 0
                """
            ).fetchone()[0]
            == 2
        )
        assert connection.execute("SELECT COUNT(*) FROM reconciliation_runs").fetchone()[0] == 0
    finally:
        connection.close()


def test_batch_checks_wall_duration_between_scope_transactions(tmp_path: Path) -> None:
    database_path = _database_with_scopes(tmp_path / "wall-bound.db", count=3)
    readings = iter((0.0, 0.0, 0.002))

    report = run_scheduled_reconciliation_batch(
        database_path,
        policy=POLICY,
        now_ms=0,
        quick_interval_ms=10,
        full_interval_ms=20,
        maximum_scopes=3,
        maximum_wall_duration_ms=1,
        monotonic=lambda: next(readings),
    )

    assert report.processed_scopes == 1
    assert report.wall_limit_reached
    assert not report.scope_limit_reached


@pytest.mark.asyncio
async def test_public_async_batch_opens_and_closes_connection_in_worker_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = _database_with_scopes(tmp_path / "worker-owned.db", count=1)
    event_loop_thread = threading.get_ident()
    opened_thread: int | None = None
    closed_thread: int | None = None
    compatible_open = open_compatible_database

    class ThreadOwnedConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def __getattr__(self, name: str) -> object:
            assert threading.get_ident() == opened_thread
            return getattr(self._connection, name)

        def close(self) -> None:
            nonlocal closed_thread
            closed_thread = threading.get_ident()
            self._connection.close()

    def open_connection(
        path: str | Path,
        *,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        nonlocal opened_thread
        opened_thread = threading.get_ident()
        assert opened_thread != event_loop_thread
        return ThreadOwnedConnection(  # type: ignore[return-value]
            compatible_open(path, busy_timeout_ms=busy_timeout_ms)
        )

    monkeypatch.setattr(scheduler_module, "open_compatible_database", open_connection)

    report = await await_scheduled_reconciliation_batch(
        database_path,
        policy=POLICY,
        now_ms=0,
        quick_interval_ms=10,
        full_interval_ms=20,
        maximum_scopes=1,
        maximum_wall_duration_ms=1_000,
        busy_timeout_ms=25,
        monotonic=lambda: 0.0,
    )

    assert report.processed_scopes == 1
    assert opened_thread is not None
    assert closed_thread == opened_thread


@pytest.mark.asyncio
async def test_async_batch_signals_cancel_and_joins_worker_after_current_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    release_scope = threading.Event()
    worker_stopped = threading.Event()
    loop = asyncio.get_running_loop()

    def blocked_batch(
        *args: object,
        cancellation_event: threading.Event | None = None,
        **kwargs: object,
    ) -> ReconciliationBatchReport:
        del args, kwargs
        loop.call_soon_threadsafe(entered.set)
        if not release_scope.wait(2):
            raise AssertionError("scheduler worker was not released")
        assert cancellation_event is not None and cancellation_event.is_set()
        worker_stopped.set()
        return ReconciliationBatchReport(1, 0, 1, False, False, True)

    monkeypatch.setattr(
        scheduler_module,
        "run_scheduled_reconciliation_batch",
        blocked_batch,
    )
    task = asyncio.create_task(
        await_scheduled_reconciliation_batch(
            tmp_path / "unused.db",
            policy=POLICY,
            now_ms=0,
            quick_interval_ms=10,
            full_interval_ms=20,
            maximum_scopes=1_000,
            maximum_wall_duration_ms=60_000,
            busy_timeout_ms=25,
            monotonic=lambda: 0.0,
        )
    )
    safety_release = threading.Timer(2, release_scope.set)
    safety_release.start()
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release_scope.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
    finally:
        release_scope.set()
        safety_release.cancel()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert worker_stopped.is_set()
