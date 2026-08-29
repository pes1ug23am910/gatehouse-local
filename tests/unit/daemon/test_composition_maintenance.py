from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path
from typing import cast

import pytest

from gatehouse.core import FixedUtcClock
from gatehouse.daemon import composition, run_database_maintenance_until_shutdown
from gatehouse.database import (
    DatabaseFootprintCapacityExceeded,
    DatabaseFootprintReport,
    DatabaseFootprintStatus,
    RetentionPolicy,
    RetentionReport,
    database_footprint,
    open_compatible_database,
    open_migrated_database,
)
from gatehouse.feedback import FeedbackCapacityExceeded


class _ThreadOwnedConnectionProbe:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.owner_thread_id = threading.get_ident()
        self.closed = threading.Event()

    @property
    def in_transaction(self) -> bool:
        return self.connection.in_transaction

    def execute(self, statement: str) -> sqlite3.Cursor:
        assert threading.get_ident() == self.owner_thread_id
        return self.connection.execute(statement)

    def close(self) -> None:
        assert threading.get_ident() == self.owner_thread_id
        self.connection.close()
        self.closed.set()


def test_composed_feedback_service_applies_the_configured_database_cap(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "composed-feedback.db"
    connection = open_migrated_database(database_path)
    observed_footprint = database_footprint(database_path)
    service = composition._feedback_service(
        connection,
        database_path=database_path,
        database_size_cap=observed_footprint,
    )

    try:
        with pytest.raises(FeedbackCapacityExceeded):
            service.submit(
                session_id=None,
                category="reliability",
                severity="low",
                component="database",
                summary="Low-priority write",
                content={},
                now_ms=1,
            )
        assert connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 0
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_database_maintenance_runs_one_batch_then_passive_checkpoint_per_wake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "maintenance.db"
    setup = open_migrated_database(database_path)
    setup.close()
    shutdown = asyncio.Event()
    policy = RetentionPolicy(maximum_rows_per_table=7)
    calls: list[tuple[str, object]] = []
    opened_connections: list[_ThreadOwnedConnectionProbe] = []
    event_loop_thread_id = threading.get_ident()
    loop = asyncio.get_running_loop()
    compatible_open = open_compatible_database

    def open_connection(
        path: str | Path,
        *,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        probe = _ThreadOwnedConnectionProbe(compatible_open(path, busy_timeout_ms=busy_timeout_ms))
        opened_connections.append(probe)
        return cast(sqlite3.Connection, probe)

    def retain(
        supplied: sqlite3.Connection,
        *,
        now_ms: int,
        policy: RetentionPolicy | None = None,
    ) -> RetentionReport:
        assert threading.get_ident() != event_loop_thread_id
        assert not supplied.in_transaction
        assert supplied.execute("PRAGMA busy_timeout").fetchone()[0] == 5_000
        calls.append(("retention", (now_ms, policy)))
        return RetentionReport(0, 0, 0, 0, 0)

    def checkpoint(
        supplied: sqlite3.Connection,
        *,
        mode: str = "PASSIVE",
    ) -> tuple[int, int, int]:
        assert supplied is cast(sqlite3.Connection, opened_connections[-1])
        assert threading.get_ident() != event_loop_thread_id
        assert not supplied.in_transaction
        calls.append(("checkpoint", mode))
        loop.call_soon_threadsafe(shutdown.set)
        return 0, 0, 0

    monkeypatch.setattr(composition, "open_compatible_database", open_connection)
    monkeypatch.setattr(composition, "apply_retention", retain)
    monkeypatch.setattr(composition, "checkpoint_wal", checkpoint)
    await run_database_maintenance_until_shutdown(
        database_path,
        shutdown,
        clock=FixedUtcClock(12_345),
        policy=policy,
        interval_ms=10,
    )

    assert calls == [
        ("retention", (12_345, policy)),
        ("checkpoint", "PASSIVE"),
    ]
    assert len(opened_connections) == 1
    assert opened_connections[0].closed.is_set()


def test_database_maintenance_reclaims_pressure_and_uses_the_fresh_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "pressure-maintenance.db"
    setup = open_migrated_database(database_path)
    setup.close()
    calls: list[str] = []
    reports = iter(
        (
            DatabaseFootprintReport(
                DatabaseFootprintStatus.PRESSURE,
                900,
                1_000,
                10,
                True,
            ),
            DatabaseFootprintReport(
                DatabaseFootprintStatus.HEALTHY,
                800,
                1_000,
                10,
                True,
            ),
        )
    )

    def retain(*args: object, **kwargs: object) -> RetentionReport:
        del args, kwargs
        calls.append("retention")
        return RetentionReport(0, 0, 0, 0, 0)

    def checkpoint(*args: object, mode: str = "PASSIVE", **kwargs: object) -> tuple[int, int, int]:
        del args, kwargs
        calls.append(f"checkpoint:{mode}")
        return 0, 0, 0

    def observe(*args: object, **kwargs: object) -> DatabaseFootprintReport:
        del args, kwargs
        calls.append("observe")
        return next(reports)

    monkeypatch.setattr(composition, "apply_retention", retain)
    monkeypatch.setattr(composition, "checkpoint_wal", checkpoint)
    monkeypatch.setattr(composition, "observe_database_footprint", observe)

    report = composition._run_database_maintenance_batch(
        database_path,
        busy_timeout_ms=5_000,
        now_ms=10,
        policy=RetentionPolicy(),
        maximum_database_bytes=1_000,
    )

    assert report is not None
    assert report.status is DatabaseFootprintStatus.HEALTHY
    assert calls == [
        "retention",
        "checkpoint:PASSIVE",
        "observe",
        "checkpoint:TRUNCATE",
        "observe",
    ]


def test_database_maintenance_raises_when_post_reclamation_footprint_is_at_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "capacity-maintenance.db"
    setup = open_migrated_database(database_path)
    setup.close()
    observations = iter((900, 1_000))

    monkeypatch.setattr(
        composition,
        "observe_database_footprint",
        lambda *args, **kwargs: DatabaseFootprintReport(
            (
                DatabaseFootprintStatus.PRESSURE
                if (observed := next(observations)) < 1_000
                else DatabaseFootprintStatus.CAPACITY_EXHAUSTED
            ),
            observed,
            1_000,
            10,
            True,
        ),
    )

    with pytest.raises(DatabaseFootprintCapacityExceeded) as captured:
        composition._run_database_maintenance_batch(
            database_path,
            busy_timeout_ms=5_000,
            now_ms=10,
            policy=RetentionPolicy(),
            maximum_database_bytes=1_000,
        )

    assert str(captured.value) == "database footprint capacity is exhausted"
    assert database_path.name not in str(captured.value)


@pytest.mark.asyncio
async def test_database_maintenance_worker_does_not_block_loop_and_is_joined_on_cancel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "blocked-maintenance.db"
    setup = open_migrated_database(database_path)
    setup.close()
    shutdown = asyncio.Event()
    worker_entered = asyncio.Event()
    release = threading.Event()
    opened_connections: list[_ThreadOwnedConnectionProbe] = []
    checkpointed = threading.Event()
    loop = asyncio.get_running_loop()
    compatible_open = open_compatible_database

    def open_connection(
        path: str | Path,
        *,
        busy_timeout_ms: int,
    ) -> sqlite3.Connection:
        probe = _ThreadOwnedConnectionProbe(compatible_open(path, busy_timeout_ms=busy_timeout_ms))
        opened_connections.append(probe)
        return cast(sqlite3.Connection, probe)

    def retain(
        supplied: sqlite3.Connection,
        *,
        now_ms: int,
        policy: RetentionPolicy | None = None,
    ) -> RetentionReport:
        del now_ms, policy
        loop.call_soon_threadsafe(worker_entered.set)
        if not release.wait(2):
            raise AssertionError("maintenance worker was not released")
        return RetentionReport(0, 0, 0, 0, 0)

    def checkpoint(
        supplied: sqlite3.Connection,
        *,
        mode: str = "PASSIVE",
    ) -> tuple[int, int, int]:
        assert supplied is cast(sqlite3.Connection, opened_connections[-1])
        assert mode == "PASSIVE"
        checkpointed.set()
        return 0, 0, 0

    monkeypatch.setattr(composition, "open_compatible_database", open_connection)
    monkeypatch.setattr(composition, "apply_retention", retain)
    monkeypatch.setattr(composition, "checkpoint_wal", checkpoint)
    task = asyncio.create_task(
        run_database_maintenance_until_shutdown(
            database_path,
            shutdown,
            interval_ms=10,
            busy_timeout_ms=25,
        )
    )
    safety_release = threading.Timer(2, release.set)
    safety_release.start()
    try:
        await asyncio.wait_for(worker_entered.wait(), timeout=1)

        # This round trip must complete while the SQLite worker remains blocked.
        loop_round_trip = asyncio.Event()
        asyncio.get_running_loop().call_soon(loop_round_trip.set)
        await asyncio.wait_for(loop_round_trip.wait(), timeout=0.25)
        assert not release.is_set()

        shutdown.set()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()

        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
    finally:
        release.set()
        safety_release.cancel()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert checkpointed.is_set()
    assert len(opened_connections) == 1
    assert opened_connections[0].closed.is_set()


@pytest.mark.asyncio
async def test_database_maintenance_stops_cleanly_without_an_extra_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shutdown = asyncio.Event()
    calls = 0

    def forbidden_retention(*args: object, **kwargs: object) -> RetentionReport:
        del args, kwargs
        nonlocal calls
        calls += 1
        return RetentionReport(0, 0, 0, 0, 0)

    monkeypatch.setattr(composition, "apply_retention", forbidden_retention)
    task = asyncio.create_task(
        run_database_maintenance_until_shutdown(
            tmp_path / "unused.db",
            shutdown,
            interval_ms=1_000,
        )
    )
    await asyncio.sleep(0)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1)

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("interval_ms", (True, 9, 24 * 60 * 60 * 1_000 + 1))
async def test_database_maintenance_rejects_unsafe_intervals(interval_ms: int) -> None:
    with pytest.raises(ValueError, match="maintenance interval"):
        await run_database_maintenance_until_shutdown(
            "unused.db",
            asyncio.Event(),
            interval_ms=interval_ms,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("busy_timeout_ms", (True, -1, 5_001))
async def test_database_maintenance_rejects_unsafe_busy_timeouts(
    busy_timeout_ms: int,
) -> None:
    with pytest.raises(ValueError, match="busy timeout"):
        await run_database_maintenance_until_shutdown(
            "unused.db",
            asyncio.Event(),
            busy_timeout_ms=busy_timeout_ms,
        )
