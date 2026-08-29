from __future__ import annotations

import importlib
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from gatehouse.database import (
    DatabaseFootprintCapacityExceeded,
    DatabaseFootprintGuard,
    DatabaseFootprintPolicy,
    DatabaseFootprintStatus,
    DatabaseFootprintUnavailable,
    database_footprint,
    observe_database_footprint,
    open_migrated_database,
)


def test_database_footprint_counts_only_the_fixed_sqlite_file_set(tmp_path: Path) -> None:
    database_path = tmp_path / "gatehouse.db"
    expected = 0
    for suffix, size in (("", 11), ("-wal", 13), ("-shm", 17), ("-journal", 19)):
        Path(f"{database_path}{suffix}").write_bytes(b"x" * size)
        expected += size
    (tmp_path / "gatehouse.db-unrelated").write_bytes(b"x" * 10_000)

    assert database_footprint(database_path) == expected


def test_database_footprint_errors_are_path_sanitized_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    footprint_module = importlib.import_module("gatehouse.database.footprint")
    calls: list[str] = []
    sensitive_path = tmp_path / "operator-private-name.db"

    def denied(path: str, *, follow_symlinks: bool) -> os.stat_result:
        calls.append(path)
        assert follow_symlinks is False
        raise PermissionError(f"denied: {path}")

    monkeypatch.setattr(
        footprint_module,
        "os",
        SimpleNamespace(fspath=os.fspath, stat=denied),
    )

    with pytest.raises(DatabaseFootprintUnavailable) as captured:
        database_footprint(sensitive_path)

    assert calls == [str(sensitive_path)]
    assert str(captured.value) == "database footprint is unavailable"
    assert sensitive_path.name not in str(captured.value)


def test_database_footprint_guard_allows_exact_cap_and_rejects_overage(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    database_path.write_bytes(b"x" * 10)
    guard = DatabaseFootprintGuard(database_path, maximum_bytes=15)

    guard.assert_write_allowed(projected_write_bytes=5)

    with pytest.raises(DatabaseFootprintCapacityExceeded) as captured:
        guard.assert_write_allowed(projected_write_bytes=6)

    assert str(captured.value) == "database footprint capacity is exhausted"
    assert "15" not in str(captured.value)


def test_database_footprint_guard_fails_closed_when_main_file_is_missing(
    tmp_path: Path,
) -> None:
    guard = DatabaseFootprintGuard(tmp_path / "missing.db", maximum_bytes=1_000)

    with pytest.raises(DatabaseFootprintCapacityExceeded):
        guard.assert_write_allowed(projected_write_bytes=1)


@pytest.mark.parametrize("maximum", (True, 1.5, "100"))
def test_database_footprint_guard_rejects_non_integer_capacity(
    tmp_path: Path,
    maximum: object,
) -> None:
    with pytest.raises(ValueError, match="capacity must be positive"):
        DatabaseFootprintGuard(tmp_path / "gatehouse.db", maximum_bytes=maximum)  # type: ignore[arg-type]


@pytest.mark.parametrize("projected", (False, 1.5, "1"))
def test_database_footprint_guard_rejects_non_integer_projection(
    tmp_path: Path,
    projected: object,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    database_path.write_bytes(b"x")
    guard = DatabaseFootprintGuard(database_path, maximum_bytes=10)

    with pytest.raises(ValueError, match="write size must be non-negative"):
        guard.assert_write_allowed(projected_write_bytes=projected)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("observed_bytes", "expected"),
    (
        (899, DatabaseFootprintStatus.HEALTHY),
        (900, DatabaseFootprintStatus.PRESSURE),
        (999, DatabaseFootprintStatus.PRESSURE),
        (1_000, DatabaseFootprintStatus.CAPACITY_EXHAUSTED),
    ),
)
def test_database_footprint_policy_has_exact_warning_and_capacity_boundaries(
    observed_bytes: int,
    expected: DatabaseFootprintStatus,
) -> None:
    policy = DatabaseFootprintPolicy(maximum_bytes=1_000)

    assert policy.status_for(observed_bytes) is expected


@pytest.mark.parametrize("maximum_bytes", (True, 0, -1, 1.5, "100"))
def test_database_footprint_policy_rejects_invalid_capacity(maximum_bytes: object) -> None:
    with pytest.raises(ValueError, match="capacity must be positive"):
        DatabaseFootprintPolicy(maximum_bytes=maximum_bytes)  # type: ignore[arg-type]


def test_footprint_observation_creates_one_path_free_pressure_alert_without_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    footprint_module = importlib.import_module("gatehouse.database.footprint")
    database_path = tmp_path / "private-operator-name.db"
    connection = open_migrated_database(database_path)
    observations = iter((900, 950))
    monkeypatch.setattr(footprint_module, "database_footprint", lambda _path: next(observations))
    try:
        first = observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=1_000,
            maximum_bytes=1_000,
        )
        changes_after_first = connection.total_changes
        second = observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=2_000,
            maximum_bytes=1_000,
        )
        rows = connection.execute(
            """
            SELECT alert_id, severity, category, state, preserve, metadata_json
              FROM alerts WHERE category = 'DATABASE_RETENTION_PRESSURE'
            """
        ).fetchall()
        total_changes = connection.total_changes
    finally:
        connection.close()

    assert first.status is DatabaseFootprintStatus.PRESSURE
    assert first.alert_updated is True
    assert first.fatal is False
    assert second.status is DatabaseFootprintStatus.PRESSURE
    assert second.alert_updated is False
    assert changes_after_first > 0
    assert total_changes == changes_after_first
    assert len(rows) == 1
    assert tuple(rows[0][:5]) == (
        "alert_database_retention_pressure",
        "HIGH",
        "DATABASE_RETENTION_PRESSURE",
        "OPEN",
        1,
    )
    assert json.loads(str(rows[0][5])) == {"footprint_status": "PRESSURE"}
    assert database_path.name not in repr(first)
    assert database_path.name not in str(rows[0])


def test_footprint_observation_escalates_at_capacity_and_resolves_below_pressure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    footprint_module = importlib.import_module("gatehouse.database.footprint")
    database_path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(database_path)
    observations = iter((900, 1_000, 899, 800))
    monkeypatch.setattr(footprint_module, "database_footprint", lambda _path: next(observations))
    try:
        observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=1_000,
            maximum_bytes=1_000,
        )
        exhausted = observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=2_000,
            maximum_bytes=1_000,
        )
        critical = connection.execute(
            """
            SELECT severity, state, preserve, metadata_json FROM alerts
             WHERE alert_id = 'alert_database_retention_pressure'
            """
        ).fetchone()
        resolved = observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=3_000,
            maximum_bytes=1_000,
        )
        changes_after_resolve = connection.total_changes
        unchanged = observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=4_000,
            maximum_bytes=1_000,
        )
        healthy = connection.execute(
            """
            SELECT severity, state, preserve, metadata_json FROM alerts
             WHERE alert_id = 'alert_database_retention_pressure'
            """
        ).fetchone()
        total_changes = connection.total_changes
    finally:
        connection.close()

    assert exhausted.status is DatabaseFootprintStatus.CAPACITY_EXHAUSTED
    assert exhausted.fatal is True
    assert exhausted.alert_updated is True
    assert tuple(critical[:3]) == ("CRITICAL", "OPEN", 1)
    assert json.loads(str(critical[3])) == {"footprint_status": "CAPACITY_EXHAUSTED"}
    assert resolved.status is DatabaseFootprintStatus.HEALTHY
    assert resolved.alert_updated is True
    assert resolved.fatal is False
    assert unchanged.alert_updated is False
    assert total_changes == changes_after_resolve
    assert tuple(healthy[:3]) == ("INFO", "RESOLVED", 0)
    assert json.loads(str(healthy[3])) == {"footprint_status": "HEALTHY"}


def test_healthy_footprint_without_prior_pressure_does_not_create_an_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    footprint_module = importlib.import_module("gatehouse.database.footprint")
    database_path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(database_path)
    monkeypatch.setattr(footprint_module, "database_footprint", lambda _path: 1)
    try:
        report = observe_database_footprint(
            connection,
            database_path=database_path,
            now_ms=1_000,
            maximum_bytes=1_000,
        )
        count = int(
            connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE category = 'DATABASE_RETENTION_PRESSURE'"
            ).fetchone()[0]
        )
    finally:
        connection.close()

    assert report.status is DatabaseFootprintStatus.HEALTHY
    assert report.alert_updated is False
    assert count == 0


def test_footprint_observation_propagates_sanitized_unavailability_without_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    footprint_module = importlib.import_module("gatehouse.database.footprint")
    database_path = tmp_path / "operator-private-name.db"
    connection = open_migrated_database(database_path)

    def unavailable(_path: object) -> int:
        raise DatabaseFootprintUnavailable

    monkeypatch.setattr(footprint_module, "database_footprint", unavailable)
    try:
        with pytest.raises(DatabaseFootprintUnavailable) as captured:
            observe_database_footprint(
                connection,
                database_path=database_path,
                now_ms=1_000,
                maximum_bytes=1_000,
            )
        count = int(
            connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE category = 'DATABASE_RETENTION_PRESSURE'"
            ).fetchone()[0]
        )
    finally:
        connection.close()

    assert str(captured.value) == "database footprint is unavailable"
    assert database_path.name not in str(captured.value)
    assert count == 0


def test_footprint_observation_propagates_alert_persistence_failure_without_partial_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    footprint_module = importlib.import_module("gatehouse.database.footprint")
    database_path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(database_path)
    monkeypatch.setattr(footprint_module, "database_footprint", lambda _path: 900)
    connection.executescript(
        """
        CREATE TRIGGER test_abort_retention_pressure_alert
        BEFORE INSERT ON alerts
        WHEN NEW.category = 'DATABASE_RETENTION_PRESSURE'
        BEGIN
            SELECT RAISE(ABORT, 'injected retention pressure persistence failure');
        END;
        """
    )
    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="injected retention pressure persistence failure",
        ):
            observe_database_footprint(
                connection,
                database_path=database_path,
                now_ms=1_000,
                maximum_bytes=1_000,
            )
        assert not connection.in_transaction
        count = int(
            connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE category = 'DATABASE_RETENTION_PRESSURE'"
            ).fetchone()[0]
        )
    finally:
        connection.close()

    assert count == 0
