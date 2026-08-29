from __future__ import annotations

import importlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from gatehouse.database import (
    DatabaseFootprintCapacityExceeded,
    DatabaseFootprintGuard,
    DatabaseFootprintUnavailable,
    database_footprint,
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
