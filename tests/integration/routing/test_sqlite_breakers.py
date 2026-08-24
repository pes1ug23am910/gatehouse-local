from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.core.states import CircuitBreakerState
from gatehouse.database import open_migrated_database
from gatehouse.providers import ProviderErrorClass
from gatehouse.routing import BreakerKey, BreakerScopeType, CircuitBreakerRegistry
from gatehouse.routing.sqlite_breakers import (
    CircuitBreakerPersistenceError,
    SqliteCircuitBreakerPersistence,
)


def _registry(
    connection: sqlite3.Connection,
    now: list[int],
) -> CircuitBreakerRegistry:
    return CircuitBreakerRegistry(
        persistence=SqliteCircuitBreakerPersistence(connection),
        now_ms=lambda: now[0],
    )


def test_open_half_open_and_closed_breaker_state_survives_restart(tmp_path: Path) -> None:
    database = tmp_path / "breaker-restart.db"
    now = [1_000]
    connection = open_migrated_database(database)
    key = BreakerKey(BreakerScopeType.PROVIDER_OPERATION, "firecrawl.search")
    registry = _registry(connection, now)
    opened = registry.record_failure(
        key,
        now_ms=now[0],
        error_class=ProviderErrorClass.RATE_LIMITED,
        open_until_ms=5_000,
        force_open=True,
    )
    assert opened.state is CircuitBreakerState.OPEN
    connection.close()

    now[0] = 2_000
    connection = open_migrated_database(database)
    registry = _registry(connection, now)
    restored = registry.snapshot(key, now_ms=now[0])
    assert restored.state is CircuitBreakerState.OPEN
    assert restored.failure_count == 1
    assert restored.last_failure_class is ProviderErrorClass.RATE_LIMITED
    assert registry.is_available(key, now_ms=4_999) is False
    assert registry.is_available(key, now_ms=5_000) is True

    now[0] = 5_000
    permit = registry.try_acquire(key, now_ms=now[0])
    assert permit is not None
    assert registry.snapshot(key, now_ms=now[0]).state is CircuitBreakerState.HALF_OPEN
    assert registry.release(permit)
    registry.record_success(key)
    connection.close()

    now[0] = 6_000
    connection = open_migrated_database(database)
    try:
        recovered = _registry(connection, now).snapshot(key, now_ms=now[0])
        assert recovered.state is CircuitBreakerState.CLOSED
        assert recovered.failure_count == 0
        assert recovered.retry_after_ms is None
    finally:
        connection.close()


def test_non_timer_breaker_does_not_recover_when_retry_time_elapses(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "authenticated-recovery.db")
    try:
        connection.execute(
            """
            INSERT INTO circuit_breakers(
                breaker_id, scope_type, scope_id, state, failure_count,
                opened_at_ms, retry_after_ms, last_failure_class, metadata_json,
                generation, updated_at_ms, recovery_policy
            ) VALUES (
                'breaker-authenticated', 'quota_scope', 'scope-authenticated', 'OPEN', 1,
                1000, 1100, 'quota_exhausted', '{"failure_times_ms":[1000]}',
                1, 1000, 'AUTHENTICATED_POSITIVE'
            )
            """
        )
        registry = _registry(connection, [2_000])
        key = BreakerKey(BreakerScopeType.QUOTA_SCOPE, "scope-authenticated")
        assert registry.is_available(key, now_ms=2_000) is False
        assert registry.try_acquire(key, now_ms=2_000) is None
    finally:
        connection.close()


def test_corrupt_breaker_history_fails_startup_closed(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "corrupt-breaker.db")
    try:
        connection.execute(
            """
            INSERT INTO circuit_breakers(
                breaker_id, scope_type, scope_id, state, failure_count,
                metadata_json, generation, updated_at_ms, recovery_policy
            ) VALUES (
                'breaker-corrupt', 'service', 'firecrawl', 'CLOSED', 1,
                '{"failure_times_ms":[]}', 1, 1000, 'TIMER'
            )
            """
        )
        with pytest.raises(
            CircuitBreakerPersistenceError,
            match="failure history",
        ):
            _registry(connection, [2_000])
    finally:
        connection.close()
