"""SQLite persistence for body-free circuit-breaker state."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from gatehouse.core.states import CircuitBreakerState
from gatehouse.database.connection import transaction
from gatehouse.providers import ProviderErrorClass

from .retry import (
    BreakerKey,
    BreakerRecoveryPolicy,
    BreakerScopeType,
    PersistedCircuitBreaker,
)

_MAXIMUM_FAILURE_TIMES = 10_000


class CircuitBreakerPersistenceError(RuntimeError):
    """Durable breaker authority is malformed or lost a generation fence."""


class SqliteCircuitBreakerPersistence:
    """Hydrate and generation-fence the daemon's transient breaker registry."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def load(self) -> tuple[PersistedCircuitBreaker, ...]:
        rows = self.connection.execute(
            """
            SELECT scope_type, scope_id, state, failure_count, opened_at_ms,
                   retry_after_ms, last_failure_class, metadata_json,
                   generation, updated_at_ms, recovery_policy
              FROM circuit_breakers
             ORDER BY scope_type, scope_id
            """
        ).fetchall()
        return tuple(self._decode(row) for row in rows)

    def save(
        self,
        breaker: PersistedCircuitBreaker,
        *,
        expected_generation: int,
    ) -> int:
        if expected_generation < 0 or breaker.generation != expected_generation:
            raise CircuitBreakerPersistenceError("circuit-breaker generation is invalid")
        metadata_json = json.dumps(
            {"failure_times_ms": list(breaker.failure_times_ms)},
            sort_keys=True,
            separators=(",", ":"),
        )
        breaker_id = self._breaker_id(breaker.key)
        new_generation = expected_generation + 1
        with transaction(self.connection, "IMMEDIATE"):
            existing = self.connection.execute(
                """
                SELECT breaker_id, generation FROM circuit_breakers
                 WHERE scope_type = ? AND scope_id = ?
                """,
                (breaker.key.scope_type.value, breaker.key.scope_id),
            ).fetchone()
            values = (
                breaker.state.value,
                len(breaker.failure_times_ms),
                breaker.opened_at_ms,
                breaker.retry_after_ms,
                None if breaker.last_failure_class is None else breaker.last_failure_class.value,
                metadata_json,
                new_generation,
                breaker.updated_at_ms,
                breaker.recovery_policy.value,
            )
            if existing is None:
                if expected_generation != 0:
                    raise CircuitBreakerPersistenceError(
                        "persisted circuit-breaker authority disappeared"
                    )
                self.connection.execute(
                    """
                    INSERT INTO circuit_breakers(
                        breaker_id, scope_type, scope_id, state, failure_count,
                        opened_at_ms, retry_after_ms, last_failure_class,
                        metadata_json, generation, updated_at_ms, recovery_policy
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        breaker_id,
                        breaker.key.scope_type.value,
                        breaker.key.scope_id,
                        *values,
                    ),
                )
            else:
                if int(existing["generation"]) != expected_generation:
                    raise CircuitBreakerPersistenceError(
                        "persisted circuit-breaker generation changed"
                    )
                updated = self.connection.execute(
                    """
                    UPDATE circuit_breakers
                       SET state = ?, failure_count = ?, opened_at_ms = ?,
                           retry_after_ms = ?, last_failure_class = ?, metadata_json = ?,
                           generation = ?, updated_at_ms = ?, recovery_policy = ?
                     WHERE breaker_id = ? AND generation = ?
                    """,
                    (*values, str(existing["breaker_id"]), expected_generation),
                )
                if updated.rowcount != 1:
                    raise CircuitBreakerPersistenceError(
                        "persisted circuit-breaker generation changed"
                    )
        return new_generation

    @staticmethod
    def _breaker_id(key: BreakerKey) -> str:
        digest = hashlib.sha256(
            f"gatehouse:breaker:v1\x00{key.scope_type.value}\x00{key.scope_id}".encode()
        ).hexdigest()
        return f"breaker_{digest}"

    @staticmethod
    def _optional_time(value: object, *, field: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CircuitBreakerPersistenceError(f"persisted {field} is invalid")
        return value

    def _decode(self, row: sqlite3.Row) -> PersistedCircuitBreaker:
        try:
            scope_type = BreakerScopeType(str(row["scope_type"]))
            state = CircuitBreakerState(str(row["state"]))
            recovery_policy = BreakerRecoveryPolicy(str(row["recovery_policy"]))
            raw_last_failure = row["last_failure_class"]
            last_failure = (
                None if raw_last_failure is None else ProviderErrorClass(str(raw_last_failure))
            )
        except (TypeError, ValueError) as error:
            raise CircuitBreakerPersistenceError(
                "persisted circuit-breaker classification is invalid"
            ) from error
        scope_id = row["scope_id"]
        if not isinstance(scope_id, str) or not 1 <= len(scope_id) <= 512:
            raise CircuitBreakerPersistenceError("persisted circuit-breaker scope is invalid")
        failure_count = row["failure_count"]
        generation = row["generation"]
        updated_at_ms = row["updated_at_ms"]
        if (
            isinstance(failure_count, bool)
            or not isinstance(failure_count, int)
            or not 0 <= failure_count <= _MAXIMUM_FAILURE_TIMES
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 0
            or isinstance(updated_at_ms, bool)
            or not isinstance(updated_at_ms, int)
            or updated_at_ms < 0
        ):
            raise CircuitBreakerPersistenceError("persisted circuit-breaker counters are invalid")
        try:
            metadata = json.loads(str(row["metadata_json"]))
        except (TypeError, ValueError) as error:
            raise CircuitBreakerPersistenceError(
                "persisted circuit-breaker metadata is invalid"
            ) from error
        if not isinstance(metadata, dict):
            raise CircuitBreakerPersistenceError("persisted circuit-breaker metadata is invalid")
        raw_times = metadata.get("failure_times_ms")
        if raw_times is None:
            anchor = updated_at_ms
            if anchor == 0:
                opened = self._optional_time(row["opened_at_ms"], field="breaker open time")
                anchor = 0 if opened is None else opened
            failure_times = (anchor,) * failure_count
        else:
            if not isinstance(raw_times, list) or len(raw_times) != failure_count:
                raise CircuitBreakerPersistenceError(
                    "persisted circuit-breaker failure history is invalid"
                )
            if any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in raw_times
            ):
                raise CircuitBreakerPersistenceError(
                    "persisted circuit-breaker failure history is invalid"
                )
            failure_times = tuple(raw_times)
        return PersistedCircuitBreaker(
            key=BreakerKey(scope_type, scope_id),
            state=state,
            failure_times_ms=failure_times,
            opened_at_ms=self._optional_time(row["opened_at_ms"], field="breaker open time"),
            retry_after_ms=self._optional_time(row["retry_after_ms"], field="breaker retry time"),
            last_failure_class=last_failure,
            recovery_policy=recovery_policy,
            generation=generation,
            updated_at_ms=updated_at_ms,
        )
