from __future__ import annotations

import sqlite3

import pytest

from gatehouse.admin.models import CredentialValidationResult
from gatehouse.admin.provider_validation import CredentialValidationProviderFailure
from gatehouse.database.connection import connect_database
from gatehouse.database.migrations import apply_migrations
from gatehouse.database.quota_state import SqliteQuotaStateRepository
from gatehouse.providers.base import ProviderErrorClass
from gatehouse.reconciliation.observer import (
    FirecrawlCreditObservationLoop,
    SqliteObservationScheduleStore,
)


class Clock:
    def __init__(self, value: int = 10_000) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value


def _database() -> sqlite3.Connection:
    connection = connect_database(":memory:")
    apply_migrations(connection, now_ms=1)
    return connection


def _insert_account(
    connection: sqlite3.Connection,
    *,
    suffix: str,
    schedule_state: str = "ENABLED",
    next_due_at_ms: int | None = 0,
) -> tuple[str, str, str]:
    principal_id = f"principal-{suffix}"
    scope_id = f"quota-{suffix}"
    credential_id = f"credential-{suffix}"
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, enabled, metadata_json,
            created_at_ms, updated_at_ms, identity_kind
        ) VALUES (?, 'firecrawl', ?, 1, '{}', 1, 1, 'ACCOUNT')
        """,
        (principal_id, f"account-{suffix}"),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit, metadata_json,
            scope_kind, state_changed_at_ms, state_reason_code
        ) VALUES (?, ?, ?, 'UNKNOWN', 'credits', '{}', 'TEAM', 1, 'ACCOUNT_ONBOARDED')
        """,
        (scope_id, principal_id, f"account-{suffix}"),
    )
    connection.execute(
        """
        UPDATE quota_dimensions
           SET name = 'account-credits', counter_kind = 'BALANCE',
               reset_window_kind = 'PROVIDER', created_at_ms = 1, updated_at_ms = 1
         WHERE quota_scope_id = ? AND is_primary = 1
        """,
        (scope_id,),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation,
            exclusive_usage, created_at_ms, metadata_json, credential_role
        ) VALUES (?, ?, ?, ?, 'memory-test', ?, 'HEALTHY', 1, 0, 1, '{}', 'WORKLOAD')
        """,
        (
            credential_id,
            principal_id,
            scope_id,
            f"account-{suffix}",
            f"memory://credential-{suffix}",
        ),
    )
    connection.execute(
        """
        INSERT INTO quota_observation_schedules(
            schedule_id, quota_scope_id, observer_credential_id,
            observer_credential_generation, state, interval_ms,
            freshness_ttl_ms, next_due_at_ms, generation,
            created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, 1, ?, 60000, 120000, ?, 1, 1, 1)
        """,
        (f"schedule-{suffix}", scope_id, credential_id, schedule_state, next_due_at_ms),
    )
    return principal_id, scope_id, credential_id


class SuccessfulCollector:
    def __init__(self, connection: sqlite3.Connection, clock: Clock) -> None:
        self._quota = SqliteQuotaStateRepository(connection)
        self._clock = clock
        self.calls: list[tuple[str, int, str, str, int]] = []

    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        scope_id = f"quota-{credential_id.removeprefix('credential-')}"
        self.calls.append((credential_id, expected_generation, actor_id, source, freshness_ttl_ms))
        snapshot_id = f"snapshot-{credential_id}"
        observed = self._quota.record_authenticated_observation(
            quota_scope_id=scope_id,
            credential_id=credential_id,
            credential_generation=expected_generation,
            unit="credits",
            exact_remaining="17.25",
            exact_plan_total="100",
            captured_at_ms=self._clock.now_ms(),
            stale_at_ms=self._clock.now_ms() + freshness_ttl_ms,
            source=source,
            now_ms=self._clock.now_ms(),
            snapshot_id=snapshot_id,
        )
        assert observed.snapshot_id == snapshot_id
        return CredentialValidationResult(
            credential_id=credential_id,
            generation=expected_generation,
            service="firecrawl",
            principal_id=f"principal-{credential_id.removeprefix('credential-')}",
            quota_scope_id=scope_id,
            state="authenticated",
            snapshot_id=snapshot_id,
            unit="credits",
            remaining_units=17,
            plan_total_units=100,
            observed_remaining_units_decimal="17.25",
            observed_plan_total_units_decimal="100",
            captured_at_ms=self._clock.now_ms(),
            audit_event_id=f"audit-{credential_id}",
        )


class ExhaustedCollector:
    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        del credential_id, expected_generation, actor_id, source, freshness_ttl_ms
        raise CredentialValidationProviderFailure(ProviderErrorClass.QUOTA_EXHAUSTED)


@pytest.mark.asyncio
async def test_observer_claims_due_accounts_and_records_authenticated_freshness() -> None:
    connection = _database()
    _, first_scope, _ = _insert_account(connection, suffix="a")
    _insert_account(connection, suffix="b", schedule_state="DISABLED")
    clock = Clock()
    collector = SuccessfulCollector(connection, clock)
    loop = FirecrawlCreditObservationLoop(
        store=SqliteObservationScheduleStore(connection),
        collector=collector,
        quota_state=SqliteQuotaStateRepository(connection),
        now_ms=clock.now_ms,
        interval_ms=60_000,
        maximum_accounts_per_cycle=20,
        maximum_concurrency=2,
    )

    assert await loop.run_once() == 1

    assert len(collector.calls) == 1
    schedule = connection.execute(
        "SELECT * FROM quota_observation_schedules WHERE quota_scope_id = ?",
        (first_scope,),
    ).fetchone()
    assert schedule is not None
    assert schedule["last_completed_at_ms"] == clock.now_ms()
    assert schedule["last_snapshot_id"] == "snapshot-credential-a"
    assert schedule["next_due_at_ms"] == clock.now_ms() + 60_000
    assert schedule["consecutive_failures"] == 0
    status = SqliteQuotaStateRepository(connection).status(
        quota_scope_id=first_scope,
        now_ms=clock.now_ms(),
    )
    assert status is not None
    assert status.state.value == "HEALTHY"
    assert status.exact_remaining == "17.25"
    connection.close()


@pytest.mark.asyncio
async def test_definitive_observer_quota_failure_durably_exhausts_account() -> None:
    connection = _database()
    _, scope_id, _ = _insert_account(connection, suffix="exhausted")
    clock = Clock()
    loop = FirecrawlCreditObservationLoop(
        store=SqliteObservationScheduleStore(connection),
        collector=ExhaustedCollector(),
        quota_state=SqliteQuotaStateRepository(connection),
        now_ms=clock.now_ms,
        interval_ms=60_000,
        maximum_accounts_per_cycle=20,
        maximum_concurrency=1,
    )

    assert await loop.run_once() == 0

    schedule = connection.execute(
        "SELECT consecutive_failures, last_error_class FROM quota_observation_schedules"
    ).fetchone()
    assert schedule is not None
    assert tuple(schedule) == (1, "quota_exhausted")
    state = connection.execute(
        "SELECT state FROM quota_scopes WHERE quota_scope_id = ?",
        (scope_id,),
    ).fetchone()
    assert state is not None and state["state"] == "EXHAUSTED"
    connection.close()


@pytest.mark.asyncio
async def test_observer_does_nothing_without_explicit_enabled_schedule() -> None:
    connection = _database()
    _insert_account(connection, suffix="disabled", schedule_state="DISABLED")
    clock = Clock()
    collector = SuccessfulCollector(connection, clock)
    loop = FirecrawlCreditObservationLoop(
        store=SqliteObservationScheduleStore(connection),
        collector=collector,
        quota_state=SqliteQuotaStateRepository(connection),
        now_ms=clock.now_ms,
        interval_ms=60_000,
        maximum_accounts_per_cycle=20,
        maximum_concurrency=1,
    )

    assert await loop.run_once() == 0
    assert collector.calls == []
    connection.close()
