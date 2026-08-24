from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from gatehouse.database import (
    AuditEvent,
    GatehouseRepository,
    LeaseStatus,
    QuotaScopeHealthState,
    QuotaTransitionStatus,
    SqliteQuotaStateRepository,
    open_migrated_database,
    redacted_status_json,
    transaction,
)


def _seed(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, identity_kind,
            created_at_ms, updated_at_ms
        ) VALUES ('principal-account', 'firecrawl', 'personal-one', 'TEAM', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit, scope_kind
        ) VALUES ('scope-account', 'principal-account', 'personal-one',
                  'UNKNOWN', 'credits', 'TEAM')
        """
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation,
            credential_role, created_at_ms
        ) VALUES ('credential-observer', 'principal-account', 'scope-account',
                  'observer', 'test', 'opaque-observer', 'HEALTHY', 2,
                  'OBSERVER', 0)
        """
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy, automatic_use
        ) VALUES ('pool-account', 'firecrawl', 'personal', 'ACTIVE', 'pinned', 1)
        """
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
        VALUES ('pool-account', 'scope-account', 1, 1, 1)
        """
    )


def test_authenticated_zero_is_durable_and_positive_refresh_recovers_after_restart(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "quota-state-restart.db"
    connection = open_migrated_database(database_path)
    try:
        _seed(connection)
        repository = SqliteQuotaStateRepository(connection)
        audit = AuditEvent(
            event_id="audit-zero",
            occurred_at_ms=10,
            event_type="credential.provider_validation_succeeded",
            severity="INFO",
            payload_json='{"credential_generation":2,"outcome":"succeeded"}',
            service_id="firecrawl",
            operation="firecrawl.credit-usage.observe",
            preserve=True,
        )
        exhausted = repository.record_authenticated_observation(
            quota_scope_id="scope-account",
            credential_id="credential-observer",
            credential_generation=2,
            unit="credits",
            exact_remaining="-0.5",
            exact_plan_total="100.25",
            captured_at_ms=10,
            stale_at_ms=100,
            period_start_ms=0,
            period_end_ms=1_000,
            source="firecrawl-credit-usage",
            now_ms=10,
            snapshot_id="snapshot-zero",
            event_id="event-zero",
            audit_event=audit,
        )
        assert exhausted.head_advanced
        assert exhausted.transition is not None
        assert exhausted.transition.status is QuotaTransitionStatus.TRANSITIONED
        assert exhausted.transition.state is QuotaScopeHealthState.EXHAUSTED
        status = repository.status(quota_scope_id="scope-account", now_ms=11)
        assert status is not None
        assert status.alias == "personal-one"
        assert status.state is QuotaScopeHealthState.EXHAUSTED
        assert status.exact_remaining == "-0.5"
        assert status.exact_plan_total == "100.25"
        assert not status.stale
        assert tuple(
            connection.execute(
                """
                SELECT period_start_ms, period_end_ms
                  FROM quota_snapshots WHERE snapshot_id = 'snapshot-zero'
                """
            ).fetchone()
        ) == (0, 1_000)
        assert (
            connection.execute(
                "SELECT event_type FROM audit_events WHERE event_id = 'audit-zero'"
            ).fetchone()[0]
            == "credential.provider_validation_succeeded"
        )
        assert set(json.loads(redacted_status_json(status))) == {
            "alias",
            "state",
            "remaining",
            "plan_total",
            "observed_at_ms",
            "stale_at_ms",
            "stale",
            "source",
        }
    finally:
        connection.close()

    restarted = open_migrated_database(database_path)
    try:
        repository = SqliteQuotaStateRepository(restarted)
        durable = repository.status(quota_scope_id="scope-account", now_ms=12)
        assert durable is not None
        assert durable.state is QuotaScopeHealthState.EXHAUSTED
        recovered = repository.record_authenticated_observation(
            quota_scope_id="scope-account",
            credential_id="credential-observer",
            credential_generation=2,
            unit="credits",
            exact_remaining="12.75",
            captured_at_ms=20,
            stale_at_ms=120,
            source="firecrawl-credit-usage",
            now_ms=20,
            snapshot_id="snapshot-positive",
            event_id="event-positive",
        )
        assert recovered.transition is not None
        assert recovered.transition.state is QuotaScopeHealthState.HEALTHY
        row = restarted.execute(
            """
            SELECT state, state_generation, exhausted_at_ms, recovered_at_ms
              FROM quota_scopes WHERE quota_scope_id = 'scope-account'
            """
        ).fetchone()
        assert tuple(row) == ("HEALTHY", 2, 10, 20)
        events = restarted.execute(
            """
            SELECT generation, previous_state, new_state, source_kind, snapshot_id
              FROM quota_scope_state_events
             WHERE quota_scope_id = 'scope-account' ORDER BY generation
            """
        ).fetchall()
        assert [tuple(event) for event in events] == [
            (1, "UNKNOWN", "EXHAUSTED", "AUTHENTICATED_OBSERVATION", "snapshot-zero"),
            (2, "EXHAUSTED", "HEALTHY", "AUTHENTICATED_OBSERVATION", "snapshot-positive"),
        ]
    finally:
        restarted.close()


def test_stale_authority_blocks_final_fence_but_exhausted_affinity_cleanup_is_allowed(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "quota-final-fence.db")
    try:
        _seed(connection)
        health = SqliteQuotaStateRepository(connection)
        health.record_authenticated_observation(
            quota_scope_id="scope-account",
            credential_id="credential-observer",
            credential_generation=2,
            unit="credits",
            exact_remaining="10",
            captured_at_ms=10,
            stale_at_ms=20,
            source="firecrawl-credit-usage",
            now_ms=10,
            snapshot_id="snapshot-fresh",
        )
        leases = GatehouseRepository(connection)
        fresh = leases.acquire_credential_lease(
            credential_id="credential-observer",
            credential_generation=2,
            quota_scope_id="scope-account",
            pool_id="pool-account",
            owner_id="request-fresh",
            now_ms=19,
            expires_at_ms=30,
            lease_id="lease-fresh",
        )
        assert fresh.status is LeaseStatus.ACQUIRED
        assert leases.release_lease(lease_id="lease-fresh", owner_id="request-fresh", now_ms=19)

        stale = leases.acquire_credential_lease(
            credential_id="credential-observer",
            credential_generation=2,
            quota_scope_id="scope-account",
            pool_id="pool-account",
            owner_id="request-stale",
            now_ms=20,
            expires_at_ms=30,
            lease_id="lease-stale",
        )
        assert stale.status is LeaseStatus.INELIGIBLE

        health.mark_definitive_exhaustion(
            quota_scope_id="scope-account",
            now_ms=21,
            event_id="event-definitive-exhaustion",
        )
        ordinary = leases.acquire_credential_lease(
            credential_id="credential-observer",
            credential_generation=2,
            quota_scope_id="scope-account",
            pool_id="pool-account",
            owner_id="request-ordinary",
            now_ms=21,
            expires_at_ms=31,
            exact_affinity=True,
            lease_id="lease-ordinary",
        )
        assert ordinary.status is LeaseStatus.INELIGIBLE
        cleanup = leases.acquire_credential_lease(
            credential_id="credential-observer",
            credential_generation=2,
            quota_scope_id="scope-account",
            pool_id="pool-account",
            owner_id="request-cleanup",
            now_ms=21,
            expires_at_ms=31,
            exact_affinity=True,
            reconciliation=True,
            lease_id="lease-cleanup",
        )
        assert cleanup.status is LeaseStatus.ACQUIRED
    finally:
        connection.close()


def test_operator_recovery_is_generation_fenced_and_never_refreshes_balance(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "operator-recovery.db")
    try:
        _seed(connection)
        repository = SqliteQuotaStateRepository(connection)
        repository.record_authenticated_observation(
            quota_scope_id="scope-account",
            credential_id="credential-observer",
            credential_generation=2,
            unit="credits",
            exact_remaining="0",
            captured_at_ms=10,
            stale_at_ms=100,
            source="firecrawl-credit-usage",
            now_ms=10,
            snapshot_id="snapshot-exhausted",
        )
        before = tuple(
            connection.execute(
                """
                SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
                  FROM quota_scopes WHERE quota_scope_id = 'scope-account'
                """
            ).fetchone()
        )
        conflict = repository.operator_recover(
            quota_scope_id="scope-account",
            actor_id="operator",
            now_ms=11,
            expected_generation=0,
        )
        assert conflict.status is QuotaTransitionStatus.GENERATION_CONFLICT
        recovered = repository.operator_recover(
            quota_scope_id="scope-account",
            actor_id="operator",
            now_ms=12,
            expected_generation=1,
            event_id="event-operator-recover",
        )
        assert recovered.status is QuotaTransitionStatus.TRANSITIONED
        after = tuple(
            connection.execute(
                """
                SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
                  FROM quota_scopes WHERE quota_scope_id = 'scope-account'
                """
            ).fetchone()
        )
        assert after == before
        status = repository.status(quota_scope_id="scope-account", now_ms=12)
        assert status is not None
        assert status.state is QuotaScopeHealthState.EXHAUSTED
        assert (
            connection.execute(
                "SELECT state FROM quota_scopes WHERE quota_scope_id = 'scope-account'"
            ).fetchone()[0]
            == "HEALTHY"
        )

        disabled = repository.operator_disable(
            quota_scope_id="scope-account",
            actor_id="operator",
            now_ms=13,
            expected_generation=2,
            event_id="event-operator-disable",
        )
        assert disabled.state is QuotaScopeHealthState.DISABLED
        recovered_disabled = repository.operator_recover(
            quota_scope_id="scope-account",
            actor_id="operator",
            now_ms=14,
            expected_generation=3,
            event_id="event-recover-disabled",
        )
        assert recovered_disabled.state is QuotaScopeHealthState.HEALTHY
        quarantined = repository.operator_quarantine(
            quota_scope_id="scope-account",
            actor_id="operator",
            now_ms=15,
            expected_generation=4,
            event_id="event-operator-quarantine",
        )
        assert quarantined.state is QuotaScopeHealthState.QUARANTINED
        recovered_quarantined = repository.operator_recover(
            quota_scope_id="scope-account",
            actor_id="operator",
            now_ms=16,
            expected_generation=5,
            event_id="event-recover-quarantined",
        )
        assert recovered_quarantined.state is QuotaScopeHealthState.HEALTHY
        assert (
            tuple(
                connection.execute(
                    """
                SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
                  FROM quota_scopes WHERE quota_scope_id = 'scope-account'
                """
                ).fetchone()
            )
            == before
        )
    finally:
        connection.close()


def test_state_events_and_snapshot_provenance_are_immutable(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "quota-immutability.db")
    try:
        _seed(connection)
        repository = SqliteQuotaStateRepository(connection)
        repository.mark_definitive_exhaustion(
            quota_scope_id="scope-account",
            now_ms=10,
            event_id="event-immutable",
        )
        with pytest.raises(sqlite3.IntegrityError, match="state event is immutable"):
            connection.execute(
                "UPDATE quota_scope_state_events SET reason_code = 'changed' "
                "WHERE event_id = 'event-immutable'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="state event is immutable"):
            connection.execute(
                "DELETE FROM quota_scope_state_events WHERE event_id = 'event-immutable'"
            )
    finally:
        connection.close()


def test_clean_install_initial_state_event_and_in_transaction_exhaustion_seam(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "quota-initial-state.db")
    try:
        _seed(connection)
        connection.execute(
            """
            INSERT INTO quota_scope_state_events(
                event_id, quota_scope_id, generation, previous_state, new_state,
                reason_code, source_kind, actor_id, occurred_at_ms
            ) VALUES ('event-onboarded', 'scope-account', 0, NULL, 'UNKNOWN',
                      'ACCOUNT_ONBOARDED', 'OPERATOR', 'operator', 0)
            """
        )
        repository = SqliteQuotaStateRepository(connection)
        with pytest.raises(RuntimeError, match="requires an active transaction"):
            repository.mark_definitive_exhaustion_in_transaction(
                quota_scope_id="scope-account",
                now_ms=10,
            )
        with transaction(connection, "IMMEDIATE"):
            result = repository.mark_definitive_exhaustion_in_transaction(
                quota_scope_id="scope-account",
                now_ms=10,
                credential_id="credential-observer",
                credential_generation=2,
                event_id="event-atomic-exhaustion",
            )
            assert result.status is QuotaTransitionStatus.TRANSITIONED
            assert result.state is QuotaScopeHealthState.EXHAUSTED
        assert (
            connection.execute(
                "SELECT state FROM quota_scopes WHERE quota_scope_id = 'scope-account'"
            ).fetchone()[0]
            == "EXHAUSTED"
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM quota_scope_state_events "
                "WHERE quota_scope_id = 'scope-account'"
            ).fetchone()[0]
            == 2
        )
    finally:
        connection.close()
