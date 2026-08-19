from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path

import pytest

from gatehouse.credentials import SecretDetectedError, SecretScanner
from gatehouse.database import open_migrated_database
from gatehouse.reconciliation import (
    ReconciliationAction,
    ReconciliationPolicy,
    ReconciliationState,
    ReconciliationStore,
    UsageSnapshot,
)

POLICY = ReconciliationPolicy(
    absolute_tolerance_units=0,
    relative_tolerance=Decimal("0"),
    consecutive_mismatches_for_incident=2,
    maximum_snapshot_age_ms=10_000,
)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES ('client', 'Client', 'test', 'default', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, bootstrap_verifier, bootstrap_version, token_epoch,
            state, identity_assurance, policy_version, created_at_ms,
            reconnect_until_ms, absolute_expires_at_ms
        ) VALUES ('session', 'client', X'01', 1, 0, 'ACTIVE', 'TEST', 'v1', 0, 9999, 9999)
        """
    )
    for suffix, exclusive in (("pending", 1), ("exclusive", 1), ("shared", 0)):
        connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, created_at_ms, updated_at_ms
            ) VALUES (?, 'firecrawl', ?, 0, 0)
            """,
            (f"principal-{suffix}", suffix),
        )
        connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit,
                last_known_remaining_units, configured_floor_units
            ) VALUES (?, ?, 'main', 'HEALTHY', 'credits', 100, 0)
            """,
            (f"quota-{suffix}", f"principal-{suffix}"),
        )
        connection.execute(
            """
            INSERT INTO credentials(
                credential_id, principal_id, quota_scope_id, alias, secret_backend,
                secret_reference, state, exclusive_usage, created_at_ms
            ) VALUES (?, ?, ?, 'primary', 'memory', ?, 'ACTIVE', ?, 0)
            """,
            (
                f"credential-{suffix}",
                f"principal-{suffix}",
                f"quota-{suffix}",
                f"secret-{suffix}",
                exclusive,
            ),
        )
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, service_id, operation, request_fingerprint,
            fingerprint_version, canonicalization_version, state, priority_class,
            request_size_bytes, received_at_ms
        ) VALUES ('request-pending', 'session', 'firecrawl', 'scrape', X'AA', 1, 1,
                  'RUNNING', 'SYSTEM_RESERVED', 1, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units, unit,
            state, created_at_ms, expires_at_ms
        ) VALUES ('reservation-pending', 'request-pending', 'quota-pending', 20,
                  'credits', 'PENDING_RECONCILIATION', 10, 1000)
        """
    )
    yield connection
    connection.close()


def _snapshot(scope: str, captured: int, remaining: int) -> UsageSnapshot:
    return UsageSnapshot(
        quota_scope_id=scope,
        unit="credits",
        captured_at_ms=captured,
        remaining_units=remaining,
        used_units=100 - remaining,
        plan_total_units=100,
        period_start_ms=0,
        period_end_ms=1_000,
        reset_marker="period-a",
    )


def test_pending_reservations_cover_usage_without_being_released(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    store.record_snapshot(_snapshot("quota-pending", 10, 100), source="summary")
    store.record_snapshot(_snapshot("quota-pending", 20, 85), source="summary")
    result = store.reconcile_scope(
        quota_scope_id="quota-pending",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=20,
    )
    assert result.decision.state is ReconciliationState.WITHIN_PENDING
    assert result.decision.preserve_pending_reservations
    assert result.alert_id is None
    reservation_state = database.execute(
        "SELECT state FROM quota_reservations WHERE reservation_id = 'reservation-pending'"
    ).fetchone()[0]
    assert reservation_state == "PENDING_RECONCILIATION"


def test_two_distinct_exclusive_mismatches_create_incident_and_local_quarantine(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    store.record_snapshot(_snapshot("quota-exclusive", 10, 100), source="summary")
    store.record_snapshot(_snapshot("quota-exclusive", 20, 80), source="summary")
    first = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=20,
    )
    assert first.decision.consecutive_mismatches == 1
    assert first.alert_id is None

    duplicate = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=21,
    )
    assert duplicate.decision.consecutive_mismatches == 1
    assert duplicate.alert_id is None

    store.record_snapshot(_snapshot("quota-exclusive", 30, 60), source="summary")
    second = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=30,
    )
    assert second.decision.action is ReconciliationAction.QUARANTINE_LOCAL
    assert second.alert_id is not None
    scope_state = database.execute(
        "SELECT state FROM quota_scopes WHERE quota_scope_id = 'quota-exclusive'"
    ).fetchone()[0]
    credential = database.execute(
        """
        SELECT state, generation FROM credentials
         WHERE credential_id = 'credential-exclusive'
        """
    ).fetchone()
    assert scope_state == "QUARANTINED"
    assert tuple(credential) == ("QUARANTINED", 2)
    assert (
        database.execute(
            "SELECT preserve FROM alerts WHERE alert_id = ?", (second.alert_id,)
        ).fetchone()[0]
        == 1
    )


def test_shared_ownership_creates_incident_but_never_local_quarantine(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    store.record_snapshot(_snapshot("quota-shared", 10, 100), source="summary")
    store.record_snapshot(_snapshot("quota-shared", 20, 70), source="summary")
    immediate_policy = ReconciliationPolicy(
        absolute_tolerance_units=0,
        relative_tolerance=Decimal("0"),
        consecutive_mismatches_for_incident=1,
        maximum_snapshot_age_ms=1_000,
    )
    result = store.reconcile_scope(
        quota_scope_id="quota-shared",
        service_id="firecrawl",
        policy=immediate_policy,
        now_ms=20,
    )
    assert result.decision.action is ReconciliationAction.INVESTIGATE
    assert result.alert_id is not None
    assert (
        database.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = 'quota-shared'"
        ).fetchone()[0]
        == "HEALTHY"
    )
    assert (
        database.execute(
            "SELECT state FROM credentials WHERE credential_id = 'credential-shared'"
        ).fetchone()[0]
        == "ACTIVE"
    )


def test_snapshot_recording_is_monotonic_for_last_known_balance(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    newer = _snapshot("quota-exclusive", 20, 80)
    older = _snapshot("quota-exclusive", 10, 90)
    store.record_snapshot(newer, source="summary")
    store.record_snapshot(older, source="summary")
    row = database.execute(
        """
        SELECT last_known_remaining_units, last_refreshed_at_ms
          FROM quota_scopes WHERE quota_scope_id = 'quota-exclusive'
        """
    ).fetchone()
    assert tuple(row) == (80, 20)

    used_only = UsageSnapshot(
        quota_scope_id="quota-exclusive",
        unit="credits",
        captured_at_ms=30,
        used_units=25,
        period_start_ms=0,
        period_end_ms=1_000,
    )
    store.record_snapshot(used_only, source="summary")
    assert (
        database.execute(
            """
        SELECT last_known_remaining_units FROM quota_scopes
         WHERE quota_scope_id = 'quota-exclusive'
        """
        ).fetchone()[0]
        == 80
    )


def test_snapshot_metadata_rejects_registered_secret_canaries(
    database: sqlite3.Connection,
) -> None:
    canary = "FAKE_RECON_CANARY_123456"
    store = ReconciliationStore(database, scanner=SecretScanner(canaries=[canary]))
    snapshot = UsageSnapshot(
        quota_scope_id="quota-exclusive",
        unit="credits",
        captured_at_ms=10,
        remaining_units=100,
        reset_marker=canary,
    )
    with pytest.raises(SecretDetectedError):
        store.record_snapshot(snapshot, source="summary")
