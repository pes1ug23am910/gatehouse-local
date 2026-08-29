from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

import pytest

from gatehouse.core.provider_numbers import SQLITE_INT64_MAX, SQLITE_INT64_MIN
from gatehouse.credentials import SecretDetectedError, SecretScanner
from gatehouse.database import (
    MIGRATIONS,
    AuditEvent,
    apply_migrations,
    connect_database,
    open_compatible_database,
    open_migrated_database,
)
from gatehouse.reconciliation import (
    ReconciliationAction,
    ReconciliationMode,
    ReconciliationPersistenceError,
    ReconciliationPolicy,
    ReconciliationState,
    ReconciliationStore,
    ScheduledReconciliationOutcome,
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
            ) VALUES (?, ?, 'main', 'HEALTHY', 'credits', NULL, 0)
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


def _audit_event(
    event_id: str,
    *,
    payload: dict[str, object] | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        occurred_at_ms=25,
        event_type="credential.provider_validation_failed",
        severity="WARNING",
        payload_json=json.dumps(payload or {"outcome": "failed"}),
        service_id="firecrawl",
        operation="firecrawl.account.credit_status",
        preserve=True,
    )


def _isolate_scheduled_scope(
    database: sqlite3.Connection,
    quota_scope_id: str,
) -> None:
    database.execute(
        """
        UPDATE reconciliation_scope_schedules
           SET quick_last_checked_at_ms = 999999,
               full_last_checked_at_ms = 999999,
               generation = generation + 1
         WHERE quota_scope_id != ?
        """,
        (quota_scope_id,),
    )


def test_audit_only_recording_uses_a_standalone_transaction(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)

    recorded = store.record_audit_event(_audit_event("audit-standalone"))

    assert recorded == "audit-standalone"
    row = database.execute(
        "SELECT event_type, severity, preserve, payload_json FROM audit_events"
    ).fetchone()
    assert tuple(row[:3]) == (
        "credential.provider_validation_failed",
        "WARNING",
        1,
    )
    assert json.loads(row["payload_json"]) == {"outcome": "failed"}


def test_audit_only_conflict_rolls_back_and_connection_remains_usable(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    store.record_audit_event(_audit_event("audit-conflict"))

    with pytest.raises(sqlite3.IntegrityError):
        store.record_audit_event(_audit_event("audit-conflict"))

    assert not database.in_transaction
    assert database.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    store.record_audit_event(_audit_event("audit-after-conflict"))
    assert database.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2


def test_audit_only_recording_rejects_registered_canary_before_transaction(
    database: sqlite3.Connection,
) -> None:
    canary = "FAKE_AUDIT_CANARY_123456789"
    store = ReconciliationStore(database, scanner=SecretScanner(canaries=[canary]))

    with pytest.raises(SecretDetectedError):
        store.record_audit_event(_audit_event("audit-canary", payload={"error_class": canary}))

    assert not database.in_transaction
    assert database.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


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


def test_fractional_snapshot_and_reconciliation_values_are_stored_as_canonical_text(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    store.record_snapshot(
        UsageSnapshot(
            quota_scope_id="quota-exclusive",
            unit="credits",
            captured_at_ms=10,
            remaining_units=0,
            plan_total_units=1,
            observed_remaining_units_decimal="-1.25",
            observed_plan_total_units_decimal="1.5",
        ),
        source="summary",
    )
    store.record_snapshot(
        UsageSnapshot(
            quota_scope_id="quota-exclusive",
            unit="credits",
            captured_at_ms=20,
            remaining_units=0,
            plan_total_units=1,
            observed_remaining_units_decimal="-3.75",
            observed_plan_total_units_decimal="1.5",
        ),
        source="summary",
    )
    result = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=ReconciliationPolicy(1, Decimal("0")),
        now_ms=20,
        manual_adjustment_units=2,
    )
    assert result.decision.state is ReconciliationState.MATCHED
    assert result.decision.provider_delta_units is None
    assert result.decision.provider_delta_units_decimal == "2.5"
    assert result.decision.unexplained_delta_units == 0
    assert result.decision.unexplained_delta_units_decimal == "0"

    snapshots = database.execute(
        """
        SELECT remaining_units, observed_remaining_units_decimal,
               plan_total_units, observed_plan_total_units_decimal
          FROM quota_snapshots
         WHERE quota_scope_id = 'quota-exclusive'
         ORDER BY captured_at_ms
        """
    ).fetchall()
    assert [tuple(row) for row in snapshots] == [
        (0, "-1.25", 1, "1.5"),
        (0, "-3.75", 1, "1.5"),
    ]
    item = database.execute(
        """
        SELECT provider_delta_units, provider_delta_units_decimal,
               unexplained_delta_units, unexplained_delta_units_decimal,
               allowed_tolerance_units_decimal, details_json
          FROM reconciliation_items WHERE item_id = ?
        """,
        (result.item_id,),
    ).fetchone()
    assert tuple(item[:5]) == (None, "2.5", 0, "0", "1")
    details = json.loads(item["details_json"])
    assert details["provider_delta_units_decimal"] == "2.5"
    assert details["unexplained_delta_units_decimal"] == "0"
    assert details["allowed_tolerance_units"] == "1"
    assert details["allowed_tolerance_units_decimal"] == "1"


def test_384_digit_unexplained_delta_round_trips_through_durable_state(
    database: sqlite3.Connection,
) -> None:
    previous_observation = "9" * 128
    current_observation = "-0." + "0" * 127 + "9" * 128
    expected_provider_delta = "9" * 128 + "." + "0" * 127 + "9" * 128
    expected_unexplained_delta = "1" + "0" * 109 + str(2**63 - 1) + "." + "0" * 127 + "9" * 128
    store = ReconciliationStore(database)
    store.record_snapshot(
        UsageSnapshot(
            quota_scope_id="quota-exclusive",
            unit="credits",
            captured_at_ms=10,
            remaining_units=SQLITE_INT64_MAX,
            observed_remaining_units_decimal=previous_observation,
        ),
        source="summary",
    )
    store.record_snapshot(
        UsageSnapshot(
            quota_scope_id="quota-exclusive",
            unit="credits",
            captured_at_ms=20,
            remaining_units=0,
            observed_remaining_units_decimal=current_observation,
        ),
        source="summary",
    )

    first = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=20,
        manual_adjustment_units=SQLITE_INT64_MIN,
    )

    assert first.decision.state is ReconciliationState.MISMATCH
    assert first.decision.provider_delta_units is None
    assert first.decision.provider_delta_units_decimal == expected_provider_delta
    assert first.decision.unexplained_delta_units is None
    assert first.decision.unexplained_delta_units_decimal == expected_unexplained_delta
    assert len(expected_provider_delta) == 384
    assert len(expected_unexplained_delta) == 385
    stored = database.execute(
        """
        SELECT provider_delta_units, provider_delta_units_decimal,
               unexplained_delta_units, unexplained_delta_units_decimal
          FROM reconciliation_items
         WHERE item_id = ?
        """,
        (first.item_id,),
    ).fetchone()
    assert tuple(stored) == (
        None,
        expected_provider_delta,
        None,
        expected_unexplained_delta,
    )

    second = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=21,
        manual_adjustment_units=SQLITE_INT64_MIN,
    )

    assert second.decision.provider_delta_units is None
    assert second.decision.provider_delta_units_decimal == expected_provider_delta
    assert second.decision.unexplained_delta_units is None
    assert second.decision.unexplained_delta_units_decimal == expected_unexplained_delta


@pytest.mark.parametrize(
    ("column", "corrupt_value"),
    [
        ("provider_delta_units_decimal", "1" * 384),
        ("unexplained_delta_units_decimal", "1" * 385),
        ("allowed_tolerance_units_decimal", "1" * 130),
        ("allowed_tolerance_units_decimal", "-1"),
        ("allowed_tolerance_units_decimal", "1.5"),
        ("allowed_tolerance_units_decimal", "01"),
    ],
)
def test_durable_reconciliation_reads_enforce_role_specific_decimal_bounds(
    database: sqlite3.Connection,
    column: str,
    corrupt_value: str,
) -> None:
    store = ReconciliationStore(database)
    store.record_snapshot(_snapshot("quota-exclusive", 10, 100), source="summary")
    store.record_snapshot(_snapshot("quota-exclusive", 20, 80), source="summary")
    recorded = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=20,
    )
    trigger_names = database.execute(
        "SELECT name FROM sqlite_schema "
        "WHERE type = 'trigger' AND tbl_name = 'reconciliation_items'"
    ).fetchall()
    for row in trigger_names:
        name = str(row["name"]).replace('"', '""')
        database.execute(f'DROP TRIGGER "{name}"')
    update_statement = {
        "provider_delta_units_decimal": (
            "UPDATE reconciliation_items SET provider_delta_units_decimal = ? WHERE item_id = ?"
        ),
        "unexplained_delta_units_decimal": (
            "UPDATE reconciliation_items SET unexplained_delta_units_decimal = ? WHERE item_id = ?"
        ),
        "allowed_tolerance_units_decimal": (
            "UPDATE reconciliation_items SET allowed_tolerance_units_decimal = ? WHERE item_id = ?"
        ),
    }[column]
    database.execute(
        update_statement,
        (corrupt_value, recorded.item_id),
    )
    counts_before = tuple(
        database.execute(
            "SELECT (SELECT COUNT(*) FROM reconciliation_runs), "
            "(SELECT COUNT(*) FROM reconciliation_items)"
        ).fetchone()
    )

    with pytest.raises(ReconciliationPersistenceError):
        store.reconcile_scope(
            quota_scope_id="quota-exclusive",
            service_id="firecrawl",
            policy=POLICY,
            now_ms=21,
        )

    counts_after = tuple(
        database.execute(
            "SELECT (SELECT COUNT(*) FROM reconciliation_runs), "
            "(SELECT COUNT(*) FROM reconciliation_items)"
        ).fetchone()
    )
    assert counts_after == counts_before


def test_two_distinct_exclusive_mismatches_create_incident_and_local_quarantine(
    database: sqlite3.Connection,
) -> None:
    database.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias, secret_backend,
            secret_reference, state, generation, exclusive_usage, created_at_ms
        ) VALUES ('credential-retired', 'principal-exclusive', 'quota-exclusive',
                  'retired', 'memory', 'retired-tombstone', 'RETIRED', 7, 1, 0)
        """
    )
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
    retired = database.execute(
        "SELECT state, generation FROM credentials WHERE credential_id = 'credential-retired'"
    ).fetchone()
    assert tuple(retired) == ("RETIRED", 7)
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


@pytest.mark.parametrize(
    "corruption",
    [
        "missing",
        "noncanonical",
        "mismatched",
        "wrong_text_type",
        "wrong_projected_type",
    ],
)
def test_durable_snapshot_reads_fail_closed_on_malformed_exact_counters(
    database: sqlite3.Connection,
    corruption: str,
) -> None:
    store = ReconciliationStore(database)
    snapshot_id = store.record_snapshot(
        UsageSnapshot(
            quota_scope_id="quota-exclusive",
            unit="credits",
            captured_at_ms=10,
            remaining_units=1,
            observed_remaining_units_decimal="1",
        ),
        source="summary",
    )
    trigger_names = database.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = 'quota_snapshots'"
    ).fetchall()
    for row in trigger_names:
        name = str(row["name"]).replace('"', '""')
        database.execute(f'DROP TRIGGER "{name}"')
    if corruption == "missing":
        database.execute(
            "UPDATE quota_snapshots SET observed_remaining_units_decimal = NULL "
            "WHERE snapshot_id = ?",
            (snapshot_id,),
        )
    elif corruption == "noncanonical":
        database.execute(
            "UPDATE quota_snapshots SET observed_remaining_units_decimal = '1.0' "
            "WHERE snapshot_id = ?",
            (snapshot_id,),
        )
    elif corruption == "mismatched":
        database.execute(
            "UPDATE quota_snapshots SET observed_remaining_units_decimal = '2' "
            "WHERE snapshot_id = ?",
            (snapshot_id,),
        )
    elif corruption == "wrong_text_type":
        database.execute(
            "UPDATE quota_snapshots "
            "SET observed_remaining_units_decimal = CAST(X'31' AS BLOB) "
            "WHERE snapshot_id = ?",
            (snapshot_id,),
        )
    else:
        assert corruption == "wrong_projected_type"
        database.execute(
            "UPDATE quota_snapshots "
            "SET remaining_units = 1.5, observed_remaining_units_decimal = '1.5' "
            "WHERE snapshot_id = ?",
            (snapshot_id,),
        )

    with pytest.raises(ReconciliationPersistenceError):
        store.latest_snapshots("quota-exclusive")


def test_manual_reconciliation_records_manual_mode_and_exact_state_pointer(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    first_snapshot_id = store.record_snapshot(
        _snapshot("quota-exclusive", 10, 100),
        source="summary",
    )
    store.record_snapshot(_snapshot("quota-exclusive", 20, 90), source="summary")

    recorded = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=ReconciliationPolicy(20, Decimal("0")),
        now_ms=20,
    )

    assert recorded.mode is ReconciliationMode.MANUAL
    assert (
        database.execute(
            "SELECT mode FROM reconciliation_runs WHERE reconciliation_id = ?",
            (recorded.reconciliation_id,),
        ).fetchone()[0]
        == "MANUAL"
    )
    schedule = database.execute(
        """
        SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
               quick_last_checked_at_ms, full_last_checked_at_ms,
               last_reconciliation_id
          FROM reconciliation_scope_schedules
         WHERE quota_scope_id = 'quota-exclusive'
        """
    ).fetchone()
    assert tuple(schedule) == (
        first_snapshot_id,
        first_snapshot_id,
        None,
        None,
        recorded.reconciliation_id,
    )


def test_v15_backfill_seeds_latest_retained_snapshot_without_inventing_history(
    tmp_path: Path,
) -> None:
    connection = connect_database(tmp_path / "v14-reconciliation.db")
    try:
        assert apply_migrations(connection, migrations=MIGRATIONS[:-1], now_ms=0) == 14
        connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, created_at_ms, updated_at_ms
            ) VALUES ('principal', 'firecrawl', 'main', 0, 0)
            """
        )
        connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit,
                last_known_remaining_units, configured_floor_units
            ) VALUES ('quota', 'principal', 'main', 'HEALTHY', 'credits', NULL, 0)
            """
        )
        store = ReconciliationStore(connection)
        store.record_snapshot(_snapshot("quota", 10, 100), source="summary")
        latest_id = store.record_snapshot(_snapshot("quota", 20, 90), source="summary")

        assert apply_migrations(connection, now_ms=1) == 15

        schedule = connection.execute(
            """
            SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
                   quick_last_checked_at_ms, full_last_checked_at_ms,
                   last_reconciliation_id
              FROM reconciliation_scope_schedules
             WHERE quota_scope_id = 'quota'
            """
        ).fetchone()
        assert tuple(schedule) == (latest_id, latest_id, None, None, None)
    finally:
        connection.close()


def test_full_supersedes_quick_while_quick_keeps_an_independent_delayed_baseline(
    database: sqlite3.Connection,
) -> None:
    _isolate_scheduled_scope(database, "quota-exclusive")
    store = ReconciliationStore(database)
    tolerant = ReconciliationPolicy(100, Decimal("0"), maximum_snapshot_age_ms=1_000)
    first_id = store.record_snapshot(
        _snapshot("quota-exclusive", 10, 100),
        source="summary",
    )

    initial_full = store.reconcile_next_due_scope(
        policy=tolerant,
        now_ms=10,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    no_redundant_initial_quick = store.reconcile_next_due_scope(
        policy=tolerant,
        now_ms=10,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    assert initial_full is not None and initial_full.mode is ReconciliationMode.FULL
    assert initial_full.recorded is None
    assert no_redundant_initial_quick is None

    second_id = store.record_snapshot(
        _snapshot("quota-exclusive", 20, 90),
        source="summary",
    )
    first_quick = store.reconcile_next_due_scope(
        policy=tolerant,
        now_ms=20,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    assert first_quick is not None and first_quick.recorded is not None
    assert first_quick.mode is ReconciliationMode.QUICK
    assert first_quick.recorded.decision.provider_delta_units_decimal == "10"

    third_id = store.record_snapshot(
        _snapshot("quota-exclusive", 30, 80),
        source="summary",
    )
    second_quick = store.reconcile_next_due_scope(
        policy=tolerant,
        now_ms=30,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    assert second_quick is not None and second_quick.recorded is not None
    assert second_quick.recorded.decision.provider_delta_units_decimal == "10"

    fourth_id = store.record_snapshot(
        _snapshot("quota-exclusive", 40, 70),
        source="summary",
    )
    delayed_full = store.reconcile_next_due_scope(
        policy=tolerant,
        now_ms=110,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    assert delayed_full is not None and delayed_full.recorded is not None
    assert delayed_full.mode is ReconciliationMode.FULL
    assert delayed_full.recorded.decision.provider_delta_units_decimal == "30"
    details = json.loads(
        database.execute(
            "SELECT details_json FROM reconciliation_items WHERE item_id = ?",
            (delayed_full.recorded.item_id,),
        ).fetchone()[0]
    )
    assert details["previous_snapshot_id"] == first_id
    assert details["current_snapshot_id"] == fourth_id
    schedule = database.execute(
        """
        SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
               quick_last_checked_at_ms, full_last_checked_at_ms
          FROM reconciliation_scope_schedules
         WHERE quota_scope_id = 'quota-exclusive'
        """
    ).fetchone()
    assert tuple(schedule) == (fourth_id, fourth_id, 110, 110)
    assert second_id != third_id


def test_unchanged_scheduled_observations_do_not_grow_reconciliation_history(
    database: sqlite3.Connection,
) -> None:
    _isolate_scheduled_scope(database, "quota-exclusive")
    store = ReconciliationStore(database)
    snapshot_id = store.record_snapshot(
        _snapshot("quota-exclusive", 0, 100),
        source="summary",
    )

    outcomes = [
        store.reconcile_next_due_scope(
            policy=POLICY,
            now_ms=now_ms,
            quick_interval_ms=10,
            full_interval_ms=20,
        )
        for now_ms in (0, 10, 20, 20)
    ]

    assert [outcome.mode for outcome in outcomes if outcome is not None] == [
        ReconciliationMode.FULL,
        ReconciliationMode.QUICK,
        ReconciliationMode.FULL,
    ]
    assert all(outcome is None or outcome.recorded is None for outcome in outcomes)
    assert outcomes[-1] is None
    counts = database.execute(
        "SELECT (SELECT COUNT(*) FROM reconciliation_runs), "
        "(SELECT COUNT(*) FROM reconciliation_items)"
    ).fetchone()
    assert tuple(counts) == (0, 0)
    schedule = database.execute(
        """
        SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
               quick_last_checked_at_ms, full_last_checked_at_ms
          FROM reconciliation_scope_schedules
         WHERE quota_scope_id = 'quota-exclusive'
        """
    ).fetchone()
    assert tuple(schedule) == (snapshot_id, snapshot_id, 20, 20)


def test_unchanged_snapshot_records_one_stale_transition_without_refresh_or_growth(
    database: sqlite3.Connection,
) -> None:
    _isolate_scheduled_scope(database, "quota-exclusive")
    store = ReconciliationStore(database)
    snapshot_id = store.record_snapshot(
        _snapshot("quota-exclusive", 0, 100),
        source="summary",
    )
    stale_policy = ReconciliationPolicy(
        0,
        Decimal("0"),
        maximum_snapshot_age_ms=10,
    )
    initial = store.reconcile_next_due_scope(
        policy=stale_policy,
        now_ms=0,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    stale = store.reconcile_next_due_scope(
        policy=stale_policy,
        now_ms=20,
        quick_interval_ms=5,
        full_interval_ms=100,
    )
    repeated = store.reconcile_next_due_scope(
        policy=stale_policy,
        now_ms=30,
        quick_interval_ms=5,
        full_interval_ms=100,
    )

    assert initial is not None and initial.recorded is None
    assert stale is not None and stale.mode is ReconciliationMode.QUICK
    assert stale.recorded is not None
    assert stale.recorded.decision.state is ReconciliationState.STALE
    assert repeated is not None and repeated.recorded is None
    assert database.execute("SELECT COUNT(*) FROM reconciliation_runs").fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM reconciliation_items").fetchone()[0] == 1
    assert (
        database.execute(
            "SELECT captured_at_ms FROM quota_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()[0]
        == 0
    )
    assert tuple(
        database.execute(
            """
            SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
                   quick_last_checked_at_ms, full_last_checked_at_ms
              FROM reconciliation_scope_schedules
             WHERE quota_scope_id = 'quota-exclusive'
            """
        ).fetchone()
    ) == (snapshot_id, snapshot_id, 30, 0)


def test_mismatch_progression_deduplicates_current_identity_across_modes(
    database: sqlite3.Connection,
) -> None:
    _isolate_scheduled_scope(database, "quota-exclusive")
    store = ReconciliationStore(database)
    first_id = store.record_snapshot(
        _snapshot("quota-exclusive", 0, 100),
        source="summary",
    )
    store.record_snapshot(_snapshot("quota-exclusive", 10, 90), source="summary")
    current_id = store.record_snapshot(
        _snapshot("quota-exclusive", 20, 80),
        source="summary",
    )
    manual = store.reconcile_scope(
        quota_scope_id="quota-exclusive",
        service_id="firecrawl",
        policy=POLICY,
        now_ms=20,
    )
    assert manual.decision.consecutive_mismatches == 1

    scheduled = store.reconcile_next_due_scope(
        policy=POLICY,
        now_ms=20,
        quick_interval_ms=5,
        full_interval_ms=100,
    )

    assert scheduled is not None and scheduled.recorded is not None
    assert scheduled.mode is ReconciliationMode.FULL
    assert scheduled.recorded.decision.consecutive_mismatches == 1
    assert scheduled.recorded.alert_id is None
    details = json.loads(
        database.execute(
            "SELECT details_json FROM reconciliation_items WHERE item_id = ?",
            (scheduled.recorded.item_id,),
        ).fetchone()[0]
    )
    assert details["previous_snapshot_id"] == first_id
    assert details["current_snapshot_id"] == current_id
    assert details["observation_is_new"] is False
    assert database.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_schedule_scope_integrity_rejects_cross_scope_baselines(
    database: sqlite3.Connection,
) -> None:
    store = ReconciliationStore(database)
    foreign_snapshot_id = store.record_snapshot(
        _snapshot("quota-shared", 10, 100),
        source="summary",
    )
    generation = database.execute(
        """
        SELECT generation FROM reconciliation_scope_schedules
         WHERE quota_scope_id = 'quota-exclusive'
        """
    ).fetchone()[0]

    with pytest.raises(
        sqlite3.IntegrityError,
        match="reconciliation schedule scope authority mismatch",
    ):
        database.execute(
            """
            UPDATE reconciliation_scope_schedules
               SET quick_baseline_snapshot_id = ?, generation = generation + 1
             WHERE quota_scope_id = 'quota-exclusive' AND generation = ?
            """,
            (foreign_snapshot_id, generation),
        )

    assert not database.in_transaction


def test_schedule_authority_cannot_be_deleted_while_its_scope_exists(
    database: sqlite3.Connection,
) -> None:
    with pytest.raises(
        sqlite3.IntegrityError,
        match="reconciliation schedule authority cannot be deleted",
    ):
        database.execute(
            """
            DELETE FROM reconciliation_scope_schedules
             WHERE quota_scope_id = 'quota-exclusive'
            """
        )

    assert not database.in_transaction
    assert (
        database.execute(
            """
        SELECT COUNT(*) FROM reconciliation_scope_schedules
         WHERE quota_scope_id = 'quota-exclusive'
        """
        ).fetchone()[0]
        == 1
    )


def test_concurrent_scheduled_incident_commits_result_alert_quarantine_and_baselines_once(
    database: sqlite3.Connection,
) -> None:
    _isolate_scheduled_scope(database, "quota-exclusive")
    store = ReconciliationStore(database)
    store.record_snapshot(_snapshot("quota-exclusive", 10, 100), source="summary")
    current_snapshot_id = store.record_snapshot(
        _snapshot("quota-exclusive", 20, 90),
        source="summary",
    )
    generation_before = database.execute(
        """
        SELECT generation FROM reconciliation_scope_schedules
         WHERE quota_scope_id = 'quota-exclusive'
        """
    ).fetchone()[0]
    database_path = Path(database.execute("PRAGMA database_list").fetchone()[2])
    barrier = threading.Barrier(2)
    incident_policy = ReconciliationPolicy(
        0,
        Decimal("0"),
        consecutive_mismatches_for_incident=1,
        maximum_snapshot_age_ms=1_000,
    )

    def reconcile_from_independent_connection() -> ScheduledReconciliationOutcome | None:
        connection = open_compatible_database(database_path, busy_timeout_ms=5_000)
        try:
            barrier.wait(timeout=2)
            return ReconciliationStore(connection).reconcile_next_due_scope(
                policy=incident_policy,
                now_ms=20,
                quick_interval_ms=5,
                full_interval_ms=100,
            )
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(
            future.result(timeout=5)
            for future in (
                executor.submit(reconcile_from_independent_connection),
                executor.submit(reconcile_from_independent_connection),
            )
        )

    recorded = [outcome.recorded for outcome in outcomes if outcome is not None]
    assert len(recorded) == 1
    assert recorded[0] is not None
    assert sum(outcome is None for outcome in outcomes) == 1
    assert recorded[0].decision.incident_required
    assert recorded[0].decision.quarantine_local
    assert (
        database.execute(
            "SELECT COUNT(*) FROM reconciliation_items WHERE quota_scope_id = 'quota-exclusive'"
        ).fetchone()[0]
        == 1
    )
    assert (
        database.execute(
            "SELECT COUNT(*) FROM alerts WHERE category = 'QUOTA_RECONCILIATION_MISMATCH'"
        ).fetchone()[0]
        == 1
    )
    assert (
        database.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = 'quota-exclusive'"
        ).fetchone()[0]
        == "QUARANTINED"
    )
    assert tuple(
        database.execute(
            """
            SELECT state, generation FROM credentials
             WHERE credential_id = 'credential-exclusive'
            """
        ).fetchone()
    ) == ("QUARANTINED", 2)
    assert tuple(
        database.execute(
            """
            SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
                   quick_last_checked_at_ms, full_last_checked_at_ms,
                   generation, last_reconciliation_id
              FROM reconciliation_scope_schedules
             WHERE quota_scope_id = 'quota-exclusive'
            """
        ).fetchone()
    ) == (
        current_snapshot_id,
        current_snapshot_id,
        20,
        20,
        generation_before + 1,
        recorded[0].reconciliation_id,
    )


def test_schedule_advance_failure_rolls_back_result_alert_and_quarantine(
    database: sqlite3.Connection,
) -> None:
    _isolate_scheduled_scope(database, "quota-exclusive")
    store = ReconciliationStore(database)
    store.record_snapshot(_snapshot("quota-exclusive", 10, 100), source="summary")
    store.record_snapshot(_snapshot("quota-exclusive", 20, 90), source="summary")
    schedule_before = tuple(
        database.execute(
            """
            SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
                   quick_last_checked_at_ms, full_last_checked_at_ms,
                   generation, last_reconciliation_id
              FROM reconciliation_scope_schedules
             WHERE quota_scope_id = 'quota-exclusive'
            """
        ).fetchone()
    )
    database.executescript(
        """
        CREATE TRIGGER test_abort_reconciliation_schedule_advance
        BEFORE UPDATE ON reconciliation_scope_schedules
        WHEN OLD.quota_scope_id = 'quota-exclusive'
        BEGIN
            SELECT RAISE(ABORT, 'injected schedule advancement failure');
        END;
        """
    )
    incident_policy = ReconciliationPolicy(
        0,
        Decimal("0"),
        consecutive_mismatches_for_incident=1,
        maximum_snapshot_age_ms=1_000,
    )

    with pytest.raises(sqlite3.IntegrityError, match="injected schedule advancement failure"):
        store.reconcile_next_due_scope(
            policy=incident_policy,
            now_ms=20,
            quick_interval_ms=5,
            full_interval_ms=100,
        )

    assert database.execute("SELECT COUNT(*) FROM reconciliation_runs").fetchone()[0] == 0
    assert database.execute("SELECT COUNT(*) FROM reconciliation_items").fetchone()[0] == 0
    assert database.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert (
        database.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = 'quota-exclusive'"
        ).fetchone()[0]
        == "HEALTHY"
    )
    assert tuple(
        database.execute(
            """
            SELECT state, generation FROM credentials
             WHERE credential_id = 'credential-exclusive'
            """
        ).fetchone()
    ) == ("ACTIVE", 1)
    assert (
        tuple(
            database.execute(
                """
            SELECT quick_baseline_snapshot_id, full_baseline_snapshot_id,
                   quick_last_checked_at_ms, full_last_checked_at_ms,
                   generation, last_reconciliation_id
              FROM reconciliation_scope_schedules
             WHERE quota_scope_id = 'quota-exclusive'
            """
            ).fetchone()
        )
        == schedule_before
    )
    assert not database.in_transaction
