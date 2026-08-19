from __future__ import annotations

from pathlib import Path

from gatehouse.database import (
    GatehouseRepository,
    QuotaReservationResult,
    QuotaReservationStatus,
    open_migrated_database,
)
from gatehouse.reconciliation import ReconciliationStore, UsageSnapshot


def _seed_database(database_path: Path) -> None:
    connection = open_migrated_database(database_path)
    try:
        connection.execute(
            """
            INSERT INTO clients(
                client_id, display_name, kind, policy_profile,
                created_at_ms, updated_at_ms
            ) VALUES ('client', 'Client', 'test', 'default', 0, 0)
            """
        )
        connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_id, bootstrap_verifier, bootstrap_version,
                token_epoch, state, identity_assurance, policy_version,
                created_at_ms, reconnect_until_ms, absolute_expires_at_ms
            ) VALUES ('session', 'client', X'01', 1, 0, 'ACTIVE', 'TEST', 'v1',
                      0, 100000, 100000)
            """
        )
        connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, created_at_ms, updated_at_ms
            ) VALUES ('principal', 'service', 'primary', 0, 0)
            """
        )
        connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit,
                last_known_remaining_units, configured_floor_units
            ) VALUES ('quota', 'principal', 'primary', 'HEALTHY', 'credits', 100, 0)
            """
        )
        for ordinal in range(1, 13):
            connection.execute(
                """
                INSERT INTO invocations(
                    request_id, session_id, service_id, operation,
                    request_fingerprint, fingerprint_version,
                    canonicalization_version, state, priority_class,
                    request_size_bytes, received_at_ms
                ) VALUES (?, 'session', 'service', 'read', X'AA', 1, 1,
                          'QUEUED', 'INTERACTIVE', 1, 0)
                """,
                (f"request-{ordinal}",),
            )
    finally:
        connection.close()


def _reserve(
    repository: GatehouseRepository,
    *,
    request_number: int,
    amount_units: int,
    now_ms: int,
) -> QuotaReservationResult:
    return repository.reserve_quota(
        request_id=f"request-{request_number}",
        quota_scope_id="quota",
        amount_units=amount_units,
        unit="credits",
        now_ms=now_ms,
        expires_at_ms=now_ms + 1_000,
        reservation_id=f"reservation-{request_number}",
    )


def test_reconciled_usage_survives_restart_and_reduces_next_admission(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)

    connection = open_migrated_database(database_path)
    repository = GatehouseRepository(connection)
    first = _reserve(repository, request_number=1, amount_units=60, now_ms=10)
    assert first.status is QuotaReservationStatus.RESERVED
    assert repository.reconcile_quota_reservation(
        reservation_id="reservation-1",
        actual_units=60,
        now_ms=20,
        outcome_known=True,
    )
    connection.close()

    connection = open_migrated_database(database_path)
    try:
        result = _reserve(
            GatehouseRepository(connection),
            request_number=2,
            amount_units=50,
            now_ms=30,
        )
        assert result.status is QuotaReservationStatus.EXHAUSTED
        assert result.available_before_units == 40
        assert result.available_after_units == 40
    finally:
        connection.close()


def test_identical_settlement_is_idempotent_without_double_debit(tmp_path: Path) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)
    connection = open_migrated_database(database_path)
    try:
        repository = GatehouseRepository(connection)
        reservation = _reserve(
            repository,
            request_number=1,
            amount_units=60,
            now_ms=10,
        )
        assert reservation.status is QuotaReservationStatus.RESERVED
        assert repository.reconcile_quota_reservation(
            reservation_id="reservation-1",
            actual_units=90,
            now_ms=20,
            outcome_known=True,
        )
        assert repository.reconcile_quota_reservation(
            reservation_id="reservation-1",
            actual_units=90,
            now_ms=20,
            outcome_known=True,
        )

        result = _reserve(repository, request_number=2, amount_units=20, now_ms=30)
        assert result.status is QuotaReservationStatus.EXHAUSTED
        assert result.available_before_units == 10
        assert result.available_after_units == 10
    finally:
        connection.close()


def test_settlement_releases_unused_estimate_before_next_reservation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)
    connection = open_migrated_database(database_path)
    try:
        repository = GatehouseRepository(connection)
        reservation = _reserve(
            repository,
            request_number=1,
            amount_units=60,
            now_ms=10,
        )
        assert reservation.status is QuotaReservationStatus.RESERVED
        assert repository.reconcile_quota_reservation(
            reservation_id="reservation-1",
            actual_units=20,
            now_ms=20,
            outcome_known=True,
        )

        result = _reserve(repository, request_number=2, amount_units=80, now_ms=30)
        assert result.status is QuotaReservationStatus.RESERVED
        assert result.available_before_units == 80
        assert result.available_after_units == 0
    finally:
        connection.close()


def test_authoritative_remaining_snapshot_advances_balance_watermark_only(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)
    connection = open_migrated_database(database_path)
    try:
        repository = GatehouseRepository(connection)
        first = _reserve(repository, request_number=1, amount_units=30, now_ms=10)
        assert first.status is QuotaReservationStatus.RESERVED
        assert repository.reconcile_quota_reservation(
            reservation_id="reservation-1",
            actual_units=30,
            now_ms=20,
            outcome_known=True,
        )

        snapshots = ReconciliationStore(connection)
        snapshots.record_snapshot(
            UsageSnapshot(
                quota_scope_id="quota",
                unit="credits",
                captured_at_ms=30,
                remaining_units=70,
                snapshot_id="snapshot-authoritative",
            ),
            source="provider-summary",
        )
        second = _reserve(repository, request_number=2, amount_units=70, now_ms=40)
        assert second.status is QuotaReservationStatus.RESERVED
        assert second.available_before_units == 70
        assert repository.reconcile_quota_reservation(
            reservation_id="reservation-2",
            actual_units=70,
            now_ms=50,
            outcome_known=True,
        )

        snapshots.record_snapshot(
            UsageSnapshot(
                quota_scope_id="quota",
                unit="credits",
                captured_at_ms=25,
                remaining_units=100,
                snapshot_id="snapshot-stale",
            ),
            source="provider-summary",
        )
        row = connection.execute(
            """
            SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
              FROM quota_scopes WHERE quota_scope_id = 'quota'
            """
        ).fetchone()
        assert tuple(row) == (70, 30, "snapshot-authoritative")

        snapshots.record_snapshot(
            UsageSnapshot(
                quota_scope_id="quota",
                unit="credits",
                captured_at_ms=60,
                used_units=100,
                snapshot_id="snapshot-used-only",
            ),
            source="provider-summary",
        )
        row = connection.execute(
            """
            SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
              FROM quota_scopes WHERE quota_scope_id = 'quota'
            """
        ).fetchone()
        assert tuple(row) == (70, 30, "snapshot-authoritative")

        exhausted = _reserve(repository, request_number=3, amount_units=1, now_ms=70)
        assert exhausted.status is QuotaReservationStatus.EXHAUSTED
        assert exhausted.available_before_units == 0
        assert exhausted.available_after_units == 0
    finally:
        connection.close()
