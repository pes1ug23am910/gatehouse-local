from __future__ import annotations

import threading
from pathlib import Path

from gatehouse.database import (
    GatehouseRepository,
    QuotaReservationStatus,
    open_migrated_database,
)


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
        for scope_id, remaining_units in (
            ("quota-primary", 100),
            ("quota-secondary", 50),
        ):
            connection.execute(
                """
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    last_known_remaining_units, configured_floor_units
                ) VALUES (?, 'principal', ?, 'HEALTHY', 'credits', NULL, 0)
                """,
                (scope_id, scope_id),
            )
            connection.execute(
                """
                INSERT INTO credentials(
                    credential_id, principal_id, quota_scope_id, alias,
                    secret_backend, secret_reference, state, generation, created_at_ms,
                    credential_role
                ) VALUES (?, 'principal', ?, ?, 'test', ?, 'HEALTHY', 1, 0, 'OBSERVER')
                """,
                (
                    f"observer-{scope_id}",
                    scope_id,
                    f"observer-{scope_id}",
                    f"reference-{scope_id}",
                ),
            )
            connection.execute(
                """
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, unit,
                    captured_at_ms, source, observed_remaining_units_decimal,
                    quota_dimension_id, credential_id, credential_generation,
                    stale_at_ms, observation_kind
                ) VALUES (?, ?, ?, 'credits', 0, 'integration-test', ?, ?, ?, 1,
                          9223372036854775807, 'AUTHENTICATED')
                """,
                (
                    f"snapshot-{scope_id}",
                    scope_id,
                    remaining_units,
                    str(remaining_units),
                    f"dimension_legacy_primary:{scope_id}",
                    f"observer-{scope_id}",
                ),
            )
            connection.execute(
                """
                UPDATE quota_scopes
                   SET last_known_remaining_units = ?,
                       balance_as_of_ms = 0,
                       balance_snapshot_id = ?
                 WHERE quota_scope_id = ?
                """,
                (remaining_units, f"snapshot-{scope_id}", scope_id),
            )
        for request_id in ("request-a", "request-b"):
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
                (request_id,),
            )
    finally:
        connection.close()


def _reserve(
    repository: GatehouseRepository,
    *,
    reservation_id: str,
    request_id: str,
    quota_scope_id: str,
    amount_units: int,
    expires_at_ms: int,
) -> None:
    result = repository.reserve_quota(
        request_id=request_id,
        quota_scope_id=quota_scope_id,
        amount_units=amount_units,
        unit="credits",
        now_ms=0,
        expires_at_ms=expires_at_ms,
        reservation_id=reservation_id,
    )
    assert result.status is QuotaReservationStatus.RESERVED


def test_expired_replacement_settles_zero_and_excludes_old_same_scope_capacity(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)
    connection = open_migrated_database(database_path)
    try:
        repository = GatehouseRepository(connection)
        _reserve(
            repository,
            reservation_id="old",
            request_id="request-a",
            quota_scope_id="quota-primary",
            amount_units=80,
            expires_at_ms=100,
        )
        _reserve(
            repository,
            reservation_id="other-active",
            request_id="request-b",
            quota_scope_id="quota-primary",
            amount_units=10,
            expires_at_ms=1_000,
        )

        result = repository.replace_quota_reservation(
            old_reservation_id="old",
            request_id="request-a",
            quota_scope_id="quota-primary",
            amount_units=90,
            unit="credits",
            now_ms=100,
            expires_at_ms=1_100,
            reservation_id="replacement",
            metadata={"reason": "expired_while_queued"},
        )

        assert result.status is QuotaReservationStatus.RESERVED
        assert result.reservation_id == "replacement"
        assert result.available_before_units == 90
        assert result.available_after_units == 0
        rows = connection.execute(
            """
            SELECT reservation_id, state, actual_units, reconciled_at_ms
              FROM quota_reservations
             WHERE request_id = 'request-a'
             ORDER BY reservation_id
            """
        ).fetchall()
        assert [tuple(row) for row in rows] == [
            ("old", "RECONCILED", 0, 100),
            ("replacement", "ACTIVE", None, None),
        ]
    finally:
        connection.close()


def test_exhausted_replacement_rolls_back_old_settlement_and_new_insert(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)
    connection = open_migrated_database(database_path)
    try:
        repository = GatehouseRepository(connection)
        _reserve(
            repository,
            reservation_id="old",
            request_id="request-a",
            quota_scope_id="quota-primary",
            amount_units=20,
            expires_at_ms=100,
        )
        _reserve(
            repository,
            reservation_id="secondary-full",
            request_id="request-b",
            quota_scope_id="quota-secondary",
            amount_units=50,
            expires_at_ms=1_000,
        )

        result = repository.replace_quota_reservation(
            old_reservation_id="old",
            request_id="request-a",
            quota_scope_id="quota-secondary",
            amount_units=1,
            unit="credits",
            now_ms=100,
            expires_at_ms=1_100,
            reservation_id="must-not-exist",
        )

        assert result.status is QuotaReservationStatus.EXHAUSTED
        assert result.reservation_id is None
        assert result.available_before_units == 0
        assert result.available_after_units == 0
        old = connection.execute(
            """
            SELECT state, actual_units, reconciled_at_ms
              FROM quota_reservations WHERE reservation_id = 'old'
            """
        ).fetchone()
        assert old is not None
        assert tuple(old) == ("ACTIVE", None, None)
        assert (
            connection.execute(
                """
                SELECT COUNT(*) FROM quota_reservations
                 WHERE reservation_id = 'must-not-exist'
                """
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()


def test_concurrent_expired_replacement_has_exactly_one_winner(tmp_path: Path) -> None:
    database_path = tmp_path / "gatehouse.db"
    _seed_database(database_path)
    setup_connection = open_migrated_database(database_path)
    try:
        _reserve(
            GatehouseRepository(setup_connection),
            reservation_id="old",
            request_id="request-a",
            quota_scope_id="quota-primary",
            amount_units=100,
            expires_at_ms=100,
        )
    finally:
        setup_connection.close()

    barrier = threading.Barrier(3)
    results = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def replace(candidate_id: str) -> None:
        connection = open_migrated_database(database_path)
        try:
            repository = GatehouseRepository(connection)
            barrier.wait(timeout=5)
            result = repository.replace_quota_reservation(
                old_reservation_id="old",
                request_id="request-a",
                quota_scope_id="quota-primary",
                amount_units=100,
                unit="credits",
                now_ms=100,
                expires_at_ms=1_100,
                reservation_id=candidate_id,
            )
            with lock:
                results.append(result)
        except BaseException as error:
            with lock:
                errors.append(error)
        finally:
            connection.close()

    threads = [
        threading.Thread(target=replace, args=(candidate_id,))
        for candidate_id in ("replacement-a", "replacement-b")
    ]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert len(results) == 2
    assert sum(result.reserved for result in results) == 1

    connection = open_migrated_database(database_path)
    try:
        old = connection.execute(
            """
            SELECT state, actual_units, reconciled_at_ms
              FROM quota_reservations WHERE reservation_id = 'old'
            """
        ).fetchone()
        assert old is not None
        assert tuple(old) == ("RECONCILED", 0, 100)
        active_replacements = connection.execute(
            """
            SELECT reservation_id
              FROM quota_reservations
             WHERE reservation_id IN ('replacement-a', 'replacement-b')
               AND state = 'ACTIVE'
            """
        ).fetchall()
        assert len(active_replacements) == 1
    finally:
        connection.close()
