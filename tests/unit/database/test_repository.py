from __future__ import annotations

import tempfile
import threading
import unittest
from collections.abc import Callable
from functools import partial
from pathlib import Path

from gatehouse.core.provider_numbers import SQLITE_INT64_MAX
from gatehouse.database.migrations import open_migrated_database
from gatehouse.database.repository import (
    ApprovalConsumeStatus,
    BalanceAuthorityStatus,
    BalanceAuthorityValidation,
    GatehouseRepository,
    LeaseStatus,
    QuotaReservationStatus,
    validate_balance_authority,
)


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name, "gatehouse.db")
        self.connection = open_migrated_database(self.database_path)
        self.repository = GatehouseRepository(self.connection)
        self._seed_graph()

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def _seed_graph(self) -> None:
        self.connection.execute(
            """
            INSERT INTO clients(
                client_id, display_name, kind, policy_profile,
                created_at_ms, updated_at_ms
            ) VALUES ('client', 'Client', 'interactive', 'default', 0, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO workspaces(
                workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
            ) VALUES ('workspace', 'Workspace', 'E:\\Workspace', 0, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_id, workspace_id, bootstrap_verifier,
                bootstrap_version, token_epoch, state, identity_assurance,
                policy_version, created_at_ms, reconnect_until_ms,
                absolute_expires_at_ms
            ) VALUES ('session', 'client', 'workspace', X'01', 1, 0, 'ACTIVE',
                      'TEST', 'v1', 0, 100000, 100000)
            """
        )
        self.connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, created_at_ms, updated_at_ms
            ) VALUES ('principal', 'firecrawl', 'primary', 0, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit,
                last_known_remaining_units, configured_floor_units
            ) VALUES ('quota', 'principal', 'team', 'HEALTHY', 'credits', NULL, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO quota_snapshots(
                snapshot_id, quota_scope_id, remaining_units, unit,
                captured_at_ms, source, observed_remaining_units_decimal
            ) VALUES ('snapshot-quota', 'quota', 100, 'credits', 0,
                      'unit-test', '100')
            """
        )
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = 100,
                   balance_as_of_ms = 0,
                   balance_snapshot_id = 'snapshot-quota'
             WHERE quota_scope_id = 'quota'
            """
        )
        self.connection.execute(
            """
            INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
            VALUES ('pool', 'firecrawl', 'default', 'ACTIVE', 'pinned')
            """
        )
        for request_id in ("request-a", "request-b", "approval-request"):
            self.connection.execute(
                """
                INSERT INTO invocations(
                    request_id, session_id, service_id, operation,
                    request_fingerprint, fingerprint_version,
                    canonicalization_version, state, priority_class,
                    request_size_bytes, received_at_ms
                ) VALUES (?, 'session', 'firecrawl', 'search', X'AA', 1, 1,
                          'QUEUED', 'INTERACTIVE', 10, 0)
                """,
                (request_id,),
            )

    def _assert_rejected_before_sql(
        self,
        callback: Callable[[], object],
        *,
        snapshot: Callable[[], object],
    ) -> None:
        before = snapshot()
        statements: list[str] = []
        self.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(ValueError):
                callback()
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(statements, [])
        self.assertEqual(snapshot(), before)

    def _reservation_rows(self) -> tuple[tuple[object, ...], ...]:
        return tuple(
            tuple(row)
            for row in self.connection.execute(
                """
                SELECT reservation_id, request_id, quota_scope_id, amount_units,
                       unit, state, actual_units, created_at_ms, expires_at_ms,
                       reconciled_at_ms, metadata_json
                  FROM quota_reservations
                 ORDER BY reservation_id
                """
            ).fetchall()
        )

    def test_active_lease_is_single_holder_but_history_is_retained(self) -> None:
        first = self.repository.acquire_lease(
            lease_type="watcher",
            lease_key="company-watcher",
            owner_id="run-a",
            now_ms=100,
            expires_at_ms=200,
            lease_id="lease-a",
        )
        self.assertEqual(first.status, LeaseStatus.ACQUIRED)

        same_owner = self.repository.acquire_lease(
            lease_type="watcher",
            lease_key="company-watcher",
            owner_id="run-a",
            now_ms=110,
            expires_at_ms=210,
        )
        self.assertEqual(same_owner.status, LeaseStatus.ALREADY_OWNED)
        contender = self.repository.acquire_lease(
            lease_type="watcher",
            lease_key="company-watcher",
            owner_id="run-b",
            now_ms=110,
            expires_at_ms=210,
        )
        self.assertEqual(contender.status, LeaseStatus.BUSY)
        self.assertEqual(contender.owner_id, "run-a")

        self.assertFalse(
            self.repository.release_lease(lease_id="lease-a", owner_id="wrong", now_ms=120)
        )
        self.assertTrue(
            self.repository.release_lease(lease_id="lease-a", owner_id="run-a", now_ms=120)
        )
        second = self.repository.acquire_lease(
            lease_type="watcher",
            lease_key="company-watcher",
            owner_id="run-b",
            now_ms=121,
            expires_at_ms=220,
            lease_id="lease-b",
        )
        self.assertTrue(second.acquired)
        self.assertTrue(
            self.repository.release_lease(lease_id="lease-b", owner_id="run-b", now_ms=130)
        )
        released_count = self.connection.execute(
            "SELECT COUNT(*) FROM leases WHERE state = 'RELEASED'"
        ).fetchone()[0]
        self.assertEqual(released_count, 2)

    def test_expired_lease_can_be_replaced_and_owner_checked_heartbeat(self) -> None:
        self.repository.acquire_lease(
            lease_type="daemon",
            lease_key="singleton",
            owner_id="old",
            now_ms=10,
            expires_at_ms=20,
            lease_id="old-lease",
        )
        replacement = self.repository.acquire_lease(
            lease_type="daemon",
            lease_key="singleton",
            owner_id="new",
            now_ms=20,
            expires_at_ms=40,
            lease_id="new-lease",
        )
        self.assertEqual(replacement.status, LeaseStatus.ACQUIRED)
        self.assertFalse(
            self.repository.heartbeat_lease(
                lease_id="new-lease", owner_id="old", now_ms=21, expires_at_ms=50
            )
        )
        self.assertTrue(
            self.repository.heartbeat_lease(
                lease_id="new-lease", owner_id="new", now_ms=21, expires_at_ms=50
            )
        )

    def test_credential_lease_absent_authority_requires_reconciliation_affinity(self) -> None:
        self.connection.execute(
            """
            INSERT INTO credentials(
                credential_id, principal_id, quota_scope_id, alias,
                secret_backend, secret_reference, state, generation, created_at_ms
            ) VALUES ('credential', 'principal', 'quota', 'primary',
                      'test', 'opaque', 'HEALTHY', 1, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
            VALUES ('pool', 'quota', 1, 1, 1)
            """
        )
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = NULL,
                   balance_as_of_ms = NULL,
                   balance_snapshot_id = NULL
             WHERE quota_scope_id = 'quota'
            """
        )

        ordinary = self.repository.acquire_credential_lease(
            credential_id="credential",
            credential_generation=1,
            quota_scope_id="quota",
            pool_id="pool",
            owner_id="request-a",
            now_ms=10,
            expires_at_ms=20,
            exact_affinity=True,
            lease_id="ordinary-lease",
        )
        self.assertEqual(ordinary.status, LeaseStatus.INELIGIBLE)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0],
            0,
        )

        cleanup = self.repository.acquire_credential_lease(
            credential_id="credential",
            credential_generation=1,
            quota_scope_id="quota",
            pool_id="pool",
            owner_id="request-a",
            now_ms=10,
            expires_at_ms=20,
            exact_affinity=True,
            reconciliation=True,
            lease_id="cleanup-lease",
        )
        self.assertEqual(cleanup.status, LeaseStatus.ACQUIRED)

    def test_concurrent_quota_reservations_cannot_oversubscribe(self) -> None:
        barrier = threading.Barrier(3)
        results = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def reserve(request_id: str) -> None:
            connection = open_migrated_database(self.database_path)
            try:
                repository = GatehouseRepository(connection)
                barrier.wait(timeout=5)
                result = repository.reserve_quota(
                    request_id=request_id,
                    quota_scope_id="quota",
                    amount_units=60,
                    unit="credits",
                    now_ms=100,
                    expires_at_ms=1_000,
                )
                with lock:
                    results.append(result)
            except BaseException as error:
                with lock:
                    errors.append(error)
            finally:
                connection.close()

        threads = [
            threading.Thread(target=reserve, args=(request_id,))
            for request_id in ("request-a", "request-b")
        ]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=10)

        self.assertFalse(errors)
        self.assertEqual(len(results), 2)
        self.assertEqual(
            sorted(result.status for result in results),
            sorted(
                [
                    QuotaReservationStatus.RESERVED,
                    QuotaReservationStatus.EXHAUSTED,
                ]
            ),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT SUM(amount_units) FROM quota_reservations WHERE state = 'ACTIVE'"
            ).fetchone()[0],
            60,
        )

    def test_ambiguous_quota_outcome_is_retained_for_reconciliation(self) -> None:
        reservation = self.repository.reserve_quota(
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=25,
            unit="credits",
            now_ms=100,
            expires_at_ms=1_000,
            reservation_id="reservation-a",
        )
        self.assertTrue(reservation.reserved)
        with self.assertRaisesRegex(ValueError, "require actual_units"):
            self.repository.reconcile_quota_reservation(
                reservation_id="reservation-a",
                actual_units=None,
                now_ms=125,
                outcome_known=True,
            )
        with self.assertRaisesRegex(ValueError, "cannot assert actual_units"):
            self.repository.reconcile_quota_reservation(
                reservation_id="reservation-a",
                actual_units=25,
                now_ms=125,
                outcome_known=False,
            )
        self.assertTrue(
            self.repository.reconcile_quota_reservation(
                reservation_id="reservation-a",
                actual_units=None,
                now_ms=150,
                outcome_known=False,
            )
        )
        row = self.connection.execute(
            "SELECT state, reconciled_at_ms FROM quota_reservations WHERE reservation_id = ?",
            ("reservation-a",),
        ).fetchone()
        self.assertEqual(row["state"], "PENDING_RECONCILIATION")
        self.assertIsNone(row["reconciled_at_ms"])

    def test_invalid_reservation_units_are_rejected_before_any_sql(self) -> None:
        for invalid in (True, SQLITE_INT64_MAX + 1):
            with self.subTest(invalid=invalid):
                self._assert_rejected_before_sql(
                    partial(
                        self.repository.reserve_quota,
                        request_id="request-a",
                        quota_scope_id="quota",
                        amount_units=invalid,
                        unit="credits",
                        now_ms=100,
                        expires_at_ms=1_000,
                    ),
                    snapshot=self._reservation_rows,
                )

    def test_invalid_replacement_units_leave_expired_reservation_unchanged(self) -> None:
        result = self.repository.reserve_quota(
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=10,
            unit="credits",
            now_ms=0,
            expires_at_ms=10,
            reservation_id="old-reservation",
        )
        self.assertTrue(result.reserved)

        for invalid in (True, SQLITE_INT64_MAX + 1):
            with self.subTest(invalid=invalid):
                self._assert_rejected_before_sql(
                    partial(
                        self.repository.replace_quota_reservation,
                        old_reservation_id="old-reservation",
                        request_id="request-a",
                        quota_scope_id="quota",
                        amount_units=invalid,
                        unit="credits",
                        now_ms=10,
                        expires_at_ms=100,
                    ),
                    snapshot=self._reservation_rows,
                )

    def test_invalid_settlement_units_leave_reservation_unchanged(self) -> None:
        result = self.repository.reserve_quota(
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=10,
            unit="credits",
            now_ms=0,
            expires_at_ms=100,
            reservation_id="reservation-to-settle",
        )
        self.assertTrue(result.reserved)

        for invalid in (True, SQLITE_INT64_MAX + 1):
            with self.subTest(invalid=invalid):
                self._assert_rejected_before_sql(
                    partial(
                        self.repository.reconcile_quota_reservation,
                        reservation_id="reservation-to-settle",
                        actual_units=invalid,
                        now_ms=10,
                        outcome_known=True,
                    ),
                    snapshot=self._reservation_rows,
                )

    def test_atomic_reservation_fails_closed_on_noncanonical_durable_observation(self) -> None:
        self.connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
        self.connection.execute(
            """
            UPDATE quota_snapshots
               SET observed_remaining_units_decimal = '100.0'
             WHERE snapshot_id = 'snapshot-quota'
            """
        )

        result = self.repository.reserve_quota(
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=1,
            unit="credits",
            now_ms=100,
            expires_at_ms=1_000,
        )

        self.assertEqual(result.status, QuotaReservationStatus.INELIGIBLE)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM quota_reservations").fetchone()[0],
            0,
        )

    def test_balance_authority_requires_exact_scope_unit_time_and_projection(self) -> None:
        def validate(
            *,
            quota_scope_id: object = "quota",
            unit: object = "credits",
            remaining: object = 100,
            captured_at_ms: object = 0,
            snapshot_id: object = "snapshot-quota",
        ) -> BalanceAuthorityValidation:
            return validate_balance_authority(
                self.connection,
                quota_scope_id=quota_scope_id,
                unit=unit,
                last_known_remaining_units=remaining,
                balance_as_of_ms=captured_at_ms,
                balance_snapshot_id=snapshot_id,
            )

        valid = validate()
        self.assertEqual(valid.status, BalanceAuthorityStatus.VALID)
        self.assertIsNotNone(valid.authority)
        self.assertEqual(
            validate(remaining=None, captured_at_ms=None, snapshot_id=None).status,
            BalanceAuthorityStatus.ABSENT,
        )
        self.assertEqual(
            validate(remaining=None, captured_at_ms=0, snapshot_id=None).status,
            BalanceAuthorityStatus.CORRUPT,
        )
        for result in (
            validate(quota_scope_id="other-quota"),
            validate(unit="requests"),
            validate(remaining=99),
            validate(captured_at_ms=1),
            validate(captured_at_ms=SQLITE_INT64_MAX + 1),
            validate(snapshot_id="other-snapshot"),
        ):
            self.assertEqual(result.status, BalanceAuthorityStatus.CORRUPT)
            self.assertIsNone(result.authority)

    def test_atomic_reservation_distinguishes_absent_balance_authority(self) -> None:
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = NULL,
                   balance_as_of_ms = NULL,
                   balance_snapshot_id = NULL
             WHERE quota_scope_id = 'quota'
            """
        )

        before = self._reservation_rows()
        result = self.repository.reserve_quota(
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=1,
            unit="credits",
            now_ms=100,
            expires_at_ms=1_000,
        )

        self.assertEqual(result.status, QuotaReservationStatus.UNKNOWN_BALANCE)
        self.assertEqual(self._reservation_rows(), before)

    def test_atomic_replacement_does_not_settle_old_hold_for_absent_or_corrupt_authority(
        self,
    ) -> None:
        result = self.repository.reserve_quota(
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=10,
            unit="credits",
            now_ms=0,
            expires_at_ms=10,
            reservation_id="old-authority-hold",
        )
        self.assertTrue(result.reserved)
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = NULL,
                   balance_as_of_ms = NULL,
                   balance_snapshot_id = NULL
             WHERE quota_scope_id = 'quota'
            """
        )

        before_absent = self._reservation_rows()
        absent = self.repository.replace_quota_reservation(
            old_reservation_id="old-authority-hold",
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=1,
            unit="credits",
            now_ms=10,
            expires_at_ms=100,
        )
        self.assertEqual(absent.status, QuotaReservationStatus.UNKNOWN_BALANCE)
        self.assertEqual(self._reservation_rows(), before_absent)

        self.connection.execute("DROP TRIGGER quota_scopes_balance_authority_update")
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = 100
             WHERE quota_scope_id = 'quota'
            """
        )
        before_corrupt = self._reservation_rows()
        corrupt = self.repository.replace_quota_reservation(
            old_reservation_id="old-authority-hold",
            request_id="request-a",
            quota_scope_id="quota",
            amount_units=1,
            unit="credits",
            now_ms=10,
            expires_at_ms=100,
        )
        self.assertEqual(corrupt.status, QuotaReservationStatus.INELIGIBLE)
        self.assertEqual(self._reservation_rows(), before_corrupt)

    def _insert_approval(
        self,
        approval_id: str,
        *,
        expires_at_ms: int = 1_000,
        maximum_uses: int = 1,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO approvals(
                approval_id, request_id, request_fingerprint, session_id,
                service_id, operation, state, maximum_uses, maximum_cost_units,
                cost_unit, pool_id, created_at_ms, expires_at_ms, decided_at_ms
            ) VALUES (?, 'approval-request', X'010203', 'session', 'firecrawl',
                      'crawl', 'APPROVED', ?, 25, 'credits', 'pool', 0, ?, 1)
            """,
            (approval_id, maximum_uses, expires_at_ms),
        )

    def test_approval_is_bound_and_consumed_exactly_once(self) -> None:
        self._insert_approval("approval")
        mismatch = self.repository.consume_approval(
            approval_id="approval",
            session_id="other-session",
            service_id="firecrawl",
            operation="crawl",
            request_fingerprint=b"\x01\x02\x03",
            pool_id="pool",
            estimated_cost_units=20,
            cost_unit="credits",
            now_ms=10,
        )
        self.assertEqual(mismatch.status, ApprovalConsumeStatus.BINDING_MISMATCH)

        consumed = self.repository.consume_approval(
            approval_id="approval",
            session_id="session",
            service_id="firecrawl",
            operation="crawl",
            request_fingerprint=b"\x01\x02\x03",
            pool_id="pool",
            estimated_cost_units=20,
            cost_unit="credits",
            now_ms=10,
        )
        self.assertTrue(consumed.consumed)
        replay = self.repository.consume_approval(
            approval_id="approval",
            session_id="session",
            service_id="firecrawl",
            operation="crawl",
            request_fingerprint=b"\x01\x02\x03",
            pool_id="pool",
            estimated_cost_units=20,
            cost_unit="credits",
            now_ms=11,
        )
        self.assertEqual(replay.status, ApprovalConsumeStatus.INACTIVE)

    def test_approval_cost_and_expiry_fail_closed(self) -> None:
        self._insert_approval("cost")
        result = self.repository.consume_approval(
            approval_id="cost",
            session_id="session",
            service_id="firecrawl",
            operation="crawl",
            request_fingerprint=b"\x01\x02\x03",
            pool_id="pool",
            estimated_cost_units=26,
            cost_unit="credits",
            now_ms=10,
        )
        self.assertEqual(result.status, ApprovalConsumeStatus.COST_EXCEEDED)

        self._insert_approval("expired", expires_at_ms=10)
        expired = self.repository.consume_approval(
            approval_id="expired",
            session_id="session",
            service_id="firecrawl",
            operation="crawl",
            request_fingerprint=b"\x01\x02\x03",
            pool_id="pool",
            estimated_cost_units=1,
            cost_unit="credits",
            now_ms=10,
        )
        self.assertEqual(expired.status, ApprovalConsumeStatus.EXPIRED)

    def test_invalid_approval_cost_is_rejected_before_any_sql_or_expiry_mutation(self) -> None:
        self._insert_approval("invalid-cost", expires_at_ms=10)

        def approval_rows() -> tuple[tuple[object, ...], ...]:
            return tuple(
                tuple(row)
                for row in self.connection.execute(
                    """
                    SELECT approval_id, state, uses_consumed, consumed_at_ms
                      FROM approvals
                     WHERE approval_id = 'invalid-cost'
                    """
                ).fetchall()
            )

        for invalid in (True, SQLITE_INT64_MAX + 1):
            with self.subTest(invalid=invalid):
                self._assert_rejected_before_sql(
                    partial(
                        self.repository.consume_approval,
                        approval_id="invalid-cost",
                        session_id="session",
                        service_id="firecrawl",
                        operation="crawl",
                        request_fingerprint=b"\x01\x02\x03",
                        pool_id="pool",
                        estimated_cost_units=invalid,
                        cost_unit="credits",
                        now_ms=10,
                    ),
                    snapshot=approval_rows,
                )


if __name__ == "__main__":
    unittest.main()
