from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gatehouse.database.migrations import open_migrated_database
from gatehouse.database.recovery import recover_startup
from gatehouse.database.retention import (
    RetentionPolicy,
    apply_retention,
    checkpoint_wal,
    database_footprint,
)


class RecoveryRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name, "gatehouse.db")
        self.connection = open_migrated_database(self.database_path)
        self._seed_base()

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def _seed_base(self) -> None:
        self.connection.execute(
            """
            INSERT INTO clients(
                client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
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
        for session_id, expires_at in (("active-session", 1_000), ("old-session", 50)):
            self.connection.execute(
                """
                INSERT INTO sessions(
                    session_id, client_id, workspace_id, bootstrap_verifier,
                    bootstrap_version, token_epoch, state, identity_assurance,
                    policy_version, created_at_ms, reconnect_until_ms,
                    absolute_expires_at_ms
                ) VALUES (?, 'client', 'workspace', X'01', 1, 0, 'ACTIVE',
                          'TEST', 'v1', 0, 500, ?)
                """,
                (session_id, expires_at),
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
                last_known_remaining_units
            ) VALUES ('quota', 'principal', 'team', 'HEALTHY', 'credits', NULL)
            """
        )
        self.connection.execute(
            """
            INSERT INTO credentials(
                credential_id, principal_id, quota_scope_id, alias,
                secret_backend, secret_reference, state, generation, created_at_ms
            ) VALUES ('credential', 'principal', 'quota', 'primary',
                      'test', 'reference', 'ACTIVE', 1, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO quota_snapshots(
                snapshot_id, quota_scope_id, remaining_units,
                observed_remaining_units_decimal, unit, captured_at_ms, source,
                quota_dimension_id, credential_id, credential_generation,
                stale_at_ms, observation_kind
            ) VALUES ('snapshot-quota-fixture', 'quota', 100, '100',
                      'credits', 0, 'recovery-fixture',
                      'dimension_legacy_primary:quota', 'credential', 1,
                      9223372036854775807, 'AUTHENTICATED')
            """
        )
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = 100,
                   balance_as_of_ms = 0,
                   balance_snapshot_id = 'snapshot-quota-fixture'
             WHERE quota_scope_id = 'quota'
            """
        )
        self.connection.execute(
            """
            INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
            VALUES ('pool', 'firecrawl', 'default', 'ACTIVE', 'CHEAPEST_FIRST')
            """
        )
        self.connection.execute(
            "INSERT INTO pool_members(pool_id, quota_scope_id) VALUES ('pool', 'quota')"
        )

    def _insert_invocation(self, request_id: str, state: str) -> None:
        self.connection.execute(
            """
            INSERT INTO invocations(
                request_id, session_id, service_id, operation, request_fingerprint,
                fingerprint_version, canonicalization_version, state, priority_class,
                request_size_bytes, received_at_ms
            ) VALUES (?, 'active-session', 'firecrawl', 'search', X'01', 1, 1,
                      ?, 'INTERACTIVE', 1, 0)
            """,
            (request_id, state),
        )

    def test_startup_recovery_is_conservative_and_epoch_based(self) -> None:
        for request_id, state in (
            ("expired-queue-request", "QUEUED"),
            ("requeue-request", "QUEUED"),
            ("running-request", "RUNNING"),
            ("coalesced-request", "DUPLICATE_IN_FLIGHT"),
        ):
            self._insert_invocation(request_id, state)
        self.connection.executemany(
            """
            INSERT INTO queue_entries(
                queue_id, request_id, state, priority_class, session_id,
                service_id, operation, enqueued_at_ms, deadline_ms,
                claimed_at_ms, claim_owner, claim_expires_at_ms
            ) VALUES (?, ?, ?, 'INTERACTIVE', 'active-session', 'firecrawl',
                      'search', 0, ?, 10, 'worker', 200)
            """,
            (
                ("queue-expired", "expired-queue-request", "CLAIMED", 90),
                ("queue-requeue", "requeue-request", "CLAIMED", 200),
                ("queue-running", "running-request", "CLAIMED", 200),
            ),
        )
        self.connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, request_id, ordinal, credential_id, principal_id,
                quota_scope_id, state, started_at_ms,
                dispatch_credential_generation, dispatch_pool_id
            ) VALUES ('attempt', 'running-request', 1, 'credential', 'principal',
                      'quota', 'RUNNING', 50, 1, 'pool')
            """
        )
        self.connection.execute(
            """
            INSERT INTO quota_reservations(
                reservation_id, request_id, quota_scope_id, amount_units,
                unit, state, created_at_ms, expires_at_ms
            ) VALUES ('reservation', 'running-request', 'quota', 10,
                      'credits', 'ACTIVE', 0, 90)
            """
        )
        self.connection.execute(
            """
            INSERT INTO approvals(
                approval_id, request_id, request_fingerprint, session_id,
                service_id, operation, state, created_at_ms, expires_at_ms
            ) VALUES ('approval', 'running-request', X'01', 'active-session',
                      'firecrawl', 'search', 'APPROVED', 0, 90)
            """
        )
        self.connection.execute(
            """
            INSERT INTO admin_sessions(
                admin_session_id, cookie_verifier, csrf_verifier, token_epoch,
                state, created_at_ms, last_seen_at_ms, idle_expires_at_ms,
                absolute_expires_at_ms
            ) VALUES ('admin', X'01', X'02', 0, 'ACTIVE', 0, 0, 500, 500)
            """
        )
        self.connection.execute(
            """
            INSERT INTO leases(
                lease_id, lease_type, lease_key, owner_id, state, acquired_at_ms,
                heartbeat_at_ms, expires_at_ms
            ) VALUES ('lease', 'watcher', 'singleton', 'run', 'ACTIVE', 0, 0, 90)
            """
        )
        self.connection.execute(
            """
            INSERT INTO jobs(
                job_id, request_id, service_id, operation, state,
                provider_job_id, created_at_ms
            ) VALUES ('job', 'running-request', 'firecrawl', 'crawl', 'RUNNING',
                      'provider-job', 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO feed_sets(
                feed_set_id, workspace_id, policy_version, state,
                config_json, created_at_ms, updated_at_ms
            ) VALUES ('feeds', 'workspace', 'v1', 'ACTIVE', '{}', 0, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO watcher_runs(
                watcher_run_id, session_id, feed_set_id, state, started_at_ms,
                heartbeat_at_ms, maximum_runtime_at_ms, cost_unit
            ) VALUES ('watcher-run', 'active-session', 'feeds', 'RUNNING',
                      0, 50, 500, 'credits')
            """
        )

        report = recover_startup(self.connection, now_ms=100)
        self.assertEqual(report.token_epoch, 1)
        self.assertEqual(report.sessions_expired, 1)
        self.assertEqual(report.sessions_disconnected, 1)
        self.assertEqual(report.approvals_expired, 1)
        self.assertEqual(report.admin_sessions_revoked, 1)
        self.assertEqual(report.leases_expired, 1)
        self.assertEqual(report.coalesced_results_lost, 1)
        self.assertEqual(report.queue_entries_expired, 1)
        self.assertEqual(report.queue_entries_requeued, 1)
        self.assertEqual(report.queue_entries_flagged, 1)
        self.assertEqual(report.invocations_unknown, 1)
        self.assertEqual(report.attempts_unknown, 1)
        self.assertEqual(report.reservations_pending_reconciliation, 1)
        self.assertEqual(report.jobs_recovering, 1)
        self.assertEqual(report.watcher_runs_recovering, 1)
        self.assertEqual(
            tuple(
                self.connection.execute(
                    """
                    SELECT state, error_code FROM invocations
                     WHERE request_id = 'coalesced-request'
                    """
                ).fetchone()
            ),
            ("FAILED", "result_unavailable_after_restart"),
        )

        states = dict(
            self.connection.execute(
                "SELECT queue_id, state FROM queue_entries ORDER BY queue_id"
            ).fetchall()
        )
        self.assertEqual(states["queue-expired"], "EXPIRED")
        self.assertEqual(states["queue-requeue"], "QUEUED")
        self.assertEqual(states["queue-running"], "RECOVERY_REQUIRED")
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM quota_reservations WHERE reservation_id = 'reservation'"
            ).fetchone()[0],
            "PENDING_RECONCILIATION",
        )

    def test_retention_is_bounded_and_preserves_flagged_events(self) -> None:
        self._insert_invocation("retention-request", "SUCCEEDED")
        self.connection.executemany(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity, preserve, payload_json
            ) VALUES (?, 0, 'test', 'INFO', ?, '{}')
            """,
            (("delete-a", 0), ("delete-b", 0), ("preserve", 1)),
        )
        self.connection.executemany(
            """
            INSERT INTO debug_excerpts(
                excerpt_id, session_id, reason, redacted_excerpt,
                size_bytes, created_at_ms, expires_at_ms
            ) VALUES (?, 'active-session', 'test', '[redacted]', 10, 0, 10)
            """,
            (("debug-a",), ("debug-b",)),
        )
        self.connection.executemany(
            """
            INSERT INTO daily_usage_aggregates(
                aggregate_id, day_utc, service_id, request_count,
                success_count, actual_cost_units, cost_unit, created_at_ms
            ) VALUES (?, ?, 'firecrawl', 1, 1, 1, 'credits', 0)
            """,
            (("daily-a", "1970-01-01"), ("daily-b", "1970-01-02")),
        )
        self.connection.execute(
            """
            INSERT INTO admin_sessions(
                admin_session_id, cookie_verifier, csrf_verifier, token_epoch,
                state, created_at_ms, last_seen_at_ms, idle_expires_at_ms,
                absolute_expires_at_ms, revoked_at_ms
            ) VALUES ('old-admin', X'01', X'02', 0, 'REVOKED', 0, 0, 10, 10, 10)
            """
        )
        self.connection.execute(
            """
            INSERT INTO approvals(
                approval_id, request_id, request_fingerprint, session_id,
                service_id, operation, state, created_at_ms, expires_at_ms,
                decided_at_ms
            ) VALUES ('old-approval', 'retention-request', X'01', 'active-session',
                      'firecrawl', 'search', 'DENIED', 0, 10, 10)
            """
        )
        policy = RetentionPolicy(
            detailed_metadata_age_ms=100,
            daily_aggregate_age_ms=100,
            closed_admin_session_age_ms=100,
            completed_approval_age_ms=100,
            maximum_rows_per_table=1,
        )
        report = apply_retention(self.connection, now_ms=1_000, policy=policy)
        self.assertEqual(report.debug_excerpts_deleted, 1)
        self.assertEqual(report.audit_events_deleted, 1)
        self.assertEqual(report.daily_aggregates_deleted, 1)
        self.assertEqual(report.admin_sessions_deleted, 1)
        self.assertEqual(report.approvals_deleted, 1)
        self.assertEqual(report.total_deleted, 5)
        self.assertEqual(
            self.connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_id = 'preserve'"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE preserve = 0"
            ).fetchone()[0],
            1,
        )

        busy, _, _ = checkpoint_wal(self.connection)
        self.assertIn(busy, (0, 1))
        self.assertGreater(database_footprint(self.database_path), 0)


if __name__ == "__main__":
    unittest.main()
