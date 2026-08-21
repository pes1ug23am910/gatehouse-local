from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from gatehouse.database.connection import (
    TransactionNestingError,
    connect_database,
    inspect_integrity,
    transaction,
)
from gatehouse.database.migrations import (
    MIGRATIONS,
    Migration,
    MigrationDriftError,
    apply_migrations,
    open_migrated_database,
)


class ConnectionMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name, "gatehouse.db")
        self.connection = open_migrated_database(self.database_path)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def test_required_pragmas_and_integrity_are_active(self) -> None:
        self.assertEqual(self.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("PRAGMA busy_timeout").fetchone()[0], 5_000)

        report = inspect_integrity(self.connection, full=True)
        self.assertTrue(report.ok)
        self.assertEqual(report.schema_version, 8)
        self.assertEqual(report.integrity_messages, ("ok",))
        self.assertEqual(report.foreign_key_violations, ())

    def test_initial_schema_contains_corrected_durable_surfaces(self) -> None:
        tables = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertTrue(
            {
                "queue_entries",
                "admin_sessions",
                "documentation_sources",
                "documentation_versions",
                "documentation_chunks",
                "documentation_chunks_fts",
                "feed_sets",
                "feed_cursors",
                "watcher_runs",
                "quota_reservations",
                "audit_events",
            }.issubset(tables)
        )

        credential_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(credentials)")
        }
        self.assertIn("secret_reference", credential_columns)
        self.assertNotIn("secret_ciphertext", credential_columns)

        lease_index_sql = self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'uq_leases_one_active_holder'"
        ).fetchone()[0]
        self.assertIn("WHERE state = 'ACTIVE'", lease_index_sql)

        affinity_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(external_resources)")
        }
        self.assertTrue(
            {
                "credential_generation",
                "pool_id",
                "owner_session_id",
                "owner_workspace_id",
                "owner_root_run_id",
            }.issubset(affinity_columns)
        )
        quota_scope_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(quota_scopes)")
        }
        self.assertTrue({"balance_as_of_ms", "balance_snapshot_id"}.issubset(quota_scope_columns))
        attempt_columns = {row[1] for row in self.connection.execute("PRAGMA table_info(attempts)")}
        self.assertTrue(
            {
                "resource_type",
                "provider_resource_id",
                "credential_generation",
                "pool_id",
                "emergency_unlock_id",
                "emergency_credential_id",
                "emergency_principal_id",
                "emergency_quota_scope_id",
                "emergency_pool_id",
                "emergency_credential_generation",
                "dispatch_credential_generation",
                "dispatch_pool_id",
            }.issubset(attempt_columns)
        )
        attempt_triggers = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'attempts'"
            )
        }
        self.assertTrue(
            {
                "attempts_dispatch_authority_shape_insert",
                "attempts_dispatch_authority_shape_update",
                "attempts_dispatch_authority_immutable",
            }.issubset(attempt_triggers)
        )

        emergency_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(emergency_unlock_records)")
        }
        self.assertTrue(
            {
                "credential_id",
                "credential_alias",
                "credential_generation",
                "principal_id",
                "principal_alias",
                "quota_scope_id",
                "quota_scope_alias",
            }.issubset(emergency_columns)
        )
        self.assertFalse(
            any("secret" in column or "reference" in column for column in emergency_columns)
        )
        emergency_foreign_keys = {
            row[3]: row[2]
            for row in self.connection.execute("PRAGMA foreign_key_list(emergency_unlock_records)")
        }
        self.assertNotIn("credential_id", emergency_foreign_keys)
        self.assertNotIn("principal_id", emergency_foreign_keys)
        self.assertNotIn("quota_scope_id", emergency_foreign_keys)
        self.assertEqual(emergency_foreign_keys["pool_id"], "pools")
        self.assertEqual(emergency_foreign_keys["session_id"], "sessions")
        self.assertEqual(emergency_foreign_keys["root_run_id"], "root_runs")

    def test_migrations_are_idempotent_and_checksum_guarded(self) -> None:
        self.assertEqual(apply_migrations(self.connection), 8)
        applied_count = self.connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]
        self.assertEqual(applied_count, 8)

        drifted = Migration(
            version=1,
            name=MIGRATIONS[0].name,
            sql=MIGRATIONS[0].sql + "\n-- changed after application",
        )
        with self.assertRaises(MigrationDriftError):
            apply_migrations(
                self.connection,
                migrations=(drifted, *MIGRATIONS[1:]),
            )

    def test_new_normal_attempt_requires_immutable_dispatch_authority(self) -> None:
        with self.assertRaisesRegex(
            sqlite3.IntegrityError,
            "invalid attempt dispatch authority shape",
        ):
            self.connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, request_id, ordinal, credential_id,
                    principal_id, quota_scope_id, state, started_at_ms
                ) VALUES (
                    'attempt-without-dispatch', 'missing-request', 1,
                    'missing-credential', 'missing-principal', 'missing-scope',
                    'RUNNING', 1
                )
                """
            )

    def test_migrated_legacy_attempt_can_update_without_dispatch_authority(self) -> None:
        self.connection.execute("PRAGMA foreign_keys = OFF")
        self.connection.execute("DROP TRIGGER attempts_dispatch_authority_shape_insert")
        self.connection.execute(
            """
            INSERT INTO attempts(
                attempt_id, request_id, ordinal, credential_id,
                principal_id, quota_scope_id, state, started_at_ms
            ) VALUES (
                'legacy-attempt', 'legacy-request', 1,
                'legacy-credential', 'legacy-principal', 'legacy-scope',
                'RUNNING', 1
            )
            """
        )

        self.connection.execute(
            "UPDATE attempts SET state = 'UNKNOWN' WHERE attempt_id = 'legacy-attempt'"
        )

        row = self.connection.execute(
            """
            SELECT state, dispatch_credential_generation, dispatch_pool_id
              FROM attempts WHERE attempt_id = 'legacy-attempt'
            """
        ).fetchone()
        self.assertEqual(tuple(row), ("UNKNOWN", None, None))

    def test_v8_backfills_only_exact_known_terminal_resource_authority(self) -> None:
        legacy_path = Path(self.temporary.name, "terminal-resources.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:7]), 7)
            connection.executescript(
                """
                INSERT INTO clients(
                    client_id, display_name, kind, policy_profile,
                    created_at_ms, updated_at_ms
                ) VALUES ('client', 'Client', 'interactive', 'default', 0, 0);
                INSERT INTO workspaces(
                    workspace_id, display_name, canonical_root,
                    created_at_ms, updated_at_ms
                ) VALUES ('workspace', 'Workspace', 'E:\\Workspace', 0, 0);
                INSERT INTO sessions(
                    session_id, client_id, workspace_id, bootstrap_verifier,
                    bootstrap_version, token_epoch, state, identity_assurance,
                    policy_version, created_at_ms, reconnect_until_ms,
                    absolute_expires_at_ms
                ) VALUES ('session', 'client', 'workspace', X'01', 1, 1,
                          'ACTIVE', 'TEST', 'policy-v1', 0, 10000, 10000);
                INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
                VALUES ('root', 'session', 'ACTIVE', 0);
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms
                ) VALUES ('principal', 'firecrawl', 'principal', 0, 0);
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit
                ) VALUES ('quota', 'principal', 'quota', 'HEALTHY', 'credits');
                INSERT INTO credentials(
                    credential_id, principal_id, quota_scope_id, alias,
                    secret_backend, secret_reference, state, generation,
                    created_at_ms
                ) VALUES ('credential', 'principal', 'quota', 'credential',
                          'test', 'test-reference', 'HEALTHY', 1, 0);
                INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
                VALUES ('pool', 'firecrawl', 'interactive-default', 'ACTIVE', 'ROUND_ROBIN');
                INSERT INTO pool_members(pool_id, quota_scope_id)
                VALUES ('pool', 'quota');
                """
            )
            cases = (
                ("SUCCEEDED", "COMPLETED", "pool"),
                ("FAILED", "FAILED", "pool"),
                ("CANCELLED", "CANCELLED", "pool"),
                ("UNKNOWN", "ACTIVE", "pool"),
                ("SUCCEEDED", "ACTIVE", "mismatched-pool"),
            )
            for index, (job_state, _, metadata_pool) in enumerate(cases, start=1):
                request_id = f"request-{index}"
                provider_id = f"provider-{index}"
                connection.execute(
                    """
                    INSERT INTO invocations(
                        request_id, session_id, root_run_id, service_id,
                        operation, request_fingerprint, fingerprint_version,
                        canonicalization_version, state, priority_class,
                        request_size_bytes, received_at_ms, completed_at_ms
                    ) VALUES (?, 'session', 'root', 'firecrawl',
                              'firecrawl.crawl.start', ?, 1, 1, 'SUCCEEDED',
                              'INTERACTIVE', 10, 0, 100)
                    """,
                    (request_id, bytes([index]) * 32),
                )
                connection.execute(
                    """
                    INSERT INTO external_resources(
                        resource_id, service_id, resource_type,
                        provider_resource_id, principal_id, quota_scope_id,
                        credential_id, credential_generation, pool_id,
                        creating_request_id, owner_session_id,
                        owner_workspace_id, owner_root_run_id, state,
                        created_at_ms, updated_at_ms
                    ) VALUES (?, 'firecrawl', 'crawl', ?, 'principal', 'quota',
                              'credential', 1, 'pool', ?, 'session', 'workspace',
                              'root', 'ACTIVE', 100, 100)
                    """,
                    (f"resource-{index}", provider_id, request_id),
                )
                connection.execute(
                    """
                    INSERT INTO jobs(
                        job_id, request_id, service_id, operation, state,
                        provider_job_id, principal_id, quota_scope_id,
                        credential_id, maximum_runtime_at_ms, created_at_ms,
                        completed_at_ms, metadata_json
                    ) VALUES (?, ?, 'firecrawl', 'firecrawl.crawl.start', ?, ?,
                              'principal', 'quota', 'credential', 10000, 100, 500, ?)
                    """,
                    (
                        f"job-{index}",
                        request_id,
                        job_state,
                        provider_id,
                        '{"schema_version":1,"revision":2,"resource_type":"crawl",'
                        '"credential_generation":1,"pool_id":"' + metadata_pool + '"}',
                    ),
                )

            self.assertEqual(apply_migrations(connection), 8)
            states = connection.execute(
                "SELECT state, updated_at_ms FROM external_resources ORDER BY resource_id"
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in states],
                [
                    ("COMPLETED", 500),
                    ("FAILED", 500),
                    ("CANCELLED", 500),
                    ("ACTIVE", 100),
                    ("ACTIVE", 100),
                ],
            )
        finally:
            connection.close()

    def test_v2_resource_rows_are_quarantined_until_authority_can_be_rebound(
        self,
    ) -> None:
        legacy_path = Path(self.temporary.name, "legacy.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(
                apply_migrations(connection, migrations=MIGRATIONS[:2]),
                2,
            )
            connection.executescript(
                """
                INSERT INTO clients(
                    client_id, display_name, kind, policy_profile,
                    created_at_ms, updated_at_ms
                ) VALUES ('client', 'Client', 'interactive', 'default', 0, 0);
                INSERT INTO workspaces(
                    workspace_id, display_name, canonical_root,
                    created_at_ms, updated_at_ms
                ) VALUES ('workspace', 'Workspace', 'E:\\Workspace', 0, 0);
                INSERT INTO sessions(
                    session_id, client_id, workspace_id, bootstrap_verifier,
                    bootstrap_version, token_epoch, state, identity_assurance,
                    policy_version, created_at_ms, reconnect_until_ms,
                    absolute_expires_at_ms
                ) VALUES ('session', 'client', 'workspace', X'01', 1, 0,
                          'ACTIVE', 'TEST', 'v1', 0, 100, 100);
                INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
                VALUES ('root', 'session', 'ACTIVE', 0);
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms
                ) VALUES ('principal', 'service', 'primary', 0, 0);
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit
                ) VALUES ('quota', 'principal', 'primary', 'HEALTHY', 'credits');
                INSERT INTO credentials(
                    credential_id, principal_id, quota_scope_id, alias,
                    secret_backend, secret_reference, state, created_at_ms
                ) VALUES ('credential', 'principal', 'quota', 'primary',
                          'test', 'reference', 'ACTIVE', 0);
                INSERT INTO invocations(
                    request_id, session_id, root_run_id, service_id, operation,
                    request_fingerprint, fingerprint_version,
                    canonicalization_version, state, priority_class,
                    request_size_bytes, received_at_ms
                ) VALUES ('request', 'session', 'root', 'service', 'crawl.start',
                          X'01', 1, 1, 'SUCCEEDED', 'INTERACTIVE', 1, 0);
                INSERT INTO external_resources(
                    resource_id, service_id, resource_type,
                    provider_resource_id, principal_id, quota_scope_id,
                    credential_id, creating_request_id, state,
                    created_at_ms, updated_at_ms
                ) VALUES ('resource', 'service', 'crawl', 'provider-job',
                          'principal', 'quota', 'credential', 'request',
                          'ACTIVE', 1, 1);
                """
            )

            self.assertEqual(apply_migrations(connection), 8)
            row = connection.execute(
                """
                SELECT state, credential_generation, pool_id,
                       owner_session_id, owner_workspace_id, owner_root_run_id
                  FROM external_resources
                """
            ).fetchone()
            self.assertEqual(row["state"], "OWNER_REBIND_REQUIRED")
            self.assertEqual(row["credential_generation"], 1)
            self.assertIsNone(row["pool_id"])
            self.assertEqual(row["owner_session_id"], "session")
            self.assertEqual(row["owner_workspace_id"], "workspace")
            self.assertEqual(row["owner_root_run_id"], "root")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE external_resources SET state = 'ACTIVE'")
        finally:
            connection.close()

    def test_explicit_transaction_rolls_back_and_rejects_nesting(self) -> None:
        original_epoch = self.connection.execute(
            "SELECT token_epoch FROM system_state WHERE singleton_id = 1"
        ).fetchone()[0]
        with self.assertRaisesRegex(RuntimeError, "force rollback"):
            with transaction(self.connection):
                self.connection.execute(
                    "UPDATE system_state SET token_epoch = 99 WHERE singleton_id = 1"
                )
                raise RuntimeError("force rollback")
        self.assertEqual(
            self.connection.execute(
                "SELECT token_epoch FROM system_state WHERE singleton_id = 1"
            ).fetchone()[0],
            original_epoch,
        )

        with transaction(self.connection):
            with self.assertRaises(TransactionNestingError):
                with transaction(self.connection):
                    pass

    def test_foreign_key_diagnostics_report_corruption_when_checks_were_bypassed(self) -> None:
        self.connection.execute("PRAGMA foreign_keys = OFF")
        self.connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_id, bootstrap_verifier, bootstrap_version,
                token_epoch, state, identity_assurance, policy_version,
                created_at_ms, reconnect_until_ms, absolute_expires_at_ms
            ) VALUES ('orphan', 'missing-client', X'00', 1, 0, 'ACTIVE',
                      'TEST', 'v1', 0, 100, 100)
            """
        )
        self.connection.execute("PRAGMA foreign_keys = ON")
        report = inspect_integrity(self.connection)
        self.assertFalse(report.ok)
        self.assertTrue(report.foreign_key_violations)


if __name__ == "__main__":
    unittest.main()
