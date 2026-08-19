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
        self.assertEqual(report.schema_version, 7)
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
            }.issubset(attempt_columns)
        )

    def test_migrations_are_idempotent_and_checksum_guarded(self) -> None:
        self.assertEqual(apply_migrations(self.connection), 7)
        applied_count = self.connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]
        self.assertEqual(applied_count, 7)

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

            self.assertEqual(apply_migrations(connection), 7)
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
