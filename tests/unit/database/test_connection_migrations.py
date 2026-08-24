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

_MIGRATION_1_TO_12_CHECKSUMS = (
    "534b54e6c679aae2b50dfe5996a26fdef61698067e96a4a41737bb5e15e4fb00",
    "51ffe6b796a8bc3c24aec0a323bd6a54422c023869addf0d4909e79a5a8d12de",
    "5fa39aa0b0ac15955aae48bacc00e27fe2c7841fedae1843902f372b62037f4d",
    "d10a0c719b1b8db7616453a576b5d152902ccbf87da7b2a4320668d2fc740cdc",
    "126d35209b8e9a76cf162c335a8d3e55ca85a42beeeb881416bc6f3bdaf3c41c",
    "239c9656de6af3c783a6c2fae59eca03b8e56d5e67810274ac3a5e6a3afa47c9",
    "e75670d1d81d7bb19728c61b29806c8c69a4ece6650c40b4d5e3e081d65dc32b",
    "6176c9fa8f166a8feb8da111b7a23c960b19ac4e846a3e4c4d2aa8e44aef8319",
    "8441d20709e561721132ab6fc4ee1171658a3db790a65656ce53be499a5aaad1",
    "05037e3e27669c092c9ff741dcaadc3ae86e186357e68f2899ecf7b7be054a93",
    "9ad28f043c2666de374bdfca8ec37fbe50194101aed1ebb2671827a38b54b5ab",
    "8b5e1cd349d4efec1845eb63023472fa5de125a96ab675c4e14c75081f00f88e",
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
        self.assertEqual(report.schema_version, 13)
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
                "runaway_quarantine_recoveries",
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
        snapshot_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(quota_snapshots)")
        }
        self.assertTrue(
            {
                "observed_remaining_units_decimal",
                "observed_plan_total_units_decimal",
            }.issubset(snapshot_columns)
        )
        reconciliation_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(reconciliation_items)")
        }
        self.assertTrue(
            {
                "provider_delta_units_decimal",
                "unexplained_delta_units_decimal",
                "allowed_tolerance_units_decimal",
            }.issubset(reconciliation_columns)
        )
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
        self.assertEqual(apply_migrations(self.connection), 13)
        applied_count = self.connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]
        self.assertEqual(applied_count, 13)

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

    def test_migrations_one_through_twelve_retain_frozen_checksums(self) -> None:
        self.assertEqual(
            tuple(item.checksum for item in MIGRATIONS[:12]),
            _MIGRATION_1_TO_12_CHECKSUMS,
        )

    def test_v12_adds_immutable_scope_identity_authority_without_rewriting_v11(self) -> None:
        legacy_path = Path(self.temporary.name, "provider-identities-v11.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:11]), 11)
            connection.executescript(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms,
                    identity_kind
                ) VALUES
                    ('principal-provider-v12', 'provider-v12', 'provider-v12',
                     0, 0, 'ACCOUNT'),
                    ('principal-other-v12', 'provider-v12', 'provider-other-v12',
                     0, 0, 'ACCOUNT');
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    configured_floor_units, scope_kind
                ) VALUES
                    ('scope-team-v12', 'principal-provider-v12', 'team',
                     'UNKNOWN', 'credits', 0, 'TEAM'),
                    ('scope-key-budget-v12', 'principal-provider-v12', 'key-budget',
                     'UNKNOWN', 'usd', 0, 'KEY_BUDGET'),
                    ('scope-rate-bucket-v12', 'principal-provider-v12', 'rate-bucket',
                     'UNKNOWN', 'requests', 0, 'RATE_BUCKET'),
                    ('scope-legacy-v12', 'principal-provider-v12', 'legacy',
                     'UNKNOWN', 'credits', 0, 'LEGACY'),
                    ('scope-other-v12', 'principal-other-v12', 'other',
                     'UNKNOWN', 'credits', 0, 'TEAM');
                """
            )

            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:12]), 12)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM provider_quota_scope_identities"
                ).fetchone()[0],
                0,
            )
            connection.execute(
                """
                INSERT INTO provider_quota_scope_identities(
                    provider_identity_id, provider_id, identity_kind,
                    identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "identity-team-v12",
                    "provider-v12",
                    "TEAM",
                    b"T" * 32,
                    "principal-provider-v12",
                    "scope-team-v12",
                    1,
                ),
            )
            connection.execute(
                """
                INSERT INTO provider_quota_scope_identities(
                    provider_identity_id, provider_id, identity_kind,
                    identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "identity-team-key-budget-v12",
                    "provider-v12",
                    "TEAM",
                    b"K" * 32,
                    "principal-provider-v12",
                    "scope-key-budget-v12",
                    1,
                ),
            )
            connection.execute(
                """
                INSERT INTO provider_quota_scope_identities(
                    provider_identity_id, provider_id, identity_kind,
                    identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "identity-user-rate-bucket-v12",
                    "provider-v12",
                    "USER",
                    b"R" * 32,
                    "principal-provider-v12",
                    "scope-rate-bucket-v12",
                    1,
                ),
            )
            self.assertEqual(
                tuple(
                    connection.execute(
                        """
                    SELECT COUNT(DISTINCT principal_id), COUNT(DISTINCT quota_scope_id)
                      FROM provider_quota_scope_identities
                    """
                    ).fetchone()
                ),
                (1, 3),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "authority mismatch"):
                connection.execute(
                    """
                    INSERT INTO provider_quota_scope_identities(
                        provider_identity_id, provider_id, identity_kind,
                        identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                    ) VALUES ('identity-owner-mismatch-v12', 'provider-v12', 'TEAM', ?,
                              'principal-provider-v12', 'scope-other-v12', 1)
                    """,
                    (b"M" * 32,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "authority mismatch"):
                connection.execute(
                    """
                    INSERT INTO provider_quota_scope_identities(
                        provider_identity_id, provider_id, identity_kind,
                        identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                    ) VALUES ('identity-provider-mismatch-v12', 'wrong-provider', 'TEAM', ?,
                              'principal-other-v12', 'scope-other-v12', 1)
                    """,
                    (b"P" * 32,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "authority mismatch"):
                connection.execute(
                    """
                    INSERT INTO provider_quota_scope_identities(
                        provider_identity_id, provider_id, identity_kind,
                        identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                    ) VALUES ('identity-legacy-scope-v12', 'provider-v12', 'ACCOUNT', ?,
                              'principal-provider-v12', 'scope-legacy-v12', 1)
                    """,
                    (b"L" * 32,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO provider_quota_scope_identities(
                        provider_identity_id, provider_id, identity_kind,
                        identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                    ) VALUES ('identity-legacy-kind-v12', 'provider-v12', 'LEGACY', ?,
                              'principal-other-v12', 'scope-other-v12', 1)
                    """,
                    (b"G" * 32,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO provider_quota_scope_identities(
                        provider_identity_id, provider_id, identity_kind,
                        identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                    ) VALUES ('identity-duplicate-fingerprint-v12', 'provider-v12', 'TEAM', ?,
                              'principal-other-v12', 'scope-other-v12', 1)
                    """,
                    (b"T" * 32,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO provider_quota_scope_identities(
                        provider_identity_id, provider_id, identity_kind,
                        identity_fingerprint, principal_id, quota_scope_id, created_at_ms
                    ) VALUES ('identity-duplicate-scope-v12', 'provider-v12', 'PROJECT', ?,
                              'principal-provider-v12', 'scope-team-v12', 1)
                    """,
                    (b"S" * 32,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE provider_quota_scope_identities SET metadata_json = '{"changed":true}'
                     WHERE provider_identity_id = 'identity-team-v12'
                    """
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retained"):
                connection.execute(
                    """
                    DELETE FROM provider_quota_scope_identities
                     WHERE provider_identity_id = 'identity-team-v12'
                    """
                )
        finally:
            connection.close()

    def test_v12_migration_failure_rolls_back_to_intact_v11(self) -> None:
        legacy_path = Path(self.temporary.name, "provider-identities-v12-rollback.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:11]), 11)
            broken = Migration(
                version=12,
                name=MIGRATIONS[11].name,
                sql=(
                    MIGRATIONS[11].sql + "\nINSERT INTO gatehouse_missing_table(value) VALUES (1);"
                ),
            )
            with self.assertRaises(sqlite3.OperationalError):
                apply_migrations(connection, migrations=(*MIGRATIONS[:11], broken))
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 11)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
                11,
            )
            self.assertIsNone(
                connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                     WHERE type = 'table' AND name = 'provider_quota_scope_identities'
                    """
                ).fetchone()
            )
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:12]), 12)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            connection.close()

    def test_v13_adds_immutable_fresh_run_recovery_authority_without_rewriting_v12(
        self,
    ) -> None:
        legacy_path = Path(self.temporary.name, "runaway-recovery-v12.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:12]), 12)
            connection.executescript(
                """
                INSERT INTO clients(
                    client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
                ) VALUES ('client-v13', 'client-v13', 'interactive', 'default', 0, 0);
                INSERT INTO sessions(
                    session_id, client_id, bootstrap_verifier, bootstrap_version,
                    token_epoch, state, identity_assurance, policy_version,
                    created_at_ms, reconnect_until_ms, absolute_expires_at_ms,
                    revoked_at_ms
                ) VALUES (
                    'session-v13', 'client-v13', X'01', 1, 0, 'REVOKED',
                    'CONTROLLED', 'v1', 0, 1000, 1000, 10
                );
                INSERT INTO root_runs(
                    root_run_id, session_id, state, started_at_ms, ended_at_ms
                ) VALUES ('root-v13', 'session-v13', 'CANCELLED', 0, 10);
                INSERT INTO runaway_quarantines(
                    quarantine_id, session_id, root_run_id, service_id, state,
                    trigger_reason, trigger_operation, generation, opened_at_ms, updated_at_ms
                ) VALUES (
                    'quarantine-v13', 'session-v13', 'root-v13', 'firecrawl', 'OPEN',
                    'AGGREGATE_BURST', 'firecrawl.search', 1, 1, 1
                );
                """
            )

            self.assertEqual(apply_migrations(connection), 13)
            indexes = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
            }
            self.assertIn("idx_runaway_quarantine_recoveries_client", indexes)
            self.assertIn("idx_sessions_client_capacity", indexes)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "authority mismatch"):
                connection.execute(
                    """
                    INSERT INTO runaway_quarantine_recoveries(
                        recovery_id, quarantine_id, quarantine_generation,
                        client_id, session_id, root_run_id, previous_state,
                        recovered_at_ms, decision_actor_id,
                        decision_reason_fingerprint, confirmation
                    ) VALUES (
                        'recovery-invalid-v13', 'quarantine-v13', 2,
                        'client-v13', 'session-v13', 'root-v13', 'OPEN',
                        20, 'admin-v13', ?, 'RECOVER_FRESH_RUN'
                    )
                    """,
                    ("a" * 64,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "authority mismatch"):
                connection.execute(
                    """
                    INSERT INTO runaway_quarantine_recoveries(
                        recovery_id, quarantine_id, quarantine_generation,
                        client_id, session_id, root_run_id, previous_state,
                        recovered_at_ms, decision_actor_id,
                        decision_reason_fingerprint, confirmation
                    ) VALUES (
                        'recovery-false-state-v13', 'quarantine-v13', 1,
                        'client-v13', 'session-v13', 'root-v13', 'AUTHORIZED',
                        1, 'admin-v13', ?, 'RECOVER_FRESH_RUN'
                    )
                    """,
                    ("c" * 64,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "authority mismatch"):
                connection.execute(
                    """
                    INSERT INTO runaway_quarantine_recoveries(
                        recovery_id, quarantine_id, quarantine_generation,
                        client_id, session_id, root_run_id, previous_state,
                        recovered_at_ms, decision_actor_id,
                        decision_reason_fingerprint, confirmation
                    ) VALUES (
                        'recovery-false-time-v13', 'quarantine-v13', 1,
                        'client-v13', 'session-v13', 'root-v13', 'OPEN',
                        20, 'admin-v13', ?, 'RECOVER_FRESH_RUN'
                    )
                    """,
                    ("d" * 64,),
                )
            connection.execute(
                """
                INSERT INTO runaway_quarantine_recoveries(
                    recovery_id, quarantine_id, quarantine_generation,
                    client_id, session_id, root_run_id, previous_state,
                    recovered_at_ms, decision_actor_id,
                    decision_reason_fingerprint, confirmation
                ) VALUES (
                    'recovery-v13', 'quarantine-v13', 1,
                    'client-v13', 'session-v13', 'root-v13', 'OPEN',
                    1, 'admin-v13', ?, 'RECOVER_FRESH_RUN'
                )
                """,
                ("b" * 64,),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute("UPDATE runaway_quarantine_recoveries SET recovered_at_ms = 21")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "retained"):
                connection.execute("DELETE FROM runaway_quarantine_recoveries")
        finally:
            connection.close()

    def test_v13_migration_failure_rolls_back_to_intact_v12(self) -> None:
        legacy_path = Path(self.temporary.name, "runaway-recovery-v13-rollback.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:12]), 12)
            broken = Migration(
                version=13,
                name=MIGRATIONS[12].name,
                sql=(
                    MIGRATIONS[12].sql + "\nINSERT INTO gatehouse_missing_table(value) VALUES (1);"
                ),
            )
            with self.assertRaises(sqlite3.OperationalError):
                apply_migrations(connection, migrations=(*MIGRATIONS[:12], broken))
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 12)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
                12,
            )
            self.assertIsNone(
                connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                     WHERE type = 'table' AND name = 'runaway_quarantine_recoveries'
                    """
                ).fetchone()
            )
            self.assertEqual(apply_migrations(connection), 13)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            connection.close()

    def test_v9_backfills_exact_strings_and_invalidates_only_unanchored_cache(self) -> None:
        legacy_path = Path(self.temporary.name, "decimal-v8.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:8]), 8)
            connection.executescript(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms
                ) VALUES ('principal-v9', 'firecrawl', 'principal-v9', 0, 0);
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    last_known_remaining_units, configured_floor_units,
                    last_refreshed_at_ms, balance_as_of_ms, balance_snapshot_id
                ) VALUES
                    ('anchored-v9', 'principal-v9', 'anchored-v9', 'HEALTHY',
                     'credits', NULL, 3, 10, NULL, NULL),
                    ('unanchored-v9', 'principal-v9', 'unanchored-v9', 'QUARANTINED',
                     'credits', 50, 7, 12, 12, NULL);
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                    unit, captured_at_ms, source
                ) VALUES ('snapshot-v9', 'anchored-v9', 100, 125,
                          'credits', 10, 'legacy-test');
                UPDATE quota_scopes
                   SET last_known_remaining_units = 100,
                       balance_as_of_ms = 10,
                       balance_snapshot_id = 'snapshot-v9'
                 WHERE quota_scope_id = 'anchored-v9';
                INSERT INTO reconciliation_runs(
                    reconciliation_id, service_id, mode, state, started_at_ms
                ) VALUES ('reconciliation-v9', 'firecrawl', 'FULL', 'COMPLETED', 20);
                INSERT INTO reconciliation_items(
                    item_id, reconciliation_id, quota_scope_id,
                    provider_delta_units, ledger_delta_units,
                    manual_adjustment_units, unexplained_delta_units,
                    unit, state, details_json
                ) VALUES (
                    'item-v9', 'reconciliation-v9', 'anchored-v9',
                    9, 8, -1, 2, 'credits', 'MISMATCH',
                    '{"allowed_tolerance_units":7,"other":"preserved"}'
                );
                INSERT INTO clients(
                    client_id, display_name, kind, policy_profile,
                    created_at_ms, updated_at_ms
                ) VALUES ('client-v9', 'Client', 'interactive', 'default', 0, 0);
                INSERT INTO sessions(
                    session_id, client_id, bootstrap_verifier, bootstrap_version,
                    token_epoch, state, identity_assurance, policy_version,
                    created_at_ms, reconnect_until_ms, absolute_expires_at_ms
                ) VALUES ('session-v9', 'client-v9', X'01', 1, 0, 'ACTIVE',
                          'TEST', 'v9', 0, 1000, 1000);
                INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
                VALUES ('root-v9', 'session-v9', 'ACTIVE', 0);
                INSERT INTO invocations(
                    request_id, session_id, root_run_id, service_id, operation,
                    request_fingerprint, fingerprint_version,
                    canonicalization_version, state, priority_class,
                    request_size_bytes, received_at_ms
                ) VALUES ('request-v9', 'session-v9', 'root-v9', 'firecrawl',
                          'firecrawl.search', X'01', 1, 1, 'QUEUED',
                          'INTERACTIVE', 1, 0);
                INSERT INTO quota_reservations(
                    reservation_id, request_id, quota_scope_id, amount_units,
                    actual_units, unit, state, created_at_ms, expires_at_ms,
                    reconciled_at_ms, metadata_json
                ) VALUES
                    ('reservation-active-v9', 'request-v9', 'unanchored-v9', 4,
                     NULL, 'credits', 'ACTIVE', 1, 1000, NULL,
                     '{"marker":"active"}'),
                    ('reservation-pending-v9', 'request-v9', 'unanchored-v9', 5,
                     NULL, 'credits', 'PENDING_RECONCILIATION', 2, 1001, NULL,
                     '{"marker":"pending"}'),
                    ('reservation-disputed-v9', 'request-v9', 'unanchored-v9', 6,
                     NULL, 'credits', 'DISPUTED', 3, 1002, NULL,
                     '{"marker":"disputed"}'),
                    ('reservation-reconciled-v9', 'request-v9', 'unanchored-v9', 7,
                     3, 'credits', 'RECONCILED', 4, 1003, 21,
                     '{"marker":"reconciled"}'),
                    ('reservation-expired-v9', 'request-v9', 'unanchored-v9', 8,
                     NULL, 'credits', 'EXPIRED', 5, 6, NULL,
                     '{"marker":"expired"}');
                """
            )
            reservation_query = """
                SELECT reservation_id, request_id, quota_scope_id, amount_units,
                       actual_units, unit, state, created_at_ms, expires_at_ms,
                       reconciled_at_ms, metadata_json
                  FROM quota_reservations
                 WHERE quota_scope_id = 'unanchored-v9'
                 ORDER BY reservation_id
            """
            legacy_reservations = [
                tuple(row) for row in connection.execute(reservation_query).fetchall()
            ]
            self.assertEqual(
                legacy_reservations,
                [
                    (
                        "reservation-active-v9",
                        "request-v9",
                        "unanchored-v9",
                        4,
                        None,
                        "credits",
                        "ACTIVE",
                        1,
                        1000,
                        None,
                        '{"marker":"active"}',
                    ),
                    (
                        "reservation-disputed-v9",
                        "request-v9",
                        "unanchored-v9",
                        6,
                        None,
                        "credits",
                        "DISPUTED",
                        3,
                        1002,
                        None,
                        '{"marker":"disputed"}',
                    ),
                    (
                        "reservation-expired-v9",
                        "request-v9",
                        "unanchored-v9",
                        8,
                        None,
                        "credits",
                        "EXPIRED",
                        5,
                        6,
                        None,
                        '{"marker":"expired"}',
                    ),
                    (
                        "reservation-pending-v9",
                        "request-v9",
                        "unanchored-v9",
                        5,
                        None,
                        "credits",
                        "PENDING_RECONCILIATION",
                        2,
                        1001,
                        None,
                        '{"marker":"pending"}',
                    ),
                    (
                        "reservation-reconciled-v9",
                        "request-v9",
                        "unanchored-v9",
                        7,
                        3,
                        "credits",
                        "RECONCILED",
                        4,
                        1003,
                        21,
                        '{"marker":"reconciled"}',
                    ),
                ],
            )

            self.assertEqual(apply_migrations(connection), 13)
            anchored = connection.execute(
                """
                SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
                  FROM quota_scopes WHERE quota_scope_id = 'anchored-v9'
                """
            ).fetchone()
            self.assertEqual(tuple(anchored), (100, 10, "snapshot-v9"))
            unanchored = connection.execute(
                """
                SELECT state, configured_floor_units, last_refreshed_at_ms,
                       last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
                  FROM quota_scopes WHERE quota_scope_id = 'unanchored-v9'
                """
            ).fetchone()
            self.assertEqual(tuple(unanchored), ("QUARANTINED", 7, 12, None, None, None))
            snapshot = connection.execute(
                """
                SELECT observed_remaining_units_decimal,
                       observed_plan_total_units_decimal
                  FROM quota_snapshots WHERE snapshot_id = 'snapshot-v9'
                """
            ).fetchone()
            self.assertEqual(tuple(snapshot), ("100", "125"))
            item = connection.execute(
                """
                SELECT provider_delta_units_decimal,
                       unexplained_delta_units_decimal,
                       allowed_tolerance_units_decimal,
                       json_extract(details_json, '$.allowed_tolerance_units'),
                       json_type(details_json, '$.allowed_tolerance_units'),
                       json_extract(details_json, '$.other')
                  FROM reconciliation_items WHERE item_id = 'item-v9'
                """
            ).fetchone()
            self.assertEqual(tuple(item), ("9", "2", "7", "7", "text", "preserved"))
            migrated_reservations = [
                tuple(row) for row in connection.execute(reservation_query).fetchall()
            ]
            self.assertEqual(migrated_reservations, legacy_reservations)
        finally:
            connection.close()

    def test_v9_corrupt_anchor_rolls_back_every_schema_change(self) -> None:
        legacy_path = Path(self.temporary.name, "corrupt-anchor-v8.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:8]), 8)
            connection.executescript(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms
                ) VALUES ('principal-corrupt', 'firecrawl', 'principal-corrupt', 0, 0);
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    last_known_remaining_units, balance_as_of_ms
                ) VALUES ('scope-corrupt', 'principal-corrupt', 'scope-corrupt',
                          'HEALTHY', 'credits', 100, 10);
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, unit,
                    captured_at_ms, source
                ) VALUES ('snapshot-corrupt', 'scope-corrupt', 99, 'credits',
                          10, 'legacy-test');
                UPDATE quota_scopes
                   SET balance_snapshot_id = 'snapshot-corrupt'
                 WHERE quota_scope_id = 'scope-corrupt';
                """
            )

            with self.assertRaises(sqlite3.IntegrityError):
                apply_migrations(connection)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 8)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
                8,
            )
            snapshot_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(quota_snapshots)")
            }
            self.assertNotIn("observed_remaining_units_decimal", snapshot_columns)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE '%decimal_shape%'"
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_v9_rejects_unproven_legacy_tolerance_sources(self) -> None:
        cases = (
            "{}",
            '{"allowed_tolerance_units":1.0}',
            '{"allowed_tolerance_units":9223372036854775808}',
            '{"allowed_tolerance_units":1,"allowed_tolerance_units":1}',
        )
        for index, details in enumerate(cases):
            with self.subTest(details=details):
                path = Path(self.temporary.name, f"bad-tolerance-{index}.db")
                connection = connect_database(path)
                try:
                    self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:8]), 8)
                    connection.execute(
                        """
                        INSERT INTO principals(
                            principal_id, service_id, alias, created_at_ms, updated_at_ms
                        ) VALUES (?, 'firecrawl', ?, 0, 0)
                        """,
                        (f"principal-{index}", f"principal-{index}"),
                    )
                    connection.execute(
                        """
                        INSERT INTO quota_scopes(
                            quota_scope_id, principal_id, alias, state, unit
                        ) VALUES (?, ?, ?, 'HEALTHY', 'credits')
                        """,
                        (f"scope-{index}", f"principal-{index}", f"scope-{index}"),
                    )
                    connection.execute(
                        """
                        INSERT INTO reconciliation_runs(
                            reconciliation_id, service_id, mode, state, started_at_ms
                        ) VALUES (?, 'firecrawl', 'FULL', 'COMPLETED', 0)
                        """,
                        (f"run-{index}",),
                    )
                    connection.execute(
                        """
                        INSERT INTO reconciliation_items(
                            item_id, reconciliation_id, quota_scope_id,
                            provider_delta_units, ledger_delta_units,
                            manual_adjustment_units, unexplained_delta_units,
                            unit, state, details_json
                        ) VALUES (?, ?, ?, 1, 1, 0, 0, 'credits', 'MATCHED', ?)
                        """,
                        (f"item-{index}", f"run-{index}", f"scope-{index}", details),
                    )
                    with self.assertRaises(sqlite3.IntegrityError):
                        apply_migrations(connection)
                    self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 8)
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
                        8,
                    )
                finally:
                    connection.close()

    def test_v10_backfills_provider_foundation_and_only_exact_scripted_authority(self) -> None:
        legacy_path = Path(self.temporary.name, "provider-foundation-v9.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:9]), 9)
            connection.executescript(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms,
                    metadata_json
                ) VALUES
                    ('principal-scripted', 'firecrawl', 'scripted', 0, 0, '{}'),
                    ('principal-live', 'firecrawl', 'live', 0, 0, '{}');
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit, metadata_json
                ) VALUES
                    ('scope-scripted', 'principal-scripted', 'scripted', 'HEALTHY',
                     'credits', '{"transport":"scripted","network":false}'),
                    ('scope-live', 'principal-live', 'live', 'HEALTHY',
                     'credits', '{}');
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, unit,
                    captured_at_ms, source, metadata_json,
                    observed_remaining_units_decimal
                ) VALUES
                    ('snapshot_gatehouse_scripted_no_network_v1', 'scope-scripted',
                     1000000, 'credits', 1, 'scripted-no-network-synthetic',
                     '{"network":false,"synthetic":true,"transport":"scripted"}',
                     '1000000'),
                    ('snapshot-live-legacy', 'scope-live', 25, 'credits', 2,
                     'admin-credential-validation', '{}', '25');
                UPDATE quota_scopes
                   SET last_known_remaining_units = 1000000, balance_as_of_ms = 1,
                       balance_snapshot_id = 'snapshot_gatehouse_scripted_no_network_v1'
                 WHERE quota_scope_id = 'scope-scripted';
                UPDATE quota_scopes
                   SET last_known_remaining_units = 25, balance_as_of_ms = 2,
                       balance_snapshot_id = 'snapshot-live-legacy'
                 WHERE quota_scope_id = 'scope-live';
                INSERT INTO circuit_breakers(
                    breaker_id, scope_type, scope_id, state
                ) VALUES ('breaker-live', 'quota_scope', 'scope-live', 'CLOSED');
                """
            )

            self.assertEqual(apply_migrations(connection), 13)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 13)
            self.assertEqual(
                tuple(
                    connection.execute(
                        """
                        SELECT identity_kind FROM principals ORDER BY principal_id
                        """
                    ).fetchone()
                ),
                ("LEGACY",),
            )
            dimensions = connection.execute(
                """
                SELECT quota_scope_id, name, native_unit, counter_kind, is_primary
                  FROM quota_dimensions ORDER BY quota_scope_id
                """
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in dimensions],
                [
                    ("scope-live", "legacy-primary", "credits", "LEGACY", 1),
                    ("scope-scripted", "legacy-primary", "credits", "LEGACY", 1),
                ],
            )
            snapshots = connection.execute(
                """
                SELECT snapshot_id, observation_kind, quota_dimension_id,
                       stale_at_ms, credential_id, credential_generation
                  FROM quota_snapshots ORDER BY snapshot_id
                """
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in snapshots],
                [
                    (
                        "snapshot-live-legacy",
                        "LEGACY",
                        "dimension_legacy_primary:scope-live",
                        None,
                        None,
                        None,
                    ),
                    (
                        "snapshot_gatehouse_scripted_no_network_v1",
                        "SCRIPTED",
                        "dimension_legacy_primary:scope-scripted",
                        None,
                        None,
                        None,
                    ),
                ],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM quota_scope_state_events WHERE generation = 0"
                ).fetchone()[0],
                2,
            )
            breaker = connection.execute(
                """
                SELECT generation, updated_at_ms, recovery_policy
                  FROM circuit_breakers WHERE breaker_id = 'breaker-live'
                """
            ).fetchone()
            self.assertEqual(tuple(breaker), (0, 0, "TIMER"))
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM quota_observation_schedules").fetchone()[
                    0
                ],
                0,
            )
        finally:
            connection.close()

    def test_v10_invalid_legacy_scope_state_rolls_back_all_schema_changes(self) -> None:
        legacy_path = Path(self.temporary.name, "provider-foundation-corrupt-v9.db")
        connection = connect_database(legacy_path)
        try:
            self.assertEqual(apply_migrations(connection, migrations=MIGRATIONS[:9]), 9)
            connection.executescript(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, created_at_ms, updated_at_ms
                ) VALUES ('principal-invalid-v10', 'firecrawl', 'invalid-v10', 0, 0);
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit
                ) VALUES ('scope-invalid-v10', 'principal-invalid-v10', 'invalid-v10',
                          'BROKEN', 'credits');
                """
            )
            with self.assertRaises(sqlite3.IntegrityError):
                apply_migrations(connection)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 9)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
                9,
            )
            principal_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(principals)")
            }
            self.assertNotIn("identity_kind", principal_columns)
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'quota_dimensions'"
                ).fetchone()
            )
        finally:
            connection.close()

    def test_v9_triggers_enforce_decimal_shapes_anchors_and_immutability(self) -> None:
        self.connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, created_at_ms, updated_at_ms
            ) VALUES ('principal-trigger', 'firecrawl', 'principal-trigger', 0, 0)
            """
        )
        self.connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit
            ) VALUES ('scope-trigger', 'principal-trigger', 'scope-trigger',
                      'HEALTHY', 'credits')
            """
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "snapshot decimal shape"):
            self.connection.execute(
                """
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, unit,
                    captured_at_ms, source, quota_dimension_id
                ) VALUES ('snapshot-missing-exact', 'scope-trigger', 10,
                          'credits', 10, 'test',
                          'dimension_legacy_primary:scope-trigger')
                """
            )
        self.connection.execute(
            """
            INSERT INTO quota_snapshots(
                snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                unit, captured_at_ms, source,
                observed_remaining_units_decimal,
                observed_plan_total_units_decimal, quota_dimension_id
            ) VALUES ('snapshot-trigger', 'scope-trigger', 10, NULL,
                      'credits', 10, 'test', '10', NULL,
                      'dimension_legacy_primary:scope-trigger')
            """
        )
        self.connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = 10,
                   balance_as_of_ms = 10,
                   balance_snapshot_id = 'snapshot-trigger'
             WHERE quota_scope_id = 'scope-trigger'
            """
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "balance authority"):
            self.connection.execute(
                "UPDATE quota_scopes SET balance_as_of_ms = 11 "
                "WHERE quota_scope_id = 'scope-trigger'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "observation is immutable"):
            self.connection.execute(
                "UPDATE quota_snapshots SET remaining_units = 9 "
                "WHERE snapshot_id = 'snapshot-trigger'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "observation is immutable"):
            self.connection.execute(
                "UPDATE quota_snapshots SET metadata_json = '{\"changed\":true}' "
                "WHERE snapshot_id = 'snapshot-trigger'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "balance authority"):
            self.connection.execute(
                """
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    last_known_remaining_units
                ) VALUES ('scope-unanchored', 'principal-trigger', 'scope-unanchored',
                          'HEALTHY', 'credits', 10)
                """
            )

        self.connection.execute(
            """
            INSERT INTO reconciliation_runs(
                reconciliation_id, service_id, mode, state, started_at_ms
            ) VALUES ('run-trigger', 'firecrawl', 'FULL', 'COMPLETED', 0)
            """
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "reconciliation decimal shape"):
            self.connection.execute(
                """
                INSERT INTO reconciliation_items(
                    item_id, reconciliation_id, quota_scope_id,
                    provider_delta_units, ledger_delta_units,
                    manual_adjustment_units, unexplained_delta_units,
                    unit, state, details_json
                ) VALUES ('item-invalid', 'run-trigger', 'scope-trigger',
                          1, 1, 0, 0, 'credits', 'MATCHED',
                          '{"allowed_tolerance_units":"0"}')
                """
            )
        self.connection.execute(
            """
            INSERT INTO reconciliation_items(
                item_id, reconciliation_id, quota_scope_id,
                provider_delta_units, ledger_delta_units,
                manual_adjustment_units, unexplained_delta_units,
                unit, state, details_json, provider_delta_units_decimal,
                unexplained_delta_units_decimal, allowed_tolerance_units_decimal
            ) VALUES ('item-valid', 'run-trigger', 'scope-trigger',
                      1, 1, 0, 0, 'credits', 'MATCHED',
                      '{"allowed_tolerance_units":"0"}', '1', '0', '0')
            """
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "reconciliation decimal shape"):
            self.connection.execute(
                "UPDATE reconciliation_items "
                "SET provider_delta_units_decimal = '1\N{SNOWMAN}' "
                "WHERE item_id = 'item-valid'"
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

            self.assertEqual(apply_migrations(connection), 13)
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

            self.assertEqual(apply_migrations(connection), 13)
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
