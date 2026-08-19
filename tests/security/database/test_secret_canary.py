from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gatehouse.credentials.redaction import SecretScanner
from gatehouse.database.audit import BoundedAuditWriter
from gatehouse.database.migrations import open_migrated_database
from gatehouse.database.retention import checkpoint_wal

FAKE_CANARY = "FAKE-DATABASE-CANARY-NOT-A-REAL-KEY-1234567890"


class DatabaseSecretCanaryTests(unittest.TestCase):
    def test_fake_secret_never_reaches_database_wal_or_shm(self) -> None:
        scanner = SecretScanner(canaries=(FAKE_CANARY,))
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary, "gatehouse.db")
            connection = open_migrated_database(database_path)
            try:
                writer = BoundedAuditWriter(scanner=scanner)
                writer.emit(
                    "secret.canary",
                    "HIGH",
                    {
                        "request_body": FAKE_CANARY,
                        "summary": f"redact this {FAKE_CANARY}",
                    },
                )
                writer.flush(connection)
                checkpoint_wal(connection, mode="FULL")
                payload = connection.execute("SELECT payload_json FROM audit_events").fetchone()[0]
                self.assertNotIn(FAKE_CANARY, payload)
                self.assertEqual(scanner.scan_files((temporary,)), ())
            finally:
                connection.close()

    def test_schema_persists_only_opaque_secret_references(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            connection = open_migrated_database(Path(temporary, "gatehouse.db"))
            try:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(credentials)")}
                self.assertIn("secret_reference", columns)
                self.assertNotIn("secret_ciphertext", columns)
                self.assertNotIn("plaintext_secret", columns)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
