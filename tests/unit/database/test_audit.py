from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from gatehouse.credentials.redaction import SecretScanner
from gatehouse.database.audit import AuditBufferFullError, BoundedAuditWriter
from gatehouse.database.migrations import open_migrated_database


class AuditWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name, "gatehouse.db")
        self.connection = open_migrated_database(self.database_path)
        self.canary = "FAKE-CANARY-DO-NOT-USE-1234567890"
        self.scanner = SecretScanner(canaries=(self.canary,))

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def test_buffer_has_hard_capacity_and_flushes_in_batches(self) -> None:
        writer = BoundedAuditWriter(capacity=2, default_batch_size=1, scanner=self.scanner)
        writer.emit("daemon.started", "INFO", {"reason": "test"}, event_id="event-1")
        writer.emit("daemon.ready", "INFO", {"ready": True}, event_id="event-2")
        with self.assertRaises(AuditBufferFullError):
            writer.emit("overflow", "ERROR", {})

        self.assertEqual(writer.flush(self.connection), 1)
        self.assertEqual(writer.pending_count, 1)
        self.assertEqual(writer.flush(self.connection, maximum_events=10), 1)
        self.assertEqual(writer.pending_count, 0)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
            2,
        )

    def test_payload_bodies_patterns_and_registered_canaries_are_redacted(self) -> None:
        writer = BoundedAuditWriter(scanner=self.scanner)
        writer.emit(
            "attempt.failed",
            "HIGH",
            {
                "request_body": {"query": self.canary},
                "response_body": "must never persist",
                "summary": f"provider rejected {self.canary}",
                "authorization": "Bearer fake-but-long-token-12345678901234567890",
                "safe": "metadata only",
            },
            event_id="redacted-event",
        )
        writer.flush(self.connection)
        payload_json = self.connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_id = 'redacted-event'"
        ).fetchone()[0]
        self.assertNotIn(self.canary, payload_json)
        self.assertNotIn("must never persist", payload_json)
        payload = json.loads(payload_json)
        self.assertEqual(payload["safe"], "metadata only")
        self.assertTrue(payload["request_body"].startswith("[REDACTED:"))
        self.assertTrue(payload["authorization"].startswith("[REDACTED:"))
        self.assertEqual(self.scanner.scan_text(payload_json), ())

    def test_failed_batch_remains_buffered_for_retry(self) -> None:
        writer = BoundedAuditWriter(scanner=self.scanner)
        writer.emit(
            "session.event",
            "INFO",
            {},
            event_id="foreign-key-failure",
            session_id="missing-session",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            writer.flush(self.connection)
        self.assertEqual(writer.pending_count, 1)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
