from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gatehouse.credentials.redaction import SecretDetectedError, SecretScanner

CANARY = "FAKE-CREDENTIAL-CANARY-1234567890"


class SecretScannerTests(unittest.TestCase):
    def test_registered_canary_is_detected_without_echoing_it_in_error(self) -> None:
        scanner = SecretScanner(canaries=(CANARY,))
        findings = scanner.scan_text(f"prefix {CANARY} suffix", location="fixture")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].location, "fixture")
        with self.assertRaises(SecretDetectedError) as caught:
            scanner.assert_clean(CANARY, location="fixture")
        self.assertNotIn(CANARY, str(caught.exception))

    def test_standard_secret_shapes_are_detected_and_redacted(self) -> None:
        scanner = SecretScanner()
        value = "Authorization: Bearer fake-abcdefghijklmnopqrstuvwxyz1234567890"
        findings = scanner.scan_text(value)
        self.assertTrue(any(item.label == "bearer_token" for item in findings))
        redacted = scanner.redact_text(value)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", redacted)
        self.assertIn("[REDACTED:bearer_token]", redacted)

    def test_sanitize_removes_body_fields_binary_and_nested_canaries(self) -> None:
        scanner = SecretScanner(canaries=(CANARY,))
        sanitized = scanner.sanitize(
            {
                "request_body": {"unsafe": CANARY},
                "nested": ["safe", CANARY, {"api_key": "not-for-storage"}],
                "binary": CANARY.encode(),
            }
        )
        rendered = repr(sanitized)
        self.assertNotIn(CANARY, rendered)
        self.assertEqual(sanitized["nested"][0], "safe")
        self.assertEqual(sanitized["binary"], "[REDACTED:binary]")
        self.assertTrue(sanitized["request_body"].startswith("[REDACTED:"))

    def test_directory_scan_finds_canary_in_nested_file(self) -> None:
        scanner = SecretScanner(canaries=(CANARY,))
        with tempfile.TemporaryDirectory() as temporary:
            nested = Path(temporary, "nested")
            nested.mkdir()
            Path(nested, "safe.txt").write_text("metadata", encoding="utf-8")
            unsafe = Path(nested, "unsafe.txt")
            unsafe.write_text(CANARY, encoding="utf-8")
            findings = scanner.scan_files((temporary,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].location, str(unsafe))


if __name__ == "__main__":
    unittest.main()
