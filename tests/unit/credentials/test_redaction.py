from __future__ import annotations

import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from typing import ClassVar

from gatehouse.core.provider_numbers import ExactProviderNumber, parse_provider_number_token
from gatehouse.credentials.redaction import SecretDetectedError, SecretScanner

CANARY = "FAKE-CREDENTIAL-CANARY-1234567890"
MALFORMED_VALUE = "malformed-wrapper-value-must-not-leak-1234567890"


class _HostileExactProviderNumber(ExactProviderNumber):
    canonical_accesses: ClassVar[int] = 0
    string_accesses: ClassVar[int] = 0
    __hash__ = object.__hash__

    @property
    def canonical(self) -> str:
        type(self).canonical_accesses += 1
        raise AssertionError("subclass canonical property executed")

    def __str__(self) -> str:
        type(self).string_accesses += 1
        raise AssertionError("subclass string conversion executed")


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
                CANARY: "canary-key",
                "[REDACTED:registered_canary_1]": "collision",
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

    def test_exact_provider_wrapper_is_preserved_but_its_canonical_value_is_scanned(self) -> None:
        safe = parse_provider_number_token("123.45")
        scanner = SecretScanner(canaries=("12345678",))

        sanitized_safe = scanner.sanitize(safe)
        sanitized_canary = scanner.sanitize(parse_provider_number_token("12345678"))

        self.assertIs(sanitized_safe, safe)
        self.assertIsInstance(sanitized_safe, ExactProviderNumber)
        self.assertEqual(sanitized_canary, "[REDACTED:registered_canary_1]")
        with self.assertRaises(SecretDetectedError):
            scanner.assert_clean(parse_provider_number_token("12345678"))

    def test_malformed_and_subclass_wrappers_are_redacted_without_access_or_leakage(self) -> None:
        scanner = SecretScanner()
        uninitialized = object.__new__(ExactProviderNumber)
        corrupted = object.__new__(ExactProviderNumber)
        object.__setattr__(corrupted, "_coefficient", MALFORMED_VALUE)
        object.__setattr__(corrupted, "_exponent", 0)
        subclass = object.__new__(_HostileExactProviderNumber)
        object.__setattr__(subclass, "_coefficient", 1)
        object.__setattr__(subclass, "_exponent", 0)
        _HostileExactProviderNumber.canonical_accesses = 0
        _HostileExactProviderNumber.string_accesses = 0

        for value in (uninitialized, corrupted, subclass):
            sanitized = scanner.sanitize(value, location="forged")
            self.assertEqual(sanitized, "[REDACTED:invalid_exact_provider_number]")
            self.assertNotIn(MALFORMED_VALUE, sanitized)
            with self.assertRaises(SecretDetectedError) as caught:
                scanner.assert_clean(value, location="forged")
            self.assertEqual(caught.exception.findings[0].label, "invalid_exact_provider_number")
            self.assertEqual(caught.exception.findings[0].location, "forged")
            self.assertNotIn(MALFORMED_VALUE, str(caught.exception))

        self.assertEqual(_HostileExactProviderNumber.canonical_accesses, 0)
        self.assertEqual(_HostileExactProviderNumber.string_accesses, 0)

    def test_malformed_and_subclass_wrapper_mapping_keys_are_sanitized_safely(self) -> None:
        scanner = SecretScanner()
        valid = parse_provider_number_token("123.45")
        corrupted = parse_provider_number_token("678.9")
        corrupted_mapping = {corrupted: "safe"}
        object.__setattr__(corrupted, "_coefficient", MALFORMED_VALUE)
        subclass = object.__new__(_HostileExactProviderNumber)
        object.__setattr__(subclass, "_coefficient", 1)
        object.__setattr__(subclass, "_exponent", 0)
        _HostileExactProviderNumber.canonical_accesses = 0
        _HostileExactProviderNumber.string_accesses = 0

        sanitized_valid = scanner.sanitize({valid: "safe"})
        sanitized_corrupted = scanner.sanitize(corrupted_mapping)
        sanitized_subclass = scanner.sanitize({subclass: "safe"})

        self.assertEqual(sanitized_valid, {"123.45": "safe"})
        self.assertEqual(
            sanitized_corrupted,
            {"[REDACTED:invalid_exact_provider_number]": "safe"},
        )
        self.assertEqual(
            sanitized_subclass,
            {"[REDACTED:invalid_exact_provider_number]": "safe"},
        )
        self.assertNotIn(MALFORMED_VALUE, repr(sanitized_corrupted))
        self.assertEqual(_HostileExactProviderNumber.canonical_accesses, 0)
        self.assertEqual(_HostileExactProviderNumber.string_accesses, 0)

    def test_arbitrary_decimal_is_not_preserved_as_a_special_scalar(self) -> None:
        sanitized = SecretScanner().sanitize(Decimal("1.25"))

        self.assertEqual(sanitized, "1.25")
        self.assertNotIsInstance(sanitized, Decimal)


if __name__ == "__main__":
    unittest.main()
