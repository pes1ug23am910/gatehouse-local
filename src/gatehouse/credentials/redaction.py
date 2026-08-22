"""Central secret-pattern detection, redaction, and fake-canary scanning."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gatehouse.core.provider_numbers import (
    ExactProviderNumber,
    ProviderNumberError,
    require_exact_provider_number,
)


@dataclass(frozen=True, slots=True)
class SecretFinding:
    label: str
    location: str


class SecretDetectedError(RuntimeError):
    """Raised without echoing the matched secret material."""

    def __init__(self, findings: Sequence[SecretFinding]) -> None:
        self.findings = tuple(findings)
        summary = ", ".join(f"{item.label}@{item.location}" for item in self.findings)
        super().__init__(f"sensitive material detected: {summary}")


DEFAULT_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("github_token", re.compile(r"(?i)\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b")),
    ("firecrawl_token", re.compile(r"(?i)\bfc-[A-Za-z0-9_-]{20,}\b")),
    ("generic_sk_token", re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}\b"),
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:[A-Z][A-Z0-9]*_)*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|"
            r"REFRESH_TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\s*[:=]\s*[\"']?[^\s\"']{8,}"
        ),
    ),
)


_SENSITIVE_FIELD_NAMES = frozenset(
    {
        "authorization",
        "authorization_header",
        "api_key",
        "credential",
        "credential_value",
        "password",
        "private_key",
        "provider_key",
        "request_body",
        "response_body",
        "page_content",
        "raw_content",
        "secret",
        "session_bootstrap",
        "access_token",
        "refresh_token",
    }
)

_INVALID_EXACT_PROVIDER_NUMBER = "[REDACTED:invalid_exact_provider_number]"


class SecretScanner:
    """Detect known key shapes and caller-registered fake canaries."""

    def __init__(
        self,
        *,
        canaries: Iterable[str | bytes] = (),
        patterns: tuple[tuple[str, re.Pattern[str]], ...] = DEFAULT_SECRET_PATTERNS,
    ) -> None:
        self._patterns = patterns
        self._canaries: list[str] = []
        for canary in canaries:
            self.register_canary(canary)

    def register_canary(self, canary: str | bytes) -> None:
        text = canary.decode("utf-8", "strict") if isinstance(canary, bytes) else canary
        if len(text) < 8:
            raise ValueError("canaries must be at least 8 characters to avoid false positives")
        if text not in self._canaries:
            self._canaries.append(text)
            self._canaries.sort(key=len, reverse=True)

    def scan_text(self, text: str, *, location: str = "text") -> tuple[SecretFinding, ...]:
        findings: list[SecretFinding] = []
        for index, canary in enumerate(self._canaries, start=1):
            if canary in text:
                findings.append(SecretFinding(f"registered_canary_{index}", location))
        for label, pattern in self._patterns:
            if pattern.search(text):
                findings.append(SecretFinding(label, location))
        return tuple(findings)

    def scan_bytes(
        self,
        value: bytes | bytearray | memoryview,
        *,
        location: str = "bytes",
    ) -> tuple[SecretFinding, ...]:
        raw = bytes(value)
        text = raw.decode("utf-8", "ignore")
        return self.scan_text(text, location=location)

    def scan_file(self, path: str | Path) -> tuple[SecretFinding, ...]:
        resolved = Path(path)
        return self.scan_bytes(resolved.read_bytes(), location=str(resolved))

    def scan_files(self, paths: Iterable[str | Path]) -> tuple[SecretFinding, ...]:
        findings: list[SecretFinding] = []
        for path in paths:
            resolved = Path(path)
            if resolved.is_dir():
                for root, _, filenames in os.walk(resolved):
                    for filename in filenames:
                        findings.extend(self.scan_file(Path(root, filename)))
            elif resolved.is_file():
                findings.extend(self.scan_file(resolved))
        return tuple(findings)

    def assert_clean(
        self,
        value: str | bytes | ExactProviderNumber,
        *,
        location: str = "value",
    ) -> None:
        if isinstance(value, ExactProviderNumber):
            try:
                exact = require_exact_provider_number(value)
                canonical = exact.canonical
            except ProviderNumberError:
                raise SecretDetectedError(
                    (SecretFinding("invalid_exact_provider_number", location),)
                ) from None
            findings = self.scan_text(canonical, location=location)
        elif isinstance(value, bytes):
            findings = self.scan_bytes(value, location=location)
        else:
            findings = self.scan_text(value, location=location)
        if findings:
            raise SecretDetectedError(findings)

    def redact_text(self, text: str) -> str:
        redacted = text
        for index, canary in enumerate(self._canaries, start=1):
            redacted = redacted.replace(canary, f"[REDACTED:registered_canary_{index}]")
        for label, pattern in self._patterns:
            redacted = pattern.sub(f"[REDACTED:{label}]", redacted)
        return redacted

    def sanitize(self, value: Any, *, location: str = "payload") -> Any:
        """Return sanitized data with body and secret fields removed.

        ``ExactProviderNumber`` is the sole preserved non-JSON-compatible scalar. It is
        transport-internal and must be consumed before generic JSON serialization.
        """

        if isinstance(value, ExactProviderNumber):
            try:
                exact = require_exact_provider_number(value)
                canonical = exact.canonical
            except ProviderNumberError:
                return _INVALID_EXACT_PROVIDER_NUMBER
            redacted = self.redact_text(canonical)
            return exact if redacted == canonical else redacted
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return "[REDACTED:binary]"
        if isinstance(value, Mapping):
            sanitized: dict[str, Any] = {}
            for index, (raw_key, item) in enumerate(value.items()):
                if isinstance(raw_key, ExactProviderNumber):
                    try:
                        key = require_exact_provider_number(raw_key).canonical
                    except ProviderNumberError:
                        key = _INVALID_EXACT_PROVIDER_NUMBER
                else:
                    key = str(raw_key)
                safe_key = self.redact_text(key)
                if safe_key in sanitized:
                    safe_key = f"{safe_key}#{index}"
                if key.casefold() in _SENSITIVE_FIELD_NAMES:
                    sanitized[safe_key] = f"[REDACTED:{key.casefold()}]"
                else:
                    sanitized[safe_key] = self.sanitize(
                        item,
                        location=f"{location}.{safe_key}",
                    )
            return sanitized
        if isinstance(value, Sequence):
            return [
                self.sanitize(item, location=f"{location}[{index}]")
                for index, item in enumerate(value)
            ]
        return self.redact_text(str(value))
