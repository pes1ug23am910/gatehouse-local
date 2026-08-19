"""Domain-separated, versioned HMAC request fingerprints."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .canonical import CanonicalValue, canonical_json_bytes


@dataclass(frozen=True, slots=True)
class FingerprintContext:
    service: str
    operation: str
    normalized_input: Mapping[str, CanonicalValue]
    workspace_scope: str
    data_scope: str
    authorization_scope: str
    result_format: str
    additional_scope: Mapping[str, CanonicalValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        required = (
            self.service,
            self.operation,
            self.workspace_scope,
            self.data_scope,
            self.authorization_scope,
            self.result_format,
        )
        if any(not value for value in required):
            raise ValueError("fingerprint scope fields cannot be empty")
        object.__setattr__(self, "normalized_input", MappingProxyType(dict(self.normalized_input)))
        object.__setattr__(self, "additional_scope", MappingProxyType(dict(self.additional_scope)))

    def semantic_value(self, *, canonicalization_version: int) -> Mapping[str, object]:
        return {
            "authorization_scope": self.authorization_scope,
            "canonicalization_version": canonicalization_version,
            "data_scope": self.data_scope,
            "input": self.normalized_input,
            "operation": self.operation,
            "result_format": self.result_format,
            "scope": self.additional_scope,
            "service": self.service,
            "workspace_scope": self.workspace_scope,
        }


@dataclass(frozen=True, slots=True)
class RequestFingerprint:
    digest: bytes
    fingerprint_version: int
    canonicalization_version: int

    def __post_init__(self) -> None:
        if len(self.digest) != 32:
            raise ValueError("request fingerprint must be a SHA-256 HMAC")
        if self.fingerprint_version <= 0 or self.canonicalization_version <= 0:
            raise ValueError("fingerprint versions must be positive")

    def __str__(self) -> str:
        encoded = base64.urlsafe_b64encode(self.digest).rstrip(b"=").decode("ascii")
        return f"hmac:v{self.fingerprint_version}:c{self.canonicalization_version}:{encoded}"

    @property
    def key(self) -> tuple[int, int, bytes]:
        return (
            self.fingerprint_version,
            self.canonicalization_version,
            self.digest,
        )


class FingerprintService:
    _DOMAIN = b"gatehouse/request-fingerprint\x00"

    def __init__(
        self,
        key: bytes,
        *,
        fingerprint_version: int = 1,
        canonicalization_version: int = 1,
    ) -> None:
        if len(key) < 32:
            raise ValueError("fingerprint key must contain at least 256 bits")
        if fingerprint_version <= 0 or canonicalization_version <= 0:
            raise ValueError("fingerprint versions must be positive")
        self._key = key
        self.fingerprint_version = fingerprint_version
        self.canonicalization_version = canonicalization_version

    def calculate(self, context: FingerprintContext) -> RequestFingerprint:
        canonical = canonical_json_bytes(
            context.semantic_value(
                canonicalization_version=self.canonicalization_version,
            )
        )
        version_prefix = (
            f"f{self.fingerprint_version}:c{self.canonicalization_version}\x00".encode()
        )
        digest = hmac.new(
            self._key,
            self._DOMAIN + version_prefix + canonical,
            hashlib.sha256,
        ).digest()
        return RequestFingerprint(
            digest=digest,
            fingerprint_version=self.fingerprint_version,
            canonicalization_version=self.canonicalization_version,
        )
