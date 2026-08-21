"""Credential-free contracts shared by provider adapters and transports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class SideEffectClass(StrEnum):
    """Externally observable effect of an operation."""

    LOCAL_READ = "local_read"
    METERED_READ = "metered_read"
    ASYNC_CREATE = "async_create"
    MUTATION = "mutation"


class RetrySafety(StrEnum):
    """Evidence required before an operation may be repeated."""

    SAFE = "safe"
    IDEMPOTENCY_KEY = "idempotency_key"
    RECONCILE_FIRST = "reconcile_first"
    NEVER = "never"


class ProviderErrorClass(StrEnum):
    """Stable provider-independent failure classes."""

    NONE = "none"
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED = "unauthorized"
    QUOTA_EXHAUSTED = "quota_exhausted"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    TRANSIENT = "transient"
    MALFORMED_RESPONSE = "malformed_response"
    UNKNOWN_OUTCOME = "unknown_outcome"


class CredentialCustodyKind(StrEnum):
    """Exact custody authority permitted to satisfy a provider request."""

    PERSISTENT = "persistent"
    EMERGENCY = "emergency"


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """Static policy and execution properties for one typed operation."""

    name: str
    side_effect: SideEffectClass
    retry_safety: RetrySafety
    coalescible: bool
    asynchronous: bool
    default_estimated_cost: float
    cost_unit: str = "credits"
    maximum_request_bytes: int = 100_000
    maximum_response_bytes: int = 20_000_000
    default_timeout_ms: int = 30_000

    def __post_init__(self) -> None:
        if not self.name or "." not in self.name:
            raise ValueError("operation name must be service-qualified")
        if self.default_estimated_cost < 0:
            raise ValueError("estimated cost cannot be negative")
        if (
            min(
                self.maximum_request_bytes,
                self.maximum_response_bytes,
                self.default_timeout_ms,
            )
            <= 0
        ):
            raise ValueError("operation bounds must be positive")
        if self.coalescible and self.side_effect is not SideEffectClass.METERED_READ:
            raise ValueError("only metered reads may be coalesced")


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """A request with a fixed provider-relative path and no secret material."""

    method: str
    path: str
    credential_id: str
    credential_generation: int
    credential_custody: CredentialCustodyKind = CredentialCustodyKind.PERSISTENT
    json_body: Mapping[str, Any] | None = None
    query: Mapping[str, str | int | bool] = field(default_factory=dict)
    timeout_ms: int = 30_000
    maximum_response_bytes: int = 20_000_000
    operation: str = ""

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in {"GET", "POST", "DELETE"}:
            raise ValueError("unsupported provider method")
        if not self.path.startswith("/v2/") or "://" in self.path or "\\" in self.path:
            raise ValueError("provider path must be a fixed v2 relative path")
        if ".." in self.path.split("/"):
            raise ValueError("provider path traversal is forbidden")
        if not self.credential_id:
            raise ValueError("credential identifier is required")
        if (
            isinstance(self.credential_generation, bool)
            or not isinstance(self.credential_generation, int)
            or self.credential_generation <= 0
        ):
            raise ValueError("credential generation must be positive")
        try:
            credential_custody = CredentialCustodyKind(self.credential_custody)
        except (TypeError, ValueError):
            raise ValueError("credential custody kind is invalid") from None
        if self.timeout_ms <= 0 or self.maximum_response_bytes <= 0:
            raise ValueError("transport bounds must be positive")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "credential_custody", credential_custody)
        if self.json_body is not None:
            object.__setattr__(self, "json_body", MappingProxyType(dict(self.json_body)))
        object.__setattr__(self, "query", MappingProxyType(dict(self.query)))


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """Provider outcome after transport-level secret removal."""

    status_code: int | None
    data: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    provider_request_id: str | None = None
    transport_error: str | None = None
    submission_may_have_occurred: bool = False

    def __post_init__(self) -> None:
        if self.status_code is not None and not 100 <= self.status_code <= 599:
            raise ValueError("invalid HTTP status code")
        if self.elapsed_ms < 0:
            raise ValueError("elapsed time cannot be negative")
        safe_headers = {
            key.lower(): value
            for key, value in self.headers.items()
            if key.lower() in {"retry-after", "x-request-id", "content-type"}
        }
        object.__setattr__(self, "headers", MappingProxyType(safe_headers))

    @property
    def succeeded(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    @property
    def retry_after_seconds(self) -> float | None:
        raw = self.headers.get("retry-after")
        if raw is None:
            return None
        try:
            value = float(raw)
        except ValueError:
            return None
        return value if value >= 0 else None
