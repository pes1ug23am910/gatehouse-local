"""Stable public error codes and structured response envelopes."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from .clock import require_utc_ms
from .ids import RequestId

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class ErrorCode(StrEnum):
    INVALID_SESSION = "invalid_session"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    ATTRIBUTED_SESSION_REQUIRED = "attributed_session_required"
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"
    POLICY_DENIED = "policy_denied"
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_UNAVAILABLE_FOR_UNATTENDED_CLIENT = "approval_unavailable_for_unattended_client"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RUNAWAY_SUSPECTED = "runaway_suspected"
    DUPLICATE_IN_FLIGHT = "duplicate_in_flight"
    INVALID_TARGET = "invalid_target"
    SENSITIVE_PAYLOAD_DENIED = "sensitive_payload_denied"
    NO_ELIGIBLE_POOL = "no_eligible_pool"
    NO_ELIGIBLE_CREDENTIAL = "no_eligible_credential"
    QUOTA_EXHAUSTED = "quota_exhausted"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_PERMISSION_DENIED = "provider_permission_denied"
    PROVIDER_UNAUTHORIZED = "provider_unauthorized"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    UNCERTAIN_OUTCOME = "uncertain_outcome"
    RESULT_UNAVAILABLE_AFTER_RESTART = "result_unavailable_after_restart"
    DAEMON_DEGRADED = "daemon_degraded"


@dataclass(frozen=True, slots=True)
class ErrorDefinition:
    """Stable catalogue entry for a machine-readable error code."""

    message: str
    retryable_by_default: bool


_ERROR_DEFINITIONS: dict[ErrorCode, ErrorDefinition] = {
    ErrorCode.INVALID_SESSION: ErrorDefinition("The session could not be authenticated.", False),
    ErrorCode.SESSION_EXPIRED: ErrorDefinition("The session has expired.", False),
    ErrorCode.SESSION_REVOKED: ErrorDefinition("The session has been revoked.", False),
    ErrorCode.ATTRIBUTED_SESSION_REQUIRED: ErrorDefinition(
        "This operation requires an attributed session.", False
    ),
    ErrorCode.SCHEMA_VALIDATION_FAILED: ErrorDefinition(
        "The request did not match the required schema.", False
    ),
    ErrorCode.POLICY_DENIED: ErrorDefinition("Policy denied the operation.", False),
    ErrorCode.APPROVAL_PENDING: ErrorDefinition("The operation is waiting for approval.", True),
    ErrorCode.APPROVAL_EXPIRED: ErrorDefinition("The approval has expired.", False),
    ErrorCode.APPROVAL_UNAVAILABLE_FOR_UNATTENDED_CLIENT: ErrorDefinition(
        "An unattended client cannot wait for approval.", False
    ),
    ErrorCode.CAPACITY_EXCEEDED: ErrorDefinition(
        "The configured capacity is currently exhausted.", True
    ),
    ErrorCode.BUDGET_EXHAUSTED: ErrorDefinition("The applicable budget is exhausted.", False),
    ErrorCode.RUNAWAY_SUSPECTED: ErrorDefinition(
        "Request activity exceeded the configured safety threshold.", True
    ),
    ErrorCode.DUPLICATE_IN_FLIGHT: ErrorDefinition(
        "An equivalent request is already in flight.", True
    ),
    ErrorCode.INVALID_TARGET: ErrorDefinition("The target is not permitted.", False),
    ErrorCode.SENSITIVE_PAYLOAD_DENIED: ErrorDefinition(
        "The payload contains a denied data classification.", False
    ),
    ErrorCode.NO_ELIGIBLE_POOL: ErrorDefinition("No authorized resource pool is eligible.", False),
    ErrorCode.NO_ELIGIBLE_CREDENTIAL: ErrorDefinition(
        "No eligible credential is available.", False
    ),
    ErrorCode.QUOTA_EXHAUSTED: ErrorDefinition("The authorized quota is exhausted.", True),
    ErrorCode.PROVIDER_RATE_LIMITED: ErrorDefinition("The external service is rate limited.", True),
    ErrorCode.PROVIDER_PERMISSION_DENIED: ErrorDefinition(
        "The external service denied permission for the operation.", False
    ),
    ErrorCode.PROVIDER_UNAUTHORIZED: ErrorDefinition(
        "The external service rejected the credential.", False
    ),
    ErrorCode.PROVIDER_TIMEOUT: ErrorDefinition(
        "The external service did not respond before the deadline.", False
    ),
    ErrorCode.PROVIDER_UNAVAILABLE: ErrorDefinition("The external service is unavailable.", True),
    ErrorCode.UNCERTAIN_OUTCOME: ErrorDefinition(
        "The external side effect could not be determined safely.", False
    ),
    ErrorCode.RESULT_UNAVAILABLE_AFTER_RESTART: ErrorDefinition(
        "The completed result is no longer available after restart.", False
    ),
    ErrorCode.DAEMON_DEGRADED: ErrorDefinition(
        "The local service is operating in a degraded state.", True
    ),
}

if set(_ERROR_DEFINITIONS) != set(ErrorCode):  # pragma: no cover - import-time invariant
    raise RuntimeError("the error catalogue must define every error code exactly once")

ERROR_CATALOGUE: Mapping[ErrorCode, ErrorDefinition] = MappingProxyType(_ERROR_DEFINITIONS)


def _copy_json(value: object, *, path: str = "details") -> JsonValue:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            result[key] = _copy_json(child, path=f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_copy_json(child, path=f"{path}[]") for child in value]
    raise TypeError(f"{path} contains a value that is not JSON-compatible")


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    code: ErrorCode
    message: str
    retryable: bool
    retry_after_seconds: int | None = None
    provider_reset_at_ms: int | None = None
    request_id: RequestId | None = None
    policy_rule_id: str | None = None
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.code, ErrorCode):
            raise TypeError("error code must be an ErrorCode")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("error message must not be blank")
        if not isinstance(self.retryable, bool):
            raise TypeError("retryable must be a boolean")
        if self.retry_after_seconds is not None:
            if (
                isinstance(self.retry_after_seconds, bool)
                or not isinstance(self.retry_after_seconds, int)
                or self.retry_after_seconds <= 0
            ):
                raise ValueError("retry_after_seconds must be a positive integer")
        if self.provider_reset_at_ms is not None:
            require_utc_ms(self.provider_reset_at_ms)
        if self.retryable:
            if self.retry_after_seconds is None and self.provider_reset_at_ms is None:
                raise ValueError("retryable errors require a retry delay or reset timestamp")
        elif self.retry_after_seconds is not None or self.provider_reset_at_ms is not None:
            raise ValueError("non-retryable errors cannot include retry timing")
        if self.request_id is not None and not isinstance(self.request_id, RequestId):
            raise TypeError("request_id must be a RequestId")
        if self.policy_rule_id is not None:
            if not isinstance(self.policy_rule_id, str) or not self.policy_rule_id.strip():
                raise ValueError("policy_rule_id must not be blank")

        copied = _copy_json(self.details)
        if not isinstance(copied, dict):  # Mapping always copies to dict; defensive invariant.
            raise TypeError("error details must be a JSON object")
        object.__setattr__(self, "details", MappingProxyType(copied))

    def to_dict(self) -> dict[str, JsonValue]:
        copied_details = _copy_json(self.details)
        if not isinstance(copied_details, dict):  # pragma: no cover - fixed field shape
            raise TypeError("error details must be a JSON object")
        return {
            "code": self.code.value,
            "message": self.message,
            "retryable": self.retryable,
            "retry_after_seconds": self.retry_after_seconds,
            "provider_reset_at_ms": self.provider_reset_at_ms,
            "request_id": str(self.request_id) if self.request_id is not None else None,
            "policy_rule_id": self.policy_rule_id,
            "details": copied_details,
        }


@dataclass(frozen=True, slots=True)
class ErrorEnvelope:
    error: ErrorDetail

    def to_dict(self) -> dict[str, JsonValue]:
        return {"error": self.error.to_dict()}


class GatehouseError(Exception):
    """Exception carrying a safe, serializable public error envelope."""

    def __init__(self, detail: ErrorDetail) -> None:
        self.detail = detail
        super().__init__(detail.message)

    @property
    def envelope(self) -> ErrorEnvelope:
        return ErrorEnvelope(self.detail)

    def to_dict(self) -> dict[str, JsonValue]:
        return self.envelope.to_dict()


def make_error(
    code: ErrorCode,
    *,
    retryable: bool | None = None,
    retry_after_seconds: int | None = None,
    provider_reset_at_ms: int | None = None,
    request_id: RequestId | None = None,
    policy_rule_id: str | None = None,
    details: Mapping[str, object] | None = None,
) -> GatehouseError:
    """Build an exception using the stable message and defaults for ``code``."""

    definition = ERROR_CATALOGUE[code]
    resolved_retryable = definition.retryable_by_default if retryable is None else retryable
    copied_details = _copy_json(details or {})
    if not isinstance(copied_details, dict):  # pragma: no cover - fixed input shape
        raise TypeError("error details must be a JSON object")
    return GatehouseError(
        ErrorDetail(
            code=code,
            message=definition.message,
            retryable=resolved_retryable,
            retry_after_seconds=retry_after_seconds,
            provider_reset_at_ms=provider_reset_at_ms,
            request_id=request_id,
            policy_rule_id=policy_rule_id,
            details=copied_details,
        )
    )
