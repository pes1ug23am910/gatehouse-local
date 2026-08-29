"""Provider-neutral values used by the invocation coordinator."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.errors import ErrorDetail
from gatehouse.core.ids import (
    ClientId,
    CredentialId,
    PoolId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import ApprovalState, InvocationState
from gatehouse.fingerprint.canonical import CanonicalValue
from gatehouse.fingerprint.hmac import RequestFingerprint
from gatehouse.policy import ClientClass
from gatehouse.policy.targets import CanonicalTarget
from gatehouse.providers import OperationSpec, ProviderErrorClass
from gatehouse.scheduler import PriorityClass


@dataclass(frozen=True, slots=True)
class InvocationRequest:
    request_id: RequestId
    access_token: str | None
    root_run_id: RootRunId
    service_id: str
    operation: str
    input_payload: Mapping[str, object]
    purpose: str
    data_classifications: frozenset[str]
    queue_deadline_ms: int
    approval_id: str | None = None
    result_format: str = "structured"

    def __post_init__(self) -> None:
        if not all(
            (
                self.service_id,
                self.operation,
                self.purpose,
                self.result_format,
            )
        ):
            raise ValueError("invocation request identifiers and purpose are required")
        if self.access_token is not None and not self.access_token:
            raise ValueError("invocation access token cannot be blank")
        require_utc_ms(self.queue_deadline_ms)
        if self.approval_id is not None and not self.approval_id:
            raise ValueError("approval identifier cannot be blank")
        object.__setattr__(self, "input_payload", MappingProxyType(dict(self.input_payload)))


@dataclass(frozen=True, slots=True)
class InvocationSession:
    session_id: SessionId
    client_id: ClientId
    root_run_id: RootRunId
    workspace_id: WorkspaceId
    client_class: ClientClass
    allowed_capabilities: frozenset[str]
    pool_bindings: Mapping[str, str]
    request_count_remaining: int
    credit_budget_remaining_units: int
    approval_mode: Literal["dashboard", "deny_on_ask", "denied"] = "dashboard"
    priority: PriorityClass = PriorityClass.NORMAL_AGENT
    feed_set_authorized: bool = False
    schedule_open: bool = True
    service_kill_switch_open: bool = False
    request_limit: int | None = None
    internal_resource_reconciliation: bool = False
    token_epoch: int = 0
    revocation_epoch: int = 0

    def __post_init__(self) -> None:
        if self.request_count_remaining < 0 or self.credit_budget_remaining_units < 0:
            raise ValueError("session budget counters cannot be negative")
        if self.token_epoch < 0 or self.revocation_epoch < 0:
            raise ValueError("session authorization epochs cannot be negative")
        if self.request_limit is not None and (
            isinstance(self.request_limit, bool)
            or not 0 <= self.request_limit < (1 << 63)
            or self.request_count_remaining > self.request_limit
        ):
            raise ValueError("session request limit is inconsistent")
        if not isinstance(self.internal_resource_reconciliation, bool):
            raise TypeError("internal reconciliation marker must be a boolean")
        if self.approval_mode not in {"dashboard", "deny_on_ask", "denied"}:
            raise ValueError("session approval mode is invalid")
        if not self.pool_bindings:
            raise ValueError("session requires at least one service pool binding")
        object.__setattr__(self, "pool_bindings", MappingProxyType(dict(self.pool_bindings)))


@dataclass(frozen=True, slots=True)
class ValidatedOperation:
    service_id: str
    operation: str
    spec: OperationSpec
    provider_payload: object

    def __post_init__(self) -> None:
        if self.spec.name != self.operation:
            raise ValueError("operation specification does not match the request")
        if not self.operation.startswith(f"{self.service_id}."):
            raise ValueError("operation must be qualified by the requested service")


@dataclass(frozen=True, slots=True)
class AsyncResourceReference:
    resource_type: str
    provider_resource_id: str

    def __post_init__(self) -> None:
        if not self.resource_type or not self.provider_resource_id:
            raise ValueError("asynchronous resource reference is incomplete")


@dataclass(frozen=True, slots=True)
class CanonicalOperation:
    validated: ValidatedOperation
    canonical_input: Mapping[str, CanonicalValue]
    canonical_target: CanonicalTarget | None = None
    async_resource_type: str | None = None
    resource_reference: AsyncResourceReference | None = None

    def __post_init__(self) -> None:
        if self.validated.spec.asynchronous and not self.async_resource_type:
            raise ValueError("asynchronous creation requires a resource type")
        object.__setattr__(
            self,
            "canonical_input",
            MappingProxyType(dict(self.canonical_input)),
        )

    @property
    def spec(self) -> OperationSpec:
        return self.validated.spec


@dataclass(frozen=True, slots=True)
class ClassifiedProviderOutcome:
    error_class: ProviderErrorClass
    data: Any = None
    retry_after_seconds: float | None = None
    provider_request_id: str | None = None
    actual_cost_units: int | None = None
    provider_resource_id: str | None = None
    submission_may_have_occurred: bool = False

    def __post_init__(self) -> None:
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            raise ValueError("retry-after cannot be negative")
        if self.actual_cost_units is not None and (
            isinstance(self.actual_cost_units, bool)
            or not isinstance(self.actual_cost_units, int)
            or not 0 <= self.actual_cost_units < (1 << 63)
        ):
            raise ValueError("actual cost must fit a non-negative SQLite integer")
        if self.provider_resource_id is not None and len(self.provider_resource_id) > 128:
            raise ValueError("provider resource identifier is too long")

    @property
    def succeeded(self) -> bool:
        return self.error_class is ProviderErrorClass.NONE


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    state: ApprovalState
    approval_id: str | None = None

    def __post_init__(self) -> None:
        if self.state is ApprovalState.APPROVED and not self.approval_id:
            raise ValueError("an approved resolution requires an approval identifier")


class PendingApprovalProbeStatus(StrEnum):
    ABSENT = "ABSENT"
    RECOVERABLE = "RECOVERABLE"
    MISMATCH = "MISMATCH"
    EXPIRED = "EXPIRED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class PendingApprovalProbe:
    status: PendingApprovalProbeStatus
    approval_id: str | None = None
    root_run_id: RootRunId | None = None

    def __post_init__(self) -> None:
        recoverable = self.status is PendingApprovalProbeStatus.RECOVERABLE
        if recoverable != (self.approval_id is not None and self.root_run_id is not None):
            raise ValueError("only a recoverable approval probe carries continuation authority")


@dataclass(frozen=True, slots=True)
class VerifiedPendingApproval:
    approval_id: str
    request_id: RequestId
    root_run_id: RootRunId
    fingerprint: RequestFingerprint

    def __post_init__(self) -> None:
        if not self.approval_id:
            raise ValueError("verified approval identifier cannot be blank")


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: str
    amount_units: int
    unit: str

    def __post_init__(self) -> None:
        if not self.reservation_id or not self.unit or self.amount_units <= 0:
            raise ValueError("budget reservation fields are invalid")


@dataclass(frozen=True, slots=True)
class InvocationStartEvent:
    """Secret-free facts required to create the durable invocation parent row."""

    request_id: RequestId
    session_id: SessionId
    root_run_id: RootRunId
    service_id: str
    operation: str
    priority: PriorityClass
    queue_deadline_ms: int
    occurred_at_ms: int
    request_limit: int | None = None
    internal_resource_reconciliation: bool = False

    def __post_init__(self) -> None:
        if not self.service_id or not self.operation:
            raise ValueError("invocation service and operation are required")
        require_utc_ms(self.queue_deadline_ms)
        require_utc_ms(self.occurred_at_ms)
        if self.request_limit is not None and (
            isinstance(self.request_limit, bool) or not 0 <= self.request_limit < (1 << 63)
        ):
            raise ValueError("invocation request limit cannot be negative")
        if not isinstance(self.internal_resource_reconciliation, bool):
            raise TypeError("internal reconciliation marker must be a boolean")


@dataclass(frozen=True, slots=True)
class InvocationValidatedEvent:
    """Canonical, body-free facts established by successful validation."""

    request_id: RequestId
    fingerprint: RequestFingerprint
    request_size_bytes: int
    estimated_cost_units: int
    cost_unit: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.request_size_bytes, bool)
            or not isinstance(self.request_size_bytes, int)
            or self.request_size_bytes < 0
        ):
            raise ValueError("validated request size must be a non-negative integer")
        if (
            isinstance(self.estimated_cost_units, bool)
            or not isinstance(self.estimated_cost_units, int)
            or self.estimated_cost_units < 0
        ):
            raise ValueError("estimated cost must be a non-negative integer")
        if not self.cost_unit:
            raise ValueError("validated cost unit is required")


@dataclass(frozen=True, slots=True)
class InvocationStateEvent:
    request_id: RequestId
    state: InvocationState
    occurred_at_ms: int
    metadata: Mapping[str, str | int | bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_utc_ms(self.occurred_at_ms)
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class AttemptEvent:
    request_id: RequestId
    ordinal: int
    state: InvocationState
    occurred_at_ms: int
    credential_id: str
    quota_scope_id: str
    provider_status_code: int | None = None
    provider_request_id: str | None = None
    error_class: ProviderErrorClass | None = None
    estimated_cost_units: int | None = None
    actual_cost_units: int | None = None
    cost_unit: str | None = None
    latency_ms: int | None = None
    resource_type: str | None = None
    provider_resource_id: str | None = None
    credential_generation: int | None = None
    pool_id: str | None = None
    dispatch_credential_generation: int | None = None
    dispatch_pool_id: str | None = None
    emergency_unlock_id: str | None = None

    def __post_init__(self) -> None:
        if self.ordinal <= 0 or not self.credential_id or not self.quota_scope_id:
            raise ValueError("attempt identity is invalid")
        require_utc_ms(self.occurred_at_ms)
        if self.provider_request_id is not None and (
            not self.provider_request_id or len(self.provider_request_id) > 256
        ):
            raise ValueError("provider request identifier is invalid")
        if self.provider_status_code is not None and not (100 <= self.provider_status_code <= 599):
            raise ValueError("provider status code is invalid")
        for value in (
            self.estimated_cost_units,
            self.actual_cost_units,
            self.latency_ms,
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 63)
            ):
                raise ValueError("attempt accounting values must fit non-negative SQLite integers")
        if self.cost_unit is not None and not self.cost_unit:
            raise ValueError("attempt cost unit cannot be blank")
        if self.emergency_unlock_id is not None:
            if (
                not isinstance(self.emergency_unlock_id, str)
                or not 16 <= len(self.emergency_unlock_id) <= 160
                or self.emergency_unlock_id != self.emergency_unlock_id.strip()
                or not all(character.isprintable() for character in self.emergency_unlock_id)
                or not isinstance(self.pool_id, str)
            ):
                raise ValueError("emergency attempt authority is invalid")
            try:
                CredentialId(self.credential_id)
                QuotaScopeId(self.quota_scope_id)
                PoolId(self.pool_id)
            except (TypeError, ValueError) as exc:
                raise ValueError("emergency attempt authority is invalid") from exc
            if any(
                value is not None
                for value in (
                    self.resource_type,
                    self.provider_resource_id,
                    self.credential_generation,
                    self.dispatch_credential_generation,
                    self.dispatch_pool_id,
                )
            ):
                raise ValueError(
                    "emergency attempt cannot carry an asynchronous resource checkpoint"
                )
            return

        dispatch_authority = (
            self.dispatch_credential_generation,
            self.dispatch_pool_id,
        )
        if not all(value is not None for value in dispatch_authority):
            raise ValueError("attempt dispatch authority is incomplete")
        if (
            isinstance(self.dispatch_credential_generation, bool)
            or not isinstance(self.dispatch_credential_generation, int)
            or self.dispatch_credential_generation <= 0
        ):
            raise ValueError("attempt dispatch credential generation is invalid")
        if not isinstance(self.dispatch_pool_id, str):
            raise ValueError("attempt dispatch pool identifier is invalid")
        try:
            PoolId(self.dispatch_pool_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("attempt dispatch pool identifier is invalid") from exc

        checkpoint = (
            self.resource_type,
            self.provider_resource_id,
            self.credential_generation,
            self.pool_id,
        )
        if any(value is not None for value in checkpoint):
            if not all(value is not None for value in checkpoint):
                raise ValueError("asynchronous resource checkpoint is incomplete")
            if self.state is not InvocationState.SUCCEEDED:
                raise ValueError("asynchronous resource checkpoint requires a successful attempt")
            if self.error_class is not ProviderErrorClass.NONE:
                raise ValueError("asynchronous resource checkpoint requires a successful outcome")
            if (
                not isinstance(self.resource_type, str)
                or not self.resource_type
                or len(self.resource_type) > 64
            ):
                raise ValueError("attempt resource type is invalid")
            if (
                not isinstance(self.provider_resource_id, str)
                or not self.provider_resource_id
                or len(self.provider_resource_id) > 128
            ):
                raise ValueError("attempt provider resource identifier is invalid")
            if (
                isinstance(self.credential_generation, bool)
                or not isinstance(self.credential_generation, int)
                or self.credential_generation <= 0
            ):
                raise ValueError("attempt credential generation is invalid")
            if not isinstance(self.pool_id, str):
                raise ValueError("attempt pool identifier is invalid")
            try:
                PoolId(self.pool_id)
            except (TypeError, ValueError) as exc:
                raise ValueError("attempt pool identifier is invalid") from exc


@dataclass(frozen=True, slots=True)
class InvocationResult:
    request_id: RequestId
    state: InvocationState
    attempts: int
    fingerprint: RequestFingerprint | None = None
    data: Any = None
    error: ErrorDetail | None = None
    provider_resource_id: str | None = None
    approval_id: str | None = None

    def __post_init__(self) -> None:
        if self.attempts < 0:
            raise ValueError("attempt count cannot be negative")
        if self.error is not None and self.data is not None:
            raise ValueError("an invocation result cannot contain data and an error")
        if self.state is InvocationState.SUCCEEDED and self.error is not None:
            raise ValueError("a successful invocation cannot contain an error")
        if self.approval_id is not None and not 1 <= len(self.approval_id) <= 160:
            raise ValueError("approval identifier must be non-empty and bounded")
