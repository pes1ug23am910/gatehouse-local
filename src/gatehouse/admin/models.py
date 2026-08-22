"""Secret-free administrative views and mutation contracts."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gatehouse.core.provider_numbers import (
    MAX_PROVIDER_FIXED_POINT_CHARS,
    SQLITE_INT64_MAX,
    parse_canonical_provider_number,
    project_routing_units,
)


class StrictAdminModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AdminStatus(StrictAdminModel):
    service_state: Annotated[str, Field(min_length=1, max_length=64)]
    uptime_seconds: Annotated[int, Field(ge=0)]
    active_sessions: Annotated[int, Field(ge=0)]
    in_flight_requests: Annotated[int, Field(ge=0)]
    queued_requests: Annotated[int, Field(ge=0)]
    pending_approvals: Annotated[int, Field(ge=0)]
    high_severity_incidents: Annotated[int, Field(ge=0)]


class ApprovalView(StrictAdminModel):
    approval_id: Annotated[str, Field(min_length=1, max_length=160)]
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    client_id: Annotated[str, Field(min_length=1, max_length=160)]
    workspace_id: Annotated[str | None, Field(max_length=256)] = None
    service: Annotated[str, Field(min_length=1, max_length=64)]
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    request_fingerprint: Annotated[str, Field(min_length=16, max_length=256)]
    target_summary: Annotated[str, Field(min_length=1, max_length=1_000)]
    pool: Annotated[str, Field(min_length=1, max_length=160)]
    maximum_estimated_cost: Annotated[int, Field(ge=0)]
    maximum_uses: Literal[1] = 1
    expires_at_ms: Annotated[int, Field(ge=0)]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    action_token: Annotated[str, Field(min_length=32, max_length=256)]


class ApprovalActionRequest(StrictAdminModel):
    action_token: Annotated[str, Field(min_length=32, max_length=256)]
    request_fingerprint: Annotated[str, Field(min_length=16, max_length=256)]
    maximum_estimated_cost: Annotated[int, Field(ge=0)]
    maximum_uses: Literal[1]


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class ApprovalActionResult(StrictAdminModel):
    approval_id: str
    state: str
    acted_at_ms: Annotated[int, Field(ge=0)]


class PoolSummary(StrictAdminModel):
    pool_id: str
    service: str
    state: str
    eligible_credentials: Annotated[int, Field(ge=0)]
    in_flight: Annotated[int, Field(ge=0)]


class CredentialSummary(StrictAdminModel):
    credential_id: str
    service: str
    alias: str
    principal_id: str
    quota_scope_id: str
    state: str
    generation: Annotated[int, Field(ge=1)]
    exclusive_usage: bool
    principal_alias: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_alias: Annotated[str, Field(min_length=1, max_length=160)]
    pool_ids: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=160)], ...],
        Field(max_length=200),
    ]
    pool_aliases: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=160)], ...],
        Field(max_length=200),
    ]
    active_lease_count: Annotated[int, Field(ge=0)]
    created_at_ms: Annotated[int, Field(ge=0)]
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None
    last_used_at_ms: Annotated[int | None, Field(ge=0)] = None
    last_local_action: Annotated[str | None, Field(max_length=64)] = None


class CredentialProvisionRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    principal_id: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_id: Annotated[str, Field(min_length=1, max_length=160)]
    pool_id: Annotated[str, Field(min_length=1, max_length=160)]
    alias: Annotated[str, Field(min_length=1, max_length=160)]
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None
    exclusive_usage: bool = True


class CredentialRotationRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None


class CredentialStateChangeRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    action: Literal["disable", "quarantine", "retire"]
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class CredentialMutationResult(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    credential_id: Annotated[str, Field(min_length=1, max_length=160)]
    action: Literal["provision", "rotate", "disable", "quarantine", "retire"]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    generation: Annotated[int, Field(ge=1)]
    alias: Annotated[str, Field(min_length=1, max_length=160)]
    principal_id: Annotated[str, Field(min_length=1, max_length=160)]
    principal_alias: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_id: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_alias: Annotated[str, Field(min_length=1, max_length=160)]
    pool_id: Annotated[str, Field(min_length=1, max_length=160)]
    pool_alias: Annotated[str, Field(min_length=1, max_length=160)]
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None
    acted_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]


class CredentialValidationRequest(StrictAdminModel):
    """Bind one validation dispatch to an exact installed generation."""

    expected_generation: Annotated[int, Field(ge=1)]


class CredentialValidationResult(StrictAdminModel):
    """Strict, provider-body-free result of an administrative validation."""

    credential_id: Annotated[str, Field(min_length=1, max_length=160)]
    generation: Annotated[int, Field(ge=1)]
    service: Literal["firecrawl"]
    principal_id: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_id: Annotated[str, Field(min_length=1, max_length=160)]
    state: Literal["authenticated"]
    snapshot_id: Annotated[str, Field(min_length=1, max_length=160)]
    unit: Literal["credits"]
    remaining_units: Annotated[int, Field(ge=0, le=SQLITE_INT64_MAX)]
    plan_total_units: Annotated[int | None, Field(ge=0, le=SQLITE_INT64_MAX)] = None
    observed_remaining_units_decimal: Annotated[
        str,
        Field(min_length=1, max_length=MAX_PROVIDER_FIXED_POINT_CHARS),
    ]
    observed_plan_total_units_decimal: Annotated[
        str | None,
        Field(min_length=1, max_length=MAX_PROVIDER_FIXED_POINT_CHARS),
    ] = None
    captured_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]

    @model_validator(mode="after")
    def validate_exact_observations(self) -> CredentialValidationResult:
        remaining = parse_canonical_provider_number(self.observed_remaining_units_decimal)
        if project_routing_units(remaining) != self.remaining_units:
            raise ValueError("remaining credit projection is inconsistent")
        if (self.plan_total_units is None) != (self.observed_plan_total_units_decimal is None):
            raise ValueError("plan credit counters are inconsistently nullable")
        if self.plan_total_units is not None:
            assert self.observed_plan_total_units_decimal is not None
            plan = parse_canonical_provider_number(self.observed_plan_total_units_decimal)
            if project_routing_units(plan) != self.plan_total_units:
                raise ValueError("plan credit projection is inconsistent")
        return self


class EmergencyUnlockRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    service: Literal["firecrawl"]
    pool_id: Annotated[str, Field(min_length=1, max_length=160)]
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    root_run_id: Annotated[str, Field(min_length=1, max_length=160)]
    alias: Annotated[str, Field(min_length=1, max_length=160)]
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    duration_ms: Annotated[int, Field(ge=1, le=15 * 60 * 1_000)]
    maximum_requests: Annotated[int, Field(ge=1, le=25)]
    maximum_credits: Annotated[int, Field(ge=1, le=100)]
    maximum_concurrency: Literal[1]


class EmergencyUnlockCancelRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class EmergencyUnlockView(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    unlock_id: Annotated[str, Field(min_length=1, max_length=160)]
    credential_id: Annotated[str, Field(min_length=1, max_length=160)]
    action: Literal["unlock", "cancel"]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    generation: Annotated[int, Field(ge=1)]
    service: Literal["firecrawl"]
    alias: Annotated[str, Field(min_length=1, max_length=160)]
    principal_id: Annotated[str, Field(min_length=1, max_length=160)]
    principal_alias: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_id: Annotated[str, Field(min_length=1, max_length=160)]
    quota_scope_alias: Annotated[str, Field(min_length=1, max_length=160)]
    pool_id: Annotated[str, Field(min_length=1, max_length=160)]
    pool_alias: Annotated[str, Field(min_length=1, max_length=160)]
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    root_run_id: Annotated[str, Field(min_length=1, max_length=160)]
    expires_at_ms: Annotated[int, Field(ge=0)]
    remaining_requests: Annotated[int, Field(ge=0, le=25)]
    remaining_credits: Annotated[int, Field(ge=0, le=100)]
    remaining_concurrency: Literal[0, 1]
    acted_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]


class IncidentSummary(StrictAdminModel):
    incident_id: str
    severity: str
    category: str
    summary: Annotated[str, Field(min_length=1, max_length=1_000)]
    state: str
    created_at_ms: Annotated[int, Field(ge=0)]


class ReconciliationSummary(StrictAdminModel):
    service: str
    state: str
    last_completed_at_ms: Annotated[int | None, Field(ge=0)] = None
    unresolved_reservations: Annotated[int, Field(ge=0)]
    ledger_mismatch_count: Annotated[int, Field(ge=0)]


class AdminBackend(Protocol):
    """Persistence/routing integration point for the separate admin realm."""

    async def status(self) -> AdminStatus: ...

    async def list_approvals(self, *, limit: int) -> Sequence[ApprovalView]: ...

    async def get_approval(self, approval_id: str) -> ApprovalView | None: ...

    async def decide_approval(
        self,
        *,
        approval: ApprovalView,
        decision: ApprovalDecision,
        now_ms: int,
    ) -> ApprovalActionResult: ...

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]: ...

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]: ...

    async def provision_credential(
        self,
        request: CredentialProvisionRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult: ...

    async def rotate_credential(
        self,
        credential_id: str,
        request: CredentialRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult: ...

    async def change_credential_state(
        self,
        credential_id: str,
        request: CredentialStateChangeRequest,
        actor_id: str,
    ) -> CredentialMutationResult: ...

    async def validate_credential(
        self,
        credential_id: str,
        request: CredentialValidationRequest,
        actor_id: str,
    ) -> CredentialValidationResult: ...

    async def unlock_emergency(
        self,
        request: EmergencyUnlockRequest,
        secret: bytearray,
        actor_id: str,
    ) -> EmergencyUnlockView: ...

    async def cancel_emergency_unlock(
        self,
        unlock_id: str,
        request: EmergencyUnlockCancelRequest,
        actor_id: str,
    ) -> EmergencyUnlockView: ...

    async def list_emergency_unlocks(
        self,
        *,
        limit: int,
    ) -> Sequence[EmergencyUnlockView]: ...

    async def list_incidents(self, *, limit: int) -> Sequence[IncidentSummary]: ...

    async def reconciliation(self) -> Sequence[ReconciliationSummary]: ...
