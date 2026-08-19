"""Secret-free administrative views and mutation contracts."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


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

    async def list_incidents(self, *, limit: int) -> Sequence[IncidentSummary]: ...

    async def reconciliation(self) -> Sequence[ReconciliationSummary]: ...
