"""Secret-free administrative views and mutation contracts."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gatehouse.core.provider_numbers import (
    MAX_PROVIDER_FIXED_POINT_CHARS,
    SQLITE_INT64_MAX,
    parse_canonical_provider_number,
    project_routing_units,
)
from gatehouse.database.runaway import (
    MAXIMUM_BURST_CONCURRENCY,
    MAXIMUM_BURST_CREDITS,
    MAXIMUM_BURST_DURATION_MS,
    MAXIMUM_BURST_OPERATIONS,
    MAXIMUM_BURST_REQUESTS,
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


class RunawayQuarantineView(StrictAdminModel):
    quarantine_id: Annotated[str, Field(min_length=1, max_length=160)]
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    client_id: Annotated[str, Field(min_length=1, max_length=160)]
    workspace_id: Annotated[str | None, Field(max_length=256)] = None
    root_run_id: Annotated[str, Field(min_length=1, max_length=160)]
    service: Annotated[str, Field(min_length=1, max_length=64)]
    state: Literal["OPEN", "AUTHORIZED", "DENIED", "EXPIRED", "EXHAUSTED"]
    trigger: Literal["REPEATED_EQUIVALENT", "AGGREGATE_BURST", "DETECTOR_CAPACITY"]
    trigger_operation: Annotated[str, Field(min_length=1, max_length=160)]
    generation: Annotated[int, Field(ge=1)]
    opened_at_ms: Annotated[int, Field(ge=0)]
    updated_at_ms: Annotated[int, Field(ge=0)]
    decided_at_ms: Annotated[int | None, Field(ge=0)] = None
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None
    maximum_requests: Annotated[
        int | None,
        Field(ge=1, le=MAXIMUM_BURST_REQUESTS),
    ] = None
    remaining_requests: Annotated[
        int | None,
        Field(ge=0, le=MAXIMUM_BURST_REQUESTS),
    ] = None
    maximum_credits: Annotated[
        int | None,
        Field(ge=1, le=MAXIMUM_BURST_CREDITS),
    ] = None
    remaining_credits: Annotated[
        int | None,
        Field(ge=0, le=MAXIMUM_BURST_CREDITS),
    ] = None
    maximum_concurrency: Annotated[
        int | None,
        Field(ge=1, le=MAXIMUM_BURST_CONCURRENCY),
    ] = None
    active_concurrency: Annotated[int, Field(ge=0, le=MAXIMUM_BURST_CONCURRENCY)]
    operations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=160)], ...],
        Field(max_length=MAXIMUM_BURST_OPERATIONS),
    ]
    fresh_run_recovery_id: Annotated[str | None, Field(max_length=160)] = None
    fresh_run_recovered_at_ms: Annotated[int | None, Field(ge=0)] = None
    action_token: Annotated[str, Field(min_length=32, max_length=256)]

    @model_validator(mode="after")
    def validate_burst_projection(self) -> RunawayQuarantineView:
        grant_fields = (
            self.maximum_requests,
            self.remaining_requests,
            self.maximum_credits,
            self.remaining_credits,
            self.maximum_concurrency,
        )
        if self.state == "OPEN":
            if (
                any(value is not None for value in grant_fields)
                or self.operations
                or self.decided_at_ms is not None
                or self.expires_at_ms is not None
            ):
                raise ValueError("inactive quarantine cannot expose a burst grant")
        elif self.state == "DENIED":
            if (
                any(value is not None for value in grant_fields)
                or self.operations
                or self.decided_at_ms is None
                or self.expires_at_ms is not None
            ):
                raise ValueError("denied quarantine has an inconsistent decision projection")
        elif (
            any(value is None for value in grant_fields)
            or not self.operations
            or self.decided_at_ms is None
            or self.expires_at_ms is None
        ):
            raise ValueError("bounded quarantine state requires a complete burst grant")
        if (
            self.maximum_requests is not None
            and self.remaining_requests is not None
            and self.remaining_requests > self.maximum_requests
        ):
            raise ValueError("remaining burst requests exceed the grant")
        if (
            self.maximum_credits is not None
            and self.remaining_credits is not None
            and self.remaining_credits > self.maximum_credits
        ):
            raise ValueError("remaining burst credits exceed the grant")
        if (
            self.maximum_concurrency is not None
            and self.active_concurrency > self.maximum_concurrency
        ):
            raise ValueError("active burst concurrency exceeds the grant")
        if len(set(self.operations)) != len(self.operations):
            raise ValueError("burst operation allowlist contains duplicates")
        if (self.fresh_run_recovery_id is None) != (self.fresh_run_recovered_at_ms is None):
            raise ValueError("fresh-run recovery projection is incomplete")
        return self


class RunawayBurstAuthorizeRequest(StrictAdminModel):
    action_token: Annotated[str, Field(min_length=32, max_length=256)]
    expected_generation: Annotated[int, Field(ge=1)]
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    duration_ms: Annotated[int, Field(ge=1, le=MAXIMUM_BURST_DURATION_MS)]
    maximum_requests: Annotated[int, Field(ge=1, le=MAXIMUM_BURST_REQUESTS)]
    maximum_credits: Annotated[int, Field(ge=1, le=MAXIMUM_BURST_CREDITS)]
    maximum_concurrency: Annotated[int, Field(ge=1, le=MAXIMUM_BURST_CONCURRENCY)]
    operations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=160)], ...],
        Field(min_length=1, max_length=MAXIMUM_BURST_OPERATIONS),
    ]

    @model_validator(mode="after")
    def validate_operations(self) -> RunawayBurstAuthorizeRequest:
        if len(set(self.operations)) != len(self.operations):
            raise ValueError("burst operation allowlist contains duplicates")
        return self


class RunawayQuarantineDenyRequest(StrictAdminModel):
    action_token: Annotated[str, Field(min_length=32, max_length=256)]
    expected_generation: Annotated[int, Field(ge=1)]
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class RunawayFreshRunRecoveryRequest(StrictAdminModel):
    action_token: Annotated[str, Field(min_length=32, max_length=256)]
    expected_generation: Annotated[int, Field(ge=1)]
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    confirmation: Literal["RECOVER_FRESH_RUN"]


class RunawayQuarantineActionResult(StrictAdminModel):
    quarantine_id: Annotated[str, Field(min_length=1, max_length=160)]
    state: Literal["AUTHORIZED", "DENIED"]
    generation: Annotated[int, Field(ge=1)]
    acted_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]


class RunawayFreshRunRecoveryResult(StrictAdminModel):
    recovery_id: Annotated[str, Field(min_length=1, max_length=160)]
    quarantine_id: Annotated[str, Field(min_length=1, max_length=160)]
    quarantine_state: Literal["OPEN", "DENIED", "EXPIRED", "EXHAUSTED"]
    generation: Annotated[int, Field(ge=1)]
    client_id: Annotated[str, Field(min_length=1, max_length=160)]
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    root_run_id: Annotated[str, Field(min_length=1, max_length=160)]
    recovered_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]


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


_ACCOUNT_ALIAS_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"
MAX_ACCOUNT_PRIORITY = 1_000_000


class AccountAddRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    provider: Literal["firecrawl"]
    provider_team_id: Annotated[str, Field(min_length=1, max_length=160)]
    alias: Annotated[str, Field(pattern=_ACCOUNT_ALIAS_PATTERN)]
    pool_alias: Annotated[str, Field(pattern=_ACCOUNT_ALIAS_PATTERN)]
    priority: Annotated[int, Field(ge=0, le=MAX_ACCOUNT_PRIORITY)]
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None

    @field_validator("provider_team_id")
    @classmethod
    def validate_provider_team_id(cls, value: str) -> str:
        if not value.isascii() or any(not "!" <= character <= "~" for character in value):
            raise ValueError("provider team identifier must contain visible ASCII characters")
        return value


class AccountRotationRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None


class AccountStateChangeRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    action: Literal["disable", "recover", "remove"]
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class AccountRefreshRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]


class AccountObservationChangeRequest(StrictAdminModel):
    mutation_id: Annotated[str, Field(min_length=1, max_length=160)]
    action: Literal["enable", "disable"]
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class AccountMutationResult(StrictAdminModel):
    """Secret-free result addressed only by operator-facing aliases."""

    alias: Annotated[str, Field(pattern=_ACCOUNT_ALIAS_PATTERN)]
    action: Literal["add", "rotate", "disable", "recover", "remove"]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    pool_alias: Annotated[str, Field(pattern=_ACCOUNT_ALIAS_PATTERN)]
    priority: Annotated[int, Field(ge=0, le=MAX_ACCOUNT_PRIORITY)]
    generation: Annotated[int, Field(ge=1)]
    acted_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]


class AccountObservationMutationResult(StrictAdminModel):
    """Audited schedule toggle; it grants no provider network permission."""

    alias: Annotated[str, Field(pattern=_ACCOUNT_ALIAS_PATTERN)]
    action: Literal["enable", "disable"]
    enabled: bool
    acted_at_ms: Annotated[int, Field(ge=0)]
    audit_event_id: Annotated[str, Field(min_length=1, max_length=160)]

    @model_validator(mode="after")
    def validate_action(self) -> AccountObservationMutationResult:
        if self.enabled != (self.action == "enable"):
            raise ValueError("account observation state does not match its action")
        return self


class AccountStatus(StrictAdminModel):
    """Exact, redacted account-capacity status safe for operator responses."""

    alias: Annotated[str, Field(pattern=_ACCOUNT_ALIAS_PATTERN)]
    state: Literal["HEALTHY", "EXHAUSTED", "UNKNOWN", "DISABLED", "QUARANTINED"]
    remaining_decimal: Annotated[
        str | None,
        Field(min_length=1, max_length=MAX_PROVIDER_FIXED_POINT_CHARS),
    ] = None
    plan_decimal: Annotated[
        str | None,
        Field(min_length=1, max_length=MAX_PROVIDER_FIXED_POINT_CHARS),
    ] = None
    unit: Annotated[str, Field(min_length=1, max_length=64)]
    observed_at_ms: Annotated[int | None, Field(ge=0)] = None
    staleness_ms: Annotated[int | None, Field(ge=0)] = None
    stale: bool
    source: Annotated[str | None, Field(min_length=1, max_length=100)] = None

    @model_validator(mode="after")
    def validate_observation(self) -> AccountStatus:
        if self.remaining_decimal is not None:
            parse_canonical_provider_number(self.remaining_decimal)
        if self.plan_decimal is not None:
            parse_canonical_provider_number(self.plan_decimal)
        observation_fields = (self.observed_at_ms, self.staleness_ms, self.source)
        if any(value is None for value in observation_fields) != all(
            value is None for value in observation_fields
        ):
            raise ValueError("account observation metadata is inconsistently nullable")
        if self.observed_at_ms is None:
            if self.remaining_decimal is not None or self.plan_decimal is not None:
                raise ValueError("account counters require observation metadata")
            if not self.stale:
                raise ValueError("an unobserved account must be stale")
        elif self.remaining_decimal is None:
            raise ValueError("an observed account requires an exact remaining balance")
        return self


class AccountLifecycleService(Protocol):
    """Account-level persistence contract implemented outside the API layer."""

    async def add_account(
        self,
        request: AccountAddRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult: ...

    async def list_accounts(self, *, limit: int) -> Sequence[AccountStatus]: ...

    async def get_account_status(self, alias: str) -> AccountStatus | None: ...

    async def rotate_account(
        self,
        alias: str,
        request: AccountRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult: ...

    async def change_account_state(
        self,
        alias: str,
        request: AccountStateChangeRequest,
        actor_id: str,
    ) -> AccountMutationResult: ...

    async def refresh_account(
        self,
        alias: str,
        request: AccountRefreshRequest,
        actor_id: str,
    ) -> AccountStatus: ...

    async def change_account_observation(
        self,
        alias: str,
        request: AccountObservationChangeRequest,
        actor_id: str,
    ) -> AccountObservationMutationResult: ...


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

    async def list_runaway_quarantines(
        self,
        *,
        limit: int,
    ) -> Sequence[RunawayQuarantineView]: ...

    async def get_runaway_quarantine(
        self,
        quarantine_id: str,
    ) -> RunawayQuarantineView | None: ...

    async def authorize_runaway_burst(
        self,
        quarantine_id: str,
        request: RunawayBurstAuthorizeRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult: ...

    async def deny_runaway_quarantine(
        self,
        quarantine_id: str,
        request: RunawayQuarantineDenyRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult: ...

    async def recover_runaway_for_fresh_run(
        self,
        quarantine_id: str,
        request: RunawayFreshRunRecoveryRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayFreshRunRecoveryResult: ...

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]: ...

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]: ...

    async def add_account(
        self,
        request: AccountAddRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult: ...

    async def list_accounts(self, *, limit: int) -> Sequence[AccountStatus]: ...

    async def get_account_status(self, alias: str) -> AccountStatus | None: ...

    async def rotate_account(
        self,
        alias: str,
        request: AccountRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult: ...

    async def change_account_state(
        self,
        alias: str,
        request: AccountStateChangeRequest,
        actor_id: str,
    ) -> AccountMutationResult: ...

    async def refresh_account(
        self,
        alias: str,
        request: AccountRefreshRequest,
        actor_id: str,
    ) -> AccountStatus: ...

    async def change_account_observation(
        self,
        alias: str,
        request: AccountObservationChangeRequest,
        actor_id: str,
    ) -> AccountObservationMutationResult: ...

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
