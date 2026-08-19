"""Provider-neutral durable asynchronous-job value objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.ids import (
    CredentialId,
    JobId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)


class JobState(StrEnum):
    """Durable lifecycle states for provider-backed asynchronous work."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    POLLING = "POLLING"
    CANCELLING = "CANCELLING"
    RECOVERING = "RECOVERING"
    SETTLING = "SETTLING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


TERMINAL_JOB_STATES = frozenset(
    {
        JobState.SUCCEEDED,
        JobState.FAILED,
        JobState.CANCELLED,
        JobState.UNKNOWN,
    }
)


@dataclass(frozen=True, slots=True)
class JobOwner:
    """The complete durable owner fence required for every job lookup."""

    session_id: SessionId
    workspace_id: WorkspaceId
    root_run_id: RootRunId

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, SessionId):
            raise TypeError("job owner session_id must be a SessionId")
        if not isinstance(self.workspace_id, WorkspaceId):
            raise TypeError("job owner workspace_id must be a WorkspaceId")
        if not isinstance(self.root_run_id, RootRunId):
            raise TypeError("job owner root_run_id must be a RootRunId")


@dataclass(frozen=True, slots=True)
class JobRecord:
    """A durable job plus the immutable authority used to reach its provider."""

    job_id: JobId
    request_id: RequestId
    service_id: str
    operation: str
    state: JobState
    provider_resource_id: str
    resource_type: str
    principal_id: PrincipalId
    quota_scope_id: QuotaScopeId
    credential_id: CredentialId
    credential_generation: int
    pool_id: PoolId
    owner: JobOwner
    revision: int
    provider_status: str | None
    provider_status_observed_at_ms: int | None
    cancel_requested_at_ms: int | None
    next_poll_at_ms: int | None
    maximum_runtime_at_ms: int
    created_at_ms: int
    completed_at_ms: int | None
    settlement_target_state: JobState | None = None
    settlement_actual_cost_units: int | None = None
    settlement_observed_at_ms: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.job_id, JobId):
            raise TypeError("job_id must be a JobId")
        if not isinstance(self.request_id, RequestId):
            raise TypeError("request_id must be a RequestId")
        if not self.service_id or len(self.service_id) > 64:
            raise ValueError("job service_id is required and bounded")
        if not self.operation or len(self.operation) > 128:
            raise ValueError("job operation is required and bounded")
        if not self.provider_resource_id or len(self.provider_resource_id) > 128:
            raise ValueError("provider resource identifier is required and bounded")
        if not self.resource_type or len(self.resource_type) > 64:
            raise ValueError("job resource_type is required and bounded")
        if self.credential_generation <= 0:
            raise ValueError("job credential generation must be positive")
        if self.revision <= 0:
            raise ValueError("job revision must be positive")

        created_at_ms = require_utc_ms(self.created_at_ms)
        maximum_runtime_at_ms = require_utc_ms(self.maximum_runtime_at_ms)
        if maximum_runtime_at_ms < created_at_ms:
            raise ValueError("job maximum runtime cannot precede creation")

        for name, value in (
            ("provider_status_observed_at_ms", self.provider_status_observed_at_ms),
            ("cancel_requested_at_ms", self.cancel_requested_at_ms),
            ("next_poll_at_ms", self.next_poll_at_ms),
            ("completed_at_ms", self.completed_at_ms),
        ):
            if value is not None and require_utc_ms(value) < created_at_ms:
                raise ValueError(f"job {name} cannot precede creation")

        if self.provider_status is not None and not self.provider_status:
            raise ValueError("provider status cannot be empty")
        if self.provider_status is None and self.provider_status_observed_at_ms is not None:
            raise ValueError("provider status observation requires a provider status")
        if self.provider_status is not None and self.provider_status_observed_at_ms is None:
            raise ValueError("provider status requires an observation time")
        if self.state in TERMINAL_JOB_STATES and self.completed_at_ms is None:
            raise ValueError("terminal job must have a completion time")
        if self.state not in TERMINAL_JOB_STATES and self.completed_at_ms is not None:
            raise ValueError("non-terminal job cannot have a completion time")

        settlement_values = (
            self.settlement_target_state,
            self.settlement_actual_cost_units,
            self.settlement_observed_at_ms,
        )
        has_settlement = any(value is not None for value in settlement_values)
        if has_settlement != all(value is not None for value in settlement_values):
            raise ValueError("job settlement checkpoint must be complete")
        if (self.state is JobState.SETTLING) != has_settlement:
            raise ValueError("only a settling job may retain a settlement checkpoint")
        if has_settlement:
            assert self.settlement_target_state is not None
            assert self.settlement_actual_cost_units is not None
            assert self.settlement_observed_at_ms is not None
            if self.settlement_target_state not in TERMINAL_JOB_STATES:
                raise ValueError("job settlement target must be terminal")
            if (
                isinstance(self.settlement_actual_cost_units, bool)
                or not isinstance(self.settlement_actual_cost_units, int)
                or self.settlement_actual_cost_units < 0
                or self.settlement_actual_cost_units >= (1 << 63)
            ):
                raise ValueError("job settlement usage is outside its integer bound")
            observed_at_ms = require_utc_ms(self.settlement_observed_at_ms)
            if observed_at_ms < created_at_ms:
                raise ValueError("job settlement observation cannot precede creation")

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_JOB_STATES


@dataclass(frozen=True, slots=True)
class JobAwaitResult:
    """Result of a bounded wait followed by an authoritative SQLite read."""

    record: JobRecord | None
    changed: bool
    timed_out: bool

    def __post_init__(self) -> None:
        if self.changed and self.timed_out:
            raise ValueError("a changed job result cannot also be timed out")
