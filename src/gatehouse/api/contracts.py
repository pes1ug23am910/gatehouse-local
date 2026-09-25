"""Typed, dependency-injected contracts for the local HTTP surfaces."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gatehouse import __version__
from gatehouse.core.errors import JsonValue
from gatehouse.feedback import (
    FeedbackCategoryValue,
    FeedbackComponentValue,
    FeedbackSeverityValue,
)
from gatehouse.sessions import (
    AccessPrincipal,
    IssuedAccessToken,
    RootRunRecord,
)
from gatehouse.watcher.store import MAX_CURSOR_BYTES, MAX_CURSOR_SEQUENCE


class StrictApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


Identifier = Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")]
RequestIdentifier = Annotated[
    str,
    Field(
        min_length=30,
        max_length=30,
        pattern=r"^req_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
        description=(
            "Stable crawl-start handle. Reuse only to recover the same prior request; "
            "omit it for a distinct crawl."
        ),
    ),
]


class SessionExchangeRequest(StrictApiModel):
    session_id: Identifier
    bootstrap_capability: Annotated[str, Field(min_length=40, max_length=128)]
    client_nonce: Annotated[str, Field(min_length=8, max_length=256)]


class HeartbeatRequest(StrictApiModel):
    active_root_runs: Annotated[list[Identifier], Field(max_length=64)] = Field(
        default_factory=list
    )
    reported_agent_count: Annotated[int, Field(ge=0, le=1_024)] = 0


class RootRunCreateRequest(StrictApiModel):
    budget: (
        Annotated[
            dict[
                Annotated[str, Field(min_length=1, max_length=64)],
                Annotated[int, Field(ge=0)],
            ],
            Field(max_length=32),
        ]
        | None
    ) = None


class InvocationContext(StrictApiModel):
    root_run_id: Identifier
    reported_context_id: Annotated[str | None, Field(max_length=256)] = None
    reported_agent_id: Annotated[str | None, Field(max_length=256)] = None
    reported_parent_agent_id: Annotated[str | None, Field(max_length=256)] = None
    tool_call_id: Annotated[str | None, Field(max_length=256)] = None
    turn_id: Annotated[str | None, Field(max_length=256)] = None


class ExecutionPreference(StrictApiModel):
    wait_up_to_ms: Annotated[int, Field(ge=0, le=60_000)] = 15_000
    allow_cached_result: bool = True


class InvocationRequest(StrictApiModel):
    request_id: RequestIdentifier | None = None
    service: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")]
    operation: Annotated[
        str,
        Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$"),
    ]
    input: Annotated[dict[str, JsonValue], Field(max_length=128)]
    context: InvocationContext
    execution: ExecutionPreference = Field(default_factory=ExecutionPreference)
    approval_id: Identifier | None = None


class PolicyExplainContext(StrictApiModel):
    root_run_id: Identifier


class PolicyExplainRequest(StrictApiModel):
    service: Literal["firecrawl"]
    operation: Literal["search", "scrape", "map", "crawl"]
    context: PolicyExplainContext


class PolicyExplainAuthority(StrictApiModel):
    session_id: Identifier
    client_id: Identifier
    client: Identifier
    workspace_id: Identifier
    workspace: Identifier
    root_run_id: Identifier


class PolicyExplainConstraints(StrictApiModel):
    maximum_search_results: Annotated[int, Field(ge=0)]
    maximum_map_results: Annotated[int, Field(ge=0)]
    maximum_crawl_pages: Annotated[int, Field(ge=0)]
    maximum_crawl_depth: Annotated[int, Field(ge=0)]
    request_count_remaining: Annotated[int, Field(ge=0)]
    credit_budget_remaining_units: Annotated[int, Field(ge=0)]


class PolicyExplainRule(StrictApiModel):
    purpose: Identifier
    decision: Literal["ALLOW", "ASK", "DENY"]
    rule_id: Identifier
    reason_code: Identifier
    targeted_only: bool
    maximum_cost_units: Annotated[float, Field(ge=0)] | None = None
    approval_required: bool
    denial_reason: Identifier | None = None


class EffectivePolicyHardDenies(StrictApiModel):
    profile: Literal["fixed-v1"]
    data_classifications: Annotated[
        list[
            Literal[
                "api_key",
                "credential",
                "identity_document",
                "private_document",
                "private_key",
                "resume",
                "sensitive_personal_information",
            ]
        ],
        Field(min_length=7, max_length=7),
    ]
    crawl_requires_include_paths: Literal[True]
    crawl_external_links: Literal[False]
    crawl_subdomains: Literal[False]

    @field_validator("data_classifications")
    @classmethod
    def validate_fixed_classifications(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("hard-denied classifications must be unique and sorted")
        return value

    @field_validator(
        "crawl_requires_include_paths", "crawl_external_links", "crawl_subdomains", mode="before"
    )
    @classmethod
    def validate_strict_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("hard-deny flags must be strict booleans")
        return value


class EffectivePolicyCreditDiscipline(StrictApiModel):
    duplicate_in_flight: Literal["return_original"]
    cross_session_public_coalescing: Literal[False]
    cache_completed_public_reads: Literal["disabled"]
    broad_crawl_without_narrow_attempt: Literal["deny"]
    prior_narrow_attempt_tracking: Literal[False]

    @field_validator(
        "cross_session_public_coalescing", "prior_narrow_attempt_tracking", mode="before"
    )
    @classmethod
    def validate_strict_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("credit-discipline flags must be strict booleans")
        return value


class EffectivePolicyLimits(StrictApiModel):
    search_results: Annotated[int, Field(gt=0)]
    map_results: Annotated[int, Field(gt=0)]
    crawl_pages: Annotated[int, Field(gt=0)]
    crawl_depth: Annotated[int, Field(ge=0)]
    requests_per_root_run: Annotated[int, Field(gt=0)]
    credits_per_root_run: Annotated[float, Field(gt=0, allow_inf_nan=False)]


class EffectivePolicyOperation(StrictApiModel):
    operation: Literal["search", "scrape", "map", "crawl"]
    decision: Literal["ALLOW", "ASK", "DENY"]
    targeted_only: bool
    maximum_cost: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None


class EffectivePolicyPurpose(StrictApiModel):
    purpose: Identifier
    operations: Annotated[list[EffectivePolicyOperation], Field(max_length=4)]

    @field_validator("operations")
    @classmethod
    def validate_operation_order(
        cls, value: list[EffectivePolicyOperation]
    ) -> list[EffectivePolicyOperation]:
        names = [item.operation for item in value]
        if names != sorted(set(names)):
            raise ValueError("effective operations must be unique and sorted")
        return value


class EffectivePolicy(StrictApiModel):
    compiler_revision: Literal[1]
    policy_id: Identifier
    service: Identifier
    default_decision: Literal["ALLOW", "ASK", "DENY"]
    default_pool: Identifier
    workspace_binding: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    hard_denies: EffectivePolicyHardDenies
    credit_discipline: EffectivePolicyCreditDiscipline
    enforce_limits: Literal[True]
    limits: EffectivePolicyLimits
    purposes: Annotated[list[EffectivePolicyPurpose], Field(max_length=64)]

    @field_validator("compiler_revision", mode="before")
    @classmethod
    def validate_strict_revision(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("compiler revision must be a strict integer")
        return value

    @field_validator("enforce_limits", mode="before")
    @classmethod
    def validate_strict_enforcement(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("limit enforcement must be a strict boolean")
        return value

    @field_validator("purposes")
    @classmethod
    def validate_purpose_order(
        cls, value: list[EffectivePolicyPurpose]
    ) -> list[EffectivePolicyPurpose]:
        names = [item.purpose for item in value]
        if names != sorted(set(names)):
            raise ValueError("effective purposes must be unique and sorted")
        return value


class PolicyExplainResponse(StrictApiModel):
    authority: PolicyExplainAuthority
    service: Literal["firecrawl"]
    operation: Literal["search", "scrape", "map", "crawl"]
    decision: Literal["ALLOW", "ASK", "DENY"]
    rule_id: Identifier
    reason_code: Identifier
    policy_id: Identifier
    policy_version: Annotated[str, Field(min_length=1, max_length=160)]
    effective_policy: EffectivePolicy
    constraints: PolicyExplainConstraints
    cost_ceiling_units: Annotated[int, Field(ge=0)]
    approval_required: bool
    denial_reason: Identifier | None = None
    purpose_rules: Annotated[list[PolicyExplainRule], Field(max_length=64)]


class JobContext(StrictApiModel):
    root_run_id: Identifier


class JobAwaitRequest(JobContext):
    maximum_wait_ms: Annotated[int, Field(ge=1, le=60_000)]


class WatcherContext(StrictApiModel):
    root_run_id: Identifier


class WatcherScanRequest(WatcherContext):
    cursor: Annotated[str | None, Field(min_length=1, max_length=MAX_CURSOR_BYTES)] = None

    @field_validator("cursor")
    @classmethod
    def validate_cursor_bytes(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > MAX_CURSOR_BYTES:
            raise ValueError("cursor exceeds the byte limit")
        return value


class WatcherCursorCommitRequest(WatcherContext):
    watcher_run_id: Identifier
    expected_version: Annotated[int, Field(ge=0)]
    cursor_value: Annotated[str, Field(min_length=1, max_length=MAX_CURSOR_BYTES)]
    cursor_sequence: Annotated[int, Field(ge=0, le=MAX_CURSOR_SEQUENCE)]

    @field_validator("cursor_value")
    @classmethod
    def validate_cursor_value_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_CURSOR_BYTES:
            raise ValueError("cursor value exceeds the byte limit")
        return value


class DocumentationSearchRequest(StrictApiModel):
    service: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")]
    query: Annotated[str, Field(min_length=2, max_length=500)]
    limit: Annotated[int, Field(ge=1, le=50)] = 10


class FeedbackSubmitRequest(StrictApiModel):
    category: FeedbackCategoryValue
    severity: FeedbackSeverityValue
    component: FeedbackComponentValue
    summary: Annotated[str, Field(min_length=1, max_length=1_000)]
    problem: Annotated[str | None, Field(max_length=4_000)] = None
    what_worked: Annotated[str | None, Field(max_length=4_000)] = None
    suggested_improvement: Annotated[str | None, Field(max_length=4_000)] = None
    related_request_ids: Annotated[list[Identifier], Field(max_length=64)] = Field(
        default_factory=list
    )


class ReadinessSnapshot(StrictApiModel):
    ready: bool
    status: Annotated[str, Field(min_length=1, max_length=64)]
    version: Annotated[str, Field(min_length=1, max_length=64)]
    schema_version: Annotated[int, Field(ge=0)]
    policy_version: Annotated[str, Field(min_length=1, max_length=160)]
    uptime_seconds: Annotated[int, Field(ge=0)]
    degraded_components: Annotated[list[str], Field(max_length=64)] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ApiResponse:
    """A safe response selected by an injected application service."""

    body: Mapping[str, JsonValue]
    status_code: int = 200
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if not 200 <= self.status_code <= 299:
            raise ValueError("successful API responses require a 2xx status")
        if self.retry_after_seconds is not None and self.retry_after_seconds <= 0:
            raise ValueError("retry_after_seconds must be positive")
        object.__setattr__(self, "body", MappingProxyType(dict(self.body)))


class SessionAuthority(Protocol):
    async def exchange_bootstrap(
        self,
        *,
        session_id: str,
        bootstrap_capability: str,
    ) -> IssuedAccessToken: ...

    async def authenticate(self, access_token: str) -> AccessPrincipal: ...

    async def heartbeat(self, access_token: str) -> AccessPrincipal: ...

    async def create_root_run(
        self,
        *,
        access_token: str,
        budget: Mapping[str, int] | None = None,
    ) -> RootRunRecord: ...

    async def resolve_root_run(
        self,
        *,
        access_token: str,
        root_run_id: str,
    ) -> RootRunRecord: ...


class HealthProbe(Protocol):
    async def readiness(self) -> ReadinessSnapshot: ...


class AgentOperations(Protocol):
    async def capabilities(self, principal: AccessPrincipal) -> Sequence[str]: ...

    async def invoke(
        self,
        principal: AccessPrincipal,
        request: InvocationRequest,
    ) -> ApiResponse: ...

    async def explain_policy(
        self,
        principal: AccessPrincipal,
        request: PolicyExplainRequest,
    ) -> ApiResponse: ...

    async def get_job(
        self,
        principal: AccessPrincipal,
        job_id: str,
        context: JobContext,
    ) -> ApiResponse: ...

    async def await_job(
        self,
        principal: AccessPrincipal,
        job_id: str,
        request: JobAwaitRequest,
    ) -> ApiResponse: ...

    async def cancel_job(
        self,
        principal: AccessPrincipal,
        job_id: str,
        context: JobContext,
    ) -> ApiResponse: ...

    async def scan_watcher_feed_set(
        self,
        principal: AccessPrincipal,
        feed_set_id: str,
        request: WatcherScanRequest,
    ) -> ApiResponse: ...

    async def get_watcher_cursor(
        self,
        principal: AccessPrincipal,
        feed_set_id: str,
        context: WatcherContext,
    ) -> ApiResponse: ...

    async def commit_watcher_cursor(
        self,
        principal: AccessPrincipal,
        feed_set_id: str,
        request: WatcherCursorCommitRequest,
    ) -> ApiResponse: ...

    async def get_watcher_previous_summary(
        self,
        principal: AccessPrincipal,
        feed_set_id: str,
        context: WatcherContext,
    ) -> ApiResponse: ...

    async def search_documentation(
        self,
        principal: AccessPrincipal,
        request: DocumentationSearchRequest,
    ) -> ApiResponse: ...

    async def get_documentation(
        self,
        principal: AccessPrincipal,
        service: str,
        document: str,
    ) -> ApiResponse | None: ...

    async def submit_feedback(
        self,
        principal: AccessPrincipal,
        request: FeedbackSubmitRequest,
    ) -> ApiResponse: ...


@dataclass(frozen=True, slots=True)
class StaticHealthProbe:
    snapshot: ReadinessSnapshot = field(
        default_factory=lambda: ReadinessSnapshot(
            ready=False,
            status="failed_closed",
            version=__version__,
            schema_version=0,
            policy_version="unavailable",
            uptime_seconds=0,
            degraded_components=["runtime_composition"],
        )
    )

    async def readiness(self) -> ReadinessSnapshot:
        return self.snapshot
