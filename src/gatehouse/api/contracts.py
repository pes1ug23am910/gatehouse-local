"""Typed, dependency-injected contracts for the local HTTP surfaces."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from gatehouse import __version__
from gatehouse.core.errors import JsonValue
from gatehouse.sessions import (
    AccessPrincipal,
    IssuedAccessToken,
    RootRunRecord,
)


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


class PolicyExplainResponse(StrictApiModel):
    authority: PolicyExplainAuthority
    service: Literal["firecrawl"]
    operation: Literal["search", "scrape", "map", "crawl"]
    decision: Literal["ALLOW", "ASK", "DENY"]
    rule_id: Identifier
    reason_code: Identifier
    policy_id: Identifier
    policy_version: Annotated[str, Field(min_length=1, max_length=160)]
    constraints: PolicyExplainConstraints
    cost_ceiling_units: Annotated[int, Field(ge=0)]
    approval_required: bool
    denial_reason: Identifier | None = None
    purpose_rules: Annotated[list[PolicyExplainRule], Field(max_length=64)]


class JobContext(StrictApiModel):
    root_run_id: Identifier


class JobAwaitRequest(JobContext):
    maximum_wait_ms: Annotated[int, Field(ge=1, le=60_000)]


class DocumentationSearchRequest(StrictApiModel):
    service: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")]
    query: Annotated[str, Field(min_length=2, max_length=500)]
    limit: Annotated[int, Field(ge=1, le=50)] = 10


class FeedbackSubmitRequest(StrictApiModel):
    category: Annotated[str, Field(min_length=1, max_length=100)]
    severity: Annotated[str, Field(min_length=1, max_length=100)]
    component: Annotated[str, Field(min_length=1, max_length=100)]
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
