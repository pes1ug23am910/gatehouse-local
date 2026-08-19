from __future__ import annotations

from typing import cast

import pytest

from gatehouse.api import GatehouseAgentOperations, InvocationRequest, PolicyExplainRequest
from gatehouse.config import ClientProfileConfig
from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.errors import ErrorCode, GatehouseError, make_error
from gatehouse.core.ids import RequestId
from gatehouse.core.states import InvocationState
from gatehouse.documentation import DocumentationService
from gatehouse.feedback import FeedbackService
from gatehouse.invocations import InvocationRequest as CoordinatedInvocationRequest
from gatehouse.invocations import (
    InvocationResult,
    InvocationSession,
)
from gatehouse.jobs import SqliteJobStore
from gatehouse.policy import Decision, WorkspacePolicy
from gatehouse.policy.engine import PurposeRule
from gatehouse.routing import ResourceAffinityStore
from gatehouse.sessions import AccessPrincipal, RootRunRecord, RootRunState

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_C = "00000000000000000000000003"
_D = "00000000000000000000000004"


def profile(*capabilities: str) -> ClientProfileConfig:
    return ClientProfileConfig.model_validate(
        {
            "schema_version": 1,
            "client": {
                "id": "editor",
                "kind": "interactive",
                "unattended": False,
                "approval_mode": "dashboard",
                "default_priority": "interactive",
                "maximum_concurrent_runs": 2,
                "maximum_in_flight": 4,
                "maximum_queued": 8,
                "maximum_run_duration": 60_000,
            },
            "capabilities": {"allow": list(capabilities)},
            "pools": {
                "bindings": {"firecrawl": "interactive-default"},
                "emergency_access": False,
            },
            "lease": {"heartbeat_interval": 1_000, "stale_after": 2_000},
        }
    )


def policy() -> WorkspacePolicy:
    return WorkspacePolicy(
        policy_id="workspace",
        version="policy-v1",
        workspace_id=f"ws_{_A}",
        service="firecrawl",
        default_decision=Decision.DENY,
        default_pool="interactive-default",
        purpose_rules={
            "career_discovery": {"search": PurposeRule(Decision.ALLOW)},
            "career_site_research": {"search": PurposeRule(Decision.ASK)},
        },
        maximum_requests_per_root_run=30,
        maximum_credits_per_root_run=200,
    )


def principal() -> AccessPrincipal:
    return AccessPrincipal(
        session_id=f"ses_{_A}",
        client_id=f"client_{_A}",
        workspace_id=f"ws_{_A}",
        identity_assurance="CONTROLLED_LAUNCH",
        policy_version="policy-v1",
        token_epoch=1,
        absolute_expires_at_ms=10_000,
    )


class FakeRoots:
    def __init__(self, record: RootRunRecord) -> None:
        self.record = record

    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None:
        return self.record if root_run_id == self.record.root_run_id else None


class FakeCoordinator:
    def __init__(self, result: InvocationResult) -> None:
        self.result = result
        self.calls: list[tuple[CoordinatedInvocationRequest, InvocationSession]] = []

    async def invoke_authenticated(
        self,
        request: CoordinatedInvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        self.calls.append((request, session))
        return self.result


class UnusedJobs:
    pass


class UnusedAffinities:
    pass


def operations(
    coordinator: FakeCoordinator,
    *,
    root: RootRunRecord | None = None,
    configured_profile: ClientProfileConfig | None = None,
    documentation: DocumentationService | None = None,
    feedback: FeedbackService | None = None,
) -> GatehouseAgentOperations:
    return GatehouseAgentOperations(
        coordinator=coordinator,
        root_runs=FakeRoots(
            root
            or RootRunRecord(
                root_run_id=f"run_{_A}",
                session_id=f"ses_{_A}",
                state=RootRunState.ACTIVE,
                started_at_ms=1,
                budget={"requests": 3, "credits": 25},
                consumed={"requests": 1, "credits": 5},
            )
        ),
        client_profiles={
            f"client_{_A}": configured_profile
            or profile(
                "firecrawl.search",
                "jobs.status",
                "jobs.await",
                "jobs.cancel",
                "docs.search",
                "docs.get",
                "feedback.submit",
                "watcher.scan_feed_set",
            )
        },
        workspace_policies={f"ws_{_A}": policy()},
        jobs=cast(SqliteJobStore, UnusedJobs()),
        affinities=cast(ResourceAffinityStore, UnusedAffinities()),
        documentation=documentation,
        feedback=feedback,
        clock=FixedUtcClock(1_000),
        request_id_factory=lambda: RequestId(f"req_{_D}"),
    )


@pytest.mark.asyncio
async def test_capabilities_are_configured_routed_and_never_advertise_watchers() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(
        coordinator,
        documentation=cast(DocumentationService, object()),
        feedback=cast(FeedbackService, object()),
    )

    assert await item.capabilities(principal()) == (
        "docs.get",
        "docs.search",
        "feedback.submit",
        "firecrawl.search",
        "jobs.await",
        "jobs.cancel",
        "jobs.status",
    )


@pytest.mark.asyncio
async def test_invoke_projects_only_authenticated_configured_authority() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(
            RequestId(f"req_{_D}"),
            InvocationState.SUCCEEDED,
            1,
            data={"data": [{"url": "https://example.com/job"}]},
        )
    )
    item = operations(coordinator)
    request = InvocationRequest.model_validate(
        {
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": f"run_{_A}"},
            "execution": {"wait_up_to_ms": 100, "allow_cached_result": True},
            "approval_id": "approval-one",
        }
    )

    response = await item.invoke(principal(), request)

    assert response.status_code == 200
    assert response.body == {
        "request_id": f"req_{_D}",
        "state": "SUCCEEDED",
        "service": "firecrawl",
        "operation": "search",
        "attempts": 1,
        "result": {
            "source_trust": "untrusted_web_content",
            "data": {"data": [{"url": "https://example.com/job"}]},
        },
    }
    internal, session = coordinator.calls[0]
    assert internal.access_token is None
    assert internal.root_run_id == f"run_{_A}"
    assert internal.operation == "firecrawl.search"
    assert internal.purpose == "career_discovery"
    assert internal.data_classifications == frozenset({"public_web_query"})
    assert internal.queue_deadline_ms == 1_100
    assert internal.approval_id == "approval-one"
    assert session.session_id == f"ses_{_A}"
    assert session.client_id == f"client_{_A}"
    assert session.workspace_id == f"ws_{_A}"
    assert session.request_count_remaining == 2
    assert session.credit_budget_remaining_units == 20
    assert session.request_limit == 3
    assert not session.internal_resource_reconciliation


@pytest.mark.asyncio
async def test_policy_explain_projects_exact_authority_without_coordinator_side_effects() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(coordinator)

    response = await item.explain_policy(
        principal(),
        PolicyExplainRequest.model_validate(
            {
                "service": "firecrawl",
                "operation": "search",
                "context": {"root_run_id": f"run_{_A}"},
            }
        ),
    )

    assert response.status_code == 200
    assert response.body["authority"] == {
        "session_id": f"ses_{_A}",
        "client_id": f"client_{_A}",
        "client": "editor",
        "workspace_id": f"ws_{_A}",
        "workspace": "workspace",
        "root_run_id": f"run_{_A}",
    }
    assert response.body["decision"] == "DENY"
    assert response.body["rule_id"] == "default-decision"
    assert response.body["denial_reason"] == "policy-deny"
    assert response.body["cost_ceiling_units"] == 20
    assert response.body["constraints"] == {
        "maximum_search_results": 20,
        "maximum_map_results": 100,
        "maximum_crawl_pages": 25,
        "maximum_crawl_depth": 2,
        "request_count_remaining": 2,
        "credit_budget_remaining_units": 20,
    }
    assert response.body["purpose_rules"] == [
        {
            "purpose": "career_discovery",
            "decision": "ALLOW",
            "rule_id": "purpose:career_discovery:search",
            "reason_code": "policy-allow",
            "targeted_only": False,
            "maximum_cost_units": None,
            "approval_required": False,
            "denial_reason": None,
        },
        {
            "purpose": "career_site_research",
            "decision": "ASK",
            "rule_id": "purpose:career_site_research:search",
            "reason_code": "policy-ask",
            "targeted_only": False,
            "maximum_cost_units": None,
            "approval_required": True,
            "denial_reason": None,
        },
    ]
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_policy_explain_reports_capability_ceiling_instead_of_executing() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(coordinator, configured_profile=profile("docs.search"))

    response = await item.explain_policy(
        principal(),
        PolicyExplainRequest.model_validate(
            {
                "service": "firecrawl",
                "operation": "search",
                "context": {"root_run_id": f"run_{_A}"},
            }
        ),
    )

    assert response.body["decision"] == "DENY"
    assert response.body["rule_id"] == "capability-ceiling"
    assert response.body["reason_code"] == "operation-not-authorized"
    assert response.body["approval_required"] is False
    rules = response.body["purpose_rules"]
    assert isinstance(rules, list)
    assert {rule["decision"] for rule in rules if isinstance(rule, dict)} == {"DENY"}
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_invoke_surfaces_pending_approval_identifier() -> None:
    error = make_error(
        ErrorCode.APPROVAL_PENDING,
        retryable=True,
        retry_after_seconds=1,
        request_id=RequestId(f"req_{_D}"),
    ).detail
    coordinator = FakeCoordinator(
        InvocationResult(
            RequestId(f"req_{_D}"),
            InvocationState.WAITING_APPROVAL,
            0,
            error=error,
            approval_id="approval-one",
        )
    )
    item = operations(coordinator)
    request = InvocationRequest.model_validate(
        {
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )

    response = await item.invoke(principal(), request)

    assert response.status_code == 202
    assert response.body["approval_id"] == "approval-one"
    response_error = response.body["error"]
    assert isinstance(response_error, dict)
    assert response_error["code"] == "approval_pending"
    assert response.retry_after_seconds == 1


@pytest.mark.asyncio
async def test_cross_session_root_is_rejected_before_coordinator() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(
        coordinator,
        root=RootRunRecord(
            root_run_id=f"run_{_A}",
            session_id=f"ses_{_B}",
            state=RootRunState.ACTIVE,
            started_at_ms=1,
        ),
    )
    request = InvocationRequest.model_validate(
        {
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )

    with pytest.raises(GatehouseError) as raised:
        await item.invoke(principal(), request)

    assert raised.value.detail.code is ErrorCode.INVALID_SESSION
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_zero_wait_still_builds_a_valid_immediate_queue_deadline() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(coordinator)
    request = InvocationRequest.model_validate(
        {
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": f"run_{_A}"},
            "execution": {"wait_up_to_ms": 0},
        }
    )

    await item.invoke(principal(), request)

    internal, _ = coordinator.calls[0]
    assert internal.queue_deadline_ms == 1_001
