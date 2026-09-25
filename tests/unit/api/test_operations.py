from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from gatehouse.api import GatehouseAgentOperations, InvocationRequest, PolicyExplainRequest
from gatehouse.api.contracts import EffectivePolicy, PolicyExplainResponse
from gatehouse.api.operations import PendingApprovalRecovery, PendingApprovalRecoveryResult
from gatehouse.config import ClientProfileConfig, load_workspace_policy
from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.errors import ErrorCode, GatehouseError, make_error
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
from gatehouse.core.states import InvocationState
from gatehouse.documentation import DocumentationService
from gatehouse.feedback import FeedbackService
from gatehouse.fingerprint import RequestFingerprint
from gatehouse.invocations import InvocationRequest as CoordinatedInvocationRequest
from gatehouse.invocations import (
    InvocationResult,
    InvocationSession,
)
from gatehouse.jobs import SqliteJobStore
from gatehouse.notifier import ApprovalPendingSignal, ApprovalPendingSignalSink
from gatehouse.policy import Decision, WorkspacePolicy, workspace_policy_from_config
from gatehouse.policy.engine import PurposeRule
from gatehouse.routing import ResourceAffinity, ResourceAffinityStore
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
        revocation_epoch=0,
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
    async def get_by_request(self, **kwargs: object) -> None:
        del kwargs
        return None


def operations(
    coordinator: FakeCoordinator,
    *,
    root: RootRunRecord | None = None,
    configured_profile: ClientProfileConfig | None = None,
    configured_policy: WorkspacePolicy | None = None,
    documentation: DocumentationService | None = None,
    feedback: FeedbackService | None = None,
    jobs: object | None = None,
    affinities: ResourceAffinityStore | None = None,
    approval_notifications: ApprovalPendingSignalSink | None = None,
    pending_approval_recovery: PendingApprovalRecovery | None = None,
    approval_dashboard_url: str | None = None,
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
        workspace_policies={f"ws_{_A}": configured_policy or policy()},
        jobs=cast(SqliteJobStore, jobs or UnusedJobs()),
        affinities=affinities or cast(ResourceAffinityStore, UnusedAffinities()),
        documentation=documentation,
        feedback=feedback,
        approval_notifications=approval_notifications,
        pending_approval_recovery=pending_approval_recovery,
        approval_dashboard_url=approval_dashboard_url,
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
    root = RootRunRecord(
        root_run_id=f"run_{_A}",
        session_id=f"ses_{_A}",
        state=RootRunState.ACTIVE,
        started_at_ms=1,
        budget={"requests": 3, "credits": 25},
        consumed={"requests": 1, "credits": 5},
    )
    item = operations(coordinator, root=root)

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
    typed = PolicyExplainResponse.model_validate(dict(response.body))
    assert typed.effective_policy.model_dump(mode="json") == json.loads(
        policy().effective_policy_json
    )
    assert typed.policy_version == "policy-v1"
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
    assert root.budget == {"requests": 3, "credits": 25}
    assert root.consumed == {"requests": 1, "credits": 5}


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
    descriptor = EffectivePolicy.model_validate(response.body["effective_policy"])
    assert descriptor.purposes[0].operations[0].decision == "ALLOW"
    assert descriptor.model_dump(mode="json") == json.loads(policy().effective_policy_json)
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_policy_explain_returns_the_compiled_descriptor_and_version_without_execution() -> (
    None
):
    configured = load_workspace_policy(
        Path(__file__).parents[3] / "config/policies/placement-schedule.example.yaml"
    )
    compiled = workspace_policy_from_config(configured)
    bound = replace(compiled, workspace_id=f"ws_{_A}")
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(coordinator, configured_policy=bound)

    response = await item.explain_policy(
        replace(principal(), policy_version=compiled.version),
        PolicyExplainRequest.model_validate(
            {
                "service": "firecrawl",
                "operation": "search",
                "context": {"root_run_id": f"run_{_A}"},
            }
        ),
    )

    assert response.status_code == 200
    typed = PolicyExplainResponse.model_validate(dict(response.body))
    descriptor = typed.effective_policy.model_dump_json()
    canonical = json.dumps(
        json.loads(descriptor),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )
    assert canonical == compiled.effective_policy_json == bound.effective_policy_json
    assert typed.policy_version == hashlib.sha256(canonical.encode()).hexdigest()[:16]
    assert configured.workspace.canonical_root not in descriptor
    assert "canonical_root" not in descriptor
    assert coordinator.calls == []


def _effective_policy_document() -> dict[str, object]:
    return cast(dict[str, object], json.loads(policy().effective_policy_json))


def _effective_policy_section(document: dict[str, object], section: str) -> dict[str, object]:
    if section == "root":
        return document
    if section in {"purpose", "operation"}:
        purposes = cast(list[dict[str, object]], document["purposes"])
        if section == "purpose":
            return purposes[0]
        return cast(list[dict[str, object]], purposes[0]["operations"])[0]
    return cast(dict[str, object], document[section])


@pytest.mark.parametrize(
    "section", ["root", "hard_denies", "credit_discipline", "limits", "purpose", "operation"]
)
def test_policy_explain_effective_schema_requires_every_declared_field(section: str) -> None:
    original = _effective_policy_document()
    for name in _effective_policy_section(original, section):
        document = deepcopy(original)
        del _effective_policy_section(document, section)[name]
        with pytest.raises(ValidationError):
            EffectivePolicy.model_validate(document)
        with pytest.raises(ValidationError):
            EffectivePolicy.model_validate_json(json.dumps(document))


@pytest.mark.parametrize(
    "section", ["root", "hard_denies", "credit_discipline", "limits", "purpose", "operation"]
)
def test_policy_explain_effective_schema_forbids_extra_fields_at_every_level(section: str) -> None:
    document = _effective_policy_document()
    _effective_policy_section(document, section)["extra_authority"] = True
    with pytest.raises(ValidationError):
        EffectivePolicy.model_validate(document)
    with pytest.raises(ValidationError):
        EffectivePolicy.model_validate_json(json.dumps(document))


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("root", "compiler_revision", True),
        ("root", "compiler_revision", 1.0),
        ("root", "compiler_revision", "1"),
        ("root", "compiler_revision", 2),
        ("root", "enforce_limits", False),
        ("root", "enforce_limits", 1),
        ("root", "enforce_limits", "true"),
        ("root", "workspace_binding", "a" * 63),
        ("root", "workspace_binding", "A" * 64),
        ("root", "policy_id", "a" * 161),
        ("root", "service", 1),
        ("root", "default_decision", "allow"),
        ("root", "default_pool", ""),
        ("hard_denies", "profile", "custom"),
        ("hard_denies", "crawl_requires_include_paths", False),
        ("hard_denies", "crawl_requires_include_paths", 1),
        ("hard_denies", "crawl_external_links", True),
        ("hard_denies", "crawl_external_links", 0),
        ("hard_denies", "crawl_subdomains", "false"),
        ("credit_discipline", "duplicate_in_flight", "retry"),
        ("credit_discipline", "cross_session_public_coalescing", True),
        ("credit_discipline", "cross_session_public_coalescing", 0),
        ("credit_discipline", "cache_completed_public_reads", "policy_controlled"),
        ("credit_discipline", "broad_crawl_without_narrow_attempt", "allow"),
        ("credit_discipline", "prior_narrow_attempt_tracking", True),
        ("credit_discipline", "prior_narrow_attempt_tracking", 0),
        ("limits", "search_results", 0),
        ("limits", "map_results", True),
        ("limits", "crawl_pages", "25"),
        ("limits", "crawl_depth", -1),
        ("limits", "requests_per_root_run", 0),
        ("limits", "credits_per_root_run", 0),
        ("limits", "credits_per_root_run", True),
        ("limits", "credits_per_root_run", "200"),
        ("limits", "credits_per_root_run", float("inf")),
        ("limits", "credits_per_root_run", float("nan")),
        ("purpose", "purpose", "bad purpose"),
        ("operation", "operation", "raw_http"),
        ("operation", "decision", "allow"),
        ("operation", "targeted_only", 1),
        ("operation", "maximum_cost", -1),
        ("operation", "maximum_cost", "1"),
        ("operation", "maximum_cost", float("inf")),
        ("operation", "maximum_cost", float("nan")),
    ],
)
def test_policy_explain_effective_schema_rejects_unsupported_and_coerced_values(
    section: str, field: str, value: object
) -> None:
    document = _effective_policy_document()
    _effective_policy_section(document, section)[field] = value
    with pytest.raises(ValidationError):
        EffectivePolicy.model_validate(document)
    with pytest.raises(ValidationError):
        EffectivePolicy.model_validate_json(json.dumps(document))


@pytest.mark.parametrize("change", ["missing", "duplicate", "unknown", "reordered", "overflow"])
def test_policy_explain_effective_schema_requires_exact_fixed_classifications(change: str) -> None:
    document = _effective_policy_document()
    hard_denies = _effective_policy_section(document, "hard_denies")
    values = cast(list[str], hard_denies["data_classifications"])
    if change == "missing":
        values.pop()
    elif change == "duplicate":
        values[-1] = values[0]
    elif change == "unknown":
        values[-1] = "public_web_page"
    elif change == "reordered":
        values.reverse()
    else:
        values.append("credential")
    with pytest.raises(ValidationError):
        EffectivePolicy.model_validate(document)


@pytest.mark.parametrize("section", ["purposes", "operations"])
@pytest.mark.parametrize("change", ["overflow", "duplicate", "reordered"])
def test_policy_explain_effective_schema_bounds_and_orders_rule_arrays(
    section: str, change: str
) -> None:
    document = _effective_policy_document()
    if section == "purposes":
        values = cast(list[dict[str, object]], document["purposes"])
        limit = 64
        name = "purpose"
    else:
        purpose_document = _effective_policy_section(document, "purpose")
        values = cast(list[dict[str, object]], purpose_document["operations"])
        values.append({**values[0], "operation": "scrape"})
        values.sort(key=lambda item: str(item["operation"]))
        limit = 4
        name = "operation"
    if change == "overflow":
        values[:] = [deepcopy(values[0]) for _ in range(limit + 1)]
    elif change == "duplicate":
        values[-1][name] = values[0][name]
    else:
        values.reverse()
    with pytest.raises(ValidationError):
        EffectivePolicy.model_validate(document)


def test_policy_explain_effective_schema_accepts_all_bounded_operation_families() -> None:
    document = _effective_policy_document()
    purpose_document = _effective_policy_section(document, "purpose")
    purpose_document["operations"] = [
        {
            "operation": name,
            "decision": "ALLOW",
            "targeted_only": False,
            "maximum_cost": None if index == 0 else float(index),
        }
        for index, name in enumerate(("crawl", "map", "scrape", "search"))
    ]
    template = deepcopy(purpose_document)
    document["purposes"] = [
        {**deepcopy(template), "purpose": f"purpose-{index:02d}"} for index in range(64)
    ]
    typed = EffectivePolicy.model_validate_json(json.dumps(document))
    assert len(typed.purposes) == 64
    assert all(len(item.operations) == 4 for item in typed.purposes)


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
async def test_runaway_authorization_error_projects_validated_local_dashboard() -> None:
    error = make_error(
        ErrorCode.RUNAWAY_SUSPECTED,
        retryable=False,
        request_id=RequestId(f"req_{_D}"),
        details={
            "authorization_required": True,
            "dashboard_url": "https://untrusted.example/approve",
            "scope": "session_root_run_service",
        },
    ).detail
    coordinator = FakeCoordinator(
        InvocationResult(
            RequestId(f"req_{_D}"),
            InvocationState.FAILED,
            0,
            error=error,
        )
    )
    item = operations(
        coordinator,
        approval_dashboard_url="http://127.0.0.1:47622/dashboard",
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

    assert raised.value.detail.code is ErrorCode.RUNAWAY_SUSPECTED
    assert dict(raised.value.detail.details) == {
        "authorization_required": True,
        "dashboard_url": "http://127.0.0.1:47622/dashboard",
        "scope": "session_root_run_service",
    }


@pytest.mark.asyncio
async def test_explicit_crawl_retry_recovers_exact_pending_approval_before_coordinator() -> None:
    class Recovery:
        def __init__(self) -> None:
            self.calls: list[tuple[CoordinatedInvocationRequest, InvocationSession]] = []

        async def recover_pending_approval(
            self,
            request: CoordinatedInvocationRequest,
            session: InvocationSession,
        ) -> PendingApprovalRecoveryResult | None:
            self.calls.append((request, session))
            return PendingApprovalRecoveryResult(
                approval_id="approval-one",
                request_id=request.request_id,
                root_run_id=RootRunId(f"run_{_B}"),
                fingerprint=RequestFingerprint(b"f" * 32, 1, 1),
            )

    recovery = Recovery()
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(
        coordinator,
        configured_profile=profile("firecrawl.crawl.start"),
        pending_approval_recovery=recovery,
        approval_dashboard_url="http://127.0.0.1:47622/dashboard",
    )
    request = InvocationRequest.model_validate(
        {
            "request_id": f"req_{_D}",
            "service": "firecrawl",
            "operation": "crawl.start",
            "input": {
                "url": "https://example.com/careers",
                "include_paths": ["^/careers/"],
                "maximum_pages": 10,
                "purpose": "multi_page_job_extraction",
                "data_classification": ["public_web"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )

    response = await item.invoke(principal(), request)

    assert response.status_code == 202
    assert response.body["approval_id"] == "approval-one"
    assert response.body["approval_context"] == {
        "root_run_id": f"run_{_B}",
        "dashboard_url": "http://127.0.0.1:47622/dashboard",
        "required_action": "decide_locally_then_retry_exact_request",
    }
    assert coordinator.calls == []
    assert len(recovery.calls) == 1
    recovered_request, recovered_session = recovery.calls[0]
    assert recovered_request.request_id == f"req_{_D}"
    assert recovered_request.input_payload["url"] == "https://example.com/careers"
    assert recovered_session.root_run_id == f"run_{_A}"


@pytest.mark.asyncio
async def test_explicit_crawl_without_pending_approval_proceeds_to_coordinator() -> None:
    class Recovery:
        def __init__(self) -> None:
            self.calls = 0

        async def recover_pending_approval(
            self,
            request: CoordinatedInvocationRequest,
            session: InvocationSession,
        ) -> PendingApprovalRecoveryResult | None:
            del request, session
            self.calls += 1
            return None

    recovery = Recovery()
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.FAILED, 0)
    )
    item = operations(
        coordinator,
        configured_profile=profile("firecrawl.crawl.start"),
        pending_approval_recovery=recovery,
    )
    request = InvocationRequest.model_validate(
        {
            "request_id": f"req_{_D}",
            "service": "firecrawl",
            "operation": "crawl.start",
            "input": {
                "url": "https://example.com/careers",
                "maximum_pages": 10,
                "purpose": "multi_page_job_extraction",
                "data_classification": ["public_web"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )

    response = await item.invoke(principal(), request)

    assert response.body["state"] == InvocationState.FAILED.value
    assert recovery.calls == 1
    assert len(coordinator.calls) == 1


@pytest.mark.asyncio
async def test_explicit_crawl_affinity_is_materialized_before_approval_recovery() -> None:
    affinity = ResourceAffinity(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id="provider-job",
        principal_id=PrincipalId(f"prn_{_A}"),
        quota_scope_id=QuotaScopeId(f"quota_{_A}"),
        credential_id=CredentialId(f"cred_{_A}"),
        credential_generation=1,
        pool_id=PoolId(f"pool_{_A}"),
        creating_request_id=RequestId(f"req_{_D}"),
        owner_session_id=SessionId(f"ses_{_A}"),
        owner_workspace_id=WorkspaceId(f"ws_{_A}"),
        owner_root_run_id=RootRunId(f"run_{_A}"),
        bound_at_ms=900,
    )

    class Affinities:
        def __init__(self) -> None:
            self.calls = 0

        async def get_by_request(self, **kwargs: object) -> ResourceAffinity:
            del kwargs
            self.calls += 1
            return affinity

    class Jobs:
        async def create_from_affinity(
            self,
            supplied: ResourceAffinity,
            **kwargs: object,
        ) -> object:
            del kwargs
            assert supplied is affinity

            class Record:
                job_id = JobId(f"job_{_A}")

            return Record()

    class Recovery:
        async def recover_pending_approval(
            self,
            request: CoordinatedInvocationRequest,
            session: InvocationSession,
        ) -> PendingApprovalRecoveryResult | None:
            del request, session
            raise AssertionError("approval recovery ran before durable affinity materialization")

    bound_affinities = Affinities()
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )
    item = operations(
        coordinator,
        configured_profile=profile("firecrawl.crawl.start"),
        jobs=Jobs(),
        affinities=cast(ResourceAffinityStore, bound_affinities),
        pending_approval_recovery=Recovery(),
    )
    request = InvocationRequest.model_validate(
        {
            "request_id": f"req_{_D}",
            "service": "firecrawl",
            "operation": "crawl.start",
            "input": {
                "url": "https://example.com/careers",
                "maximum_pages": 10,
                "purpose": "multi_page_job_extraction",
                "data_classification": ["public_web"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )

    response = await item.invoke(principal(), request)

    assert response.body["state"] == InvocationState.SUCCEEDED.value
    assert response.body["job_id"] == f"job_{_A}"
    assert bound_affinities.calls == 1
    assert coordinator.calls == []


def test_approval_dashboard_url_must_be_a_fixed_numeric_loopback_dashboard() -> None:
    coordinator = FakeCoordinator(
        InvocationResult(RequestId(f"req_{_D}"), InvocationState.SUCCEEDED, 1)
    )

    with pytest.raises(ValueError, match="dashboard URL"):
        operations(
            coordinator,
            approval_dashboard_url="https://example.com/dashboard?approve=true",
        )


@pytest.mark.asyncio
async def test_new_pending_approval_emits_one_secret_free_bounded_signal() -> None:
    class Signals:
        def __init__(self) -> None:
            self.items: list[ApprovalPendingSignal] = []

        def submit(self, signal: ApprovalPendingSignal) -> bool:
            self.items.append(signal)
            return True

    signals = Signals()
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
    item = operations(coordinator, approval_notifications=signals)
    request = InvocationRequest.model_validate(
        {
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "secret-canary-must-not-reach-signal",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )

    await item.invoke(principal(), request)

    assert len(signals.items) == 1
    signal = signals.items[0]
    assert signal.approval_id == "approval-one"
    assert signal.request_id == f"req_{_D}"
    assert signal.session_id == f"ses_{_A}"
    assert signal.root_run_id == f"run_{_A}"
    assert signal.workspace_id == f"ws_{_A}"
    assert signal.requesting_client == "editor"
    assert signal.service == "firecrawl"
    assert signal.operation == "search"
    assert "secret-canary" not in repr(signal)


@pytest.mark.asyncio
async def test_pending_approval_continuation_does_not_emit_a_second_signal() -> None:
    class Signals:
        def __init__(self) -> None:
            self.items: list[ApprovalPendingSignal] = []

        def submit(self, signal: ApprovalPendingSignal) -> bool:
            self.items.append(signal)
            return True

    signals = Signals()
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
    item = operations(coordinator, approval_notifications=signals)
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
            "approval_id": "approval-one",
        }
    )

    await item.invoke(principal(), request)

    assert signals.items == []


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
