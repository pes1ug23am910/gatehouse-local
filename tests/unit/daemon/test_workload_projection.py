"""Configured ordinary workload coverage and authenticated health projection."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from pydantic import ValidationError

from gatehouse.admin import AdminAuthManager, LocalControlService
from gatehouse.admin.control import ControlWorkloadReadiness
from gatehouse.config import ClientProfileConfig
from gatehouse.daemon.composition import _ControlHealthAdapter
from gatehouse.daemon.configuration import SynchronizedConfiguration
from gatehouse.daemon.health import RuntimeHealthProbe
from gatehouse.daemon.workload_health import derive_workload_coverage
from gatehouse.policy import Decision, WorkspacePolicy
from gatehouse.policy.engine import PurposeRule
from gatehouse.sessions import SessionManager

OPERATIONS = ("firecrawl.search", "firecrawl.scrape", "firecrawl.map", "firecrawl.crawl.start")


def _profile(
    name: str = "agent-a",
    *,
    pool: str = "configured-pool",
    operations: tuple[str, ...] = OPERATIONS,
    workspaces: tuple[str, ...] = ("workspace-a",),
    unattended: bool = False,
) -> ClientProfileConfig:
    return ClientProfileConfig.model_validate(
        {
            "schema_version": 1,
            "client": {
                "id": name,
                "kind": "system" if unattended else "interactive",
                "unattended": unattended,
                "approval_mode": "deny_on_ask" if unattended else "dashboard",
                "default_priority": "system_reserved" if unattended else "interactive",
                "maximum_concurrent_runs": 1,
                "maximum_in_flight": 2,
                "maximum_queued": 3,
                "maximum_run_duration": "1m",
            },
            "capabilities": {"allow": list(operations)},
            "workspaces": {"allow": list(workspaces)},
            "pools": {"emergency_access": False, "firecrawl": pool},
            "lease": {"heartbeat_interval": "1s", "stale_after": "5s"},
        }
    )


def _policy(
    name: str = "workspace-a",
    *,
    default: Decision = Decision.DENY,
    rules: dict[str, dict[str, PurposeRule]] | None = None,
) -> WorkspacePolicy:
    return WorkspacePolicy(
        policy_id=name,
        version="synthetic-policy",
        workspace_id="ws-" + name,
        service="firecrawl",
        default_decision=default,
        default_pool="not-the-profile-pool",
        purpose_rules=rules
        if rules is not None
        else {
            "research": {"search": PurposeRule(Decision.ALLOW)},
        },
    )


def _synchronized(
    profiles: tuple[ClientProfileConfig, ...] | None = None,
    policies: tuple[WorkspacePolicy, ...] | None = None,
) -> SynchronizedConfiguration:
    selected_profiles = profiles if profiles is not None else (_profile(),)
    selected_policies = policies if policies is not None else (_policy(),)
    return SynchronizedConfiguration(
        clients_by_id={"client-" + item.client.id: item for item in selected_profiles},
        client_ids_by_name={
            item.client.id: "client-" + item.client.id for item in selected_profiles
        },
        policies_by_workspace_id={item.workspace_id: item for item in selected_policies},
        workspace_ids_by_name={item.policy_id: item.workspace_id for item in selected_policies},
        workspace_ids_by_root={},
    )


def test_coverage_uses_actual_client_workspace_purpose_and_profile_pool_bindings() -> None:
    coverage = derive_workload_coverage(
        _synchronized(
            (_profile(operations=("firecrawl.search", "firecrawl.scrape")),),
            (_policy(), _policy("unbound-workspace", default=Decision.ALLOW)),
        )
    )
    assert coverage.verified is True
    assert len(coverage.bindings) == len(coverage.requirements) == 1
    binding = coverage.bindings[0]
    assert (binding.client_id, binding.workspace_id, binding.purpose) == (
        "client-agent-a",
        "ws-workspace-a",
        "research",
    )
    assert binding.requirement == coverage.requirements[0]
    assert (binding.requirement.pool_name, binding.requirement.operation) == (
        "configured-pool",
        "firecrawl.search",
    )


def test_multiple_real_bindings_share_one_probe_without_losing_coverage() -> None:
    coverage = derive_workload_coverage(
        _synchronized(
            (_profile("agent-a"), _profile("agent-b")),
            (
                _policy(
                    rules={
                        "research": {"search": PurposeRule(Decision.ALLOW)},
                        "verification": {"search": PurposeRule(Decision.ALLOW)},
                    }
                ),
            ),
        )
    )
    assert coverage.verified and len(coverage.bindings) == 4
    assert len(coverage.requirements) == 1


def test_effective_default_and_operation_overrides_remain_distinct() -> None:
    coverage = derive_workload_coverage(
        _synchronized(
            (_profile(operations=("firecrawl.search", "firecrawl.map")),),
            (
                _policy(
                    default=Decision.ALLOW,
                    rules={
                        "research": {"search": PurposeRule(Decision.DENY)},
                    },
                ),
            ),
        )
    )
    assert coverage.verified
    assert {(item.purpose, item.requirement.operation) for item in coverage.bindings} == {
        (None, "firecrawl.search"),
        (None, "firecrawl.map"),
        ("research", "firecrawl.map"),
    }


@pytest.mark.parametrize(
    "reason",
    [
        "legacy",
        "watcher",
        "no_capability",
        "ask",
        "deny",
        "other_service",
        "budget",
        "crawl_limit",
    ],
)
def test_no_effective_ordinary_allowed_coverage_never_becomes_green(reason: str) -> None:
    profile, policy = _profile(), _policy()
    if reason == "legacy":
        profile = profile.model_copy(update={"workspaces": None})
    elif reason == "watcher":
        profile = _profile(unattended=True, pool="watcher-reserved")
    elif reason == "no_capability":
        profile = _profile(operations=("docs.search",))
    elif reason in {"ask", "deny"}:
        policy = _policy(rules={"research": {"search": PurposeRule(Decision(reason))}})
    elif reason == "other_service":
        policy = replace(policy, service="github")
    elif reason == "budget":
        policy = replace(policy, maximum_credits_per_root_run=0.5)
    else:
        profile = _profile(operations=("firecrawl.crawl.start",))
        policy = replace(_policy(default=Decision.ALLOW), maximum_crawl_pages=0)
    coverage = derive_workload_coverage(_synchronized((profile,), (policy,)))
    assert coverage.verified and coverage.bindings == () and coverage.requirements == ()


@pytest.mark.parametrize("reason", ["missing_workspace", "missing_policy", "wrong_identity"])
def test_inconsistent_configured_authority_is_unverified(reason: str) -> None:
    synchronized = _synchronized()
    if reason == "missing_workspace":
        synchronized = replace(synchronized, workspace_ids_by_name={})
    elif reason == "missing_policy":
        synchronized = replace(synchronized, policies_by_workspace_id={})
    else:
        synchronized = replace(synchronized, client_ids_by_name={"agent-a": "another-client"})
    coverage = derive_workload_coverage(synchronized)
    assert not coverage.verified and not coverage.requirements and not coverage.bindings


@pytest.mark.parametrize("bound", ["profiles", "routes", "bindings", "policy_checks"])
def test_coverage_overflow_refuses_the_whole_projection_without_truncation(bound: str) -> None:
    policies: tuple[WorkspacePolicy, ...]
    if bound == "profiles":
        profiles = tuple(_profile(f"agent-{index}") for index in range(65))
        policies = (_policy(),)
    elif bound == "routes":
        profiles = tuple(_profile(f"agent-{index}", pool=f"pool-{index}") for index in range(33))
        policies = (_policy(),)
    elif bound == "bindings":
        profiles = (_profile("agent-a"), _profile("agent-b"))
        policies = (
            _policy(
                rules={
                    f"purpose-{index}": {
                        operation: PurposeRule(Decision.ALLOW)
                        for operation in (
                            "search",
                            "scrape",
                            "map",
                            "crawl",
                        )
                    }
                    for index in range(64)
                }
            ),
        )
    else:
        profiles = tuple(
            _profile(f"agent-{index}", workspaces=("workspace-a", "workspace-b"))
            for index in range(10)
        )
        policies = tuple(
            _policy(
                name,
                rules={
                    f"purpose-{index}": {"search": PurposeRule(Decision.DENY)}
                    for index in range(64)
                },
            )
            for name in ("workspace-a", "workspace-b")
        )
    coverage = derive_workload_coverage(_synchronized(profiles, policies))
    assert not coverage.verified and not coverage.bindings and not coverage.requirements


@pytest.mark.parametrize(
    "field,value",
    [
        ("ready", True),
        ("scope", "all_workloads"),
        ("watcher_assessed", True),
        ("provider_reachability_verified", True),
        ("eligible_routes", 1),
        ("status", "READY"),
        ("watcher_assessed", 0),
        ("watcher_assessed", 0.0),
        ("request_authorization_assessed", 0),
        ("provider_reachability_verified", 0),
    ],
)
def test_workload_status_schema_cannot_overstate_coverage(field: str, value: object) -> None:
    body = ControlWorkloadReadiness(status="UNCONFIGURED").model_dump()
    body[field] = value
    with pytest.raises(ValidationError):
        ControlWorkloadReadiness.model_validate(body)


@pytest.mark.asyncio
@pytest.mark.parametrize("lifecycle", ["RECOVERING", "DRAINING", "FAILED_CLOSED", "STOPPED"])
async def test_nonserving_lifecycle_skips_workload_reads(lifecycle: str) -> None:
    def forbidden(_now_ms: int) -> ControlWorkloadReadiness:
        raise AssertionError("nonserving health attempted route assessment")

    health = RuntimeHealthProbe(
        version="test",
        schema_version=16,
        policy_version="test",
        now_ms=lambda: 100,
        started_at_ms=0,
    )
    health.bind_workload_probe(forbidden)
    health.transition(lifecycle)
    workload = health.workload_readiness()
    assert workload.status == "UNAVAILABLE" and workload.ready is False
    assert (await health.readiness()).status == lifecycle


@pytest.mark.asyncio
async def test_authenticated_control_reports_workload_degradation_preserving_controls() -> None:
    calls: list[int] = []

    def assess(now_ms: int) -> ControlWorkloadReadiness:
        calls.append(now_ms)
        return ControlWorkloadReadiness(
            status="DEGRADED",
            checked_at_ms=now_ms,
            binding_count=1,
            required_routes=1,
            ineligible_routes=1,
        )

    health = RuntimeHealthProbe(
        version="test",
        schema_version=16,
        policy_version="test",
        now_ms=lambda: 100,
        started_at_ms=0,
    )
    health.bind_workload_probe(assess)
    health.transition("READY")
    adapter = _ControlHealthAdapter(health, config_digest="a" * 64)

    async def cancel(_session_id: str) -> tuple[int, int]:
        raise AssertionError("status attempted session cancellation")

    service = LocalControlService(
        sessions=cast(SessionManager, object()),
        admin_auth=cast(AdminAuthManager, object()),
        health=adapter,
        launch_authorities={},
        shutdown=lambda: None,
        cancel_session=cancel,
    )
    public = await health.readiness()
    assert public.ready and public.status == "READY"
    assert "workload" not in public.model_dump()
    status = await service.status()
    assert status.ready and status.status == "READY"
    assert status.workload is not None and status.workload.status == "DEGRADED"
    assert status.workload.scope == "ordinary_new_work"
    assert status.workload.watcher_assessed is False
    assert status.workload.request_authorization_assessed is False
    assert status.workload.provider_reachability_verified is False
    assert calls == [100]


@pytest.mark.parametrize("failure", [ValueError, RuntimeError, KeyboardInterrupt])
def test_workload_probe_errors_are_fixed_and_control_flow_is_preserved(
    failure: type[BaseException],
) -> None:
    def broken(_now_ms: int) -> ControlWorkloadReadiness:
        raise failure("synthetic-private-detail")

    health = RuntimeHealthProbe(
        version="test",
        schema_version=16,
        policy_version="test",
        now_ms=lambda: 100,
        started_at_ms=0,
    )
    health.bind_workload_probe(broken)
    health.transition("READY")
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            health.workload_readiness()
    else:
        status = health.workload_readiness()
        assert status.status == "UNVERIFIED"
        assert "synthetic-private-detail" not in status.model_dump_json()
