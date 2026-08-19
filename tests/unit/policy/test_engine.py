from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from gatehouse.policy.engine import (
    ApprovalEvidence,
    ClientClass,
    Decision,
    PolicyContext,
    PolicyEngine,
    default_placement_policy,
    workspace_policy_from_config,
)
from gatehouse.policy.targets import canonicalize_public_url


def context(**changes: Any) -> PolicyContext:
    now = datetime(2026, 8, 19, tzinfo=UTC)
    base = PolicyContext(
        client_class=ClientClass.INTERACTIVE,
        client_id="client-1",
        session_id="session-1",
        root_run_id="run-1",
        workspace_id="placement-schedule",
        service="firecrawl",
        operation="firecrawl.search",
        purpose="career_discovery",
        data_classifications=frozenset({"public_web_query"}),
        input_payload={"query": "graduate roles", "limit": 10},
        request_fingerprint="fp-1",
        estimated_cost=1,
        proposed_pool="interactive-default",
        request_count_remaining=10,
        credit_budget_remaining=100,
        now=now,
        allowed_capabilities=frozenset(
            {
                "firecrawl.search",
                "firecrawl.scrape",
                "firecrawl.map",
                "firecrawl.crawl.start",
            }
        ),
    )
    return replace(base, **changes)


def test_allows_bounded_discovery_search() -> None:
    result = PolicyEngine(default_placement_policy()).evaluate(context())

    assert result.decision is Decision.ALLOW


def test_sensitive_classification_is_non_overridable() -> None:
    approval = ApprovalEvidence(
        approval_id="approval-1",
        session_id="session-1",
        service="firecrawl",
        operation="firecrawl.search",
        request_fingerprint="fp-1",
        target_summary=None,
        pool="interactive-default",
        maximum_estimated_cost=10,
        expires_at=datetime(2026, 8, 20, tzinfo=UTC),
        uses_remaining=1,
    )
    denied = context(
        data_classifications=frozenset({"credential"}),
        approval=approval,
    )

    result = PolicyEngine(default_placement_policy()).evaluate(denied)

    assert result.decision is Decision.DENY
    assert result.rule_id == "no-sensitive-payloads"


def test_targeted_scrape_of_domain_root_requires_approval() -> None:
    target = canonicalize_public_url("https://example.com/")
    request = context(
        operation="firecrawl.scrape",
        purpose="career_discovery",
        data_classifications=frozenset({"public_web"}),
        input_payload={"url": target.url},
        canonical_target=target,
    )

    result = PolicyEngine(default_placement_policy()).evaluate(request)

    assert result.decision is Decision.ASK


def test_bound_approval_changes_only_ask_to_allow() -> None:
    target = canonicalize_public_url("https://example.com/")
    request = context(
        operation="firecrawl.scrape",
        purpose="career_discovery",
        data_classifications=frozenset({"public_web"}),
        input_payload={"url": target.url},
        canonical_target=target,
    )
    approval = ApprovalEvidence(
        approval_id="approval-1",
        session_id=request.session_id,
        service=request.service,
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        target_summary=target.summary,
        pool=request.proposed_pool,
        maximum_estimated_cost=1,
        expires_at=request.now + timedelta(minutes=5),
        uses_remaining=1,
    )

    result = PolicyEngine(default_placement_policy()).evaluate(replace(request, approval=approval))

    assert result.decision is Decision.ALLOW
    assert result.approval_id == "approval-1"


def test_unattended_ask_is_immediate_deny() -> None:
    target = canonicalize_public_url("https://example.com/jobs")
    request = context(
        client_class=ClientClass.UNATTENDED,
        operation="firecrawl.crawl.start",
        purpose="opening_monitoring",
        data_classifications=frozenset({"public_job_data"}),
        input_payload={
            "url": target.url,
            "include_paths": ["^/jobs"],
            "maximum_pages": 10,
            "maximum_depth": 1,
        },
        canonical_target=target,
        feed_set_authorized=True,
        schedule_open=True,
        proposed_pool="watcher-reserved",
    )

    result = PolicyEngine(default_placement_policy()).evaluate(request)

    assert result.decision is Decision.ALLOW


def test_watcher_outside_schedule_is_denied() -> None:
    target = canonicalize_public_url("https://example.com/jobs")
    request = context(
        client_class=ClientClass.UNATTENDED,
        operation="firecrawl.scrape",
        purpose="opening_monitoring",
        data_classifications=frozenset({"public_job_data"}),
        input_payload={"url": target.url},
        canonical_target=target,
        feed_set_authorized=True,
        schedule_open=False,
        proposed_pool="watcher-reserved",
    )

    result = PolicyEngine(default_placement_policy()).evaluate(request)

    assert result.decision is Decision.DENY
    assert result.reason_code == "watcher_outside_schedule"


def test_validated_yaml_policy_compiles_without_pseudo_decisions() -> None:
    from pathlib import Path

    from gatehouse.config import load_workspace_policy

    root = Path(__file__).parents[3]
    config = load_workspace_policy(root / "config" / "policies" / "placement-schedule.example.yaml")
    compiled = workspace_policy_from_config(config)

    assert compiled.maximum_crawl_pages == 25
    assert compiled.purpose_rules["multi_page_job_extraction"]["crawl"].decision is Decision.ALLOW
    assert compiled.purpose_rules["career_discovery"]["scrape"].targeted_only


def test_resource_bound_crawl_status_uses_ownership_instead_of_url() -> None:
    request = context(
        operation="firecrawl.crawl.status",
        purpose="multi_page_job_extraction",
        input_payload={"provider_job_id": "job-1"},
        allowed_capabilities=frozenset({"firecrawl.crawl.status"}),
        resource_ownership_verified=True,
    )

    result = PolicyEngine(default_placement_policy()).evaluate(request)

    assert result.decision is Decision.ALLOW


def test_configured_active_job_verification_is_owner_authorized() -> None:
    from pathlib import Path

    from gatehouse.config import load_workspace_policy

    root = Path(__file__).parents[3]
    compiled = workspace_policy_from_config(
        load_workspace_policy(root / "config" / "policies" / "placement-schedule.example.yaml")
    )
    request = context(
        operation="firecrawl.crawl.status",
        purpose="active_job_verification",
        input_payload={"provider_job_id": "job-1"},
        allowed_capabilities=frozenset({"firecrawl.crawl.status"}),
        resource_ownership_verified=True,
    )

    result = PolicyEngine(compiled).evaluate(request)

    assert result.decision is Decision.ALLOW
    assert result.rule_id == "resource-bound-owner"


def test_resource_bound_operation_without_affinity_is_denied() -> None:
    request = context(
        operation="firecrawl.crawl.cancel",
        purpose="multi_page_job_extraction",
        input_payload={"provider_job_id": "job-1"},
        allowed_capabilities=frozenset({"firecrawl.crawl.cancel"}),
        resource_ownership_verified=False,
    )

    result = PolicyEngine(default_placement_policy()).evaluate(request)

    assert result.decision is Decision.DENY
    assert result.reason_code == "resource_ownership_required"


def test_agent_policy_never_exposes_account_credit_status() -> None:
    request = context(
        operation="firecrawl.account.credit_status",
        purpose="career_discovery",
        input_payload={},
        allowed_capabilities=frozenset({"firecrawl.account.credit_status"}),
    )

    result = PolicyEngine(default_placement_policy()).evaluate(request)

    assert result.decision is Decision.DENY
    assert result.rule_id == "admin-only-operation"
