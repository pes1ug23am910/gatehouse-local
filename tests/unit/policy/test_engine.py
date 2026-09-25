from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from gatehouse.config import WorkspacePolicyConfig, load_workspace_policy
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


def policy_config() -> WorkspacePolicyConfig:
    return load_workspace_policy(
        Path(__file__).parents[3] / "config/policies/placement-schedule.example.yaml"
    )


def test_effective_policy_versions_normalize_order_and_shorthand() -> None:
    original = policy_config()
    document = original.model_dump(mode="python")
    document["hard_denies"].reverse()
    for rule in document["hard_denies"]:
        if rule["data_classifications_any"] is not None:
            rule["data_classifications_any"].reverse()
    document["purposes"] = dict(reversed(list(document["purposes"].items())))
    for purpose in document["purposes"]:
        document["purposes"][purpose] = dict(reversed(list(document["purposes"][purpose].items())))
    document["purposes"]["career_discovery"]["search"] = "allow_with_limits"
    document["purposes"]["career_discovery"]["scrape"] = {
        "decision": "allow",
        "constraints": {"targeted_only": True, "enforce_limits": True},
    }
    equivalent = WorkspacePolicyConfig.model_validate(document)
    first = workspace_policy_from_config(original)
    second = workspace_policy_from_config(equivalent)
    assert first.effective_policy_json == second.effective_policy_json
    assert first.version == second.version
    assert first.version == hashlib.sha256(first.effective_policy_json.encode()).hexdigest()[:16]


@pytest.mark.parametrize(
    ("section", "name", "value"),
    [
        ("limits", "search_results", 19),
        ("limits", "map_results", 99),
        ("limits", "crawl_pages", 24),
        ("limits", "crawl_depth", 1),
        ("limits", "requests_per_root_run", 29),
        ("limits", "credits_per_root_run", 199.0),
        ("workspace", "id", "another-workspace"),
        ("workspace", "canonical_root", r"E:\Projects\Another-Workspace"),
    ],
)
def test_effective_policy_version_binds_limits_and_workspace(
    section: str, name: str, value: object
) -> None:
    original = policy_config()
    document = original.model_dump(mode="python")
    document[section][name] = value
    changed = WorkspacePolicyConfig.model_validate(document)
    assert (
        workspace_policy_from_config(changed).version
        != workspace_policy_from_config(original).version
    )


@pytest.mark.parametrize("field", ["default_decision", "default_pool", "purpose", "targeted_only"])
def test_effective_policy_version_binds_decisions_and_pool(field: str) -> None:
    original = policy_config()
    document = original.model_dump(mode="python")
    if field == "purpose":
        document["purposes"]["career_discovery"]["search"] = "deny"
    elif field == "targeted_only":
        document["purposes"]["career_discovery"]["scrape"] = "allow"
    else:
        document[field] = "deny" if field == "default_decision" else "another-pool"
    changed = workspace_policy_from_config(WorkspacePolicyConfig.model_validate(document))
    assert changed.version != workspace_policy_from_config(original).version


def test_effective_policy_keeps_logical_binding_when_catalog_replaces_runtime_id() -> None:
    compiled = workspace_policy_from_config(policy_config())
    synchronized = replace(compiled, workspace_id="wsp_opaque_runtime_identity")
    assert synchronized.effective_policy_json == compiled.effective_policy_json
    assert synchronized.version == compiled.version
    assert PolicyEngine(synchronized).evaluate(context()).reason_code == "workspace_not_authorized"
    assert (
        PolicyEngine(synchronized)
        .evaluate(context(workspace_id=synchronized.workspace_id))
        .decision
        is Decision.ALLOW
    )
    assert "E:\\Projects" not in compiled.effective_policy_json
    descriptor = json.loads(compiled.effective_policy_json)
    assert len(descriptor["workspace_binding"]) == 64


def test_effective_policy_is_immutable_and_independent_of_nested_configuration() -> None:
    config = policy_config()
    compiled = workspace_policy_from_config(config)
    previous = compiled.effective_policy_json
    config.purposes["career_discovery"].root.clear()
    config.hard_denies.clear()
    assert compiled.effective_policy_json == previous
    assert PolicyEngine(compiled).evaluate(context()).decision is Decision.ALLOW
    with pytest.raises(TypeError):
        compiled.purpose_rules["career_discovery"]["search"] = compiled.purpose_rules[  # type: ignore[index]
            "career_discovery"
        ]["crawl"]
    with pytest.raises(FrozenInstanceError):
        compiled.effective_policy_json = "{}"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        workspace_policy_from_config(config)


def test_default_policy_uses_the_same_canonical_version_contract() -> None:
    policy = default_placement_policy()
    assert policy.version == hashlib.sha256(policy.effective_policy_json.encode()).hexdigest()[:16]
    descriptor = json.loads(policy.effective_policy_json)
    assert descriptor["compiler_revision"] == 1
    assert descriptor["enforce_limits"] is True
    assert descriptor["hard_denies"]["profile"] == "fixed-v1"
    assert descriptor["credit_discipline"] == {
        "duplicate_in_flight": "return_original",
        "cross_session_public_coalescing": False,
        "cache_completed_public_reads": "disabled",
        "broad_crawl_without_narrow_attempt": "deny",
        "prior_narrow_attempt_tracking": False,
    }


@pytest.mark.parametrize("shorthand", ["allow", "allow_with_limits"])
def test_policy_limits_cannot_be_disabled_by_an_allow_shorthand(shorthand: str) -> None:
    document = policy_config().model_dump(mode="python")
    document["purposes"]["career_discovery"]["search"] = shorthand
    policy = workspace_policy_from_config(WorkspacePolicyConfig.model_validate(document))
    assert (
        PolicyEngine(policy)
        .evaluate(context(input_payload={"query": "graduate roles", "limit": 21}))
        .reason_code
        == "limit_exceeded"
    )
    assert (
        PolicyEngine(policy)
        .evaluate(context(data_classifications=frozenset({"private_document"})))
        .reason_code
        == "sensitive_classification_denied"
    )


@pytest.mark.parametrize(
    ("payload_changes", "reason"),
    [
        ({"include_paths": []}, "broad_crawl_denied"),
        ({"allow_external_links": True}, "invalid_target"),
        ({"allow_subdomains": True}, "invalid_target"),
        ({"maximum_pages": 26}, "limit_exceeded"),
        ({"maximum_depth": 3}, "limit_exceeded"),
    ],
)
def test_fixed_crawl_controls_precede_allow_and_approval(
    payload_changes: dict[str, object], reason: str
) -> None:
    target = canonicalize_public_url("https://example.com/jobs")
    payload = {
        "include_paths": ["^/jobs"],
        "maximum_pages": 10,
        "maximum_depth": 1,
        **payload_changes,
    }
    request = context(
        operation="firecrawl.crawl.start",
        purpose="multi_page_job_extraction",
        canonical_target=target,
        input_payload=payload,
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
    result = PolicyEngine(workspace_policy_from_config(policy_config())).evaluate(
        replace(request, approval=approval)
    )
    assert result.decision is Decision.DENY
    assert result.reason_code == reason
