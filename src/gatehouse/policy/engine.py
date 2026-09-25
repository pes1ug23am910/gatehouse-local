"""Deterministic authorization policy with explicit precedence and reasons."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from gatehouse.config.models import FIXED_POLICY_SENSITIVE_CLASSIFICATIONS, WorkspacePolicyConfig
from gatehouse.policy.sensitive import inspect_sensitive_content
from gatehouse.policy.targets import CanonicalTarget


class Decision(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class ClientClass(StrEnum):
    INTERACTIVE = "interactive"
    UNATTENDED = "unattended"


HARD_DENIED_CLASSIFICATIONS = FIXED_POLICY_SENSITIVE_CLASSIFICATIONS
RESOURCE_BOUND_OPERATIONS = frozenset({"firecrawl.crawl.status", "firecrawl.crawl.cancel"})
POLICY_COMPILER_REVISION = 1


@dataclass(frozen=True, slots=True)
class PurposeRule:
    decision: Decision
    targeted_only: bool = False
    maximum_cost: float | None = None


@dataclass(frozen=True, slots=True)
class WorkspacePolicy:
    policy_id: str
    version: str
    workspace_id: str
    service: str
    default_decision: Decision
    default_pool: str
    purpose_rules: Mapping[str, Mapping[str, PurposeRule]]
    maximum_search_results: int = 20
    maximum_map_results: int = 100
    maximum_crawl_pages: int = 25
    maximum_crawl_depth: int = 2
    maximum_requests_per_root_run: int = 30
    maximum_credits_per_root_run: float = 200
    canonical_root: str | None = field(default=None, repr=False)
    effective_policy_json: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        frozen_rules = {
            purpose: MappingProxyType(dict(operations))
            for purpose, operations in self.purpose_rules.items()
        }
        object.__setattr__(self, "purpose_rules", MappingProxyType(frozen_rules))
        object.__setattr__(self, "effective_policy_json", _effective_policy_json(self))


def _effective_policy_json(policy: WorkspacePolicy) -> str:
    """Freeze effective semantics without exposing the configured filesystem root."""

    # The catalog replaces workspace_id with a durable identifier after compilation.
    # Bind its logical inputs instead; the root digest is not filesystem-trust evidence.
    binding = json.dumps(
        [policy.policy_id, policy.canonical_root.casefold() if policy.canonical_root else None],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    descriptor = {
        "compiler_revision": POLICY_COMPILER_REVISION,
        "policy_id": policy.policy_id,
        "service": policy.service,
        "default_decision": policy.default_decision.value.upper(),
        "default_pool": policy.default_pool,
        "workspace_binding": hashlib.sha256(binding.encode("utf-8")).hexdigest(),
        "hard_denies": {
            "profile": "fixed-v1",
            "data_classifications": sorted(HARD_DENIED_CLASSIFICATIONS),
            "crawl_requires_include_paths": True,
            "crawl_external_links": False,
            "crawl_subdomains": False,
        },
        "credit_discipline": {
            "duplicate_in_flight": "return_original",
            "cross_session_public_coalescing": False,
            "cache_completed_public_reads": "disabled",
            "broad_crawl_without_narrow_attempt": "deny",
            "prior_narrow_attempt_tracking": False,
        },
        "enforce_limits": True,
        "limits": {
            "search_results": policy.maximum_search_results,
            "map_results": policy.maximum_map_results,
            "crawl_pages": policy.maximum_crawl_pages,
            "crawl_depth": policy.maximum_crawl_depth,
            "requests_per_root_run": policy.maximum_requests_per_root_run,
            "credits_per_root_run": float(policy.maximum_credits_per_root_run),
        },
        "purposes": [
            {
                "purpose": purpose,
                "operations": [
                    {
                        "operation": operation,
                        "decision": rule.decision.value.upper(),
                        "targeted_only": rule.targeted_only,
                        "maximum_cost": (
                            float(rule.maximum_cost) if rule.maximum_cost is not None else None
                        ),
                    }
                    for operation, rule in sorted(operations.items())
                ],
            }
            for purpose, operations in sorted(policy.purpose_rules.items())
        ],
    }
    return json.dumps(
        descriptor, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    )


def _with_effective_version(policy: WorkspacePolicy) -> WorkspacePolicy:
    version = hashlib.sha256(policy.effective_policy_json.encode("utf-8")).hexdigest()[:16]
    return replace(policy, version=version)


@dataclass(frozen=True, slots=True)
class ApprovalEvidence:
    """Server-issued approval facts; callers cannot construct these through the API."""

    approval_id: str
    session_id: str
    service: str
    operation: str
    request_fingerprint: str
    target_summary: str | None
    pool: str
    maximum_estimated_cost: float
    expires_at: datetime
    uses_remaining: int


@dataclass(frozen=True, slots=True)
class PolicyContext:
    client_class: ClientClass
    client_id: str
    session_id: str
    root_run_id: str
    workspace_id: str
    service: str
    operation: str
    purpose: str
    data_classifications: frozenset[str]
    input_payload: Mapping[str, Any]
    request_fingerprint: str
    estimated_cost: float
    proposed_pool: str
    request_count_remaining: int
    credit_budget_remaining: float
    now: datetime
    canonical_target: CanonicalTarget | None = None
    allowed_capabilities: frozenset[str] = field(default_factory=frozenset)
    service_kill_switch_open: bool = False
    circuit_breaker_open: bool = False
    automatic_pool_selection: bool = True
    approval: ApprovalEvidence | None = None
    feed_set_authorized: bool = False
    schedule_open: bool = True
    resource_ownership_verified: bool = False


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: Decision
    rule_id: str
    reason_code: str
    policy_id: str
    policy_version: str
    constraints: Mapping[str, int | float | str | bool] = field(default_factory=dict)
    approval_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "constraints", MappingProxyType(dict(self.constraints)))


def _operation_family(operation: str) -> str:
    if operation.startswith("firecrawl."):
        operation = operation.removeprefix("firecrawl.")
    if operation.startswith("crawl."):
        return "crawl"
    if operation == "account.credit_status":
        return "credit_status"
    return operation


class PolicyEngine:
    """Evaluate one already validated, canonical request without side effects."""

    def __init__(self, policy: WorkspacePolicy) -> None:
        self._policy = policy

    def _result(
        self,
        decision: Decision,
        rule_id: str,
        reason_code: str,
        *,
        constraints: Mapping[str, int | float | str | bool] | None = None,
        approval_id: str | None = None,
    ) -> PolicyResult:
        return PolicyResult(
            decision=decision,
            rule_id=rule_id,
            reason_code=reason_code,
            policy_id=self._policy.policy_id,
            policy_version=self._policy.version,
            constraints=constraints or {},
            approval_id=approval_id,
        )

    def evaluate(self, context: PolicyContext) -> PolicyResult:
        """Apply non-overridable denies before any approval or allow rule."""

        if context.workspace_id != self._policy.workspace_id:
            return self._result(Decision.DENY, "workspace-mismatch", "workspace_not_authorized")
        if context.service != self._policy.service:
            return self._result(Decision.DENY, "service-mismatch", "service_not_authorized")
        if context.operation not in context.allowed_capabilities:
            return self._result(Decision.DENY, "capability-ceiling", "operation_not_authorized")
        if context.operation == "firecrawl.account.credit_status":
            return self._result(Decision.DENY, "admin-only-operation", "operation_not_authorized")
        denied_classes = HARD_DENIED_CLASSIFICATIONS & context.data_classifications
        if denied_classes:
            return self._result(
                Decision.DENY,
                "no-sensitive-payloads",
                "sensitive_classification_denied",
            )
        inspection = inspect_sensitive_content(context.input_payload)
        if inspection.denied:
            return self._result(
                Decision.DENY,
                "sensitive-content-heuristic",
                inspection.findings[0],
            )
        if context.service_kill_switch_open:
            return self._result(Decision.DENY, "service-kill-switch", "service_disabled")
        if context.circuit_breaker_open:
            return self._result(Decision.DENY, "circuit-breaker", "service_unavailable")
        if context.proposed_pool == "emergency-locked" and context.automatic_pool_selection:
            return self._result(Decision.DENY, "emergency-manual-only", "emergency_pool_locked")
        if context.request_count_remaining <= 0:
            return self._result(Decision.DENY, "root-run-request-budget", "budget_exhausted")
        if context.estimated_cost < 0 or context.estimated_cost > context.credit_budget_remaining:
            return self._result(Decision.DENY, "root-run-credit-budget", "budget_exhausted")

        operation = _operation_family(context.operation)
        payload = context.input_payload
        resource_bound = context.operation in RESOURCE_BOUND_OPERATIONS
        if resource_bound and not context.resource_ownership_verified:
            return self._result(
                Decision.DENY,
                "resource-ownership",
                "resource_ownership_required",
            )
        if resource_bound:
            return self._result(
                Decision.ALLOW,
                "resource-bound-owner",
                "resource_owner_authorized",
            )
        if operation in {"scrape", "map", "crawl"} and context.canonical_target is None:
            return self._result(Decision.DENY, "canonical-target-required", "invalid_target")
        if (
            operation == "search"
            and int(payload.get("limit", 10)) > self._policy.maximum_search_results
        ):
            return self._result(Decision.DENY, "search-result-cap", "limit_exceeded")
        if operation == "map" and int(payload.get("limit", 100)) > self._policy.maximum_map_results:
            return self._result(Decision.DENY, "map-result-cap", "limit_exceeded")
        if operation == "crawl":
            if bool(payload.get("allow_external_links", False)):
                return self._result(Decision.DENY, "no-external-link-crawl", "invalid_target")
            if bool(payload.get("allow_subdomains", False)):
                return self._result(Decision.DENY, "no-subdomain-crawl", "invalid_target")
            if not payload.get("include_paths"):
                return self._result(Decision.DENY, "narrow-crawl-required", "broad_crawl_denied")
            if int(payload.get("maximum_pages", 0)) > self._policy.maximum_crawl_pages:
                return self._result(Decision.DENY, "crawl-page-cap", "limit_exceeded")
            if int(payload.get("maximum_depth", 0)) > self._policy.maximum_crawl_depth:
                return self._result(Decision.DENY, "crawl-depth-cap", "limit_exceeded")

        if context.client_class is ClientClass.UNATTENDED:
            if context.purpose != "opening_monitoring":
                return self._result(Decision.DENY, "watcher-purpose", "watcher_scope_denied")
            if not context.feed_set_authorized:
                return self._result(Decision.DENY, "watcher-feed-set", "watcher_target_denied")
            if not context.schedule_open:
                return self._result(Decision.DENY, "watcher-schedule", "watcher_outside_schedule")
            if context.proposed_pool != "watcher-reserved":
                return self._result(Decision.DENY, "watcher-pool", "watcher_pool_required")

        purpose_rules = self._policy.purpose_rules.get(context.purpose, {})
        purpose_rule = purpose_rules.get(operation)
        if purpose_rule is None:
            decision = self._policy.default_decision
            rule_id = "default-decision"
        else:
            decision = purpose_rule.decision
            rule_id = f"purpose:{context.purpose}:{operation}"
            if purpose_rule.targeted_only and (
                context.canonical_target is None or context.canonical_target.path == "/"
            ):
                decision = Decision.ASK
            if (
                purpose_rule.maximum_cost is not None
                and context.estimated_cost > purpose_rule.maximum_cost
            ):
                decision = Decision.ASK

        approval = context.approval
        if (
            decision is Decision.ASK
            and approval is not None
            and self._approval_matches(context, approval)
        ):
            return self._result(
                Decision.ALLOW,
                "valid-bound-approval",
                "approved",
                approval_id=approval.approval_id,
            )
        if decision is Decision.ASK and context.client_class is ClientClass.UNATTENDED:
            return self._result(
                Decision.DENY,
                rule_id,
                "approval_unavailable_for_unattended_client",
            )
        constraints: dict[str, int | float | str | bool] = {
            "maximum_search_results": self._policy.maximum_search_results,
            "maximum_map_results": self._policy.maximum_map_results,
            "maximum_crawl_pages": self._policy.maximum_crawl_pages,
            "maximum_crawl_depth": self._policy.maximum_crawl_depth,
        }
        return self._result(decision, rule_id, f"policy_{decision.value}", constraints=constraints)

    @staticmethod
    def _approval_matches(context: PolicyContext, approval: ApprovalEvidence) -> bool:
        target_summary = context.canonical_target.summary if context.canonical_target else None
        return (
            approval.session_id == context.session_id
            and approval.service == context.service
            and approval.operation == context.operation
            and approval.request_fingerprint == context.request_fingerprint
            and approval.target_summary == target_summary
            and approval.pool == context.proposed_pool
            and approval.maximum_estimated_cost >= context.estimated_cost
            and approval.expires_at > context.now
            and approval.uses_remaining > 0
        )


def default_placement_policy() -> WorkspacePolicy:
    """Return the frozen, normalized placement-research policy seed."""

    allow = PurposeRule(Decision.ALLOW)
    ask = PurposeRule(Decision.ASK)
    deny = PurposeRule(Decision.DENY)
    targeted = PurposeRule(Decision.ALLOW, targeted_only=True)
    policy = WorkspacePolicy(
        policy_id="placement-schedule",
        version="",
        workspace_id="placement-schedule",
        service="firecrawl",
        default_decision=Decision.ASK,
        default_pool="interactive-default",
        purpose_rules={
            "career_discovery": {
                "search": allow,
                "scrape": targeted,
                "map": ask,
                "crawl": deny,
            },
            "career_site_research": {
                "search": allow,
                "scrape": allow,
                "map": allow,
                "crawl": ask,
            },
            "active_job_verification": {
                "search": allow,
                "scrape": allow,
                "map": deny,
                "crawl": deny,
            },
            "js_heavy_extraction": {
                "search": allow,
                "scrape": allow,
                "map": allow,
                "crawl": ask,
            },
            "multi_page_job_extraction": {
                "search": allow,
                "scrape": allow,
                "map": allow,
                "crawl": allow,
            },
            "opening_monitoring": {
                "search": allow,
                "scrape": allow,
                "map": allow,
                "crawl": allow,
            },
        },
    )
    return _with_effective_version(policy)


def workspace_policy_from_config(config: WorkspacePolicyConfig) -> WorkspacePolicy:
    """Compile validated configuration into the policy engine's immutable form."""

    # Frozen model attributes can still contain mutable dictionaries/lists. Revalidate
    # the snapshot so a changed nested value cannot bypass fixed-profile admission.
    config = WorkspacePolicyConfig.model_validate(config.model_dump(mode="python"))
    purpose_rules: dict[str, dict[str, PurposeRule]] = {}
    for purpose, operation_policy in config.purposes.items():
        purpose_rules[purpose] = {
            operation: PurposeRule(
                decision=Decision(rule.decision.value.lower()),
                targeted_only=rule.constraints.targeted_only,
            )
            for operation, rule in operation_policy.root.items()
        }
    policy = WorkspacePolicy(
        policy_id=config.workspace.id,
        version="",
        workspace_id=config.workspace.id,
        canonical_root=config.workspace.canonical_root,
        service=config.service,
        default_decision=Decision(config.default_decision.value.lower()),
        default_pool=config.default_pool,
        purpose_rules=purpose_rules,
        maximum_search_results=config.limits.search_results,
        maximum_map_results=config.limits.map_results,
        maximum_crawl_pages=config.limits.crawl_pages,
        maximum_crawl_depth=config.limits.crawl_depth,
        maximum_requests_per_root_run=config.limits.requests_per_root_run,
        maximum_credits_per_root_run=config.limits.credits_per_root_run,
    )
    return _with_effective_version(policy)
