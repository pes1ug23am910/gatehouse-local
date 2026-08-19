"""Fail-closed target, content, and authorization policy."""

from gatehouse.policy.engine import (
    ClientClass,
    Decision,
    PolicyContext,
    PolicyEngine,
    PolicyResult,
    WorkspacePolicy,
    default_placement_policy,
    workspace_policy_from_config,
)
from gatehouse.policy.sensitive import InspectionResult, inspect_sensitive_content
from gatehouse.policy.targets import CanonicalTarget, canonicalize_public_url

__all__ = [
    "CanonicalTarget",
    "ClientClass",
    "Decision",
    "InspectionResult",
    "PolicyContext",
    "PolicyEngine",
    "PolicyResult",
    "WorkspacePolicy",
    "canonicalize_public_url",
    "default_placement_policy",
    "inspect_sensitive_content",
    "workspace_policy_from_config",
]
