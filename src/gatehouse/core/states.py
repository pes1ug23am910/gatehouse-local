"""Explicit persistent states and validated transition graphs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class SessionState(StrEnum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class InvocationState(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    POLICY_CHECK = "POLICY_CHECK"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    DEDUPLICATION = "DEDUPLICATION"
    QUEUED = "QUEUED"
    QUOTA_RESERVED = "QUOTA_RESERVED"
    DISPATCHING = "DISPATCHING"
    RUNNING = "RUNNING"
    RETRY_WAIT = "RETRY_WAIT"
    RECONCILING = "RECONCILING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"
    DUPLICATE_IN_FLIGHT = "DUPLICATE_IN_FLIGHT"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"


class CredentialState(StrEnum):
    HEALTHY = "HEALTHY"
    DRAINING = "DRAINING"
    COOLDOWN = "COOLDOWN"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    DISABLED = "DISABLED"
    QUARANTINED = "QUARANTINED"
    UNKNOWN = "UNKNOWN"


class CircuitBreakerState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ApprovalState(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"


class InvalidStateTransition(ValueError):
    def __init__(self, current: StrEnum, target: StrEnum) -> None:
        self.current = current
        self.target = target
        super().__init__(f"invalid state transition: {current.value} -> {target.value}")


@dataclass(frozen=True, slots=True)
class TransitionGraph[StateT: StrEnum]:
    """Immutable transition graph for one state enum."""

    transitions: Mapping[StateT, frozenset[StateT]]

    @classmethod
    def build(
        cls,
        state_type: type[StateT],
        transitions: Mapping[StateT, Iterable[StateT]],
    ) -> TransitionGraph[StateT]:
        missing = set(state_type) - set(transitions)
        extra = set(transitions) - set(state_type)
        if missing or extra:
            raise ValueError("transition graph must define every state exactly once")
        frozen = {state: frozenset(targets) for state, targets in transitions.items()}
        for targets in frozen.values():
            if not targets <= set(state_type):
                raise ValueError("transition graph contains a target from another state enum")
        return cls(MappingProxyType(frozen))

    def can_transition(self, current: StateT, target: StateT) -> bool:
        return target in self.transitions[current]

    def require(self, current: StateT, target: StateT) -> StateT:
        if not self.can_transition(current, target):
            raise InvalidStateTransition(current, target)
        return target

    def is_terminal(self, state: StateT) -> bool:
        return not self.transitions[state]


SESSION_TRANSITIONS = TransitionGraph.build(
    SessionState,
    {
        SessionState.CREATED: {
            SessionState.ACTIVE,
            SessionState.EXPIRED,
            SessionState.REVOKED,
        },
        SessionState.ACTIVE: {
            SessionState.DISCONNECTED,
            SessionState.SUSPENDED,
            SessionState.EXPIRED,
            SessionState.REVOKED,
        },
        SessionState.DISCONNECTED: {
            SessionState.ACTIVE,
            SessionState.SUSPENDED,
            SessionState.EXPIRED,
            SessionState.REVOKED,
        },
        SessionState.SUSPENDED: {
            SessionState.ACTIVE,
            SessionState.EXPIRED,
            SessionState.REVOKED,
        },
        SessionState.EXPIRED: set(),
        SessionState.REVOKED: set(),
    },
)

INVOCATION_TRANSITIONS = TransitionGraph.build(
    InvocationState,
    {
        InvocationState.RECEIVED: {
            InvocationState.VALIDATING,
            InvocationState.CANCELLED,
        },
        InvocationState.VALIDATING: {
            InvocationState.POLICY_CHECK,
            InvocationState.FAILED,
            InvocationState.DENIED,
            InvocationState.CANCELLED,
        },
        InvocationState.POLICY_CHECK: {
            InvocationState.WAITING_APPROVAL,
            InvocationState.DEDUPLICATION,
            InvocationState.DENIED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
        },
        InvocationState.WAITING_APPROVAL: {
            InvocationState.DEDUPLICATION,
            InvocationState.DENIED,
            InvocationState.CANCELLED,
        },
        InvocationState.DEDUPLICATION: {
            InvocationState.QUOTA_RESERVED,
            InvocationState.QUOTA_EXHAUSTED,
            InvocationState.DUPLICATE_IN_FLIGHT,
            InvocationState.CAPACITY_EXCEEDED,
            InvocationState.DENIED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
        },
        InvocationState.QUEUED: {
            InvocationState.QUOTA_RESERVED,
            InvocationState.DISPATCHING,
            InvocationState.CAPACITY_EXCEEDED,
            InvocationState.QUOTA_EXHAUSTED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
        },
        InvocationState.QUOTA_RESERVED: {
            InvocationState.QUEUED,
            InvocationState.DISPATCHING,
            InvocationState.QUOTA_EXHAUSTED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
        },
        InvocationState.DISPATCHING: {
            InvocationState.RUNNING,
            InvocationState.QUOTA_EXHAUSTED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
            InvocationState.UNKNOWN,
        },
        InvocationState.RUNNING: {
            InvocationState.SUCCEEDED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
            InvocationState.UNKNOWN,
            InvocationState.RETRY_WAIT,
            InvocationState.RECONCILING,
            InvocationState.QUOTA_EXHAUSTED,
        },
        InvocationState.RETRY_WAIT: {
            InvocationState.QUEUED,
            InvocationState.QUOTA_RESERVED,
            InvocationState.QUOTA_EXHAUSTED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
            InvocationState.UNKNOWN,
        },
        InvocationState.RECONCILING: {
            InvocationState.SUCCEEDED,
            InvocationState.FAILED,
            InvocationState.UNKNOWN,
        },
        InvocationState.SUCCEEDED: set(),
        InvocationState.FAILED: set(),
        InvocationState.DENIED: set(),
        InvocationState.CANCELLED: set(),
        InvocationState.UNKNOWN: set(),
        InvocationState.DUPLICATE_IN_FLIGHT: {
            InvocationState.SUCCEEDED,
            InvocationState.FAILED,
            InvocationState.CANCELLED,
            InvocationState.UNKNOWN,
            InvocationState.CAPACITY_EXCEEDED,
            InvocationState.QUOTA_EXHAUSTED,
        },
        InvocationState.CAPACITY_EXCEEDED: set(),
        InvocationState.QUOTA_EXHAUSTED: set(),
    },
)

CREDENTIAL_TRANSITIONS = TransitionGraph.build(
    CredentialState,
    {
        CredentialState.HEALTHY: {
            CredentialState.DRAINING,
            CredentialState.COOLDOWN,
            CredentialState.EXPIRED,
            CredentialState.REVOKED,
            CredentialState.INSUFFICIENT_SCOPE,
            CredentialState.DISABLED,
            CredentialState.QUARANTINED,
            CredentialState.UNKNOWN,
        },
        CredentialState.DRAINING: {
            CredentialState.HEALTHY,
            CredentialState.DISABLED,
            CredentialState.EXPIRED,
            CredentialState.REVOKED,
            CredentialState.QUARANTINED,
        },
        CredentialState.COOLDOWN: {
            CredentialState.HEALTHY,
            CredentialState.DISABLED,
            CredentialState.EXPIRED,
            CredentialState.REVOKED,
            CredentialState.QUARANTINED,
        },
        CredentialState.EXPIRED: {
            CredentialState.HEALTHY,
            CredentialState.DISABLED,
            CredentialState.REVOKED,
        },
        CredentialState.REVOKED: {CredentialState.DISABLED},
        CredentialState.INSUFFICIENT_SCOPE: {
            CredentialState.HEALTHY,
            CredentialState.DISABLED,
            CredentialState.REVOKED,
        },
        CredentialState.DISABLED: {CredentialState.HEALTHY, CredentialState.REVOKED},
        CredentialState.QUARANTINED: {
            CredentialState.HEALTHY,
            CredentialState.DISABLED,
            CredentialState.REVOKED,
        },
        CredentialState.UNKNOWN: {
            CredentialState.HEALTHY,
            CredentialState.DISABLED,
            CredentialState.EXPIRED,
            CredentialState.REVOKED,
            CredentialState.INSUFFICIENT_SCOPE,
            CredentialState.QUARANTINED,
        },
    },
)

CIRCUIT_BREAKER_TRANSITIONS = TransitionGraph.build(
    CircuitBreakerState,
    {
        CircuitBreakerState.CLOSED: {CircuitBreakerState.OPEN},
        CircuitBreakerState.OPEN: {
            CircuitBreakerState.HALF_OPEN,
            CircuitBreakerState.CLOSED,
        },
        CircuitBreakerState.HALF_OPEN: {
            CircuitBreakerState.CLOSED,
            CircuitBreakerState.OPEN,
        },
    },
)

APPROVAL_TRANSITIONS = TransitionGraph.build(
    ApprovalState,
    {
        ApprovalState.PENDING: {
            ApprovalState.APPROVED,
            ApprovalState.DENIED,
            ApprovalState.EXPIRED,
            ApprovalState.REVOKED,
        },
        ApprovalState.APPROVED: {
            ApprovalState.CONSUMED,
            ApprovalState.EXPIRED,
            ApprovalState.REVOKED,
        },
        ApprovalState.DENIED: set(),
        ApprovalState.EXPIRED: set(),
        ApprovalState.CONSUMED: set(),
        ApprovalState.REVOKED: set(),
    },
)
