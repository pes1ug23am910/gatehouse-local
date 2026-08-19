from __future__ import annotations

import pytest

from gatehouse.core.states import (
    APPROVAL_TRANSITIONS,
    CIRCUIT_BREAKER_TRANSITIONS,
    INVOCATION_TRANSITIONS,
    SESSION_TRANSITIONS,
    ApprovalState,
    CircuitBreakerState,
    InvalidStateTransition,
    InvocationState,
    SessionState,
    TransitionGraph,
)


def test_session_can_reconnect_without_extending_terminal_states() -> None:
    assert SESSION_TRANSITIONS.can_transition(SessionState.DISCONNECTED, SessionState.ACTIVE)
    assert SESSION_TRANSITIONS.is_terminal(SessionState.EXPIRED)
    assert SESSION_TRANSITIONS.is_terminal(SessionState.REVOKED)


def test_session_cannot_resume_after_revocation() -> None:
    with pytest.raises(InvalidStateTransition) as captured:
        SESSION_TRANSITIONS.require(SessionState.REVOKED, SessionState.ACTIVE)

    assert captured.value.current is SessionState.REVOKED
    assert captured.value.target is SessionState.ACTIVE


def test_invocation_happy_path_is_explicit() -> None:
    path = [
        InvocationState.RECEIVED,
        InvocationState.VALIDATING,
        InvocationState.POLICY_CHECK,
        InvocationState.DEDUPLICATION,
        InvocationState.QUOTA_RESERVED,
        InvocationState.QUEUED,
        InvocationState.DISPATCHING,
        InvocationState.RUNNING,
        InvocationState.SUCCEEDED,
    ]

    for current, target in zip(path[:-1], path[1:], strict=True):
        assert INVOCATION_TRANSITIONS.require(current, target) is target


@pytest.mark.parametrize(
    "state",
    [
        InvocationState.SUCCEEDED,
        InvocationState.FAILED,
        InvocationState.DENIED,
        InvocationState.CANCELLED,
        InvocationState.UNKNOWN,
        InvocationState.CAPACITY_EXCEEDED,
        InvocationState.QUOTA_EXHAUSTED,
    ],
)
def test_invocation_terminal_states_cannot_be_replayed(state: InvocationState) -> None:
    assert INVOCATION_TRANSITIONS.is_terminal(state)
    with pytest.raises(InvalidStateTransition):
        INVOCATION_TRANSITIONS.require(state, InvocationState.QUEUED)


def test_ambiguous_running_operation_becomes_terminal_unknown() -> None:
    assert INVOCATION_TRANSITIONS.can_transition(InvocationState.RUNNING, InvocationState.UNKNOWN)
    assert INVOCATION_TRANSITIONS.is_terminal(InvocationState.UNKNOWN)


def test_coalesced_invocation_resolves_to_a_stable_terminal_outcome() -> None:
    assert INVOCATION_TRANSITIONS.can_transition(
        InvocationState.DUPLICATE_IN_FLIGHT,
        InvocationState.SUCCEEDED,
    )
    assert not INVOCATION_TRANSITIONS.is_terminal(InvocationState.DUPLICATE_IN_FLIGHT)


def test_approval_is_one_way_after_consumption() -> None:
    assert APPROVAL_TRANSITIONS.can_transition(ApprovalState.PENDING, ApprovalState.APPROVED)
    assert APPROVAL_TRANSITIONS.can_transition(ApprovalState.APPROVED, ApprovalState.CONSUMED)
    assert APPROVAL_TRANSITIONS.is_terminal(ApprovalState.CONSUMED)


def test_circuit_breaker_only_uses_defined_recovery_path() -> None:
    assert CIRCUIT_BREAKER_TRANSITIONS.can_transition(
        CircuitBreakerState.CLOSED, CircuitBreakerState.OPEN
    )
    assert CIRCUIT_BREAKER_TRANSITIONS.can_transition(
        CircuitBreakerState.OPEN, CircuitBreakerState.HALF_OPEN
    )
    assert not CIRCUIT_BREAKER_TRANSITIONS.can_transition(
        CircuitBreakerState.CLOSED, CircuitBreakerState.HALF_OPEN
    )


def test_transition_graph_requires_every_enum_member() -> None:
    with pytest.raises(ValueError, match="every state"):
        TransitionGraph.build(
            CircuitBreakerState,
            {CircuitBreakerState.CLOSED: {CircuitBreakerState.OPEN}},
        )
