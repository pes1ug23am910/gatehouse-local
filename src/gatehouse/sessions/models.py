"""Immutable session and root-run records plus their explicit state machines."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType

from gatehouse.core.states import SESSION_TRANSITIONS
from gatehouse.core.states import SessionState as SessionState


class RootRunState(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class SessionTransitionConditionError(ValueError):
    """Raised when time or epoch conditions make a legal graph edge unavailable."""


class InvalidRootRunTransition(ValueError):
    """Raised when code attempts to change a terminal root run."""


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: str
    client_id: str
    workspace_id: str | None
    bootstrap_verifier: bytes
    bootstrap_version: int
    token_epoch: int
    revocation_epoch: int
    state: SessionState
    identity_assurance: str
    policy_version: str
    created_at_ms: int
    last_seen_at_ms: int | None
    disconnected_at_ms: int | None
    reconnect_until_ms: int
    absolute_expires_at_ms: int
    revoked_at_ms: int | None = None
    budget: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.session_id or not self.client_id:
            raise ValueError("session and client identifiers are required")
        if len(self.bootstrap_verifier) != 32:
            raise ValueError("bootstrap verifier must be a SHA-256 HMAC")
        if self.bootstrap_version <= 0:
            raise ValueError("bootstrap version must be positive")
        if self.token_epoch < 0 or self.revocation_epoch < 0:
            raise ValueError("epochs must be non-negative")
        if self.absolute_expires_at_ms <= self.created_at_ms:
            raise ValueError("absolute expiration must follow creation")
        if self.reconnect_until_ms > self.absolute_expires_at_ms:
            raise ValueError("reconnect deadline cannot exceed absolute expiration")
        if any(value < 0 for value in self.budget.values()):
            raise ValueError("session budgets must be non-negative")
        object.__setattr__(self, "budget", MappingProxyType(dict(self.budget)))

    @property
    def terminal(self) -> bool:
        return SESSION_TRANSITIONS.is_terminal(self.state)

    def transition(
        self,
        target: SessionState,
        *,
        now_ms: int,
        reconnect_grace_ms: int | None = None,
        token_epoch: int | None = None,
    ) -> SessionRecord:
        """Return a validated replacement record for one explicit transition."""

        SESSION_TRANSITIONS.require(self.state, target)

        next_token_epoch = self.token_epoch
        if token_epoch is not None:
            if token_epoch < self.token_epoch:
                raise ValueError("token epoch cannot move backwards")
            next_token_epoch = token_epoch

        if target is SessionState.ACTIVE:
            if now_ms >= self.absolute_expires_at_ms:
                raise SessionTransitionConditionError("expired session cannot become active")
            if self.state is SessionState.DISCONNECTED and now_ms > self.reconnect_until_ms:
                raise SessionTransitionConditionError("session reconnect grace has expired")
            return replace(
                self,
                state=target,
                token_epoch=next_token_epoch,
                last_seen_at_ms=now_ms,
                disconnected_at_ms=None,
            )
        if target is SessionState.DISCONNECTED:
            if reconnect_grace_ms is None or reconnect_grace_ms <= 0:
                raise ValueError("disconnect requires a positive reconnect grace")
            return replace(
                self,
                state=target,
                token_epoch=next_token_epoch,
                disconnected_at_ms=now_ms,
                reconnect_until_ms=min(
                    self.absolute_expires_at_ms,
                    now_ms + reconnect_grace_ms,
                ),
            )
        if target is SessionState.REVOKED:
            return replace(
                self,
                state=target,
                token_epoch=next_token_epoch,
                revoked_at_ms=now_ms,
                revocation_epoch=self.revocation_epoch + 1,
            )
        return replace(self, state=target, token_epoch=next_token_epoch)

    def touch(self, *, now_ms: int, token_epoch: int | None = None) -> SessionRecord:
        if self.state is not SessionState.ACTIVE:
            raise SessionTransitionConditionError("only an active session can be touched")
        if now_ms >= self.absolute_expires_at_ms:
            raise SessionTransitionConditionError("session has reached absolute expiry")
        if token_epoch is not None and token_epoch < self.token_epoch:
            raise ValueError("token epoch cannot move backwards")
        return replace(
            self,
            last_seen_at_ms=now_ms,
            token_epoch=self.token_epoch if token_epoch is None else token_epoch,
        )


@dataclass(frozen=True, slots=True)
class RootRunRecord:
    root_run_id: str
    session_id: str
    state: RootRunState
    started_at_ms: int
    ended_at_ms: int | None = None
    budget: Mapping[str, int] = field(default_factory=dict)
    consumed: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.root_run_id or not self.session_id:
            raise ValueError("root-run and session identifiers are required")
        if any(value < 0 for value in (*self.budget.values(), *self.consumed.values())):
            raise ValueError("root-run accounting values must be non-negative")
        for unit, consumed in self.consumed.items():
            maximum = self.budget.get(unit)
            if maximum is not None and consumed > maximum:
                raise ValueError(f"consumed {unit} exceeds the root-run budget")
        object.__setattr__(self, "budget", MappingProxyType(dict(self.budget)))
        object.__setattr__(self, "consumed", MappingProxyType(dict(self.consumed)))

    def transition(self, target: RootRunState, *, now_ms: int) -> RootRunRecord:
        if self.state is not RootRunState.ACTIVE:
            raise InvalidRootRunTransition("a terminal root run cannot transition")
        if target not in {RootRunState.COMPLETED, RootRunState.CANCELLED}:
            raise InvalidRootRunTransition(f"cannot transition root run to {target}")
        return replace(self, state=target, ended_at_ms=now_ms)
