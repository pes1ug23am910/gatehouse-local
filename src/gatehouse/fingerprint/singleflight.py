"""Bounded same-session single-flight groups with explicit cancellation ownership."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .hmac import RequestFingerprint


class SingleFlightError(RuntimeError):
    pass


class SingleFlightCapacityExceeded(SingleFlightError):
    pass


class SingleFlightRole(StrEnum):
    LEADER = "LEADER"
    WAITER = "WAITER"


@dataclass(frozen=True, slots=True)
class CancellationDecision:
    detached: bool
    cancel_underlying: bool
    promoted_request_id: str | None = None


@dataclass(frozen=True, slots=True)
class _Outcome:
    value: Any = None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class SingleFlightHandle:
    group_id: int
    request_id: str
    original_request_id: str
    role: SingleFlightRole
    _future: asyncio.Future[_Outcome]

    async def wait(self) -> Any:
        outcome = await asyncio.shield(self._future)
        if outcome.error is not None:
            raise outcome.error
        return outcome.value


@dataclass(slots=True)
class _Participant:
    role: SingleFlightRole
    future: asyncio.Future[_Outcome]


@dataclass(slots=True)
class _Group:
    group_id: int
    key: tuple[object, ...]
    original_request_id: str
    execution_owner_id: str
    participants: OrderedDict[str, _Participant]


class SingleFlightCoordinator:
    """Coordinate one execution without spawning an execution task itself.

    By default the group key always includes the session.  Cross-session sharing must
    be explicitly enabled and supply an identical non-empty sharing scope; it remains
    disabled in Gatehouse v1 until its authorization/cancellation model is integrated.
    """

    def __init__(
        self,
        *,
        maximum_groups: int = 300,
        maximum_waiters_per_group: int = 64,
        allow_cross_session: bool = False,
    ) -> None:
        if min(maximum_groups, maximum_waiters_per_group) <= 0:
            raise ValueError("single-flight bounds must be positive")
        self.maximum_groups = maximum_groups
        self.maximum_waiters_per_group = maximum_waiters_per_group
        self.allow_cross_session = allow_cross_session
        self._lock = asyncio.Lock()
        self._groups_by_key: dict[tuple[object, ...], _Group] = {}
        self._groups_by_id: dict[int, _Group] = {}
        self._next_group_id = 1

    def _key(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        sharing_scope: str | None,
    ) -> tuple[object, ...]:
        if self.allow_cross_session:
            if not sharing_scope:
                raise ValueError("cross-session single-flight requires a sharing scope")
            scope: object = ("shared", sharing_scope)
        else:
            scope = ("session", session_id)
        return (scope, *fingerprint.key)

    async def join_or_create(
        self,
        *,
        session_id: str,
        request_id: str,
        fingerprint: RequestFingerprint,
        sharing_scope: str | None = None,
    ) -> SingleFlightHandle:
        if not session_id or not request_id:
            raise ValueError("session_id and request_id are required")
        key = self._key(
            session_id=session_id,
            fingerprint=fingerprint,
            sharing_scope=sharing_scope,
        )
        async with self._lock:
            group = self._groups_by_key.get(key)
            if group is not None:
                if request_id in group.participants:
                    raise ValueError("request is already attached to the single-flight group")
                waiter_count = len(group.participants) - 1
                if waiter_count >= self.maximum_waiters_per_group:
                    raise SingleFlightCapacityExceeded("single-flight waiter capacity exceeded")
                waiter_future: asyncio.Future[_Outcome] = asyncio.get_running_loop().create_future()
                group.participants[request_id] = _Participant(
                    role=SingleFlightRole.WAITER,
                    future=waiter_future,
                )
                return SingleFlightHandle(
                    group_id=group.group_id,
                    request_id=request_id,
                    original_request_id=group.original_request_id,
                    role=SingleFlightRole.WAITER,
                    _future=waiter_future,
                )

            if len(self._groups_by_key) >= self.maximum_groups:
                raise SingleFlightCapacityExceeded("single-flight group capacity exceeded")
            loop = asyncio.get_running_loop()
            group_id = self._next_group_id
            self._next_group_id += 1
            leader_future: asyncio.Future[_Outcome] = loop.create_future()
            group = _Group(
                group_id=group_id,
                key=key,
                original_request_id=request_id,
                execution_owner_id=request_id,
                participants=OrderedDict(
                    [
                        (
                            request_id,
                            _Participant(
                                role=SingleFlightRole.LEADER,
                                future=leader_future,
                            ),
                        )
                    ]
                ),
            )
            self._groups_by_key[key] = group
            self._groups_by_id[group_id] = group
            return SingleFlightHandle(
                group_id=group_id,
                request_id=request_id,
                original_request_id=request_id,
                role=SingleFlightRole.LEADER,
                _future=leader_future,
            )

    async def complete(self, group_id: int, value: Any) -> bool:
        return await self._finish(group_id, _Outcome(value=value))

    async def fail(self, group_id: int, error: BaseException) -> bool:
        return await self._finish(group_id, _Outcome(error=error))

    async def _finish(self, group_id: int, outcome: _Outcome) -> bool:
        async with self._lock:
            group = self._groups_by_id.pop(group_id, None)
            if group is None:
                return False
            self._groups_by_key.pop(group.key, None)
            for participant in group.participants.values():
                if not participant.future.done():
                    participant.future.set_result(outcome)
            return True

    async def cancel(self, handle: SingleFlightHandle) -> CancellationDecision:
        async with self._lock:
            group = self._groups_by_id.get(handle.group_id)
            if group is None or handle.request_id not in group.participants:
                return CancellationDecision(detached=False, cancel_underlying=False)
            participant = group.participants.pop(handle.request_id)
            if not participant.future.done():
                participant.future.set_result(_Outcome(error=asyncio.CancelledError()))
            if not group.participants:
                self._groups_by_id.pop(group.group_id, None)
                self._groups_by_key.pop(group.key, None)
                return CancellationDecision(detached=True, cancel_underlying=True)

            promoted: str | None = None
            if handle.request_id == group.execution_owner_id:
                promoted = next(iter(group.participants))
                group.execution_owner_id = promoted
                group.participants[promoted].role = SingleFlightRole.LEADER
            return CancellationDecision(
                detached=True,
                cancel_underlying=False,
                promoted_request_id=promoted,
            )

    @property
    def active_groups(self) -> int:
        return len(self._groups_by_id)
