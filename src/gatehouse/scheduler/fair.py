"""A bounded weighted deficit round-robin scheduler.

The scheduler creates no worker or expiry task.  Callers enqueue bounded records,
await the returned ticket, release permits, and run one shared expiry pump from the
daemon.  This keeps task creation under the daemon's control rather than creating one
background task for every request.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict, defaultdict, deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class SchedulerError(RuntimeError):
    pass


class QueueCapacityExceeded(SchedulerError):
    pass


class QuotaScopeSaturated(SchedulerError):
    pass


class QueueExpired(SchedulerError):
    pass


class RequestCancelled(SchedulerError):
    pass


class DuplicateRequest(SchedulerError):
    pass


class UnknownService(SchedulerError):
    pass


class UnknownClient(QueueCapacityExceeded):
    pass


class PriorityClass(StrEnum):
    SYSTEM_RESERVED = "SYSTEM_RESERVED"
    INTERACTIVE = "INTERACTIVE"
    NORMAL_AGENT = "NORMAL_AGENT"
    BACKGROUND = "BACKGROUND"
    MAINTENANCE = "MAINTENANCE"


DEFAULT_WEIGHTS: Mapping[PriorityClass, int] = MappingProxyType(
    {
        PriorityClass.SYSTEM_RESERVED: 8,
        PriorityClass.INTERACTIVE: 6,
        PriorityClass.NORMAL_AGENT: 4,
        PriorityClass.BACKGROUND: 2,
        PriorityClass.MAINTENANCE: 1,
    }
)


@dataclass(frozen=True, slots=True)
class ServiceLimits:
    maximum_in_flight: int
    maximum_queued: int
    reserved_system_in_flight: int = 0
    reserved_system_queue: int = 0
    maximum_per_quota_scope: int = 2_147_483_647

    def __post_init__(self) -> None:
        if self.maximum_in_flight <= 0 or self.maximum_queued <= 0:
            raise ValueError("service limits must be positive")
        if not 0 <= self.reserved_system_in_flight <= self.maximum_in_flight:
            raise ValueError("invalid reserved service in-flight capacity")
        if not 0 <= self.reserved_system_queue <= self.maximum_queued:
            raise ValueError("invalid reserved service queue capacity")
        if self.maximum_per_quota_scope <= 0:
            raise ValueError("quota-scope in-flight capacity must be positive")


@dataclass(frozen=True, slots=True)
class ClientCapacityLimits:
    maximum_in_flight: int
    maximum_queued: int

    def __post_init__(self) -> None:
        if self.maximum_in_flight <= 0 or self.maximum_queued <= 0:
            raise ValueError("client capacity limits must be positive")


@dataclass(frozen=True, slots=True)
class SchedulerLimits:
    global_maximum_in_flight: int
    global_maximum_queued: int
    per_session_maximum_in_flight: int
    per_session_maximum_queued: int
    services: Mapping[str, ServiceLimits]
    clients: Mapping[str, ClientCapacityLimits]
    reserved_system_in_flight: int = 0
    reserved_system_queue: int = 0
    maximum_work_cost: int = 64

    def __post_init__(self) -> None:
        if (
            min(
                self.global_maximum_in_flight,
                self.global_maximum_queued,
                self.per_session_maximum_in_flight,
                self.per_session_maximum_queued,
                self.maximum_work_cost,
            )
            <= 0
        ):
            raise ValueError("scheduler limits must be positive")
        if not 0 <= self.reserved_system_in_flight <= self.global_maximum_in_flight:
            raise ValueError("invalid reserved global in-flight capacity")
        if not 0 <= self.reserved_system_queue <= self.global_maximum_queued:
            raise ValueError("invalid reserved global queue capacity")
        if not self.services:
            raise ValueError("at least one service must be configured")
        if not self.clients or any(not client_id for client_id in self.clients):
            raise ValueError("at least one bounded client profile must be configured")
        object.__setattr__(self, "services", MappingProxyType(dict(self.services)))
        object.__setattr__(self, "clients", MappingProxyType(dict(self.clients)))


@dataclass(frozen=True, slots=True)
class WorkItem:
    request_id: str
    session_id: str
    client_id: str
    service_id: str
    priority: PriorityClass
    enqueued_at_ms: int
    deadline_ms: int
    cost: int = 1
    quota_scope_id: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.request_id or not self.session_id or not self.client_id or not self.service_id:
            raise ValueError("request, session, client, and service identifiers are required")
        if self.deadline_ms <= self.enqueued_at_ms:
            raise ValueError("queue deadline must follow enqueue time")
        if self.cost <= 0:
            raise ValueError("work cost must be positive")
        if self.quota_scope_id is not None and not self.quota_scope_id:
            raise ValueError("quota scope identifier cannot be blank")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def system_reserved(self) -> bool:
        return self.priority is PriorityClass.SYSTEM_RESERVED


@dataclass(frozen=True, slots=True)
class DispatchPermit:
    dispatch_id: int
    request_id: str
    session_id: str
    client_id: str
    service_id: str
    quota_scope_id: str | None
    priority: PriorityClass
    dispatched_at_ms: int
    cancel_event: asyncio.Event


@dataclass(frozen=True, slots=True)
class _QueueFailure:
    error: SchedulerError


@dataclass(slots=True)
class _TicketClaim:
    wait_started: bool = False


@dataclass(frozen=True, slots=True)
class QueueTicket:
    request_id: str
    deadline_ms: int
    _future: asyncio.Future[DispatchPermit | _QueueFailure]
    _now_ms: Callable[[], int]
    _surrender: Callable[
        [str, asyncio.Future[DispatchPermit | _QueueFailure], _QueueFailure],
        Awaitable[None],
    ]
    _claim: _TicketClaim = field(default_factory=_TicketClaim, repr=False, compare=False)

    @property
    def ready(self) -> bool:
        return self._future.done()

    async def wait(self) -> DispatchPermit:
        if self._claim.wait_started:
            raise RuntimeError("a queue ticket can only be awaited once")
        self._claim.wait_started = True
        remaining_ms = self.deadline_ms - self._now_ms()
        if remaining_ms <= 0:
            failure = _QueueFailure(QueueExpired("queue deadline expired"))
            await asyncio.shield(self._surrender(self.request_id, self._future, failure))
            raise failure.error
        try:
            result = await asyncio.wait_for(
                asyncio.shield(self._future),
                timeout=remaining_ms / 1_000,
            )
        except TimeoutError:
            failure = _QueueFailure(QueueExpired("queue deadline expired"))
            await asyncio.shield(self._surrender(self.request_id, self._future, failure))
            raise failure.error from None
        except asyncio.CancelledError:
            # Shielding keeps shared scheduler state out of the caller's cancellation
            # scope. Explicitly surrender the ticket so a cancelled waiter cannot
            # occupy queue or in-flight capacity that it will never release.
            await asyncio.shield(
                self._surrender(
                    self.request_id,
                    self._future,
                    _QueueFailure(RequestCancelled("queue waiter was cancelled")),
                )
            )
            raise
        if isinstance(result, _QueueFailure):
            raise result.error
        return result


class CancellationResult(StrEnum):
    NOT_FOUND = "NOT_FOUND"
    QUEUED_CANCELLED = "QUEUED_CANCELLED"
    RUNNING_SIGNALLED = "RUNNING_SIGNALLED"


@dataclass(frozen=True, slots=True)
class SchedulerSnapshot:
    queued_total: int
    running_total: int
    queued_by_service: Mapping[str, int]
    running_by_service: Mapping[str, int]
    running_by_quota_scope: Mapping[str, int]
    queued_by_session: Mapping[str, int]
    running_by_session: Mapping[str, int]
    queued_by_client: Mapping[str, int]
    running_by_client: Mapping[str, int]


@dataclass(slots=True)
class _Entry:
    item: WorkItem
    future: asyncio.Future[DispatchPermit | _QueueFailure]
    reject_quota_scope_saturation: bool = False


class BoundedFairScheduler:
    """Bounded WDRR across priority classes and round-robin within each session."""

    def __init__(
        self,
        *,
        limits: SchedulerLimits,
        now_ms: Callable[[], int],
        weights: Mapping[PriorityClass, int] = DEFAULT_WEIGHTS,
    ) -> None:
        if set(weights) != set(PriorityClass):
            raise ValueError("a positive weight is required for every priority class")
        if any(weight <= 0 for weight in weights.values()):
            raise ValueError("scheduler weights must be positive")
        self.limits = limits
        self._now_ms = now_ms
        self._weights = dict(weights)
        self._lock = asyncio.Lock()
        self._entries: dict[str, _Entry] = {}
        self._running: dict[str, DispatchPermit] = {}
        self._queues: dict[PriorityClass, OrderedDict[str, deque[str]]] = {
            priority: OrderedDict() for priority in PriorityClass
        }
        self._session_rotation: dict[PriorityClass, deque[str]] = {
            priority: deque() for priority in PriorityClass
        }
        self._class_order = tuple(PriorityClass)
        self._class_cursor = 0
        self._deficit = {priority: 0 for priority in PriorityClass}
        self._needs_quantum = {priority: True for priority in PriorityClass}
        self._dispatch_sequence = 0

        self._queued_by_service: defaultdict[str, int] = defaultdict(int)
        self._queued_by_session: defaultdict[str, int] = defaultdict(int)
        self._queued_by_client: defaultdict[str, int] = defaultdict(int)
        self._queued_non_system = 0
        self._queued_non_system_by_service: defaultdict[str, int] = defaultdict(int)
        self._running_by_service: defaultdict[str, int] = defaultdict(int)
        self._running_by_quota_scope: defaultdict[tuple[str, str], int] = defaultdict(int)
        self._running_by_session: defaultdict[str, int] = defaultdict(int)
        self._running_by_client: defaultdict[str, int] = defaultdict(int)
        self._running_non_system = 0
        self._running_system = 0
        self._running_non_system_by_service: defaultdict[str, int] = defaultdict(int)
        self._running_system_by_service: defaultdict[str, int] = defaultdict(int)

    async def enqueue(self, item: WorkItem) -> QueueTicket:
        return await self._enqueue(item, reject_quota_scope_saturation=False)

    async def enqueue_unless_quota_scope_saturated(self, item: WorkItem) -> QueueTicket:
        """Enqueue atomically, or reject a queued item whose quota scope is saturated."""

        return await self._enqueue(item, reject_quota_scope_saturation=True)

    async def _enqueue(
        self,
        item: WorkItem,
        *,
        reject_quota_scope_saturation: bool,
    ) -> QueueTicket:
        if item.cost > self.limits.maximum_work_cost:
            raise ValueError("work cost exceeds the configured scheduler bound")
        async with self._lock:
            now = self._now_ms()
            self._expire_locked(now)
            if item.request_id in self._entries or item.request_id in self._running:
                raise DuplicateRequest("request is already queued or running")
            if item.deadline_ms <= now:
                raise QueueExpired("queue deadline has expired")
            service_limits = self.limits.services.get(item.service_id)
            if service_limits is None:
                raise UnknownService(item.service_id)
            if item.client_id not in self.limits.clients:
                raise UnknownClient(item.client_id)
            if reject_quota_scope_saturation and self._quota_scope_saturated(item):
                raise QuotaScopeSaturated("quota-scope in-flight capacity is exhausted")
            self._assert_queue_capacity(item, service_limits)

            future: asyncio.Future[DispatchPermit | _QueueFailure] = (
                asyncio.get_running_loop().create_future()
            )
            entry = _Entry(
                item=item,
                future=future,
                reject_quota_scope_saturation=reject_quota_scope_saturation,
            )
            self._entries[item.request_id] = entry
            session_queues = self._queues[item.priority]
            if item.session_id not in session_queues:
                session_queues[item.session_id] = deque()
                self._session_rotation[item.priority].append(item.session_id)
            session_queues[item.session_id].append(item.request_id)
            self._increment_queue_counts(item)
            self._pump_locked(now)
            if future.done():
                outcome = future.result()
                if isinstance(outcome, _QueueFailure) and isinstance(
                    outcome.error, QuotaScopeSaturated
                ):
                    raise outcome.error
            return QueueTicket(
                item.request_id,
                item.deadline_ms,
                future,
                self._now_ms,
                self._surrender_ticket,
            )

    async def pump(self) -> int:
        """Expire stale entries and dispatch every currently eligible request."""

        async with self._lock:
            before = len(self._running)
            now = self._now_ms()
            self._expire_locked(now)
            self._pump_locked(now)
            return len(self._running) - before

    async def release(self, permit: DispatchPermit) -> bool:
        async with self._lock:
            current = self._running.get(permit.request_id)
            if current is None or current.dispatch_id != permit.dispatch_id:
                return False
            self._running.pop(permit.request_id)
            self._decrement_running_counts(current)
            now = self._now_ms()
            self._expire_locked(now)
            self._pump_locked(now)
            return True

    async def cancel(self, request_id: str) -> CancellationResult:
        async with self._lock:
            entry = self._entries.get(request_id)
            if entry is not None:
                self._remove_queued_locked(
                    entry,
                    _QueueFailure(RequestCancelled("queued request was cancelled")),
                )
                now = self._now_ms()
                self._expire_locked(now)
                self._pump_locked(now)
                return CancellationResult.QUEUED_CANCELLED
            permit = self._running.get(request_id)
            if permit is not None:
                permit.cancel_event.set()
                return CancellationResult.RUNNING_SIGNALLED
            return CancellationResult.NOT_FOUND

    async def cancel_session(self, session_id: str) -> tuple[int, int]:
        """Cancel queued requests and signal running requests for one session."""

        async with self._lock:
            queued = [
                entry for entry in self._entries.values() if entry.item.session_id == session_id
            ]
            for entry in queued:
                self._remove_queued_locked(
                    entry,
                    _QueueFailure(RequestCancelled("session was cancelled")),
                )
            running = [
                permit for permit in self._running.values() if permit.session_id == session_id
            ]
            for permit in running:
                permit.cancel_event.set()
            now = self._now_ms()
            self._expire_locked(now)
            self._pump_locked(now)
            return len(queued), len(running)

    async def _surrender_ticket(
        self,
        request_id: str,
        future: asyncio.Future[DispatchPermit | _QueueFailure],
        failure: _QueueFailure,
    ) -> None:
        """Reclaim a ticket whose waiter was cancelled before taking ownership."""

        async with self._lock:
            entry = self._entries.get(request_id)
            if entry is not None and entry.future is future:
                self._remove_queued_locked(
                    entry,
                    failure,
                )
                now = self._now_ms()
                self._expire_locked(now)
                self._pump_locked(now)
                return
            if not future.done():
                return
            outcome = future.result()
            if isinstance(outcome, _QueueFailure):
                return
            permit = self._running.get(request_id)
            if permit is None or permit.dispatch_id != outcome.dispatch_id:
                return
            self._running.pop(request_id)
            permit.cancel_event.set()
            self._decrement_running_counts(permit)
            now = self._now_ms()
            self._expire_locked(now)
            self._pump_locked(now)

    async def snapshot(self) -> SchedulerSnapshot:
        async with self._lock:
            return SchedulerSnapshot(
                queued_total=len(self._entries),
                running_total=len(self._running),
                queued_by_service=MappingProxyType(dict(self._queued_by_service)),
                running_by_service=MappingProxyType(dict(self._running_by_service)),
                running_by_quota_scope=MappingProxyType(
                    {
                        f"{service_id}:{scope_id}": count
                        for (service_id, scope_id), count in self._running_by_quota_scope.items()
                    }
                ),
                queued_by_session=MappingProxyType(dict(self._queued_by_session)),
                running_by_session=MappingProxyType(dict(self._running_by_session)),
                queued_by_client=MappingProxyType(dict(self._queued_by_client)),
                running_by_client=MappingProxyType(dict(self._running_by_client)),
            )

    def _assert_queue_capacity(
        self,
        item: WorkItem,
        service_limits: ServiceLimits,
    ) -> None:
        if len(self._entries) >= self.limits.global_maximum_queued:
            raise QueueCapacityExceeded("global queue capacity is exhausted")
        if self._queued_by_session[item.session_id] >= self.limits.per_session_maximum_queued:
            raise QueueCapacityExceeded("session queue capacity is exhausted")
        client_limits = self.limits.clients[item.client_id]
        if self._queued_by_client[item.client_id] >= client_limits.maximum_queued:
            raise QueueCapacityExceeded("client profile queue capacity is exhausted")
        if self._queued_by_service[item.service_id] >= service_limits.maximum_queued:
            raise QueueCapacityExceeded("service queue capacity is exhausted")
        if not item.system_reserved:
            ordinary_global = self.limits.global_maximum_queued - self.limits.reserved_system_queue
            ordinary_service = service_limits.maximum_queued - service_limits.reserved_system_queue
            if self._queued_non_system >= ordinary_global:
                raise QueueCapacityExceeded("reserved system queue capacity is protected")
            if self._queued_non_system_by_service[item.service_id] >= ordinary_service:
                raise QueueCapacityExceeded("reserved service queue capacity is protected")

    def _increment_queue_counts(self, item: WorkItem) -> None:
        self._queued_by_service[item.service_id] += 1
        self._queued_by_session[item.session_id] += 1
        self._queued_by_client[item.client_id] += 1
        if not item.system_reserved:
            self._queued_non_system += 1
            self._queued_non_system_by_service[item.service_id] += 1

    def _decrement_queue_counts(self, item: WorkItem) -> None:
        self._queued_by_service[item.service_id] -= 1
        self._queued_by_session[item.session_id] -= 1
        self._queued_by_client[item.client_id] -= 1
        if not item.system_reserved:
            self._queued_non_system -= 1
            self._queued_non_system_by_service[item.service_id] -= 1

    def _increment_running_counts(self, permit: DispatchPermit) -> None:
        self._running_by_service[permit.service_id] += 1
        self._running_by_session[permit.session_id] += 1
        self._running_by_client[permit.client_id] += 1
        if permit.quota_scope_id is not None:
            self._running_by_quota_scope[(permit.service_id, permit.quota_scope_id)] += 1
        if permit.priority is PriorityClass.SYSTEM_RESERVED:
            self._running_system += 1
            self._running_system_by_service[permit.service_id] += 1
        else:
            self._running_non_system += 1
            self._running_non_system_by_service[permit.service_id] += 1

    def _decrement_running_counts(self, permit: DispatchPermit) -> None:
        self._running_by_service[permit.service_id] -= 1
        self._running_by_session[permit.session_id] -= 1
        self._running_by_client[permit.client_id] -= 1
        if permit.quota_scope_id is not None:
            quota_scope_key = (permit.service_id, permit.quota_scope_id)
            self._running_by_quota_scope[quota_scope_key] -= 1
            if self._running_by_quota_scope[quota_scope_key] == 0:
                del self._running_by_quota_scope[quota_scope_key]
        if permit.priority is PriorityClass.SYSTEM_RESERVED:
            self._running_system -= 1
            self._running_system_by_service[permit.service_id] -= 1
        else:
            self._running_non_system -= 1
            self._running_non_system_by_service[permit.service_id] -= 1

    def _eligible(self, item: WorkItem) -> bool:
        service = self.limits.services[item.service_id]
        if len(self._running) >= self.limits.global_maximum_in_flight:
            return False
        if self._running_by_service[item.service_id] >= service.maximum_in_flight:
            return False
        if (
            item.quota_scope_id is not None
            and self._running_by_quota_scope.get((item.service_id, item.quota_scope_id), 0)
            >= service.maximum_per_quota_scope
        ):
            return False
        if self._running_by_session[item.session_id] >= self.limits.per_session_maximum_in_flight:
            return False
        if (
            self._running_by_client[item.client_id]
            >= self.limits.clients[item.client_id].maximum_in_flight
        ):
            return False
        if item.system_reserved:
            return True

        remaining_global_reserve = max(
            0,
            self.limits.reserved_system_in_flight - self._running_system,
        )
        non_system_global_cap = self.limits.global_maximum_in_flight - remaining_global_reserve
        if self._running_non_system >= non_system_global_cap:
            return False
        remaining_service_reserve = max(
            0,
            service.reserved_system_in_flight - self._running_system_by_service[item.service_id],
        )
        non_system_service_cap = service.maximum_in_flight - remaining_service_reserve
        return self._running_non_system_by_service[item.service_id] < non_system_service_cap

    def _quota_scope_saturated(self, item: WorkItem) -> bool:
        if item.quota_scope_id is None:
            return False
        service = self.limits.services[item.service_id]
        return (
            self._running_by_quota_scope.get((item.service_id, item.quota_scope_id), 0)
            >= service.maximum_per_quota_scope
        )

    def _pump_locked(self, now_ms: int) -> None:
        while True:
            while self._entries and len(self._running) < self.limits.global_maximum_in_flight:
                entry = self._select_next_locked()
                if entry is None:
                    break
                item = entry.item
                self._remove_from_queue_structures(item)
                self._entries.pop(item.request_id, None)
                self._decrement_queue_counts(item)
                self._dispatch_sequence += 1
                permit = DispatchPermit(
                    dispatch_id=self._dispatch_sequence,
                    request_id=item.request_id,
                    session_id=item.session_id,
                    client_id=item.client_id,
                    service_id=item.service_id,
                    quota_scope_id=item.quota_scope_id,
                    priority=item.priority,
                    dispatched_at_ms=now_ms,
                    cancel_event=asyncio.Event(),
                )
                self._running[item.request_id] = permit
                self._increment_running_counts(permit)
                if not entry.future.done():
                    entry.future.set_result(permit)
            saturated = [
                entry
                for entry in self._entries.values()
                if entry.reject_quota_scope_saturation and self._quota_scope_saturated(entry.item)
            ]
            if not saturated:
                return
            for entry in saturated:
                self._remove_queued_locked(
                    entry,
                    _QueueFailure(
                        QuotaScopeSaturated("quota-scope in-flight capacity is exhausted")
                    ),
                )

    def _select_next_locked(self) -> _Entry | None:
        maximum_visits = len(self._class_order) * (self.limits.maximum_work_cost + 1)
        for _ in range(maximum_visits):
            priority = self._class_order[self._class_cursor]
            session_queues = self._queues[priority]
            if not session_queues:
                self._deficit[priority] = 0
                self._needs_quantum[priority] = True
                self._advance_class()
                continue
            if self._needs_quantum[priority]:
                self._deficit[priority] = min(
                    self.limits.maximum_work_cost,
                    self._deficit[priority] + self._weights[priority],
                )
                self._needs_quantum[priority] = False

            candidate = self._candidate_for_class(priority)
            if candidate is not None:
                self._deficit[priority] -= candidate.item.cost
                if self._deficit[priority] <= 0:
                    self._deficit[priority] = 0
                    self._needs_quantum[priority] = True
                    self._advance_class()
                return candidate

            # Either the next cost needs another quantum or every item is blocked by
            # a concurrency cap. Moving classes prevents a blocked service/session
            # from stalling unrelated work.
            self._needs_quantum[priority] = True
            self._advance_class()
        return None

    def _candidate_for_class(self, priority: PriorityClass) -> _Entry | None:
        rotation = self._session_rotation[priority]
        queues = self._queues[priority]
        for _ in range(len(rotation)):
            session_id = rotation.popleft()
            request_ids = queues.get(session_id)
            if not request_ids:
                queues.pop(session_id, None)
                continue

            while request_ids and request_ids[0] not in self._entries:
                request_ids.popleft()
            if not request_ids:
                queues.pop(session_id, None)
                continue

            entry = self._entries[request_ids[0]]
            rotation.append(session_id)
            if entry.item.cost <= self._deficit[priority] and self._eligible(entry.item):
                return entry
        return None

    def _advance_class(self) -> None:
        self._class_cursor = (self._class_cursor + 1) % len(self._class_order)

    def _remove_from_queue_structures(self, item: WorkItem) -> None:
        session_queue = self._queues[item.priority].get(item.session_id)
        if session_queue is None:
            return
        try:
            session_queue.remove(item.request_id)
        except ValueError:
            pass
        if session_queue:
            return
        self._queues[item.priority].pop(item.session_id, None)
        rotation = self._session_rotation[item.priority]
        try:
            rotation.remove(item.session_id)
        except ValueError:
            pass

    def _remove_queued_locked(
        self,
        entry: _Entry,
        outcome: _QueueFailure,
    ) -> None:
        item = entry.item
        if self._entries.pop(item.request_id, None) is None:
            return
        self._remove_from_queue_structures(item)
        self._decrement_queue_counts(item)
        if not entry.future.done():
            entry.future.set_result(outcome)

    def _expire_locked(self, now_ms: int) -> None:
        expired = [entry for entry in self._entries.values() if entry.item.deadline_ms <= now_ms]
        for entry in expired:
            self._remove_queued_locked(
                entry,
                _QueueFailure(QueueExpired("queue deadline expired")),
            )
