"""Ordered, protocol-driven invocation orchestration with bounded failover."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from functools import partial

from gatehouse.core.clock import UtcMsClock, datetime_from_utc_ms
from gatehouse.core.errors import ErrorCode, ErrorDetail, make_error
from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.core.states import INVOCATION_TRANSITIONS, ApprovalState, InvocationState
from gatehouse.credentials.emergency import (
    EmergencyRequestPermit,
    EmergencyUnlockError,
    EmergencyUnlockManager,
    EmergencyUnlockProjection,
    EmergencyUnlockState,
)
from gatehouse.fingerprint.canonical import CanonicalizationError, canonical_json_bytes
from gatehouse.fingerprint.runaway import RunawayDecision, RunawayDetector
from gatehouse.fingerprint.singleflight import (
    SingleFlightCapacityExceeded,
    SingleFlightCoordinator,
    SingleFlightHandle,
    SingleFlightRole,
)
from gatehouse.policy import Decision, PolicyContext, PolicyResult
from gatehouse.policy.targets import TargetValidationError
from gatehouse.providers import CredentialCustodyKind, ProviderErrorClass, ProviderResponse
from gatehouse.providers.transport import (
    ProviderNetworkDisabledError,
    ProviderPreHandoffError,
)
from gatehouse.routing import (
    AffinityUnavailableError,
    BreakerKey,
    BreakerScopeType,
    CircuitBreakerPermit,
    CircuitBreakerRegistry,
    CredentialDispatchLease,
    CredentialLeaseUnavailableError,
    NoEligibleCredentialError,
    NoEligiblePoolError,
    QuotaReservation,
    QuotaScopeSnapshot,
    QuotaUnavailableError,
    ReservationGrant,
    ResourceAffinity,
    ResourceAffinityStore,
    RetryAction,
    RetryPolicy,
    RouteCandidate,
    RoutingCredential,
    RoutingPlan,
)
from gatehouse.scheduler import (
    DispatchPermit,
    QueueCapacityExceeded,
    QueueExpired,
    RequestCancelled,
    WorkItem,
)

from .budget import BudgetUnavailableError
from .contracts import (
    ApprovalGateway,
    BudgetGateway,
    CredentialLeaseGateway,
    FingerprintGateway,
    InvocationRepository,
    OperationGateway,
    PolicyGateway,
    ProviderTransport,
    QuotaGateway,
    RoutingGateway,
    RunawayGateway,
    SchedulerGateway,
    SensitiveInspector,
    SessionGateway,
    SingleFlightGateway,
)
from .models import (
    AttemptEvent,
    BudgetReservation,
    CanonicalOperation,
    ClassifiedProviderOutcome,
    InvocationRequest,
    InvocationResult,
    InvocationSession,
    InvocationStartEvent,
    InvocationStateEvent,
    InvocationValidatedEvent,
)
from .persistence import InvocationRequestLimitExceeded

_INTERNAL_RESOURCE_RECONCILIATION_OPERATIONS = frozenset(
    {"firecrawl.crawl.status", "firecrawl.crawl.cancel"}
)


class TransactionBoundaryError(RuntimeError):
    """A provider dispatch was attempted while persistence reported a transaction."""


@dataclass(slots=True)
class _ExecutionOwnership:
    reservation: QuotaReservation | None
    budget: BudgetReservation | None
    emergency_permit: EmergencyRequestPermit | None = None
    permit: DispatchPermit | None = None
    lease: CredentialDispatchLease | None = None
    breaker_permit: CircuitBreakerPermit | None = None
    outcome: ClassifiedProviderOutcome | None = None
    quota_resolved: bool = False
    budget_resolved: bool = False
    emergency_resolved: bool = False
    submission_may_have_occurred: bool = False
    defer_success_accounting: bool = False
    attempts: int = 0


class _StateTracker:
    def __init__(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        repository: InvocationRepository,
        clock: UtcMsClock,
    ) -> None:
        self.request = request
        self.session = session
        self.repository = repository
        self.clock = clock
        self.current = InvocationState.RECEIVED

    async def start(self) -> None:
        await self.repository.begin_invocation(
            InvocationStartEvent(
                request_id=self.request.request_id,
                session_id=self.session.session_id,
                root_run_id=self.session.root_run_id,
                service_id=self.request.service_id,
                operation=self.request.operation,
                priority=self.session.priority,
                queue_deadline_ms=self.request.queue_deadline_ms,
                occurred_at_ms=self.clock.now_ms(),
                request_limit=self.session.request_limit,
                internal_resource_reconciliation=(self.session.internal_resource_reconciliation),
            )
        )

    async def transition(
        self,
        target: InvocationState,
        *,
        metadata: Mapping[str, str | int | bool] | None = None,
    ) -> None:
        INVOCATION_TRANSITIONS.require(self.current, target)
        await self.repository.record_state(
            InvocationStateEvent(
                request_id=self.request.request_id,
                state=target,
                occurred_at_ms=self.clock.now_ms(),
                metadata=metadata or {},
            )
        )
        self.current = target


class InvocationCoordinator:
    """Execute one logical call without owning any concrete external integration."""

    def __init__(
        self,
        *,
        clock: UtcMsClock,
        sessions: SessionGateway,
        operations: OperationGateway,
        fingerprints: FingerprintGateway,
        sensitive: SensitiveInspector,
        policy: PolicyGateway,
        approvals: ApprovalGateway,
        budgets: BudgetGateway,
        router: RoutingGateway,
        quota: QuotaGateway,
        scheduler: SchedulerGateway,
        credential_leases: CredentialLeaseGateway,
        repository: InvocationRepository,
        transport: ProviderTransport,
        affinities: ResourceAffinityStore,
        circuit_breakers: CircuitBreakerRegistry,
        singleflight: SingleFlightGateway | None = None,
        runaway: RunawayGateway | None = None,
        retry_policy: RetryPolicy | None = None,
        emergency: EmergencyUnlockManager | None = None,
        reservation_ttl_ms: int = 900_000,
        credential_lease_ttl_ms: int = 330_000,
        capacity_retry_after_seconds: int = 1,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if (
            min(
                reservation_ttl_ms,
                credential_lease_ttl_ms,
                capacity_retry_after_seconds,
            )
            <= 0
        ):
            raise ValueError("coordinator timing bounds must be positive")
        self.clock = clock
        self.sessions = sessions
        self.operations = operations
        self.fingerprints = fingerprints
        self.sensitive = sensitive
        self.policy = policy
        self.approvals = approvals
        self.budgets = budgets
        self.router = router
        self.quota = quota
        self.scheduler = scheduler
        self.credential_leases = credential_leases
        self.repository = repository
        self.transport = transport
        self.affinities = affinities
        self.circuit_breakers = circuit_breakers
        self.singleflight = singleflight or SingleFlightCoordinator()
        self.runaway = runaway or RunawayDetector()
        self.retry_policy = retry_policy or RetryPolicy()
        self.emergency = emergency
        self.reservation_ttl_ms = reservation_ttl_ms
        self.credential_lease_ttl_ms = credential_lease_ttl_ms
        self.capacity_retry_after_seconds = capacity_retry_after_seconds
        self._sleep = sleeper
        self._singleflight_tasks: dict[int, asyncio.Task[None]] = {}

    async def invoke(self, request: InvocationRequest) -> InvocationResult:
        """Run the fixed admission and dispatch pipeline in security-critical order."""

        if request.access_token is None:
            raise ValueError("unauthenticated invocation requires an access token")
        session = await self.sessions.authenticate(request)
        return await self.invoke_authenticated(request, session)

    async def invoke_authenticated(
        self,
        request: InvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        """Invoke using an already-authenticated, trusted session projection."""

        if session.root_run_id != request.root_run_id:
            raise ValueError("authenticated session did not authorize the root run")
        if session.internal_resource_reconciliation and (
            request.service_id != "firecrawl"
            or request.operation not in _INTERNAL_RESOURCE_RECONCILIATION_OPERATIONS
        ):
            raise ValueError("internal reconciliation is restricted to resource-bound operations")
        tracker = _StateTracker(
            request=request,
            session=session,
            repository=self.repository,
            clock=self.clock,
        )
        try:
            await tracker.start()
        except InvocationRequestLimitExceeded:
            return self._error_result(
                request,
                InvocationState.DENIED,
                ErrorCode.BUDGET_EXHAUSTED,
            )
        await tracker.transition(InvocationState.VALIDATING)

        try:
            validated = self.operations.validate(
                request.service_id,
                request.operation,
                request.input_payload,
            )
            canonical = self.operations.canonicalize(validated)
            canonical_bytes = canonical_json_bytes(canonical.canonical_input)
            if len(canonical_bytes) > canonical.spec.maximum_request_bytes:
                raise ValueError("canonical request exceeds the operation size bound")
            estimated_cost_units = self._integer_cost(canonical.spec.default_estimated_cost)
            fingerprint = self.fingerprints.calculate(
                session=session,
                request=request,
                canonical=canonical,
            )
        except TargetValidationError:
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.INVALID_TARGET,
            )
        except (CanonicalizationError, TypeError, ValueError):
            await tracker.transition(InvocationState.FAILED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.SCHEMA_VALIDATION_FAILED,
            )

        await self.repository.record_validated(
            InvocationValidatedEvent(
                request_id=request.request_id,
                fingerprint=fingerprint,
                request_size_bytes=len(canonical_bytes),
                estimated_cost_units=estimated_cost_units,
                cost_unit=canonical.spec.cost_unit,
            )
        )

        await tracker.transition(InvocationState.POLICY_CHECK)
        inspection = self.sensitive.inspect(canonical.canonical_input)
        if inspection.denied:
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.SENSITIVE_PAYLOAD_DENIED,
                fingerprint=fingerprint,
            )

        try:
            affinity = await self._resolve_affinity(request, session, canonical)
        except AffinityUnavailableError:
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.POLICY_DENIED,
                policy_rule_id="resource-ownership",
                fingerprint=fingerprint,
            )

        try:
            emergency_projection = await self._emergency_projection(
                request=request,
                session=session,
                affinity=affinity,
            )
        except EmergencyUnlockError:
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.POLICY_DENIED,
                policy_rule_id="emergency-authority",
                fingerprint=fingerprint,
            )

        pool_name = (
            emergency_projection.pool_name
            if emergency_projection is not None
            else session.pool_bindings.get(request.service_id)
        )
        if pool_name is None:
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.NO_ELIGIBLE_POOL,
                fingerprint=fingerprint,
            )
        policy_result = self.policy.evaluate(
            self._policy_context(
                request=request,
                session=session,
                canonical=canonical,
                fingerprint=str(fingerprint),
                estimated_cost_units=estimated_cost_units,
                pool_name=pool_name,
                affinity=affinity,
                automatic_pool_selection=emergency_projection is None,
            )
        )
        approval_result = await self._resolve_policy(
            tracker=tracker,
            request=request,
            session=session,
            fingerprint=fingerprint,
            policy_result=policy_result,
            pool_name=pool_name,
            estimated_cost_units=estimated_cost_units,
        )
        if approval_result is not None:
            return approval_result

        await tracker.transition(InvocationState.DEDUPLICATION)
        runaway_decision = self.runaway.record_arrival(
            session_id=str(session.session_id),
            fingerprint=fingerprint,
            now_ms=self.clock.now_ms(),
        )
        if runaway_decision is not RunawayDecision.ALLOW:
            retry_after_ms = self.runaway.retry_after_ms(
                session_id=str(session.session_id),
                fingerprint=fingerprint,
                now_ms=self.clock.now_ms(),
            )
            await tracker.transition(InvocationState.FAILED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.RUNAWAY_SUSPECTED,
                retryable=True,
                retry_after_seconds=max(1, math.ceil((retry_after_ms or 1) / 1_000)),
                fingerprint=fingerprint,
            )
        # Emergency execution owns a process-local, unlock-scoped accounting
        # permit.  It must never share a singleflight group with an ordinary
        # request from before/after the unlock boundary (or with another
        # unlock epoch), even when the canonical request fingerprints match.
        if not canonical.spec.coalescible or emergency_projection is not None:
            return await self._admit_and_execute(
                tracker=tracker,
                request=request,
                session=session,
                canonical=canonical,
                fingerprint=fingerprint,
                pool_name=pool_name,
                estimated_cost_units=estimated_cost_units,
                affinity=affinity,
                emergency_projection=emergency_projection,
            )
        try:
            singleflight_handle = await self.singleflight.join_or_create(
                session_id=str(session.session_id),
                request_id=str(request.request_id),
                fingerprint=fingerprint,
            )
        except SingleFlightCapacityExceeded:
            await tracker.transition(InvocationState.CAPACITY_EXCEEDED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=self.capacity_retry_after_seconds,
                fingerprint=fingerprint,
            )
        if singleflight_handle.role is SingleFlightRole.WAITER:
            await tracker.transition(
                InvocationState.DUPLICATE_IN_FLIGHT,
                metadata={
                    "coalesced_from_request_id": str(singleflight_handle.original_request_id)
                },
            )
        else:
            execution_task = asyncio.create_task(
                self._run_singleflight_execution(
                    group_id=singleflight_handle.group_id,
                    tracker=tracker,
                    request=request,
                    session=session,
                    canonical=canonical,
                    fingerprint=fingerprint,
                    pool_name=pool_name,
                    estimated_cost_units=estimated_cost_units,
                    affinity=affinity,
                    emergency_projection=emergency_projection,
                ),
                name=f"gatehouse-singleflight-{singleflight_handle.group_id}",
            )
            self._singleflight_tasks[singleflight_handle.group_id] = execution_task
            execution_task.add_done_callback(
                partial(
                    self._singleflight_task_done,
                    singleflight_handle.group_id,
                )
            )
        return await self._await_singleflight_participant(
            tracker=tracker,
            request=request,
            fingerprint=fingerprint,
            handle=singleflight_handle,
        )

    async def _run_singleflight_execution(
        self,
        *,
        group_id: int,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
        fingerprint: object,
        pool_name: str,
        estimated_cost_units: int,
        affinity: ResourceAffinity | None,
        emergency_projection: EmergencyUnlockProjection | None,
    ) -> None:
        try:
            result = await self._admit_and_execute(
                tracker=tracker,
                request=request,
                session=session,
                canonical=canonical,
                fingerprint=fingerprint,
                pool_name=pool_name,
                estimated_cost_units=estimated_cost_units,
                affinity=affinity,
                emergency_projection=emergency_projection,
            )
        except BaseException as error:
            await self.singleflight.fail(group_id, error)
        else:
            await self.singleflight.complete(group_id, result)

    def _singleflight_task_done(
        self,
        group_id: int,
        completed: asyncio.Task[None],
    ) -> None:
        current = self._singleflight_tasks.get(group_id)
        if current is completed:
            self._singleflight_tasks.pop(group_id, None)
        if not completed.cancelled():
            completed.exception()

    async def _await_singleflight_participant(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        fingerprint: object,
        handle: SingleFlightHandle,
    ) -> InvocationResult:
        from gatehouse.fingerprint.hmac import RequestFingerprint

        if not isinstance(fingerprint, RequestFingerprint):
            raise TypeError("fingerprint gateway returned an invalid value")
        if handle.role is SingleFlightRole.LEADER:
            try:
                leader_result = await handle.wait()
            except asyncio.CancelledError:
                await self._detach_singleflight_participant(handle)
                raise
            if not isinstance(leader_result, InvocationResult):
                raise TypeError("single-flight leader returned an invalid result")
            return leader_result

        remaining_ms = request.queue_deadline_ms - self.clock.now_ms()
        if remaining_ms <= 0:
            await self._detach_singleflight_participant(handle)
            await tracker.transition(InvocationState.CAPACITY_EXCEEDED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=self.capacity_retry_after_seconds,
                fingerprint=fingerprint,
            )
        try:
            leader_result = await asyncio.wait_for(
                handle.wait(),
                timeout=remaining_ms / 1_000,
            )
        except TimeoutError:
            await self._detach_singleflight_participant(handle)
            await tracker.transition(InvocationState.CAPACITY_EXCEEDED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=self.capacity_retry_after_seconds,
                fingerprint=fingerprint,
            )
        except asyncio.CancelledError:
            await self._detach_singleflight_participant(handle)
            await tracker.transition(InvocationState.CANCELLED)
            raise
        if not isinstance(leader_result, InvocationResult):
            raise TypeError("single-flight leader returned an invalid result")
        await tracker.transition(
            leader_result.state,
            metadata={
                "coalesced_from_request_id": str(handle.original_request_id),
            },
        )
        error = leader_result.error
        if error is not None:
            error = replace(error, request_id=request.request_id)
        return InvocationResult(
            request_id=request.request_id,
            state=leader_result.state,
            attempts=0,
            fingerprint=fingerprint,
            data=leader_result.data,
            error=error,
            provider_resource_id=leader_result.provider_resource_id,
            approval_id=leader_result.approval_id,
        )

    async def _detach_singleflight_participant(
        self,
        handle: SingleFlightHandle,
    ) -> None:
        decision = await self.singleflight.cancel(handle)
        if not decision.cancel_underlying:
            return
        execution_task = self._singleflight_tasks.get(handle.group_id)
        if execution_task is not None and not execution_task.done():
            execution_task.cancel()
            await asyncio.shield(execution_task)

    async def _admit_and_execute(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
        fingerprint: object,
        pool_name: str,
        estimated_cost_units: int,
        affinity: ResourceAffinity | None,
        emergency_projection: EmergencyUnlockProjection | None,
    ) -> InvocationResult:
        emergency_plan = (
            self._emergency_routing_plan(
                projection=emergency_projection,
                operation=request.operation,
                estimated_cost_units=estimated_cost_units,
                unit=canonical.spec.cost_unit,
            )
            if emergency_projection is not None
            else None
        )
        if emergency_projection is not None and canonical.spec.asynchronous:
            await tracker.transition(InvocationState.CAPACITY_EXCEEDED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=False,
                fingerprint=fingerprint,
            )
        emergency_permit: EmergencyRequestPermit | None = None
        if emergency_projection is not None:
            if self.emergency is None:
                raise RuntimeError("emergency projection has no manager")
            try:
                emergency_permit = await self.emergency.reserve(
                    service_id=request.service_id,
                    pool_name=emergency_projection.pool_name,
                    session_id=str(session.session_id),
                    root_run_id=str(session.root_run_id),
                    operation=request.operation,
                    estimated_credits=max(1, estimated_cost_units),
                    automatic=False,
                )
            except EmergencyUnlockError:
                await tracker.transition(InvocationState.CAPACITY_EXCEEDED)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.CAPACITY_EXCEEDED,
                    retryable=False,
                    fingerprint=fingerprint,
                )

        async def release_emergency() -> None:
            if emergency_permit is not None and self.emergency is not None:
                await self.emergency.settle(
                    emergency_permit,
                    actual_credits=0,
                    outcome_known=True,
                )

        budget_reservation: BudgetReservation | None = None
        if estimated_cost_units:
            try:
                budget_reservation = await self.budgets.reserve(
                    request=request,
                    session=session,
                    amount_units=estimated_cost_units,
                    unit=canonical.spec.cost_unit,
                )
            except BudgetUnavailableError:
                await release_emergency()
                await tracker.transition(InvocationState.FAILED)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.BUDGET_EXHAUSTED,
                    fingerprint=fingerprint,
                )
            except asyncio.CancelledError:
                await release_emergency()
                await tracker.transition(InvocationState.CANCELLED)
                raise
            except Exception:
                await release_emergency()
                await tracker.transition(InvocationState.FAILED)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.DAEMON_DEGRADED,
                    retryable=True,
                    retry_after_seconds=5,
                    fingerprint=fingerprint,
                )

        try:
            if emergency_plan is not None:
                plan = emergency_plan
                grant = ReservationGrant(
                    reservation=None,
                    selected=plan.candidates[0],
                    same_scope_candidates=plan.candidates,
                )
            else:
                plan = self.router.plan(
                    service_id=request.service_id,
                    operation=request.operation,
                    pool_name=pool_name,
                    estimated_cost_units=estimated_cost_units,
                    unit=canonical.spec.cost_unit,
                    now_ms=self.clock.now_ms(),
                    affinity=affinity,
                    automatic=True,
                    reconciliation=session.internal_resource_reconciliation,
                )
                grant = self.quota.reserve(
                    plan=plan,
                    request_id=request.request_id,
                    now_ms=self.clock.now_ms(),
                    expires_at_ms=self.clock.now_ms() + self.reservation_ttl_ms,
                )
        except NoEligiblePoolError:
            await self._release_budget(budget_reservation, actual_units=0)
            await release_emergency()
            await tracker.transition(InvocationState.FAILED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.NO_ELIGIBLE_POOL,
                fingerprint=fingerprint,
            )
        except (NoEligibleCredentialError, AffinityUnavailableError):
            await self._release_budget(budget_reservation, actual_units=0)
            await release_emergency()
            await tracker.transition(InvocationState.FAILED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.NO_ELIGIBLE_CREDENTIAL,
                fingerprint=fingerprint,
            )
        except QuotaUnavailableError:
            await self._release_budget(budget_reservation, actual_units=0)
            await release_emergency()
            await tracker.transition(InvocationState.QUOTA_EXHAUSTED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.QUOTA_EXHAUSTED,
                retryable=True,
                retry_after_seconds=60,
                fingerprint=fingerprint,
            )
        except asyncio.CancelledError:
            await self._release_budget(budget_reservation, actual_units=0)
            await release_emergency()
            await tracker.transition(InvocationState.CANCELLED)
            raise
        except Exception:
            await self._release_budget(budget_reservation, actual_units=0)
            await release_emergency()
            await tracker.transition(InvocationState.FAILED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=5,
                fingerprint=fingerprint,
            )

        return await self._execute(
            tracker=tracker,
            request=request,
            session=session,
            canonical=canonical,
            fingerprint=fingerprint,
            plan=plan,
            grant=grant,
            budget_reservation=budget_reservation,
            exact_affinity=affinity is not None,
            emergency_permit=emergency_permit,
            skip_credential_lease=emergency_plan is not None,
        )

    async def _resolve_policy(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: object,
        policy_result: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> InvocationResult | None:
        from gatehouse.fingerprint.hmac import RequestFingerprint

        if not isinstance(fingerprint, RequestFingerprint):
            raise TypeError("fingerprint gateway returned an invalid value")
        if policy_result.decision is Decision.DENY:
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.POLICY_DENIED,
                policy_rule_id=policy_result.rule_id,
                fingerprint=fingerprint,
            )
        if policy_result.decision is Decision.ALLOW:
            return None
        if session.client_class.value == "unattended":
            await tracker.transition(InvocationState.DENIED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.APPROVAL_UNAVAILABLE_FOR_UNATTENDED_CLIENT,
                policy_rule_id=policy_result.rule_id,
                fingerprint=fingerprint,
            )
        await tracker.transition(InvocationState.WAITING_APPROVAL)
        resolution = await self.approvals.resolve(
            request=request,
            session=session,
            fingerprint=fingerprint,
            policy=policy_result,
            pool_name=pool_name,
            estimated_cost_units=estimated_cost_units,
        )
        if resolution.state is ApprovalState.APPROVED:
            return None
        if resolution.state is ApprovalState.PENDING:
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.APPROVAL_PENDING,
                retryable=True,
                retry_after_seconds=1,
                policy_rule_id=policy_result.rule_id,
                fingerprint=fingerprint,
                approval_id=resolution.approval_id,
            )
        await tracker.transition(InvocationState.DENIED)
        code = (
            ErrorCode.APPROVAL_EXPIRED
            if resolution.state is ApprovalState.EXPIRED
            else ErrorCode.POLICY_DENIED
        )
        return self._error_result(
            request,
            tracker.current,
            code,
            policy_rule_id=policy_result.rule_id,
            fingerprint=fingerprint,
        )

    async def _execute(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
        fingerprint: object,
        plan: RoutingPlan,
        grant: ReservationGrant,
        budget_reservation: BudgetReservation | None,
        exact_affinity: bool,
        emergency_permit: EmergencyRequestPermit | None,
        skip_credential_lease: bool,
    ) -> InvocationResult:
        ownership = _ExecutionOwnership(
            reservation=grant.reservation,
            budget=budget_reservation,
            emergency_permit=emergency_permit,
            quota_resolved=grant.reservation is None,
            budget_resolved=budget_reservation is None,
            emergency_resolved=emergency_permit is None,
            defer_success_accounting=canonical.spec.asynchronous,
        )
        try:
            await tracker.transition(InvocationState.QUOTA_RESERVED)
            return await self._execute_owned(
                tracker=tracker,
                request=request,
                session=session,
                canonical=canonical,
                fingerprint=fingerprint,
                plan=plan,
                grant=grant,
                ownership=ownership,
                exact_affinity=exact_affinity,
                skip_credential_lease=skip_credential_lease,
            )
        except asyncio.CancelledError:
            ambiguous = ownership.submission_may_have_occurred
            await self._finalize_exceptional_execution(
                ownership,
                tracker=tracker,
                terminal=(InvocationState.UNKNOWN if ambiguous else InvocationState.CANCELLED),
                ambiguous=ambiguous,
            )
            raise
        except Exception:
            ambiguous = ownership.submission_may_have_occurred
            await self._finalize_exceptional_execution(
                ownership,
                tracker=tracker,
                terminal=(InvocationState.UNKNOWN if ambiguous else InvocationState.FAILED),
                ambiguous=ambiguous,
            )
            if ambiguous:
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.UNCERTAIN_OUTCOME,
                    attempts=ownership.attempts,
                    fingerprint=fingerprint,
                )
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=5,
                attempts=ownership.attempts,
                fingerprint=fingerprint,
            )

    async def _execute_owned(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
        fingerprint: object,
        plan: RoutingPlan,
        grant: ReservationGrant,
        ownership: _ExecutionOwnership,
        exact_affinity: bool,
        skip_credential_lease: bool,
    ) -> InvocationResult:
        from gatehouse.fingerprint.hmac import RequestFingerprint

        if not isinstance(fingerprint, RequestFingerprint):
            raise TypeError("fingerprint gateway returned an invalid value")
        attempt_number = 0
        emergency_unlock_id = (
            ownership.emergency_permit.unlock_id if ownership.emergency_permit is not None else None
        )
        excluded_scopes: set[QuotaScopeId] = set()
        blocked_credentials: set[str] = set()
        current_grant = grant
        candidate = current_grant.selected

        while True:
            if any(
                resource is not None
                for resource in (
                    ownership.permit,
                    ownership.lease,
                    ownership.breaker_permit,
                )
            ):
                raise RuntimeError("attempt-scoped resource survived into the next attempt")
            ownership.submission_may_have_occurred = False
            ownership.outcome = None
            permit_result = await self._queue(
                tracker=tracker,
                request=request,
                session=session,
                plan=plan,
                quota_scope_id=current_grant.selected.scope.quota_scope_id,
            )
            if isinstance(permit_result, InvocationResult):
                self._settle_owned_quota(ownership, actual_units=0)
                await self._settle_owned_budget(ownership, actual_units=0)
                return InvocationResult(
                    request_id=request.request_id,
                    state=permit_result.state,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                    error=permit_result.error,
                )
            permit = permit_result
            ownership.permit = permit
            reservation = current_grant.reservation
            if reservation is not None and reservation.expires_at_ms <= self.clock.now_ms():
                try:
                    current_grant = self.quota.replace_expired(
                        reservation,
                        plan=plan,
                        request_id=request.request_id,
                        now_ms=self.clock.now_ms(),
                        expires_at_ms=self.clock.now_ms() + self.reservation_ttl_ms,
                        exclude_scope_ids=excluded_scopes,
                    )
                    self._adopt_atomically_replaced_reservation(
                        ownership,
                        current_grant.reservation,
                    )
                    await tracker.transition(InvocationState.QUOTA_RESERVED)
                except QuotaUnavailableError:
                    self._settle_owned_quota(ownership, actual_units=0)
                    await self._settle_owned_budget(ownership, actual_units=0)
                    await self._release_owned_permit(ownership)
                    await tracker.transition(InvocationState.QUOTA_EXHAUSTED)
                    return self._error_result(
                        request,
                        tracker.current,
                        ErrorCode.QUOTA_EXHAUSTED,
                        retryable=True,
                        retry_after_seconds=60,
                        attempts=attempt_number,
                        fingerprint=fingerprint,
                    )
                candidate = current_grant.selected
                if permit.quota_scope_id != str(candidate.scope.quota_scope_id):
                    await self._release_owned_permit(ownership)
                    continue
            lease: CredentialDispatchLease | None = None
            response: ProviderResponse | None = None
            try:
                lease_choice = self._acquire_candidate_lease(
                    request=request,
                    grant=current_grant,
                    blocked_credentials=blocked_credentials,
                    bypass_circuit_breakers=(session.internal_resource_reconciliation),
                    exact_affinity=exact_affinity,
                    reconciliation=session.internal_resource_reconciliation,
                    skip_credential_lease=skip_credential_lease,
                )
                scope_changed = False
                if lease_choice is None and skip_credential_lease:
                    await self._release_owned_permit(ownership)
                    await self._settle_owned_budget(ownership, actual_units=0)
                    await tracker.transition(InvocationState.FAILED)
                    return self._error_result(
                        request,
                        tracker.current,
                        ErrorCode.NO_ELIGIBLE_CREDENTIAL,
                        attempts=attempt_number,
                        fingerprint=fingerprint,
                    )
                while lease_choice is None:
                    self._settle_owned_quota(ownership, actual_units=0)
                    excluded_scopes.add(current_grant.selected.scope.quota_scope_id)
                    try:
                        current_grant = self.quota.reserve(
                            plan=plan,
                            request_id=request.request_id,
                            now_ms=self.clock.now_ms(),
                            expires_at_ms=self.clock.now_ms() + self.reservation_ttl_ms,
                            exclude_scope_ids=excluded_scopes,
                        )
                        self._replace_owned_reservation(
                            ownership,
                            current_grant.reservation,
                        )
                        if tracker.current is not InvocationState.QUOTA_RESERVED:
                            await tracker.transition(InvocationState.QUOTA_RESERVED)
                    except QuotaUnavailableError:
                        await self._release_owned_permit(ownership)
                        await tracker.transition(InvocationState.FAILED)
                        await self._settle_owned_budget(ownership, actual_units=0)
                        return self._error_result(
                            request,
                            tracker.current,
                            ErrorCode.NO_ELIGIBLE_CREDENTIAL,
                            attempts=attempt_number,
                            fingerprint=fingerprint,
                        )
                    candidate = current_grant.selected
                    if permit.quota_scope_id != str(candidate.scope.quota_scope_id):
                        await self._release_owned_permit(ownership)
                        scope_changed = True
                        break
                    lease_choice = self._acquire_candidate_lease(
                        request=request,
                        grant=current_grant,
                        blocked_credentials=blocked_credentials,
                        bypass_circuit_breakers=(session.internal_resource_reconciliation),
                        exact_affinity=exact_affinity,
                        reconciliation=session.internal_resource_reconciliation,
                        skip_credential_lease=skip_credential_lease,
                    )
                if scope_changed:
                    continue
                if lease_choice is None:
                    raise RuntimeError("credential selection ended without a lease")
                candidate, lease, breaker_permit = lease_choice
                ownership.lease = lease
                ownership.breaker_permit = breaker_permit
                attempt_number += 1
                ownership.attempts = attempt_number
                await tracker.transition(InvocationState.DISPATCHING)
                expired_result = await self._fail_if_quota_expired_before_handoff(
                    tracker=tracker,
                    request=request,
                    fingerprint=fingerprint,
                    ownership=ownership,
                    attempts=attempt_number,
                )
                if expired_result is not None:
                    return expired_result
                await self.repository.record_attempt(
                    self._attempt_event(
                        request=request,
                        candidate=candidate,
                        emergency_unlock_id=emergency_unlock_id,
                        ordinal=attempt_number,
                        state=InvocationState.DISPATCHING,
                        estimated_cost_units=self._integer_cost(
                            canonical.spec.default_estimated_cost
                        ),
                        cost_unit=canonical.spec.cost_unit,
                    )
                )
                expired_result = await self._fail_if_quota_expired_before_handoff(
                    tracker=tracker,
                    request=request,
                    fingerprint=fingerprint,
                    ownership=ownership,
                    attempts=attempt_number,
                )
                if expired_result is not None:
                    return expired_result
                provider_request = self.operations.build_request(
                    canonical,
                    credential_id=str(candidate.credential.credential_id),
                    credential_generation=candidate.credential.generation,
                )
                provider_request = replace(
                    provider_request,
                    credential_custody=(
                        CredentialCustodyKind.EMERGENCY
                        if ownership.emergency_permit is not None
                        else CredentialCustodyKind.PERSISTENT
                    ),
                )
                await tracker.transition(InvocationState.RUNNING)
                expired_result = await self._fail_if_quota_expired_before_handoff(
                    tracker=tracker,
                    request=request,
                    fingerprint=fingerprint,
                    ownership=ownership,
                    attempts=attempt_number,
                )
                if expired_result is not None:
                    return expired_result
                if self.repository.transaction_active:
                    raise TransactionBoundaryError(
                        "provider transport cannot run inside a persistence transaction"
                    )
                await self.repository.record_attempt(
                    self._attempt_event(
                        request=request,
                        candidate=candidate,
                        emergency_unlock_id=emergency_unlock_id,
                        ordinal=attempt_number,
                        state=InvocationState.RUNNING,
                        estimated_cost_units=self._integer_cost(
                            canonical.spec.default_estimated_cost
                        ),
                        cost_unit=canonical.spec.cost_unit,
                    )
                )
                expired_result = await self._fail_if_quota_expired_before_handoff(
                    tracker=tracker,
                    request=request,
                    fingerprint=fingerprint,
                    ownership=ownership,
                    attempts=attempt_number,
                )
                if expired_result is not None:
                    await self.repository.record_attempt(
                        self._attempt_event(
                            request=request,
                            candidate=candidate,
                            emergency_unlock_id=emergency_unlock_id,
                            ordinal=attempt_number,
                            state=InvocationState.FAILED,
                            estimated_cost_units=self._integer_cost(
                                canonical.spec.default_estimated_cost
                            ),
                            cost_unit=canonical.spec.cost_unit,
                        )
                    )
                    return expired_result
                if self.repository.transaction_active:
                    raise TransactionBoundaryError(
                        "provider transport cannot run inside a persistence transaction"
                    )
                ownership.submission_may_have_occurred = True
                response = await self.transport.send(provider_request)
            except (
                TransactionBoundaryError,
                ProviderNetworkDisabledError,
                ProviderPreHandoffError,
            ):
                ownership.submission_may_have_occurred = False
                await self.repository.record_attempt(
                    self._attempt_event(
                        request=request,
                        candidate=candidate,
                        emergency_unlock_id=emergency_unlock_id,
                        ordinal=attempt_number,
                        state=InvocationState.FAILED,
                        estimated_cost_units=self._integer_cost(
                            canonical.spec.default_estimated_cost
                        ),
                        cost_unit=canonical.spec.cost_unit,
                    )
                )
                self._release_owned_breaker_permit(ownership)
                self._settle_owned_quota(ownership, actual_units=0)
                await self._settle_owned_budget(ownership, actual_units=0)
                await tracker.transition(InvocationState.FAILED)
                await self._release_owned_permit(ownership)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.DAEMON_DEGRADED,
                    retryable=True,
                    retry_after_seconds=5,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                )
            except TargetValidationError:
                ownership.submission_may_have_occurred = False
                await self.repository.record_attempt(
                    self._attempt_event(
                        request=request,
                        candidate=candidate,
                        emergency_unlock_id=emergency_unlock_id,
                        ordinal=attempt_number,
                        state=InvocationState.FAILED,
                        estimated_cost_units=self._integer_cost(
                            canonical.spec.default_estimated_cost
                        ),
                        cost_unit=canonical.spec.cost_unit,
                    )
                )
                self._release_owned_breaker_permit(ownership)
                self._settle_owned_quota(ownership, actual_units=0)
                await self._settle_owned_budget(ownership, actual_units=0)
                await tracker.transition(InvocationState.FAILED)
                await self._release_owned_permit(ownership)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.INVALID_TARGET,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                )
            except (TypeError, ValueError):
                if ownership.submission_may_have_occurred:
                    raise
                ownership.submission_may_have_occurred = False
                await self.repository.record_attempt(
                    self._attempt_event(
                        request=request,
                        candidate=candidate,
                        emergency_unlock_id=emergency_unlock_id,
                        ordinal=attempt_number,
                        state=InvocationState.FAILED,
                        estimated_cost_units=self._integer_cost(
                            canonical.spec.default_estimated_cost
                        ),
                        cost_unit=canonical.spec.cost_unit,
                    )
                )
                self._release_owned_breaker_permit(ownership)
                self._settle_owned_quota(ownership, actual_units=0)
                await self._settle_owned_budget(ownership, actual_units=0)
                await tracker.transition(InvocationState.FAILED)
                await self._release_owned_permit(ownership)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.SCHEMA_VALIDATION_FAILED,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                )
            finally:
                if lease is not None and response is None:
                    self._release_owned_lease(ownership)

            if response is None:
                raise RuntimeError("provider transport returned no response")
            outcome = self.operations.classify_response(request.operation, response)
            ownership.outcome = outcome
            await self.repository.record_attempt(
                self._attempt_event(
                    request=request,
                    candidate=candidate,
                    emergency_unlock_id=emergency_unlock_id,
                    ordinal=attempt_number,
                    state=(
                        InvocationState.SUCCEEDED
                        if outcome.succeeded
                        else InvocationState.UNKNOWN
                        if outcome.submission_may_have_occurred
                        else InvocationState.FAILED
                    ),
                    status_code=response.status_code,
                    error_class=outcome.error_class,
                    provider_request_id=(
                        outcome.provider_request_id or response.provider_request_id
                    ),
                    estimated_cost_units=self._integer_cost(canonical.spec.default_estimated_cost),
                    actual_cost_units=outcome.actual_cost_units,
                    cost_unit=canonical.spec.cost_unit,
                    latency_ms=response.elapsed_ms,
                    resource_type=(
                        canonical.async_resource_type
                        if (
                            canonical.spec.asynchronous
                            and outcome.succeeded
                            and outcome.provider_resource_id is not None
                        )
                        else None
                    ),
                    provider_resource_id=(
                        outcome.provider_resource_id
                        if canonical.spec.asynchronous and outcome.succeeded
                        else None
                    ),
                    credential_generation=(
                        candidate.credential.generation
                        if (
                            canonical.spec.asynchronous
                            and outcome.succeeded
                            and outcome.provider_resource_id is not None
                        )
                        else None
                    ),
                    pool_id=(
                        str(candidate.pool_id)
                        if (
                            canonical.spec.asynchronous
                            and outcome.succeeded
                            and outcome.provider_resource_id is not None
                        )
                        else None
                    ),
                )
            )
            retain_lease_through_affinity_bind = (
                canonical.spec.asynchronous
                and outcome.succeeded
                and outcome.provider_resource_id is not None
            )
            if not retain_lease_through_affinity_bind:
                self._release_owned_lease(ownership)
            await self._release_owned_permit(ownership)
            if outcome.succeeded:
                try:
                    result = await self._complete_success(
                        tracker=tracker,
                        request=request,
                        session=session,
                        canonical=canonical,
                        fingerprint=fingerprint,
                        candidate=candidate,
                        outcome=outcome,
                        attempts=attempt_number,
                        ownership=ownership,
                    )
                finally:
                    self._release_owned_lease(ownership)
                await self._release_owned_permit(ownership)
                return result

            self._release_owned_breaker_permit(ownership)
            self._record_failure(candidate, request.operation, outcome)
            if ownership.emergency_permit is not None:
                if outcome.submission_may_have_occurred:
                    self._hold_owned_quota(ownership)
                    await self._hold_owned_budget(ownership)
                    await tracker.transition(
                        InvocationState.UNKNOWN,
                        metadata={"provider_handoff": True},
                    )
                    return self._error_result(
                        request,
                        tracker.current,
                        ErrorCode.UNCERTAIN_OUTCOME,
                        attempts=attempt_number,
                        fingerprint=fingerprint,
                    )
                actual_units = outcome.actual_cost_units or 0
                self._settle_owned_quota(ownership, actual_units=actual_units)
                await self._settle_owned_budget(ownership, actual_units=actual_units)
                await tracker.transition(InvocationState.FAILED)
                return self._provider_error_result(
                    request=request,
                    state=tracker.current,
                    outcome=outcome,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                )
            remaining = plan.remaining_after(candidate.credential.credential_id)
            decision = self.retry_policy.decide(
                operation=canonical.spec,
                error_class=outcome.error_class,
                attempt_number=attempt_number,
                submission_may_have_occurred=outcome.submission_may_have_occurred,
                retry_after_seconds=outcome.retry_after_seconds,
                has_pool_failover=bool(remaining),
            )
            if decision.action in {RetryAction.UNKNOWN, RetryAction.RECONCILE}:
                self._hold_owned_quota(ownership)
                await self._hold_owned_budget(ownership)
                if decision.action is RetryAction.RECONCILE:
                    await tracker.transition(InvocationState.RECONCILING)
                await tracker.transition(
                    InvocationState.UNKNOWN,
                    metadata={"provider_handoff": True},
                )
                await self._release_owned_permit(ownership)
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.UNCERTAIN_OUTCOME,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                )
            if decision.action is RetryAction.FAIL:
                self._settle_owned_quota(ownership, actual_units=0)
                await self._settle_owned_budget(ownership, actual_units=0)
                await tracker.transition(InvocationState.FAILED)
                await self._release_owned_permit(ownership)
                return self._provider_error_result(
                    request=request,
                    state=tracker.current,
                    outcome=outcome,
                    attempts=attempt_number,
                    fingerprint=fingerprint,
                )

            await tracker.transition(InvocationState.RETRY_WAIT)
            await self._release_owned_permit(ownership)
            if decision.action is RetryAction.FAILOVER_WITHIN_POOL:
                next_same_scope = next(
                    (
                        item
                        for item in remaining
                        if item.scope.quota_scope_id == candidate.scope.quota_scope_id
                        and str(item.credential.credential_id) not in blocked_credentials
                    ),
                    None,
                )
                if (
                    outcome.error_class is ProviderErrorClass.UNAUTHORIZED
                    and next_same_scope is not None
                ):
                    blocked_credentials.add(str(candidate.credential.credential_id))
                    candidate = next_same_scope
                else:
                    self._settle_owned_quota(ownership, actual_units=0)
                    excluded_scopes.add(candidate.scope.quota_scope_id)
                    try:
                        current_grant = self.quota.reserve(
                            plan=plan,
                            request_id=request.request_id,
                            now_ms=self.clock.now_ms(),
                            expires_at_ms=self.clock.now_ms() + self.reservation_ttl_ms,
                            exclude_scope_ids=excluded_scopes,
                        )
                        self._replace_owned_reservation(
                            ownership,
                            current_grant.reservation,
                        )
                        if tracker.current is not InvocationState.QUOTA_RESERVED:
                            await tracker.transition(InvocationState.QUOTA_RESERVED)
                    except QuotaUnavailableError:
                        await self._settle_owned_budget(ownership, actual_units=0)
                        await tracker.transition(InvocationState.FAILED)
                        return self._provider_error_result(
                            request=request,
                            state=tracker.current,
                            outcome=outcome,
                            attempts=attempt_number,
                            fingerprint=fingerprint,
                        )
                    candidate = current_grant.selected
            elif decision.delay_ms:
                if self.clock.now_ms() + decision.delay_ms >= request.queue_deadline_ms:
                    self._settle_owned_quota(ownership, actual_units=0)
                    await self._settle_owned_budget(ownership, actual_units=0)
                    await tracker.transition(InvocationState.FAILED)
                    return self._provider_error_result(
                        request=request,
                        state=tracker.current,
                        outcome=outcome,
                        attempts=attempt_number,
                        fingerprint=fingerprint,
                    )
                await self._sleep(decision.delay_ms / 1_000)

    async def _queue(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        plan: RoutingPlan,
        quota_scope_id: QuotaScopeId,
    ) -> DispatchPermit | InvocationResult:
        await tracker.transition(
            InvocationState.QUEUED,
            metadata={"pool_id": str(plan.pool_id)},
        )
        try:
            ticket = await self.scheduler.enqueue(
                WorkItem(
                    request_id=str(request.request_id),
                    session_id=str(session.session_id),
                    service_id=request.service_id,
                    priority=session.priority,
                    enqueued_at_ms=self.clock.now_ms(),
                    deadline_ms=request.queue_deadline_ms,
                    cost=1,
                    quota_scope_id=str(quota_scope_id),
                    metadata={"pool_id": str(plan.pool_id)},
                )
            )
            permit = await ticket.wait()
        except RequestCancelled:
            await tracker.transition(InvocationState.CANCELLED)
            return InvocationResult(
                request_id=request.request_id,
                state=tracker.current,
                attempts=0,
            )
        except (QueueCapacityExceeded, QueueExpired):
            await tracker.transition(InvocationState.CAPACITY_EXCEEDED)
            return self._error_result(
                request,
                tracker.current,
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=self.capacity_retry_after_seconds,
            )
        return permit

    def _acquire_candidate_lease(
        self,
        *,
        request: InvocationRequest,
        grant: ReservationGrant,
        blocked_credentials: set[str],
        bypass_circuit_breakers: bool = False,
        exact_affinity: bool = False,
        reconciliation: bool = False,
        skip_credential_lease: bool = False,
    ) -> (
        tuple[
            RouteCandidate,
            CredentialDispatchLease | None,
            CircuitBreakerPermit | None,
        ]
        | None
    ):
        for candidate in grant.same_scope_candidates:
            if str(candidate.credential.credential_id) in blocked_credentials:
                continue
            lease: CredentialDispatchLease | None = None
            if not skip_credential_lease:
                try:
                    lease = self.credential_leases.acquire(
                        candidate=candidate,
                        request_id=request.request_id,
                        now_ms=self.clock.now_ms(),
                        expires_at_ms=self.clock.now_ms() + self.credential_lease_ttl_ms,
                        exact_affinity=exact_affinity,
                        reconciliation=reconciliation,
                    )
                except CredentialLeaseUnavailableError:
                    blocked_credentials.add(str(candidate.credential.credential_id))
                    continue
            if bypass_circuit_breakers:
                return candidate, lease, None
            try:
                breaker_permit = self.circuit_breakers.try_acquire_many(
                    self._breaker_keys(candidate, request.operation),
                    now_ms=self.clock.now_ms(),
                )
            except BaseException as error:
                if lease is not None and not self.credential_leases.release(
                    lease, now_ms=self.clock.now_ms()
                ):
                    raise RuntimeError(
                        "credential lease release failed after breaker error"
                    ) from error
                raise
            if breaker_permit is None:
                if lease is not None and not self.credential_leases.release(
                    lease, now_ms=self.clock.now_ms()
                ):
                    raise RuntimeError("credential lease release failed after breaker denial")
                blocked_credentials.add(str(candidate.credential.credential_id))
                continue
            return candidate, lease, breaker_permit
        return None

    async def _complete_success(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
        fingerprint: object,
        candidate: RouteCandidate,
        outcome: ClassifiedProviderOutcome,
        attempts: int,
        ownership: _ExecutionOwnership,
    ) -> InvocationResult:
        from gatehouse.fingerprint.hmac import RequestFingerprint

        if not isinstance(fingerprint, RequestFingerprint):
            raise TypeError("fingerprint gateway returned an invalid value")
        if canonical.spec.asynchronous:
            if outcome.provider_resource_id is None or canonical.async_resource_type is None:
                self._release_owned_breaker_permit(ownership)
                self._hold_owned_quota(ownership)
                await self._hold_owned_budget(ownership)
                await tracker.transition(
                    InvocationState.UNKNOWN,
                    metadata={"provider_handoff": True},
                )
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.UNCERTAIN_OUTCOME,
                    attempts=attempts,
                    fingerprint=fingerprint,
                )
            try:
                await self.affinities.bind(
                    ResourceAffinity(
                        service_id=request.service_id,
                        resource_type=canonical.async_resource_type,
                        provider_resource_id=outcome.provider_resource_id,
                        principal_id=candidate.scope.principal_id,
                        quota_scope_id=candidate.scope.quota_scope_id,
                        credential_id=candidate.credential.credential_id,
                        credential_generation=candidate.credential.generation,
                        pool_id=candidate.pool_id,
                        creating_request_id=request.request_id,
                        owner_session_id=session.session_id,
                        owner_workspace_id=session.workspace_id,
                        owner_root_run_id=session.root_run_id,
                        bound_at_ms=self.clock.now_ms(),
                    )
                )
            except Exception:
                self._release_owned_breaker_permit(ownership)
                self._hold_owned_quota(ownership)
                await self._hold_owned_budget(ownership)
                await tracker.transition(
                    InvocationState.UNKNOWN,
                    metadata={"provider_handoff": True},
                )
                return self._error_result(
                    request,
                    tracker.current,
                    ErrorCode.UNCERTAIN_OUTCOME,
                    attempts=attempts,
                    fingerprint=fingerprint,
                )
            self._release_owned_lease(ownership)
        self._release_owned_breaker_permit(ownership)
        self._record_success(candidate, request.operation)
        if canonical.spec.asynchronous:
            self._hold_owned_quota(ownership)
            await self._hold_owned_budget(ownership)
        elif outcome.actual_cost_units is None:
            self._hold_owned_quota(ownership)
            await self._hold_owned_budget(ownership)
        else:
            self._settle_owned_quota(ownership, actual_units=outcome.actual_cost_units)
            await self._settle_owned_budget(
                ownership,
                actual_units=outcome.actual_cost_units,
            )
        await tracker.transition(InvocationState.SUCCEEDED)
        return InvocationResult(
            request_id=request.request_id,
            state=tracker.current,
            attempts=attempts,
            fingerprint=fingerprint,
            data=outcome.data,
            provider_resource_id=outcome.provider_resource_id,
        )

    async def _resolve_affinity(
        self,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
    ) -> ResourceAffinity | None:
        reference = canonical.resource_reference
        if reference is None:
            return None
        affinity = await self.affinities.get(
            service_id=request.service_id,
            resource_type=reference.resource_type,
            provider_resource_id=reference.provider_resource_id,
            owner_session_id=session.session_id,
            owner_workspace_id=session.workspace_id,
            owner_root_run_id=session.root_run_id,
        )
        if affinity is None:
            raise AffinityUnavailableError("asynchronous resource ownership could not be verified")
        if (
            affinity.owner_session_id != session.session_id
            or affinity.owner_workspace_id != session.workspace_id
            or affinity.owner_root_run_id != session.root_run_id
            or affinity.owner_root_run_id != request.root_run_id
        ):
            raise AffinityUnavailableError(
                "asynchronous resource belongs to a different execution owner"
            )
        return affinity

    async def _emergency_projection(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        affinity: ResourceAffinity | None,
    ) -> EmergencyUnlockProjection | None:
        if self.emergency is None or affinity is not None:
            return None
        status = await self.emergency.status()
        if status.state is not EmergencyUnlockState.ACTIVE:
            return None
        exact_authority = (
            status.service_id == request.service_id
            and status.session_id == str(session.session_id)
            and status.root_run_id == str(session.root_run_id)
            and status.root_run_id == str(request.root_run_id)
            and status.pool_id is not None
            and status.pool_name is not None
        )
        if not exact_authority:
            return None
        assert status.pool_name is not None
        return await self.emergency.project(
            service_id=request.service_id,
            pool_name=status.pool_name,
            session_id=str(session.session_id),
            root_run_id=str(session.root_run_id),
            automatic=False,
        )

    @staticmethod
    def _emergency_routing_plan(
        *,
        projection: EmergencyUnlockProjection,
        operation: str,
        estimated_cost_units: int,
        unit: str,
    ) -> RoutingPlan:
        pool_id = PoolId(projection.pool_id)
        principal_id = PrincipalId(projection.principal_id)
        quota_scope_id = QuotaScopeId(projection.quota_scope_id)
        candidate = RouteCandidate(
            pool_id=pool_id,
            pool_name=projection.pool_name,
            service_id=projection.service_id,
            scope=QuotaScopeSnapshot(
                quota_scope_id=quota_scope_id,
                principal_id=principal_id,
                service_id=projection.service_id,
                unit=unit,
                last_known_remaining_units=projection.remaining_credits,
            ),
            credential=RoutingCredential(
                credential_id=CredentialId(projection.credential_id),
                principal_id=principal_id,
                quota_scope_id=quota_scope_id,
                generation=1,
                expires_at_ms=projection.expires_at_ms,
            ),
            priority=0,
            cost_rank=0,
        )
        return RoutingPlan(
            pool_id=pool_id,
            pool_name=projection.pool_name,
            service_id=projection.service_id,
            operation=operation,
            estimated_cost_units=estimated_cost_units,
            unit=unit,
            automatic_failover_within_pool=False,
            candidates=(candidate,),
        )

    def _policy_context(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        canonical: CanonicalOperation,
        fingerprint: str,
        estimated_cost_units: int,
        pool_name: str,
        affinity: ResourceAffinity | None,
        automatic_pool_selection: bool,
    ) -> PolicyContext:
        service_key = BreakerKey(BreakerScopeType.SERVICE, request.service_id)
        return PolicyContext(
            client_class=session.client_class,
            client_id=str(session.client_id),
            session_id=str(session.session_id),
            root_run_id=str(session.root_run_id),
            workspace_id=str(session.workspace_id),
            service=request.service_id,
            operation=request.operation,
            purpose=request.purpose,
            data_classifications=request.data_classifications,
            input_payload=canonical.canonical_input,
            request_fingerprint=fingerprint,
            estimated_cost=float(estimated_cost_units),
            proposed_pool=pool_name,
            request_count_remaining=session.request_count_remaining,
            credit_budget_remaining=float(session.credit_budget_remaining_units),
            now=datetime_from_utc_ms(self.clock.now_ms()),
            canonical_target=canonical.canonical_target,
            allowed_capabilities=session.allowed_capabilities,
            service_kill_switch_open=session.service_kill_switch_open,
            circuit_breaker_open=not self.circuit_breakers.is_available(
                service_key,
                now_ms=self.clock.now_ms(),
            ),
            feed_set_authorized=session.feed_set_authorized,
            schedule_open=session.schedule_open,
            resource_ownership_verified=affinity is not None,
            automatic_pool_selection=automatic_pool_selection,
        )

    def _record_success(self, candidate: RouteCandidate, operation: str) -> None:
        for key in self._breaker_keys(candidate, operation):
            self.circuit_breakers.record_success(key)

    def _record_failure(
        self,
        candidate: RouteCandidate,
        operation: str,
        outcome: ClassifiedProviderOutcome,
    ) -> None:
        now_ms = self.clock.now_ms()
        if outcome.error_class is ProviderErrorClass.UNAUTHORIZED:
            self.circuit_breakers.record_failure(
                BreakerKey(
                    BreakerScopeType.CREDENTIAL,
                    str(candidate.credential.credential_id),
                ),
                now_ms=now_ms,
                error_class=outcome.error_class,
                force_open=True,
            )
            return
        if outcome.error_class in {
            ProviderErrorClass.QUOTA_EXHAUSTED,
            ProviderErrorClass.RATE_LIMITED,
        }:
            open_until_ms: int | None = None
            if outcome.retry_after_seconds is not None:
                open_until_ms = now_ms + max(
                    1,
                    math.ceil(outcome.retry_after_seconds * 1_000),
                )
            self.circuit_breakers.record_failure(
                BreakerKey(
                    BreakerScopeType.QUOTA_SCOPE,
                    str(candidate.scope.quota_scope_id),
                ),
                now_ms=now_ms,
                error_class=outcome.error_class,
                open_until_ms=open_until_ms,
                force_open=True,
            )
            return
        self.circuit_breakers.record_failure(
            BreakerKey(BreakerScopeType.PROVIDER_OPERATION, operation),
            now_ms=now_ms,
            error_class=outcome.error_class,
        )

    @staticmethod
    def _breaker_keys(
        candidate: RouteCandidate,
        operation: str,
    ) -> tuple[BreakerKey, ...]:
        return (
            BreakerKey(BreakerScopeType.SERVICE, candidate.service_id),
            BreakerKey(BreakerScopeType.PROVIDER_OPERATION, operation),
            BreakerKey(
                BreakerScopeType.QUOTA_SCOPE,
                str(candidate.scope.quota_scope_id),
            ),
            BreakerKey(
                BreakerScopeType.CREDENTIAL,
                str(candidate.credential.credential_id),
            ),
        )

    async def _finalize_exceptional_execution(
        self,
        ownership: _ExecutionOwnership,
        *,
        tracker: _StateTracker,
        terminal: InvocationState,
        ambiguous: bool,
    ) -> None:
        """Resolve every owned resource even when one cleanup action fails."""

        errors: list[Exception] = []

        def run_sync(action: Callable[[], None]) -> None:
            try:
                action()
            except Exception as error:  # cleanup continues for remaining resources
                errors.append(error)

        async def run_async(action: Callable[[], Awaitable[None]]) -> None:
            try:
                await action()
            except Exception as error:  # cleanup continues for remaining resources
                errors.append(error)

        run_sync(lambda: self._release_owned_lease(ownership))
        await run_async(lambda: self._release_owned_permit(ownership))
        run_sync(lambda: self._release_owned_breaker_permit(ownership))

        outcome = ownership.outcome
        known_actual: int | None = None
        outcome_known = not ambiguous
        if ambiguous and outcome is not None:
            if outcome.succeeded:
                outcome_known = (
                    outcome.actual_cost_units is not None and not ownership.defer_success_accounting
                )
                if outcome_known:
                    known_actual = outcome.actual_cost_units
            elif not outcome.submission_may_have_occurred:
                outcome_known = True
                known_actual = outcome.actual_cost_units or 0
        elif outcome_known:
            known_actual = 0

        if outcome_known:
            actual_units = known_actual or 0
            run_sync(
                lambda: self._settle_owned_quota(
                    ownership,
                    actual_units=actual_units,
                )
            )
            await run_async(
                lambda: self._settle_owned_budget(
                    ownership,
                    actual_units=actual_units,
                )
            )
        else:
            run_sync(lambda: self._hold_owned_quota(ownership))
            await run_async(lambda: self._hold_owned_budget(ownership))

        if tracker.current is not terminal and INVOCATION_TRANSITIONS.can_transition(
            tracker.current,
            terminal,
        ):
            await run_async(
                lambda: tracker.transition(
                    terminal,
                    metadata={"provider_handoff": True} if ambiguous else None,
                )
            )
        if errors:
            raise ExceptionGroup("invocation cleanup failed", errors)

    def _replace_owned_reservation(
        self,
        ownership: _ExecutionOwnership,
        reservation: QuotaReservation | None,
    ) -> None:
        if not ownership.quota_resolved:
            raise RuntimeError("cannot replace an unresolved quota reservation")
        ownership.reservation = reservation
        ownership.quota_resolved = reservation is None

    def _adopt_atomically_replaced_reservation(
        self,
        ownership: _ExecutionOwnership,
        reservation: QuotaReservation | None,
    ) -> None:
        if ownership.quota_resolved or ownership.reservation is None:
            raise RuntimeError("atomic replacement requires an owned reservation")
        if reservation is None:
            raise RuntimeError("an atomic replacement must return a reservation")
        ownership.reservation = reservation
        ownership.quota_resolved = False

    async def _fail_if_quota_expired_before_handoff(
        self,
        *,
        tracker: _StateTracker,
        request: InvocationRequest,
        fingerprint: object,
        ownership: _ExecutionOwnership,
        attempts: int,
    ) -> InvocationResult | None:
        reservation = ownership.reservation
        if (
            ownership.quota_resolved
            or reservation is None
            or reservation.expires_at_ms > self.clock.now_ms()
        ):
            return None
        self._release_owned_breaker_permit(ownership)
        self._settle_owned_quota(ownership, actual_units=0)
        await self._settle_owned_budget(ownership, actual_units=0)
        await tracker.transition(
            InvocationState.QUOTA_EXHAUSTED,
            metadata={"provider_handoff": False, "quota_expired": True},
        )
        await self._release_owned_permit(ownership)
        return self._error_result(
            request,
            tracker.current,
            ErrorCode.QUOTA_EXHAUSTED,
            retryable=True,
            retry_after_seconds=60,
            attempts=attempts,
            fingerprint=fingerprint,
        )

    def _release_owned_breaker_permit(
        self,
        ownership: _ExecutionOwnership,
    ) -> None:
        permit = ownership.breaker_permit
        if permit is None:
            return
        if not self.circuit_breakers.release(permit):
            raise RuntimeError("circuit-breaker permit release was rejected")
        ownership.breaker_permit = None

    def _settle_owned_quota(
        self,
        ownership: _ExecutionOwnership,
        *,
        actual_units: int,
    ) -> None:
        if ownership.quota_resolved:
            return
        self._settle_quota_known(ownership.reservation, actual_units=actual_units)
        ownership.quota_resolved = True

    def _hold_owned_quota(self, ownership: _ExecutionOwnership) -> None:
        if ownership.quota_resolved:
            return
        self._hold_quota(ownership.reservation)
        ownership.quota_resolved = True

    async def _settle_owned_budget(
        self,
        ownership: _ExecutionOwnership,
        *,
        actual_units: int,
    ) -> None:
        errors: list[Exception] = []
        if not ownership.budget_resolved:
            try:
                await self._release_budget(ownership.budget, actual_units=actual_units)
            except Exception as error:
                errors.append(error)
            else:
                ownership.budget_resolved = True
        if not ownership.emergency_resolved:
            if self.emergency is None or ownership.emergency_permit is None:
                errors.append(RuntimeError("emergency accounting ownership is incomplete"))
            else:
                try:
                    await self.emergency.settle(
                        ownership.emergency_permit,
                        actual_credits=actual_units,
                        outcome_known=True,
                    )
                except Exception as error:
                    errors.append(error)
                else:
                    ownership.emergency_resolved = True
        if errors:
            raise ExceptionGroup("budget settlement failed", errors)

    async def _hold_owned_budget(self, ownership: _ExecutionOwnership) -> None:
        errors: list[Exception] = []
        if not ownership.budget_resolved:
            try:
                await self._hold_budget(ownership.budget)
            except Exception as error:
                errors.append(error)
            else:
                ownership.budget_resolved = True
        if not ownership.emergency_resolved:
            if self.emergency is None or ownership.emergency_permit is None:
                errors.append(RuntimeError("emergency accounting ownership is incomplete"))
            else:
                try:
                    await self.emergency.settle(
                        ownership.emergency_permit,
                        actual_credits=None,
                        outcome_known=False,
                    )
                except Exception as error:
                    errors.append(error)
                else:
                    ownership.emergency_resolved = True
        if errors:
            raise ExceptionGroup("budget settlement failed", errors)

    async def _release_owned_permit(
        self,
        ownership: _ExecutionOwnership,
    ) -> None:
        permit = ownership.permit
        if permit is None:
            return
        if not await self.scheduler.release(permit):
            raise RuntimeError("scheduler rejected an owned dispatch permit")
        ownership.permit = None

    def _release_owned_lease(self, ownership: _ExecutionOwnership) -> None:
        lease = ownership.lease
        if lease is None:
            return
        if not self.credential_leases.release(lease, now_ms=self.clock.now_ms()):
            raise RuntimeError("credential lease release was rejected")
        ownership.lease = None

    def _settle_quota_known(
        self,
        reservation: QuotaReservation | None,
        *,
        actual_units: int,
    ) -> None:
        if reservation is not None:
            self.quota.reconcile_known(
                reservation,
                actual_units=actual_units,
                now_ms=self.clock.now_ms(),
            )

    def _hold_quota(self, reservation: QuotaReservation | None) -> None:
        if reservation is not None:
            self.quota.hold_for_reconciliation(
                reservation,
                now_ms=self.clock.now_ms(),
            )

    async def _release_budget(
        self,
        reservation: BudgetReservation | None,
        *,
        actual_units: int,
    ) -> None:
        if reservation is not None:
            await self.budgets.reconcile(
                reservation,
                actual_units=actual_units,
                outcome_known=True,
            )

    async def _hold_budget(self, reservation: BudgetReservation | None) -> None:
        if reservation is not None:
            await self.budgets.reconcile(
                reservation,
                actual_units=None,
                outcome_known=False,
            )

    def _provider_error_result(
        self,
        *,
        request: InvocationRequest,
        state: InvocationState,
        outcome: ClassifiedProviderOutcome,
        attempts: int,
        fingerprint: object,
    ) -> InvocationResult:
        from gatehouse.fingerprint.hmac import RequestFingerprint

        if not isinstance(fingerprint, RequestFingerprint):
            raise TypeError("fingerprint gateway returned an invalid value")
        code = {
            ProviderErrorClass.UNAUTHORIZED: ErrorCode.PROVIDER_UNAUTHORIZED,
            ProviderErrorClass.QUOTA_EXHAUSTED: ErrorCode.QUOTA_EXHAUSTED,
            ProviderErrorClass.PERMISSION_DENIED: ErrorCode.PROVIDER_PERMISSION_DENIED,
            ProviderErrorClass.TIMEOUT: ErrorCode.PROVIDER_TIMEOUT,
            ProviderErrorClass.RATE_LIMITED: ErrorCode.PROVIDER_RATE_LIMITED,
        }.get(outcome.error_class, ErrorCode.PROVIDER_UNAVAILABLE)
        retryable = code in {
            ErrorCode.QUOTA_EXHAUSTED,
            ErrorCode.PROVIDER_RATE_LIMITED,
            ErrorCode.PROVIDER_UNAVAILABLE,
        }
        retry_after = None
        if retryable:
            retry_after = max(
                1,
                math.ceil(outcome.retry_after_seconds or 1),
            )
        return self._error_result(
            request,
            state,
            code,
            retryable=retryable,
            retry_after_seconds=retry_after,
            attempts=attempts,
            fingerprint=fingerprint,
        )

    @staticmethod
    def _integer_cost(value: float) -> int:
        normalized = float(value)
        if not math.isfinite(normalized) or normalized < 0 or not normalized.is_integer():
            raise ValueError("operation estimated cost must be non-negative integer units")
        return int(normalized)

    def _attempt_event(
        self,
        *,
        request: InvocationRequest,
        candidate: RouteCandidate,
        emergency_unlock_id: str | None,
        ordinal: int,
        state: InvocationState,
        status_code: int | None = None,
        error_class: ProviderErrorClass | None = None,
        provider_request_id: str | None = None,
        estimated_cost_units: int | None = None,
        actual_cost_units: int | None = None,
        cost_unit: str | None = None,
        latency_ms: int | None = None,
        resource_type: str | None = None,
        provider_resource_id: str | None = None,
        credential_generation: int | None = None,
        pool_id: str | None = None,
    ) -> AttemptEvent:
        return AttemptEvent(
            request_id=request.request_id,
            ordinal=ordinal,
            state=state,
            occurred_at_ms=self.clock.now_ms(),
            credential_id=str(candidate.credential.credential_id),
            quota_scope_id=str(candidate.scope.quota_scope_id),
            provider_status_code=status_code,
            provider_request_id=provider_request_id,
            error_class=error_class,
            estimated_cost_units=estimated_cost_units,
            actual_cost_units=actual_cost_units,
            cost_unit=cost_unit,
            latency_ms=latency_ms,
            resource_type=resource_type,
            provider_resource_id=provider_resource_id,
            credential_generation=credential_generation,
            pool_id=(str(candidate.pool_id) if emergency_unlock_id is not None else pool_id),
            dispatch_credential_generation=(
                None if emergency_unlock_id is not None else candidate.credential.generation
            ),
            dispatch_pool_id=(None if emergency_unlock_id is not None else str(candidate.pool_id)),
            emergency_unlock_id=emergency_unlock_id,
        )

    @staticmethod
    def _error_result(
        request: InvocationRequest,
        state: InvocationState,
        code: ErrorCode,
        *,
        retryable: bool | None = None,
        retry_after_seconds: int | None = None,
        policy_rule_id: str | None = None,
        attempts: int = 0,
        fingerprint: object | None = None,
        approval_id: str | None = None,
    ) -> InvocationResult:
        from gatehouse.fingerprint.hmac import RequestFingerprint

        if fingerprint is not None and not isinstance(fingerprint, RequestFingerprint):
            raise TypeError("fingerprint gateway returned an invalid value")
        error = make_error(
            code,
            retryable=retryable,
            retry_after_seconds=retry_after_seconds,
            request_id=request.request_id,
            policy_rule_id=policy_rule_id,
        )
        detail: ErrorDetail = error.detail
        return InvocationResult(
            request_id=request.request_id,
            state=state,
            attempts=attempts,
            fingerprint=fingerprint,
            error=detail,
            approval_id=approval_id,
        )
