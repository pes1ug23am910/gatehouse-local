"""Explicit dependency protocols for the invocation orchestration boundary."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from gatehouse.core.ids import QuotaScopeId, RequestId
from gatehouse.database.runaway import RunawayAdmission
from gatehouse.fingerprint.hmac import RequestFingerprint
from gatehouse.fingerprint.runaway import RunawayDecision
from gatehouse.fingerprint.singleflight import CancellationDecision, SingleFlightHandle
from gatehouse.policy import PolicyContext, PolicyResult
from gatehouse.policy.sensitive import InspectionResult
from gatehouse.providers import ProviderRequest, ProviderResponse
from gatehouse.routing import (
    CredentialDispatchLease,
    QuotaReservation,
    ReservationGrant,
    ResourceAffinity,
    RouteCandidate,
    RoutingPlan,
)
from gatehouse.scheduler import DispatchPermit, QueueTicket, WorkItem

from .models import (
    ApprovalResolution,
    AttemptEvent,
    BudgetReservation,
    CanonicalOperation,
    ClassifiedProviderOutcome,
    InvocationRequest,
    InvocationSession,
    InvocationStartEvent,
    InvocationStateEvent,
    InvocationValidatedEvent,
    PendingApprovalProbe,
    ValidatedOperation,
)


class SessionGateway(Protocol):
    async def authenticate(self, request: InvocationRequest) -> InvocationSession: ...

    async def revalidate(self, session: InvocationSession) -> bool: ...


class OperationGateway(Protocol):
    def validate(
        self,
        service_id: str,
        operation: str,
        payload: object,
    ) -> ValidatedOperation: ...

    def canonicalize(self, validated: ValidatedOperation) -> CanonicalOperation: ...

    def build_request(
        self,
        canonical: CanonicalOperation,
        *,
        credential_id: str,
        credential_generation: int,
    ) -> ProviderRequest: ...

    def classify_response(
        self,
        operation: str,
        response: ProviderResponse,
    ) -> ClassifiedProviderOutcome: ...


class FingerprintGateway(Protocol):
    def calculate(
        self,
        *,
        session: InvocationSession,
        request: InvocationRequest,
        canonical: CanonicalOperation,
    ) -> RequestFingerprint: ...


class SensitiveInspector(Protocol):
    def inspect(self, payload: object) -> InspectionResult: ...


class RunawayGateway(Protocol):
    def record_arrival(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> RunawayDecision: ...

    def retry_after_ms(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> int | None: ...


class RunawayQuarantineGateway(Protocol):
    async def admit(
        self,
        *,
        session_id: str,
        root_run_id: str,
        request_id: str,
        service_id: str,
        operation: str,
        fingerprint: RequestFingerprint,
        estimated_cost_units: int,
        now_ms: int,
    ) -> RunawayAdmission: ...

    async def settle_permit(self, permit_id: str, *, now_ms: int) -> bool: ...


class SingleFlightGateway(Protocol):
    async def join_or_create(
        self,
        *,
        session_id: str,
        request_id: str,
        fingerprint: RequestFingerprint,
        sharing_scope: str | None = None,
    ) -> SingleFlightHandle: ...

    async def complete(self, group_id: int, value: Any) -> bool: ...

    async def fail(self, group_id: int, error: BaseException) -> bool: ...

    async def cancel(self, handle: SingleFlightHandle) -> CancellationDecision: ...


class PolicyGateway(Protocol):
    def evaluate(self, context: PolicyContext) -> PolicyResult: ...


class ApprovalGateway(Protocol):
    async def resolve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> ApprovalResolution: ...


class PendingApprovalProbeGateway(Protocol):
    async def probe_pending_approval(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> PendingApprovalProbe: ...


class BudgetGateway(Protocol):
    async def reserve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        amount_units: int,
        unit: str,
    ) -> BudgetReservation: ...

    async def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        actual_units: int | None,
        outcome_known: bool,
    ) -> None: ...


class RoutingGateway(Protocol):
    def plan(
        self,
        *,
        service_id: str,
        operation: str,
        pool_name: str,
        estimated_cost_units: int,
        unit: str,
        now_ms: int,
        affinity: ResourceAffinity | None = None,
        automatic: bool = True,
        reconciliation: bool = False,
    ) -> RoutingPlan: ...


class QuotaGateway(Protocol):
    def reserve(
        self,
        *,
        plan: RoutingPlan,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
        exclude_scope_ids: Iterable[QuotaScopeId] = (),
    ) -> ReservationGrant: ...

    def reconcile_known(
        self,
        reservation: QuotaReservation,
        *,
        actual_units: int,
        now_ms: int,
    ) -> QuotaReservation: ...

    def replace_expired(
        self,
        reservation: QuotaReservation,
        *,
        plan: RoutingPlan,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
        exclude_scope_ids: Iterable[QuotaScopeId] = (),
    ) -> ReservationGrant: ...

    def hold_for_reconciliation(
        self,
        reservation: QuotaReservation,
        *,
        now_ms: int,
    ) -> QuotaReservation: ...


class SchedulerGateway(Protocol):
    async def enqueue(self, item: WorkItem) -> QueueTicket: ...

    async def enqueue_unless_quota_scope_saturated(self, item: WorkItem) -> QueueTicket: ...

    async def release(self, permit: DispatchPermit) -> bool: ...


class CredentialLeaseGateway(Protocol):
    def acquire(
        self,
        *,
        candidate: RouteCandidate,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
        exact_affinity: bool = False,
        reconciliation: bool = False,
    ) -> CredentialDispatchLease: ...

    def release(self, lease: CredentialDispatchLease, *, now_ms: int) -> bool: ...


class InvocationRepository(Protocol):
    @property
    def transaction_active(self) -> bool: ...

    async def begin_invocation(self, event: InvocationStartEvent) -> None: ...

    async def record_validated(self, event: InvocationValidatedEvent) -> None: ...

    async def record_state(self, event: InvocationStateEvent) -> None: ...

    async def record_attempt(self, event: AttemptEvent) -> None: ...


class ProviderTransport(Protocol):
    """Transport leases secret material internally, then performs the only network I/O."""

    async def send(self, request: ProviderRequest) -> ProviderResponse: ...
