"""Coordinator-backed observations for durable provider jobs."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Mapping
from typing import Protocol

from gatehouse.config import ClientProfileConfig
from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock, require_utc_ms
from gatehouse.core.errors import ErrorDetail
from gatehouse.core.ids import ClientId, RequestId
from gatehouse.core.provider_numbers import SQLITE_INT64_MAX
from gatehouse.core.states import InvocationState
from gatehouse.invocations import InvocationRequest, InvocationResult, InvocationSession
from gatehouse.policy import ClientClass
from gatehouse.scheduler import PriorityClass

from .models import JobRecord, JobState
from .supervisor import CANCEL_RECONCILIATION_STATUS, JobObservation

_LIVE_PROVIDER_STATUSES = frozenset(
    {"accepted", "pending", "queued", "running", "scraping", "processing"}
)
_SUCCESS_PROVIDER_STATUSES = frozenset({"completed", "complete", "succeeded"})
_FAILED_PROVIDER_STATUSES = frozenset({"failed", "error"})
_CANCELLED_PROVIDER_STATUSES = frozenset({"cancelled", "canceled"})


class AuthenticatedInvocationCoordinator(Protocol):
    async def invoke_authenticated(
        self,
        request: InvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult: ...


class JobSessionResolver(Protocol):
    def resolve(self, job: JobRecord) -> InvocationSession: ...


class JobAuthorityUnavailable(RuntimeError):
    """The local facts needed to supervise an owned job are unavailable."""


class SqliteJobSessionResolver:
    """Reconstruct a minimal trusted session from an exact durable job owner."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        client_profiles: Mapping[str, ClientProfileConfig],
    ) -> None:
        self._connection = connection
        self._client_profiles = dict(client_profiles)

    def resolve(self, job: JobRecord) -> InvocationSession:
        row = self._connection.execute(
            """
            SELECT s.client_id, s.session_id, s.workspace_id, s.token_epoch,
                   s.revocation_epoch, rr.root_run_id,
                   p.alias AS pool_alias
              FROM sessions AS s
              JOIN root_runs AS rr ON rr.session_id = s.session_id
              JOIN pools AS p ON p.pool_id = ? AND p.service_id = ?
             WHERE s.session_id = ? AND s.workspace_id = ? AND rr.root_run_id = ?
            """,
            (
                str(job.pool_id),
                job.service_id,
                str(job.owner.session_id),
                str(job.owner.workspace_id),
                str(job.owner.root_run_id),
            ),
        ).fetchone()
        if row is None:
            raise JobAuthorityUnavailable("durable job owner cannot be reconstructed")
        try:
            client_id = ClientId(str(row["client_id"]))
        except (TypeError, ValueError) as error:
            raise JobAuthorityUnavailable("durable job client authority is invalid") from error
        profile = self._client_profiles.get(str(client_id))
        if profile is None:
            raise JobAuthorityUnavailable("durable job client profile is unavailable")
        pool_alias = str(row["pool_alias"])
        if not pool_alias:
            raise JobAuthorityUnavailable("durable job pool alias is invalid")
        try:
            priority = PriorityClass(profile.client.default_priority.upper())
        except ValueError as error:
            raise JobAuthorityUnavailable("durable job priority is invalid") from error
        unattended = profile.client.unattended
        return InvocationSession(
            session_id=job.owner.session_id,
            client_id=client_id,
            root_run_id=job.owner.root_run_id,
            workspace_id=job.owner.workspace_id,
            client_class=(ClientClass.UNATTENDED if unattended else ClientClass.INTERACTIVE),
            allowed_capabilities=frozenset(
                {
                    "firecrawl.crawl.status",
                    "firecrawl.crawl.cancel",
                }
            ),
            pool_bindings={job.service_id: pool_alias},
            request_count_remaining=1,
            credit_budget_remaining_units=0,
            approval_mode=profile.client.approval_mode,
            priority=priority,
            feed_set_authorized=unattended,
            request_limit=None,
            internal_resource_reconciliation=True,
            token_epoch=int(row["token_epoch"]),
            revocation_epoch=int(row["revocation_epoch"]),
        )


class CoordinatorJobObservationGateway:
    """Use the normal policy/routing/affinity pipeline for status and cancellation."""

    def __init__(
        self,
        *,
        coordinator: AuthenticatedInvocationCoordinator,
        sessions: JobSessionResolver,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
        poll_interval_ms: int = 30_000,
        request_timeout_ms: int = 30_000,
    ) -> None:
        if not 1_000 <= poll_interval_ms <= 300_000:
            raise ValueError("job provider poll interval is outside the supported bound")
        if not 1_000 <= request_timeout_ms <= 300_000:
            raise ValueError("job observation timeout is outside the supported bound")
        self._coordinator = coordinator
        self._sessions = sessions
        self._clock = clock
        self._poll_interval_ms = poll_interval_ms
        self._request_timeout_ms = request_timeout_ms

    async def observe(self, job: JobRecord) -> JobObservation:
        if (
            job.service_id != "firecrawl"
            or job.resource_type != "crawl"
            or job.operation != "firecrawl.crawl.start"
        ):
            return JobObservation(target_state=JobState.UNKNOWN)
        try:
            session = self._sessions.resolve(job)
        except JobAuthorityUnavailable:
            return JobObservation(target_state=JobState.UNKNOWN)

        reconcile_cancel = job.provider_status == CANCEL_RECONCILIATION_STATUS
        cancelling = job.cancel_requested_at_ms is not None
        operation = (
            "firecrawl.crawl.cancel"
            if cancelling and not reconcile_cancel
            else "firecrawl.crawl.status"
        )
        now_ms = self._clock.now_ms()
        remaining_ms = job.maximum_runtime_at_ms - now_ms
        if remaining_ms <= 0:
            return JobObservation(target_state=JobState.UNKNOWN)
        request = InvocationRequest(
            request_id=RequestId.new(clock=self._clock),
            access_token=None,
            root_run_id=job.owner.root_run_id,
            service_id=job.service_id,
            operation=operation,
            input_payload={"provider_job_id": job.provider_resource_id},
            purpose=(
                "opening_monitoring"
                if session.client_class is ClientClass.UNATTENDED
                else "active_job_verification"
            ),
            data_classifications=frozenset({"public_job_data"}),
            queue_deadline_ms=require_utc_ms(now_ms + min(self._request_timeout_ms, remaining_ms)),
        )
        try:
            async with asyncio.timeout(remaining_ms / 1_000):
                result = await self._coordinator.invoke_authenticated(request, session)
        except TimeoutError:
            return JobObservation(target_state=JobState.UNKNOWN)
        if operation.endswith(".cancel"):
            return self._cancel_observation(result)
        return self._status_observation(result, cancelling=cancelling)

    def _cancel_observation(self, result: InvocationResult) -> JobObservation:
        # A successful DELETE confirms cancellation intent, not final billable
        # usage.  Always reconcile through status before terminalizing the job.
        return JobObservation(
            target_state=JobState.CANCELLING,
            provider_status=CANCEL_RECONCILIATION_STATUS,
            poll_after_ms=self._retry_delay(result.error),
        )

    def _status_observation(
        self,
        result: InvocationResult,
        *,
        cancelling: bool,
    ) -> JobObservation:
        live_state = JobState.CANCELLING if cancelling else JobState.RUNNING
        if result.state is not InvocationState.SUCCEEDED or result.error is not None:
            return JobObservation(
                target_state=live_state,
                poll_after_ms=self._retry_delay(result.error),
            )
        data = result.data
        raw_status = data.get("status") if isinstance(data, Mapping) else None
        status = raw_status.casefold() if isinstance(raw_status, str) else None
        actual_units = self._actual_units(data)
        reconciliation_status = CANCEL_RECONCILIATION_STATUS if cancelling else status
        if status in _SUCCESS_PROVIDER_STATUSES:
            if actual_units is None:
                return JobObservation(
                    target_state=live_state,
                    provider_status=reconciliation_status,
                    poll_after_ms=self._poll_interval_ms,
                )
            return JobObservation(
                target_state=JobState.SUCCEEDED,
                provider_status=status,
                actual_cost_units=actual_units,
            )
        if status in _FAILED_PROVIDER_STATUSES:
            if actual_units is None:
                return JobObservation(
                    target_state=live_state,
                    provider_status=reconciliation_status,
                    poll_after_ms=self._poll_interval_ms,
                )
            return JobObservation(
                target_state=JobState.FAILED,
                provider_status=status,
                actual_cost_units=actual_units,
            )
        if status in _CANCELLED_PROVIDER_STATUSES:
            if actual_units is None:
                return JobObservation(
                    target_state=live_state,
                    provider_status=reconciliation_status,
                    poll_after_ms=self._poll_interval_ms,
                )
            return JobObservation(
                target_state=JobState.CANCELLED,
                provider_status=status,
                actual_cost_units=actual_units,
            )
        if status in _LIVE_PROVIDER_STATUSES:
            return JobObservation(
                target_state=live_state,
                provider_status=reconciliation_status,
                poll_after_ms=self._poll_interval_ms,
            )
        return JobObservation(
            target_state=live_state,
            poll_after_ms=self._poll_interval_ms,
        )

    def _retry_delay(self, error: ErrorDetail | None) -> int:
        if error is None or error.retry_after_seconds is None:
            return self._poll_interval_ms
        return min(300_000, max(1_000, error.retry_after_seconds * 1_000))

    @staticmethod
    def _actual_units(data: object) -> int | None:
        if not isinstance(data, Mapping):
            return None
        value = data.get("creditsUsed")
        if type(value) is not int or not 0 <= value <= SQLITE_INT64_MAX:
            return None
        return value
