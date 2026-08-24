"""Bounded, default-disabled scheduling for authenticated quota observations."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from gatehouse.admin.models import CredentialValidationResult
from gatehouse.admin.provider_validation import (
    CredentialValidationBusy,
    CredentialValidationPersistenceError,
    CredentialValidationProviderFailure,
    CredentialValidationUnavailable,
)
from gatehouse.database.connection import transaction
from gatehouse.database.quota_state import SqliteQuotaStateRepository
from gatehouse.providers.base import ProviderErrorClass

_SOURCE = "scheduled-firecrawl-credit-observation"
_ACTOR = "system-credit-observer"
_MAXIMUM_LOOP_POLL_MS = 60_000


class ScheduledObservationCollector(Protocol):
    """One fixed provider collector with no generic request surface."""

    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult: ...


@dataclass(frozen=True, slots=True)
class ObservationClaim:
    schedule_id: str
    quota_scope_id: str
    credential_id: str
    credential_generation: int
    schedule_generation: int
    freshness_ttl_ms: int


class SqliteObservationScheduleStore:
    """Claim and settle due observations without holding a transaction over I/O."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def claim_due(self, *, now_ms: int, limit: int) -> tuple[ObservationClaim, ...]:
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("observation time is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise ValueError("observation claim limit is invalid")
        claims: list[ObservationClaim] = []
        with transaction(self.connection, "IMMEDIATE"):
            rows = self.connection.execute(
                """
                SELECT schedule.schedule_id, schedule.quota_scope_id,
                       schedule.observer_credential_id,
                       schedule.observer_credential_generation,
                       schedule.interval_ms, schedule.freshness_ttl_ms,
                       schedule.generation
                  FROM quota_observation_schedules AS schedule
                  JOIN quota_scopes AS scope
                    ON scope.quota_scope_id = schedule.quota_scope_id
                  JOIN principals AS principal
                    ON principal.principal_id = scope.principal_id
                  JOIN credentials AS credential
                    ON credential.credential_id = schedule.observer_credential_id
                   AND credential.quota_scope_id = schedule.quota_scope_id
                   AND credential.generation = schedule.observer_credential_generation
                 WHERE schedule.state = 'ENABLED'
                   AND (schedule.next_due_at_ms IS NULL OR schedule.next_due_at_ms <= ?)
                   AND principal.service_id = 'firecrawl' AND principal.enabled = 1
                   AND scope.state NOT IN ('DISABLED', 'QUARANTINED')
                   AND credential.state = 'HEALTHY'
                   AND credential.credential_role IN ('WORKLOAD', 'OBSERVER')
                 ORDER BY COALESCE(schedule.next_due_at_ms, 0),
                          schedule.quota_scope_id, schedule.schedule_id
                 LIMIT ?
                """,
                (now_ms, limit),
            ).fetchall()
            for row in rows:
                credential_id = row["observer_credential_id"]
                credential_generation = row["observer_credential_generation"]
                if credential_id is None or credential_generation is None:
                    continue
                old_generation = int(row["generation"])
                new_generation = old_generation + 1
                updated = self.connection.execute(
                    """
                    UPDATE quota_observation_schedules
                       SET generation = ?, last_started_at_ms = ?,
                           next_due_at_ms = ?, updated_at_ms = ?
                     WHERE schedule_id = ? AND state = 'ENABLED' AND generation = ?
                    """,
                    (
                        new_generation,
                        now_ms,
                        now_ms + int(row["interval_ms"]),
                        now_ms,
                        str(row["schedule_id"]),
                        old_generation,
                    ),
                )
                if updated.rowcount != 1:
                    continue
                claims.append(
                    ObservationClaim(
                        schedule_id=str(row["schedule_id"]),
                        quota_scope_id=str(row["quota_scope_id"]),
                        credential_id=str(credential_id),
                        credential_generation=int(credential_generation),
                        schedule_generation=new_generation,
                        freshness_ttl_ms=int(row["freshness_ttl_ms"]),
                    )
                )
        return tuple(claims)

    def complete(
        self,
        claim: ObservationClaim,
        *,
        snapshot_id: str,
        completed_at_ms: int,
    ) -> bool:
        if not snapshot_id or len(snapshot_id) > 160:
            raise ValueError("observation snapshot identifier is invalid")
        if completed_at_ms < 0:
            raise ValueError("observation completion time is invalid")
        with transaction(self.connection, "IMMEDIATE"):
            updated = self.connection.execute(
                """
                UPDATE quota_observation_schedules
                   SET last_completed_at_ms = ?, last_snapshot_id = ?,
                       consecutive_failures = 0, last_error_class = NULL,
                       updated_at_ms = ?
                 WHERE schedule_id = ? AND generation = ?
                """,
                (
                    completed_at_ms,
                    snapshot_id,
                    completed_at_ms,
                    claim.schedule_id,
                    claim.schedule_generation,
                ),
            )
        return updated.rowcount == 1

    def fail(
        self,
        claim: ObservationClaim,
        *,
        error_class: str,
        completed_at_ms: int,
    ) -> bool:
        if (
            not error_class
            or len(error_class) > 64
            or not error_class.isascii()
            or completed_at_ms < 0
        ):
            raise ValueError("observation failure evidence is invalid")
        with transaction(self.connection, "IMMEDIATE"):
            updated = self.connection.execute(
                """
                UPDATE quota_observation_schedules
                   SET last_completed_at_ms = ?,
                       consecutive_failures = consecutive_failures + 1,
                       last_error_class = ?, updated_at_ms = ?
                 WHERE schedule_id = ? AND generation = ?
                """,
                (
                    completed_at_ms,
                    error_class,
                    completed_at_ms,
                    claim.schedule_id,
                    claim.schedule_generation,
                ),
            )
        return updated.rowcount == 1


class FirecrawlCreditObservationLoop:
    """Run fixed Firecrawl credit observations under explicit bounded policy."""

    def __init__(
        self,
        *,
        store: SqliteObservationScheduleStore,
        collector: ScheduledObservationCollector,
        quota_state: SqliteQuotaStateRepository,
        now_ms: Callable[[], int],
        interval_ms: int,
        maximum_accounts_per_cycle: int,
        maximum_concurrency: int,
    ) -> None:
        if isinstance(interval_ms, bool) or not 60_000 <= interval_ms <= 604_800_000:
            raise ValueError("observation interval is outside its bound")
        if not 1 <= maximum_accounts_per_cycle <= 1_000:
            raise ValueError("observation account bound is invalid")
        if not 1 <= maximum_concurrency <= 8:
            raise ValueError("observation concurrency bound is invalid")
        self._store = store
        self._collector = collector
        self._quota_state = quota_state
        self._now_ms = now_ms
        self._interval_ms = interval_ms
        self._maximum_accounts = maximum_accounts_per_cycle
        self._semaphore = asyncio.Semaphore(maximum_concurrency)

    async def run_once(self) -> int:
        claims = self._store.claim_due(
            now_ms=self._safe_now(),
            limit=self._maximum_accounts,
        )
        if not claims:
            return 0
        results = await asyncio.gather(*(self._observe(claim) for claim in claims))
        return sum(results)

    async def _observe(self, claim: ObservationClaim) -> int:
        async with self._semaphore:
            result: CredentialValidationResult | None = None
            failure_class: str | None = None
            try:
                result = await self._collector.observe_credential(
                    claim.credential_id,
                    expected_generation=claim.credential_generation,
                    actor_id=_ACTOR,
                    source=_SOURCE,
                    freshness_ttl_ms=claim.freshness_ttl_ms,
                )
            except asyncio.CancelledError:
                raise
            except CredentialValidationProviderFailure as error:
                failure_class = error.error_class.value
                if error.error_class is ProviderErrorClass.QUOTA_EXHAUSTED:
                    self._quota_state.mark_definitive_exhaustion(
                        quota_scope_id=claim.quota_scope_id,
                        now_ms=self._safe_now(),
                        credential_id=claim.credential_id,
                        credential_generation=claim.credential_generation,
                        reason_code="OBSERVATION_QUOTA_EXHAUSTED",
                    )
                _scrub_exception(error)
            except CredentialValidationBusy as error:
                failure_class = "BUSY"
                _scrub_exception(error)
            except CredentialValidationUnavailable as error:
                failure_class = "UNAVAILABLE"
                _scrub_exception(error)
            except CredentialValidationPersistenceError:
                raise
            except Exception as error:
                failure_class = "UNKNOWN"
                _scrub_exception(error)
            completed_at_ms = self._safe_now()
            if result is not None:
                settled = self._store.complete(
                    claim,
                    snapshot_id=result.snapshot_id,
                    completed_at_ms=completed_at_ms,
                )
                return int(settled)
            assert failure_class is not None
            self._store.fail(
                claim,
                error_class=failure_class,
                completed_at_ms=completed_at_ms,
            )
            return 0

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=min(self._interval_ms, _MAXIMUM_LOOP_POLL_MS) / 1_000,
                )
            except TimeoutError:
                continue

    def _safe_now(self) -> int:
        value = self._now_ms()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeError("observation clock is invalid")
        return value


def _scrub_exception(error: BaseException) -> None:
    error.args = ()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
