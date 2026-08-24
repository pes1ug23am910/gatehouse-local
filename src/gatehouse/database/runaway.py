"""Durable offender-scoped runaway quarantine and bounded burst authority."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from gatehouse.core.clock import require_utc_ms
from gatehouse.fingerprint.hmac import RequestFingerprint
from gatehouse.fingerprint.runaway import (
    RunawayDecision,
    RunawayDetector,
    RunawayTrigger,
)
from gatehouse.providers.registry import (
    DEFAULT_PROVIDER_REGISTRY,
    ProviderContractError,
    ProviderRegistry,
)

from .connection import transaction

MAXIMUM_BURST_DURATION_MS = 15 * 60_000
MAXIMUM_BURST_REQUESTS = 25
MAXIMUM_BURST_CREDITS = 100
MAXIMUM_BURST_CONCURRENCY = 8
MAXIMUM_BURST_OPERATIONS = 16
_ACTION_TOKEN_DOMAIN = b"gatehouse/runaway-quarantine-action/v1\x00"
_DETECTOR_SCOPE_DOMAIN = b"gatehouse/runaway-detector-scope/v1\x00"
_DECISION_REASON_DOMAIN = b"gatehouse/runaway-decision-reason/v1\x00"


class RunawayQuarantineError(RuntimeError):
    """Base class for durable runaway authority failures."""


class RunawayQuarantineConflict(RunawayQuarantineError):
    """A stale or unavailable human decision was rejected."""


class RunawayQuarantinePersistenceError(RunawayQuarantineError):
    """Durable quarantine state could not be safely represented."""


class RunawayQuarantineState(StrEnum):
    OPEN = "OPEN"
    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"


class RunawayAdmissionState(StrEnum):
    ALLOW = "ALLOW"
    QUARANTINED = "QUARANTINED"
    AUTHORIZED = "AUTHORIZED"
    CAPACITY = "CAPACITY"


@dataclass(frozen=True, slots=True)
class RunawayBurstPermit:
    permit_id: str
    quarantine_id: str
    authorization_generation: int
    reserved_credits: int


@dataclass(frozen=True, slots=True)
class RunawayAdmission:
    state: RunawayAdmissionState
    quarantine_id: str | None = None
    quarantine_state: RunawayQuarantineState | None = None
    trigger: RunawayTrigger | None = None
    reason_code: str | None = None
    permit: RunawayBurstPermit | None = None

    def __post_init__(self) -> None:
        if self.state is RunawayAdmissionState.ALLOW:
            if any(
                value is not None
                for value in (
                    self.quarantine_id,
                    self.quarantine_state,
                    self.trigger,
                    self.reason_code,
                    self.permit,
                )
            ):
                raise ValueError("an ordinary admission cannot carry quarantine authority")
            return
        if self.quarantine_id is None or self.quarantine_state is None or self.reason_code is None:
            raise ValueError("a quarantine admission requires a sanitized durable projection")
        if (self.state is RunawayAdmissionState.AUTHORIZED) != (self.permit is not None):
            raise ValueError("only an authorized admission can carry a burst permit")


@dataclass(frozen=True, slots=True)
class RunawayQuarantineRecord:
    quarantine_id: str
    session_id: str
    client_id: str
    workspace_id: str | None
    root_run_id: str
    service_id: str
    state: RunawayQuarantineState
    trigger: RunawayTrigger
    trigger_operation: str
    generation: int
    opened_at_ms: int
    updated_at_ms: int
    decided_at_ms: int | None
    expires_at_ms: int | None
    maximum_requests: int | None
    remaining_requests: int | None
    maximum_credits: int | None
    remaining_credits: int | None
    maximum_concurrency: int | None
    active_concurrency: int
    operations: tuple[str, ...]
    action_token: str


@dataclass(frozen=True, slots=True)
class RunawayQuarantineActionResult:
    quarantine_id: str
    state: RunawayQuarantineState
    generation: int
    acted_at_ms: int
    audit_event_id: str


def _new_quarantine_id() -> str:
    return f"rqu_{uuid.uuid4().hex}"


def _new_permit_id() -> str:
    return f"rbp_{uuid.uuid4().hex}"


def _new_audit_event_id() -> str:
    return f"evt_runaway_{uuid.uuid4().hex}"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _reason_fingerprint(reason: str) -> str:
    digest = hashlib.sha256()
    digest.update(_DECISION_REASON_DOMAIN)
    digest.update(reason.encode("utf-8"))
    return digest.hexdigest()


def _bounded_text(value: str, *, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or not all(character.isprintable() for character in value)
    ):
        raise ValueError(f"{name} is invalid")
    return value


class SqliteRunawayQuarantineService:
    """Atomically persist and consume bounded human-authorized burst grants."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        action_token_key: bytes,
        now_ms: Callable[[], int],
        detector: RunawayDetector | None = None,
        quarantine_id_factory: Callable[[], str] = _new_quarantine_id,
        permit_id_factory: Callable[[], str] = _new_permit_id,
        audit_event_id_factory: Callable[[], str] = _new_audit_event_id,
        maximum_expirations_per_call: int = 100,
        provider_registry: ProviderRegistry = DEFAULT_PROVIDER_REGISTRY,
    ) -> None:
        if len(action_token_key) < 32:
            raise ValueError("runaway action-token key must contain at least 256 bits")
        if not 1 <= maximum_expirations_per_call <= 1_000:
            raise ValueError("runaway expiration batch is outside its bound")
        self.connection = connection
        self._action_token_key = bytes(action_token_key)
        self._now_ms = now_ms
        self._detector = detector or RunawayDetector()
        self._quarantine_id_factory = quarantine_id_factory
        self._permit_id_factory = permit_id_factory
        self._audit_event_id_factory = audit_event_id_factory
        self._maximum_expirations_per_call = maximum_expirations_per_call
        self._provider_registry = provider_registry

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
    ) -> RunawayAdmission:
        session_id = _bounded_text(session_id, name="session_id", maximum=160)
        root_run_id = _bounded_text(root_run_id, name="root_run_id", maximum=160)
        request_id = _bounded_text(request_id, name="request_id", maximum=160)
        service_id = _bounded_text(service_id, name="service_id", maximum=64)
        operation = _bounded_text(operation, name="operation", maximum=160)
        require_utc_ms(now_ms)
        if (
            isinstance(estimated_cost_units, bool)
            or not isinstance(estimated_cost_units, int)
            or not 0 <= estimated_cost_units < (1 << 63)
        ):
            raise ValueError("estimated burst cost must fit a non-negative SQLite integer")

        parent = self.connection.execute(
            """
            SELECT 1
              FROM invocations AS invocation
              JOIN root_runs AS root ON root.root_run_id = invocation.root_run_id
             WHERE invocation.request_id = ?
               AND invocation.session_id = ?
               AND invocation.root_run_id = ?
               AND invocation.service_id = ?
               AND invocation.operation = ?
               AND root.session_id = invocation.session_id
            """,
            (request_id, session_id, root_run_id, service_id, operation),
        ).fetchone()
        if parent is None:
            raise RunawayQuarantinePersistenceError(
                "runaway admission parent is unavailable or mismatched"
            )

        row = self._load_scope_row(session_id, root_run_id, service_id)
        if row is not None:
            return self._admit_from_durable(
                row=row,
                request_id=request_id,
                operation=operation,
                estimated_cost_units=estimated_cost_units,
                now_ms=now_ms,
            )

        detector_scope = self._detector_scope(session_id, root_run_id, service_id)
        observation = self._detector.observe_arrival(
            session_id=detector_scope,
            fingerprint=fingerprint,
            now_ms=now_ms,
        )
        if observation.decision is RunawayDecision.ALLOW:
            return RunawayAdmission(RunawayAdmissionState.ALLOW)
        trigger = observation.trigger or RunawayTrigger.DETECTOR_CAPACITY
        try:
            with transaction(self.connection, "IMMEDIATE"):
                row = self._load_scope_row(session_id, root_run_id, service_id)
                if row is None:
                    quarantine_id = _bounded_text(
                        self._quarantine_id_factory(),
                        name="quarantine_id",
                        maximum=160,
                    )
                    self.connection.execute(
                        """
                        INSERT INTO runaway_quarantines(
                            quarantine_id, session_id, root_run_id, service_id,
                            state, trigger_reason, trigger_operation, generation,
                            opened_at_ms, updated_at_ms
                        ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, 1, ?, ?)
                        """,
                        (
                            quarantine_id,
                            session_id,
                            root_run_id,
                            service_id,
                            trigger.value,
                            operation,
                            now_ms,
                            now_ms,
                        ),
                    )
                    self._audit_locked(
                        event_type="runaway.quarantine_opened",
                        session_id=session_id,
                        root_run_id=root_run_id,
                        service_id=service_id,
                        operation=operation,
                        occurred_at_ms=now_ms,
                        payload={
                            "quarantine_id": quarantine_id,
                            "scope": "session_root_run_service",
                            "trigger": trigger.value,
                        },
                    )
                    row = self._load_scope_row(session_id, root_run_id, service_id)
                if row is None:
                    raise RunawayQuarantinePersistenceError(
                        "runaway quarantine disappeared during creation"
                    )
        except sqlite3.IntegrityError as exc:
            raise RunawayQuarantinePersistenceError(
                "runaway quarantine persistence constraint failed"
            ) from exc
        self._detector.forget_session(detector_scope)
        return self._blocked_admission(row, reason_code="operator_authorization_required")

    def _admit_from_durable(
        self,
        *,
        row: sqlite3.Row,
        request_id: str,
        operation: str,
        estimated_cost_units: int,
        now_ms: int,
    ) -> RunawayAdmission:
        state = RunawayQuarantineState(str(row["state"]))
        if state is RunawayQuarantineState.AUTHORIZED:
            expires_at_ms = int(row["expires_at_ms"])
            if expires_at_ms <= now_ms:
                with transaction(self.connection, "IMMEDIATE"):
                    refreshed = self._load_quarantine_row(str(row["quarantine_id"]))
                    if refreshed is not None:
                        self._expire_locked(refreshed, now_ms)
                expired = self._load_quarantine_row(str(row["quarantine_id"]))
                if expired is None:
                    raise RunawayQuarantinePersistenceError(
                        "expired runaway quarantine disappeared"
                    )
                if str(expired["state"]) == RunawayQuarantineState.AUTHORIZED.value:
                    if int(expired["expires_at_ms"]) <= now_ms:
                        raise RunawayQuarantinePersistenceError(
                            "expired runaway quarantine lost its generation fence"
                        )
                    return self._admit_from_durable(
                        row=expired,
                        request_id=request_id,
                        operation=operation,
                        estimated_cost_units=estimated_cost_units,
                        now_ms=now_ms,
                    )
                return self._blocked_admission(expired, reason_code="authorization_expired")

            operations = self._operations_from_row(row)
            if operation not in operations:
                return self._blocked_admission(row, reason_code="operation_not_authorized")
            remaining_requests = int(row["remaining_requests"])
            remaining_credits = int(row["remaining_credits"])
            if remaining_requests <= 0 or remaining_credits <= 0:
                with transaction(self.connection, "IMMEDIATE"):
                    refreshed = self._load_quarantine_row(str(row["quarantine_id"]))
                    if refreshed is not None:
                        self._exhaust_locked(refreshed, now_ms)
                exhausted = self._load_quarantine_row(str(row["quarantine_id"]))
                if exhausted is None:
                    raise RunawayQuarantinePersistenceError(
                        "exhausted runaway quarantine disappeared"
                    )
                if str(exhausted["state"]) == RunawayQuarantineState.AUTHORIZED.value:
                    if (
                        int(exhausted["remaining_requests"]) <= 0
                        or int(exhausted["remaining_credits"]) <= 0
                    ):
                        raise RunawayQuarantinePersistenceError(
                            "exhausted runaway quarantine lost its generation fence"
                        )
                    return self._admit_from_durable(
                        row=exhausted,
                        request_id=request_id,
                        operation=operation,
                        estimated_cost_units=estimated_cost_units,
                        now_ms=now_ms,
                    )
                return self._blocked_admission(exhausted, reason_code="authorization_exhausted")
            if estimated_cost_units > remaining_credits:
                return self._blocked_admission(row, reason_code="burst_credit_limit")
            if int(row["active_concurrency"]) >= int(row["maximum_concurrency"]):
                return RunawayAdmission(
                    state=RunawayAdmissionState.CAPACITY,
                    quarantine_id=str(row["quarantine_id"]),
                    quarantine_state=state,
                    trigger=RunawayTrigger(str(row["trigger_reason"])),
                    reason_code="burst_concurrency_limit",
                )
            return self._reserve_permit(
                row=row,
                request_id=request_id,
                operation=operation,
                estimated_cost_units=estimated_cost_units,
                now_ms=now_ms,
            )
        reason_codes = {
            RunawayQuarantineState.OPEN: "operator_authorization_required",
            RunawayQuarantineState.DENIED: "authorization_denied",
            RunawayQuarantineState.EXPIRED: "authorization_expired",
            RunawayQuarantineState.EXHAUSTED: "authorization_exhausted",
        }
        return self._blocked_admission(row, reason_code=reason_codes[state])

    def _reserve_permit(
        self,
        *,
        row: sqlite3.Row,
        request_id: str,
        operation: str,
        estimated_cost_units: int,
        now_ms: int,
    ) -> RunawayAdmission:
        permit_id = _bounded_text(
            self._permit_id_factory(),
            name="permit_id",
            maximum=160,
        )
        quarantine_id = str(row["quarantine_id"])
        generation = int(row["generation"])
        try:
            with transaction(self.connection, "IMMEDIATE"):
                current = self._load_quarantine_row(quarantine_id)
                if current is None:
                    raise RunawayQuarantinePersistenceError(
                        "runaway quarantine disappeared before admission"
                    )
                rejection = self._reservation_rejection_locked(
                    current=current,
                    expected_generation=generation,
                    operation=operation,
                    estimated_cost_units=estimated_cost_units,
                    now_ms=now_ms,
                )
                if rejection is not None:
                    return rejection
                self.connection.execute(
                    """
                    INSERT INTO runaway_burst_permits(
                        permit_id, quarantine_id, authorization_generation,
                        request_id, operation, reserved_credits, state, created_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
                    """,
                    (
                        permit_id,
                        quarantine_id,
                        generation,
                        request_id,
                        operation,
                        estimated_cost_units,
                        now_ms,
                    ),
                )
                updated = self.connection.execute(
                    """
                    UPDATE runaway_quarantines
                       SET remaining_requests = remaining_requests - 1,
                           remaining_credits = remaining_credits - ?,
                           active_concurrency = active_concurrency + 1,
                           updated_at_ms = ?
                     WHERE quarantine_id = ? AND state = 'AUTHORIZED'
                       AND generation = ? AND expires_at_ms > ?
                       AND remaining_requests > 0
                       AND remaining_credits >= ?
                       AND active_concurrency < maximum_concurrency
                    """,
                    (
                        estimated_cost_units,
                        now_ms,
                        quarantine_id,
                        generation,
                        now_ms,
                        estimated_cost_units,
                    ),
                )
                if updated.rowcount != 1:
                    raise RunawayQuarantinePersistenceError(
                        "runaway burst reservation lost its authority fence"
                    )
                current = self._load_quarantine_row(quarantine_id)
                if current is None:
                    raise RunawayQuarantinePersistenceError(
                        "runaway quarantine disappeared after admission"
                    )
                if (
                    int(current["remaining_requests"]) == 0
                    or int(current["remaining_credits"]) == 0
                ):
                    self._exhaust_locked(current, now_ms)
        except sqlite3.IntegrityError as exc:
            raise RunawayQuarantinePersistenceError(
                "runaway burst permit persistence constraint failed"
            ) from exc
        return RunawayAdmission(
            state=RunawayAdmissionState.AUTHORIZED,
            quarantine_id=quarantine_id,
            quarantine_state=RunawayQuarantineState.AUTHORIZED,
            trigger=RunawayTrigger(str(row["trigger_reason"])),
            reason_code="bounded_burst_authorized",
            permit=RunawayBurstPermit(
                permit_id=permit_id,
                quarantine_id=quarantine_id,
                authorization_generation=generation,
                reserved_credits=estimated_cost_units,
            ),
        )

    def _reservation_rejection_locked(
        self,
        *,
        current: sqlite3.Row,
        expected_generation: int,
        operation: str,
        estimated_cost_units: int,
        now_ms: int,
    ) -> RunawayAdmission | None:
        state = RunawayQuarantineState(str(current["state"]))
        if state is not RunawayQuarantineState.AUTHORIZED:
            return self._blocked_admission(current, reason_code="authorization_changed")
        if int(current["generation"]) != expected_generation:
            return self._blocked_admission(current, reason_code="authorization_changed")
        if int(current["expires_at_ms"]) <= now_ms:
            self._expire_locked(current, now_ms)
            refreshed = self._load_quarantine_row(str(current["quarantine_id"]))
            if refreshed is None:
                raise RunawayQuarantinePersistenceError(
                    "expired runaway quarantine disappeared during reservation"
                )
            return self._blocked_admission(refreshed, reason_code="authorization_expired")
        if operation not in self._operations_from_row(current):
            return self._blocked_admission(current, reason_code="operation_not_authorized")
        if int(current["remaining_requests"]) <= 0 or int(current["remaining_credits"]) <= 0:
            self._exhaust_locked(current, now_ms)
            refreshed = self._load_quarantine_row(str(current["quarantine_id"]))
            if refreshed is None:
                raise RunawayQuarantinePersistenceError(
                    "exhausted runaway quarantine disappeared during reservation"
                )
            return self._blocked_admission(refreshed, reason_code="authorization_exhausted")
        if estimated_cost_units > int(current["remaining_credits"]):
            return self._blocked_admission(current, reason_code="burst_credit_limit")
        if int(current["active_concurrency"]) >= int(current["maximum_concurrency"]):
            return RunawayAdmission(
                state=RunawayAdmissionState.CAPACITY,
                quarantine_id=str(current["quarantine_id"]),
                quarantine_state=state,
                trigger=RunawayTrigger(str(current["trigger_reason"])),
                reason_code="burst_concurrency_limit",
            )
        return None

    async def settle_permit(self, permit_id: str, *, now_ms: int) -> bool:
        permit_id = _bounded_text(permit_id, name="permit_id", maximum=160)
        require_utc_ms(now_ms)
        with transaction(self.connection, "IMMEDIATE"):
            permit = self.connection.execute(
                """
                SELECT permit.*, invocation.state AS invocation_state,
                       invocation.actual_cost_units
                  FROM runaway_burst_permits AS permit
                  JOIN invocations AS invocation ON invocation.request_id = permit.request_id
                 WHERE permit.permit_id = ?
                """,
                (permit_id,),
            ).fetchone()
            if permit is None or str(permit["state"]) != "ACTIVE":
                return False
            invocation_state = str(permit["invocation_state"])
            if permit["actual_cost_units"] is not None:
                actual_cost_state = "KNOWN"
                observed_actual_credits = int(permit["actual_cost_units"])
            elif invocation_state == "UNKNOWN":
                actual_cost_state = "UNKNOWN"
                observed_actual_credits = None
            else:
                actual_cost_state = "NOT_REPORTED"
                observed_actual_credits = None
            updated = self.connection.execute(
                """
                UPDATE runaway_burst_permits
                   SET state = 'SETTLED', settled_at_ms = ?,
                       actual_cost_state = ?, observed_actual_credits = ?
                 WHERE permit_id = ? AND state = 'ACTIVE'
                """,
                (
                    now_ms,
                    actual_cost_state,
                    observed_actual_credits,
                    permit_id,
                ),
            )
            if updated.rowcount != 1:
                return False
            quarantine = self.connection.execute(
                """
                UPDATE runaway_quarantines
                   SET active_concurrency = active_concurrency - 1,
                       updated_at_ms = MAX(updated_at_ms, ?)
                 WHERE quarantine_id = ? AND active_concurrency > 0
                """,
                (now_ms, str(permit["quarantine_id"])),
            )
            if quarantine.rowcount != 1:
                raise RunawayQuarantinePersistenceError(
                    "runaway burst concurrency accounting is inconsistent"
                )
            self._reconcile_permit_cost_locked(
                quarantine_id=str(permit["quarantine_id"]),
                request_id=str(permit["request_id"]),
                operation=str(permit["operation"]),
                reserved_credits=int(permit["reserved_credits"]),
                actual_cost_state=actual_cost_state,
                observed_actual_credits=observed_actual_credits,
                now_ms=now_ms,
            )
        return True

    def _reconcile_permit_cost_locked(
        self,
        *,
        quarantine_id: str,
        request_id: str,
        operation: str,
        reserved_credits: int,
        actual_cost_state: str,
        observed_actual_credits: int | None,
        now_ms: int,
    ) -> None:
        if actual_cost_state == "KNOWN":
            if observed_actual_credits is None:
                raise RunawayQuarantinePersistenceError(
                    "known runaway burst cost omitted its exact value"
                )
            additional = max(0, observed_actual_credits - reserved_credits)
            if additional == 0:
                return
            quarantine = self._load_quarantine_row(quarantine_id)
            if quarantine is None:
                raise RunawayQuarantinePersistenceError(
                    "runaway quarantine disappeared during cost reconciliation"
                )
            remaining = quarantine["remaining_credits"]
            consumed = 0 if remaining is None else min(int(remaining), additional)
            if remaining is not None:
                self.connection.execute(
                    """
                    UPDATE runaway_quarantines
                       SET remaining_credits = MAX(0, remaining_credits - ?),
                           updated_at_ms = MAX(updated_at_ms, ?)
                     WHERE quarantine_id = ? AND remaining_credits IS NOT NULL
                    """,
                    (additional, now_ms, quarantine_id),
                )
            refreshed = self._load_quarantine_row(quarantine_id)
            if refreshed is not None:
                self._exhaust_locked(refreshed, now_ms)
            self._audit_locked(
                event_type="runaway.burst_cost_overrun",
                session_id=str(quarantine["session_id"]),
                root_run_id=str(quarantine["root_run_id"]),
                service_id=str(quarantine["service_id"]),
                operation=operation,
                occurred_at_ms=now_ms,
                payload={
                    "actual_credits": observed_actual_credits,
                    "additional_credits_consumed": consumed,
                    "overrun_credits": additional,
                    "quarantine_id": quarantine_id,
                    "request_id": request_id,
                    "reserved_credits": reserved_credits,
                },
            )
            return
        if actual_cost_state != "UNKNOWN":
            return
        quarantine = self._load_quarantine_row(quarantine_id)
        if quarantine is None:
            raise RunawayQuarantinePersistenceError(
                "runaway quarantine disappeared during unknown-cost reconciliation"
            )
        if quarantine["remaining_credits"] is not None:
            self.connection.execute(
                """
                UPDATE runaway_quarantines
                   SET remaining_credits = 0, updated_at_ms = MAX(updated_at_ms, ?)
                 WHERE quarantine_id = ? AND remaining_credits IS NOT NULL
                """,
                (now_ms, quarantine_id),
            )
        refreshed = self._load_quarantine_row(quarantine_id)
        if refreshed is not None:
            self._exhaust_locked(refreshed, now_ms)
        self._audit_locked(
            event_type="runaway.burst_cost_unknown",
            session_id=str(quarantine["session_id"]),
            root_run_id=str(quarantine["root_run_id"]),
            service_id=str(quarantine["service_id"]),
            operation=operation,
            occurred_at_ms=now_ms,
            payload={
                "quarantine_id": quarantine_id,
                "request_id": request_id,
                "reserved_credits": reserved_credits,
            },
        )

    async def recover_orphaned_permits(self, *, now_ms: int) -> int:
        """Fence every pre-existing live permit after a daemon restart.

        Requests and reserved credits remain consumed.  Admission is closed and
        only a fresh human decision can restore the exact offender scope.
        """

        require_utc_ms(now_ms)
        with transaction(self.connection, "IMMEDIATE"):
            rows = self.connection.execute(
                """
                SELECT permit.permit_id, permit.quarantine_id, permit.request_id,
                       invocation.state AS invocation_state
                  FROM runaway_burst_permits AS permit
                  JOIN invocations AS invocation ON invocation.request_id = permit.request_id
                 WHERE permit.state = 'ACTIVE'
                 ORDER BY permit.quarantine_id, permit.permit_id
                """
            ).fetchall()
            grouped: dict[str, list[sqlite3.Row]] = {}
            for row in rows:
                grouped.setdefault(str(row["quarantine_id"]), []).append(row)
            for quarantine_id, permits in grouped.items():
                permit_ids = tuple(str(row["permit_id"]) for row in permits)
                for permit_id in permit_ids:
                    updated_permit = self.connection.execute(
                        """
                        UPDATE runaway_burst_permits
                           SET state = 'ORPHANED', settled_at_ms = ?,
                               actual_cost_state = 'UNKNOWN',
                               observed_actual_credits = NULL
                         WHERE state = 'ACTIVE' AND permit_id = ?
                        """,
                        (now_ms, permit_id),
                    )
                    if updated_permit.rowcount != 1:
                        raise RunawayQuarantinePersistenceError(
                            "runaway orphan recovery lost a permit fence"
                        )
                quarantine = self._load_quarantine_row(quarantine_id)
                if quarantine is None:
                    raise RunawayQuarantinePersistenceError(
                        "runaway quarantine disappeared during orphan recovery"
                    )
                released = self.connection.execute(
                    """
                    UPDATE runaway_quarantines
                       SET active_concurrency = active_concurrency - ?,
                           updated_at_ms = MAX(updated_at_ms, ?)
                     WHERE quarantine_id = ? AND active_concurrency >= ?
                    """,
                    (len(permit_ids), now_ms, quarantine_id, len(permit_ids)),
                )
                if released.rowcount != 1:
                    raise RunawayQuarantinePersistenceError(
                        "runaway orphan recovery found inconsistent concurrency accounting"
                    )
                refreshed = self._load_quarantine_row(quarantine_id)
                if refreshed is None:
                    raise RunawayQuarantinePersistenceError(
                        "runaway quarantine disappeared after orphan recovery"
                    )
                if str(refreshed["state"]) == RunawayQuarantineState.AUTHORIZED.value:
                    next_generation = int(refreshed["generation"]) + 1
                    expired = self.connection.execute(
                        """
                        UPDATE runaway_quarantines
                           SET state = 'EXPIRED', generation = ?, updated_at_ms = ?
                         WHERE quarantine_id = ? AND state = 'AUTHORIZED'
                           AND generation = ? AND active_concurrency = 0
                        """,
                        (
                            next_generation,
                            now_ms,
                            quarantine_id,
                            int(refreshed["generation"]),
                        ),
                    )
                    if expired.rowcount != 1:
                        raise RunawayQuarantinePersistenceError(
                            "runaway orphan recovery lost the quarantine fence"
                        )
                self._audit_locked(
                    event_type="runaway.burst_recovery_required",
                    session_id=str(quarantine["session_id"]),
                    root_run_id=str(quarantine["root_run_id"]),
                    service_id=str(quarantine["service_id"]),
                    operation=None,
                    occurred_at_ms=now_ms,
                    payload={
                        "invocation_states": sorted(
                            {str(row["invocation_state"]) for row in permits}
                        ),
                        "orphaned_permits": len(permit_ids),
                        "quarantine_id": quarantine_id,
                    },
                )
        return len(rows)

    async def list_quarantines(self, *, limit: int) -> Sequence[RunawayQuarantineRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("runaway quarantine list limit is outside its bound")
        now = self._now_ms()
        require_utc_ms(now)
        self._expire_due(now)
        rows = self.connection.execute(
            f"{self._view_query()} ORDER BY quarantine.updated_at_ms, "
            "quarantine.quarantine_id LIMIT ?",
            (limit,),
        ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    async def get_quarantine(self, quarantine_id: str) -> RunawayQuarantineRecord | None:
        quarantine_id = _bounded_text(
            quarantine_id,
            name="quarantine_id",
            maximum=160,
        )
        now = self._now_ms()
        require_utc_ms(now)
        row = self._load_quarantine_row(quarantine_id)
        if (
            row is not None
            and str(row["state"]) == RunawayQuarantineState.AUTHORIZED.value
            and int(row["expires_at_ms"]) <= now
        ):
            with transaction(self.connection, "IMMEDIATE"):
                refreshed = self._load_quarantine_row(quarantine_id)
                if refreshed is not None:
                    self._expire_locked(refreshed, now)
        row = self.connection.execute(
            f"{self._view_query()} WHERE quarantine.quarantine_id = ?",
            (quarantine_id,),
        ).fetchone()
        return None if row is None else self._record_from_row(row)

    async def authorize(
        self,
        *,
        quarantine_id: str,
        expected_generation: int,
        action_token: str,
        actor_id: str,
        reason: str,
        duration_ms: int,
        maximum_requests: int,
        maximum_credits: int,
        maximum_concurrency: int,
        operations: Sequence[str],
        now_ms: int,
    ) -> RunawayQuarantineActionResult:
        self._validate_action(
            quarantine_id=quarantine_id,
            expected_generation=expected_generation,
            action_token=action_token,
            actor_id=actor_id,
            reason=reason,
            now_ms=now_ms,
        )
        if not 1 <= duration_ms <= MAXIMUM_BURST_DURATION_MS:
            raise ValueError("burst duration is outside its hard bound")
        if not 1 <= maximum_requests <= MAXIMUM_BURST_REQUESTS:
            raise ValueError("burst request count is outside its hard bound")
        if not 1 <= maximum_credits <= MAXIMUM_BURST_CREDITS:
            raise ValueError("burst credit count is outside its hard bound")
        if not 1 <= maximum_concurrency <= MAXIMUM_BURST_CONCURRENCY:
            raise ValueError("burst concurrency is outside its hard bound")
        normalized_operations = self._validate_operations(operations)
        reason_fingerprint = _reason_fingerprint(reason)
        audit_event_id = _bounded_text(
            self._audit_event_id_factory(),
            name="audit_event_id",
            maximum=160,
        )
        try:
            with transaction(self.connection, "IMMEDIATE"):
                row = self._load_quarantine_row(quarantine_id)
                if row is None:
                    raise RunawayQuarantineConflict("runaway quarantine does not exist")
                self._require_action_fence(row, expected_generation, action_token)
                if int(row["active_concurrency"]) != 0:
                    raise RunawayQuarantineConflict(
                        "runaway quarantine still owns active burst permits"
                    )
                try:
                    descriptor = self._provider_registry.descriptor(str(row["service_id"]))
                except ProviderContractError as exc:
                    raise ValueError(
                        "burst provider is not registered for typed operations"
                    ) from exc
                if any(
                    operation not in descriptor.operations for operation in normalized_operations
                ):
                    raise ValueError(
                        "burst operations must be code-owned operations of the quarantined provider"
                    )
                session = self.connection.execute(
                    "SELECT absolute_expires_at_ms FROM sessions WHERE session_id = ?",
                    (str(row["session_id"]),),
                ).fetchone()
                if session is None:
                    raise RunawayQuarantinePersistenceError(
                        "runaway quarantine session is unavailable"
                    )
                expires_at_ms = min(now_ms + duration_ms, int(session["absolute_expires_at_ms"]))
                if expires_at_ms <= now_ms:
                    raise RunawayQuarantineConflict("runaway quarantine session has expired")
                next_generation = expected_generation + 1
                updated = self.connection.execute(
                    """
                    UPDATE runaway_quarantines
                       SET state = 'AUTHORIZED', generation = ?, updated_at_ms = ?,
                           decided_at_ms = ?, expires_at_ms = ?, decision_actor_id = ?,
                            decision_reason_fingerprint = ?,
                            decision_reason_supplied = 1, maximum_requests = ?,
                           remaining_requests = ?, maximum_credits = ?,
                           remaining_credits = ?, maximum_concurrency = ?,
                           active_concurrency = 0, operations_json = ?
                     WHERE quarantine_id = ? AND generation = ?
                    """,
                    (
                        next_generation,
                        now_ms,
                        now_ms,
                        expires_at_ms,
                        actor_id,
                        reason_fingerprint,
                        maximum_requests,
                        maximum_requests,
                        maximum_credits,
                        maximum_credits,
                        maximum_concurrency,
                        _canonical_json(normalized_operations),
                        quarantine_id,
                        expected_generation,
                    ),
                )
                if updated.rowcount != 1:
                    raise RunawayQuarantineConflict("runaway quarantine decision lost its fence")
                self._insert_audit_locked(
                    event_id=audit_event_id,
                    event_type="runaway.burst_authorized",
                    session_id=str(row["session_id"]),
                    root_run_id=str(row["root_run_id"]),
                    service_id=str(row["service_id"]),
                    operation=None,
                    occurred_at_ms=now_ms,
                    payload={
                        "actor_id": actor_id,
                        "duration_ms": expires_at_ms - now_ms,
                        "generation": next_generation,
                        "maximum_concurrency": maximum_concurrency,
                        "maximum_credits": maximum_credits,
                        "maximum_requests": maximum_requests,
                        "operation_count": len(normalized_operations),
                        "operations": list(normalized_operations),
                        "quarantine_id": quarantine_id,
                        "reason_fingerprint": reason_fingerprint,
                        "reason_supplied": True,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise RunawayQuarantinePersistenceError(
                "runaway authorization persistence constraint failed"
            ) from exc
        self._detector.forget_session(
            self._detector_scope(
                str(row["session_id"]),
                str(row["root_run_id"]),
                str(row["service_id"]),
            )
        )
        return RunawayQuarantineActionResult(
            quarantine_id=quarantine_id,
            state=RunawayQuarantineState.AUTHORIZED,
            generation=next_generation,
            acted_at_ms=now_ms,
            audit_event_id=audit_event_id,
        )

    async def deny(
        self,
        *,
        quarantine_id: str,
        expected_generation: int,
        action_token: str,
        actor_id: str,
        reason: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult:
        self._validate_action(
            quarantine_id=quarantine_id,
            expected_generation=expected_generation,
            action_token=action_token,
            actor_id=actor_id,
            reason=reason,
            now_ms=now_ms,
        )
        audit_event_id = _bounded_text(
            self._audit_event_id_factory(),
            name="audit_event_id",
            maximum=160,
        )
        reason_fingerprint = _reason_fingerprint(reason)
        try:
            with transaction(self.connection, "IMMEDIATE"):
                row = self._load_quarantine_row(quarantine_id)
                if row is None:
                    raise RunawayQuarantineConflict("runaway quarantine does not exist")
                self._require_action_fence(row, expected_generation, action_token)
                next_generation = expected_generation + 1
                updated = self.connection.execute(
                    """
                    UPDATE runaway_quarantines
                       SET state = 'DENIED', generation = ?, updated_at_ms = ?,
                           decided_at_ms = ?, expires_at_ms = NULL,
                            decision_actor_id = ?, decision_reason_fingerprint = ?,
                            decision_reason_supplied = 1,
                           maximum_requests = NULL, remaining_requests = NULL,
                           maximum_credits = NULL, remaining_credits = NULL,
                           maximum_concurrency = NULL, operations_json = '[]'
                     WHERE quarantine_id = ? AND generation = ?
                    """,
                    (
                        next_generation,
                        now_ms,
                        now_ms,
                        actor_id,
                        reason_fingerprint,
                        quarantine_id,
                        expected_generation,
                    ),
                )
                if updated.rowcount != 1:
                    raise RunawayQuarantineConflict("runaway quarantine decision lost its fence")
                self._insert_audit_locked(
                    event_id=audit_event_id,
                    event_type="runaway.quarantine_denied",
                    session_id=str(row["session_id"]),
                    root_run_id=str(row["root_run_id"]),
                    service_id=str(row["service_id"]),
                    operation=None,
                    occurred_at_ms=now_ms,
                    payload={
                        "actor_id": actor_id,
                        "generation": next_generation,
                        "quarantine_id": quarantine_id,
                        "reason_fingerprint": reason_fingerprint,
                        "reason_supplied": True,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise RunawayQuarantinePersistenceError(
                "runaway denial persistence constraint failed"
            ) from exc
        return RunawayQuarantineActionResult(
            quarantine_id=quarantine_id,
            state=RunawayQuarantineState.DENIED,
            generation=next_generation,
            acted_at_ms=now_ms,
            audit_event_id=audit_event_id,
        )

    def _validate_action(
        self,
        *,
        quarantine_id: str,
        expected_generation: int,
        action_token: str,
        actor_id: str,
        reason: str,
        now_ms: int,
    ) -> None:
        _bounded_text(quarantine_id, name="quarantine_id", maximum=160)
        _bounded_text(action_token, name="action_token", maximum=256)
        _bounded_text(actor_id, name="actor_id", maximum=160)
        _bounded_text(reason, name="reason", maximum=500)
        require_utc_ms(now_ms)
        if isinstance(expected_generation, bool) or expected_generation <= 0:
            raise ValueError("runaway quarantine generation is invalid")

    def _require_action_fence(
        self,
        row: sqlite3.Row,
        expected_generation: int,
        action_token: str,
    ) -> None:
        current_generation = int(row["generation"])
        expected_token = self._action_token(str(row["quarantine_id"]), current_generation)
        if current_generation != expected_generation or not hmac.compare_digest(
            expected_token,
            action_token,
        ):
            raise RunawayQuarantineConflict("runaway quarantine action fence is stale")

    def _expire_due(self, now_ms: int) -> None:
        with transaction(self.connection, "IMMEDIATE"):
            rows = self.connection.execute(
                """
                SELECT * FROM runaway_quarantines
                 WHERE state = 'AUTHORIZED' AND expires_at_ms <= ?
                 ORDER BY expires_at_ms, quarantine_id LIMIT ?
                """,
                (now_ms, self._maximum_expirations_per_call),
            ).fetchall()
            for row in rows:
                self._expire_locked(row, now_ms)

    def _expire_locked(self, row: sqlite3.Row, now_ms: int) -> bool:
        if (
            str(row["state"]) != RunawayQuarantineState.AUTHORIZED.value
            or int(row["expires_at_ms"]) > now_ms
        ):
            return False
        quarantine_id = str(row["quarantine_id"])
        next_generation = int(row["generation"]) + 1
        updated = self.connection.execute(
            """
            UPDATE runaway_quarantines
               SET state = 'EXPIRED', generation = ?, updated_at_ms = ?
             WHERE quarantine_id = ? AND state = 'AUTHORIZED' AND generation = ?
               AND expires_at_ms <= ?
            """,
            (
                next_generation,
                now_ms,
                quarantine_id,
                int(row["generation"]),
                now_ms,
            ),
        )
        if updated.rowcount == 1:
            self._audit_locked(
                event_type="runaway.burst_expired",
                session_id=str(row["session_id"]),
                root_run_id=str(row["root_run_id"]),
                service_id=str(row["service_id"]),
                operation=None,
                occurred_at_ms=now_ms,
                payload={
                    "generation": next_generation,
                    "quarantine_id": quarantine_id,
                },
            )
            return True
        return False

    def _exhaust_locked(self, row: sqlite3.Row, now_ms: int) -> bool:
        if str(row["state"]) != RunawayQuarantineState.AUTHORIZED.value or (
            int(row["remaining_requests"]) > 0 and int(row["remaining_credits"]) > 0
        ):
            return False
        quarantine_id = str(row["quarantine_id"])
        next_generation = int(row["generation"]) + 1
        updated = self.connection.execute(
            """
            UPDATE runaway_quarantines
               SET state = 'EXHAUSTED', generation = ?, updated_at_ms = ?
             WHERE quarantine_id = ? AND state = 'AUTHORIZED' AND generation = ?
               AND (remaining_requests <= 0 OR remaining_credits <= 0)
            """,
            (next_generation, now_ms, quarantine_id, int(row["generation"])),
        )
        if updated.rowcount == 1:
            self._audit_locked(
                event_type="runaway.burst_exhausted",
                session_id=str(row["session_id"]),
                root_run_id=str(row["root_run_id"]),
                service_id=str(row["service_id"]),
                operation=None,
                occurred_at_ms=now_ms,
                payload={
                    "generation": next_generation,
                    "quarantine_id": quarantine_id,
                },
            )
            return True
        return False

    def _blocked_admission(self, row: sqlite3.Row, *, reason_code: str) -> RunawayAdmission:
        return RunawayAdmission(
            state=RunawayAdmissionState.QUARANTINED,
            quarantine_id=str(row["quarantine_id"]),
            quarantine_state=RunawayQuarantineState(str(row["state"])),
            trigger=RunawayTrigger(str(row["trigger_reason"])),
            reason_code=reason_code,
        )

    def _load_scope_row(
        self,
        session_id: str,
        root_run_id: str,
        service_id: str,
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self.connection.execute(
                """
                SELECT * FROM runaway_quarantines
                 WHERE session_id = ? AND root_run_id = ? AND service_id = ?
                """,
                (session_id, root_run_id, service_id),
            ).fetchone(),
        )

    def _load_quarantine_row(self, quarantine_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self.connection.execute(
                "SELECT * FROM runaway_quarantines WHERE quarantine_id = ?",
                (quarantine_id,),
            ).fetchone(),
        )

    @staticmethod
    def _view_query() -> str:
        return """
            SELECT quarantine.*, session.client_id, session.workspace_id
              FROM runaway_quarantines AS quarantine
              JOIN sessions AS session ON session.session_id = quarantine.session_id
        """

    def _record_from_row(self, row: sqlite3.Row) -> RunawayQuarantineRecord:
        operations = self._operations_from_row(row)
        state = RunawayQuarantineState(str(row["state"]))
        generation = int(row["generation"])
        return RunawayQuarantineRecord(
            quarantine_id=str(row["quarantine_id"]),
            session_id=str(row["session_id"]),
            client_id=str(row["client_id"]),
            workspace_id=(None if row["workspace_id"] is None else str(row["workspace_id"])),
            root_run_id=str(row["root_run_id"]),
            service_id=str(row["service_id"]),
            state=state,
            trigger=RunawayTrigger(str(row["trigger_reason"])),
            trigger_operation=str(row["trigger_operation"]),
            generation=generation,
            opened_at_ms=int(row["opened_at_ms"]),
            updated_at_ms=int(row["updated_at_ms"]),
            decided_at_ms=(None if row["decided_at_ms"] is None else int(row["decided_at_ms"])),
            expires_at_ms=(None if row["expires_at_ms"] is None else int(row["expires_at_ms"])),
            maximum_requests=(
                None if row["maximum_requests"] is None else int(row["maximum_requests"])
            ),
            remaining_requests=(
                None if row["remaining_requests"] is None else int(row["remaining_requests"])
            ),
            maximum_credits=(
                None if row["maximum_credits"] is None else int(row["maximum_credits"])
            ),
            remaining_credits=(
                None if row["remaining_credits"] is None else int(row["remaining_credits"])
            ),
            maximum_concurrency=(
                None if row["maximum_concurrency"] is None else int(row["maximum_concurrency"])
            ),
            active_concurrency=int(row["active_concurrency"]),
            operations=operations,
            action_token=self._action_token(str(row["quarantine_id"]), generation),
        )

    @staticmethod
    def _operations_from_row(row: sqlite3.Row) -> tuple[str, ...]:
        try:
            parsed = json.loads(str(row["operations_json"]))
        except json.JSONDecodeError as exc:
            raise RunawayQuarantinePersistenceError(
                "runaway operation allowlist is not valid JSON"
            ) from exc
        if not isinstance(parsed, list):
            raise RunawayQuarantinePersistenceError("runaway operation allowlist is not an array")
        state = RunawayQuarantineState(str(row["state"]))
        if not parsed and state in {
            RunawayQuarantineState.OPEN,
            RunawayQuarantineState.DENIED,
        }:
            return ()
        try:
            return SqliteRunawayQuarantineService._validate_operations(parsed)
        except (TypeError, ValueError) as exc:
            raise RunawayQuarantinePersistenceError(
                "runaway operation allowlist is invalid"
            ) from exc

    @staticmethod
    def _validate_operations(operations: Sequence[str]) -> tuple[str, ...]:
        if isinstance(operations, (str, bytes)):
            raise TypeError("burst operations must be a sequence of typed operation names")
        normalized = tuple(
            _bounded_text(operation, name="operation", maximum=160) for operation in operations
        )
        if not 1 <= len(normalized) <= MAXIMUM_BURST_OPERATIONS:
            raise ValueError("burst operation count is outside its hard bound")
        if len(set(normalized)) != len(normalized):
            raise ValueError("burst operation allowlist contains duplicates")
        return normalized

    def _action_token(self, quarantine_id: str, generation: int) -> str:
        payload = (
            _ACTION_TOKEN_DOMAIN
            + quarantine_id.encode("utf-8")
            + b"\x00"
            + str(generation).encode("ascii")
        )
        digest = hmac.new(self._action_token_key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def _detector_scope(session_id: str, root_run_id: str, service_id: str) -> str:
        digest = hashlib.sha256(
            _DETECTOR_SCOPE_DOMAIN
            + session_id.encode("utf-8")
            + b"\x00"
            + root_run_id.encode("utf-8")
            + b"\x00"
            + service_id.encode("utf-8")
        ).hexdigest()
        return f"runaway-scope:{digest}"

    def _audit_locked(
        self,
        *,
        event_type: str,
        session_id: str,
        root_run_id: str,
        service_id: str,
        operation: str | None,
        occurred_at_ms: int,
        payload: dict[str, object],
    ) -> str:
        event_id = _bounded_text(
            self._audit_event_id_factory(),
            name="audit_event_id",
            maximum=160,
        )
        self._insert_audit_locked(
            event_id=event_id,
            event_type=event_type,
            session_id=session_id,
            root_run_id=root_run_id,
            service_id=service_id,
            operation=operation,
            occurred_at_ms=occurred_at_ms,
            payload=payload,
        )
        return event_id

    def _insert_audit_locked(
        self,
        *,
        event_id: str,
        event_type: str,
        session_id: str,
        root_run_id: str,
        service_id: str,
        operation: str | None,
        occurred_at_ms: int,
        payload: dict[str, object],
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity, session_id,
                root_run_id, service_id, operation, preserve, payload_json
            ) VALUES (?, ?, ?, 'warning', ?, ?, ?, ?, 1, ?)
            """,
            (
                event_id,
                occurred_at_ms,
                event_type,
                session_id,
                root_run_id,
                service_id,
                operation,
                _canonical_json(payload),
            ),
        )
