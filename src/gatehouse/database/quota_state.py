"""Durable, provider-neutral quota-scope health and observation transitions."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from enum import StrEnum

from gatehouse.core.provider_numbers import (
    MAX_PROVIDER_FIXED_POINT_CHARS,
    parse_canonical_provider_number,
    project_routing_units,
    require_sqlite_int64,
)
from gatehouse.credentials.redaction import SecretScanner

from .audit import AuditEvent
from .connection import transaction
from .repository import BalanceAuthorityStatus, validate_balance_authority


class QuotaScopeHealthState(StrEnum):
    HEALTHY = "HEALTHY"
    EXHAUSTED = "EXHAUSTED"
    UNKNOWN = "UNKNOWN"
    DISABLED = "DISABLED"
    QUARANTINED = "QUARANTINED"
    COOLDOWN = "COOLDOWN"


class QuotaStateSource(StrEnum):
    PROVIDER_RESPONSE = "PROVIDER_RESPONSE"
    AUTHENTICATED_OBSERVATION = "AUTHENTICATED_OBSERVATION"
    OPERATOR = "OPERATOR"
    SYSTEM = "SYSTEM"


class QuotaTransitionStatus(StrEnum):
    TRANSITIONED = "TRANSITIONED"
    UNCHANGED = "UNCHANGED"
    NOT_FOUND = "NOT_FOUND"
    INELIGIBLE = "INELIGIBLE"
    GENERATION_CONFLICT = "GENERATION_CONFLICT"


@dataclass(frozen=True, slots=True)
class QuotaTransitionResult:
    status: QuotaTransitionStatus
    state: QuotaScopeHealthState | None
    generation: int | None
    event_id: str | None = None


class QuotaObservationStatus(StrEnum):
    RECORDED = "RECORDED"
    RECORDED_STALE = "RECORDED_STALE"
    NOT_FOUND = "NOT_FOUND"
    INELIGIBLE = "INELIGIBLE"


@dataclass(frozen=True, slots=True)
class QuotaObservationResult:
    status: QuotaObservationStatus
    snapshot_id: str | None
    head_advanced: bool
    transition: QuotaTransitionResult | None


@dataclass(frozen=True, slots=True)
class RedactedQuotaScopeStatus:
    alias: str
    state: QuotaScopeHealthState
    exact_remaining: str | None
    exact_plan_total: str | None
    observed_at_ms: int | None
    stale_at_ms: int | None
    stale: bool
    source: str | None


def _identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _bounded_text(value: str, *, field: str, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum or not value.isascii():
        raise ValueError(f"{field} is required and bounded")
    return value


def _optional_identifier(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, field=field, maximum=160)


def _canonical_counter(value: str, *, field: str) -> tuple[str, int, int]:
    if type(value) is not str:
        raise ValueError(f"{field} must be canonical text")
    try:
        exact = parse_canonical_provider_number(
            value,
            maximum_fixed_point_chars=MAX_PROVIDER_FIXED_POINT_CHARS,
        )
        projected = project_routing_units(exact)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be canonical text") from None
    return exact.canonical, projected, exact.coefficient


class SqliteQuotaStateRepository:
    """Persist snapshots and scope-state events in one short write transaction."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        scanner: SecretScanner | None = None,
    ) -> None:
        self.connection = connection
        self._scanner = scanner or SecretScanner()

    def _validate_audit_event(self, event: AuditEvent) -> None:
        bounded_fields = (
            (event.event_id, 160),
            (event.event_type, 100),
            (event.severity, 32),
            (event.session_id, 160),
            (event.root_run_id, 160),
            (event.request_id, 160),
            (event.attempt_id, 160),
            (event.service_id, 64),
            (event.operation, 100),
        )
        require_sqlite_int64(event.occurred_at_ms, field="audit event time", minimum=0)
        if not isinstance(event.preserve, bool):
            raise ValueError("audit event fields are invalid")
        for value, maximum in bounded_fields:
            if value is not None and (type(value) is not str or not value or len(value) > maximum):
                raise ValueError("audit event fields are invalid")
            if value is not None:
                self._scanner.assert_clean(value, location="quota_state.audit_field")
        if type(event.payload_json) is not str or len(event.payload_json.encode("utf-8")) > 8_192:
            raise ValueError("audit event payload exceeds its byte limit")
        try:
            payload: object = json.loads(event.payload_json)
        except json.JSONDecodeError:
            raise ValueError("audit event payload is malformed") from None
        if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
            raise ValueError("audit event payload is malformed")
        self._scanner.assert_clean(event.payload_json, location="quota_state.audit_payload")

    def _insert_audit_event(self, event: AuditEvent) -> None:
        self.connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity,
                session_id, root_run_id, request_id, attempt_id,
                service_id, operation, preserve, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.occurred_at_ms,
                event.event_type,
                event.severity,
                event.session_id,
                event.root_run_id,
                event.request_id,
                event.attempt_id,
                event.service_id,
                event.operation,
                int(event.preserve),
                event.payload_json,
            ),
        )

    def _transition_in_transaction(
        self,
        *,
        scope: sqlite3.Row,
        new_state: QuotaScopeHealthState,
        reason_code: str,
        source: QuotaStateSource,
        occurred_at_ms: int,
        expected_generation: int | None,
        event_id: str,
        snapshot_id: str | None = None,
        credential_id: str | None = None,
        credential_generation: int | None = None,
        request_id: str | None = None,
        attempt_id: str | None = None,
        actor_id: str | None = None,
    ) -> QuotaTransitionResult:
        current_state = QuotaScopeHealthState(str(scope["state"]))
        current_generation = int(scope["state_generation"])
        if expected_generation is not None and expected_generation != current_generation:
            return QuotaTransitionResult(
                QuotaTransitionStatus.GENERATION_CONFLICT,
                current_state,
                current_generation,
            )
        if current_state is new_state:
            return QuotaTransitionResult(
                QuotaTransitionStatus.UNCHANGED,
                current_state,
                current_generation,
            )
        next_generation = current_generation + 1
        self.connection.execute(
            """
            INSERT INTO quota_scope_state_events(
                event_id, quota_scope_id, generation, previous_state, new_state,
                reason_code, source_kind, snapshot_id, credential_id,
                credential_generation, request_id, attempt_id, actor_id,
                occurred_at_ms, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')
            """,
            (
                event_id,
                str(scope["quota_scope_id"]),
                next_generation,
                current_state.value,
                new_state.value,
                reason_code,
                source.value,
                snapshot_id,
                credential_id,
                credential_generation,
                request_id,
                attempt_id,
                actor_id,
                occurred_at_ms,
            ),
        )
        cursor = self.connection.execute(
            """
            UPDATE quota_scopes
               SET state = ?, state_generation = ?, state_changed_at_ms = ?,
                   state_reason_code = ?,
                   cooldown_until_ms = CASE WHEN ? = 'COOLDOWN'
                                            THEN cooldown_until_ms ELSE NULL END,
                   exhausted_at_ms = CASE WHEN ? = 'EXHAUSTED'
                                          THEN ? ELSE exhausted_at_ms END,
                   recovered_at_ms = CASE WHEN ? = 'HEALTHY'
                                          THEN ? ELSE recovered_at_ms END
             WHERE quota_scope_id = ? AND state_generation = ? AND state = ?
            """,
            (
                new_state.value,
                next_generation,
                occurred_at_ms,
                reason_code,
                new_state.value,
                new_state.value,
                occurred_at_ms,
                new_state.value,
                occurred_at_ms,
                str(scope["quota_scope_id"]),
                current_generation,
                current_state.value,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("quota scope state compare-and-set failed")
        return QuotaTransitionResult(
            QuotaTransitionStatus.TRANSITIONED,
            new_state,
            next_generation,
            event_id,
        )

    def _load_scope(self, quota_scope_id: str) -> sqlite3.Row | None:
        row = self.connection.execute(
            """
            SELECT quota_scope_id, principal_id, alias, state, state_generation,
                   unit, last_known_remaining_units, balance_as_of_ms,
                   balance_snapshot_id
              FROM quota_scopes WHERE quota_scope_id = ?
            """,
            (quota_scope_id,),
        ).fetchone()
        if row is None:
            return None
        if not isinstance(row, sqlite3.Row):
            raise RuntimeError("quota state repository requires sqlite3.Row results")
        return row

    def mark_definitive_exhaustion(
        self,
        *,
        quota_scope_id: str,
        now_ms: int,
        reason_code: str = "PROVIDER_QUOTA_EXHAUSTED",
        credential_id: str | None = None,
        credential_generation: int | None = None,
        request_id: str | None = None,
        attempt_id: str | None = None,
        expected_generation: int | None = None,
        event_id: str | None = None,
    ) -> QuotaTransitionResult:
        quota_scope_id = _bounded_text(quota_scope_id, field="quota scope identifier", maximum=160)
        reason_code = _bounded_text(reason_code, field="reason code", maximum=96)
        now_ms = require_sqlite_int64(now_ms, field="transition time", minimum=0)
        credential_id = _optional_identifier(credential_id, field="credential identifier")
        request_id = _optional_identifier(request_id, field="request identifier")
        attempt_id = _optional_identifier(attempt_id, field="attempt identifier")
        if (credential_id is None) != (credential_generation is None):
            raise ValueError("credential identifier and generation must be paired")
        if credential_generation is not None:
            credential_generation = require_sqlite_int64(
                credential_generation,
                field="credential generation",
                minimum=1,
            )
        candidate_event_id = event_id or _identifier("quota_state")
        _bounded_text(candidate_event_id, field="state event identifier", maximum=160)
        if expected_generation is not None:
            expected_generation = require_sqlite_int64(
                expected_generation,
                field="state generation",
                minimum=0,
            )
        with transaction(self.connection, "IMMEDIATE"):
            return self._mark_definitive_exhaustion_locked(
                quota_scope_id=quota_scope_id,
                now_ms=now_ms,
                reason_code=reason_code,
                credential_id=credential_id,
                credential_generation=credential_generation,
                request_id=request_id,
                attempt_id=attempt_id,
                expected_generation=expected_generation,
                event_id=candidate_event_id,
            )

    def mark_definitive_exhaustion_in_transaction(
        self,
        *,
        quota_scope_id: str,
        now_ms: int,
        reason_code: str = "PROVIDER_QUOTA_EXHAUSTED",
        credential_id: str | None = None,
        credential_generation: int | None = None,
        request_id: str | None = None,
        attempt_id: str | None = None,
        expected_generation: int | None = None,
        event_id: str | None = None,
    ) -> QuotaTransitionResult:
        """Append exhaustion inside a caller-owned write transaction.

        This is the atomic seam for a definitive terminal attempt checkpoint.
        It never begins or commits a transaction of its own.
        """

        if not self.connection.in_transaction:
            raise RuntimeError("definitive exhaustion requires an active transaction")
        quota_scope_id = _bounded_text(
            quota_scope_id,
            field="quota scope identifier",
            maximum=160,
        )
        reason_code = _bounded_text(reason_code, field="reason code", maximum=96)
        now_ms = require_sqlite_int64(now_ms, field="transition time", minimum=0)
        credential_id = _optional_identifier(credential_id, field="credential identifier")
        request_id = _optional_identifier(request_id, field="request identifier")
        attempt_id = _optional_identifier(attempt_id, field="attempt identifier")
        if (credential_id is None) != (credential_generation is None):
            raise ValueError("credential identifier and generation must be paired")
        if credential_generation is not None:
            credential_generation = require_sqlite_int64(
                credential_generation,
                field="credential generation",
                minimum=1,
            )
        if expected_generation is not None:
            expected_generation = require_sqlite_int64(
                expected_generation,
                field="state generation",
                minimum=0,
            )
        candidate_event_id = event_id or _identifier("quota_state")
        _bounded_text(candidate_event_id, field="state event identifier", maximum=160)
        return self._mark_definitive_exhaustion_locked(
            quota_scope_id=quota_scope_id,
            now_ms=now_ms,
            reason_code=reason_code,
            credential_id=credential_id,
            credential_generation=credential_generation,
            request_id=request_id,
            attempt_id=attempt_id,
            expected_generation=expected_generation,
            event_id=candidate_event_id,
        )

    def _mark_definitive_exhaustion_locked(
        self,
        *,
        quota_scope_id: str,
        now_ms: int,
        reason_code: str,
        credential_id: str | None,
        credential_generation: int | None,
        request_id: str | None,
        attempt_id: str | None,
        expected_generation: int | None,
        event_id: str,
    ) -> QuotaTransitionResult:
        scope = self._load_scope(quota_scope_id)
        if scope is None:
            return QuotaTransitionResult(QuotaTransitionStatus.NOT_FOUND, None, None)
        current_state = QuotaScopeHealthState(str(scope["state"]))
        if current_state in {
            QuotaScopeHealthState.DISABLED,
            QuotaScopeHealthState.QUARANTINED,
        }:
            return QuotaTransitionResult(
                QuotaTransitionStatus.INELIGIBLE,
                current_state,
                int(scope["state_generation"]),
            )
        if credential_id is not None:
            bound = self.connection.execute(
                """
                SELECT 1 FROM credentials
                 WHERE credential_id = ? AND quota_scope_id = ?
                   AND generation = ?
                """,
                (credential_id, quota_scope_id, credential_generation),
            ).fetchone()
            if bound is None:
                return QuotaTransitionResult(
                    QuotaTransitionStatus.INELIGIBLE,
                    current_state,
                    int(scope["state_generation"]),
                )
        return self._transition_in_transaction(
            scope=scope,
            new_state=QuotaScopeHealthState.EXHAUSTED,
            reason_code=reason_code,
            source=QuotaStateSource.PROVIDER_RESPONSE,
            occurred_at_ms=now_ms,
            expected_generation=expected_generation,
            event_id=event_id,
            credential_id=credential_id,
            credential_generation=credential_generation,
            request_id=request_id,
            attempt_id=attempt_id,
        )

    def record_authenticated_observation(
        self,
        *,
        quota_scope_id: str,
        credential_id: str,
        credential_generation: int,
        unit: str,
        exact_remaining: str,
        captured_at_ms: int,
        stale_at_ms: int,
        source: str,
        now_ms: int,
        exact_plan_total: str | None = None,
        exact_used: str | None = None,
        period_start_ms: int | None = None,
        period_end_ms: int | None = None,
        snapshot_id: str | None = None,
        event_id: str | None = None,
        audit_event: AuditEvent | None = None,
    ) -> QuotaObservationResult:
        quota_scope_id = _bounded_text(quota_scope_id, field="quota scope identifier", maximum=160)
        credential_id = _bounded_text(credential_id, field="credential identifier", maximum=160)
        unit = _bounded_text(unit, field="quota unit", maximum=64)
        source = _bounded_text(source, field="observation source", maximum=96)
        credential_generation = require_sqlite_int64(
            credential_generation,
            field="credential generation",
            minimum=1,
        )
        captured_at_ms = require_sqlite_int64(captured_at_ms, field="capture time", minimum=0)
        stale_at_ms = require_sqlite_int64(stale_at_ms, field="stale time", minimum=0)
        now_ms = require_sqlite_int64(now_ms, field="current time", minimum=0)
        if captured_at_ms > now_ms or stale_at_ms <= captured_at_ms:
            raise ValueError("observation time bounds are invalid")
        if period_start_ms is not None:
            period_start_ms = require_sqlite_int64(
                period_start_ms,
                field="reset window start",
                minimum=0,
            )
        if period_end_ms is not None:
            period_end_ms = require_sqlite_int64(
                period_end_ms,
                field="reset window end",
                minimum=0,
            )
        if period_start_ms is not None and period_end_ms is not None:
            if period_end_ms <= period_start_ms:
                raise ValueError("observation reset window is invalid")
        remaining_text, remaining_units, remaining_coefficient = _canonical_counter(
            exact_remaining,
            field="remaining counter",
        )
        plan_text: str | None = None
        plan_units: int | None = None
        if exact_plan_total is not None:
            plan_text, plan_units, _ = _canonical_counter(
                exact_plan_total,
                field="plan total counter",
            )
        used_text: str | None = None
        used_units: int | None = None
        if exact_used is not None:
            used_text, used_units, used_coefficient = _canonical_counter(
                exact_used,
                field="used counter",
            )
            if used_coefficient < 0:
                raise ValueError("used counter must be nonnegative")
        candidate_snapshot_id = snapshot_id or _identifier("quota_snapshot")
        candidate_event_id = event_id or _identifier("quota_state")
        _bounded_text(candidate_snapshot_id, field="snapshot identifier", maximum=160)
        _bounded_text(candidate_event_id, field="state event identifier", maximum=160)
        if audit_event is not None:
            self._validate_audit_event(audit_event)
            if audit_event.occurred_at_ms != captured_at_ms:
                raise ValueError("audit event and snapshot capture times do not match")

        with transaction(self.connection, "IMMEDIATE"):
            scope = self._load_scope(quota_scope_id)
            if scope is None:
                return QuotaObservationResult(
                    QuotaObservationStatus.NOT_FOUND,
                    None,
                    False,
                    None,
                )
            if str(scope["unit"]) != unit:
                return QuotaObservationResult(
                    QuotaObservationStatus.INELIGIBLE,
                    None,
                    False,
                    None,
                )
            credential = self.connection.execute(
                """
                SELECT 1 FROM credentials
                 WHERE credential_id = ? AND quota_scope_id = ?
                   AND generation = ? AND state = 'HEALTHY'
                """,
                (credential_id, quota_scope_id, credential_generation),
            ).fetchone()
            dimension = self.connection.execute(
                """
                SELECT quota_dimension_id
                  FROM quota_dimensions
                 WHERE quota_scope_id = ? AND is_primary = 1 AND state = 'ACTIVE'
                   AND native_unit = ?
                """,
                (quota_scope_id, unit),
            ).fetchone()
            if credential is None or dimension is None:
                return QuotaObservationResult(
                    QuotaObservationStatus.INELIGIBLE,
                    None,
                    False,
                    None,
                )
            self.connection.execute(
                """
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                    unit, period_start_ms, period_end_ms, captured_at_ms,
                    source, metadata_json,
                    observed_remaining_units_decimal,
                    observed_plan_total_units_decimal, quota_dimension_id,
                    credential_id, credential_generation, stale_at_ms,
                    observation_kind, used_units, observed_used_units_decimal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, ?, ?,
                          'AUTHENTICATED', ?, ?)
                """,
                (
                    candidate_snapshot_id,
                    quota_scope_id,
                    remaining_units,
                    plan_units,
                    unit,
                    period_start_ms,
                    period_end_ms,
                    captured_at_ms,
                    source,
                    remaining_text,
                    plan_text,
                    str(dimension["quota_dimension_id"]),
                    credential_id,
                    credential_generation,
                    stale_at_ms,
                    used_units,
                    used_text,
                ),
            )
            if audit_event is not None:
                self._insert_audit_event(audit_event)
            previous_as_of = scope["balance_as_of_ms"]
            previous_snapshot_id = scope["balance_snapshot_id"]
            head_advanced = previous_as_of is None or (
                captured_at_ms > int(previous_as_of)
                or (
                    captured_at_ms == int(previous_as_of)
                    and (
                        previous_snapshot_id is None
                        or candidate_snapshot_id > str(previous_snapshot_id)
                    )
                )
            )
            if not head_advanced:
                return QuotaObservationResult(
                    QuotaObservationStatus.RECORDED_STALE,
                    candidate_snapshot_id,
                    False,
                    None,
                )
            self.connection.execute(
                """
                UPDATE quota_scopes
                   SET last_known_remaining_units = ?, balance_as_of_ms = ?,
                       balance_snapshot_id = ?, last_refreshed_at_ms = ?
                 WHERE quota_scope_id = ?
                """,
                (
                    remaining_units,
                    captured_at_ms,
                    candidate_snapshot_id,
                    captured_at_ms,
                    quota_scope_id,
                ),
            )
            refreshed_scope = self._load_scope(quota_scope_id)
            if refreshed_scope is None:
                raise RuntimeError("quota scope disappeared during observation")
            current_state = QuotaScopeHealthState(str(refreshed_scope["state"]))
            transition: QuotaTransitionResult | None = None
            if remaining_coefficient <= 0 and current_state not in {
                QuotaScopeHealthState.DISABLED,
                QuotaScopeHealthState.QUARANTINED,
            }:
                transition = self._transition_in_transaction(
                    scope=refreshed_scope,
                    new_state=QuotaScopeHealthState.EXHAUSTED,
                    reason_code="AUTHENTICATED_NONPOSITIVE_BALANCE",
                    source=QuotaStateSource.AUTHENTICATED_OBSERVATION,
                    occurred_at_ms=captured_at_ms,
                    expected_generation=None,
                    event_id=candidate_event_id,
                    snapshot_id=candidate_snapshot_id,
                    credential_id=credential_id,
                    credential_generation=credential_generation,
                )
            elif remaining_coefficient > 0 and current_state in {
                QuotaScopeHealthState.EXHAUSTED,
                QuotaScopeHealthState.UNKNOWN,
                QuotaScopeHealthState.COOLDOWN,
            }:
                transition = self._transition_in_transaction(
                    scope=refreshed_scope,
                    new_state=QuotaScopeHealthState.HEALTHY,
                    reason_code="AUTHENTICATED_POSITIVE_BALANCE",
                    source=QuotaStateSource.AUTHENTICATED_OBSERVATION,
                    occurred_at_ms=captured_at_ms,
                    expected_generation=None,
                    event_id=candidate_event_id,
                    snapshot_id=candidate_snapshot_id,
                    credential_id=credential_id,
                    credential_generation=credential_generation,
                )
            return QuotaObservationResult(
                QuotaObservationStatus.RECORDED,
                candidate_snapshot_id,
                True,
                transition,
            )

    def operator_recover(
        self,
        *,
        quota_scope_id: str,
        actor_id: str,
        now_ms: int,
        expected_generation: int | None = None,
        event_id: str | None = None,
    ) -> QuotaTransitionResult:
        return self._operator_transition(
            quota_scope_id=quota_scope_id,
            actor_id=actor_id,
            now_ms=now_ms,
            new_state=QuotaScopeHealthState.HEALTHY,
            reason_code="OPERATOR_RECOVERY",
            expected_generation=expected_generation,
            event_id=event_id,
            allowed_from=set(QuotaScopeHealthState),
        )

    def operator_disable(
        self,
        *,
        quota_scope_id: str,
        actor_id: str,
        now_ms: int,
        expected_generation: int | None = None,
        event_id: str | None = None,
    ) -> QuotaTransitionResult:
        return self._operator_transition(
            quota_scope_id=quota_scope_id,
            actor_id=actor_id,
            now_ms=now_ms,
            new_state=QuotaScopeHealthState.DISABLED,
            reason_code="OPERATOR_DISABLED",
            expected_generation=expected_generation,
            event_id=event_id,
            allowed_from=set(QuotaScopeHealthState),
        )

    def operator_quarantine(
        self,
        *,
        quota_scope_id: str,
        actor_id: str,
        now_ms: int,
        expected_generation: int | None = None,
        event_id: str | None = None,
    ) -> QuotaTransitionResult:
        return self._operator_transition(
            quota_scope_id=quota_scope_id,
            actor_id=actor_id,
            now_ms=now_ms,
            new_state=QuotaScopeHealthState.QUARANTINED,
            reason_code="OPERATOR_QUARANTINED",
            expected_generation=expected_generation,
            event_id=event_id,
            allowed_from=set(QuotaScopeHealthState) - {QuotaScopeHealthState.DISABLED},
        )

    def _operator_transition(
        self,
        *,
        quota_scope_id: str,
        actor_id: str,
        now_ms: int,
        new_state: QuotaScopeHealthState,
        reason_code: str,
        expected_generation: int | None,
        event_id: str | None,
        allowed_from: set[QuotaScopeHealthState],
    ) -> QuotaTransitionResult:
        quota_scope_id = _bounded_text(quota_scope_id, field="quota scope identifier", maximum=160)
        actor_id = _bounded_text(actor_id, field="actor identifier", maximum=160)
        now_ms = require_sqlite_int64(now_ms, field="transition time", minimum=0)
        candidate_event_id = event_id or _identifier("quota_state")
        with transaction(self.connection, "IMMEDIATE"):
            scope = self._load_scope(quota_scope_id)
            if scope is None:
                return QuotaTransitionResult(QuotaTransitionStatus.NOT_FOUND, None, None)
            current_state = QuotaScopeHealthState(str(scope["state"]))
            if current_state not in allowed_from:
                return QuotaTransitionResult(
                    QuotaTransitionStatus.INELIGIBLE,
                    current_state,
                    int(scope["state_generation"]),
                )
            return self._transition_in_transaction(
                scope=scope,
                new_state=new_state,
                reason_code=reason_code,
                source=QuotaStateSource.OPERATOR,
                occurred_at_ms=now_ms,
                expected_generation=expected_generation,
                event_id=candidate_event_id,
                actor_id=actor_id,
            )

    def status(self, *, quota_scope_id: str, now_ms: int) -> RedactedQuotaScopeStatus | None:
        quota_scope_id = _bounded_text(quota_scope_id, field="quota scope identifier", maximum=160)
        now_ms = require_sqlite_int64(now_ms, field="current time", minimum=0)
        scope = self._load_scope(quota_scope_id)
        if scope is None:
            return None
        validation = validate_balance_authority(
            self.connection,
            quota_scope_id=scope["quota_scope_id"],
            unit=scope["unit"],
            last_known_remaining_units=scope["last_known_remaining_units"],
            balance_as_of_ms=scope["balance_as_of_ms"],
            balance_snapshot_id=scope["balance_snapshot_id"],
            now_ms=now_ms,
        )
        snapshot: sqlite3.Row | None = None
        if scope["balance_snapshot_id"] is not None:
            snapshot = self.connection.execute(
                """
                SELECT observed_remaining_units_decimal,
                       observed_plan_total_units_decimal, captured_at_ms,
                       stale_at_ms, source
                  FROM quota_snapshots WHERE snapshot_id = ?
                """,
                (scope["balance_snapshot_id"],),
            ).fetchone()
        stored_state = QuotaScopeHealthState(str(scope["state"]))
        effective_state = stored_state
        if stored_state not in {
            QuotaScopeHealthState.DISABLED,
            QuotaScopeHealthState.QUARANTINED,
            QuotaScopeHealthState.EXHAUSTED,
            QuotaScopeHealthState.COOLDOWN,
        }:
            if validation.status is not BalanceAuthorityStatus.VALID:
                effective_state = QuotaScopeHealthState.UNKNOWN
            elif scope["last_known_remaining_units"] == 0:
                effective_state = QuotaScopeHealthState.EXHAUSTED
            else:
                effective_state = QuotaScopeHealthState.HEALTHY
        exact_remaining: str | None = None
        exact_plan_total: str | None = None
        observed_at_ms: int | None = None
        stale_at_ms: int | None = None
        source: str | None = None
        if snapshot is not None:
            remaining = snapshot["observed_remaining_units_decimal"]
            plan = snapshot["observed_plan_total_units_decimal"]
            if type(remaining) is str:
                try:
                    exact_remaining = parse_canonical_provider_number(remaining).canonical
                except (TypeError, ValueError):
                    exact_remaining = None
            if type(plan) is str:
                try:
                    exact_plan_total = parse_canonical_provider_number(plan).canonical
                except (TypeError, ValueError):
                    exact_plan_total = None
            if type(snapshot["captured_at_ms"]) is int:
                observed_at_ms = int(snapshot["captured_at_ms"])
            if type(snapshot["stale_at_ms"]) is int:
                stale_at_ms = int(snapshot["stale_at_ms"])
            if type(snapshot["source"]) is str:
                source = str(snapshot["source"])
        return RedactedQuotaScopeStatus(
            alias=str(scope["alias"]),
            state=effective_state,
            exact_remaining=exact_remaining,
            exact_plan_total=exact_plan_total,
            observed_at_ms=observed_at_ms,
            stale_at_ms=stale_at_ms,
            stale=validation.status is not BalanceAuthorityStatus.VALID,
            source=source,
        )


def redacted_status_json(status: RedactedQuotaScopeStatus) -> str:
    """Serialize only the documented, non-secret account-status fields."""

    return json.dumps(
        {
            "alias": status.alias,
            "state": status.state.value,
            "remaining": status.exact_remaining,
            "plan_total": status.exact_plan_total,
            "observed_at_ms": status.observed_at_ms,
            "stale_at_ms": status.stale_at_ms,
            "stale": status.stale,
            "source": status.source,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
