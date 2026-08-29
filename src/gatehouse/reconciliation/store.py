"""Durable snapshot, mismatch, incident, and quarantine transitions."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace

from gatehouse.core.provider_numbers import (
    ExactProviderNumber,
    compatibility_sqlite_int,
    parse_canonical_allowed_tolerance,
    parse_canonical_provider_delta,
    parse_canonical_reconciliation_delta,
)
from gatehouse.credentials import SecretScanner
from gatehouse.database import AuditEvent, transaction

from .engine import reconcile_usage
from .models import (
    LedgerWindow,
    OwnershipMode,
    ReconciliationDecision,
    ReconciliationMode,
    ReconciliationPolicy,
    ReconciliationState,
    RecordedReconciliation,
    ScheduledReconciliationOutcome,
    UsageSnapshot,
)


@dataclass(frozen=True, slots=True)
class _DueReconciliation:
    quota_scope_id: str
    service_id: str
    mode: ReconciliationMode
    baseline_snapshot_id: str | None
    generation: int
    last_reconciliation_id: str | None


class ReconciliationPersistenceError(RuntimeError):
    """Raised when persisted quota state violates reconciliation assumptions."""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _metadata(raw: str) -> dict[str, object]:
    value: object = json.loads(raw)
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReconciliationPersistenceError("snapshot or reconciliation metadata is malformed")
    return {str(key): item for key, item in value.items()}


def _durable_reconciliation_decimal(
    value: object,
    *,
    required: bool,
    parser: Callable[[str], ExactProviderNumber],
) -> ExactProviderNumber | None:
    if value is None:
        if required:
            raise ReconciliationPersistenceError("stored exact reconciliation value is missing")
        return None
    if type(value) is not str:
        raise ReconciliationPersistenceError("stored exact reconciliation value is malformed")
    try:
        exact = parser(value)
    except (TypeError, ValueError):
        raise ReconciliationPersistenceError(
            "stored exact reconciliation value is malformed"
        ) from None
    return exact


class ReconciliationStore:
    """Persist summary counters only; no provider request or response bodies."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        scanner: SecretScanner | None = None,
    ) -> None:
        self.connection = connection
        self._scanner = scanner or SecretScanner()

    def record_snapshot(
        self,
        snapshot: UsageSnapshot,
        *,
        source: str,
        audit_event: AuditEvent | None = None,
    ) -> str:
        if not source or len(source) > 100:
            raise ValueError("snapshot source is required and bounded")
        self._scanner.assert_clean(source, location="reconciliation.snapshot_source")
        if snapshot.reset_marker is not None:
            self._scanner.assert_clean(
                snapshot.reset_marker,
                location="reconciliation.reset_marker",
            )
        for observation in (
            snapshot.observed_remaining_units_decimal,
            snapshot.observed_plan_total_units_decimal,
        ):
            if observation is not None:
                self._scanner.assert_clean(
                    observation,
                    location="reconciliation.exact_observation",
                )
        if audit_event is not None:
            self._validate_audit_event(audit_event)
            if audit_event.occurred_at_ms != snapshot.captured_at_ms:
                raise ValueError("audit event and snapshot capture times do not match")
        snapshot_id = snapshot.snapshot_id or _new_id("snapshot")
        metadata: dict[str, object] = {}
        if snapshot.used_units is not None:
            metadata["used_units"] = snapshot.used_units
        if snapshot.reset_marker is not None:
            metadata["reset_marker"] = snapshot.reset_marker
        with transaction(self.connection, "IMMEDIATE"):
            scope = self.connection.execute(
                """
                SELECT scope.unit, scope.last_refreshed_at_ms,
                       scope.balance_as_of_ms, scope.balance_snapshot_id,
                       dimension.quota_dimension_id
                  FROM quota_scopes AS scope
                  JOIN quota_dimensions AS dimension
                    ON dimension.quota_scope_id = scope.quota_scope_id
                   AND dimension.is_primary = 1
                   AND dimension.state = 'ACTIVE'
                   AND dimension.native_unit = scope.unit
                 WHERE scope.quota_scope_id = ?
                """,
                (snapshot.quota_scope_id,),
            ).fetchone()
            if scope is None:
                raise ReconciliationPersistenceError("quota scope does not exist")
            if str(scope["unit"]) != snapshot.unit:
                raise ReconciliationPersistenceError("snapshot unit does not match quota scope")
            self.connection.execute(
                """
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                    observed_remaining_units_decimal,
                    observed_plan_total_units_decimal,
                    unit, period_start_ms, period_end_ms, captured_at_ms,
                    source, metadata_json, quota_dimension_id,
                    used_units, observed_used_units_decimal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    snapshot.quota_scope_id,
                    snapshot.remaining_units,
                    snapshot.plan_total_units,
                    snapshot.observed_remaining_units_decimal,
                    snapshot.observed_plan_total_units_decimal,
                    snapshot.unit,
                    snapshot.period_start_ms,
                    snapshot.period_end_ms,
                    snapshot.captured_at_ms,
                    source,
                    _json(metadata),
                    str(scope["quota_dimension_id"]),
                    snapshot.used_units,
                    str(snapshot.used_units) if snapshot.used_units is not None else None,
                ),
            )
            last_refreshed = scope["last_refreshed_at_ms"]
            if last_refreshed is None or int(last_refreshed) <= snapshot.captured_at_ms:
                self.connection.execute(
                    """
                    UPDATE quota_scopes
                       SET billing_period_start_ms = COALESCE(?, billing_period_start_ms),
                           billing_period_end_ms = COALESCE(?, billing_period_end_ms),
                           last_refreshed_at_ms = ?
                     WHERE quota_scope_id = ?
                    """,
                    (
                        snapshot.period_start_ms,
                        snapshot.period_end_ms,
                        snapshot.captured_at_ms,
                        snapshot.quota_scope_id,
                    ),
                )
            balance_as_of = scope["balance_as_of_ms"]
            balance_snapshot_id = scope["balance_snapshot_id"]
            balance_is_newer = balance_as_of is None or (
                snapshot.captured_at_ms > int(balance_as_of)
                or (
                    snapshot.captured_at_ms == int(balance_as_of)
                    and (balance_snapshot_id is None or snapshot_id > str(balance_snapshot_id))
                )
            )
            if snapshot.remaining_units is not None and balance_is_newer:
                self.connection.execute(
                    """
                    UPDATE quota_scopes
                       SET last_known_remaining_units = ?,
                           balance_as_of_ms = ?,
                           balance_snapshot_id = ?
                     WHERE quota_scope_id = ?
                    """,
                    (
                        snapshot.remaining_units,
                        snapshot.captured_at_ms,
                        snapshot_id,
                        snapshot.quota_scope_id,
                    ),
                )
            if audit_event is not None:
                self._insert_audit_event(audit_event)
        return snapshot_id

    def record_snapshot_with_audit(
        self,
        snapshot: UsageSnapshot,
        *,
        source: str,
        audit_event: AuditEvent,
    ) -> str:
        """Persist a sanitized snapshot and its audit event in one transaction."""

        return self.record_snapshot(snapshot, source=source, audit_event=audit_event)

    def record_audit_event(self, event: AuditEvent) -> str:
        """Persist one sanitized audit event in its own short transaction."""

        self._validate_audit_event(event)
        with transaction(self.connection, "IMMEDIATE"):
            self._insert_audit_event(event)
        return event.event_id

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
        if event.occurred_at_ms < 0 or not isinstance(event.preserve, bool):
            raise ValueError("audit event fields are invalid")
        for value, maximum in bounded_fields:
            if value is not None and (not value or len(value) > maximum):
                raise ValueError("audit event fields are invalid")
            if value is not None:
                self._scanner.assert_clean(value, location="reconciliation.audit_field")
        if len(event.payload_json.encode("utf-8")) > 8_192:
            raise ValueError("audit event payload exceeds its byte limit")
        try:
            payload: object = json.loads(event.payload_json)
        except json.JSONDecodeError:
            raise ValueError("audit event payload is malformed") from None
        if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
            raise ValueError("audit event payload is malformed")
        self._scanner.assert_clean(
            event.payload_json,
            location="reconciliation.audit_payload",
        )

    def latest_snapshots(self, quota_scope_id: str, *, limit: int = 2) -> tuple[UsageSnapshot, ...]:
        if limit <= 0 or limit > 100:
            raise ValueError("snapshot limit is outside the supported range")
        rows = self.connection.execute(
            """
            SELECT snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                   observed_remaining_units_decimal,
                   observed_plan_total_units_decimal,
                   unit, period_start_ms, period_end_ms, captured_at_ms, metadata_json
              FROM quota_snapshots
             WHERE quota_scope_id = ?
             ORDER BY captured_at_ms DESC, snapshot_id DESC
             LIMIT ?
            """,
            (quota_scope_id, limit),
        ).fetchall()
        return tuple(self._snapshot_from_row(row) for row in rows)

    def reconcile_scope(
        self,
        *,
        quota_scope_id: str,
        service_id: str,
        policy: ReconciliationPolicy,
        now_ms: int,
        manual_adjustment_units: int = 0,
    ) -> RecordedReconciliation:
        """Record one operator-requested comparison without advancing either cadence."""

        self._validate_now(now_ms)
        with transaction(self.connection, "IMMEDIATE"):
            schedule = self._schedule_state_locked(quota_scope_id)
            self._require_scope_service_locked(
                quota_scope_id=quota_scope_id,
                service_id=service_id,
            )
            snapshots = self._latest_snapshots_locked(quota_scope_id)
            current = snapshots[0] if snapshots else None
            previous = snapshots[1] if len(snapshots) > 1 else None
            result = self._record_reconciliation_locked(
                quota_scope_id,
                service_id=service_id,
                mode=ReconciliationMode.MANUAL,
                previous=previous,
                current=current,
                last_reconciliation_id=schedule.last_reconciliation_id,
                policy=policy,
                now_ms=now_ms,
                manual_adjustment_units=manual_adjustment_units,
            )
            self._advance_schedule_locked(
                schedule,
                reconciliation_id=result.reconciliation_id,
                current_snapshot_id=None,
                checked_at_ms=None,
                mode=ReconciliationMode.MANUAL,
            )
        return result

    def reconcile_next_due_scope(
        self,
        *,
        policy: ReconciliationPolicy,
        now_ms: int,
        quick_interval_ms: int,
        full_interval_ms: int,
    ) -> ScheduledReconciliationOutcome | None:
        """Atomically reconcile and advance at most one due local scope."""

        self._validate_schedule_inputs(
            now_ms=now_ms,
            quick_interval_ms=quick_interval_ms,
            full_interval_ms=full_interval_ms,
        )
        with transaction(self.connection, "IMMEDIATE"):
            due = self._next_due_scope_locked(
                now_ms=now_ms,
                quick_interval_ms=quick_interval_ms,
                full_interval_ms=full_interval_ms,
            )
            if due is None:
                return None
            current = self._latest_snapshot_locked(due.quota_scope_id)
            current_snapshot_id = None if current is None else current.snapshot_id
            if current_snapshot_id == due.baseline_snapshot_id:
                should_record_stale_transition = current is not None and (
                    current.captured_at_ms > now_ms
                    or now_ms - current.captured_at_ms > policy.maximum_snapshot_age_ms
                )
                if should_record_stale_transition and due.last_reconciliation_id is not None:
                    _, recorded_current_snapshot_id, recorded_state = self._prior_state_locked(
                        due.quota_scope_id,
                        reconciliation_id=due.last_reconciliation_id,
                    )
                    should_record_stale_transition = not (
                        recorded_current_snapshot_id == current_snapshot_id
                        and recorded_state is ReconciliationState.STALE
                    )
                if not should_record_stale_transition:
                    self._advance_schedule_locked(
                        due,
                        reconciliation_id=None,
                        current_snapshot_id=current_snapshot_id,
                        checked_at_ms=now_ms,
                        mode=due.mode,
                    )
                    return ScheduledReconciliationOutcome(
                        quota_scope_id=due.quota_scope_id,
                        mode=due.mode,
                        recorded=None,
                    )
            previous = self._baseline_snapshot_locked(
                due.quota_scope_id,
                baseline_snapshot_id=due.baseline_snapshot_id,
                current=current,
            )
            result = self._record_reconciliation_locked(
                due.quota_scope_id,
                service_id=due.service_id,
                mode=due.mode,
                previous=previous,
                current=current,
                last_reconciliation_id=due.last_reconciliation_id,
                policy=policy,
                now_ms=now_ms,
                manual_adjustment_units=0,
            )
            self._advance_schedule_locked(
                due,
                reconciliation_id=result.reconciliation_id,
                current_snapshot_id=current_snapshot_id,
                checked_at_ms=now_ms,
                mode=due.mode,
            )
        return ScheduledReconciliationOutcome(
            quota_scope_id=due.quota_scope_id,
            mode=due.mode,
            recorded=result,
        )

    @staticmethod
    def _validate_now(now_ms: int) -> None:
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("reconciliation time is invalid")

    @classmethod
    def _validate_schedule_inputs(
        cls,
        *,
        now_ms: int,
        quick_interval_ms: int,
        full_interval_ms: int,
    ) -> None:
        cls._validate_now(now_ms)
        for interval in (quick_interval_ms, full_interval_ms):
            if (
                isinstance(interval, bool)
                or not isinstance(interval, int)
                or not 1 <= interval <= 2**63 - 1
            ):
                raise ValueError("reconciliation interval is invalid")
        if full_interval_ms < quick_interval_ms:
            raise ValueError("full reconciliation interval must not be shorter than quick")

    def _require_scope_service_locked(
        self,
        *,
        quota_scope_id: str,
        service_id: str,
    ) -> None:
        service = self.connection.execute(
            """
            SELECT p.service_id
              FROM quota_scopes AS qs
              JOIN principals AS p ON p.principal_id = qs.principal_id
             WHERE qs.quota_scope_id = ?
            """,
            (quota_scope_id,),
        ).fetchone()
        if service is None or str(service["service_id"]) != service_id:
            raise ReconciliationPersistenceError("quota scope does not belong to service")

    def _schedule_state_locked(self, quota_scope_id: str) -> _DueReconciliation:
        row = self.connection.execute(
            """
            SELECT schedule.quota_scope_id, principal.service_id,
                   schedule.generation, schedule.last_reconciliation_id
              FROM reconciliation_scope_schedules AS schedule
              JOIN quota_scopes AS scope
                ON scope.quota_scope_id = schedule.quota_scope_id
              JOIN principals AS principal
                ON principal.principal_id = scope.principal_id
             WHERE schedule.quota_scope_id = ?
            """,
            (quota_scope_id,),
        ).fetchone()
        if row is None:
            raise ReconciliationPersistenceError("reconciliation schedule state is missing")
        return self._due_from_row(row, mode=ReconciliationMode.MANUAL, baseline_column=None)

    def _next_due_scope_locked(
        self,
        *,
        now_ms: int,
        quick_interval_ms: int,
        full_interval_ms: int,
    ) -> _DueReconciliation | None:
        full_cutoff = now_ms - full_interval_ms
        quick_cutoff = now_ms - quick_interval_ms
        row = self.connection.execute(
            """
            SELECT schedule.quota_scope_id, principal.service_id,
                   schedule.full_baseline_snapshot_id,
                   schedule.generation, schedule.last_reconciliation_id
              FROM reconciliation_scope_schedules AS schedule
              JOIN quota_scopes AS scope
                ON scope.quota_scope_id = schedule.quota_scope_id
              JOIN principals AS principal
                ON principal.principal_id = scope.principal_id
             WHERE schedule.full_last_checked_at_ms IS NULL
             ORDER BY schedule.quota_scope_id
             LIMIT 1
            """
        ).fetchone()
        if row is None and full_cutoff >= 0:
            row = self.connection.execute(
                """
                SELECT schedule.quota_scope_id, principal.service_id,
                       schedule.full_baseline_snapshot_id,
                       schedule.generation, schedule.last_reconciliation_id
                  FROM reconciliation_scope_schedules AS schedule
                  JOIN quota_scopes AS scope
                    ON scope.quota_scope_id = schedule.quota_scope_id
                  JOIN principals AS principal
                    ON principal.principal_id = scope.principal_id
                 WHERE schedule.full_last_checked_at_ms <= ?
                 ORDER BY schedule.full_last_checked_at_ms, schedule.quota_scope_id
                 LIMIT 1
                """,
                (full_cutoff,),
            ).fetchone()
        if row is not None:
            return self._due_from_row(
                row,
                mode=ReconciliationMode.FULL,
                baseline_column="full_baseline_snapshot_id",
            )
        row = self.connection.execute(
            """
            SELECT schedule.quota_scope_id, principal.service_id,
                   schedule.quick_baseline_snapshot_id,
                   schedule.generation, schedule.last_reconciliation_id
              FROM reconciliation_scope_schedules AS schedule
              JOIN quota_scopes AS scope
                ON scope.quota_scope_id = schedule.quota_scope_id
              JOIN principals AS principal
                ON principal.principal_id = scope.principal_id
             WHERE schedule.quick_last_checked_at_ms IS NULL
             ORDER BY schedule.quota_scope_id
             LIMIT 1
            """
        ).fetchone()
        if row is None and quick_cutoff >= 0:
            row = self.connection.execute(
                """
                SELECT schedule.quota_scope_id, principal.service_id,
                       schedule.quick_baseline_snapshot_id,
                       schedule.generation, schedule.last_reconciliation_id
                  FROM reconciliation_scope_schedules AS schedule
                  JOIN quota_scopes AS scope
                    ON scope.quota_scope_id = schedule.quota_scope_id
                  JOIN principals AS principal
                    ON principal.principal_id = scope.principal_id
                 WHERE schedule.quick_last_checked_at_ms <= ?
                 ORDER BY schedule.quick_last_checked_at_ms, schedule.quota_scope_id
                 LIMIT 1
                """,
                (quick_cutoff,),
            ).fetchone()
        if row is None:
            return None
        return self._due_from_row(
            row,
            mode=ReconciliationMode.QUICK,
            baseline_column="quick_baseline_snapshot_id",
        )

    @staticmethod
    def _due_from_row(
        row: sqlite3.Row,
        *,
        mode: ReconciliationMode,
        baseline_column: str | None,
    ) -> _DueReconciliation:
        raw_generation = row["generation"]
        if type(raw_generation) is not int or raw_generation < 0:
            raise ReconciliationPersistenceError("reconciliation schedule generation is invalid")
        raw_pointer = row["last_reconciliation_id"]
        if raw_pointer is not None and type(raw_pointer) is not str:
            raise ReconciliationPersistenceError("reconciliation state pointer is invalid")
        raw_baseline = None if baseline_column is None else row[baseline_column]
        if raw_baseline is not None and type(raw_baseline) is not str:
            raise ReconciliationPersistenceError("reconciliation baseline pointer is invalid")
        return _DueReconciliation(
            quota_scope_id=str(row["quota_scope_id"]),
            service_id=str(row["service_id"]),
            mode=mode,
            baseline_snapshot_id=raw_baseline,
            generation=raw_generation,
            last_reconciliation_id=raw_pointer,
        )

    def _record_reconciliation_locked(
        self,
        quota_scope_id: str,
        *,
        service_id: str,
        mode: ReconciliationMode,
        previous: UsageSnapshot | None,
        current: UsageSnapshot | None,
        last_reconciliation_id: str | None,
        policy: ReconciliationPolicy,
        now_ms: int,
        manual_adjustment_units: int,
    ) -> RecordedReconciliation:
        reconciliation_id = _new_id("recon")
        item_id = _new_id("reconitem")
        ledger = self._ledger_window_locked(
            quota_scope_id,
            previous=previous,
            current=current,
            manual_adjustment_units=manual_adjustment_units,
        )
        ownership = self._ownership_locked(quota_scope_id)
        prior_consecutive, recorded_current_snapshot_id, _ = self._prior_state_locked(
            quota_scope_id,
            reconciliation_id=last_reconciliation_id,
        )
        previous_snapshot_id = None if previous is None else previous.snapshot_id
        current_snapshot_id = None if current is None else current.snapshot_id
        observation_is_new = (
            current_snapshot_id is not None and current_snapshot_id != recorded_current_snapshot_id
        )
        decision = reconcile_usage(
            previous=previous,
            current=current,
            ledger=ledger,
            ownership=ownership,
            policy=policy,
            prior_consecutive_mismatches=prior_consecutive,
            now_ms=now_ms,
            observation_is_new=observation_is_new,
        )
        if not observation_is_new and decision.consecutive_mismatches != prior_consecutive:
            decision = replace(
                decision,
                consecutive_mismatches=prior_consecutive,
                incident_required=False,
                quarantine_local=False,
            )
        self.connection.execute(
            """
            INSERT INTO reconciliation_runs(
                reconciliation_id, service_id, mode, state, started_at_ms,
                completed_at_ms, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reconciliation_id,
                service_id,
                mode.value,
                "COMPLETED",
                now_ms,
                now_ms,
                _json(
                    {
                        "state": decision.state.value,
                        "action": decision.action.value,
                        "incident_required": decision.incident_required,
                        "quarantine_local": decision.quarantine_local,
                    }
                ),
            ),
        )
        self.connection.execute(
            """
            INSERT INTO reconciliation_items(
                item_id, reconciliation_id, quota_scope_id, provider_delta_units,
                ledger_delta_units, manual_adjustment_units,
                unexplained_delta_units, provider_delta_units_decimal,
                unexplained_delta_units_decimal, allowed_tolerance_units_decimal,
                unit, state, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                reconciliation_id,
                quota_scope_id,
                decision.provider_delta_units,
                decision.ledger_settled_units,
                decision.manual_adjustment_units,
                decision.unexplained_delta_units,
                decision.provider_delta_units_decimal,
                decision.unexplained_delta_units_decimal,
                decision.allowed_tolerance_units_decimal,
                self._scope_unit_locked(quota_scope_id),
                decision.state.value,
                _json(
                    self._decision_details(
                        decision,
                        mode=mode,
                        observation_is_new=observation_is_new,
                        previous_snapshot_id=previous_snapshot_id,
                        current_snapshot_id=current_snapshot_id,
                    )
                ),
            ),
        )
        alert_id = self._apply_incident_locked(
            quota_scope_id=quota_scope_id,
            service_id=service_id,
            reconciliation_id=reconciliation_id,
            decision=decision,
            now_ms=now_ms,
        )
        return RecordedReconciliation(
            reconciliation_id,
            item_id,
            decision,
            alert_id,
            mode,
        )

    def _advance_schedule_locked(
        self,
        schedule: _DueReconciliation,
        *,
        reconciliation_id: str | None,
        current_snapshot_id: str | None,
        checked_at_ms: int | None,
        mode: ReconciliationMode,
    ) -> None:
        if mode is ReconciliationMode.MANUAL:
            assert reconciliation_id is not None
            updated = self.connection.execute(
                """
                UPDATE reconciliation_scope_schedules
                   SET last_reconciliation_id = ?, generation = generation + 1
                 WHERE quota_scope_id = ? AND generation = ?
                """,
                (
                    reconciliation_id,
                    schedule.quota_scope_id,
                    schedule.generation,
                ),
            )
        elif mode is ReconciliationMode.QUICK:
            assert checked_at_ms is not None
            if reconciliation_id is None:
                updated = self.connection.execute(
                    """
                    UPDATE reconciliation_scope_schedules
                       SET quick_last_checked_at_ms = ?, generation = generation + 1
                     WHERE quota_scope_id = ? AND generation = ?
                    """,
                    (
                        checked_at_ms,
                        schedule.quota_scope_id,
                        schedule.generation,
                    ),
                )
            else:
                updated = self.connection.execute(
                    """
                    UPDATE reconciliation_scope_schedules
                       SET quick_baseline_snapshot_id = COALESCE(
                               ?, quick_baseline_snapshot_id
                           ),
                           quick_last_checked_at_ms = ?,
                           last_reconciliation_id = ?, generation = generation + 1
                     WHERE quota_scope_id = ? AND generation = ?
                    """,
                    (
                        current_snapshot_id,
                        checked_at_ms,
                        reconciliation_id,
                        schedule.quota_scope_id,
                        schedule.generation,
                    ),
                )
        else:
            assert mode is ReconciliationMode.FULL
            assert checked_at_ms is not None
            updated = self.connection.execute(
                """
                UPDATE reconciliation_scope_schedules
                   SET quick_baseline_snapshot_id = COALESCE(
                           ?, quick_baseline_snapshot_id
                       ),
                       full_baseline_snapshot_id = COALESCE(
                           ?, full_baseline_snapshot_id
                       ),
                       quick_last_checked_at_ms = ?,
                       full_last_checked_at_ms = ?,
                       last_reconciliation_id = COALESCE(?, last_reconciliation_id),
                       generation = generation + 1
                 WHERE quota_scope_id = ? AND generation = ?
                """,
                (
                    current_snapshot_id,
                    current_snapshot_id,
                    checked_at_ms,
                    checked_at_ms,
                    reconciliation_id,
                    schedule.quota_scope_id,
                    schedule.generation,
                ),
            )
        if updated.rowcount != 1:
            raise ReconciliationPersistenceError("reconciliation schedule state changed")

    def _latest_snapshots_locked(self, quota_scope_id: str) -> tuple[UsageSnapshot, ...]:
        rows = self.connection.execute(
            """
            SELECT snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                   observed_remaining_units_decimal,
                   observed_plan_total_units_decimal,
                   unit, period_start_ms, period_end_ms, captured_at_ms, metadata_json
              FROM quota_snapshots WHERE quota_scope_id = ?
             ORDER BY captured_at_ms DESC, snapshot_id DESC LIMIT 2
            """,
            (quota_scope_id,),
        ).fetchall()
        return tuple(self._snapshot_from_row(row) for row in rows)

    def _latest_snapshot_locked(self, quota_scope_id: str) -> UsageSnapshot | None:
        snapshots = self._latest_snapshots_locked(quota_scope_id)
        return snapshots[0] if snapshots else None

    def _baseline_snapshot_locked(
        self,
        quota_scope_id: str,
        *,
        baseline_snapshot_id: str | None,
        current: UsageSnapshot | None,
    ) -> UsageSnapshot | None:
        if baseline_snapshot_id is None:
            if current is not None:
                raise ReconciliationPersistenceError(
                    "reconciliation baseline is missing for an observed scope"
                )
            return None
        row = self.connection.execute(
            """
            SELECT snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                   observed_remaining_units_decimal,
                   observed_plan_total_units_decimal,
                   unit, period_start_ms, period_end_ms, captured_at_ms, metadata_json
              FROM quota_snapshots
             WHERE snapshot_id = ? AND quota_scope_id = ?
            """,
            (baseline_snapshot_id, quota_scope_id),
        ).fetchone()
        if row is None:
            raise ReconciliationPersistenceError("reconciliation baseline is unavailable")
        return self._snapshot_from_row(row)

    @staticmethod
    def _snapshot_from_row(row: sqlite3.Row) -> UsageSnapshot:
        metadata = _metadata(str(row["metadata_json"]))
        raw_used = metadata.get("used_units")
        raw_reset = metadata.get("reset_marker")
        if raw_used is not None and (isinstance(raw_used, bool) or not isinstance(raw_used, int)):
            raise ReconciliationPersistenceError("stored used counter is malformed")
        if raw_reset is not None and not isinstance(raw_reset, str):
            raise ReconciliationPersistenceError("stored reset marker is malformed")
        raw_remaining = row["remaining_units"]
        raw_plan = row["plan_total_units"]
        raw_remaining_observation = row["observed_remaining_units_decimal"]
        raw_plan_observation = row["observed_plan_total_units_decimal"]
        for projected, observation in (
            (raw_remaining, raw_remaining_observation),
            (raw_plan, raw_plan_observation),
        ):
            if (projected is None) != (observation is None):
                raise ReconciliationPersistenceError(
                    "stored projected and exact snapshot counters are unpaired"
                )
            if projected is not None and type(projected) is not int:
                raise ReconciliationPersistenceError("stored projected counter is malformed")
            if observation is not None and type(observation) is not str:
                raise ReconciliationPersistenceError("stored exact counter is malformed")
        try:
            return UsageSnapshot(
                snapshot_id=str(row["snapshot_id"]),
                quota_scope_id=str(row["quota_scope_id"]),
                remaining_units=raw_remaining,
                used_units=raw_used,
                plan_total_units=raw_plan,
                unit=str(row["unit"]),
                period_start_ms=(
                    None if row["period_start_ms"] is None else int(row["period_start_ms"])
                ),
                period_end_ms=(None if row["period_end_ms"] is None else int(row["period_end_ms"])),
                captured_at_ms=int(row["captured_at_ms"]),
                reset_marker=raw_reset,
                observed_remaining_units_decimal=raw_remaining_observation,
                observed_plan_total_units_decimal=raw_plan_observation,
            )
        except (TypeError, ValueError):
            raise ReconciliationPersistenceError("stored snapshot counters are malformed") from None

    def _ledger_window_locked(
        self,
        quota_scope_id: str,
        *,
        previous: UsageSnapshot | None,
        current: UsageSnapshot | None,
        manual_adjustment_units: int,
    ) -> LedgerWindow:
        if previous is None or current is None:
            settled = 0
        else:
            settled = int(
                self.connection.execute(
                    """
                    SELECT COALESCE(SUM(actual_units), 0) FROM quota_reservations
                     WHERE quota_scope_id = ? AND state = 'RECONCILED'
                       AND actual_units IS NOT NULL
                       AND reconciled_at_ms > ? AND reconciled_at_ms <= ?
                    """,
                    (quota_scope_id, previous.captured_at_ms, current.captured_at_ms),
                ).fetchone()[0]
            )
        pending = int(
            self.connection.execute(
                """
                SELECT COALESCE(SUM(amount_units), 0) FROM quota_reservations
                 WHERE quota_scope_id = ?
                   AND state IN ('ACTIVE', 'PENDING_RECONCILIATION', 'DISPUTED')
                   AND (? IS NULL OR created_at_ms <= ?)
                """,
                (
                    quota_scope_id,
                    None if current is None else current.captured_at_ms,
                    None if current is None else current.captured_at_ms,
                ),
            ).fetchone()[0]
        )
        return LedgerWindow(
            settled_units=settled,
            pending_reserved_units=pending,
            manual_adjustment_units=manual_adjustment_units,
        )

    def _ownership_locked(self, quota_scope_id: str) -> OwnershipMode:
        rows = self.connection.execute(
            "SELECT exclusive_usage FROM credentials WHERE quota_scope_id = ?",
            (quota_scope_id,),
        ).fetchall()
        if not rows:
            return OwnershipMode.UNKNOWN
        return (
            OwnershipMode.EXCLUSIVE
            if all(int(row["exclusive_usage"]) == 1 for row in rows)
            else OwnershipMode.SHARED
        )

    def _prior_state_locked(
        self,
        quota_scope_id: str,
        *,
        reconciliation_id: str | None,
    ) -> tuple[int, str | None, ReconciliationState | None]:
        if reconciliation_id is None:
            return 0, None, None
        rows = self.connection.execute(
            """
            SELECT ri.provider_delta_units, ri.provider_delta_units_decimal,
                   ri.unexplained_delta_units, ri.unexplained_delta_units_decimal,
                   ri.allowed_tolerance_units_decimal, ri.state, ri.details_json
              FROM reconciliation_items AS ri
              JOIN reconciliation_runs AS rr
                ON rr.reconciliation_id = ri.reconciliation_id
             WHERE ri.quota_scope_id = ? AND rr.reconciliation_id = ?
             LIMIT 2
            """,
            (quota_scope_id, reconciliation_id),
        ).fetchall()
        if len(rows) != 1:
            raise ReconciliationPersistenceError("exact reconciliation state pointer is invalid")
        row = rows[0]
        try:
            state = ReconciliationState(str(row["state"]))
        except ValueError:
            raise ReconciliationPersistenceError(
                "stored reconciliation state is malformed"
            ) from None
        metadata = _metadata(str(row["details_json"]))
        provider_exact = _durable_reconciliation_decimal(
            row["provider_delta_units_decimal"],
            required=False,
            parser=parse_canonical_provider_delta,
        )
        unexplained_exact = _durable_reconciliation_decimal(
            row["unexplained_delta_units_decimal"],
            required=False,
            parser=parse_canonical_reconciliation_delta,
        )
        allowed_exact = _durable_reconciliation_decimal(
            row["allowed_tolerance_units_decimal"],
            required=True,
            parser=parse_canonical_allowed_tolerance,
        )
        for compatibility, exact in (
            (row["provider_delta_units"], provider_exact),
            (row["unexplained_delta_units"], unexplained_exact),
        ):
            if compatibility is not None and type(compatibility) is not int:
                raise ReconciliationPersistenceError("stored compatibility delta is malformed")
            expected_compatibility = None if exact is None else compatibility_sqlite_int(exact)
            if compatibility != expected_compatibility:
                raise ReconciliationPersistenceError("stored exact and compatibility deltas differ")
        if allowed_exact is None:  # pragma: no cover - required above
            raise ReconciliationPersistenceError("stored exact tolerance is missing")
        stored_allowed_detail = metadata.get("allowed_tolerance_units")
        if stored_allowed_detail != allowed_exact.canonical:
            raise ReconciliationPersistenceError("stored exact tolerance details differ")
        for key, exact in (
            ("provider_delta_units_decimal", provider_exact),
            ("unexplained_delta_units_decimal", unexplained_exact),
            ("allowed_tolerance_units_decimal", allowed_exact),
        ):
            if key in metadata and metadata[key] != (None if exact is None else exact.canonical):
                raise ReconciliationPersistenceError("stored exact reconciliation details differ")
        value = metadata.get("consecutive_mismatches", 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReconciliationPersistenceError("stored mismatch counter is malformed")
        previous_snapshot_id = metadata.get("previous_snapshot_id")
        current_snapshot_id = metadata.get("current_snapshot_id")
        if previous_snapshot_id is not None and not isinstance(previous_snapshot_id, str):
            raise ReconciliationPersistenceError("stored snapshot identity is malformed")
        if current_snapshot_id is not None and not isinstance(current_snapshot_id, str):
            raise ReconciliationPersistenceError("stored snapshot identity is malformed")
        for snapshot_id in (previous_snapshot_id, current_snapshot_id):
            if snapshot_id is not None:
                snapshot = self.connection.execute(
                    """
                    SELECT 1 FROM quota_snapshots
                     WHERE snapshot_id = ? AND quota_scope_id = ?
                    """,
                    (snapshot_id, quota_scope_id),
                ).fetchone()
                if snapshot is None:
                    raise ReconciliationPersistenceError(
                        "stored reconciliation snapshot identity is invalid"
                    )
        return value, current_snapshot_id, state

    def _scope_unit_locked(self, quota_scope_id: str) -> str:
        row = self.connection.execute(
            "SELECT unit FROM quota_scopes WHERE quota_scope_id = ?",
            (quota_scope_id,),
        ).fetchone()
        if row is None:  # pragma: no cover - checked earlier in the transaction
            raise ReconciliationPersistenceError("quota scope does not exist")
        return str(row["unit"])

    @staticmethod
    def _decision_details(
        decision: ReconciliationDecision,
        *,
        mode: ReconciliationMode,
        observation_is_new: bool,
        previous_snapshot_id: str | None,
        current_snapshot_id: str | None,
    ) -> dict[str, object]:
        return {
            "action": decision.action.value,
            "allowed_tolerance_units": decision.allowed_tolerance_units_decimal,
            "allowed_tolerance_units_decimal": decision.allowed_tolerance_units_decimal,
            "consecutive_mismatches": decision.consecutive_mismatches,
            "incident_required": decision.incident_required,
            "mode": mode.value,
            "observation_is_new": observation_is_new,
            "ownership": decision.ownership.value,
            "pending_reserved_units": decision.pending_reserved_units,
            "preserve_pending_reservations": decision.preserve_pending_reservations,
            "quarantine_local": decision.quarantine_local,
            "reason": decision.reason,
            "provider_delta_units_decimal": decision.provider_delta_units_decimal,
            "unexplained_delta_units_decimal": decision.unexplained_delta_units_decimal,
            "previous_snapshot_id": previous_snapshot_id,
            "current_snapshot_id": current_snapshot_id,
        }

    def _apply_incident_locked(
        self,
        *,
        quota_scope_id: str,
        service_id: str,
        reconciliation_id: str,
        decision: ReconciliationDecision,
        now_ms: int,
    ) -> str | None:
        if not decision.incident_required:
            return None
        alert_id = _new_id("alert")
        severity = "CRITICAL" if decision.quarantine_local else "HIGH"
        self.connection.execute(
            """
            INSERT INTO alerts(
                alert_id, severity, category, state, title, summary,
                created_at_ms, preserve, metadata_json
            ) VALUES (?, ?, 'QUOTA_RECONCILIATION_MISMATCH', 'OPEN', ?, ?, ?, 1, ?)
            """,
            (
                alert_id,
                severity,
                "Quota reconciliation mismatch",
                "Provider summary counters differ from the local usage ledger.",
                now_ms,
                _json(
                    {
                        "reconciliation_id": reconciliation_id,
                        "quota_scope_id": quota_scope_id,
                        "service_id": service_id,
                        "ownership": decision.ownership.value,
                    }
                ),
            ),
        )
        if decision.quarantine_local:
            self.connection.execute(
                "UPDATE quota_scopes SET state = 'QUARANTINED' WHERE quota_scope_id = ?",
                (quota_scope_id,),
            )
            self.connection.execute(
                """
                UPDATE credentials SET state = 'QUARANTINED', generation = generation + 1
                 WHERE quota_scope_id = ?
                   AND state NOT IN ('REVOKED', 'RETIRED', 'EXPIRED')
                """,
                (quota_scope_id,),
            )
        return alert_id
