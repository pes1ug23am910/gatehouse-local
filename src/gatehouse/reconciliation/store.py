"""Durable snapshot, mismatch, incident, and quarantine transitions."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping

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
    ReconciliationPolicy,
    RecordedReconciliation,
    UsageSnapshot,
)


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
        reconciliation_id = _new_id("recon")
        item_id = _new_id("reconitem")
        with transaction(self.connection, "IMMEDIATE"):
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
            snapshots = self._latest_snapshots_locked(quota_scope_id)
            current = snapshots[0] if snapshots else None
            previous = snapshots[1] if len(snapshots) > 1 else None
            ledger = self._ledger_window_locked(
                quota_scope_id,
                previous=previous,
                current=current,
                manual_adjustment_units=manual_adjustment_units,
            )
            ownership = self._ownership_locked(quota_scope_id)
            (
                prior_consecutive,
                recorded_previous_snapshot_id,
                recorded_current_snapshot_id,
            ) = self._prior_state_locked(quota_scope_id)
            previous_snapshot_id = None if previous is None else previous.snapshot_id
            current_snapshot_id = None if current is None else current.snapshot_id
            decision = reconcile_usage(
                previous=previous,
                current=current,
                ledger=ledger,
                ownership=ownership,
                policy=policy,
                prior_consecutive_mismatches=prior_consecutive,
                now_ms=now_ms,
                observation_is_new=(previous_snapshot_id, current_snapshot_id)
                != (recorded_previous_snapshot_id, recorded_current_snapshot_id),
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
                    ownership.value,
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
        return RecordedReconciliation(reconciliation_id, item_id, decision, alert_id)

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
    ) -> tuple[int, str | None, str | None]:
        row = self.connection.execute(
            """
            SELECT ri.provider_delta_units, ri.provider_delta_units_decimal,
                   ri.unexplained_delta_units, ri.unexplained_delta_units_decimal,
                   ri.allowed_tolerance_units_decimal, ri.details_json
              FROM reconciliation_items AS ri
              JOIN reconciliation_runs AS rr
                ON rr.reconciliation_id = ri.reconciliation_id
             WHERE ri.quota_scope_id = ?
             ORDER BY rr.started_at_ms DESC, ri.item_id DESC LIMIT 1
            """,
            (quota_scope_id,),
        ).fetchone()
        if row is None:
            return 0, None, None
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
        return value, previous_snapshot_id, current_snapshot_id

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
        previous_snapshot_id: str | None,
        current_snapshot_id: str | None,
    ) -> dict[str, object]:
        return {
            "action": decision.action.value,
            "allowed_tolerance_units": decision.allowed_tolerance_units_decimal,
            "allowed_tolerance_units_decimal": decision.allowed_tolerance_units_decimal,
            "consecutive_mismatches": decision.consecutive_mismatches,
            "incident_required": decision.incident_required,
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
