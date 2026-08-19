"""Idempotent settlement of usage reported by terminal asynchronous jobs."""

from __future__ import annotations

import sqlite3
from typing import Protocol

from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock
from gatehouse.invocations import BudgetReservation

from .models import JobRecord


class QuotaSettlementRepository(Protocol):
    def reconcile_quota_reservation(
        self,
        *,
        reservation_id: str,
        actual_units: int | None,
        now_ms: int,
        outcome_known: bool,
    ) -> bool: ...


class BudgetSettlementGateway(Protocol):
    async def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        actual_units: int | None,
        outcome_known: bool,
    ) -> None: ...


class JobSettlementError(RuntimeError):
    """A terminal observation could not safely settle its creating request."""


class SqliteJobSettlementGateway:
    """Resolve the original crawl reservation, never the zero-cost status call."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        quota: QuotaSettlementRepository,
        budgets: BudgetSettlementGateway,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
    ) -> None:
        self._connection = connection
        self._quota = quota
        self._budgets = budgets
        self._clock = clock

    async def reconcile(self, job: JobRecord, *, actual_units: int) -> None:
        if (
            isinstance(actual_units, bool)
            or not isinstance(actual_units, int)
            or not 0 <= actual_units < (1 << 63)
        ):
            raise ValueError("job settlement usage is outside its integer bound")
        rows = self._connection.execute(
            """
            SELECT qr.reservation_id, qr.quota_scope_id, qr.amount_units,
                   qr.actual_units, qr.unit, qr.state, qr.created_at_ms
              FROM quota_reservations AS qr
              JOIN invocations AS i ON i.request_id = qr.request_id
             WHERE qr.request_id = ?
               AND i.session_id = ? AND i.root_run_id = ?
               AND i.service_id = ? AND i.operation = ? AND i.state = 'SUCCEEDED'
             ORDER BY qr.created_at_ms DESC, qr.reservation_id DESC
            """,
            (
                str(job.request_id),
                str(job.owner.session_id),
                str(job.owner.root_run_id),
                job.service_id,
                job.operation,
            ),
        ).fetchall()
        if not rows:
            raise JobSettlementError("job creating request has no quota reservation")
        unresolved = [
            row
            for row in rows
            if str(row["state"]) in {"ACTIVE", "PENDING_RECONCILIATION", "DISPUTED"}
        ]
        if len(unresolved) > 1:
            raise JobSettlementError("job has multiple unresolved quota reservations")
        if unresolved:
            selected = unresolved[0]
            if str(selected["quota_scope_id"]) != str(job.quota_scope_id):
                raise JobSettlementError("job quota reservation authority changed")
        else:
            matching = [
                row
                for row in rows
                if str(row["quota_scope_id"]) == str(job.quota_scope_id)
                and str(row["state"]) == "RECONCILED"
                and row["actual_units"] is not None
                and int(row["actual_units"]) == actual_units
            ]
            if not matching:
                raise JobSettlementError("job quota reservation was settled differently")
            selected = matching[0]
        for historical in rows:
            if historical is selected:
                continue
            if (
                str(historical["state"]) != "RECONCILED"
                or historical["actual_units"] is None
                or int(historical["actual_units"]) != 0
            ):
                raise JobSettlementError("job has conflicting historical quota usage")
        unit = str(selected["unit"])
        if unresolved:
            settled = self._quota.reconcile_quota_reservation(
                reservation_id=str(selected["reservation_id"]),
                actual_units=actual_units,
                now_ms=self._clock.now_ms(),
                outcome_known=True,
            )
            if not settled:
                raise JobSettlementError("job quota reservation changed concurrently")
        elif (
            str(selected["state"]) != "RECONCILED"
            or selected["actual_units"] is None
            or int(selected["actual_units"]) != actual_units
        ):
            raise JobSettlementError("job quota reservation was settled differently")

        budget = self._connection.execute(
            """
            SELECT budget_reservation_id, amount_units, unit
              FROM budget_reservations
             WHERE request_id = ? AND root_run_id = ?
            """,
            (str(job.request_id), str(job.owner.root_run_id)),
        ).fetchone()
        if budget is None:
            raise JobSettlementError("job creating request has no budget reservation")
        if str(budget["unit"]) != unit:
            raise JobSettlementError("job quota and budget units differ")
        await self._budgets.reconcile(
            BudgetReservation(
                reservation_id=str(budget["budget_reservation_id"]),
                amount_units=int(budget["amount_units"]),
                unit=unit,
            ),
            actual_units=actual_units,
            outcome_known=True,
        )
