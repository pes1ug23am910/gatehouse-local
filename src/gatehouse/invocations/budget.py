"""Bounded in-memory root-run budgets behind the coordinator budget protocol."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping

from gatehouse.core.ids import RootRunId
from gatehouse.database.connection import transaction

from .models import BudgetReservation, InvocationRequest, InvocationSession


class BudgetUnavailableError(RuntimeError):
    pass


class InMemoryBudgetGateway:
    """Atomic process-local budget accounting for tests and non-durable deployments."""

    def __init__(self, limits: Mapping[RootRunId, int]) -> None:
        if not limits or any(
            isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
            for limit in limits.values()
        ):
            raise ValueError("root-run budget limits must be non-negative integers")
        self._remaining = dict(limits)
        self._reservations: dict[str, tuple[RootRunId, int, str]] = {}
        self._sequence = 0
        self._lock = asyncio.Lock()

    async def reserve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        amount_units: int,
        unit: str,
    ) -> BudgetReservation:
        if amount_units <= 0 or not unit:
            raise ValueError("budget reservation amount and unit are required")
        if request.root_run_id != session.root_run_id:
            raise ValueError("request root run does not match the authenticated session")
        async with self._lock:
            remaining = self._remaining.get(session.root_run_id)
            if remaining is None or remaining < amount_units:
                raise BudgetUnavailableError("root-run budget is exhausted")
            self._remaining[session.root_run_id] = remaining - amount_units
            self._sequence += 1
            reservation_id = f"budget-{self._sequence}"
            self._reservations[reservation_id] = (
                session.root_run_id,
                amount_units,
                unit,
            )
            return BudgetReservation(reservation_id, amount_units, unit)

    async def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        actual_units: int | None,
        outcome_known: bool,
    ) -> None:
        if actual_units is not None and actual_units < 0:
            raise ValueError("actual budget usage cannot be negative")
        async with self._lock:
            stored = self._reservations.get(reservation.reservation_id)
            if stored is None:
                raise RuntimeError("budget reservation is not active")
            if not outcome_known:
                return
            root_run_id, amount_units, unit = self._reservations.pop(reservation.reservation_id)
            if unit != reservation.unit:
                raise RuntimeError("budget reservation unit changed")
            resolved_actual = amount_units if actual_units is None else actual_units
            refund = amount_units - resolved_actual
            self._remaining[root_run_id] = max(
                0,
                self._remaining[root_run_id] + refund,
            )

    async def remaining(self, root_run_id: RootRunId) -> int:
        async with self._lock:
            return self._remaining[root_run_id]


class SqliteBudgetGateway:
    """Atomic, restart-persistent accounting against one root-run budget."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        now_ms: Callable[[], int],
    ) -> None:
        self._connection = connection
        self._now_ms = now_ms

    @staticmethod
    def _mapping(raw: str) -> dict[str, int]:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("root-run budget metadata is invalid") from exc
        if not isinstance(value, dict):
            raise RuntimeError("root-run budget metadata is invalid")
        result: dict[str, int] = {}
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not key
                or isinstance(item, bool)
                or not isinstance(item, int)
                or item < 0
            ):
                raise RuntimeError("root-run budget metadata is invalid")
            result[key] = item
        return result

    def _remaining_locked(self, root_run_id: str, unit: str) -> int:
        row = self._connection.execute(
            "SELECT state, budget_json, consumed_json FROM root_runs WHERE root_run_id = ?",
            (root_run_id,),
        ).fetchone()
        if row is None or row["state"] != "ACTIVE":
            raise BudgetUnavailableError("root run is unavailable")
        maximum = self._mapping(str(row["budget_json"])).get(unit)
        if maximum is None:
            raise BudgetUnavailableError("root-run budget unit is unavailable")
        consumed = self._mapping(str(row["consumed_json"])).get(unit, 0)
        held = int(
            self._connection.execute(
                """
                SELECT COALESCE(SUM(amount_units), 0)
                  FROM budget_reservations
                 WHERE root_run_id = ? AND unit = ?
                   AND state IN ('ACTIVE', 'PENDING_RECONCILIATION')
                """,
                (root_run_id, unit),
            ).fetchone()[0]
        )
        return max(0, maximum - consumed - held)

    async def reserve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        amount_units: int,
        unit: str,
    ) -> BudgetReservation:
        if amount_units <= 0 or not unit:
            raise ValueError("budget reservation amount and unit are required")
        if request.root_run_id != session.root_run_id:
            raise ValueError("request root run does not match the authenticated session")
        reservation_id = f"budget_{uuid.uuid4().hex}"
        now = self._now_ms()
        with transaction(self._connection, "IMMEDIATE"):
            owner = self._connection.execute(
                """
                SELECT rr.session_id
                  FROM root_runs AS rr
                  JOIN invocations AS i ON i.root_run_id = rr.root_run_id
                 WHERE rr.root_run_id = ? AND i.request_id = ?
                """,
                (str(session.root_run_id), str(request.request_id)),
            ).fetchone()
            if owner is None or owner["session_id"] != str(session.session_id):
                raise ValueError("request and root run ownership do not match")
            if self._remaining_locked(str(session.root_run_id), unit) < amount_units:
                raise BudgetUnavailableError("root-run budget is exhausted")
            try:
                self._connection.execute(
                    """
                    INSERT INTO budget_reservations(
                        budget_reservation_id, request_id, root_run_id,
                        amount_units, unit, state, created_at_ms
                    ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
                    """,
                    (
                        reservation_id,
                        str(request.request_id),
                        str(session.root_run_id),
                        amount_units,
                        unit,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeError("request already owns a budget reservation") from exc
        return BudgetReservation(reservation_id, amount_units, unit)

    async def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        actual_units: int | None,
        outcome_known: bool,
    ) -> None:
        if actual_units is not None and actual_units < 0:
            raise ValueError("actual budget usage cannot be negative")
        if outcome_known and actual_units is None:
            raise ValueError("known budget outcomes require actual usage")
        if not outcome_known and actual_units is not None:
            raise ValueError("ambiguous budget outcomes cannot assert usage")
        with transaction(self._connection, "IMMEDIATE"):
            row = self._connection.execute(
                "SELECT * FROM budget_reservations WHERE budget_reservation_id = ?",
                (reservation.reservation_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("budget reservation does not exist")
            if (
                int(row["amount_units"]) != reservation.amount_units
                or row["unit"] != reservation.unit
            ):
                raise RuntimeError("budget reservation authority changed")
            if not outcome_known:
                if row["state"] == "RECONCILED":
                    raise RuntimeError("a reconciled budget cannot become ambiguous")
                self._connection.execute(
                    """
                    UPDATE budget_reservations SET state = 'PENDING_RECONCILIATION'
                     WHERE budget_reservation_id = ? AND state = 'ACTIVE'
                    """,
                    (reservation.reservation_id,),
                )
                return
            assert actual_units is not None
            if row["state"] == "RECONCILED":
                if row["actual_units"] is None or int(row["actual_units"]) != actual_units:
                    raise RuntimeError("budget reservation was reconciled differently")
                return
            root_run = self._connection.execute(
                "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
                (row["root_run_id"],),
            ).fetchone()
            if root_run is None:
                raise RuntimeError("budget reservation root run does not exist")
            consumed = self._mapping(str(root_run["consumed_json"]))
            consumed[reservation.unit] = consumed.get(reservation.unit, 0) + actual_units
            updated = self._connection.execute(
                """
                UPDATE budget_reservations
                   SET state = 'RECONCILED', actual_units = ?, reconciled_at_ms = ?
                 WHERE budget_reservation_id = ?
                   AND state IN ('ACTIVE', 'PENDING_RECONCILIATION')
                """,
                (actual_units, self._now_ms(), reservation.reservation_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("budget reservation changed concurrently")
            self._connection.execute(
                "UPDATE root_runs SET consumed_json = ? WHERE root_run_id = ?",
                (
                    json.dumps(consumed, sort_keys=True, separators=(",", ":")),
                    row["root_run_id"],
                ),
            )

    async def remaining(self, root_run_id: RootRunId, unit: str) -> int:
        if not unit:
            raise ValueError("budget unit is required")
        with transaction(self._connection, "DEFERRED"):
            return self._remaining_locked(str(root_run_id), unit)
