"""Fixed-field lifecycle diagnostics retained in the private state database."""

from __future__ import annotations

import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from gatehouse.core.clock import require_utc_ms
from gatehouse.database.connection import transaction


class LifecyclePhase(StrEnum):
    RECOVERING = "RECOVERING"
    READY = "READY"
    DEGRADED_NO_PROVIDER = "DEGRADED_NO_PROVIDER"
    DRAINING = "DRAINING"
    FAILED_CLOSED = "FAILED_CLOSED"
    CUSTODY_CLOSED = "CUSTODY_CLOSED"
    TRANSPORT_CLOSED = "TRANSPORT_CLOSED"
    DATABASE_FINALIZING = "DATABASE_FINALIZING"


class LifecycleDiagnosticsUnavailable(RuntimeError):
    """No bounded trusted diagnostic projection could be read."""


class LifecycleConnectionUnavailable(RuntimeError):
    """A failed diagnostic write left its shared connection unusable."""

    def __init__(self) -> None:
        super().__init__("lifecycle diagnostic connection is unavailable")


@dataclass(frozen=True, slots=True)
class LifecycleRecord:
    sequence: int
    run_id: str
    occurred_at_ms: int
    phase: LifecyclePhase


class LifecycleJournal:
    """Keep 256 fixed-field records; failed writes are explicit best-effort loss.

    Ordinary lost records leave the caller's lifecycle result intact. An unusable
    shared connection is a hard failure requiring admission to close. This journal
    cannot certify effects occurring after database closure.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        now_ms: Callable[[], int],
        run_id: str | None = None,
    ) -> None:
        selected = uuid.uuid4().hex if run_id is None else run_id
        if type(selected) is not str or re.fullmatch(r"[0-9a-f]{32}", selected) is None:
            raise ValueError("lifecycle correlation is invalid")
        self._connection = connection
        self._now_ms = now_ms
        self._run_id = selected
        self._dropped = 0
        self._connection_unavailable = False

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def dropped_count(self) -> int:
        return self._dropped

    @property
    def connection_unavailable(self) -> bool:
        return self._connection_unavailable

    def record(self, phase: LifecyclePhase) -> bool:
        if type(phase) is not LifecyclePhase:
            raise ValueError("lifecycle phase is invalid")
        if self._connection_unavailable:
            self._dropped = min(256, self._dropped + 1)
            raise LifecycleConnectionUnavailable()
        try:
            if self._connection.in_transaction:
                self._dropped = min(256, self._dropped + 1)
                return False
            now = require_utc_ms(self._now_ms())
            with transaction(self._connection, "IMMEDIATE"):
                # Read at most 257 keys, even if an externally changed database
                # violates the schema's bounded insertion contract.
                keys = self._connection.execute(
                    "SELECT sequence FROM lifecycle_diagnostics ORDER BY sequence DESC LIMIT 257"
                ).fetchall()
                if len(keys) > 256:
                    raise LifecycleDiagnosticsUnavailable
                if len(keys) == 256:
                    self._connection.execute(
                        "DELETE FROM lifecycle_diagnostics WHERE sequence = ?", (keys[-1][0],)
                    )
                self._connection.execute(
                    "INSERT INTO lifecycle_diagnostics(run_id, occurred_at_ms, phase) "
                    "VALUES (?, ?, ?)",
                    (self.run_id, now, phase.value),
                )
            return True
        except BaseException as error:
            if isinstance(error, Exception):
                self._dropped = min(256, self._dropped + 1)
            usable = False
            try:
                usable = not self._connection.in_transaction
            except Exception:
                usable = False
            except BaseException:
                if isinstance(error, Exception):
                    raise
            if not usable:
                self._connection_unavailable = True
            if not isinstance(error, Exception):
                raise
            if usable:
                return False
        raise LifecycleConnectionUnavailable() from None

    def recent(self, *, limit: int = 100) -> tuple[LifecycleRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("lifecycle read limit is invalid")
        try:
            rows = self._connection.execute(
                "SELECT sequence, substr(CAST(run_id AS BLOB), 1, 33), "
                "CASE WHEN typeof(occurred_at_ms) = 'integer' THEN occurred_at_ms ELSE NULL END, "
                "substr(CAST(phase AS BLOB), 1, 33) FROM lifecycle_diagnostics "
                "ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()
            result: list[LifecycleRecord] = []
            for sequence, encoded_run, occurred, encoded_phase in rows:
                if type(sequence) is not int or not 1 <= sequence < 2**63:
                    raise ValueError
                if type(encoded_run) is not bytes or type(encoded_phase) is not bytes:
                    raise ValueError
                run = encoded_run.decode("ascii")
                if re.fullmatch(r"[0-9a-f]{32}", run) is None:
                    raise ValueError
                result.append(
                    LifecycleRecord(
                        sequence,
                        run,
                        require_utc_ms(occurred),
                        LifecyclePhase(encoded_phase.decode("ascii")),
                    )
                )
            return tuple(result)
        except Exception:  # noqa: S110 - fixed refusal is raised outside the exception context
            pass
        raise LifecycleDiagnosticsUnavailable("lifecycle diagnostics are unavailable")
