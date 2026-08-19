"""Bounded retention and WAL-maintenance primitives."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .connection import TransactionNestingError, transaction

DAY_MS = 24 * 60 * 60 * 1_000


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    detailed_metadata_age_ms: int = 60 * DAY_MS
    daily_aggregate_age_ms: int = 365 * DAY_MS
    closed_admin_session_age_ms: int = 7 * DAY_MS
    completed_approval_age_ms: int = 180 * DAY_MS
    maximum_rows_per_table: int = 1_000

    def __post_init__(self) -> None:
        values = (
            self.detailed_metadata_age_ms,
            self.daily_aggregate_age_ms,
            self.closed_admin_session_age_ms,
            self.completed_approval_age_ms,
            self.maximum_rows_per_table,
        )
        if any(value <= 0 for value in values):
            raise ValueError("retention durations and batch limits must be positive")


@dataclass(frozen=True, slots=True)
class RetentionReport:
    debug_excerpts_deleted: int
    audit_events_deleted: int
    daily_aggregates_deleted: int
    admin_sessions_deleted: int
    approvals_deleted: int

    @property
    def total_deleted(self) -> int:
        return sum(
            (
                self.debug_excerpts_deleted,
                self.audit_events_deleted,
                self.daily_aggregates_deleted,
                self.admin_sessions_deleted,
                self.approvals_deleted,
            )
        )


def apply_retention(
    connection: sqlite3.Connection,
    *,
    now_ms: int,
    policy: RetentionPolicy | None = None,
) -> RetentionReport:
    """Delete at most one configured batch from each eligible data class."""

    active_policy = policy or RetentionPolicy()
    limit = active_policy.maximum_rows_per_table
    with transaction(connection, "IMMEDIATE"):
        debug_deleted = connection.execute(
            """
            DELETE FROM debug_excerpts
             WHERE excerpt_id IN (
                 SELECT excerpt_id FROM debug_excerpts
                  WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?
             )
            """,
            (now_ms, limit),
        ).rowcount
        audit_deleted = connection.execute(
            """
            DELETE FROM audit_events
             WHERE event_id IN (
                 SELECT event_id FROM audit_events
                  WHERE preserve = 0 AND occurred_at_ms <= ?
                  ORDER BY occurred_at_ms LIMIT ?
             )
            """,
            (now_ms - active_policy.detailed_metadata_age_ms, limit),
        ).rowcount
        daily_deleted = connection.execute(
            """
            DELETE FROM daily_usage_aggregates
             WHERE aggregate_id IN (
                 SELECT aggregate_id FROM daily_usage_aggregates
                  WHERE created_at_ms <= ? ORDER BY created_at_ms LIMIT ?
             )
            """,
            (now_ms - active_policy.daily_aggregate_age_ms, limit),
        ).rowcount
        admin_deleted = connection.execute(
            """
            DELETE FROM admin_sessions
             WHERE admin_session_id IN (
                 SELECT admin_session_id FROM admin_sessions
                  WHERE state IN ('REVOKED', 'EXPIRED')
                    AND COALESCE(revoked_at_ms, absolute_expires_at_ms) <= ?
                  ORDER BY COALESCE(revoked_at_ms, absolute_expires_at_ms) LIMIT ?
             )
            """,
            (now_ms - active_policy.closed_admin_session_age_ms, limit),
        ).rowcount
        approvals_deleted = connection.execute(
            """
            DELETE FROM approvals
             WHERE approval_id IN (
                 SELECT approval_id FROM approvals
                  WHERE state IN ('CONSUMED', 'DENIED', 'EXPIRED')
                    AND COALESCE(consumed_at_ms, decided_at_ms, expires_at_ms) <= ?
                  ORDER BY COALESCE(consumed_at_ms, decided_at_ms, expires_at_ms) LIMIT ?
             )
            """,
            (now_ms - active_policy.completed_approval_age_ms, limit),
        ).rowcount

    return RetentionReport(
        debug_excerpts_deleted=debug_deleted,
        audit_events_deleted=audit_deleted,
        daily_aggregates_deleted=daily_deleted,
        admin_sessions_deleted=admin_deleted,
        approvals_deleted=approvals_deleted,
    )


def checkpoint_wal(
    connection: sqlite3.Connection,
    *,
    mode: Literal["PASSIVE", "FULL", "RESTART", "TRUNCATE"] = "PASSIVE",
) -> tuple[int, int, int]:
    """Run an explicit WAL checkpoint outside a write transaction."""

    if mode not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
        raise ValueError(f"unsupported WAL checkpoint mode: {mode!r}")
    if connection.in_transaction:
        raise TransactionNestingError("WAL checkpoint cannot run inside a transaction")
    row = connection.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()
    return int(row[0]), int(row[1]), int(row[2])


def database_footprint(path: str | Path) -> int:
    """Return database + WAL + shared-memory bytes without opening the database."""

    database_path = Path(path)
    return sum(
        candidate.stat().st_size
        for candidate in (
            database_path,
            Path(f"{database_path}-wal"),
            Path(f"{database_path}-shm"),
        )
        if candidate.exists()
    )
