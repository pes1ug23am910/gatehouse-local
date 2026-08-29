"""Bounded retention and WAL-maintenance primitives."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Literal

from .connection import TransactionNestingError, transaction
from .footprint import database_footprint as database_footprint

DAY_MS = 24 * 60 * 60 * 1_000


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    detailed_metadata_age_ms: int = 60 * DAY_MS
    daily_aggregate_age_ms: int = 365 * DAY_MS
    closed_admin_session_age_ms: int = 7 * DAY_MS
    completed_approval_age_ms: int = 180 * DAY_MS
    maximum_rows_per_table: int = 1_000
    feedback_age_ms: int = 60 * DAY_MS
    debug_excerpt_age_ms: int = 3 * DAY_MS
    closed_alert_age_ms: int = 60 * DAY_MS

    def __post_init__(self) -> None:
        values = (
            self.detailed_metadata_age_ms,
            self.feedback_age_ms,
            self.daily_aggregate_age_ms,
            self.closed_admin_session_age_ms,
            self.completed_approval_age_ms,
            self.maximum_rows_per_table,
            self.debug_excerpt_age_ms,
            self.closed_alert_age_ms,
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
    feedback_deleted: int = 0
    alerts_deleted: int = 0

    @property
    def total_deleted(self) -> int:
        return sum(
            (
                self.debug_excerpts_deleted,
                self.audit_events_deleted,
                self.feedback_deleted,
                self.alerts_deleted,
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
        debug_expired_deleted = connection.execute(
            """
            DELETE FROM debug_excerpts
             WHERE excerpt_id IN (
                 SELECT excerpt_id
                   FROM debug_excerpts INDEXED BY idx_debug_excerpts_retention_expiry
                  WHERE expires_at_ms <= ?
                  ORDER BY expires_at_ms, excerpt_id LIMIT ?
             )
            """,
            (now_ms, limit),
        ).rowcount
        debug_age_deleted = 0
        debug_remaining = limit - debug_expired_deleted
        if debug_remaining > 0:
            debug_age_deleted = connection.execute(
                """
                DELETE FROM debug_excerpts
                 WHERE excerpt_id IN (
                     SELECT excerpt_id
                       FROM debug_excerpts INDEXED BY idx_debug_excerpts_retention_created
                      WHERE created_at_ms <= ?
                      ORDER BY created_at_ms, excerpt_id LIMIT ?
                 )
                """,
                (now_ms - active_policy.debug_excerpt_age_ms, debug_remaining),
            ).rowcount
        debug_deleted = debug_expired_deleted + debug_age_deleted
        audit_deleted = connection.execute(
            """
            DELETE FROM audit_events
             WHERE event_id IN (
                 SELECT event_id FROM audit_events INDEXED BY idx_audit_events_retention
                  WHERE preserve = 0 AND occurred_at_ms <= ?
                  ORDER BY occurred_at_ms, event_id LIMIT ?
             )
            """,
            (now_ms - active_policy.detailed_metadata_age_ms, limit),
        ).rowcount
        feedback_deleted = connection.execute(
            """
            DELETE FROM feedback
             WHERE feedback_id IN (
                 SELECT feedback_id FROM feedback INDEXED BY idx_feedback_retention
                  WHERE created_at_ms <= ?
                  ORDER BY created_at_ms, feedback_id LIMIT ?
             )
            """,
            (now_ms - active_policy.feedback_age_ms, limit),
        ).rowcount
        alerts_deleted = connection.execute(
            """
            DELETE FROM alerts
             WHERE alert_id IN (
                 SELECT alert_id FROM alerts INDEXED BY idx_alerts_retention
                  WHERE created_at_ms <= ?
                    AND state IN ('RESOLVED', 'CLOSED')
                    AND severity IN ('INFO', 'LOW')
                    AND preserve = 0
                    AND substr(lower(category), 1, 8) <> 'watchdog'
                  ORDER BY created_at_ms, alert_id LIMIT ?
             )
            """,
            (now_ms - active_policy.closed_alert_age_ms, limit),
        ).rowcount
        daily_deleted = connection.execute(
            """
            DELETE FROM daily_usage_aggregates
             WHERE aggregate_id IN (
                 SELECT aggregate_id
                   FROM daily_usage_aggregates
                        INDEXED BY idx_daily_usage_aggregates_retention
                  WHERE created_at_ms <= ?
                  ORDER BY created_at_ms, aggregate_id LIMIT ?
             )
            """,
            (now_ms - active_policy.daily_aggregate_age_ms, limit),
        ).rowcount
        admin_deleted = connection.execute(
            """
            DELETE FROM admin_sessions
             WHERE admin_session_id IN (
                 SELECT admin_session_id
                   FROM admin_sessions INDEXED BY idx_admin_sessions_retention
                  WHERE state IN ('REVOKED', 'EXPIRED')
                    AND COALESCE(revoked_at_ms, absolute_expires_at_ms) <= ?
                  ORDER BY COALESCE(revoked_at_ms, absolute_expires_at_ms),
                           admin_session_id LIMIT ?
             )
            """,
            (now_ms - active_policy.closed_admin_session_age_ms, limit),
        ).rowcount
        approvals_deleted = connection.execute(
            """
            DELETE FROM approvals
             WHERE approval_id IN (
                 SELECT approval_id
                   FROM approvals INDEXED BY idx_approvals_retention
                  WHERE state IN ('CONSUMED', 'DENIED', 'EXPIRED')
                    AND COALESCE(consumed_at_ms, decided_at_ms, expires_at_ms) <= ?
                  ORDER BY COALESCE(consumed_at_ms, decided_at_ms, expires_at_ms),
                           approval_id LIMIT ?
             )
            """,
            (now_ms - active_policy.completed_approval_age_ms, limit),
        ).rowcount

    return RetentionReport(
        debug_excerpts_deleted=debug_deleted,
        audit_events_deleted=audit_deleted,
        feedback_deleted=feedback_deleted,
        alerts_deleted=alerts_deleted,
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
