"""Read-only, bounded operator Markdown projection of the authoritative audit log."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from gatehouse.core.clock import MAX_UTC_MS

_EVENT_TYPES = frozenset(
    {
        "account.added",
        "account.disabled",
        "account.recovered",
        "account.removed",
        "account.refreshed",
        "account.observation.changed",
        "pool.failover.changed",
        "credential.provisioned",
        "credential.rotated",
        "credential.disabled",
        "credential.quarantined",
        "credential.retired",
        "credential.rotation_recovery_failed",
        "credential.provider_validated",
        "credential.provider_validation_failed",
        "emergency.unlocked",
        "emergency.cancelled",
        "emergency.expired",
        "emergency.relocked_after_memory_loss",
        "emergency.relocked_on_shutdown",
        "runaway.quarantine_opened",
        "runaway.burst_cost_overrun",
        "runaway.burst_cost_unknown",
        "runaway.burst_recovery_required",
        "runaway.burst_authorized",
        "runaway.quarantine_denied",
        "runaway.fresh_run_recovered",
        "runaway.burst_expired",
        "runaway.burst_exhausted",
    }
)
_SEVERITIES = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_QUERY = """
    SELECT CASE WHEN typeof(occurred_at_ms) = 'integer'
                     AND occurred_at_ms BETWEEN 0 AND ?
                THEN occurred_at_ms ELSE NULL END AS timestamp_ms,
           substr(CAST(event_type AS BLOB), 1, 97) AS event_label,
           substr(CAST(severity AS BLOB), 1, 17) AS severity_label,
           CASE WHEN preserve = 1 THEN 1 ELSE 0 END AS retained
      FROM audit_events INDEXED BY idx_audit_events_time
     ORDER BY occurred_at_ms DESC, rowid DESC
     LIMIT ?
"""


class AuditViewUnavailable(RuntimeError):
    """No trustworthy bounded audit view could be produced."""


def _fixed_label(
    value: object, allowed: frozenset[str], *, fallback: str, uppercase: bool = False
) -> str:
    if type(value) is not bytes:
        return fallback
    try:
        decoded = value.decode("ascii")
    except UnicodeError:
        return fallback
    if uppercase:
        decoded = decoded.upper()
    return decoded if decoded in allowed else fallback


class SqliteAuditView:
    """Export at most 200 indexed rows without selecting payloads or arbitrary identifiers.

    SQLite and filesystem calls are synchronous. This caps rows, selected values and output;
    it does not promise a preemptive wall-clock deadline for local storage operations.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def markdown(self, *, limit: int = 100) -> str:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("audit view limit is invalid")
        rows: list[sqlite3.Row] | None = None
        try:
            if not self._connection.in_transaction:
                cursor = self._connection.execute(_QUERY, (MAX_UTC_MS, limit + 1))
                try:
                    rows = cursor.fetchall()
                finally:
                    cursor.close()
        except sqlite3.Error:
            pass
        if rows is None:
            raise AuditViewUnavailable("audit view is unavailable")
        lines = [
            "# Gatehouse audit events",
            "",
            f"{min(len(rows), limit)} event(s), newest first. Times are UTC.",
            "",
            "This metadata view omits payloads, identifiers, credentials and provider responses. "
            "Unrecognized event labels appear as Other. The database is authoritative.",
            "",
            "| Time (UTC) | Event | Severity | Preserved |",
            "| --- | --- | --- | --- |",
        ]
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        for row in rows[:limit]:
            timestamp = row["timestamp_ms"]
            displayed_time = "Unavailable"
            if type(timestamp) is int and 0 <= timestamp <= MAX_UTC_MS:
                displayed_time = (
                    (epoch + timedelta(milliseconds=timestamp))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                )
            event = _fixed_label(row["event_label"], _EVENT_TYPES, fallback="Other")
            severity = _fixed_label(
                row["severity_label"], _SEVERITIES, fallback="UNKNOWN", uppercase=True
            )
            retained = "Yes" if row["retained"] == 1 else "No"
            lines.append(f"| {displayed_time} | {event} | {severity} | {retained} |")
        if len(rows) > limit:
            lines.extend(
                ("", "Older events are available in the database; this export is bounded.")
            )
        result = "\n".join(lines) + "\n"
        if len(result.encode("utf-8")) > 65_536:
            raise AuditViewUnavailable("audit view is unavailable")
        return result
