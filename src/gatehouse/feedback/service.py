"""Bounded advisory feedback that cannot mutate privileged control state."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from gatehouse.credentials.redaction import SecretScanner
from gatehouse.database.connection import transaction


class FeedbackState(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ACCEPTED = "ACCEPTED"
    PLANNED = "PLANNED"
    FIXED = "FIXED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"


@dataclass(frozen=True, slots=True)
class FeedbackRecord:
    feedback_id: str
    session_id: str | None
    category: str
    severity: str
    component: str
    summary: str
    state: FeedbackState
    created_at_ms: int
    content: Mapping[str, Any]


class FeedbackService:
    """Persist untrusted suggestions with no policy-changing side effects."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        identifier: Callable[[str], str] | None = None,
        scanner: SecretScanner | None = None,
    ) -> None:
        self._connection = connection
        self._identifier = identifier or (lambda prefix: f"{prefix}_{uuid.uuid4().hex}")
        self._scanner = scanner or SecretScanner()

    def submit(
        self,
        *,
        session_id: str | None,
        category: str,
        severity: str,
        component: str,
        summary: str,
        content: Mapping[str, Any] | None,
        now_ms: int,
    ) -> FeedbackRecord:
        values = (category, severity, component, summary)
        if any(not value.strip() for value in values):
            raise ValueError("feedback metadata fields are required")
        if len(summary) > 1_000 or max(map(len, values[:3])) > 100:
            raise ValueError("feedback metadata exceeds its size bound")
        sanitized = self._scanner.sanitize(dict(content or {}), location="feedback")
        encoded = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 16_384:
            raise ValueError("feedback content exceeds its size bound")
        feedback_id = self._identifier("feedback")
        with transaction(self._connection):
            self._connection.execute(
                """
                INSERT INTO feedback(
                    feedback_id, session_id, category, severity, component,
                    summary, state, created_at_ms, content_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?, ?)
                """,
                (
                    feedback_id,
                    session_id,
                    category.strip(),
                    severity.strip(),
                    component.strip(),
                    summary.strip(),
                    now_ms,
                    encoded,
                ),
            )
        return FeedbackRecord(
            feedback_id=feedback_id,
            session_id=session_id,
            category=category.strip(),
            severity=severity.strip(),
            component=component.strip(),
            summary=summary.strip(),
            state=FeedbackState.NEW,
            created_at_ms=now_ms,
            content=sanitized,
        )

    def update_state(self, feedback_id: str, state: FeedbackState) -> bool:
        with transaction(self._connection):
            cursor = self._connection.execute(
                "UPDATE feedback SET state = ? WHERE feedback_id = ?",
                (state.value, feedback_id),
            )
        return cursor.rowcount == 1

    def list(
        self,
        *,
        state: FeedbackState | None = None,
        limit: int = 100,
    ) -> tuple[FeedbackRecord, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("feedback list limit is outside its bound")
        if state is None:
            rows = self._connection.execute(
                "SELECT * FROM feedback ORDER BY created_at_ms DESC, feedback_id LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = self._connection.execute(
                """
                SELECT * FROM feedback WHERE state = ?
                ORDER BY created_at_ms DESC, feedback_id LIMIT ?
                """,
                (state.value, limit),
            ).fetchall()
        return tuple(self._row(row) for row in rows)

    def export_markdown(self, *, limit: int = 500) -> str:
        lines = ["# Feedback report", ""]
        for record in self.list(limit=limit):
            lines.extend(
                [
                    f"## {record.feedback_id}: {record.summary}",
                    "",
                    f"- State: {record.state.value}",
                    f"- Category: {record.category}",
                    f"- Severity: {record.severity}",
                    f"- Component: {record.component}",
                    f"- Created: {record.created_at_ms}",
                    "",
                ]
            )
        return "\n".join(lines)

    @staticmethod
    def _row(row: sqlite3.Row) -> FeedbackRecord:
        return FeedbackRecord(
            feedback_id=str(row["feedback_id"]),
            session_id=str(row["session_id"]) if row["session_id"] is not None else None,
            category=str(row["category"]),
            severity=str(row["severity"]),
            component=str(row["component"]),
            summary=str(row["summary"]),
            state=FeedbackState(str(row["state"])),
            created_at_ms=int(row["created_at_ms"]),
            content=json.loads(str(row["content_json"])),
        )
