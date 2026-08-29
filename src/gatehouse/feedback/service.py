"""Bounded advisory feedback that cannot mutate privileged control state."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from gatehouse.credentials.redaction import (
    SecretDetectedError,
    SecretFinding,
    SecretScanner,
)
from gatehouse.database.connection import transaction
from gatehouse.database.footprint import (
    DatabaseFootprintCapacityExceeded,
    DatabaseFootprintGuard,
)

type FeedbackCategoryValue = Literal[
    "contract",
    "documentation",
    "performance",
    "reliability",
    "security",
    "usability",
    "other",
]
type FeedbackSeverityValue = Literal["low", "medium", "high", "critical"]
type FeedbackComponentValue = Literal[
    "agent-api",
    "cli",
    "client",
    "configuration",
    "credentials",
    "database",
    "documentation",
    "feedback",
    "firecrawl.crawl",
    "firecrawl.map",
    "firecrawl.scrape",
    "firecrawl.search",
    "mcp",
    "policy",
    "routing",
    "runtime",
    "scheduler",
    "sessions",
    "transport",
    "watchdog",
    "watcher",
    "other",
]


class FeedbackCategory(StrEnum):
    CONTRACT = "contract"
    DOCUMENTATION = "documentation"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    SECURITY = "security"
    USABILITY = "usability"
    OTHER = "other"


class FeedbackSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeedbackComponent(StrEnum):
    AGENT_API = "agent-api"
    CLI = "cli"
    CLIENT = "client"
    CONFIGURATION = "configuration"
    CREDENTIALS = "credentials"
    DATABASE = "database"
    DOCUMENTATION = "documentation"
    FEEDBACK = "feedback"
    FIRECRAWL_CRAWL = "firecrawl.crawl"
    FIRECRAWL_MAP = "firecrawl.map"
    FIRECRAWL_SCRAPE = "firecrawl.scrape"
    FIRECRAWL_SEARCH = "firecrawl.search"
    MCP = "mcp"
    POLICY = "policy"
    ROUTING = "routing"
    RUNTIME = "runtime"
    SCHEDULER = "scheduler"
    SESSIONS = "sessions"
    TRANSPORT = "transport"
    WATCHDOG = "watchdog"
    WATCHER = "watcher"
    OTHER = "other"


class FeedbackState(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ACCEPTED = "ACCEPTED"
    PLANNED = "PLANNED"
    FIXED = "FIXED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"


class FeedbackCapacityExceeded(RuntimeError):
    """Raised without exposing feedback contents when admission is full."""

    def __init__(self) -> None:
        super().__init__("feedback capacity is exhausted")


@dataclass(frozen=True, slots=True)
class FeedbackRecord:
    feedback_id: str
    session_id: str | None
    category: FeedbackCategory
    severity: FeedbackSeverity
    component: FeedbackComponent
    summary: str
    state: FeedbackState
    created_at_ms: int
    content: Mapping[str, Any]


_GATEHOUSE_CAPABILITY_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
_FEEDBACK_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_MAXIMUM_CONTENT_BYTES = 16_384
_MAXIMUM_RECORDS_PER_SESSION = 100
_MAXIMUM_BYTES_PER_SESSION = 1_048_576
_MAXIMUM_CONFIGURED_RECORDS_PER_SESSION = 10_000
_MAXIMUM_CONFIGURED_BYTES_PER_SESSION = 64 * 1_048_576


def _require_enum[EnumValue: StrEnum](
    value: str,
    enum_type: type[EnumValue],
    *,
    field: str,
) -> EnumValue:
    for member in enum_type:
        if value == member.value:
            return member
    raise ValueError(f"feedback {field} is invalid")


def _markdown_literal(value: str) -> str:
    """Encode untrusted text without leaving Markdown control characters active."""

    return "".join(
        character
        if character.isascii() and (character.isalnum() or character in " .,:/_-")
        else f"&#x{ord(character):X};"
        for character in value
    )


class FeedbackService:
    """Persist untrusted suggestions with no policy-changing side effects."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        identifier: Callable[[str], str] | None = None,
        scanner: SecretScanner | None = None,
        maximum_records_per_session: int = _MAXIMUM_RECORDS_PER_SESSION,
        maximum_bytes_per_session: int = _MAXIMUM_BYTES_PER_SESSION,
        database_footprint_guard: DatabaseFootprintGuard | None = None,
    ) -> None:
        if (
            isinstance(maximum_records_per_session, bool)
            or not isinstance(maximum_records_per_session, int)
            or not 1 <= maximum_records_per_session <= _MAXIMUM_CONFIGURED_RECORDS_PER_SESSION
        ):
            raise ValueError("feedback record capacity is outside its bound")
        if (
            isinstance(maximum_bytes_per_session, bool)
            or not isinstance(maximum_bytes_per_session, int)
            or not 1 <= maximum_bytes_per_session <= _MAXIMUM_CONFIGURED_BYTES_PER_SESSION
        ):
            raise ValueError("feedback byte capacity is outside its bound")
        self._connection = connection
        self._identifier = identifier or (lambda prefix: f"{prefix}_{uuid.uuid4().hex}")
        self._scanner = scanner or SecretScanner()
        self._maximum_records_per_session = maximum_records_per_session
        self._maximum_bytes_per_session = maximum_bytes_per_session
        self._database_footprint_guard = database_footprint_guard

    def submit(
        self,
        *,
        session_id: str | None,
        category: str | FeedbackCategory,
        severity: str | FeedbackSeverity,
        component: str | FeedbackComponent,
        summary: str,
        content: Mapping[str, Any] | None,
        now_ms: int,
    ) -> FeedbackRecord:
        normalized = self._validated_metadata(
            category=category,
            severity=severity,
            component=component,
            summary=summary,
        )
        category_value, severity_value, component_value, summary_value = normalized
        content_value, encoded = self._validated_content(content)
        feedback_id = self._identifier("feedback")
        if not isinstance(feedback_id, str) or not _FEEDBACK_ID_PATTERN.fullmatch(feedback_id):
            raise ValueError("feedback identifier is invalid")

        record_bytes = sum(
            len(value.encode("utf-8"))
            for value in (
                category_value.value,
                severity_value.value,
                component_value.value,
                summary_value,
                encoded,
            )
        )
        projected_write_bytes = (
            record_bytes
            + sum(
                len(value.encode("utf-8"))
                for value in (
                    feedback_id,
                    session_id or "",
                    FeedbackState.NEW.value,
                )
            )
            + 9
        )  # SQLite signed integers use at most nine bytes including serial type.
        with transaction(self._connection, "IMMEDIATE"):
            usage = self._connection.execute(
                """
                SELECT COUNT(*),
                       COALESCE(SUM(
                           length(CAST(category AS BLOB))
                           + length(CAST(severity AS BLOB))
                           + length(CAST(component AS BLOB))
                           + length(CAST(summary AS BLOB))
                           + length(CAST(content_json AS BLOB))
                       ), 0)
                  FROM feedback
                 WHERE session_id IS ?
                """,
                (session_id,),
            ).fetchone()
            retained_records = int(usage[0])
            retained_bytes = int(usage[1])
            if (
                retained_records >= self._maximum_records_per_session
                or retained_bytes + record_bytes > self._maximum_bytes_per_session
            ):
                raise FeedbackCapacityExceeded
            if self._database_footprint_guard is not None:
                try:
                    self._database_footprint_guard.assert_write_allowed(
                        projected_write_bytes=projected_write_bytes
                    )
                except DatabaseFootprintCapacityExceeded:
                    raise FeedbackCapacityExceeded from None
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
                    category_value.value,
                    severity_value.value,
                    component_value.value,
                    summary_value,
                    now_ms,
                    encoded,
                ),
            )
        return FeedbackRecord(
            feedback_id=feedback_id,
            session_id=session_id,
            category=category_value,
            severity=severity_value,
            component=component_value,
            summary=summary_value,
            state=FeedbackState.NEW,
            created_at_ms=now_ms,
            content=content_value,
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
                    f"## {_markdown_literal(record.feedback_id)}",
                    "",
                    f"- State: {_markdown_literal(record.state.value)}",
                    f"- Category: {_markdown_literal(record.category.value)}",
                    f"- Severity: {_markdown_literal(record.severity.value)}",
                    f"- Component: {_markdown_literal(record.component.value)}",
                    f"- Created: {record.created_at_ms}",
                    f"- Summary: {_markdown_literal(record.summary)}",
                    "",
                ]
            )
        return "\n".join(lines)

    def _validated_metadata(
        self,
        *,
        category: str | FeedbackCategory,
        severity: str | FeedbackSeverity,
        component: str | FeedbackComponent,
        summary: str,
    ) -> tuple[FeedbackCategory, FeedbackSeverity, FeedbackComponent, str]:
        raw_values = (category, severity, component, summary)
        if any(not isinstance(value, str) for value in raw_values):
            raise ValueError("feedback metadata fields must be strings")
        values = tuple(value.strip() for value in raw_values)
        if any(not value for value in values):
            raise ValueError("feedback metadata fields are required")
        if len(values[3]) > 1_000 or max(map(len, values[:3])) > 100:
            raise ValueError("feedback metadata exceeds its size bound")

        fields = ("category", "severity", "component", "summary")
        for field, value in zip(fields, values, strict=True):
            self._assert_clean(value, location=f"feedback.{field}")

        return (
            _require_enum(values[0], FeedbackCategory, field="category"),
            _require_enum(values[1], FeedbackSeverity, field="severity"),
            _require_enum(values[2], FeedbackComponent, field="component"),
            values[3],
        )

    def _validated_content(
        self,
        content: Mapping[str, Any] | None,
    ) -> tuple[Mapping[str, Any], str]:
        try:
            encoded = json.dumps(
                dict(content or {}),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (RecursionError, TypeError, ValueError):
            raise ValueError("feedback content is invalid") from None
        if len(encoded.encode("utf-8")) > _MAXIMUM_CONTENT_BYTES:
            raise ValueError("feedback content exceeds its size bound")
        self._assert_clean(encoded, location="feedback.content")

        try:
            parsed = json.loads(encoded)
            sanitized = self._scanner.sanitize(parsed, location="feedback.content")
            sanitized_encoded = json.dumps(
                sanitized,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (RecursionError, TypeError, ValueError):
            raise ValueError("feedback content is invalid") from None
        if not isinstance(parsed, Mapping):
            raise ValueError("feedback content must be an object")
        if sanitized_encoded != encoded:
            raise SecretDetectedError((SecretFinding("sensitive_field", "feedback.content"),))
        return parsed, encoded

    def _assert_clean(self, value: str, *, location: str) -> None:
        self._scanner.assert_clean(value, location=location)
        if _GATEHOUSE_CAPABILITY_PATTERN.search(value):
            raise SecretDetectedError((SecretFinding("gatehouse_capability", location),))

    def _row(self, row: sqlite3.Row) -> FeedbackRecord:
        category = str(row["category"])
        severity = str(row["severity"])
        component = str(row["component"])
        summary = str(row["summary"])
        normalized = self._validated_metadata(
            category=category,
            severity=severity,
            component=component,
            summary=summary,
        )
        try:
            content = json.loads(str(row["content_json"]))
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("stored feedback content is invalid") from None
        if not isinstance(content, Mapping):
            raise ValueError("stored feedback content is invalid")
        content_value, _ = self._validated_content(content)
        state = _require_enum(str(row["state"]), FeedbackState, field="state")
        return FeedbackRecord(
            feedback_id=str(row["feedback_id"]),
            session_id=str(row["session_id"]) if row["session_id"] is not None else None,
            category=normalized[0],
            severity=normalized[1],
            component=normalized[2],
            summary=normalized[3],
            state=state,
            created_at_ms=int(row["created_at_ms"]),
            content=content_value,
        )
