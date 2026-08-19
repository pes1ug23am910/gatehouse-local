from __future__ import annotations

from pathlib import Path

from gatehouse.database.migrations import open_migrated_database
from gatehouse.feedback import FeedbackService, FeedbackState


def test_feedback_is_bounded_advisory_data(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection)

    record = service.submit(
        session_id=None,
        category="usability",
        severity="low",
        component="client",
        summary="Clarify a validation error",
        content={"reproduction": ["submit invalid input"]},
        now_ms=1_000,
    )

    assert record.state is FeedbackState.NEW
    assert service.update_state(record.feedback_id, FeedbackState.TRIAGED)
    assert service.list(state=FeedbackState.TRIAGED)[0].feedback_id == record.feedback_id
    assert record.feedback_id in service.export_markdown()
    connection.close()


def test_feedback_secret_fields_are_redacted(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection)
    fake = "unit-test-provider-secret-123456"

    record = service.submit(
        session_id=None,
        category="security",
        severity="high",
        component="transport",
        summary="A secret field was present",
        content={"api_key": fake},
        now_ms=1_000,
    )

    assert fake not in repr(record)
    assert fake not in connection.execute("SELECT content_json FROM feedback").fetchone()[0]
    connection.close()
