from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gatehouse.credentials.redaction import SecretDetectedError, SecretScanner
from gatehouse.database import DatabaseFootprintGuard
from gatehouse.database.migrations import open_migrated_database
from gatehouse.feedback import (
    FeedbackCapacityExceeded,
    FeedbackCategory,
    FeedbackRecord,
    FeedbackService,
    FeedbackState,
)


def _submission(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "session_id": None,
        "category": "usability",
        "severity": "low",
        "component": "client",
        "summary": "Clarify a validation error",
        "content": {"reproduction": ["submit invalid input"]},
        "now_ms": 1_000,
    }
    values.update(overrides)
    return values


def _submit(service: FeedbackService, values: dict[str, Any]) -> FeedbackRecord:
    return service.submit(
        session_id=values["session_id"],
        category=values["category"],
        severity=values["severity"],
        component=values["component"],
        summary=values["summary"],
        content=values["content"],
        now_ms=values["now_ms"],
    )


def test_feedback_is_bounded_advisory_data(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection)

    record = _submit(service, _submission())

    assert record.state is FeedbackState.NEW
    assert record.category is FeedbackCategory.USABILITY
    assert service.update_state(record.feedback_id, FeedbackState.TRIAGED)
    assert service.list(state=FeedbackState.TRIAGED)[0].feedback_id == record.feedback_id
    assert record.feedback_id in service.export_markdown()
    connection.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("category", "active-secret-canary-123456"),
        ("severity", "active-secret-canary-123456"),
        ("component", "active-secret-canary-123456"),
        ("summary", "active-secret-canary-123456"),
        ("content", {"problem": "active-secret-canary-123456"}),
    ),
)
def test_feedback_rejects_active_secret_overlap_in_every_field_before_write(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    canary = "active-secret-canary-123456"
    database_path = tmp_path / f"feedback-{field}.db"
    connection = open_migrated_database(database_path)
    service = FeedbackService(connection, scanner=SecretScanner(canaries=(canary,)))

    with pytest.raises(SecretDetectedError) as captured:
        _submit(service, _submission(**{field: value}))

    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)
    assert connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 0
    assert canary not in service.export_markdown()
    assert not connection.in_transaction
    assert all(canary.encode() not in path.read_bytes() for path in tmp_path.iterdir())
    connection.close()


@pytest.mark.parametrize(
    "value",
    (
        "fc-synthetic-provider-token-1234567890",
        "A" * 43,
    ),
)
def test_feedback_rejects_credential_and_gatehouse_capability_shapes(
    tmp_path: Path,
    value: str,
) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection)

    with pytest.raises(SecretDetectedError) as captured:
        _submit(service, _submission(summary=value))

    assert value not in str(captured.value)
    assert connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 0
    connection.close()


def test_feedback_rejects_sensitive_content_fields_instead_of_redacting(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection)
    value = "synthetic-nonsecret-value"

    with pytest.raises(SecretDetectedError) as captured:
        _submit(service, _submission(content={"api_key": value}))

    assert value not in str(captured.value)
    assert connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 0
    connection.close()


def test_feedback_classifications_are_closed_and_errors_do_not_echo_input(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection)
    invalid = "custom-unreviewed-classification"

    with pytest.raises(ValueError) as captured:
        _submit(service, _submission(category=invalid))

    assert invalid not in str(captured.value)
    assert connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 0
    connection.close()


def test_feedback_count_and_byte_quotas_are_checked_atomically(tmp_path: Path) -> None:
    count_connection = open_migrated_database(tmp_path / "feedback-count.db")
    count_service = FeedbackService(count_connection, maximum_records_per_session=1)
    _submit(count_service, _submission(summary="first"))

    with pytest.raises(FeedbackCapacityExceeded):
        _submit(count_service, _submission(summary="second", now_ms=2_000))

    assert count_connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 1
    assert not count_connection.in_transaction
    count_connection.close()

    byte_connection = open_migrated_database(tmp_path / "feedback-bytes.db")
    byte_service = FeedbackService(
        byte_connection,
        maximum_records_per_session=100,
        maximum_bytes_per_session=30,
    )
    _submit(byte_service, _submission(summary="x", content={}))

    with pytest.raises(FeedbackCapacityExceeded):
        _submit(byte_service, _submission(summary="y", content={}, now_ms=2_000))

    assert byte_connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 1
    assert not byte_connection.in_transaction
    byte_connection.close()


def test_feedback_footprint_admission_is_inside_the_immediate_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "feedback-footprint.db"
    connection = open_migrated_database(database_path)
    transaction_states: list[bool] = []

    def measured(path: str | Path) -> int:
        assert Path(path) == database_path
        transaction_states.append(connection.in_transaction)
        return 100

    monkeypatch.setattr(
        "gatehouse.database.footprint.database_footprint",
        measured,
    )
    service = FeedbackService(
        connection,
        database_footprint_guard=DatabaseFootprintGuard(
            database_path,
            maximum_bytes=100,
        ),
    )

    with pytest.raises(FeedbackCapacityExceeded) as captured:
        _submit(service, _submission())

    assert transaction_states == [True]
    assert str(captured.value) == "feedback capacity is exhausted"
    assert database_path.name not in str(captured.value)
    assert connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 0
    assert not connection.in_transaction
    connection.close()


def test_feedback_markdown_export_encodes_untrusted_structure(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "feedback.db")
    service = FeedbackService(connection, identifier=lambda _: "feedback-safe")
    summary = "Useful note\n## injected\n<script>*unsafe*</script>"
    _submit(service, _submission(summary=summary))

    exported = service.export_markdown()

    assert summary not in exported
    assert "\n## injected" not in exported
    assert "<script>" not in exported
    assert "&#xA;" in exported
    connection.close()
