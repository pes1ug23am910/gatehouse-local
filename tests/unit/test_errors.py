from __future__ import annotations

import math

import pytest

from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.errors import (
    ERROR_CATALOGUE,
    ErrorCode,
    ErrorDetail,
    make_error,
)
from gatehouse.core.ids import RequestId


def test_error_catalogue_defines_every_public_code() -> None:
    assert set(ERROR_CATALOGUE) == set(ErrorCode)
    assert all(definition.message.endswith(".") for definition in ERROR_CATALOGUE.values())


def test_error_envelope_is_stable_and_json_safe() -> None:
    request_id = RequestId.new(
        clock=FixedUtcClock(1_700_000_000_000), entropy=lambda length: bytes(length)
    )
    error = make_error(
        ErrorCode.CAPACITY_EXCEEDED,
        retry_after_seconds=20,
        request_id=request_id,
        policy_rule_id="queue-cap",
        details={"queue": {"depth": 50}, "classes": ["interactive"]},
    )

    assert error.to_dict() == {
        "error": {
            "code": "capacity_exceeded",
            "message": "The configured capacity is currently exhausted.",
            "retryable": True,
            "retry_after_seconds": 20,
            "provider_reset_at_ms": None,
            "request_id": str(request_id),
            "policy_rule_id": "queue-cap",
            "details": {
                "queue": {"depth": 50},
                "classes": ["interactive"],
            },
        }
    }


def test_retryable_error_requires_bounded_retry_information() -> None:
    with pytest.raises(ValueError, match="retry delay or reset timestamp"):
        make_error(ErrorCode.PROVIDER_UNAVAILABLE)


def test_retryable_error_accepts_provider_reset_timestamp() -> None:
    error = make_error(
        ErrorCode.QUOTA_EXHAUSTED,
        provider_reset_at_ms=1_800_000_000_000,
    )

    assert error.detail.provider_reset_at_ms == 1_800_000_000_000


def test_non_retryable_error_rejects_retry_timing() -> None:
    with pytest.raises(ValueError, match="non-retryable"):
        make_error(ErrorCode.POLICY_DENIED, retry_after_seconds=1)


@pytest.mark.parametrize(
    "details",
    [
        {"bad": object()},
        {"bad": math.inf},
        {1: "non-string-key"},
    ],
)
def test_error_details_reject_non_json_values(details: dict[object, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        ErrorDetail(
            code=ErrorCode.POLICY_DENIED,
            message="Denied.",
            retryable=False,
            details=details,  # type: ignore[arg-type]
        )


def test_exception_string_never_includes_details() -> None:
    error = make_error(
        ErrorCode.SCHEMA_VALIDATION_FAILED,
        details={"internal": "diagnostic"},
    )

    assert str(error) == "The request did not match the required schema."
    assert "diagnostic" not in str(error)


def test_error_detail_requires_typed_code_and_request_id() -> None:
    with pytest.raises(TypeError, match="ErrorCode"):
        ErrorDetail(
            code="policy_denied",  # type: ignore[arg-type]
            message="Denied.",
            retryable=False,
        )
    with pytest.raises(TypeError, match="RequestId"):
        ErrorDetail(
            code=ErrorCode.POLICY_DENIED,
            message="Denied.",
            retryable=False,
            request_id="req_01ARZ3NDEKTSV4RRFFQ69G5FAV",  # type: ignore[arg-type]
        )


def test_serialized_details_do_not_mutate_the_error() -> None:
    error = make_error(
        ErrorCode.POLICY_DENIED,
        details={"nested": {"decision": "deny"}},
    )
    serialized = error.to_dict()
    detail = serialized["error"]
    assert isinstance(detail, dict)
    details = detail["details"]
    assert isinstance(details, dict)
    nested = details["nested"]
    assert isinstance(nested, dict)
    nested["decision"] = "allow"

    assert error.to_dict()["error"] != detail
