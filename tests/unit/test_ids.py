from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from gatehouse.core.clock import (
    FixedUtcClock,
    datetime_from_utc_ms,
    datetime_to_utc_ms,
    require_utc_ms,
)
from gatehouse.core.ids import (
    ApprovalId,
    AttemptId,
    CredentialId,
    RequestId,
    RootRunId,
    SessionId,
)


def zero_entropy(length: int) -> bytes:
    return bytes(length)


def one_entropy(length: int) -> bytes:
    return bytes([1]) * length


@pytest.mark.parametrize(
    ("id_type", "prefix"),
    [
        (SessionId, "ses"),
        (RootRunId, "run"),
        (RequestId, "req"),
        (AttemptId, "att"),
        (ApprovalId, "apr"),
        (CredentialId, "cred"),
    ],
)
def test_ids_have_stable_domain_prefixes(id_type: type[SessionId], prefix: str) -> None:
    value = id_type.new(clock=FixedUtcClock(1_700_000_000_000), entropy=zero_entropy)

    assert value.startswith(f"{prefix}_")
    assert len(value.removeprefix(f"{prefix}_")) == 26
    assert id_type(str(value)) == value


def test_ids_sort_by_timestamp() -> None:
    earlier = RequestId.new(clock=FixedUtcClock(1_000), entropy=one_entropy)
    later = RequestId.new(clock=FixedUtcClock(1_001), entropy=zero_entropy)

    assert earlier < later


def test_id_generation_is_fully_injectable() -> None:
    first = SessionId.new(clock=FixedUtcClock(123_456), entropy=one_entropy)
    second = SessionId.new(clock=FixedUtcClock(123_456), entropy=one_entropy)

    assert first == second


@pytest.mark.parametrize(
    "value",
    [
        "req_",
        "req_01arz3ndektsv4rrffq69g5fav",
        "req_81ARZ3NDEKTSV4RRFFQ69G5FAV",
        "req_01ARZ3NDEKTSV4RRFFQ69G5FAI",
        "ses_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "req_01ARZ3NDEKTSV4RRFFQ69G5FAV_extra",
    ],
)
def test_request_id_rejects_malformed_or_wrong_domain_values(value: str) -> None:
    with pytest.raises(ValueError):
        RequestId(value)


def test_id_generation_rejects_bad_entropy_contract() -> None:
    with pytest.raises(ValueError, match="exactly 10 bytes"):
        RequestId.new(clock=FixedUtcClock(10), entropy=lambda _: b"short")


def test_utc_millisecond_helpers_round_trip_aware_datetimes() -> None:
    value = datetime(2026, 8, 19, 12, 30, 15, 123_999, tzinfo=UTC)

    milliseconds = datetime_to_utc_ms(value)

    assert datetime_from_utc_ms(milliseconds) == value.replace(microsecond=123_000)


def test_utc_conversion_normalizes_offsets() -> None:
    offset = timezone(timedelta(hours=5, minutes=30))
    value = datetime(2026, 8, 19, 12, 30, tzinfo=offset)

    converted = datetime_from_utc_ms(datetime_to_utc_ms(value))

    assert converted.tzinfo is UTC
    assert converted.hour == 7


def test_utc_helpers_reject_naive_and_boolean_values() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        datetime_to_utc_ms(datetime(2026, 8, 19))
    with pytest.raises(TypeError, match="integer"):
        require_utc_ms(True)


def test_utc_conversion_rejects_pre_epoch_values() -> None:
    with pytest.raises(ValueError, match="supported range"):
        datetime_to_utc_ms(datetime(1969, 12, 31, 23, 59, 59, tzinfo=UTC))
