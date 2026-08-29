from __future__ import annotations

import pytest

from gatehouse.policy.targets import (
    TargetValidationError,
    canonicalize_public_url,
    validate_resolved_addresses,
)


def test_canonicalize_https_url() -> None:
    target = canonicalize_public_url("https://EXAMPLE.com./jobs/?b=2&a=hello%20world")

    assert target.url == "https://example.com/jobs/?a=hello+world&b=2"
    assert target.summary == "example.com/jobs/"


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com/jobs",
        "file:///etc/passwd",
        "https://user:secret@example.com/jobs",
        "https://localhost/jobs",
        "https://127.0.0.1/jobs",
        "https://10.0.0.1/jobs",
        "https://metadata/jobs",
        "https://example.com:8443/jobs",
        "https://example.com/%2e%2e/private",
        "https://example.com/jobs#fragment",
        "https://example.com/line\nbreak",
    ],
)
def test_rejects_non_public_or_noncanonical_targets(value: str) -> None:
    with pytest.raises(TargetValidationError):
        canonicalize_public_url(value)


def test_accepts_global_literal_ipv6() -> None:
    target = canonicalize_public_url("https://[2606:4700:4700::1111]/jobs")

    assert target.host == "2606:4700:4700::1111"
    assert target.url.startswith("https://[")


def test_all_dns_answers_must_be_public() -> None:
    with pytest.raises(TargetValidationError) as error:
        validate_resolved_addresses(["93.184.216.34", "127.0.0.1"])

    assert error.value.reason == "non_public_address"


def test_dns_answers_are_normalized() -> None:
    assert validate_resolved_addresses(["2606:4700:4700::1111", "93.184.216.34"]) == (
        "2606:4700:4700::1111",
        "93.184.216.34",
    )


def test_dns_answer_iteration_is_explicitly_bounded() -> None:
    answers = (f"2001:4860:4860::{index:x}" for index in range(1, 66))

    with pytest.raises(TargetValidationError) as error:
        validate_resolved_addresses(answers)

    assert error.value.reason == "too_many_dns_answers"
