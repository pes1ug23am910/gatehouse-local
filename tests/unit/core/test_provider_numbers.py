from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal, getcontext
from typing import ClassVar

import pytest

import gatehouse.core.provider_numbers as provider_numbers
from gatehouse.core.provider_numbers import (
    MAX_ALLOWED_TOLERANCE_DECIMAL_CHARS,
    MAX_ALLOWED_TOLERANCE_SIGNIFICANT_DIGITS,
    MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS,
    MAX_RECONCILIATION_DECIMAL_CHARS,
    MAX_RECONCILIATION_SIGNIFICANT_DIGITS,
    SQLITE_INT64_MAX,
    SQLITE_INT64_MIN,
    ExactProviderNumber,
    ProviderNumberError,
    canonicalize_decimal,
    compare_provider_numbers,
    compatibility_sqlite_int,
    parse_canonical_allowed_tolerance,
    parse_canonical_provider_delta,
    parse_canonical_provider_number,
    parse_canonical_reconciliation_delta,
    parse_json_provider_number,
    parse_provider_number_token,
    parse_provider_number_value,
    project_routing_units,
    require_exact_provider_number,
    require_provider_observation,
    require_sqlite_int64,
    subtract_provider_numbers,
)

_MISSING = object()


class _ExactProviderNumberSubclass(ExactProviderNumber):
    pass


class _HostileInt(int):
    calls: ClassVar[list[str]] = []

    def __eq__(self, other: object) -> bool:
        self.calls.append("eq")
        raise AssertionError("hostile integer equality executed")

    def __mod__(self, other: int) -> int:
        self.calls.append("mod")
        raise AssertionError("hostile integer modulo executed")

    def __floordiv__(self, other: int) -> int:
        self.calls.append("floordiv")
        raise AssertionError("hostile integer floor division executed")

    def __add__(self, other: int) -> int:
        self.calls.append("add")
        raise AssertionError("hostile integer addition executed")

    def __radd__(self, other: int) -> int:
        self.calls.append("radd")
        raise AssertionError("hostile integer reflected addition executed")


def _forged_wrapper(
    coefficient: object = _MISSING,
    exponent: object = _MISSING,
) -> ExactProviderNumber:
    forged = object.__new__(ExactProviderNumber)
    if coefficient is not _MISSING:
        object.__setattr__(forged, "_coefficient", coefficient)
    if exponent is not _MISSING:
        object.__setattr__(forged, "_exponent", exponent)
    return forged


@pytest.mark.parametrize(
    ("token", "canonical", "projection"),
    [
        ("1", "1", 1),
        ("1.0", "1", 1),
        ("1e0", "1", 1),
        ("-0", "0", 0),
        ("-0.000e+12", "0", 0),
        ("0.999999999999999999999999999999", "0.999999999999999999999999999999", 0),
        ("41.999", "41.999", 41),
        ("-3.75", "-3.75", 0),
        (str(SQLITE_INT64_MAX + 1), str(SQLITE_INT64_MAX + 1), SQLITE_INT64_MAX),
        ("1e127", "1" + "0" * 127, SQLITE_INT64_MAX),
        ("1e-128", "0." + "0" * 127 + "1", 0),
    ],
)
def test_provider_tokens_are_canonicalized_exactly(
    token: str,
    canonical: str,
    projection: int,
) -> None:
    value = parse_provider_number_token(token)

    assert isinstance(value, ExactProviderNumber)
    assert value.canonical == canonical
    assert value.routing_units == projection
    assert project_routing_units(value) == projection
    assert value.to_decimal() == Decimal(token)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "+1",
        "01",
        "-01",
        ".1",
        "1.",
        "1_000",
        " 1",
        "1 ",
        "NaN",
        "Infinity",
        "-Infinity",
        "1e257",
        "1e-257",
        "1" * 129,
        "1e128",
        "1e-129",
        "0" * 257,
        "１２",
    ],
)
def test_provider_token_rejections_are_sanitized(token: str) -> None:
    with pytest.raises(ProviderNumberError) as captured:
        parse_provider_number_token(token)

    assert token not in str(captured.value) or not token


def test_transport_envelope_is_distinct_from_observation_envelope() -> None:
    extension = parse_json_provider_number("1" * 200)

    assert extension.significant_digits == 200
    with pytest.raises(ProviderNumberError):
        parse_provider_number_value(extension)


def test_significant_digit_and_fixed_point_boundaries() -> None:
    coefficient = "1" * 128
    minimum = parse_provider_number_token(f"-{coefficient}e-255")

    assert minimum.significant_digits == 128
    assert minimum.adjusted_exponent == -128
    assert len(minimum.canonical) == 258
    with pytest.raises(ProviderNumberError):
        parse_provider_number_token(f"-{coefficient}e-256")


def test_lexical_length_and_explicit_exponent_boundaries_apply_transport_wide() -> None:
    assert parse_json_provider_number("0." + "0" * 254).canonical == "0"
    assert parse_json_provider_number("0e+256").canonical == "0"
    assert parse_json_provider_number("0e-256").canonical == "0"
    with pytest.raises(ProviderNumberError):
        parse_json_provider_number("0e+257")
    with pytest.raises(ProviderNumberError):
        parse_json_provider_number("0e-257")
    with pytest.raises(ProviderNumberError):
        parse_json_provider_number("0." + "0" * 255)


def test_injected_values_accept_only_exact_non_boolean_integers_or_wrappers() -> None:
    assert parse_provider_number_value(41).canonical == "41"
    assert parse_provider_number_value(parse_provider_number_token("4.1")).canonical == "4.1"
    invalid_values: tuple[object, ...] = (True, False, 1.0, "1", Decimal("1"), {}, [])
    for value in invalid_values:
        with pytest.raises(ProviderNumberError):
            parse_provider_number_value(value)


def test_direct_construction_and_subclass_factory_construction_are_rejected() -> None:
    with pytest.raises(
        ProviderNumberError,
        match="^exact provider numbers require a validated factory$",
    ):
        ExactProviderNumber()

    with pytest.raises(ProviderNumberError, match="^provider number is invalid$"):
        _ExactProviderNumberSubclass._from_normalized(1, 0)


def test_integer_subclasses_are_rejected_before_overridden_arithmetic() -> None:
    hostile = _HostileInt(10)
    operations: tuple[Callable[[], object], ...] = (
        lambda: parse_provider_number_value(hostile),
        lambda: ExactProviderNumber._from_normalized(hostile, 0),
        lambda: ExactProviderNumber._from_normalized(1, hostile),
        lambda: require_exact_provider_number(_forged_wrapper(hostile, 0)),
        lambda: require_exact_provider_number(_forged_wrapper(1, hostile)),
    )

    for operation in operations:
        _HostileInt.calls.clear()
        with pytest.raises(ProviderNumberError):
            operation()
        assert _HostileInt.calls == []


def test_forged_and_corrupted_wrappers_fail_every_public_trust_boundary_safely() -> None:
    valid = parse_provider_number_token("1.25")
    subclass = object.__new__(_ExactProviderNumberSubclass)
    object.__setattr__(subclass, "_coefficient", 125)
    object.__setattr__(subclass, "_exponent", -2)
    malformed = (
        _forged_wrapper(),
        _forged_wrapper(1),
        _forged_wrapper(exponent=0),
        _forged_wrapper("1", 0),
        _forged_wrapper(1, "0"),
        _forged_wrapper(10, 0),
        _forged_wrapper(0, 1),
        _forged_wrapper(10**600, 0),
        _forged_wrapper(1, 10**100),
        subclass,
    )
    boundaries: tuple[Callable[[ExactProviderNumber], object], ...] = (
        require_exact_provider_number,
        require_provider_observation,
        parse_provider_number_value,
        project_routing_units,
        lambda value: compare_provider_numbers(value, valid),
        lambda value: compare_provider_numbers(valid, value),
        lambda value: subtract_provider_numbers(value, valid),
        lambda value: subtract_provider_numbers(valid, value),
        compatibility_sqlite_int,
    )
    properties: tuple[Callable[[ExactProviderNumber], object], ...] = (
        lambda value: value.coefficient,
        lambda value: value.exponent,
        lambda value: value.canonical,
        lambda value: value.significant_digits,
        lambda value: value.adjusted_exponent,
        lambda value: value.routing_units,
        lambda value: value.to_decimal(),
        str,
    )

    for value in malformed:
        for boundary in boundaries + properties:
            with pytest.raises(ProviderNumberError) as captured:
                boundary(value)
            assert str(captured.value) == "provider number wrapper is invalid"


def test_value_protocols_validate_or_sanitize_wrapper_state() -> None:
    first = parse_provider_number_token("1.25")
    same = parse_provider_number_token("1.250")
    different = parse_provider_number_token("1.5")

    assert first == same
    assert first != different
    assert first != object()
    assert hash(first) == hash(same)
    assert repr(first) == "ExactProviderNumber(_coefficient=125, _exponent=-2)"

    malformed = (_forged_wrapper(), _forged_wrapper("leak-me", 0))
    for value in malformed:
        assert repr(value) == "ExactProviderNumber(<invalid>)"
        assert "leak-me" not in repr(value)
        operations: tuple[Callable[[ExactProviderNumber], object], ...] = (
            hash,
            lambda candidate: candidate == first,
            lambda candidate: first == candidate,
        )
        for operation in operations:
            with pytest.raises(ProviderNumberError) as captured:
                operation(value)
            assert str(captured.value) == "provider number wrapper is invalid"


def test_hostile_injected_integer_is_rejected_before_trailing_zero_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_normalization(coefficient: int, exponent: int) -> tuple[int, int]:
        raise AssertionError((coefficient, exponent))

    monkeypatch.setattr(provider_numbers, "_normalize_parts", unexpected_normalization)

    with pytest.raises(ProviderNumberError):
        parse_provider_number_value(10**100_000)


def test_exact_raw_exponent_boundaries_preserve_every_admissible_nonzero_value() -> None:
    maximum_trailing_zeroes = provider_numbers._MAX_EXACT_FIXED_POINT_CHARS

    minimum = ExactProviderNumber._from_normalized(
        10**maximum_trailing_zeroes,
        provider_numbers._MIN_EXACT_RAW_EXPONENT,
    )
    maximum = ExactProviderNumber._from_normalized(
        1,
        provider_numbers._MAX_EXACT_RAW_EXPONENT,
    )

    assert (minimum.coefficient, minimum.exponent) == (1, 2 - maximum_trailing_zeroes)
    assert (maximum.coefficient, maximum.exponent) == (1, maximum_trailing_zeroes - 1)
    assert len(minimum.canonical) == maximum_trailing_zeroes
    assert len(maximum.canonical) == maximum_trailing_zeroes


@pytest.mark.parametrize(
    ("coefficient", "exponent"),
    [
        (1, 10**100_000),
        (10**provider_numbers._MAX_EXACT_FIXED_POINT_CHARS, -(10**100_000)),
        (1, provider_numbers._MAX_EXACT_RAW_EXPONENT + 1),
        (
            10**provider_numbers._MAX_EXACT_FIXED_POINT_CHARS,
            provider_numbers._MIN_EXACT_RAW_EXPONENT - 1,
        ),
    ],
    ids=(
        "huge-positive",
        "huge-negative-maximum-trailing-zeroes",
        "immediately-above-upper-bound",
        "immediately-below-lower-bound-maximum-trailing-zeroes",
    ),
)
def test_factory_rejects_oversized_raw_exponents_before_normalization(
    coefficient: int,
    exponent: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_normalization(_coefficient: int, _exponent: int) -> tuple[int, int]:
        raise AssertionError("oversized exponent reached normalization")

    monkeypatch.setattr(provider_numbers, "_normalize_parts", unexpected_normalization)

    with pytest.raises(
        ProviderNumberError,
        match="^provider number exceeds the exact-number envelope$",
    ):
        ExactProviderNumber._from_normalized(coefficient, exponent)


@pytest.mark.parametrize(
    "exponent",
    [10**100_000, -(10**100_000)],
    ids=("huge-positive", "huge-negative"),
)
def test_forged_oversized_exponents_fail_before_normalization_at_public_boundaries(
    exponent: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = parse_provider_number_token("1.25")
    forged = _forged_wrapper(1, exponent)
    original_normalization = provider_numbers._normalize_parts

    def guarded_normalization(coefficient: int, raw_exponent: int) -> tuple[int, int]:
        if not (
            provider_numbers._MIN_EXACT_RAW_EXPONENT
            <= raw_exponent
            <= provider_numbers._MAX_EXACT_RAW_EXPONENT
        ):
            raise AssertionError("oversized exponent reached normalization")
        return original_normalization(coefficient, raw_exponent)

    monkeypatch.setattr(provider_numbers, "_normalize_parts", guarded_normalization)
    boundaries: tuple[Callable[[], object], ...] = (
        lambda: require_exact_provider_number(forged),
        lambda: require_provider_observation(forged),
        lambda: parse_provider_number_value(forged),
        lambda: project_routing_units(forged),
        lambda: compare_provider_numbers(forged, valid),
        lambda: compare_provider_numbers(valid, forged),
        lambda: subtract_provider_numbers(forged, valid),
        lambda: subtract_provider_numbers(valid, forged),
        lambda: compatibility_sqlite_int(forged),
        lambda: forged.coefficient,
        lambda: forged.exponent,
        lambda: forged.canonical,
        lambda: forged.significant_digits,
        lambda: forged.adjusted_exponent,
        lambda: forged.routing_units,
        lambda: forged.to_decimal(),
        lambda: str(forged),
        lambda: hash(forged),
        lambda: forged == valid,
        lambda: valid == forged,
    )

    for boundary in boundaries:
        with pytest.raises(ProviderNumberError) as captured:
            boundary()
        assert str(captured.value) == "provider number wrapper is invalid"
    assert repr(forged) == "ExactProviderNumber(<invalid>)"


@pytest.mark.parametrize(
    "value",
    ["-0", "+1", "01", "1.0", "1.", ".1", "1e0", "NaN", "Infinity"],
)
def test_canonical_parser_rejects_normalizable_or_nonfinite_text(value: str) -> None:
    with pytest.raises(ProviderNumberError):
        parse_canonical_provider_number(value)


def test_exact_comparison_subtraction_and_compatibility_conversion() -> None:
    first = parse_provider_number_token("1.9")
    second = parse_provider_number_token("1.1")
    delta = subtract_provider_numbers(first, second)

    assert compare_provider_numbers(first, second) == 1
    assert compare_provider_numbers(second, first) == -1
    assert compare_provider_numbers(first, first) == 0
    assert delta.canonical == "0.8"
    assert compatibility_sqlite_int(delta) is None
    assert compatibility_sqlite_int(subtract_provider_numbers(first, first)) == 0
    assert compatibility_sqlite_int(parse_provider_number_token(str(SQLITE_INT64_MAX))) == (
        SQLITE_INT64_MAX
    )
    assert compatibility_sqlite_int(parse_provider_number_token(str(SQLITE_INT64_MAX + 1))) is None


@pytest.mark.parametrize(
    ("previous", "current", "expected"),
    [
        ("0.25", "-0.75", "1"),
        ("-1.25", "-3.75", "2.5"),
        ("1.9", "1.1", "0.8"),
    ],
)
def test_required_exact_remaining_counter_differences(
    previous: str,
    current: str,
    expected: str,
) -> None:
    delta = subtract_provider_numbers(
        parse_provider_number_token(previous),
        parse_provider_number_token(current),
    )

    assert delta.canonical == expected


def test_maximum_provider_difference_has_proven_383_digit_385_character_shape() -> None:
    maximum = parse_provider_number_token("9" * 128)
    minimum = parse_provider_number_token("-" + "1" * 128 + "e-255")
    signed_difference = subtract_provider_numbers(minimum, maximum)

    assert signed_difference.significant_digits == MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS
    assert len(signed_difference.canonical) == MAX_RECONCILIATION_DECIMAL_CHARS
    assert signed_difference.canonical.startswith("-")


def test_provider_and_reconciliation_delta_parsers_keep_distinct_bounds() -> None:
    reconciliation_only = "9" * MAX_RECONCILIATION_SIGNIFICANT_DIGITS

    assert (
        parse_canonical_reconciliation_delta(reconciliation_only).significant_digits
        == MAX_RECONCILIATION_SIGNIFICANT_DIGITS
    )
    with pytest.raises(ProviderNumberError):
        parse_canonical_provider_delta(reconciliation_only)
    with pytest.raises(ProviderNumberError):
        parse_canonical_reconciliation_delta(reconciliation_only + "9")


def test_allowed_tolerance_parser_uses_its_independent_integral_envelope() -> None:
    maximum = "9" * MAX_ALLOWED_TOLERANCE_SIGNIFICANT_DIGITS

    parsed = parse_canonical_allowed_tolerance(maximum)

    assert parsed.canonical == maximum
    assert len(parsed.canonical) == MAX_ALLOWED_TOLERANCE_DECIMAL_CHARS
    for invalid in ("-1", "0.1", "1.0", maximum + "9"):
        with pytest.raises(ProviderNumberError):
            parse_canonical_allowed_tolerance(invalid)


def test_decimal_canonicalization_is_exact_and_does_not_mutate_global_context() -> None:
    original_precision = getcontext().prec

    assert canonicalize_decimal(Decimal("-0.000")) == "0"
    assert canonicalize_decimal(Decimal("123.45000")) == "123.45"
    assert getcontext().prec == original_precision
    for invalid in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
        with pytest.raises(ProviderNumberError):
            canonicalize_decimal(invalid)
    with pytest.raises(ProviderNumberError):
        canonicalize_decimal(Decimal("1e1000000"))


def test_strict_sqlite_int64_helper_validates_values_and_custom_bounds() -> None:
    assert require_sqlite_int64(SQLITE_INT64_MIN, field="units") == SQLITE_INT64_MIN
    assert require_sqlite_int64(SQLITE_INT64_MAX, field="units") == SQLITE_INT64_MAX
    assert require_sqlite_int64(0, field="units", minimum=0) == 0

    for invalid in (True, False, 1.0, "1", SQLITE_INT64_MIN - 1, SQLITE_INT64_MAX + 1):
        with pytest.raises(ValueError):
            require_sqlite_int64(invalid, field="units")

    invalid_bounds: tuple[tuple[int, int], ...] = (
        (True, SQLITE_INT64_MAX),
        (SQLITE_INT64_MIN, False),
        (SQLITE_INT64_MIN - 1, SQLITE_INT64_MAX),
        (SQLITE_INT64_MIN, SQLITE_INT64_MAX + 1),
        (1, 0),
    )
    for minimum, maximum in invalid_bounds:
        with pytest.raises(ValueError):
            require_sqlite_int64(0, field="units", minimum=minimum, maximum=maximum)

    with pytest.raises(ValueError):
        require_sqlite_int64(0, field="")
