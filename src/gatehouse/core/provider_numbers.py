"""Bounded exact decimal numbers for provider observations and reconciliation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Final

SQLITE_INT64_MIN: Final[int] = -(2**63)
SQLITE_INT64_MAX: Final[int] = 2**63 - 1

MAX_PROVIDER_NUMBER_TOKEN_CHARS: Final[int] = 256
MAX_PROVIDER_EXPLICIT_EXPONENT: Final[int] = 256
MIN_PROVIDER_ADJUSTED_EXPONENT: Final[int] = -128
MAX_PROVIDER_ADJUSTED_EXPONENT: Final[int] = 127
MAX_PROVIDER_SIGNIFICANT_DIGITS: Final[int] = 128
MAX_PROVIDER_FIXED_POINT_CHARS: Final[int] = 258

MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS: Final[int] = 383
MAX_RECONCILIATION_SIGNIFICANT_DIGITS: Final[int] = 384
MAX_RECONCILIATION_DECIMAL_CHARS: Final[int] = 385
MAX_ALLOWED_TOLERANCE_SIGNIFICANT_DIGITS: Final[int] = MAX_PROVIDER_ADJUSTED_EXPONENT + 2
MAX_ALLOWED_TOLERANCE_DECIMAL_CHARS: Final[int] = MAX_PROVIDER_ADJUSTED_EXPONENT + 2
DECIMAL_WORK_PRECISION: Final[int] = 512

# A 256-character JSON token with a -256 explicit exponent can render to a
# little over 500 fixed-point characters. This is only an internal transport
# envelope; counter observations are checked against the narrower bounds above.
_MAX_EXACT_FIXED_POINT_CHARS: Final[int] = 512
_MAX_EXACT_SIGNIFICANT_DIGITS: Final[int] = MAX_RECONCILIATION_SIGNIFICANT_DIGITS
# This pre-normalization bound keeps even a coefficient made almost entirely of
# trailing zeroes inside a small, fixed amount of integer work. The later exact
# significant-digit and rendered-length checks remain authoritative.
_MAX_EXACT_COEFFICIENT_BITS: Final[int] = (10**_MAX_EXACT_FIXED_POINT_CHARS - 1).bit_length()
# Let F be the 512-character fixed-point envelope. The coefficient bit bound
# admits 10**F, but not 10**(F + 1), so normalization can remove at most F
# trailing zeroes. A normalized positive nonzero value fits only when its
# exponent is in [2 - F, F - 1]. Since normalization adds between zero and F
# to the raw exponent, every nonzero value that can enter the exact envelope
# has a raw exponent in [2 - 2F, F - 1]. Both endpoints are attainable:
# (10**F, 2 - 2F) normalizes to (1, 2 - F), while (1, F - 1) is already
# normalized. Oversized alternate encodings of zero are rejected while the
# canonical value (0, 0) remains available.
_MIN_EXACT_RAW_EXPONENT: Final[int] = 2 - (2 * _MAX_EXACT_FIXED_POINT_CHARS)
_MAX_EXACT_RAW_EXPONENT: Final[int] = _MAX_EXACT_FIXED_POINT_CHARS - 1
_INVALID_WRAPPER_MESSAGE: Final[str] = "provider number wrapper is invalid"

_JSON_NUMBER_PATTERN = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z",
    re.ASCII,
)
_CANONICAL_NUMBER_PATTERN = re.compile(
    r"(?:0|-?(?:(?:[1-9][0-9]*)(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9]))\Z",
    re.ASCII,
)


class ProviderNumberError(ValueError):
    """A sanitized exact-number validation failure.

    Messages deliberately never include the rejected provider token.
    """


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class ExactProviderNumber:
    """An immutable exact decimal represented only by normalized integer parts."""

    _coefficient: int
    _exponent: int

    def __new__(cls, *_args: object, **_kwargs: object) -> ExactProviderNumber:
        raise ProviderNumberError("exact provider numbers require a validated factory")

    @classmethod
    def _from_normalized(cls, coefficient: int, exponent: int) -> ExactProviderNumber:
        if cls is not ExactProviderNumber:
            raise ProviderNumberError("provider number is invalid")
        if type(coefficient) is not int:
            raise ProviderNumberError("provider number is invalid")
        if type(exponent) is not int:
            raise ProviderNumberError("provider number is invalid")
        if not _MIN_EXACT_RAW_EXPONENT <= exponent <= _MAX_EXACT_RAW_EXPONENT:
            raise ProviderNumberError("provider number exceeds the exact-number envelope")
        if int.bit_length(coefficient) > _MAX_EXACT_COEFFICIENT_BITS:
            raise ProviderNumberError("provider number exceeds the exact-number envelope")
        normalized_coefficient, normalized_exponent = _normalize_parts(coefficient, exponent)
        significant_digits = _significant_digits(normalized_coefficient)
        if significant_digits > _MAX_EXACT_SIGNIFICANT_DIGITS:
            raise ProviderNumberError("provider number exceeds the exact-number envelope")
        if (
            _fixed_point_length(normalized_coefficient, normalized_exponent)
            > _MAX_EXACT_FIXED_POINT_CHARS
        ):
            raise ProviderNumberError("provider number exceeds the exact-number envelope")
        instance = object.__new__(ExactProviderNumber)
        object.__setattr__(instance, "_coefficient", normalized_coefficient)
        object.__setattr__(instance, "_exponent", normalized_exponent)
        return instance

    @property
    def coefficient(self) -> int:
        coefficient, _ = _validated_exact_parts(self)
        return coefficient

    @property
    def exponent(self) -> int:
        _, exponent = _validated_exact_parts(self)
        return exponent

    @property
    def canonical(self) -> str:
        coefficient, exponent = _validated_exact_parts(self)
        return _render_fixed(coefficient, exponent)

    @property
    def significant_digits(self) -> int:
        coefficient, _ = _validated_exact_parts(self)
        return _significant_digits(coefficient)

    @property
    def adjusted_exponent(self) -> int:
        coefficient, exponent = _validated_exact_parts(self)
        if coefficient == 0:
            return 0
        return exponent + _significant_digits(coefficient) - 1

    @property
    def routing_units(self) -> int:
        return project_routing_units(self)

    def to_decimal(self) -> Decimal:
        """Return an exact Decimal without consulting or mutating its global context."""

        coefficient, exponent = _validated_exact_parts(self)
        return Decimal(
            (
                1 if coefficient < 0 else 0,
                _digits_tuple(coefficient),
                exponent,
            )
        )

    def __str__(self) -> str:
        return self.canonical

    def __repr__(self) -> str:
        try:
            coefficient, exponent = _validated_exact_parts(self)
        except ProviderNumberError:
            return "ExactProviderNumber(<invalid>)"
        return f"ExactProviderNumber(_coefficient={coefficient!r}, _exponent={exponent!r})"

    def __eq__(self, other: object) -> bool:
        parts = _validated_exact_parts(self)
        if not isinstance(other, ExactProviderNumber):
            return NotImplemented
        return parts == _validated_exact_parts(other)

    def __hash__(self) -> int:
        return hash(_validated_exact_parts(self))


def require_exact_provider_number(value: object) -> ExactProviderNumber:
    """Require an exact, normalized wrapper inside the transport-wide envelope."""

    _validated_exact_parts(value)
    assert type(value) is ExactProviderNumber
    return value


def _validated_exact_parts(value: object) -> tuple[int, int]:
    if type(value) is not ExactProviderNumber:
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE)
    try:
        coefficient = object.__getattribute__(value, "_coefficient")
        exponent = object.__getattribute__(value, "_exponent")
    except (AttributeError, TypeError):
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE) from None
    if type(coefficient) is not int or type(exponent) is not int:
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE)
    if not _MIN_EXACT_RAW_EXPONENT <= exponent <= _MAX_EXACT_RAW_EXPONENT:
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE)
    try:
        coefficient_too_large = int.bit_length(coefficient) > _MAX_EXACT_COEFFICIENT_BITS
    except (ArithmeticError, AttributeError, TypeError, ValueError):
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE) from None
    if coefficient_too_large:
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE)
    try:
        normalized = _normalize_parts(coefficient, exponent)
        significant_digits = _significant_digits(coefficient)
        fixed_point_length = _fixed_point_length(coefficient, exponent)
    except (ArithmeticError, AttributeError, TypeError, ValueError):
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE) from None
    if (
        normalized != (coefficient, exponent)
        or significant_digits > _MAX_EXACT_SIGNIFICANT_DIGITS
        or fixed_point_length > _MAX_EXACT_FIXED_POINT_CHARS
    ):
        raise ProviderNumberError(_INVALID_WRAPPER_MESSAGE)
    return coefficient, exponent


def parse_json_provider_number(token: str) -> ExactProviderNumber:
    """Parse one bounded RFC 8259 token for the successful transport body.

    This enforces transport-wide lexical and allocation bounds only. Call
    ``require_provider_observation`` for the narrower credit-counter envelope.
    """

    if not isinstance(token, str) or not token.isascii():
        raise ProviderNumberError("provider number token is invalid")
    if not token or len(token) > MAX_PROVIDER_NUMBER_TOKEN_CHARS:
        raise ProviderNumberError("provider number token is invalid")
    match = _JSON_NUMBER_PATTERN.fullmatch(token)
    if match is None:
        raise ProviderNumberError("provider number token is invalid")

    mantissa, explicit_exponent = _split_exponent(token)
    if not -MAX_PROVIDER_EXPLICIT_EXPONENT <= explicit_exponent <= MAX_PROVIDER_EXPLICIT_EXPONENT:
        raise ProviderNumberError("provider number exponent is out of bounds")
    negative = mantissa.startswith("-")
    unsigned = mantissa[1:] if negative else mantissa
    integer_part, separator, fractional_part = unsigned.partition(".")
    digits = integer_part + fractional_part
    coefficient = int(digits)
    if negative:
        coefficient = -coefficient
    exponent = explicit_exponent - (len(fractional_part) if separator else 0)
    return ExactProviderNumber._from_normalized(coefficient, exponent)


def parse_provider_number_token(token: str) -> ExactProviderNumber:
    """Parse and validate one provider credit-counter token."""

    return require_provider_observation(parse_json_provider_number(token))


def parse_provider_number_value(value: object) -> ExactProviderNumber:
    """Validate an exact transport wrapper or injected strict Python integer."""

    if isinstance(value, ExactProviderNumber):
        return require_provider_observation(value)
    if type(value) is not int:
        raise ProviderNumberError("provider number value is invalid")
    return require_provider_observation(ExactProviderNumber._from_normalized(value, 0))


def require_provider_observation(value: ExactProviderNumber) -> ExactProviderNumber:
    """Require the complete Firecrawl observation envelope."""

    coefficient, exponent = _validated_exact_parts(value)
    significant_digits = _significant_digits(coefficient)
    if significant_digits > MAX_PROVIDER_SIGNIFICANT_DIGITS:
        raise ProviderNumberError("provider number has too many significant digits")
    if coefficient != 0:
        adjusted_exponent = exponent + significant_digits - 1
        if (
            not MIN_PROVIDER_ADJUSTED_EXPONENT
            <= adjusted_exponent
            <= MAX_PROVIDER_ADJUSTED_EXPONENT
        ):
            raise ProviderNumberError("provider number adjusted exponent is out of bounds")
    if _fixed_point_length(coefficient, exponent) > MAX_PROVIDER_FIXED_POINT_CHARS:
        raise ProviderNumberError("provider number fixed-point form is too long")
    return value


def parse_canonical_provider_number(
    value: str,
    *,
    maximum_significant_digits: int = MAX_PROVIDER_SIGNIFICANT_DIGITS,
    maximum_fixed_point_chars: int = MAX_PROVIDER_FIXED_POINT_CHARS,
    minimum_adjusted_exponent: int | None = MIN_PROVIDER_ADJUSTED_EXPONENT,
    maximum_adjusted_exponent: int | None = MAX_PROVIDER_ADJUSTED_EXPONENT,
) -> ExactProviderNumber:
    """Parse strict canonical fixed-point text without silently normalizing it."""

    _validate_custom_bounds(maximum_significant_digits, maximum_fixed_point_chars)
    if not isinstance(value, str) or not value.isascii():
        raise ProviderNumberError("canonical provider number is invalid")
    if not value or len(value) > maximum_fixed_point_chars:
        raise ProviderNumberError("canonical provider number is invalid")
    if _CANONICAL_NUMBER_PATTERN.fullmatch(value) is None:
        raise ProviderNumberError("canonical provider number is invalid")
    negative = value.startswith("-")
    unsigned = value[1:] if negative else value
    integer_part, separator, fractional_part = unsigned.partition(".")
    coefficient = int(integer_part + fractional_part)
    if negative:
        coefficient = -coefficient
    exponent = -len(fractional_part) if separator else 0
    exact = ExactProviderNumber._from_normalized(coefficient, exponent)
    if exact.canonical != value:
        raise ProviderNumberError("canonical provider number is invalid")
    if exact.significant_digits > maximum_significant_digits:
        raise ProviderNumberError("canonical provider number is out of bounds")
    if exact.coefficient != 0:
        if (
            minimum_adjusted_exponent is not None
            and exact.adjusted_exponent < minimum_adjusted_exponent
        ):
            raise ProviderNumberError("canonical provider number is out of bounds")
        if (
            maximum_adjusted_exponent is not None
            and exact.adjusted_exponent > maximum_adjusted_exponent
        ):
            raise ProviderNumberError("canonical provider number is out of bounds")
    return exact


def parse_canonical_provider_delta(value: str) -> ExactProviderNumber:
    """Parse canonical provider-observation subtraction under its proven bound."""

    return parse_canonical_provider_number(
        value,
        maximum_significant_digits=MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS,
        maximum_fixed_point_chars=MAX_RECONCILIATION_DECIMAL_CHARS,
        minimum_adjusted_exponent=None,
        maximum_adjusted_exponent=None,
    )


def parse_canonical_reconciliation_delta(value: str) -> ExactProviderNumber:
    """Parse a derived reconciliation delta under its distinct proven bound."""

    return parse_canonical_provider_number(
        value,
        maximum_significant_digits=MAX_RECONCILIATION_SIGNIFICANT_DIGITS,
        maximum_fixed_point_chars=MAX_RECONCILIATION_DECIMAL_CHARS,
        minimum_adjusted_exponent=None,
        maximum_adjusted_exponent=None,
    )


def parse_canonical_allowed_tolerance(value: str) -> ExactProviderNumber:
    """Parse the independently bounded canonical nonnegative integral tolerance."""

    exact = parse_canonical_provider_number(
        value,
        maximum_significant_digits=MAX_ALLOWED_TOLERANCE_SIGNIFICANT_DIGITS,
        maximum_fixed_point_chars=MAX_ALLOWED_TOLERANCE_DECIMAL_CHARS,
        minimum_adjusted_exponent=None,
        maximum_adjusted_exponent=None,
    )
    if exact.coefficient < 0 or exact.exponent < 0:
        raise ProviderNumberError("canonical allowed tolerance is invalid")
    return exact


def canonicalize_decimal(
    value: Decimal,
    *,
    maximum_significant_digits: int = MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS,
    maximum_fixed_point_chars: int = MAX_RECONCILIATION_DECIMAL_CHARS,
) -> str:
    """Validate a finite Decimal and return its exact canonical fixed-point text."""

    _validate_custom_bounds(maximum_significant_digits, maximum_fixed_point_chars)
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ProviderNumberError("decimal value is invalid")
    parts = value.as_tuple()
    normalized_digits = list(parts.digits)
    while len(normalized_digits) > 1 and normalized_digits[0] == 0:
        normalized_digits.pop(0)
    trailing_zeros = 0
    while len(normalized_digits) > 1 and normalized_digits[-1] == 0:
        normalized_digits.pop()
        trailing_zeros += 1
    if len(normalized_digits) > maximum_significant_digits:
        raise ProviderNumberError("decimal value is out of bounds")
    coefficient = 0
    for digit in normalized_digits:
        coefficient = coefficient * 10 + digit
    if parts.sign:
        coefficient = -coefficient
    exponent = parts.exponent
    if not isinstance(exponent, int):
        raise ProviderNumberError("decimal value is invalid")
    exact = ExactProviderNumber._from_normalized(coefficient, exponent + trailing_zeros)
    if exact.significant_digits > maximum_significant_digits:
        raise ProviderNumberError("decimal value is out of bounds")
    canonical = exact.canonical
    if len(canonical) > maximum_fixed_point_chars:
        raise ProviderNumberError("decimal value is out of bounds")
    return canonical


def project_routing_units(value: ExactProviderNumber | str) -> int:
    """Conservatively floor nonnegative observations and saturate at INT64_MAX."""

    exact = (
        parse_canonical_provider_number(value)
        if isinstance(value, str)
        else require_provider_observation(value)
    )
    if exact.coefficient <= 0:
        return 0
    if exact.exponent >= 0:
        if exact.significant_digits + exact.exponent > len(str(SQLITE_INT64_MAX)):
            return SQLITE_INT64_MAX
        integral = exact.coefficient * _integer_power_of_ten(exact.exponent)
    else:
        integral = exact.coefficient // _integer_power_of_ten(-exact.exponent)
    return min(SQLITE_INT64_MAX, integral)


def compare_provider_numbers(left: ExactProviderNumber, right: ExactProviderNumber) -> int:
    """Return -1, 0, or 1 using exact integer scaling."""

    left = require_provider_observation(left)
    right = require_provider_observation(right)
    left_coefficient, left_exponent = _validated_exact_parts(left)
    right_coefficient, right_exponent = _validated_exact_parts(right)
    common_exponent = min(left_exponent, right_exponent)
    left_coefficient *= _integer_power_of_ten(left_exponent - common_exponent)
    right_coefficient *= _integer_power_of_ten(right_exponent - common_exponent)
    return (left_coefficient > right_coefficient) - (left_coefficient < right_coefficient)


def subtract_provider_numbers(
    left: ExactProviderNumber,
    right: ExactProviderNumber,
) -> ExactProviderNumber:
    """Subtract two observations within the proven reconciliation envelope."""

    left = require_provider_observation(left)
    right = require_provider_observation(right)
    left_coefficient, left_exponent = _validated_exact_parts(left)
    right_coefficient, right_exponent = _validated_exact_parts(right)
    common_exponent = min(left_exponent, right_exponent)
    coefficient = left_coefficient * _integer_power_of_ten(left_exponent - common_exponent)
    coefficient -= right_coefficient * _integer_power_of_ten(right_exponent - common_exponent)
    result = ExactProviderNumber._from_normalized(coefficient, common_exponent)
    if result.significant_digits > MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS:
        raise ProviderNumberError("provider number difference is out of bounds")
    if len(result.canonical) > MAX_RECONCILIATION_DECIMAL_CHARS:
        raise ProviderNumberError("provider number difference is out of bounds")
    return result


def compatibility_sqlite_int(value: ExactProviderNumber) -> int | None:
    """Return an exact signed SQLite integer, or ``None`` when not representable."""

    coefficient, exponent = _validated_exact_parts(value)
    if coefficient == 0:
        return 0
    if exponent < 0:
        return None
    integral = coefficient * _integer_power_of_ten(exponent)
    return integral if SQLITE_INT64_MIN <= integral <= SQLITE_INT64_MAX else None


def require_sqlite_int64(
    value: object,
    *,
    field: str,
    minimum: int = SQLITE_INT64_MIN,
    maximum: int = SQLITE_INT64_MAX,
) -> int:
    """Require a strict non-Boolean integer inside explicit signed-INT64 bounds."""

    if (
        type(minimum) is not int
        or type(maximum) is not int
        or minimum < SQLITE_INT64_MIN
        or maximum > SQLITE_INT64_MAX
        or minimum > maximum
    ):
        raise ValueError("SQLite integer bounds are invalid")
    if type(field) is not str or not field:
        raise ValueError("SQLite integer field is invalid")
    if type(value) is not int:
        raise ValueError(f"{field} must be a strict integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field} is outside the SQLite integer range")
    return value


def _split_exponent(token: str) -> tuple[str, int]:
    for marker in ("e", "E"):
        if marker in token:
            mantissa, exponent_text = token.split(marker, 1)
            return mantissa, int(exponent_text)
    return token, 0


def _integer_power_of_ten(exponent: int) -> int:
    if exponent < 0:
        raise ValueError("power-of-ten exponent must be nonnegative")
    return int(10**exponent)


def _normalize_parts(coefficient: int, exponent: int) -> tuple[int, int]:
    if coefficient == 0:
        return 0, 0
    while coefficient % 10 == 0:
        coefficient //= 10
        exponent += 1
    return coefficient, exponent


def _significant_digits(coefficient: int) -> int:
    if coefficient == 0:
        return 1
    try:
        return len(str(abs(coefficient)))
    except ValueError:
        raise ProviderNumberError("provider number exceeds the exact-number envelope") from None


def _digits_tuple(coefficient: int) -> tuple[int, ...]:
    return tuple(ord(character) - ord("0") for character in str(abs(coefficient)))


def _render_fixed(coefficient: int, exponent: int) -> str:
    if coefficient == 0:
        return "0"
    negative = coefficient < 0
    digits = str(abs(coefficient))
    if exponent >= 0:
        rendered = digits + "0" * exponent
    else:
        point = len(digits) + exponent
        if point > 0:
            rendered = f"{digits[:point]}.{digits[point:]}"
        else:
            rendered = f"0.{('0' * -point)}{digits}"
    return f"-{rendered}" if negative else rendered


def _fixed_point_length(coefficient: int, exponent: int) -> int:
    if coefficient == 0:
        return 1
    sign_chars = 1 if coefficient < 0 else 0
    digit_chars = _significant_digits(coefficient)
    if exponent >= 0:
        return sign_chars + digit_chars + exponent
    point = digit_chars + exponent
    if point > 0:
        return sign_chars + digit_chars + 1
    return sign_chars + 2 - point + digit_chars


def _validate_custom_bounds(maximum_significant_digits: int, maximum_chars: int) -> None:
    if (
        type(maximum_significant_digits) is not int
        or not 1 <= maximum_significant_digits <= _MAX_EXACT_SIGNIFICANT_DIGITS
        or type(maximum_chars) is not int
        or not 1 <= maximum_chars <= _MAX_EXACT_FIXED_POINT_CHARS
    ):
        raise ValueError("exact-number bounds are invalid")
