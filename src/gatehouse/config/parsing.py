"""Bounded parsers for human-readable configuration quantities."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Annotated

from pydantic import BeforeValidator, Field

_MAX_SIGNED_64 = (1 << 63) - 1
_DURATION_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h|d|w)$")
_SIZE_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(B|KiB|MiB|GiB|TiB|kB|MB|GB|TB)$")

_DURATION_FACTORS = {
    "ms": 1,
    "s": 1_000,
    "m": 60_000,
    "h": 3_600_000,
    "d": 86_400_000,
    "w": 604_800_000,
}

_SIZE_FACTORS = {
    "B": 1,
    "KiB": 1 << 10,
    "MiB": 1 << 20,
    "GiB": 1 << 30,
    "TiB": 1 << 40,
    "kB": 1_000,
    "MB": 1_000_000,
    "GB": 1_000_000_000,
    "TB": 1_000_000_000_000,
}


def _parse_quantity(
    value: object,
    *,
    pattern: re.Pattern[str],
    factors: dict[str, int],
    name: str,
) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be a boolean")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        match = pattern.fullmatch(value.strip())
        if match is None:
            raise ValueError(f"{name} has an invalid unit or format")
        try:
            quantity = Decimal(match.group(1))
        except InvalidOperation as error:  # pragma: no cover - guarded by regex
            raise ValueError(f"{name} has an invalid numeric value") from error
        result_decimal = quantity * factors[match.group(2)]
        if result_decimal != result_decimal.to_integral_value():
            raise ValueError(f"{name} must resolve to a whole base unit")
        result = int(result_decimal)
    else:
        raise TypeError(f"{name} must be an integer or unit-suffixed string")

    if result <= 0:
        raise ValueError(f"{name} must be positive")
    if result > _MAX_SIGNED_64:
        raise ValueError(f"{name} exceeds the supported range")
    return result


def parse_duration_ms(value: object) -> int:
    """Parse a duration into positive integer milliseconds."""

    return _parse_quantity(
        value,
        pattern=_DURATION_PATTERN,
        factors=_DURATION_FACTORS,
        name="duration",
    )


def parse_size_bytes(value: object) -> int:
    """Parse a storage quantity into positive integer bytes."""

    return _parse_quantity(
        value,
        pattern=_SIZE_PATTERN,
        factors=_SIZE_FACTORS,
        name="size",
    )


DurationMs = Annotated[int, BeforeValidator(parse_duration_ms), Field(gt=0)]
SizeBytes = Annotated[int, BeforeValidator(parse_size_bytes), Field(gt=0)]
