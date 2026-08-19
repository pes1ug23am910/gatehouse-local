"""A deliberately narrow canonical JSON representation for equality decisions."""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping, Sequence

type CanonicalScalar = bool | int | str | None
type CanonicalValue = CanonicalScalar | Mapping[str, CanonicalValue] | Sequence[CanonicalValue]


class CanonicalizationError(ValueError):
    """Raised when an input cannot be represented without ambiguous semantics."""


def _normalize(value: object, *, depth: int, maximum_depth: int) -> object:
    if depth > maximum_depth:
        raise CanonicalizationError("canonical request exceeds the maximum nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating-point values must be normalized by the schema")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("canonical object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise CanonicalizationError("key normalization produced a duplicate key")
            normalized[normalized_key] = _normalize(
                item,
                depth=depth + 1,
                maximum_depth=maximum_depth,
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, memoryview)):
        return [_normalize(item, depth=depth + 1, maximum_depth=maximum_depth) for item in value]
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json_bytes(value: object, *, maximum_depth: int = 32) -> bytes:
    """Return stable UTF-8 JSON bytes after rejecting ambiguous Python values.

    Operation schemas must convert decimal quantities and URLs into their semantic
    string/integer representation before this function is called.  Floats are rejected
    so equality does not depend on binary floating-point formatting.
    """

    if maximum_depth <= 0:
        raise ValueError("maximum_depth must be positive")
    normalized = _normalize(value, depth=0, maximum_depth=maximum_depth)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
