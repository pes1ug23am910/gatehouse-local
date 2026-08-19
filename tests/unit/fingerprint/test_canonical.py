from __future__ import annotations

import pytest

from gatehouse.fingerprint import CanonicalizationError, canonical_json_bytes


def test_canonical_json_sorts_keys_and_normalizes_unicode() -> None:
    first = {"z": [2, 1], "name": "e\u0301", "nested": {"b": True, "a": None}}
    second = {"nested": {"a": None, "b": True}, "name": "é", "z": [2, 1]}
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert canonical_json_bytes(first).decode() == (
        '{"name":"é","nested":{"a":null,"b":true},"z":[2,1]}'
    )


@pytest.mark.parametrize("value", [{"cost": 1.5}, {1: "not-a-string-key"}, {"x": b"bytes"}])
def test_canonical_json_rejects_ambiguous_types(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes(value)


def test_normalized_duplicate_keys_are_rejected() -> None:
    with pytest.raises(CanonicalizationError, match="duplicate"):
        canonical_json_bytes({"é": 1, "e\u0301": 2})
