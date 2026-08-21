"""Credential-value namespace validation for the stock Firecrawl boundary."""

from __future__ import annotations

from typing import Final

_FIRECRAWL_PREFIX: Final = b"fc-"
_FAKE_PREFIX: Final = b"FAKE-"
_SYNTHETIC_PREFIX: Final = b"synthetic-"
_MINIMUM_SUFFIX_BYTES: Final = 20


def is_admissible_firecrawl_secret(
    secret: bytes | bytearray,
    *,
    maximum_bytes: int,
) -> bool:
    """Keep accepted secrets in a namespace disjoint from durable state values.

    ``fc-`` is the stock provider-token namespace. ``FAKE-`` and ``synthetic-``
    are reserved for no-network verification; accepting them does not make them
    provider credentials or live-provider evidence.
    """

    if not secret or len(secret) > maximum_bytes:
        return False
    if secret.startswith(_FIRECRAWL_PREFIX):
        prefix_length = len(_FIRECRAWL_PREFIX)
        if len(secret) < prefix_length + _MINIMUM_SUFFIX_BYTES:
            return False
        return all(
            48 <= secret[index] <= 57
            or 65 <= secret[index] <= 90
            or 97 <= secret[index] <= 122
            or secret[index] in (45, 95)
            for index in range(prefix_length, len(secret))
        )
    for prefix in (_FAKE_PREFIX, _SYNTHETIC_PREFIX):
        prefix_length = len(prefix)
        if secret.startswith(prefix) and len(secret) >= prefix_length + _MINIMUM_SUFFIX_BYTES:
            return all(33 <= secret[index] <= 126 for index in range(prefix_length, len(secret)))
    return False
