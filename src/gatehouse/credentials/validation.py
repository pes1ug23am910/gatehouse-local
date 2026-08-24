"""Credential-value namespace validation for the stock Firecrawl boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
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


ProviderSecretValidator = Callable[[bytes | bytearray, int], bool]


def _validate_firecrawl(secret: bytes | bytearray, maximum_bytes: int) -> bool:
    return is_admissible_firecrawl_secret(secret, maximum_bytes=maximum_bytes)


PROVIDER_SECRET_VALIDATORS: Mapping[str, ProviderSecretValidator] = MappingProxyType(
    {"firecrawl": _validate_firecrawl}
)


def is_admissible_provider_secret(
    provider_id: str,
    secret: bytes | bytearray,
    *,
    maximum_bytes: int,
) -> bool:
    """Dispatch to a provider-specific validator; unknown providers fail closed."""

    validator = PROVIDER_SECRET_VALIDATORS.get(provider_id)
    return validator is not None and validator(secret, maximum_bytes)
