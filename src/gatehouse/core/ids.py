"""Opaque, time-sortable identifiers with domain-specific prefixes."""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from typing import ClassVar, Self

from .clock import SYSTEM_UTC_CLOCK, UtcMsClock, require_utc_ms

_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PAYLOAD_PATTERN = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_LEGACY_ACCOUNT_UUID_HEX_PATTERN = re.compile(r"^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$")
_ULID_TIMESTAMP_MAX = (1 << 48) - 1
_ULID_RANDOM_BYTES = 10

EntropySource = Callable[[int], bytes]


def _encode_base32_128(value: int) -> str:
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_ALPHABET[value & 31]
        value >>= 5
    return "".join(characters)


class OpaqueId(str):
    """Base class for validated opaque identifiers.

    The payload uses the 128-bit ULID layout so lexical order preserves the
    timestamp portion. Subclasses make IDs non-interchangeable to type checkers
    and use a stable prefix at API and persistence boundaries.
    """

    prefix: ClassVar[str] = ""
    legacy_account_prefix: ClassVar[str | None] = None

    def __new__(cls, value: str) -> Self:
        if cls is OpaqueId or not cls.prefix:
            raise TypeError("OpaqueId must be instantiated through a concrete ID type")
        if not isinstance(value, str):
            raise TypeError(f"{cls.__name__} must be created from a string")

        expected_prefix = f"{cls.prefix}_"
        if value.startswith(expected_prefix):
            payload = value[len(expected_prefix) :]
            if _PAYLOAD_PATTERN.fullmatch(payload) is not None:
                return str.__new__(cls, value)

        legacy_prefix = cls.legacy_account_prefix
        if legacy_prefix is not None:
            expected_legacy_prefix = f"{legacy_prefix}_"
            if value.startswith(expected_legacy_prefix):
                payload = value[len(expected_legacy_prefix) :]
                if _LEGACY_ACCOUNT_UUID_HEX_PATTERN.fullmatch(payload) is not None:
                    return str.__new__(cls, value)

        if not value.startswith(expected_prefix):
            raise ValueError(f"{cls.__name__} must start with {expected_prefix!r}")
        raise ValueError(f"{cls.__name__} has an invalid opaque payload")

    @classmethod
    def new(
        cls,
        *,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
        entropy: EntropySource = secrets.token_bytes,
    ) -> Self:
        """Create a new ID using injected clock and entropy providers."""

        timestamp_ms = require_utc_ms(clock.now_ms())
        if timestamp_ms > _ULID_TIMESTAMP_MAX:
            raise ValueError("timestamp does not fit the opaque ID layout")

        random_bytes = entropy(_ULID_RANDOM_BYTES)
        if not isinstance(random_bytes, bytes) or len(random_bytes) != _ULID_RANDOM_BYTES:
            raise ValueError("entropy source must return exactly 10 bytes")

        value = (timestamp_ms << 80) | int.from_bytes(random_bytes, "big")
        return cls(f"{cls.prefix}_{_encode_base32_128(value)}")


class SessionId(OpaqueId):
    prefix = "ses"


class RootRunId(OpaqueId):
    prefix = "run"


class RequestId(OpaqueId):
    prefix = "req"


class AttemptId(OpaqueId):
    prefix = "att"


class JobId(OpaqueId):
    prefix = "job"


class ApprovalId(OpaqueId):
    prefix = "apr"


class CredentialId(OpaqueId):
    prefix = "cred"
    legacy_account_prefix = "credential"


class QuotaScopeId(OpaqueId):
    prefix = "quota"
    legacy_account_prefix = "quota"


class PoolId(OpaqueId):
    prefix = "pool"
    legacy_account_prefix = "pool"


class AlertId(OpaqueId):
    prefix = "alert"


class ClientId(OpaqueId):
    prefix = "client"


class WorkspaceId(OpaqueId):
    prefix = "ws"


class PrincipalId(OpaqueId):
    prefix = "prn"
    legacy_account_prefix = "principal"


class LeaseId(OpaqueId):
    prefix = "lease"


class FeedbackId(OpaqueId):
    prefix = "fb"


class EventId(OpaqueId):
    prefix = "evt"
