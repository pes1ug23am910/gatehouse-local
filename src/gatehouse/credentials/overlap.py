"""Lease-bounded exact active-secret overlap inspection."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

from .base import (
    CredentialGenerationMismatchError,
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyStore,
    KeyStoreError,
)
from .redaction import SecretDetectedError, SecretFinding

_ACTIVE_CREDENTIAL_STATES = frozenset({"HEALTHY", "DRAINING"})
_MAXIMUM_CANDIDATE_NODES = 10_000
_MAXIMUM_CANDIDATE_BYTES = 128 * 1_024
_COMPARISONS_PER_YIELD = 4_096


class ActiveSecretInspectionUnavailable(RuntimeError):
    """Exact overlap inspection could not be completed safely."""


def _candidate_text(value: object) -> tuple[bytes, ...]:
    pending = [value]
    encoded: list[bytes] = []
    nodes = 0
    total_bytes = 0
    while pending:
        current = pending.pop()
        nodes += 1
        if nodes > _MAXIMUM_CANDIDATE_NODES:
            raise ActiveSecretInspectionUnavailable("active-secret inspection is unavailable")
        if isinstance(current, str):
            item = current.encode("utf-8")
            total_bytes += len(item)
            if total_bytes > _MAXIMUM_CANDIDATE_BYTES:
                raise ActiveSecretInspectionUnavailable("active-secret inspection is unavailable")
            encoded.append(item)
        elif isinstance(current, Mapping):
            for key, item in current.items():
                pending.append(key)
                pending.append(item)
        elif isinstance(current, Sequence) and not isinstance(
            current,
            (bytes, bytearray, memoryview),
        ):
            pending.extend(current)
    return tuple(encoded)


async def _contains_secret(candidates: tuple[bytes, ...], secret: memoryview) -> bool:
    secret_length = len(secret)
    if secret_length == 0:
        return False
    comparisons_until_yield = _COMPARISONS_PER_YIELD
    for candidate in candidates:
        if secret_length > len(candidate):
            continue
        candidate_view = memoryview(candidate)
        for offset in range(len(candidate) - secret_length + 1):
            if candidate_view[offset : offset + secret_length] == secret:
                return True
            comparisons_until_yield -= 1
            if comparisons_until_yield == 0:
                comparisons_until_yield = _COMPARISONS_PER_YIELD
                await asyncio.sleep(0)
    # Give the enclosing timeout one final cancellation point before a
    # no-overlap result can be accepted.
    await asyncio.sleep(0)
    return False


class ActiveSecretOverlapInspector:
    """Compare bounded untrusted text with active leased secrets one at a time."""

    def __init__(
        self,
        stores: Sequence[KeyStore],
        *,
        maximum_credentials: int = 1_024,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not stores:
            raise ValueError("at least one credential store is required")
        if (
            isinstance(maximum_credentials, bool)
            or not isinstance(maximum_credentials, int)
            or not 1 <= maximum_credentials <= 4_096
        ):
            raise ValueError("active-secret credential bound is invalid")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("active-secret inspection timeout is invalid")
        self._stores = tuple(stores)
        self._maximum_credentials = maximum_credentials
        self._timeout_seconds = timeout_seconds

    async def reject_overlap(self, value: object) -> None:
        try:
            candidates = _candidate_text(value)
            if not candidates:
                return
            async with asyncio.timeout(self._timeout_seconds):
                await self._inspect(candidates)
        except SecretDetectedError:
            raise
        except asyncio.CancelledError:
            raise
        except (KeyStoreError, OSError, RuntimeError, TimeoutError, ValueError):
            raise ActiveSecretInspectionUnavailable(
                "active-secret inspection is unavailable"
            ) from None

    async def _inspect(self, candidates: tuple[bytes, ...]) -> None:
        inspected = 0
        for store in self._stores:
            metadata_items = await store.list_metadata()
            inspected += len(metadata_items)
            if inspected > self._maximum_credentials:
                raise ActiveSecretInspectionUnavailable("active-secret inspection is unavailable")
            for metadata in metadata_items:
                if metadata.state not in _ACTIVE_CREDENTIAL_STATES:
                    continue
                try:
                    lease = await store.open_lease(
                        metadata.credential_id,
                        "feedback-active-secret-overlap",
                        expected_generation=metadata.generation,
                        ttl_seconds=self._timeout_seconds,
                    )
                except (
                    CredentialGenerationMismatchError,
                    CredentialNotFoundError,
                    CredentialUnavailableError,
                ):
                    continue
                async with lease as secret:
                    if await _contains_secret(candidates, secret):
                        raise SecretDetectedError(
                            (SecretFinding("active_secret_overlap", "feedback"),)
                        )
