"""In-memory KeyStore for deterministic tests and mock-only workflows."""

from __future__ import annotations

import threading
import time
import uuid
import weakref
from dataclasses import dataclass, replace

from .base import (
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialUnavailableError,
)
from .lease import ZeroingSecretLease, zero_bytearray


@dataclass(slots=True)
class _Entry:
    metadata: CredentialMetadata
    secret: bytearray


class InMemoryKeyStore:
    """A non-persistent KeyStore that still enforces lease-only access."""

    def __init__(
        self,
        *,
        default_lease_ttl_seconds: float = 30.0,
        maximum_lease_ttl_seconds: float = 300.0,
    ) -> None:
        if default_lease_ttl_seconds <= 0:
            raise ValueError("default lease TTL must be positive")
        if maximum_lease_ttl_seconds < default_lease_ttl_seconds:
            raise ValueError("maximum lease TTL must cover the default")
        self._default_ttl = default_lease_ttl_seconds
        self._maximum_ttl = maximum_lease_ttl_seconds
        self._entries: dict[str, _Entry] = {}
        self._active_leases: dict[str, weakref.WeakSet[ZeroingSecretLease]] = {}
        self._lock = threading.RLock()

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        if not secret:
            raise ValueError("credential secret must not be empty")
        secret_buffer = bytearray(secret)
        stored = False
        try:
            with self._lock:
                if metadata.credential_id in self._entries:
                    raise CredentialAlreadyExistsError("credential already exists")
                secret_reference = metadata.secret_reference or f"memory://{uuid.uuid4().hex}"
                stored_metadata = replace(metadata, secret_reference=secret_reference)
                self._active_leases.setdefault(metadata.credential_id, weakref.WeakSet())
                self._entries[metadata.credential_id] = _Entry(stored_metadata, secret_buffer)
                stored = True
            return secret_reference
        except BaseException:
            if not stored:
                zero_bytearray(secret_buffer)
            raise

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        _validate_expected_generation(expected_generation)
        with self._lock:
            entry = self._entries.get(metadata.credential_id)
            if entry is None:
                raise CredentialNotFoundError(metadata.credential_id)
            current = entry.metadata
            if current.generation != expected_generation:
                raise CredentialGenerationMismatchError("credential generation does not match")
            updated = _prepare_metadata_update(current, metadata)
            entry.metadata = updated
            if updated.generation != current.generation or updated.state not in {
                "HEALTHY",
                "DRAINING",
            }:
                self._close_leases(metadata.credential_id)
            return updated

    async def discard_partial(self, credential_id: str) -> bool:
        if not credential_id:
            raise ValueError("credential_id is required")
        return False

    async def discard_staged(self, credential_id: str, *, staged_alias: str) -> bool:
        if not credential_id:
            raise ValueError("credential_id is required")
        if not isinstance(staged_alias, str) or not staged_alias:
            raise ValueError("staged_alias is required")
        with self._lock:
            entry = self._entries.get(credential_id)
            if entry is None:
                return True
            if entry.metadata.alias != staged_alias:
                return False
            self._close_leases(credential_id)
            self._entries.pop(credential_id)
            zero_bytearray(entry.secret)
            self._active_leases.pop(credential_id, None)
            return True

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        expected_generation: int | None = None,
        ttl_seconds: float | None = None,
    ) -> ZeroingSecretLease:
        if not purpose:
            raise ValueError("lease purpose is required")
        if expected_generation is not None:
            _validate_expected_generation(expected_generation)
        requested_ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if requested_ttl <= 0 or requested_ttl > self._maximum_ttl:
            raise ValueError("lease TTL is outside the configured bound")

        with self._lock:
            entry = self._entries.get(credential_id)
            if entry is None:
                raise CredentialNotFoundError(credential_id)
            _assert_lease_eligible(entry.metadata, expected_generation)
            if entry.metadata.expires_at_ms is not None and entry.metadata.expires_at_ms <= int(
                time.time() * 1_000
            ):
                raise CredentialUnavailableError("credential is unavailable")

            lease = ZeroingSecretLease(
                credential_id=credential_id,
                generation=entry.metadata.generation,
                purpose=purpose,
                secret_buffer=bytearray(entry.secret),
                ttl_seconds=requested_ttl,
            )
            self._active_leases.setdefault(credential_id, weakref.WeakSet()).add(lease)
            return lease

    async def disable(self, credential_id: str) -> None:
        with self._lock:
            entry = self._entries.get(credential_id)
            if entry is None:
                raise CredentialNotFoundError(credential_id)
            self._close_leases(credential_id)
            entry.metadata = replace(entry.metadata, state="DISABLED")

    async def delete(self, credential_id: str) -> None:
        with self._lock:
            entry = self._entries.pop(credential_id, None)
            if entry is None:
                raise CredentialNotFoundError(credential_id)
            self._close_leases(credential_id)
            zero_bytearray(entry.secret)
            self._active_leases.pop(credential_id, None)

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        with self._lock:
            return tuple(self._entries[key].metadata for key in sorted(self._entries))

    def _close_leases(self, credential_id: str) -> None:
        for lease in tuple(self._active_leases.get(credential_id, ())):
            lease.close()


def _validate_expected_generation(expected_generation: int) -> None:
    if (
        isinstance(expected_generation, bool)
        or not isinstance(expected_generation, int)
        or expected_generation <= 0
    ):
        raise ValueError("expected credential generation must be positive")


def _prepare_metadata_update(
    current: CredentialMetadata,
    requested: CredentialMetadata,
) -> CredentialMetadata:
    if (
        requested.principal_id != current.principal_id
        or requested.quota_scope_id != current.quota_scope_id
    ):
        raise ValueError("credential authority metadata is immutable")
    if requested.secret_reference not in {None, current.secret_reference}:
        raise ValueError("credential secret reference is immutable")
    if requested.generation < current.generation:
        raise ValueError("credential generation cannot decrease")
    return replace(requested, secret_reference=current.secret_reference)


def _assert_lease_eligible(
    metadata: CredentialMetadata,
    expected_generation: int | None,
) -> None:
    if expected_generation is not None and metadata.generation != expected_generation:
        raise CredentialGenerationMismatchError("credential generation does not match")
    if metadata.state == "HEALTHY":
        return
    if metadata.state == "DRAINING" and expected_generation == metadata.generation:
        return
    raise CredentialUnavailableError("credential is unavailable")
