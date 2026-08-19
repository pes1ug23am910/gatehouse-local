"""In-memory KeyStore for deterministic tests and mock-only workflows."""

from __future__ import annotations

import threading
import time
import uuid
import weakref
from dataclasses import dataclass, replace

from .base import (
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
        with self._lock:
            existing = self._entries.get(metadata.credential_id)
            if existing is not None:
                self._close_leases(metadata.credential_id)
                zero_bytearray(existing.secret)
            secret_reference = metadata.secret_reference or f"memory://{uuid.uuid4().hex}"
            stored_metadata = replace(metadata, secret_reference=secret_reference)
            self._entries[metadata.credential_id] = _Entry(stored_metadata, secret_buffer)
            self._active_leases.setdefault(metadata.credential_id, weakref.WeakSet())
        return secret_reference

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        ttl_seconds: float | None = None,
    ) -> ZeroingSecretLease:
        if not purpose:
            raise ValueError("lease purpose is required")
        requested_ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if requested_ttl <= 0 or requested_ttl > self._maximum_ttl:
            raise ValueError("lease TTL is outside the configured bound")

        with self._lock:
            entry = self._entries.get(credential_id)
            if entry is None:
                raise CredentialNotFoundError(credential_id)
            if entry.metadata.state != "HEALTHY":
                raise CredentialUnavailableError(
                    f"credential {credential_id!r} is {entry.metadata.state}"
                )
            if entry.metadata.expires_at_ms is not None and entry.metadata.expires_at_ms <= int(
                time.time() * 1_000
            ):
                raise CredentialUnavailableError(f"credential {credential_id!r} is expired")

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
