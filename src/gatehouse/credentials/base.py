"""Credential metadata and the deliberately narrow KeyStore contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class KeyStoreError(RuntimeError):
    """Base class for credential-custody failures."""


class CredentialNotFoundError(KeyStoreError):
    """The requested credential reference does not exist."""


class CredentialUnavailableError(KeyStoreError):
    """The credential exists but cannot issue a lease."""


class SecretLeaseExpiredError(KeyStoreError):
    """A secret lease reached its absolute lifetime."""


class UnsupportedKeyStorePlatformError(KeyStoreError):
    """The selected KeyStore cannot be made safe on this platform."""


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    credential_id: str
    principal_id: str
    quota_scope_id: str
    alias: str
    state: str = "HEALTHY"
    generation: int = 1
    secret_reference: str | None = None
    expires_at_ms: int | None = None

    def __post_init__(self) -> None:
        if not all((self.credential_id, self.principal_id, self.quota_scope_id, self.alias)):
            raise ValueError("credential identifiers and alias are required")
        if self.generation <= 0:
            raise ValueError("credential generation must be positive")


@runtime_checkable
class SecretLease(Protocol):
    credential_id: str
    generation: int
    purpose: str

    async def __aenter__(self) -> memoryview:
        """Open a temporary mutable view inside the provider boundary."""

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Best-effort zero the temporary storage and close the lease."""

    def close(self) -> None:
        """Close early and best-effort zero the temporary storage."""


@runtime_checkable
class KeyStore(Protocol):
    """A store that can issue leases but cannot generally return plaintext."""

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        """Persist a secret and return its backend-neutral opaque reference."""

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        ttl_seconds: float | None = None,
    ) -> SecretLease:
        """Open a bounded secret lease for a declared transport purpose."""

    async def disable(self, credential_id: str) -> None:
        """Prevent future leases without deleting custody material."""

    async def delete(self, credential_id: str) -> None:
        """Delete custody material and its metadata."""

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        """List non-secret metadata only."""
