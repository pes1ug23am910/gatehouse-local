"""Transport-facing overlay for persistent and process-local emergency custody."""

from __future__ import annotations

from .base import (
    CredentialAlreadyExistsError,
    CredentialMetadata,
    KeyStore,
    SecretLease,
)


class CompositeKeyStore:
    """Expose exact persistent and emergency custody without cross-store fallback.

    The standard ``KeyStore.open_lease`` contract selects persistent custody.
    Provider requests explicitly marked as emergency use ``open_emergency_lease``.
    Lifecycle mutations always target persistent custody and never affect
    emergency state.
    """

    def __init__(self, *, persistent: KeyStore, emergency: KeyStore) -> None:
        self._persistent = persistent
        self._emergency = emergency

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        persistent, emergency = await self._metadata()
        if metadata.credential_id in {item.credential_id for item in (*persistent, *emergency)}:
            raise CredentialAlreadyExistsError("credential already exists")
        return await self._persistent.put(metadata, secret)

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        await self._metadata()
        return await self._persistent.update_metadata(
            metadata,
            expected_generation=expected_generation,
        )

    async def discard_partial(self, credential_id: str) -> bool:
        return await self._persistent.discard_partial(credential_id)

    async def discard_staged(self, credential_id: str, *, staged_alias: str) -> bool:
        return await self._persistent.discard_staged(
            credential_id,
            staged_alias=staged_alias,
        )

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        expected_generation: int | None = None,
        ttl_seconds: float | None = None,
    ) -> SecretLease:
        await self._metadata()
        return await self._persistent.open_lease(
            credential_id,
            purpose,
            expected_generation=expected_generation,
            ttl_seconds=ttl_seconds,
        )

    async def open_emergency_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        expected_generation: int | None = None,
        ttl_seconds: float | None = None,
    ) -> SecretLease:
        """Open only process-local emergency custody, never persistent custody."""

        await self._metadata()
        return await self._emergency.open_lease(
            credential_id,
            purpose,
            expected_generation=expected_generation,
            ttl_seconds=ttl_seconds,
        )

    async def disable(self, credential_id: str) -> None:
        await self._metadata()
        await self._persistent.disable(credential_id)

    async def delete(self, credential_id: str) -> None:
        await self._metadata()
        await self._persistent.delete(credential_id)

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        persistent, emergency = await self._metadata()
        return tuple(
            sorted(
                (*persistent, *emergency),
                key=lambda item: item.credential_id,
            )
        )

    async def _metadata(
        self,
    ) -> tuple[tuple[CredentialMetadata, ...], tuple[CredentialMetadata, ...]]:
        emergency = await self._emergency.list_metadata()
        persistent = await self._persistent.list_metadata()
        identifiers = [item.credential_id for item in (*persistent, *emergency)]
        if len(identifiers) != len(set(identifiers)):
            raise CredentialAlreadyExistsError("credential identifier exists in multiple stores")
        return persistent, emergency
