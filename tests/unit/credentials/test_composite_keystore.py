from __future__ import annotations

from dataclasses import replace

import pytest

from gatehouse.credentials import (
    CompositeKeyStore,
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialUnavailableError,
    InMemoryKeyStore,
    KeyStore,
    KeyStoreError,
    ZeroingSecretLease,
)

PERSISTENT_METADATA = CredentialMetadata(
    credential_id="cred_00000000000000000000000001",
    principal_id="prn_00000000000000000000000001",
    quota_scope_id="quota_00000000000000000000000001",
    alias="persistent",
)
EMERGENCY_METADATA = CredentialMetadata(
    credential_id="cred_00000000000000000000000002",
    principal_id="prn_00000000000000000000000002",
    quota_scope_id="quota_00000000000000000000000002",
    alias="emergency",
)
PERSISTENT_SECRET = b"synthetic-persistent-secret-not-a-real-key"
EMERGENCY_SECRET = b"synthetic-emergency-secret-not-a-real-key"


class TrackingMemoryKeyStore(InMemoryKeyStore):
    def __init__(self) -> None:
        super().__init__()
        self.open_calls: list[str] = []
        self.put_calls: list[str] = []
        self.update_calls: list[str] = []
        self.discard_calls: list[str] = []
        self.discard_staged_calls: list[tuple[str, str]] = []
        self.disable_calls: list[str] = []
        self.delete_calls: list[str] = []
        self.open_failure: Exception | None = None

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        self.put_calls.append(metadata.credential_id)
        return await super().put(metadata, secret)

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        self.update_calls.append(metadata.credential_id)
        return await super().update_metadata(
            metadata,
            expected_generation=expected_generation,
        )

    async def discard_partial(self, credential_id: str) -> bool:
        self.discard_calls.append(credential_id)
        return await super().discard_partial(credential_id)

    async def discard_staged(self, credential_id: str, *, staged_alias: str) -> bool:
        self.discard_staged_calls.append((credential_id, staged_alias))
        return await super().discard_staged(credential_id, staged_alias=staged_alias)

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        expected_generation: int | None = None,
        ttl_seconds: float | None = None,
    ) -> ZeroingSecretLease:
        self.open_calls.append(credential_id)
        if self.open_failure is not None:
            raise self.open_failure
        return await super().open_lease(
            credential_id,
            purpose,
            expected_generation=expected_generation,
            ttl_seconds=ttl_seconds,
        )

    async def disable(self, credential_id: str) -> None:
        self.disable_calls.append(credential_id)
        await super().disable(credential_id)

    async def delete(self, credential_id: str) -> None:
        self.delete_calls.append(credential_id)
        await super().delete(credential_id)


@pytest.mark.asyncio
async def test_exact_custody_open_never_crosses_store_authority() -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    await persistent.put(PERSISTENT_METADATA, PERSISTENT_SECRET)
    await emergency.put(EMERGENCY_METADATA, EMERGENCY_SECRET)
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    assert isinstance(overlay, KeyStore)
    assert not hasattr(overlay, "get_secret")
    emergency_lease = await overlay.open_emergency_lease(
        EMERGENCY_METADATA.credential_id,
        "provider transport",
        expected_generation=1,
    )
    async with emergency_lease as view:
        assert bytes(view) == EMERGENCY_SECRET
    assert emergency.open_calls == [EMERGENCY_METADATA.credential_id]
    assert persistent.open_calls == []

    persistent_lease = await overlay.open_lease(
        PERSISTENT_METADATA.credential_id,
        "provider transport",
        expected_generation=1,
    )
    async with persistent_lease as view:
        assert bytes(view) == PERSISTENT_SECRET
    assert emergency.open_calls == [EMERGENCY_METADATA.credential_id]
    assert persistent.open_calls == [PERSISTENT_METADATA.credential_id]

    combined = await overlay.list_metadata()
    assert tuple(item.credential_id for item in combined) == (
        PERSISTENT_METADATA.credential_id,
        EMERGENCY_METADATA.credential_id,
    )
    assert PERSISTENT_SECRET.decode() not in repr(combined)
    assert EMERGENCY_SECRET.decode() not in repr(combined)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        CredentialNotFoundError("credential does not exist"),
        CredentialUnavailableError("credential is unavailable"),
        CredentialGenerationMismatchError("credential generation does not match"),
        KeyStoreError("credential could not be opened"),
    ],
)
async def test_emergency_failure_never_reaches_persistent(
    failure: Exception,
) -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    await persistent.put(PERSISTENT_METADATA, PERSISTENT_SECRET)
    emergency.open_failure = failure
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    with pytest.raises(type(failure), match=str(failure)):
        await overlay.open_emergency_lease(
            PERSISTENT_METADATA.credential_id,
            "provider transport",
            expected_generation=1,
        )

    assert emergency.open_calls == [PERSISTENT_METADATA.credential_id]
    assert persistent.open_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        CredentialNotFoundError("credential does not exist"),
        CredentialUnavailableError("credential is unavailable"),
        CredentialGenerationMismatchError("credential generation does not match"),
        KeyStoreError("credential could not be opened"),
    ],
)
async def test_persistent_failure_never_reaches_emergency(
    failure: Exception,
) -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    await emergency.put(EMERGENCY_METADATA, EMERGENCY_SECRET)
    persistent.open_failure = failure
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    with pytest.raises(type(failure), match=str(failure)):
        await overlay.open_lease(
            EMERGENCY_METADATA.credential_id,
            "provider transport",
            expected_generation=1,
        )

    assert persistent.open_calls == [EMERGENCY_METADATA.credential_id]
    assert emergency.open_calls == []


@pytest.mark.asyncio
async def test_duplicate_metadata_identifier_fails_closed_before_open() -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    await persistent.put(PERSISTENT_METADATA, PERSISTENT_SECRET)
    await emergency.put(PERSISTENT_METADATA, EMERGENCY_SECRET)
    persistent.open_calls.clear()
    emergency.open_calls.clear()
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    with pytest.raises(
        CredentialAlreadyExistsError,
        match="^credential identifier exists in multiple stores$",
    ):
        await overlay.list_metadata()
    with pytest.raises(CredentialAlreadyExistsError):
        await overlay.open_lease(
            PERSISTENT_METADATA.credential_id,
            "provider transport",
            expected_generation=1,
        )
    with pytest.raises(CredentialAlreadyExistsError):
        await overlay.open_emergency_lease(
            PERSISTENT_METADATA.credential_id,
            "provider transport",
            expected_generation=1,
        )

    assert emergency.open_calls == []
    assert persistent.open_calls == []


@pytest.mark.asyncio
async def test_lifecycle_mutations_target_only_persistent_store() -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    reference = await overlay.put(PERSISTENT_METADATA, PERSISTENT_SECRET)
    current = (await persistent.list_metadata())[0]
    updated = await overlay.update_metadata(
        replace(current, generation=2),
        expected_generation=1,
    )
    assert updated.generation == 2
    assert not await overlay.discard_partial(PERSISTENT_METADATA.credential_id)
    await overlay.disable(PERSISTENT_METADATA.credential_id)
    await overlay.delete(PERSISTENT_METADATA.credential_id)

    assert reference.startswith("memory://")
    assert persistent.put_calls == [PERSISTENT_METADATA.credential_id]
    assert persistent.update_calls == [PERSISTENT_METADATA.credential_id]
    assert persistent.discard_calls == [PERSISTENT_METADATA.credential_id]
    assert persistent.disable_calls == [PERSISTENT_METADATA.credential_id]
    assert persistent.delete_calls == [PERSISTENT_METADATA.credential_id]
    assert emergency.put_calls == []
    assert emergency.update_calls == []
    assert emergency.discard_calls == []
    assert emergency.disable_calls == []
    assert emergency.delete_calls == []


@pytest.mark.asyncio
async def test_staged_cleanup_forwards_exact_ownership_only_to_persistent_store() -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    await persistent.put(PERSISTENT_METADATA, PERSISTENT_SECRET)
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    assert not await overlay.discard_staged(
        PERSISTENT_METADATA.credential_id,
        staged_alias="different-owner",
    )
    assert await overlay.discard_staged(
        PERSISTENT_METADATA.credential_id,
        staged_alias=PERSISTENT_METADATA.alias,
    )
    assert await persistent.list_metadata() == ()
    assert persistent.discard_staged_calls == [
        (PERSISTENT_METADATA.credential_id, "different-owner"),
        (PERSISTENT_METADATA.credential_id, PERSISTENT_METADATA.alias),
    ]
    assert emergency.discard_staged_calls == []


@pytest.mark.asyncio
async def test_lifecycle_cannot_mutate_or_duplicate_emergency_identifier() -> None:
    persistent = TrackingMemoryKeyStore()
    emergency = TrackingMemoryKeyStore()
    await emergency.put(EMERGENCY_METADATA, EMERGENCY_SECRET)
    emergency.put_calls.clear()
    overlay = CompositeKeyStore(persistent=persistent, emergency=emergency)

    with pytest.raises(CredentialAlreadyExistsError):
        await overlay.put(EMERGENCY_METADATA, PERSISTENT_SECRET)
    with pytest.raises(CredentialNotFoundError):
        await overlay.delete(EMERGENCY_METADATA.credential_id)

    assert persistent.put_calls == []
    assert persistent.delete_calls == [EMERGENCY_METADATA.credential_id]
    assert emergency.put_calls == []
    assert emergency.delete_calls == []
    assert len(await emergency.list_metadata()) == 1
