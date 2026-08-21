from __future__ import annotations

import asyncio
import unittest
from dataclasses import replace

from gatehouse.credentials.base import (
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialUnavailableError,
    KeyStore,
    SecretLeaseExpiredError,
)
from gatehouse.credentials.memory import InMemoryKeyStore

METADATA = CredentialMetadata(
    credential_id="credential-a",
    principal_id="principal-a",
    quota_scope_id="quota-a",
    alias="test-only",
)
FAKE_SECRET = b"FAKE-KEY-FOR-TESTS-ONLY-1234567890"


class InMemoryKeyStoreTests(unittest.TestCase):
    def test_store_implements_narrow_protocol_without_plaintext_getter(self) -> None:
        store = InMemoryKeyStore()
        self.assertIsInstance(store, KeyStore)
        self.assertFalse(hasattr(store, "get_secret"))

        async def scenario() -> None:
            reference = await store.put(METADATA, FAKE_SECRET)
            self.assertTrue(reference.startswith("memory://"))
            listed = await store.list_metadata()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].secret_reference, reference)
            self.assertNotIn(FAKE_SECRET.decode(), repr(listed))

        asyncio.run(scenario())

    def test_put_is_create_only_and_preserves_the_existing_secret(self) -> None:
        store = InMemoryKeyStore()
        replacement = b"FAKE-REPLACEMENT-FOR-TESTS-ONLY-123456"

        async def scenario() -> None:
            reference = await store.put(METADATA, FAKE_SECRET)
            with self.assertRaisesRegex(
                CredentialAlreadyExistsError,
                "^credential already exists$",
            ):
                await store.put(METADATA, replacement)

            self.assertEqual((await store.list_metadata())[0].secret_reference, reference)
            lease = await store.open_lease(
                "credential-a",
                "provider transport",
                expected_generation=1,
            )
            async with lease as view:
                self.assertEqual(bytes(view), FAKE_SECRET)

        asyncio.run(scenario())

    def test_metadata_cas_fences_generation_and_draining_leases(self) -> None:
        store = InMemoryKeyStore(default_lease_ttl_seconds=1)

        async def scenario() -> None:
            reference = await store.put(METADATA, FAKE_SECRET)
            initial_lease = await store.open_lease(
                "credential-a",
                "provider transport",
                expected_generation=1,
            )
            initial_view = await initial_lease.__aenter__()

            draining = await store.update_metadata(
                replace(METADATA, state="DRAINING"),
                expected_generation=1,
            )
            self.assertEqual(draining.secret_reference, reference)
            with self.assertRaises(CredentialUnavailableError):
                await store.open_lease("credential-a", "provider transport")
            with self.assertRaisesRegex(
                CredentialGenerationMismatchError,
                "^credential generation does not match$",
            ):
                await store.open_lease(
                    "credential-a",
                    "provider transport",
                    expected_generation=2,
                )

            draining_lease = await store.open_lease(
                "credential-a",
                "provider transport",
                expected_generation=1,
            )
            draining_view = await draining_lease.__aenter__()
            promoted = await store.update_metadata(
                replace(draining, state="HEALTHY", generation=2),
                expected_generation=1,
            )
            self.assertEqual(promoted.generation, 2)
            self.assertEqual(bytes(initial_view), b"\x00" * len(FAKE_SECRET))
            self.assertEqual(bytes(draining_view), b"\x00" * len(FAKE_SECRET))

            with self.assertRaises(CredentialGenerationMismatchError):
                await store.update_metadata(draining, expected_generation=1)
            generation_two = await store.open_lease(
                "credential-a",
                "provider transport",
                expected_generation=2,
            )
            async with generation_two as view:
                self.assertEqual(bytes(view), FAKE_SECRET)

        asyncio.run(scenario())

    def test_discard_partial_is_an_idempotent_noop_for_memory_store(self) -> None:
        store = InMemoryKeyStore()

        async def scenario() -> None:
            self.assertFalse(await store.discard_partial("credential-a"))
            await store.put(METADATA, FAKE_SECRET)
            self.assertFalse(await store.discard_partial("credential-a"))
            self.assertEqual(len(await store.list_metadata()), 1)

        asyncio.run(scenario())

    def test_discard_staged_requires_exact_alias_and_is_idempotent(self) -> None:
        store = InMemoryKeyStore()

        async def scenario() -> None:
            self.assertTrue(
                await store.discard_staged("missing-credential", staged_alias="pending-owner")
            )
            await store.put(METADATA, FAKE_SECRET)
            lease = await store.open_lease(METADATA.credential_id, "staged cleanup test")
            retained = await lease.__aenter__()

            self.assertFalse(
                await store.discard_staged(METADATA.credential_id, staged_alias="other-owner")
            )
            self.assertEqual(bytes(retained), FAKE_SECRET)
            self.assertEqual(len(await store.list_metadata()), 1)

            self.assertTrue(
                await store.discard_staged(
                    METADATA.credential_id,
                    staged_alias=METADATA.alias,
                )
            )
            self.assertEqual(bytes(retained), b"\x00" * len(FAKE_SECRET))
            self.assertEqual(await store.list_metadata(), ())
            self.assertTrue(
                await store.discard_staged(
                    METADATA.credential_id,
                    staged_alias=METADATA.alias,
                )
            )

        asyncio.run(scenario())

    def test_context_exit_zeroes_the_owned_lease_buffer(self) -> None:
        store = InMemoryKeyStore(default_lease_ttl_seconds=1)

        async def scenario() -> None:
            await store.put(METADATA, FAKE_SECRET)
            lease = await store.open_lease("credential-a", "provider transport")
            async with lease as view:
                self.assertEqual(bytes(view), FAKE_SECRET)
                retained_view = view
            self.assertEqual(bytes(retained_view), b"\x00" * len(FAKE_SECRET))
            self.assertTrue(lease.closed)

        asyncio.run(scenario())

    def test_timer_expires_and_zeroes_a_forgotten_lease(self) -> None:
        store = InMemoryKeyStore(
            default_lease_ttl_seconds=0.03,
            maximum_lease_ttl_seconds=1,
        )

        async def scenario() -> None:
            await store.put(METADATA, FAKE_SECRET)
            lease = await store.open_lease("credential-a", "provider transport")
            view = await lease.__aenter__()
            self.assertEqual(bytes(view), FAKE_SECRET)
            await asyncio.sleep(0.10)
            self.assertEqual(bytes(view), b"\x00" * len(FAKE_SECRET))
            self.assertTrue(lease.expired)
            with self.assertRaises(SecretLeaseExpiredError):
                await lease.__aenter__()

        asyncio.run(scenario())

    def test_disable_revokes_existing_and_future_leases(self) -> None:
        store = InMemoryKeyStore(default_lease_ttl_seconds=1)

        async def scenario() -> None:
            await store.put(METADATA, FAKE_SECRET)
            lease = await store.open_lease("credential-a", "provider transport")
            view = await lease.__aenter__()
            await store.disable("credential-a")
            self.assertEqual(bytes(view), b"\x00" * len(FAKE_SECRET))
            with self.assertRaises(CredentialUnavailableError):
                await store.open_lease("credential-a", "provider transport")

        asyncio.run(scenario())

    def test_lease_ttl_is_hard_bounded(self) -> None:
        store = InMemoryKeyStore(
            default_lease_ttl_seconds=1,
            maximum_lease_ttl_seconds=2,
        )

        async def scenario() -> None:
            await store.put(METADATA, FAKE_SECRET)
            with self.assertRaises(ValueError):
                await store.open_lease("credential-a", "provider transport", ttl_seconds=3)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
