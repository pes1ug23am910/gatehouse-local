from __future__ import annotations

import asyncio
import unittest

from gatehouse.credentials.base import (
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
