from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from unittest import mock

from gatehouse.credentials.base import (
    CredentialMetadata,
    CredentialUnavailableError,
    UnsupportedKeyStorePlatformError,
)
from gatehouse.credentials.dpapi import DpapiCurrentUserKeyStore
from gatehouse.credentials.redaction import SecretScanner

FAKE_CANARY = b"FAKE-DPAPI-CANARY-NOT-A-REAL-KEY-1234567890"


class DpapiKeyStoreTests(unittest.TestCase):
    def test_non_windows_platform_fails_closed(self) -> None:
        with mock.patch("gatehouse.credentials.dpapi.os.name", "posix"):
            with self.assertRaises(UnsupportedKeyStorePlatformError):
                DpapiCurrentUserKeyStore("unused")

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI integration test")
    def test_current_user_round_trip_persists_only_ciphertext_and_metadata(self) -> None:
        scanner = SecretScanner(canaries=(FAKE_CANARY,))
        metadata = CredentialMetadata(
            credential_id="credential-dpapi",
            principal_id="principal",
            quota_scope_id="quota",
            alias="fake-test-key",
        )

        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, default_lease_ttl_seconds=1)
            self.assertFalse(hasattr(store, "get_secret"))
            reference = await store.put(metadata, FAKE_CANARY)
            self.assertTrue(reference.startswith("dpapi-current-user://"))
            self.assertEqual(scanner.scan_files((root,)), ())

            lease = await store.open_lease("credential-dpapi", "provider transport", ttl_seconds=1)
            async with lease as view:
                self.assertEqual(bytes(view), FAKE_CANARY)
                retained_view = view
            self.assertEqual(bytes(retained_view), b"\x00" * len(FAKE_CANARY))

            listed = await store.list_metadata()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].secret_reference, reference)
            self.assertNotIn(FAKE_CANARY.decode(), repr(listed))

            await store.disable("credential-dpapi")
            with self.assertRaises(CredentialUnavailableError):
                await store.open_lease("credential-dpapi", "provider transport")
            await store.delete("credential-dpapi")
            self.assertEqual(await store.list_metadata(), ())

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))


if __name__ == "__main__":
    unittest.main()
