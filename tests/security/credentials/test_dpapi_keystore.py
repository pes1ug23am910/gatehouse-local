from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from unittest import mock

from gatehouse.credentials.base import (
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialUnavailableError,
    KeyStoreError,
    UnsupportedKeyStorePlatformError,
)
from gatehouse.credentials.dpapi import DpapiCurrentUserKeyStore
from gatehouse.credentials.redaction import SecretScanner

FAKE_CANARY = b"FAKE-DPAPI-CANARY-NOT-A-REAL-KEY-1234567890"


class _FakeDpapi:
    def __init__(self) -> None:
        self.fail_protect = False
        self.fail_unprotect = False
        self.protect_calls = 0
        self.unprotect_calls = 0

    def protect(self, plaintext: bytes | bytearray) -> bytes:
        self.protect_calls += 1
        if self.fail_protect:
            raise OSError("synthetic platform protection detail")
        return b"FAKE-DPAPI\x00" + bytes(value ^ 0xA5 for value in plaintext)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        self.unprotect_calls += 1
        if self.fail_unprotect:
            raise OSError("synthetic platform unprotection detail")
        prefix = b"FAKE-DPAPI\x00"
        if not ciphertext.startswith(prefix):
            raise OSError("synthetic malformed ciphertext detail")
        return bytearray(value ^ 0xA5 for value in ciphertext[len(prefix) :])


class _SyntheticBaseException(BaseException):
    pass


class _CapturingDpapi(_FakeDpapi):
    def __init__(self) -> None:
        super().__init__()
        self.protect_input: bytes | bytearray | None = None
        self.unprotect_result: bytearray | None = None

    def protect(self, plaintext: bytes | bytearray) -> bytes:
        self.protect_input = plaintext
        return super().protect(plaintext)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        value = super().unprotect(ciphertext)
        self.unprotect_result = value
        return value


class _ReflectingDpapi(_FakeDpapi):
    def protect(self, plaintext: bytes | bytearray) -> bytes:
        self.protect_calls += 1
        return bytes(plaintext)


class _BlockingDpapi(_FakeDpapi):
    def __init__(self) -> None:
        super().__init__()
        self.protect_started = threading.Event()
        self.release_protect = threading.Event()
        self.protect_input: bytes | bytearray | None = None
        self.unprotect_started = threading.Event()
        self.release_unprotect = threading.Event()
        self.unprotect_result: bytearray | None = None

    def protect(self, plaintext: bytes | bytearray) -> bytes:
        self.protect_input = plaintext
        self.protect_started.set()
        if not self.release_protect.wait(timeout=5):
            raise TimeoutError("synthetic protect worker timed out")
        return super().protect(plaintext)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        value = super().unprotect(ciphertext)
        self.unprotect_result = value
        self.unprotect_started.set()
        if not self.release_unprotect.wait(timeout=5):
            raise TimeoutError("synthetic unprotect worker timed out")
        return value


async def _wait_for_thread_event(event: threading.Event) -> None:
    for _ in range(500):
        if event.is_set():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("synthetic worker did not reach its cancellation checkpoint")


async def _wait_for_zeroed(value: bytearray) -> None:
    for _ in range(500):
        if not any(value):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("worker plaintext was not zeroed after cancellation")


def _metadata(credential_id: str = "credential-dpapi") -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=credential_id,
        principal_id="principal",
        quota_scope_id="quota",
        alias="fake-test-key",
    )


class DpapiKeyStoreTests(unittest.TestCase):
    def test_non_windows_platform_fails_closed(self) -> None:
        with mock.patch("gatehouse.credentials.dpapi.os.name", "posix"):
            with self.assertRaises(UnsupportedKeyStorePlatformError):
                DpapiCurrentUserKeyStore("unused")

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_is_exclusive_and_partial_pairs_are_recoverable(self) -> None:
        async def scenario(root: str) -> None:
            api = _FakeDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            metadata = _metadata()
            reference = await store.put(metadata, FAKE_CANARY)

            with self.assertRaisesRegex(
                CredentialAlreadyExistsError,
                "^credential already exists$",
            ):
                await store.put(metadata, b"FAKE-REPLACEMENT-NOT-A-REAL-KEY-123456")
            self.assertFalse(await store.discard_partial(metadata.credential_id))
            self.assertEqual(api.protect_calls, 1)

            lease = await store.open_lease(
                metadata.credential_id,
                "provider transport",
                expected_generation=1,
            )
            async with lease as view:
                self.assertEqual(bytes(view), FAKE_CANARY)
            self.assertEqual((await store.list_metadata())[0].secret_reference, reference)

            for suffix, partial_id in ((".dpapi", "partial-blob"), (".json", "partial-meta")):
                blob_path, metadata_path = store._paths(partial_id)
                partial_path = blob_path if suffix == ".dpapi" else metadata_path
                partial_path.write_bytes(b"synthetic partial")
                with self.assertRaises(CredentialAlreadyExistsError):
                    await store.put(_metadata(partial_id), FAKE_CANARY)
                self.assertTrue(await store.discard_partial(partial_id))
                self.assertFalse(await store.discard_partial(partial_id))
                self.assertFalse(blob_path.exists())
                self.assertFalse(metadata_path.exists())

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_publishes_intent_before_blob_and_metadata(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata()
            intent_path = store._intent_path(metadata.credential_id)
            blob_path, metadata_path = store._paths(metadata.credential_id)
            expected_stages = store._staging_paths(metadata.credential_id, metadata.alias)
            original_link = os.link
            original_stage = store._stage_owned_file
            published: list[Path] = []
            staged: list[Path] = []

            def observe_stage(path: Path, data: bytes) -> Path:
                if path in {expected_stages[1], expected_stages[2]}:
                    self.assertTrue(intent_path.is_file())
                if path == expected_stages[2]:
                    self.assertTrue(blob_path.is_file())
                staged.append(path)
                return original_stage(path, data)

            def observe_publish(source: str | Path, target: str | Path) -> None:
                target_path = Path(target)
                if target_path == blob_path:
                    self.assertTrue(intent_path.is_file())
                    self.assertFalse(metadata_path.exists())
                elif target_path == metadata_path:
                    self.assertTrue(intent_path.is_file())
                    self.assertTrue(blob_path.is_file())
                original_link(source, target)
                published.append(target_path)
                if target_path == intent_path:
                    self.assertEqual(
                        json.loads(intent_path.read_text(encoding="utf-8")),
                        {
                            "credential_id": metadata.credential_id,
                            "staged_alias": metadata.alias,
                        },
                    )

            with (
                mock.patch.object(store, "_stage_owned_file", side_effect=observe_stage),
                mock.patch(
                    "gatehouse.credentials.dpapi.os.link",
                    side_effect=observe_publish,
                ),
            ):
                await store.put(metadata, FAKE_CANARY)

            self.assertEqual(published, [intent_path, blob_path, metadata_path])
            self.assertEqual(staged, list(expected_stages))
            self.assertTrue(all(metadata.alias not in path.name for path in expected_stages))
            self.assertFalse(intent_path.exists())
            self.assertTrue(blob_path.is_file())
            self.assertTrue(metadata_path.is_file())

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_rolls_back_intent_and_blob_when_metadata_publish_fails(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            original_link = os.link
            calls = 0

            def fail_metadata_publish(source: str | Path, target: str | Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("synthetic platform publish detail")
                original_link(source, target)

            with mock.patch(
                "gatehouse.credentials.dpapi.os.link",
                side_effect=fail_metadata_publish,
            ):
                with self.assertRaisesRegex(
                    KeyStoreError,
                    "^credential custody could not be persisted$",
                ):
                    await store.put(_metadata(), FAKE_CANARY)

            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_base_exception_after_final_hardlink_removes_exact_owned_files(self) -> None:
        async def scenario(root: str, fail_after: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata(f"post-{fail_after}-link-crash")
            intent_path = store._intent_path(metadata.credential_id)
            blob_path, metadata_path = store._paths(metadata.credential_id)
            failing_target = {
                "blob": blob_path,
                "metadata": metadata_path,
            }[fail_after]
            original_link = os.link

            def publish_then_abort(source: str | Path, target: str | Path) -> None:
                original_link(source, target)
                if Path(target) == failing_target:
                    raise _SyntheticBaseException(f"synthetic {fail_after} post-link crash")

            with mock.patch(
                "gatehouse.credentials.dpapi.os.link",
                side_effect=publish_then_abort,
            ):
                with self.assertRaises(_SyntheticBaseException):
                    await store.put(metadata, FAKE_CANARY)

            self.assertFalse(intent_path.exists())
            self.assertFalse(blob_path.exists())
            self.assertFalse(metadata_path.exists())
            self.assertEqual(os.listdir(root), [])

        for fail_after in ("blob", "metadata"):
            with self.subTest(fail_after=fail_after):
                with tempfile.TemporaryDirectory() as temporary:
                    asyncio.run(scenario(temporary, fail_after))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_failed_rollback_retains_intent_until_owned_partial_is_removed(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata()
            intent_path = store._intent_path(metadata.credential_id)
            blob_path, metadata_path = store._paths(metadata.credential_id)
            original_link = os.link
            original_unlink = Path.unlink
            calls = 0

            def fail_metadata_publish(source: str | Path, target: str | Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("synthetic platform publish detail")
                original_link(source, target)

            def fail_blob_cleanup(path: Path, missing_ok: bool = False) -> None:
                if path == blob_path:
                    raise PermissionError("synthetic cleanup denial")
                original_unlink(path, missing_ok=missing_ok)

            with (
                mock.patch(
                    "gatehouse.credentials.dpapi.os.link",
                    side_effect=fail_metadata_publish,
                ),
                mock.patch.object(Path, "unlink", new=fail_blob_cleanup),
            ):
                with self.assertRaisesRegex(
                    KeyStoreError,
                    "^credential custody could not be persisted$",
                ):
                    await store.put(metadata, FAKE_CANARY)

            self.assertTrue(intent_path.is_file())
            self.assertTrue(blob_path.is_file())
            self.assertFalse(metadata_path.exists())
            self.assertTrue(
                await store.discard_staged(
                    metadata.credential_id,
                    staged_alias=metadata.alias,
                )
            )
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_staged_cleanup_requires_exact_marker_and_preserves_collisions(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            staged_alias = "pending-owned-stage"

            self.assertTrue(await store.discard_staged("absent", staged_alias=staged_alias))

            orphan_id = "unowned-orphan"
            orphan_blob, orphan_metadata = store._paths(orphan_id)
            orphan_blob.write_bytes(b"unowned collision")
            self.assertFalse(await store.discard_staged(orphan_id, staged_alias=staged_alias))
            self.assertEqual(orphan_blob.read_bytes(), b"unowned collision")
            self.assertFalse(orphan_metadata.exists())

            temporary_only_id = "unowned-temporary"
            temporary_only = Path(root) / (f".{store._stem(temporary_only_id)}.dpapi.synthetic")
            temporary_only.write_bytes(b"unowned staged collision")
            self.assertFalse(
                await store.discard_staged(
                    temporary_only_id,
                    staged_alias=staged_alias,
                )
            )
            self.assertEqual(temporary_only.read_bytes(), b"unowned staged collision")

            mismatched_stage_id = "mismatched-staging-token"
            mismatched_stage = store._staging_paths(
                mismatched_stage_id,
                "different-stage",
            )[0]
            mismatched_stage.write_bytes(b"")
            self.assertFalse(
                await store.discard_staged(
                    mismatched_stage_id,
                    staged_alias=staged_alias,
                )
            )
            self.assertTrue(mismatched_stage.exists())

            mismatch_id = "mismatched-owner"
            mismatch_blob, _ = store._paths(mismatch_id)
            mismatch_intent = store._intent_path(mismatch_id)
            mismatch_intent.write_text(
                json.dumps(
                    {
                        "credential_id": mismatch_id,
                        "staged_alias": "different-stage",
                    }
                ),
                encoding="utf-8",
            )
            mismatch_blob.write_bytes(b"mismatched collision")
            self.assertFalse(await store.discard_staged(mismatch_id, staged_alias=staged_alias))
            self.assertTrue(mismatch_intent.is_file())
            self.assertEqual(mismatch_blob.read_bytes(), b"mismatched collision")

            mixed_id = "owned-marker-with-unrelated-temp"
            mixed_blob, _ = store._paths(mixed_id)
            mixed_intent = store._intent_path(mixed_id)
            mixed_intent.write_text(
                json.dumps(
                    {
                        "credential_id": mixed_id,
                        "staged_alias": staged_alias,
                    }
                ),
                encoding="utf-8",
            )
            mixed_blob.write_bytes(b"owned ciphertext partial")
            unrelated_temp = Path(root) / (f".{store._stem(mixed_id)}.dpapi.unrelated")
            unrelated_temp.write_bytes(b"unrelated collision")
            self.assertFalse(
                await store.discard_staged(
                    mixed_id,
                    staged_alias=staged_alias,
                )
            )
            self.assertFalse(mixed_intent.exists())
            self.assertFalse(mixed_blob.exists())
            self.assertEqual(unrelated_temp.read_bytes(), b"unrelated collision")

            for index, (has_blob, has_metadata) in enumerate(
                ((False, False), (True, False), (False, True), (True, True))
            ):
                credential_id = f"owned-stage-{index}"
                blob_path, metadata_path = store._paths(credential_id)
                intent_path = store._intent_path(credential_id)
                intent_path.write_text(
                    json.dumps(
                        {
                            "credential_id": credential_id,
                            "staged_alias": staged_alias,
                        }
                    ),
                    encoding="utf-8",
                )
                if has_blob:
                    blob_path.write_bytes(b"owned ciphertext partial")
                if has_metadata:
                    metadata_path.write_bytes(b"owned metadata partial")
                temporary_path = store._staging_paths(credential_id, staged_alias)[1]
                temporary_path.write_bytes(b"owned staged temporary")

                self.assertTrue(
                    await store.discard_staged(
                        credential_id,
                        staged_alias=staged_alias,
                    )
                )
                self.assertFalse(intent_path.exists())
                self.assertFalse(blob_path.exists())
                self.assertFalse(metadata_path.exists())
                self.assertFalse(temporary_path.exists())
                self.assertTrue(
                    await store.discard_staged(
                        credential_id,
                        staged_alias=staged_alias,
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_pre_marker_intent_stage_is_exactly_owned_even_when_empty_or_truncated(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            staged_alias = "pending-pre-marker-owner"

            for index, payload in enumerate((b"", b'{"credential_id":')):
                credential_id = f"pre-marker-crash-{index}"
                intent_stage, _, _ = store._staging_paths(credential_id, staged_alias)
                intent_stage.write_bytes(payload)

                self.assertTrue(
                    await store.discard_staged(
                        credential_id,
                        staged_alias=staged_alias,
                    )
                )
                self.assertFalse(intent_stage.exists())

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_delete_removes_matching_staging_intent(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata()
            await store.put(metadata, FAKE_CANARY)
            intent_path = store._intent_path(metadata.credential_id)
            intent_path.write_text(
                json.dumps(
                    {
                        "credential_id": metadata.credential_id,
                        "staged_alias": metadata.alias,
                    }
                ),
                encoding="utf-8",
            )
            temporary_path = store._staging_paths(metadata.credential_id, metadata.alias)[2]
            temporary_path.write_bytes(b"owned staged temporary")

            await store.delete(metadata.credential_id)

            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_delete_removes_owned_namespace_metadata_temps_and_allows_reuse(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata()
            await store.put(metadata, FAKE_CANARY)
            stale_metadata = Path(root) / f".{store._stem(metadata.credential_id)}.json.crash-temp"
            stale_metadata.write_bytes(b"fully written but not replaced")

            await store.delete(metadata.credential_id)

            self.assertEqual(os.listdir(root), [])
            await store.put(metadata, FAKE_CANARY)
            await store.delete(metadata.credential_id)
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_rejects_secret_overlap_before_protection_or_filesystem_write(self) -> None:
        async def scenario(root: str) -> None:
            for index, secret in enumerate(
                (b"dpapi-current-user", b"secret_reference", b"staged_alias")
            ):
                api = _FakeDpapi()
                store = DpapiCurrentUserKeyStore(root, _api=api)
                with self.assertRaisesRegex(
                    KeyStoreError,
                    "^credential custody metadata is invalid$",
                ):
                    await store.put(_metadata(f"metadata-overlap-{index}"), secret)
                self.assertEqual(api.protect_calls, 0)
                self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_rejects_protector_reflection_before_filesystem_write(self) -> None:
        async def scenario(root: str) -> None:
            api = _ReflectingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)

            with self.assertRaisesRegex(
                KeyStoreError,
                "^credential custody payload is invalid$",
            ):
                await store.put(_metadata("protector-reflection"), FAKE_CANARY)

            self.assertEqual(api.protect_calls, 1)
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_platform_failures_are_sanitized_and_generation_is_checked_first(self) -> None:
        async def scenario(root: str) -> None:
            api = _FakeDpapi()
            api.fail_protect = True
            store = DpapiCurrentUserKeyStore(root, _api=api)
            with self.assertRaisesRegex(
                KeyStoreError,
                "^credential could not be protected$",
            ):
                await store.put(_metadata(), FAKE_CANARY)
            self.assertEqual(os.listdir(root), [])

            api.fail_protect = False
            await store.put(_metadata(), FAKE_CANARY)
            with self.assertRaises(CredentialGenerationMismatchError):
                await store.open_lease(
                    "credential-dpapi",
                    "provider transport",
                    expected_generation=2,
                )
            self.assertEqual(api.unprotect_calls, 0)

            api.fail_unprotect = True
            with self.assertRaisesRegex(
                CredentialUnavailableError,
                "^credential could not be opened$",
            ):
                await store.open_lease(
                    "credential-dpapi",
                    "provider transport",
                    expected_generation=1,
                )

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_protect_owns_and_zeroes_its_worker_input(self) -> None:
        async def scenario(root: str) -> None:
            api = _BlockingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            caller_secret = bytearray(FAKE_CANARY)
            task = asyncio.create_task(store.put(_metadata(), caller_secret))
            await _wait_for_thread_event(api.protect_started)

            worker_input = api.protect_input
            self.assertIsInstance(worker_input, bytearray)
            self.assertIsNot(worker_input, caller_secret)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            assert isinstance(worker_input, bytearray)
            self.assertEqual(bytes(worker_input), FAKE_CANARY)
            self.assertEqual(bytes(caller_secret), FAKE_CANARY)
            api.release_protect.set()
            await _wait_for_zeroed(worker_input)
            self.assertEqual(bytes(worker_input), b"\x00" * len(FAKE_CANARY))
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_queued_protect_zeroes_before_worker_can_start(self) -> None:
        async def scenario(root: str) -> None:
            api = _FakeDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            queued = asyncio.Event()
            never_start = asyncio.Event()
            queued_worker: Callable[[], bytes] | None = None
            queued_secret: bytearray | None = None

            async def queue_without_start(function: Callable[[], bytes]) -> bytes:
                nonlocal queued_secret, queued_worker
                queued_worker = function
                captured = [
                    cell.cell_contents
                    for cell in function.__closure__ or ()
                    if isinstance(cell.cell_contents, bytearray)
                ]
                self.assertEqual(len(captured), 1)
                queued_secret = captured[0]
                queued.set()
                await never_start.wait()
                raise AssertionError("cancelled queued worker unexpectedly resumed")

            with mock.patch(
                "gatehouse.credentials.dpapi.asyncio.to_thread",
                new=queue_without_start,
            ):
                task = asyncio.create_task(store.put(_metadata(), FAKE_CANARY))
                await asyncio.wait_for(queued.wait(), timeout=1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

            assert queued_secret is not None
            assert queued_worker is not None
            self.assertEqual(bytes(queued_secret), b"\x00" * len(FAKE_CANARY))
            self.assertEqual(queued_worker(), b"")
            self.assertEqual(api.protect_calls, 0)
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_queued_base_exception_abandons_protect_and_late_unprotect_workers(self) -> None:
        async def scenario(root: str) -> None:
            api = _CapturingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            queued_workers: list[Callable[[], bytes | bytearray]] = []
            queued_secrets: list[bytearray] = []

            async def queue_then_fail(
                function: Callable[[], bytes | bytearray],
            ) -> bytes | bytearray:
                queued_workers[:] = [function]
                captured: list[bytearray] = [
                    cell.cell_contents
                    for cell in function.__closure__ or ()
                    if isinstance(cell.cell_contents, bytearray)
                ]
                queued_secrets[:] = captured
                raise _SyntheticBaseException("synthetic queued failure")

            with mock.patch(
                "gatehouse.credentials.dpapi.asyncio.to_thread",
                new=queue_then_fail,
            ):
                with self.assertRaises(_SyntheticBaseException):
                    await store.put(_metadata(), FAKE_CANARY)

            self.assertEqual(len(queued_secrets), 1)
            self.assertEqual(bytes(queued_secrets[0]), b"\x00" * len(FAKE_CANARY))
            self.assertEqual(len(queued_workers), 1)
            self.assertEqual(queued_workers[0](), b"")
            self.assertEqual(api.protect_calls, 0)

            metadata = _metadata("queued-unprotect")
            await store.put(metadata, FAKE_CANARY)
            queued_workers.clear()
            queued_secrets.clear()
            with mock.patch(
                "gatehouse.credentials.dpapi.asyncio.to_thread",
                new=queue_then_fail,
            ):
                with self.assertRaises(_SyntheticBaseException):
                    await store.open_lease(metadata.credential_id, "queued worker test")

            self.assertEqual(len(queued_workers), 1)
            late_plaintext = queued_workers[0]()
            self.assertIsInstance(late_plaintext, bytearray)
            self.assertEqual(bytes(late_plaintext), b"")
            self.assertIsNone(api.unprotect_result)
            self.assertEqual(api.unprotect_calls, 0)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_running_base_exception_keeps_worker_owned_buffers_zeroed(self) -> None:
        async def scenario(root: str) -> None:
            api = _CapturingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            worker_results: list[bytes | bytearray] = []

            async def run_then_fail(
                function: Callable[[], bytes | bytearray],
            ) -> bytes | bytearray:
                worker_results.append(function())
                raise _SyntheticBaseException("synthetic running failure")

            with mock.patch(
                "gatehouse.credentials.dpapi.asyncio.to_thread",
                new=run_then_fail,
            ):
                with self.assertRaises(_SyntheticBaseException):
                    await store.put(_metadata(), FAKE_CANARY)

            failed_protect_input = api.protect_input
            assert isinstance(failed_protect_input, bytearray)
            self.assertEqual(
                bytes(failed_protect_input),
                b"\x00" * len(FAKE_CANARY),
            )
            self.assertEqual(os.listdir(root), [])

            metadata = _metadata("running-unprotect")
            await store.put(metadata, FAKE_CANARY)
            worker_results.clear()
            with mock.patch(
                "gatehouse.credentials.dpapi.asyncio.to_thread",
                new=run_then_fail,
            ):
                with self.assertRaises(_SyntheticBaseException):
                    await store.open_lease(metadata.credential_id, "running worker test")

            self.assertEqual(len(worker_results), 1)
            worker_result = worker_results[0]
            assert isinstance(worker_result, bytearray)
            self.assertEqual(bytes(worker_result), b"\x00" * len(FAKE_CANARY))
            self.assertIs(api.unprotect_result, worker_result)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_unprotect_zeroes_the_worker_result(self) -> None:
        async def scenario(root: str) -> None:
            api = _BlockingDpapi()
            api.release_protect.set()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            await store.put(_metadata(), FAKE_CANARY)

            task = asyncio.create_task(
                store.open_lease(
                    "credential-dpapi",
                    "provider transport",
                    expected_generation=1,
                )
            )
            await _wait_for_thread_event(api.unprotect_started)
            plaintext = api.unprotect_result
            self.assertIsNotNone(plaintext)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            api.release_unprotect.set()
            assert plaintext is not None
            await _wait_for_zeroed(plaintext)
            self.assertEqual(bytes(plaintext), b"\x00" * len(FAKE_CANARY))

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_metadata_cas_allows_only_exact_generation_draining_leases(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata()
            reference = await store.put(metadata, FAKE_CANARY)
            draining = await store.update_metadata(
                replace(metadata, state="DRAINING"),
                expected_generation=1,
            )
            self.assertEqual(draining.secret_reference, reference)

            with self.assertRaises(CredentialUnavailableError):
                await store.open_lease(metadata.credential_id, "provider transport")
            with self.assertRaises(CredentialGenerationMismatchError):
                await store.open_lease(
                    metadata.credential_id,
                    "provider transport",
                    expected_generation=2,
                )
            draining_lease = await store.open_lease(
                metadata.credential_id,
                "provider transport",
                expected_generation=1,
            )
            retained = await draining_lease.__aenter__()

            promoted = await store.update_metadata(
                replace(draining, state="HEALTHY", generation=2),
                expected_generation=1,
            )
            self.assertEqual(promoted.generation, 2)
            self.assertEqual(bytes(retained), b"\x00" * len(FAKE_CANARY))
            with self.assertRaises(CredentialGenerationMismatchError):
                await store.update_metadata(draining, expected_generation=1)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI integration test")
    def test_current_user_round_trip_persists_only_ciphertext_and_metadata(self) -> None:
        scanner = SecretScanner(canaries=(FAKE_CANARY,))
        metadata = _metadata()

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
