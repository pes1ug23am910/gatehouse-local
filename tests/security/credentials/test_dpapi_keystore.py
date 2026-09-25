from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import threading
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest import mock

from gatehouse.core.ids import CredentialId
from gatehouse.credentials import dpapi as dpapi_module
from gatehouse.credentials.base import (
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialUnavailableError,
    KeyStoreError,
    UnsupportedKeyStorePlatformError,
)
from gatehouse.credentials.dpapi import DpapiCurrentUserKeyStore
from gatehouse.credentials.lease import ZeroingSecretLease, zero_bytearray
from gatehouse.credentials.redaction import SecretScanner
from gatehouse.state_security import StateDirectorySecurityError

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


class _BoundedDpapi(_FakeDpapi):
    def __init__(self) -> None:
        super().__init__()
        self.release_crypto = threading.Event()
        self.release_crypto.set()
        self._counter_lock = threading.Lock()
        self.crypto_starts = 0
        self.active_crypto = 0
        self.maximum_active_crypto = 0
        self.unprotected_results: list[bytearray] = []

    def _enter_crypto(self) -> None:
        with self._counter_lock:
            self.crypto_starts += 1
            self.active_crypto += 1
            self.maximum_active_crypto = max(self.maximum_active_crypto, self.active_crypto)
        if not self.release_crypto.wait(timeout=5):
            raise TimeoutError("synthetic crypto worker timed out")

    def _leave_crypto(self) -> None:
        with self._counter_lock:
            self.active_crypto -= 1

    def snapshot(self) -> tuple[int, int, int]:
        with self._counter_lock:
            return self.crypto_starts, self.active_crypto, self.maximum_active_crypto

    def protect(self, plaintext: bytes | bytearray) -> bytes:
        self._enter_crypto()
        try:
            return super().protect(plaintext)
        finally:
            self._leave_crypto()

    def unprotect(self, ciphertext: bytes) -> bytearray:
        self._enter_crypto()
        try:
            value = super().unprotect(ciphertext)
            self.unprotected_results.append(value)
            return value
        finally:
            self._leave_crypto()


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


async def _wait_for_crypto_state(
    api: _BoundedDpapi,
    *,
    starts: int,
    active: int,
) -> None:
    for _ in range(500):
        current_starts, current_active, _ = api.snapshot()
        if current_starts == starts and current_active == active:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("synthetic crypto workers did not reach the expected state")


def _metadata(credential_id: str = "credential-dpapi") -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=credential_id,
        principal_id="principal",
        quota_scope_id="quota",
        alias="fake-test-key",
    )


def _write_owned_intent(store: DpapiCurrentUserKeyStore, credential_id: str, alias: str) -> None:
    blob, metadata = store._paths(credential_id)
    stages = store._staging_paths(credential_id, alias)
    identities = []
    for canonical, stage in ((blob, stages[1]), (metadata, stages[2])):
        if canonical.exists():
            identities.append(dpapi_module._staged_identity(canonical))
        else:
            stage.write_bytes(b"synthetic owned stage")
            identities.append(dpapi_module._staged_identity(stage))
    store._intent_path(credential_id).write_bytes(
        dpapi_module._serialize_staging_intent(
            credential_id,
            alias,
            blob_identity=identities[0],
            metadata_identity=identities[1],
        )
    )


class DpapiKeyStoreTests(unittest.TestCase):
    def test_legacy_account_credential_id_preserves_existing_custody_stem(self) -> None:
        legacy_id = "credential_6234567812344abc8abc1234567890ab"

        parsed = str(CredentialId(legacy_id))

        self.assertEqual(parsed, legacy_id)
        self.assertEqual(
            DpapiCurrentUserKeyStore._stem(parsed),
            hashlib.sha256(legacy_id.encode("utf-8")).hexdigest(),
        )

    def test_non_windows_platform_fails_closed(self) -> None:
        with mock.patch("gatehouse.credentials.dpapi.os.name", "posix"):
            with self.assertRaises(UnsupportedKeyStorePlatformError):
                DpapiCurrentUserKeyStore("unused")

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_private_directory_failure_uses_typed_sanitized_custody_error(self) -> None:
        with mock.patch(
            "gatehouse.credentials.dpapi.secure_private_directory",
            side_effect=StateDirectorySecurityError("synthetic account and path detail"),
        ):
            with self.assertRaisesRegex(
                KeyStoreError,
                "^credential custody permissions are unavailable$",
            ) as captured:
                DpapiCurrentUserKeyStore("sensitive-custody-path", _api=_FakeDpapi())

        self.assertNotIn("synthetic", str(captured.exception))
        self.assertNotIn("sensitive-custody-path", str(captured.exception))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_acl_backend_construction_failure_uses_sanitized_custody_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sensitive_root = Path(temporary) / "sensitive-custody-path"
            with mock.patch(
                "gatehouse.state_security._windows_backend",
                side_effect=AttributeError("synthetic missing Windows ACL symbol"),
            ):
                with self.assertRaisesRegex(
                    KeyStoreError,
                    "^credential custody permissions are unavailable$",
                ) as captured:
                    DpapiCurrentUserKeyStore(sensitive_root, _api=_FakeDpapi())

            self.assertNotIn("synthetic", str(captured.exception))
            self.assertNotIn(str(sensitive_root), str(captured.exception))
            self.assertFalse(sensitive_root.exists())

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
                self.assertFalse(await store.discard_partial(partial_id))
                self.assertFalse(await store.discard_partial(partial_id))
                self.assertEqual(partial_path.read_bytes(), b"synthetic partial")

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_protected_envelope_rejects_transplanted_ciphertext_and_metadata_identity(self) -> None:
        async def scenario(root: str) -> None:
            api = _CapturingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            first, second = _metadata("envelope-first"), _metadata("envelope-second")
            await store.put(first, FAKE_CANARY)
            await store.put(second, FAKE_CANARY)
            first_blob, first_metadata = store._paths(first.credential_id)
            second_blob, _ = store._paths(second.credential_id)
            original_blob = first_blob.read_bytes()
            first_blob.write_bytes(second_blob.read_bytes())
            with self.assertRaisesRegex(
                CredentialUnavailableError,
                "^credential could not be opened$",
            ):
                await store.open_lease(first.credential_id, "synthetic transport")
            self.assertIsNotNone(api.unprotect_result)
            assert api.unprotect_result is not None
            self.assertFalse(any(api.unprotect_result))
            first_blob.write_bytes(original_blob)
            body = json.loads(first_metadata.read_text(encoding="utf-8"))
            body["principal_id"] = "substituted-principal"
            first_metadata.write_text(json.dumps(body), encoding="utf-8")
            with self.assertRaisesRegex(
                CredentialUnavailableError,
                "^credential could not be opened$",
            ):
                await store.open_lease(first.credential_id, "synthetic transport")
            assert api.unprotect_result is not None
            self.assertFalse(any(api.unprotect_result))

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_envelope_rechecks_immutable_metadata_after_unprotection(self) -> None:
        async def scenario(root: str) -> None:
            api = _CapturingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            metadata = _metadata("identity-race")
            await store.put(metadata, FAKE_CANARY)
            original_load = store._load_metadata
            calls = 0

            def changed(credential_id: str) -> CredentialMetadata:
                nonlocal calls
                calls += 1
                item = original_load(credential_id)
                return replace(item, quota_scope_id="changed-scope") if calls == 2 else item

            with mock.patch.object(store, "_load_metadata", side_effect=changed):
                with self.assertRaisesRegex(
                    CredentialUnavailableError,
                    "^credential could not be opened$",
                ):
                    await store.open_lease(metadata.credential_id, "synthetic transport")
            assert api.unprotect_result is not None
            self.assertFalse(any(api.unprotect_result))
            self.assertFalse(store._active_leases[metadata.credential_id])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_generation_and_alias_cas_preserve_ciphertext_and_future_bound_leases(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata("mutable-envelope-fields")
            await store.put(metadata, FAKE_CANARY)
            blob, _ = store._paths(metadata.credential_id)
            before = blob.read_bytes()
            await store.update_metadata(
                replace(metadata, generation=2, alias="committed"),
                expected_generation=1,
            )
            self.assertEqual(blob.read_bytes(), before)
            lease = await store.open_lease(
                metadata.credential_id,
                "synthetic transport",
                expected_generation=2,
            )
            async with lease as view:
                self.assertEqual(bytes(view), FAKE_CANARY)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_put_rejects_noncanonical_supplied_reference_before_protection(self) -> None:
        async def scenario(root: str) -> None:
            api = _FakeDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            with self.assertRaisesRegex(KeyStoreError, "credential custody metadata is invalid"):
                await store.put(replace(_metadata(), secret_reference="unrelated"), FAKE_CANARY)
            self.assertEqual(api.protect_calls, 0)
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_intent_overlap_uses_owned_original_secret_after_caller_zeroes_its_buffer(self) -> None:
        async def scenario(root: str) -> None:
            original = b"730671849276153802994"
            caller = bytearray(original)
            cleaned: list[bytearray] = []
            original_zero = zero_bytearray

            class MutatingDpapi(_FakeDpapi):
                def protect(self, plaintext: bytes | bytearray) -> bytes:
                    caller[:] = b"\x00" * len(caller)
                    return super().protect(plaintext)

            def capture_zero(value: bytearray) -> None:
                cleaned.append(value)
                original_zero(value)

            store = DpapiCurrentUserKeyStore(root, _api=MutatingDpapi())
            with (
                mock.patch(
                    "gatehouse.credentials.dpapi._staged_identity", return_value=(0, int(original))
                ),
                mock.patch("gatehouse.credentials.dpapi.zero_bytearray", side_effect=capture_zero),
            ):
                with self.assertRaisesRegex(
                    KeyStoreError,
                    "credential custody metadata is invalid",
                ):
                    await store.put(_metadata("intent-owned-comparison"), caller)
            self.assertFalse(any(caller))
            self.assertTrue(any(len(value) == len(original) for value in cleaned))
            self.assertTrue(all(not any(value) for value in cleaned))
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_queued_persistence_scrubs_snapshot_without_later_file_claims(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            captured: list[object] = []

            async def queue_persist(
                operation: Callable[[], object],
                *,
                late_result_cleanup: Callable[[object], None] | None = None,
            ) -> object:
                if operation.__name__ == "persist":
                    captured.extend((operation, late_result_cleanup))
                    raise asyncio.CancelledError
                return operation()

            with (
                mock.patch.object(store, "_put_owned", wraps=store._put_owned) as owned_put,
                mock.patch.object(store, "_run_bounded_offload", side_effect=queue_persist),
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await store.put(_metadata("queued-persistence"), FAKE_CANARY)
            comparison_secret = owned_put.call_args.args[1]
            self.assertFalse(any(comparison_secret))
            self.assertEqual(len(captured), 2)
            with mock.patch.object(store, "_discard_staged_sync") as discard:
                result = cast(Callable[[], str], captured[0])()
                self.assertEqual(result, "")
                cast(Callable[[str], None], captured[1])(result)
                discard.assert_not_called()
            self.assertEqual(os.listdir(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_only_publication_preserves_races_and_refuses_later_cleanup(self) -> None:
        async def scenario(root: str, collision_index: int) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata(f"publication-race-{collision_index}")
            original_publish = dpapi_module._publish_create_only
            calls = 0
            raced: Path | None = None

            def race(source: Path, destination: Path) -> None:
                nonlocal calls, raced
                calls += 1
                if calls == collision_index:
                    raced = destination
                    destination.write_bytes(b"synthetic unrelated collision")
                original_publish(source, destination)

            with mock.patch("gatehouse.credentials.dpapi._publish_create_only", side_effect=race):
                with self.assertRaises(CredentialAlreadyExistsError):
                    await store.put(metadata, FAKE_CANARY)
            assert raced is not None
            self.assertEqual(
                raced.read_bytes(),  # noqa: ASYNC240 - bounded synthetic fixture assertion
                b"synthetic unrelated collision",
            )
            self.assertFalse(
                await store.discard_staged(
                    metadata.credential_id,
                    staged_alias=metadata.alias,
                )
            )
            self.assertEqual(
                raced.read_bytes(),  # noqa: ASYNC240 - bounded synthetic fixture assertion
                b"synthetic unrelated collision",
            )

        for collision_index in (1, 2, 3):
            with self.subTest(collision_index=collision_index):
                with tempfile.TemporaryDirectory() as temporary:
                    asyncio.run(scenario(temporary, collision_index))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_failed_publication_preserves_replaced_staged_file_identity(self) -> None:
        async def scenario(root: str, publication: int) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            original_publish = dpapi_module._publish_create_only
            calls = 0
            replaced: Path | None = None

            def replace_stage_then_fail(source: Path, destination: Path) -> None:
                nonlocal calls, replaced
                calls += 1
                if calls == publication:
                    foreign = Path(root) / "foreign-stage-replacement"
                    foreign.write_bytes(b"synthetic foreign staged file")
                    os.replace(foreign, source)
                    replaced = source
                    raise OSError("synthetic publish failure after replacement")
                original_publish(source, destination)

            with mock.patch(
                "gatehouse.credentials.dpapi._publish_create_only",
                side_effect=replace_stage_then_fail,
            ):
                with self.assertRaises(KeyStoreError):
                    await store.put(_metadata(f"stage-replacement-{publication}"), FAKE_CANARY)
            assert replaced is not None
            self.assertEqual(
                replaced.read_bytes(),  # noqa: ASYNC240 - bounded synthetic fixture assertion
                b"synthetic foreign staged file",
            )

        for publication in (1, 2, 3):
            with self.subTest(publication=publication):
                with tempfile.TemporaryDirectory() as temporary:
                    asyncio.run(scenario(temporary, publication))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_partial_stage_write_cleanup_preserves_replacement_and_primary_control(self) -> None:
        def scenario(failure_type: type[BaseException]) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                store = DpapiCurrentUserKeyStore(temporary, _api=_FakeDpapi())
                staged = Path(temporary) / "partial.stage"
                original_fdopen = os.fdopen
                signal = failure_type("synthetic partial write failure")

                class PartialFile:
                    def __init__(self, descriptor: int) -> None:
                        self.handle = original_fdopen(descriptor, "wb")

                    def __enter__(self) -> PartialFile:
                        return self

                    def write(self, value: bytes) -> None:
                        self.handle.write(value[:3])
                        raise signal

                    def __exit__(self, *_args: object) -> None:
                        self.handle.close()
                        foreign = Path(temporary) / "foreign-partial-replacement"
                        foreign.write_bytes(b"synthetic foreign partial stage")
                        os.replace(foreign, staged)

                with mock.patch(
                    "gatehouse.credentials.dpapi.os.fdopen",
                    side_effect=lambda descriptor, _mode: PartialFile(descriptor),
                ):
                    with self.assertRaises(failure_type) as caught:
                        store._stage_owned_file(staged, b"synthetic staged ciphertext")
                self.assertIs(caught.exception, signal)
                self.assertEqual(staged.read_bytes(), b"synthetic foreign partial stage")

        for failure_type in (RuntimeError, KeyboardInterrupt, SystemExit):
            with self.subTest(failure_type=failure_type):
                scenario(failure_type)

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_legacy_marker_and_replaced_file_identity_cannot_authorize_recovery(self) -> None:
        async def scenario(root: str, defect: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata(f"recovery-{defect}")
            await store.put(metadata, FAKE_CANARY)
            marker = store._intent_path(metadata.credential_id)
            blob, metadata_path = store._paths(metadata.credential_id)
            if defect == "legacy":
                marker.write_text(
                    json.dumps(
                        {
                            "credential_id": metadata.credential_id,
                            "staged_alias": metadata.alias,
                        }
                    ),
                    encoding="utf-8",
                )
            else:
                replacement = Path(root) / "unrelated-replacement"
                replacement.write_bytes(b"synthetic unrelated replacement")
                os.replace(replacement, blob)
            before = {path: path.read_bytes() for path in (marker, blob, metadata_path)}
            self.assertFalse(
                await store.discard_staged(
                    metadata.credential_id,
                    staged_alias=metadata.alias,
                )
            )
            self.assertEqual({path: path.read_bytes() for path in before}, before)

        for defect in ("legacy", "identity"):
            with self.subTest(defect=defect):
                with tempfile.TemporaryDirectory() as temporary:
                    asyncio.run(scenario(temporary, defect))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_every_canonical_publication_checkpoint_has_single_link_owned_recovery(self) -> None:
        async def scenario(root: str, published_count: int) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            credential_id, alias = "crash-checkpoint", "owned-crash-stage"
            blob, metadata_path = store._paths(credential_id)
            marker = store._intent_path(credential_id)
            stages = store._staging_paths(credential_id, alias)
            store._stage_owned_file(stages[1], b"synthetic ciphertext")
            store._stage_owned_file(stages[2], b"synthetic metadata")
            store._stage_owned_file(
                stages[0],
                dpapi_module._serialize_staging_intent(
                    credential_id,
                    alias,
                    blob_identity=dpapi_module._staged_identity(stages[1]),
                    metadata_identity=dpapi_module._staged_identity(stages[2]),
                ),
            )
            publications = tuple(zip(stages, (marker, blob, metadata_path), strict=True))
            for source, target in publications[:published_count]:
                dpapi_module._publish_create_only(source, target)
                self.assertFalse(source.exists())
                self.assertEqual(target.stat().st_nlink, 1)
            restarted = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            self.assertTrue(await restarted.discard_staged(credential_id, staged_alias=alias))
            self.assertEqual(os.listdir(root), [])

        for count in range(4):
            with self.subTest(published_count=count):
                with tempfile.TemporaryDirectory() as temporary:
                    asyncio.run(scenario(temporary, count))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_metadata_replacement_releases_staging_identity_even_without_alias_change(self) -> None:
        async def scenario(root: str, operation: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata(f"metadata-replacement-{operation}")
            await store.put(metadata, FAKE_CANARY)
            marker = store._intent_path(metadata.credential_id)
            self.assertTrue(marker.exists())
            if operation == "disable":
                await store.disable(metadata.credential_id)
            else:
                await store.update_metadata(replace(metadata, generation=2), expected_generation=1)
            self.assertFalse(marker.exists())
            self.assertFalse(
                await store.discard_staged(
                    metadata.credential_id,
                    staged_alias=metadata.alias,
                )
            )

        for operation in ("disable", "generation"):
            with self.subTest(operation=operation):
                with tempfile.TemporaryDirectory() as temporary:
                    asyncio.run(scenario(temporary, operation))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_metadata_count_and_file_sizes_are_bounded_before_read(self) -> None:
        async def scenario(root: str) -> None:
            api = _FakeDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            metadata = _metadata()
            await store.put(metadata, FAKE_CANARY)

            extra_path = Path(root, "extra.json")
            await asyncio.to_thread(extra_path.write_text, "{}", encoding="utf-8")
            count_bounded = DpapiCurrentUserKeyStore(
                root,
                _api=api,
                maximum_metadata_files=1,
            )
            with self.assertRaisesRegex(KeyStoreError, "file count"):
                await count_bounded.list_metadata()

            await asyncio.to_thread(extra_path.unlink)
            metadata_bounded = DpapiCurrentUserKeyStore(
                root,
                _api=api,
                maximum_metadata_bytes=32,
            )
            with self.assertRaisesRegex(KeyStoreError, "metadata files are invalid"):
                await metadata_bounded.list_metadata()

            ciphertext_bounded = DpapiCurrentUserKeyStore(
                root,
                _api=api,
                maximum_ciphertext_bytes=4,
            )
            with self.assertRaisesRegex(CredentialUnavailableError, "could not be opened"):
                await ciphertext_bounded.open_lease(
                    metadata.credential_id,
                    "provider transport",
                    expected_generation=1,
                )

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_metadata_scan_bounds_all_directory_entries_with_sanitized_failure(self) -> None:
        async def scenario(root: str) -> None:
            sensitive_name = FAKE_CANARY.decode("ascii")
            for index in range(4):
                await asyncio.to_thread(
                    Path(root, f"{sensitive_name}-{index}.noise").write_bytes,
                    b"noise",
                )
            store = DpapiCurrentUserKeyStore(
                root,
                _api=_FakeDpapi(),
                maximum_directory_entries=3,
            )

            with self.assertRaises(KeyStoreError) as captured:
                await store.list_metadata()

            self.assertEqual(
                str(captured.exception),
                "credential custody directory entry count exceeds its bound",
            )
            self.assertNotIn(sensitive_name, str(captured.exception))

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
            original_publish = dpapi_module._publish_create_only
            original_stage = store._stage_owned_file
            published: list[Path] = []
            staged: list[Path] = []

            def observe_stage(path: Path, data: bytes) -> Path:
                if path in {expected_stages[1], expected_stages[2]}:
                    self.assertFalse(intent_path.exists())
                    self.assertFalse(blob_path.exists())
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
                original_publish(Path(source), Path(target))
                self.assertFalse(Path(source).exists())
                self.assertEqual(target_path.stat().st_nlink, 1)
                published.append(target_path)
                if target_path == intent_path:
                    intent = json.loads(intent_path.read_text(encoding="utf-8"))
                    self.assertEqual(intent["schema_version"], 1)
                    self.assertEqual(intent["credential_id"], metadata.credential_id)
                    self.assertEqual(intent["staged_alias"], metadata.alias)
                    self.assertEqual(
                        tuple(intent["blob_identity"]),
                        dpapi_module._staged_identity(expected_stages[1]),
                    )
                    self.assertEqual(
                        tuple(intent["metadata_identity"]),
                        dpapi_module._staged_identity(expected_stages[2]),
                    )

            with (
                mock.patch.object(store, "_stage_owned_file", side_effect=observe_stage),
                mock.patch(
                    "gatehouse.credentials.dpapi._publish_create_only",
                    side_effect=observe_publish,
                ),
            ):
                await store.put(metadata, FAKE_CANARY)

            self.assertEqual(published, [intent_path, blob_path, metadata_path])
            self.assertEqual(staged, [expected_stages[1], expected_stages[2], expected_stages[0]])
            self.assertTrue(all(metadata.alias not in path.name for path in expected_stages))
            self.assertTrue(intent_path.is_file())
            self.assertTrue(blob_path.is_file())
            self.assertTrue(metadata_path.is_file())

            committed = await store.update_metadata(
                replace(metadata, alias="committed-alias"),
                expected_generation=1,
            )
            self.assertEqual(committed.alias, "committed-alias")
            self.assertFalse(intent_path.exists())

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_publication_cleans_before_releasing_worker_capacity(self) -> None:
        async def scenario(root: str) -> None:
            metadata = _metadata("cancelled-publication")
            store = DpapiCurrentUserKeyStore(
                root,
                _api=_FakeDpapi(),
                maximum_io_workers=1,
            )
            intent_path = store._intent_path(metadata.credential_id)
            blob_path, metadata_path = store._paths(metadata.credential_id)
            metadata_stage_path = store._staging_paths(
                metadata.credential_id,
                metadata.alias,
            )[2]
            original_stage = store._stage_owned_file
            original_discard = store._discard_staged_sync
            event_loop_thread = threading.get_ident()
            publication_blocked = threading.Event()
            release_publication = threading.Event()
            cleanup_blocked = threading.Event()
            release_cleanup = threading.Event()
            cleanup_threads: list[int] = []
            caller_secret = bytearray(FAKE_CANARY)

            def block_metadata_stage(path: Path, data: bytes) -> Path:
                if path == metadata_stage_path:
                    publication_blocked.set()
                    if not release_publication.wait(timeout=5):
                        raise TimeoutError("synthetic publication worker timed out")
                return original_stage(path, data)

            def block_late_cleanup(credential_id: str, *, staged_alias: str) -> bool:
                cleanup_threads.append(threading.get_ident())
                cleanup_blocked.set()
                if not release_cleanup.wait(timeout=5):
                    raise TimeoutError("synthetic cleanup worker timed out")
                return original_discard(credential_id, staged_alias=staged_alias)

            task: asyncio.Task[str] | None = None
            follower: asyncio.Task[tuple[CredentialMetadata, ...]] | None = None
            safety_release = threading.Timer(2, release_publication.set)
            cleanup_safety_release = threading.Timer(4, release_cleanup.set)
            safety_release.start()
            cleanup_safety_release.start()
            try:
                with (
                    mock.patch.object(store, "_put_owned", wraps=store._put_owned) as owned_put,
                    mock.patch.object(
                        store,
                        "_stage_owned_file",
                        side_effect=block_metadata_stage,
                    ),
                    mock.patch.object(
                        store,
                        "_discard_staged_sync",
                        side_effect=block_late_cleanup,
                    ),
                ):
                    task = asyncio.create_task(store.put(metadata, caller_secret))
                    await _wait_for_thread_event(publication_blocked)
                    comparison_secret = owned_put.call_args.args[1]
                    self.assertIsInstance(comparison_secret, bytearray)
                    self.assertIsNot(comparison_secret, caller_secret)
                    caller_secret[:] = b"\x00" * len(caller_secret)
                    self.assertFalse(intent_path.exists())
                    self.assertFalse(blob_path.exists())
                    self.assertFalse(metadata_path.exists())

                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assertEqual(comparison_secret, FAKE_CANARY)

                    follower = asyncio.create_task(store.list_metadata())
                    await asyncio.sleep(0.05)
                    self.assertFalse(follower.done())

                    release_publication.set()
                    await _wait_for_thread_event(cleanup_blocked)
                    self.assertEqual(len(cleanup_threads), 1)
                    self.assertNotEqual(cleanup_threads[0], event_loop_thread)

                    responsive = asyncio.Event()
                    asyncio.get_running_loop().call_soon(responsive.set)
                    await asyncio.wait_for(responsive.wait(), timeout=0.5)
                    self.assertFalse(follower.done())

                    release_cleanup.set()
                    self.assertEqual(
                        await asyncio.wait_for(follower, timeout=1),
                        (),
                    )
                    self.assertFalse(any(comparison_secret))
                self.assertEqual(os.listdir(root), [])
            finally:
                release_publication.set()
                release_cleanup.set()
                safety_release.cancel()
                cleanup_safety_release.cancel()
                for pending in (task, follower):
                    if pending is not None and not pending.done():
                        pending.cancel()
                await asyncio.gather(
                    *(pending for pending in (task, follower) if pending is not None),
                    return_exceptions=True,
                )

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_create_rolls_back_intent_and_blob_when_metadata_publish_fails(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            original_publish = dpapi_module._publish_create_only
            calls = 0

            def fail_metadata_publish(source: str | Path, target: str | Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("synthetic platform publish detail")
                original_publish(Path(source), Path(target))

            with mock.patch(
                "gatehouse.credentials.dpapi._publish_create_only",
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
    def test_base_exception_after_final_rename_removes_exact_owned_files(self) -> None:
        async def scenario(root: str, fail_after: str) -> None:
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            metadata = _metadata(f"post-{fail_after}-rename-crash")
            intent_path = store._intent_path(metadata.credential_id)
            blob_path, metadata_path = store._paths(metadata.credential_id)
            failing_target = {
                "intent": intent_path,
                "blob": blob_path,
                "metadata": metadata_path,
            }[fail_after]
            original_publish = dpapi_module._publish_create_only

            def publish_then_abort(source: str | Path, target: str | Path) -> None:
                original_publish(Path(source), Path(target))
                if Path(target) == failing_target:
                    raise _SyntheticBaseException(f"synthetic {fail_after} post-rename crash")

            with mock.patch(
                "gatehouse.credentials.dpapi._publish_create_only",
                side_effect=publish_then_abort,
            ):
                with self.assertRaises(_SyntheticBaseException):
                    await store.put(metadata, FAKE_CANARY)

            self.assertFalse(intent_path.exists())
            self.assertFalse(blob_path.exists())
            self.assertFalse(metadata_path.exists())
            self.assertEqual(os.listdir(root), [])

        for fail_after in ("intent", "blob", "metadata"):
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
            original_publish = dpapi_module._publish_create_only
            original_unlink = Path.unlink
            calls = 0

            def fail_metadata_publish(source: str | Path, target: str | Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("synthetic platform publish detail")
                original_publish(Path(source), Path(target))

            def fail_blob_cleanup(path: Path, missing_ok: bool = False) -> None:
                if path == blob_path:
                    raise PermissionError("synthetic cleanup denial")
                original_unlink(path, missing_ok=missing_ok)

            with (
                mock.patch(
                    "gatehouse.credentials.dpapi._publish_create_only",
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
            mixed_blob.write_bytes(b"owned ciphertext partial")
            _write_owned_intent(store, mixed_id, staged_alias)
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
                if has_blob:
                    blob_path.write_bytes(b"owned ciphertext partial")
                if has_metadata:
                    metadata_path.write_bytes(b"owned metadata partial")
                _write_owned_intent(store, credential_id, staged_alias)
                temporary_path = store._staging_paths(credential_id, staged_alias)[0]
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
            self.assertTrue(intent_path.is_file())
            temporary_path = store._staging_paths(metadata.credential_id, metadata.alias)[0]
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
            with mock.patch.object(store, "_put_owned", wraps=store._put_owned) as owned_put:
                task = asyncio.create_task(store.put(_metadata(), caller_secret))
                await _wait_for_thread_event(api.protect_started)
                comparison_secret = owned_put.call_args.args[1]

            worker_input = api.protect_input
            self.assertIsInstance(worker_input, bytearray)
            self.assertIsNot(worker_input, caller_secret)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            assert isinstance(worker_input, bytearray)
            self.assertTrue(worker_input.startswith(dpapi_module._ENVELOPE_MAGIC))
            self.assertTrue(worker_input.endswith(FAKE_CANARY))
            self.assertFalse(any(comparison_secret))
            self.assertEqual(bytes(caller_secret), FAKE_CANARY)
            api.release_protect.set()
            await _wait_for_zeroed(worker_input)
            self.assertEqual(bytes(worker_input), b"\x00" * len(worker_input))
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
                if function.__name__ != "protect":
                    return function()
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
            self.assertEqual(bytes(queued_secret), b"\x00" * len(queued_secret))
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
            queued_workers: list[Callable[[], object]] = []
            queued_secrets: list[bytearray] = []

            async def queue_then_fail(
                function: Callable[[], object],
            ) -> object:
                if function.__name__ in {"ensure_absent", "persist"}:
                    return function()
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
            self.assertEqual(bytes(queued_secrets[0]), b"\x00" * len(queued_secrets[0]))
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
            self.assertEqual(queued_workers[0].__name__, "open_credential")
            with self.assertRaises(CredentialUnavailableError):
                queued_workers[0]()
            self.assertIsNone(api.unprotect_result)
            self.assertEqual(api.unprotect_calls, 0)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_running_base_exception_keeps_worker_owned_buffers_zeroed(self) -> None:
        async def scenario(root: str) -> None:
            api = _CapturingDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api)
            worker_results: list[object] = []

            async def run_then_fail(
                function: Callable[[], object],
            ) -> object:
                if function.__name__ in {"ensure_absent", "persist"}:
                    return function()
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
                b"\x00" * len(failed_protect_input),
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
            assert isinstance(worker_result, ZeroingSecretLease)
            self.assertTrue(worker_result.closed)
            assert api.unprotect_result is not None
            self.assertEqual(
                bytes(api.unprotect_result),
                b"\x00" * len(api.unprotect_result),
            )

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
            self.assertEqual(bytes(plaintext), b"\x00" * len(plaintext))

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_abandoned_unprotect_worker_closes_lease_without_late_cleanup_dispatch(self) -> None:
        async def scenario(root: str) -> None:
            api = _BlockingDpapi()
            api.release_protect.set()
            store = DpapiCurrentUserKeyStore(root, _api=api, maximum_io_workers=1)
            await store.put(_metadata(), FAKE_CANARY)
            completed = asyncio.Event()
            results: list[ZeroingSecretLease] = []

            def drop_late_cleanup(
                worker: asyncio.Task[ZeroingSecretLease],
                *,
                late_result_cleanup: Callable[[ZeroingSecretLease], None] | None,
            ) -> None:
                del late_result_cleanup
                try:
                    results.append(worker.result())
                finally:
                    store._io_semaphore.release()
                    completed.set()

            with mock.patch.object(store, "_release_offload_slot", side_effect=drop_late_cleanup):
                opening = asyncio.create_task(
                    store.open_lease(
                        "credential-dpapi",
                        "abandoned worker test",
                        expected_generation=1,
                    )
                )
                try:
                    await _wait_for_thread_event(api.unprotect_started)
                    opening.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await opening
                    api.release_unprotect.set()
                    await asyncio.wait_for(completed.wait(), timeout=1)
                    self.assertEqual(len(results), 1)
                    self.assertTrue(results[0].closed)
                    self.assertFalse(any(results[0]._buffer))
                    assert api.unprotect_result is not None
                    self.assertFalse(any(api.unprotect_result))
                finally:
                    api.release_unprotect.set()
                    if not opening.done():
                        opening.cancel()
                        await asyncio.gather(opening, return_exceptions=True)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_crypto_worker_retains_the_shared_offload_slot_until_exit(self) -> None:
        async def scenario(root: str) -> None:
            api = _BoundedDpapi()
            store = DpapiCurrentUserKeyStore(root, _api=api, maximum_io_workers=1)
            seed = _metadata("bounded-offload-seed")
            await store.put(seed, FAKE_CANARY)
            self.assertEqual(api.snapshot(), (1, 0, 1))

            api.release_crypto.clear()
            opening = asyncio.create_task(
                store.open_lease(seed.credential_id, "bounded cancellation test")
            )
            await _wait_for_crypto_state(api, starts=2, active=1)
            opening.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await opening

            queued = [
                asyncio.create_task(
                    store.put(_metadata(f"bounded-offload-queued-{index}"), FAKE_CANARY)
                )
                for index in range(8)
            ]
            await asyncio.sleep(0.05)
            self.assertEqual(api.snapshot(), (2, 1, 1))

            for task in queued:
                task.cancel()
            results = await asyncio.gather(*queued, return_exceptions=True)
            self.assertTrue(all(isinstance(result, asyncio.CancelledError) for result in results))
            self.assertEqual(api.snapshot(), (2, 1, 1))

            api.release_crypto.set()
            await _wait_for_crypto_state(api, starts=2, active=0)
            self.assertEqual(len(api.unprotected_results), 1)
            await _wait_for_zeroed(api.unprotected_results[0])
            self.assertEqual(api.snapshot(), (2, 0, 1))
            filenames = await asyncio.to_thread(os.listdir, root)
            self.assertEqual(
                sorted(Path(name).suffix for name in filenames),
                [".dpapi", ".intent", ".json"],
            )

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_slow_metadata_filesystem_work_does_not_block_the_event_loop(self) -> None:
        async def scenario(root: str) -> None:
            metadata = _metadata("slow-metadata")
            store = DpapiCurrentUserKeyStore(root, _api=_FakeDpapi())
            await store.put(metadata, FAKE_CANARY)
            loop = asyncio.get_running_loop()
            worker_started = asyncio.Event()
            release_worker = threading.Event()
            original_load = store._load_metadata

            def slow_load(credential_id: str) -> CredentialMetadata:
                loop.call_soon_threadsafe(worker_started.set)
                if not release_worker.wait(timeout=5):
                    raise TimeoutError("synthetic metadata worker timed out")
                return original_load(credential_id)

            task: asyncio.Task[CredentialMetadata] | None = None
            safety_release = threading.Timer(2, release_worker.set)
            safety_release.start()
            try:
                with mock.patch.object(store, "_load_metadata", side_effect=slow_load):
                    task = asyncio.create_task(
                        store.update_metadata(
                            replace(metadata, alias="updated-after-slow-read"),
                            expected_generation=1,
                        )
                    )
                    await asyncio.wait_for(worker_started.wait(), timeout=1)

                    round_trip = asyncio.Event()
                    loop.call_soon(round_trip.set)
                    await asyncio.wait_for(round_trip.wait(), timeout=0.25)
                    self.assertFalse(release_worker.is_set())

                    release_worker.set()
                    updated = await asyncio.wait_for(task, timeout=1)
                    self.assertEqual(updated.alias, "updated-after-slow-read")
            finally:
                release_worker.set()
                safety_release.cancel()
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(scenario(temporary))

    @unittest.skipUnless(os.name == "nt", "DPAPI custody filesystem test requires Windows")
    def test_cancelled_filesystem_storm_never_exceeds_the_worker_bound(self) -> None:
        async def scenario(root: str) -> None:
            store = DpapiCurrentUserKeyStore(
                root,
                _api=_FakeDpapi(),
                maximum_io_workers=2,
            )
            loop = asyncio.get_running_loop()
            two_workers_started = asyncio.Event()
            workers_finished = asyncio.Event()
            release_workers = threading.Event()
            counter_lock = threading.Lock()
            starts = 0
            active = 0
            maximum_active = 0

            def blocked_list() -> tuple[CredentialMetadata, ...]:
                nonlocal active, maximum_active, starts
                with counter_lock:
                    starts += 1
                    active += 1
                    maximum_active = max(maximum_active, active)
                    if active == 2:
                        loop.call_soon_threadsafe(two_workers_started.set)
                try:
                    if not release_workers.wait(timeout=5):
                        raise TimeoutError("synthetic filesystem worker timed out")
                    return ()
                finally:
                    with counter_lock:
                        active -= 1
                        if active == 0:
                            loop.call_soon_threadsafe(workers_finished.set)

            safety_release = threading.Timer(2, release_workers.set)
            safety_release.start()
            tasks: list[asyncio.Task[tuple[CredentialMetadata, ...]]] = []
            try:
                with mock.patch.object(store, "_list_metadata_sync", side_effect=blocked_list):
                    tasks = [asyncio.create_task(store.list_metadata()) for _ in range(16)]
                    await asyncio.wait_for(two_workers_started.wait(), timeout=1)
                    with counter_lock:
                        self.assertEqual((starts, active, maximum_active), (2, 2, 2))

                    for task in tasks:
                        task.cancel()
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    self.assertTrue(
                        all(isinstance(result, asyncio.CancelledError) for result in results)
                    )
                    with counter_lock:
                        self.assertEqual((starts, active, maximum_active), (2, 2, 2))

                    release_workers.set()
                    await asyncio.wait_for(workers_finished.wait(), timeout=1)
                self.assertEqual(await asyncio.wait_for(store.list_metadata(), timeout=1), ())
                with counter_lock:
                    self.assertEqual((starts, active, maximum_active), (2, 0, 2))
            finally:
                release_workers.set()
                safety_release.cancel()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

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
