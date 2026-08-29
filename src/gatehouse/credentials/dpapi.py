"""Windows DPAPI CurrentUser KeyStore implemented with stdlib ``ctypes``."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import suppress
from ctypes import wintypes
from dataclasses import asdict, replace
from pathlib import Path
from typing import Protocol, TypeVar

from gatehouse.state_security import StateDirectorySecurityError, secure_private_directory

from .base import (
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyStoreError,
    UnsupportedKeyStorePlatformError,
)
from .lease import ZeroingSecretLease, zero_bytearray

CRYPTPROTECT_UI_FORBIDDEN = 0x1
_MINIMUM_ACL_VERIFICATION_ENTRIES = 16_384
_IoResult = TypeVar("_IoResult")


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class _DpapiApi(Protocol):
    def protect(self, plaintext: bytes | bytearray) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytearray: ...


class _WindowsDpapi:
    """Minimal CryptProtectData/CryptUnprotectData wrapper."""

    def __init__(self) -> None:
        crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
        kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        self._crypt32 = crypt32
        self._kernel32 = kernel32

    @staticmethod
    def _input_blob(data: bytes | bytearray) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
        buffer_type = ctypes.c_ubyte * len(data)
        buffer = buffer_type.from_buffer_copy(data)
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        return _DataBlob(len(data), pointer), buffer

    @staticmethod
    def _zero_ctypes_buffer(buffer: ctypes.Array[ctypes.c_ubyte]) -> None:
        if ctypes.sizeof(buffer):
            ctypes.memset(ctypes.addressof(buffer), 0, ctypes.sizeof(buffer))

    def protect(self, plaintext: bytes | bytearray) -> bytes:
        input_blob, input_buffer = self._input_blob(plaintext)
        output_blob = _DataBlob()
        try:
            success = self._crypt32.CryptProtectData(
                ctypes.byref(input_blob),
                "Gatehouse credential",
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            if not success:
                raise ctypes.WinError(ctypes.get_last_error())
            return bytes(ctypes.string_at(output_blob.pbData, output_blob.cbData))
        finally:
            self._zero_ctypes_buffer(input_buffer)
            if output_blob.pbData:
                self._kernel32.LocalFree(output_blob.pbData)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        input_blob, input_buffer = self._input_blob(ciphertext)
        output_blob = _DataBlob()
        description = wintypes.LPWSTR()
        try:
            success = self._crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                ctypes.byref(description),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
            if not success:
                raise ctypes.WinError(ctypes.get_last_error())

            plaintext = bytearray(int(output_blob.cbData))
            if plaintext:
                destination = (ctypes.c_ubyte * len(plaintext)).from_buffer(plaintext)
                ctypes.memmove(destination, output_blob.pbData, len(plaintext))
                ctypes.memset(output_blob.pbData, 0, len(plaintext))
            return plaintext
        finally:
            self._zero_ctypes_buffer(input_buffer)
            if description:
                self._kernel32.LocalFree(description)
            if output_blob.pbData:
                self._kernel32.LocalFree(output_blob.pbData)


class DpapiCurrentUserKeyStore:
    """Persist DPAPI ciphertext and non-secret metadata under a private root."""

    def __init__(
        self,
        root: str | Path,
        *,
        default_lease_ttl_seconds: float = 30.0,
        maximum_lease_ttl_seconds: float = 300.0,
        maximum_metadata_files: int = 4_096,
        maximum_directory_entries: int = 16_384,
        maximum_metadata_bytes: int = 16_384,
        maximum_ciphertext_bytes: int = 65_536,
        maximum_io_workers: int = 4,
        _api: _DpapiApi | None = None,
    ) -> None:
        if os.name != "nt":
            raise UnsupportedKeyStorePlatformError(
                "DpapiCurrentUserKeyStore is available only on Windows"
            )
        if default_lease_ttl_seconds <= 0:
            raise ValueError("default lease TTL must be positive")
        if maximum_lease_ttl_seconds < default_lease_ttl_seconds:
            raise ValueError("maximum lease TTL must cover the default")
        if (
            min(
                maximum_metadata_files,
                maximum_directory_entries,
                maximum_metadata_bytes,
                maximum_ciphertext_bytes,
                maximum_io_workers,
            )
            <= 0
            or maximum_metadata_files > 100_000
            or maximum_directory_entries > 200_000
            or maximum_metadata_bytes > 1_048_576
            or maximum_ciphertext_bytes > 1_048_576
            or maximum_io_workers > 32
        ):
            raise ValueError("credential filesystem bounds are invalid")

        try:
            self._root = secure_private_directory(
                root,
                recursive=True,
                maximum_entries=max(
                    maximum_directory_entries,
                    _MINIMUM_ACL_VERIFICATION_ENTRIES,
                ),
            )
        except StateDirectorySecurityError:
            raise KeyStoreError("credential custody permissions are unavailable") from None
        self._default_ttl = default_lease_ttl_seconds
        self._maximum_ttl = maximum_lease_ttl_seconds
        self._api: _DpapiApi = _api or _WindowsDpapi()
        self._maximum_metadata_files = maximum_metadata_files
        self._maximum_directory_entries = maximum_directory_entries
        self._maximum_metadata_bytes = maximum_metadata_bytes
        self._maximum_ciphertext_bytes = maximum_ciphertext_bytes
        self._io_semaphore = asyncio.Semaphore(maximum_io_workers)
        self._late_cleanup_tasks: set[asyncio.Task[None]] = set()
        self._lock = threading.RLock()
        self._active_leases: dict[str, weakref.WeakSet[ZeroingSecretLease]] = {}

    @staticmethod
    def _stem(credential_id: str) -> str:
        if not credential_id:
            raise ValueError("credential_id is required")
        return hashlib.sha256(credential_id.encode("utf-8")).hexdigest()

    def _paths(self, credential_id: str) -> tuple[Path, Path]:
        stem = self._stem(credential_id)
        return self._root / f"{stem}.dpapi", self._root / f"{stem}.json"

    @staticmethod
    def _read_bounded(path: Path, *, maximum_bytes: int) -> bytes:
        try:
            if not path.is_file() or path.stat().st_size > maximum_bytes:
                raise KeyStoreError("credential custody file exceeds its bound")
            with path.open("rb") as handle:
                value = handle.read(maximum_bytes + 1)
        except KeyStoreError:
            raise
        except OSError:
            raise KeyStoreError("credential custody file is unavailable") from None
        if len(value) > maximum_bytes:
            raise KeyStoreError("credential custody file exceeds its bound")
        return value

    async def _run_bounded_offload(
        self,
        operation: Callable[[], _IoResult],
        *,
        late_result_cleanup: Callable[[_IoResult], None] | None = None,
    ) -> _IoResult:
        await self._io_semaphore.acquire()
        try:
            worker = asyncio.create_task(asyncio.to_thread(operation))
        except BaseException:
            self._io_semaphore.release()
            raise
        release_on_completion = False
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            release_on_completion = True
            worker.add_done_callback(
                lambda completed: self._release_offload_slot(
                    completed,
                    late_result_cleanup=late_result_cleanup,
                )
            )
            raise
        finally:
            if not release_on_completion:
                self._io_semaphore.release()

    def _release_offload_slot(
        self,
        worker: asyncio.Task[_IoResult],
        *,
        late_result_cleanup: Callable[[_IoResult], None] | None,
    ) -> None:
        # A cancelled waiter must not release capacity while its non-pre-emptible
        # thread or its filesystem cleanup is still running. Retrieve late
        # failures so they cannot become unhandled task exceptions.
        try:
            result = worker.result()
        except BaseException:
            self._io_semaphore.release()
            return
        if late_result_cleanup is None:
            self._io_semaphore.release()
            return

        cleanup_coroutine = asyncio.to_thread(late_result_cleanup, result)
        try:
            cleanup_task = asyncio.create_task(cleanup_coroutine)
        except BaseException:
            cleanup_coroutine.close()
            self._io_semaphore.release()
            return
        self._late_cleanup_tasks.add(cleanup_task)
        cleanup_task.add_done_callback(self._complete_late_cleanup)

    def _complete_late_cleanup(self, cleanup_task: asyncio.Task[None]) -> None:
        try:
            with suppress(BaseException):
                cleanup_task.result()
        finally:
            self._late_cleanup_tasks.discard(cleanup_task)
            self._io_semaphore.release()

    def _intent_path(self, credential_id: str) -> Path:
        return self._root / f"{self._stem(credential_id)}.intent"

    def _staging_paths(self, credential_id: str, staged_alias: str) -> tuple[Path, Path, Path]:
        if not isinstance(staged_alias, str) or not staged_alias:
            raise ValueError("staged_alias is required")
        stem = self._stem(credential_id)
        ownership_token = hashlib.sha256(staged_alias.encode("utf-8")).hexdigest()
        return (
            self._root / f".{stem}.intent.{ownership_token}.stage",
            self._root / f".{stem}.dpapi.{ownership_token}.stage",
            self._root / f".{stem}.json.{ownership_token}.stage",
        )

    def _temporary_paths(self, credential_id: str) -> tuple[Path, ...]:
        stem = self._stem(credential_id)
        paths: list[Path] = []
        for suffix in (".intent", ".dpapi", ".json"):
            paths.extend(self._root.glob(f".{stem}{suffix}.*"))
        return tuple(sorted(paths))

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
            ) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _stage_owned_file(self, path: Path, data: bytes) -> Path:
        descriptor: int | None = None
        created = False
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(path, 0o600)
            self._flush_published_file(path)
            return path
        except BaseException:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            if created:
                with suppress(OSError):
                    path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _path_exists(path: Path) -> bool:
        return os.path.lexists(path)

    @staticmethod
    def _flush_published_file(path: Path) -> None:
        # Windows requires a writable handle for FlushFileBuffers, which backs
        # os.fsync().  Open without truncation so durability checks work on the
        # same platform as the DPAPI implementation.
        with path.open("r+b") as handle:
            os.fsync(handle.fileno())

    @staticmethod
    def _intent_matches(path: Path, credential_id: str, staged_alias: str) -> bool:
        try:
            if not path.is_file() or path.stat().st_size > 4_096:
                return False
            raw: object = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(raw, dict):
            return False
        return (
            set(raw) == {"credential_id", "staged_alias"}
            and raw.get("credential_id") == credential_id
            and raw.get("staged_alias") == staged_alias
        )

    def _load_metadata(self, credential_id: str) -> CredentialMetadata:
        blob_path, metadata_path = self._paths(credential_id)
        if not blob_path.is_file() or not metadata_path.is_file():
            raise CredentialNotFoundError(credential_id)
        try:
            encoded = self._read_bounded(
                metadata_path,
                maximum_bytes=self._maximum_metadata_bytes,
            )
            raw = json.loads(encoded.decode("utf-8"))
            metadata = CredentialMetadata(**raw)
        except (KeyStoreError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
            raise KeyStoreError("credential metadata is invalid") from None
        if metadata.credential_id != credential_id:
            raise KeyStoreError("credential metadata identifier mismatch")
        expected_reference = f"dpapi-current-user://{self._stem(credential_id)}"
        if metadata.secret_reference != expected_reference:
            raise KeyStoreError("credential metadata reference mismatch")
        return metadata

    async def put(self, metadata: CredentialMetadata, secret: bytes | bytearray) -> str:
        if not secret:
            raise ValueError("credential secret must not be empty")
        reference = f"dpapi-current-user://{self._stem(metadata.credential_id)}"
        stored = replace(metadata, secret_reference=reference)
        blob_path, metadata_path = self._paths(metadata.credential_id)
        intent_path = self._intent_path(metadata.credential_id)
        intent_bytes = _serialize_staging_intent(metadata.credential_id, metadata.alias)
        intent_stage_path, blob_stage_path, metadata_stage_path = self._staging_paths(
            metadata.credential_id,
            metadata.alias,
        )
        metadata_bytes = json.dumps(asdict(stored), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(metadata_bytes) > self._maximum_metadata_bytes:
            raise KeyStoreError("credential metadata exceeds its size bound")
        cleartext_surfaces = (
            reference.encode("utf-8"),
            intent_bytes,
            metadata_bytes,
            *(
                path.name.encode("utf-8")
                for path in (
                    intent_path,
                    blob_path,
                    metadata_path,
                    intent_stage_path,
                    blob_stage_path,
                    metadata_stage_path,
                )
            ),
        )
        if any(surface.find(secret) >= 0 for surface in cleartext_surfaces):
            raise KeyStoreError("credential custody metadata is invalid")

        def ensure_absent() -> None:
            with self._lock:
                if any(
                    self._path_exists(path)
                    for path in (
                        intent_path,
                        blob_path,
                        metadata_path,
                        *self._temporary_paths(metadata.credential_id),
                    )
                ):
                    raise CredentialAlreadyExistsError("credential already exists")

        await self._run_bounded_offload(ensure_absent)
        # Own a mutable input across the worker boundary.  A cancelled caller may
        # zero or release its buffer while CryptProtectData is still running, so
        # the worker must never borrow that caller-owned storage.
        owned_secret = bytearray(secret)
        protect_lock = threading.Lock()
        abandoned = False
        worker_started = False

        def protect() -> bytes:
            nonlocal worker_started
            with protect_lock:
                worker_started = True
                skip_protection = abandoned
            if skip_protection:
                zero_bytearray(owned_secret)
                return b""
            try:
                return self._api.protect(owned_secret)
            finally:
                zero_bytearray(owned_secret)

        protection_failed = False
        try:
            protected = await self._run_bounded_offload(protect)
        except BaseException as error:
            with protect_lock:
                abandoned = True
                if not worker_started:
                    zero_bytearray(owned_secret)
            if not isinstance(error, Exception):
                raise
            protection_failed = True
            protected = b""
        if protection_failed:
            raise KeyStoreError("credential could not be protected") from None
        if len(protected) > self._maximum_ciphertext_bytes:
            raise KeyStoreError("credential ciphertext exceeds its size bound")
        if protected.find(secret) >= 0:
            raise KeyStoreError("credential custody payload is invalid")

        def persist() -> str:
            staged_intent: Path | None = None
            staged_blob: Path | None = None
            staged_metadata: Path | None = None
            try:
                try:
                    staged_intent = self._stage_owned_file(intent_stage_path, intent_bytes)
                except FileExistsError:
                    raise CredentialAlreadyExistsError("credential already exists") from None
                except Exception:
                    raise KeyStoreError("credential custody could not be persisted") from None

                with self._lock:
                    if any(
                        self._path_exists(path) for path in (intent_path, blob_path, metadata_path)
                    ):
                        raise CredentialAlreadyExistsError("credential already exists")
                    try:
                        os.link(staged_intent, intent_path)
                        self._flush_published_file(intent_path)
                        staged_intent.unlink()
                        staged_intent = None
                        staged_blob = self._stage_owned_file(blob_stage_path, protected)
                        os.link(staged_blob, blob_path)
                        self._flush_published_file(blob_path)
                        staged_blob.unlink()
                        staged_blob = None
                        staged_metadata = self._stage_owned_file(
                            metadata_stage_path,
                            metadata_bytes,
                        )
                        os.link(staged_metadata, metadata_path)
                        self._flush_published_file(metadata_path)
                        staged_metadata.unlink()
                        staged_metadata = None
                    except FileExistsError:
                        raise CredentialAlreadyExistsError("credential already exists") from None
                    except OSError:
                        raise KeyStoreError("credential custody could not be persisted") from None
                    self._active_leases.setdefault(metadata.credential_id, weakref.WeakSet())
                return reference
            except BaseException:
                cleanup_complete = True
                marker_matches = self._intent_matches(
                    intent_path,
                    metadata.credential_id,
                    metadata.alias,
                )
                if marker_matches:
                    for published_path in (metadata_path, blob_path):
                        try:
                            published_path.unlink(missing_ok=True)
                        except OSError:
                            cleanup_complete = False
                for staged_path in (staged_metadata, staged_blob, staged_intent):
                    if staged_path is None:
                        continue
                    try:
                        staged_path.unlink(missing_ok=True)
                    except OSError:
                        cleanup_complete = False
                canonical_paths_absent = not any(
                    self._path_exists(path) for path in (blob_path, metadata_path)
                )
                if marker_matches and cleanup_complete and canonical_paths_absent:
                    try:
                        intent_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise
            finally:
                if staged_metadata is not None:
                    with suppress(OSError):
                        staged_metadata.unlink(missing_ok=True)
                if staged_blob is not None:
                    with suppress(OSError):
                        staged_blob.unlink(missing_ok=True)
                if staged_intent is not None:
                    with suppress(OSError):
                        staged_intent.unlink(missing_ok=True)

        def cleanup_cancelled_persist(_reference: str) -> None:
            if not self._discard_staged_sync(
                metadata.credential_id,
                staged_alias=metadata.alias,
            ):
                raise KeyStoreError("cancelled credential custody could not be discarded")

        return await self._run_bounded_offload(
            persist,
            late_result_cleanup=cleanup_cancelled_persist,
        )

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        _validate_expected_generation(expected_generation)

        def update() -> CredentialMetadata:
            with self._lock:
                current = self._load_metadata(metadata.credential_id)
                if current.generation != expected_generation:
                    raise CredentialGenerationMismatchError("credential generation does not match")
                updated = _prepare_metadata_update(current, metadata)
                _, metadata_path = self._paths(metadata.credential_id)
                intent_path = self._intent_path(metadata.credential_id)
                has_staging_intent = self._path_exists(intent_path)
                if has_staging_intent and not self._intent_matches(
                    intent_path,
                    metadata.credential_id,
                    current.alias,
                ):
                    raise KeyStoreError("credential custody ownership marker is invalid")
                try:
                    # A lifecycle caller advances its durable journal before changing
                    # the staging alias.  Retire the ownership proof first so every
                    # crash point is recoverable by exactly one side: PREPARED keeps
                    # the marker, while CUSTODY_CREATED owns the complete pair.
                    if has_staging_intent and updated.alias != current.alias:
                        intent_path.unlink()
                    self._atomic_write(metadata_path, _serialize_metadata(updated))
                except OSError:
                    raise KeyStoreError("credential metadata could not be updated") from None
                if updated.generation != current.generation or updated.state not in {
                    "HEALTHY",
                    "DRAINING",
                }:
                    self._close_leases(metadata.credential_id)
                return updated

        return await self._run_bounded_offload(update)

    async def discard_partial(self, credential_id: str) -> bool:
        blob_path, metadata_path = self._paths(credential_id)

        def discard() -> bool:
            with self._lock:
                blob_exists = self._path_exists(blob_path)
                metadata_exists = self._path_exists(metadata_path)
                if blob_exists == metadata_exists:
                    return False
                self._close_leases(credential_id)
                partial_path = blob_path if blob_exists else metadata_path
                try:
                    partial_path.unlink(missing_ok=True)
                except OSError:
                    raise KeyStoreError(
                        "partial credential custody could not be discarded"
                    ) from None
                self._active_leases.pop(credential_id, None)
                return True

        return await self._run_bounded_offload(discard)

    async def discard_staged(self, credential_id: str, *, staged_alias: str) -> bool:
        if not isinstance(staged_alias, str) or not staged_alias:
            raise ValueError("staged_alias is required")

        return await self._run_bounded_offload(
            lambda: self._discard_staged_sync(
                credential_id,
                staged_alias=staged_alias,
            )
        )

    def _discard_staged_sync(self, credential_id: str, *, staged_alias: str) -> bool:
        blob_path, metadata_path = self._paths(credential_id)
        intent_path = self._intent_path(credential_id)
        owned_temporary_paths = self._staging_paths(credential_id, staged_alias)

        with self._lock:
            temporary_paths = self._temporary_paths(credential_id)
            paths = (intent_path, blob_path, metadata_path, *temporary_paths)
            if not any(self._path_exists(path) for path in paths):
                return True
            marker_matches = self._intent_matches(intent_path, credential_id, staged_alias)
            if not marker_matches and not any(
                self._path_exists(path) for path in owned_temporary_paths
            ):
                return False
            if marker_matches:
                self._close_leases(credential_id)
            try:
                if marker_matches:
                    metadata_path.unlink(missing_ok=True)
                    blob_path.unlink(missing_ok=True)
                for path in owned_temporary_paths:
                    path.unlink(missing_ok=True)
                if marker_matches:
                    intent_path.unlink()
            except OSError:
                raise KeyStoreError("staged credential custody could not be discarded") from None
            if marker_matches:
                self._active_leases.pop(credential_id, None)
            remaining_paths = (
                intent_path,
                blob_path,
                metadata_path,
                *self._temporary_paths(credential_id),
            )
            return not any(self._path_exists(path) for path in remaining_paths)

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
        lease_result_lock = threading.Lock()
        worker_lease: ZeroingSecretLease | None = None

        def open_credential() -> ZeroingSecretLease:
            nonlocal worker_lease
            with self._lock:
                loaded = self._load_metadata(credential_id)
                _assert_lease_eligible(loaded, expected_generation)
                if loaded.expires_at_ms is not None and loaded.expires_at_ms <= int(
                    time.time() * 1_000
                ):
                    raise CredentialUnavailableError("credential is unavailable")
                blob_path, _ = self._paths(credential_id)
                try:
                    ciphertext_value = self._read_bounded(
                        blob_path,
                        maximum_bytes=self._maximum_ciphertext_bytes,
                    )
                except KeyStoreError:
                    raise CredentialUnavailableError("credential could not be opened") from None
            try:
                plaintext = self._api.unprotect(ciphertext_value)
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise CredentialUnavailableError("credential could not be opened") from None
            try:
                with self._lock:
                    current = self._load_metadata(credential_id)
                    if current.generation != loaded.generation:
                        raise CredentialGenerationMismatchError(
                            "credential generation does not match"
                        )
                    _assert_lease_eligible(current, expected_generation)
                    if current.expires_at_ms is not None and current.expires_at_ms <= int(
                        time.time() * 1_000
                    ):
                        raise CredentialUnavailableError("credential is unavailable")
                    lease = ZeroingSecretLease(
                        credential_id=credential_id,
                        generation=current.generation,
                        purpose=purpose,
                        secret_buffer=plaintext,
                        ttl_seconds=requested_ttl,
                    )
                    self._active_leases.setdefault(credential_id, weakref.WeakSet()).add(lease)
            except BaseException:
                zero_bytearray(plaintext)
                raise
            with lease_result_lock:
                worker_lease = lease
            return lease

        try:
            return await self._run_bounded_offload(
                open_credential,
                late_result_cleanup=lambda lease: lease.close(),
            )
        except BaseException:
            with lease_result_lock:
                if worker_lease is not None:
                    worker_lease.close()
            raise

    async def disable(self, credential_id: str) -> None:
        def disable() -> None:
            with self._lock:
                metadata = self._load_metadata(credential_id)
                self._close_leases(credential_id)
                updated = replace(metadata, state="DISABLED")
                _, metadata_path = self._paths(credential_id)
                try:
                    self._atomic_write(metadata_path, _serialize_metadata(updated))
                except OSError:
                    raise KeyStoreError("credential metadata could not be updated") from None

        await self._run_bounded_offload(disable)

    async def delete(self, credential_id: str) -> None:
        def delete() -> None:
            with self._lock:
                metadata = self._load_metadata(credential_id)
                self._close_leases(credential_id)
                blob_path, metadata_path = self._paths(credential_id)
                intent_path = self._intent_path(credential_id)
                temporary_paths = self._temporary_paths(credential_id)
                if self._path_exists(intent_path) and not self._intent_matches(
                    intent_path,
                    credential_id,
                    metadata.alias,
                ):
                    raise KeyStoreError("credential custody ownership marker is invalid")
                try:
                    metadata_path.unlink()
                    blob_path.unlink()
                    for path in temporary_paths:
                        path.unlink(missing_ok=True)
                    intent_path.unlink(missing_ok=True)
                except OSError:
                    raise KeyStoreError("credential custody could not be deleted") from None
                self._active_leases.pop(credential_id, None)

        await self._run_bounded_offload(delete)

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        return await self._run_bounded_offload(self._list_metadata_sync)

    def _list_metadata_sync(self) -> tuple[CredentialMetadata, ...]:
        with self._lock:
            paths: list[Path] = []
            traversed_entries = 0
            try:
                with os.scandir(self._root) as entries:
                    for entry in entries:
                        traversed_entries += 1
                        if traversed_entries > self._maximum_directory_entries:
                            raise KeyStoreError(
                                "credential custody directory entry count exceeds its bound"
                            )
                        if not entry.name.endswith(".json") or not entry.is_file():
                            continue
                        paths.append(Path(entry.path))
                        if len(paths) > self._maximum_metadata_files:
                            raise KeyStoreError("credential metadata file count exceeds its bound")
            except KeyStoreError:
                raise
            except OSError:
                raise KeyStoreError("credential metadata could not be enumerated") from None
            metadata: list[CredentialMetadata] = []
            invalid = 0
            for path in sorted(paths):
                try:
                    encoded = self._read_bounded(
                        path,
                        maximum_bytes=self._maximum_metadata_bytes,
                    )
                    raw = json.loads(encoded.decode("utf-8"))
                    item = CredentialMetadata(**raw)
                    self._load_metadata(item.credential_id)
                except (
                    KeyStoreError,
                    UnicodeDecodeError,
                    ValueError,
                    TypeError,
                    json.JSONDecodeError,
                ):
                    invalid += 1
                    continue
                metadata.append(item)
            if invalid:
                raise KeyStoreError("one or more credential metadata files are invalid")
            return tuple(sorted(metadata, key=lambda item: item.credential_id))

    def _close_leases(self, credential_id: str) -> None:
        for lease in tuple(self._active_leases.get(credential_id, ())):
            lease.close()


def _serialize_metadata(metadata: CredentialMetadata) -> bytes:
    return json.dumps(asdict(metadata), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _serialize_staging_intent(credential_id: str, staged_alias: str) -> bytes:
    if not isinstance(staged_alias, str) or not staged_alias:
        raise ValueError("staged_alias is required")
    return json.dumps(
        {
            "credential_id": credential_id,
            "staged_alias": staged_alias,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


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
