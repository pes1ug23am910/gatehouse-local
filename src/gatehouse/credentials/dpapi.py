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
from ctypes import wintypes
from dataclasses import asdict, replace
from pathlib import Path

from .base import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyStoreError,
    UnsupportedKeyStorePlatformError,
)
from .lease import ZeroingSecretLease, zero_bytearray

CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


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
    def _input_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
        buffer_type = ctypes.c_ubyte * len(data)
        buffer = buffer_type.from_buffer_copy(data)
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        return _DataBlob(len(data), pointer), buffer

    @staticmethod
    def _zero_ctypes_buffer(buffer: ctypes.Array[ctypes.c_ubyte]) -> None:
        if ctypes.sizeof(buffer):
            ctypes.memset(ctypes.addressof(buffer), 0, ctypes.sizeof(buffer))

    def protect(self, plaintext: bytes) -> bytes:
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
        _api: _WindowsDpapi | None = None,
    ) -> None:
        if os.name != "nt":
            raise UnsupportedKeyStorePlatformError(
                "DpapiCurrentUserKeyStore is available only on Windows"
            )
        if default_lease_ttl_seconds <= 0:
            raise ValueError("default lease TTL must be positive")
        if maximum_lease_ttl_seconds < default_lease_ttl_seconds:
            raise ValueError("maximum lease TTL must cover the default")

        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._default_ttl = default_lease_ttl_seconds
        self._maximum_ttl = maximum_lease_ttl_seconds
        self._api = _api or _WindowsDpapi()
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

    def _load_metadata(self, credential_id: str) -> CredentialMetadata:
        blob_path, metadata_path = self._paths(credential_id)
        if not blob_path.is_file() or not metadata_path.is_file():
            raise CredentialNotFoundError(credential_id)
        try:
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata = CredentialMetadata(**raw)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise KeyStoreError(f"credential metadata for {credential_id!r} is invalid") from error
        if metadata.credential_id != credential_id:
            raise KeyStoreError("credential metadata identifier mismatch")
        expected_reference = f"dpapi-current-user://{self._stem(credential_id)}"
        if metadata.secret_reference != expected_reference:
            raise KeyStoreError("credential metadata reference mismatch")
        return metadata

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        if not secret:
            raise ValueError("credential secret must not be empty")
        reference = f"dpapi-current-user://{self._stem(metadata.credential_id)}"
        stored = replace(metadata, secret_reference=reference)
        blob_path, metadata_path = self._paths(metadata.credential_id)
        protected = await asyncio.to_thread(self._api.protect, secret)
        metadata_bytes = json.dumps(asdict(stored), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        with self._lock:
            self._close_leases(metadata.credential_id)
            self._atomic_write(blob_path, protected)
            self._atomic_write(metadata_path, metadata_bytes)
            self._active_leases.setdefault(metadata.credential_id, weakref.WeakSet())
        return reference

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
            metadata = self._load_metadata(credential_id)
            if metadata.state != "HEALTHY":
                raise CredentialUnavailableError(
                    f"credential {credential_id!r} is {metadata.state}"
                )
            if metadata.expires_at_ms is not None and metadata.expires_at_ms <= int(
                time.time() * 1_000
            ):
                raise CredentialUnavailableError(f"credential {credential_id!r} is expired")
            blob_path, _ = self._paths(credential_id)
            ciphertext = blob_path.read_bytes()

        plaintext = await asyncio.to_thread(self._api.unprotect, ciphertext)
        try:
            lease = ZeroingSecretLease(
                credential_id=credential_id,
                generation=metadata.generation,
                purpose=purpose,
                secret_buffer=plaintext,
                ttl_seconds=requested_ttl,
            )
        except BaseException:
            zero_bytearray(plaintext)
            raise
        with self._lock:
            self._active_leases.setdefault(credential_id, weakref.WeakSet()).add(lease)
        return lease

    async def disable(self, credential_id: str) -> None:
        with self._lock:
            metadata = self._load_metadata(credential_id)
            self._close_leases(credential_id)
            updated = replace(metadata, state="DISABLED")
            _, metadata_path = self._paths(credential_id)
            self._atomic_write(
                metadata_path,
                json.dumps(asdict(updated), sort_keys=True, separators=(",", ":")).encode("utf-8"),
            )

    async def delete(self, credential_id: str) -> None:
        with self._lock:
            self._load_metadata(credential_id)
            self._close_leases(credential_id)
            blob_path, metadata_path = self._paths(credential_id)
            metadata_path.unlink()
            blob_path.unlink()
            self._active_leases.pop(credential_id, None)

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        with self._lock:
            metadata: list[CredentialMetadata] = []
            for path in sorted(self._root.glob("*.json")):
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    item = CredentialMetadata(**raw)
                    self._load_metadata(item.credential_id)
                except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                    raise KeyStoreError(f"invalid KeyStore metadata file: {path.name}") from error
                metadata.append(item)
            return tuple(sorted(metadata, key=lambda item: item.credential_id))

    def _close_leases(self, credential_id: str) -> None:
        for lease in tuple(self._active_leases.get(credential_id, ())):
            lease.close()
