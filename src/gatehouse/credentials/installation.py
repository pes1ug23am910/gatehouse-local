"""DPAPI-protected installation key material for local HMAC derivation."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .base import KeyStoreError, UnsupportedKeyStorePlatformError
from .dpapi import _WindowsDpapi
from .lease import zero_bytearray


class DataProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytearray: ...


def load_or_create_installation_key(
    path: str | Path,
    *,
    protector: DataProtector | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> bytes:
    """Load one 256-bit master key; the file contains protected bytes only."""

    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    if protector is None:
        if os.name != "nt":
            raise UnsupportedKeyStorePlatformError(
                "the production installation key requires Windows DPAPI"
            )
        protector = _WindowsDpapi()
    if resolved.exists():
        try:
            ciphertext = resolved.read_bytes()
        except OSError as exc:
            raise KeyStoreError("installation key file is unavailable") from exc
        if not ciphertext or len(ciphertext) > 16_384:
            raise KeyStoreError("installation key file is invalid")
        try:
            plaintext = protector.unprotect(ciphertext)
        except OSError as exc:
            raise KeyStoreError("installation key could not be unprotected") from exc
        try:
            if len(plaintext) != 32:
                raise KeyStoreError("installation key has an invalid length")
            return bytes(plaintext)
        finally:
            zero_bytearray(plaintext)

    plaintext = bytearray(random_bytes(32))
    if len(plaintext) != 32:
        zero_bytearray(plaintext)
        raise ValueError("installation entropy source returned the wrong length")
    try:
        ciphertext = protector.protect(bytes(plaintext))
        if not ciphertext or len(ciphertext) > 16_384:
            raise KeyStoreError("installation key protection failed")
        try:
            with resolved.open("xb") as handle:
                handle.write(ciphertext)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            return load_or_create_installation_key(
                resolved,
                protector=protector,
                random_bytes=random_bytes,
            )
        except OSError as exc:
            resolved.unlink(missing_ok=True)
            raise KeyStoreError("installation key could not be persisted") from exc
        return bytes(plaintext)
    finally:
        zero_bytearray(plaintext)


def derive_installation_key(master_key: bytes, purpose: str) -> bytes:
    if len(master_key) != 32:
        raise ValueError("installation master key must contain exactly 256 bits")
    if not purpose or len(purpose) > 100 or not purpose.isascii():
        raise ValueError("installation key purpose is invalid")
    return hmac.new(
        master_key,
        b"gatehouse/installation-key/v1\x00" + purpose.encode("ascii"),
        hashlib.sha256,
    ).digest()
