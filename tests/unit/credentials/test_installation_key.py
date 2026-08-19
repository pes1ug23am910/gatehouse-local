from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.credentials import derive_installation_key, load_or_create_installation_key
from gatehouse.credentials.base import KeyStoreError


class _Protector:
    def protect(self, plaintext: bytes) -> bytes:
        return b"protected:" + bytes(value ^ 0xA5 for value in plaintext)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        if not ciphertext.startswith(b"protected:"):
            raise OSError("invalid")
        return bytearray(value ^ 0xA5 for value in ciphertext.removeprefix(b"protected:"))


def test_installation_key_persists_only_protected_bytes(tmp_path: Path) -> None:
    path = tmp_path / "installation-key.dpapi"
    key = load_or_create_installation_key(
        path,
        protector=_Protector(),
        random_bytes=lambda length: b"k" * length,
    )
    assert key == b"k" * 32
    assert key not in path.read_bytes()
    assert load_or_create_installation_key(path, protector=_Protector()) == key

    session_key = derive_installation_key(key, "session-verifier")
    fingerprint_key = derive_installation_key(key, "request-fingerprint")
    assert len(session_key) == 32
    assert session_key != fingerprint_key


def test_invalid_protected_installation_key_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "installation-key.dpapi"
    path.write_bytes(b"broken")
    with pytest.raises(KeyStoreError, match="unprotected"):
        load_or_create_installation_key(path, protector=_Protector())


def test_entropy_source_must_return_exactly_256_bits(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="wrong length"):
        load_or_create_installation_key(
            tmp_path / "installation-key.dpapi",
            protector=_Protector(),
            random_bytes=lambda _length: b"short",
        )
