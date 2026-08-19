"""Split storage and constant-time verification for same-user local control."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from gatehouse.credentials.base import KeyStoreError, UnsupportedKeyStorePlatformError
from gatehouse.credentials.dpapi import _WindowsDpapi
from gatehouse.credentials.installation import DataProtector
from gatehouse.credentials.lease import zero_bytearray

_CAPABILITY_BYTES = 32
_ENCODED_CAPABILITY_BYTES = 43
_MAX_PROTECTED_BYTES = 16_384
_DOMAIN = b"gatehouse/local-control/v1\x00"
_VERIFIER_PREFIX = b"GATEHOUSE-CONTROL-VERIFIER-V1\x00"
_CAPABILITY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class ControlCapabilityStorageError(KeyStoreError):
    """The split local-control capability files are unavailable or inconsistent."""


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _digest(encoded: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + encoded).digest()


@dataclass(frozen=True, slots=True)
class ControlCapabilityVerifier:
    """Non-secret verifier retained by the daemon after installation."""

    _expected_digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self._expected_digest) != hashlib.sha256().digest_size:
            raise ValueError("control capability verifier has an invalid length")

    @classmethod
    def _from_raw(cls, raw: bytes) -> ControlCapabilityVerifier:
        if len(raw) != _CAPABILITY_BYTES:
            raise ValueError("control capability must contain exactly 256 bits")
        return cls(_digest(_encode(raw).encode("ascii")))

    @classmethod
    def from_serialized(cls, serialized: bytes) -> ControlCapabilityVerifier:
        if not serialized.startswith(_VERIFIER_PREFIX):
            raise ControlCapabilityStorageError("control capability verifier is invalid")
        digest = serialized.removeprefix(_VERIFIER_PREFIX)
        if len(digest) != hashlib.sha256().digest_size:
            raise ControlCapabilityStorageError("control capability verifier is invalid")
        return cls(bytes(digest))

    def serialize(self) -> bytes:
        return _VERIFIER_PREFIX + self._expected_digest

    def verify(self, supplied: str | None) -> bool:
        """Compare fixed-size digests even for missing or malformed candidates."""

        shape_valid = isinstance(supplied, str)
        candidate = b"\x00" * _ENCODED_CAPABILITY_BYTES
        if isinstance(supplied, str):
            try:
                encoded = supplied.encode("ascii")
            except UnicodeEncodeError:
                shape_valid = False
            else:
                shape_valid = (
                    len(encoded) == _ENCODED_CAPABILITY_BYTES
                    and _CAPABILITY_PATTERN.fullmatch(supplied) is not None
                )
                if shape_valid:
                    candidate = encoded
        matched = hmac.compare_digest(_digest(candidate), self._expected_digest)
        return bool(matched & shape_valid)


def _data_protector(protector: DataProtector | None) -> DataProtector:
    if protector is not None:
        return protector
    if os.name != "nt":
        raise UnsupportedKeyStorePlatformError(
            "the production control capability requires Windows DPAPI"
        )
    return _WindowsDpapi()


def _read_bounded(path: Path, *, label: str) -> bytes:
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ControlCapabilityStorageError(f"{label} file is unavailable") from error
    if not value or len(value) > _MAX_PROTECTED_BYTES:
        raise ControlCapabilityStorageError(f"{label} file is invalid")
    return value


def _write_exclusive(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def _unprotect_raw(path: Path, protector: DataProtector) -> bytearray:
    ciphertext = _read_bounded(path, label="protected control capability")
    try:
        raw = protector.unprotect(ciphertext)
    except OSError as error:
        raise ControlCapabilityStorageError(
            "protected control capability could not be unprotected"
        ) from error
    if len(raw) != _CAPABILITY_BYTES:
        zero_bytearray(raw)
        raise ControlCapabilityStorageError("protected control capability has an invalid length")
    return raw


def load_control_capability_verifier(
    path: str | Path,
) -> ControlCapabilityVerifier:
    """Load only the non-secret verifier used by the daemon."""

    serialized = _read_bounded(Path(path), label="control capability verifier")
    return ControlCapabilityVerifier.from_serialized(serialized)


def load_control_capability(
    path: str | Path,
    *,
    protector: DataProtector | None = None,
) -> str:
    """Load the raw capability for a same-user CLI and immediately zero its buffer."""

    resolved_protector = _data_protector(protector)
    raw = _unprotect_raw(Path(path), resolved_protector)
    try:
        return _encode(bytes(raw))
    finally:
        zero_bytearray(raw)


def provision_control_capability(
    *,
    protected_path: str | Path,
    verifier_path: str | Path,
    protector: DataProtector | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> ControlCapabilityVerifier:
    """Create or validate a DPAPI raw capability plus a separate verifier file.

    This installation-side operation never returns the raw capability. The daemon
    subsequently opens only ``verifier_path``; a CLI opens only ``protected_path``.
    """

    protected = Path(protected_path)
    verifier = Path(verifier_path)
    if protected.resolve() == verifier.resolve():
        raise ValueError("control capability and verifier require separate files")
    resolved_protector = _data_protector(protector)

    if verifier.exists() and not protected.exists():
        raise ControlCapabilityStorageError(
            "control capability is missing while its verifier exists"
        )
    if protected.exists():
        raw = _unprotect_raw(protected, resolved_protector)
        try:
            derived = ControlCapabilityVerifier._from_raw(bytes(raw))
        finally:
            zero_bytearray(raw)
        if verifier.exists():
            loaded = load_control_capability_verifier(verifier)
            if not hmac.compare_digest(loaded.serialize(), derived.serialize()):
                raise ControlCapabilityStorageError(
                    "control capability does not match its verifier"
                )
            return loaded
        try:
            _write_exclusive(verifier, derived.serialize())
        except FileExistsError as error:
            loaded = load_control_capability_verifier(verifier)
            if not hmac.compare_digest(loaded.serialize(), derived.serialize()):
                raise ControlCapabilityStorageError(
                    "control capability does not match its verifier"
                ) from error
            return loaded
        return derived

    raw = bytearray(random_bytes(_CAPABILITY_BYTES))
    if len(raw) != _CAPABILITY_BYTES:
        zero_bytearray(raw)
        raise ValueError("control capability entropy source returned the wrong length")
    try:
        derived = ControlCapabilityVerifier._from_raw(bytes(raw))
        ciphertext = resolved_protector.protect(bytes(raw))
        if (
            not ciphertext
            or len(ciphertext) > _MAX_PROTECTED_BYTES
            or hmac.compare_digest(ciphertext, bytes(raw))
        ):
            raise ControlCapabilityStorageError("control capability protection failed")
    except BaseException:
        zero_bytearray(raw)
        raise
    zero_bytearray(raw)

    try:
        _write_exclusive(protected, ciphertext)
    except FileExistsError:
        return provision_control_capability(
            protected_path=protected,
            verifier_path=verifier,
            protector=resolved_protector,
            random_bytes=random_bytes,
        )
    try:
        _write_exclusive(verifier, derived.serialize())
    except FileExistsError as error:
        loaded = load_control_capability_verifier(verifier)
        if not hmac.compare_digest(loaded.serialize(), derived.serialize()):
            raise ControlCapabilityStorageError(
                "control capability does not match its verifier"
            ) from error
        return loaded
    return derived
