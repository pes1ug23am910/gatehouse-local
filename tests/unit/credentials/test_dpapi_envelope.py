"""Pure protected-envelope and Windows create-only publication boundaries."""

from __future__ import annotations

import asyncio
import ctypes
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypedDict, cast

import pytest

from gatehouse.credentials import dpapi
from gatehouse.credentials.base import CredentialMetadata, CredentialUnavailableError, KeyStoreError
from gatehouse.credentials.lease import zero_bytearray

SECRET = b"FAKE-ENVELOPE-SECRET-FOR-LOCAL-TESTS-123456789"


class _MetadataChanges(TypedDict, total=False):
    credential_id: str
    principal_id: str
    quota_scope_id: str
    secret_reference: str
    alias: str
    state: str
    generation: int
    expires_at_ms: int | None


def _metadata() -> CredentialMetadata:
    item = CredentialMetadata("credential-a", "principal-a", "scope-a", "staged-alias")
    return replace(
        item,
        secret_reference=(
            "dpapi-current-user://" + dpapi.DpapiCurrentUserKeyStore._stem(item.credential_id)
        ),
    )


def test_envelope_round_trip_owns_only_mutable_secret_copies_and_scrubs_opened_envelope() -> None:
    secret = bytearray(SECRET)
    envelope = dpapi._encode_credential_envelope(_metadata(), secret)
    assert type(envelope) is bytearray and envelope is not secret
    assert envelope.startswith(dpapi._ENVELOPE_MAGIC) and envelope.endswith(secret)
    extracted = dpapi._decode_credential_envelope(envelope, _metadata())
    assert type(extracted) is bytearray and bytes(extracted) == SECRET
    assert secret == SECRET and not any(envelope)
    zero_bytearray(extracted)
    assert not any(extracted)


@pytest.mark.parametrize(
    "field,value",
    [
        ("credential_id", "credential-b"),
        ("principal_id", "principal-b"),
        ("quota_scope_id", "scope-b"),
        ("secret_reference", "dpapi-current-user://another"),
    ],
)
def test_envelope_identity_mismatch_refuses_and_scrubs_without_error_details(
    field: str,
    value: str,
) -> None:
    envelope = dpapi._encode_credential_envelope(_metadata(), SECRET)
    with pytest.raises(CredentialUnavailableError) as caught:
        dpapi._decode_credential_envelope(
            envelope, replace(_metadata(), **cast(_MetadataChanges, {field: value}))
        )
    assert not any(envelope)
    assert caught.value.args == ("credential could not be opened",)
    assert caught.value.__cause__ is caught.value.__context__ is None
    assert caught.value.__dict__ == {}


@pytest.mark.parametrize(
    "mutation",
    [
        {"alias": "committed-alias"},
        {"state": "DRAINING"},
        {"generation": 2},
        {"expires_at_ms": 1234},
    ],
)
def test_mutable_lifecycle_metadata_does_not_rebind_protected_identity(
    mutation: _MetadataChanges,
) -> None:
    envelope = dpapi._encode_credential_envelope(_metadata(), SECRET)
    secret = dpapi._decode_credential_envelope(envelope, replace(_metadata(), **mutation))
    assert secret == SECRET and not any(envelope)
    zero_bytearray(secret)


@pytest.mark.parametrize(
    "defect",
    [
        "raw_legacy",
        "empty",
        "version",
        "short_header",
        "zero_identity",
        "large_identity",
        "zero_secret",
        "large_secret",
        "truncated_identity",
        "truncated_secret",
        "trailing",
        "changed_identity",
        "oversized_plaintext",
    ],
)
def test_malformed_or_legacy_envelopes_refuse_with_bounded_parsing_and_zeroing(defect: str) -> None:
    envelope = dpapi._encode_credential_envelope(_metadata(), SECRET)
    offset = len(dpapi._ENVELOPE_MAGIC)
    if defect == "raw_legacy":
        envelope = bytearray(SECRET)
    elif defect == "empty":
        envelope = bytearray()
    elif defect == "version":
        envelope[offset - 1] ^= 1
    elif defect == "short_header":
        del envelope[offset + 1 :]
    elif defect in {"zero_identity", "large_identity"}:
        value = 0 if defect == "zero_identity" else dpapi._MAXIMUM_IDENTITY_BYTES + 1
        envelope[offset : offset + 4] = value.to_bytes(4, "big")
    elif defect in {"zero_secret", "large_secret"}:
        value = 0 if defect == "zero_secret" else dpapi._MAXIMUM_SECRET_BYTES + 1
        envelope[offset + 4 : offset + 8] = value.to_bytes(4, "big")
    elif defect == "truncated_identity":
        del envelope[offset + 10 :]
    elif defect == "truncated_secret":
        del envelope[-1:]
    elif defect == "trailing":
        envelope.extend(b"extra")
    elif defect == "changed_identity":
        envelope[offset + 8] ^= 1
    else:
        envelope.extend(b"x" * dpapi._MAXIMUM_ENVELOPE_BYTES)
    with pytest.raises(CredentialUnavailableError, match="^credential could not be opened$"):
        dpapi._decode_credential_envelope(envelope, _metadata())
    assert not any(envelope)


def test_secret_exact_size_bound_and_one_over() -> None:
    secret = bytearray(b"z" * dpapi._MAXIMUM_SECRET_BYTES)
    envelope = dpapi._encode_credential_envelope(_metadata(), secret)
    extracted = dpapi._decode_credential_envelope(envelope, _metadata())
    assert extracted == secret
    zero_bytearray(extracted)
    secret.append(122)
    with pytest.raises(KeyStoreError, match="credential custody payload is invalid"):
        dpapi._encode_credential_envelope(_metadata(), secret)
    zero_bytearray(secret)


@pytest.mark.parametrize("value", ["x" * 4096, "é" * 2048])
def test_identity_field_exact_utf8_bound_is_accepted(value: str) -> None:
    metadata = replace(_metadata(), principal_id=value)
    envelope = dpapi._encode_credential_envelope(metadata, SECRET)
    extracted = dpapi._decode_credential_envelope(envelope, metadata)
    assert extracted == SECRET and not any(envelope)
    zero_bytearray(extracted)


@pytest.mark.parametrize(
    "value",
    [
        object(),
        b"principal",
        "x" * 4097,
        "é" * 2049,
        "bad\x00name",
        "bad\ud800",
    ],
)
def test_invalid_identity_values_are_refused_before_envelope_allocation(value: object) -> None:
    metadata = replace(_metadata(), principal_id=cast(str, value))
    with pytest.raises(KeyStoreError, match="credential custody metadata is invalid"):
        dpapi._encode_credential_envelope(metadata, SECRET)


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_identity_check_interruption_still_scrubs_plaintext(
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
) -> None:
    envelope = dpapi._encode_credential_envelope(_metadata(), SECRET)
    signal = interruption("synthetic identity interruption")

    def interrupted(_metadata: CredentialMetadata) -> bytes:
        raise signal

    monkeypatch.setattr(dpapi, "_credential_identity", interrupted)
    with pytest.raises(interruption) as caught:
        dpapi._decode_credential_envelope(envelope, _metadata())
    assert caught.value is signal and not any(envelope)


@pytest.mark.parametrize("interruption", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_envelope_cleanup_failure_scrubs_the_extracted_secret_before_refusal(
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
) -> None:
    envelope = dpapi._encode_credential_envelope(_metadata(), SECRET)
    original_zero = zero_bytearray
    cleaned: list[bytearray] = []
    signal = interruption("synthetic envelope cleanup failure")

    def fail_envelope_cleanup(value: bytearray) -> None:
        cleaned.append(value)
        original_zero(value)
        if value is envelope:
            raise signal

    monkeypatch.setattr(dpapi, "zero_bytearray", fail_envelope_cleanup)
    expected = CredentialUnavailableError if interruption is RuntimeError else interruption
    with pytest.raises(expected) as caught:
        dpapi._decode_credential_envelope(envelope, _metadata())
    assert len(cleaned) == 2 and cleaned[0] is envelope and not any(cleaned[1])
    assert len(cleaned[1]) == len(SECRET)
    if interruption is RuntimeError:
        assert caught.value.args == ("credential could not be opened",)
        assert caught.value.__context__ is None
    else:
        assert caught.value is signal


def test_windows_publication_is_one_same_parent_rename_without_link_or_replace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target = Path("stage"), Path("final")
    calls: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        dpapi,
        "os",
        SimpleNamespace(
            name="nt",
            rename=lambda a, b: calls.append((a, b)),
        ),
    )
    dpapi._publish_create_only(source, target)
    assert calls == [(source, target)]


@pytest.mark.parametrize("defect", ["platform", "parent", "same_path"])
def test_unsupported_publication_refuses_before_native_effect(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    calls: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        dpapi,
        "os",
        SimpleNamespace(
            name="posix" if defect == "platform" else "nt",
            rename=lambda a, b: calls.append((a, b)),
        ),
    )
    source = Path("stage")
    target = Path("final")
    if defect == "parent":
        target = Path("elsewhere/final")
    elif defect == "same_path":
        target = source
    with pytest.raises(KeyStoreError, match="credential publication is unavailable"):
        dpapi._publish_create_only(source, target)
    assert calls == []


def test_windows_publication_preserves_native_destination_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signal = FileExistsError("synthetic existing destination")

    def collision(_source: Path, _target: Path) -> None:
        raise signal

    monkeypatch.setattr(dpapi, "os", SimpleNamespace(name="nt", rename=collision))
    with pytest.raises(FileExistsError) as caught:
        dpapi._publish_create_only(Path("stage"), Path("final"))
    assert caught.value is signal


def test_versioned_intent_round_trip_contains_only_exact_owned_file_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = dpapi._serialize_staging_intent(
        "credential-a",
        "stage-a",
        blob_identity=(12, 34),
        metadata_identity=(12, 56),
    )
    bounds: list[int] = []

    def read(_path: Path, *, maximum_bytes: int) -> bytes:
        bounds.append(maximum_bytes)
        return encoded

    monkeypatch.setattr(dpapi.DpapiCurrentUserKeyStore, "_read_bounded", staticmethod(read))
    intent = dpapi.DpapiCurrentUserKeyStore._read_intent(Path("unused"), "credential-a")
    assert intent is not None
    assert (intent.staged_alias, intent.blob_identity, intent.metadata_identity) == (
        "stage-a",
        (12, 34),
        (12, 56),
    )
    assert bounds == [4096]


@pytest.mark.parametrize(
    "defect",
    [
        "legacy",
        "version",
        "bool_version",
        "duplicate",
        "extra",
        "missing",
        "credential",
        "alias",
        "blob_type",
        "metadata_type",
        "bool_identity",
        "negative",
        "overflow",
        "malformed",
    ],
)
def test_unknown_or_malformed_intent_cannot_authorize_recovery(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    body = json.loads(
        dpapi._serialize_staging_intent(
            "credential-a",
            "stage-a",
            blob_identity=(12, 34),
            metadata_identity=(12, 56),
        )
    )
    if defect == "legacy":
        body = {"credential_id": "credential-a", "staged_alias": "stage-a"}
    elif defect == "version":
        body["schema_version"] = 2
    elif defect == "bool_version":
        body["schema_version"] = True
    elif defect == "extra":
        body["extra"] = 1
    elif defect == "missing":
        del body["metadata_identity"]
    elif defect == "credential":
        body["credential_id"] = "credential-b"
    elif defect == "alias":
        body["staged_alias"] = 2
    elif defect == "blob_type":
        body["blob_identity"] = "12,34"
    elif defect == "metadata_type":
        body["metadata_identity"] = [12]
    elif defect == "bool_identity":
        body["blob_identity"] = [True, 34]
    elif defect == "negative":
        body["blob_identity"] = [-1, 34]
    elif defect == "overflow":
        body["metadata_identity"] = [12, 2**128]
    encoded = json.dumps(body).encode("utf-8")
    if defect == "duplicate":
        encoded = b'{"schema_version":1,' + encoded[1:]
    elif defect == "malformed":
        encoded = b"{"
    monkeypatch.setattr(
        dpapi.DpapiCurrentUserKeyStore,
        "_read_bounded",
        staticmethod(lambda _path, **_kwargs: encoded),
    )
    assert dpapi.DpapiCurrentUserKeyStore._read_intent(Path("unused"), "credential-a") is None


def _fake_native_unprotect(
    payload: bytes,
) -> tuple[dpapi._WindowsDpapi, ctypes.Array[ctypes.c_ubyte], list[object]]:
    native_output = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    freed: list[object] = []

    def unprotect(*arguments: Any) -> int:
        output = arguments[-1]._obj
        output.cbData = len(payload)
        output.pbData = ctypes.cast(native_output, ctypes.POINTER(ctypes.c_ubyte))
        return 1

    api = object.__new__(dpapi._WindowsDpapi)
    cast(Any, api)._crypt32 = SimpleNamespace(CryptUnprotectData=unprotect)
    cast(Any, api)._kernel32 = SimpleNamespace(LocalFree=freed.append)
    return api, native_output, freed


def test_native_unprotect_transfers_owned_bytes_and_scrubs_native_allocation() -> None:
    api, native_output, freed = _fake_native_unprotect(SECRET)
    plaintext = api.unprotect(b"synthetic ciphertext")
    assert plaintext == SECRET and type(plaintext) is bytearray
    assert not any(native_output) and len(freed) == 1
    zero_bytearray(plaintext)


@pytest.mark.parametrize("signal", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_copy_interruption_scrubs_partial_managed_and_native_plaintext(
    monkeypatch: pytest.MonkeyPatch,
    signal: type[BaseException],
) -> None:
    api, native_output, freed = _fake_native_unprotect(SECRET)
    original_move = ctypes.memmove
    captured: list[ctypes.Array[ctypes.c_ubyte]] = []
    interruption = signal("synthetic interruption")

    def copy_then_interrupt(
        destination: ctypes.Array[ctypes.c_ubyte],
        source: ctypes._Pointer[ctypes.c_ubyte],
        count: int,
    ) -> None:
        original_move(destination, source, count)
        captured.append(destination)
        raise interruption

    monkeypatch.setattr(ctypes, "memmove", copy_then_interrupt)
    with pytest.raises(signal) as caught:
        api.unprotect(b"synthetic ciphertext")
    assert caught.value is interruption
    assert len(captured) == 1 and not any(captured[0])
    assert not any(native_output) and len(freed) == 1


@pytest.mark.parametrize("signal", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_cleanup_interruption_scrubs_managed_plaintext_before_propagation(
    monkeypatch: pytest.MonkeyPatch,
    signal: type[BaseException],
) -> None:
    api, native_output, freed = _fake_native_unprotect(SECRET)
    original_move = ctypes.memmove
    captured: list[ctypes.Array[ctypes.c_ubyte]] = []
    interruption = signal("synthetic cleanup interruption")

    def capture(
        destination: ctypes.Array[ctypes.c_ubyte],
        source: ctypes._Pointer[ctypes.c_ubyte],
        count: int,
    ) -> None:
        original_move(destination, source, count)
        captured.append(destination)

    def fail_cleanup(pointer: object) -> None:
        freed.append(pointer)
        raise interruption

    monkeypatch.setattr(ctypes, "memmove", capture)
    cast(Any, api._kernel32).LocalFree = fail_cleanup
    with pytest.raises(signal) as caught:
        api.unprotect(b"synthetic ciphertext")
    assert caught.value is interruption
    assert len(captured) == 1 and not any(captured[0])
    assert not any(native_output) and len(freed) == 1


@pytest.mark.parametrize("length", [0, dpapi._MAXIMUM_ENVELOPE_BYTES + 1])
def test_native_unprotect_refuses_invalid_output_bound_and_clears_owned_native_bytes(
    length: int,
) -> None:
    api, native_output, freed = _fake_native_unprotect(b"x" * length)
    with pytest.raises(KeyStoreError, match="^credential could not be opened$"):
        api.unprotect(b"synthetic ciphertext")
    assert not any(native_output) and len(freed) == 1


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("cleanup", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_envelope_retains_primary_control_when_plaintext_cleanup_also_fails(
    monkeypatch: pytest.MonkeyPatch,
    primary: type[BaseException],
    cleanup: type[BaseException],
) -> None:
    envelope = dpapi._encode_credential_envelope(_metadata(), SECRET)
    signal = primary("synthetic primary control")
    original_zero = zero_bytearray

    def reject_identity(_metadata: CredentialMetadata) -> bytes:
        raise signal

    def cleanup_then_fail(value: bytearray) -> None:
        original_zero(value)
        raise cleanup("synthetic cleanup control")

    monkeypatch.setattr(dpapi, "_credential_identity", reject_identity)
    monkeypatch.setattr(dpapi, "zero_bytearray", cleanup_then_fail)
    with pytest.raises(primary) as caught:
        dpapi._decode_credential_envelope(envelope, _metadata())
    assert caught.value is signal and not any(envelope)


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("cleanup", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_copy_retains_primary_control_and_scrubs_after_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
    primary: type[BaseException],
    cleanup: type[BaseException],
) -> None:
    api, native_output, freed = _fake_native_unprotect(SECRET)
    signal = primary("synthetic primary control")
    copied: list[ctypes.Array[ctypes.c_ubyte]] = []
    original_move = ctypes.memmove

    def copy_then_fail(
        destination: ctypes.Array[ctypes.c_ubyte],
        source: ctypes._Pointer[ctypes.c_ubyte],
        count: int,
    ) -> None:
        original_move(destination, source, count)
        copied.append(destination)
        raise signal

    def free_then_fail(pointer: object) -> None:
        freed.append(pointer)
        raise cleanup("synthetic cleanup control")

    monkeypatch.setattr(ctypes, "memmove", copy_then_fail)
    cast(Any, api._kernel32).LocalFree = free_then_fail
    with pytest.raises(primary) as caught:
        api.unprotect(b"synthetic ciphertext")
    assert caught.value is signal
    assert not any(native_output) and len(freed) == 1
    assert len(copied) == 1 and not any(copied[0])


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("cleanup", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_protect_retains_primary_control_when_input_cleanup_fails(
    primary: type[BaseException],
    cleanup: type[BaseException],
) -> None:
    signal = primary("synthetic primary control")
    captured: list[ctypes.Array[ctypes.c_ubyte]] = []

    def protect_then_fail(*_arguments: object) -> int:
        raise signal

    def zero_then_fail(buffer: ctypes.Array[ctypes.c_ubyte]) -> None:
        captured.append(buffer)
        dpapi._WindowsDpapi._zero_ctypes_buffer(buffer)
        raise cleanup("synthetic cleanup control")

    api = object.__new__(dpapi._WindowsDpapi)
    cast(Any, api)._crypt32 = SimpleNamespace(CryptProtectData=protect_then_fail)
    cast(Any, api)._kernel32 = SimpleNamespace(LocalFree=lambda _: None)
    cast(Any, api)._zero_ctypes_buffer = zero_then_fail
    with pytest.raises(primary) as caught:
        api.protect(SECRET)
    assert caught.value is signal and len(captured) == 1 and not any(captured[0])
