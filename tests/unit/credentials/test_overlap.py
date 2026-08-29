from __future__ import annotations

import pytest

from gatehouse.credentials import (
    ActiveSecretInspectionUnavailable,
    ActiveSecretOverlapInspector,
    CredentialMetadata,
    SecretDetectedError,
)
from gatehouse.credentials.memory import InMemoryKeyStore


def _metadata() -> CredentialMetadata:
    return CredentialMetadata(
        credential_id="credential-one",
        principal_id="principal-one",
        quota_scope_id="scope-one",
        alias="primary",
    )


@pytest.mark.asyncio
async def test_unpaired_unicode_fails_closed_with_a_sanitized_typed_error() -> None:
    inspector = ActiveSecretOverlapInspector((InMemoryKeyStore(),))

    with pytest.raises(ActiveSecretInspectionUnavailable) as captured:
        await inspector.reject_overlap({"summary": "prefix\ud800suffix"})

    assert str(captured.value) == "active-secret inspection is unavailable"
    assert "prefix" not in str(captured.value)


@pytest.mark.asyncio
async def test_exact_active_secret_overlap_is_rejected() -> None:
    store = InMemoryKeyStore()
    await store.put(_metadata(), b"active-secret-canary")
    inspector = ActiveSecretOverlapInspector((store,))

    with pytest.raises(SecretDetectedError):
        await inspector.reject_overlap({"summary": "prefix-active-secret-canary-suffix"})


@pytest.mark.asyncio
async def test_cpu_bound_no_match_obeys_the_inspection_timeout() -> None:
    store = InMemoryKeyStore()
    await store.put(_metadata(), b"b" * 32)
    inspector = ActiveSecretOverlapInspector((store,), timeout_seconds=0.001)

    with pytest.raises(ActiveSecretInspectionUnavailable) as captured:
        await inspector.reject_overlap("a" * (128 * 1_024))

    assert str(captured.value) == "active-secret inspection is unavailable"
