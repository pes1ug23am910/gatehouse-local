from __future__ import annotations

from gatehouse.fingerprint import FingerprintContext, FingerprintService


def context(*, workspace_scope: str = "workspace-one") -> FingerprintContext:
    return FingerprintContext(
        service="firecrawl",
        operation="scrape",
        normalized_input={"url": "https://example.com"},
        workspace_scope=workspace_scope,
        data_scope="public_web",
        authorization_scope="public",
        result_format="markdown",
    )


def test_hmac_fingerprint_is_stable_scoped_and_versioned() -> None:
    first = FingerprintService(b"k" * 32)
    same = FingerprintService(b"k" * 32)
    rotated = FingerprintService(b"r" * 32, fingerprint_version=2)
    fingerprint = first.calculate(context())

    assert fingerprint == same.calculate(context())
    assert fingerprint != first.calculate(context(workspace_scope="workspace-two"))
    assert fingerprint != rotated.calculate(context())
    assert str(fingerprint).startswith("hmac:v1:c1:")
    assert b"https://example.com" not in fingerprint.digest
