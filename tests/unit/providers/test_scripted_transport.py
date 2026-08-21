from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from gatehouse.providers import ProviderRequest
from gatehouse.providers.scripted import (
    ScriptedManifestError,
    ScriptedProviderTransport,
    ScriptedResponseExhausted,
)


def _request(operation: str = "firecrawl.search") -> ProviderRequest:
    return ProviderRequest(
        method="POST",
        path="/v2/search",
        credential_id="scripted-credential",
        credential_generation=1,
        operation=operation,
    )


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.mark.asyncio
async def test_manifest_transport_is_finite_ordered_and_no_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network_calls: list[str] = []

    def deny_socket(*_args: object, **_kwargs: object) -> None:
        network_calls.append("socket")
        raise AssertionError("scripted transport attempted socket activity")

    def deny_dns(*_args: object, **_kwargs: object) -> None:
        network_calls.append("dns")
        raise AssertionError("scripted transport attempted DNS activity")

    monkeypatch.setattr(socket, "socket", deny_socket)
    monkeypatch.setattr(socket, "create_connection", deny_socket)
    monkeypatch.setattr(socket, "getaddrinfo", deny_dns)
    path = tmp_path / "responses.json"
    _write(
        path,
        {
            "schema_version": 1,
            "responses": {
                "firecrawl.search": [
                    {
                        "status_code": 200,
                        "data": {"success": True, "creditsUsed": 1},
                        "provider_request_id": "script-one",
                    },
                    {"status_code": 429, "headers": {"retry-after": "2"}},
                ]
            },
        },
    )
    transport = ScriptedProviderTransport.from_path(path)

    first = await transport.send(_request())
    second = await transport.send(_request())

    assert first.status_code == 200
    assert first.provider_request_id == "script-one"
    assert second.status_code == 429
    assert second.retry_after_seconds == 2
    assert transport.dispatch_count == 2
    with pytest.raises(ScriptedResponseExhausted):
        await transport.send(_request())
    await transport.aclose()
    assert network_calls == []


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"schema_version": 2, "responses": {"firecrawl.search": [{}]}},
        {"schema_version": 1, "responses": {"unknown.operation": [{}]}},
        {
            "schema_version": 1,
            "responses": {"firecrawl.search": [{"transport_error": "arbitrary"}]},
        },
        {"schema_version": 1, "responses": {"firecrawl.search": []}},
    ],
)
def test_manifest_rejects_unsupported_or_unbounded_shapes(
    tmp_path: Path,
    manifest: object,
) -> None:
    path = tmp_path / "bad.json"
    _write(path, manifest)
    with pytest.raises(ScriptedManifestError):
        ScriptedProviderTransport.from_path(path)


def test_manifest_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":1,"schema_version":1,"responses":{"firecrawl.search":[{}]}}',
        encoding="utf-8",
    )
    with pytest.raises(ScriptedManifestError, match="duplicate"):
        ScriptedProviderTransport.from_path(path)
