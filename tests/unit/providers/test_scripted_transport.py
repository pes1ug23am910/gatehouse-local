from __future__ import annotations

import json
import socket
from io import BytesIO
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


def test_manifest_reader_stops_at_the_limit_plus_one_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    class BoundedStream(BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            assert size is not None
            reads.append(size)
            assert size == 33
            return super().read(size)

    stream = BoundedStream(b"x" * 100)

    def open_stream(path: Path, mode: str) -> BytesIO:
        assert path == Path("synthetic-manifest.json")
        assert mode == "rb"
        return stream

    monkeypatch.setattr(Path, "open", open_stream)
    with pytest.raises(ScriptedManifestError, match="size"):
        ScriptedProviderTransport.from_path("synthetic-manifest.json", maximum_bytes=32)
    assert reads == [33]
    assert stream.closed


@pytest.mark.parametrize("maximum_bytes", [True, False, 0, -1, 1.5, "32", 1_048_577])
def test_manifest_limit_is_checked_before_any_open(
    monkeypatch: pytest.MonkeyPatch,
    maximum_bytes: object,
) -> None:
    def forbidden_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid limit opened a file")

    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(ValueError, match="bound"):
        ScriptedProviderTransport.from_path(
            "synthetic-manifest.json",
            maximum_bytes=maximum_bytes,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_captured_manifest_parser_uses_only_the_supplied_immutable_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b'{"schema_version":1,"responses":{"firecrawl.search":[{"status_code":204}]}}'

    def forbidden_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("captured parser reopened an origin")

    monkeypatch.setattr(Path, "open", forbidden_open)
    transport = ScriptedProviderTransport.from_bytes(raw, maximum_bytes=len(raw))
    assert (await transport.send(_request())).status_code == 204
    with pytest.raises(ScriptedManifestError, match="size"):
        ScriptedProviderTransport.from_bytes(raw, maximum_bytes=len(raw) - 1)
    with pytest.raises(ScriptedManifestError, match="immutable"):
        ScriptedProviderTransport.from_bytes(bytearray(raw))  # type: ignore[arg-type]


@pytest.mark.parametrize("version", [True, 1.0, "1"])
def test_manifest_version_requires_the_exact_integer(version: object) -> None:
    raw = json.dumps({"schema_version": version, "responses": {"firecrawl.search": [{}]}}).encode(
        "utf-8"
    )
    with pytest.raises(ScriptedManifestError, match="version"):
        ScriptedProviderTransport.from_bytes(raw)
