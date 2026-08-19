from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import httpx
import pytest

from gatehouse.api import (
    AgentOperations,
    SessionAuthority,
    StaticHealthProbe,
    create_agent_app,
)
from gatehouse.credentials import (
    CredentialMetadata,
    InMemoryKeyStore,
    SecretScanner,
)
from gatehouse.database import BoundedAuditWriter, open_migrated_database
from gatehouse.providers.firecrawl import FirecrawlAdapter
from gatehouse.providers.transport import FIRECRAWL_ORIGIN, HttpxProviderTransport
from gatehouse.sessions import InvalidAccessToken
from gatehouse.testing import ProviderScriptStep, ScriptedProviderASGI

_CANARY = "FAKE_END_TO_END_SECRET_CANARY_123456"


class _RejectingSessions:
    async def authenticate(self, _access_token: str) -> None:
        raise InvalidAccessToken("invalid access token")


async def _public_resolver(_host: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


@pytest.mark.asyncio
async def test_secret_canary_absent_from_provider_api_audit_and_export_like_output(
    tmp_path: Path,
) -> None:
    scanner = SecretScanner(canaries=[_CANARY])

    provider_app = ScriptedProviderASGI()
    provider_app.script(
        "POST",
        "/v2/search",
        [
            ProviderScriptStep(
                json_data={"summary": _CANARY, "response_body": _CANARY},
                headers={"x-request-id": "safe-id"},
            )
        ],
    )
    key_store = InMemoryKeyStore()
    await key_store.put(
        CredentialMetadata("credential", "principal", "quota", "canary"),
        _CANARY.encode(),
    )
    provider_client = httpx.AsyncClient(
        base_url=FIRECRAWL_ORIGIN,
        transport=httpx.ASGITransport(app=provider_app),
    )
    provider_transport = HttpxProviderTransport(
        key_store=key_store,
        network_enabled=True,
        client=provider_client,
        resolver=_public_resolver,
        scanner=scanner,
    )
    provider_request = FirecrawlAdapter().build_request(
        "firecrawl.search",
        {
            "query": "safe query",
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        },
        credential_id="credential",
    )
    try:
        provider_response = await provider_transport.send(provider_request)
    finally:
        await provider_client.aclose()
    assert _CANARY not in repr(provider_response)
    assert _CANARY not in repr(provider_app.observations)

    agent_app = create_agent_app(
        sessions=cast(SessionAuthority, _RejectingSessions()),
        operations=cast(AgentOperations, object()),
        health=StaticHealthProbe(),
        now_ms=lambda: 1_000,
        allowed_hosts=("127.0.0.1:47621",),
    )
    api_client = httpx.AsyncClient(
        base_url="http://127.0.0.1:47621",
        transport=httpx.ASGITransport(app=agent_app),
    )
    try:
        api_response = await api_client.post(
            "/v1/invocations",
            headers={"authorization": f"Bearer {_CANARY}"},
            json={
                "service": "firecrawl",
                "operation": "search",
                "input": {
                    "query": "safe query",
                    "purpose": "career_discovery",
                    "data_classification": ["public_web_query"],
                },
                "context": {"root_run_id": "run-test"},
            },
        )
    finally:
        await api_client.aclose()
    assert api_response.status_code == 401
    assert _CANARY not in api_response.text
    assert _CANARY not in repr(dict(api_response.headers))

    connection = open_migrated_database(tmp_path / "canary.db")
    try:
        audit = BoundedAuditWriter(scanner=scanner)
        audit.emit(
            "canary_test",
            "INFO",
            {"note": _CANARY, "response_body": _CANARY},
            occurred_at_ms=1_000,
        )
        assert audit.flush(connection) == 1
        rows = [
            dict(row)
            for row in connection.execute(
                "SELECT event_type, severity, payload_json FROM audit_events"
            )
        ]
        export_like_json = json.dumps(rows, sort_keys=True)
        assert _CANARY not in export_like_json
        assert "REDACTED" in export_like_json
        assert not scanner.scan_text(export_like_json, location="audit_export")
    finally:
        connection.close()
