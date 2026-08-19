from __future__ import annotations

import pytest

from gatehouse.providers.firecrawl import MockFirecrawlTransport, ScriptedResponse
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter


@pytest.mark.asyncio
async def test_mock_transport_consumes_script_in_order() -> None:
    transport = MockFirecrawlTransport()
    transport.script(
        "firecrawl.search",
        [
            ScriptedResponse(status_code=429, headers={"retry-after": "2"}),
            ScriptedResponse(status_code=200, data={"success": True, "data": []}),
        ],
    )
    request = FirecrawlAdapter().build_request(
        "firecrawl.search",
        {
            "query": "graduate roles",
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        },
        credential_id="credential-1",
    )

    first = await transport.send(request)
    second = await transport.send(request)

    assert first.status_code == 429
    assert second.status_code == 200
    assert len(transport.requests) == 2
