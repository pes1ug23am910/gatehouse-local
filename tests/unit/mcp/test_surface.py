from __future__ import annotations

import asyncio
from collections.abc import Mapping

from gatehouse.core.errors import JsonValue
from gatehouse.mcp import create_mcp_server


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, JsonValue]]] = []
        self.request_ids: list[str | None] = []
        self.session_heartbeat_interval_seconds = 30.0

    async def call(
        self,
        operation: str,
        payload: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> dict[str, JsonValue]:
        self.calls.append((operation, payload))
        self.request_ids.append(request_id)
        return {"operation": operation, "state": "accepted"}

    async def maintain_session(self) -> dict[str, JsonValue]:
        return {
            "status": "active",
            "session_id": "ses_test",
            "reported_agent_count": 1,
        }


def test_tool_registration_is_capability_sensitive_and_has_no_privileged_escape_hatch() -> None:
    backend = FakeBackend()
    server = create_mcp_server(
        backend=backend,
        capabilities=frozenset(
            {
                "docs.search",
                "feedback.submit",
                "firecrawl.search",
                "firecrawl.account.credit_status",
                "watcher.scan_feed_set",
                "watcher.get_previous_summary",
            }
        ),
    )
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert names == {
        "gatehouse_status",
        "gatehouse_capabilities",
        "gatehouse_docs_search",
        "gatehouse_feedback_submit",
        "firecrawl_search",
        "watcher_scan_feed_set",
        "watcher_get_previous_summary",
    }
    prohibited_fragments = {
        "secret",
        "credential",
        "raw_http",
        "provider_header",
        "admin",
        "credit_status",
    }
    assert not any(fragment in name for name in names for fragment in prohibited_fragments)
    advertised = asyncio.run(server.call_tool("gatehouse_capabilities", {}))
    assert "credit_status" not in str(advertised)

    watcher = next(tool for tool in tools if tool.name == "watcher_scan_feed_set")
    properties = watcher.inputSchema["properties"]
    assert set(properties) == {"feed_set_id", "cursor"}
    assert "targets" not in properties
    assert "url" not in properties


def test_typed_provider_tool_validates_and_forwards_only_schema_fields() -> None:
    backend = FakeBackend()
    server = create_mcp_server(
        backend=backend,
        capabilities=frozenset({"firecrawl.search"}),
    )
    asyncio.run(
        server.call_tool(
            "firecrawl_search",
            {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
                "limit": 5,
                "include_content": False,
            },
        )
    )
    assert len(backend.calls) == 1
    operation, payload = backend.calls[0]
    assert operation == "firecrawl.search"
    assert set(payload) == {
        "query",
        "limit",
        "include_content",
        "purpose",
        "data_classification",
    }


def test_crawl_start_exposes_an_explicit_stable_request_handle() -> None:
    backend = FakeBackend()
    server = create_mcp_server(
        backend=backend,
        capabilities=frozenset({"firecrawl.crawl.start"}),
    )
    tools = asyncio.run(server.list_tools())
    crawl = next(tool for tool in tools if tool.name == "firecrawl_crawl_start")
    assert "request_id" in crawl.inputSchema["properties"]

    request_id = "req_00000000000000000000000001"
    asyncio.run(
        server.call_tool(
            "firecrawl_crawl_start",
            {
                "url": "https://example.com/careers",
                "include_paths": ["^/careers/"],
                "data_classification": ["public_web"],
                "request_id": request_id,
            },
        )
    )

    assert backend.request_ids == [request_id]
    operation, payload = backend.calls[0]
    assert operation == "firecrawl.crawl.start"
    assert "request_id" not in payload
