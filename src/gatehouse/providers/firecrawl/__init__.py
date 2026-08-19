"""Typed Firecrawl v2 adapter and deterministic mock transport."""

from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter, FirecrawlOutcome
from gatehouse.providers.firecrawl.mock import MockFirecrawlTransport, ScriptedResponse

__all__ = [
    "FirecrawlAdapter",
    "FirecrawlOutcome",
    "MockFirecrawlTransport",
    "ScriptedResponse",
]
