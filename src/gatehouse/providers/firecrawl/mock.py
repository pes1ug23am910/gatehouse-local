"""Scriptable provider transport used for deterministic integration tests."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from gatehouse.providers.base import ProviderRequest, ProviderResponse


@dataclass(frozen=True, slots=True)
class ScriptedResponse:
    status_code: int | None = 200
    data: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: int = 1
    transport_error: str | None = None
    submission_may_have_occurred: bool = False


class MockFirecrawlTransport:
    """Consume per-operation scripts and retain only credential-free requests."""

    def __init__(self) -> None:
        self._scripts: dict[str, deque[ScriptedResponse]] = defaultdict(deque)
        self._requests: list[ProviderRequest] = []
        self._lock = Lock()

    @property
    def requests(self) -> tuple[ProviderRequest, ...]:
        with self._lock:
            return tuple(self._requests)

    def script(self, operation: str, responses: Iterable[ScriptedResponse]) -> None:
        with self._lock:
            self._scripts[operation].extend(responses)

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        with self._lock:
            self._requests.append(request)
            queue = self._scripts[request.operation]
            scripted = queue.popleft() if queue else ScriptedResponse()
        return ProviderResponse(
            status_code=scripted.status_code,
            data=scripted.data,
            headers=scripted.headers,
            elapsed_ms=scripted.elapsed_ms,
            transport_error=scripted.transport_error,
            submission_may_have_occurred=scripted.submission_may_have_occurred,
        )
