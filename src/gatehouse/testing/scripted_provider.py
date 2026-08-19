"""Bounded scripted ASGI provider used only by local verification suites."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

import httpx

type AsgiMessage = MutableMapping[str, Any]
type AsgiScope = MutableMapping[str, Any]
type AsgiReceive = Callable[[], Awaitable[AsgiMessage]]
type AsgiSend = Callable[[AsgiMessage], Awaitable[None]]


class ScriptMode(StrEnum):
    RESPONSE = "response"
    MALFORMED = "malformed"
    DELAY = "delay"
    PRE_SEND_RESET = "pre_send_reset"
    POST_SEND_RESET = "post_send_reset"


@dataclass(frozen=True, slots=True)
class ProviderScriptStep:
    mode: ScriptMode = ScriptMode.RESPONSE
    status_code: int = 200
    json_data: object = field(default_factory=lambda: {"success": True})
    headers: Mapping[str, str] = field(default_factory=dict)
    delay_ms: int = 0
    malformed_bytes: bytes = b"{not-json"

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("scripted status code is invalid")
        if self.delay_ms < 0 or self.delay_ms > 1_000:
            raise ValueError("scripted delay must be between zero and one second")
        if len(self.malformed_bytes) > 64 * 1_024:
            raise ValueError("malformed response exceeds the fixture bound")
        safe_headers: dict[str, str] = {}
        for key, value in self.headers.items():
            normalized = key.casefold()
            if normalized not in {"content-type", "retry-after", "x-request-id"}:
                raise ValueError("scripted response header is not allowlisted")
            if "\r" in value or "\n" in value or len(value) > 500:
                raise ValueError("scripted response header value is invalid")
            safe_headers[normalized] = value
        object.__setattr__(self, "headers", MappingProxyType(safe_headers))


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    sequence: int
    method: str
    path: str
    query_size: int
    query_sha256: str
    body_size: int
    body_sha256: str
    authorization_present: bool
    accepted: bool


class ScriptCapacityExceeded(RuntimeError):
    """Raised when fixture scripts or observations hit their explicit bound."""


class ScriptedProviderASGI:
    """A deterministic ASGI app that never stores authorization or body bytes."""

    def __init__(
        self,
        *,
        maximum_script_steps: int = 1_000,
        maximum_observations: int = 2_000,
        maximum_request_bytes: int = 128 * 1_024,
    ) -> None:
        if min(maximum_script_steps, maximum_observations, maximum_request_bytes) <= 0:
            raise ValueError("fixture bounds must be positive")
        self.maximum_script_steps = maximum_script_steps
        self.maximum_observations = maximum_observations
        self.maximum_request_bytes = maximum_request_bytes
        self._scripts: dict[tuple[str, str], deque[ProviderScriptStep]] = defaultdict(deque)
        self._observations: deque[ProviderObservation] = deque()
        self._script_count = 0
        self._sequence = 0
        self._lock = threading.Lock()

    @property
    def observations(self) -> tuple[ProviderObservation, ...]:
        with self._lock:
            return tuple(self._observations)

    @property
    def pending_script_steps(self) -> int:
        with self._lock:
            return self._script_count

    def script(
        self,
        method: str,
        path: str,
        steps: Iterable[ProviderScriptStep],
    ) -> None:
        normalized_method = method.upper()
        if normalized_method not in {"GET", "POST", "DELETE"}:
            raise ValueError("script method is unsupported")
        if not path.startswith("/v2/") or "?" in path or "#" in path:
            raise ValueError("script path must be a fixed v2 path")
        batch = tuple(steps)
        if not batch:
            raise ValueError("at least one script step is required")
        with self._lock:
            if self._script_count + len(batch) > self.maximum_script_steps:
                raise ScriptCapacityExceeded("script step capacity is exhausted")
            self._scripts[(normalized_method, path)].extend(batch)
            self._script_count += len(batch)

    async def __call__(
        self,
        scope: AsgiScope,
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("scripted provider accepts HTTP ASGI scopes only")
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", ""))
        step = self._next_step(method, path)
        if step.mode is ScriptMode.PRE_SEND_RESET:
            raise httpx.ConnectError("scripted pre-send connection reset")

        body_size, body_sha256 = await self._consume_body(receive)
        raw_query = bytes(scope.get("query_string", b""))
        self._record(
            method=method,
            path=path,
            query_size=len(raw_query),
            query_sha256=hashlib.sha256(raw_query).hexdigest(),
            body_size=body_size,
            body_sha256=body_sha256,
            authorization_present=self._authorization_present(scope),
            accepted=True,
        )
        if step.mode is ScriptMode.POST_SEND_RESET:
            raise httpx.ReadError("scripted post-send connection reset")
        if step.mode is ScriptMode.DELAY:
            await asyncio.sleep(step.delay_ms / 1_000)

        if step.mode is ScriptMode.MALFORMED:
            content = step.malformed_bytes
        else:
            content = json.dumps(
                step.json_data,
                allow_nan=False,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        headers = dict(step.headers)
        headers.setdefault("content-type", "application/json")
        await send(
            {
                "type": "http.response.start",
                "status": step.status_code,
                "headers": [
                    (key.encode("ascii"), value.encode("ascii")) for key, value in headers.items()
                ],
            }
        )
        await send({"type": "http.response.body", "body": content, "more_body": False})

    def _next_step(self, method: str, path: str) -> ProviderScriptStep:
        with self._lock:
            queue = self._scripts.get((method, path))
            if not queue:
                return ProviderScriptStep(status_code=500, json_data={"error": "unscripted"})
            step = queue.popleft()
            self._script_count -= 1
            return step

    async def _consume_body(self, receive: AsgiReceive) -> tuple[int, str]:
        size = 0
        digest = hashlib.sha256()
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                raise httpx.ReadError("request disconnected before body completion")
            if message_type != "http.request":
                raise RuntimeError("unexpected ASGI request message")
            raw = message.get("body", b"")
            if not isinstance(raw, bytes):
                raise RuntimeError("ASGI request body is not bytes")
            size += len(raw)
            if size > self.maximum_request_bytes:
                raise RuntimeError("scripted provider request exceeded its body bound")
            digest.update(raw)
            if not bool(message.get("more_body", False)):
                break
        return size, digest.hexdigest()

    def _record(
        self,
        *,
        method: str,
        path: str,
        query_size: int,
        query_sha256: str,
        body_size: int,
        body_sha256: str,
        authorization_present: bool,
        accepted: bool,
    ) -> None:
        with self._lock:
            if len(self._observations) >= self.maximum_observations:
                raise ScriptCapacityExceeded("provider observation capacity is exhausted")
            self._sequence += 1
            self._observations.append(
                ProviderObservation(
                    sequence=self._sequence,
                    method=method,
                    path=path,
                    query_size=query_size,
                    query_sha256=query_sha256,
                    body_size=body_size,
                    body_sha256=body_sha256,
                    authorization_present=authorization_present,
                    accepted=accepted,
                )
            )

    @staticmethod
    def _authorization_present(scope: AsgiScope) -> bool:
        raw_headers = scope.get("headers", ())
        if not isinstance(raw_headers, Iterable):
            return False
        for item in raw_headers:
            if (
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], bytes)
                and item[0].lower() == b"authorization"
            ):
                return True
        return False
