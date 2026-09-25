"""Bounded, no-socket provider transport for installed verification runs."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .base import ProviderRequest, ProviderResponse
from .firecrawl.adapter import OPERATION_SPECS
from .transport import ProviderNetworkDisabledError

_MAXIMUM_MANIFEST_BYTES = 1_048_576
_MAXIMUM_STEPS_PER_OPERATION = 100
_MAXIMUM_TOTAL_STEPS = 1_000
_ALLOWED_STEP_KEYS = frozenset(
    {
        "status_code",
        "data",
        "headers",
        "elapsed_ms",
        "provider_request_id",
        "transport_error",
        "submission_may_have_occurred",
    }
)
_ALLOWED_TRANSPORT_ERRORS = frozenset(
    {"timeout", "connect_error", "malformed_response", "response_too_large"}
)


class ScriptedProviderError(RuntimeError):
    """Base error for installed scripted-provider verification."""


class ScriptedManifestError(ScriptedProviderError):
    """The supplied no-network response manifest is invalid."""


class ScriptedResponseExhausted(ProviderNetworkDisabledError, ScriptedProviderError):
    """No declared response remains for an operation."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScriptedManifestError("scripted provider manifest contains a duplicate key")
        result[key] = value
    return result


def _required_integer(value: object, *, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ScriptedManifestError(f"scripted provider {field} is invalid")
    return value


def _optional_text(value: object, *, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ScriptedManifestError(f"scripted provider {field} is invalid")
    return value


def _headers(value: object) -> Mapping[str, str]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, dict) or len(value) > 16:
        raise ScriptedManifestError("scripted provider headers are invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not key
            or len(key) > 100
            or len(item) > 1_000
        ):
            raise ScriptedManifestError("scripted provider header is invalid")
        result[key] = item
    return MappingProxyType(result)


class _Step:
    __slots__ = (
        "data",
        "elapsed_ms",
        "headers",
        "provider_request_id",
        "status_code",
        "submission_may_have_occurred",
        "transport_error",
    )

    def __init__(self, value: object) -> None:
        if not isinstance(value, dict) or set(value) - _ALLOWED_STEP_KEYS:
            raise ScriptedManifestError("scripted provider response step is invalid")
        status = value.get("status_code", 200)
        if status is not None:
            status = _required_integer(status, field="status_code", minimum=100)
            if status > 599:
                raise ScriptedManifestError("scripted provider status_code is invalid")
        elapsed = _required_integer(value.get("elapsed_ms", 1), field="elapsed_ms")
        if elapsed > 3_600_000:
            raise ScriptedManifestError("scripted provider elapsed_ms exceeds its bound")
        transport_error = _optional_text(
            value.get("transport_error"),
            field="transport_error",
            maximum=64,
        )
        if transport_error is not None and transport_error not in _ALLOWED_TRANSPORT_ERRORS:
            raise ScriptedManifestError("scripted provider transport_error is unsupported")
        submission = value.get("submission_may_have_occurred", False)
        if not isinstance(submission, bool):
            raise ScriptedManifestError("scripted provider submission flag is invalid")
        self.status_code = status
        self.data = value.get("data")
        self.headers = _headers(value.get("headers"))
        self.elapsed_ms = elapsed
        self.provider_request_id = _optional_text(
            value.get("provider_request_id"),
            field="provider_request_id",
            maximum=256,
        )
        self.transport_error = transport_error
        self.submission_may_have_occurred = submission


class ScriptedProviderTransport:
    """Consume an explicit finite response script without opening a socket."""

    def __init__(self, scripts: Mapping[str, tuple[_Step, ...]]) -> None:
        self._scripts = {operation: deque(steps) for operation, steps in scripts.items()}
        self._lock = asyncio.Lock()
        self._dispatch_count = 0

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        maximum_bytes: int = _MAXIMUM_MANIFEST_BYTES,
    ) -> ScriptedProviderTransport:
        cls._validate_maximum_bytes(maximum_bytes)
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(maximum_bytes + 1)
        except OSError as error:
            raise ScriptedManifestError("scripted provider manifest is unavailable") from error
        return cls.from_bytes(raw, maximum_bytes=maximum_bytes)

    @staticmethod
    def _validate_maximum_bytes(value: int) -> None:
        if type(value) is not int or not 1 <= value <= _MAXIMUM_MANIFEST_BYTES:
            raise ValueError("scripted provider maximum_bytes is outside its bound")

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        maximum_bytes: int = _MAXIMUM_MANIFEST_BYTES,
    ) -> ScriptedProviderTransport:
        """Parse bounded captured content without reopening its origin.

        This content parser does not establish filesystem trust or bind the
        manifest to a configuration snapshot.
        """

        cls._validate_maximum_bytes(maximum_bytes)
        if type(raw) is not bytes:
            raise ScriptedManifestError("scripted provider manifest must be immutable bytes")
        if not raw or len(raw) > maximum_bytes:
            raise ScriptedManifestError("scripted provider manifest size is invalid")
        try:
            decoded: Any = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScriptedManifestError("scripted provider manifest is invalid JSON") from error
        if not isinstance(decoded, dict) or set(decoded) != {"schema_version", "responses"}:
            raise ScriptedManifestError("scripted provider manifest envelope is invalid")
        if type(decoded["schema_version"]) is not int or decoded["schema_version"] != 1:
            raise ScriptedManifestError("scripted provider manifest version is unsupported")
        responses = decoded["responses"]
        if not isinstance(responses, dict) or not responses:
            raise ScriptedManifestError("scripted provider responses are required")
        scripts: dict[str, tuple[_Step, ...]] = {}
        total = 0
        for operation, values in responses.items():
            if operation not in OPERATION_SPECS:
                raise ScriptedManifestError("scripted provider operation is unsupported")
            if (
                not isinstance(values, list)
                or not values
                or len(values) > _MAXIMUM_STEPS_PER_OPERATION
            ):
                raise ScriptedManifestError("scripted provider operation steps are invalid")
            steps = tuple(_Step(value) for value in values)
            scripts[operation] = steps
            total += len(steps)
        if total > _MAXIMUM_TOTAL_STEPS:
            raise ScriptedManifestError("scripted provider manifest has too many steps")
        return cls(scripts)

    @property
    def dispatch_count(self) -> int:
        return self._dispatch_count

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        async with self._lock:
            queue = self._scripts.get(request.operation)
            if not queue:
                raise ScriptedResponseExhausted(
                    "scripted provider has no remaining response for the operation"
                )
            step = queue.popleft()
            self._dispatch_count += 1
        return ProviderResponse(
            status_code=step.status_code,
            data=step.data,
            headers=step.headers,
            elapsed_ms=step.elapsed_ms,
            provider_request_id=step.provider_request_id,
            transport_error=step.transport_error,
            submission_may_have_occurred=step.submission_may_have_occurred,
        )

    async def aclose(self) -> None:
        """Match the live transport lifecycle without owning any I/O resource."""
