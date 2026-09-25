"""Bounded loopback HTTP client used by the stock MCP entry point."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import traceback
from collections import OrderedDict, deque
from collections.abc import AsyncIterator, Callable, Mapping, MutableMapping
from contextlib import suppress
from dataclasses import dataclass
from itertools import islice
from typing import Literal, Never, cast
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from gatehouse.core.errors import JsonValue
from gatehouse.core.ids import RequestId
from gatehouse.watcher.store import MAX_CURSOR_BYTES, MAX_CURSOR_SEQUENCE

DEFAULT_AGENT_URL = "http://127.0.0.1:47621"
SESSION_ID_ENVIRONMENT = "GATEHOUSE_SESSION_ID"
SESSION_BOOTSTRAP_ENVIRONMENT = "GATEHOUSE_SESSION_BOOTSTRAP"
AGENT_URL_ENVIRONMENT = "GATEHOUSE_AGENT_URL"

_MAXIMUM_REQUEST_BYTES = 64 * 1_024
_MAXIMUM_RESPONSE_BYTES = 4 * 1_024 * 1_024
_DEFAULT_TIMEOUT_SECONDS = 35.0
_MINIMUM_HEARTBEAT_INTERVAL_MS = 1_000
_MAXIMUM_HEARTBEAT_INTERVAL_MS = 300_000
_MAXIMUM_READOPTION_WAITERS = 64
_READOPTION_STATE_LOCK_TIMEOUT_SECONDS = 1.0
_MAXIMUM_PENDING_APPROVALS = 64
_PENDING_APPROVAL_TTL_SECONDS = 5 * 60.0
_APPROVAL_STATE_LOCK_TIMEOUT_SECONDS = 1.0
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_ROUTABLE_CAPABILITIES = frozenset(
    {
        "jobs.status",
        "jobs.await",
        "jobs.cancel",
        "docs.search",
        "docs.get",
        "feedback.submit",
        "firecrawl.search",
        "firecrawl.scrape",
        "firecrawl.map",
        "firecrawl.crawl.start",
        "firecrawl.crawl.status",
        "firecrawl.crawl.cancel",
        "watcher.scan_feed_set",
        "watcher.get_cursor",
        "watcher.commit_cursor",
        "watcher.get_previous_summary",
    }
)

TransportFactory = Callable[[], httpx.AsyncBaseTransport]
type _ReadoptionResult = Literal[
    "adopted",
    "daemon_degraded",
    "invalid_session",
    "session_expired",
    "session_revoked",
]
type _ApprovalClaimState = Literal["claimed", "missing", "busy", "degraded"]

_TERMINAL_SESSION_ERRORS = frozenset(
    {
        "invalid_session",
        "session_expired",
        "session_revoked",
    }
)


class McpStartupError(RuntimeError):
    """Sanitized failure to adopt the controlled Gatehouse session."""


class _AgentClientError(RuntimeError):
    pass


def _control_failure(error: BaseException) -> str | None:
    if isinstance(error, asyncio.CancelledError):
        return "cancelled"
    if isinstance(error, KeyboardInterrupt):
        return "keyboard_interrupt"
    if isinstance(error, SystemExit):
        return "system_exit"
    return None


def _scrub_http_state(*roots: object) -> None:
    """Detach bounded owned HTTP/error graphs; Python cannot erase immutable copies."""

    # Visit direct owners before descendants so a capped exception chain cannot
    # consume the work budget ahead of request fields and mutable body buffers.
    pending = deque(roots[:64])
    seen: set[int] = set()
    while pending and len(seen) < 64:
        current = pending.popleft()
        if id(current) in seen:
            continue
        seen.add(id(current))
        children: list[object] = []
        if isinstance(current, bytearray):
            current[:] = b"\x00" * len(current)
        elif isinstance(current, memoryview):
            if not current.readonly:
                with suppress(Exception):
                    current[:] = b"\x00" * len(current)
        elif isinstance(current, BaseException):
            children.extend((current.__cause__, current.__context__))
            if isinstance(current, BaseExceptionGroup):
                children.extend(current.exceptions[:64])
            children.extend(islice(current.__dict__.values(), 128))
            # These built-in references live outside args and __dict__.
            if isinstance(current, SystemExit):
                children.append(current.code)
                current.code = None
            if isinstance(current, (UnicodeDecodeError, UnicodeEncodeError, UnicodeTranslateError)):
                if isinstance(current, UnicodeDecodeError):
                    current.object = b""
                else:
                    current.object = ""
                if isinstance(current, (UnicodeDecodeError, UnicodeEncodeError)):
                    current.encoding = ""
                current.reason = ""
                current.start = current.end = 0
            if isinstance(current, OSError):
                current.filename = current.filename2 = current.strerror = None
            if current.__traceback__ is not None:
                traceback.clear_frames(current.__traceback__)
            current.args = ()
            current.__dict__.clear()
            current.__traceback__ = None
            current.__cause__ = None
            current.__context__ = None
        elif isinstance(current, httpx.Request):
            children.append(current.stream)
            current.headers.clear()
            current.extensions.clear()
            current.method = ""
            current.url = httpx.URL("")
            current.stream = httpx.ByteStream(b"")
            current._content = b""
        elif isinstance(current, httpx.Response):
            children.append(current.stream)
            with suppress(RuntimeError):
                children.append(current.request)
            children.append(current.next_request)
            current.next_request = None
            current.headers.clear()
            current.extensions.clear()
            current.stream = httpx.ByteStream(b"")
            current._content = b""
            # HTTPX caches decoded text independently of the byte content.
            current.__dict__.pop("_text", None)
            current.__dict__.pop("_decoder", None)
        elif isinstance(current, (httpx.AsyncByteStream, httpx.SyncByteStream)):
            state = getattr(current, "__dict__", {})
            for name, value in tuple(islice(state.items(), 128)):
                if isinstance(value, (bytearray, memoryview)):
                    children.append(value)
                    setattr(current, name, bytearray())
                elif isinstance(value, bytes):
                    setattr(current, name, b"")
                elif isinstance(value, str):
                    setattr(current, name, "")
                elif isinstance(value, BaseException):
                    children.append(value)
                    setattr(current, name, None)
                elif name == "_stream":
                    children.append(value)
                    setattr(current, name, httpx.ByteStream(b""))
        pending.extend(children[: max(0, 64 - len(pending))])


def _raise_sanitized_failure(*, control: str | None = None, startup: bool = False) -> Never:
    message = (
        "Gatehouse MCP session adoption failed." if startup else "Gatehouse agent request failed"
    )
    failure: BaseException
    if control == "cancelled":
        failure = asyncio.CancelledError(message)
    elif control == "keyboard_interrupt":
        failure = KeyboardInterrupt(message)
    elif control == "system_exit":
        failure = SystemExit(1)
        failure.add_note(message)
    else:
        failure = McpStartupError(message) if startup else _AgentClientError(message)
    try:
        raise failure from None
    except BaseException as sanitized:
        sanitized.__context__ = None
        sanitized.__cause__ = None
        raise


class _OwnedJsonBody(httpx.AsyncByteStream):
    def __init__(self, body: bytearray) -> None:
        self.body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield bytes(self.body)

    async def aclose(self) -> None:
        self.body[:] = b"\x00" * len(self.body)


@dataclass(slots=True)
class _PendingApproval:
    approval_id: str
    root_run_id: str
    expires_at_monotonic: float
    continuation_request_id: str | None = None
    in_flight: bool = False
    claim_generation: int = 0
    claim_expires_at_monotonic: float | None = None


@dataclass(frozen=True, slots=True)
class _ApprovalClaim:
    approval_id: str
    root_run_id: str
    continuation_request_id: str | None
    generation: int


@dataclass(frozen=True, slots=True)
class _PendingApprovalResponse:
    approval_id: str
    root_run_id: str


def _validated_agent_url(value: str) -> str:
    if type(value) is not str or len(value) > 256 or any(ord(char) <= 0x20 for char in value):
        raise McpStartupError("Gatehouse agent URL is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise McpStartupError("Gatehouse agent URL is invalid.") from error
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65_535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise McpStartupError(
            "Gatehouse agent URL must be an explicit HTTP loopback URL with a port."
        )
    return urlunsplit(("http", f"127.0.0.1:{port}", "", "", ""))


def _safe_error(
    *,
    code: str,
    message: str,
    retryable: bool,
    retry_after_seconds: int | None = None,
) -> dict[str, JsonValue]:
    error: dict[str, JsonValue] = {
        "code": code,
        "message": message,
        "retryable": retryable,
    }
    if retry_after_seconds is not None:
        error["retry_after_seconds"] = retry_after_seconds
    return {"error": error}


def _response_error_code(payload: Mapping[str, JsonValue]) -> str | None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, str) else None


def _approval_request_key(
    *,
    cache_key: bytes,
    session_id: str,
    root_run_id: str,
    operation: str,
    payload: Mapping[str, JsonValue],
    caller_request_id: str | None,
) -> str:
    """Commit exact continuation facts without retaining agent-supplied request data."""

    if len(cache_key) < 32:
        raise ValueError("approval continuation cache key must contain at least 256 bits")

    try:
        encoded = json.dumps(
            {
                "session_id": session_id,
                "root_run_id": root_run_id,
                "operation": operation,
                "payload": dict(payload),
                "caller_request_id": caller_request_id,
            },
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _AgentClientError("request body is not valid JSON") from error
    return hmac.new(
        cache_key,
        b"gatehouse/mcp/approval-continuation/v1\x00" + encoded,
        hashlib.sha256,
    ).hexdigest()


def _validated_dashboard_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1 <= port <= 65_535
        and parsed.username is None
        and parsed.password is None
        and parsed.path == "/dashboard"
        and not parsed.query
        and not parsed.fragment
    )


def _pending_approval_response(
    payload: Mapping[str, JsonValue],
    *,
    default_root_run_id: str,
) -> _PendingApprovalResponse | None:
    if payload.get("state") != "WAITING_APPROVAL":
        return None
    if _response_error_code(payload) != "approval_pending":
        return None
    approval_id = payload.get("approval_id")
    request_id = payload.get("request_id")
    if (
        not isinstance(approval_id, str)
        or approval_id in {".", ".."}
        or _IDENTIFIER_PATTERN.fullmatch(approval_id) is None
        or not isinstance(request_id, str)
    ):
        return None
    try:
        RequestId(request_id)
    except (TypeError, ValueError):
        return None
    context = payload.get("approval_context")
    if context is None:
        raw_root_run_id: object = default_root_run_id
    elif isinstance(context, dict):
        raw_root_run_id = context.get("root_run_id")
        dashboard_url = context.get("dashboard_url")
        required_action = context.get("required_action")
        if dashboard_url is not None and not _validated_dashboard_url(dashboard_url):
            return None
        if required_action is not None and required_action != (
            "decide_locally_then_retry_exact_request"
        ):
            return None
    else:
        return None
    if (
        not isinstance(raw_root_run_id, str)
        or raw_root_run_id in {".", ".."}
        or _IDENTIFIER_PATTERN.fullmatch(raw_root_run_id) is None
    ):
        return None
    return _PendingApprovalResponse(approval_id, raw_root_run_id)


def _approval_continuation_in_progress() -> dict[str, JsonValue]:
    return _safe_error(
        code="approval_pending",
        message=(
            "The exact request already has a local approval continuation in progress. "
            "Retry the same request shortly."
        ),
        retryable=True,
        retry_after_seconds=1,
    )


def _validated_heartbeat_interval_ms(payload: Mapping[str, JsonValue]) -> int:
    value = payload.get("heartbeat_interval_ms")
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not _MINIMUM_HEARTBEAT_INTERVAL_MS <= value <= _MAXIMUM_HEARTBEAT_INTERVAL_MS
    ):
        raise _AgentClientError("session heartbeat interval is invalid")
    return value


class _BoundedAgentClient:
    __slots__ = (
        "_base_url",
        "_maximum_request_bytes",
        "_maximum_response_bytes",
        "_timeout_seconds",
        "_transport_factory",
    )

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float,
        maximum_request_bytes: int,
        maximum_response_bytes: int,
        transport_factory: TransportFactory | None,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("MCP HTTP timeout must be between zero and 60 seconds")
        if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
            raise ValueError("MCP HTTP body limits must be positive")
        self._base_url = _validated_agent_url(base_url)
        self._timeout_seconds = timeout_seconds
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes
        self._transport_factory = transport_factory

    def _client(self) -> httpx.AsyncClient:
        transport = self._transport_factory() if self._transport_factory is not None else None
        return httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
            transport=transport,
        )

    @staticmethod
    def _encoded_body(payload: Mapping[str, JsonValue] | None) -> bytearray | None:
        if payload is None:
            return None
        try:
            return bytearray(
                json.dumps(
                    dict(payload),
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                "utf-8",
            )
        except (TypeError, ValueError) as error:
            raise _AgentClientError("request body is not valid JSON") from error

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
        access_token: str | None = None,
        query: Mapping[str, str] | None = None,
    ) -> tuple[int, dict[str, JsonValue]]:
        encoded: bytearray | None = None
        body: _OwnedJsonBody | None = None
        client: httpx.AsyncClient | None = None
        request: httpx.Request | None = None
        response: httpx.Response | None = None
        content = bytearray()
        chunk = b""
        headers: dict[str, str] = {}
        decoded: object = None
        content_type: str | None = None
        status = 0
        failed = False
        control: str | None = None
        failures: list[BaseException] = []
        try:
            encoded = self._encoded_body(payload)
            if encoded is not None and len(encoded) > self._maximum_request_bytes:
                raise _AgentClientError("request body exceeds the configured limit")
            headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
            if encoded is not None:
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(encoded))
                body = _OwnedJsonBody(encoded)
            if access_token is not None:
                headers["Authorization"] = f"Bearer {access_token}"
            async with asyncio.timeout(self._timeout_seconds):
                client = self._client()
                request = client.build_request(
                    method,
                    path,
                    content=body,
                    headers=headers,
                    params=query,
                )
                response = await client.send(request, stream=True)
                length = response.headers.get("content-length")
                if length is not None:
                    declared_length = int(length)
                    if declared_length < 0 or declared_length > self._maximum_response_bytes:
                        raise _AgentClientError("response body exceeds the configured limit")
                async for chunk in response.aiter_bytes():
                    if len(chunk) > self._maximum_response_bytes - len(content):
                        raise _AgentClientError("response body exceeds the configured limit")
                    content.extend(chunk)
                content_type = response.headers.get("content-type", "")
                if content_type.partition(";")[0].strip().casefold() != "application/json":
                    raise _AgentClientError("response is not JSON")
                decoded = json.loads(content.decode("utf-8"))
                if not isinstance(decoded, dict) or any(
                    not isinstance(key, str) for key in decoded
                ):
                    raise _AgentClientError("response JSON root is not an object")
                status = response.status_code
        except BaseException as error:
            failed = True
            control = _control_failure(error)
            failures.append(error)
        finally:
            # Close separately so a failed close cannot replace the primary control
            # interruption or skip the remaining owner. Each close has its own cap.
            for owner in (response, client):
                if owner is None:
                    continue
                try:
                    async with asyncio.timeout(min(1.0, self._timeout_seconds)):
                        await owner.aclose()
                except BaseException as error:
                    failed = True
                    control = control or _control_failure(error)
                    failures.append(error)
            if client is not None:
                client.cookies.clear()
            _scrub_http_state(request, response, body, encoded, content, *failures)
            failures.clear()
            headers.clear()
            payload = access_token = query = None
            chunk = b""
            method = path = ""
            length = content_type = None
        if failed:
            decoded = None
            _raise_sanitized_failure(control=control)
        return status, cast(dict[str, JsonValue], decoded)


def _required_identifier(payload: Mapping[str, JsonValue], name: str) -> str:
    value = payload.get(name)
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise _AgentClientError(f"{name} is invalid")
    return value


def _required_wait(payload: Mapping[str, JsonValue]) -> int:
    value = payload.get("maximum_wait_ms")
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 30_000:
        raise _AgentClientError("maximum_wait_ms is invalid")
    return value


def _request_scoped_failure(request_id: RequestId) -> dict[str, JsonValue]:
    result = _safe_error(
        code="daemon_degraded",
        message="The local Gatehouse agent returned an invalid response.",
        retryable=True,
        retry_after_seconds=1,
    )
    error = result.get("error")
    if not isinstance(error, dict):  # pragma: no cover - fixed local envelope
        raise TypeError("local MCP error envelope is invalid")
    error["request_id"] = str(request_id)
    return result


def _bind_request_result(
    result: dict[str, JsonValue],
    *,
    request_id: RequestId,
) -> dict[str, JsonValue]:
    """Keep the retry handle even when the loopback response is lost or degraded."""

    error = result.get("error")
    if isinstance(error, dict):
        returned = error.get("request_id")
        if returned is not None and returned != str(request_id):
            return _request_scoped_failure(request_id)
        copied = dict(result)
        copied_error = dict(error)
        copied_error["request_id"] = str(request_id)
        copied["error"] = copied_error
        return copied
    if result.get("request_id") != str(request_id):
        return _request_scoped_failure(request_id)
    return result


class LoopbackMcpBackend:
    """Adopt one launched session and route authorized MCP tools to its agent API."""

    __slots__ = (
        "_access_token",
        "_approval_cache_key",
        "_approval_cache_ttl_seconds",
        "_approval_claim_lease_seconds",
        "_approval_lock",
        "_bootstrap_capability",
        "_client",
        "_heartbeat_interval_ms",
        "_maximum_pending_approvals",
        "_monotonic",
        "_pending_approvals",
        "_readoption_inflight",
        "_readoption_lock",
        "_readoption_waiters",
        "_readoption_wait_seconds",
        "_root_run_id",
        "_session_id",
        "capabilities",
    )

    def __init__(
        self,
        *,
        client: _BoundedAgentClient,
        access_token: str,
        session_id: str,
        bootstrap_capability: str,
        root_run_id: str,
        capabilities: frozenset[str],
        heartbeat_interval_ms: int,
        readoption_wait_seconds: float,
        maximum_pending_approvals: int,
        approval_cache_ttl_seconds: float,
        approval_claim_lease_seconds: float,
        approval_cache_key: bytes,
        monotonic: Callable[[], float],
    ) -> None:
        if not 1 <= maximum_pending_approvals <= 1_024:
            raise ValueError("pending approval cache bound must be between one and 1024")
        if not 1 <= approval_cache_ttl_seconds <= 600:
            raise ValueError("pending approval cache TTL must be between one and 600 seconds")
        if not 1 <= approval_claim_lease_seconds <= 61:
            raise ValueError("pending approval claim lease must be between one and 61 seconds")
        if len(approval_cache_key) < 32:
            raise ValueError("approval continuation cache key must contain at least 256 bits")
        self._client = client
        self._access_token = access_token
        self._session_id = session_id
        self._bootstrap_capability = bootstrap_capability
        self._root_run_id = root_run_id
        self.capabilities = capabilities
        self._heartbeat_interval_ms = heartbeat_interval_ms
        self._readoption_wait_seconds = readoption_wait_seconds
        self._readoption_inflight: tuple[str, asyncio.Task[_ReadoptionResult]] | None = None
        self._readoption_lock = asyncio.Lock()
        self._readoption_waiters = 0
        self._maximum_pending_approvals = maximum_pending_approvals
        self._approval_cache_key = bytes(approval_cache_key)
        self._approval_cache_ttl_seconds = approval_cache_ttl_seconds
        self._approval_claim_lease_seconds = approval_claim_lease_seconds
        self._monotonic = monotonic
        self._pending_approvals: OrderedDict[str, _PendingApproval] = OrderedDict()
        self._approval_lock = asyncio.Lock()

    @property
    def session_heartbeat_interval_seconds(self) -> float:
        return self._heartbeat_interval_ms / 1_000

    @property
    def pending_approval_count(self) -> int:
        """Return only a bounded diagnostic count; approval handles stay private."""

        return len(self._pending_approvals)

    @classmethod
    async def from_environment(
        cls,
        *,
        environment: MutableMapping[str, str] | None = None,
        agent_url: str | None = None,
        client_nonce: str | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        maximum_request_bytes: int = _MAXIMUM_REQUEST_BYTES,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
        transport_factory: TransportFactory | None = None,
        maximum_pending_approvals: int = _MAXIMUM_PENDING_APPROVALS,
        approval_cache_ttl_seconds: float = _PENDING_APPROVAL_TTL_SECONDS,
        approval_claim_lease_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> LoopbackMcpBackend:
        try:
            return await cls._from_environment(
                environment=environment,
                agent_url=agent_url,
                client_nonce=client_nonce,
                timeout_seconds=timeout_seconds,
                maximum_request_bytes=maximum_request_bytes,
                maximum_response_bytes=maximum_response_bytes,
                transport_factory=transport_factory,
                maximum_pending_approvals=maximum_pending_approvals,
                approval_cache_ttl_seconds=approval_cache_ttl_seconds,
                approval_claim_lease_seconds=approval_claim_lease_seconds,
                monotonic=monotonic,
            )
        except BaseException as error:
            control = _control_failure(error)
            _scrub_http_state(error)
        # The completed adoption frame has been cleared; do not leave caller
        # capabilities or malformed URLs in the new outward failure traceback.
        environment = None
        agent_url = client_nonce = None
        _raise_sanitized_failure(control=control, startup=True)

    @classmethod
    async def _from_environment(
        cls,
        *,
        environment: MutableMapping[str, str] | None = None,
        agent_url: str | None = None,
        client_nonce: str | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        maximum_request_bytes: int = _MAXIMUM_REQUEST_BYTES,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
        transport_factory: TransportFactory | None = None,
        maximum_pending_approvals: int = _MAXIMUM_PENDING_APPROVALS,
        approval_cache_ttl_seconds: float = _PENDING_APPROVAL_TTL_SECONDS,
        approval_claim_lease_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> LoopbackMcpBackend:
        source = os.environ if environment is None else environment
        session_id = source.get(SESSION_ID_ENVIRONMENT)
        bootstrap = source.get(SESSION_BOOTSTRAP_ENVIRONMENT)
        source.pop(SESSION_ID_ENVIRONMENT, None)
        source.pop(SESSION_BOOTSTRAP_ENVIRONMENT, None)
        if (
            not session_id
            or session_id in {".", ".."}
            or _IDENTIFIER_PATTERN.fullmatch(session_id) is None
            or not bootstrap
            or not 40 <= len(bootstrap) <= 128
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in bootstrap)
        ):
            raise McpStartupError("Gatehouse MCP startup requires a controlled session bootstrap.")
        selected_url = agent_url or source.get(AGENT_URL_ENVIRONMENT) or DEFAULT_AGENT_URL
        client = _BoundedAgentClient(
            base_url=selected_url,
            timeout_seconds=timeout_seconds,
            maximum_request_bytes=maximum_request_bytes,
            maximum_response_bytes=maximum_response_bytes,
            transport_factory=transport_factory,
        )
        nonce = client_nonce or secrets.token_urlsafe(24)
        if not 8 <= len(nonce) <= 256:
            raise McpStartupError("Gatehouse MCP client nonce is invalid.")

        try:
            exchange_status, exchange = await client.request(
                "POST",
                "/v1/sessions/exchange",
                payload={
                    "session_id": session_id,
                    "bootstrap_capability": bootstrap,
                    "client_nonce": nonce,
                },
            )
            if exchange_status != 200:
                raise _AgentClientError("session exchange was rejected")
            access_token = exchange.get("access_token")
            token_type = exchange.get("token_type")
            returned_capabilities = exchange.get("capabilities")
            session = exchange.get("session")
            heartbeat_interval_ms = _validated_heartbeat_interval_ms(exchange)
            if (
                not isinstance(access_token, str)
                or not 40 <= len(access_token) <= 512
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in access_token)
                or not isinstance(token_type, str)
                or token_type.casefold() != "bearer"
                or not isinstance(returned_capabilities, list)
                or any(not isinstance(item, str) for item in returned_capabilities)
                or not isinstance(session, dict)
                or session.get("session_id") != session_id
                or session.get("state") != "ACTIVE"
            ):
                raise _AgentClientError("session exchange response is invalid")
            capabilities = (
                frozenset(cast(list[str], returned_capabilities)) & _ROUTABLE_CAPABILITIES
            )

            root_status, root_run = await client.request(
                "POST",
                "/v1/root-runs",
                payload={},
                access_token=access_token,
            )
            root_run_id = root_run.get("root_run_id")
            if (
                root_status != 201
                or not isinstance(root_run_id, str)
                or root_run_id in {".", ".."}
                or _IDENTIFIER_PATTERN.fullmatch(root_run_id) is None
                or root_run.get("session_id") != session_id
                or root_run.get("state") != "ACTIVE"
            ):
                raise _AgentClientError("root run response is invalid")
        except _AgentClientError as error:
            raise McpStartupError("Gatehouse MCP session adoption failed.") from error

        return cls(
            client=client,
            access_token=access_token,
            session_id=session_id,
            bootstrap_capability=bootstrap,
            root_run_id=root_run_id,
            capabilities=capabilities,
            heartbeat_interval_ms=heartbeat_interval_ms,
            readoption_wait_seconds=min(timeout_seconds + 1.0, 60.0),
            maximum_pending_approvals=maximum_pending_approvals,
            approval_cache_ttl_seconds=approval_cache_ttl_seconds,
            approval_claim_lease_seconds=(
                min(timeout_seconds + 1.0, 61.0)
                if approval_claim_lease_seconds is None
                else approval_claim_lease_seconds
            ),
            approval_cache_key=secrets.token_bytes(32),
            monotonic=monotonic,
        )

    def _prune_pending_approvals_locked(self, *, now: float) -> None:
        for pending in self._pending_approvals.values():
            if (
                pending.in_flight
                and pending.claim_expires_at_monotonic is not None
                and pending.claim_expires_at_monotonic <= now
            ):
                pending.in_flight = False
                pending.claim_expires_at_monotonic = None
        expired = [
            key
            for key, pending in self._pending_approvals.items()
            if pending.expires_at_monotonic <= now and not pending.in_flight
        ]
        for key in expired:
            self._pending_approvals.pop(key, None)

    async def _claim_pending_approval(
        self,
        *,
        key: str,
        operation: str,
    ) -> tuple[_ApprovalClaimState, _ApprovalClaim | None]:
        try:
            async with asyncio.timeout(_APPROVAL_STATE_LOCK_TIMEOUT_SECONDS):
                async with self._approval_lock:
                    self._prune_pending_approvals_locked(now=self._monotonic())
                    pending = self._pending_approvals.get(key)
                    if pending is None:
                        return "missing", None
                    if pending.in_flight:
                        return "busy", None
                    pending.in_flight = True
                    pending.claim_generation += 1
                    pending.claim_expires_at_monotonic = (
                        self._monotonic() + self._approval_claim_lease_seconds
                    )
                    if (
                        operation == "firecrawl.crawl.start"
                        and pending.continuation_request_id is None
                    ):
                        pending.continuation_request_id = str(RequestId.new())
                    self._pending_approvals.move_to_end(key)
                    return (
                        "claimed",
                        _ApprovalClaim(
                            pending.approval_id,
                            pending.root_run_id,
                            pending.continuation_request_id,
                            pending.claim_generation,
                        ),
                    )
        except TimeoutError:
            return "degraded", None

    async def _remember_pending_approval(
        self,
        *,
        key: str,
        response: _PendingApprovalResponse,
        claim: _ApprovalClaim | None,
    ) -> bool:
        try:
            async with asyncio.timeout(_APPROVAL_STATE_LOCK_TIMEOUT_SECONDS):
                async with self._approval_lock:
                    now = self._monotonic()
                    self._prune_pending_approvals_locked(now=now)
                    current = self._pending_approvals.get(key)
                    if claim is not None:
                        if (
                            current is None
                            or current.claim_generation != claim.generation
                            or current.approval_id != claim.approval_id
                            or current.root_run_id != claim.root_run_id
                            or response.approval_id != claim.approval_id
                            or response.root_run_id != claim.root_run_id
                        ):
                            return False
                    if current is not None:
                        if (
                            current.approval_id != response.approval_id
                            or current.root_run_id != response.root_run_id
                        ):
                            self._pending_approvals.pop(key, None)
                            return False
                        current.in_flight = False
                        current.claim_expires_at_monotonic = None
                        # A continuation which is still pending has its own durable
                        # WAITING_APPROVAL parent. A future attempt must use a fresh
                        # request handle while presenting the same one-use approval.
                        current.continuation_request_id = None
                        self._pending_approvals.move_to_end(key)
                        return True
                    while len(self._pending_approvals) >= self._maximum_pending_approvals:
                        removable = next(
                            (
                                candidate
                                for candidate, pending in self._pending_approvals.items()
                                if not pending.in_flight
                            ),
                            None,
                        )
                        if removable is None:
                            return False
                        self._pending_approvals.pop(removable, None)
                    self._pending_approvals[key] = _PendingApproval(
                        approval_id=response.approval_id,
                        root_run_id=response.root_run_id,
                        expires_at_monotonic=now + self._approval_cache_ttl_seconds,
                    )
                    return True
        except TimeoutError:
            return False

    async def _release_pending_approval(
        self,
        *,
        key: str,
        claim: _ApprovalClaim,
        retain_for_ambiguous_result: bool,
    ) -> bool:
        try:
            async with asyncio.timeout(_APPROVAL_STATE_LOCK_TIMEOUT_SECONDS):
                async with self._approval_lock:
                    pending = self._pending_approvals.get(key)
                    if (
                        pending is None
                        or pending.claim_generation != claim.generation
                        or pending.approval_id != claim.approval_id
                        or pending.root_run_id != claim.root_run_id
                    ):
                        return True
                    if retain_for_ambiguous_result:
                        pending.in_flight = False
                        pending.claim_expires_at_monotonic = None
                        self._pending_approvals.move_to_end(key)
                    else:
                        self._pending_approvals.pop(key, None)
                    return True
        except TimeoutError:
            return False

    @staticmethod
    def _approval_cleanup_finished(task: asyncio.Task[bool]) -> None:
        if not task.cancelled():
            task.exception()

    async def _release_claim_after_interruption(
        self,
        *,
        key: str,
        claim: _ApprovalClaim,
    ) -> None:
        cleanup = asyncio.create_task(
            self._release_pending_approval(
                key=key,
                claim=claim,
                retain_for_ambiguous_result=True,
            ),
            name="gatehouse-mcp-approval-claim-cleanup",
        )
        cleanup.add_done_callback(self._approval_cleanup_finished)
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            return

    async def _active_root_run_ids(self) -> list[str] | None:
        try:
            async with asyncio.timeout(_APPROVAL_STATE_LOCK_TIMEOUT_SECONDS):
                async with self._approval_lock:
                    self._prune_pending_approvals_locked(now=self._monotonic())
                    result = [self._root_run_id]
                    for pending in self._pending_approvals.values():
                        if pending.root_run_id not in result:
                            result.append(pending.root_run_id)
                        if len(result) == 64:
                            break
                    return result
        except TimeoutError:
            return None

    async def _perform_readoption(self) -> _ReadoptionResult:
        try:
            status, exchange = await self._client.request(
                "POST",
                "/v1/sessions/exchange",
                payload={
                    "session_id": self._session_id,
                    "bootstrap_capability": self._bootstrap_capability,
                    "client_nonce": secrets.token_urlsafe(24),
                },
            )
        except _AgentClientError:
            return "daemon_degraded"
        if status != 200:
            if status not in {401, 403}:
                return "daemon_degraded"
            code = _response_error_code(exchange)
            if code in _TERMINAL_SESSION_ERRORS:
                return cast(_ReadoptionResult, code)
            return "invalid_session"
        access_token = exchange.get("access_token")
        token_type = exchange.get("token_type")
        returned_capabilities = exchange.get("capabilities")
        session = exchange.get("session")
        try:
            heartbeat_interval_ms = _validated_heartbeat_interval_ms(exchange)
        except _AgentClientError:
            return "daemon_degraded"
        if (
            not isinstance(access_token, str)
            or not 40 <= len(access_token) <= 512
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in access_token)
            or not isinstance(token_type, str)
            or token_type.casefold() != "bearer"
            or not isinstance(returned_capabilities, list)
            or any(not isinstance(item, str) for item in returned_capabilities)
            or not isinstance(session, dict)
            or session.get("session_id") != self._session_id
            or session.get("state") != "ACTIVE"
        ):
            return "daemon_degraded"
        self._access_token = access_token
        self._heartbeat_interval_ms = heartbeat_interval_ms
        self.capabilities = (
            frozenset(cast(list[str], returned_capabilities)) & _ROUTABLE_CAPABILITIES
        )
        return "adopted"

    def _readoption_finished(self, task: asyncio.Task[_ReadoptionResult]) -> None:
        current = self._readoption_inflight
        if current is not None and current[1] is task:
            self._readoption_inflight = None
        if not task.cancelled():
            task.exception()

    async def _readopt(self, *, expected_access_token: str) -> _ReadoptionResult:
        """Share one bounded exchange among callers holding the same stale token."""

        task: asyncio.Task[_ReadoptionResult]
        registered_waiter = False
        try:
            try:
                async with asyncio.timeout(_READOPTION_STATE_LOCK_TIMEOUT_SECONDS):
                    async with self._readoption_lock:
                        if self._access_token != expected_access_token:
                            return "adopted"
                        if self._readoption_waiters >= _MAXIMUM_READOPTION_WAITERS:
                            return "daemon_degraded"
                        current = self._readoption_inflight
                        if (
                            current is not None
                            and current[0] == expected_access_token
                            and not current[1].done()
                        ):
                            task = current[1]
                        else:
                            task = asyncio.create_task(
                                self._perform_readoption(),
                                name="gatehouse-mcp-session-readoption",
                            )
                            self._readoption_inflight = (expected_access_token, task)
                            task.add_done_callback(self._readoption_finished)
                        self._readoption_waiters += 1
                        registered_waiter = True
            except TimeoutError:
                return "daemon_degraded"

            try:
                async with asyncio.timeout(self._readoption_wait_seconds):
                    return await asyncio.shield(task)
            except TimeoutError:
                return "daemon_degraded"
        finally:
            if registered_waiter:
                self._readoption_waiters -= 1

    async def _authorized_request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
        query: Mapping[str, str] | None = None,
        allow_degraded_readiness: bool = False,
        required_capability: str | None = None,
    ) -> dict[str, JsonValue]:
        access_token = self._access_token
        try:
            status, body = await self._client.request(
                method,
                path,
                payload=payload,
                access_token=access_token,
                query=query,
            )
        except _AgentClientError:
            return _safe_error(
                code="daemon_degraded",
                message="The local Gatehouse agent request failed.",
                retryable=True,
                retry_after_seconds=1,
            )
        if status == 401:
            readoption = await self._readopt(expected_access_token=access_token)
            if readoption in _TERMINAL_SESSION_ERRORS:
                message = {
                    "invalid_session": "The controlled Gatehouse session could not be re-adopted.",
                    "session_expired": "The controlled Gatehouse session has expired.",
                    "session_revoked": "The controlled Gatehouse session has been revoked.",
                }[readoption]
                return _safe_error(
                    code=readoption,
                    message=message,
                    retryable=False,
                )
            if readoption == "daemon_degraded":
                return _safe_error(
                    code="daemon_degraded",
                    message="The controlled Gatehouse session could not be re-adopted yet.",
                    retryable=True,
                    retry_after_seconds=1,
                )
            if required_capability is not None and required_capability not in self.capabilities:
                return _safe_error(
                    code="policy_denied",
                    message="The re-adopted Gatehouse session no longer grants this capability.",
                    retryable=False,
                )
            try:
                status, body = await self._client.request(
                    method,
                    path,
                    payload=payload,
                    access_token=self._access_token,
                    query=query,
                )
            except _AgentClientError:
                return _safe_error(
                    code="daemon_degraded",
                    message="The local Gatehouse agent request failed.",
                    retryable=True,
                    retry_after_seconds=1,
                )
        if 200 <= status <= 299:
            return body
        if allow_degraded_readiness and status == 503 and isinstance(body.get("status"), str):
            return body
        if 400 <= status <= 599 and isinstance(body.get("error"), dict):
            return body
        return _safe_error(
            code="daemon_degraded",
            message="The local Gatehouse agent returned an invalid response.",
            retryable=True,
            retry_after_seconds=1,
        )

    async def maintain_session(self) -> dict[str, JsonValue]:
        """Heartbeat the exact adopted session/root and re-adopt after an epoch change."""

        active_root_runs = await self._active_root_run_ids()
        if active_root_runs is None:
            return _safe_error(
                code="daemon_degraded",
                message="The local approval continuation state is temporarily unavailable.",
                retryable=True,
                retry_after_seconds=1,
            )
        result = await self._authorized_request(
            "POST",
            "/v1/sessions/heartbeat",
            payload={
                "active_root_runs": cast(JsonValue, active_root_runs),
                "reported_agent_count": 1,
            },
        )
        if isinstance(result.get("error"), dict):
            return result
        if (
            result.get("status") != "active"
            or result.get("session_id") != self._session_id
            or result.get("reported_agent_count") != 1
        ):
            return _safe_error(
                code="daemon_degraded",
                message="The local Gatehouse session heartbeat returned an invalid response.",
                retryable=True,
                retry_after_seconds=1,
            )
        return result

    async def call(
        self,
        operation: str,
        payload: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> dict[str, JsonValue]:
        if operation == "gatehouse.status":
            return await self._authorized_request(
                "GET",
                "/health/ready",
                allow_degraded_readiness=True,
            )
        if operation == "gatehouse.capabilities":
            return {"capabilities": cast(JsonValue, sorted(self.capabilities))}
        if operation not in self.capabilities:
            return _safe_error(
                code="policy_denied",
                message="The adopted Gatehouse session did not grant this capability.",
                retryable=False,
            )
        if request_id is not None and operation != "firecrawl.crawl.start":
            return _safe_error(
                code="schema_validation_failed",
                message="A stable request handle is only valid for crawl creation.",
                retryable=False,
            )
        try:
            if operation.startswith("watcher."):
                feed_set_id = _required_identifier(payload, "feed_set_id")
                feed_path = quote(feed_set_id, safe="")
                if operation == "watcher.scan_feed_set":
                    cursor = payload.get("cursor")
                    if cursor is not None and (
                        not isinstance(cursor, str)
                        or not cursor
                        or len(cursor.encode("utf-8")) > MAX_CURSOR_BYTES
                    ):
                        raise _AgentClientError("cursor is invalid")
                    return await self._authorized_request(
                        "POST",
                        f"/v1/watcher/feed-sets/{feed_path}/scan",
                        payload={"root_run_id": self._root_run_id, "cursor": cursor},
                        required_capability=operation,
                    )
                if operation == "watcher.get_cursor":
                    return await self._authorized_request(
                        "GET",
                        f"/v1/watcher/feed-sets/{feed_path}/cursor",
                        query={"root_run_id": self._root_run_id},
                        required_capability=operation,
                    )
                if operation == "watcher.get_previous_summary":
                    return await self._authorized_request(
                        "GET",
                        f"/v1/watcher/feed-sets/{feed_path}/previous-summary",
                        query={"root_run_id": self._root_run_id},
                        required_capability=operation,
                    )
                if operation == "watcher.commit_cursor":
                    watcher_run_id = _required_identifier(payload, "watcher_run_id")
                    expected_version = payload.get("expected_version")
                    cursor_sequence = payload.get("cursor_sequence")
                    cursor_value = payload.get("cursor_value")
                    if (
                        isinstance(expected_version, bool)
                        or not isinstance(expected_version, int)
                        or expected_version < 0
                        or isinstance(cursor_sequence, bool)
                        or not isinstance(cursor_sequence, int)
                        or cursor_sequence < 0
                        or cursor_sequence > MAX_CURSOR_SEQUENCE
                        or not isinstance(cursor_value, str)
                        or not cursor_value
                        or len(cursor_value.encode("utf-8")) > MAX_CURSOR_BYTES
                    ):
                        raise _AgentClientError("watcher cursor commit is invalid")
                    return await self._authorized_request(
                        "POST",
                        f"/v1/watcher/feed-sets/{feed_path}/cursor/commit",
                        payload={
                            "root_run_id": self._root_run_id,
                            "watcher_run_id": watcher_run_id,
                            "expected_version": expected_version,
                            "cursor_value": cursor_value,
                            "cursor_sequence": cursor_sequence,
                        },
                        required_capability=operation,
                    )
            if operation.startswith("firecrawl."):
                approval_key = _approval_request_key(
                    cache_key=self._approval_cache_key,
                    session_id=self._session_id,
                    root_run_id=self._root_run_id,
                    operation=operation,
                    payload=payload,
                    caller_request_id=request_id,
                )
                claim_state, claim = await self._claim_pending_approval(
                    key=approval_key,
                    operation=operation,
                )
                if claim_state == "busy":
                    return _approval_continuation_in_progress()
                if claim_state == "degraded":
                    return _safe_error(
                        code="daemon_degraded",
                        message="The local approval continuation state is temporarily unavailable.",
                        retryable=True,
                        retry_after_seconds=1,
                    )
                claim_finalized = claim is None
                try:
                    continuation_root_run_id = (
                        self._root_run_id if claim is None else claim.root_run_id
                    )
                    invocation: dict[str, JsonValue] = {
                        "service": "firecrawl",
                        "operation": operation.removeprefix("firecrawl."),
                        "input": dict(payload),
                        "context": {"root_run_id": continuation_root_run_id},
                        "execution": {
                            "wait_up_to_ms": 15_000,
                            "allow_cached_result": True,
                        },
                    }
                    if claim is not None:
                        invocation["approval_id"] = claim.approval_id
                    stable_request_id: RequestId | None = None
                    if operation == "firecrawl.crawl.start":
                        try:
                            stable_request_id = (
                                RequestId(claim.continuation_request_id)
                                if claim is not None and claim.continuation_request_id is not None
                                else (
                                    RequestId.new() if request_id is None else RequestId(request_id)
                                )
                            )
                        except (TypeError, ValueError) as error:
                            raise _AgentClientError("request_id is invalid") from error
                        invocation["request_id"] = str(stable_request_id)
                    result = await self._authorized_request(
                        "POST",
                        "/v1/invocations",
                        payload=invocation,
                        required_capability=operation,
                    )
                    if stable_request_id is not None:
                        result = _bind_request_result(
                            result,
                            request_id=stable_request_id,
                        )
                    pending_response = _pending_approval_response(
                        result,
                        default_root_run_id=continuation_root_run_id,
                    )
                    if pending_response is not None:
                        remembered = await self._remember_pending_approval(
                            key=approval_key,
                            response=pending_response,
                            claim=claim,
                        )
                        claim_finalized = claim is None or remembered
                        if claim is not None and not remembered:
                            return _safe_error(
                                code="daemon_degraded",
                                message="The local approval continuation response was invalid.",
                                retryable=True,
                                retry_after_seconds=1,
                            )
                        return result
                    if _response_error_code(result) == "approval_pending":
                        if claim is not None:
                            claim_finalized = await self._release_pending_approval(
                                key=approval_key,
                                claim=claim,
                                retain_for_ambiguous_result=False,
                            )
                        return _safe_error(
                            code="daemon_degraded",
                            message="The local approval continuation response was invalid.",
                            retryable=True,
                            retry_after_seconds=1,
                        )
                    if claim is not None:
                        claim_finalized = await self._release_pending_approval(
                            key=approval_key,
                            claim=claim,
                            retain_for_ambiguous_result=(
                                _response_error_code(result) == "daemon_degraded"
                            ),
                        )
                    return result
                finally:
                    if claim is not None and not claim_finalized:
                        await self._release_claim_after_interruption(
                            key=approval_key,
                            claim=claim,
                        )
            if operation == "jobs.status":
                job_id = _required_identifier(payload, "job_id")
                return await self._authorized_request(
                    "GET",
                    f"/v1/jobs/{quote(job_id, safe='')}",
                    query={"root_run_id": self._root_run_id},
                    required_capability=operation,
                )
            if operation == "jobs.await":
                job_id = _required_identifier(payload, "job_id")
                return await self._authorized_request(
                    "POST",
                    f"/v1/jobs/{quote(job_id, safe='')}/await",
                    payload={
                        "root_run_id": self._root_run_id,
                        "maximum_wait_ms": _required_wait(payload),
                    },
                    required_capability=operation,
                )
            if operation == "jobs.cancel":
                job_id = _required_identifier(payload, "job_id")
                return await self._authorized_request(
                    "POST",
                    f"/v1/jobs/{quote(job_id, safe='')}/cancel",
                    payload={"root_run_id": self._root_run_id},
                    required_capability=operation,
                )
            if operation == "docs.search":
                return await self._authorized_request(
                    "POST",
                    "/v1/docs/search",
                    payload=payload,
                    required_capability=operation,
                )
            if operation == "docs.get":
                service = _required_identifier(payload, "service")
                document = _required_identifier(payload, "document")
                return await self._authorized_request(
                    "GET",
                    f"/v1/docs/{quote(service, safe='')}/{quote(document, safe='')}",
                    required_capability=operation,
                )
            if operation == "feedback.submit":
                return await self._authorized_request(
                    "POST",
                    "/v1/feedback",
                    payload=payload,
                    required_capability=operation,
                )
        except _AgentClientError:
            return _safe_error(
                code="schema_validation_failed",
                message="The MCP tool arguments are invalid.",
                retryable=False,
            )
        return _safe_error(
            code="schema_validation_failed",
            message="The MCP operation is not routable.",
            retryable=False,
        )
