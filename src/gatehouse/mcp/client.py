"""Bounded loopback HTTP client used by the stock MCP entry point."""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
from collections.abc import Callable, Mapping, MutableMapping
from typing import Literal, cast
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from gatehouse.core.errors import JsonValue
from gatehouse.core.ids import RequestId

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


def _validated_agent_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise McpStartupError("Gatehouse agent URL is invalid.") from error
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
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
    host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
    return urlunsplit(("http", f"{host}:{port}", "", "", ""))


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
    def _encoded_body(payload: Mapping[str, JsonValue] | None) -> bytes | None:
        if payload is None:
            return None
        try:
            return json.dumps(
                dict(payload),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
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
        encoded = self._encoded_body(payload)
        if encoded is not None and len(encoded) > self._maximum_request_bytes:
            raise _AgentClientError("request body exceeds the configured limit")
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        if access_token is not None:
            headers["Authorization"] = f"Bearer {access_token}"

        try:
            async with asyncio.timeout(self._timeout_seconds):
                async with self._client() as client:
                    async with client.stream(
                        method,
                        path,
                        content=encoded,
                        headers=headers,
                        params=query,
                    ) as response:
                        length = response.headers.get("content-length")
                        if length is not None:
                            try:
                                declared_length = int(length)
                            except ValueError as error:
                                raise _AgentClientError(
                                    "response content length is invalid"
                                ) from error
                            if (
                                declared_length < 0
                                or declared_length > self._maximum_response_bytes
                            ):
                                raise _AgentClientError(
                                    "response body exceeds the configured limit"
                                )
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            content.extend(chunk)
                            if len(content) > self._maximum_response_bytes:
                                raise _AgentClientError(
                                    "response body exceeds the configured limit"
                                )
                        content_type = response.headers.get("content-type", "")
                        if content_type.partition(";")[0].strip().casefold() != "application/json":
                            raise _AgentClientError("response is not JSON")
                        try:
                            decoded = json.loads(content.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as error:
                            raise _AgentClientError("response JSON is invalid") from error
                        if not isinstance(decoded, dict) or any(
                            not isinstance(key, str) for key in decoded
                        ):
                            raise _AgentClientError("response JSON root is not an object")
                        return response.status_code, cast(dict[str, JsonValue], decoded)
        except (httpx.HTTPError, TimeoutError) as error:
            raise _AgentClientError("Gatehouse agent request failed") from error


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
        "_bootstrap_capability",
        "_client",
        "_heartbeat_interval_ms",
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
    ) -> None:
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

    @property
    def session_heartbeat_interval_seconds(self) -> float:
        return self._heartbeat_interval_ms / 1_000

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
        )

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

        result = await self._authorized_request(
            "POST",
            "/v1/sessions/heartbeat",
            payload={
                "active_root_runs": [self._root_run_id],
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
            if operation.startswith("firecrawl."):
                invocation: dict[str, JsonValue] = {
                    "service": "firecrawl",
                    "operation": operation.removeprefix("firecrawl."),
                    "input": dict(payload),
                    "context": {"root_run_id": self._root_run_id},
                    "execution": {
                        "wait_up_to_ms": 15_000,
                        "allow_cached_result": True,
                    },
                }
                stable_request_id: RequestId | None = None
                if operation == "firecrawl.crawl.start":
                    try:
                        stable_request_id = (
                            RequestId.new() if request_id is None else RequestId(request_id)
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
                    return _bind_request_result(
                        result,
                        request_id=stable_request_id,
                    )
                return result
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
