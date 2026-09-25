"""Production loopback clients and process adapters for the installed CLI."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Concatenate, Never, Protocol, cast
from urllib.parse import quote

import httpx

from gatehouse.admin.control import (
    CONTROL_CAPABILITY_HEADER,
    CONTROL_CONFIG_DIGEST_HEADER,
    ControlWorkloadReadiness,
    canonical_existing_directory,
)
from gatehouse.admin.control_capability import (
    ControlCapabilityStorageError,
    load_control_capability,
)
from gatehouse.admin.models import (
    AccountAddRequest,
    AccountMutationResult,
    AccountObservationChangeRequest,
    AccountObservationMutationResult,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    AccountStatus,
    ApprovalView,
    CredentialMutationResult,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    CredentialSummary,
    CredentialValidationRequest,
    CredentialValidationResult,
    EmergencyUnlockCancelRequest,
    EmergencyUnlockRequest,
    EmergencyUnlockView,
    PoolFailoverChangeRequest,
    PoolFailoverMutationResult,
)
from gatehouse.api.admin import (
    ADMIN_COOKIE_NAME,
    COMMAND_HEADER_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    MAXIMUM_COMMAND_BYTES,
    MAXIMUM_SECRET_BYTES,
)
from gatehouse.api.contracts import PolicyExplainRequest, PolicyExplainResponse
from gatehouse.config import ConfigLoadError
from gatehouse.config.security import ConfigSecurityError
from gatehouse.core.errors import JsonValue
from gatehouse.credentials.validation import is_admissible_firecrawl_secret
from gatehouse.daemon.composition import installation_state_paths
from gatehouse.daemon.configuration import (
    load_runtime_configuration,
    require_configuration_snapshot_digest,
    validate_expected_config_digest,
)
from gatehouse.daemon.main import default_config_path
from gatehouse.daemon_executable import select_adjacent_daemon_path
from gatehouse.sessions import build_long_lived_environment

from .contracts import CliUnavailable, ControlledLaunch
from .operator import (
    OperatorCommandError,
    create_support_bundle,
    diagnose_installation,
    initialize_configuration,
    validate_configuration,
)

_MAXIMUM_REQUEST_BYTES = 64 * 1_024
_MAXIMUM_RESPONSE_BYTES = 4 * 1_024 * 1_024
_DEFAULT_TIMEOUT_SECONDS = 35.0
_OWNED_DAEMON_STOP_TIMEOUT_SECONDS = 1.0
_OWNED_SESSION_CLEANUP_TIMEOUT_SECONDS = 1.0
_SESSION_CLEANUP_PENDING = "controlled session cleanup is pending"
_SESSION_CREATION_INDETERMINATE = (
    "controlled session creation is indeterminate; further session creation is blocked"
)
_SUPPRESS_BINARY_HTTP_LOGS: ContextVar[bool] = ContextVar(
    "gatehouse_suppress_binary_http_logs",
    default=False,
)


class _BinaryHttpLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        del record
        return not _SUPPRESS_BINARY_HTTP_LOGS.get()


_BINARY_HTTP_LOG_FILTER = _BinaryHttpLogFilter()
for _logger_name in (
    "httpx",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
):
    logging.getLogger(_logger_name).addFilter(_BINARY_HTTP_LOG_FILTER)

_CONTROL_CAPABILITY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_APPROVAL_PUBLIC_FIELDS = (
    "approval_id",
    "session_id",
    "client_id",
    "workspace_id",
    "service",
    "operation",
    "request_fingerprint",
    "target_summary",
    "pool",
    "maximum_estimated_cost",
    "maximum_uses",
    "expires_at_ms",
    "state",
)
_CREDENTIAL_RESULT_FIELDS = frozenset(
    {
        "mutation_id",
        "credential_id",
        "action",
        "state",
        "generation",
        "alias",
        "principal_id",
        "principal_alias",
        "quota_scope_id",
        "quota_scope_alias",
        "pool_id",
        "pool_alias",
        "expires_at_ms",
        "acted_at_ms",
        "audit_event_id",
    }
)
_ACCOUNT_RESULT_FIELDS = frozenset(
    {
        "alias",
        "action",
        "state",
        "pool_alias",
        "priority",
        "generation",
        "acted_at_ms",
        "audit_event_id",
    }
)
_ACCOUNT_STATUS_FIELDS = frozenset(
    {
        "alias",
        "state",
        "remaining_decimal",
        "plan_decimal",
        "unit",
        "observed_at_ms",
        "staleness_ms",
        "stale",
        "source",
    }
)
_ACCOUNT_OBSERVATION_RESULT_FIELDS = frozenset(
    {
        "alias",
        "action",
        "enabled",
        "acted_at_ms",
        "audit_event_id",
    }
)
_CREDENTIAL_VALIDATION_RESULT_FIELDS = frozenset(
    {
        "credential_id",
        "generation",
        "service",
        "principal_id",
        "quota_scope_id",
        "state",
        "snapshot_id",
        "unit",
        "remaining_units",
        "plan_total_units",
        "observed_remaining_units_decimal",
        "observed_plan_total_units_decimal",
        "captured_at_ms",
        "audit_event_id",
    }
)
_EMERGENCY_RESULT_FIELDS = frozenset(
    {
        "mutation_id",
        "unlock_id",
        "credential_id",
        "action",
        "state",
        "generation",
        "service",
        "alias",
        "principal_id",
        "principal_alias",
        "quota_scope_id",
        "quota_scope_alias",
        "pool_id",
        "pool_alias",
        "session_id",
        "root_run_id",
        "expires_at_ms",
        "remaining_requests",
        "remaining_credits",
        "remaining_concurrency",
        "acted_at_ms",
        "audit_event_id",
    }
)
_POLICY_OPERATION_CAPABILITIES = MappingProxyType(
    {
        "search": "firecrawl.search",
        "scrape": "firecrawl.scrape",
        "map": "firecrawl.map",
        "crawl": "firecrawl.crawl.start",
    }
)

type TransportFactory = Callable[[], httpx.BaseTransport]
type CapabilityLoader = Callable[[Path], str]
type JsonObject = dict[str, JsonValue]


class _LoopbackRequestError(RuntimeError):
    """Internal sanitized transport/protocol failure."""


class DaemonChild(Protocol):
    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float) -> int: ...


class DaemonProcessRunner(Protocol):
    def run(self, arguments: Sequence[str]) -> int: ...

    def start(self, arguments: Sequence[str]) -> DaemonChild: ...


class NativeDaemonProcessRunner:
    """Start the installed daemon without a shell or inherited console handles."""

    def __init__(self, *, environment: Mapping[str, str] | None = None) -> None:
        source = os.environ if environment is None else environment
        self._environment = MappingProxyType(build_long_lived_environment(source))

    def run(self, arguments: Sequence[str]) -> int:
        try:
            completed = subprocess.run(  # noqa: S603
                tuple(arguments),
                check=False,
                env=dict(self._environment),
            )
        except OSError as error:
            raise CliUnavailable("the installed Gatehouse daemon could not be started") from error
        return completed.returncode

    def start(self, arguments: Sequence[str]) -> DaemonChild:
        try:
            if os.name == "nt":
                return subprocess.Popen(  # noqa: S603
                    tuple(arguments),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=dict(self._environment),
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        | subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP
                    ),
                )
            return subprocess.Popen(  # noqa: S603
                tuple(arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(self._environment),
                start_new_session=True,
            )
        except OSError as error:
            raise CliUnavailable("the installed Gatehouse daemon could not be started") from error


class NativeProcessRunner:
    """Run one explicitly requested controlled child without shell interpretation."""

    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int:
        try:
            working_directory = canonical_existing_directory(launch.working_directory)
            if working_directory != launch.working_directory:
                raise CliUnavailable(
                    "the controlled client working directory changed before launch"
                )
            completed = subprocess.run(  # noqa: S603
                launch.argv,
                env=dict(environment),
                cwd=working_directory,
                check=False,
            )
        except ValueError as error:
            raise CliUnavailable(
                "the controlled client working directory is unavailable"
            ) from error
        except OSError as error:
            raise CliUnavailable("the controlled client process could not be started") from error
        return completed.returncode


@dataclass(frozen=True, slots=True)
class _LocalSettings:
    config_path: Path
    database_path: Path
    agent_url: str
    admin_url: str
    readiness_timeout_seconds: float
    config_digest: str
    allow_provider_disabled_state: bool


@dataclass(slots=True)
class _ConfigurationOperation:
    settings: _LocalSettings | None = None
    control_capability: str | None = field(default=None, repr=False)
    request_deadline: float | None = None


@dataclass(frozen=True, slots=True, repr=False)
class _OwnedControlledLaunch:
    session_id: str | None
    settings: _LocalSettings
    control_capability: str = field(repr=False)
    request_id: str
    launch: ControlledLaunch | None = None


class _DeferredSessionResponseStream(httpx.SyncByteStream):
    """Let HTTPX finish decoding before closing one session-mint stream."""

    def __init__(self, original: httpx.SyncByteStream) -> None:
        self._original = original
        self._original_closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self._original

    def close(self) -> None:
        # Response.iter_raw closes at EOF. Ownership must be recorded first.
        pass

    def close_original(self) -> None:
        if not self._original_closed:
            self._original_closed = True
            self._original.close()


def _configuration_operation[**P, R](
    method: Callable[Concatenate[LocalCliBackend, P], R],
) -> Callable[Concatenate[LocalCliBackend, P], R]:
    @wraps(method)
    def scoped(self: LocalCliBackend, /, *args: P.args, **kwargs: P.kwargs) -> R:
        # Capture lazily inside the method's existing cleanup boundary, including
        # secret-buffer cleanup. Only one invocation retains settings/capability.
        token = self._configuration_context.set(_ConfigurationOperation())
        try:
            return method(self, *args, **kwargs)
        finally:
            self._configuration_context.reset(token)

    return scoped


def _scrub_httpx_request(request: httpx.Request, *, scrub_target: bool = False) -> None:
    with suppress(Exception):
        request.headers.clear()
    if scrub_target:
        with suppress(Exception):
            request.method = ""
        with suppress(Exception):
            request.url = httpx.URL("")
    with suppress(Exception):
        request.stream = httpx.ByteStream(b"")
    with suppress(Exception):
        request._content = b""
    if scrub_target:
        with suppress(Exception):
            request.extensions.clear()


def _scrub_httpx_stream(stream: object) -> None:
    """Drop byte-bearing state from a detached, already-closed stream graph."""

    pending = [stream]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        state = getattr(current, "__dict__", None)
        if not isinstance(state, dict):
            continue
        for name, value in tuple(state.items()):
            if isinstance(value, bytearray):
                value[:] = b"\x00" * len(value)
                with suppress(Exception):
                    setattr(current, name, bytearray())
            elif isinstance(value, bytes):
                with suppress(Exception):
                    setattr(current, name, b"")
            elif isinstance(value, memoryview):
                if not value.readonly:
                    with suppress(Exception):
                        value[:] = b"\x00" * len(value)
                with suppress(Exception):
                    setattr(current, name, memoryview(b""))
            elif name == "_stream":
                pending.append(value)
                with suppress(Exception):
                    setattr(current, name, httpx.ByteStream(b""))


def _scrub_httpx_response(
    response: httpx.Response,
    *,
    scrub_target: bool = True,
) -> None:
    try:
        response_request = response.request
    except RuntimeError:
        response_request = None
    if response_request is not None:
        _scrub_httpx_request(response_request, scrub_target=scrub_target)
    with suppress(Exception):
        response.headers.clear()
    with suppress(Exception):
        response.extensions.clear()
    with suppress(Exception):
        response.stream = httpx.ByteStream(b"")
    with suppress(Exception):
        response._content = b""


def _close_and_scrub_binary_response(
    response: httpx.Response,
    original_stream: object,
) -> str | None:
    """Detach first, close exactly once, and return only a safe failure class."""

    stream_was_closed = response.is_closed
    _scrub_httpx_response(response)
    failure: str | None = None
    try:
        if not stream_was_closed:
            response.is_closed = True
            close = getattr(original_stream, "close", None)
            if not callable(close):
                failure = "failure"
            else:
                try:
                    close()
                except asyncio.CancelledError:
                    failure = "cancelled"
                except KeyboardInterrupt:
                    failure = "keyboard_interrupt"
                except SystemExit:
                    failure = "system_exit"
                except BaseException:
                    failure = "failure"
    finally:
        _scrub_httpx_stream(original_stream)
    return failure


def _scrub_httpx_error(error: httpx.HTTPError, *, scrub_target: bool = False) -> None:
    try:
        request = error.request
    except RuntimeError:
        request = None
    if request is not None:
        _scrub_httpx_request(request, scrub_target=scrub_target)
    response = getattr(error, "response", None)
    if isinstance(response, httpx.Response):
        try:
            response_request = response.request
        except RuntimeError:
            response_request = None
        if response_request is not None:
            _scrub_httpx_request(response_request, scrub_target=scrub_target)
        _scrub_httpx_response(response, scrub_target=scrub_target)


def _text_contains_secret(value: str, secret: bytearray) -> bool:
    encoded = bytearray(value, "utf-8", "surrogatepass")
    try:
        return encoded.find(secret) >= 0
    finally:
        encoded[:] = b"\x00" * len(encoded)


def _headers_contain_secret(headers: httpx.Headers, secret: bytearray) -> bool:
    return any(name.find(secret) >= 0 or value.find(secret) >= 0 for name, value in headers.raw)


def _response_extensions_contain_secret(response: httpx.Response, secret: bytearray) -> bool:
    for name, value in response.extensions.items():
        candidates: tuple[object, ...] = (name, value)
        for candidate in candidates:
            if isinstance(candidate, str) and _text_contains_secret(candidate, secret):
                return True
            if (
                isinstance(candidate, (bytes, bytearray, memoryview))
                and bytes(candidate).find(secret) >= 0
            ):
                return True
    return False


def _cookies_contain_secret(cookies: httpx.Cookies, secret: bytearray) -> bool:
    for cookie in cookies.jar:
        for attribute in ("name", "value", "domain", "path", "port", "comment", "comment_url"):
            value = getattr(cookie, attribute, None)
            if isinstance(value, str) and _text_contains_secret(value, secret):
                return True
    return False


def _request_nonbody_contains_secret(request: httpx.Request, secret: bytearray) -> bool:
    """Exact-check the serialized request surfaces outside the authorized body."""

    if not secret:
        return False
    method = bytearray(request.method.encode("ascii", "strict"))
    url = bytearray(str(request.url).encode("utf-8", "surrogatepass"))
    try:
        if method.find(secret) >= 0 or url.find(secret) >= 0:
            return True
        return any(
            name.find(secret) >= 0 or value.find(secret) >= 0 for name, value in request.headers.raw
        )
    finally:
        method[:] = b"\x00" * len(method)
        url[:] = b"\x00" * len(url)


def _json_contains_secret(value: object, secret: bytearray) -> bool:
    """Find an exact active secret in decoded JSON keys or string leaves."""

    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if _text_contains_secret(current, secret):
                return True
        elif isinstance(current, dict):
            pending.extend(current)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return False


class _BoundedJsonClient:
    """Small synchronous JSON client with fixed local-only transport policy."""

    __slots__ = (
        "_client",
        "_maximum_request_bytes",
        "_maximum_response_bytes",
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
        if not 0 < timeout_seconds <= 60:
            raise ValueError("CLI HTTP timeout must be between zero and 60 seconds")
        if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
            raise ValueError("CLI HTTP body limits must be positive")
        transport = transport_factory() if transport_factory is not None else None
        self._client = httpx.Client(
            base_url=base_url,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
            transport=transport,
        )
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes

    @property
    def cookies(self) -> httpx.Cookies:
        return self._client.cookies

    def __enter__(self) -> _BoundedJsonClient:
        self._client.__enter__()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._client.__exit__(exception_type, exception, traceback)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
        binary: bytearray | None = None,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        before_session_dispatch: Callable[[], None] | None = None,
        observe_session_response: Callable[[int, JsonObject], None] | None = None,
    ) -> tuple[int, JsonObject]:
        session_request = (
            before_session_dispatch is not None or observe_session_response is not None
        )
        encoded: bytes | Iterable[bytes] | None = None
        request_headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        content = bytearray()
        result: tuple[int, JsonObject] | None = None
        pending_result: tuple[int, JsonObject] | None = None
        failure_message: str | None = None
        control_failure: str | None = None
        request: httpx.Request | None = None
        response: httpx.Response | None = None
        original_response_stream: object | None = None
        deferred_session_stream: _DeferredSessionResponseStream | None = None
        decoded: object | None = None
        try:
            if session_request and (
                method != "POST"
                or path != "/v2/control/sessions"
                or payload is None
                or binary is not None
                or query is not None
                or not callable(before_session_dispatch)
                or not callable(observe_session_response)
            ):
                raise _LoopbackRequestError("session response observation is invalid")
            if payload is not None and binary is not None:
                raise _LoopbackRequestError("request body mode is ambiguous")
            if payload is not None:
                encoding_failed = False
                try:
                    encoded = json.dumps(
                        dict(payload),
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                except (TypeError, ValueError):
                    encoding_failed = True
                if encoding_failed or not isinstance(encoded, bytes):
                    raise _LoopbackRequestError("request body is not valid JSON")
                if len(encoded) > self._maximum_request_bytes:
                    raise _LoopbackRequestError("request body exceeds the configured limit")
                request_headers["Content-Type"] = "application/json"
            elif binary is not None:
                if not binary or len(binary) > self._maximum_request_bytes:
                    raise _LoopbackRequestError("request body exceeds the configured limit")
                if not is_admissible_firecrawl_secret(
                    binary,
                    maximum_bytes=min(self._maximum_request_bytes, MAXIMUM_SECRET_BYTES),
                ):
                    raise _LoopbackRequestError("credential format is not accepted")
                encoded = (cast(bytes, memoryview(binary).toreadonly()),)
                request_headers["Content-Type"] = "application/octet-stream"
                request_headers["Content-Length"] = str(len(binary))
            if headers is not None:
                request_headers.update(headers)

            # Retain the exact request object before transport dispatch.  A
            # transport may raise any BaseException after materializing its body
            # and authority headers, so response.request is not a sufficient
            # cleanup handle.
            request = self._client.build_request(
                method,
                path,
                content=encoded,
                headers=request_headers,
                params=query,
            )
            if binary is not None and _request_nonbody_contains_secret(request, binary):
                raise _LoopbackRequestError(
                    "credential request metadata overlaps credential material"
                )
            log_token = _SUPPRESS_BINARY_HTTP_LOGS.set(binary is not None)
            try:
                if before_session_dispatch is not None:
                    before_session_dispatch()
                response = self._client.send(
                    request,
                    stream=True,
                    follow_redirects=False,
                )
            finally:
                _SUPPRESS_BINARY_HTTP_LOGS.reset(log_token)
            if session_request and not response.is_closed:
                if not isinstance(response.stream, httpx.SyncByteStream):
                    raise _LoopbackRequestError("session response stream is invalid")
                deferred_session_stream = _DeferredSessionResponseStream(response.stream)
                response.stream = deferred_session_stream
            if binary is not None:
                original_response_stream = response.stream
                reflected_header = _headers_contain_secret(response.headers, binary)
                reflected_extension = _response_extensions_contain_secret(response, binary)
                reflected_cookie = _cookies_contain_secret(self._client.cookies, binary)
                sets_cookie = bool(response.headers.get_list("set-cookie"))
                if reflected_header or reflected_extension or reflected_cookie or sets_cookie:
                    raise _LoopbackRequestError("credential endpoint response headers are invalid")
            declared = response.headers.get("content-length")
            if declared is not None:
                declared_length: int | None = None
                try:
                    declared_length = int(declared)
                except ValueError:
                    pass
                if declared_length is None:
                    raise _LoopbackRequestError("response content length is invalid")
                if not 0 <= declared_length <= self._maximum_response_bytes:
                    raise _LoopbackRequestError("response body exceeds the configured limit")
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) > self._maximum_response_bytes:
                    raise _LoopbackRequestError("response body exceeds the configured limit")
            if binary is not None and content.find(binary) >= 0:
                raise _LoopbackRequestError("response contains credential material")
            content_type = response.headers.get("content-type", "")
            if content_type.partition(";")[0].strip().casefold() != "application/json":
                raise _LoopbackRequestError("response is not JSON")
            decoded_json = True
            try:
                decoded = json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded_json = False
            if not decoded_json:
                raise _LoopbackRequestError("response JSON is invalid")
            if binary is not None and _json_contains_secret(decoded, binary):
                raise _LoopbackRequestError("response contains credential material")
            if not isinstance(decoded, dict) or any(not isinstance(key, str) for key in decoded):
                raise _LoopbackRequestError("response JSON root is not an object")
            pending_result = response.status_code, cast(JsonObject, decoded)
            if observe_session_response is not None:
                observe_session_response(*pending_result)
            result = pending_result
        except _LoopbackRequestError as error:
            failure_message = str(error)
        except httpx.HTTPError as error:
            _scrub_httpx_error(error, scrub_target=binary is not None)
            failure_message = "loopback request failed"
        except Exception:
            failure_message = "loopback request failed"
        except asyncio.CancelledError:
            if binary is None and not session_request:
                raise
            control_failure = "cancelled"
        except KeyboardInterrupt:
            if binary is None and not session_request:
                raise
            control_failure = "keyboard_interrupt"
        except SystemExit:
            if binary is None and not session_request:
                raise
            control_failure = "system_exit"
        except BaseException:
            if binary is None and not session_request:
                raise
            control_failure = "failure"
        finally:
            try:
                if response is not None:
                    if binary is not None and original_response_stream is not None:
                        cleanup_failure = _close_and_scrub_binary_response(
                            response,
                            original_response_stream,
                        )
                        if cleanup_failure is not None and control_failure is None:
                            control_failure = cleanup_failure
                    else:
                        try:
                            try:
                                response.close()
                            finally:
                                if deferred_session_stream is not None:
                                    deferred_session_stream.close_original()
                        except asyncio.CancelledError:
                            if not session_request:
                                raise
                            control_failure = control_failure or "cancelled"
                        except KeyboardInterrupt:
                            if not session_request:
                                raise
                            control_failure = control_failure or "keyboard_interrupt"
                        except SystemExit:
                            if not session_request:
                                raise
                            control_failure = control_failure or "system_exit"
                        except BaseException:
                            if not session_request:
                                raise
                            control_failure = control_failure or "failure"
            finally:
                if request is not None:
                    _scrub_httpx_request(request, scrub_target=binary is not None)
                if binary is not None and (
                    failure_message is not None or control_failure is not None
                ):
                    with suppress(Exception):
                        self._client.cookies.clear()
                if binary is not None:
                    _zero_secret(binary)
                request_headers.clear()
                encoded = None
                payload = None
                headers = None
                query = None
                binary = None
                original_response_stream = None
                content[:] = b"\x00" * len(content)
                if result is None:
                    if isinstance(decoded, (dict, list)):
                        decoded.clear()
                    decoded = None
        if control_failure == "cancelled":
            raise asyncio.CancelledError(
                "session loopback request interrupted"
                if session_request
                else "credential loopback request interrupted"
            ) from None
        if control_failure == "keyboard_interrupt":
            raise KeyboardInterrupt(
                "session loopback request interrupted"
                if session_request
                else "credential loopback request interrupted"
            ) from None
        if control_failure == "system_exit":
            raise SystemExit(1) from None
        if control_failure is not None:
            raise CliUnavailable(
                "the session loopback request failed"
                if session_request
                else "the credential loopback request failed"
            ) from None
        if failure_message is not None:
            with suppress(Exception):
                self._client.cookies.clear()
            for name in tuple(self._client.headers):
                if name.casefold() in {"authorization", "cookie"} or name.casefold().startswith(
                    "x-gatehouse-"
                ):
                    with suppress(KeyError):
                        del self._client.headers[name]
            raise _LoopbackRequestError(failure_message)
        if result is None:
            raise _LoopbackRequestError("loopback request failed")
        return result


def _required_identifier(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise _LoopbackRequestError(f"{label} is invalid")
    return value


def _required_string(
    value: object,
    *,
    label: str,
    minimum: int = 1,
    maximum: int = 1_000,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise _LoopbackRequestError(f"{label} is invalid")
    return value


def _required_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _LoopbackRequestError(f"{label} is invalid")
    return value


def _success(
    result: tuple[int, JsonObject],
    *,
    expected: frozenset[int] = frozenset({200}),
    action: str,
) -> JsonObject:
    status, body = result
    if status not in expected:
        raise _LoopbackRequestError(f"{action} was rejected")
    return body


def _command_header(command: Mapping[str, JsonValue]) -> str:
    encoded: str | None = None
    try:
        encoded = json.dumps(
            dict(command),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        pass
    if encoded is None:
        raise _LoopbackRequestError("admin command metadata is invalid")
    if not encoded or len(encoded.encode("utf-8")) > MAXIMUM_COMMAND_BYTES:
        raise _LoopbackRequestError("admin command metadata exceeds the configured limit")
    return encoded


def _credential_result(
    body: JsonObject,
    *,
    mutation_id: str,
    action: str,
    credential_id: str | None = None,
) -> JsonObject:
    if set(body) != _CREDENTIAL_RESULT_FIELDS:
        body.clear()
        raise _LoopbackRequestError("credential mutation response is invalid")
    result: CredentialMutationResult | None = None
    try:
        result = CredentialMutationResult.model_validate(body)
    except (TypeError, ValueError):
        pass
    if result is None:
        body.clear()
        raise _LoopbackRequestError("credential mutation response is invalid")
    if (
        result.mutation_id != mutation_id
        or result.action != action
        or (credential_id is not None and result.credential_id != credential_id)
    ):
        body.clear()
        raise _LoopbackRequestError("credential mutation response does not match request")
    dumped = result.model_dump(mode="json")
    body.clear()
    return {name: cast(JsonValue, dumped[name]) for name in _CREDENTIAL_RESULT_FIELDS}


def _account_result(
    body: JsonObject,
    *,
    alias: str,
    action: str,
) -> JsonObject:
    if set(body) != _ACCOUNT_RESULT_FIELDS:
        body.clear()
        raise _LoopbackRequestError("account mutation response is invalid")
    result: AccountMutationResult | None = None
    try:
        result = AccountMutationResult.model_validate(body)
    except (TypeError, ValueError):
        pass
    if result is None:
        body.clear()
        raise _LoopbackRequestError("account mutation response is invalid")
    if result.alias != alias or result.action != action:
        body.clear()
        raise _LoopbackRequestError("account mutation response does not match request")
    dumped = result.model_dump(mode="json")
    body.clear()
    return {name: cast(JsonValue, dumped[name]) for name in _ACCOUNT_RESULT_FIELDS}


def _account_status(body: JsonObject, *, alias: str | None = None) -> JsonObject:
    if set(body) != _ACCOUNT_STATUS_FIELDS:
        body.clear()
        raise _LoopbackRequestError("account status response is invalid")
    result: AccountStatus | None = None
    try:
        result = AccountStatus.model_validate(body)
    except (TypeError, ValueError):
        pass
    if result is None:
        body.clear()
        raise _LoopbackRequestError("account status response is invalid")
    if alias is not None and result.alias != alias:
        body.clear()
        raise _LoopbackRequestError("account status response does not match request")
    dumped = result.model_dump(mode="json")
    body.clear()
    return {name: cast(JsonValue, dumped[name]) for name in _ACCOUNT_STATUS_FIELDS}


def _account_observation_result(
    body: JsonObject,
    *,
    alias: str,
    action: str,
) -> JsonObject:
    if set(body) != _ACCOUNT_OBSERVATION_RESULT_FIELDS:
        body.clear()
        raise _LoopbackRequestError("account observation response is invalid")
    result: AccountObservationMutationResult | None = None
    try:
        result = AccountObservationMutationResult.model_validate(body)
    except (TypeError, ValueError):
        pass
    if result is None:
        body.clear()
        raise _LoopbackRequestError("account observation response is invalid")
    if result.alias != alias or result.action != action:
        body.clear()
        raise _LoopbackRequestError("account observation response does not match request")
    dumped = result.model_dump(mode="json")
    body.clear()
    return {name: cast(JsonValue, dumped[name]) for name in _ACCOUNT_OBSERVATION_RESULT_FIELDS}


def _credential_validation_result(
    body: JsonObject,
    *,
    credential_id: str,
    expected_generation: int,
) -> JsonObject:
    if set(body) != _CREDENTIAL_VALIDATION_RESULT_FIELDS:
        body.clear()
        raise _LoopbackRequestError("credential validation response is invalid")
    result: CredentialValidationResult | None = None
    try:
        result = CredentialValidationResult.model_validate(body)
    except (TypeError, ValueError):
        pass
    if result is None:
        body.clear()
        raise _LoopbackRequestError("credential validation response is invalid")
    if result.credential_id != credential_id or result.generation != expected_generation:
        body.clear()
        raise _LoopbackRequestError("credential validation response does not match request")
    dumped = result.model_dump(mode="json")
    body.clear()
    return {name: cast(JsonValue, dumped[name]) for name in _CREDENTIAL_VALIDATION_RESULT_FIELDS}


def _emergency_result(
    body: JsonObject,
    *,
    mutation_id: str | None = None,
    action: str | None = None,
    unlock_id: str | None = None,
) -> JsonObject:
    if set(body) != _EMERGENCY_RESULT_FIELDS:
        body.clear()
        raise _LoopbackRequestError("emergency unlock response is invalid")
    result: EmergencyUnlockView | None = None
    try:
        result = EmergencyUnlockView.model_validate(body)
    except (TypeError, ValueError):
        pass
    if result is None:
        body.clear()
        raise _LoopbackRequestError("emergency unlock response is invalid")
    if (
        (mutation_id is not None and result.mutation_id != mutation_id)
        or (action is not None and result.action != action)
        or (unlock_id is not None and result.unlock_id != unlock_id)
    ):
        body.clear()
        raise _LoopbackRequestError("emergency unlock response does not match request")
    dumped = result.model_dump(mode="json")
    body.clear()
    return {name: cast(JsonValue, dumped[name]) for name in _EMERGENCY_RESULT_FIELDS}


def _zero_secret(secret: bytearray) -> None:
    secret[:] = b"\x00" * len(secret)


def _loopback_url(host: str, port: int) -> str:
    # Stock composition binds only this literal; rejecting other loopback aliases
    # keeps proxy/DNS behavior completely outside the CLI trust boundary.
    if host != "127.0.0.1":
        raise CliUnavailable("Gatehouse v1 requires the numeric loopback host 127.0.0.1")
    return f"http://127.0.0.1:{port}"


def _locate_daemon_executable(requested: Path | None = None) -> Path | None:
    try:
        interpreter = sys.executable
        if requested is not None and type(requested) is not type(Path()):
            return None
        selected = select_adjacent_daemon_path(
            interpreter,
            requested_executable=None if requested is None else str(requested),
            platform=os.name,
        )
        candidate = Path(selected)
        return candidate if candidate.is_file() is True else None
    except Exception:
        # All ordinary selection/availability failures have one fixed refusal.
        # This pathname check does not attest native identity or runtime trust.
        return None


class LocalCliBackend:
    """DPAPI-authenticated local control plus short-lived typed API sessions."""

    __slots__ = (
        "_capability_loader",
        "_config_path",
        "_configuration_context",
        "_current_directory",
        "_daemon_executable",
        "_daemon_processes",
        "_environment",
        "_maximum_request_bytes",
        "_maximum_response_bytes",
        "_monotonic",
        "_launch_lock",
        "_launch_pending",
        "_owned_launch",
        "_session_mint_unknown",
        "_sleep",
        "_timeout_seconds",
        "_transport_factory",
    )

    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        environment: Mapping[str, str] | None = None,
        transport_factory: TransportFactory | None = None,
        capability_loader: CapabilityLoader = load_control_capability,
        daemon_processes: DaemonProcessRunner | None = None,
        daemon_executable: Path | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        maximum_request_bytes: int = _MAXIMUM_REQUEST_BYTES,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        current_directory: Callable[[], Path] = Path.cwd,
    ) -> None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("CLI timeout must be between zero and 60 seconds")
        if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
            raise ValueError("CLI HTTP body limits must be positive")
        source = os.environ if environment is None else environment
        self._environment = MappingProxyType(build_long_lived_environment(source))
        self._config_path = (
            config_path
            if config_path is not None
            else default_config_path(environment=dict(self._environment))
        )
        self._transport_factory = transport_factory
        self._capability_loader = capability_loader
        self._daemon_processes = daemon_processes or NativeDaemonProcessRunner(
            environment=self._environment
        )
        self._daemon_executable = daemon_executable
        self._timeout_seconds = timeout_seconds
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes
        self._monotonic = monotonic
        self._sleep = sleep
        self._current_directory = current_directory
        self._configuration_context: ContextVar[_ConfigurationOperation | None] = ContextVar(
            "gatehouse_cli_configuration_operation", default=None
        )
        self._launch_lock = threading.Lock()
        self._launch_pending = False
        self._owned_launch: _OwnedControlledLaunch | None = None
        self._session_mint_unknown = False

    def set_config_path(self, config_path: str | Path) -> None:
        raw = str(config_path)
        if not raw or any(character in raw for character in "\x00\n\r"):
            raise CliUnavailable("the Gatehouse configuration path is invalid")
        if self._configuration_context.get() is not None:
            raise CliUnavailable("configuration cannot change during a CLI operation")
        self._config_path = config_path

    def config_init(self) -> Mapping[str, object]:
        try:
            return initialize_configuration(self._config_path)
        except OperatorCommandError as error:
            raise CliUnavailable(str(error)) from error

    def config_validate(self, *, explain: bool) -> Mapping[str, object]:
        try:
            return validate_configuration(
                self._config_path,
                environment=self._environment,
                explain=explain,
            )
        except ConfigLoadError as error:
            raise CliUnavailable(str(error)) from error
        except OperatorCommandError as error:
            raise CliUnavailable(str(error)) from error

    def diagnose(self, *, support_bundle: Path | None = None) -> Mapping[str, object]:
        try:
            if support_bundle is not None:
                return create_support_bundle(
                    self._config_path,
                    support_bundle,
                    environment=self._environment,
                )
            return diagnose_installation(
                self._config_path,
                environment=self._environment,
            )
        except OperatorCommandError as error:
            raise CliUnavailable(str(error)) from error

    def _settings(self, *, expected_config_digest: str | None = None) -> _LocalSettings:
        operation = self._configuration_context.get()
        cached = operation.settings if operation is not None else None
        if cached is not None:
            if (
                expected_config_digest is not None
                and cached.config_digest != expected_config_digest
            ):
                raise CliUnavailable("configuration does not match its expected digest")
            return cached
        try:
            expected = (
                validate_expected_config_digest(expected_config_digest)
                if expected_config_digest is not None
                else None
            )
            runtime = load_runtime_configuration(
                self._config_path,
                environment=self._environment,
                expected_config_digest=expected,
            )
            snapshot = runtime.snapshot
            if snapshot is None or not snapshot.matches_main_path(self._config_path):
                raise ConfigSecurityError("verified configuration snapshot is unavailable")
            observed = validate_expected_config_digest(snapshot.manifest_digest)
            require_configuration_snapshot_digest(snapshot, expected or observed)
            configuration = runtime.main
            agent_url = _loopback_url(
                configuration.server.agent.host,
                configuration.server.agent.port,
            )
            admin_url = _loopback_url(
                configuration.server.admin.host,
                configuration.server.admin.port,
            )
        except ConfigLoadError as error:
            failure = CliUnavailable(str(error))
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            failure = CliUnavailable("the Gatehouse configuration is invalid")
        else:
            cached = _LocalSettings(
                config_path=snapshot.main_path,
                database_path=Path(configuration.database.path),
                agent_url=agent_url,
                admin_url=admin_url,
                readiness_timeout_seconds=configuration.watchdog.readiness_timeout / 1_000,
                config_digest=observed if expected is None else expected,
                allow_provider_disabled_state=(
                    configuration.firecrawl_workload.mode == "disabled"
                    and configuration.firecrawl_observer.mode == "disabled"
                ),
            )
            if operation is not None:
                operation.settings = cached
            return cached
        raise failure

    def _http(self, base_url: str) -> _BoundedJsonClient:
        timeout = self._timeout_seconds
        operation = self._configuration_context.get()
        if operation is not None and operation.request_deadline is not None:
            # HTTPX applies this to individual I/O phases. The caller rechecks
            # the deadline after a response; this is not preemptive wall timing.
            timeout = min(timeout, self._startup_remaining(operation.request_deadline))
        return _BoundedJsonClient(
            base_url=base_url,
            timeout_seconds=timeout,
            maximum_request_bytes=self._maximum_request_bytes,
            maximum_response_bytes=self._maximum_response_bytes,
            transport_factory=self._transport_factory,
        )

    def _capability(self) -> str:
        operation = self._configuration_context.get()
        if operation is not None and operation.control_capability is not None:
            return operation.control_capability
        path = installation_state_paths(self._settings().database_path).control_capability
        try:
            capability = self._capability_loader(path)
        except (ControlCapabilityStorageError, OSError, RuntimeError, ValueError) as error:
            raise _LoopbackRequestError("local control capability is unavailable") from error
        if (
            not isinstance(capability, str)
            or _CONTROL_CAPABILITY_PATTERN.fullmatch(capability) is None
        ):
            raise _LoopbackRequestError("local control capability is invalid")
        if operation is not None:
            operation.control_capability = capability
        return capability

    def _control_request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
        before_session_dispatch: Callable[[], None] | None = None,
        observe_session_response: Callable[[int, JsonObject], None] | None = None,
    ) -> tuple[int, JsonObject]:
        settings = self._settings()
        capability = self._capability()
        headers = {CONTROL_CAPABILITY_HEADER: capability}
        if method == "POST":
            headers[CONTROL_CONFIG_DIGEST_HEADER] = validate_expected_config_digest(
                settings.config_digest
            )
        with self._http(settings.admin_url) as client:
            return client.request(
                method,
                path,
                payload=payload,
                headers=headers,
                before_session_dispatch=before_session_dispatch,
                observe_session_response=observe_session_response,
            )

    def _control_status(self) -> JsonObject:
        return _success(
            self._control_request("GET", "/v1/control/status"),
            action="daemon status request",
        )

    def _agent_live(self) -> bool:
        try:
            with self._http(self._settings().agent_url) as client:
                status, body = client.request("GET", "/health/live")
            return status == 200 and body.get("status") == "live"
        except _LoopbackRequestError:
            return False

    @staticmethod
    def _status_view(
        body: Mapping[str, JsonValue],
        *,
        ready: bool | None = None,
    ) -> JsonObject:
        readiness = body.get("ready") if ready is None else ready
        if not isinstance(readiness, bool):
            raise _LoopbackRequestError("daemon readiness is invalid")
        status = _required_string(body.get("status"), label="daemon status", maximum=64)
        version = _required_string(body.get("version"), label="daemon version", maximum=64)
        schema_version = _required_integer(body.get("schema_version"), label="schema version")
        policy_version = _required_string(
            body.get("policy_version"),
            label="policy version",
            maximum=160,
        )
        uptime = _required_integer(body.get("uptime_seconds"), label="daemon uptime")
        degraded = body.get("degraded_components")
        if not isinstance(degraded, list) or any(not isinstance(item, str) for item in degraded):
            raise _LoopbackRequestError("degraded component list is invalid")
        return {
            "ready": readiness,
            "status": status,
            "version": version,
            "schema_version": schema_version,
            "policy_version": policy_version,
            "uptime_seconds": uptime,
            "degraded_components": degraded,
        }

    @_configuration_operation
    def status(self) -> Mapping[str, object]:
        try:
            with self._http(self._settings().agent_url) as client:
                status, body = client.request("GET", "/health/ready")
            if status not in {200, 503}:
                raise _LoopbackRequestError("readiness request was rejected")
            return self._status_view(body, ready=status == 200)
        except _LoopbackRequestError:
            if not self._agent_live():
                return {"ready": False, "status": "STOPPED"}
            raise CliUnavailable("the local Gatehouse readiness response is invalid") from None

    def _daemon_arguments(self, settings: _LocalSettings) -> tuple[str, ...]:
        executable = _locate_daemon_executable(self._daemon_executable)
        if executable is None:
            raise CliUnavailable("the installed gatehoused entry point was not found")
        return (
            str(executable),
            "--config",
            str(settings.config_path),
            "--expected-config-digest",
            settings.config_digest,
        )

    @_configuration_operation
    def daemon_run(self, *, expected_config_digest: str) -> Mapping[str, object]:
        expected = self._launch_expectation(expected_config_digest)
        settings = self._settings(expected_config_digest=expected)
        code = self._daemon_processes.run(self._daemon_arguments(settings))
        return {"action": "run", "exit_code": code}

    @staticmethod
    def _launch_expectation(value: object) -> str:
        try:
            return validate_expected_config_digest(value)
        except ConfigSecurityError:
            pass
        raise CliUnavailable("a valid expected configuration digest is required")

    @staticmethod
    def _startup_accepted(view: Mapping[str, object], settings: _LocalSettings) -> bool:
        return (view.get("status") == "READY" and view.get("ready") is True) or (
            settings.allow_provider_disabled_state
            and view.get("status") == "DEGRADED_NO_PROVIDER"
            and view.get("ready") is False
        )

    @staticmethod
    def _startup_status_view(
        body: Mapping[str, JsonValue],
        settings: _LocalSettings,
    ) -> JsonObject:
        observed: str | None
        try:
            observed = validate_expected_config_digest(body.get("config_digest"))
        except ConfigSecurityError:
            observed = None
        if observed is None or observed != settings.config_digest:
            raise CliUnavailable(
                "the Gatehouse daemon configuration does not match the verified configuration"
            )
        try:
            view = LocalCliBackend._status_view(body)
        except _LoopbackRequestError:
            raise CliUnavailable("the Gatehouse daemon startup response is invalid") from None
        return {**view, "config_digest": observed}

    def _startup_remaining(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise CliUnavailable("the Gatehouse daemon did not become ready in time")
        return remaining

    @staticmethod
    def _stop_owned_daemon(child: DaemonChild) -> None:
        if child.poll() is not None:
            return
        try:
            child.terminate()
        except OSError:
            pass
        try:
            child.wait(timeout=_OWNED_DAEMON_STOP_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            if child.poll() is not None:
                return
            raise CliUnavailable("the owned daemon child exit could not be confirmed") from None
        if child.poll() is None:
            raise CliUnavailable("the owned daemon child exit could not be confirmed")

    @_configuration_operation
    def daemon_start(self, *, expected_config_digest: str) -> Mapping[str, object]:
        expected = self._launch_expectation(expected_config_digest)
        settings = self._settings(expected_config_digest=expected)
        deadline = self._monotonic() + settings.readiness_timeout_seconds
        operation = self._configuration_context.get()
        assert operation is not None
        operation.request_deadline = deadline
        self._startup_remaining(deadline)
        try:
            existing_body = self._control_status()
        except _LoopbackRequestError:
            self._startup_remaining(deadline)
            if self._agent_live():
                raise CliUnavailable(
                    "a process is listening on the Gatehouse port but failed control authentication"
                ) from None
        else:
            self._startup_remaining(deadline)
            existing = self._startup_status_view(existing_body, settings)
            if not self._startup_accepted(existing, settings):
                raise CliUnavailable(
                    "the existing Gatehouse daemon is not in an accepted startup state"
                )
            return {"action": "start", "started": False, **existing}

        arguments = self._daemon_arguments(settings)
        self._startup_remaining(deadline)
        child = self._daemon_processes.start(arguments)
        accepted = False
        try:
            while True:
                self._startup_remaining(deadline)
                if child.poll() is not None:
                    raise CliUnavailable("the Gatehouse daemon exited before becoming ready")
                try:
                    ready_body = self._control_status()
                except _LoopbackRequestError:
                    pass
                else:
                    self._startup_remaining(deadline)
                    if child.poll() is not None:
                        raise CliUnavailable("the Gatehouse daemon exited before becoming ready")
                    ready = self._startup_status_view(ready_body, settings)
                    if self._startup_accepted(ready, settings):
                        accepted = True
                        return {"action": "start", "started": True, **ready}
                    if ready["status"] != "RECOVERING" or ready["ready"] is not False:
                        raise CliUnavailable(
                            "the Gatehouse daemon entered an unacceptable startup state"
                        )
                remaining = self._startup_remaining(deadline)
                self._sleep(min(0.1, remaining))
        finally:
            if not accepted:
                self._stop_owned_daemon(child)

    @_configuration_operation
    def daemon_stop(self) -> Mapping[str, object]:
        try:
            self._control_status()
        except _LoopbackRequestError as error:
            if not self._agent_live():
                return {"action": "stop", "stopped": False, "status": "STOPPED"}
            raise CliUnavailable(
                "the live Gatehouse daemon failed local control authentication"
            ) from error
        try:
            _success(
                self._control_request("POST", "/v2/control/drain"),
                action="daemon stop request",
            )
        except _LoopbackRequestError as error:
            raise CliUnavailable("the Gatehouse daemon rejected the authenticated stop") from error
        deadline = self._monotonic() + self._settings().readiness_timeout_seconds
        while self._agent_live():
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise CliUnavailable("the Gatehouse daemon did not stop in time")
            self._sleep(min(0.1, remaining))
        return {"action": "stop", "stopped": True, "status": "STOPPED"}

    @_configuration_operation
    def daemon_status(self) -> Mapping[str, object]:
        try:
            body = self._control_status()
            view = self._status_view(body)
            workload = body.get("workload")
            if workload is not None:
                validated: ControlWorkloadReadiness | None = None
                try:
                    validated = ControlWorkloadReadiness.model_validate(workload)
                except (TypeError, ValueError):
                    pass
                if validated is None:
                    raise _LoopbackRequestError("workload readiness is invalid")
                view["workload"] = validated.model_dump(mode="json")
        except _LoopbackRequestError as error:
            if not self._agent_live():
                return {"ready": False, "status": "STOPPED"}
            raise CliUnavailable(
                "the live Gatehouse daemon failed local control authentication"
            ) from error
        return view

    def _launch_session(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
        working_directory: Path | None = None,
    ) -> tuple[str, str]:
        if not self._launch_pending or self._owned_launch is not None:
            raise CliUnavailable("controlled session creation is not reserved")
        try:
            resolved_directory = canonical_existing_directory(
                self._current_directory() if working_directory is None else working_directory
            )
        except ValueError as error:
            raise CliUnavailable("the current working directory is unavailable") from error
        settings = self._settings()
        capability = self._capability()

        request_id = secrets.token_hex(16)

        def before_dispatch() -> None:
            # A send failure cannot establish whether the daemon minted a session.
            self._session_mint_unknown = True
            self._owned_launch = _OwnedControlledLaunch(
                None,
                settings,
                capability,
                request_id,
            )

        def observe_response(status: int, body: JsonObject) -> None:
            if status != 201:
                return
            try:
                session_id = _required_identifier(
                    body.get("session_id"), label="session identifier"
                )
            except _LoopbackRequestError:
                return
            self._owned_launch = _OwnedControlledLaunch(
                session_id,
                settings,
                capability,
                request_id,
            )
            self._session_mint_unknown = False

        try:
            body = _success(
                self._control_request(
                    "POST",
                    "/v2/control/sessions",
                    payload={
                        "request_id": request_id,
                        "client": client,
                        "workspace": workspace,
                        "working_directory": str(resolved_directory),
                        "non_interactive": non_interactive,
                    },
                    before_session_dispatch=before_dispatch,
                    observe_session_response=observe_response,
                ),
                expected=frozenset({201}),
                action="controlled session launch",
            )
            session_id = _required_identifier(body.get("session_id"), label="session identifier")
            bootstrap = _required_string(
                body.get("bootstrap_capability"),
                label="session bootstrap",
                minimum=40,
                maximum=128,
            )
            response_directory = canonical_existing_directory(
                _required_string(
                    body.get("working_directory"),
                    label="controlled working directory",
                    minimum=3,
                    maximum=32_767,
                )
            )
            if response_directory != resolved_directory:
                raise _LoopbackRequestError("controlled working directory response is invalid")
        except Exception:
            raise CliUnavailable("the daemon rejected the configured client session") from None
        return session_id, bootstrap

    @contextmanager
    def _launch_guard(self) -> Iterator[None]:
        if not self._launch_lock.acquire(blocking=False):
            raise CliUnavailable("owned controlled launch operation is busy")
        try:
            yield
        finally:
            self._launch_lock.release()

    def _reserve_session_creation(self) -> None:
        with self._launch_guard():
            if self._launch_pending:
                raise CliUnavailable("owned controlled launch operation is busy")
            if self._session_mint_unknown:
                raise CliUnavailable(_SESSION_CREATION_INDETERMINATE)
            if self._owned_launch is not None:
                raise CliUnavailable("owned controlled launch cleanup is pending")
            self._launch_pending = True

    def _cleanup_owned_session(self, owned: _OwnedControlledLaunch, *, revoke: bool) -> None:
        operation = self._configuration_context.get()
        assert operation is not None
        previous = (operation.settings, operation.control_capability, operation.request_deadline)
        operation.settings = owned.settings
        operation.control_capability = owned.control_capability
        # One request, with a fresh deadline and a bound on each HTTPX I/O phase.
        # A synchronous transport is not preempted at this wall-clock deadline.
        try:
            deadline = self._monotonic() + min(
                self._timeout_seconds, _OWNED_SESSION_CLEANUP_TIMEOUT_SECONDS
            )
            operation.request_deadline = deadline
            self._startup_remaining(deadline)
            if owned.session_id is None:
                self._cleanup_session_request(owned.request_id)
            else:
                self._cleanup_session(owned.session_id, revoke=revoke)
            self._startup_remaining(deadline)
        except BaseException as failure:
            self._raise_pending_failure(
                "the controlled session could not be cleaned up",
                self._session_control_flow(failure),
            )
        finally:
            operation.settings, operation.control_capability, operation.request_deadline = previous

    @staticmethod
    def _session_control_flow(failure: BaseException) -> str | None:
        if isinstance(failure, asyncio.CancelledError):
            return "cancelled"
        if isinstance(failure, KeyboardInterrupt):
            return "keyboard_interrupt"
        if isinstance(failure, SystemExit):
            return "system_exit"
        return None

    @staticmethod
    def _raise_pending_failure(message: str, control_flow: str | None = None) -> Never:
        # Preserve interruption intent without chaining transport/response errors.
        pending: BaseException
        if control_flow == "keyboard_interrupt":
            pending = KeyboardInterrupt(message)
        elif control_flow == "cancelled":
            pending = asyncio.CancelledError(message)
        elif control_flow == "system_exit":
            pending = SystemExit(1)
            pending.add_note(message)
        else:
            pending = CliUnavailable(message)
        try:
            raise pending from None
        except BaseException as sanitized:
            # `from None` alone only hides an active exception's context.
            sanitized.__context__ = None
            sanitized.__cause__ = None
            raise

    def _cleanup_failed_session(self, control_flow: str | None) -> None:
        owned = self._owned_launch
        if owned is not None:
            try:
                self._cleanup_owned_session(owned, revoke=True)
            except BaseException as cleanup_failure:
                self._raise_pending_failure(
                    _SESSION_CLEANUP_PENDING,
                    control_flow or self._session_control_flow(cleanup_failure),
                )
            else:
                self._session_mint_unknown = False
                self._owned_launch = None
        elif self._session_mint_unknown:
            self._raise_pending_failure(_SESSION_CREATION_INDETERMINATE, control_flow)

    def _finish_pending_session(self) -> None:
        owned = self._owned_launch
        if owned is None or owned.launch is not None:
            raise CliUnavailable("no pending controlled session cleanup is available")
        try:
            self._cleanup_owned_session(owned, revoke=True)
        except BaseException as failure:
            self._raise_pending_failure(
                _SESSION_CLEANUP_PENDING, self._session_control_flow(failure)
            )
        else:
            self._session_mint_unknown = False
            self._owned_launch = None

    @_configuration_operation
    def retry_pending_session_cleanup(self) -> None:
        """Retry only this backend's retained provisional session; accept no target."""

        with self._launch_guard():
            if self._launch_pending:
                raise CliUnavailable("owned controlled launch operation is busy")
            owned = self._owned_launch
            if self._session_mint_unknown and owned is None:
                raise CliUnavailable(_SESSION_CREATION_INDETERMINATE)
            if owned is None or owned.launch is not None:
                raise CliUnavailable("no pending controlled session cleanup is available")
            self._launch_pending = True
        try:
            self._finish_pending_session()
        finally:
            self._launch_pending = False

    @_configuration_operation
    def prepare_launch(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
        command: Sequence[str],
    ) -> ControlledLaunch:
        self._reserve_session_creation()
        try:
            arguments = tuple(command)
            if not arguments or any(not argument for argument in arguments):
                raise CliUnavailable("a controlled launch requires a command")
            try:
                working_directory = canonical_existing_directory(self._current_directory())
            except ValueError as error:
                raise CliUnavailable("the current working directory is unavailable") from error
            settings = self._settings()
            try:
                capability = self._capability()
            except _LoopbackRequestError:
                raise CliUnavailable("the controlled launch authority is unavailable") from None
            session_id, bootstrap = self._launch_session(
                client=client,
                workspace=workspace,
                non_interactive=non_interactive,
                working_directory=working_directory,
            )
            launch = ControlledLaunch(
                session_id=session_id,
                argv=arguments,
                working_directory=working_directory,
                environment={
                    "GATEHOUSE_AGENT_URL": settings.agent_url,
                    "GATEHOUSE_SESSION_BOOTSTRAP": bootstrap,
                    "GATEHOUSE_SESSION_ID": session_id,
                },
            )
            owned = self._owned_launch
            if owned is None or owned.session_id != session_id:
                raise CliUnavailable("controlled session cleanup authority is unavailable")
            self._owned_launch = _OwnedControlledLaunch(
                session_id,
                settings,
                capability,
                owned.request_id,
                launch,
            )
            return launch
        except BaseException as failure:
            control_flow = self._session_control_flow(failure)
            self._cleanup_failed_session(control_flow)
            if control_flow is not None:
                self._raise_pending_failure(
                    "controlled session operation interrupted", control_flow
                )
            if isinstance(failure, CliUnavailable):
                raise
            raise CliUnavailable("the controlled client session could not be prepared") from None
        finally:
            # The entry guard granted exclusive mutation until this flag clears;
            # no lock wait can interrupt publication of the cleanup authority.
            self._launch_pending = False

    def _cleanup_session_request(self, request_id: str) -> None:
        body = _success(
            self._control_request(
                "POST",
                "/v2/control/session-requests/cancel",
                payload={"request_id": request_id},
            ),
            action="controlled session request cancellation",
        )
        if body.get("request_id") != request_id or body.get("state") != "CANCELLED":
            raise _LoopbackRequestError("session request cancellation response is invalid")
        session_id = body.get("session_id")
        if session_id is not None:
            _required_identifier(session_id, label="session identifier")

    def _cleanup_session(self, session_id: str, *, revoke: bool) -> None:
        try:
            segment = quote(
                _required_identifier(session_id, label="session identifier"),
                safe="",
            )
            action = "revoke" if revoke else "disconnect"
            body = _success(
                self._control_request(
                    "POST",
                    f"/v2/control/sessions/{segment}/{action}",
                ),
                action="controlled session cleanup",
            )
            if body.get("session_id") != session_id:
                raise _LoopbackRequestError("session cleanup response is invalid")
            expected = "REVOKED" if revoke else "DISCONNECTED"
            if body.get("state") != expected:
                raise _LoopbackRequestError("session cleanup state is invalid")
        except _LoopbackRequestError as error:
            raise CliUnavailable("the controlled session could not be cleaned up") from error

    @_configuration_operation
    def cleanup_launch(self, launch: ControlledLaunch, *, revoke: bool) -> None:
        with self._launch_guard():
            owned = self._owned_launch
            if owned is None or owned.launch is not launch or self._launch_pending:
                raise CliUnavailable("no matching owned controlled launch is available for cleanup")
            self._launch_pending = True
        try:
            self._cleanup_owned_session(owned, revoke=revoke)
        except BaseException:
            # Keep exact original cleanup authority for a caller retry. No fresh
            # configuration or capability can rebind this owned session.
            raise
        else:
            self._session_mint_unknown = False
            self._owned_launch = None
        finally:
            self._launch_pending = False

    def _mint_admin_code(self) -> str:
        try:
            body = _success(
                self._control_request("POST", "/v2/control/admin/login-code"),
                action="admin login-code request",
            )
            code = _required_string(
                body.get("code"),
                label="admin login code",
                minimum=40,
                maximum=128,
            )
            _required_integer(body.get("expires_at_ms"), label="admin login-code expiry")
            return code
        except _LoopbackRequestError as error:
            raise CliUnavailable("the daemon could not create an admin login code") from error

    @contextmanager
    def _admin_session(self) -> Iterator[tuple[_BoundedJsonClient, str]]:
        code = self._mint_admin_code()
        with self._http(self._settings().admin_url) as client:
            try:
                login = _success(
                    client.request(
                        "POST",
                        "/v1/admin/login/exchange",
                        payload={"code": code},
                    ),
                    action="admin login exchange",
                )
                csrf = _required_string(
                    login.get("csrf_token"),
                    label="admin CSRF token",
                    minimum=32,
                    maximum=256,
                )
                _required_identifier(
                    login.get("admin_session_id"),
                    label="admin session identifier",
                )
                _required_integer(
                    login.get("idle_expires_at_ms"),
                    label="admin idle expiry",
                )
                _required_integer(
                    login.get("absolute_expires_at_ms"),
                    label="admin absolute expiry",
                )
                try:
                    admin_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
                    csrf_cookie = client.cookies.get(CSRF_COOKIE_NAME)
                except httpx.CookieConflict as error:
                    raise _LoopbackRequestError("admin login cookies are ambiguous") from error
                if (
                    not isinstance(admin_cookie, str)
                    or not 32 <= len(admin_cookie) <= 512
                    or not isinstance(csrf_cookie, str)
                    or not hmac.compare_digest(csrf, csrf_cookie)
                ):
                    raise _LoopbackRequestError("admin login cookies are invalid")
            except _LoopbackRequestError as error:
                raise CliUnavailable("the admin login exchange failed") from error
            yielded_cleanly = False
            try:
                yield client, csrf
                yielded_cleanly = True
            finally:
                try:
                    _success(
                        client.request(
                            "POST",
                            "/v1/admin/logout",
                            headers={
                                CSRF_HEADER_NAME: csrf,
                                "Origin": self._settings().admin_url,
                            },
                        ),
                        action="admin logout",
                    )
                except _LoopbackRequestError as error:
                    if yielded_cleanly:
                        raise CliUnavailable("the admin session could not be revoked") from error

    @staticmethod
    def _approval_view(item: object) -> JsonObject:
        try:
            approval = ApprovalView.model_validate(item)
        except (TypeError, ValueError) as error:
            raise _LoopbackRequestError("approval list response is invalid") from error
        dumped = approval.model_dump(mode="json", exclude={"action_token"})
        return {name: cast(JsonValue, dumped[name]) for name in _APPROVAL_PUBLIC_FIELDS}

    @_configuration_operation
    def approval_list(self) -> Sequence[Mapping[str, object]]:
        try:
            with self._admin_session() as (client, _):
                body = _success(
                    client.request(
                        "GET",
                        "/v1/admin/approvals",
                        query={"limit": "50"},
                    ),
                    action="approval list request",
                )
                approvals = body.get("approvals")
                if not isinstance(approvals, list):
                    raise _LoopbackRequestError("approval list response is invalid")
                return tuple(self._approval_view(item) for item in approvals)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the daemon returned an invalid approval list") from error

    @_configuration_operation
    def approval_action(self, approval_id: str, decision: str) -> Mapping[str, object]:
        if decision not in {"approve", "deny"}:
            raise CliUnavailable("the approval decision is invalid")
        try:
            segment = quote(_required_identifier(approval_id, label="approval identifier"), safe="")
            with self._admin_session() as (client, csrf):
                approval = _success(
                    client.request("GET", f"/v1/admin/approvals/{segment}"),
                    action="approval detail request",
                )
                try:
                    validated = ApprovalView.model_validate(approval)
                except (TypeError, ValueError) as error:
                    raise _LoopbackRequestError("approval detail response is invalid") from error
                if validated.approval_id != approval_id:
                    raise _LoopbackRequestError("approval detail identifier does not match")
                action_token = _required_string(
                    validated.action_token,
                    label="approval action token",
                    minimum=32,
                    maximum=256,
                )
                fingerprint = _required_string(
                    validated.request_fingerprint,
                    label="approval request fingerprint",
                    minimum=16,
                    maximum=256,
                )
                maximum_cost = _required_integer(
                    validated.maximum_estimated_cost,
                    label="approval maximum cost",
                )
                if validated.maximum_uses != 1:
                    raise _LoopbackRequestError("approval use bound is invalid")
                result = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/approvals/{segment}/{decision}",
                        payload={
                            "action_token": action_token,
                            "request_fingerprint": fingerprint,
                            "maximum_estimated_cost": maximum_cost,
                            "maximum_uses": 1,
                        },
                        headers={
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="approval decision request",
                )
                returned_id = _required_identifier(
                    result.get("approval_id"),
                    label="approval result identifier",
                )
                state = _required_string(
                    result.get("state"),
                    label="approval result state",
                    maximum=64,
                )
                acted_at_ms = _required_integer(
                    result.get("acted_at_ms"),
                    label="approval action time",
                )
                if returned_id != approval_id:
                    raise _LoopbackRequestError("approval result identifier does not match")
                expected_state = {"approve": "APPROVED", "deny": "DENIED"}[decision]
                if state != expected_state:
                    raise _LoopbackRequestError("approval result state does not match decision")
                return {
                    "approval_id": returned_id,
                    "state": state,
                    "acted_at_ms": acted_at_ms,
                }
        except _LoopbackRequestError as error:
            raise CliUnavailable("the approval action failed") from error

    @_configuration_operation
    def account_add(
        self,
        secret: bytearray,
        *,
        provider: str,
        provider_team_id: str,
        alias: str,
        pool_alias: str,
        priority: int,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        try:
            if not is_admissible_firecrawl_secret(secret, maximum_bytes=MAXIMUM_SECRET_BYTES):
                raise _LoopbackRequestError("account secret format is invalid")
            command: AccountAddRequest | None = None
            try:
                command = AccountAddRequest.model_validate(
                    {
                        "mutation_id": mutation_id,
                        "provider": provider,
                        "provider_team_id": provider_team_id,
                        "alias": alias,
                        "pool_alias": pool_alias,
                        "priority": priority,
                        "expires_at_ms": expires_at_ms,
                    }
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("account add command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        "/v1/admin/accounts",
                        binary=secret,
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    expected=frozenset({201}),
                    action="account add request",
                )
            result = _account_result(body, alias=command.alias, action="add")
            if (
                result.get("pool_alias") != command.pool_alias
                or result.get("priority") != command.priority
            ):
                raise _LoopbackRequestError("account add response does not match request")
            return result
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account add failed") from error
        finally:
            _zero_secret(secret)

    @_configuration_operation
    def account_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise CliUnavailable("the account list limit is invalid")
        try:
            with self._admin_session() as (client, _):
                body = _success(
                    client.request(
                        "GET",
                        "/v1/admin/accounts",
                        query={"limit": str(limit)},
                    ),
                    action="account list request",
                )
            if set(body) != {"accounts"}:
                raise _LoopbackRequestError("account list response is invalid")
            items = body.get("accounts")
            if not isinstance(items, list) or len(items) > limit:
                raise _LoopbackRequestError("account list response is invalid")
            results: list[Mapping[str, object]] = []
            aliases: set[str] = set()
            for item in items:
                if not isinstance(item, dict):
                    raise _LoopbackRequestError("account list response is invalid")
                status = _account_status(item)
                status_alias = cast(str, status["alias"])
                if status_alias in aliases:
                    raise _LoopbackRequestError("account list response contains duplicate aliases")
                aliases.add(status_alias)
                results.append(status)
            return tuple(results)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account list failed") from error

    @_configuration_operation
    def account_status(self, alias: str) -> Mapping[str, object]:
        try:
            alias_segment = quote(_required_identifier(alias, label="account alias"), safe="")
            with self._admin_session() as (client, _):
                body = _success(
                    client.request("GET", f"/v1/admin/accounts/{alias_segment}"),
                    action="account status request",
                )
            return _account_status(body, alias=alias)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account status request failed") from error

    @_configuration_operation
    def account_rotate(
        self,
        alias: str,
        secret: bytearray,
        *,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        try:
            if not is_admissible_firecrawl_secret(secret, maximum_bytes=MAXIMUM_SECRET_BYTES):
                raise _LoopbackRequestError("account secret format is invalid")
            alias_segment = quote(_required_identifier(alias, label="account alias"), safe="")
            command: AccountRotationRequest | None = None
            try:
                command = AccountRotationRequest.model_validate(
                    {"mutation_id": mutation_id, "expires_at_ms": expires_at_ms}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("account rotation command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/accounts/{alias_segment}/rotate",
                        binary=secret,
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="account rotation request",
                )
            return _account_result(body, alias=alias, action="rotate")
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account rotation failed") from error
        finally:
            _zero_secret(secret)

    @_configuration_operation
    def account_change_state(
        self,
        alias: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        try:
            alias_segment = quote(_required_identifier(alias, label="account alias"), safe="")
            command: AccountStateChangeRequest | None = None
            try:
                command = AccountStateChangeRequest.model_validate(
                    {"mutation_id": mutation_id, "action": action, "reason": reason}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("account state command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/accounts/{alias_segment}/{command.action}",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="account state request",
                )
            return _account_result(body, alias=alias, action=command.action)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account state change failed") from error

    @_configuration_operation
    def account_refresh(
        self,
        alias: str,
        *,
        mutation_id: str,
    ) -> Mapping[str, object]:
        try:
            alias_segment = quote(_required_identifier(alias, label="account alias"), safe="")
            command: AccountRefreshRequest | None = None
            try:
                command = AccountRefreshRequest.model_validate({"mutation_id": mutation_id})
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("account refresh command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/accounts/{alias_segment}/refresh",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="account refresh request",
                )
            return _account_status(body, alias=alias)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account refresh failed") from error

    @_configuration_operation
    def account_observation_change(
        self,
        alias: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        try:
            alias_segment = quote(_required_identifier(alias, label="account alias"), safe="")
            command: AccountObservationChangeRequest | None = None
            try:
                command = AccountObservationChangeRequest.model_validate(
                    {"mutation_id": mutation_id, "action": action, "reason": reason}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("account observation command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/accounts/{alias_segment}/observation",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="account observation request",
                )
            return _account_observation_result(body, alias=alias, action=command.action)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the account observation change failed") from error

    @_configuration_operation
    def pool_failover_change(
        self,
        alias: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        try:
            alias_segment = quote(_required_identifier(alias, label="pool alias"), safe="")
            try:
                command = PoolFailoverChangeRequest.model_validate(
                    {"mutation_id": mutation_id, "action": action, "reason": reason}
                )
            except (TypeError, ValueError):
                raise _LoopbackRequestError("pool failover command is invalid") from None
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/pools/{alias_segment}/failover",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="pool failover request",
                )
            try:
                result = PoolFailoverMutationResult.model_validate(body)
            except (TypeError, ValueError):
                body.clear()
                raise _LoopbackRequestError("pool failover response is invalid") from None
            body.clear()
            if result.pool_alias != alias or result.action != command.action:
                raise _LoopbackRequestError("pool failover response does not match request")
            return cast(Mapping[str, object], result.model_dump(mode="json"))
        except _LoopbackRequestError as error:
            raise CliUnavailable("the pool failover change failed") from error

    @_configuration_operation
    def credential_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise CliUnavailable("the credential list limit is invalid")
        try:
            with self._admin_session() as (client, _):
                body = _success(
                    client.request(
                        "GET",
                        "/v1/admin/credentials",
                        query={"limit": str(limit)},
                    ),
                    action="credential list request",
                )
            if set(body) != {"credentials"}:
                raise _LoopbackRequestError("credential list response is invalid")
            items = body.get("credentials")
            if not isinstance(items, list) or len(items) > limit:
                raise _LoopbackRequestError("credential list response is invalid")
            results: list[Mapping[str, object]] = []
            for item in items:
                if not isinstance(item, dict):
                    raise _LoopbackRequestError("credential list response is invalid")
                normalized: dict[str, object] = dict(item)
                for field in ("pool_ids", "pool_aliases"):
                    value = normalized.get(field)
                    if not isinstance(value, list):
                        raise _LoopbackRequestError("credential list response is invalid")
                    normalized[field] = tuple(value)
                try:
                    summary = CredentialSummary.model_validate(normalized)
                except (TypeError, ValueError) as error:
                    raise _LoopbackRequestError("credential list response is invalid") from error
                results.append(summary.model_dump(mode="json"))
            return tuple(results)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the credential list failed") from error

    @_configuration_operation
    def credential_provision(
        self,
        secret: bytearray,
        *,
        mutation_id: str,
        principal_id: str,
        quota_scope_id: str,
        pool_id: str,
        alias: str,
        expires_at_ms: int | None,
        exclusive_usage: bool,
    ) -> Mapping[str, object]:
        try:
            if not secret or len(secret) > MAXIMUM_SECRET_BYTES:
                raise _LoopbackRequestError("credential secret size is invalid")
            command: CredentialProvisionRequest | None = None
            try:
                command = CredentialProvisionRequest.model_validate(
                    {
                        "mutation_id": mutation_id,
                        "principal_id": principal_id,
                        "quota_scope_id": quota_scope_id,
                        "pool_id": pool_id,
                        "alias": alias,
                        "expires_at_ms": expires_at_ms,
                        "exclusive_usage": exclusive_usage,
                    }
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("credential provision command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        "/v1/admin/credentials",
                        binary=secret,
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    expected=frozenset({201}),
                    action="credential provision request",
                )
            result = _credential_result(
                body,
                mutation_id=command.mutation_id,
                action="provision",
            )
            if (
                result.get("principal_id") != command.principal_id
                or result.get("quota_scope_id") != command.quota_scope_id
                or result.get("pool_id") != command.pool_id
                or result.get("alias") != command.alias
                or result.get("expires_at_ms") != command.expires_at_ms
            ):
                raise _LoopbackRequestError("credential provision response does not match request")
            return result
        except _LoopbackRequestError as error:
            raise CliUnavailable("the credential provision failed") from error
        finally:
            _zero_secret(secret)

    @_configuration_operation
    def credential_rotate(
        self,
        credential_id: str,
        secret: bytearray,
        *,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        try:
            if not secret or len(secret) > MAXIMUM_SECRET_BYTES:
                raise _LoopbackRequestError("credential secret size is invalid")
            credential_segment = quote(
                _required_identifier(credential_id, label="credential identifier"),
                safe="",
            )
            command: CredentialRotationRequest | None = None
            try:
                command = CredentialRotationRequest.model_validate(
                    {"mutation_id": mutation_id, "expires_at_ms": expires_at_ms}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("credential rotation command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/credentials/{credential_segment}/rotate",
                        binary=secret,
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="credential rotation request",
                )
            result = _credential_result(
                body,
                mutation_id=command.mutation_id,
                action="rotate",
            )
            if (
                result.get("credential_id") == credential_id
                or result.get("expires_at_ms") != command.expires_at_ms
            ):
                raise _LoopbackRequestError("credential rotation response does not match request")
            return result
        except _LoopbackRequestError as error:
            raise CliUnavailable("the credential rotation failed") from error
        finally:
            _zero_secret(secret)

    @_configuration_operation
    def credential_validate(
        self,
        credential_id: str,
        *,
        expected_generation: int,
    ) -> Mapping[str, object]:
        try:
            credential_segment = quote(
                _required_identifier(credential_id, label="credential identifier"),
                safe="",
            )
            command: CredentialValidationRequest | None = None
            try:
                command = CredentialValidationRequest.model_validate(
                    {"expected_generation": expected_generation}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("credential validation command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/credentials/{credential_segment}/validate",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="credential validation request",
                )
            return _credential_validation_result(
                body,
                credential_id=credential_id,
                expected_generation=command.expected_generation,
            )
        except _LoopbackRequestError as error:
            raise CliUnavailable("the credential validation failed") from error

    @_configuration_operation
    def credential_change_state(
        self,
        credential_id: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        try:
            credential_segment = quote(
                _required_identifier(credential_id, label="credential identifier"),
                safe="",
            )
            command: CredentialStateChangeRequest | None = None
            try:
                command = CredentialStateChangeRequest.model_validate(
                    {"mutation_id": mutation_id, "action": action, "reason": reason}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("credential state command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/credentials/{credential_segment}/{command.action}",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="credential state request",
                )
            return _credential_result(
                body,
                mutation_id=command.mutation_id,
                action=command.action,
                credential_id=credential_id,
            )
        except _LoopbackRequestError as error:
            raise CliUnavailable("the credential state change failed") from error

    @_configuration_operation
    def emergency_unlock(
        self,
        secret: bytearray,
        *,
        mutation_id: str,
        service: str,
        pool_id: str,
        session_id: str,
        root_run_id: str,
        alias: str,
        reason: str,
        duration_ms: int,
        maximum_requests: int,
        maximum_credits: int,
    ) -> Mapping[str, object]:
        try:
            if not secret or len(secret) > MAXIMUM_SECRET_BYTES:
                raise _LoopbackRequestError("emergency credential secret size is invalid")
            command: EmergencyUnlockRequest | None = None
            try:
                command = EmergencyUnlockRequest.model_validate(
                    {
                        "mutation_id": mutation_id,
                        "service": service,
                        "pool_id": pool_id,
                        "session_id": session_id,
                        "root_run_id": root_run_id,
                        "alias": alias,
                        "reason": reason,
                        "duration_ms": duration_ms,
                        "maximum_requests": maximum_requests,
                        "maximum_credits": maximum_credits,
                        "maximum_concurrency": 1,
                    }
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("emergency unlock command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        "/v1/admin/emergency-unlocks",
                        binary=secret,
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    expected=frozenset({201}),
                    action="emergency unlock request",
                )
            result = _emergency_result(
                body,
                mutation_id=command.mutation_id,
                action="unlock",
            )
            if (
                result.get("service") != command.service
                or result.get("pool_id") != command.pool_id
                or result.get("session_id") != command.session_id
                or result.get("root_run_id") != command.root_run_id
            ):
                raise _LoopbackRequestError("emergency unlock response does not match authority")
            return result
        except _LoopbackRequestError as error:
            raise CliUnavailable("the emergency unlock failed") from error
        finally:
            _zero_secret(secret)

    @_configuration_operation
    def emergency_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise CliUnavailable("the emergency unlock list limit is invalid")
        try:
            with self._admin_session() as (client, _):
                body = _success(
                    client.request(
                        "GET",
                        "/v1/admin/emergency-unlocks",
                        query={"limit": str(limit)},
                    ),
                    action="emergency unlock list request",
                )
            if set(body) != {"emergency_unlocks"}:
                raise _LoopbackRequestError("emergency unlock list response is invalid")
            items = body.get("emergency_unlocks")
            if not isinstance(items, list) or len(items) > limit:
                raise _LoopbackRequestError("emergency unlock list response is invalid")
            results: list[Mapping[str, object]] = []
            for item in items:
                if not isinstance(item, dict):
                    raise _LoopbackRequestError("emergency unlock list response is invalid")
                results.append(_emergency_result(item))
            return tuple(results)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the emergency unlock list failed") from error

    @_configuration_operation
    def emergency_cancel(
        self,
        unlock_id: str,
        *,
        mutation_id: str,
        reason: str,
    ) -> Mapping[str, object]:
        try:
            unlock_segment = quote(
                _required_identifier(unlock_id, label="emergency unlock identifier"),
                safe="",
            )
            command: EmergencyUnlockCancelRequest | None = None
            try:
                command = EmergencyUnlockCancelRequest.model_validate(
                    {"mutation_id": mutation_id, "reason": reason}
                )
            except (TypeError, ValueError):
                pass
            if command is None:
                raise _LoopbackRequestError("emergency cancel command is invalid")
            metadata = cast(Mapping[str, JsonValue], command.model_dump(mode="json"))
            with self._admin_session() as (client, csrf):
                body = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/emergency-unlocks/{unlock_segment}/cancel",
                        headers={
                            COMMAND_HEADER_NAME: _command_header(metadata),
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="emergency unlock cancellation request",
                )
            return _emergency_result(
                body,
                mutation_id=command.mutation_id,
                action="cancel",
                unlock_id=unlock_id,
            )
        except _LoopbackRequestError as error:
            raise CliUnavailable("the emergency unlock cancellation failed") from error

    @_configuration_operation
    def policy_explain(
        self,
        *,
        client: str,
        workspace: str,
        service: str,
        operation: str,
    ) -> Mapping[str, object]:
        capability = _POLICY_OPERATION_CAPABILITIES.get(operation)
        if service != "firecrawl" or capability is None:
            raise CliUnavailable("the policy explanation request is not a supported operation")
        try:
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=False,
                required_capability=None,
            ) as (agent, access_token, session_id):
                root_run_id = self._create_agent_root_run(
                    agent,
                    access_token=access_token,
                    expected_session_id=session_id,
                )
                request = PolicyExplainRequest.model_validate(
                    {
                        "service": "firecrawl",
                        "operation": operation,
                        "context": {"root_run_id": root_run_id},
                    }
                )
                body = _success(
                    agent.request(
                        "POST",
                        "/v1/policy/explain",
                        payload=request.model_dump(mode="json"),
                        headers=self._bearer(access_token),
                    ),
                    action="policy explanation",
                )
                try:
                    explained = PolicyExplainResponse.model_validate(body)
                except (TypeError, ValueError) as error:
                    raise _LoopbackRequestError("policy explanation response is invalid") from error
                authority = explained.authority
                if (
                    authority.client != client
                    or authority.workspace != workspace
                    or authority.session_id != session_id
                    or authority.root_run_id != root_run_id
                    or explained.service != service
                    or explained.operation != operation
                ):
                    raise _LoopbackRequestError(
                        "policy explanation response does not match authority"
                    )
                return cast(Mapping[str, object], explained.model_dump(mode="json"))
        except _LoopbackRequestError as error:
            raise CliUnavailable("the policy explanation failed") from error

    @contextmanager
    def _agent_session(
        self,
        *,
        client_name: str,
        workspace: str,
        non_interactive: bool,
        required_capability: str | None,
    ) -> Iterator[tuple[_BoundedJsonClient, str, str]]:
        self._reserve_session_creation()
        try:
            session_id, bootstrap = self._launch_session(
                client=client_name,
                workspace=workspace,
                non_interactive=non_interactive,
            )
            with self._http(self._settings().agent_url) as agent:
                try:
                    exchange = _success(
                        agent.request(
                            "POST",
                            "/v1/sessions/exchange",
                            payload={
                                "session_id": session_id,
                                "bootstrap_capability": bootstrap,
                                "client_nonce": secrets.token_urlsafe(24),
                            },
                        ),
                        action="session exchange",
                    )
                    access_token = _required_string(
                        exchange.get("access_token"),
                        label="session access token",
                        minimum=40,
                        maximum=512,
                    )
                    capabilities = exchange.get("capabilities")
                    session = exchange.get("session")
                    if (
                        exchange.get("token_type") != "Bearer"
                        or not isinstance(capabilities, list)
                        or any(not isinstance(item, str) for item in capabilities)
                        or (
                            required_capability is not None
                            and required_capability not in capabilities
                        )
                        or not isinstance(session, dict)
                        or session.get("session_id") != session_id
                        or session.get("state") != "ACTIVE"
                    ):
                        raise _LoopbackRequestError("session exchange response is invalid")
                except _LoopbackRequestError as error:
                    raise CliUnavailable(
                        "the controlled API session could not be adopted"
                    ) from error
                yield agent, access_token, session_id
        except BaseException as failure:
            control_flow = self._session_control_flow(failure)
            self._cleanup_failed_session(control_flow)
            if control_flow is not None:
                self._raise_pending_failure(
                    "controlled session operation interrupted", control_flow
                )
            raise
        else:
            self._finish_pending_session()
        finally:
            self._launch_pending = False

    @staticmethod
    def _bearer(access_token: str) -> Mapping[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def _create_agent_root_run(
        self,
        agent: _BoundedJsonClient,
        *,
        access_token: str,
        expected_session_id: str,
    ) -> str:
        body = _success(
            agent.request(
                "POST",
                "/v1/root-runs",
                payload={},
                headers=self._bearer(access_token),
            ),
            expected=frozenset({201}),
            action="root-run creation",
        )
        if set(body) != {
            "root_run_id",
            "session_id",
            "state",
            "started_at_ms",
            "budget",
        }:
            raise _LoopbackRequestError("root-run response is invalid")
        root_run_id = _required_identifier(
            body.get("root_run_id"),
            label="root-run identifier",
        )
        session_id = _required_identifier(
            body.get("session_id"),
            label="root-run session identifier",
        )
        _required_integer(body.get("started_at_ms"), label="root-run start time")
        budget = body.get("budget")
        if (
            session_id != expected_session_id
            or body.get("state") != "ACTIVE"
            or not isinstance(budget, dict)
            or len(budget) > 32
            or any(
                not isinstance(key, str)
                or not 1 <= len(key) <= 64
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for key, value in budget.items()
            )
        ):
            raise _LoopbackRequestError("root-run response is invalid")
        return root_run_id

    @_configuration_operation
    def docs_search(
        self,
        service: str,
        query: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Sequence[Mapping[str, object]]:
        try:
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=non_interactive,
                required_capability="docs.search",
            ) as (agent, access_token, _):
                body = _success(
                    agent.request(
                        "POST",
                        "/v1/docs/search",
                        payload={"service": service, "query": query, "limit": 10},
                        headers=self._bearer(access_token),
                    ),
                    action="documentation search",
                )
                results = body.get("results")
                if not isinstance(results, list) or any(
                    not isinstance(item, dict) for item in results
                ):
                    raise _LoopbackRequestError("documentation search response is invalid")
                return tuple(cast(dict[str, object], item) for item in results)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the documentation search failed") from error

    @_configuration_operation
    def docs_get(
        self,
        service: str,
        document: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]:
        try:
            service_segment = quote(_required_identifier(service, label="service"), safe="")
            document_segment = quote(
                _required_identifier(document, label="document"),
                safe="",
            )
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=non_interactive,
                required_capability="docs.get",
            ) as (agent, access_token, _):
                body = _success(
                    agent.request(
                        "GET",
                        f"/v1/docs/{service_segment}/{document_segment}",
                        headers=self._bearer(access_token),
                    ),
                    action="documentation retrieval",
                )
                returned_service = _required_string(
                    body.get("service"), label="documentation service", maximum=64
                )
                returned_document = _required_identifier(
                    body.get("document"), label="documentation identifier"
                )
                content = _required_string(
                    body.get("content"),
                    label="documentation content",
                    maximum=self._maximum_response_bytes,
                )
                if returned_service != service or returned_document != document:
                    raise _LoopbackRequestError("documentation response does not match request")
                return {
                    "service": returned_service,
                    "document": returned_document,
                    "content": content,
                }
        except _LoopbackRequestError as error:
            raise CliUnavailable("the documentation request failed") from error

    @_configuration_operation
    def feedback_submit(
        self,
        *,
        category: str,
        severity: str,
        component: str,
        summary: str,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]:
        try:
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=non_interactive,
                required_capability="feedback.submit",
            ) as (agent, access_token, _):
                body = _success(
                    agent.request(
                        "POST",
                        "/v1/feedback",
                        payload={
                            "category": category,
                            "severity": severity,
                            "component": component,
                            "summary": summary,
                        },
                        headers=self._bearer(access_token),
                    ),
                    action="feedback submission",
                )
                feedback_id = _required_identifier(
                    body.get("feedback_id"), label="feedback identifier"
                )
                state = _required_string(body.get("state"), label="feedback state", maximum=64)
                created_at_ms = _required_integer(
                    body.get("created_at_ms"), label="feedback creation time"
                )
                return {
                    "feedback_id": feedback_id,
                    "state": state,
                    "created_at_ms": created_at_ms,
                }
        except _LoopbackRequestError as error:
            raise CliUnavailable("the feedback submission failed") from error

    @_configuration_operation
    def dashboard_login_url(self) -> str:
        code = self._mint_admin_code()
        return f"{self._settings().admin_url}/login#code={quote(code, safe='')}"
