"""Secret-injecting HTTP transport with a fixed provider origin and hard bounds."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from collections.abc import Awaitable, Callable, Iterable
from contextlib import suppress
from contextvars import ContextVar
from typing import Final

import anyio
import httpx

from gatehouse import __version__
from gatehouse.core.provider_numbers import (
    ExactProviderNumber,
    ProviderNumberError,
    parse_json_provider_number,
    require_exact_provider_number,
)
from gatehouse.credentials.base import KeyStore, KeyStoreError
from gatehouse.credentials.composite import CompositeKeyStore
from gatehouse.credentials.redaction import SecretScanner
from gatehouse.policy.targets import (
    TargetValidationError,
    canonicalize_public_url,
    validate_resolved_addresses,
)
from gatehouse.providers.base import CredentialCustodyKind, ProviderRequest, ProviderResponse
from gatehouse.providers.registry import (
    DEFAULT_PROVIDER_REGISTRY,
    FIRECRAWL_DESCRIPTOR,
    AuthenticationStrategy,
    ProviderContractError,
    ProviderOperationPolicy,
)

assert FIRECRAWL_DESCRIPTOR.origin is not None
FIRECRAWL_ORIGIN: Final[str] = FIRECRAWL_DESCRIPTOR.origin
_SUPPRESS_PROVIDER_HTTP_LOGS: ContextVar[bool] = ContextVar(
    "gatehouse_suppress_provider_http_logs",
    default=False,
)


class _ProviderHttpLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        del record
        return not _SUPPRESS_PROVIDER_HTTP_LOGS.get()


_PROVIDER_HTTP_LOG_FILTER = _ProviderHttpLogFilter()
for _logger_name in (
    "httpx",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
):
    logging.getLogger(_logger_name).addFilter(_PROVIDER_HTTP_LOG_FILTER)


class ProviderTransportError(RuntimeError):
    """A transport-boundary failure that contains no secret or response body."""


class ProviderNetworkDisabledError(ProviderTransportError):
    """Real provider networking was not explicitly enabled for this process."""


class ProviderPreHandoffError(ProviderTransportError):
    """A sanitized local failure occurred before an HTTP request could be submitted."""


class ProviderResponseTooLargeError(ProviderTransportError):
    """A provider response exceeded its operation-specific byte ceiling."""


class _ProviderRequestCredentialOverlap(Exception):
    """Internal control signal removed before crossing the transport boundary."""


class _ProviderJsonStructureError(ValueError):
    """A sanitized successful-body JSON structural failure."""


Resolver = Callable[[str], Awaitable[Iterable[str]]]


async def _resolve_public_addresses(host: str) -> tuple[str, ...]:
    def resolve() -> list[str]:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return [str(answer[4][0]) for answer in answers]

    # The surrounding request deadline must not remain shielded behind a stuck
    # platform resolver. AnyIO's bounded default worker limiter caps abandoned
    # calls, while the invocation can fail closed before credential custody.
    addresses = await anyio.to_thread.run_sync(resolve, abandon_on_cancel=True)
    return validate_resolved_addresses(addresses)


class HttpxProviderTransport:
    """Resolve a KeyStore lease only while sending a fixed-origin HTTP request.

    The network switch defaults off. Production startup must enable it only after
    configuration, policy, redaction, persistence, and recovery readiness pass.
    """

    def __init__(
        self,
        *,
        key_store: KeyStore,
        network_enabled: bool = False,
        client: httpx.AsyncClient | None = None,
        resolver: Resolver = _resolve_public_addresses,
        scanner: SecretScanner | None = None,
        provider_id: str = "firecrawl",
    ) -> None:
        descriptor = DEFAULT_PROVIDER_REGISTRY.descriptor(provider_id)
        if descriptor.origin is None or descriptor.host is None:
            raise ProviderContractError("provider dispatch is not implemented")
        self._key_store = key_store
        self._network_enabled = network_enabled
        self._resolver = resolver
        self._scanner = scanner or SecretScanner()
        self._descriptor = descriptor
        self._client = client or httpx.AsyncClient(
            base_url=descriptor.origin,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        policy: ProviderOperationPolicy | None = None
        contract_invalid = False
        try:
            policy = self._descriptor.validate_request(request)
        except ProviderContractError:
            contract_invalid = True
        if contract_invalid:
            raise ProviderPreHandoffError("provider request is not permitted") from None
        assert policy is not None
        if not self._network_enabled:
            raise ProviderNetworkDisabledError("provider networking is disabled")
        started = time.monotonic()
        await self._validate_targets_before_custody(request, policy)
        lease_failed = False
        try:
            lease_ttl_seconds = max(5.0, min(request.timeout_ms / 1_000 + 5.0, 300.0))
            if request.credential_custody is CredentialCustodyKind.EMERGENCY:
                if not isinstance(self._key_store, CompositeKeyStore):
                    lease_failed = True
                else:
                    lease = await self._key_store.open_emergency_lease(
                        request.credential_id,
                        f"provider-transport:{request.operation}",
                        expected_generation=request.credential_generation,
                        ttl_seconds=lease_ttl_seconds,
                    )
            else:
                lease = await self._key_store.open_lease(
                    request.credential_id,
                    f"provider-transport:{request.operation}",
                    expected_generation=request.credential_generation,
                    ttl_seconds=lease_ttl_seconds,
                )
        except KeyStoreError:
            lease_failed = True
        if lease_failed:
            # Raise outside the KeyStore exception frame so a hostile backend
            # error cannot survive in __context__ with secret-bearing args.
            raise ProviderPreHandoffError("credential is unavailable") from None
        secret_view: memoryview | None = None
        lease_entry_failed = False
        try:
            secret_view = await lease.__aenter__()
        except KeyStoreError:
            lease_entry_failed = True
        except BaseException:
            lease.close()
            raise
        if lease_entry_failed:
            lease.close()
            raise ProviderPreHandoffError("credential is unavailable") from None
        if secret_view is None:
            lease.close()
            raise ProviderPreHandoffError("credential is unavailable")
        try:
            if self._descriptor.authentication is not AuthenticationStrategy.BEARER:
                raise ProviderContractError("provider authentication strategy is unsupported")
            authorization = bytearray(b"Bearer ")
            authorization.extend(secret_view)
            authorization_text: str | None = None
            try:
                authorization_text = _decode_authorization(authorization)
                if authorization_text is None:
                    raise ProviderPreHandoffError("credential encoding is invalid")
                return await self._send_with_authorization(
                    request,
                    authorization_text,
                    started=started,
                    policy=policy,
                )
            finally:
                authorization_text = None
                authorization[:] = b"\x00" * len(authorization)
        finally:
            lease.close()

    async def _validate_targets_before_custody(
        self,
        request: ProviderRequest,
        policy: ProviderOperationPolicy,
    ) -> None:
        failed = False
        try:
            assert self._descriptor.host is not None
            with anyio.fail_after(min(5.0, max(0.001, request.timeout_ms / 1_000))):
                validate_resolved_addresses(await self._resolver(self._descriptor.host))
                if request.json_body is not None:
                    for field_name in policy.target_url_fields:
                        raw_target = request.json_body.get(field_name)
                        if isinstance(raw_target, str):
                            target = canonicalize_public_url(raw_target)
                            validate_resolved_addresses(await self._resolver(target.host))
        except TargetValidationError:
            raise
        except Exception:
            failed = True
        if failed:
            raise ProviderPreHandoffError("provider address resolution failed") from None

    async def _send_with_authorization(
        self,
        request: ProviderRequest,
        authorization: str,
        *,
        started: float,
        policy: ProviderOperationPolicy,
    ) -> ProviderResponse:
        credential_text = authorization.removeprefix("Bearer ")
        headers = {
            "accept": "application/json",
            "authorization": authorization,
            "user-agent": f"gatehouse-local/{__version__}",
        }
        if request.json_body is not None:
            headers["content-type"] = "application/json"
        timeout = httpx.Timeout(request.timeout_ms / 1_000)
        transport_failure: tuple[str, bool] | None = None
        pre_handoff_overlap = False
        cancelled = False
        outbound_request: httpx.Request | None = None
        response: httpx.Response | None = None
        try:
            _clear_httpx_cookies(self._client)
            assert self._descriptor.origin is not None
            outbound_request = self._client.build_request(
                request.method,
                f"{self._descriptor.origin}{request.path}",
                params=request.query,
                json=dict(request.json_body) if request.json_body is not None else None,
                headers=headers,
                timeout=timeout,
            )
            # Provider transport is stateless. Never inherit a caller-injected
            # default Cookie header even if its jar could not be cleared.
            with suppress(KeyError):
                del outbound_request.headers["cookie"]
            if _provider_request_overlaps_credential(
                outbound_request,
                operation=request.operation,
                credential_text=credential_text,
            ):
                raise _ProviderRequestCredentialOverlap
            log_suppression = _SUPPRESS_PROVIDER_HTTP_LOGS.set(True)
            try:
                response = await self._client.send(outbound_request, stream=True)
            finally:
                _SUPPRESS_PROVIDER_HTTP_LOGS.reset(log_suppression)
            try:
                raw = bytearray()
                try:
                    if _unsafe_provider_response_headers(response, credential_text):
                        return ProviderResponse(
                            status_code=response.status_code,
                            elapsed_ms=_elapsed_ms(started),
                            transport_error="malformed_response",
                            submission_may_have_occurred=True,
                        )
                    stream_failure: BaseException | None = None
                    try:
                        async for chunk in response.aiter_bytes():
                            try:
                                if len(raw) + len(chunk) > request.maximum_response_bytes:
                                    return ProviderResponse(
                                        status_code=response.status_code,
                                        elapsed_ms=_elapsed_ms(started),
                                        provider_request_id=_request_id(
                                            response,
                                            scanner=self._scanner,
                                            credential_text=credential_text,
                                        ),
                                        transport_error="response_too_large",
                                        submission_may_have_occurred=True,
                                    )
                                raw.extend(chunk)
                            finally:
                                # Do not leave the preceding immutable stream chunk in
                                # this frame if the next iterator step raises.
                                chunk = b""
                    except BaseException as error:
                        # HTTPX iterator frames retain their most recently decoded
                        # chunk. Preserve the exception instance while detaching that
                        # internal response-body traceback before it can escape.
                        error.__traceback__ = None
                        error.__cause__ = None
                        error.__context__ = None
                        stream_failure = error
                    if stream_failure is not None:
                        raise stream_failure from None
                    transport_error: str | None
                    if credential_text and credential_text.encode("utf-8") in raw:
                        data = None
                        transport_error = "malformed_response"
                    elif policy.discard_error_body and response.status_code != 200:
                        # The HTTP status is authoritative for this fixed operation.
                        # Discard its error body without decoding, but only after the
                        # credential, header, stream, and size checks above have passed.
                        data = None
                        transport_error = None
                    else:
                        try:
                            data = _decode_response_json(
                                raw,
                                exact_credit_numbers=(
                                    policy.exact_response_numbers and response.status_code == 200
                                ),
                            )
                        except (
                            UnicodeDecodeError,
                            json.JSONDecodeError,
                            ProviderNumberError,
                            _ProviderJsonStructureError,
                        ) as error:
                            _scrub_json_decode_error(error)
                            data = None
                            transport_error = "malformed_response"
                        else:
                            transport_error = None
                            data = self._scanner.sanitize(data, location="provider_response")
                            data = _redact_active_credential(data, credential_text)
                    safe_headers: dict[str, str] = {}
                    for key, value in tuple(response.headers.items()):
                        if key.lower() not in {"retry-after", "x-request-id", "content-type"}:
                            continue
                        safe_value = _provider_text(
                            value,
                            scanner=self._scanner,
                            credential_text=credential_text,
                            maximum=512,
                        )
                        safe_headers[key] = safe_value
                        response.headers[key] = safe_value
                    return ProviderResponse(
                        status_code=response.status_code,
                        data=data,
                        headers=safe_headers,
                        elapsed_ms=_elapsed_ms(started),
                        provider_request_id=_request_id(
                            response,
                            scanner=self._scanner,
                            credential_text=credential_text,
                        ),
                        transport_error=transport_error,
                    )
                finally:
                    raw[:] = b"\x00" * len(raw)
            finally:
                # Scrub before an awaited close as well as in the outer finally:
                # a slow or failing response stream must not extend the secret's
                # lifetime in a request retained by the transport.
                original_stream = response.stream
                stream_was_closed = response.is_closed
                _redact_httpx_request(outbound_request)
                _redact_httpx_response(response)
                _clear_httpx_cookies(self._client)
                try:
                    if not stream_was_closed:
                        if isinstance(original_stream, httpx.AsyncByteStream):
                            await original_stream.aclose()
                        else:
                            original_stream.close()
                finally:
                    _scrub_httpx_stream(original_stream)
                    original_stream = httpx.ByteStream(b"")
        except _ProviderRequestCredentialOverlap:
            pre_handoff_overlap = True
        except asyncio.CancelledError:
            cancelled = True
        except httpx.HTTPError as error:
            _redact_httpx_error_requests(error)
            if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout)):
                transport_failure = ("connect_error", False)
            elif isinstance(error, httpx.PoolTimeout):
                transport_failure = ("pool_timeout", False)
            else:
                transport_failure = ("ambiguous_transport_failure", True)
        except Exception as error:
            # Third-party transports are permitted to raise non-httpx errors.
            # Never let their exception graph retain the authorization-bearing
            # request; conservatively treat the provider handoff as ambiguous.
            _redact_httpx_error_requests(error)
            transport_failure = ("ambiguous_transport_failure", True)
        finally:
            # This handle exists before provider handoff and is scrubbed on every
            # exit, including cancellation and BaseException paths where HTTPX
            # never returns a response or exception carrying the request.
            _redact_httpx_request(outbound_request)
            if response is not None:
                _redact_httpx_response(response)
            _clear_httpx_cookies(self._client)
            headers.clear()
            authorization = ""
            credential_text = ""
        if pre_handoff_overlap:
            raise ProviderPreHandoffError("provider request overlaps credential material") from None
        if cancelled:
            raise asyncio.CancelledError() from None
        if transport_failure is None:
            raise ProviderTransportError("provider transport failed without an outcome")
        error_name, submission_may_have_occurred = transport_failure
        return ProviderResponse(
            status_code=None,
            elapsed_ms=_elapsed_ms(started),
            transport_error=error_name,
            submission_may_have_occurred=submission_may_have_occurred,
        )


def _decode_authorization(value: bytearray) -> str | None:
    """Decode outside the raising frame so codec failures cannot retain secret bytes."""

    try:
        return value.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None


def _redact_httpx_error_requests(error: BaseException) -> None:
    candidates: list[object] = [getattr(error, "request", None)]
    response = getattr(error, "response", None)
    if response is not None:
        candidates.append(getattr(response, "request", None))
    for candidate in candidates:
        _redact_httpx_request(candidate)
    if isinstance(response, httpx.Response):
        _redact_httpx_response(response)


def _redact_httpx_request(candidate: object) -> None:
    if not isinstance(candidate, httpx.Request):
        return
    with suppress(Exception):
        candidate.headers.clear()
    with suppress(Exception):
        candidate.method = ""
    with suppress(Exception):
        candidate.url = httpx.URL("")
    with suppress(Exception):
        candidate.stream = httpx.ByteStream(b"")
    with suppress(Exception):
        candidate._content = b""
    with suppress(Exception):
        candidate.extensions.clear()


def _redact_httpx_response(response: httpx.Response) -> None:
    with suppress(Exception):
        _redact_httpx_request(response.request)
    with suppress(Exception):
        next_request = response.next_request
        _redact_httpx_request(next_request)
        response.next_request = None
    with suppress(Exception):
        response.headers.clear()
    with suppress(Exception):
        response.extensions.clear()
    with suppress(Exception):
        response.stream = httpx.ByteStream(b"")
    with suppress(Exception):
        response._content = b""


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


def _clear_httpx_cookies(client: httpx.AsyncClient) -> None:
    with suppress(Exception):
        client.cookies.clear()


def _unsafe_provider_response_headers(
    response: httpx.Response,
    credential_text: str,
) -> bool:
    credential = bytearray(credential_text.encode("utf-8"))
    try:
        for name, value in response.headers.raw:
            if name.lower() == b"set-cookie":
                return True
            if credential and (name.find(credential) >= 0 or value.find(credential) >= 0):
                return True
        return _extension_graph_overlaps_credential(response.extensions, credential)
    finally:
        credential[:] = b"\x00" * len(credential)


def _extension_graph_overlaps_credential(value: object, credential: bytearray) -> bool:
    """Inspect bounded HTTP extension containers without rendering attacker data."""

    pending = [value]
    seen: set[int] = set()
    remaining_nodes = 256
    while pending:
        remaining_nodes -= 1
        if remaining_nodes < 0:
            return True
        current = pending.pop()
        if isinstance(current, str):
            encoded = bytearray(current.encode("utf-8", "surrogatepass"))
            try:
                if encoded.find(credential) >= 0:
                    return True
            finally:
                encoded[:] = b"\x00" * len(encoded)
            continue
        if isinstance(current, bytes):
            if current.find(credential) >= 0:
                return True
            continue
        if isinstance(current, bytearray):
            if current.find(credential) >= 0:
                return True
            continue
        if isinstance(current, memoryview):
            encoded = bytearray(current)
            try:
                if encoded.find(credential) >= 0:
                    return True
            finally:
                encoded[:] = b"\x00" * len(encoded)
            continue
        if current is None or isinstance(current, (bool, int, float)):
            encoded = bytearray(json.dumps(current, separators=(",", ":")).encode("ascii"))
            try:
                if encoded.find(credential) >= 0:
                    return True
            finally:
                encoded[:] = b"\x00" * len(encoded)
            continue
        if isinstance(current, dict):
            if id(current) in seen:
                continue
            seen.add(id(current))
            for key, item in current.items():
                pending.extend((key, item))
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            if id(current) in seen:
                continue
            seen.add(id(current))
            pending.extend(current)
    return False


def _provider_request_overlaps_credential(
    request: httpx.Request,
    *,
    operation: str,
    credential_text: str,
) -> bool:
    credential = bytearray(credential_text.encode("utf-8"))
    if not credential:
        return False
    try:
        surfaces = (
            request.method.encode("ascii", "strict"),
            str(request.url).encode("utf-8", "surrogatepass"),
            request.content,
            operation.encode("utf-8", "surrogatepass"),
        )
        if any(surface.find(credential) >= 0 for surface in surfaces):
            return True
        return any(
            name.lower() != b"authorization"
            and (name.find(credential) >= 0 or value.find(credential) >= 0)
            for name, value in request.headers.raw
        )
    finally:
        credential[:] = b"\x00" * len(credential)


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


def _request_id(
    response: httpx.Response,
    *,
    scanner: SecretScanner,
    credential_text: str,
) -> str | None:
    value = response.headers.get("x-request-id")
    if not value:
        return None
    safe = _provider_text(
        value,
        scanner=scanner,
        credential_text=credential_text,
        maximum=200,
    )
    response.headers["x-request-id"] = safe
    return safe


def _provider_text(
    value: str,
    *,
    scanner: SecretScanner,
    credential_text: str,
    maximum: int,
) -> str:
    safe = scanner.redact_text(value)
    if credential_text:
        safe = safe.replace(credential_text, "[REDACTED:active_credential]")
    return safe[:maximum]


def _redact_active_credential(value: object, credential_text: str) -> object:
    if isinstance(value, ExactProviderNumber):
        try:
            return require_exact_provider_number(value)
        except ProviderNumberError:
            return "[REDACTED:invalid_exact_provider_number]"
    if not credential_text:
        return value
    if isinstance(value, str):
        return value.replace(credential_text, "[REDACTED:active_credential]")
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for index, (key, item) in enumerate(value.items()):
            if isinstance(key, ExactProviderNumber):
                try:
                    key_text = require_exact_provider_number(key).canonical
                except ProviderNumberError:
                    key_text = "[REDACTED:invalid_exact_provider_number]"
            else:
                key_text = str(key)
            safe_key = key_text.replace(credential_text, "[REDACTED:active_credential]")
            if safe_key in sanitized:
                safe_key = f"{safe_key}#{index}"
            sanitized[safe_key] = _redact_active_credential(item, credential_text)
        return sanitized
    if isinstance(value, list):
        return [_redact_active_credential(item, credential_text) for item in value]
    return value


def _decode_response_json(raw: bytearray, *, exact_credit_numbers: bool) -> object:
    if not raw:
        return None
    if not exact_credit_numbers:
        return json.loads(raw)
    return json.loads(
        raw,
        parse_int=parse_json_provider_number,
        parse_float=parse_json_provider_number,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_json_keys,
    )


def _reject_json_constant(_: str) -> object:
    raise ProviderNumberError("provider number constant is invalid")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise _ProviderJsonStructureError("provider response has duplicate object keys")
        decoded[key] = value
    return decoded


def _scrub_json_decode_error(error: BaseException) -> None:
    error.args = ()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
