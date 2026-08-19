"""Secret-injecting HTTP transport with a fixed provider origin and hard bounds."""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import Final

import anyio
import httpx

from gatehouse.credentials.base import KeyStore
from gatehouse.credentials.redaction import SecretScanner
from gatehouse.policy.targets import canonicalize_public_url, validate_resolved_addresses
from gatehouse.providers.base import ProviderRequest, ProviderResponse

FIRECRAWL_ORIGIN: Final[str] = "https://api.firecrawl.dev"


class ProviderTransportError(RuntimeError):
    """A transport-boundary failure that contains no secret or response body."""


class ProviderNetworkDisabledError(ProviderTransportError):
    """Real provider networking was not explicitly enabled for this process."""


class ProviderResponseTooLargeError(ProviderTransportError):
    """A provider response exceeded its operation-specific byte ceiling."""


Resolver = Callable[[str], Awaitable[Iterable[str]]]


async def _resolve_public_addresses(host: str) -> tuple[str, ...]:
    def resolve() -> list[str]:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return [str(answer[4][0]) for answer in answers]

    addresses = await anyio.to_thread.run_sync(resolve)
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
    ) -> None:
        self._key_store = key_store
        self._network_enabled = network_enabled
        self._resolver = resolver
        self._scanner = scanner or SecretScanner()
        self._client = client or httpx.AsyncClient(
            base_url=FIRECRAWL_ORIGIN,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        if not self._network_enabled:
            raise ProviderNetworkDisabledError("provider networking is disabled")
        await self._resolver("api.firecrawl.dev")
        if request.json_body is not None:
            raw_target = request.json_body.get("url")
            if isinstance(raw_target, str):
                target = canonicalize_public_url(raw_target)
                await self._resolver(target.host)

        started = time.monotonic()
        lease = await self._key_store.open_lease(
            request.credential_id,
            f"provider-transport:{request.operation}",
            ttl_seconds=max(5.0, min(request.timeout_ms / 1_000 + 5.0, 300.0)),
        )
        try:
            async with lease as secret_view:
                authorization = bytearray(b"Bearer ")
                authorization.extend(secret_view)
                try:
                    return await self._send_with_authorization(
                        request,
                        authorization.decode("utf-8", "strict"),
                        started=started,
                    )
                finally:
                    authorization[:] = b"\x00" * len(authorization)
        except UnicodeDecodeError as exc:
            raise ProviderTransportError("credential encoding is invalid") from exc

    async def _send_with_authorization(
        self,
        request: ProviderRequest,
        authorization: str,
        *,
        started: float,
    ) -> ProviderResponse:
        headers = {
            "accept": "application/json",
            "authorization": authorization,
            "user-agent": "gatehouse-local/0.0.1",
        }
        if request.json_body is not None:
            headers["content-type"] = "application/json"
        timeout = httpx.Timeout(request.timeout_ms / 1_000)
        try:
            async with self._client.stream(
                request.method,
                request.path,
                params=request.query,
                json=dict(request.json_body) if request.json_body is not None else None,
                headers=headers,
                timeout=timeout,
            ) as response:
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(raw) + len(chunk) > request.maximum_response_bytes:
                        raw[:] = b"\x00" * len(raw)
                        return ProviderResponse(
                            status_code=response.status_code,
                            elapsed_ms=_elapsed_ms(started),
                            provider_request_id=_request_id(response),
                            transport_error="response_too_large",
                            submission_may_have_occurred=True,
                        )
                    raw.extend(chunk)
                transport_error: str | None
                try:
                    data = json.loads(raw) if raw else None
                except (UnicodeDecodeError, json.JSONDecodeError):
                    data = None
                    transport_error = "malformed_response"
                else:
                    transport_error = None
                    data = self._scanner.sanitize(data, location="provider_response")
                finally:
                    raw[:] = b"\x00" * len(raw)
                return ProviderResponse(
                    status_code=response.status_code,
                    data=data,
                    headers={
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() in {"retry-after", "x-request-id", "content-type"}
                    },
                    elapsed_ms=_elapsed_ms(started),
                    provider_request_id=_request_id(response),
                    transport_error=transport_error,
                )
        except httpx.ConnectError:
            return ProviderResponse(
                status_code=None,
                elapsed_ms=_elapsed_ms(started),
                transport_error="connect_error",
                submission_may_have_occurred=False,
            )
        except httpx.ConnectTimeout:
            return ProviderResponse(
                status_code=None,
                elapsed_ms=_elapsed_ms(started),
                transport_error="connect_timeout",
                submission_may_have_occurred=False,
            )
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.ReadError, httpx.WriteError):
            return ProviderResponse(
                status_code=None,
                elapsed_ms=_elapsed_ms(started),
                transport_error="ambiguous_transport_failure",
                submission_may_have_occurred=True,
            )
        finally:
            headers["authorization"] = "[REDACTED]"


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


def _request_id(response: httpx.Response) -> str | None:
    value = response.headers.get("x-request-id")
    return value[:200] if value else None
