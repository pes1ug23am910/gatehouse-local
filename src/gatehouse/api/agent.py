"""Loopback agent API factory with typed, bounded operations only."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gatehouse.core.errors import ErrorCode, JsonValue, make_error
from gatehouse.providers.firecrawl.models import validate_operation_input
from gatehouse.sessions import (
    AccessPrincipal,
    AccessTokenCapacityExceeded,
    BootstrapCapabilityError,
    BootstrapExchangeRateLimited,
    CrossSessionRootRun,
    InvalidAccessToken,
    RootRunNotFound,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
    SessionUnavailable,
)

from .contracts import (
    AgentOperations,
    ApiResponse,
    DocumentationSearchRequest,
    FeedbackSubmitRequest,
    HealthProbe,
    HeartbeatRequest,
    InvocationRequest,
    JobAwaitRequest,
    JobContext,
    PolicyExplainRequest,
    RootRunCreateRequest,
    SessionAuthority,
    SessionExchangeRequest,
    WatcherContext,
    WatcherCursorCommitRequest,
    WatcherScanRequest,
)
from .errors import error_response, install_error_handlers, schema_error
from .middleware import LocalRequestBoundsMiddleware

_AGENT_OPERATIONS = frozenset(
    {
        "firecrawl.search",
        "firecrawl.scrape",
        "firecrawl.map",
        "firecrawl.crawl.start",
        "firecrawl.crawl.status",
        "firecrawl.crawl.cancel",
    }
)
_PUBLIC_AGENT_CAPABILITIES = _AGENT_OPERATIONS | {
    "docs.search",
    "docs.get",
    "feedback.submit",
    "jobs.status",
    "jobs.await",
    "jobs.cancel",
    "watcher.scan_feed_set",
    "watcher.get_cursor",
    "watcher.commit_cursor",
    "watcher.get_previous_summary",
}
_WATCHER_CAPABILITIES = frozenset(
    {
        "watcher.scan_feed_set",
        "watcher.get_cursor",
        "watcher.commit_cursor",
        "watcher.get_previous_summary",
    }
)
_MINIMUM_SESSION_HEARTBEAT_INTERVAL_MS = 1_000
_MAXIMUM_SESSION_HEARTBEAT_INTERVAL_MS = 300_000


class AgentAdmission(Protocol):
    def require_root_run_creation(self) -> None: ...

    def require_invocation(self, operation_id: str) -> None: ...


class _OpenAgentAdmission:
    def require_root_run_creation(self) -> None:
        return

    def require_invocation(self, operation_id: str) -> None:
        del operation_id


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.casefold() != "bearer" or not token.strip():
        raise make_error(ErrorCode.INVALID_SESSION, retryable=False)
    return token.strip()


def _raise_session_error(exception: Exception) -> None:
    if isinstance(exception, SessionUnavailable):
        message = str(exception).casefold()
        if "expired" in message:
            raise make_error(ErrorCode.SESSION_EXPIRED, retryable=False) from exception
        if "revoked" in message:
            raise make_error(ErrorCode.SESSION_REVOKED, retryable=False) from exception
    raise make_error(ErrorCode.INVALID_SESSION, retryable=False) from exception


def _result(response: ApiResponse) -> JSONResponse:
    headers = (
        {"Retry-After": str(response.retry_after_seconds)}
        if response.retry_after_seconds is not None
        else None
    )
    return JSONResponse(
        status_code=response.status_code,
        content=dict(response.body),
        headers=headers,
    )


def _valid_resource_identifier(value: str) -> bool:
    return (
        1 <= len(value) <= 160
        and value not in {".", ".."}
        and all(character.isalnum() or character in "_.:-" for character in value)
    )


def _requires_bearer_before_body(scope: Mapping[str, object]) -> bool:
    path = scope.get("path")
    return isinstance(path, str) and path not in {
        "/health/live",
        "/health/ready",
        "/v1/sessions/exchange",
    }


def create_agent_app(
    *,
    sessions: SessionAuthority,
    operations: AgentOperations,
    health: HealthProbe,
    now_ms: Callable[[], int],
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:47621", "localhost:47621"),
    maximum_body_bytes: int = 64 * 1_024,
    total_body_timeout_ms: int = 10_000,
    inter_chunk_timeout_ms: int = 2_000,
    maximum_wait_ms: int = 30_000,
    session_heartbeat_interval_ms: int = 30_000,
    admission: AgentAdmission | None = None,
) -> FastAPI:
    if maximum_wait_ms <= 0 or maximum_wait_ms > 60_000:
        raise ValueError("maximum_wait_ms is outside the server bound")
    if (
        isinstance(session_heartbeat_interval_ms, bool)
        or not isinstance(session_heartbeat_interval_ms, int)
        or not _MINIMUM_SESSION_HEARTBEAT_INTERVAL_MS
        <= session_heartbeat_interval_ms
        <= _MAXIMUM_SESSION_HEARTBEAT_INTERVAL_MS
    ):
        raise ValueError("session heartbeat interval is outside the server bound")

    async def preauthenticate_bearer(token: str) -> bool:
        try:
            await sessions.authenticate(token)
        except (InvalidAccessToken, SessionUnavailable):
            return False
        return True

    app = FastAPI(title="Gatehouse Agent API", docs_url=None, redoc_url=None)
    app.add_middleware(
        LocalRequestBoundsMiddleware,
        allowed_hosts=allowed_hosts,
        maximum_body_bytes=maximum_body_bytes,
        total_body_timeout_ms=total_body_timeout_ms,
        inter_chunk_timeout_ms=inter_chunk_timeout_ms,
        require_bearer=_requires_bearer_before_body,
        authenticate_bearer=preauthenticate_bearer,
    )
    install_error_handlers(app)
    admission = admission or _OpenAgentAdmission()

    async def authenticated(request: Request) -> tuple[str, AccessPrincipal]:
        token = _bearer_token(request)
        try:
            principal = await sessions.authenticate(token)
        except (InvalidAccessToken, SessionUnavailable) as exc:
            _raise_session_error(exc)
        return token, principal

    async def watcher_authenticated(
        request: Request,
        root_run_id: str,
    ) -> AccessPrincipal:
        token, principal = await authenticated(request)
        try:
            await sessions.resolve_root_run(
                access_token=token,
                root_run_id=root_run_id,
            )
        except (
            CrossSessionRootRun,
            InvalidAccessToken,
            RootRunNotFound,
            SessionUnavailable,
        ) as exc:
            _raise_session_error(exc)
        if principal.identity_assurance != "CONTROLLED_UNATTENDED_LAUNCH":
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False)
        return principal

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        snapshot = await health.readiness()
        return JSONResponse(
            status_code=200 if snapshot.ready else 503,
            content=snapshot.model_dump(mode="json", exclude={"ready"}),
        )

    @app.post("/v1/sessions/exchange")
    async def exchange(body: SessionExchangeRequest) -> JSONResponse:
        try:
            issued = await sessions.exchange_bootstrap(
                session_id=body.session_id,
                bootstrap_capability=body.bootstrap_capability,
            )
        except (BootstrapCapabilityError, SessionUnavailable) as exc:
            _raise_session_error(exc)
        except (AccessTokenCapacityExceeded, BootstrapExchangeRateLimited) as exc:
            return error_response(
                make_error(
                    ErrorCode.CAPACITY_EXCEEDED,
                    retryable=True,
                    retry_after_seconds=exc.retry_after_seconds,
                ),
                status_code=503,
            )
        capabilities = (
            set(await operations.capabilities(issued.principal)) & _PUBLIC_AGENT_CAPABILITIES
        )
        if issued.principal.identity_assurance != "CONTROLLED_UNATTENDED_LAUNCH":
            capabilities -= _WATCHER_CAPABILITIES
        expires_in_seconds = max(0, (issued.expires_at_ms - now_ms()) // 1_000)
        return JSONResponse(
            content={
                "access_token": issued.access_token,
                "token_type": "Bearer",
                "expires_in_seconds": expires_in_seconds,
                "heartbeat_interval_ms": session_heartbeat_interval_ms,
                "session": {
                    "session_id": issued.principal.session_id,
                    "client_id": issued.principal.client_id,
                    "workspace_id": issued.principal.workspace_id,
                    "state": "ACTIVE",
                    "absolute_expires_at_ms": issued.principal.absolute_expires_at_ms,
                },
                "capabilities": sorted(capabilities),
            }
        )

    @app.post("/v1/sessions/heartbeat")
    async def heartbeat(request: Request, body: HeartbeatRequest) -> JSONResponse:
        token = _bearer_token(request)
        try:
            for root_run_id in body.active_root_runs:
                await sessions.resolve_root_run(
                    access_token=token,
                    root_run_id=root_run_id,
                )
            principal = await sessions.heartbeat(token)
        except (
            CrossSessionRootRun,
            InvalidAccessToken,
            RootRunNotFound,
            SessionUnavailable,
        ) as exc:
            _raise_session_error(exc)
        return JSONResponse(
            content={
                "status": "active",
                "session_id": principal.session_id,
                "reported_agent_count": body.reported_agent_count,
            }
        )

    @app.post("/v1/root-runs", status_code=201)
    async def create_root_run(
        request: Request,
        body: RootRunCreateRequest,
    ) -> JSONResponse:
        admission.require_root_run_creation()
        token = _bearer_token(request)
        try:
            root_run = await sessions.create_root_run(
                access_token=token,
                budget=body.budget,
            )
        except SessionRunCapacityExceeded as exc:
            raise make_error(
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=1,
            ) from exc
        except SessionRunawayQuarantined as exc:
            raise make_error(
                ErrorCode.RUNAWAY_SUSPECTED,
                retryable=False,
                details={
                    "authorization_required": True,
                    "scope": "client_profile",
                },
            ) from exc
        except (InvalidAccessToken, SessionUnavailable) as exc:
            _raise_session_error(exc)
        return JSONResponse(
            status_code=201,
            content={
                "root_run_id": root_run.root_run_id,
                "session_id": root_run.session_id,
                "state": root_run.state.value,
                "started_at_ms": root_run.started_at_ms,
                "budget": dict(root_run.budget),
            },
        )

    @app.post("/v1/invocations")
    async def invoke(request: Request, body: InvocationRequest) -> JSONResponse:
        token = _bearer_token(request)
        try:
            principal = await sessions.authenticate(token)
            await sessions.resolve_root_run(
                access_token=token,
                root_run_id=body.context.root_run_id,
            )
        except (
            CrossSessionRootRun,
            InvalidAccessToken,
            RootRunNotFound,
            SessionUnavailable,
        ) as exc:
            _raise_session_error(exc)
        if body.execution.wait_up_to_ms > maximum_wait_ms:
            raise schema_error(fields=[{"field": "execution.wait_up_to_ms", "type": "bound"}])
        operation_id = f"{body.service}.{body.operation}"
        if operation_id not in _AGENT_OPERATIONS:
            raise schema_error(fields=[{"field": "operation", "type": "unsupported"}])
        if body.request_id is not None and operation_id != "firecrawl.crawl.start":
            raise schema_error(
                fields=[{"field": "request_id", "type": "unsupported_for_operation"}]
            )
        admission.require_invocation(operation_id)
        try:
            normalized = validate_operation_input(
                operation_id,
                body.input,
            ).model_dump(mode="json")
        except (TypeError, ValueError) as exc:
            raise schema_error(fields=[{"field": "input", "type": "operation_schema"}]) from exc
        validated = body.model_copy(update={"input": normalized})
        return _result(await operations.invoke(principal, validated))

    @app.post("/v1/policy/explain")
    async def explain_policy(
        request: Request,
        body: PolicyExplainRequest,
    ) -> JSONResponse:
        token = _bearer_token(request)
        try:
            principal = await sessions.authenticate(token)
            await sessions.resolve_root_run(
                access_token=token,
                root_run_id=body.context.root_run_id,
            )
        except (
            CrossSessionRootRun,
            InvalidAccessToken,
            RootRunNotFound,
            SessionUnavailable,
        ) as exc:
            _raise_session_error(exc)
        return _result(await operations.explain_policy(principal, body))

    @app.get("/v1/jobs/{job_id}")
    async def get_job(request: Request, job_id: str, root_run_id: str) -> JSONResponse:
        if not _valid_resource_identifier(job_id) or not _valid_resource_identifier(root_run_id):
            raise schema_error(fields=[{"field": "job_id", "type": "identifier"}])
        _, principal = await authenticated(request)
        return _result(
            await operations.get_job(
                principal,
                job_id,
                JobContext(root_run_id=root_run_id),
            )
        )

    @app.post("/v1/jobs/{job_id}/await")
    async def await_job(
        request: Request,
        job_id: str,
        body: JobAwaitRequest,
    ) -> JSONResponse:
        if not _valid_resource_identifier(job_id):
            raise schema_error(fields=[{"field": "job_id", "type": "identifier"}])
        if body.maximum_wait_ms > maximum_wait_ms:
            raise schema_error(fields=[{"field": "maximum_wait_ms", "type": "bound"}])
        _, principal = await authenticated(request)
        return _result(await operations.await_job(principal, job_id, body))

    @app.post("/v1/jobs/{job_id}/cancel")
    async def cancel_job(
        request: Request,
        job_id: str,
        body: JobContext,
    ) -> JSONResponse:
        if not _valid_resource_identifier(job_id):
            raise schema_error(fields=[{"field": "job_id", "type": "identifier"}])
        _, principal = await authenticated(request)
        return _result(await operations.cancel_job(principal, job_id, body))

    @app.post("/v1/watcher/feed-sets/{feed_set_id}/scan")
    async def scan_watcher_feed_set(
        request: Request,
        feed_set_id: str,
        body: WatcherScanRequest,
    ) -> JSONResponse:
        if not _valid_resource_identifier(feed_set_id):
            raise schema_error(fields=[{"field": "feed_set_id", "type": "identifier"}])
        principal = await watcher_authenticated(request, body.root_run_id)
        admission.require_invocation("watcher.scan_feed_set")
        return _result(await operations.scan_watcher_feed_set(principal, feed_set_id, body))

    @app.get("/v1/watcher/feed-sets/{feed_set_id}/cursor")
    async def get_watcher_cursor(
        request: Request,
        feed_set_id: str,
        root_run_id: str,
    ) -> JSONResponse:
        invalid_fields: list[dict[str, JsonValue]] = [
            {"field": field, "type": "identifier"}
            for field, value in (("feed_set_id", feed_set_id), ("root_run_id", root_run_id))
            if not _valid_resource_identifier(value)
        ]
        if invalid_fields:
            raise schema_error(fields=invalid_fields)
        principal = await watcher_authenticated(request, root_run_id)
        return _result(
            await operations.get_watcher_cursor(
                principal,
                feed_set_id,
                WatcherContext(root_run_id=root_run_id),
            )
        )

    @app.post("/v1/watcher/feed-sets/{feed_set_id}/cursor/commit")
    async def commit_watcher_cursor(
        request: Request,
        feed_set_id: str,
        body: WatcherCursorCommitRequest,
    ) -> JSONResponse:
        if not _valid_resource_identifier(feed_set_id):
            raise schema_error(fields=[{"field": "feed_set_id", "type": "identifier"}])
        principal = await watcher_authenticated(request, body.root_run_id)
        # Cursor completion remains available while draining so a successful scan
        # can release its durable feed lease without dispatching provider work.
        return _result(await operations.commit_watcher_cursor(principal, feed_set_id, body))

    @app.get("/v1/watcher/feed-sets/{feed_set_id}/previous-summary")
    async def get_watcher_previous_summary(
        request: Request,
        feed_set_id: str,
        root_run_id: str,
    ) -> JSONResponse:
        invalid_fields: list[dict[str, JsonValue]] = [
            {"field": field, "type": "identifier"}
            for field, value in (("feed_set_id", feed_set_id), ("root_run_id", root_run_id))
            if not _valid_resource_identifier(value)
        ]
        if invalid_fields:
            raise schema_error(fields=invalid_fields)
        principal = await watcher_authenticated(request, root_run_id)
        return _result(
            await operations.get_watcher_previous_summary(
                principal,
                feed_set_id,
                WatcherContext(root_run_id=root_run_id),
            )
        )

    @app.post("/v1/docs/search")
    async def search_docs(
        request: Request,
        body: DocumentationSearchRequest,
    ) -> JSONResponse:
        _, principal = await authenticated(request)
        return _result(await operations.search_documentation(principal, body))

    @app.get("/v1/docs/{service}/{document}")
    async def get_docs(request: Request, service: str, document: str) -> JSONResponse:
        if not _valid_resource_identifier(service) or not _valid_resource_identifier(document):
            raise schema_error(fields=[{"field": "document", "type": "identifier"}])
        _, principal = await authenticated(request)
        response = await operations.get_documentation(
            principal,
            service,
            document,
        )
        if response is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        return _result(response)

    @app.post("/v1/feedback")
    async def feedback(request: Request, body: FeedbackSubmitRequest) -> JSONResponse:
        _, principal = await authenticated(request)
        return _result(await operations.submit_feedback(principal, body))

    return app
