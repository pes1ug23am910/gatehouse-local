"""Capability-authenticated service and router for same-user daemon control."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Protocol, Self

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.requests import ClientDisconnect

from gatehouse.core.clock import MAX_UTC_MS
from gatehouse.core.errors import ErrorCode, make_error
from gatehouse.core.ids import ClientId, SessionId, WorkspaceId
from gatehouse.sessions import (
    SessionCreationOutcomeUnresolved,
    SessionCreationRequest,
    SessionCreationRequestConflict,
    SessionManager,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
    SessionUnavailable,
)

from .auth import AdminAuthCapacityExceeded, AdminAuthManager
from .control_capability import ControlCapabilityVerifier

CONTROL_CAPABILITY_HEADER = "x-gatehouse-control-capability"
CONTROL_CONFIG_DIGEST_HEADER = "x-gatehouse-expected-config-digest"
_CONFIGURED_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def canonical_existing_directory(value: str | Path) -> Path:
    """Resolve one existing directory through Windows links without guessing authority."""

    raw = str(value)
    if not raw or len(raw) > 32_767 or any(character in raw for character in "\x00\n\r"):
        raise ValueError("canonical workspace directory is invalid")
    path = Path(raw)
    if not path.is_absolute():
        raise ValueError("canonical workspace directory must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("canonical workspace directory does not exist") from error
    if not resolved.is_dir():
        raise ValueError("canonical workspace directory is not a directory")
    return resolved


def _is_within_directory(candidate: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.path.normcase(str(candidate)), os.path.normcase(str(root))))
    except ValueError:
        return False
    return common == os.path.normcase(str(root))


class StrictControlModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ControlWorkloadReadiness(StrictControlModel):
    """Local routes for configured ordinary work, separate from control readiness."""

    status: Literal["READY", "DEGRADED", "UNCONFIGURED", "UNVERIFIED", "DISABLED", "UNAVAILABLE"]
    ready: bool = False
    scope: Literal["ordinary_new_work"] = "ordinary_new_work"
    watcher_assessed: Literal[False] = False
    request_authorization_assessed: Literal[False] = False
    provider_reachability_verified: Literal[False] = False
    checked_at_ms: Annotated[int, Field(ge=0, le=MAX_UTC_MS)] | None = None
    binding_count: Annotated[int, Field(ge=0, le=256)] = 0
    required_routes: Annotated[int, Field(ge=0, le=32)] = 0
    eligible_routes: Annotated[int, Field(ge=0, le=32)] = 0
    ineligible_routes: Annotated[int, Field(ge=0, le=32)] = 0
    unverified_routes: Annotated[int, Field(ge=0, le=32)] = 0

    @field_validator(
        "watcher_assessed",
        "request_authorization_assessed",
        "provider_reachability_verified",
        mode="before",
    )
    @classmethod
    def validate_unassessed_fact(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("workload readiness fact must be false")
        return False

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        if (
            self.eligible_routes + self.ineligible_routes + self.unverified_routes
            != self.required_routes
            or self.binding_count < self.required_routes
            or (self.binding_count == 0) != (self.required_routes == 0)
            or self.ready != (self.status == "READY")
        ):
            raise ValueError("workload readiness coverage is inconsistent")
        if self.status in {"READY", "DEGRADED"} and (
            self.checked_at_ms is None
            or self.required_routes == 0
            or self.unverified_routes != 0
            or (self.status == "READY" and self.ineligible_routes != 0)
            or (self.status == "DEGRADED" and self.ineligible_routes == 0)
        ):
            raise ValueError("workload readiness requires assessed routes")
        if self.status in {"UNCONFIGURED", "DISABLED", "UNAVAILABLE"} and self.binding_count:
            raise ValueError("workload readiness has no assessed coverage")
        if self.status == "UNVERIFIED" and self.required_routes and not self.unverified_routes:
            raise ValueError("unverified workload readiness requires unverified routes")
        return self


class ControlDaemonStatus(StrictControlModel):
    ready: bool
    status: Annotated[str, Field(min_length=1, max_length=64)]
    version: Annotated[str, Field(min_length=1, max_length=64)]
    schema_version: Annotated[int, Field(ge=0)]
    policy_version: Annotated[str, Field(min_length=1, max_length=160)]
    uptime_seconds: Annotated[int, Field(ge=0)]
    degraded_components: Annotated[list[str], Field(max_length=64)] = Field(default_factory=list)
    config_digest: str | None = None
    workload: ControlWorkloadReadiness | None = None

    @field_validator("config_digest", mode="before")
    @classmethod
    def validate_config_digest(cls, value: object) -> str | None:
        if value is None:
            return None
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("configuration digest must be 64 lowercase hexadecimal characters")
        return value


class ControlSessionLaunchRequest(StrictControlModel):
    request_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$", min_length=32, max_length=32)]
    client: Annotated[
        str,
        Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"),
    ]
    workspace: Annotated[
        str,
        Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"),
    ]
    working_directory: Annotated[str, Field(min_length=3, max_length=32_767)]
    non_interactive: bool


class ControlSessionLaunch(StrictControlModel):
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    bootstrap_capability: Annotated[str, Field(min_length=40, max_length=128)]
    client_id: Annotated[str, Field(min_length=1, max_length=160)]
    workspace_id: Annotated[str, Field(min_length=1, max_length=160)]
    working_directory: Annotated[str, Field(min_length=3, max_length=32_767)]
    identity_assurance: Annotated[str, Field(min_length=1, max_length=64)]
    policy_version: Annotated[str, Field(min_length=1, max_length=160)]
    absolute_expires_at_ms: Annotated[int, Field(ge=0)]


class ControlSessionMutation(StrictControlModel):
    session_id: Annotated[str, Field(min_length=1, max_length=160)]
    state: Annotated[str, Field(min_length=1, max_length=64)]


class ControlSessionRequestCancellation(StrictControlModel):
    request_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$", min_length=32, max_length=32)]


class ControlSessionRequestCancelled(ControlSessionRequestCancellation):
    state: Literal["CANCELLED"] = "CANCELLED"
    session_id: Annotated[str, Field(min_length=1, max_length=160)] | None = None


class ControlAdminLoginCode(StrictControlModel):
    code: Annotated[str, Field(min_length=40, max_length=128)]
    expires_at_ms: Annotated[int, Field(ge=0)]


class ControlDrainResult(StrictControlModel):
    state: str = "DRAINING"
    requested: bool


class ControlHealthProbe(Protocol):
    async def readiness(self) -> ControlDaemonStatus: ...


class ControlAdmission(Protocol):
    def require_session_launch(self) -> None: ...


type ShutdownCallback = Callable[[], Awaitable[None] | None]


class ControlAuthorityError(RuntimeError):
    """A launch request did not exactly match configured authority."""


@dataclass(frozen=True, slots=True)
class ControlLaunchAuthority:
    """Server-owned launch facts for one explicitly allowed client/workspace pair."""

    client_name: str
    workspace_name: str
    client_id: ClientId
    workspace_id: WorkspaceId
    canonical_root: str
    unattended: bool
    policy_version: str
    absolute_ttl_ms: int
    maximum_concurrent_runs: int
    budget: Mapping[str, int]

    def __post_init__(self) -> None:
        if (
            _CONFIGURED_NAME_PATTERN.fullmatch(self.client_name) is None
            or _CONFIGURED_NAME_PATTERN.fullmatch(self.workspace_name) is None
        ):
            raise ValueError("control launch names must be configured identifiers")
        if not isinstance(self.client_id, ClientId):
            raise TypeError("control launch client_id must be a ClientId")
        if not isinstance(self.workspace_id, WorkspaceId):
            raise TypeError("control launch workspace_id must be a WorkspaceId")
        canonical_root = canonical_existing_directory(self.canonical_root)
        object.__setattr__(self, "canonical_root", str(canonical_root))
        if not self.policy_version or len(self.policy_version) > 160:
            raise ValueError("control launch policy version is required and bounded")
        if self.absolute_ttl_ms <= 0:
            raise ValueError("control launch session TTL must be positive")
        if self.maximum_concurrent_runs <= 0:
            raise ValueError("control launch concurrent-run limit must be positive")
        budget = dict(self.budget)
        if not {"requests", "credits"}.issubset(budget):
            raise ValueError("control launch budget requires requests and credits ceilings")
        if any(
            not isinstance(key, str)
            or not key
            or len(key) > 64
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for key, value in budget.items()
        ):
            raise ValueError("control launch budget ceilings must be bounded nonnegative integers")
        object.__setattr__(self, "budget", MappingProxyType(budget))

    @property
    def key(self) -> tuple[str, str]:
        return self.client_name, self.workspace_name


class LocalControlService:
    """Apply same-user control requests using only injected durable authority."""

    def __init__(
        self,
        *,
        sessions: SessionManager,
        admin_auth: AdminAuthManager,
        health: ControlHealthProbe,
        launch_authorities: Mapping[tuple[str, str], ControlLaunchAuthority],
        shutdown: ShutdownCallback | asyncio.Event,
        cancel_session: Callable[[str], Awaitable[tuple[int, int]]],
        mark_draining: Callable[[], None] | None = None,
        admission: ControlAdmission | None = None,
    ) -> None:
        authorities = dict(launch_authorities)
        if any(key != authority.key for key, authority in authorities.items()):
            raise ValueError("control launch authority mapping key does not match its facts")
        self._sessions = sessions
        self._admin_auth = admin_auth
        self._health = health
        self._launch_authorities = MappingProxyType(authorities)
        self._shutdown = shutdown
        self._cancel_session = cancel_session
        self._mark_draining = mark_draining
        self._admission = admission
        self._drain_requested = False
        self._drain_lock = asyncio.Lock()
        self._session_cancellation_tasks: set[asyncio.Task[tuple[int, int]]] = set()

    async def status(self) -> ControlDaemonStatus:
        snapshot = await self._health.readiness()
        return ControlDaemonStatus(
            ready=snapshot.ready,
            status=snapshot.status,
            version=snapshot.version,
            schema_version=snapshot.schema_version,
            policy_version=snapshot.policy_version,
            uptime_seconds=snapshot.uptime_seconds,
            degraded_components=list(snapshot.degraded_components),
            config_digest=snapshot.config_digest,
            workload=snapshot.workload,
        )

    async def launch_session(
        self,
        request: ControlSessionLaunchRequest,
    ) -> ControlSessionLaunch:
        if self._admission is not None:
            self._admission.require_session_launch()
        authority = self._launch_authorities.get((request.client, request.workspace))
        if authority is None or request.non_interactive is not authority.unattended:
            raise ControlAuthorityError("controlled launch is not configured")
        try:
            working_directory = canonical_existing_directory(request.working_directory)
            canonical_root = canonical_existing_directory(authority.canonical_root)
        except ValueError as error:
            raise ControlAuthorityError("controlled launch working directory is invalid") from error
        if not _is_within_directory(working_directory, canonical_root):
            raise ControlAuthorityError("controlled launch working directory is outside workspace")
        identity_assurance = (
            "CONTROLLED_UNATTENDED_LAUNCH"
            if authority.unattended
            else "CONTROLLED_INTERACTIVE_LAUNCH"
        )
        authority_digest = hashlib.sha256(
            b"gatehouse:controlled-session-authority:v1\x00"
            + json.dumps(
                {
                    "client": authority.client_name,
                    "workspace": authority.workspace_name,
                    "client_id": str(authority.client_id),
                    "workspace_id": str(authority.workspace_id),
                    "canonical_root": str(canonical_root),
                    "working_directory": str(working_directory),
                    "identity_assurance": identity_assurance,
                    "policy_version": authority.policy_version,
                    "absolute_ttl_ms": authority.absolute_ttl_ms,
                    "maximum_concurrent_runs": authority.maximum_concurrent_runs,
                    "budget": dict(authority.budget),
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        launched = await self._sessions.create_session(
            client_id=str(authority.client_id),
            workspace_id=str(authority.workspace_id),
            identity_assurance=identity_assurance,
            policy_version=authority.policy_version,
            absolute_ttl_ms=authority.absolute_ttl_ms,
            budget=authority.budget,
            maximum_concurrent_runs=authority.maximum_concurrent_runs,
            block_on_runaway_quarantine=True,
            creation_request=SessionCreationRequest(request.request_id, authority_digest),
        )
        return ControlSessionLaunch(
            session_id=launched.session.session_id,
            bootstrap_capability=launched.bootstrap_capability,
            client_id=launched.session.client_id,
            workspace_id=str(launched.session.workspace_id),
            working_directory=str(working_directory),
            identity_assurance=launched.session.identity_assurance,
            policy_version=launched.session.policy_version,
            absolute_expires_at_ms=launched.session.absolute_expires_at_ms,
        )

    async def cancel_session_request(self, request_id: str) -> ControlSessionRequestCancelled:
        record = await self._sessions.cancel_creation_request(request_id)
        if record is not None:
            cancellation = asyncio.create_task(
                self._signal_session_cancellation(record.session_id),
                name="gatehouse-cancel-session-request",
            )
            self._session_cancellation_tasks.add(cancellation)
            cancellation.add_done_callback(self._observe_session_cancellation)
            try:
                await asyncio.shield(cancellation)
            except Exception:
                raise SessionCreationOutcomeUnresolved() from None
        return ControlSessionRequestCancelled(
            request_id=request_id,
            session_id=None if record is None else record.session_id,
        )

    async def disconnect_session(self, session_id: str) -> ControlSessionMutation:
        try:
            validated = SessionId(session_id)
        except (TypeError, ValueError) as error:
            raise ControlAuthorityError("session identifier is invalid") from error
        record = await self._sessions.mark_disconnected(validated)
        return ControlSessionMutation(session_id=record.session_id, state=record.state.value)

    async def revoke_session(self, session_id: str) -> ControlSessionMutation:
        try:
            validated = SessionId(session_id)
        except (TypeError, ValueError) as error:
            raise ControlAuthorityError("session identifier is invalid") from error
        record = await self._sessions.revoke(validated)
        cancellation = asyncio.create_task(
            self._signal_session_cancellation(str(validated)),
            name=f"gatehouse-revoke-{validated}",
        )
        self._session_cancellation_tasks.add(cancellation)
        cancellation.add_done_callback(self._observe_session_cancellation)
        await asyncio.shield(cancellation)
        return ControlSessionMutation(session_id=record.session_id, state=record.state.value)

    async def _signal_session_cancellation(self, session_id: str) -> tuple[int, int]:
        return await self._cancel_session(session_id)

    def _observe_session_cancellation(
        self,
        task: asyncio.Task[tuple[int, int]],
    ) -> None:
        self._session_cancellation_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def mint_admin_login_code(self) -> ControlAdminLoginCode:
        minted = await self._admin_auth.mint_login_code()
        return ControlAdminLoginCode(code=minted.code, expires_at_ms=minted.expires_at_ms)

    async def request_drain(self) -> ControlDrainResult:
        async with self._drain_lock:
            if self._drain_requested:
                return ControlDrainResult(requested=False)
            if self._mark_draining is not None:
                self._mark_draining()
            if isinstance(self._shutdown, asyncio.Event):
                self._shutdown.set()
            else:
                result = self._shutdown()
                if inspect.isawaitable(result):
                    await result
            self._drain_requested = True
            return ControlDrainResult(requested=True)


def create_local_control_router(
    *,
    capability: ControlCapabilityVerifier,
    service: LocalControlService,
    config_digest: str | None = None,
) -> APIRouter:
    """Bind versioned control mutations to one verified configuration digest."""

    bound_config_digest = ControlDaemonStatus.validate_config_digest(config_digest)

    async def authenticate_control(request: Request) -> None:
        supplied_values = request.headers.getlist(CONTROL_CAPABILITY_HEADER)
        supplied = supplied_values[0] if len(supplied_values) == 1 else None
        if not capability.verify(supplied):
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False)

    class _ConfigurationBoundControlRoute(APIRoute):
        def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
            original_handler = super().get_route_handler()
            has_typed_body = self.body_field is not None

            async def guarded(request: Request) -> Response:
                await authenticate_control(request)
                if request.method == "POST":
                    values = request.headers.getlist(CONTROL_CONFIG_DIGEST_HEADER)
                    supplied_digest: str | None
                    try:
                        supplied_digest = ControlDaemonStatus.validate_config_digest(
                            values[0] if len(values) == 1 else None
                        )
                    except ValueError:
                        supplied_digest = None
                    if bound_config_digest is None or supplied_digest != bound_config_digest:
                        raise make_error(ErrorCode.POLICY_DENIED, retryable=False)
                    # The stock middleware binds this private key only on its
                    # deferred path; bare or replaced receivers cannot admit work.
                    if request.scope.get("gatehouse.bounded_body_receive") is not request.receive:
                        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)
                    try:
                        if has_typed_body:
                            # Read through the stock bounded receive before FastAPI's
                            # parser can translate a byte/deadline refusal to HTTP 400.
                            # The original typed handler consumes these cached bytes.
                            await request.body()
                        else:
                            async for chunk in request.stream():
                                if chunk:
                                    raise make_error(
                                        ErrorCode.SCHEMA_VALIDATION_FAILED, retryable=False
                                    )
                    except ClientDisconnect:
                        raise HTTPException(status_code=400) from None
                return await original_handler(request)

            return guarded

    router = APIRouter(route_class=_ConfigurationBoundControlRoute)

    @router.get("/v1/control/status")
    async def status() -> JSONResponse:
        return JSONResponse(content=(await service.status()).model_dump(mode="json"))

    @router.post("/v2/control/drain")
    async def drain() -> JSONResponse:
        return JSONResponse(content=(await service.request_drain()).model_dump(mode="json"))

    @router.post("/v2/control/sessions", status_code=201)
    async def launch_session(body: ControlSessionLaunchRequest) -> JSONResponse:
        try:
            launched = await service.launch_session(body)
        except ControlAuthorityError as error:
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False) from error
        except (SessionCreationRequestConflict, SessionCreationOutcomeUnresolved) as error:
            raise make_error(ErrorCode.UNCERTAIN_OUTCOME, retryable=False) from error
        except SessionRunCapacityExceeded as error:
            raise make_error(
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=1,
            ) from error
        except SessionRunawayQuarantined as error:
            raise make_error(
                ErrorCode.RUNAWAY_SUSPECTED,
                retryable=False,
                details={
                    "authorization_required": True,
                    "scope": "client_profile",
                },
            ) from error
        return JSONResponse(status_code=201, content=launched.model_dump(mode="json"))

    @router.post("/v2/control/session-requests/cancel")
    async def cancel_session_request(body: ControlSessionRequestCancellation) -> JSONResponse:
        try:
            result = await service.cancel_session_request(body.request_id)
        except (
            SessionCreationRequestConflict,
            SessionCreationOutcomeUnresolved,
            SessionUnavailable,
        ) as error:
            raise make_error(ErrorCode.UNCERTAIN_OUTCOME, retryable=False) from error
        return JSONResponse(content=result.model_dump(mode="json"))

    async def mutate_session(session_id: str, *, revoke: bool) -> JSONResponse:
        try:
            result = (
                await service.revoke_session(session_id)
                if revoke
                else await service.disconnect_session(session_id)
            )
        except (ControlAuthorityError, SessionUnavailable) as error:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False) from error
        return JSONResponse(content=result.model_dump(mode="json"))

    @router.post("/v2/control/sessions/{session_id}/disconnect")
    async def disconnect_session(session_id: str) -> JSONResponse:
        return await mutate_session(session_id, revoke=False)

    @router.post("/v2/control/sessions/{session_id}/revoke")
    async def revoke_session(session_id: str) -> JSONResponse:
        return await mutate_session(session_id, revoke=True)

    @router.post("/v2/control/admin/login-code")
    async def mint_admin_login_code() -> JSONResponse:
        try:
            minted = await service.mint_admin_login_code()
        except AdminAuthCapacityExceeded as error:
            raise make_error(
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=5,
            ) from error
        return JSONResponse(content=minted.model_dump(mode="json"))

    return router
