"""Configuration attestation through in-memory health and authenticated ASGI adapters."""

from __future__ import annotations

import asyncio
import json
from typing import Any, NotRequired, TypedDict, cast

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gatehouse.admin.control import (
    CONTROL_CAPABILITY_HEADER,
    CONTROL_CONFIG_DIGEST_HEADER,
    ControlAdminLoginCode,
    ControlDaemonStatus,
    ControlDrainResult,
    ControlSessionLaunch,
    ControlSessionLaunchRequest,
    ControlSessionMutation,
    ControlSessionRequestCancelled,
    LocalControlService,
    create_local_control_router,
)
from gatehouse.admin.control_capability import ControlCapabilityVerifier
from gatehouse.api.admin import _defer_sensitive_admin_body
from gatehouse.api.errors import install_error_handlers
from gatehouse.api.middleware import LocalRequestBoundsMiddleware
from gatehouse.daemon.composition import _ControlHealthAdapter
from gatehouse.daemon.health import RuntimeHealthProbe

DIGEST = "0123456789abcdef" * 4
CAPABILITY = "c" * 43


class _StatusFields(TypedDict):
    ready: bool
    status: str
    version: str
    schema_version: int
    policy_version: str
    uptime_seconds: int
    degraded_components: list[str]
    workload: None


class _DigestField(TypedDict):
    config_digest: NotRequired[None]


def _status_fields() -> _StatusFields:
    return {
        "ready": True,
        "status": "READY",
        "version": "synthetic",
        "schema_version": 16,
        "policy_version": "synthetic",
        "uptime_seconds": 0,
        "degraded_components": [],
        "workload": None,
    }


@pytest.mark.parametrize(
    "digest",
    (
        True,
        7,
        b"a" * 64,
        "",
        "a" * 63,
        "a" * 65,
        "A" * 64,
        " " + DIGEST,
        DIGEST + " ",
        DIGEST + "\n",
        "z" * 64,
    ),
)
def test_control_status_rejects_digest_coercion_or_normalization(digest: object) -> None:
    with pytest.raises(ValidationError):
        ControlDaemonStatus(**_status_fields(), config_digest=cast(str, digest))


def test_control_status_serializes_exact_digest_and_explicit_unverified_state() -> None:
    variants: tuple[_DigestField, ...] = ({}, {"config_digest": None})
    for fields in variants:
        unverified = ControlDaemonStatus(**_status_fields(), **fields)
        assert unverified.config_digest is None
        assert unverified.model_dump(mode="json")["config_digest"] is None
    verified = ControlDaemonStatus(**_status_fields(), config_digest=DIGEST)
    encoded = json.loads(verified.model_dump_json())
    assert encoded == {**_status_fields(), "config_digest": DIGEST}
    assert ControlDaemonStatus.model_validate_json(verified.model_dump_json()) == verified
    with pytest.raises(ValidationError):
        cast(Any, verified).config_digest = "b" * 64


def _health() -> RuntimeHealthProbe:
    return RuntimeHealthProbe(
        version="synthetic",
        schema_version=16,
        policy_version="synthetic",
        now_ms=lambda: 1_000,
        started_at_ms=1_000,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", (None, DIGEST))
async def test_control_adapter_retains_attestation_across_health_transitions(
    digest: str | None,
) -> None:
    health = _health()
    adapter = _ControlHealthAdapter(health, config_digest=digest)
    for state in ("RECOVERING", "READY", "DEGRADED_NO_PROVIDER", "FAILED_CLOSED"):
        health.transition(state)
        status = await adapter.readiness()
        assert status.config_digest == digest
        assert status.status == state
        assert status.ready is (state == "READY")
        assert "config_digest" not in (await health.readiness()).model_dump(mode="json")


@pytest.mark.asyncio
@pytest.mark.parametrize("authorization", ("missing", "wrong", "duplicate", "valid"))
async def test_control_route_authenticates_before_exposing_frozen_attestation(
    authorization: str,
) -> None:
    health = _health()
    health.transition("DEGRADED_NO_PROVIDER")
    adapter = _ControlHealthAdapter(health, config_digest=DIGEST)
    reads: list[str] = []
    supplied: list[str | None] = []

    class CountingHealth:
        async def readiness(self) -> ControlDaemonStatus:
            reads.append("readiness")
            return await adapter.readiness()

    class Capability:
        def verify(self, value: str | None) -> bool:
            supplied.append(value)
            return value == CAPABILITY

    class ForbiddenMutation:
        def __getattr__(self, name: str) -> object:
            pytest.fail("status accessed a mutation service")

    async def cancel_session(_: str) -> tuple[int, int]:
        pytest.fail("status cancelled a session")

    service = LocalControlService(
        sessions=ForbiddenMutation(),  # type: ignore[arg-type]
        admin_auth=ForbiddenMutation(),  # type: ignore[arg-type]
        health=CountingHealth(),
        launch_authorities={},
        shutdown=lambda: pytest.fail("status requested shutdown"),
        cancel_session=cancel_session,
    )
    app = FastAPI()
    install_error_handlers(app)
    app.include_router(
        create_local_control_router(
            capability=cast(ControlCapabilityVerifier, Capability()),
            service=service,
        )
    )
    headers = {
        "missing": [],
        "wrong": [(CONTROL_CAPABILITY_HEADER, "w" * 43)],
        "duplicate": [(CONTROL_CAPABILITY_HEADER, CAPABILITY)] * 2,
        "valid": [(CONTROL_CAPABILITY_HEADER, CAPABILITY)],
    }[authorization]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.get("/v1/control/status", headers=headers)
    assert supplied == [{"valid": CAPABILITY, "wrong": "w" * 43}.get(authorization)]
    if authorization == "valid":
        assert response.status_code == 200
        assert response.json() == {
            **_status_fields(),
            "ready": False,
            "status": "DEGRADED_NO_PROVIDER",
            "config_digest": DIGEST,
            "workload": {
                "status": "UNVERIFIED",
                "ready": False,
                "scope": "ordinary_new_work",
                "watcher_assessed": False,
                "request_authorization_assessed": False,
                "provider_reachability_verified": False,
                "checked_at_ms": None,
                "binding_count": 0,
                "required_routes": 0,
                "eligible_routes": 0,
                "ineligible_routes": 0,
                "unverified_routes": 0,
            },
        }
        assert reads == ["readiness"]
    else:
        assert response.status_code == 401
        assert reads == []
        assert "config_digest" not in response.text
        assert DIGEST not in response.text
        assert CAPABILITY not in response.text


_MUTATIONS = (
    "drain",
    "sessions",
    "sessions/ses_one/disconnect",
    "sessions/ses_one/revoke",
    "admin/login-code",
    "session-requests/cancel",
)
_SESSION_BODY = {
    "request_id": "1" * 32,
    "client": "synthetic",
    "workspace": "synthetic",
    "working_directory": r"C:\synthetic\workspace",
    "non_interactive": False,
}


def _mutation_app(
    *,
    digest: str | None = DIGEST,
    status_digest: str = DIGEST,
    bounds_mode: str = "normal",
) -> tuple[ASGIApp, list[str], list[str]]:
    effects: list[str] = []
    events: list[str] = []

    def effect(name: str) -> None:
        effects.append(name)
        events.append("effect")

    class Capability:
        def verify(self, value: str | None) -> bool:
            events.append("capability")
            return value == CAPABILITY

    class Service:
        async def status(self) -> ControlDaemonStatus:
            return ControlDaemonStatus(**_status_fields(), config_digest=status_digest)

        async def request_drain(self) -> ControlDrainResult:
            effect("drain")
            return ControlDrainResult(requested=True)

        async def launch_session(self, body: ControlSessionLaunchRequest) -> ControlSessionLaunch:
            assert type(body) is ControlSessionLaunchRequest
            assert body.model_dump(mode="json") == _SESSION_BODY
            effect("sessions")
            return ControlSessionLaunch(
                session_id="ses_one",
                bootstrap_capability="b" * 43,
                client_id="client_one",
                workspace_id="workspace_one",
                working_directory=body.working_directory,
                identity_assurance="CONTROLLED_INTERACTIVE_LAUNCH",
                policy_version="synthetic",
                absolute_expires_at_ms=1_000,
            )

        async def disconnect_session(self, session_id: str) -> ControlSessionMutation:
            assert session_id == "ses_one"
            effect("sessions/ses_one/disconnect")
            return ControlSessionMutation(session_id=session_id, state="DISCONNECTED")

        async def revoke_session(self, session_id: str) -> ControlSessionMutation:
            assert session_id == "ses_one"
            effect("sessions/ses_one/revoke")
            return ControlSessionMutation(session_id=session_id, state="REVOKED")

        async def mint_admin_login_code(self) -> ControlAdminLoginCode:
            effect("admin/login-code")
            return ControlAdminLoginCode(code="l" * 43, expires_at_ms=1_000)

        async def cancel_session_request(self, request_id: str) -> ControlSessionRequestCancelled:
            assert request_id == "1" * 32
            effect("session-requests/cancel")
            return ControlSessionRequestCancelled(request_id=request_id)

    app = FastAPI()
    install_error_handlers(app)
    app.include_router(
        create_local_control_router(
            capability=cast(ControlCapabilityVerifier, Capability()),
            service=cast(LocalControlService, Service()),
            config_digest=digest,
        )
    )
    assert bounds_mode in {"normal", "bare", "substituted"}
    if bounds_mode == "substituted":

        class SubstitutedReceive:
            def __init__(self, app: ASGIApp) -> None:
                self.app = app

            async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
                assert scope.get("gatehouse.bounded_body_receive") is receive

                async def substitute() -> Message:
                    return cast(Message, await receive())

                await self.app(scope, substitute, send)

        app.add_middleware(SubstitutedReceive)
    if bounds_mode != "bare":
        app.add_middleware(
            LocalRequestBoundsMiddleware,
            allowed_hosts={"127.0.0.1"},
            maximum_body_bytes=512,
            defer_body_read=_defer_sensitive_admin_body,
            total_body_timeout_ms=40,
            inter_chunk_timeout_ms=20,
        )
    return app, effects, events


def _headers(digest: str = DIGEST) -> list[tuple[str, str]]:
    return [(CONTROL_CAPABILITY_HEADER, CAPABILITY), (CONTROL_CONFIG_DIGEST_HEADER, digest)]


async def _asgi_request(
    app: ASGIApp,
    events: list[str],
    path: str,
    *,
    headers: list[tuple[str, str]],
    method: str = "POST",
    chunks: tuple[bytes, ...] = (b"",),
    stall: bool = False,
    disconnect: bool = False,
) -> tuple[int, dict[str, object]]:
    sent: list[Message] = []
    position = 0
    scope = cast(
        Scope,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "root_path": "",
            "query_string": b"",
            "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"application/json")]
            + [(name.encode("ascii"), value.encode("ascii")) for name, value in headers],
            "server": ("127.0.0.1", 80),
            "client": ("127.0.0.1", 12_345),
        },
    )

    async def receive() -> Message:
        nonlocal position
        events.append("receive")
        if stall:
            try:
                await asyncio.Event().wait()
            finally:
                events.append("receive_finished")
        if disconnect or position >= len(chunks):
            return {"type": "http.disconnect"}
        body = chunks[position]
        position += 1
        return {"type": "http.request", "body": body, "more_body": position < len(chunks)}

    async def send(message: Message) -> None:
        sent.append(message)

    await asyncio.wait_for(app(scope, receive, send), timeout=1.0)
    assert "gatehouse.bounded_body_receive" not in scope
    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert len(starts) == 1
    raw = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    decoded = json.loads(raw)
    assert type(decoded) is dict
    return starts[0]["status"], decoded


def _assert_policy_refusal(status: int, body: dict[str, object]) -> None:
    assert status == 403
    error = cast(dict[str, object], body["error"])
    assert error["code"] == "policy_denied"
    assert error["message"] == "Policy denied the operation."
    assert error["retryable"] is False
    rendered = json.dumps(body)
    assert DIGEST not in rendered
    assert "b" * 64 not in rendered
    assert CAPABILITY not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize("bounds_mode", ("bare", "substituted"))
async def test_mutation_refuses_missing_or_substituted_bounded_receive_before_body(
    bounds_mode: str,
) -> None:
    app, effects, events = _mutation_app(bounds_mode=bounds_mode)
    status, body = await _asgi_request(
        app,
        events,
        "/v2/control/sessions",
        headers=_headers(),
        chunks=(b"SYNTHETIC_BODY_MUST_NOT_BE_READ",),
    )
    assert status == 503
    error = cast(dict[str, object], body["error"])
    assert error["code"] == "daemon_degraded"
    assert error["retryable"] is False
    assert events == ["capability"]
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _MUTATIONS)
@pytest.mark.parametrize("defect", ("missing", "mismatch", "unbound_server"))
async def test_every_control_mutation_requires_its_own_matching_digest_before_body(
    route: str,
    defect: str,
) -> None:
    app, effects, events = _mutation_app(digest=None if defect == "unbound_server" else DIGEST)
    headers = _headers("b" * 64 if defect == "mismatch" else DIGEST)
    if defect == "missing":
        headers = headers[:1]
    status, body = await _asgi_request(
        app,
        events,
        "/v2/control/" + route,
        headers=headers,
        chunks=(b"SYNTHETIC_BODY_MUST_NOT_BE_READ",),
    )
    _assert_policy_refusal(status, body)
    assert events == ["capability"]
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "defect",
    (
        "uppercase",
        "leading",
        "trailing",
        "newline",
        "short",
        "long",
        "nonhex",
        "empty",
        "number",
        "bool",
        "duplicate_same",
        "duplicate_mixed",
    ),
)
async def test_mutation_header_is_single_exact_lowercase_digest_before_json(defect: str) -> None:
    app, effects, events = _mutation_app()
    values = {
        "uppercase": DIGEST.upper(),
        "leading": " " + DIGEST,
        "trailing": DIGEST + " ",
        "newline": DIGEST + "\n",
        "short": DIGEST[:-1],
        "long": DIGEST + "0",
        "nonhex": "z" * 64,
        "empty": "",
        "number": "7",
        "bool": "True",
    }
    headers = _headers(values.get(defect, DIGEST))
    if defect.startswith("duplicate"):
        headers.append(
            (CONTROL_CONFIG_DIGEST_HEADER, DIGEST if defect == "duplicate_same" else "b" * 64)
        )
    status, body = await _asgi_request(
        app,
        events,
        "/v2/control/sessions",
        headers=headers,
        chunks=(b"{",),
    )
    _assert_policy_refusal(status, body)
    assert effects == []
    assert events == ["capability"]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _MUTATIONS)
async def test_capability_refusal_precedes_digest_and_body_for_every_mutation(route: str) -> None:
    app, effects, events = _mutation_app(digest=None)
    status, body = await _asgi_request(
        app,
        events,
        "/v2/control/" + route,
        headers=[],
        chunks=(b"{",),
    )
    assert status == 401
    assert cast(dict[str, object], body["error"])["code"] == "invalid_session"
    assert events == ["capability"]
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("authorization", ("wrong", "duplicate"))
async def test_invalid_capability_cannot_reach_mutation_digest_admission(
    authorization: str,
) -> None:
    app, effects, events = _mutation_app()
    headers = _headers()
    if authorization == "wrong":
        headers[0] = (CONTROL_CAPABILITY_HEADER, "w" * 43)
    else:
        headers.append(headers[0])
    status, _ = await _asgi_request(app, events, "/v2/control/sessions", headers=headers)
    assert status == 401
    assert events == ["capability"]
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _MUTATIONS)
async def test_matching_mutation_digest_reaches_only_its_typed_service(route: str) -> None:
    app, effects, events = _mutation_app()
    raw = json.dumps(_SESSION_BODY).encode("utf-8") if route == "sessions" else b""
    if route == "session-requests/cancel":
        raw = json.dumps({"request_id": "1" * 32}).encode("utf-8")
    status, _ = await _asgi_request(
        app,
        events,
        "/v2/control/" + route,
        headers=_headers(),
        chunks=(raw,),
    )
    assert status == (201 if route == "sessions" else 200)
    assert effects == [route]
    assert events[0] == "capability"
    assert events.count("receive") == 1
    assert events.index("receive") < events.index("effect")


@pytest.mark.asyncio
@pytest.mark.parametrize("route", _MUTATIONS)
async def test_old_control_post_paths_cannot_mutate_even_with_both_headers(route: str) -> None:
    app, effects, events = _mutation_app()
    status, body = await _asgi_request(app, events, "/v1/control/" + route, headers=_headers())
    assert status == 404
    assert cast(dict[str, object], body["error"])["code"] == "invalid_target"
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route",
    tuple(route for route in _MUTATIONS if route not in {"sessions", "session-requests/cancel"}),
)
async def test_bodyless_mutation_refuses_nonempty_body_before_effect(route: str) -> None:
    app, effects, events = _mutation_app()
    status, body = await _asgi_request(
        app,
        events,
        "/v2/control/" + route,
        headers=_headers(),
        chunks=(b" ", b"ignored"),
    )
    assert status == 422
    assert cast(dict[str, object], body["error"])["code"] == "schema_validation_failed"
    assert events.count("receive") == 1
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("defect", ("malformed_json", "wrong_type", "extra_field"))
async def test_matching_digest_preserves_strict_session_body_parsing(defect: str) -> None:
    app, effects, events = _mutation_app()
    body = dict(_SESSION_BODY)
    if defect == "wrong_type":
        body["non_interactive"] = "false"
    elif defect == "extra_field":
        body["unexpected"] = True
    raw = b"{" if defect == "malformed_json" else json.dumps(body).encode("utf-8")
    status, response = await _asgi_request(
        app,
        events,
        "/v2/control/sessions",
        headers=_headers(),
        chunks=(raw,),
    )
    assert status == 422
    assert cast(dict[str, object], response["error"])["code"] == "schema_validation_failed"
    assert events[0] == "capability"
    assert events.count("receive") == 1
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ("at_limit", "over_limit", "stalled", "disconnected"))
async def test_session_admission_retains_body_byte_deadline_and_disconnect_bounds(
    case: str,
) -> None:
    app, effects, events = _mutation_app()
    raw = json.dumps(_SESSION_BODY).encode("utf-8")
    assert len(raw) < 512
    raw = raw + b" " * (512 - len(raw) + (case == "over_limit"))
    status, _ = await _asgi_request(
        app,
        events,
        "/v2/control/sessions",
        headers=_headers(),
        chunks=(raw,),
        stall=case == "stalled",
        disconnect=case == "disconnected",
    )
    assert status == {"at_limit": 201, "over_limit": 413, "stalled": 408, "disconnected": 400}[case]
    assert effects == (["sessions"] if case == "at_limit" else [])
    assert events[0] == "capability"
    assert events.count("receive") == 1
    if case == "stalled":
        assert events.count("receive_finished") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ("over_limit", "stalled", "disconnected"))
async def test_bodyless_admission_retains_middleware_bounds_and_disconnect_refusal(
    case: str,
) -> None:
    app, effects, events = _mutation_app()
    status, _ = await _asgi_request(
        app,
        events,
        "/v2/control/drain",
        headers=_headers(),
        chunks=(b"x" * 513,),
        stall=case == "stalled",
        disconnect=case == "disconnected",
    )
    assert status == {"over_limit": 413, "stalled": 408, "disconnected": 400}[case]
    assert events[0] == "capability"
    assert events.count("receive") == 1
    assert effects == []
    if case == "stalled":
        assert events.count("receive_finished") == 1


@pytest.mark.asyncio
async def test_status_digest_a_cannot_authorize_mutation_of_frozen_daemon_b() -> None:
    first_app, first_effects, first_events = _mutation_app()
    status, observed = await _asgi_request(
        first_app,
        first_events,
        "/v1/control/status",
        method="GET",
        headers=_headers()[:1],
    )
    assert status == 200
    assert observed["config_digest"] == DIGEST
    app, effects, events = _mutation_app(digest="b" * 64, status_digest="b" * 64)
    status, body = await _asgi_request(
        app,
        events,
        "/v2/control/drain",
        headers=_headers(observed["config_digest"]),
    )
    _assert_policy_refusal(status, body)
    assert events == ["capability"]
    assert first_effects == []
    assert effects == []
