from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from gatehouse.admin import (
    AdminAuthenticationError,
    AdminAuthManager,
    ControlDaemonStatus,
    ControlLaunchAuthority,
    LocalControlService,
    create_local_control_router,
    load_control_capability,
    load_control_capability_verifier,
    provision_control_capability,
)
from gatehouse.admin.control_capability import ControlCapabilityVerifier
from gatehouse.api.admin import _defer_sensitive_admin_body
from gatehouse.api.errors import install_error_handlers
from gatehouse.api.middleware import LocalRequestBoundsMiddleware
from gatehouse.core.admission import RuntimeAdmissionController
from gatehouse.core.ids import ClientId, WorkspaceId
from gatehouse.core.states import SessionState
from gatehouse.sessions import (
    RootRunRecord,
    SessionCreationRequest,
    SessionCreationRequestConflict,
    SessionManager,
    SessionRecord,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_CONTROL_HEADER = "x-gatehouse-control-capability"
_CONFIG_DIGEST_HEADER = "x-gatehouse-expected-config-digest"
_CONFIG_DIGEST = hashlib.sha256(b"synthetic control fixture configuration").hexdigest()


class FakeProtector:
    def protect(self, plaintext: bytes) -> bytes:
        return b"protected:" + bytes(value ^ 0xA5 for value in plaintext)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        if not ciphertext.startswith(b"protected:"):
            raise OSError("invalid protected value")
        return bytearray(value ^ 0xA5 for value in ciphertext.removeprefix(b"protected:"))


class FakeClock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class DeterministicRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        seed = hashlib.sha512(f"control-{self.counter}".encode()).digest()
        return (seed * ((length + len(seed) - 1) // len(seed)))[:length]


class MemorySessionPersistence:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionRecord] = {}
        self.root_runs: dict[str, RootRunRecord] = {}
        self.insert_error: Exception | None = None
        self.creation_requests: dict[str, str | None] = {}
        self.creation_authority: dict[str, str] = {}

    async def begin_daemon_epoch(self, *, now_ms: int, reconnect_grace_ms: int) -> int:
        del now_ms, reconnect_grace_ms
        return 1

    async def insert_session(
        self,
        session: SessionRecord,
        *,
        maximum_concurrent_runs: int | None,
        stale_after_ms: int,
        reconnect_grace_ms: int,
        block_on_runaway_quarantine: bool,
        creation_request: SessionCreationRequest | None = None,
    ) -> None:
        del maximum_concurrent_runs, stale_after_ms, reconnect_grace_ms
        del block_on_runaway_quarantine
        if self.insert_error is not None:
            raise self.insert_error
        if creation_request is not None:
            key = creation_request.request_id
            if key in self.creation_requests:
                raise SessionCreationRequestConflict()
            self.creation_requests[key] = session.session_id
            self.creation_authority[key] = creation_request.authority_digest
        if session.session_id in self.sessions:
            raise ValueError("duplicate session")
        self.sessions[session.session_id] = session

    async def cancel_session_request(self, request_id: str, *, now_ms: int) -> str | None:
        del now_ms
        return self.creation_requests.setdefault(request_id, None)

    async def load_session(self, session_id: str) -> SessionRecord | None:
        return self.sessions.get(session_id)

    async def replace_session(
        self,
        *,
        expected: SessionRecord,
        replacement: SessionRecord,
    ) -> bool:
        if self.sessions.get(expected.session_id) != expected:
            return False
        self.sessions[expected.session_id] = replacement
        return True

    async def insert_root_run(
        self,
        root_run: RootRunRecord,
        *,
        client_id: str,
        maximum_concurrent_runs: int | None,
        now_ms: int,
        stale_after_ms: int,
        reconnect_grace_ms: int,
        block_on_runaway_quarantine: bool,
    ) -> None:
        del client_id, maximum_concurrent_runs, now_ms, stale_after_ms, reconnect_grace_ms
        del block_on_runaway_quarantine
        self.root_runs[root_run.root_run_id] = root_run

    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None:
        return self.root_runs.get(root_run_id)


class MutableHealth:
    def __init__(self) -> None:
        self.state = "READY"

    async def readiness(self) -> ControlDaemonStatus:
        return ControlDaemonStatus(
            ready=self.state == "READY",
            status=self.state,
            version="0.0.1",
            schema_version=5,
            policy_version="policy-v1",
            uptime_seconds=12,
            degraded_components=[],
            config_digest=_CONFIG_DIGEST,
        )

    def mark_draining(self) -> None:
        self.state = "DRAINING"


class ControlFixture:
    def __init__(
        self,
        tmp_path: Path,
        *,
        admission: RuntimeAdmissionController | None = None,
    ) -> None:
        self.clock = FakeClock()
        self.persistence = MemorySessionPersistence()
        self.sessions = SessionManager(
            persistence=self.persistence,
            verifier_key=b"s" * 32,
            token_epoch=1,
            now_ms=self.clock,
            random_bytes=DeterministicRandom(),
            access_token_ttl_ms=500,
            reconnect_grace_ms=2_000,
            maximum_access_tokens=16,
        )
        self.admin_auth = AdminAuthManager(
            verifier_key=b"a" * 32,
            now_ms=self.clock,
            random_bytes=DeterministicRandom(),
        )
        # Route tests use explicit in-memory authority; storage has a separate test.
        self.capability = base64.urlsafe_b64encode(b"c" * 32).rstrip(b"=").decode("ascii")
        verifier = ControlCapabilityVerifier._from_raw(b"c" * 32)
        self.health = MutableHealth()
        self.workspace_root = (tmp_path / "workspace-one").resolve()
        self.workspace_root.mkdir()
        self.workspace_child = self.workspace_root / "nested"
        self.workspace_child.mkdir()
        self.shutdown_requested = False
        self.shutdown_calls = 0
        self.cancelled_sessions: list[str] = []

        def shutdown() -> None:
            self.shutdown_requested = True
            self.shutdown_calls += 1

        async def cancel_session(session_id: str) -> tuple[int, int]:
            record = self.persistence.sessions[session_id]
            assert record.state is SessionState.REVOKED
            self.cancelled_sessions.append(session_id)
            return (0, 0)

        authorities: Mapping[tuple[str, str], ControlLaunchAuthority] = {
            ("editor-one", "workspace-one"): ControlLaunchAuthority(
                client_name="editor-one",
                workspace_name="workspace-one",
                client_id=ClientId(f"client_{_A}"),
                workspace_id=WorkspaceId(f"ws_{_A}"),
                canonical_root=str(self.workspace_root),
                unattended=False,
                policy_version="policy-interactive",
                absolute_ttl_ms=10_000,
                maximum_concurrent_runs=2,
                budget={"requests": 30, "credits": 200},
            ),
            ("watcher-one", "workspace-one"): ControlLaunchAuthority(
                client_name="watcher-one",
                workspace_name="workspace-one",
                client_id=ClientId(f"client_{_B}"),
                workspace_id=WorkspaceId(f"ws_{_A}"),
                canonical_root=str(self.workspace_root),
                unattended=True,
                policy_version="policy-unattended",
                absolute_ttl_ms=5_000,
                maximum_concurrent_runs=1,
                budget={"requests": 10, "credits": 50},
            ),
        }
        service = LocalControlService(
            sessions=self.sessions,
            admin_auth=self.admin_auth,
            health=self.health,
            launch_authorities=authorities,
            shutdown=shutdown,
            cancel_session=cancel_session,
            mark_draining=self.health.mark_draining,
            admission=admission,
        )
        self.service = service
        self.app = FastAPI()
        self.app.add_middleware(
            LocalRequestBoundsMiddleware,
            allowed_hosts=("test",),
            maximum_body_bytes=32 * 1_024,
            defer_body_read=_defer_sensitive_admin_body,
        )
        self.app.include_router(
            create_local_control_router(
                capability=verifier,
                service=service,
                config_digest=_CONFIG_DIGEST,
            )
        )
        install_error_handlers(self.app)

    @property
    def headers(self) -> dict[str, str]:
        return {_CONTROL_HEADER: self.capability, _CONFIG_DIGEST_HEADER: _CONFIG_DIGEST}


def _create_directory_link(linked: Path, target: Path) -> bool:
    try:
        linked.symlink_to(target, target_is_directory=True)
        return True
    except OSError:
        command_processor = os.environ.get("COMSPEC")
        if command_processor is None:
            return False
        created = subprocess.run(  # noqa: S603
            (
                str(Path(command_processor).resolve(strict=True)),
                "/d",
                "/c",
                "mklink",
                "/J",
                str(linked),
                str(target),
            ),
            check=False,
            capture_output=True,
        )
        return created.returncode == 0


def test_control_capability_is_split_protected_and_constant_time_verifiable(
    tmp_path: Path,
) -> None:
    protected_path = tmp_path / "control.dpapi"
    verifier_path = tmp_path / "control.verifier"
    protector = FakeProtector()
    created = provision_control_capability(
        protected_path=protected_path,
        verifier_path=verifier_path,
        protector=protector,
        random_bytes=lambda length: b"r" * length,
    )
    loaded = load_control_capability_verifier(verifier_path)
    raw = load_control_capability(protected_path, protector=protector)

    assert created == loaded
    assert loaded.verify(raw)
    assert not loaded.verify(None)
    assert not loaded.verify("")
    assert not loaded.verify("wrong")
    assert raw.encode() not in protected_path.read_bytes()
    assert raw.encode() not in verifier_path.read_bytes()
    assert raw not in repr(loaded)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("GET", "/v1/control/status", None),
        ("POST", "/v2/control/drain", None),
        (
            "POST",
            "/v2/control/sessions",
            {
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": r"C:\Gatehouse\workspace-one",
                "request_id": "00000000000000000000000000000001",
                "non_interactive": False,
            },
        ),
        ("POST", f"/v2/control/sessions/ses_{_A}/disconnect", None),
        ("POST", f"/v2/control/sessions/ses_{_A}/revoke", None),
        ("POST", "/v2/control/admin/login-code", None),
    ],
)
async def test_every_control_route_rejects_missing_and_wrong_capability(
    tmp_path: Path,
    method: str,
    path: str,
    payload: object,
) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.request(method, path, json=payload)
        wrong_capability = "unit-test-wrong-value-must-not-be-echoed"
        wrong = await client.request(
            method,
            path,
            json=payload,
            headers={_CONTROL_HEADER: wrong_capability},
        )

    assert missing.status_code == wrong.status_code == 401
    assert missing.json()["error"]["code"] == "invalid_session"
    assert wrong.json()["error"]["code"] == "invalid_session"
    assert wrong_capability not in wrong.text
    assert not fixture.persistence.sessions
    assert not fixture.shutdown_requested


@pytest.mark.asyncio
async def test_launch_uses_only_exact_injected_authority_and_returns_bootstrap_once(
    tmp_path: Path,
) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        rejected = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "unconfigured-workspace",
                "working_directory": str(fixture.workspace_root),
                "request_id": "00000000000000000000000000000002",
                "non_interactive": False,
            },
        )
        launched = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_child),
                "request_id": "00000000000000000000000000000003",
                "non_interactive": False,
            },
        )

    assert rejected.status_code == 403
    assert launched.status_code == 201
    body = launched.json()
    record = fixture.persistence.sessions[body["session_id"]]
    assert body["client_id"] == f"client_{_A}"
    assert body["workspace_id"] == f"ws_{_A}"
    assert body["working_directory"] == str(fixture.workspace_child)
    assert body["policy_version"] == "policy-interactive"
    assert body["identity_assurance"] == "CONTROLLED_INTERACTIVE_LAUNCH"
    assert record.client_id == f"client_{_A}"
    assert record.workspace_id == f"ws_{_A}"
    assert record.policy_version == "policy-interactive"
    assert record.absolute_expires_at_ms == fixture.clock.value + 10_000
    assert record.budget == {"requests": 30, "credits": 200}
    assert body["bootstrap_capability"].encode() not in record.bootstrap_verifier
    assert len(fixture.persistence.sessions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "code", "details"),
    [
        (
            SessionRunCapacityExceeded("internal profile identifier"),
            "capacity_exceeded",
            {},
        ),
        (
            SessionRunawayQuarantined("internal quarantine identifier"),
            "runaway_suspected",
            {"authorization_required": True, "scope": "client_profile"},
        ),
    ],
)
async def test_controlled_launch_profile_fences_are_sanitized(
    tmp_path: Path,
    error: Exception,
    code: str,
    details: dict[str, object],
) -> None:
    fixture = ControlFixture(tmp_path)
    fixture.persistence.insert_error = error
    transport = httpx.ASGITransport(app=fixture.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "request_id": "00000000000000000000000000000004",
                "non_interactive": False,
            },
        )

    assert response.status_code == 429
    assert response.json()["error"]["code"] == code
    assert response.json()["error"]["details"] == details
    assert "internal" not in response.text


@pytest.mark.asyncio
async def test_launch_schema_requires_the_actual_working_directory(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "request_id": "00000000000000000000000000000005",
                "non_interactive": False,
            },
        )

    assert response.status_code == 422
    assert fixture.persistence.sessions == {}


@pytest.mark.asyncio
async def test_launch_rejects_unattended_mismatch_in_both_directions(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)
    requests = (
        {
            "client": "editor-one",
            "workspace": "workspace-one",
            "working_directory": str(fixture.workspace_root),
            "request_id": "00000000000000000000000000000006",
            "non_interactive": True,
        },
        {
            "client": "watcher-one",
            "workspace": "workspace-one",
            "working_directory": str(fixture.workspace_root),
            "request_id": "00000000000000000000000000000007",
            "non_interactive": False,
        },
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        responses = [
            await client.post(
                "/v2/control/sessions",
                headers=fixture.headers,
                json=payload,
            )
            for payload in requests
        ]
        accepted = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "watcher-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "request_id": "00000000000000000000000000000008",
                "non_interactive": True,
            },
        )

    assert [response.status_code for response in responses] == [403, 403]
    assert accepted.status_code == 201
    accepted_record = fixture.persistence.sessions[accepted.json()["session_id"]]
    assert accepted_record.client_id == f"client_{_B}"
    assert accepted_record.identity_assurance == "CONTROLLED_UNATTENDED_LAUNCH"
    assert accepted_record.absolute_expires_at_ms == fixture.clock.value + 5_000
    assert len(fixture.persistence.sessions) == 1


@pytest.mark.asyncio
async def test_disconnect_revoke_and_admin_code_are_control_capability_bound(
    tmp_path: Path,
) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "request_id": "00000000000000000000000000000009",
                "non_interactive": False,
            },
        )
        first_body = first.json()
        await fixture.sessions.exchange_bootstrap(
            session_id=first_body["session_id"],
            bootstrap_capability=first_body["bootstrap_capability"],
        )
        disconnected = await client.post(
            f"/v2/control/sessions/{first_body['session_id']}/disconnect",
            headers=fixture.headers,
        )
        second = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "request_id": "0000000000000000000000000000000a",
                "non_interactive": False,
            },
        )
        revoked = await client.post(
            f"/v2/control/sessions/{second.json()['session_id']}/revoke",
            headers=fixture.headers,
        )
        minted = await client.post(
            "/v2/control/admin/login-code",
            headers=fixture.headers,
        )

    assert disconnected.json()["state"] == SessionState.DISCONNECTED
    assert revoked.json()["state"] == SessionState.REVOKED
    assert fixture.cancelled_sessions == [second.json()["session_id"]]
    code = minted.json()["code"]
    await fixture.admin_auth.exchange_login_code(code)
    with pytest.raises(AdminAuthenticationError):
        await fixture.admin_auth.exchange_login_code(code)


@pytest.mark.asyncio
async def test_revoke_signalling_survives_request_task_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = ControlFixture(tmp_path)
    launched = await fixture.sessions.create_session(
        client_id=f"client_{_A}",
        workspace_id=f"ws_{_A}",
        identity_assurance="CONTROLLED_INTERACTIVE_LAUNCH",
        policy_version="policy-interactive",
        absolute_ttl_ms=10_000,
    )
    signalling_started = asyncio.Event()
    release_signalling = asyncio.Event()
    signalling_completed = asyncio.Event()

    async def delayed_cancel(session_id: str) -> tuple[int, int]:
        assert session_id == launched.session.session_id
        assert fixture.persistence.sessions[session_id].state is SessionState.REVOKED
        signalling_started.set()
        await release_signalling.wait()
        signalling_completed.set()
        return (0, 1)

    monkeypatch.setattr(fixture.service, "_cancel_session", delayed_cancel)
    request = asyncio.create_task(fixture.service.revoke_session(launched.session.session_id))
    await asyncio.wait_for(signalling_started.wait(), timeout=1)
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request

    release_signalling.set()
    await asyncio.wait_for(signalling_completed.wait(), timeout=1)
    assert fixture.persistence.sessions[launched.session.session_id].state is SessionState.REVOKED


@pytest.mark.asyncio
async def test_status_and_drain_signal_are_authenticated_and_idempotent(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ready = await client.get("/v1/control/status", headers=fixture.headers)
        first = await client.post("/v2/control/drain", headers=fixture.headers)
        repeated = await client.post("/v2/control/drain", headers=fixture.headers)
        draining = await client.get("/v1/control/status", headers=fixture.headers)

    assert ready.json()["status"] == "READY"
    assert first.json() == {"state": "DRAINING", "requested": True}
    assert repeated.json() == {"state": "DRAINING", "requested": False}
    assert draining.json()["status"] == "DRAINING"
    assert fixture.shutdown_requested
    assert fixture.shutdown_calls == 1


@pytest.mark.asyncio
async def test_draining_rejects_new_control_session_launch(tmp_path: Path) -> None:
    admission = RuntimeAdmissionController()
    admission.begin_accepting()
    fixture = ControlFixture(tmp_path, admission=admission)
    admission.begin_draining()
    transport = httpx.ASGITransport(app=fixture.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "request_id": "0000000000000000000000000000000b",
                "non_interactive": False,
            },
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "daemon_degraded"
    assert response.json()["error"]["details"] == {"daemon_state": "DRAINING"}
    assert fixture.persistence.sessions == {}


@pytest.mark.asyncio
async def test_launch_rejects_nonexistent_and_outside_working_directories(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    transport = httpx.ASGITransport(app=fixture.app)
    payloads = (
        {
            "client": "editor-one",
            "workspace": "workspace-one",
            "working_directory": str(outside),
            "request_id": "0000000000000000000000000000000c",
            "non_interactive": False,
        },
        {
            "client": "editor-one",
            "workspace": "workspace-one",
            "working_directory": str(tmp_path / "missing"),
            "request_id": "0000000000000000000000000000000d",
            "non_interactive": False,
        },
        {
            "client": "editor-one",
            "workspace": "workspace-one",
            "working_directory": "child",
            "request_id": "0000000000000000000000000000000e",
            "non_interactive": False,
        },
    )

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        responses = [
            await client.post("/v2/control/sessions", headers=fixture.headers, json=payload)
            for payload in payloads
        ]

    assert [response.status_code for response in responses] == [403, 403, 403]
    assert fixture.persistence.sessions == {}


@pytest.mark.asyncio
async def test_launch_resolves_directory_links_before_workspace_comparison(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    linked = tmp_path / "workspace-link"
    if not _create_directory_link(linked, fixture.workspace_root):
        pytest.skip("directory links and junctions are unavailable")
    transport = httpx.ASGITransport(app=fixture.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v2/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(linked),
                "request_id": "0000000000000000000000000000000f",
                "non_interactive": False,
            },
        )

    assert response.status_code == 201
    assert response.json()["working_directory"] == str(fixture.workspace_root)


@pytest.mark.asyncio
async def test_controlled_launch_requires_client_request_and_never_replays_bootstrap(
    tmp_path: Path,
) -> None:
    fixture = ControlFixture(tmp_path)
    body = {
        "client": "editor-one",
        "workspace": "workspace-one",
        "working_directory": str(fixture.workspace_root),
        "non_interactive": False,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fixture.app),
        base_url="http://test",
        headers=fixture.headers,
    ) as client:
        missing = await client.post("/v2/control/sessions", json=body)
        assert missing.status_code == 422 and not fixture.persistence.sessions
        body["request_id"] = "1" * 32
        launched = await client.post("/v2/control/sessions", json=body)
        replay = await client.post("/v2/control/sessions", json=body)
    assert launched.status_code == 201
    assert replay.json()["error"]["code"] == "uncertain_outcome"
    assert replay.json()["error"]["retryable"] is False
    assert launched.json()["bootstrap_capability"] not in replay.text
    assert len(fixture.persistence.sessions) == 1


@pytest.mark.asyncio
async def test_request_cancellation_before_creation_blocks_late_control_launch(
    tmp_path: Path,
) -> None:
    fixture = ControlFixture(tmp_path)
    request_id = "1" * 32
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fixture.app),
        base_url="http://test",
        headers=fixture.headers,
    ) as client:
        cancelled = await client.post(
            "/v2/control/session-requests/cancel",
            json={"request_id": request_id},
        )
        late = await client.post(
            "/v2/control/sessions",
            json={
                "request_id": request_id,
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "non_interactive": False,
            },
        )
    assert cancelled.status_code == 200
    assert cancelled.json() == {"request_id": request_id, "state": "CANCELLED", "session_id": None}
    assert late.json()["error"]["code"] == "uncertain_outcome"
    assert not fixture.persistence.sessions and not fixture.cancelled_sessions


@pytest.mark.asyncio
async def test_request_cancellation_revokes_only_mapped_session_and_is_idempotent(
    tmp_path: Path,
) -> None:
    fixture = ControlFixture(tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fixture.app),
        base_url="http://test",
        headers=fixture.headers,
    ) as client:
        launched = []
        for request_id in ("1" * 32, "2" * 32):
            response = await client.post(
                "/v2/control/sessions",
                json={
                    "request_id": request_id,
                    "client": "editor-one",
                    "workspace": "workspace-one",
                    "working_directory": str(fixture.workspace_root),
                    "non_interactive": False,
                },
            )
            assert response.status_code == 201
            launched.append(response.json()["session_id"])
        for _ in range(2):
            response = await client.post(
                "/v2/control/session-requests/cancel",
                json={"request_id": "1" * 32},
            )
            assert response.status_code == 200
            assert response.json()["session_id"] == launched[0]
            assert fixture.persistence.sessions[launched[0]].state is SessionState.REVOKED
    assert fixture.persistence.sessions[launched[1]].state is SessionState.CREATED
    assert fixture.cancelled_sessions == [launched[0], launched[0]]


@pytest.mark.asyncio
async def test_request_authority_digest_includes_actual_working_directory(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fixture.app),
        base_url="http://test",
        headers=fixture.headers,
    ) as client:
        for request_id, directory in (
            ("1" * 32, fixture.workspace_root),
            ("2" * 32, fixture.workspace_child),
        ):
            response = await client.post(
                "/v2/control/sessions",
                json={
                    "request_id": request_id,
                    "client": "editor-one",
                    "workspace": "workspace-one",
                    "working_directory": str(directory),
                    "non_interactive": False,
                },
            )
            assert response.status_code == 201
    assert (
        fixture.persistence.creation_authority["1" * 32]
        != (fixture.persistence.creation_authority["2" * 32])
    )


@pytest.mark.asyncio
async def test_request_cancellation_refuses_acknowledgement_until_cancellation_signal_finishes(
    tmp_path: Path,
) -> None:
    fixture = ControlFixture(tmp_path)
    attempts = 0

    async def cancel_signal(session_id: str) -> tuple[int, int]:
        nonlocal attempts
        attempts += 1
        assert fixture.persistence.sessions[session_id].state is SessionState.REVOKED
        if attempts == 1:
            raise RuntimeError("synthetic cancellation delivery failure")
        return 0, 0

    fixture.service._cancel_session = cancel_signal
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fixture.app, raise_app_exceptions=False),
        base_url="http://test",
        headers=fixture.headers,
    ) as client:
        launched = await client.post(
            "/v2/control/sessions",
            json={
                "request_id": "1" * 32,
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "non_interactive": False,
            },
        )
        assert launched.status_code == 201
        first = await client.post(
            "/v2/control/session-requests/cancel",
            json={"request_id": "1" * 32},
        )
        assert first.status_code != 200
        assert "synthetic cancellation delivery failure" not in first.text
        second = await client.post(
            "/v2/control/session-requests/cancel",
            json={"request_id": "1" * 32},
        )
    assert second.status_code == 200 and second.json()["state"] == "CANCELLED"
    assert attempts == 2
