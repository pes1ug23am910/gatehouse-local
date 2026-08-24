from __future__ import annotations

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
from gatehouse.api.errors import install_error_handlers
from gatehouse.core.admission import RuntimeAdmissionController
from gatehouse.core.ids import ClientId, WorkspaceId
from gatehouse.core.states import SessionState
from gatehouse.sessions import RootRunRecord, SessionManager, SessionRecord

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_CONTROL_HEADER = "x-gatehouse-control-capability"


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

    async def begin_daemon_epoch(self, *, now_ms: int, reconnect_grace_ms: int) -> int:
        del now_ms, reconnect_grace_ms
        return 1

    async def insert_session(self, session: SessionRecord) -> None:
        if session.session_id in self.sessions:
            raise ValueError("duplicate session")
        self.sessions[session.session_id] = session

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

    async def insert_root_run(self, root_run: RootRunRecord) -> None:
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
        protector = FakeProtector()
        protected_path = tmp_path / "control.dpapi"
        verifier_path = tmp_path / "control.verifier"
        provision_control_capability(
            protected_path=protected_path,
            verifier_path=verifier_path,
            protector=protector,
            random_bytes=lambda length: b"c" * length,
        )
        self.capability = load_control_capability(protected_path, protector=protector)
        verifier = load_control_capability_verifier(verifier_path)
        self.health = MutableHealth()
        self.workspace_root = (tmp_path / "workspace-one").resolve()
        self.workspace_root.mkdir()
        self.workspace_child = self.workspace_root / "nested"
        self.workspace_child.mkdir()
        self.shutdown_requested = False
        self.shutdown_calls = 0

        def shutdown() -> None:
            self.shutdown_requested = True
            self.shutdown_calls += 1

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
                budget={"requests": 10, "credits": 50},
            ),
        }
        service = LocalControlService(
            sessions=self.sessions,
            admin_auth=self.admin_auth,
            health=self.health,
            launch_authorities=authorities,
            shutdown=shutdown,
            mark_draining=self.health.mark_draining,
            admission=admission,
        )
        self.app = FastAPI()
        self.app.include_router(
            create_local_control_router(
                capability=verifier,
                service=service,
            )
        )
        install_error_handlers(self.app)

    @property
    def headers(self) -> dict[str, str]:
        return {_CONTROL_HEADER: self.capability}


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
        ("POST", "/v1/control/drain", None),
        (
            "POST",
            "/v1/control/sessions",
            {
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": r"C:\Gatehouse\workspace-one",
                "non_interactive": False,
            },
        ),
        ("POST", f"/v1/control/sessions/ses_{_A}/disconnect", None),
        ("POST", f"/v1/control/sessions/ses_{_A}/revoke", None),
        ("POST", "/v1/control/admin/login-code", None),
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
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "unconfigured-workspace",
                "working_directory": str(fixture.workspace_root),
                "non_interactive": False,
            },
        )
        launched = await client.post(
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_child),
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
async def test_launch_schema_requires_the_actual_working_directory(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
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
            "non_interactive": True,
        },
        {
            "client": "watcher-one",
            "workspace": "workspace-one",
            "working_directory": str(fixture.workspace_root),
            "non_interactive": False,
        },
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        responses = [
            await client.post(
                "/v1/control/sessions",
                headers=fixture.headers,
                json=payload,
            )
            for payload in requests
        ]
        accepted = await client.post(
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "watcher-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
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
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "non_interactive": False,
            },
        )
        first_body = first.json()
        await fixture.sessions.exchange_bootstrap(
            session_id=first_body["session_id"],
            bootstrap_capability=first_body["bootstrap_capability"],
        )
        disconnected = await client.post(
            f"/v1/control/sessions/{first_body['session_id']}/disconnect",
            headers=fixture.headers,
        )
        second = await client.post(
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
                "non_interactive": False,
            },
        )
        revoked = await client.post(
            f"/v1/control/sessions/{second.json()['session_id']}/revoke",
            headers=fixture.headers,
        )
        minted = await client.post(
            "/v1/control/admin/login-code",
            headers=fixture.headers,
        )

    assert disconnected.json()["state"] == SessionState.DISCONNECTED
    assert revoked.json()["state"] == SessionState.REVOKED
    code = minted.json()["code"]
    await fixture.admin_auth.exchange_login_code(code)
    with pytest.raises(AdminAuthenticationError):
        await fixture.admin_auth.exchange_login_code(code)


@pytest.mark.asyncio
async def test_status_and_drain_signal_are_authenticated_and_idempotent(tmp_path: Path) -> None:
    fixture = ControlFixture(tmp_path)
    transport = httpx.ASGITransport(app=fixture.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ready = await client.get("/v1/control/status", headers=fixture.headers)
        first = await client.post("/v1/control/drain", headers=fixture.headers)
        repeated = await client.post("/v1/control/drain", headers=fixture.headers)
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
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(fixture.workspace_root),
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
            "non_interactive": False,
        },
        {
            "client": "editor-one",
            "workspace": "workspace-one",
            "working_directory": str(tmp_path / "missing"),
            "non_interactive": False,
        },
        {
            "client": "editor-one",
            "workspace": "workspace-one",
            "working_directory": "child",
            "non_interactive": False,
        },
    )

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        responses = [
            await client.post("/v1/control/sessions", headers=fixture.headers, json=payload)
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
            "/v1/control/sessions",
            headers=fixture.headers,
            json={
                "client": "editor-one",
                "workspace": "workspace-one",
                "working_directory": str(linked),
                "non_interactive": False,
            },
        )

    assert response.status_code == 201
    assert response.json()["working_directory"] == str(fixture.workspace_root)
