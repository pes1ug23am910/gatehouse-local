from __future__ import annotations

import asyncio
from collections.abc import Sequence

from fastapi.testclient import TestClient

from gatehouse.admin import (
    AdminAuthManager,
    AdminStatus,
    ApprovalActionResult,
    ApprovalDecision,
    ApprovalView,
    CredentialSummary,
    IncidentSummary,
    PoolSummary,
    ReconciliationSummary,
)
from gatehouse.api.admin import CSRF_HEADER_NAME, create_admin_app


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000

    def __call__(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class DeterministicRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, count: int) -> bytes:
        self.counter += 1
        return bytes([self.counter % 251 + 1]) * count


def pending_approval() -> ApprovalView:
    return ApprovalView(
        approval_id="approval-one",
        session_id="ses_one",
        client_id="editor-one",
        workspace_id="workspace-one",
        service="firecrawl",
        operation="crawl.start",
        request_fingerprint="hmac:v1:c1:fingerprint",
        target_summary="careers.example.test/jobs",
        pool="interactive-default",
        maximum_estimated_cost=25,
        expires_at_ms=20_000,
        state="PENDING",
        action_token="t" * 32,
    )


class FakeAdminBackend:
    def __init__(self) -> None:
        self.approval = pending_approval()
        self.decisions: list[ApprovalDecision] = []

    async def status(self) -> AdminStatus:
        return AdminStatus(
            service_state="READY",
            uptime_seconds=10,
            active_sessions=2,
            in_flight_requests=1,
            queued_requests=3,
            pending_approvals=1,
            high_severity_incidents=0,
        )

    async def list_approvals(self, *, limit: int) -> Sequence[ApprovalView]:
        return (self.approval,)[:limit]

    async def get_approval(self, approval_id: str) -> ApprovalView | None:
        return self.approval if approval_id == self.approval.approval_id else None

    async def decide_approval(
        self,
        *,
        approval: ApprovalView,
        decision: ApprovalDecision,
        now_ms: int,
    ) -> ApprovalActionResult:
        self.decisions.append(decision)
        state = "APPROVED" if decision is ApprovalDecision.APPROVE else "DENIED"
        self.approval = approval.model_copy(update={"state": state})
        return ApprovalActionResult(
            approval_id=approval.approval_id,
            state=state,
            acted_at_ms=now_ms,
        )

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]:
        return (
            PoolSummary(
                pool_id="interactive-default",
                service="firecrawl",
                state="READY",
                eligible_credentials=1,
                in_flight=0,
            ),
        )[:limit]

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]:
        return (
            CredentialSummary(
                credential_id="credential-one",
                service="firecrawl",
                alias="primary-account",
                principal_id="principal-one",
                quota_scope_id="quota-one",
                state="HEALTHY",
            ),
        )[:limit]

    async def list_incidents(self, *, limit: int) -> Sequence[IncidentSummary]:
        return (
            IncidentSummary(
                incident_id="incident-one",
                severity="high",
                category="reconciliation",
                summary="Usage requires review",
                state="OPEN",
                created_at_ms=500,
            ),
        )[:limit]

    async def reconciliation(self) -> Sequence[ReconciliationSummary]:
        return (
            ReconciliationSummary(
                service="firecrawl",
                state="CURRENT",
                last_completed_at_ms=900,
                unresolved_reservations=0,
                ledger_mismatch_count=0,
            ),
        )


def make_client() -> tuple[TestClient, AdminAuthManager, FakeAdminBackend, FakeClock]:
    clock = FakeClock()
    auth = AdminAuthManager(
        verifier_key=b"k" * 32,
        now_ms=clock,
        random_bytes=DeterministicRandom(),
        login_code_ttl_ms=100,
        idle_ttl_ms=200,
        absolute_ttl_ms=1_000,
    )
    backend = FakeAdminBackend()
    app = create_admin_app(
        auth=auth,
        backend=backend,
        now_ms=clock,
        allowed_hosts=("testserver",),
    )
    return TestClient(app), auth, backend, clock


def login(client: TestClient, auth: AdminAuthManager) -> str:
    code = asyncio.run(auth.mint_login_code())
    response = client.post("/v1/admin/login/exchange", json={"code": code.code})
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    admin_cookie = next(value for value in cookies if value.startswith("gatehouse_admin="))
    assert "HttpOnly" in admin_cookie
    assert "SameSite=strict" in admin_cookie
    return str(response.json()["csrf_token"])


def approval_body() -> dict[str, object]:
    approval = pending_approval()
    return {
        "action_token": approval.action_token,
        "request_fingerprint": approval.request_fingerprint,
        "maximum_estimated_cost": approval.maximum_estimated_cost,
        "maximum_uses": 1,
    }


def test_one_use_login_cookie_and_admin_realm_separation() -> None:
    client, auth, _, _ = make_client()
    code = asyncio.run(auth.mint_login_code())
    first = client.post("/v1/admin/login/exchange", json={"code": code.code})
    assert first.status_code == 200
    replay = client.post("/v1/admin/login/exchange", json={"code": code.code})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "invalid_session"

    status = client.get("/v1/admin/status")
    assert status.status_code == 200
    agent_token = client.get(
        "/v1/admin/status",
        headers={"Authorization": "Bearer agent-access-token"},
    )
    assert agent_token.status_code == 401


def test_csrf_and_request_binding_protect_approval_mutations() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    missing_csrf = client.post(
        "/v1/admin/approvals/approval-one/approve",
        json=approval_body(),
    )
    assert missing_csrf.status_code == 401
    assert backend.decisions == []

    mismatched = approval_body()
    mismatched["maximum_estimated_cost"] = 24
    rejected = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={CSRF_HEADER_NAME: csrf},
        json=mismatched,
    )
    assert rejected.status_code == 403
    assert backend.decisions == []

    approved = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={CSRF_HEADER_NAME: csrf},
        json=approval_body(),
    )
    assert approved.status_code == 200
    assert approved.json()["state"] == "APPROVED"
    assert backend.decisions == [ApprovalDecision.APPROVE]

    replay = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={CSRF_HEADER_NAME: csrf},
        json=approval_body(),
    )
    assert replay.status_code == 409


def test_origin_host_idle_expiry_and_read_surfaces_fail_closed() -> None:
    client, auth, _, clock = make_client()
    csrf = login(client, auth)
    wrong_host = client.get("/v1/admin/status", headers={"Host": "remote.example"})
    assert wrong_host.status_code == 400

    wrong_origin = client.post(
        "/v1/admin/approvals/approval-one/deny",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://remote.example"},
        json=approval_body(),
    )
    assert wrong_origin.status_code == 401

    for route, key in (
        ("/v1/admin/pools", "pools"),
        ("/v1/admin/credentials", "credentials"),
        ("/v1/admin/incidents", "incidents"),
        ("/v1/admin/reconciliation", "reconciliation"),
    ):
        response = client.get(route)
        assert response.status_code == 200
        assert key in response.json()
    credential = client.get("/v1/admin/credentials").json()["credentials"][0]
    assert set(credential) == {
        "credential_id",
        "service",
        "alias",
        "principal_id",
        "quota_scope_id",
        "state",
    }

    clock.advance(201)
    expired = client.get("/v1/admin/status")
    assert expired.status_code == 401


def test_dashboard_is_accessible_bounded_and_secret_free() -> None:
    client, auth, _, _ = make_client()
    login(client, auth)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert '<html lang="en">' in dashboard.text
    assert "Skip to main content" in dashboard.text
    assert "Request-bound approvals" in dashboard.text
    assert "Approve once" in dashboard.text
    assert "api_key" not in dashboard.text.casefold()
    assert dashboard.headers["x-frame-options"] == "DENY"
