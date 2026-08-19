from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest
from fastapi.testclient import TestClient

from gatehouse.api import (
    ApiResponse,
    DocumentationSearchRequest,
    FeedbackSubmitRequest,
    InvocationRequest,
    JobAwaitRequest,
    JobContext,
    PolicyExplainRequest,
    ReadinessSnapshot,
    create_agent_app,
)
from gatehouse.core import RuntimeAdmissionController
from gatehouse.sessions import (
    AccessPrincipal,
    CrossSessionRootRun,
    InvalidAccessToken,
    IssuedAccessToken,
    RootRunRecord,
    RootRunState,
)


def principal() -> AccessPrincipal:
    return AccessPrincipal(
        session_id="ses_one",
        client_id="editor-one",
        workspace_id="workspace-one",
        identity_assurance="CONTROLLED_LAUNCH",
        policy_version="policy-one",
        token_epoch=1,
        absolute_expires_at_ms=100_000,
    )


class FakeAuthority:
    def __init__(self) -> None:
        self.resolved: list[str] = []

    async def exchange_bootstrap(
        self,
        *,
        session_id: str,
        bootstrap_capability: str,
    ) -> IssuedAccessToken:
        if session_id != "ses_one" or bootstrap_capability != "b" * 43:
            raise InvalidAccessToken("bad bootstrap")
        return IssuedAccessToken("a" * 43, 10_000, principal())

    async def authenticate(self, access_token: str) -> AccessPrincipal:
        if access_token != "a" * 43:
            raise InvalidAccessToken("bad token")
        return principal()

    async def heartbeat(self, access_token: str) -> AccessPrincipal:
        return await self.authenticate(access_token)

    async def create_root_run(
        self,
        *,
        access_token: str,
        budget: Mapping[str, int] | None = None,
    ) -> RootRunRecord:
        await self.authenticate(access_token)
        return RootRunRecord(
            root_run_id="run_server_minted",
            session_id="ses_one",
            state=RootRunState.ACTIVE,
            started_at_ms=1,
            budget=budget or {},
        )

    async def resolve_root_run(
        self,
        *,
        access_token: str,
        root_run_id: str,
    ) -> RootRunRecord:
        await self.authenticate(access_token)
        self.resolved.append(root_run_id)
        if root_run_id != "run_server_minted":
            raise CrossSessionRootRun("root run does not belong to the session")
        return RootRunRecord(
            root_run_id=root_run_id,
            session_id="ses_one",
            state=RootRunState.ACTIVE,
            started_at_ms=1,
        )


class FakeHealth:
    async def readiness(self) -> ReadinessSnapshot:
        return ReadinessSnapshot(
            ready=False,
            status="degraded_no_provider",
            version="0.0.1",
            schema_version=2,
            policy_version="policy-one",
            uptime_seconds=5,
            degraded_components=["provider"],
        )


class FakeOperations:
    def __init__(self) -> None:
        self.invocations: list[InvocationRequest] = []
        self.explanations: list[PolicyExplainRequest] = []

    async def capabilities(self, _: AccessPrincipal) -> Sequence[str]:
        return (
            "firecrawl.search",
            "firecrawl.account.credit_status",
            "docs.search",
            "feedback.submit",
            "watcher.scan_feed_set",
        )

    async def invoke(
        self,
        _: AccessPrincipal,
        request: InvocationRequest,
    ) -> ApiResponse:
        self.invocations.append(request)
        return ApiResponse({"request_id": "req_one", "state": "SUCCEEDED"})

    async def explain_policy(
        self,
        _: AccessPrincipal,
        request: PolicyExplainRequest,
    ) -> ApiResponse:
        self.explanations.append(request)
        return ApiResponse(
            {
                "authority": {
                    "session_id": "ses_one",
                    "client_id": "editor-one",
                    "client": "editor-one",
                    "workspace_id": "workspace-one",
                    "workspace": "workspace-one",
                    "root_run_id": request.context.root_run_id,
                },
                "service": request.service,
                "operation": request.operation,
                "decision": "ASK",
                "rule_id": "default-decision",
                "reason_code": "purpose-context-required",
                "policy_id": "workspace-one",
                "policy_version": "policy-one",
                "constraints": {
                    "maximum_search_results": 20,
                    "maximum_map_results": 100,
                    "maximum_crawl_pages": 25,
                    "maximum_crawl_depth": 2,
                    "request_count_remaining": 30,
                    "credit_budget_remaining_units": 200,
                },
                "cost_ceiling_units": 200,
                "approval_required": True,
                "denial_reason": None,
                "purpose_rules": [],
            }
        )

    async def get_job(
        self,
        _: AccessPrincipal,
        job_id: str,
        context: JobContext,
    ) -> ApiResponse:
        assert context.root_run_id == "run_server_minted"
        return ApiResponse({"job_id": job_id, "state": "RUNNING"})

    async def await_job(
        self,
        _: AccessPrincipal,
        job_id: str,
        request: JobAwaitRequest,
    ) -> ApiResponse:
        return ApiResponse(
            {
                "job_id": job_id,
                "state": "RUNNING",
                "waited_ms": request.maximum_wait_ms,
            },
            status_code=202,
            retry_after_seconds=1,
        )

    async def cancel_job(
        self,
        _: AccessPrincipal,
        job_id: str,
        context: JobContext,
    ) -> ApiResponse:
        assert context.root_run_id == "run_server_minted"
        return ApiResponse({"job_id": job_id, "state": "CANCELLED"})

    async def search_documentation(
        self,
        _: AccessPrincipal,
        request: DocumentationSearchRequest,
    ) -> ApiResponse:
        return ApiResponse({"service": request.service, "results": []})

    async def get_documentation(
        self,
        _: AccessPrincipal,
        service: str,
        document: str,
    ) -> ApiResponse | None:
        if document == "missing":
            return None
        return ApiResponse({"service": service, "document": document, "content": "safe"})

    async def submit_feedback(
        self,
        _: AccessPrincipal,
        request: FeedbackSubmitRequest,
    ) -> ApiResponse:
        return ApiResponse({"feedback_id": "feedback_one", "summary": request.summary})


def make_client(
    *,
    maximum_body_bytes: int = 64 * 1_024,
    maximum_wait_ms: int = 30_000,
    session_heartbeat_interval_ms: int = 30_000,
    admission: RuntimeAdmissionController | None = None,
) -> tuple[TestClient, FakeAuthority, FakeOperations]:
    authority = FakeAuthority()
    operations = FakeOperations()
    app = create_agent_app(
        sessions=authority,
        operations=operations,
        health=FakeHealth(),
        now_ms=lambda: 0,
        allowed_hosts=("testserver",),
        maximum_body_bytes=maximum_body_bytes,
        maximum_wait_ms=maximum_wait_ms,
        session_heartbeat_interval_ms=session_heartbeat_interval_ms,
        admission=admission,
    )
    return TestClient(app), authority, operations


def bearer() -> dict[str, str]:
    return {"Authorization": f"Bearer {'a' * 43}"}


def test_health_and_host_validation_are_stable() -> None:
    client, _, _ = make_client()
    assert client.get("/health/live").json() == {"status": "live"}
    ready = client.get("/health/ready")
    assert ready.status_code == 503
    assert ready.json()["status"] == "degraded_no_provider"

    rejected = client.get("/health/live", headers={"Host": "remote.example"})
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "invalid_target"


def test_exchange_and_server_minted_root_run() -> None:
    client, _, _ = make_client(session_heartbeat_interval_ms=1_250)
    exchange = client.post(
        "/v1/sessions/exchange",
        json={
            "session_id": "ses_one",
            "bootstrap_capability": "b" * 43,
            "client_nonce": "nonce-one",
        },
    )
    assert exchange.status_code == 200
    assert exchange.json()["access_token"] == "a" * 43
    assert exchange.json()["heartbeat_interval_ms"] == 1_250
    assert exchange.json()["capabilities"] == sorted(exchange.json()["capabilities"])
    assert "firecrawl.account.credit_status" not in exchange.json()["capabilities"]
    assert "watcher.scan_feed_set" not in exchange.json()["capabilities"]

    created = client.post(
        "/v1/root-runs",
        headers=bearer(),
        json={"budget": {"requests": 3}},
    )
    assert created.status_code == 201
    assert created.json()["root_run_id"] == "run_server_minted"
    assert created.json()["session_id"] == "ses_one"


@pytest.mark.parametrize("interval_ms", [True, 999, 300_001])
def test_session_heartbeat_interval_is_strictly_bounded(interval_ms: int) -> None:
    with pytest.raises(ValueError, match="heartbeat interval"):
        make_client(session_heartbeat_interval_ms=interval_ms)


def test_invoke_validates_typed_input_and_session_bound_root_run() -> None:
    client, authority, operations = make_client()
    response = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "limit": 5,
                "include_content": False,
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": "run_server_minted"},
            "execution": {"wait_up_to_ms": 100, "allow_cached_result": True},
        },
    )
    assert response.status_code == 200
    assert response.json()["state"] == "SUCCEEDED"
    assert authority.resolved == ["run_server_minted"]
    assert operations.invocations[0].input["limit"] == 5

    stable_crawl = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "request_id": "req_00000000000000000000000001",
            "service": "firecrawl",
            "operation": "crawl.start",
            "input": {
                "url": "https://careers.example.com/jobs",
                "include_paths": [r"^/jobs(?:/.*)?$"],
                "maximum_pages": 5,
                "maximum_depth": 1,
                "maximum_concurrency": 2,
                "purpose": "multi_page_job_extraction",
                "data_classification": ["public_web"],
            },
            "context": {"root_run_id": "run_server_minted"},
        },
    )
    assert stable_crawl.status_code == 200
    assert operations.invocations[1].request_id == "req_00000000000000000000000001"

    unsupported_handle = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "request_id": "req_00000000000000000000000002",
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": "run_server_minted"},
        },
    )
    assert unsupported_handle.status_code == 422
    assert unsupported_handle.json()["error"]["code"] == "schema_validation_failed"

    malformed_handle = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "request_id": "retry-me",
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": "run_server_minted"},
        },
    )
    assert malformed_handle.status_code == 422
    assert malformed_handle.json()["error"]["code"] == "schema_validation_failed"

    wrong_run = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": "run_other"},
        },
    )
    assert wrong_run.status_code == 401
    assert wrong_run.json()["error"]["code"] == "invalid_session"


def test_draining_rejects_new_work_but_keeps_bounded_reconciliation_open() -> None:
    admission = RuntimeAdmissionController()
    admission.begin_accepting()
    client, _, operations = make_client(admission=admission)
    admission.begin_draining()

    root_run = client.post("/v1/root-runs", headers=bearer(), json={})
    search = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "search",
            "input": {
                "query": "graduate roles",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
            "context": {"root_run_id": "run_server_minted"},
        },
    )
    reconciliations = [
        client.post(
            "/v1/invocations",
            headers=bearer(),
            json={
                "service": "firecrawl",
                "operation": operation,
                "input": {"provider_job_id": "provider-job-one"},
                "context": {"root_run_id": "run_server_minted"},
            },
        )
        for operation in ("crawl.status", "crawl.cancel")
    ]
    job_status = client.get(
        "/v1/jobs/job_one",
        headers=bearer(),
        params={"root_run_id": "run_server_minted"},
    )
    job_cancel = client.post(
        "/v1/jobs/job_one/cancel",
        headers=bearer(),
        json={"root_run_id": "run_server_minted"},
    )

    assert [root_run.status_code, search.status_code] == [503, 503]
    assert root_run.json()["error"]["details"] == {"daemon_state": "DRAINING"}
    assert search.json()["error"]["code"] == "daemon_degraded"
    assert [response.status_code for response in reconciliations] == [200, 200]
    assert [request.operation for request in operations.invocations] == [
        "crawl.status",
        "crawl.cancel",
    ]
    assert job_status.status_code == job_cancel.status_code == 200


def test_policy_explain_uses_authenticated_server_bound_root_without_execution() -> None:
    client, authority, operations = make_client()
    response = client.post(
        "/v1/policy/explain",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "crawl",
            "context": {"root_run_id": "run_server_minted"},
        },
    )

    assert response.status_code == 200
    assert response.json()["operation"] == "crawl"
    assert response.json()["decision"] == "ASK"
    assert authority.resolved == ["run_server_minted"]
    assert operations.invocations == []
    assert operations.explanations[0].context.root_run_id == "run_server_minted"

    unauthenticated = client.post(
        "/v1/policy/explain",
        json={
            "service": "firecrawl",
            "operation": "crawl",
            "context": {"root_run_id": "run_server_minted"},
        },
    )
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == "invalid_session"

    wrong_root = client.post(
        "/v1/policy/explain",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "crawl",
            "context": {"root_run_id": "run_other"},
        },
    )
    assert wrong_root.status_code == 401
    assert wrong_root.json()["error"]["code"] == "invalid_session"


def test_policy_explain_schema_is_typed_and_forbids_extra_authority() -> None:
    client, _, operations = make_client()
    response = client.post(
        "/v1/policy/explain",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "raw_http",
            "client": "attacker-selected-client",
            "context": {"root_run_id": "run_server_minted"},
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "schema_validation_failed"
    assert operations.explanations == []


def test_internal_credit_status_and_unbounded_wait_are_not_agent_capabilities() -> None:
    client, _, operations = make_client(maximum_wait_ms=1_000)
    credit_status = client.post(
        "/v1/invocations",
        headers=bearer(),
        json={
            "service": "firecrawl",
            "operation": "account.credit_status",
            "input": {},
            "context": {"root_run_id": "run_server_minted"},
        },
    )
    assert credit_status.status_code == 422
    assert operations.invocations == []

    unbounded = client.post(
        "/v1/jobs/job_one/await",
        headers=bearer(),
        json={"root_run_id": "run_server_minted", "maximum_wait_ms": 1_001},
    )
    assert unbounded.status_code == 422
    assert unbounded.json()["error"]["code"] == "schema_validation_failed"


def test_error_envelope_does_not_echo_invalid_payload_and_body_is_bounded() -> None:
    client, _, _ = make_client(maximum_body_bytes=128)
    secret_canary = "secret-canary-value"
    response = client.post(
        "/v1/feedback",
        headers=bearer(),
        content=secret_canary * 20,
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "schema_validation_failed"
    assert secret_canary not in response.text


def test_docs_feedback_and_job_routes_require_agent_authentication() -> None:
    client, _, _ = make_client()
    missing = client.post(
        "/v1/docs/search",
        json={"service": "firecrawl", "query": "rate limit", "limit": 5},
    )
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "invalid_session"

    docs = client.get("/v1/docs/firecrawl/guide", headers=bearer())
    assert docs.status_code == 200
    assert docs.json()["document"] == "guide"
    feedback = client.post(
        "/v1/feedback",
        headers=bearer(),
        json={
            "category": "contract",
            "severity": "medium",
            "component": "firecrawl.search",
            "summary": "Unexpected field",
        },
    )
    assert feedback.status_code == 200
    awaited = client.post(
        "/v1/jobs/job_one/await",
        headers=bearer(),
        json={"root_run_id": "run_server_minted", "maximum_wait_ms": 100},
    )
    assert awaited.status_code == 202
    assert awaited.headers["retry-after"] == "1"

    missing_root = client.get("/v1/jobs/job_one", headers=bearer())
    assert missing_root.status_code == 422
    status = client.get(
        "/v1/jobs/job_one",
        headers=bearer(),
        params={"root_run_id": "run_server_minted"},
    )
    assert status.status_code == 200
    cancelled = client.post(
        "/v1/jobs/job_one/cancel",
        headers=bearer(),
        json={"root_run_id": "run_server_minted"},
    )
    assert cancelled.status_code == 200
