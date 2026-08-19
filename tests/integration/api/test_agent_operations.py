from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.api import (
    DocumentationSearchRequest,
    FeedbackSubmitRequest,
    GatehouseAgentOperations,
    InvocationRequest,
    JobContext,
)
from gatehouse.config import ClientProfileConfig
from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.errors import ErrorCode, GatehouseError
from gatehouse.core.ids import (
    CredentialId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import InvocationState
from gatehouse.database import open_migrated_database
from gatehouse.documentation import DocumentationService
from gatehouse.feedback import FeedbackService
from gatehouse.invocations import InvocationRequest as CoordinatedInvocationRequest
from gatehouse.invocations import InvocationResult, InvocationSession
from gatehouse.jobs import JobRecord, SqliteJobStore
from gatehouse.policy import Decision, WorkspacePolicy
from gatehouse.routing import ResourceAffinity, SqliteResourceAffinityStore
from gatehouse.sessions import AccessPrincipal, SqliteSessionPersistence

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


class UnusedCoordinator:
    async def invoke_authenticated(
        self,
        request: CoordinatedInvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        del request, session
        raise AssertionError("job and local-service operations must not invoke a provider")


class BindingCoordinator:
    def __init__(
        self,
        affinities: SqliteResourceAffinityStore,
        affinity: ResourceAffinity,
    ) -> None:
        self.affinities = affinities
        self.affinity = affinity
        self.calls = 0

    async def invoke_authenticated(
        self,
        request: CoordinatedInvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        del session
        self.calls += 1
        assert request.request_id == self.affinity.creating_request_id
        await self.affinities.bind(self.affinity)
        return InvocationResult(
            request.request_id,
            state=InvocationState.SUCCEEDED,
            attempts=1,
            provider_resource_id=self.affinity.provider_resource_id,
        )


class FailFirstJobCreate(SqliteJobStore):
    def __init__(self, connection: sqlite3.Connection) -> None:
        super().__init__(connection)
        self.calls = 0

    async def create_from_affinity(
        self,
        affinity: ResourceAffinity,
        *,
        maximum_runtime_at_ms: int,
        next_poll_at_ms: int | None = None,
        provider_status: str | None = None,
    ) -> JobRecord:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("injected job materialization failure")
        return await super().create_from_affinity(
            affinity,
            maximum_runtime_at_ms=maximum_runtime_at_ms,
            next_poll_at_ms=next_poll_at_ms,
            provider_status=provider_status,
        )


def profile(*capabilities: str) -> ClientProfileConfig:
    return ClientProfileConfig.model_validate(
        {
            "schema_version": 1,
            "client": {
                "id": "editor",
                "kind": "interactive",
                "unattended": False,
                "approval_mode": "dashboard",
                "default_priority": "interactive",
                "maximum_concurrent_runs": 2,
                "maximum_in_flight": 4,
                "maximum_queued": 8,
                "maximum_run_duration": 60_000,
            },
            "capabilities": {"allow": list(capabilities)},
            "pools": {
                "bindings": {"firecrawl": "interactive-default"},
                "emergency_access": False,
            },
            "lease": {"heartbeat_interval": 1_000, "stale_after": 2_000},
        }
    )


def policy() -> WorkspacePolicy:
    return WorkspacePolicy(
        policy_id="workspace",
        version="policy-v1",
        workspace_id=f"ws_{_A}",
        service="firecrawl",
        default_decision=Decision.DENY,
        default_pool="interactive-default",
        purpose_rules={},
    )


def principal() -> AccessPrincipal:
    return AccessPrincipal(
        session_id=f"ses_{_A}",
        client_id=f"client_{_A}",
        workspace_id=f"ws_{_A}",
        identity_assurance="CONTROLLED_LAUNCH",
        policy_version="policy-v1",
        token_epoch=1,
        absolute_expires_at_ms=10_000,
    )


def seed_authority(connection: sqlite3.Connection) -> ResourceAffinity:
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile,
            created_at_ms, updated_at_ms
        ) VALUES (?, 'Editor', 'interactive', 'default', 0, 0)
        """,
        (f"client_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root,
            created_at_ms, updated_at_ms
        ) VALUES (?, 'Workspace', 'E:\\Workspace', 0, 0)
        """,
        (f"ws_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms,
            absolute_expires_at_ms
        ) VALUES (?, ?, ?, X'01', 1, 1, 'ACTIVE', 'TEST', 'policy-v1',
                  0, 10000, 10000)
        """,
        (f"ses_{_A}", f"client_{_A}", f"ws_{_A}"),
    )
    for root_suffix in (_A, _B):
        connection.execute(
            """
            INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
            VALUES (?, ?, 'ACTIVE', 0)
            """,
            (f"run_{root_suffix}", f"ses_{_A}"),
        )
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version,
            canonicalization_version, state, priority_class,
            request_size_bytes, received_at_ms, completed_at_ms
        ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.crawl.start', ?, 1, 1,
                  'SUCCEEDED', 'INTERACTIVE', 10, 0, 100)
        """,
        (f"req_{_A}", f"ses_{_A}", f"run_{_A}", b"f" * 32),
    )
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'principal', 0, 0)
        """,
        (f"prn_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES (?, ?, 'quota', 'HEALTHY', 'credits', 0)
        """,
        (f"quota_{_A}", f"prn_{_A}"),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES (?, ?, ?, 'credential', 'test', 'reference', 'ACTIVE', 1, 0)
        """,
        (f"cred_{_A}", f"prn_{_A}", f"quota_{_A}"),
    )
    connection.execute(
        """
        INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
        VALUES (?, 'firecrawl', 'interactive-default', 'ACTIVE', 'CHEAPEST_FIRST')
        """,
        (f"pool_{_A}",),
    )
    connection.execute(
        "INSERT INTO pool_members(pool_id, quota_scope_id) VALUES (?, ?)",
        (f"pool_{_A}", f"quota_{_A}"),
    )
    return ResourceAffinity(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id="provider-job-one",
        principal_id=PrincipalId(f"prn_{_A}"),
        quota_scope_id=QuotaScopeId(f"quota_{_A}"),
        credential_id=CredentialId(f"cred_{_A}"),
        credential_generation=1,
        pool_id=PoolId(f"pool_{_A}"),
        creating_request_id=RequestId(f"req_{_A}"),
        owner_session_id=SessionId(f"ses_{_A}"),
        owner_workspace_id=WorkspaceId(f"ws_{_A}"),
        owner_root_run_id=RootRunId(f"run_{_A}"),
        bound_at_ms=100,
    )


def bridge(
    connection: sqlite3.Connection,
    *,
    capabilities: tuple[str, ...],
    documentation: DocumentationService | None = None,
    feedback: FeedbackService | None = None,
) -> GatehouseAgentOperations:
    return GatehouseAgentOperations(
        coordinator=UnusedCoordinator(),
        root_runs=SqliteSessionPersistence(connection),
        client_profiles={f"client_{_A}": profile(*capabilities)},
        workspace_policies={f"ws_{_A}": policy()},
        jobs=SqliteJobStore(connection),
        affinities=SqliteResourceAffinityStore(connection),
        documentation=documentation,
        feedback=feedback,
        clock=FixedUtcClock(150),
    )


def crawl_start_request(*, request_id: str) -> InvocationRequest:
    return InvocationRequest.model_validate(
        {
            "request_id": request_id,
            "service": "firecrawl",
            "operation": "crawl.start",
            "input": {
                "url": "https://example.com/careers",
                "include_paths": ["/careers/**"],
                "maximum_pages": 5,
                "maximum_depth": 1,
                "maximum_concurrency": 1,
                "purpose": "multi_page_job_extraction",
                "data_classification": ["public_web_page"],
            },
            "context": {"root_run_id": f"run_{_A}"},
        }
    )


@pytest.mark.asyncio
async def test_explicit_request_recovers_materialization_after_fault_and_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "materialization-retry.db"
    connection = open_migrated_database(path)
    affinity = seed_authority(connection)
    affinity_store = SqliteResourceAffinityStore(connection)
    coordinator = BindingCoordinator(affinity_store, affinity)
    faulting_jobs = FailFirstJobCreate(connection)
    first = GatehouseAgentOperations(
        coordinator=coordinator,
        root_runs=SqliteSessionPersistence(connection),
        client_profiles={f"client_{_A}": profile("firecrawl.crawl.start", "jobs.status")},
        workspace_policies={f"ws_{_A}": policy()},
        jobs=faulting_jobs,
        affinities=affinity_store,
        clock=FixedUtcClock(150),
    )
    request = crawl_start_request(request_id=f"req_{_A}")

    with pytest.raises(GatehouseError) as failed:
        await first.invoke(principal(), request)

    assert failed.value.detail.code is ErrorCode.DAEMON_DEGRADED
    assert failed.value.detail.request_id == RequestId(f"req_{_A}")
    assert coordinator.calls == 1
    assert faulting_jobs.calls == 1
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    connection.close()

    reopened = open_migrated_database(path)
    recovered = GatehouseAgentOperations(
        coordinator=UnusedCoordinator(),
        root_runs=SqliteSessionPersistence(reopened),
        client_profiles={f"client_{_A}": profile("firecrawl.crawl.start", "jobs.status")},
        workspace_policies={f"ws_{_A}": policy()},
        jobs=SqliteJobStore(reopened),
        affinities=SqliteResourceAffinityStore(reopened),
        clock=FixedUtcClock(200),
    )

    response = await recovered.invoke(principal(), request)

    assert response.body["request_id"] == f"req_{_A}"
    assert response.body["state"] == "SUCCEEDED"
    assert response.body["job_id"]
    assert reopened.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    repeated = await recovered.invoke(principal(), request)
    assert repeated.body["job_id"] == response.body["job_id"]
    assert reopened.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    reopened.close()


@pytest.mark.asyncio
async def test_file_backed_jobs_require_the_exact_root_owner_and_cancel_durably(
    tmp_path: Path,
) -> None:
    path = tmp_path / "agent-operations.db"
    connection = open_migrated_database(path)
    affinity = seed_authority(connection)
    affinity_store = SqliteResourceAffinityStore(connection)
    await affinity_store.bind(affinity)
    store = SqliteJobStore(connection)
    job = await store.create_from_affinity(
        affinity,
        maximum_runtime_at_ms=10_000,
        next_poll_at_ms=200,
    )
    item = bridge(
        connection,
        capabilities=("jobs.status", "jobs.await", "jobs.cancel"),
    )

    found = await item.get_job(
        principal(),
        str(job.job_id),
        JobContext(root_run_id=f"run_{_A}"),
    )
    assert found.body["state"] == "CREATED"

    with pytest.raises(GatehouseError) as wrong_root:
        await item.get_job(
            principal(),
            str(job.job_id),
            JobContext(root_run_id=f"run_{_B}"),
        )
    assert wrong_root.value.detail.code is ErrorCode.INVALID_TARGET

    cancelled = await item.cancel_job(
        principal(),
        str(job.job_id),
        JobContext(root_run_id=f"run_{_A}"),
    )
    assert cancelled.status_code == 202
    assert cancelled.body["state"] == "CANCELLING"
    connection.close()

    reopened = open_migrated_database(path)
    try:
        restored = await bridge(
            reopened,
            capabilities=("jobs.status", "jobs.await", "jobs.cancel"),
        ).get_job(
            principal(),
            str(job.job_id),
            JobContext(root_run_id=f"run_{_A}"),
        )
        assert restored.body["state"] == "CANCELLING"
        assert restored.body["cancel_requested_at_ms"] == 150
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_documentation_and_feedback_use_the_existing_local_services(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "local-services.db")
    seed_authority(connection)
    identifiers = iter(("doc-source", "doc-version", "doc-chunk"))
    documentation = DocumentationService(connection, identifier=lambda _: next(identifiers))
    source = documentation.register_source(
        service="firecrawl",
        canonical_url="https://docs.firecrawl.dev/guide",
        now_ms=100,
    )
    documentation.ingest_markdown(
        source_id=source.source_id,
        markdown="# Search\n\nOfficial rate limit guidance.",
        retrieved_at_ms=100,
    )
    feedback = FeedbackService(connection, identifier=lambda _: "feedback-one")
    item = bridge(
        connection,
        capabilities=("docs.search", "docs.get", "feedback.submit"),
        documentation=documentation,
        feedback=feedback,
    )

    searched = await item.search_documentation(
        principal(),
        DocumentationSearchRequest(
            service="firecrawl",
            query="rate limit",
            limit=5,
        ),
    )
    results = searched.body["results"]
    assert isinstance(results, list)
    first_result = results[0]
    assert isinstance(first_result, dict)
    assert first_result["source_id"] == source.source_id
    document = await item.get_documentation(principal(), "firecrawl", source.source_id)
    assert document is not None
    content = document.body["content"]
    assert isinstance(content, str)
    assert "Official rate limit guidance" in content

    submitted = await item.submit_feedback(
        principal(),
        FeedbackSubmitRequest(
            category="contract",
            severity="medium",
            component="firecrawl.search",
            summary="Unexpected field",
            problem="The response shape changed.",
        ),
    )
    assert submitted.body == {
        "feedback_id": "feedback-one",
        "state": "NEW",
        "summary": "Unexpected field",
        "created_at_ms": 150,
    }
    connection.close()
