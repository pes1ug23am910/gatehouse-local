from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

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
from gatehouse.database import open_migrated_database
from gatehouse.routing import (
    ResourceAffinity,
    ResourceAffinityConflictError,
    SqliteResourceAffinityStore,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_CREDENTIAL_GENERATION = 7


def _seed_authority_graph(connection: sqlite3.Connection) -> None:
    for suffix in (_A, _B):
        connection.execute(
            """
            INSERT INTO clients(
                client_id, display_name, kind, policy_profile,
                created_at_ms, updated_at_ms
            ) VALUES (?, ?, 'interactive', 'default', 0, 0)
            """,
            (f"client_{suffix}", f"Client {suffix[-1]}"),
        )
        connection.execute(
            """
            INSERT INTO workspaces(
                workspace_id, display_name, canonical_root,
                created_at_ms, updated_at_ms
            ) VALUES (?, ?, ?, 0, 0)
            """,
            (f"ws_{suffix}", f"Workspace {suffix[-1]}", f"E:\\Workspace-{suffix[-1]}"),
        )
        connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_id, workspace_id, bootstrap_verifier,
                bootstrap_version, token_epoch, state, identity_assurance,
                policy_version, created_at_ms, reconnect_until_ms,
                absolute_expires_at_ms
            ) VALUES (?, ?, ?, X'01', 1, 0, 'ACTIVE', 'TEST', 'v1',
                      0, 100000, 100000)
            """,
            (f"ses_{suffix}", f"client_{suffix}", f"ws_{suffix}"),
        )
        connection.execute(
            """
            INSERT INTO root_runs(
                root_run_id, session_id, state, started_at_ms
            ) VALUES (?, ?, 'ACTIVE', 0)
            """,
            (f"run_{suffix}", f"ses_{suffix}"),
        )
        connection.execute(
            """
            INSERT INTO invocations(
                request_id, session_id, root_run_id, service_id, operation,
                request_fingerprint, fingerprint_version,
                canonicalization_version, state, priority_class,
                request_size_bytes, received_at_ms
            ) VALUES (?, ?, ?, 'service', 'crawl.start', ?, 1, 1,
                      'SUCCEEDED', 'INTERACTIVE', 10, 0)
            """,
            (
                f"req_{suffix}",
                f"ses_{suffix}",
                f"run_{suffix}",
                suffix.encode("ascii"),
            ),
        )

    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'service', 'principal', 0, 0)
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
        ) VALUES (?, ?, ?, 'credential', 'test', 'reference', 'ACTIVE', ?, 0)
        """,
        (f"cred_{_A}", f"prn_{_A}", f"quota_{_A}", _CREDENTIAL_GENERATION),
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy
        ) VALUES (?, 'service', 'default', 'ACTIVE', 'CHEAPEST_FIRST')
        """,
        (f"pool_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id)
        VALUES (?, ?)
        """,
        (f"pool_{_A}", f"quota_{_A}"),
    )


def _affinity(
    *,
    owner_suffix: str = _A,
    provider_resource_id: str = "provider-job",
    bound_at_ms: int = 100,
    credential_generation: int = _CREDENTIAL_GENERATION,
) -> ResourceAffinity:
    return ResourceAffinity(
        service_id="service",
        resource_type="job",
        provider_resource_id=provider_resource_id,
        principal_id=PrincipalId(f"prn_{_A}"),
        quota_scope_id=QuotaScopeId(f"quota_{_A}"),
        credential_id=CredentialId(f"cred_{_A}"),
        credential_generation=credential_generation,
        pool_id=PoolId(f"pool_{_A}"),
        creating_request_id=RequestId(f"req_{owner_suffix}"),
        owner_session_id=SessionId(f"ses_{owner_suffix}"),
        owner_workspace_id=WorkspaceId(f"ws_{owner_suffix}"),
        owner_root_run_id=RootRunId(f"run_{owner_suffix}"),
        bound_at_ms=bound_at_ms,
    )


def _seed_successful_attempt(
    connection: sqlite3.Connection,
    affinity: ResourceAffinity,
) -> None:
    connection.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, error_class, started_at_ms, completed_at_ms,
            resource_type, provider_resource_id, credential_generation, pool_id,
            dispatch_credential_generation, dispatch_pool_id
        ) VALUES (?, ?, 1, ?, ?, ?, 'SUCCEEDED', 'none', 90, 100,
                  ?, ?, ?, ?, ?, ?)
        """,
        (
            f"attempt-{affinity.creating_request_id}",
            str(affinity.creating_request_id),
            str(affinity.credential_id),
            str(affinity.principal_id),
            str(affinity.quota_scope_id),
            affinity.resource_type,
            affinity.provider_resource_id,
            affinity.credential_generation,
            str(affinity.pool_id),
            affinity.credential_generation,
            str(affinity.pool_id),
        ),
    )


@pytest.mark.asyncio
async def test_affinity_survives_restart_and_idempotent_rebind_keeps_first_fact(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    affinity = _affinity()

    connection = open_migrated_database(database_path)
    try:
        _seed_authority_graph(connection)
        _seed_successful_attempt(connection, affinity)
        store = SqliteResourceAffinityStore(
            connection,
            identifier=lambda: "resource-row",
        )
        assert await store.bind(affinity) == affinity
    finally:
        connection.close()

    restarted_connection = open_migrated_database(database_path)
    try:
        restarted_store = SqliteResourceAffinityStore(restarted_connection)
        restored = await restarted_store.get(
            service_id="service",
            resource_type="job",
            provider_resource_id="provider-job",
            owner_session_id=SessionId(f"ses_{_A}"),
            owner_workspace_id=WorkspaceId(f"ws_{_A}"),
            owner_root_run_id=RootRunId(f"run_{_A}"),
        )

        assert restored == affinity
        assert restored is not None
        assert restored.owner_session_id == SessionId(f"ses_{_A}")
        assert restored.owner_workspace_id == WorkspaceId(f"ws_{_A}")
        assert restored.owner_root_run_id == RootRunId(f"run_{_A}")
        assert restored.credential_generation == _CREDENTIAL_GENERATION
        assert (
            await restarted_store.get_by_request(
                service_id="service",
                resource_type="job",
                creating_request_id=RequestId(f"req_{_A}"),
                owner_session_id=SessionId(f"ses_{_A}"),
                owner_workspace_id=WorkspaceId(f"ws_{_A}"),
                owner_root_run_id=RootRunId(f"run_{_A}"),
            )
            == affinity
        )
        assert (
            await restarted_store.get_by_request(
                service_id="service",
                resource_type="job",
                creating_request_id=RequestId(f"req_{_A}"),
                owner_session_id=SessionId(f"ses_{_B}"),
                owner_workspace_id=WorkspaceId(f"ws_{_B}"),
                owner_root_run_id=RootRunId(f"run_{_B}"),
            )
            is None
        )
        assert (
            await restarted_store.get(
                service_id="service",
                resource_type="job",
                provider_resource_id="provider-job",
                owner_session_id=SessionId(f"ses_{_B}"),
                owner_workspace_id=WorkspaceId(f"ws_{_B}"),
                owner_root_run_id=RootRunId(f"run_{_B}"),
            )
            is None
        )

        rebound = await restarted_store.bind(replace(affinity, bound_at_ms=200))
        assert rebound == affinity
        assert rebound.bound_at_ms == 100
        assert (
            restarted_connection.execute("SELECT COUNT(*) FROM external_resources").fetchone()[0]
            == 1
        )
    finally:
        restarted_connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_state", ("COMPLETED", "FAILED", "CANCELLED"))
async def test_request_recovery_includes_terminal_affinity_but_provider_lookup_does_not(
    tmp_path: Path,
    terminal_state: str,
) -> None:
    connection = open_migrated_database(tmp_path / f"terminal-{terminal_state}.db")
    try:
        _seed_authority_graph(connection)
        affinity = _affinity()
        _seed_successful_attempt(connection, affinity)
        store = SqliteResourceAffinityStore(connection)
        await store.bind(affinity)
        connection.execute(
            "UPDATE external_resources SET state = ?, updated_at_ms = 200",
            (terminal_state,),
        )

        assert (
            await store.get(
                service_id="service",
                resource_type="job",
                provider_resource_id="provider-job",
                owner_session_id=SessionId(f"ses_{_A}"),
                owner_workspace_id=WorkspaceId(f"ws_{_A}"),
                owner_root_run_id=RootRunId(f"run_{_A}"),
            )
            is None
        )
        assert (
            await store.get_by_request(
                service_id="service",
                resource_type="job",
                creating_request_id=RequestId(f"req_{_A}"),
                owner_session_id=SessionId(f"ses_{_A}"),
                owner_workspace_id=WorkspaceId(f"ws_{_A}"),
                owner_root_run_id=RootRunId(f"run_{_A}"),
            )
            == affinity
        )
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_affinity_rejects_a_valid_but_conflicting_owner_chain(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    try:
        _seed_authority_graph(connection)
        store = SqliteResourceAffinityStore(
            connection,
            identifier=lambda: "resource-row",
        )
        original = _affinity()
        _seed_successful_attempt(connection, original)
        await store.bind(original)

        conflicting = _affinity(owner_suffix=_B, bound_at_ms=200)
        _seed_successful_attempt(connection, conflicting)

        with pytest.raises(
            ResourceAffinityConflictError,
            match="already bound to another authority",
        ):
            await store.bind(conflicting)

        assert (
            await store.get(
                service_id="service",
                resource_type="job",
                provider_resource_id="provider-job",
                owner_session_id=SessionId(f"ses_{_A}"),
                owner_workspace_id=WorkspaceId(f"ws_{_A}"),
                owner_root_run_id=RootRunId(f"run_{_A}"),
            )
            == original
        )
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_affinity_rejects_an_invalid_durable_authority_chain(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    try:
        _seed_authority_graph(connection)
        store = SqliteResourceAffinityStore(
            connection,
            identifier=lambda: "resource-row",
        )
        stale_generation = _affinity(
            provider_resource_id="provider-job-stale-generation",
            credential_generation=_CREDENTIAL_GENERATION - 1,
        )
        _seed_successful_attempt(
            connection,
            replace(stale_generation, credential_generation=_CREDENTIAL_GENERATION),
        )

        with pytest.raises(
            ResourceAffinityConflictError,
            match="does not match durable ownership",
        ):
            await store.bind(stale_generation)

        assert (
            await store.get(
                service_id="service",
                resource_type="job",
                provider_resource_id="provider-job-stale-generation",
                owner_session_id=SessionId(f"ses_{_A}"),
                owner_workspace_id=WorkspaceId(f"ws_{_A}"),
                owner_root_run_id=RootRunId(f"run_{_A}"),
            )
            is None
        )
        assert connection.execute("SELECT COUNT(*) FROM external_resources").fetchone()[0] == 0
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_affinity_bind_uses_frozen_dispatch_after_credential_is_fenced(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    try:
        _seed_authority_graph(connection)
        affinity = _affinity(provider_resource_id="provider-job-fenced")
        _seed_successful_attempt(connection, affinity)
        connection.execute(
            """
            UPDATE credentials
               SET state = 'DISABLED', generation = generation + 1
             WHERE credential_id = ?
            """,
            (str(affinity.credential_id),),
        )

        store = SqliteResourceAffinityStore(
            connection,
            identifier=lambda: "resource-row-fenced",
        )
        assert await store.bind(affinity) == affinity

        row = connection.execute(
            """
            SELECT state, credential_generation
              FROM external_resources
             WHERE resource_id = 'resource-row-fenced'
            """
        ).fetchone()
        assert row is not None
        assert tuple(row) == ("ACTIVE", _CREDENTIAL_GENERATION)
    finally:
        connection.close()
