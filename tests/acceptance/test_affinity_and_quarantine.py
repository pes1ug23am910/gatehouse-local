from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from gatehouse.core.ids import (
    CredentialId,
    OpaqueId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import CredentialState
from gatehouse.database import open_migrated_database
from gatehouse.reconciliation import (
    ReconciliationAction,
    ReconciliationPolicy,
    ReconciliationStore,
    UsageSnapshot,
)
from gatehouse.routing import (
    AffinityUnavailableError,
    InMemoryResourceAffinityStore,
    NamedPool,
    NamedPoolRouter,
    PoolMember,
    PoolSelectionStrategy,
    QuotaScopeSnapshot,
    ResourceAffinity,
    RoutingCredential,
)


def _opaque[OpaqueIdT: OpaqueId](
    identifier_type: type[OpaqueIdT],
    suffix: str,
) -> OpaqueIdT:
    return identifier_type(f"{identifier_type.prefix}_{'0' * 25}{suffix}")


@pytest.mark.asyncio
async def test_async_resource_affinity_stays_on_its_creating_principal() -> None:
    principal_a = _opaque(PrincipalId, "1")
    principal_b = _opaque(PrincipalId, "2")
    quota_a = _opaque(QuotaScopeId, "1")
    quota_b = _opaque(QuotaScopeId, "2")
    credential_a = _opaque(CredentialId, "1")
    credential_b = _opaque(CredentialId, "2")
    pool_id = _opaque(PoolId, "1")
    request_id = _opaque(RequestId, "1")
    scope_a = QuotaScopeSnapshot(
        quota_scope_id=quota_a,
        principal_id=principal_a,
        service_id="firecrawl",
        unit="credits",
        last_known_remaining_units=100,
    )
    scope_b = QuotaScopeSnapshot(
        quota_scope_id=quota_b,
        principal_id=principal_b,
        service_id="firecrawl",
        unit="credits",
        last_known_remaining_units=100,
    )
    member_a = PoolMember(
        scope_a,
        (RoutingCredential(credential_a, principal_a, quota_a),),
        priority=1,
    )
    member_b = PoolMember(
        scope_b,
        (RoutingCredential(credential_b, principal_b, quota_b),),
        priority=2,
    )
    pool = NamedPool(
        pool_id=pool_id,
        name="primary",
        service_id="firecrawl",
        selection_strategy=PoolSelectionStrategy.FILL_FIRST,
        members=(member_a, member_b),
    )
    affinity = ResourceAffinity(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id="provider-job-1",
        principal_id=principal_b,
        quota_scope_id=quota_b,
        credential_id=credential_b,
        credential_generation=1,
        pool_id=pool_id,
        creating_request_id=request_id,
        owner_session_id=_opaque(SessionId, "1"),
        owner_workspace_id=_opaque(WorkspaceId, "1"),
        owner_root_run_id=_opaque(RootRunId, "1"),
        bound_at_ms=1_000,
    )
    affinity_store = InMemoryResourceAffinityStore(maximum_entries=10)
    await affinity_store.bind(affinity)
    persisted = await affinity_store.get(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id="provider-job-1",
        owner_session_id=affinity.owner_session_id,
        owner_workspace_id=affinity.owner_workspace_id,
        owner_root_run_id=affinity.owner_root_run_id,
    )
    assert persisted == affinity

    plan = NamedPoolRouter([pool]).plan(
        service_id="firecrawl",
        operation="firecrawl.crawl.status",
        pool_name="primary",
        estimated_cost_units=0,
        unit="credits",
        now_ms=2_000,
        affinity=persisted,
    )
    assert [candidate.credential.credential_id for candidate in plan.candidates] == [credential_b]
    assert all(candidate.scope.principal_id == principal_b for candidate in plan.candidates)

    quarantined_b = PoolMember(
        scope_b,
        (
            RoutingCredential(
                credential_b,
                principal_b,
                quota_b,
                state=CredentialState.QUARANTINED,
            ),
        ),
        priority=2,
    )
    unavailable_router = NamedPoolRouter(
        [
            NamedPool(
                pool_id=pool_id,
                name="primary",
                service_id="firecrawl",
                selection_strategy=PoolSelectionStrategy.FILL_FIRST,
                members=(member_a, quarantined_b),
            )
        ]
    )
    with pytest.raises(AffinityUnavailableError):
        unavailable_router.plan(
            service_id="firecrawl",
            operation="firecrawl.crawl.status",
            pool_name="primary",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2_000,
            affinity=affinity,
        )


def test_off_ledger_exclusive_usage_opens_incident_and_quarantines_locally(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "acceptance.db")
    try:
        connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, created_at_ms, updated_at_ms
            ) VALUES ('principal', 'firecrawl', 'primary', 0, 0)
            """
        )
        connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit,
                last_known_remaining_units, configured_floor_units
            ) VALUES ('quota', 'principal', 'main', 'HEALTHY', 'credits', 100, 0)
            """
        )
        connection.execute(
            """
            INSERT INTO credentials(
                credential_id, principal_id, quota_scope_id, alias, secret_backend,
                secret_reference, state, exclusive_usage, created_at_ms
            ) VALUES ('credential', 'principal', 'quota', 'primary', 'memory',
                      'opaque-reference', 'ACTIVE', 1, 0)
            """
        )
        store = ReconciliationStore(connection)
        for snapshot in (
            UsageSnapshot("quota", "credits", 10, remaining_units=100),
            UsageSnapshot("quota", "credits", 20, remaining_units=90),
        ):
            store.record_snapshot(snapshot, source="account_summary")
        result = store.reconcile_scope(
            quota_scope_id="quota",
            service_id="firecrawl",
            policy=ReconciliationPolicy(
                absolute_tolerance_units=0,
                relative_tolerance=Decimal("0"),
                consecutive_mismatches_for_incident=1,
                maximum_snapshot_age_ms=1_000,
            ),
            now_ms=20,
        )
        assert result.decision.action is ReconciliationAction.QUARANTINE_LOCAL
        assert result.alert_id is not None
        assert (
            connection.execute(
                "SELECT state FROM quota_scopes WHERE quota_scope_id = 'quota'"
            ).fetchone()[0]
            == "QUARANTINED"
        )
        assert (
            connection.execute(
                "SELECT state FROM credentials WHERE credential_id = 'credential'"
            ).fetchone()[0]
            == "QUARANTINED"
        )
    finally:
        connection.close()
