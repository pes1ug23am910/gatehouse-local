from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import httpx
import pytest

from gatehouse.credentials import CredentialMetadata, InMemoryKeyStore
from gatehouse.database import GatehouseRepository, QuotaReservationStatus, open_migrated_database
from gatehouse.fingerprint import (
    FingerprintContext,
    FingerprintService,
    SingleFlightCoordinator,
    SingleFlightRole,
)
from gatehouse.providers.firecrawl import FirecrawlAdapter
from gatehouse.providers.transport import FIRECRAWL_ORIGIN, HttpxProviderTransport
from gatehouse.testing import ProviderScriptStep, ScriptedProviderASGI, ScriptMode


def _seed_quota_database(path: Path, request_count: int) -> None:
    connection = open_migrated_database(path)
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES ('client', 'Client', 'test', 'default', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, bootstrap_verifier, bootstrap_version, token_epoch,
            state, identity_assurance, policy_version, created_at_ms,
            reconnect_until_ms, absolute_expires_at_ms
        ) VALUES ('session', 'client', X'01', 1, 0, 'ACTIVE', 'TEST', 'v1', 0, 9999, 9999)
        """
    )
    connection.execute(
        """
        INSERT INTO principals(principal_id, service_id, alias, created_at_ms, updated_at_ms)
        VALUES ('principal', 'firecrawl', 'primary', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES ('quota', 'principal', 'main', 'HEALTHY', 'credits', NULL, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias, secret_backend,
            secret_reference, state, generation, created_at_ms, credential_role
        ) VALUES ('credential-quota-observer', 'principal', 'quota', 'observer',
                  'test', 'reference', 'HEALTHY', 1, 0, 'OBSERVER')
        """
    )
    connection.execute(
        """
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units, unit,
            captured_at_ms, source, observed_remaining_units_decimal,
            quota_dimension_id, credential_id, credential_generation,
            stale_at_ms, observation_kind
        ) VALUES ('snapshot-quota', 'quota', 100, 'credits', 0,
                  'concurrency-test', '100', 'dimension_legacy_primary:quota',
                  'credential-quota-observer', 1, 9223372036854775807,
                  'AUTHENTICATED')
        """
    )
    connection.execute(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = 100,
               balance_as_of_ms = 0,
               balance_snapshot_id = 'snapshot-quota'
         WHERE quota_scope_id = 'quota'
        """
    )
    for index in range(request_count):
        connection.execute(
            """
            INSERT INTO invocations(
                request_id, session_id, service_id, operation, request_fingerprint,
                fingerprint_version, canonicalization_version, state, priority_class,
                request_size_bytes, received_at_ms
            ) VALUES (?, 'session', 'firecrawl', 'search', X'AA', 1, 1,
                      'QUEUED', 'NORMAL_AGENT', 1, 0)
            """,
            (f"request-{index}",),
        )
    connection.close()


def test_concurrent_quota_reservation_never_oversubscribes(tmp_path: Path) -> None:
    path = tmp_path / "quota.db"
    contender_count = 40
    _seed_quota_database(path, contender_count)
    barrier = threading.Barrier(contender_count)
    lock = threading.Lock()
    statuses: list[QuotaReservationStatus] = []
    errors: list[BaseException] = []

    def reserve(index: int) -> None:
        connection = open_migrated_database(path)
        try:
            barrier.wait(timeout=10)
            result = GatehouseRepository(connection).reserve_quota(
                request_id=f"request-{index}",
                quota_scope_id="quota",
                amount_units=7,
                unit="credits",
                now_ms=100,
                expires_at_ms=1_000,
            )
            with lock:
                statuses.append(result.status)
        except BaseException as error:
            with lock:
                errors.append(error)
        finally:
            connection.close()

    threads = [threading.Thread(target=reserve, args=(index,)) for index in range(contender_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert statuses.count(QuotaReservationStatus.RESERVED) == 14
    check = open_migrated_database(path)
    try:
        held = int(
            check.execute(
                "SELECT COALESCE(SUM(amount_units), 0) FROM quota_reservations"
            ).fetchone()[0]
        )
    finally:
        check.close()
    assert held == 98 and held <= 100


async def _public_resolver(_host: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


@pytest.mark.asyncio
async def test_eligible_duplicates_make_one_provider_call_and_cancel_one_waiter_only() -> None:
    app = ScriptedProviderASGI()
    app.script(
        "POST",
        "/v2/search",
        [
            ProviderScriptStep(
                mode=ScriptMode.DELAY,
                delay_ms=15,
                json_data={"success": True, "creditsUsed": 1},
            )
        ],
    )
    store = InMemoryKeyStore()
    await store.put(
        CredentialMetadata("credential", "principal", "quota", "test"),
        b"SINGLEFLIGHT_ONLY_SECRET_123456",
    )
    client = httpx.AsyncClient(
        base_url=FIRECRAWL_ORIGIN,
        transport=httpx.ASGITransport(app=app),
    )
    transport = HttpxProviderTransport(
        key_store=store,
        network_enabled=True,
        client=client,
        resolver=_public_resolver,
    )
    adapter = FirecrawlAdapter()
    request = adapter.build_request(
        "firecrawl.search",
        {
            "query": "same graduate roles",
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        },
        credential_id="credential",
    )
    fingerprint = FingerprintService(b"f" * 32).calculate(
        FingerprintContext(
            service="firecrawl",
            operation="firecrawl.search",
            normalized_input={"query": "same graduate roles"},
            workspace_scope="workspace",
            data_scope="public_web_query",
            authorization_scope="session",
            result_format="structured",
        )
    )
    singleflight = SingleFlightCoordinator(maximum_waiters_per_group=64)
    handles = await asyncio.gather(
        *(
            singleflight.join_or_create(
                session_id="session",
                request_id=f"duplicate-{index}",
                fingerprint=fingerprint,
            )
            for index in range(50)
        )
    )
    leader = next(handle for handle in handles if handle.role is SingleFlightRole.LEADER)
    cancelled = next(handle for handle in handles if handle.role is SingleFlightRole.WAITER)

    async def execute_once() -> None:
        response = await transport.send(request)
        await singleflight.complete(leader.group_id, response.data)

    provider_task = asyncio.create_task(execute_once())
    decision = await singleflight.cancel(cancelled)
    assert decision.detached and not decision.cancel_underlying
    with pytest.raises(asyncio.CancelledError):
        await cancelled.wait()
    remaining = [handle for handle in handles if handle is not cancelled]
    try:
        values = await asyncio.gather(*(handle.wait() for handle in remaining))
        await provider_task
    finally:
        await client.aclose()
    assert len(values) == 49
    assert all(value == {"success": True, "creditsUsed": 1} for value in values)
    assert len(app.observations) == 1
    assert singleflight.active_groups == 0
