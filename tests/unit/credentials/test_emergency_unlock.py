from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import pytest

from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.credentials.base import CredentialMetadata
from gatehouse.credentials.emergency import (
    EmergencyRequestPermit,
    EmergencyUnlockError,
    EmergencyUnlockManager,
    EmergencyUnlockProjection,
)
from gatehouse.credentials.memory import InMemoryKeyStore

SERVICE_ID = "svc_firecrawl"
POOL_NAME = "emergency-locked"
POOL_ID = "pool_00000000000000000000000001"
SESSION_ID = "ses_interactive_0001"
ROOT_RUN_ID = "run_root_0001"
UNLOCK_ID = "unl_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CREDENTIAL_ID = "cred_00000000000000000000000001"
PRINCIPAL_ID = "prn_00000000000000000000000001"
QUOTA_SCOPE_ID = "quota_00000000000000000000000001"
CREDENTIAL_ALIAS = "emergency-memory-only"
SYNTHETIC_SECRET = b"synthetic-emergency-canary-not-a-real-key"


class FakeClock:
    def __init__(self, now_ms: int = 2_000_000_000_000) -> None:
        self.value = now_ms

    def __call__(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class ControlledSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        self.started.set()
        await self.release.wait()


def make_manager(
    *,
    clock: FakeClock | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    maximum_duration_ms: int = 1_000,
    maximum_requests: int = 3,
    maximum_credits: int = 10,
) -> tuple[EmergencyUnlockManager, InMemoryKeyStore]:
    store = InMemoryKeyStore(
        default_lease_ttl_seconds=30,
        maximum_lease_ttl_seconds=30,
    )
    manager = EmergencyUnlockManager(
        key_store=store,
        now_ms=clock or FakeClock(),
        sleep=sleep or asyncio.sleep,
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: CREDENTIAL_ID,
        principal_id_factory=lambda: PRINCIPAL_ID,
        quota_scope_id_factory=lambda: QUOTA_SCOPE_ID,
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=maximum_duration_ms,
        hard_maximum_requests=maximum_requests,
        hard_maximum_credits=maximum_credits,
    )
    return manager, store


async def unlock(
    manager: EmergencyUnlockManager,
    *,
    secret: bytes | bytearray = SYNTHETIC_SECRET,
    duration_ms: int = 1_000,
    maximum_requests: int = 3,
    maximum_credits: int = 10,
    maximum_concurrency: int = 1,
) -> EmergencyUnlockProjection:
    return await manager.unlock(
        secret=secret,
        service_id=SERVICE_ID,
        pool_id=POOL_ID,
        pool_name=POOL_NAME,
        session_id=SESSION_ID,
        root_run_id=ROOT_RUN_ID,
        interactive=True,
        duration_ms=duration_ms,
        maximum_requests=maximum_requests,
        maximum_credits=maximum_credits,
        maximum_concurrency=maximum_concurrency,
    )


async def reserve(
    manager: EmergencyUnlockManager,
    *,
    operation: str = "firecrawl.scrape",
    estimated_credits: int = 1,
) -> EmergencyRequestPermit:
    return await manager.reserve(
        service_id=SERVICE_ID,
        pool_name=POOL_NAME,
        session_id=SESSION_ID,
        root_run_id=ROOT_RUN_ID,
        operation=operation,
        estimated_credits=estimated_credits,
        automatic=False,
    )


@pytest.mark.asyncio
async def test_one_active_unlock_uses_only_the_injected_store_and_is_redacted() -> None:
    manager, store = make_manager()
    assert (await manager.status()).locked

    caller_buffer = bytearray(SYNTHETIC_SECRET)
    projection = await unlock(manager, secret=caller_buffer)
    caller_buffer[:] = b"x" * len(caller_buffer)

    assert projection.unlock_id == UNLOCK_ID
    assert projection.credential_id == CREDENTIAL_ID
    assert projection.principal_id == PRINCIPAL_ID
    assert projection.quota_scope_id == QUOTA_SCOPE_ID
    assert projection.pool_id == POOL_ID
    assert projection.alias == CREDENTIAL_ALIAS
    assert projection.maximum_concurrency == 1
    assert not projection.automatic
    assert SERVICE_ID not in projection.unlock_id
    assert SESSION_ID not in projection.unlock_id
    assert ROOT_RUN_ID not in projection.credential_id

    metadata = await store.list_metadata()
    assert len(metadata) == 1
    assert metadata[0].credential_id == CREDENTIAL_ID
    assert metadata[0].principal_id == PRINCIPAL_ID
    assert metadata[0].quota_scope_id == QUOTA_SCOPE_ID
    assert metadata[0].alias == CREDENTIAL_ALIAS
    assert metadata[0].secret_reference is not None
    assert metadata[0].secret_reference.startswith("memory://")

    lease = await store.open_lease(CREDENTIAL_ID, "synthetic-test")
    async with lease as secret_view:
        assert bytes(secret_view) == SYNTHETIC_SECRET

    with pytest.raises(EmergencyUnlockError, match="emergency unlock is unavailable"):
        await unlock(manager)

    rendered = " ".join(
        (
            repr(manager),
            repr(await manager.status()),
            repr(projection),
        )
    )
    assert SYNTHETIC_SECRET.decode() not in rendered
    assert "xxxxxxxx" not in rendered
    await manager.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"interactive": False}, "emergency unlock request was denied"),
        ({"duration_ms": 0}, "emergency unlock request was denied"),
        ({"duration_ms": 1_001}, "emergency unlock request was denied"),
        ({"maximum_requests": 0}, "emergency unlock request was denied"),
        ({"maximum_requests": 4}, "emergency unlock request was denied"),
        ({"maximum_credits": 0}, "emergency unlock request was denied"),
        ({"maximum_credits": 11}, "emergency unlock request was denied"),
        ({"maximum_concurrency": 0}, "emergency unlock request was denied"),
        ({"maximum_concurrency": 2}, "emergency unlock request was denied"),
        ({"pool_id": "emergency-locked"}, "emergency unlock request was denied"),
        ({"pool_name": "ordinary-pool"}, "emergency unlock request was denied"),
        ({"credential_alias": ""}, "emergency unlock request was denied"),
        ({"credential_alias": "x" * 257}, "emergency unlock request was denied"),
        (
            {"credential_alias": SYNTHETIC_SECRET.decode()},
            "emergency unlock request was denied",
        ),
    ],
)
async def test_unlock_requires_interactive_bounded_exact_emergency_request(
    overrides: dict[str, object], message: str
) -> None:
    manager, store = make_manager()
    arguments: dict[str, object] = {
        "secret": SYNTHETIC_SECRET,
        "service_id": SERVICE_ID,
        "pool_id": POOL_ID,
        "pool_name": POOL_NAME,
        "session_id": SESSION_ID,
        "root_run_id": ROOT_RUN_ID,
        "interactive": True,
        "duration_ms": 1_000,
        "maximum_requests": 3,
        "maximum_credits": 10,
        "maximum_concurrency": 1,
    }
    arguments.update(overrides)

    with pytest.raises(EmergencyUnlockError, match=message):
        await manager.unlock(**arguments)  # type: ignore[arg-type]

    assert (await manager.status()).locked
    assert await store.list_metadata() == ()
    await manager.close()


@pytest.mark.asyncio
async def test_projection_is_manual_and_requires_the_exact_authority_binding() -> None:
    manager, _ = make_manager()
    await unlock(manager)

    projection = await manager.project(
        service_id=SERVICE_ID,
        pool_name=POOL_NAME,
        session_id=SESSION_ID,
        root_run_id=ROOT_RUN_ID,
        automatic=False,
    )
    assert projection.service_id == SERVICE_ID
    assert projection.pool_name == POOL_NAME
    assert projection.session_id == SESSION_ID
    assert projection.root_run_id == ROOT_RUN_ID
    assert projection.principal_id == PRINCIPAL_ID
    assert projection.quota_scope_id == QUOTA_SCOPE_ID
    assert projection.alias == CREDENTIAL_ALIAS
    assert projection.remaining_requests == 3
    assert projection.remaining_credits == 10

    mismatches = (
        {"service_id": "svc_other"},
        {"pool_name": "another-emergency-pool"},
        {"session_id": "ses_other"},
        {"root_run_id": "run_other"},
        {"automatic": True},
    )
    for mismatch in mismatches:
        arguments: dict[str, object] = {
            "service_id": SERVICE_ID,
            "pool_name": POOL_NAME,
            "session_id": SESSION_ID,
            "root_run_id": ROOT_RUN_ID,
            "automatic": False,
        }
        arguments.update(mismatch)
        with pytest.raises(EmergencyUnlockError, match="emergency unlock is unavailable"):
            await manager.project(**arguments)  # type: ignore[arg-type]

    await manager.close()


@pytest.mark.asyncio
async def test_reservation_is_nonwaiting_manual_sync_only_and_consumes_request() -> None:
    manager, _ = make_manager()
    await unlock(manager)

    for operation, automatic in (
        ("firecrawl.scrape", True),
        ("firecrawl.crawl.start", False),
    ):
        with pytest.raises(EmergencyUnlockError, match="emergency request was denied"):
            await manager.reserve(
                service_id=SERVICE_ID,
                pool_name=POOL_NAME,
                session_id=SESSION_ID,
                root_run_id=ROOT_RUN_ID,
                estimated_credits=1,
                operation=operation,
                automatic=automatic,
            )

    permit = await reserve(manager, estimated_credits=4)
    status = await manager.status()
    assert status.remaining_requests == 2
    assert status.remaining_credits == 6
    assert status.available_concurrency == 0

    with pytest.raises(EmergencyUnlockError, match="emergency capacity is unavailable"):
        await reserve(manager)

    assert await manager.settle(permit, actual_credits=4, outcome_known=True)
    assert not await manager.settle(permit, actual_credits=4, outcome_known=True)
    assert (await manager.status()).available_concurrency == 1
    await manager.close()


@pytest.mark.asyncio
async def test_known_pre_handoff_cancel_refunds_credit_but_never_request() -> None:
    manager, _ = make_manager()
    await unlock(manager)

    permit = await reserve(manager, estimated_credits=7)
    assert await manager.settle(permit, actual_credits=0, outcome_known=True)

    status = await manager.status()
    assert status.remaining_requests == 2
    assert status.remaining_credits == 10
    assert status.available_concurrency == 1
    await manager.close()


@pytest.mark.asyncio
async def test_known_usage_above_estimate_records_the_full_actual_cost() -> None:
    manager, _ = make_manager()
    await unlock(manager)

    permit = await reserve(manager, estimated_credits=3)
    assert await manager.settle(permit, actual_credits=7, outcome_known=True)

    status = await manager.status()
    assert status.remaining_requests == 2
    assert status.remaining_credits == 3
    assert status.available_concurrency == 1
    await manager.close()


@pytest.mark.asyncio
async def test_unknown_outcome_holds_estimated_credit_and_releases_concurrency() -> None:
    manager, _ = make_manager()
    await unlock(manager)

    permit = await reserve(manager, estimated_credits=10)
    assert await manager.settle(permit, actual_credits=None, outcome_known=False)

    status = await manager.status()
    assert status.remaining_requests == 2
    assert status.remaining_credits == 0
    assert status.available_concurrency == 1
    with pytest.raises(EmergencyUnlockError, match="emergency capacity is unavailable"):
        await reserve(manager, estimated_credits=1)
    await manager.close()


@pytest.mark.asyncio
async def test_request_ceiling_is_never_refunded() -> None:
    manager, _ = make_manager(maximum_requests=2)
    await unlock(manager, maximum_requests=2)

    for _ in range(2):
        permit = await reserve(manager)
        assert await manager.settle(permit, actual_credits=0, outcome_known=True)

    with pytest.raises(EmergencyUnlockError, match="emergency capacity is unavailable"):
        await reserve(manager)
    await manager.close()


@pytest.mark.asyncio
async def test_explicit_cancel_closes_leases_zeroes_secret_and_is_idempotent() -> None:
    manager, store = make_manager()
    projection = await unlock(manager)
    permit = await reserve(manager)
    lease = await store.open_lease(CREDENTIAL_ID, "synthetic-cancel-test")
    secret_view = await lease.__aenter__()
    assert bytes(secret_view) == SYNTHETIC_SECRET

    assert await manager.cancel(projection.unlock_id)
    assert lease.closed
    assert bytes(secret_view) == b"\x00" * len(SYNTHETIC_SECRET)
    assert await store.list_metadata() == ()
    assert (await manager.status()).locked
    unsettled = permit.settled
    assert not unsettled
    assert not await manager.cancel(projection.unlock_id)
    assert await manager.settle(permit, actual_credits=1, outcome_known=True)
    settled = permit.settled
    assert settled
    await manager.close()


@pytest.mark.asyncio
async def test_cancelled_in_flight_permit_blocks_reunlock_until_terminal_settlement() -> None:
    manager, store = make_manager()
    projection = await unlock(manager)
    permit = await reserve(manager)

    assert await manager.cancel(projection.unlock_id)
    assert await store.list_metadata() == ()
    assert (await manager.status()).locked
    with pytest.raises(EmergencyUnlockError, match="emergency unlock is unavailable"):
        await unlock(manager)

    assert await manager.settle(permit, actual_credits=None, outcome_known=False)
    replacement = await unlock(manager)
    assert replacement.unlock_id == UNLOCK_ID
    await manager.cancel(replacement.unlock_id)
    await manager.close()


@pytest.mark.asyncio
async def test_timer_expiry_immediately_relocks_and_deletes_secret() -> None:
    clock = FakeClock()
    sleeper = ControlledSleep()
    manager, store = make_manager(clock=clock, sleep=sleeper)
    await unlock(manager, duration_ms=500)
    permit = await reserve(manager)
    lease = await store.open_lease(CREDENTIAL_ID, "synthetic-expiry-test")
    secret_view = await lease.__aenter__()

    await asyncio.wait_for(sleeper.started.wait(), timeout=1)
    assert sleeper.calls == [0.5]
    clock.advance(500)
    sleeper.release.set()
    for _ in range(10):
        if (await manager.status()).locked:
            break
        await asyncio.sleep(0)

    assert (await manager.status()).locked
    assert lease.closed
    assert bytes(secret_view) == b"\x00" * len(SYNTHETIC_SECRET)
    assert await store.list_metadata() == ()
    with pytest.raises(EmergencyUnlockError, match="emergency unlock is unavailable"):
        await unlock(manager)
    assert await manager.settle(permit, actual_credits=None, outcome_known=False)
    await manager.close()


@pytest.mark.asyncio
async def test_close_and_fresh_manager_are_empty_locked_and_close_is_idempotent() -> None:
    clock = FakeClock()
    manager, store = make_manager(clock=clock)
    await unlock(manager)

    await manager.close()
    await manager.close()
    assert (await manager.status()).locked
    assert await store.list_metadata() == ()
    with pytest.raises(EmergencyUnlockError, match="emergency manager is closed"):
        await unlock(manager)

    restarted = EmergencyUnlockManager(
        key_store=store,
        now_ms=clock,
        sleep=asyncio.sleep,
        unlock_id_factory=lambda: "unl_cccccccccccccccccccccccccccccccc",
        credential_id_factory=lambda: "cred_00000000000000000000000002",
        principal_id_factory=lambda: "prn_00000000000000000000000002",
        quota_scope_id_factory=lambda: "quota_00000000000000000000000002",
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=1_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )
    assert (await restarted.status()).locked
    await restarted.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("factory", "invalid_value"),
    [
        ("credential_id_factory", "crd_not-a-routing-id"),
        ("principal_id_factory", "emergency-principal"),
        ("quota_scope_id_factory", "emergency-quota"),
    ],
)
async def test_invalid_routing_identifier_factory_fails_safely(
    factory: str,
    invalid_value: str,
) -> None:
    store = InMemoryKeyStore()
    arguments: dict[str, object] = {
        "key_store": store,
        "now_ms": FakeClock(),
        "unlock_id_factory": lambda: UNLOCK_ID,
        "credential_id_factory": lambda: CREDENTIAL_ID,
        "principal_id_factory": lambda: PRINCIPAL_ID,
        "quota_scope_id_factory": lambda: QUOTA_SCOPE_ID,
        "emergency_pool_name": POOL_NAME,
        "hard_maximum_duration_ms": 1_000,
        "hard_maximum_requests": 3,
        "hard_maximum_credits": 10,
    }
    arguments[factory] = lambda: invalid_value
    manager = EmergencyUnlockManager(**arguments)  # type: ignore[arg-type]

    with pytest.raises(
        EmergencyUnlockError,
        match="^emergency unlock request was denied$",
    ):
        await unlock(manager)

    assert await store.list_metadata() == ()
    assert invalid_value not in repr(await manager.status())
    await manager.close()


@pytest.mark.asyncio
async def test_valid_generated_credential_id_equal_to_secret_never_reaches_custody() -> None:
    store = InMemoryKeyStore()
    active_secret = CREDENTIAL_ID.encode("utf-8")
    manager = EmergencyUnlockManager(
        key_store=store,
        now_ms=FakeClock(),
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: CREDENTIAL_ID,
        principal_id_factory=lambda: PRINCIPAL_ID,
        quota_scope_id_factory=lambda: QUOTA_SCOPE_ID,
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=1_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )

    with pytest.raises(
        EmergencyUnlockError,
        match="^emergency unlock request was denied$",
    ) as captured:
        await unlock(manager, secret=active_secret)

    assert await store.list_metadata() == ()
    status = await manager.status()
    assert status.locked
    assert CREDENTIAL_ID not in repr(status)
    assert CREDENTIAL_ID not in repr(captured.value)
    await manager.close()


@pytest.mark.asyncio
async def test_generated_clock_value_equal_to_secret_never_reaches_custody() -> None:
    clock = FakeClock()
    manager, store = make_manager(clock=clock)

    with pytest.raises(EmergencyUnlockError, match="emergency unlock request was denied"):
        await unlock(manager, secret=str(clock.value).encode("ascii"))

    assert await store.list_metadata() == ()
    assert (await manager.status()).locked
    await manager.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "secret",
    (b"HEALTHY", b"ACTIVE", b"RUNNING", b"none", b"application/json", b"false", b"null", b"1"),
)
async def test_fixed_projection_value_equal_to_secret_never_reaches_custody(
    secret: bytes,
) -> None:
    manager, store = make_manager()

    with pytest.raises(EmergencyUnlockError, match="emergency unlock request was denied"):
        await unlock(manager, secret=secret)

    assert await store.list_metadata() == ()
    assert (await manager.status()).locked
    await manager.close()


@pytest.mark.asyncio
async def test_default_metadata_factories_produce_routing_valid_identifiers() -> None:
    store = InMemoryKeyStore()
    manager = EmergencyUnlockManager(
        key_store=store,
        now_ms=FakeClock(),
        unlock_id_factory=lambda: UNLOCK_ID,
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=1_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )

    projection = await unlock(manager)

    assert str(CredentialId(projection.credential_id)) == projection.credential_id
    assert str(PrincipalId(projection.principal_id)) == projection.principal_id
    assert str(QuotaScopeId(projection.quota_scope_id)) == projection.quota_scope_id
    assert str(PoolId(projection.pool_id)) == projection.pool_id
    status = await manager.status()
    assert status.principal_id == projection.principal_id
    assert status.quota_scope_id == projection.quota_scope_id
    assert status.pool_id == projection.pool_id
    assert status.alias == CREDENTIAL_ALIAS
    assert projection.principal_id not in repr(projection)
    assert projection.quota_scope_id not in repr(status)
    await manager.close()


@pytest.mark.asyncio
async def test_custom_bounded_alias_is_shared_by_metadata_projection_and_status() -> None:
    manager, store = make_manager()
    alias = "manual-emergency-primary"

    projection = await manager.unlock(
        secret=SYNTHETIC_SECRET,
        service_id=SERVICE_ID,
        pool_id=POOL_ID,
        pool_name=POOL_NAME,
        session_id=SESSION_ID,
        root_run_id=ROOT_RUN_ID,
        interactive=True,
        duration_ms=1_000,
        maximum_requests=3,
        maximum_credits=10,
        credential_alias=alias,
    )

    assert projection.alias == alias
    assert (await manager.status()).alias == alias
    assert (await store.list_metadata())[0].alias == alias
    assert alias not in repr(projection)
    assert alias not in repr(await manager.status())
    await manager.close()


@pytest.mark.asyncio
async def test_create_only_collision_never_deletes_preexisting_emergency_custody() -> None:
    store = InMemoryKeyStore()
    existing_secret = b"synthetic-existing-emergency-secret"
    await store.put(
        CredentialMetadata(
            credential_id=CREDENTIAL_ID,
            principal_id=PRINCIPAL_ID,
            quota_scope_id=QUOTA_SCOPE_ID,
            alias=CREDENTIAL_ALIAS,
        ),
        existing_secret,
    )
    manager = EmergencyUnlockManager(
        key_store=store,
        now_ms=FakeClock(),
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: CREDENTIAL_ID,
        principal_id_factory=lambda: PRINCIPAL_ID,
        quota_scope_id_factory=lambda: QUOTA_SCOPE_ID,
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=1_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )

    with pytest.raises(
        EmergencyUnlockError,
        match="^emergency credential custody failed$",
    ):
        await unlock(manager)

    assert len(await store.list_metadata()) == 1
    lease = await store.open_lease(CREDENTIAL_ID, "synthetic-collision-check")
    async with lease as view:
        assert bytes(view) == existing_secret
    await manager.close()


@pytest.mark.asyncio
async def test_secret_and_attacker_controlled_authority_never_reach_repr_status_or_errors() -> None:
    manager, _ = make_manager()
    projection = await unlock(manager)
    permit = await reserve(manager)
    canary = SYNTHETIC_SECRET.decode()

    with pytest.raises(EmergencyUnlockError) as captured:
        await manager.project(
            service_id=canary,
            pool_name=POOL_NAME,
            session_id=SESSION_ID,
            root_run_id=ROOT_RUN_ID,
            automatic=False,
        )

    rendered = " ".join(
        (
            repr(manager),
            repr(await manager.status()),
            repr(projection),
            repr(permit),
            repr(captured.value),
            str(captured.value),
        )
    )
    assert canary not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    await manager.close()


@pytest.mark.asyncio
async def test_custody_failure_detaches_secret_bearing_exception_graph() -> None:
    canary = SYNTHETIC_SECRET.decode()

    class FailingStore(InMemoryKeyStore):
        async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
            del metadata, secret
            raise RuntimeError(canary)

    manager = EmergencyUnlockManager(
        key_store=FailingStore(),
        now_ms=FakeClock(),
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: CREDENTIAL_ID,
        principal_id_factory=lambda: PRINCIPAL_ID,
        quota_scope_id_factory=lambda: QUOTA_SCOPE_ID,
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=1_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )

    with pytest.raises(EmergencyUnlockError) as captured:
        await unlock(manager)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert canary not in repr(captured.value)
    await manager.close()


@pytest.mark.asyncio
async def test_cleanup_failure_detaches_secret_bearing_exception_graph() -> None:
    canary = SYNTHETIC_SECRET.decode()

    class FailingCleanupStore(InMemoryKeyStore):
        async def delete(self, credential_id: str) -> None:
            del credential_id
            raise RuntimeError(canary)

    manager = EmergencyUnlockManager(
        key_store=FailingCleanupStore(),
        now_ms=FakeClock(),
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: CREDENTIAL_ID,
        principal_id_factory=lambda: PRINCIPAL_ID,
        quota_scope_id_factory=lambda: QUOTA_SCOPE_ID,
        emergency_pool_name=POOL_NAME,
        hard_maximum_duration_ms=1_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )
    await unlock(manager)

    with pytest.raises(EmergencyUnlockError) as captured:
        await manager.cancel(UNLOCK_ID)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert canary not in repr(captured.value)
