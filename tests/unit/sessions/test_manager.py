from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import replace

import pytest

from gatehouse.core.ids import RootRunId, SessionId
from gatehouse.core.states import InvalidStateTransition
from gatehouse.sessions import (
    AccessTokenCapacityExceeded,
    BootstrapExchangeRateLimited,
    CrossSessionRootRun,
    InvalidAccessToken,
    RootRunNotFound,
    SessionManager,
    SessionRecord,
    SessionState,
    SessionUnavailable,
)
from gatehouse.sessions.models import RootRunRecord, SessionTransitionConditionError


class FakeClock:
    def __init__(self, now_ms: int = 1_000) -> None:
        self.value = now_ms

    def __call__(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class DeterministicRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        seed = hashlib.sha512(f"random-{self.counter}".encode()).digest()
        repeats = (length + len(seed) - 1) // len(seed)
        return (seed * repeats)[:length]


class MemorySessionPersistence:
    def __init__(self) -> None:
        self.epoch = 0
        self.sessions: dict[str, SessionRecord] = {}
        self.root_runs: dict[str, RootRunRecord] = {}

    async def begin_daemon_epoch(self, *, now_ms: int, reconnect_grace_ms: int) -> int:
        self.epoch += 1
        for session_id, session in tuple(self.sessions.items()):
            if session.state is SessionState.ACTIVE:
                self.sessions[session_id] = session.transition(
                    SessionState.DISCONNECTED,
                    now_ms=now_ms,
                    reconnect_grace_ms=reconnect_grace_ms,
                )
        return self.epoch

    async def insert_session(
        self,
        session: SessionRecord,
        *,
        maximum_concurrent_runs: int | None,
        stale_after_ms: int,
        reconnect_grace_ms: int,
        block_on_runaway_quarantine: bool,
    ) -> None:
        del maximum_concurrent_runs, stale_after_ms, reconnect_grace_ms
        del block_on_runaway_quarantine
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
        if root_run.root_run_id in self.root_runs:
            raise ValueError("duplicate root run")
        self.root_runs[root_run.root_run_id] = root_run

    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None:
        return self.root_runs.get(root_run_id)


async def make_manager(
    persistence: MemorySessionPersistence,
    clock: FakeClock,
    random: DeterministicRandom,
    *,
    token_ttl_ms: int = 600,
    stale_after_ms: int = 120_000,
    reconnect_grace_ms: int = 2_000,
    maximum_access_tokens: int = 16,
    maximum_active_access_tokens_per_session: int = 1,
    maximum_bootstrap_exchanges_per_window: int = 8,
    bootstrap_exchange_window_ms: int = 60_000,
) -> SessionManager:
    return await SessionManager.start(
        persistence=persistence,
        verifier_key=b"v" * 32,
        now_ms=clock,
        random_bytes=random,
        access_token_ttl_ms=token_ttl_ms,
        reconnect_grace_ms=reconnect_grace_ms,
        stale_after_ms=stale_after_ms,
        maximum_access_tokens=maximum_access_tokens,
        maximum_active_access_tokens_per_session=(maximum_active_access_tokens_per_session),
        maximum_bootstrap_exchanges_per_window=(maximum_bootstrap_exchanges_per_window),
        bootstrap_exchange_window_ms=bootstrap_exchange_window_ms,
    )


async def launch_and_exchange(
    manager: SessionManager,
    *,
    client_id: str = "editor-one",
) -> tuple[str, str, str]:
    launched = await manager.create_session(
        client_id=client_id,
        workspace_id="workspace-one",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
        budget={"credits": 100},
    )
    issued = await manager.exchange_bootstrap(
        session_id=launched.session.session_id,
        bootstrap_capability=launched.bootstrap_capability,
    )
    return (
        launched.session.session_id,
        launched.bootstrap_capability,
        issued.access_token,
    )


@pytest.mark.asyncio
async def test_bootstrap_is_256_bits_and_only_hmac_verifier_is_persisted() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    random = DeterministicRandom()
    manager = await make_manager(persistence, clock, random)

    launched = await manager.create_session(
        client_id="editor-two",
        workspace_id="workspace-one",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
    )

    padding = "=" * (-len(launched.bootstrap_capability) % 4)
    raw = base64.urlsafe_b64decode(launched.bootstrap_capability + padding)
    persisted = persistence.sessions[launched.session.session_id]
    assert len(raw) == 32
    assert len(persisted.bootstrap_verifier) == 32
    assert raw != persisted.bootstrap_verifier
    assert launched.bootstrap_capability not in repr(persisted)


@pytest.mark.asyncio
async def test_token_rotation_preserves_capacity_for_an_unrelated_session() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        maximum_access_tokens=2,
    )
    first_session, first_bootstrap, oldest_token = await launch_and_exchange(
        manager,
        client_id="editor-one",
    )

    newest_token = oldest_token
    for _ in range(4):
        issued = await manager.exchange_bootstrap(
            session_id=first_session,
            bootstrap_capability=first_bootstrap,
        )
        newest_token = issued.access_token

    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(oldest_token)
    second_session, _, second_token = await launch_and_exchange(
        manager,
        client_id="editor-two",
    )
    assert (await manager.authenticate(newest_token)).session_id == first_session
    assert (await manager.authenticate(second_token)).session_id == second_session


@pytest.mark.asyncio
async def test_per_session_token_capacity_cannot_consume_all_global_slots() -> None:
    with pytest.raises(ValueError, match="preserve global capacity for a peer"):
        await make_manager(
            MemorySessionPersistence(),
            FakeClock(),
            DeterministicRandom(),
            maximum_access_tokens=4,
            maximum_active_access_tokens_per_session=4,
        )


@pytest.mark.asyncio
async def test_rotation_evicts_oldest_issue_even_after_it_was_recently_used() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        maximum_active_access_tokens_per_session=2,
    )
    session_id, bootstrap, oldest_token = await launch_and_exchange(manager)
    middle = await manager.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )
    await manager.authenticate(oldest_token)

    newest = await manager.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )

    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(oldest_token)
    assert (await manager.authenticate(middle.access_token)).session_id == session_id
    assert (await manager.authenticate(newest.access_token)).session_id == session_id


@pytest.mark.asyncio
async def test_global_token_capacity_has_bounded_retry_guidance() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        maximum_access_tokens=1,
    )
    await launch_and_exchange(manager, client_id="editor-one")
    waiting = await manager.create_session(
        client_id="editor-two",
        workspace_id="workspace-one",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
    )

    with pytest.raises(AccessTokenCapacityExceeded) as raised:
        await manager.exchange_bootstrap(
            session_id=waiting.session.session_id,
            bootstrap_capability=waiting.bootstrap_capability,
        )
    assert raised.value.retry_after_seconds == 1


@pytest.mark.asyncio
async def test_concurrent_exchange_abuse_is_rate_limited_without_blocking_peers() -> None:
    class BarrierPersistence(MemorySessionPersistence):
        def __init__(self) -> None:
            super().__init__()
            self.blocked_tasks: set[str] = set()
            self.all_loaded = asyncio.Event()
            self.release = asyncio.Event()

        async def load_session(self, session_id: str) -> SessionRecord | None:
            snapshot = await super().load_session(session_id)
            task = asyncio.current_task()
            if task is not None and task.get_name().startswith("bootstrap-abuse-"):
                self.blocked_tasks.add(task.get_name())
                if len(self.blocked_tasks) == 10:
                    self.all_loaded.set()
                await self.release.wait()
            return snapshot

    persistence = BarrierPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        maximum_access_tokens=2,
        maximum_bootstrap_exchanges_per_window=3,
        bootstrap_exchange_window_ms=1_000,
    )
    first = await manager.create_session(
        client_id="editor-one",
        workspace_id="workspace-one",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
    )

    tasks = [
        asyncio.create_task(
            manager.exchange_bootstrap(
                session_id=first.session.session_id,
                bootstrap_capability=first.bootstrap_capability,
            ),
            name=f"bootstrap-abuse-{index}",
        )
        for index in range(10)
    ]
    try:
        await asyncio.wait_for(persistence.all_loaded.wait(), timeout=1)
    finally:
        persistence.release.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    issued = [result for result in results if not isinstance(result, Exception)]
    limited = [result for result in results if isinstance(result, BootstrapExchangeRateLimited)]
    assert len(issued) == 3
    assert len(limited) == 7
    assert {error.retry_after_seconds for error in limited} == {1}

    second_session, _, second_token = await launch_and_exchange(
        manager,
        client_id="editor-two",
    )
    assert (await manager.authenticate(second_token)).session_id == second_session

    clock.advance(1_000)
    refreshed = await manager.exchange_bootstrap(
        session_id=first.session.session_id,
        bootstrap_capability=first.bootstrap_capability,
    )
    assert (
        await manager.authenticate(refreshed.access_token)
    ).session_id == first.session.session_id


@pytest.mark.asyncio
async def test_full_exchange_tracker_fails_closed_without_evicting_a_rate_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SessionManager, "_MAXIMUM_TRACKED_BOOTSTRAP_EXCHANGE_SESSIONS", 2)
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        maximum_access_tokens=4,
        maximum_bootstrap_exchanges_per_window=1,
        bootstrap_exchange_window_ms=1_000,
    )
    first_session, first_bootstrap, _ = await launch_and_exchange(
        manager,
        client_id="editor-one",
    )
    await launch_and_exchange(manager, client_id="editor-two")
    third = await manager.create_session(
        client_id="editor-three",
        workspace_id="workspace-one",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
    )

    with pytest.raises(BootstrapExchangeRateLimited) as tracker_full:
        await manager.exchange_bootstrap(
            session_id=third.session.session_id,
            bootstrap_capability=third.bootstrap_capability,
        )
    assert tracker_full.value.retry_after_seconds == 1

    with pytest.raises(BootstrapExchangeRateLimited) as first_still_limited:
        await manager.exchange_bootstrap(
            session_id=first_session,
            bootstrap_capability=first_bootstrap,
        )
    assert first_still_limited.value.retry_after_seconds == 1

    clock.advance(1_000)
    issued = await manager.exchange_bootstrap(
        session_id=third.session.session_id,
        bootstrap_capability=third.bootstrap_capability,
    )
    assert (await manager.authenticate(issued.access_token)).session_id == third.session.session_id


@pytest.mark.asyncio
async def test_access_token_expires_and_revocation_invalidates_it() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(persistence, clock, DeterministicRandom())
    session_id, bootstrap, token = await launch_and_exchange(manager)

    principal = await manager.authenticate(token)
    assert principal.session_id == session_id
    assert principal.revocation_epoch == 0
    revoked = await manager.revoke(session_id)
    retried = await manager.revoke(session_id)
    assert retried == revoked
    assert retried.revocation_epoch == 1
    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(token)
    with pytest.raises(SessionUnavailable):
        await manager.exchange_bootstrap(
            session_id=session_id,
            bootstrap_capability=bootstrap,
        )

    short_clock = FakeClock()
    manager = await make_manager(
        MemorySessionPersistence(),
        short_clock,
        DeterministicRandom(),
        token_ttl_ms=50,
    )
    _, _, short_token = await launch_and_exchange(manager)
    short_clock.advance(50)
    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(short_token)


@pytest.mark.asyncio
async def test_stale_authentication_disconnects_and_drops_every_session_token() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        stale_after_ms=100,
        reconnect_grace_ms=500,
        maximum_active_access_tokens_per_session=2,
    )
    session_id, bootstrap, first_token = await launch_and_exchange(manager)
    second = await manager.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )

    clock.advance(100)
    with pytest.raises(InvalidAccessToken, match="heartbeat"):
        await manager.authenticate(first_token)

    disconnected = persistence.sessions[session_id]
    assert disconnected.state is SessionState.DISCONNECTED
    assert disconnected.disconnected_at_ms == clock()
    assert disconnected.reconnect_until_ms == clock() + 500
    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(second.access_token)

    replacement = await manager.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )
    assert persistence.sessions[session_id].state is SessionState.ACTIVE
    assert (await manager.authenticate(replacement.access_token)).session_id == session_id


@pytest.mark.asyncio
async def test_active_epoch_revalidation_checks_epochs_expiry_and_staleness() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        stale_after_ms=100,
        reconnect_grace_ms=500,
    )
    session_id, _, token = await launch_and_exchange(manager)
    principal = await manager.authenticate(token)

    assert await manager.is_active_epoch(
        session_id=session_id,
        token_epoch=principal.token_epoch,
        revocation_epoch=principal.revocation_epoch,
    )
    assert not await manager.is_active_epoch(
        session_id=session_id,
        token_epoch=principal.token_epoch + 1,
        revocation_epoch=principal.revocation_epoch,
    )
    assert not await manager.is_active_epoch(
        session_id=session_id,
        token_epoch=principal.token_epoch,
        revocation_epoch=principal.revocation_epoch + 1,
    )
    current = persistence.sessions[session_id]
    old_epoch = principal.token_epoch - 1
    persistence.sessions[session_id] = replace(current, token_epoch=old_epoch)
    assert not await manager.is_active_epoch(
        session_id=session_id,
        token_epoch=old_epoch,
        revocation_epoch=principal.revocation_epoch,
    )
    persistence.sessions[session_id] = current

    clock.advance(100)
    assert not await manager.is_active_epoch(
        session_id=session_id,
        token_epoch=principal.token_epoch,
        revocation_epoch=principal.revocation_epoch,
    )
    assert persistence.sessions[session_id].state is SessionState.DISCONNECTED
    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(token)

    expiry_persistence = MemorySessionPersistence()
    expiry_clock = FakeClock()
    expiry_manager = await make_manager(
        expiry_persistence,
        expiry_clock,
        DeterministicRandom(),
        stale_after_ms=20_000,
    )
    expiring_session, _, expiring_token = await launch_and_exchange(expiry_manager)
    expiring_principal = await expiry_manager.authenticate(expiring_token)
    expiry_clock.advance(10_000)
    assert not await expiry_manager.is_active_epoch(
        session_id=expiring_session,
        token_epoch=expiring_principal.token_epoch,
        revocation_epoch=expiring_principal.revocation_epoch,
    )
    assert expiry_persistence.sessions[expiring_session].state is SessionState.EXPIRED


@pytest.mark.asyncio
async def test_active_epoch_revalidation_propagates_storage_failures() -> None:
    class FailingPersistence(MemorySessionPersistence):
        async def load_session(self, session_id: str) -> SessionRecord | None:
            del session_id
            raise OSError("synthetic storage failure")

    manager = await make_manager(
        FailingPersistence(),
        FakeClock(),
        DeterministicRandom(),
    )

    with pytest.raises(OSError, match="synthetic storage failure"):
        await manager.is_active_epoch(
            session_id="ses_missing",
            token_epoch=manager.token_epoch,
            revocation_epoch=0,
        )


@pytest.mark.asyncio
async def test_bootstrap_exchange_readopts_a_stale_active_session_within_grace() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        stale_after_ms=100,
        reconnect_grace_ms=500,
    )
    session_id, bootstrap, old_token = await launch_and_exchange(manager)
    clock.advance(100)

    replacement = await manager.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )

    active = persistence.sessions[session_id]
    assert active.state is SessionState.ACTIVE
    assert active.last_seen_at_ms == clock()
    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(old_token)
    assert (await manager.authenticate(replacement.access_token)).session_id == session_id


@pytest.mark.asyncio
async def test_stale_disconnect_cas_preserves_a_concurrent_fresh_heartbeat() -> None:
    clock = FakeClock()

    class RacingPersistence(MemorySessionPersistence):
        def __init__(self) -> None:
            super().__init__()
            self.stale_disconnect_attempts = 0

        async def replace_session(
            self,
            *,
            expected: SessionRecord,
            replacement: SessionRecord,
        ) -> bool:
            if replacement.state is SessionState.DISCONNECTED:
                self.stale_disconnect_attempts += 1
                self.sessions[expected.session_id] = expected.touch(now_ms=clock())
                return False
            return await super().replace_session(expected=expected, replacement=replacement)

    persistence = RacingPersistence()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        stale_after_ms=100,
    )
    session_id, _, token = await launch_and_exchange(manager)
    clock.advance(100)

    assert (await manager.authenticate(token)).session_id == session_id
    assert persistence.stale_disconnect_attempts == 1
    assert persistence.sessions[session_id].state is SessionState.ACTIVE
    assert persistence.sessions[session_id].last_seen_at_ms == clock()


@pytest.mark.asyncio
async def test_stale_authentication_rejects_token_dropped_by_concurrent_readoption() -> None:
    class RacingPersistence(MemorySessionPersistence):
        def __init__(self) -> None:
            super().__init__()
            self.block_stale_authentication = False
            self.stale_authentication_loaded = asyncio.Event()
            self.release_stale_authentication = asyncio.Event()

        async def load_session(self, session_id: str) -> SessionRecord | None:
            snapshot = await super().load_session(session_id)
            task = asyncio.current_task()
            if (
                self.block_stale_authentication
                and task is not None
                and task.get_name() == "stale-session-authentication"
                and not self.stale_authentication_loaded.is_set()
            ):
                self.stale_authentication_loaded.set()
                await self.release_stale_authentication.wait()
            return snapshot

    persistence = RacingPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        stale_after_ms=100,
        reconnect_grace_ms=500,
    )
    session_id, bootstrap, stale_token = await launch_and_exchange(manager)
    clock.advance(100)
    persistence.block_stale_authentication = True
    authentication = asyncio.create_task(
        manager.authenticate(stale_token),
        name="stale-session-authentication",
    )
    await asyncio.wait_for(persistence.stale_authentication_loaded.wait(), timeout=1)

    try:
        replacement = await manager.exchange_bootstrap(
            session_id=session_id,
            bootstrap_capability=bootstrap,
        )
    finally:
        persistence.release_stale_authentication.set()

    with pytest.raises(InvalidAccessToken, match="no longer authorized"):
        await authentication
    assert (await manager.authenticate(replacement.access_token)).session_id == session_id


@pytest.mark.asyncio
async def test_stale_session_cannot_readopt_after_reconnect_grace_expires() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(
        persistence,
        clock,
        DeterministicRandom(),
        stale_after_ms=100,
        reconnect_grace_ms=200,
    )
    session_id, bootstrap, token = await launch_and_exchange(manager)
    clock.advance(301)
    with pytest.raises(SessionUnavailable, match="reconnect grace"):
        await manager.exchange_bootstrap(
            session_id=session_id,
            bootstrap_capability=bootstrap,
        )

    disconnected = persistence.sessions[session_id]
    assert disconnected.disconnected_at_ms == 1_100
    assert disconnected.reconnect_until_ms == 1_300
    with pytest.raises(InvalidAccessToken):
        await manager.authenticate(token)


@pytest.mark.asyncio
async def test_restart_invalidates_tokens_but_bootstrap_readopts_session() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    random = DeterministicRandom()
    first = await make_manager(persistence, clock, random)
    session_id, bootstrap, old_token = await launch_and_exchange(first)
    assert persistence.sessions[session_id].state is SessionState.ACTIVE

    clock.advance(100)
    second = await make_manager(persistence, clock, random)
    assert second.token_epoch == first.token_epoch + 1
    assert persistence.sessions[session_id].state is SessionState.DISCONNECTED
    with pytest.raises(InvalidAccessToken):
        await second.authenticate(old_token)

    replacement = await second.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )
    assert replacement.principal.token_epoch == second.token_epoch
    assert persistence.sessions[session_id].state is SessionState.ACTIVE
    assert (await second.authenticate(replacement.access_token)).session_id == session_id


@pytest.mark.asyncio
async def test_root_runs_are_server_minted_bound_and_budget_attenuated() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(persistence, clock, DeterministicRandom())
    first_session, _, first_token = await launch_and_exchange(manager, client_id="editor-one")
    _, _, second_token = await launch_and_exchange(manager, client_id="editor-two")

    root_run = await manager.create_root_run(
        access_token=first_token,
        budget={"credits": 25},
    )
    assert root_run.root_run_id.startswith("run_")
    assert root_run.session_id == first_session
    assert (
        await manager.resolve_root_run(
            access_token=first_token,
            root_run_id=root_run.root_run_id,
        )
    ) == root_run
    with pytest.raises(CrossSessionRootRun):
        await manager.resolve_root_run(
            access_token=second_token,
            root_run_id=root_run.root_run_id,
        )
    with pytest.raises(RootRunNotFound):
        await manager.resolve_root_run(
            access_token=first_token,
            root_run_id="run_client_supplied",
        )
    with pytest.raises(ValueError, match="exceeds the session ceiling"):
        await manager.create_root_run(
            access_token=first_token,
            budget={"credits": 101},
        )


@pytest.mark.asyncio
async def test_server_minted_ids_are_valid_and_deterministic_under_injection() -> None:
    first_clock = FakeClock()
    first = await make_manager(
        MemorySessionPersistence(),
        first_clock,
        DeterministicRandom(),
    )
    first_session, _, first_token = await launch_and_exchange(first)
    first_root = await first.create_root_run(access_token=first_token)

    second_clock = FakeClock()
    second = await make_manager(
        MemorySessionPersistence(),
        second_clock,
        DeterministicRandom(),
    )
    second_session, _, second_token = await launch_and_exchange(second)
    second_root = await second.create_root_run(access_token=second_token)

    assert SessionId(first_session) == first_session == second_session
    assert RootRunId(first_root.root_run_id) == first_root.root_run_id
    assert first_root.root_run_id == second_root.root_run_id


def test_session_state_machine_rejects_skips_and_expired_reactivation() -> None:
    record = SessionRecord(
        session_id="ses_one",
        client_id="client",
        workspace_id=None,
        bootstrap_verifier=b"x" * 32,
        bootstrap_version=1,
        token_epoch=1,
        revocation_epoch=0,
        state=SessionState.CREATED,
        identity_assurance="LAUNCHER_SESSION",
        policy_version="v1",
        created_at_ms=0,
        last_seen_at_ms=None,
        disconnected_at_ms=None,
        reconnect_until_ms=100,
        absolute_expires_at_ms=100,
    )
    with pytest.raises(InvalidStateTransition):
        record.transition(SessionState.SUSPENDED, now_ms=1)
    active = record.transition(SessionState.ACTIVE, now_ms=1)
    disconnected = active.transition(
        SessionState.DISCONNECTED,
        now_ms=10,
        reconnect_grace_ms=20,
    )
    with pytest.raises(SessionTransitionConditionError, match="reconnect grace"):
        disconnected.transition(SessionState.ACTIVE, now_ms=31)
    expired = replace(disconnected, state=SessionState.EXPIRED)
    with pytest.raises(InvalidStateTransition):
        expired.transition(SessionState.ACTIVE, now_ms=20)
