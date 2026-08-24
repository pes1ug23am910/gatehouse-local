from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import replace

import pytest

from gatehouse.core.ids import RootRunId, SessionId
from gatehouse.core.states import InvalidStateTransition
from gatehouse.sessions import (
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
) -> SessionManager:
    return await SessionManager.start(
        persistence=persistence,
        verifier_key=b"v" * 32,
        now_ms=clock,
        random_bytes=random,
        access_token_ttl_ms=token_ttl_ms,
        reconnect_grace_ms=reconnect_grace_ms,
        stale_after_ms=stale_after_ms,
        maximum_access_tokens=16,
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
async def test_access_token_expires_and_revocation_invalidates_it() -> None:
    persistence = MemorySessionPersistence()
    clock = FakeClock()
    manager = await make_manager(persistence, clock, DeterministicRandom())
    session_id, bootstrap, token = await launch_and_exchange(manager)

    principal = await manager.authenticate(token)
    assert principal.session_id == session_id
    await manager.revoke(session_id)
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
