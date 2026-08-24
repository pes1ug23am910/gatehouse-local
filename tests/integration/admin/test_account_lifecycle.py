from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from gatehouse.admin.accounts import (
    AccountLifecycleConflict,
    AccountLifecycleFailure,
    AccountRefreshUnavailable,
    SqliteAccountLifecycleService,
)
from gatehouse.admin.models import (
    AccountAddRequest,
    AccountObservationChangeRequest,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    CredentialValidationResult,
)
from gatehouse.credentials import InMemoryKeyStore
from gatehouse.credentials.base import CredentialMetadata, KeyStore, SecretLease
from gatehouse.database import SqliteQuotaStateRepository, open_migrated_database

NOW_MS = 1_900_000_000_000
CANARY = b"FAKE-ACCOUNT-CANARY-NOT-A-REAL-CREDENTIAL-123456"
ROTATED_CANARY = b"FAKE-ROTATED-CANARY-NOT-A-REAL-CREDENTIAL-654321"
IDENTITY_HMAC_KEY = b"I" * 32
TEAM_ID_CANARY = "TEAM-ID-CANARY-NOT-SECRET-7f58b0d6"


class MutableClock:
    def __init__(self, value: int = NOW_MS) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class CoordinatedPutStore(InMemoryKeyStore):
    """Hold the first staged secret until a competing add has also staged."""

    def __init__(self) -> None:
        super().__init__()
        self._put_count = 0
        self._both_staged = asyncio.Event()

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        reference = await super().put(metadata, secret)
        self._put_count += 1
        if self._put_count == 2:
            self._both_staged.set()
        await self._both_staged.wait()
        return reference


def _add_request(
    mutation_id: str = "account-add-mutation-0001",
    *,
    alias: str = "personal-primary",
    pool_alias: str = "personal-firecrawl",
    priority: int = 10,
    provider_team_id: str | None = None,
) -> AccountAddRequest:
    return AccountAddRequest(
        mutation_id=mutation_id,
        provider="firecrawl",
        provider_team_id=provider_team_id or f"team-{alias}",
        alias=alias,
        pool_alias=pool_alias,
        priority=priority,
    )


def _service(
    connection: sqlite3.Connection,
    store: KeyStore,
    clock: Callable[[], int],
    **kwargs: object,
) -> SqliteAccountLifecycleService:
    return SqliteAccountLifecycleService(
        connection,
        persistent_key_store=store,
        provider_identity_hmac_key=IDENTITY_HMAC_KEY,
        now_ms=clock,
        **kwargs,  # type: ignore[arg-type]
    )


def _account_ids(
    connection: sqlite3.Connection,
    alias: str = "personal-primary",
) -> tuple[str, str, int]:
    row = connection.execute(
        """
        SELECT scope.quota_scope_id, credential.credential_id, credential.generation
          FROM principals AS principal
          JOIN quota_scopes AS scope ON scope.principal_id = principal.principal_id
          JOIN credentials AS credential ON credential.quota_scope_id = scope.quota_scope_id
         WHERE principal.alias = ? AND credential.state != 'RETIRED'
         ORDER BY credential.generation DESC LIMIT 1
        """,
        (alias,),
    ).fetchone()
    assert row is not None
    return str(row["quota_scope_id"]), str(row["credential_id"]), int(row["generation"])


def _observe(
    connection: sqlite3.Connection,
    *,
    clock: MutableClock,
    remaining: str,
    plan: str | None = "100",
    ttl_ms: int = 60_000,
) -> None:
    scope_id, credential_id, generation = _account_ids(connection)
    result = SqliteQuotaStateRepository(connection).record_authenticated_observation(
        quota_scope_id=scope_id,
        credential_id=credential_id,
        credential_generation=generation,
        unit="credits",
        exact_remaining=remaining,
        exact_plan_total=plan,
        captured_at_ms=clock.value,
        stale_at_ms=clock.value + ttl_ms,
        source="account-manual-refresh",
        now_ms=clock.value,
    )
    assert result.head_advanced


def _database_text(connection: sqlite3.Connection) -> str:
    values: list[str] = []
    tables = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    )
    for table in tables:
        for row in connection.execute(f'SELECT * FROM "{table}"'):  # noqa: S608
            values.extend(str(value) for value in row if value is not None)
    return "\n".join(values)


async def test_clean_install_add_is_atomic_idempotent_and_secret_free(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    path = tmp_path / "accounts.sqlite3"
    connection = open_migrated_database(path)
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)

    secret = bytearray(CANARY)
    request = _add_request(provider_team_id=TEAM_ID_CANARY)
    result = await service.add_account(request, secret, "local-account-operator")

    assert result.model_dump() == {
        "alias": "personal-primary",
        "action": "add",
        "state": "UNKNOWN",
        "pool_alias": "personal-firecrawl",
        "priority": 10,
        "generation": 1,
        "acted_at_ms": NOW_MS,
        "audit_event_id": result.audit_event_id,
    }
    assert secret == bytearray(len(CANARY))
    principal = connection.execute("SELECT * FROM principals").fetchone()
    scope = connection.execute("SELECT * FROM quota_scopes").fetchone()
    credential = connection.execute("SELECT * FROM credentials").fetchone()
    dimension = connection.execute("SELECT * FROM quota_dimensions").fetchone()
    pool = connection.execute("SELECT * FROM pools").fetchone()
    member = connection.execute("SELECT * FROM pool_members").fetchone()
    schedule = connection.execute("SELECT * FROM quota_observation_schedules").fetchone()
    state_event = connection.execute("SELECT * FROM quota_scope_state_events").fetchone()
    identity = connection.execute("SELECT * FROM provider_quota_scope_identities").fetchone()
    assert principal is not None and principal["identity_kind"] == "ACCOUNT"
    assert scope is not None and scope["scope_kind"] == "TEAM" and scope["state"] == "UNKNOWN"
    assert credential is not None and credential["credential_role"] == "WORKLOAD"
    assert dimension is not None
    assert (
        dimension["name"],
        dimension["native_unit"],
        dimension["counter_kind"],
        dimension["reset_window_kind"],
    ) == (
        "account_credits",
        "credits",
        "BALANCE",
        "PROVIDER",
    )
    assert pool is not None and pool["selection_strategy"] == "fill_first"
    assert member is not None and (member["priority"], member["enabled"]) == (10, 1)
    assert schedule is not None and schedule["state"] == "DISABLED"
    assert state_event is not None
    assert identity is not None
    assert identity["provider_id"] == "firecrawl"
    assert identity["identity_kind"] == "TEAM"
    assert isinstance(identity["identity_fingerprint"], bytes)
    assert len(identity["identity_fingerprint"]) == 32
    expected_fingerprint = hmac.new(
        IDENTITY_HMAC_KEY,
        b"gatehouse:provider-quota-scope-identity:v1\x00firecrawl\x00TEAM\x00"
        + TEAM_ID_CANARY.encode("ascii"),
        hashlib.sha256,
    ).digest()
    assert identity["identity_fingerprint"] == expected_fingerprint
    assert identity["principal_id"] == principal["principal_id"]
    assert identity["quota_scope_id"] == scope["quota_scope_id"]
    assert (
        state_event["generation"],
        state_event["source_kind"],
        state_event["actor_id"],
    ) == (0, "OPERATOR", "local-account-operator")
    assert CANARY.decode() not in _database_text(connection)
    assert TEAM_ID_CANARY not in _database_text(connection)

    journal = connection.execute(
        """
        SELECT actor_id, metadata_json, result_json
          FROM credential_mutations WHERE mutation_id = ?
        """,
        (request.mutation_id,),
    ).fetchone()
    assert journal is not None and journal["actor_id"] == "local-account-operator"
    assert expected_fingerprint.hex() in str(journal["metadata_json"])
    assert expected_fingerprint.hex() not in str(journal["result_json"])
    assert expected_fingerprint.hex() not in str(
        connection.execute("SELECT payload_json FROM audit_events").fetchone()[0]
    )
    assert TEAM_ID_CANARY not in caplog.text
    assert CANARY.decode() not in caplog.text
    assert TEAM_ID_CANARY not in result.model_dump_json()
    assert expected_fingerprint.hex() not in result.model_dump_json()
    connection.close()
    connection = open_migrated_database(path)
    service = _service(connection, store, clock)

    replay_secret = bytearray(CANARY)
    replay = await service.add_account(request, replay_secret, "local-account-operator")
    assert replay == result
    assert replay_secret == bytearray(len(CANARY))
    assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 1
    assert len(await store.list_metadata()) == 1

    wrong_actor_secret = bytearray(CANARY)
    with pytest.raises(AccountLifecycleConflict, match="already bound"):
        await service.add_account(_add_request(), wrong_actor_secret, "different-operator")
    assert wrong_actor_secret == bytearray(len(CANARY))

    mismatched = bytearray(CANARY)
    with pytest.raises(AccountLifecycleConflict, match="already bound"):
        await service.add_account(
            _add_request(pool_alias="different-pool"),
            mismatched,
            "local-account-operator",
        )
    assert mismatched == bytearray(len(CANARY))
    mismatched_identity = bytearray(CANARY)
    with pytest.raises(AccountLifecycleConflict, match="already bound"):
        await service.add_account(
            _add_request(provider_team_id="different-team-id"),
            mismatched_identity,
            "local-account-operator",
        )
    assert mismatched_identity == bytearray(len(CANARY))
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if candidate.exists():
            assert CANARY not in candidate.read_bytes()
            assert TEAM_ID_CANARY.encode() not in candidate.read_bytes()
    connection.close()


async def test_multiple_accounts_share_one_fill_first_pool_with_independent_scopes(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "multi-account.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(
        _add_request(priority=20),
        bytearray(CANARY),
        "operator-test",
    )
    await service.add_account(
        _add_request(
            "account-add-mutation-0002",
            alias="personal-secondary",
            priority=5,
        ),
        bytearray(ROTATED_CANARY),
        "operator-test",
    )

    assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 2
    assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 2
    assert connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 2
    assert connection.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 1
    priorities = tuple(
        int(row[0])
        for row in connection.execute("SELECT priority FROM pool_members ORDER BY priority")
    )
    assert priorities == (5, 20)
    statuses = await service.list_accounts(limit=10)
    assert tuple(status.alias for status in statuses) == (
        "personal-primary",
        "personal-secondary",
    )
    assert all(status.state == "UNKNOWN" for status in statuses)
    assert len(await store.list_metadata()) == 2
    connection.close()


async def test_duplicate_provider_team_is_rejected_without_a_second_scope_or_custody(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "duplicate-team.sqlite3")
    store = InMemoryKeyStore()
    service = _service(connection, store, MutableClock())
    await service.add_account(
        _add_request(provider_team_id="shared-provider-team"),
        bytearray(CANARY),
        "operator-test",
    )

    rejected_secret = bytearray(ROTATED_CANARY)
    with pytest.raises(AccountLifecycleConflict, match="already onboarded"):
        await service.add_account(
            _add_request(
                "account-add-duplicate-team-0002",
                alias="duplicate-team-alias",
                provider_team_id="shared-provider-team",
            ),
            rejected_secret,
            "operator-test",
        )

    assert rejected_secret == bytearray(len(ROTATED_CANARY))
    assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 1
    assert (
        connection.execute("SELECT COUNT(*) FROM provider_quota_scope_identities").fetchone()[0]
        == 1
    )
    assert len(await store.list_metadata()) == 1
    connection.close()


async def test_concurrent_duplicate_provider_team_commits_at_most_one_scope_and_cleans_loser(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "concurrent-duplicate-team.sqlite3")
    store = CoordinatedPutStore()
    service = _service(connection, store, MutableClock())
    first_secret = bytearray(CANARY)
    second_secret = bytearray(ROTATED_CANARY)

    outcomes = await asyncio.gather(
        service.add_account(
            _add_request(
                "account-add-concurrent-team-0001",
                alias="concurrent-primary",
                provider_team_id="concurrent-shared-team",
            ),
            first_secret,
            "operator-test",
        ),
        service.add_account(
            _add_request(
                "account-add-concurrent-team-0002",
                alias="concurrent-secondary",
                provider_team_id="concurrent-shared-team",
            ),
            second_secret,
            "operator-test",
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(outcome, BaseException) for outcome in outcomes) == 1
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    assert len(conflicts) == 1 and isinstance(conflicts[0], AccountLifecycleConflict)
    assert first_secret == bytearray(len(CANARY))
    assert second_secret == bytearray(len(ROTATED_CANARY))
    assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 1
    assert (
        connection.execute("SELECT COUNT(*) FROM provider_quota_scope_identities").fetchone()[0]
        == 1
    )
    assert len(await store.list_metadata()) == 1
    journal_states = sorted(
        str(row[0])
        for row in connection.execute("SELECT state FROM credential_mutations ORDER BY mutation_id")
    )
    assert journal_states == ["COMMITTED", "ROLLED_BACK"]
    connection.close()


async def test_status_is_exact_redacted_and_stale_information_is_unknown(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "status.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")

    unobserved = await service.get_account_status("personal-primary")
    assert unobserved is not None
    assert unobserved.model_dump() == {
        "alias": "personal-primary",
        "state": "UNKNOWN",
        "remaining_decimal": None,
        "plan_decimal": None,
        "unit": "credits",
        "observed_at_ms": None,
        "staleness_ms": None,
        "stale": True,
        "source": None,
    }

    _observe(connection, clock=clock, remaining="12.34", plan="-20.125")
    fresh = await service.get_account_status("personal-primary")
    assert fresh is not None
    assert fresh.state == "HEALTHY"
    assert fresh.remaining_decimal == "12.34"
    assert fresh.plan_decimal == "-20.125"
    assert fresh.observed_at_ms == NOW_MS
    assert fresh.staleness_ms == 0
    assert not fresh.stale
    assert fresh.source == "account-manual-refresh"
    assert set(fresh.model_dump()) == {
        "alias",
        "state",
        "remaining_decimal",
        "plan_decimal",
        "unit",
        "observed_at_ms",
        "staleness_ms",
        "stale",
        "source",
    }

    clock.value += 60_001
    stale = await service.get_account_status("personal-primary")
    assert stale is not None
    assert stale.state == "UNKNOWN"
    assert stale.remaining_decimal == "12.34"
    assert stale.stale
    assert stale.staleness_ms == 60_001
    connection.close()


async def test_exhaustion_survives_restart_and_rotation(tmp_path: Path) -> None:
    path = tmp_path / "restart.sqlite3"
    connection = open_migrated_database(path)
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    _observe(connection, clock=clock, remaining="0")
    exhausted = await service.get_account_status("personal-primary")
    assert exhausted is not None and exhausted.state == "EXHAUSTED"
    connection.close()

    restarted_connection = open_migrated_database(path)
    restarted = _service(restarted_connection, store, clock)
    after_restart = await restarted.get_account_status("personal-primary")
    assert after_restart is not None and after_restart.state == "EXHAUSTED"

    rotation = await restarted.rotate_account(
        "personal-primary",
        AccountRotationRequest(mutation_id="account-rotate-mutation-0001"),
        bytearray(ROTATED_CANARY),
        "operator-test",
    )
    assert rotation.state == "EXHAUSTED"
    assert rotation.generation == 2
    rotated_status = await restarted.get_account_status("personal-primary")
    assert rotated_status is not None and rotated_status.state == "EXHAUSTED"
    schedule = restarted_connection.execute(
        """
        SELECT observer_credential_id, observer_credential_generation
          FROM quota_observation_schedules
        """
    ).fetchone()
    assert schedule is not None and schedule["observer_credential_generation"] == 2

    replay = await restarted.rotate_account(
        "personal-primary",
        AccountRotationRequest(mutation_id="account-rotate-mutation-0001"),
        bytearray(ROTATED_CANARY),
        "operator-test",
    )
    assert replay == rotation
    assert len(await store.list_metadata()) == 2
    restarted_connection.close()


async def test_restart_repairs_committed_rotation_schedule_without_changing_opt_in(
    tmp_path: Path,
) -> None:
    path = tmp_path / "rotation-repair.sqlite3"
    connection = open_migrated_database(path)
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    _, old_credential_id, old_generation = _account_ids(connection)
    await service.change_account_observation(
        "personal-primary",
        AccountObservationChangeRequest(
            mutation_id="account-observe-before-rotation-0001",
            action="enable",
            reason="operator enabled observation",
        ),
        "operator-test",
    )
    await service.rotate_account(
        "personal-primary",
        AccountRotationRequest(mutation_id="account-rotate-for-repair-0001"),
        bytearray(ROTATED_CANARY),
        "operator-test",
    )
    _, current_credential_id, current_generation = _account_ids(connection)
    assert current_credential_id != old_credential_id

    # This is the durable image of a crash after the credential mutation commit
    # and before the account wrapper's observer-generation rebind.
    connection.execute(
        """
        UPDATE quota_observation_schedules
           SET observer_credential_id = ?, observer_credential_generation = ?
        """,
        (old_credential_id, old_generation),
    )
    connection.close()

    restarted_connection = open_migrated_database(path)
    restarted = _service(restarted_connection, store, clock)
    assert await restarted.recover_incomplete_account_mutations() == 1
    schedule = restarted_connection.execute(
        """
        SELECT observer_credential_id, observer_credential_generation, state
          FROM quota_observation_schedules
        """
    ).fetchone()
    assert schedule is not None
    assert schedule["observer_credential_id"] == current_credential_id
    assert schedule["observer_credential_generation"] == current_generation
    assert schedule["state"] == "ENABLED"
    assert await restarted.recover_incomplete_account_mutations() == 0
    restarted_connection.close()


async def test_restart_finishes_durable_disable_after_final_journal_crash(tmp_path: Path) -> None:
    path = tmp_path / "disable-recovery.sqlite3"
    connection = open_migrated_database(path)
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    connection.execute(
        """
        CREATE TRIGGER simulate_account_disable_commit_crash
        BEFORE UPDATE OF state ON credential_mutations
        WHEN OLD.operation = 'account.disabled' AND NEW.state = 'COMMITTED'
        BEGIN
            SELECT RAISE(ABORT, 'simulated account commit crash');
        END
        """
    )
    with pytest.raises(sqlite3.IntegrityError, match="simulated account commit crash"):
        await service.change_account_state(
            "personal-primary",
            AccountStateChangeRequest(
                mutation_id="account-disable-crash-mutation-0001",
                action="disable",
                reason="operator maintenance",
            ),
            "operator-test",
        )
    assert connection.execute("SELECT state FROM quota_scopes").fetchone()[0] == "DISABLED"
    assert connection.execute("SELECT enabled FROM pool_members").fetchone()[0] == 1
    journal = connection.execute(
        """
        SELECT state FROM credential_mutations
         WHERE mutation_id = 'account-disable-crash-mutation-0001'
        """
    ).fetchone()
    assert journal is not None and journal["state"] == "ACCOUNT_STATE_PREPARED"
    connection.execute("DROP TRIGGER simulate_account_disable_commit_crash")
    connection.close()

    restarted_connection = open_migrated_database(path)
    restarted = _service(restarted_connection, store, clock)
    assert await restarted.recover_incomplete_account_mutations() == 1
    assert restarted_connection.execute("SELECT enabled FROM pool_members").fetchone()[0] == 0
    completed = restarted_connection.execute(
        """
        SELECT state FROM credential_mutations
         WHERE mutation_id = 'account-disable-crash-mutation-0001'
        """
    ).fetchone()
    assert completed is not None and completed["state"] == "COMMITTED"
    status = await restarted.get_account_status("personal-primary")
    assert status is not None and status.state == "DISABLED"
    restarted_connection.close()


async def test_disable_recover_and_observation_toggle_remain_separately_gated(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "state.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    _observe(connection, clock=clock, remaining="10")

    enabled = await service.change_account_observation(
        "personal-primary",
        AccountObservationChangeRequest(
            mutation_id="account-observe-enable-0001",
            action="enable",
            reason="operator opted in to scheduling",
        ),
        "operator-test",
    )
    assert enabled.enabled
    assert (
        connection.execute("SELECT state FROM quota_observation_schedules").fetchone()[0]
        == "ENABLED"
    )

    disabled = await service.change_account_state(
        "personal-primary",
        AccountStateChangeRequest(
            mutation_id="account-disable-mutation-0001",
            action="disable",
            reason="operator maintenance",
        ),
        "operator-test",
    )
    assert disabled.state == "DISABLED"
    assert connection.execute("SELECT enabled FROM pool_members").fetchone()[0] == 0
    assert (
        connection.execute("SELECT state FROM quota_observation_schedules").fetchone()[0]
        == "DISABLED"
    )

    clock.value += 60_001
    recovered = await service.change_account_state(
        "personal-primary",
        AccountStateChangeRequest(
            mutation_id="account-recover-mutation-0001",
            action="recover",
            reason="operator recovery",
        ),
        "operator-test",
    )
    assert recovered.state == "UNKNOWN"
    assert connection.execute("SELECT enabled FROM pool_members").fetchone()[0] == 1
    assert (
        connection.execute("SELECT state FROM quota_observation_schedules").fetchone()[0]
        == "DISABLED"
    )
    assert (
        await service.change_account_state(
            "personal-primary",
            AccountStateChangeRequest(
                mutation_id="account-recover-mutation-0001",
                action="recover",
                reason="operator recovery",
            ),
            "operator-test",
        )
        == recovered
    )
    connection.close()


class RecordingCollector:
    def __init__(self, connection: sqlite3.Connection, clock: MutableClock) -> None:
        self.connection = connection
        self.clock = clock
        self.calls = 0

    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        self.calls += 1
        row = self.connection.execute(
            "SELECT principal_id, quota_scope_id FROM credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()
        assert row is not None
        snapshot_id = f"refresh-snapshot-{self.calls}"
        SqliteQuotaStateRepository(self.connection).record_authenticated_observation(
            quota_scope_id=str(row["quota_scope_id"]),
            credential_id=credential_id,
            credential_generation=expected_generation,
            unit="credits",
            exact_remaining="9.75",
            exact_plan_total="25",
            captured_at_ms=self.clock.value,
            stale_at_ms=self.clock.value + freshness_ttl_ms,
            source=source,
            now_ms=self.clock.value,
            snapshot_id=snapshot_id,
        )
        return CredentialValidationResult(
            credential_id=credential_id,
            generation=expected_generation,
            service="firecrawl",
            principal_id=str(row["principal_id"]),
            quota_scope_id=str(row["quota_scope_id"]),
            state="authenticated",
            snapshot_id=snapshot_id,
            unit="credits",
            remaining_units=9,
            plan_total_units=25,
            observed_remaining_units_decimal="9.75",
            observed_plan_total_units_decimal="25",
            captured_at_ms=self.clock.value,
            audit_event_id=f"refresh-audit-{self.calls}",
        )


async def test_refresh_is_default_disabled_bounded_redacted_and_idempotent(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "refresh.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    collector = RecordingCollector(connection, clock)
    disabled_service = _service(
        connection,
        store,
        clock,
        observation_collector=collector,
        manual_refresh_enabled=False,
    )
    await disabled_service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    with pytest.raises(AccountRefreshUnavailable, match="disabled"):
        await disabled_service.refresh_account(
            "personal-primary",
            AccountRefreshRequest(mutation_id="account-refresh-disabled-0001"),
            "operator-test",
        )
    assert collector.calls == 0

    enabled_service = _service(
        connection,
        store,
        clock,
        observation_collector=collector,
        manual_refresh_enabled=True,
    )
    request = AccountRefreshRequest(mutation_id="account-refresh-mutation-0001")
    result = await enabled_service.refresh_account("personal-primary", request, "operator-test")
    assert result.remaining_decimal == "9.75"
    assert result.plan_decimal == "25"
    assert result.source == "account-manual-refresh"
    assert collector.calls == 1
    assert (
        await enabled_service.refresh_account("personal-primary", request, "operator-test")
        == result
    )
    assert collector.calls == 1
    connection.close()


class ProviderCanaryFailureCollector:
    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        raise RuntimeError(CANARY.decode())


async def test_refresh_scrubs_provider_errors_and_never_persists_canary(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "refresh-error.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(
        connection,
        store,
        clock,
        observation_collector=ProviderCanaryFailureCollector(),
        manual_refresh_enabled=True,
    )
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    with pytest.raises(AccountLifecycleFailure) as raised:
        await service.refresh_account(
            "personal-primary",
            AccountRefreshRequest(mutation_id="account-refresh-failure-0001"),
            "operator-test",
        )
    assert CANARY.decode() not in str(raised.value)
    assert CANARY.decode() not in _database_text(connection)
    connection.close()


class SimulatedCrash(BaseException):
    pass


class CrashAfterCustodyStore:
    def __init__(self, delegate: InMemoryKeyStore) -> None:
        self.delegate = delegate

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        return await self.delegate.put(metadata, secret)

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        raise SimulatedCrash

    async def discard_partial(self, credential_id: str) -> bool:
        return await self.delegate.discard_partial(credential_id)

    async def discard_staged(self, credential_id: str, *, staged_alias: str) -> bool:
        return await self.delegate.discard_staged(credential_id, staged_alias=staged_alias)

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        expected_generation: int | None = None,
        ttl_seconds: float | None = None,
    ) -> SecretLease:
        return await self.delegate.open_lease(
            credential_id,
            purpose,
            expected_generation=expected_generation,
            ttl_seconds=ttl_seconds,
        )

    async def disable(self, credential_id: str) -> None:
        await self.delegate.disable(credential_id)

    async def delete(self, credential_id: str) -> None:
        await self.delegate.delete(credential_id)

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        return await self.delegate.list_metadata()


async def test_restart_recovery_deletes_only_owned_staged_custody(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "crash.sqlite3")
    delegate = InMemoryKeyStore()
    crashing = CrashAfterCustodyStore(delegate)
    clock = MutableClock()
    service = _service(connection, crashing, clock)
    secret = bytearray(CANARY)
    with pytest.raises(SimulatedCrash):
        await service.add_account(_add_request(), secret, "operator-test")
    assert secret == bytearray(len(CANARY))
    assert len(await delegate.list_metadata()) == 1
    journal = connection.execute("SELECT state FROM credential_mutations").fetchone()
    assert journal is not None and journal["state"] == "ACCOUNT_CUSTODY_CREATED"
    assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 0

    restarted = _service(connection, delegate, clock)
    assert await restarted.recover_incomplete_account_mutations() == 1
    assert await delegate.list_metadata() == ()
    assert (
        connection.execute("SELECT state FROM credential_mutations").fetchone()[0] == "ROLLED_BACK"
    )
    connection.close()


async def test_custody_collision_recovery_never_deletes_unowned_entry(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "custody-collision.sqlite3")
    store = InMemoryKeyStore()
    collision_id = "credential-collision-owned-elsewhere"
    await store.put(
        CredentialMetadata(
            credential_id=collision_id,
            principal_id="unrelated-principal",
            quota_scope_id="unrelated-scope",
            alias="unrelated-alias",
        ),
        b"FAKE-UNRELATED-CUSTODY-NOT-A-REAL-CREDENTIAL-123456",
    )
    clock = MutableClock()
    service = SqliteAccountLifecycleService(
        connection,
        persistent_key_store=store,
        provider_identity_hmac_key=IDENTITY_HMAC_KEY,
        now_ms=clock,
        credential_id_factory=lambda: collision_id,
    )
    secret = bytearray(CANARY)
    with pytest.raises(AccountLifecycleConflict, match="custody identifier"):
        await service.add_account(_add_request(), secret, "operator-test")
    assert secret == bytearray(len(CANARY))
    assert await service.recover_incomplete_account_mutations() == 0
    metadata = await store.list_metadata()
    assert len(metadata) == 1
    assert metadata[0].credential_id == collision_id
    assert metadata[0].alias == "unrelated-alias"
    connection.close()


async def test_remove_is_tombstone_with_active_work_fencing(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "remove.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    scope_id, credential_id, _ = _account_ids(connection)
    connection.execute(
        """
        INSERT INTO leases(
            lease_id, lease_type, lease_key, owner_id, state, generation,
            acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
        ) VALUES ('lease-account-active-0001', 'provider-credential', ?, 'test-owner',
                  'ACTIVE', 1, ?, ?, ?, ?)
        """,
        (
            credential_id,
            NOW_MS,
            NOW_MS,
            NOW_MS + 60_000,
            '{"credential_id":"' + credential_id + '"}',
        ),
    )
    request = AccountStateChangeRequest(
        mutation_id="account-remove-mutation-0001",
        action="remove",
        reason="operator confirmed removal",
    )
    with pytest.raises(AccountLifecycleConflict, match="active work"):
        await service.change_account_state("personal-primary", request, "operator-test")
    connection.execute(
        """
        UPDATE leases SET state = 'RELEASED', released_at_ms = ?
         WHERE lease_id = 'lease-account-active-0001'
        """,
        (NOW_MS,),
    )

    removed = await service.change_account_state("personal-primary", request, "operator-test")
    assert removed.state == "DISABLED"
    assert await service.get_account_status("personal-primary") is None
    assert connection.execute("SELECT enabled FROM principals").fetchone()[0] == 0
    assert connection.execute("SELECT state FROM quota_scopes").fetchone()[0] == "DISABLED"
    assert connection.execute("SELECT state FROM credentials").fetchone()[0] == "RETIRED"
    assert connection.execute("SELECT COUNT(*) FROM quota_scope_state_events").fetchone()[0] >= 2
    assert connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 1
    identity = connection.execute(
        "SELECT provider_identity_id FROM provider_quota_scope_identities"
    ).fetchone()
    assert identity is not None
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE provider_quota_scope_identities SET metadata_json = '{\"changed\":true}'"
        )
    with pytest.raises(sqlite3.IntegrityError, match="retained"):
        connection.execute("DELETE FROM provider_quota_scope_identities")
    assert await store.list_metadata() == ()
    assert scope_id in _database_text(connection)

    replacement_secret = bytearray(ROTATED_CANARY)
    with pytest.raises(AccountLifecycleConflict, match="already onboarded"):
        await service.add_account(
            _add_request(
                "account-add-after-tombstone-0001",
                alias="replacement-alias",
                provider_team_id="team-personal-primary",
            ),
            replacement_secret,
            "operator-test",
        )
    assert replacement_secret == bytearray(len(ROTATED_CANARY))
    assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 1
    assert (
        connection.execute("SELECT COUNT(*) FROM provider_quota_scope_identities").fetchone()[0]
        == 1
    )
    connection.close()


async def test_second_account_recovery_pass_finishes_nested_retirement_journal(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "remove-recovery.sqlite3")
    store = InMemoryKeyStore()
    clock = MutableClock()
    service = _service(connection, store, clock)
    await service.add_account(_add_request(), bytearray(CANARY), "operator-test")
    _, credential_id, _ = _account_ids(connection)
    account_mutation_id = "account-remove-recovery-mutation-0001"
    retire_digest = hashlib.sha256()
    retire_digest.update(b"gatehouse:account-remove-retire:v1\x00")
    retire_digest.update(account_mutation_id.encode())
    retire_digest.update(b"\x00")
    retire_digest.update(credential_id.encode())
    retire_mutation_id = f"account-retire-{retire_digest.hexdigest()}"
    reason_digest = hashlib.sha256()
    reason_digest.update(b"gatehouse:credential-state-reason:v1\x00")
    reason_digest.update(b"account removal")
    connection.execute(
        """
        INSERT INTO credential_mutations(
            mutation_id, operation, state, actor_id, created_at_ms,
            updated_at_ms, metadata_json
        ) VALUES (?, 'account.removed', 'ACCOUNT_STATE_PREPARED',
                  'operator-test', ?, ?, ?)
        """,
        (
            account_mutation_id,
            NOW_MS,
            NOW_MS,
            json.dumps(
                {
                    "action": "remove",
                    "alias": "personal-primary",
                    "reason_fingerprint": "opaque-account-reason-fingerprint",
                    "audit_event_id": "account-remove-recovery-audit",
                    "state_event_id": "account-remove-recovery-state",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        ),
    )
    connection.execute(
        """
        INSERT INTO credential_mutations(
            mutation_id, operation, credential_id, state, actor_id,
            created_at_ms, updated_at_ms, metadata_json
        ) VALUES (?, 'credential.retired', ?, 'PREPARED', 'operator-test', ?, ?, ?)
        """,
        (
            retire_mutation_id,
            credential_id,
            NOW_MS,
            NOW_MS,
            json.dumps(
                {
                    "action": "retire",
                    "credential_id": credential_id,
                    "reason_fingerprint": reason_digest.hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        ),
    )

    assert await service.recover_incomplete_account_mutations() == 0
    assert await service.recover_incomplete_mutations() >= 1
    assert await service.recover_incomplete_account_mutations() == 1
    assert await service.get_account_status("personal-primary") is None
    assert connection.execute("SELECT enabled FROM principals").fetchone()[0] == 0
    assert connection.execute("SELECT state FROM credentials").fetchone()[0] == "RETIRED"
    assert await store.list_metadata() == ()
    connection.close()


class YieldingStore(InMemoryKeyStore):
    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        result = await super().put(metadata, secret)
        await asyncio.sleep(0)
        return result


async def test_concurrent_same_alias_add_has_one_winner_and_no_custody_spray(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent.sqlite3"
    first_connection = open_migrated_database(path)
    second_connection = open_migrated_database(path)
    store = YieldingStore()
    clock = MutableClock()
    first = _service(first_connection, store, clock)
    second = _service(second_connection, store, clock)

    outcomes = await asyncio.gather(
        first.add_account(
            _add_request("account-concurrent-mutation-0001"),
            bytearray(CANARY),
            "operator-one",
        ),
        second.add_account(
            _add_request("account-concurrent-mutation-0002"),
            bytearray(ROTATED_CANARY),
            "operator-two",
        ),
        return_exceptions=True,
    )
    assert sum(not isinstance(outcome, BaseException) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, AccountLifecycleConflict) for outcome in outcomes) == 1
    assert first_connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 1
    assert first_connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 1
    assert len(await store.list_metadata()) == 1
    first_connection.close()
    second_connection.close()
