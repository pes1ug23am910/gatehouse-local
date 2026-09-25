"""Durable send evidence for synthetic credit observations and account refreshes."""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from contextlib import closing
from typing import Literal

import pytest

from gatehouse.admin.accounts import (
    AccountLifecycleConflict,
    AccountLifecycleFailure,
    SqliteAccountLifecycleService,
)
from gatehouse.admin.models import AccountRefreshRequest
from gatehouse.admin.provider_validation import (
    CredentialValidationPersistenceError,
    CredentialValidationProviderFailure,
    CredentialValidationUnavailable,
    SqliteCredentialValidationService,
)
from gatehouse.credentials import CredentialMetadata, InMemoryKeyStore, SecretScanner
from gatehouse.database import open_migrated_database
from gatehouse.database.observation_intents import (
    ObservationIntentConflict,
    SqliteObservationIntentStore,
)
from gatehouse.providers.base import ProviderRequest, ProviderResponse

NOW = 1_900_000_000_000
SOURCE = "account-manual-refresh"
SCHEDULED = "scheduled-firecrawl-credit-observation"
CREDENTIAL = "credential_observation_test"
PRIVATE = "synthetic-private-observation-detail-812793"


async def _custody(connection: sqlite3.Connection) -> InMemoryKeyStore:
    reference = "dpapi-current-user://" + hashlib.sha256(CREDENTIAL.encode()).hexdigest()
    connection.execute(
        "INSERT INTO principals(principal_id, service_id, alias, identity_kind, "
        "created_at_ms, updated_at_ms) VALUES ('principal_observation', 'firecrawl', "
        "'test-account', 'ACCOUNT', ?, ?)",
        (NOW, NOW),
    )
    connection.execute(
        "INSERT INTO quota_scopes(quota_scope_id, principal_id, alias, scope_kind, state, unit) "
        "VALUES ('quota_observation', 'principal_observation', 'test-scope', 'TEAM', "
        "'UNKNOWN', 'credits')",
    )
    connection.execute(
        "INSERT INTO credentials(credential_id, principal_id, quota_scope_id, alias, "
        "secret_backend, secret_reference, state, generation, created_at_ms) "
        "VALUES (?, 'principal_observation', 'quota_observation', 'test-credential', "
        "'dpapi-current-user', ?, 'HEALTHY', 7, ?)",
        (CREDENTIAL, reference, NOW),
    )
    connection.execute(
        "INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy) "
        "VALUES ('pool_observation', 'firecrawl', 'test-pool', 'ACTIVE', 'priority')",
    )
    connection.execute(
        "INSERT INTO pool_members(pool_id, quota_scope_id, priority) "
        "VALUES ('pool_observation', 'quota_observation', 1)",
    )
    store = InMemoryKeyStore()
    await store.put(
        CredentialMetadata(
            credential_id=CREDENTIAL,
            principal_id="principal_observation",
            quota_scope_id="quota_observation",
            alias="test-credential",
            state="HEALTHY",
            generation=7,
            secret_reference=reference,
        ),
        b"synthetic-custody-only",
    )
    return store


class _Transport:
    def __init__(self, connection: sqlite3.Connection, *, failure: str | None = None) -> None:
        self.connection = connection
        self.failure = failure
        self.calls = 0
        self.started = asyncio.Event()

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        assert not self.connection.in_transaction
        rows = self.connection.execute(
            "SELECT * FROM provider_observation_intents WHERE state = 'SEND_INTENT'",
        ).fetchall()
        assert rows and rows[-1]["credential_id"] == request.credential_id
        assert rows[-1]["credential_generation"] == request.credential_generation
        self.calls += 1
        self.started.set()
        if self.failure == "cancel":
            await asyncio.Event().wait()
        if self.failure == "transport":
            raise RuntimeError(PRIVATE)
        if self.failure == "timeout":
            raise TimeoutError(PRIVATE)
        if self.failure == "unauthorized":
            return ProviderResponse(status_code=401, data={"error": PRIVATE})
        if self.failure == "malformed":
            return ProviderResponse(status_code=200, data={"unexpected": PRIVATE})
        return ProviderResponse(
            status_code=200,
            data={
                "success": True,
                "data": {"remainingCredits": 41, "planCredits": 100},
                "private": PRIVATE,
            },
        )


def _collector(
    connection: sqlite3.Connection,
    custody: InMemoryKeyStore,
    transport: _Transport,
    *,
    intents: SqliteObservationIntentStore | None = None,
) -> SqliteCredentialValidationService:
    return SqliteCredentialValidationService(
        connection,
        transport=transport,
        persistent_key_store=custody,
        provider_mode="live",
        network_enabled=True,
        now_ms=lambda: NOW,
        scanner=SecretScanner(canaries=(PRIVATE,)),
        intent_store=intents,
    )


async def _observe(
    service: SqliteCredentialValidationService,
    *,
    request_id: str = "request-one",
    source: str = SOURCE,
    actor_id: str = "operator-test",
    generation: int = 7,
) -> object:
    return await service.observe_credential(
        CREDENTIAL,
        expected_generation=generation,
        actor_id=actor_id,
        source=source,
        freshness_ttl_ms=60_000,
        request_id=request_id,
    )


def _row(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM provider_observation_intents ORDER BY ordinal DESC LIMIT 1",
    ).fetchone()
    assert isinstance(row, sqlite3.Row)
    return row


async def test_send_has_committed_exact_intent_and_success_links_sanitized_evidence() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        service = _collector(connection, custody, transport)
        await _observe(service)
        row = _row(connection)
        assert row["state"] == "SUCCEEDED" and row["source"] == SOURCE
        assert row["actor_id"] == "operator-test" and row["credential_generation"] == 7
        assert row["operation"] == "firecrawl.account.credit_status"
        assert row["snapshot_id"] and row["audit_event_id"]
        assert len(row["request_digest"]) == 64
        text = " ".join(str(value) for value in row)
        assert PRIVATE not in text and "request-one" not in text and "dpapi" not in text
        assert transport.calls == 1
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(service)
        assert transport.calls == 1


@pytest.mark.parametrize("failure", ["transport", "timeout", "malformed", "cancel"])
async def test_ambiguous_exchange_blocks_automatic_dispatch(failure: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection, failure=failure)
        service = _collector(connection, custody, transport)
        if failure == "cancel":
            task = asyncio.create_task(_observe(service))
            await asyncio.wait_for(transport.started.wait(), timeout=1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(
                (
                    CredentialValidationUnavailable,
                    CredentialValidationProviderFailure,
                )
            ):
                await _observe(service)
        assert _row(connection)["state"] == "UNKNOWN"
        assert PRIVATE not in " ".join(str(value) for value in _row(connection))
        restarted = _collector(connection, custody, transport)
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(restarted, request_id="next-scheduled", source=SCHEDULED)
        assert transport.calls == 1


async def test_definitive_failure_is_distinct_from_unknown_and_does_not_replay_request() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection, failure="unauthorized")
        service = _collector(connection, custody, transport)
        with pytest.raises(CredentialValidationProviderFailure):
            await _observe(service)
        assert _row(connection)["state"] == "FAILED"
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(service)
        assert transport.calls == 1


@pytest.mark.parametrize("window", ["intent", "terminal"])
async def test_commit_refusal_never_creates_a_replayable_send(window: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        event = "INSERT" if window == "intent" else "UPDATE"
        condition = "1" if window == "intent" else "NEW.state = 'SUCCEEDED'"
        connection.execute(
            f"CREATE TRIGGER refuse_intent BEFORE {event} ON provider_observation_intents "
            f"WHEN {condition} BEGIN SELECT RAISE(ABORT, 'synthetic refusal'); END",  # noqa: S608
        )
        service = _collector(connection, custody, transport)
        with pytest.raises(CredentialValidationPersistenceError):
            await _observe(service)
        assert transport.calls == (0 if window == "intent" else 1)
        if window == "terminal":
            assert _row(connection)["state"] == "UNKNOWN"
            with pytest.raises(CredentialValidationUnavailable):
                await _observe(service)
            assert transport.calls == 1


async def test_pending_crash_requires_explicit_fresh_success_and_retains_unknown() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        intents = SqliteObservationIntentStore(connection)
        intent = intents.begin(
            intent_id="interrupted-intent",
            request_id="interrupted-request",
            credential_id=CREDENTIAL,
            credential_generation=7,
            principal_id="principal_observation",
            quota_scope_id="quota_observation",
            actor_id="operator-test",
            source=SOURCE,
            now_ms=NOW,
        )
        assert intent.state == "SEND_INTENT" and intents.has_unresolved(CREDENTIAL, 7)
        transport = _Transport(connection)
        service = _collector(connection, custody, transport)
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(service, source=SCHEDULED)
        assert transport.calls == 0
        await _observe(service, request_id="explicit-fresh-read")
        old = connection.execute(
            "SELECT state, resolved_by_intent_id FROM provider_observation_intents "
            "WHERE intent_id = 'interrupted-intent'",
        ).fetchone()
        assert old is not None and old["state"] == "UNKNOWN" and old["resolved_by_intent_id"]
        assert not intents.has_unresolved(CREDENTIAL, 7)
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(service, request_id="interrupted-request")
        assert transport.calls == 1


@pytest.mark.parametrize("mutation", ["actor", "generation", "source"])
async def test_intent_authority_cannot_be_rebound(mutation: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        service = _collector(connection, custody, transport)
        await _observe(service)
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(
                service,
                actor_id="different-actor" if mutation == "actor" else "operator-test",
                generation=8 if mutation == "generation" else 7,
                source=SCHEDULED if mutation == "source" else SOURCE,
            )
        assert transport.calls == 1


async def test_intent_capacity_is_finite_without_eviction_or_provider_dispatch() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        connection.execute(
            "INSERT INTO sqlite_sequence(name, seq) "
            "VALUES ('provider_observation_intents', 100000)",
        )
        transport = _Transport(connection)
        with pytest.raises(CredentialValidationPersistenceError):
            await _observe(_collector(connection, custody, transport))
        assert transport.calls == 0


@pytest.mark.parametrize("binding", ["actor", "generation", "source", "request"])
async def test_existing_success_evidence_cannot_settle_a_different_intent(binding: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        await _observe(_collector(connection, custody, _Transport(connection)))
        completed = _row(connection)
        store = SqliteObservationIntentStore(connection)
        if binding == "generation":
            connection.execute("UPDATE credentials SET generation = 8")
        intent = store.begin(
            intent_id="different-intent",
            request_id="different-request",
            credential_id=CREDENTIAL,
            credential_generation=8 if binding == "generation" else 7,
            principal_id="principal_observation",
            quota_scope_id="quota_observation",
            actor_id="other-actor" if binding == "actor" else "operator-test",
            source="admin-credential-validation" if binding == "source" else SOURCE,
            now_ms=NOW,
        )
        with pytest.raises(ObservationIntentConflict):
            store.succeed(
                intent.intent_id,
                snapshot_id=completed["snapshot_id"],
                audit_event_id=completed["audit_event_id"],
                now_ms=NOW,
            )
        assert _row(connection)["state"] == "SEND_INTENT"


@pytest.mark.parametrize("interruption", [asyncio.CancelledError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_failure", [RuntimeError, KeyboardInterrupt, SystemExit])
async def test_primary_interruption_survives_lease_release_failure(
    interruption: type[BaseException],
    cleanup_failure: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        service = _collector(connection, custody, transport)

        async def interrupted(**kwargs: object) -> object:
            del kwargs
            raise interruption

        def release_failure(**kwargs: object) -> bool:
            del kwargs
            raise cleanup_failure(PRIVATE)

        monkeypatch.setattr(service, "_send_and_record", interrupted)
        monkeypatch.setattr(service._repository, "release_lease", release_failure)
        with pytest.raises(interruption) as failure:
            await _observe(service)
        assert PRIVATE not in str(failure.value)
        assert failure.value.__context__ is None
        assert failure.value.__notes__ == ["credential validation lease release failed"]
        assert _row(connection)["state"] == "UNKNOWN"


@pytest.mark.parametrize(
    "field,value",
    [
        ("intent_id", "é" * 81),
        ("actor_id", "é" * 81),
        ("credential_generation", 7.5),
        ("created_at_ms", NOW + 0.5),
        ("request_digest", "a" * 64 + "\x00"),
        ("request_digest", "a" * 64 + "\x00" + "x" * 100_000),
    ],
    ids=[
        "intent-bytes",
        "actor-bytes",
        "generation-fraction",
        "timestamp-fraction",
        "digest-nul",
        "digest-hidden-large-tail",
    ],
)
async def test_sql_rejects_unbounded_or_noninteger_intent_facts(field: str, value: object) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        await _custody(connection)
        SqliteObservationIntentStore(connection).begin(
            intent_id="valid-intent",
            request_id="valid-request",
            credential_id=CREDENTIAL,
            credential_generation=7,
            principal_id="principal_observation",
            quota_scope_id="quota_observation",
            actor_id="operator-test",
            source=SOURCE,
            now_ms=NOW,
        )
        values = dict(_row(connection))
        values.pop("ordinal")
        values.update(intent_id="new-intent", request_digest="b" * 64)
        values[field] = value
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO provider_observation_intents("  # noqa: S608 - fixed schema column names
                + ",".join(values)
                + ") VALUES ("
                + ",".join("?" for _ in values)
                + ")",
                tuple(values.values()),
            )


@pytest.mark.parametrize("target", ["older_success", "self"])
async def test_resolution_requires_a_newer_success_for_the_same_authority(target: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        await _observe(_collector(connection, custody, _Transport(connection)))
        earlier = _row(connection)["intent_id"]
        SqliteObservationIntentStore(connection).begin(
            intent_id="unresolved-intent",
            request_id="unresolved-request",
            credential_id=CREDENTIAL,
            credential_generation=7,
            principal_id="principal_observation",
            quota_scope_id="quota_observation",
            actor_id="operator-test",
            source=SOURCE,
            now_ms=NOW,
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE provider_observation_intents SET state = 'UNKNOWN', "
                "resolved_by_intent_id = ? WHERE intent_id = 'unresolved-intent'",
                (earlier if target == "older_success" else "unresolved-intent",),
            )


class _Interrupted(BaseException):
    pass


async def test_crash_after_observation_commit_retains_unknown_request_authority() -> None:
    class InterruptingStore(SqliteObservationIntentStore):
        def succeed(
            self,
            intent_id: str,
            *,
            snapshot_id: str,
            audit_event_id: str,
            now_ms: int,
        ) -> None:
            raise _Interrupted

    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        collector = _collector(
            connection,
            custody,
            transport,
            intents=InterruptingStore(connection),
        )
        with pytest.raises(_Interrupted):
            await _observe(collector)
        assert _row(connection)["state"] == "SEND_INTENT"
        assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 1
        restarted = _collector(connection, custody, transport)
        with pytest.raises(CredentialValidationUnavailable):
            await _observe(restarted, request_id="after-crash", source=SCHEDULED)
        assert transport.calls == 1


@pytest.mark.parametrize(
    "mutation", ["actor", "generation", "source", "delete", "replace", "replace-ordinal"]
)
async def test_send_identity_and_retained_history_are_immutable(mutation: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        await _custody(connection)
        store = SqliteObservationIntentStore(connection)
        store.begin(
            intent_id="retained-intent",
            request_id="retained-request",
            credential_id=CREDENTIAL,
            credential_generation=7,
            principal_id="principal_observation",
            quota_scope_id="quota_observation",
            actor_id="operator-test",
            source=SOURCE,
            now_ms=NOW,
        )
        statements = {
            "actor": "UPDATE provider_observation_intents SET actor_id = 'other'",
            "generation": "UPDATE provider_observation_intents SET credential_generation = 8",
            "source": (
                "UPDATE provider_observation_intents SET source = 'admin-credential-validation'"
            ),
            "delete": "DELETE FROM provider_observation_intents",
            "replace": (
                "INSERT OR REPLACE INTO provider_observation_intents "
                "SELECT * FROM provider_observation_intents"
            ),
        }
        original = dict(_row(connection))
        with pytest.raises(sqlite3.IntegrityError):
            if mutation == "replace-ordinal":
                values = {**original, "intent_id": "new-identity", "request_digest": "c" * 64}
                connection.execute(
                    "INSERT OR REPLACE INTO provider_observation_intents("  # noqa: S608
                    + ",".join(values)
                    + ") VALUES ("
                    + ",".join("?" for _ in values)
                    + ")",
                    tuple(values.values()),
                )
            else:
                connection.execute(statements[mutation])
        assert _row(connection)["state"] == "SEND_INTENT"
        assert dict(_row(connection)) == original


async def test_account_commit_failure_is_unresolved_and_recovery_cannot_dispatch_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        account = SqliteAccountLifecycleService(
            connection,
            persistent_key_store=custody,
            provider_identity_hmac_key=b"i" * 32,
            now_ms=lambda: NOW,
            observation_collector=_collector(connection, custody, transport),
            manual_refresh_enabled=True,
        )

        def refuse(**kwargs: object) -> None:
            del kwargs
            raise RuntimeError(PRIVATE)

        monkeypatch.setattr(account, "_commit_result_locked", refuse)
        request = AccountRefreshRequest(mutation_id="commit-refused-request")
        with pytest.raises(AccountLifecycleFailure) as failure:
            await account.refresh_account("test-account", request, "operator")
        assert PRIVATE not in str(failure.value)
        assert _row(connection)["state"] == "SUCCEEDED"
        await account.recover_incomplete_account_mutations()
        with pytest.raises(AccountLifecycleConflict):
            await account.refresh_account("test-account", request, "operator")
        assert transport.calls == 1


async def test_restart_keeps_prepared_refresh_without_send_proof_unresolved() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection)
        connection.execute(
            "INSERT INTO credential_mutations(mutation_id, operation, credential_id, state, "
            "actor_id, created_at_ms, updated_at_ms, metadata_json) "
            "VALUES ('interrupted-refresh', 'account.refreshed', ?, 'ACCOUNT_REFRESH_PREPARED', "
            "'operator', ?, ?, ?)",
            (CREDENTIAL, NOW, NOW, '{"alias":"test-account","credential_generation":7}'),
        )
        account = SqliteAccountLifecycleService(
            connection,
            persistent_key_store=custody,
            provider_identity_hmac_key=b"i" * 32,
            now_ms=lambda: NOW,
            observation_collector=_collector(connection, custody, transport),
            manual_refresh_enabled=True,
        )
        assert await account.recover_incomplete_account_mutations() == 1
        assert await account.recover_incomplete_account_mutations() == 0
        with pytest.raises(AccountLifecycleConflict):
            await account.refresh_account(
                "test-account",
                AccountRefreshRequest(mutation_id="interrupted-refresh"),
                "operator",
            )
        assert transport.calls == 0
        assert (
            connection.execute(
                "SELECT state FROM credential_mutations WHERE mutation_id = 'interrupted-refresh'",
            ).fetchone()[0]
            == "ACCOUNT_REFRESH_UNKNOWN"
        )


@pytest.mark.parametrize("failure", ["transport", "cancel"])
async def test_account_refresh_unknown_survives_recovery_and_same_mutation_never_sends(
    failure: Literal["transport", "cancel"],
) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        custody = await _custody(connection)
        transport = _Transport(connection, failure=failure)
        collector = _collector(connection, custody, transport)
        account = SqliteAccountLifecycleService(
            connection,
            persistent_key_store=custody,
            provider_identity_hmac_key=b"i" * 32,
            now_ms=lambda: NOW,
            observation_collector=collector,
            manual_refresh_enabled=True,
        )
        request = AccountRefreshRequest(mutation_id="refresh-request-one")
        if failure == "cancel":
            task = asyncio.create_task(account.refresh_account("test-account", request, "operator"))
            await asyncio.wait_for(transport.started.wait(), timeout=1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(AccountLifecycleFailure):
                await account.refresh_account("test-account", request, "operator")
        await account.recover_incomplete_account_mutations()
        row = connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            (request.mutation_id,),
        ).fetchone()
        assert row is not None and row["state"] == "ACCOUNT_REFRESH_UNKNOWN"
        with pytest.raises(AccountLifecycleConflict):
            await account.refresh_account("test-account", request, "operator")
        assert transport.calls == 1
