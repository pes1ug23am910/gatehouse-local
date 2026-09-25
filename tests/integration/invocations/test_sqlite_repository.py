from __future__ import annotations

import sqlite3
from dataclasses import fields, replace
from pathlib import Path
from typing import Literal, cast

import pytest

from gatehouse.core.ids import (
    ClientId,
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
from gatehouse.database import (
    QuotaTransitionResult,
    QuotaTransitionStatus,
    SqliteQuotaStateRepository,
    open_migrated_database,
)
from gatehouse.database.connection import connect_database
from gatehouse.database.migrations import MIGRATIONS, apply_migrations
from gatehouse.database.recovery import recover_startup
from gatehouse.fingerprint import RequestFingerprint
from gatehouse.invocations import (
    AttemptEvent,
    InvocationPersistenceConflictError,
    InvocationRequestLimitExceeded,
    InvocationStartEvent,
    InvocationStateEvent,
    InvocationValidatedEvent,
    ProviderSubmissionLimitExceeded,
    SqliteInvocationRepository,
)
from gatehouse.providers import ProviderErrorClass
from gatehouse.routing import SqliteRoutingCatalog
from gatehouse.scheduler import PriorityClass

_A = "01K32J0B80E4G7P6H9Q2R5T8VW"
_B = "01K32J0B80F5H8Q7J0R3S6V9WX"


@pytest.mark.parametrize("limit", [True, False, 0, 2, -1, 1.0, "1", None])
def test_submission_limit_requires_exact_supported_integer(limit: object) -> None:
    with pytest.raises(ValueError, match="provider attempt limit"):
        replace(
            _start(
                {
                    "request": f"req_{_A}",
                    "session": f"ses_{_A}",
                    "root_run": f"run_{_A}",
                }
            ),
            maximum_total_provider_attempts=cast(int, limit),
        )


async def _submission_running(
    connection: sqlite3.Connection,
    *,
    emergency: bool = False,
) -> tuple[SqliteInvocationRepository, dict[str, str], AttemptEvent]:
    identifiers = (
        _seed_emergency_authority(connection) if emergency else _seed_authority(connection)
    )
    repository = SqliteInvocationRepository(connection)
    await repository.begin_invocation(_start(identifiers))
    connection.execute("UPDATE invocations SET state = 'RUNNING'")
    attempt = (
        replace(
            _emergency_dispatch(identifiers),
            state=InvocationState.RUNNING,
            estimated_cost_units=None,
            cost_unit=None,
        )
        if emergency
        else AttemptEvent(
            request_id=RequestId(identifiers["request"]),
            ordinal=1,
            state=InvocationState.RUNNING,
            occurred_at_ms=16,
            credential_id=identifiers["credential"],
            quota_scope_id=identifiers["scope"],
            dispatch_credential_generation=1,
            dispatch_pool_id=identifiers["pool"],
        )
    )
    await repository.record_attempt(attempt)
    return repository, identifiers, attempt


@pytest.mark.asyncio
@pytest.mark.parametrize("emergency", [False, True])
async def test_submission_claim_is_one_durable_authority_before_handoff(
    tmp_path: Path,
    emergency: bool,
) -> None:
    database_path = tmp_path / "submission.db"
    connection = open_migrated_database(database_path)
    try:
        repository, identifiers, attempt = await _submission_running(
            connection, emergency=emergency
        )
        await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=17)
        assert not repository.transaction_active
        claim = connection.execute("SELECT * FROM provider_submission_claims").fetchone()
        assert dict(claim) == {
            "request_id": identifiers["request"],
            "ordinal": 1,
            "claimed_at_ms": 17,
            "provenance": "TRANSPORT_HANDOFF",
        }
        assert (
            connection.execute(
                "SELECT maximum_total_provider_attempts FROM invocations"
            ).fetchone()[0]
            == 1
        )
        with pytest.raises(ProviderSubmissionLimitExceeded):
            await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=18)
        await repository.record_attempt(
            replace(attempt, state=InvocationState.FAILED, occurred_at_ms=19)
        )
        await repository.record_attempt(replace(attempt, ordinal=2, occurred_at_ms=20))
        with pytest.raises(ProviderSubmissionLimitExceeded):
            await repository.claim_provider_submission(attempt.request_id, 2, occurred_at_ms=21)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE provider_submission_claims SET claimed_at_ms = 22")
        with pytest.raises(sqlite3.IntegrityError, match="retained"):
            connection.execute("DELETE FROM provider_submission_claims")
        with pytest.raises(sqlite3.IntegrityError, match="authority"):
            connection.execute(
                "INSERT OR REPLACE INTO provider_submission_claims "
                "VALUES (?, 2, 22, 'TRANSPORT_HANDOFF')",
                (identifiers["request"],),
            )
    finally:
        connection.close()
    reopened = open_migrated_database(database_path)
    try:
        with pytest.raises(ProviderSubmissionLimitExceeded):
            await SqliteInvocationRepository(reopened).claim_provider_submission(
                RequestId(identifiers["request"]),
                2,
                occurred_at_ms=23,
            )
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_submission_claim_requires_matching_running_attempt(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "authority.db")
    try:
        repository, _, attempt = await _submission_running(connection)
        with pytest.raises(InvocationPersistenceConflictError):
            await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=15)
        for ordinal in (True, 0, 1.5, "1"):
            with pytest.raises(ValueError):
                await repository.claim_provider_submission(
                    attempt.request_id,
                    cast(int, ordinal),
                    occurred_at_ms=17,
                )
        with pytest.raises(InvocationPersistenceConflictError):
            await repository.claim_provider_submission(attempt.request_id, 2, occurred_at_ms=17)
        connection.execute("UPDATE invocations SET state = 'DISPATCHING'")
        with pytest.raises(InvocationPersistenceConflictError):
            await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=17)
        connection.execute("UPDATE invocations SET state = 'RUNNING'")
        connection.execute("UPDATE attempts SET state = 'DISPATCHING'")
        with pytest.raises(InvocationPersistenceConflictError):
            await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=17)
        with pytest.raises(sqlite3.IntegrityError, match="authority"):
            connection.execute(
                "INSERT INTO provider_submission_claims VALUES (?, 1, 17, 'TRANSPORT_HANDOFF')",
                (str(attempt.request_id),),
            )
        assert (
            connection.execute("SELECT COUNT(*) FROM provider_submission_claims").fetchone()[0] == 0
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE invocations SET maximum_total_provider_attempts = 2")
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_submission_predispatch_attempt_does_not_consume_first_handoff(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "predispatch.db")
    try:
        repository, _, attempt = await _submission_running(connection)
        await repository.record_attempt(
            replace(attempt, state=InvocationState.FAILED, occurred_at_ms=17)
        )
        await repository.record_attempt(replace(attempt, ordinal=2, occurred_at_ms=18))
        await repository.claim_provider_submission(attempt.request_id, 2, occurred_at_ms=19)
        assert (
            connection.execute("SELECT ordinal FROM provider_submission_claims").fetchone()[0] == 2
        )
    finally:
        connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["RETRY_WAIT", "DISPATCHING", "QUEUED", "FAILED", "RUNNING"])
@pytest.mark.parametrize("actual_cost", [None, 3])
async def test_submission_recovery_never_releases_handed_off_billing_at_zero(
    tmp_path: Path,
    state: str,
    actual_cost: int | None,
) -> None:
    connection = open_migrated_database(tmp_path / "billing.db")
    try:
        repository, identifiers, attempt = await _submission_running(connection)
        await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=17)
        connection.execute(
            "UPDATE invocations SET state = ?, actual_cost_units = ?, cost_unit = 'credits'",
            (state, actual_cost),
        )
        connection.execute(
            "INSERT INTO quota_reservations(reservation_id, request_id, quota_scope_id, "
            "amount_units, unit, state, created_at_ms, expires_at_ms) "
            "VALUES ('submission-quota', ?, ?, 2, 'credits', 'ACTIVE', 15, 100000)",
            (identifiers["request"], identifiers["scope"]),
        )
        connection.execute(
            "INSERT INTO budget_reservations(budget_reservation_id, request_id, root_run_id, "
            "amount_units, unit, state, created_at_ms) "
            "VALUES ('submission-budget', ?, ?, 2, 'credits', 'ACTIVE', 15)",
            (identifiers["request"], identifiers["root_run"]),
        )
        recover_startup(connection, now_ms=30)
        for table in ("quota_reservations", "budget_reservations"):
            row = connection.execute(
                f"SELECT state, actual_units, amount_units FROM {table}"  # noqa: S608 -- fixed pair
            ).fetchone()
            assert tuple(row) == ("PENDING_RECONCILIATION", None, max(2, actual_cost or 0))
        recover_startup(connection, now_ms=31)
        for table in ("quota_reservations", "budget_reservations"):
            assert connection.execute(f"SELECT amount_units FROM {table}").fetchone()[0] == max(  # noqa: S608 -- fixed pair
                2,
                actual_cost or 0,
            )
        expected_state = "FAILED" if state == "FAILED" else "UNKNOWN"
        assert connection.execute("SELECT state FROM invocations").fetchone()[0] == expected_state
        with pytest.raises(ProviderSubmissionLimitExceeded):
            await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=32)
    finally:
        connection.close()


def _submission_legacy_fixture(connection: sqlite3.Connection, *, dangling: bool = False) -> str:
    identifiers = _seed_authority(connection)
    request_id = identifiers["request"]
    connection.execute(
        "INSERT INTO invocations(request_id, session_id, root_run_id, service_id, operation, "
        "request_fingerprint, fingerprint_version, canonicalization_version, state, "
        "priority_class, request_size_bytes, received_at_ms) "
        "VALUES (?, ?, ?, 'firecrawl', 'firecrawl.search', ?, 1, 1, 'DISPATCHING', "
        "'normal_agent', 0, 10)",
        (request_id, identifiers["session"], identifiers["root_run"], b"f" * 32),
    )
    if dangling:
        connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(
        "INSERT INTO attempts(attempt_id, request_id, ordinal, credential_id, principal_id, "
        "quota_scope_id, state, started_at_ms, dispatch_credential_generation, dispatch_pool_id) "
        "VALUES (?, ?, 1, ?, ?, ?, 'DISPATCHING', 12, 1, ?)",
        (
            f"att_{_A}",
            f"req_{_B}" if dangling else request_id,
            identifiers["credential"],
            identifiers["principal"],
            identifiers["scope"],
            identifiers["pool"],
        ),
    )
    connection.execute("PRAGMA foreign_keys = ON")
    return request_id


@pytest.mark.asyncio
@pytest.mark.parametrize("actual_cost", [None, 3])
async def test_submission_migration_legacy_exhaustion_is_not_fabricated_handoff(
    tmp_path: Path,
    actual_cost: int | None,
) -> None:
    connection = connect_database(tmp_path / "legacy.db")
    try:
        apply_migrations(connection, migrations=MIGRATIONS[:15], now_ms=1)
        request_id = _submission_legacy_fixture(connection)
        connection.execute(
            "UPDATE invocations SET actual_cost_units = ?, cost_unit = 'credits'",
            (actual_cost,),
        )
        connection.execute(
            "INSERT INTO quota_reservations(reservation_id, request_id, quota_scope_id, "
            "amount_units, unit, state, created_at_ms, expires_at_ms) "
            "VALUES ('legacy-quota', ?, ?, 2, 'credits', 'ACTIVE', 15, 100000)",
            (request_id, f"quota_{_A}"),
        )
        connection.execute(
            "INSERT INTO budget_reservations(budget_reservation_id, request_id, root_run_id, "
            "amount_units, unit, state, created_at_ms) "
            "VALUES ('legacy-budget', ?, ?, 2, 'credits', 'ACTIVE', 15)",
            (request_id, f"run_{_A}"),
        )
        original = [tuple(row) for row in connection.execute("SELECT * FROM attempts")]
        ledger = [tuple(row) for row in connection.execute("SELECT * FROM schema_migrations")]
        assert apply_migrations(connection, now_ms=20) == MIGRATIONS[-1].version
        assert [tuple(row) for row in connection.execute("SELECT * FROM attempts")] == original
        assert [
            tuple(row)
            for row in connection.execute("SELECT * FROM schema_migrations WHERE version <= 15")
        ] == ledger
        assert dict(connection.execute("SELECT * FROM provider_submission_claims").fetchone()) == {
            "request_id": request_id,
            "ordinal": None,
            "claimed_at_ms": None,
            "provenance": "LEGACY_EXHAUSTED",
        }
        with pytest.raises(ProviderSubmissionLimitExceeded):
            await SqliteInvocationRepository(connection).claim_provider_submission(
                RequestId(request_id),
                1,
                occurred_at_ms=21,
            )
        recover_startup(connection, now_ms=22)
        assert connection.execute("SELECT state FROM invocations").fetchone()[0] == "UNKNOWN"
        recover_startup(connection, now_ms=23)
        for table in ("quota_reservations", "budget_reservations"):
            row = connection.execute(
                f"SELECT state, actual_units, amount_units FROM {table}"  # noqa: S608 -- fixed pair
            ).fetchone()
            assert tuple(row) == ("PENDING_RECONCILIATION", None, max(2, actual_cost or 0))
    finally:
        connection.close()


def test_submission_migration_rollback_preserves_version_fifteen(tmp_path: Path) -> None:
    connection = connect_database(tmp_path / "rollback.db")
    try:
        apply_migrations(connection, migrations=MIGRATIONS[:15], now_ms=1)
        _submission_legacy_fixture(connection, dangling=True)
        with pytest.raises(sqlite3.IntegrityError):
            apply_migrations(connection, now_ms=20)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 15
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 15
        assert "maximum_total_provider_attempts" not in {
            row[1] for row in connection.execute("PRAGMA table_info(invocations)")
        }
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'provider_submission_claims'"
            ).fetchone()
            is None
        )
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_submission_claim_retires_only_with_owning_invocation(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "retention.db")
    try:
        repository, _, attempt = await _submission_running(connection)
        await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=17)
        connection.execute("DELETE FROM attempts")
        with pytest.raises(ProviderSubmissionLimitExceeded):
            await repository.claim_provider_submission(attempt.request_id, 1, occurred_at_ms=18)
        connection.execute("DELETE FROM invocations")
        assert (
            connection.execute("SELECT COUNT(*) FROM provider_submission_claims").fetchone()[0] == 0
        )
    finally:
        connection.close()


def _seed_authority(connection: sqlite3.Connection) -> dict[str, str]:
    identifiers = {
        "client": str(ClientId(f"client_{_A}")),
        "workspace": str(WorkspaceId(f"ws_{_A}")),
        "session": str(SessionId(f"ses_{_A}")),
        "root_run": str(RootRunId(f"run_{_A}")),
        "request": str(RequestId(f"req_{_A}")),
        "principal": str(PrincipalId(f"prn_{_A}")),
        "scope": str(QuotaScopeId(f"quota_{_A}")),
        "credential": str(CredentialId(f"cred_{_A}")),
        "pool": str(PoolId(f"pool_{_A}")),
    }
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES (?, 'Client', 'interactive', 'default', 1, 1)
        """,
        (identifiers["client"],),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES (?, 'Workspace', 'E:\\Workspace', 1, 1)
        """,
        (identifiers["workspace"],),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms,
            absolute_expires_at_ms
        ) VALUES (?, ?, ?, ?, 1, 1, 'ACTIVE', 'LAUNCHER_SESSION',
                  'policy-v1', 1, 100000, 100000)
        """,
        (
            identifiers["session"],
            identifiers["client"],
            identifiers["workspace"],
            b"b" * 32,
        ),
    )
    connection.execute(
        """
        INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
        VALUES (?, ?, 'ACTIVE', 1)
        """,
        (identifiers["root_run"], identifiers["session"]),
    )
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'principal', 1, 1)
        """,
        (identifiers["principal"],),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES (?, ?, 'scope', 'HEALTHY', 'credits', 0)
        """,
        (identifiers["scope"], identifiers["principal"]),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES (?, ?, ?, 'credential', 'test', 'opaque-reference',
                  'HEALTHY', 1, 1)
        """,
        (
            identifiers["credential"],
            identifiers["principal"],
            identifiers["scope"],
        ),
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy
        ) VALUES (?, 'firecrawl', 'interactive-default', 'ACTIVE', 'cheapest_first')
        """,
        (identifiers["pool"],),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, enabled)
        VALUES (?, ?, 1)
        """,
        (identifiers["pool"], identifiers["scope"]),
    )
    return identifiers


def _seed_fresh_balance(
    connection: sqlite3.Connection,
    *,
    scope_id: str,
    credential_id: str,
    credential_generation: int,
    snapshot_id: str,
) -> None:
    connection.execute(
        """
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units, unit,
            captured_at_ms, source, observed_remaining_units_decimal,
            quota_dimension_id, credential_id, credential_generation,
            stale_at_ms, observation_kind
        ) VALUES (?, ?, 100, 'credits', 10, 'integration-test', '100',
                  ?, ?, ?, 1000000, 'AUTHENTICATED')
        """,
        (
            snapshot_id,
            scope_id,
            f"dimension_legacy_primary:{scope_id}",
            credential_id,
            credential_generation,
        ),
    )
    connection.execute(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = 100,
               balance_as_of_ms = 10,
               balance_snapshot_id = ?
         WHERE quota_scope_id = ?
        """,
        (snapshot_id, scope_id),
    )


def _start(identifiers: dict[str, str]) -> InvocationStartEvent:
    return InvocationStartEvent(
        request_id=RequestId(identifiers["request"]),
        session_id=SessionId(identifiers["session"]),
        root_run_id=RootRunId(identifiers["root_run"]),
        service_id="firecrawl",
        operation="firecrawl.search",
        priority=PriorityClass.NORMAL_AGENT,
        queue_deadline_ms=100_000,
        occurred_at_ms=10,
    )


def _seed_emergency_authority(
    connection: sqlite3.Connection,
    *,
    state: str = "ACTIVE",
    expires_at_ms: int = 1_000,
) -> dict[str, str]:
    identifiers = _seed_authority(connection)
    connection.execute("DELETE FROM pool_members")
    connection.execute("DELETE FROM credentials")
    connection.execute("DELETE FROM quota_dimensions")
    connection.execute("DELETE FROM quota_scopes")
    connection.execute("DELETE FROM principals")
    connection.execute(
        "UPDATE pools SET alias = 'emergency-locked', automatic_use = 0 WHERE pool_id = ?",
        (identifiers["pool"],),
    )
    identifiers["unlock"] = "unl_0000000000000000000000000000000000000000"
    connection.execute(
        """
        INSERT INTO credential_mutations(
            mutation_id, operation, credential_id, state, actor_id,
            created_at_ms, updated_at_ms, completed_at_ms
        ) VALUES ('mutation-emergency-attempt', 'emergency.unlocked', ?,
                  'COMMITTED', 'admin-session', 1, 1, 1)
        """,
        (identifiers["credential"],),
    )
    connection.execute(
        """
        INSERT INTO emergency_unlock_records(
            unlock_id, mutation_id, last_mutation_id, audit_event_id,
            credential_id, credential_alias, credential_generation,
            principal_id, principal_alias, quota_scope_id, quota_scope_alias,
            service_id, pool_id, session_id, root_run_id, state,
            maximum_requests, maximum_credits, maximum_concurrency,
            created_at_ms, updated_at_ms, expires_at_ms
        ) VALUES (?, 'mutation-emergency-attempt', 'mutation-emergency-attempt',
                  'audit-emergency-attempt', ?, 'emergency', 1, ?, 'emergency',
                  ?, 'emergency', 'firecrawl', ?, ?, ?, ?, 2, 10, 1, 1, 1, ?)
        """,
        (
            identifiers["unlock"],
            identifiers["credential"],
            identifiers["principal"],
            identifiers["scope"],
            identifiers["pool"],
            identifiers["session"],
            identifiers["root_run"],
            state,
            expires_at_ms,
        ),
    )
    assert connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 0
    return identifiers


@pytest.mark.asyncio
async def test_begin_inserts_safe_parent_before_quota_foreign_key(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "invocations.db")
    try:
        identifiers = _seed_authority(connection)
        repository = SqliteInvocationRepository(connection)

        assert not repository.transaction_active
        durable_field_names = {field.name for field in fields(InvocationStartEvent)}
        assert "access_token" not in durable_field_names
        assert "input_payload" not in durable_field_names
        await repository.begin_invocation(_start(identifiers))
        assert not repository.transaction_active

        row = connection.execute(
            "SELECT * FROM invocations WHERE request_id = ?",
            (identifiers["request"],),
        ).fetchone()
        assert row is not None
        assert row["session_id"] == identifiers["session"]
        assert row["root_run_id"] == identifiers["root_run"]
        assert row["service_id"] == "firecrawl"
        assert row["operation"] == "firecrawl.search"
        assert bytes(row["request_fingerprint"])
        assert len(bytes(row["request_fingerprint"])) == 32
        assert row["fingerprint_version"] == 0
        assert row["canonicalization_version"] == 0
        assert row["request_size_bytes"] == 0
        assert row["metadata_json"] == '{"fingerprint_state":"PROVISIONAL_REQUEST_BOUND"}'

        connection.execute(
            """
            INSERT INTO quota_reservations(
                reservation_id, request_id, quota_scope_id, amount_units,
                unit, state, created_at_ms, expires_at_ms
            ) VALUES ('reservation', ?, ?, 1, 'credits', 'ACTIVE', 11, 1000)
            """,
            (identifiers["request"], identifiers["scope"]),
        )
        assert (
            connection.execute("SELECT request_id FROM quota_reservations").fetchone()[0]
            == identifiers["request"]
        )
        connection.execute(
            """
            INSERT INTO approvals(
                approval_id, request_id, request_fingerprint, session_id,
                service_id, operation, state, created_at_ms, expires_at_ms
            )
            SELECT 'approval', request_id, request_fingerprint, session_id,
                   service_id, operation, 'PENDING', 11, 1000
              FROM invocations WHERE request_id = ?
            """,
            (identifiers["request"],),
        )
        assert (
            connection.execute("SELECT request_id FROM approvals").fetchone()[0]
            == identifiers["request"]
        )

        with pytest.raises(ValueError, match="unsupported field"):
            await repository.record_state(
                InvocationStateEvent(
                    request_id=RequestId(identifiers["request"]),
                    state=InvocationState.VALIDATING,
                    occurred_at_ms=12,
                    metadata={"access_token": "SUPER_SECRET_ACCESS_TOKEN"},
                )
            )
        with pytest.raises(ValueError, match="unsupported field"):
            await repository.record_state(
                InvocationStateEvent(
                    request_id=RequestId(identifiers["request"]),
                    state=InvocationState.VALIDATING,
                    occurred_at_ms=12,
                    metadata={"input_payload": "PAYLOAD_SENTINEL_NEVER_PERSIST"},
                )
            )

        database_text = "\n".join(connection.iterdump())
        assert "SUPER_SECRET_ACCESS_TOKEN" not in database_text
        assert "PAYLOAD_SENTINEL_NEVER_PERSIST" not in database_text
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_begin_consumes_request_budget_once_and_rejects_the_next_request(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "request-budget.db")
    try:
        identifiers = _seed_authority(connection)
        connection.execute(
            "UPDATE root_runs SET budget_json = '{\"requests\":1}' WHERE root_run_id = ?",
            (identifiers["root_run"],),
        )
        repository = SqliteInvocationRepository(connection)
        start = replace(_start(identifiers), request_limit=1)

        await repository.begin_invocation(start)
        await repository.begin_invocation(start)

        consumed = connection.execute(
            "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
            (identifiers["root_run"],),
        ).fetchone()
        assert consumed is not None
        assert consumed[0] == '{"requests":1}'

        with pytest.raises(InvocationRequestLimitExceeded):
            await repository.begin_invocation(replace(start, request_id=RequestId(f"req_{_B}")))
        assert connection.execute("SELECT COUNT(*) FROM invocations").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
                (identifiers["root_run"],),
            ).fetchone()[0]
            == '{"requests":1}'
        )
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_internal_resource_reconciliation_skips_public_accounting_on_terminal_run(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "internal-reconciliation.db")
    try:
        identifiers = _seed_authority(connection)
        connection.execute(
            """
            UPDATE root_runs
               SET state = 'COMPLETED', ended_at_ms = 9,
                   budget_json = '{"requests":0}'
             WHERE root_run_id = ?
            """,
            (identifiers["root_run"],),
        )
        repository = SqliteInvocationRepository(connection)
        internal = replace(
            _start(identifiers),
            operation="firecrawl.crawl.status",
            request_limit=0,
            internal_resource_reconciliation=True,
        )

        await repository.begin_invocation(internal)
        await repository.begin_invocation(internal)

        row = connection.execute(
            """
            SELECT metadata_json FROM invocations WHERE request_id = ?
            """,
            (identifiers["request"],),
        ).fetchone()
        assert row is not None
        assert row[0] == (
            '{"accounting_class":"internal_resource_reconciliation",'
            '"fingerprint_state":"PROVISIONAL_REQUEST_BOUND"}'
        )
        assert (
            connection.execute(
                "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
                (identifiers["root_run"],),
            ).fetchone()[0]
            == "{}"
        )

        with pytest.raises(InvocationPersistenceConflictError, match="active root run"):
            await repository.begin_invocation(
                replace(
                    internal,
                    request_id=RequestId(f"req_{_B}"),
                    internal_resource_reconciliation=False,
                )
            )
        with pytest.raises(ValueError, match="resource-bound"):
            await repository.begin_invocation(replace(internal, operation="firecrawl.search"))
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_successful_async_attempt_persists_exact_resource_checkpoint(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "async-checkpoint.db")
    try:
        identifiers = _seed_authority(connection)
        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(
            replace(_start(identifiers), operation="firecrawl.crawl.start")
        )
        succeeded = AttemptEvent(
            request_id=RequestId(identifiers["request"]),
            ordinal=1,
            state=InvocationState.SUCCEEDED,
            occurred_at_ms=25,
            credential_id=identifiers["credential"],
            quota_scope_id=identifiers["scope"],
            provider_status_code=200,
            error_class=ProviderErrorClass.NONE,
            resource_type="crawl",
            provider_resource_id="provider-job-checkpoint",
            credential_generation=1,
            pool_id=identifiers["pool"],
            dispatch_credential_generation=1,
            dispatch_pool_id=identifiers["pool"],
        )

        await repository.record_attempt(succeeded)
        await repository.record_attempt(succeeded)

        row = connection.execute(
            """
            SELECT state, resource_type, provider_resource_id,
                   credential_generation, pool_id
              FROM attempts WHERE request_id = ?
            """,
            (identifiers["request"],),
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "SUCCEEDED",
            "crawl",
            "provider-job-checkpoint",
            1,
            identifiers["pool"],
        )

        with pytest.raises(
            InvocationPersistenceConflictError,
            match="resource checkpoint changed",
        ):
            await repository.record_attempt(
                replace(succeeded, provider_resource_id="provider-job-other")
            )
        with pytest.raises(
            InvocationPersistenceConflictError,
            match="missing its resource checkpoint",
        ):
            await SqliteInvocationRepository(connection).record_attempt(
                replace(
                    succeeded,
                    ordinal=2,
                    resource_type=None,
                    provider_resource_id=None,
                    credential_generation=None,
                    pool_id=None,
                )
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="checkpoint is immutable",
        ):
            connection.execute(
                """
                UPDATE attempts
                   SET resource_type = NULL, provider_resource_id = NULL,
                       credential_generation = NULL, pool_id = NULL
                 WHERE request_id = ?
                """,
                (identifiers["request"],),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="checkpoint is immutable",
        ):
            connection.execute(
                """
                UPDATE attempts SET request_id = 'req_other-owner'
                 WHERE request_id = ?
                """,
                (identifiers["request"],),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="checkpoint is immutable",
        ):
            connection.execute(
                """
                UPDATE attempts SET credential_id = 'cred_other-authority'
                 WHERE request_id = ?
                """,
                (identifiers["request"],),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="checkpoint is immutable",
        ):
            connection.execute(
                """
                UPDATE attempts SET provider_resource_id = 'provider-job-other'
                 WHERE request_id = ?
                """,
                (identifiers["request"],),
            )
    finally:
        connection.close()


def test_normal_attempt_requires_immutable_dispatch_authority() -> None:
    with pytest.raises(ValueError, match="attempt dispatch authority is incomplete"):
        AttemptEvent(
            request_id=RequestId(f"req_{_A}"),
            ordinal=1,
            state=InvocationState.RUNNING,
            occurred_at_ms=1,
            credential_id=f"cred_{_A}",
            quota_scope_id=f"quota_{_A}",
        )


@pytest.mark.asyncio
async def test_async_terminal_checkpoint_uses_frozen_dispatch_after_generation_fence(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "async-generation-fence.db")
    try:
        identifiers = _seed_authority(connection)
        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(
            replace(_start(identifiers), operation="firecrawl.crawl.start")
        )
        dispatch = AttemptEvent(
            request_id=RequestId(identifiers["request"]),
            ordinal=1,
            state=InvocationState.RUNNING,
            occurred_at_ms=20,
            credential_id=identifiers["credential"],
            quota_scope_id=identifiers["scope"],
            estimated_cost_units=4,
            cost_unit="credits",
            dispatch_credential_generation=1,
            dispatch_pool_id=identifiers["pool"],
        )
        await repository.record_attempt(dispatch)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="attempt dispatch authority is immutable",
        ):
            connection.execute(
                "UPDATE attempts SET credential_id = ? WHERE request_id = ?",
                ("different-credential", identifiers["request"]),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="attempt dispatch authority is immutable",
        ):
            connection.execute(
                "UPDATE attempts SET principal_id = ? WHERE request_id = ?",
                ("different-principal", identifiers["request"]),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="attempt dispatch authority is immutable",
        ):
            connection.execute(
                "UPDATE attempts SET quota_scope_id = ? WHERE request_id = ?",
                ("different-scope", identifiers["request"]),
            )

        connection.execute(
            """
            UPDATE credentials
               SET state = 'DISABLED', generation = 2
             WHERE credential_id = ?
            """,
            (identifiers["credential"],),
        )

        await repository.record_attempt(
            replace(
                dispatch,
                state=InvocationState.SUCCEEDED,
                occurred_at_ms=30,
                provider_status_code=200,
                error_class=ProviderErrorClass.NONE,
                actual_cost_units=3,
                resource_type="crawl",
                provider_resource_id="provider-job-fenced",
                credential_generation=1,
                pool_id=identifiers["pool"],
            )
        )

        row = connection.execute(
            """
            SELECT state, credential_generation, pool_id,
                   dispatch_credential_generation, dispatch_pool_id
              FROM attempts
             WHERE request_id = ? AND ordinal = 1
            """,
            (identifiers["request"],),
        ).fetchone()
        assert row is not None
        assert tuple(row) == (
            "SUCCEEDED",
            1,
            identifiers["pool"],
            1,
            identifiers["pool"],
        )
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_definitive_quota_attempt_survives_restart_and_timer_expiry(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "definitive-quota-restart.db"
    connection = open_migrated_database(database_path)
    identifiers = _seed_authority(connection)
    backup = {
        "principal": str(PrincipalId(f"prn_{_B}")),
        "scope": str(QuotaScopeId(f"quota_{_B}")),
        "credential": str(CredentialId(f"cred_{_B}")),
    }
    connection.execute(
        """
        INSERT INTO principals(principal_id, service_id, alias, created_at_ms, updated_at_ms)
        VALUES (?, 'firecrawl', 'backup', 1, 1)
        """,
        (backup["principal"],),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit, configured_floor_units
        ) VALUES (?, ?, 'backup', 'HEALTHY', 'credits', 0)
        """,
        (backup["scope"], backup["principal"]),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES (?, ?, ?, 'backup', 'test', 'opaque-backup', 'HEALTHY', 1, 1)
        """,
        (backup["credential"], backup["principal"], backup["scope"]),
    )
    connection.execute(
        """
        UPDATE pools SET selection_strategy = 'fill_first' WHERE pool_id = ?
        """,
        (identifiers["pool"],),
    )
    connection.execute(
        """
        UPDATE pool_members SET priority = 1, cost_rank = 1
         WHERE pool_id = ? AND quota_scope_id = ?
        """,
        (identifiers["pool"], identifiers["scope"]),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
        VALUES (?, ?, 2, 2, 1)
        """,
        (identifiers["pool"], backup["scope"]),
    )
    _seed_fresh_balance(
        connection,
        scope_id=identifiers["scope"],
        credential_id=identifiers["credential"],
        credential_generation=1,
        snapshot_id="snapshot-definitive-primary",
    )
    _seed_fresh_balance(
        connection,
        scope_id=backup["scope"],
        credential_id=backup["credential"],
        credential_generation=1,
        snapshot_id="snapshot-definitive-backup",
    )
    repository = SqliteInvocationRepository(
        connection,
        attempt_id_factory=lambda: f"att_{_A}",
    )
    await repository.begin_invocation(_start(identifiers))
    dispatch = AttemptEvent(
        request_id=RequestId(identifiers["request"]),
        ordinal=1,
        state=InvocationState.DISPATCHING,
        occurred_at_ms=20,
        credential_id=identifiers["credential"],
        quota_scope_id=identifiers["scope"],
        estimated_cost_units=1,
        cost_unit="credits",
        dispatch_credential_generation=1,
        dispatch_pool_id=identifiers["pool"],
    )
    await repository.record_attempt(dispatch)
    await repository.record_attempt(
        replace(
            dispatch,
            state=InvocationState.FAILED,
            occurred_at_ms=21,
            provider_status_code=402,
            error_class=ProviderErrorClass.QUOTA_EXHAUSTED,
        )
    )

    attempt = connection.execute(
        "SELECT attempt_id, state, error_class FROM attempts WHERE request_id = ?",
        (identifiers["request"],),
    ).fetchone()
    transition = connection.execute(
        """
        SELECT credential_id, credential_generation, request_id, attempt_id,
               source_kind, reason_code
          FROM quota_scope_state_events
         WHERE quota_scope_id = ?
        """,
        (identifiers["scope"],),
    ).fetchone()
    assert attempt is not None
    assert transition is not None
    assert tuple(attempt) == (f"att_{_A}", "FAILED", "quota_exhausted")
    assert tuple(transition) == (
        identifiers["credential"],
        1,
        identifiers["request"],
        f"att_{_A}",
        "PROVIDER_RESPONSE",
        "PROVIDER_QUOTA_EXHAUSTED",
    )
    assert (
        connection.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = ?",
            (identifiers["scope"],),
        ).fetchone()[0]
        == "EXHAUSTED"
    )
    connection.close()

    restarted = open_migrated_database(database_path)
    try:
        plan = SqliteRoutingCatalog(restarted).plan(
            service_id="firecrawl",
            operation="firecrawl.search",
            pool_name="interactive-default",
            estimated_cost_units=1,
            unit="credits",
            now_ms=120_022,
        )
        assert [str(candidate.scope.quota_scope_id) for candidate in plan.candidates] == [
            backup["scope"]
        ]
        assert (
            restarted.execute(
                "SELECT state FROM quota_scopes WHERE quota_scope_id = ?",
                (identifiers["scope"],),
            ).fetchone()[0]
            == "EXHAUSTED"
        )
    finally:
        restarted.close()


@pytest.mark.asyncio
async def test_failed_exhaustion_transition_rolls_back_terminal_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = open_migrated_database(tmp_path / "definitive-quota-rollback.db")
    try:
        identifiers = _seed_authority(connection)
        repository = SqliteInvocationRepository(
            connection,
            attempt_id_factory=lambda: f"att_{_A}",
        )
        await repository.begin_invocation(_start(identifiers))
        dispatch = AttemptEvent(
            request_id=RequestId(identifiers["request"]),
            ordinal=1,
            state=InvocationState.DISPATCHING,
            occurred_at_ms=20,
            credential_id=identifiers["credential"],
            quota_scope_id=identifiers["scope"],
            dispatch_credential_generation=1,
            dispatch_pool_id=identifiers["pool"],
        )
        await repository.record_attempt(dispatch)

        def reject_transition(
            _repository: SqliteQuotaStateRepository,
            **_kwargs: object,
        ) -> QuotaTransitionResult:
            return QuotaTransitionResult(QuotaTransitionStatus.NOT_FOUND, None, None)

        monkeypatch.setattr(
            SqliteQuotaStateRepository,
            "mark_definitive_exhaustion_in_transaction",
            reject_transition,
        )
        with pytest.raises(
            InvocationPersistenceConflictError,
            match="definitive quota exhaustion could not be persisted",
        ):
            await repository.record_attempt(
                replace(
                    dispatch,
                    state=InvocationState.FAILED,
                    occurred_at_ms=21,
                    provider_status_code=402,
                    error_class=ProviderErrorClass.QUOTA_EXHAUSTED,
                )
            )

        durable = connection.execute(
            """
            SELECT state, provider_status_code, error_class
              FROM attempts WHERE request_id = ? AND ordinal = 1
            """,
            (identifiers["request"],),
        ).fetchone()
        assert durable is not None
        assert tuple(durable) == ("DISPATCHING", None, None)
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_validated_facts_queue_and_attempts_are_idempotent_across_reopen(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "reopen.db"
    connection = open_migrated_database(database_path)
    identifiers = _seed_authority(connection)
    start = _start(identifiers)
    validated = InvocationValidatedEvent(
        request_id=RequestId(identifiers["request"]),
        fingerprint=RequestFingerprint(b"f" * 32, 3, 2),
        request_size_bytes=137,
        estimated_cost_units=7,
        cost_unit="credits",
    )
    repository = SqliteInvocationRepository(
        connection,
        attempt_id_factory=lambda: f"att_{_A}",
    )

    await repository.begin_invocation(start)
    await repository.record_validated(validated)
    for state, occurred_at_ms in (
        (InvocationState.VALIDATING, 11),
        (InvocationState.POLICY_CHECK, 12),
        (InvocationState.DEDUPLICATION, 13),
        (InvocationState.QUOTA_RESERVED, 14),
        (InvocationState.QUEUED, 15),
        (InvocationState.DISPATCHING, 16),
    ):
        await repository.record_state(
            InvocationStateEvent(
                request_id=RequestId(identifiers["request"]),
                state=state,
                occurred_at_ms=occurred_at_ms,
                metadata={"pool_id": f"pool_{_A}"} if state is InvocationState.QUEUED else {},
            )
        )

    dispatch = AttemptEvent(
        request_id=RequestId(identifiers["request"]),
        ordinal=1,
        state=InvocationState.DISPATCHING,
        occurred_at_ms=16,
        credential_id=identifiers["credential"],
        quota_scope_id=identifiers["scope"],
        estimated_cost_units=7,
        cost_unit="credits",
        dispatch_credential_generation=1,
        dispatch_pool_id=identifiers["pool"],
    )
    running = AttemptEvent(
        request_id=dispatch.request_id,
        ordinal=dispatch.ordinal,
        state=InvocationState.RUNNING,
        occurred_at_ms=17,
        credential_id=dispatch.credential_id,
        quota_scope_id=dispatch.quota_scope_id,
        estimated_cost_units=dispatch.estimated_cost_units,
        cost_unit=dispatch.cost_unit,
        dispatch_credential_generation=dispatch.dispatch_credential_generation,
        dispatch_pool_id=dispatch.dispatch_pool_id,
    )
    succeeded = AttemptEvent(
        request_id=dispatch.request_id,
        ordinal=dispatch.ordinal,
        state=InvocationState.SUCCEEDED,
        occurred_at_ms=23,
        credential_id=dispatch.credential_id,
        quota_scope_id=dispatch.quota_scope_id,
        provider_status_code=200,
        provider_request_id="provider-request-safe",
        error_class=ProviderErrorClass.NONE,
        estimated_cost_units=7,
        actual_cost_units=5,
        cost_unit="credits",
        latency_ms=6,
        dispatch_credential_generation=dispatch.dispatch_credential_generation,
        dispatch_pool_id=dispatch.dispatch_pool_id,
    )
    await repository.record_attempt(dispatch)
    await repository.record_state(
        InvocationStateEvent(
            request_id=dispatch.request_id,
            state=InvocationState.RUNNING,
            occurred_at_ms=17,
        )
    )
    await repository.record_attempt(running)
    await repository.record_attempt(succeeded)
    await repository.record_attempt(succeeded)
    await repository.record_state(
        InvocationStateEvent(
            request_id=dispatch.request_id,
            state=InvocationState.SUCCEEDED,
            occurred_at_ms=23,
        )
    )

    row = connection.execute(
        "SELECT * FROM invocations WHERE request_id = ?",
        (identifiers["request"],),
    ).fetchone()
    assert row is not None
    assert bytes(row["request_fingerprint"]) == b"f" * 32
    assert (row["fingerprint_version"], row["canonicalization_version"]) == (3, 2)
    assert row["request_size_bytes"] == 137
    assert row["estimated_cost_units"] == 7
    assert row["actual_cost_units"] == 5
    assert row["cost_unit"] == "credits"
    assert row["state"] == "SUCCEEDED"
    assert row["metadata_json"] == (f'{{"fingerprint_state":"FINAL","pool_id":"pool_{_A}"}}')

    queue = connection.execute(
        "SELECT * FROM queue_entries WHERE request_id = ?",
        (identifiers["request"],),
    ).fetchone()
    assert queue is not None
    assert queue["state"] == "SUCCEEDED"
    assert queue["priority_class"] == "NORMAL_AGENT"
    assert queue["estimated_cost_units"] == 7
    assert queue["cost_unit"] == "credits"
    assert queue["dispatch_attempts"] == 1
    assert queue["metadata_json"] == f'{{"pool_id":"pool_{_A}"}}'

    attempt = connection.execute(
        "SELECT * FROM attempts WHERE request_id = ?",
        (identifiers["request"],),
    ).fetchone()
    assert attempt is not None
    assert attempt["attempt_id"] == f"att_{_A}"
    assert attempt["principal_id"] == identifiers["principal"]
    assert attempt["state"] == "SUCCEEDED"
    assert attempt["provider_request_id"] == "provider-request-safe"
    assert attempt["actual_cost_units"] == 5
    assert attempt["latency_ms"] == 6
    connection.close()

    reopened = open_migrated_database(database_path)
    try:
        restarted = SqliteInvocationRepository(
            reopened,
            attempt_id_factory=lambda: f"att_{_B}",
        )
        await restarted.begin_invocation(start)
        await restarted.record_validated(validated)
        await restarted.record_attempt(succeeded)
        with pytest.raises(
            InvocationPersistenceConflictError,
            match="validated invocation facts changed",
        ):
            await restarted.record_validated(
                replace(
                    validated,
                    fingerprint=RequestFingerprint(b"x" * 32, 3, 2),
                )
            )
        with pytest.raises(
            InvocationPersistenceConflictError,
            match="attempt actual_cost_units changed",
        ):
            await restarted.record_attempt(replace(succeeded, actual_cost_units=6))

        assert reopened.execute("SELECT COUNT(*) FROM invocations").fetchone()[0] == 1
        assert reopened.execute("SELECT COUNT(*) FROM queue_entries").fetchone()[0] == 1
        assert reopened.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 1
        assert (
            reopened.execute(
                "SELECT state FROM invocations WHERE request_id = ?",
                (identifiers["request"],),
            ).fetchone()[0]
            == "SUCCEEDED"
        )
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_provisional_parent_can_finish_validation_after_reopen(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "provisional.db"
    connection = open_migrated_database(database_path)
    identifiers = _seed_authority(connection)
    start = _start(identifiers)
    await SqliteInvocationRepository(connection).begin_invocation(start)
    connection.close()

    reopened = open_migrated_database(database_path)
    try:
        repository = SqliteInvocationRepository(reopened)
        await repository.begin_invocation(start)
        await repository.record_validated(
            InvocationValidatedEvent(
                request_id=RequestId(identifiers["request"]),
                fingerprint=RequestFingerprint(b"r" * 32, 1, 1),
                request_size_bytes=29,
                estimated_cost_units=2,
                cost_unit="credits",
            )
        )

        row = reopened.execute(
            """
            SELECT request_fingerprint, fingerprint_version,
                   canonicalization_version, request_size_bytes,
                   estimated_cost_units, cost_unit
              FROM invocations WHERE request_id = ?
            """,
            (identifiers["request"],),
        ).fetchone()
        assert row is not None
        assert tuple(row) == (b"r" * 32, 1, 1, 29, 2, "credits")
    finally:
        reopened.close()


def _emergency_dispatch(identifiers: dict[str, str], *, occurred_at_ms: int = 16) -> AttemptEvent:
    return AttemptEvent(
        request_id=RequestId(identifiers["request"]),
        ordinal=1,
        state=InvocationState.DISPATCHING,
        occurred_at_ms=occurred_at_ms,
        credential_id=identifiers["credential"],
        quota_scope_id=identifiers["scope"],
        estimated_cost_units=4,
        cost_unit="credits",
        pool_id=identifiers["pool"],
        emergency_unlock_id=identifiers["unlock"],
    )


def _replace_emergency_authority(
    event: AttemptEvent,
    field_name: Literal[
        "emergency_unlock_id",
        "credential_id",
        "quota_scope_id",
        "pool_id",
    ],
    replacement_value: str | None,
) -> AttemptEvent:
    if field_name == "pool_id":
        return replace(event, pool_id=replacement_value)
    assert replacement_value is not None
    if field_name == "emergency_unlock_id":
        return replace(event, emergency_unlock_id=replacement_value)
    if field_name == "credential_id":
        return replace(event, credential_id=replacement_value)
    return replace(event, quota_scope_id=replacement_value)


@pytest.mark.asyncio
async def test_emergency_attempt_uses_fk_less_authority_and_settles_after_relock(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "emergency-attempt.db")
    try:
        identifiers = _seed_emergency_authority(connection)
        repository = SqliteInvocationRepository(
            connection,
            attempt_id_factory=lambda: f"att_{_A}",
        )
        await repository.begin_invocation(_start(identifiers))
        await repository.record_validated(
            InvocationValidatedEvent(
                request_id=RequestId(identifiers["request"]),
                fingerprint=RequestFingerprint(b"e" * 32, 1, 1),
                request_size_bytes=13,
                estimated_cost_units=4,
                cost_unit="credits",
            )
        )

        dispatch = _emergency_dispatch(identifiers)
        await repository.record_attempt(dispatch)
        row = connection.execute(
            "SELECT * FROM attempts WHERE request_id = ?",
            (identifiers["request"],),
        ).fetchone()
        assert row is not None
        assert row["credential_id"] is None
        assert row["principal_id"] is None
        assert row["quota_scope_id"] is None
        assert row["resource_type"] is None
        assert row["provider_resource_id"] is None
        assert row["credential_generation"] is None
        assert row["pool_id"] is None
        assert (
            row["emergency_unlock_id"],
            row["emergency_credential_id"],
            row["emergency_principal_id"],
            row["emergency_quota_scope_id"],
            row["emergency_pool_id"],
            row["emergency_credential_generation"],
        ) == (
            identifiers["unlock"],
            identifiers["credential"],
            identifiers["principal"],
            identifiers["scope"],
            identifiers["pool"],
            1,
        )
        assert connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 0

        connection.execute(
            "UPDATE emergency_unlock_records SET state = 'RELOCKED', closed_at_ms = 17"
        )
        with pytest.raises(
            InvocationPersistenceConflictError,
            match="relocked emergency attempt requires a terminal update",
        ):
            await repository.record_attempt(
                replace(dispatch, state=InvocationState.RUNNING, occurred_at_ms=18)
            )

        failed = replace(
            dispatch,
            state=InvocationState.FAILED,
            occurred_at_ms=19,
            error_class=ProviderErrorClass.TRANSIENT,
            actual_cost_units=3,
            latency_ms=3,
        )
        await repository.record_attempt(failed)
        await repository.record_attempt(failed)
        settled = connection.execute(
            "SELECT state, actual_cost_units FROM attempts WHERE request_id = ?",
            (identifiers["request"],),
        ).fetchone()
        assert settled is not None
        assert tuple(settled) == ("FAILED", 3)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("field_name", "replacement_value"),
    (
        ("emergency_unlock_id", "unl_1111111111111111111111111111111111111111"),
        ("credential_id", f"cred_{_B}"),
        ("quota_scope_id", f"quota_{_B}"),
        ("pool_id", f"pool_{_B}"),
    ),
)
@pytest.mark.asyncio
async def test_emergency_attempt_rejects_claimed_authority_mismatch(
    tmp_path: Path,
    field_name: Literal[
        "emergency_unlock_id",
        "credential_id",
        "quota_scope_id",
        "pool_id",
    ],
    replacement_value: str,
) -> None:
    connection = open_migrated_database(tmp_path / f"emergency-{field_name}.db")
    try:
        identifiers = _seed_emergency_authority(connection)
        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(_start(identifiers))
        event = _replace_emergency_authority(
            _emergency_dispatch(identifiers),
            field_name,
            replacement_value,
        )

        with pytest.raises(
            InvocationPersistenceConflictError,
            match="emergency attempt authority is invalid",
        ):
            await repository.record_attempt(event)
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    finally:
        connection.close()


@pytest.mark.parametrize("mismatch", ("service", "session", "root"))
@pytest.mark.asyncio
async def test_emergency_attempt_rejects_invocation_binding_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    connection = open_migrated_database(tmp_path / f"emergency-binding-{mismatch}.db")
    try:
        identifiers = _seed_emergency_authority(connection)
        alternate_session = str(SessionId(f"ses_{_B}"))
        alternate_root = str(RootRunId(f"run_{_B}"))
        connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_id, workspace_id, bootstrap_verifier,
                bootstrap_version, token_epoch, state, identity_assurance,
                policy_version, created_at_ms, reconnect_until_ms,
                absolute_expires_at_ms
            ) VALUES (?, ?, ?, ?, 1, 1, 'ACTIVE', 'LAUNCHER_SESSION',
                      'policy-v1', 1, 100000, 100000)
            """,
            (
                alternate_session,
                identifiers["client"],
                identifiers["workspace"],
                b"c" * 32,
            ),
        )
        connection.execute(
            """
            INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
            VALUES (?, ?, 'ACTIVE', 1)
            """,
            (alternate_root, alternate_session),
        )
        if mismatch == "service":
            connection.execute("UPDATE emergency_unlock_records SET service_id = 'other-service'")
        elif mismatch == "session":
            connection.execute(
                "UPDATE emergency_unlock_records SET session_id = ?",
                (alternate_session,),
            )
        else:
            connection.execute(
                "UPDATE emergency_unlock_records SET root_run_id = ?",
                (alternate_root,),
            )

        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(_start(identifiers))
        with pytest.raises(
            InvocationPersistenceConflictError,
            match="emergency attempt authority is invalid",
        ):
            await repository.record_attempt(_emergency_dispatch(identifiers))
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("unlock_state", "occurred_at_ms"),
    (("RELOCKED", 16), ("ACTIVE", 1_000)),
)
@pytest.mark.asyncio
async def test_new_emergency_attempt_requires_active_unexpired_unlock(
    tmp_path: Path,
    unlock_state: str,
    occurred_at_ms: int,
) -> None:
    connection = open_migrated_database(tmp_path / f"emergency-{unlock_state}.db")
    try:
        identifiers = _seed_emergency_authority(connection, state=unlock_state)
        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(_start(identifiers))

        with pytest.raises(
            InvocationPersistenceConflictError,
            match="emergency unlock is not active for attempt admission",
        ):
            await repository.record_attempt(
                _emergency_dispatch(identifiers, occurred_at_ms=occurred_at_ms)
            )
    finally:
        connection.close()


@pytest.mark.parametrize("closed_authority", ("pool", "session", "root", "unattended"))
@pytest.mark.asyncio
async def test_new_emergency_attempt_revalidates_runtime_authority(
    tmp_path: Path,
    closed_authority: str,
) -> None:
    connection = open_migrated_database(tmp_path / f"emergency-runtime-{closed_authority}.db")
    try:
        identifiers = _seed_emergency_authority(connection)
        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(_start(identifiers))
        if closed_authority == "pool":
            connection.execute(
                "UPDATE pools SET state = 'DISABLED' WHERE pool_id = ?",
                (identifiers["pool"],),
            )
        elif closed_authority == "session":
            connection.execute(
                "UPDATE sessions SET state = 'REVOKED' WHERE session_id = ?",
                (identifiers["session"],),
            )
        elif closed_authority == "root":
            connection.execute(
                "UPDATE root_runs SET state = 'CANCELLED' WHERE root_run_id = ?",
                (identifiers["root_run"],),
            )
        else:
            connection.execute(
                "UPDATE clients SET unattended = 1 WHERE client_id = ?",
                (identifiers["client"],),
            )

        with pytest.raises(
            InvocationPersistenceConflictError,
            match="emergency unlock is not active for attempt admission",
        ):
            await repository.record_attempt(_emergency_dispatch(identifiers))
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_emergency_attempt_rejects_async_creation_operation(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "emergency-async.db")
    try:
        identifiers = _seed_emergency_authority(connection)
        repository = SqliteInvocationRepository(connection)
        await repository.begin_invocation(
            replace(_start(identifiers), operation="firecrawl.crawl.start")
        )

        with pytest.raises(
            InvocationPersistenceConflictError,
            match="emergency authority cannot create asynchronous resources",
        ):
            await repository.record_attempt(_emergency_dispatch(identifiers))
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("field_name", "replacement_value"),
    (
        ("emergency_unlock_id", "short"),
        ("credential_id", "credential-not-opaque"),
        ("quota_scope_id", "quota-not-opaque"),
        ("pool_id", "pool-not-opaque"),
        ("pool_id", None),
    ),
)
def test_emergency_attempt_model_rejects_invalid_opaque_authority(
    field_name: Literal[
        "emergency_unlock_id",
        "credential_id",
        "quota_scope_id",
        "pool_id",
    ],
    replacement_value: str | None,
) -> None:
    identifiers = {
        "request": str(RequestId(f"req_{_A}")),
        "credential": str(CredentialId(f"cred_{_A}")),
        "scope": str(QuotaScopeId(f"quota_{_A}")),
        "pool": str(PoolId(f"pool_{_A}")),
        "unlock": "unl_0000000000000000000000000000000000000000",
    }
    with pytest.raises(ValueError, match="emergency attempt authority is invalid"):
        _replace_emergency_authority(
            _emergency_dispatch(identifiers),
            field_name,
            replacement_value,
        )


def test_emergency_attempt_model_rejects_async_checkpoint() -> None:
    identifiers = {
        "request": str(RequestId(f"req_{_A}")),
        "credential": str(CredentialId(f"cred_{_A}")),
        "scope": str(QuotaScopeId(f"quota_{_A}")),
        "pool": str(PoolId(f"pool_{_A}")),
        "unlock": "unl_0000000000000000000000000000000000000000",
    }
    with pytest.raises(ValueError, match="cannot carry an asynchronous resource checkpoint"):
        replace(
            _emergency_dispatch(identifiers),
            state=InvocationState.SUCCEEDED,
            error_class=ProviderErrorClass.NONE,
            resource_type="crawl",
            provider_resource_id="provider-job",
            credential_generation=1,
        )
