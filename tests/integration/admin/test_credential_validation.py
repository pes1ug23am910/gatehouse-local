from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatehouse.admin.lifecycle import (
    CredentialLifecycleConflict,
    SqliteCredentialLifecycleService,
)
from gatehouse.admin.models import CredentialRotationRequest, CredentialValidationRequest
from gatehouse.admin.provider_validation import (
    CredentialValidationBusy,
    CredentialValidationPersistenceError,
    CredentialValidationProviderFailure,
    CredentialValidationUnavailable,
    SqliteCredentialValidationService,
)
from gatehouse.core.provider_numbers import ExactProviderNumber, parse_json_provider_number
from gatehouse.credentials import (
    CredentialMetadata,
    InMemoryKeyStore,
    SecretScanner,
    ZeroingSecretLease,
)
from gatehouse.database import GatehouseRepository, open_migrated_database
from gatehouse.providers.base import ProviderErrorClass, ProviderRequest, ProviderResponse

NOW_MS = 1_800_000_000_000
PRINCIPAL_ID = "prn_validation_01"
SCOPE_ID = "quota_validation_01"
CREDENTIAL_ID = "credential_validation_01"
GENERATION = 7
ACTOR_ID = "admin_validation_actor"
PROVIDER_BODY_CANARY = "provider-body-field-must-not-persist-918273645"
TRANSPORT_ERROR_CANARY = "fc-SYNTHETIC-TRANSPORT-ERROR-CANARY-123456789"
SYNTHETIC_SECRET = b"synthetic-validation-custody-material"
_OPEN_SERVICE_CONNECTIONS: list[sqlite3.Connection] = []


@pytest.fixture(autouse=True)
def _close_service_connections() -> Iterator[None]:
    try:
        yield
    finally:
        for connection in _OPEN_SERVICE_CONNECTIONS:
            connection.close()
        _OPEN_SERVICE_CONNECTIONS.clear()


def _reference(credential_id: str = CREDENTIAL_ID) -> str:
    stem = hashlib.sha256(credential_id.encode("utf-8")).hexdigest()
    return f"dpapi-current-user://{stem}"


def _seed_exact_credential(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, enabled, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'validation-principal', 1, ?, ?)
        """,
        (PRINCIPAL_ID, NOW_MS, NOW_MS),
    )
    # Provider validation is intentionally independent of routing quota state.
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES (?, ?, 'validation-scope', 'EXHAUSTED', 'credits', 0)
        """,
        (SCOPE_ID, PRINCIPAL_ID),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation,
            exclusive_usage, created_at_ms
        ) VALUES (?, ?, ?, 'validation-credential', 'dpapi-current-user', ?,
                  'HEALTHY', ?, 1, ?)
        """,
        (CREDENTIAL_ID, PRINCIPAL_ID, SCOPE_ID, _reference(), GENERATION, NOW_MS),
    )


class _MetadataStore(InMemoryKeyStore):
    def __init__(self) -> None:
        super().__init__()
        self.list_calls = 0
        self.open_calls = 0

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        self.list_calls += 1
        return await super().list_metadata()

    async def open_lease(
        self,
        credential_id: str,
        purpose: str,
        *,
        expected_generation: int | None = None,
        ttl_seconds: float | None = None,
    ) -> ZeroingSecretLease:
        self.open_calls += 1
        return await super().open_lease(
            credential_id,
            purpose,
            expected_generation=expected_generation,
            ttl_seconds=ttl_seconds,
        )


class _RecordingTransport:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        response: ProviderResponse | None = None,
        error: Exception | None = None,
        block: bool = False,
    ) -> None:
        self.connection = connection
        self.response = response or _valid_response()
        self.error = error
        self.requests: list[ProviderRequest] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.block = block

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        assert not self.connection.in_transaction
        self.requests.append(request)
        self.started.set()
        if self.block:
            await asyncio.wait_for(self.release.wait(), timeout=2)
        if self.error is not None:
            raise self.error
        return self.response


class _ReleaseFailingRepository(GatehouseRepository):
    def release_lease(
        self,
        *,
        lease_id: str,
        owner_id: str,
        now_ms: int,
    ) -> bool:
        del lease_id, owner_id, now_ms
        raise RuntimeError(TRANSPORT_ERROR_CANARY)


def _valid_response() -> ProviderResponse:
    return ProviderResponse(
        status_code=200,
        data={
            "success": True,
            "data": {
                "remainingCredits": 41,
                "planCredits": 100,
                "billingPeriodStart": "2025-01-01T00:00:00Z",
                "billingPeriodEnd": "2025-01-31T23:59:59Z",
                "team": PROVIDER_BODY_CANARY,
            },
            "account": PROVIDER_BODY_CANARY,
        },
    )


async def _service(
    path: Path,
    *,
    provider_mode: str = "live",
    network_enabled: bool = True,
    response: ProviderResponse | None = None,
    error: Exception | None = None,
    block: bool = False,
    event_id_factory: object | None = None,
    snapshot_id_factory: object | None = None,
    dispatch_deadline_seconds: float = 15.0,
    lease_ttl_ms: int = 45_000,
    release_fails: bool = False,
) -> tuple[
    sqlite3.Connection,
    _MetadataStore,
    _RecordingTransport,
    SqliteCredentialValidationService,
]:
    connection = open_migrated_database(path)
    _OPEN_SERVICE_CONNECTIONS.append(connection)
    _seed_exact_credential(connection)
    store = _MetadataStore()
    await store.put(
        CredentialMetadata(
            credential_id=CREDENTIAL_ID,
            principal_id=PRINCIPAL_ID,
            quota_scope_id=SCOPE_ID,
            alias="validation-credential",
            state="HEALTHY",
            generation=GENERATION,
            secret_reference=_reference(),
        ),
        SYNTHETIC_SECRET,
    )
    transport = _RecordingTransport(
        connection,
        response=response,
        error=error,
        block=block,
    )
    options: dict[str, object] = {}
    if event_id_factory is not None:
        options["event_id_factory"] = event_id_factory
    if snapshot_id_factory is not None:
        options["snapshot_id_factory"] = snapshot_id_factory
    service = SqliteCredentialValidationService(
        connection,
        transport=transport,
        persistent_key_store=store,
        provider_mode=provider_mode,  # type: ignore[arg-type]
        network_enabled=network_enabled,
        now_ms=lambda: NOW_MS,
        scanner=SecretScanner(canaries=(PROVIDER_BODY_CANARY, TRANSPORT_ERROR_CANARY)),
        repository=(_ReleaseFailingRepository(connection) if release_fails else None),
        dispatch_deadline_seconds=dispatch_deadline_seconds,
        lease_ttl_ms=lease_ttl_ms,
        **options,  # type: ignore[arg-type]
    )
    return connection, store, transport, service


def _request(generation: int = GENERATION) -> CredentialValidationRequest:
    return CredentialValidationRequest(expected_generation=generation)


def _database_text(connection: sqlite3.Connection) -> str:
    values: list[str] = []
    table_names = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    )
    for table_name in table_names:
        for row in connection.execute(f'SELECT * FROM "{table_name}"'):  # noqa: S608
            values.extend(str(value) for value in row if value is not None)
    return "\n".join(values)


def _exception_graph_text(exception: BaseException) -> str:
    pending = [exception]
    seen: set[int] = set()
    rendered: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered.append(f"{type(current).__name__}: {current!s}")
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(rendered)


@pytest.mark.asyncio
async def test_live_validation_dispatches_once_and_persists_only_sanitized_evidence(
    tmp_path: Path,
) -> None:
    connection, store, transport, service = await _service(tmp_path / "gatehouse.db")

    result = await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert result.credential_id == CREDENTIAL_ID
    assert result.generation == GENERATION
    assert result.service == "firecrawl"
    assert result.state == "authenticated"
    assert result.remaining_units == 41
    assert result.plan_total_units == 100
    assert result.observed_remaining_units_decimal == "41"
    assert result.observed_plan_total_units_decimal == "100"
    assert len(transport.requests) == 1
    provider_request = transport.requests[0]
    assert provider_request.method == "GET"
    assert provider_request.path == "/v2/team/credit-usage"
    assert provider_request.credential_id == CREDENTIAL_ID
    assert provider_request.credential_generation == GENERATION
    assert provider_request.json_body is None
    assert dict(provider_request.query) == {}
    assert provider_request.timeout_ms == 10_000
    assert provider_request.maximum_response_bytes == 64 * 1_024
    assert store.list_calls == 1
    assert store.open_calls == 0

    snapshot = connection.execute(
        "SELECT * FROM quota_snapshots WHERE snapshot_id = ?",
        (result.snapshot_id,),
    ).fetchone()
    assert snapshot is not None
    assert snapshot["quota_scope_id"] == SCOPE_ID
    assert snapshot["remaining_units"] == 41
    assert snapshot["plan_total_units"] == 100
    assert snapshot["observed_remaining_units_decimal"] == "41"
    assert snapshot["observed_plan_total_units_decimal"] == "100"
    assert snapshot["period_start_ms"] == 1_735_689_600_000
    assert snapshot["period_end_ms"] == 1_738_367_999_000
    assert snapshot["source"] == "admin-credential-validation"
    assert snapshot["observation_kind"] == "AUTHENTICATED"
    assert snapshot["credential_id"] == CREDENTIAL_ID
    assert snapshot["credential_generation"] == GENERATION
    assert snapshot["stale_at_ms"] == NOW_MS + 30 * 60 * 1_000
    assert json.loads(snapshot["metadata_json"]) == {}
    audit = connection.execute(
        "SELECT * FROM audit_events WHERE event_id = ?",
        (result.audit_event_id,),
    ).fetchone()
    assert audit is not None
    assert audit["event_type"] == "credential.provider_validated"
    assert audit["service_id"] == "firecrawl"
    assert audit["operation"] == "firecrawl.account.credit_status"
    assert audit["preserve"] == 1
    assert json.loads(audit["payload_json"]) == {
        "actor_id": ACTOR_ID,
        "credential_generation": GENERATION,
        "credential_id": CREDENTIAL_ID,
        "outcome": "authenticated",
        "principal_id": PRINCIPAL_ID,
        "quota_scope_id": SCOPE_ID,
        "snapshot_id": result.snapshot_id,
        "source": "admin-credential-validation",
    }
    lease = connection.execute(
        """
        SELECT state, generation, metadata_json
          FROM leases WHERE lease_type = 'provider-credential'
        """
    ).fetchone()
    assert lease is not None
    assert lease["state"] == "RELEASED"
    assert lease["generation"] == 2
    assert json.loads(lease["metadata_json"]) == {
        "credential_generation": GENERATION,
        "credential_id": CREDENTIAL_ID,
        "credential_validation": True,
    }
    assert connection.execute("SELECT COUNT(*) FROM invocations").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM external_resources").fetchone()[0] == 0
    assert PROVIDER_BODY_CANARY not in _database_text(connection)


@pytest.mark.asyncio
async def test_definitive_credit_status_exhaustion_is_durable_across_reopen(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gatehouse.db"
    connection, _, transport, service = await _service(
        database_path,
        response=ProviderResponse(status_code=402),
    )
    connection.execute(
        "UPDATE quota_scopes SET state = 'HEALTHY' WHERE quota_scope_id = ?",
        (SCOPE_ID,),
    )

    with pytest.raises(CredentialValidationProviderFailure) as captured:
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert captured.value.error_class is ProviderErrorClass.QUOTA_EXHAUSTED
    assert len(transport.requests) == 1
    assert (
        connection.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = ?",
            (SCOPE_ID,),
        ).fetchone()[0]
        == "EXHAUSTED"
    )
    connection.close()

    reopened = open_migrated_database(database_path)
    assert (
        reopened.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = ?",
            (SCOPE_ID,),
        ).fetchone()[0]
        == "EXHAUSTED"
    )
    event = reopened.execute(
        """
        SELECT new_state, reason_code, source_kind
          FROM quota_scope_state_events
         WHERE quota_scope_id = ? ORDER BY generation DESC LIMIT 1
        """,
        (SCOPE_ID,),
    ).fetchone()
    assert event is not None
    assert tuple(event) == ("EXHAUSTED", "OBSERVATION_QUOTA_EXHAUSTED", "PROVIDER_RESPONSE")
    reopened.close()


@pytest.mark.asyncio
async def test_fractional_negative_validation_persists_exact_observations_and_projections(
    tmp_path: Path,
) -> None:
    response = ProviderResponse(
        status_code=200,
        data={
            "success": True,
            "data": {
                "remainingCredits": parse_json_provider_number("-0.25"),
                "planCredits": parse_json_provider_number("100.999999999999999999"),
            },
        },
    )
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        response=response,
    )

    result = await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert len(transport.requests) == 1
    assert result.remaining_units == 0
    assert result.observed_remaining_units_decimal == "-0.25"
    assert result.plan_total_units == 100
    assert result.observed_plan_total_units_decimal == "100.999999999999999999"
    snapshot = connection.execute(
        "SELECT * FROM quota_snapshots WHERE snapshot_id = ?",
        (result.snapshot_id,),
    ).fetchone()
    assert snapshot is not None
    assert snapshot["remaining_units"] == 0
    assert snapshot["observed_remaining_units_decimal"] == "-0.25"
    assert snapshot["plan_total_units"] == 100
    assert snapshot["observed_plan_total_units_decimal"] == "100.999999999999999999"
    assert (
        connection.execute(
            "SELECT state FROM quota_scopes WHERE quota_scope_id = ?",
            (SCOPE_ID,),
        ).fetchone()[0]
        == "EXHAUSTED"
    )
    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("provider_mode", "network_enabled"),
    [
        ("disabled", False),
        ("disabled", True),
        ("scripted", False),
        ("scripted", True),
        ("live", False),
    ],
)
@pytest.mark.asyncio
async def test_non_live_or_network_disabled_modes_reject_before_any_dispatch_or_lease(
    tmp_path: Path,
    provider_mode: str,
    network_enabled: bool,
) -> None:
    connection, store, transport, service = await _service(
        tmp_path / "gatehouse.db",
        provider_mode=provider_mode,
        network_enabled=network_enabled,
    )

    with pytest.raises(CredentialValidationUnavailable):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert transport.requests == []
    assert store.list_calls == 0
    assert connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_live_validation_rejects_excessive_database_wait_before_lease_or_dispatch(
    tmp_path: Path,
) -> None:
    connection, store, transport, service = await _service(tmp_path / "gatehouse.db")
    connection.execute("PRAGMA busy_timeout = 6000")

    with pytest.raises(CredentialValidationUnavailable):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert transport.requests == []
    assert store.list_calls == 0
    assert connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("mutation", "arguments"),
    [
        (
            "UPDATE credentials SET generation = generation + 1 WHERE credential_id = ?",
            (CREDENTIAL_ID,),
        ),
        (
            "UPDATE credentials SET state = 'DRAINING' WHERE credential_id = ?",
            (CREDENTIAL_ID,),
        ),
        (
            "UPDATE credentials SET secret_backend = 'memory-test', "
            "secret_reference = 'memory://synthetic' WHERE credential_id = ?",
            (CREDENTIAL_ID,),
        ),
    ],
)
@pytest.mark.asyncio
async def test_exact_persistent_generation_is_revalidated_before_dispatch(
    tmp_path: Path,
    mutation: str,
    arguments: tuple[str, ...],
) -> None:
    connection, store, transport, service = await _service(tmp_path / "gatehouse.db")
    connection.execute(mutation, arguments)

    with pytest.raises(CredentialValidationUnavailable):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert transport.requests == []
    assert store.list_calls == 0
    assert connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_existing_exact_credential_lease_rejects_without_pool_or_failover(
    tmp_path: Path,
) -> None:
    connection, store, transport, service = await _service(tmp_path / "gatehouse.db")
    connection.execute(
        """
        INSERT INTO leases(
            lease_id, lease_type, lease_key, owner_id, state, generation,
            acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
        ) VALUES ('lease-existing', 'provider-credential', ?, 'another-owner',
                  'ACTIVE', 1, ?, ?, ?, ?)
        """,
        (
            f"{CREDENTIAL_ID}:{GENERATION}",
            NOW_MS,
            NOW_MS,
            NOW_MS + 60_000,
            json.dumps({"credential_id": CREDENTIAL_ID}),
        ),
    )

    with pytest.raises(CredentialValidationBusy):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert transport.requests == []
    assert store.list_calls == 0
    assert connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        pytest.param(
            ProviderResponse(
                status_code=200,
                data={
                    "success": True,
                    "data": {"remainingCredits": object.__new__(ExactProviderNumber)},
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
            id="uninitialized-exact-provider-wrapper",
        ),
        (
            ProviderResponse(
                status_code=401,
                data={"provider_detail": PROVIDER_BODY_CANARY},
                headers={"x-request-id": PROVIDER_BODY_CANARY},
                provider_request_id=PROVIDER_BODY_CANARY,
            ),
            ProviderErrorClass.UNAUTHORIZED,
        ),
        (
            ProviderResponse(
                status_code=200,
                data={
                    "success": True,
                    "data": {"remainingCredits": True},
                    "provider_detail": PROVIDER_BODY_CANARY,
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(
                status_code=200,
                data={
                    "success": True,
                    "data": {"remainingCredits": 1, "planCredits": None},
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(
                status_code=201,
                data={
                    "success": True,
                    "data": {"remainingCredits": 1},
                    "provider_detail": PROVIDER_BODY_CANARY,
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(
                status_code=201,
                data={
                    "success": True,
                    "data": {"remainingCredits": 1.5},
                    "provider_detail": PROVIDER_BODY_CANARY,
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(status_code=201),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(
                status_code=204,
                data={
                    "success": True,
                    "data": {"remainingCredits": 1},
                    "provider_detail": PROVIDER_BODY_CANARY,
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(
                status_code=204,
                data={
                    "success": True,
                    "data": {"remainingCredits": 1.5},
                    "provider_detail": PROVIDER_BODY_CANARY,
                },
            ),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
        (
            ProviderResponse(status_code=204),
            ProviderErrorClass.MALFORMED_RESPONSE,
        ),
    ],
)
@pytest.mark.asyncio
async def test_provider_failure_is_not_retried_and_persists_only_sanitized_audit(
    tmp_path: Path,
    response: ProviderResponse,
    expected: ProviderErrorClass,
) -> None:
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        response=response,
    )

    with pytest.raises(CredentialValidationProviderFailure) as captured:
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert captured.value.error_class is expected
    assert len(transport.requests) == 1
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 0
    audit = connection.execute("SELECT * FROM audit_events").fetchone()
    assert audit is not None
    assert audit["event_type"] == "credential.provider_validation_failed"
    assert audit["severity"] == "WARNING"
    assert audit["service_id"] == "firecrawl"
    assert audit["operation"] == "firecrawl.account.credit_status"
    assert audit["preserve"] == 1
    assert json.loads(audit["payload_json"]) == {
        "actor_id": ACTOR_ID,
        "credential_generation": GENERATION,
        "credential_id": CREDENTIAL_ID,
        "error_class": expected.value,
        "outcome": "failed",
    }
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
    assert PROVIDER_BODY_CANARY not in _database_text(connection)


@pytest.mark.asyncio
async def test_hostile_transport_error_is_removed_from_the_public_exception_graph(
    tmp_path: Path,
) -> None:
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        error=RuntimeError(TRANSPORT_ERROR_CANARY),
    )

    with pytest.raises(CredentialValidationUnavailable) as captured:
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert len(transport.requests) == 1
    assert TRANSPORT_ERROR_CANARY not in _exception_graph_text(captured.value)
    assert TRANSPORT_ERROR_CANARY not in _database_text(connection)
    audit = connection.execute("SELECT * FROM audit_events").fetchone()
    assert audit is not None
    assert audit["event_type"] == "credential.provider_validation_failed"
    assert audit["severity"] == "WARNING"
    assert json.loads(audit["payload_json"]) == {
        "actor_id": ACTOR_ID,
        "credential_generation": GENERATION,
        "credential_id": CREDENTIAL_ID,
        "error_class": ProviderErrorClass.UNKNOWN_OUTCOME.value,
        "outcome": "failed",
    }
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"


@pytest.mark.asyncio
async def test_transport_returning_no_response_records_unknown_outcome(
    tmp_path: Path,
) -> None:
    connection, _, transport, service = await _service(tmp_path / "gatehouse.db")
    transport.response = None  # type: ignore[assignment]

    with pytest.raises(CredentialValidationUnavailable):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert len(transport.requests) == 1
    audit = connection.execute("SELECT * FROM audit_events").fetchone()
    assert audit is not None
    assert json.loads(audit["payload_json"]) == {
        "actor_id": ACTOR_ID,
        "credential_generation": GENERATION,
        "credential_id": CREDENTIAL_ID,
        "error_class": ProviderErrorClass.UNKNOWN_OUTCOME.value,
        "outcome": "failed",
    }
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"


@pytest.mark.asyncio
async def test_single_process_slot_rejects_contention_without_queueing(
    tmp_path: Path,
) -> None:
    _, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        block=True,
    )
    first = asyncio.create_task(service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID))
    await asyncio.wait_for(transport.started.wait(), timeout=1)

    with pytest.raises(CredentialValidationBusy):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert len(transport.requests) == 1
    transport.release.set()
    result = await asyncio.wait_for(first, timeout=2)
    assert result.state == "authenticated"


@pytest.mark.asyncio
async def test_end_to_end_dispatch_deadline_releases_lease_and_records_only_failure_audit(
    tmp_path: Path,
) -> None:
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        block=True,
        dispatch_deadline_seconds=0.01,
        lease_ttl_ms=30_000,
    )

    with pytest.raises(CredentialValidationProviderFailure) as captured:
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert captured.value.error_class is ProviderErrorClass.TIMEOUT
    assert len(transport.requests) == 1
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 0
    audit = connection.execute("SELECT * FROM audit_events").fetchone()
    assert audit is not None
    assert audit["event_type"] == "credential.provider_validation_failed"
    assert json.loads(audit["payload_json"]) == {
        "actor_id": ACTOR_ID,
        "credential_generation": GENERATION,
        "credential_id": CREDENTIAL_ID,
        "error_class": ProviderErrorClass.TIMEOUT.value,
        "outcome": "failed",
    }


@pytest.mark.asyncio
async def test_cancellation_releases_the_exact_validation_lease(
    tmp_path: Path,
) -> None:
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        block=True,
    )
    task = asyncio.create_task(service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID))
    await asyncio.wait_for(transport.started.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert len(transport.requests) == 1
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_cancellation_is_preserved_when_lease_release_reports_failure(
    tmp_path: Path,
) -> None:
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        block=True,
        release_fails=True,
    )
    task = asyncio.create_task(service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID))
    await asyncio.wait_for(transport.started.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError) as captured:
        await task

    assert captured.value.__notes__ == ["credential validation lease release failed"]
    assert TRANSPORT_ERROR_CANARY not in _exception_graph_text(captured.value)
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "ACTIVE"


@pytest.mark.asyncio
async def test_in_flight_validation_lease_fences_rotation_until_transport_cleanup(
    tmp_path: Path,
) -> None:
    connection, store, transport, service = await _service(
        tmp_path / "gatehouse.db",
        block=True,
    )
    task = asyncio.create_task(service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID))
    await asyncio.wait_for(transport.started.wait(), timeout=1)
    lifecycle = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
    )
    replacement = bytearray(b"synthetic-validation-rotation-material")

    with pytest.raises(CredentialLifecycleConflict, match="not ready for rotation"):
        await lifecycle.rotate_credential(
            CREDENTIAL_ID,
            CredentialRotationRequest(
                mutation_id="mutation-validation-race",
                expires_at_ms=None,
            ),
            replacement,
            ACTOR_ID,
        )

    assert replacement == bytearray(len(replacement))
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "ACTIVE"
    transport.release.set()
    result = await asyncio.wait_for(task, timeout=2)
    assert result.state == "authenticated"
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"


@pytest.mark.asyncio
async def test_snapshot_and_audit_roll_back_together_on_audit_conflict(
    tmp_path: Path,
) -> None:
    duplicate_event_id = "evt_validation_duplicate"
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        event_id_factory=lambda: duplicate_event_id,
        snapshot_id_factory=lambda: "snapshot_validation_atomic",
    )
    connection.execute(
        """
        INSERT INTO audit_events(
            event_id, occurred_at_ms, event_type, severity, preserve, payload_json
        ) VALUES (?, ?, 'existing.event', 'INFO', 1, '{}')
        """,
        (duplicate_event_id, NOW_MS),
    )

    with pytest.raises(CredentialValidationPersistenceError):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert len(transport.requests) == 1
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 0
    scope = connection.execute(
        """
        SELECT last_known_remaining_units, last_refreshed_at_ms,
               balance_as_of_ms, balance_snapshot_id
          FROM quota_scopes WHERE quota_scope_id = ?
        """,
        (SCOPE_ID,),
    ).fetchone()
    assert tuple(scope) == (None, None, None, None)
    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"


@pytest.mark.asyncio
async def test_failure_audit_conflict_is_a_persistence_failure_without_retry(
    tmp_path: Path,
) -> None:
    duplicate_event_id = "evt_validation_failure_duplicate"
    connection, _, transport, service = await _service(
        tmp_path / "gatehouse.db",
        response=ProviderResponse(status_code=401),
        event_id_factory=lambda: duplicate_event_id,
    )
    connection.execute(
        """
        INSERT INTO audit_events(
            event_id, occurred_at_ms, event_type, severity, preserve, payload_json
        ) VALUES (?, ?, 'existing.event', 'INFO', 1, '{}')
        """,
        (duplicate_event_id, NOW_MS),
    )

    with pytest.raises(CredentialValidationPersistenceError):
        await service.validate_credential(CREDENTIAL_ID, _request(), ACTOR_ID)

    assert len(transport.requests) == 1
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
