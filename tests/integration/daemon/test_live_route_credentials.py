from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.core.clock import SYSTEM_UTC_CLOCK
from gatehouse.credentials import CredentialMetadata
from gatehouse.daemon import composition, installation_state_paths, load_runtime_configuration
from gatehouse.daemon.provider import (
    LiveRouteCredentialError,
    validate_live_route_credentials,
)
from gatehouse.database import open_migrated_database
from gatehouse.state_security import secure_private_directory, secure_private_file

_A = "01K32J0B80E4G7P6H9Q2R5T8VW"
_CREDENTIAL_ID = f"cred_{_A}"
_PRINCIPAL_ID = f"prn_{_A}"
_QUOTA_SCOPE_ID = f"quota_{_A}"
_REFERENCE = "dpapi-current-user://" + hashlib.sha256(_CREDENTIAL_ID.encode("utf-8")).hexdigest()


class MetadataReader:
    def __init__(self, *metadata: CredentialMetadata) -> None:
        self._metadata = metadata
        self.calls = 0

    async def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        self.calls += 1
        return self._metadata


def _metadata() -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=_CREDENTIAL_ID,
        principal_id=_PRINCIPAL_ID,
        quota_scope_id=_QUOTA_SCOPE_ID,
        alias="primary",
        state="HEALTHY",
        generation=3,
        secret_reference=_REFERENCE,
        expires_at_ms=10_000,
    )


def _seed_route(
    connection: sqlite3.Connection,
    *,
    backend: str = "dpapi-current-user",
    reference: str = _REFERENCE,
    credential_state: str = "HEALTHY",
) -> None:
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'primary', 1, 1)
        """,
        (_PRINCIPAL_ID,),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES (?, ?, 'primary', 'HEALTHY', 'credits', NULL, 0)
        """,
        (_QUOTA_SCOPE_ID, _PRINCIPAL_ID),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation,
            expires_at_ms, created_at_ms
        ) VALUES (?, ?, ?, 'primary', ?, ?, ?, 3, 10000, 1)
        """,
        (
            _CREDENTIAL_ID,
            _PRINCIPAL_ID,
            _QUOTA_SCOPE_ID,
            backend,
            reference,
            credential_state,
        ),
    )
    connection.execute(
        """
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units, unit,
            captured_at_ms, source, observed_remaining_units_decimal,
            quota_dimension_id, credential_id, credential_generation,
            stale_at_ms, observation_kind
        ) VALUES ('snapshot-live-route-credentials', ?, 100, 'credits', 1,
                  'integration-test', '100', ?, ?, 3, 10000, 'AUTHENTICATED')
        """,
        (
            _QUOTA_SCOPE_ID,
            f"dimension_legacy_primary:{_QUOTA_SCOPE_ID}",
            _CREDENTIAL_ID,
        ),
    )
    connection.execute(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = 100,
               balance_as_of_ms = 1,
               balance_snapshot_id = 'snapshot-live-route-credentials'
         WHERE quota_scope_id = ?
        """,
        (_QUOTA_SCOPE_ID,),
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy,
            automatic_use, config_json
        ) VALUES (?, 'firecrawl', 'interactive-default', 'ACTIVE',
                  'pinned', 1,
                  '{"automatic_failover_within_pool":false,"minimum_remaining_floor_units":0}')
        """,
        (f"pool_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
        VALUES (?, ?, 1, 1, 1)
        """,
        (f"pool_{_A}", _QUOTA_SCOPE_ID),
    )


@pytest.mark.asyncio
async def test_live_route_accepts_only_exact_dpapi_keystore_metadata(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "valid-live-route.db")
    try:
        _seed_route(connection)
        reader = MetadataReader(_metadata())

        assert (
            await validate_live_route_credentials(
                connection,
                key_store=reader,
            )
            == 1
        )
        assert reader.calls == 1
    finally:
        connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reader", "backend", "reference"),
    [
        (MetadataReader(_metadata()), "scripted", _REFERENCE),
        (MetadataReader(), "dpapi-current-user", _REFERENCE),
        (
            MetadataReader(_metadata()),
            "dpapi-current-user",
            "dpapi-current-user://" + ("0" * 64),
        ),
        (
            MetadataReader(replace(_metadata(), generation=2)),
            "dpapi-current-user",
            _REFERENCE,
        ),
        (
            MetadataReader(replace(_metadata(), principal_id=f"prn_{'2' * 26}")),
            "dpapi-current-user",
            _REFERENCE,
        ),
        (
            MetadataReader(replace(_metadata(), state="DISABLED")),
            "dpapi-current-user",
            _REFERENCE,
        ),
    ],
    ids=(
        "non-dpapi-backend",
        "missing-custody-entry",
        "noncanonical-reference",
        "generation-mismatch",
        "principal-mismatch",
        "state-mismatch",
    ),
)
async def test_live_route_rejects_non_dpapi_or_mismatched_custody(
    tmp_path: Path,
    reader: MetadataReader,
    backend: str,
    reference: str,
) -> None:
    connection = open_migrated_database(tmp_path / "invalid-live-route.db")
    try:
        _seed_route(connection, backend=backend, reference=reference)

        with pytest.raises(LiveRouteCredentialError):
            await validate_live_route_credentials(connection, key_store=reader)
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_live_route_validation_ignores_non_routed_or_inactive_credentials(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "inactive-live-route.db")
    try:
        _seed_route(
            connection,
            backend="scripted",
            reference="builtin:no-network:v1",
            credential_state="DISABLED",
        )
        reader = MetadataReader()

        assert (
            await validate_live_route_credentials(
                connection,
                key_store=reader,
            )
            == 0
        )
        assert reader.calls == 1
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_live_transport_composition_runs_custody_validation_before_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).parents[3] / "config" / "config.example.yaml"
    config_root = tmp_path / "configuration"
    secure_private_directory(config_root)
    config_path = config_root / "config.yaml"
    database_path = tmp_path / "state" / "gatehouse.db"
    document = source.read_text(encoding="utf-8").replace(
        r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
        f"'{database_path.as_posix()}'",
    )
    document = document.replace(
        "    workload:\n      mode: disabled\n      network_enabled: false",
        "    workload:\n      mode: live\n      network_enabled: true",
    )
    config_path.write_text(document, encoding="utf-8")
    secure_private_file(config_path)
    configuration = load_runtime_configuration(config_path)
    connection = open_migrated_database(database_path)
    reader = MetadataReader()
    observed: list[object] = []

    async def reject_live_routes(
        candidate: sqlite3.Connection,
        *,
        key_store: object,
    ) -> int:
        assert candidate is connection
        observed.append(key_store)
        raise LiveRouteCredentialError("test rejection")

    monkeypatch.setattr(
        composition,
        "DpapiCurrentUserKeyStore",
        lambda _path: reader,
    )
    monkeypatch.setattr(
        composition,
        "validate_live_route_credentials",
        reject_live_routes,
        raising=False,
    )
    try:
        with pytest.raises(LiveRouteCredentialError, match="test rejection"):
            await composition._provider_transport(
                configuration,
                config_path=config_path,
                connection=connection,
                state_paths=installation_state_paths(database_path),
                clock=SYSTEM_UTC_CLOCK,
            )
        assert observed == [reader]
    finally:
        connection.close()
