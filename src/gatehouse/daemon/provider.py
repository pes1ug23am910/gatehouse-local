"""Provider-mode assembly helpers with an explicit no-network verification route."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock
from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.credentials import CredentialMetadata
from gatehouse.database import transaction
from gatehouse.database.repository import (
    BalanceAuthorityStatus,
    validate_balance_authority,
)

_SCRIPTED_SERVICE = "firecrawl"
_SCRIPTED_ALIAS = "gatehouse-scripted-no-network"
_SCRIPTED_REFERENCE = "builtin:no-network:v1"
_SCRIPTED_SNAPSHOT_ID = "snapshot_gatehouse_scripted_no_network_v1"
_SCRIPTED_SNAPSHOT_SOURCE = "scripted-no-network-synthetic"
_SCRIPTED_SNAPSHOT_METADATA = '{"network":false,"synthetic":true,"transport":"scripted"}'
_SCRIPTED_SCOPE_METADATA = '{"transport":"scripted","network":false}'
_SCRIPTED_CREDENTIAL_METADATA = '{"network":false}'
_SCRIPTED_POOL_CONFIG = '{"automatic_failover_within_pool":false,"minimum_remaining_floor_units":0}'
_SCRIPTED_REMAINING_UNITS = 1_000_000
_SCRIPTED_REMAINING_DECIMAL = "1000000"
_LIVE_CREDENTIAL_BACKEND = "dpapi-current-user"
_LIVE_REFERENCE_PREFIX = "dpapi-current-user://"


class LiveRouteCredentialError(RuntimeError):
    """An active live route cannot be proven to have valid DPAPI custody."""


class CredentialMetadataReader(Protocol):
    async def list_metadata(self) -> tuple[CredentialMetadata, ...]: ...


@dataclass(frozen=True, slots=True)
class ScriptedRouteAuthority:
    principal_id: PrincipalId
    quota_scope_id: QuotaScopeId
    credential_id: CredentialId
    pool_ids_by_alias: dict[str, PoolId]


async def validate_live_route_credentials(
    connection: sqlite3.Connection,
    *,
    key_store: CredentialMetadataReader,
) -> int:
    """Verify active live routes using non-secret DPAPI metadata only.

    This deliberately does not open a secret lease. ``list_metadata`` proves that
    both custody files exist and that each stored DPAPI reference is internally
    canonical; the comparisons below bind that custody metadata to the durable
    routing row before the daemon may report readiness.
    """

    rows = connection.execute(
        """
        SELECT DISTINCT c.credential_id, c.principal_id, c.quota_scope_id,
                        c.alias, c.secret_backend, c.secret_reference,
                        c.state, c.generation, c.expires_at_ms
          FROM pools AS p
          JOIN pool_members AS pm ON pm.pool_id = p.pool_id
          JOIN credentials AS c ON c.quota_scope_id = pm.quota_scope_id
         WHERE p.state IN ('ACTIVE', 'ENABLED')
           AND pm.enabled = 1
           AND c.state = 'HEALTHY'
           AND c.credential_role IN ('WORKLOAD', 'INFERENCE')
         ORDER BY c.credential_id
        """
    ).fetchall()
    try:
        listed = await key_store.list_metadata()
    except Exception as error:
        raise LiveRouteCredentialError(
            "live credential custody metadata could not be verified"
        ) from error

    by_credential_id: dict[str, CredentialMetadata] = {}
    for stored_metadata in listed:
        if stored_metadata.credential_id in by_credential_id:
            raise LiveRouteCredentialError(
                "live credential custody metadata contains a duplicate identifier"
            )
        by_credential_id[stored_metadata.credential_id] = stored_metadata

    for row in rows:
        credential_id = str(row["credential_id"])
        expected_reference = (
            _LIVE_REFERENCE_PREFIX + hashlib.sha256(credential_id.encode("utf-8")).hexdigest()
        )
        if (
            str(row["secret_backend"]) != _LIVE_CREDENTIAL_BACKEND
            or str(row["secret_reference"]) != expected_reference
        ):
            raise LiveRouteCredentialError(
                "an active live route is not backed by a canonical DPAPI reference"
            )

        metadata = by_credential_id.get(credential_id)
        if metadata is None:
            raise LiveRouteCredentialError(
                "an active live route has no matching credential custody entry"
            )
        durable_expires_at = None if row["expires_at_ms"] is None else int(row["expires_at_ms"])
        if (
            metadata.principal_id != str(row["principal_id"])
            or metadata.quota_scope_id != str(row["quota_scope_id"])
            or metadata.alias != str(row["alias"])
            or metadata.state != str(row["state"])
            or metadata.generation != int(row["generation"])
            or metadata.secret_reference != expected_reference
            or metadata.expires_at_ms != durable_expires_at
        ):
            raise LiveRouteCredentialError(
                "an active live route does not match its credential custody metadata"
            )
    return len(rows)


def _existing_identifier(
    connection: sqlite3.Connection,
    *,
    table: str,
    id_column: str,
    predicate: str,
    parameters: tuple[object, ...],
) -> str | None:
    if table not in {"principals", "quota_scopes", "credentials", "pools"}:
        raise ValueError("unsupported scripted authority table")
    row = connection.execute(
        f"SELECT {id_column} FROM {table} WHERE {predicate}",  # noqa: S608
        parameters,
    ).fetchone()
    return None if row is None else str(row[id_column])


def synchronize_scripted_routes(
    connection: sqlite3.Connection,
    *,
    pool_aliases: Iterable[str],
    clock: UtcMsClock = SYSTEM_UTC_CLOCK,
) -> ScriptedRouteAuthority:
    """Create only synthetic, credential-free authority for explicit scripted mode."""

    aliases = tuple(sorted(set(pool_aliases)))
    if not aliases or any(not alias or len(alias) > 160 for alias in aliases):
        raise ValueError("scripted provider requires bounded named pools")
    now = clock.now_ms()
    pools: dict[str, PoolId] = {}
    with transaction(connection, "IMMEDIATE"):
        principal_raw = _existing_identifier(
            connection,
            table="principals",
            id_column="principal_id",
            predicate="service_id = ? AND alias = ?",
            parameters=(_SCRIPTED_SERVICE, _SCRIPTED_ALIAS),
        )
        principal = (
            PrincipalId(principal_raw)
            if principal_raw is not None
            else PrincipalId.new(clock=clock)
        )
        if principal_raw is None:
            connection.execute(
                """
                INSERT INTO principals(
                    principal_id, service_id, alias, enabled,
                    metadata_json, created_at_ms, updated_at_ms
                ) VALUES (?, ?, ?, 1, '{"transport":"scripted","network":false}', ?, ?)
                """,
                (str(principal), _SCRIPTED_SERVICE, _SCRIPTED_ALIAS, now, now),
            )
        else:
            valid = connection.execute(
                """
                SELECT 1 FROM principals
                 WHERE principal_id = ? AND service_id = ? AND alias = ? AND enabled = 1
                   AND metadata_json = ?
                """,
                (
                    str(principal),
                    _SCRIPTED_SERVICE,
                    _SCRIPTED_ALIAS,
                    _SCRIPTED_SCOPE_METADATA,
                ),
            ).fetchone()
            if valid is None:
                raise RuntimeError("scripted provider principal conflicts with durable state")

        scope_raw = _existing_identifier(
            connection,
            table="quota_scopes",
            id_column="quota_scope_id",
            predicate="principal_id = ? AND alias = ?",
            parameters=(str(principal), _SCRIPTED_ALIAS),
        )
        scope = QuotaScopeId(scope_raw) if scope_raw is not None else QuotaScopeId.new(clock=clock)
        if scope_raw is None:
            connection.execute(
                """
                INSERT INTO quota_scopes(
                    quota_scope_id, principal_id, alias, state, unit,
                    last_known_remaining_units, configured_floor_units,
                    last_refreshed_at_ms, metadata_json, balance_as_of_ms,
                    balance_snapshot_id
                ) VALUES (?, ?, ?, 'HEALTHY', 'credits', NULL, 0, NULL, ?, NULL, NULL)
                """,
                (str(scope), str(principal), _SCRIPTED_ALIAS, _SCRIPTED_SCOPE_METADATA),
            )
        else:
            valid = connection.execute(
                """
                SELECT 1 FROM quota_scopes
                 WHERE quota_scope_id = ? AND principal_id = ? AND alias = ?
                   AND state = 'HEALTHY' AND unit = 'credits'
                   AND configured_floor_units = 0
                   AND metadata_json = ?
                """,
                (str(scope), str(principal), _SCRIPTED_ALIAS, _SCRIPTED_SCOPE_METADATA),
            ).fetchone()
            if valid is None:
                raise RuntimeError("scripted provider quota scope conflicts with durable state")

        scope_balance = connection.execute(
            """
            SELECT last_known_remaining_units, balance_as_of_ms,
                   balance_snapshot_id, last_refreshed_at_ms
              FROM quota_scopes
             WHERE quota_scope_id = ?
            """,
            (str(scope),),
        ).fetchone()
        assert scope_balance is not None
        dimension_id = f"dimension_legacy_primary:{scope}"
        last_refreshed_at_ms = scope_balance["last_refreshed_at_ms"]
        if last_refreshed_at_ms is not None and (
            type(last_refreshed_at_ms) is not int or last_refreshed_at_ms < 0
        ):
            raise RuntimeError("scripted provider quota scope conflicts with durable state")
        if (
            connection.execute(
                """
            SELECT 1
              FROM quota_snapshots
             WHERE snapshot_id != ?
               AND (source = ? OR metadata_json = ?)
             LIMIT 1
            """,
                (
                    _SCRIPTED_SNAPSHOT_ID,
                    _SCRIPTED_SNAPSHOT_SOURCE,
                    _SCRIPTED_SNAPSHOT_METADATA,
                ),
            ).fetchone()
            is not None
        ):
            raise RuntimeError("scripted provider snapshot conflicts with durable state")
        snapshot = connection.execute(
            """
            SELECT snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                   observed_remaining_units_decimal,
                   observed_plan_total_units_decimal, unit, period_start_ms,
                   period_end_ms, captured_at_ms, source, metadata_json,
                   quota_dimension_id, credential_id, credential_generation,
                   stale_at_ms, observation_kind, used_units,
                   observed_used_units_decimal
              FROM quota_snapshots
             WHERE snapshot_id = ?
            """,
            (_SCRIPTED_SNAPSHOT_ID,),
        ).fetchone()
        if snapshot is None:
            snapshot_captured_at_ms = (
                now
                if scope_raw is None
                else (0 if last_refreshed_at_ms is None else last_refreshed_at_ms)
            )
            connection.execute(
                """
                INSERT INTO quota_snapshots(
                    snapshot_id, quota_scope_id, remaining_units, plan_total_units,
                    unit, period_start_ms, period_end_ms, captured_at_ms, source,
                    metadata_json, observed_remaining_units_decimal,
                    observed_plan_total_units_decimal, quota_dimension_id,
                    observation_kind
                ) VALUES (
                    ?, ?, ?, NULL, 'credits', NULL, NULL, ?, ?, ?, ?, NULL, ?, 'SCRIPTED'
                )
                """,
                (
                    _SCRIPTED_SNAPSHOT_ID,
                    str(scope),
                    _SCRIPTED_REMAINING_UNITS,
                    snapshot_captured_at_ms,
                    _SCRIPTED_SNAPSHOT_SOURCE,
                    _SCRIPTED_SNAPSHOT_METADATA,
                    _SCRIPTED_REMAINING_DECIMAL,
                    dimension_id,
                ),
            )
        else:
            snapshot_captured_at_ms = snapshot["captured_at_ms"]
            if (
                type(snapshot_captured_at_ms) is not int
                or snapshot["snapshot_id"] != _SCRIPTED_SNAPSHOT_ID
                or snapshot["quota_scope_id"] != str(scope)
                or snapshot["remaining_units"] != _SCRIPTED_REMAINING_UNITS
                or snapshot["plan_total_units"] is not None
                or snapshot["observed_remaining_units_decimal"] != _SCRIPTED_REMAINING_DECIMAL
                or snapshot["observed_plan_total_units_decimal"] is not None
                or snapshot["unit"] != "credits"
                or snapshot["period_start_ms"] is not None
                or snapshot["period_end_ms"] is not None
                or snapshot["source"] != _SCRIPTED_SNAPSHOT_SOURCE
                or snapshot["metadata_json"] != _SCRIPTED_SNAPSHOT_METADATA
                or snapshot["quota_dimension_id"] != dimension_id
                or snapshot["credential_id"] is not None
                or snapshot["credential_generation"] is not None
                or snapshot["stale_at_ms"] is not None
                or snapshot["observation_kind"] != "SCRIPTED"
                or snapshot["used_units"] is not None
                or snapshot["observed_used_units_decimal"] is not None
            ):
                raise RuntimeError("scripted provider snapshot conflicts with durable state")

        snapshot_authority = validate_balance_authority(
            connection,
            quota_scope_id=str(scope),
            unit="credits",
            last_known_remaining_units=_SCRIPTED_REMAINING_UNITS,
            balance_as_of_ms=snapshot_captured_at_ms,
            balance_snapshot_id=_SCRIPTED_SNAPSHOT_ID,
            now_ms=now,
        )
        authority = snapshot_authority.authority
        if snapshot_authority.status is not BalanceAuthorityStatus.VALID or authority is None:
            raise RuntimeError("scripted provider snapshot conflicts with durable state")
        triplet = (
            scope_balance["last_known_remaining_units"],
            scope_balance["balance_as_of_ms"],
            scope_balance["balance_snapshot_id"],
        )
        if triplet == (None, None, None):
            connection.execute(
                """
                UPDATE quota_scopes
                   SET last_known_remaining_units = ?,
                       balance_as_of_ms = ?,
                       balance_snapshot_id = ?,
                       last_refreshed_at_ms = COALESCE(last_refreshed_at_ms, ?)
                 WHERE quota_scope_id = ?
                """,
                (
                    authority.remaining_units,
                    authority.balance_as_of_ms,
                    authority.snapshot_id,
                    authority.balance_as_of_ms,
                    str(scope),
                ),
            )
        elif triplet != (
            authority.remaining_units,
            authority.balance_as_of_ms,
            authority.snapshot_id,
        ):
            raise RuntimeError("scripted provider quota scope conflicts with durable state")

        credential_raw = _existing_identifier(
            connection,
            table="credentials",
            id_column="credential_id",
            predicate="secret_backend = 'scripted' AND secret_reference = ?",
            parameters=(_SCRIPTED_REFERENCE,),
        )
        credential = (
            CredentialId(credential_raw)
            if credential_raw is not None
            else CredentialId.new(clock=clock)
        )
        if credential_raw is None:
            connection.execute(
                """
                INSERT INTO credentials(
                    credential_id, principal_id, quota_scope_id, alias,
                    secret_backend, secret_reference, state, generation,
                    exclusive_usage, created_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, 'scripted', ?, 'HEALTHY', 1, 1, ?,
                          '{"network":false}')
                """,
                (
                    str(credential),
                    str(principal),
                    str(scope),
                    _SCRIPTED_ALIAS,
                    _SCRIPTED_REFERENCE,
                    now,
                ),
            )
        else:
            valid = connection.execute(
                """
                SELECT 1 FROM credentials
                 WHERE credential_id = ? AND principal_id = ? AND quota_scope_id = ?
                   AND alias = ? AND state = 'HEALTHY' AND generation = 1
                   AND secret_backend = 'scripted' AND secret_reference = ?
                   AND exclusive_usage = 1 AND expires_at_ms IS NULL
                   AND metadata_json = ?
                """,
                (
                    str(credential),
                    str(principal),
                    str(scope),
                    _SCRIPTED_ALIAS,
                    _SCRIPTED_REFERENCE,
                    _SCRIPTED_CREDENTIAL_METADATA,
                ),
            ).fetchone()
            if valid is None:
                raise RuntimeError("scripted provider credential conflicts with durable state")

        for alias in aliases:
            pool_raw = _existing_identifier(
                connection,
                table="pools",
                id_column="pool_id",
                predicate="service_id = ? AND alias = ?",
                parameters=(_SCRIPTED_SERVICE, alias),
            )
            pool = PoolId(pool_raw) if pool_raw is not None else PoolId.new(clock=clock)
            if pool_raw is None:
                connection.execute(
                    """
                    INSERT INTO pools(
                        pool_id, service_id, alias, state, selection_strategy,
                        automatic_use, config_json
                    ) VALUES (?, ?, ?, 'ACTIVE', 'pinned', 1,
                              '{"automatic_failover_within_pool":false,"minimum_remaining_floor_units":0}')
                    """,
                    (str(pool), _SCRIPTED_SERVICE, alias),
                )
                connection.execute(
                    """
                    INSERT INTO pool_members(
                        pool_id, quota_scope_id, priority, cost_rank, enabled
                    ) VALUES (?, ?, 1, 1, 1)
                    """,
                    (str(pool), str(scope)),
                )
            else:
                member_rows = connection.execute(
                    """
                    SELECT quota_scope_id, priority, cost_rank, enabled
                      FROM pool_members
                     WHERE pool_id = ?
                     ORDER BY quota_scope_id
                    """,
                    (str(pool),),
                ).fetchall()
                if connection.execute(
                    """
                        SELECT 1 FROM pools
                         WHERE pool_id = ? AND service_id = ? AND alias = ?
                            AND state = 'ACTIVE' AND selection_strategy = 'pinned'
                            AND automatic_use = 1 AND config_json = ?
                         """,
                    (str(pool), _SCRIPTED_SERVICE, alias, _SCRIPTED_POOL_CONFIG),
                ).fetchone() is None or [
                    (
                        str(row["quota_scope_id"]),
                        row["priority"],
                        row["cost_rank"],
                        row["enabled"],
                    )
                    for row in member_rows
                ] != [(str(scope), 1, 1, 1)]:
                    raise RuntimeError("scripted provider pool conflicts with durable state")
            pools[alias] = pool
    return ScriptedRouteAuthority(
        principal_id=principal,
        quota_scope_id=scope,
        credential_id=credential,
        pool_ids_by_alias=pools,
    )
