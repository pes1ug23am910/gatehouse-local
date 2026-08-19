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

_SCRIPTED_SERVICE = "firecrawl"
_SCRIPTED_ALIAS = "gatehouse-scripted-no-network"
_SCRIPTED_REFERENCE = "builtin:no-network:v1"
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
                """,
                (str(principal), _SCRIPTED_SERVICE, _SCRIPTED_ALIAS),
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
                    last_refreshed_at_ms, metadata_json, balance_as_of_ms
                ) VALUES (?, ?, ?, 'HEALTHY', 'credits', 1000000, 0, ?,
                          '{"transport":"scripted","network":false}', ?)
                """,
                (str(scope), str(principal), _SCRIPTED_ALIAS, now, now),
            )
        else:
            valid = connection.execute(
                """
                SELECT 1 FROM quota_scopes
                 WHERE quota_scope_id = ? AND principal_id = ? AND alias = ?
                   AND state = 'HEALTHY' AND unit = 'credits'
                """,
                (str(scope), str(principal), _SCRIPTED_ALIAS),
            ).fetchone()
            if valid is None:
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
                """,
                (
                    str(credential),
                    str(principal),
                    str(scope),
                    _SCRIPTED_ALIAS,
                    _SCRIPTED_REFERENCE,
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
                    SELECT quota_scope_id FROM pool_members
                     WHERE pool_id = ? AND enabled = 1
                    """,
                    (str(pool),),
                ).fetchall()
                if connection.execute(
                    """
                        SELECT 1 FROM pools
                         WHERE pool_id = ? AND service_id = ? AND alias = ?
                           AND state = 'ACTIVE' AND selection_strategy = 'pinned'
                        """,
                    (str(pool), _SCRIPTED_SERVICE, alias),
                ).fetchone() is None or [str(row["quota_scope_id"]) for row in member_rows] != [
                    str(scope)
                ]:
                    raise RuntimeError("scripted provider pool conflicts with durable state")
            pools[alias] = pool
    return ScriptedRouteAuthority(
        principal_id=principal,
        quota_scope_id=scope,
        credential_id=credential,
        pool_ids_by_alias=pools,
    )
