"""Live SQLite-backed routing catalog with fail-closed row validation."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable

from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.core.provider_numbers import require_sqlite_int64
from gatehouse.core.states import CredentialState
from gatehouse.database.repository import (
    BalanceAuthorityStatus,
    validate_balance_authority,
)

from .affinity import ResourceAffinity
from .models import (
    NamedPool,
    PoolMember,
    PoolSelectionStrategy,
    QuotaScopeSnapshot,
    QuotaScopeState,
    RoutingCredential,
    RoutingPlan,
)
from .retry import CircuitBreakerRegistry
from .router import NamedPoolRouter, NoEligiblePoolError


class SqliteRoutingCatalog:
    """Rebuild the selected pool for every plan so quarantine takes effect at once."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        circuit_breakers: CircuitBreakerRegistry | None = None,
    ) -> None:
        self._connection = connection
        self._circuit_breakers = circuit_breakers

    @staticmethod
    def _config(raw: str) -> tuple[bool, int]:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("pool configuration is invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("pool configuration is invalid")
        allowed = {
            "automatic_failover_within_pool",
            "minimum_remaining_floor_units",
        }
        if set(value) - allowed:
            raise ValueError("pool configuration contains unsupported fields")
        failover = value.get("automatic_failover_within_pool", True)
        raw_floor = value.get("minimum_remaining_floor_units", 0)
        if not isinstance(failover, bool):
            raise ValueError("pool failover configuration is invalid")
        try:
            floor = require_sqlite_int64(
                raw_floor,
                field="pool floor configuration",
                minimum=0,
            )
        except ValueError as exc:
            raise ValueError("pool floor configuration is invalid") from exc
        return failover, floor

    def _committed_units(self, scope_id: str, balance_as_of_ms: int | None) -> int:
        return int(
            self._connection.execute(
                """
                SELECT COALESCE(SUM(
                           CASE
                               WHEN state IN (
                                   'ACTIVE', 'PENDING_RECONCILIATION', 'DISPUTED'
                               ) THEN amount_units
                               WHEN state = 'RECONCILED'
                                AND actual_units IS NOT NULL
                                AND (? IS NULL OR reconciled_at_ms > ?)
                               THEN actual_units
                               ELSE 0
                           END
                       ), 0)
                  FROM quota_reservations
                 WHERE quota_scope_id = ?
                """,
                (balance_as_of_ms, balance_as_of_ms, scope_id),
            ).fetchone()[0]
        )

    def _load_pool(self, *, service_id: str, pool_name: str, now_ms: int) -> NamedPool:
        pool = self._connection.execute(
            """
            SELECT pool_id, service_id, alias, state, selection_strategy,
                   automatic_use, config_json
              FROM pools
             WHERE service_id = ? AND alias = ?
            """,
            (service_id, pool_name),
        ).fetchone()
        if pool is None or str(pool["state"]).upper() not in {"ACTIVE", "ENABLED"}:
            raise NoEligiblePoolError("the selected named pool is unavailable")
        failover, minimum_floor = self._config(str(pool["config_json"]))
        rows = self._connection.execute(
            """
            SELECT pm.priority, pm.cost_rank, pm.enabled,
                   qs.quota_scope_id, qs.principal_id, qs.state AS scope_state,
                   qs.unit, qs.last_known_remaining_units,
                   qs.configured_floor_units, qs.balance_as_of_ms,
                   qs.balance_snapshot_id
              FROM pool_members AS pm
              JOIN quota_scopes AS qs ON qs.quota_scope_id = pm.quota_scope_id
             WHERE pm.pool_id = ?
             ORDER BY pm.priority, pm.cost_rank, pm.quota_scope_id
            """,
            (pool["pool_id"],),
        ).fetchall()
        members: list[PoolMember] = []
        for row in rows:
            scope_id = QuotaScopeId(str(row["quota_scope_id"]))
            principal_id = PrincipalId(str(row["principal_id"]))
            credentials = self._connection.execute(
                """
                SELECT credential_id, principal_id, quota_scope_id, state,
                       generation, expires_at_ms
                  FROM credentials
                 WHERE quota_scope_id = ?
                   AND credential_role = 'WORKLOAD'
                 ORDER BY generation DESC, credential_id
                """,
                (str(scope_id),),
            ).fetchall()
            typed_credentials = tuple(
                RoutingCredential(
                    credential_id=CredentialId(str(item["credential_id"])),
                    principal_id=PrincipalId(str(item["principal_id"])),
                    quota_scope_id=QuotaScopeId(str(item["quota_scope_id"])),
                    state=CredentialState(str(item["state"])),
                    generation=int(item["generation"]),
                    expires_at_ms=(
                        int(item["expires_at_ms"]) if item["expires_at_ms"] is not None else None
                    ),
                )
                for item in credentials
            )
            if not typed_credentials:
                continue
            validation = validate_balance_authority(
                self._connection,
                quota_scope_id=row["quota_scope_id"],
                unit=row["unit"],
                last_known_remaining_units=row["last_known_remaining_units"],
                balance_as_of_ms=row["balance_as_of_ms"],
                balance_snapshot_id=row["balance_snapshot_id"],
                now_ms=now_ms,
            )
            authority = validation.authority
            balance_as_of_ms = None if authority is None else authority.balance_as_of_ms
            authority_corrupt = validation.status is BalanceAuthorityStatus.CORRUPT
            members.append(
                PoolMember(
                    scope=QuotaScopeSnapshot(
                        quota_scope_id=scope_id,
                        principal_id=principal_id,
                        service_id=str(pool["service_id"]),
                        unit=str(row["unit"]),
                        state=QuotaScopeState(str(row["scope_state"])),
                        last_known_remaining_units=(
                            authority.remaining_units if authority is not None else None
                        ),
                        configured_floor_units=int(row["configured_floor_units"]),
                        active_reserved_units=self._committed_units(str(scope_id), balance_as_of_ms)
                        if authority is not None
                        else 0,
                        cooldown_until_ms=None,
                    ),
                    credentials=typed_credentials,
                    priority=int(row["priority"]),
                    cost_rank=int(row["cost_rank"]),
                    enabled=bool(row["enabled"]),
                    balance_authority_corrupt=authority_corrupt,
                )
            )
        if not members:
            raise NoEligiblePoolError("the selected named pool has no configured members")
        return NamedPool(
            pool_id=PoolId(str(pool["pool_id"])),
            name=str(pool["alias"]),
            service_id=str(pool["service_id"]),
            selection_strategy=PoolSelectionStrategy(str(pool["selection_strategy"])),
            members=tuple(members),
            automatic_failover_within_pool=failover,
            automatic_use=bool(pool["automatic_use"]),
            minimum_remaining_floor_units=minimum_floor,
        )

    def plan(
        self,
        *,
        service_id: str,
        operation: str,
        pool_name: str,
        estimated_cost_units: int,
        unit: str,
        now_ms: int,
        affinity: ResourceAffinity | None = None,
        automatic: bool = True,
        reconciliation: bool = False,
    ) -> RoutingPlan:
        estimated_cost_units = require_sqlite_int64(
            estimated_cost_units,
            field="estimated_cost_units",
            minimum=0,
        )
        pool = self._load_pool(service_id=service_id, pool_name=pool_name, now_ms=now_ms)
        return NamedPoolRouter(
            (pool,),
            circuit_breakers=self._circuit_breakers,
        ).plan(
            service_id=service_id,
            operation=operation,
            pool_name=pool_name,
            estimated_cost_units=estimated_cost_units,
            unit=unit,
            now_ms=now_ms,
            affinity=affinity,
            automatic=automatic,
            reconciliation=reconciliation,
        )

    def validate(self, *, now_ms: int) -> int:
        rows: Iterable[sqlite3.Row] = self._connection.execute(
            """
            SELECT service_id, alias FROM pools
             WHERE state IN ('ACTIVE', 'ENABLED') AND automatic_use = 1
            """
        )
        count = 0
        for row in rows:
            self._load_pool(
                service_id=str(row["service_id"]),
                pool_name=str(row["alias"]),
                now_ms=now_ms,
            )
            count += 1
        return count
