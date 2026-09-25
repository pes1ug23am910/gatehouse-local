"""Explicit metadata-only named-pool administration with atomic audit evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable

from gatehouse.core.clock import require_utc_ms
from gatehouse.database import transaction
from gatehouse.routing.catalog import SqliteRoutingCatalog

from .models import PoolFailoverChangeRequest, PoolFailoverMutationResult


class PoolMutationConflict(RuntimeError):
    """The requested pool authority or idempotency binding is unavailable."""


class SqlitePoolAdminService:
    """Never creates a pool, credential, provider request, or network permission."""

    def __init__(self, connection: sqlite3.Connection, *, now_ms: Callable[[], int]) -> None:
        self._connection = connection
        self._now_ms = now_ms

    async def change_pool_failover(
        self,
        alias: str,
        request: PoolFailoverChangeRequest,
        actor_id: str,
    ) -> PoolFailoverMutationResult:
        # Revalidate even callers that bypass normal Pydantic construction.
        request = PoolFailoverChangeRequest.model_validate(request.model_dump())
        now = self._now_ms()
        require_utc_ms(now)
        audit_id = f"evt_{uuid.uuid4().hex}"
        result = PoolFailoverMutationResult(
            pool_alias=alias,
            action=request.action,
            enabled=request.action == "enable",
            acted_at_ms=now,
            audit_event_id=audit_id,
        )
        if type(actor_id) is not str or not actor_id.strip() or len(actor_id) > 160:
            raise ValueError("pool mutation actor is invalid")
        reason_fingerprint = hashlib.sha256(
            b"gatehouse/pool-failover-reason/v1\x00" + request.reason.encode("utf-8")
        ).hexdigest()
        binding = {
            "pool_alias": alias,
            "action": request.action,
            "reason_fingerprint": reason_fingerprint,
        }
        binding_json = json.dumps(binding, sort_keys=True, separators=(",", ":"))
        operation = "pool.failover.changed"
        with transaction(self._connection, "IMMEDIATE"):
            row = self._connection.execute(
                "SELECT operation, actor_id, state, metadata_json, result_json "
                "FROM credential_mutations WHERE mutation_id = ?",
                (request.mutation_id,),
            ).fetchone()
            if row is not None:
                if (
                    row["operation"] != operation
                    or row["actor_id"] != actor_id
                    or row["state"] != "COMMITTED"
                    or row["metadata_json"] != binding_json
                ):
                    raise PoolMutationConflict("pool mutation identifier is already bound")
                completed = PoolFailoverMutationResult.model_validate_json(row["result_json"])
                if completed.pool_alias != alias or completed.action != request.action:
                    raise PoolMutationConflict("pool mutation result does not match its binding")
                return completed
            pool = self._connection.execute(
                "SELECT pool_id, state, automatic_use, selection_strategy, config_json "
                "FROM pools WHERE service_id = 'firecrawl' AND alias = ?",
                (alias,),
            ).fetchone()
            if (
                pool is None
                or pool["state"] not in {"ACTIVE", "ENABLED"}
                or pool["automatic_use"] != 1
                or pool["selection_strategy"] not in {"fill_first", "cheapest_first"}
            ):
                raise PoolMutationConflict("the selected ordinary pool is unavailable")
            SqliteRoutingCatalog._config(pool["config_json"])
            config = json.loads(pool["config_json"])
            previous = config.get("automatic_failover_within_pool", False)
            config["automatic_failover_within_pool"] = result.enabled
            self._connection.execute(
                "UPDATE pools SET config_json = ? WHERE pool_id = ?",
                (json.dumps(config, sort_keys=True, separators=(",", ":")), pool["pool_id"]),
            )
            payload = {
                "actor_id": actor_id,
                "mutation_id": request.mutation_id,
                **binding,
                "previous_enabled": previous,
                "enabled": result.enabled,
                "reason_supplied": True,
            }
            self._connection.execute(
                """INSERT INTO audit_events(event_id, occurred_at_ms, event_type, severity,
                       service_id, operation, preserve, payload_json)
                   VALUES (?, ?, ?, 'INFO', 'firecrawl', ?, 1, ?)""",
                (
                    audit_id,
                    now,
                    operation,
                    operation,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                ),
            )
            # The shared metadata journal uses no credential reference here. All
            # three writes commit together, so there is no cross-store recovery phase.
            self._connection.execute(
                """INSERT INTO credential_mutations(mutation_id, operation, state, actor_id,
                       created_at_ms, updated_at_ms, completed_at_ms, metadata_json, result_json)
                   VALUES (?, ?, 'COMMITTED', ?, ?, ?, ?, ?, ?)""",
                (
                    request.mutation_id,
                    operation,
                    actor_id,
                    now,
                    now,
                    now,
                    binding_json,
                    result.model_dump_json(),
                ),
            )
        return result
