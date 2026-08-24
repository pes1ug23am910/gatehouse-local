"""SQLite-backed request approvals and secret-free administrative read models."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from gatehouse.core.ids import RootRunId
from gatehouse.core.states import ApprovalState
from gatehouse.credentials import SecretScanner
from gatehouse.database import ApprovalConsumeStatus, GatehouseRepository, transaction
from gatehouse.fingerprint import RequestFingerprint
from gatehouse.invocations.models import (
    ApprovalResolution,
    InvocationRequest,
    InvocationSession,
    PendingApprovalProbe,
    PendingApprovalProbeStatus,
)
from gatehouse.policy import Decision, PolicyResult

from .models import (
    AdminStatus,
    ApprovalActionResult,
    ApprovalDecision,
    ApprovalView,
    CredentialSummary,
    IncidentSummary,
    PoolSummary,
    ReconciliationSummary,
)

_ACTION_TOKEN_DOMAIN = b"gatehouse/approval-action-token/v1\x00"
_ACTIVE_INVOCATION_STATES = (
    "DISPATCHING",
    "RUNNING",
    "RETRY_WAIT",
    "RECONCILING",
)
_UNRESOLVED_RESERVATION_STATES = (
    "ACTIVE",
    "PENDING_RECONCILIATION",
    "DISPUTED",
)


class ApprovalPersistenceError(RuntimeError):
    """An approval could not be represented without weakening its binding."""


class ApprovalDecisionConflict(ApprovalPersistenceError):
    """Another actor won, or the approval is no longer actionable."""

    def __init__(self, current_state: str) -> None:
        self.current_state = current_state
        super().__init__(f"approval decision is unavailable in state {current_state}")


@dataclass(frozen=True, slots=True)
class _PoolBinding:
    pool_id: str
    alias: str
    cost_unit: str


def _new_approval_id() -> str:
    return f"apr_{uuid.uuid4().hex}"


def _json(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class SqliteApprovalAdminService:
    """Implement both invocation approvals and the bounded admin read surface.

    Approval rows contain only durable binding facts.  The action token shown to an
    authenticated administrator is a domain-separated HMAC derived on demand and is
    therefore stable across reopen without ever being persisted as plaintext.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        action_token_key: bytes,
        now_ms: Callable[[], int],
        approval_ttl_ms: int = 5 * 60_000,
        identifier: Callable[[], str] = _new_approval_id,
        service_cost_units: Mapping[str, str] | None = None,
        scanner: SecretScanner | None = None,
        maximum_reconciliation_services: int = 200,
    ) -> None:
        if len(action_token_key) < 32:
            raise ValueError("approval action-token key must contain at least 256 bits")
        if approval_ttl_ms <= 0:
            raise ValueError("approval TTL must be positive")
        if maximum_reconciliation_services <= 0:
            raise ValueError("reconciliation service bound must be positive")
        units = dict(service_cost_units or {"firecrawl": "credits"})
        if any(not service or not unit for service, unit in units.items()):
            raise ValueError("service cost-unit bindings cannot be blank")
        self.connection = connection
        self._repository = GatehouseRepository(connection)
        self._action_token_key = bytes(action_token_key)
        self._now_ms = now_ms
        self._approval_ttl_ms = approval_ttl_ms
        self._identifier = identifier
        self._service_cost_units = units
        self._scanner = scanner or SecretScanner()
        self._maximum_reconciliation_services = maximum_reconciliation_services

    async def resolve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> ApprovalResolution:
        if policy.decision is not Decision.ASK:
            raise ValueError("approval resolution requires an ASK policy decision")
        if estimated_cost_units < 0:
            raise ValueError("approval cost cannot be negative")
        if session.client_class.value != "interactive":
            return ApprovalResolution(ApprovalState.DENIED)
        now = self._now_ms()
        self._expire_approvals(now)
        pool = self._resolve_pool(
            service_id=request.service_id,
            pool_name=pool_name,
        )
        if pool is None:
            return ApprovalResolution(ApprovalState.DENIED)
        if request.approval_id is not None:
            return self._consume_supplied(
                approval_id=request.approval_id,
                request=request,
                session=session,
                fingerprint=fingerprint,
                policy=policy,
                pool=pool,
                estimated_cost_units=estimated_cost_units,
                now_ms=now,
            )
        located = self._create_or_return_pending(
            request=request,
            session=session,
            fingerprint=fingerprint,
            policy=policy,
            pool=pool,
            estimated_cost_units=estimated_cost_units,
            now_ms=now,
        )
        if located.state is not ApprovalState.APPROVED:
            return located
        if located.approval_id is None:
            raise ApprovalPersistenceError("approved continuation is missing its identifier")
        return self._consume_supplied(
            approval_id=located.approval_id,
            request=request,
            session=session,
            fingerprint=fingerprint,
            policy=policy,
            pool=pool,
            estimated_cost_units=estimated_cost_units,
            now_ms=now,
        )

    async def probe_pending_approval(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> PendingApprovalProbe:
        """Rehydrate exact approval authority without consuming or replaying its invocation."""

        if policy.decision is not Decision.ASK:
            return PendingApprovalProbe(PendingApprovalProbeStatus.MISMATCH)
        if estimated_cost_units < 0:
            raise ValueError("approval cost cannot be negative")
        now = self._now_ms()
        pool = self._resolve_pool(service_id=request.service_id, pool_name=pool_name)
        if pool is None:
            return PendingApprovalProbe(PendingApprovalProbeStatus.MISMATCH)
        with transaction(self.connection, "IMMEDIATE"):
            rows = self.connection.execute(
                """
                SELECT i.state AS invocation_state,
                       i.session_id AS parent_session_id,
                       i.root_run_id AS parent_root_run_id,
                       i.service_id AS parent_service_id,
                       i.operation AS parent_operation,
                       i.request_fingerprint AS parent_fingerprint,
                       i.fingerprint_version, i.canonicalization_version,
                       i.estimated_cost_units AS parent_estimated_cost_units,
                       i.cost_unit AS parent_cost_unit,
                       s.client_id AS parent_client_id,
                       s.workspace_id AS parent_workspace_id,
                       s.state AS parent_session_state,
                       s.absolute_expires_at_ms AS parent_session_expires_at_ms,
                       rr.session_id AS root_session_id,
                       rr.state AS parent_root_state,
                       rr.ended_at_ms AS parent_root_ended_at_ms,
                       a.approval_id, a.request_fingerprint,
                       a.session_id, a.service_id, a.operation, a.state,
                       a.maximum_uses, a.uses_consumed,
                       a.maximum_cost_units, a.cost_unit, a.pool_id,
                       a.expires_at_ms, a.metadata_json,
                       p.alias AS pool_alias, p.service_id AS pool_service_id,
                       p.state AS pool_state
                  FROM invocations AS i
                  JOIN sessions AS s ON s.session_id = i.session_id
                  LEFT JOIN root_runs AS rr ON rr.root_run_id = i.root_run_id
                  LEFT JOIN approvals AS a ON a.request_id = i.request_id
                  LEFT JOIN pools AS p ON p.pool_id = a.pool_id
                 WHERE i.request_id = ?
                 ORDER BY a.created_at_ms DESC, a.approval_id DESC
                 LIMIT 2
                """,
                (str(request.request_id),),
            ).fetchall()
        if not rows:
            return PendingApprovalProbe(PendingApprovalProbeStatus.ABSENT)
        if len(rows) != 1:
            return PendingApprovalProbe(PendingApprovalProbeStatus.AMBIGUOUS)
        row = rows[0]
        if str(row["invocation_state"]) != "WAITING_APPROVAL":
            return PendingApprovalProbe(PendingApprovalProbeStatus.AMBIGUOUS)
        if row["approval_id"] is None:
            return PendingApprovalProbe(PendingApprovalProbeStatus.AMBIGUOUS)
        try:
            metadata = json.loads(str(row["metadata_json"]))
        except (TypeError, ValueError):
            return PendingApprovalProbe(PendingApprovalProbeStatus.MISMATCH)
        root_run_id = row["parent_root_run_id"]
        exact_binding = (
            isinstance(metadata, dict)
            and str(row["parent_session_id"]) == str(session.session_id)
            and str(row["session_id"]) == str(session.session_id)
            and str(row["parent_client_id"]) == str(session.client_id)
            and str(row["parent_workspace_id"]) == str(session.workspace_id)
            and root_run_id is not None
            and str(row["root_session_id"]) == str(session.session_id)
            and str(row["parent_session_state"]) == "ACTIVE"
            and int(row["parent_session_expires_at_ms"]) > now
            and str(row["parent_root_state"]) == "ACTIVE"
            and row["parent_root_ended_at_ms"] is None
            and str(row["parent_service_id"]) == request.service_id
            and str(row["parent_operation"]) == request.operation
            and str(row["service_id"]) == request.service_id
            and str(row["operation"]) == request.operation
            and hmac.compare_digest(bytes(row["parent_fingerprint"]), fingerprint.digest)
            and hmac.compare_digest(bytes(row["request_fingerprint"]), fingerprint.digest)
            and int(row["fingerprint_version"]) == fingerprint.fingerprint_version
            and int(row["canonicalization_version"]) == fingerprint.canonicalization_version
            and row["parent_estimated_cost_units"] is not None
            and int(row["parent_estimated_cost_units"]) == estimated_cost_units
            and str(row["parent_cost_unit"]) == pool.cost_unit
            and row["maximum_cost_units"] is not None
            and int(row["maximum_cost_units"]) == estimated_cost_units
            and str(row["cost_unit"]) == pool.cost_unit
            and str(row["pool_id"]) == pool.pool_id
            and str(row["pool_alias"]) == pool.alias
            and str(row["pool_service_id"]) == request.service_id
            and str(row["pool_state"]) == "ACTIVE"
            and int(row["maximum_uses"]) == 1
            and int(row["uses_consumed"]) == 0
            and metadata.get("policy_id") == policy.policy_id
            and metadata.get("policy_rule_id") == policy.rule_id
            and metadata.get("policy_version") == policy.policy_version
        )
        if not exact_binding:
            return PendingApprovalProbe(PendingApprovalProbeStatus.MISMATCH)
        if int(row["expires_at_ms"]) <= now or str(row["state"]) == "EXPIRED":
            return PendingApprovalProbe(PendingApprovalProbeStatus.EXPIRED)
        if str(row["state"]) not in {"PENDING", "APPROVED"}:
            return PendingApprovalProbe(PendingApprovalProbeStatus.AMBIGUOUS)
        return PendingApprovalProbe(
            PendingApprovalProbeStatus.RECOVERABLE,
            approval_id=str(row["approval_id"]),
            root_run_id=RootRunId(str(root_run_id)),
        )

    def _consume_supplied(
        self,
        *,
        approval_id: str,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool: _PoolBinding,
        estimated_cost_units: int,
        now_ms: int,
    ) -> ApprovalResolution:
        bound = self.connection.execute(
            """
            SELECT a.*, i.request_fingerprint AS parent_fingerprint,
                   i.fingerprint_version, i.canonicalization_version,
                   i.session_id AS parent_session_id,
                   i.root_run_id AS parent_root_run_id,
                   s.client_id AS parent_client_id,
                   s.workspace_id AS parent_workspace_id
              FROM approvals AS a
              JOIN invocations AS i ON i.request_id = a.request_id
              JOIN sessions AS s ON s.session_id = i.session_id
             WHERE a.approval_id = ?
            """,
            (approval_id,),
        ).fetchone()
        if bound is None or not self._approval_binding_matches(
            bound,
            request=request,
            session=session,
            fingerprint=fingerprint,
            policy=policy,
            pool=pool,
            estimated_cost_units=estimated_cost_units,
        ):
            return ApprovalResolution(ApprovalState.DENIED)
        result = self._repository.consume_approval(
            approval_id=approval_id,
            session_id=str(session.session_id),
            service_id=request.service_id,
            operation=request.operation,
            request_fingerprint=fingerprint.digest,
            pool_id=pool.pool_id,
            estimated_cost_units=estimated_cost_units,
            cost_unit=pool.cost_unit,
            policy_id=policy.policy_id,
            policy_rule_id=policy.rule_id,
            policy_version=policy.policy_version,
            now_ms=now_ms,
        )
        if result.status is ApprovalConsumeStatus.CONSUMED:
            return ApprovalResolution(ApprovalState.APPROVED, approval_id)
        if result.status is ApprovalConsumeStatus.EXPIRED:
            return ApprovalResolution(ApprovalState.EXPIRED)
        if result.status is not ApprovalConsumeStatus.INACTIVE:
            return ApprovalResolution(ApprovalState.DENIED)

        row = self.connection.execute(
            """
            SELECT a.*, i.request_fingerprint AS parent_fingerprint,
                   i.fingerprint_version, i.canonicalization_version,
                   i.session_id AS parent_session_id,
                   i.root_run_id AS parent_root_run_id,
                   s.client_id AS parent_client_id,
                   s.workspace_id AS parent_workspace_id
              FROM approvals AS a
              JOIN invocations AS i ON i.request_id = a.request_id
              JOIN sessions AS s ON s.session_id = i.session_id
             WHERE a.approval_id = ?
            """,
            (approval_id,),
        ).fetchone()
        if row is None or not self._approval_binding_matches(
            row,
            request=request,
            session=session,
            fingerprint=fingerprint,
            policy=policy,
            pool=pool,
            estimated_cost_units=estimated_cost_units,
        ):
            return ApprovalResolution(ApprovalState.DENIED)
        state = ApprovalState(str(row["state"]))
        if state is ApprovalState.PENDING:
            return ApprovalResolution(ApprovalState.PENDING, approval_id)
        if state is ApprovalState.EXPIRED:
            return ApprovalResolution(ApprovalState.EXPIRED)
        return ApprovalResolution(ApprovalState.DENIED)

    @staticmethod
    def _approval_binding_matches(
        row: sqlite3.Row,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool: _PoolBinding,
        estimated_cost_units: int,
    ) -> bool:
        raw_fingerprint = bytes(row["request_fingerprint"])
        try:
            metadata = json.loads(str(row["metadata_json"]))
        except (TypeError, ValueError):
            return False
        if not isinstance(metadata, dict):
            return False
        return (
            str(row["session_id"]) == str(session.session_id)
            and str(row["parent_session_id"]) == str(session.session_id)
            and str(row["parent_root_run_id"])
            == str(request.root_run_id)
            == str(session.root_run_id)
            and str(row["parent_client_id"]) == str(session.client_id)
            and str(row["parent_workspace_id"]) == str(session.workspace_id)
            and str(row["service_id"]) == request.service_id
            and str(row["operation"]) == request.operation
            and hmac.compare_digest(raw_fingerprint, fingerprint.digest)
            and hmac.compare_digest(bytes(row["parent_fingerprint"]), fingerprint.digest)
            and int(row["fingerprint_version"]) == fingerprint.fingerprint_version
            and int(row["canonicalization_version"]) == fingerprint.canonicalization_version
            and metadata.get("policy_id") == policy.policy_id
            and metadata.get("policy_rule_id") == policy.rule_id
            and metadata.get("policy_version") == policy.policy_version
            and row["pool_id"] == pool.pool_id
            and row["maximum_cost_units"] is not None
            and int(row["maximum_cost_units"]) == estimated_cost_units
            and row["cost_unit"] == pool.cost_unit
            and int(row["maximum_uses"]) == 1
        )

    def _create_or_return_pending(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool: _PoolBinding,
        estimated_cost_units: int,
        now_ms: int,
    ) -> ApprovalResolution:
        try:
            with transaction(self.connection, "IMMEDIATE"):
                self._expire_approvals_locked(now_ms)
                parent = self.connection.execute(
                    """
                    SELECT i.session_id, i.root_run_id, i.service_id, i.operation,
                           i.request_fingerprint, i.fingerprint_version,
                           i.canonicalization_version, i.estimated_cost_units,
                           i.cost_unit, s.client_id, s.workspace_id,
                           s.absolute_expires_at_ms
                      FROM invocations AS i
                      JOIN sessions AS s ON s.session_id = i.session_id
                     WHERE i.request_id = ?
                    """,
                    (str(request.request_id),),
                ).fetchone()
                if parent is None or not self._parent_matches(
                    parent,
                    request=request,
                    session=session,
                    fingerprint=fingerprint,
                    estimated_cost_units=estimated_cost_units,
                    cost_unit=pool.cost_unit,
                ):
                    raise ApprovalPersistenceError(
                        "approval parent invocation is unavailable or mismatched"
                    )
                durable_pool = self.connection.execute(
                    """
                    SELECT pool_id FROM pools
                     WHERE pool_id = ? AND service_id = ? AND alias = ? AND state = 'ACTIVE'
                    """,
                    (pool.pool_id, request.service_id, pool.alias),
                ).fetchone()
                if durable_pool is None:
                    return ApprovalResolution(ApprovalState.DENIED)
                expires_at_ms = min(
                    now_ms + self._approval_ttl_ms,
                    int(parent["absolute_expires_at_ms"]),
                )
                if expires_at_ms <= now_ms:
                    return ApprovalResolution(ApprovalState.EXPIRED)
                existing = self.connection.execute(
                    """
                    SELECT a.approval_id, a.state
                      FROM approvals AS a
                      JOIN invocations AS i ON i.request_id = a.request_id
                     WHERE a.session_id = ? AND i.root_run_id = ?
                       AND a.service_id = ? AND a.operation = ?
                       AND a.request_fingerprint = ? AND a.pool_id = ?
                       AND a.maximum_cost_units = ? AND a.cost_unit = ?
                       AND a.maximum_uses = 1 AND a.uses_consumed = 0
                       AND a.state IN ('APPROVED', 'PENDING')
                       AND a.expires_at_ms > ?
                       AND i.fingerprint_version = ? AND i.canonicalization_version = ?
                       AND json_extract(a.metadata_json, '$.policy_id') = ?
                       AND json_extract(a.metadata_json, '$.policy_rule_id') = ?
                       AND json_extract(a.metadata_json, '$.policy_version') = ?
                     ORDER BY CASE a.state WHEN 'APPROVED' THEN 0 ELSE 1 END,
                              a.created_at_ms DESC, a.approval_id DESC LIMIT 1
                    """,
                    (
                        str(session.session_id),
                        str(session.root_run_id),
                        request.service_id,
                        request.operation,
                        fingerprint.digest,
                        pool.pool_id,
                        estimated_cost_units,
                        pool.cost_unit,
                        now_ms,
                        fingerprint.fingerprint_version,
                        fingerprint.canonicalization_version,
                        policy.policy_id,
                        policy.rule_id,
                        policy.policy_version,
                    ),
                ).fetchone()
                if existing is not None:
                    return ApprovalResolution(
                        ApprovalState(str(existing["state"])),
                        str(existing["approval_id"]),
                    )
                approval_id = self._identifier()
                if not 1 <= len(approval_id) <= 160:
                    raise ValueError("generated approval identifier is outside its bound")
                metadata = {
                    "policy_id": policy.policy_id,
                    "policy_rule_id": policy.rule_id,
                    "policy_version": policy.policy_version,
                    "target_summary": self._target_summary(request),
                }
                self.connection.execute(
                    """
                    INSERT INTO approvals(
                        approval_id, request_id, request_fingerprint, session_id,
                        service_id, operation, state, maximum_uses, uses_consumed,
                        maximum_cost_units, cost_unit, pool_id, created_at_ms,
                        expires_at_ms, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 1, 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        str(request.request_id),
                        fingerprint.digest,
                        str(session.session_id),
                        request.service_id,
                        request.operation,
                        estimated_cost_units,
                        pool.cost_unit,
                        pool.pool_id,
                        now_ms,
                        expires_at_ms,
                        _json(metadata),
                    ),
                )
                return ApprovalResolution(ApprovalState.PENDING, approval_id)
        except sqlite3.IntegrityError as exc:
            raise ApprovalPersistenceError("approval persistence constraint failed") from exc

    @staticmethod
    def _parent_matches(
        row: sqlite3.Row,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        estimated_cost_units: int,
        cost_unit: str,
    ) -> bool:
        persisted_cost = row["estimated_cost_units"]
        persisted_unit = row["cost_unit"]
        return (
            str(row["session_id"]) == str(session.session_id)
            and row["root_run_id"] == str(session.root_run_id) == str(request.root_run_id)
            and str(row["client_id"]) == str(session.client_id)
            and row["workspace_id"] == str(session.workspace_id)
            and str(row["service_id"]) == request.service_id
            and str(row["operation"]) == request.operation
            and hmac.compare_digest(bytes(row["request_fingerprint"]), fingerprint.digest)
            and int(row["fingerprint_version"]) == fingerprint.fingerprint_version
            and int(row["canonicalization_version"]) == fingerprint.canonicalization_version
            and (persisted_cost is None or int(persisted_cost) == estimated_cost_units)
            and (persisted_unit is None or str(persisted_unit) == cost_unit)
        )

    def _resolve_pool(self, *, service_id: str, pool_name: str) -> _PoolBinding | None:
        rows = self.connection.execute(
            """
            SELECT p.pool_id, p.alias, p.state, qs.unit
              FROM pools AS p
              LEFT JOIN pool_members AS pm ON pm.pool_id = p.pool_id
              LEFT JOIN quota_scopes AS qs ON qs.quota_scope_id = pm.quota_scope_id
             WHERE p.service_id = ? AND p.alias = ?
            """,
            (service_id, pool_name),
        ).fetchall()
        if not rows or str(rows[0]["state"]) != "ACTIVE":
            return None
        units = {str(row["unit"]) for row in rows if row["unit"] is not None}
        configured = self._service_cost_units.get(service_id)
        if len(units) > 1 or (configured is not None and units and configured not in units):
            raise ApprovalPersistenceError("pool cost-unit binding is inconsistent")
        if units:
            unit = next(iter(units))
        elif configured is not None:
            unit = configured
        else:
            raise ApprovalPersistenceError("pool cost-unit binding is unavailable")
        return _PoolBinding(str(rows[0]["pool_id"]), str(rows[0]["alias"]), unit)

    def _target_summary(self, request: InvocationRequest) -> str:
        raw_url = request.input_payload.get("url")
        summary = f"{request.service_id}.{request.operation}"
        if isinstance(raw_url, str):
            try:
                parsed = urlsplit(raw_url)
            except ValueError:
                parsed = None
            if parsed is not None and parsed.hostname:
                path = parsed.path or "/"
                summary = f"{parsed.scheme.casefold()}://{parsed.hostname.casefold()}{path}"
        return self._scanner.redact_text(summary)[:1_000] or "approval target"

    def _action_token(self, approval_id: str) -> str:
        digest = hmac.new(
            self._action_token_key,
            _ACTION_TOKEN_DOMAIN + approval_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _expire_approvals(self, now_ms: int) -> None:
        with transaction(self.connection, "IMMEDIATE"):
            self._expire_approvals_locked(now_ms)

    def _expire_approvals_locked(self, now_ms: int) -> None:
        self.connection.execute(
            """
            UPDATE approvals SET state = 'EXPIRED'
             WHERE state IN ('PENDING', 'APPROVED') AND expires_at_ms <= ?
            """,
            (now_ms,),
        )

    async def list_approvals(self, *, limit: int) -> Sequence[ApprovalView]:
        if not 1 <= limit <= 100:
            raise ValueError("approval list limit is outside its bound")
        self._expire_approvals(self._now_ms())
        rows = self.connection.execute(
            f"{self._approval_view_query()} AND a.state = 'PENDING' "
            "ORDER BY a.created_at_ms, a.approval_id LIMIT ?",
            (limit,),
        ).fetchall()
        return tuple(self._view_from_row(row) for row in rows)

    async def get_approval(self, approval_id: str) -> ApprovalView | None:
        self._expire_approvals(self._now_ms())
        row = self.connection.execute(
            f"{self._approval_view_query()} AND a.approval_id = ?",
            (approval_id,),
        ).fetchone()
        return None if row is None else self._view_from_row(row)

    @staticmethod
    def _approval_view_query() -> str:
        return """
            SELECT a.*, s.client_id, s.workspace_id, p.alias AS pool_alias,
                   i.fingerprint_version, i.canonicalization_version
              FROM approvals AS a
              JOIN sessions AS s ON s.session_id = a.session_id
              JOIN invocations AS i ON i.request_id = a.request_id
              LEFT JOIN pools AS p ON p.pool_id = a.pool_id
             WHERE a.maximum_uses = 1
        """

    def _view_from_row(self, row: sqlite3.Row) -> ApprovalView:
        metadata: object
        try:
            metadata = json.loads(str(row["metadata_json"]))
        except json.JSONDecodeError:
            metadata = {}
        target = metadata.get("target_summary") if isinstance(metadata, dict) else None
        if not isinstance(target, str) or not target:
            target = f"{row['service_id']}.{row['operation']}"
        target = self._scanner.redact_text(target)[:1_000] or "approval target"
        fingerprint = RequestFingerprint(
            bytes(row["request_fingerprint"]),
            int(row["fingerprint_version"]),
            int(row["canonicalization_version"]),
        )
        return ApprovalView(
            approval_id=str(row["approval_id"]),
            session_id=str(row["session_id"]),
            client_id=str(row["client_id"]),
            workspace_id=None if row["workspace_id"] is None else str(row["workspace_id"]),
            service=str(row["service_id"]),
            operation=str(row["operation"]),
            request_fingerprint=str(fingerprint),
            target_summary=target,
            pool="unbound" if row["pool_alias"] is None else str(row["pool_alias"]),
            maximum_estimated_cost=(
                0 if row["maximum_cost_units"] is None else int(row["maximum_cost_units"])
            ),
            maximum_uses=1,
            expires_at_ms=int(row["expires_at_ms"]),
            state=str(row["state"]),
            action_token=self._action_token(str(row["approval_id"])),
        )

    async def decide_approval(
        self,
        *,
        approval: ApprovalView,
        decision: ApprovalDecision,
        now_ms: int,
    ) -> ApprovalActionResult:
        target_state = (
            ApprovalState.APPROVED if decision is ApprovalDecision.APPROVE else ApprovalState.DENIED
        )
        with transaction(self.connection, "IMMEDIATE"):
            self._expire_approvals_locked(now_ms)
            row = self.connection.execute(
                f"{self._approval_view_query()} AND a.approval_id = ?",
                (approval.approval_id,),
            ).fetchone()
            if row is None:
                raise ApprovalDecisionConflict("NOT_FOUND")
            current = self._view_from_row(row)
            if current.state != ApprovalState.PENDING.value:
                raise ApprovalDecisionConflict(current.state)
            if not self._same_action_binding(current, approval):
                raise ApprovalDecisionConflict("BINDING_MISMATCH")
            cursor = self.connection.execute(
                """
                UPDATE approvals
                   SET state = ?, decided_at_ms = ?, decision_source = 'ADMIN',
                       reason = 'human_admin_action'
                 WHERE approval_id = ? AND state = 'PENDING' AND expires_at_ms > ?
                """,
                (target_state.value, now_ms, approval.approval_id, now_ms),
            )
            if cursor.rowcount != 1:
                winner = self.connection.execute(
                    "SELECT state FROM approvals WHERE approval_id = ?",
                    (approval.approval_id,),
                ).fetchone()
                raise ApprovalDecisionConflict(
                    "NOT_FOUND" if winner is None else str(winner["state"])
                )
        return ApprovalActionResult(
            approval_id=approval.approval_id,
            state=target_state.value,
            acted_at_ms=now_ms,
        )

    @staticmethod
    def _same_action_binding(current: ApprovalView, supplied: ApprovalView) -> bool:
        return (
            current.approval_id == supplied.approval_id
            and current.session_id == supplied.session_id
            and current.client_id == supplied.client_id
            and current.workspace_id == supplied.workspace_id
            and current.service == supplied.service
            and current.operation == supplied.operation
            and hmac.compare_digest(
                current.request_fingerprint,
                supplied.request_fingerprint,
            )
            and current.target_summary == supplied.target_summary
            and current.pool == supplied.pool
            and current.maximum_estimated_cost == supplied.maximum_estimated_cost
            and current.maximum_uses == supplied.maximum_uses == 1
            and current.expires_at_ms == supplied.expires_at_ms
            and hmac.compare_digest(current.action_token, supplied.action_token)
        )

    async def status(self) -> AdminStatus:
        now = self._now_ms()
        self._expire_approvals(now)
        system = self.connection.execute(
            "SELECT daemon_state, last_started_at_ms FROM system_state WHERE singleton_id = 1"
        ).fetchone()
        if system is None:
            raise ApprovalPersistenceError("system state is unavailable")
        started = system["last_started_at_ms"]
        return AdminStatus(
            service_state=str(system["daemon_state"]),
            uptime_seconds=(0 if started is None else max(0, (now - int(started)) // 1_000)),
            active_sessions=self._count(
                "SELECT COUNT(*) FROM sessions WHERE state = 'ACTIVE' "
                "AND absolute_expires_at_ms > ?",
                (now,),
            ),
            in_flight_requests=self._count(
                "SELECT COUNT(*) FROM invocations WHERE state IN (?, ?, ?, ?)",
                _ACTIVE_INVOCATION_STATES,
            ),
            queued_requests=self._count("SELECT COUNT(*) FROM invocations WHERE state = 'QUEUED'"),
            pending_approvals=self._count(
                "SELECT COUNT(*) FROM approvals WHERE state = 'PENDING' AND expires_at_ms > ?",
                (now,),
            ),
            high_severity_incidents=self._count(
                "SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL') "
                "AND state NOT IN ('RESOLVED', 'CLOSED')"
            ),
        )

    def _count(self, query: str, parameters: tuple[object, ...] = ()) -> int:
        return int(self.connection.execute(query, parameters).fetchone()[0])

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]:
        if not 1 <= limit <= 200:
            raise ValueError("pool list limit is outside its bound")
        now = self._now_ms()
        rows = self.connection.execute(
            """
            SELECT p.pool_id, p.service_id, p.state,
                   (SELECT COUNT(DISTINCT c.credential_id)
                      FROM pool_members AS pm
                      JOIN quota_scopes AS qs ON qs.quota_scope_id = pm.quota_scope_id
                      JOIN credentials AS c ON c.quota_scope_id = qs.quota_scope_id
                     WHERE pm.pool_id = p.pool_id AND pm.enabled = 1
                       AND qs.state = 'HEALTHY' AND c.state = 'HEALTHY'
                       AND (c.expires_at_ms IS NULL OR c.expires_at_ms > ?)
                   ) AS eligible_credentials,
                   (SELECT COUNT(DISTINCT qr.request_id)
                      FROM pool_members AS pm
                      JOIN quota_reservations AS qr
                        ON qr.quota_scope_id = pm.quota_scope_id
                     WHERE pm.pool_id = p.pool_id AND pm.enabled = 1
                       AND qr.state IN ('ACTIVE', 'PENDING_RECONCILIATION', 'DISPUTED')
                   ) AS in_flight
              FROM pools AS p
             ORDER BY p.service_id, p.alias, p.pool_id LIMIT ?
            """,
            (now, limit),
        ).fetchall()
        return tuple(
            PoolSummary(
                pool_id=str(row["pool_id"]),
                service=str(row["service_id"]),
                state=str(row["state"]),
                eligible_credentials=int(row["eligible_credentials"]),
                in_flight=int(row["in_flight"]),
            )
            for row in rows
        )

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]:
        if not 1 <= limit <= 200:
            raise ValueError("credential list limit is outside its bound")
        now = self._now_ms()
        rows = self.connection.execute(
            """
            SELECT c.credential_id, p.service_id, c.alias, c.principal_id,
                   p.alias AS principal_alias, c.quota_scope_id,
                   q.alias AS quota_scope_alias, c.state, c.generation,
                   c.expires_at_ms, c.exclusive_usage, c.created_at_ms,
                   c.last_used_at_ms,
                   CASE
                       WHEN json_type(c.metadata_json, '$.last_local_action') = 'text'
                       THEN json_extract(c.metadata_json, '$.last_local_action')
                       ELSE NULL
                   END AS last_local_action,
                   COALESCE(
                       (
                           SELECT json_group_array(bindings.pool_id)
                             FROM (
                                 SELECT pm.pool_id
                                   FROM pool_members AS pm
                                   JOIN pools AS bound_pool
                                     ON bound_pool.pool_id = pm.pool_id
                                  WHERE pm.quota_scope_id = c.quota_scope_id
                                  ORDER BY pm.pool_id
                                  LIMIT 200
                             ) AS bindings
                       ),
                       '[]'
                   ) AS pool_ids_json,
                   COALESCE(
                       (
                           SELECT json_group_array(bindings.pool_alias)
                             FROM (
                                 SELECT bound_pool.alias AS pool_alias
                                   FROM pool_members AS pm
                                   JOIN pools AS bound_pool
                                     ON bound_pool.pool_id = pm.pool_id
                                  WHERE pm.quota_scope_id = c.quota_scope_id
                                  ORDER BY pm.pool_id
                                  LIMIT 200
                             ) AS bindings
                       ),
                       '[]'
                   ) AS pool_aliases_json,
                   (
                       SELECT COUNT(*)
                         FROM leases AS active_lease
                        WHERE active_lease.lease_type = 'provider-credential'
                          AND active_lease.state = 'ACTIVE'
                          AND active_lease.expires_at_ms > ?
                          AND (
                              json_extract(
                                  active_lease.metadata_json,
                                  '$.credential_id'
                              ) = c.credential_id
                              OR active_lease.lease_key = c.credential_id
                          )
                   ) AS active_lease_count
              FROM credentials AS c
              JOIN principals AS p ON p.principal_id = c.principal_id
              JOIN quota_scopes AS q ON q.quota_scope_id = c.quota_scope_id
             ORDER BY p.service_id, c.alias, c.credential_id LIMIT ?
            """,
            (now, limit),
        ).fetchall()

        def pool_values(raw: object) -> tuple[str, ...]:
            try:
                decoded = json.loads(str(raw))
            except (TypeError, ValueError) as error:
                raise ApprovalPersistenceError("credential pool bindings are invalid") from error
            if (
                not isinstance(decoded, list)
                or len(decoded) > 200
                or any(not isinstance(item, str) or not 1 <= len(item) <= 160 for item in decoded)
            ):
                raise ApprovalPersistenceError("credential pool bindings are invalid")
            return tuple(decoded)

        def safe_last_action(raw: object) -> str | None:
            if raw is None:
                return None
            value = self._scanner.redact_text(str(raw))[:64]
            return value or None

        return tuple(
            CredentialSummary(
                credential_id=str(row["credential_id"]),
                service=str(row["service_id"]),
                alias=str(row["alias"]),
                principal_id=str(row["principal_id"]),
                principal_alias=str(row["principal_alias"]),
                quota_scope_id=str(row["quota_scope_id"]),
                quota_scope_alias=str(row["quota_scope_alias"]),
                state=str(row["state"]),
                generation=int(row["generation"]),
                expires_at_ms=(None if row["expires_at_ms"] is None else int(row["expires_at_ms"])),
                exclusive_usage=bool(row["exclusive_usage"]),
                pool_ids=pool_values(row["pool_ids_json"]),
                pool_aliases=pool_values(row["pool_aliases_json"]),
                active_lease_count=int(row["active_lease_count"]),
                created_at_ms=int(row["created_at_ms"]),
                last_used_at_ms=(
                    None if row["last_used_at_ms"] is None else int(row["last_used_at_ms"])
                ),
                last_local_action=safe_last_action(row["last_local_action"]),
            )
            for row in rows
        )

    async def list_incidents(self, *, limit: int) -> Sequence[IncidentSummary]:
        if not 1 <= limit <= 200:
            raise ValueError("incident list limit is outside its bound")
        rows = self.connection.execute(
            """
            SELECT alert_id, severity, category, summary, state, created_at_ms
              FROM alerts ORDER BY created_at_ms DESC, alert_id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(
            IncidentSummary(
                incident_id=str(row["alert_id"]),
                severity=str(row["severity"]),
                category=str(row["category"]),
                summary=(
                    self._scanner.redact_text(str(row["summary"]))[:1_000]
                    or "Incident summary unavailable."
                ),
                state=str(row["state"]),
                created_at_ms=int(row["created_at_ms"]),
            )
            for row in rows
        )

    async def reconciliation(self) -> Sequence[ReconciliationSummary]:
        rows = self.connection.execute(
            """
            WITH services(service_id) AS (
                SELECT service_id FROM principals
                UNION SELECT service_id FROM pools
                UNION SELECT service_id FROM reconciliation_runs
            )
            SELECT services.service_id,
                   COALESCE(
                       (SELECT rr.state FROM reconciliation_runs AS rr
                         WHERE rr.service_id = services.service_id
                         ORDER BY rr.started_at_ms DESC, rr.reconciliation_id DESC LIMIT 1),
                       'NOT_RUN'
                   ) AS state,
                   (SELECT MAX(rr.completed_at_ms) FROM reconciliation_runs AS rr
                     WHERE rr.service_id = services.service_id) AS last_completed_at_ms,
                   (SELECT COUNT(*) FROM quota_reservations AS qr
                      JOIN quota_scopes AS qs ON qs.quota_scope_id = qr.quota_scope_id
                      JOIN principals AS p ON p.principal_id = qs.principal_id
                     WHERE p.service_id = services.service_id
                       AND qr.state IN ('ACTIVE', 'PENDING_RECONCILIATION', 'DISPUTED')
                   ) AS unresolved_reservations,
                   (SELECT COUNT(*) FROM reconciliation_items AS ri
                      JOIN reconciliation_runs AS rr
                        ON rr.reconciliation_id = ri.reconciliation_id
                     WHERE rr.service_id = services.service_id AND ri.state = 'MISMATCH'
                   ) AS ledger_mismatch_count
              FROM services ORDER BY services.service_id LIMIT ?
            """,
            (self._maximum_reconciliation_services,),
        ).fetchall()
        return tuple(
            ReconciliationSummary(
                service=str(row["service_id"]),
                state=str(row["state"]),
                last_completed_at_ms=(
                    None
                    if row["last_completed_at_ms"] is None
                    else int(row["last_completed_at_ms"])
                ),
                unresolved_reservations=int(row["unresolved_reservations"]),
                ledger_mismatch_count=int(row["ledger_mismatch_count"]),
            )
            for row in rows
        )
