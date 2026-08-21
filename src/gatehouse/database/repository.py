"""Race-safe repository helpers for security-critical state transitions."""

from __future__ import annotations

import hmac
import json
import sqlite3
import uuid
from dataclasses import dataclass
from enum import StrEnum

from .connection import transaction


def _identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json(value: dict[str, object] | None) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"))


class LeaseStatus(StrEnum):
    ACQUIRED = "ACQUIRED"
    ALREADY_OWNED = "ALREADY_OWNED"
    BUSY = "BUSY"
    INELIGIBLE = "INELIGIBLE"


@dataclass(frozen=True, slots=True)
class LeaseResult:
    status: LeaseStatus
    lease_id: str | None
    owner_id: str | None
    expires_at_ms: int | None

    @property
    def acquired(self) -> bool:
        return self.status in {LeaseStatus.ACQUIRED, LeaseStatus.ALREADY_OWNED}


class QuotaReservationStatus(StrEnum):
    RESERVED = "RESERVED"
    NOT_FOUND = "NOT_FOUND"
    INELIGIBLE = "INELIGIBLE"
    UNKNOWN_BALANCE = "UNKNOWN_BALANCE"
    UNIT_MISMATCH = "UNIT_MISMATCH"
    EXHAUSTED = "EXHAUSTED"


@dataclass(frozen=True, slots=True)
class QuotaReservationResult:
    status: QuotaReservationStatus
    reservation_id: str | None
    available_before_units: int | None
    available_after_units: int | None

    @property
    def reserved(self) -> bool:
        return self.status is QuotaReservationStatus.RESERVED


class ApprovalConsumeStatus(StrEnum):
    CONSUMED = "CONSUMED"
    NOT_FOUND = "NOT_FOUND"
    INACTIVE = "INACTIVE"
    EXPIRED = "EXPIRED"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    COST_EXCEEDED = "COST_EXCEEDED"


@dataclass(frozen=True, slots=True)
class ApprovalConsumeResult:
    status: ApprovalConsumeStatus
    uses_consumed: int = 0
    maximum_uses: int = 0

    @property
    def consumed(self) -> bool:
        return self.status is ApprovalConsumeStatus.CONSUMED


class GatehouseRepository:
    """Own atomic transitions that must not be spread across service layers."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def acquire_lease(
        self,
        *,
        lease_type: str,
        lease_key: str,
        owner_id: str,
        now_ms: int,
        expires_at_ms: int,
        lease_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> LeaseResult:
        """Acquire a single-holder lease without destroying historical rows."""

        if not lease_type or not lease_key or not owner_id:
            raise ValueError("lease_type, lease_key, and owner_id are required")
        if expires_at_ms <= now_ms:
            raise ValueError("lease expiration must be in the future")
        candidate_id = lease_id or _identifier("lease")

        with transaction(self.connection, "IMMEDIATE"):
            self.connection.execute(
                """
                UPDATE leases
                   SET state = 'EXPIRED', released_at_ms = ?
                 WHERE lease_type = ? AND lease_key = ?
                   AND state = 'ACTIVE' AND expires_at_ms <= ?
                """,
                (now_ms, lease_type, lease_key, now_ms),
            )
            existing = self.connection.execute(
                """
                SELECT lease_id, owner_id, expires_at_ms
                  FROM leases
                 WHERE lease_type = ? AND lease_key = ? AND state = 'ACTIVE'
                """,
                (lease_type, lease_key),
            ).fetchone()
            if existing is not None:
                status = (
                    LeaseStatus.ALREADY_OWNED
                    if existing["owner_id"] == owner_id
                    else LeaseStatus.BUSY
                )
                return LeaseResult(
                    status=status,
                    lease_id=str(existing["lease_id"]),
                    owner_id=str(existing["owner_id"]),
                    expires_at_ms=int(existing["expires_at_ms"]),
                )

            self.connection.execute(
                """
                INSERT INTO leases(
                    lease_id, lease_type, lease_key, owner_id, state, generation,
                    acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, 'ACTIVE', 1, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    lease_type,
                    lease_key,
                    owner_id,
                    now_ms,
                    now_ms,
                    expires_at_ms,
                    _json(metadata),
                ),
            )
            return LeaseResult(
                status=LeaseStatus.ACQUIRED,
                lease_id=candidate_id,
                owner_id=owner_id,
                expires_at_ms=expires_at_ms,
            )

    def acquire_credential_lease(
        self,
        *,
        credential_id: str,
        credential_generation: int,
        quota_scope_id: str,
        pool_id: str,
        owner_id: str,
        now_ms: int,
        expires_at_ms: int,
        exact_affinity: bool = False,
        lease_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> LeaseResult:
        """Atomically revalidate and lease one exact credential generation."""

        if not all((credential_id, quota_scope_id, pool_id, owner_id)):
            raise ValueError("credential lease identifiers are required")
        if (
            isinstance(credential_generation, bool)
            or not isinstance(credential_generation, int)
            or credential_generation <= 0
        ):
            raise ValueError("credential generation must be positive")
        if not isinstance(exact_affinity, bool):
            raise ValueError("exact_affinity must be boolean")
        if expires_at_ms <= now_ms:
            raise ValueError("lease expiration must be in the future")

        candidate_id = lease_id or _identifier("lease")
        lease_key = f"{credential_id}:{credential_generation}"
        stored_metadata = dict(metadata or {})
        stored_metadata.update(
            {
                "credential_id": credential_id,
                "credential_generation": credential_generation,
                "quota_scope_id": quota_scope_id,
                "pool_id": pool_id,
                "exact_affinity": exact_affinity,
            }
        )

        with transaction(self.connection, "IMMEDIATE"):
            self.connection.execute(
                """
                UPDATE leases
                   SET state = 'EXPIRED', released_at_ms = ?
                 WHERE lease_type = 'provider-credential'
                   AND state = 'ACTIVE' AND expires_at_ms <= ?
                   AND (
                       lease_key = ?
                       OR substr(lease_key, 1, length(?) + 1) = ? || ':'
                       OR json_extract(metadata_json, '$.credential_id') = ?
                   )
                """,
                (
                    now_ms,
                    now_ms,
                    credential_id,
                    credential_id,
                    credential_id,
                    credential_id,
                ),
            )

            eligible = self.connection.execute(
                """
                SELECT 1
                  FROM credentials AS c
                  JOIN quota_scopes AS qs
                    ON qs.quota_scope_id = c.quota_scope_id
                   AND qs.principal_id = c.principal_id
                  JOIN principals AS pr
                    ON pr.principal_id = c.principal_id
                  JOIN pool_members AS pm
                    ON pm.quota_scope_id = c.quota_scope_id
                   AND pm.pool_id = ?
                  JOIN pools AS p
                    ON p.pool_id = pm.pool_id
                   AND p.service_id = pr.service_id
                 WHERE c.credential_id = ?
                   AND c.generation = ?
                   AND c.quota_scope_id = ?
                   AND (
                       c.state = 'HEALTHY'
                       OR (? = 1 AND c.state = 'DRAINING')
                   )
                   AND (c.expires_at_ms IS NULL OR c.expires_at_ms > ?)
                   AND pr.enabled = 1
                   AND qs.state = 'HEALTHY'
                   AND pm.enabled = 1
                   AND p.state IN ('ACTIVE', 'ENABLED')
                """,
                (
                    pool_id,
                    credential_id,
                    credential_generation,
                    quota_scope_id,
                    int(exact_affinity),
                    now_ms,
                ),
            ).fetchone()
            if eligible is None:
                return LeaseResult(LeaseStatus.INELIGIBLE, None, None, None)

            existing = self.connection.execute(
                """
                SELECT lease_id, lease_key, owner_id, expires_at_ms
                  FROM leases
                 WHERE lease_type = 'provider-credential' AND state = 'ACTIVE'
                   AND (
                       lease_key = ?
                       OR substr(lease_key, 1, length(?) + 1) = ? || ':'
                       OR json_extract(metadata_json, '$.credential_id') = ?
                   )
                 ORDER BY acquired_at_ms, lease_id
                LIMIT 1
                """,
                (credential_id, credential_id, credential_id, credential_id),
            ).fetchone()
            if existing is not None:
                already_owned = (
                    existing["lease_key"] == lease_key and existing["owner_id"] == owner_id
                )
                return LeaseResult(
                    status=(LeaseStatus.ALREADY_OWNED if already_owned else LeaseStatus.BUSY),
                    lease_id=str(existing["lease_id"]),
                    owner_id=str(existing["owner_id"]),
                    expires_at_ms=int(existing["expires_at_ms"]),
                )

            self.connection.execute(
                """
                INSERT INTO leases(
                    lease_id, lease_type, lease_key, owner_id, state, generation,
                    acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
                ) VALUES (?, 'provider-credential', ?, ?, 'ACTIVE', 1, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    lease_key,
                    owner_id,
                    now_ms,
                    now_ms,
                    expires_at_ms,
                    _json(stored_metadata),
                ),
            )
            return LeaseResult(
                status=LeaseStatus.ACQUIRED,
                lease_id=candidate_id,
                owner_id=owner_id,
                expires_at_ms=expires_at_ms,
            )

    def acquire_credential_validation_lease(
        self,
        *,
        credential_id: str,
        expected_generation: int,
        owner_id: str,
        now_ms: int,
        expires_at_ms: int,
        lease_id: str | None = None,
    ) -> LeaseResult:
        """Lease one exact live Firecrawl credential without routing through a pool."""

        if not credential_id or len(credential_id) > 160 or not owner_id or len(owner_id) > 160:
            raise ValueError("credential validation lease identifiers are invalid")
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation <= 0
        ):
            raise ValueError("credential generation must be positive")
        if expires_at_ms <= now_ms:
            raise ValueError("lease expiration must be in the future")

        candidate_id = lease_id or _identifier("lease")
        lease_key = f"{credential_id}:{expected_generation}"

        with transaction(self.connection, "IMMEDIATE"):
            self.connection.execute(
                """
                UPDATE leases
                   SET state = 'EXPIRED', released_at_ms = ?
                 WHERE lease_type = 'provider-credential'
                   AND state = 'ACTIVE' AND expires_at_ms <= ?
                   AND (
                       lease_key = ?
                       OR substr(lease_key, 1, length(?) + 1) = ? || ':'
                       OR json_extract(metadata_json, '$.credential_id') = ?
                   )
                """,
                (
                    now_ms,
                    now_ms,
                    credential_id,
                    credential_id,
                    credential_id,
                    credential_id,
                ),
            )
            eligible = self.connection.execute(
                """
                SELECT 1
                  FROM credentials AS c
                  JOIN quota_scopes AS qs
                    ON qs.quota_scope_id = c.quota_scope_id
                   AND qs.principal_id = c.principal_id
                  JOIN principals AS pr
                    ON pr.principal_id = c.principal_id
                 WHERE c.credential_id = ?
                   AND c.generation = ?
                   AND c.state = 'HEALTHY'
                   AND (c.expires_at_ms IS NULL OR c.expires_at_ms > ?)
                   AND c.secret_backend = 'dpapi-current-user'
                   AND pr.enabled = 1
                   AND pr.service_id = 'firecrawl'
                   AND qs.unit = 'credits'
                """,
                (credential_id, expected_generation, now_ms),
            ).fetchone()
            if eligible is None:
                return LeaseResult(LeaseStatus.INELIGIBLE, None, None, None)

            existing = self.connection.execute(
                """
                SELECT lease_id, lease_key, owner_id, expires_at_ms
                  FROM leases
                 WHERE lease_type = 'provider-credential' AND state = 'ACTIVE'
                   AND (
                       lease_key = ?
                       OR substr(lease_key, 1, length(?) + 1) = ? || ':'
                       OR json_extract(metadata_json, '$.credential_id') = ?
                   )
                 ORDER BY acquired_at_ms, lease_id
                 LIMIT 1
                """,
                (credential_id, credential_id, credential_id, credential_id),
            ).fetchone()
            if existing is not None:
                already_owned = (
                    existing["lease_key"] == lease_key and existing["owner_id"] == owner_id
                )
                return LeaseResult(
                    status=(LeaseStatus.ALREADY_OWNED if already_owned else LeaseStatus.BUSY),
                    lease_id=str(existing["lease_id"]),
                    owner_id=str(existing["owner_id"]),
                    expires_at_ms=int(existing["expires_at_ms"]),
                )

            self.connection.execute(
                """
                INSERT INTO leases(
                    lease_id, lease_type, lease_key, owner_id, state, generation,
                    acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
                ) VALUES (?, 'provider-credential', ?, ?, 'ACTIVE', 1, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    lease_key,
                    owner_id,
                    now_ms,
                    now_ms,
                    expires_at_ms,
                    _json(
                        {
                            "credential_id": credential_id,
                            "credential_generation": expected_generation,
                            "credential_validation": True,
                        }
                    ),
                ),
            )
            return LeaseResult(
                status=LeaseStatus.ACQUIRED,
                lease_id=candidate_id,
                owner_id=owner_id,
                expires_at_ms=expires_at_ms,
            )

    def heartbeat_lease(
        self,
        *,
        lease_id: str,
        owner_id: str,
        now_ms: int,
        expires_at_ms: int,
    ) -> bool:
        """Extend an unexpired lease only for its current owner."""

        if expires_at_ms <= now_ms:
            raise ValueError("lease expiration must be in the future")
        with transaction(self.connection, "IMMEDIATE"):
            cursor = self.connection.execute(
                """
                UPDATE leases
                   SET heartbeat_at_ms = ?, expires_at_ms = ?, generation = generation + 1
                 WHERE lease_id = ? AND owner_id = ? AND state = 'ACTIVE'
                   AND expires_at_ms > ?
                """,
                (now_ms, expires_at_ms, lease_id, owner_id, now_ms),
            )
            return cursor.rowcount == 1

    def release_lease(
        self,
        *,
        lease_id: str,
        owner_id: str,
        now_ms: int,
    ) -> bool:
        """Release a lease with an owner-checked compare-and-set."""

        with transaction(self.connection, "IMMEDIATE"):
            cursor = self.connection.execute(
                """
                UPDATE leases
                   SET state = 'RELEASED', released_at_ms = ?, heartbeat_at_ms = ?
                 WHERE lease_id = ? AND owner_id = ? AND state = 'ACTIVE'
                """,
                (now_ms, now_ms, lease_id, owner_id),
            )
            return cursor.rowcount == 1

    def reserve_quota(
        self,
        *,
        request_id: str,
        quota_scope_id: str,
        amount_units: int,
        unit: str,
        now_ms: int,
        expires_at_ms: int,
        reservation_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> QuotaReservationResult:
        """Atomically reserve integer quota units before provider dispatch."""

        if amount_units <= 0:
            raise ValueError("amount_units must be positive")
        if not unit:
            raise ValueError("unit is required")
        if expires_at_ms <= now_ms:
            raise ValueError("reservation expiration must be in the future")
        candidate_id = reservation_id or _identifier("reservation")

        with transaction(self.connection, "IMMEDIATE"):
            scope = self.connection.execute(
                """
                SELECT state, unit, last_known_remaining_units,
                       configured_floor_units, balance_as_of_ms
                  FROM quota_scopes WHERE quota_scope_id = ?
                """,
                (quota_scope_id,),
            ).fetchone()
            if scope is None:
                return QuotaReservationResult(QuotaReservationStatus.NOT_FOUND, None, None, None)
            if scope["state"] != "HEALTHY":
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)
            if scope["unit"] != unit:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNIT_MISMATCH, None, None, None
                )
            if scope["last_known_remaining_units"] is None:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNKNOWN_BALANCE, None, None, None
                )

            committed_units = int(
                self.connection.execute(
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
                    (
                        scope["balance_as_of_ms"],
                        scope["balance_as_of_ms"],
                        quota_scope_id,
                    ),
                ).fetchone()[0]
            )
            available = (
                int(scope["last_known_remaining_units"])
                - int(scope["configured_floor_units"])
                - committed_units
            )
            if available < amount_units:
                return QuotaReservationResult(
                    QuotaReservationStatus.EXHAUSTED,
                    None,
                    max(0, available),
                    max(0, available),
                )

            self.connection.execute(
                """
                INSERT INTO quota_reservations(
                    reservation_id, request_id, quota_scope_id, amount_units, unit,
                    state, created_at_ms, expires_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
                """,
                (
                    candidate_id,
                    request_id,
                    quota_scope_id,
                    amount_units,
                    unit,
                    now_ms,
                    expires_at_ms,
                    _json(metadata),
                ),
            )
            return QuotaReservationResult(
                QuotaReservationStatus.RESERVED,
                candidate_id,
                available,
                available - amount_units,
            )

    def reconcile_quota_reservation(
        self,
        *,
        reservation_id: str,
        actual_units: int | None,
        now_ms: int,
        outcome_known: bool,
    ) -> bool:
        """Settle known usage or conservatively retain an ambiguous reservation."""

        if actual_units is not None and actual_units < 0:
            raise ValueError("actual_units must be non-negative")
        if outcome_known and actual_units is None:
            raise ValueError("known quota outcomes require actual_units")
        if not outcome_known and actual_units is not None:
            raise ValueError("ambiguous quota outcomes cannot assert actual_units")
        with transaction(self.connection, "IMMEDIATE"):
            existing = self.connection.execute(
                """
                SELECT state, actual_units
                  FROM quota_reservations
                 WHERE reservation_id = ?
                """,
                (reservation_id,),
            ).fetchone()
            if existing is None:
                return False
            if outcome_known and existing["state"] == "RECONCILED":
                stored_actual = existing["actual_units"]
                return stored_actual is not None and int(stored_actual) == actual_units
            if not outcome_known and existing["state"] == "PENDING_RECONCILIATION":
                return existing["actual_units"] is None
            state = "RECONCILED" if outcome_known else "PENDING_RECONCILIATION"
            cursor = self.connection.execute(
                """
                UPDATE quota_reservations
                   SET state = ?, actual_units = ?, reconciled_at_ms = ?
                 WHERE reservation_id = ?
                   AND state IN ('ACTIVE', 'PENDING_RECONCILIATION', 'DISPUTED')
                """,
                (state, actual_units, now_ms if outcome_known else None, reservation_id),
            )
            return cursor.rowcount == 1

    def replace_quota_reservation(
        self,
        *,
        old_reservation_id: str,
        request_id: str,
        quota_scope_id: str,
        amount_units: int,
        unit: str,
        now_ms: int,
        expires_at_ms: int,
        reservation_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> QuotaReservationResult:
        """Atomically settle an expired pre-dispatch hold and replace it."""

        if amount_units <= 0:
            raise ValueError("amount_units must be positive")
        if not unit:
            raise ValueError("unit is required")
        if expires_at_ms <= now_ms:
            raise ValueError("reservation expiration must be in the future")
        candidate_id = reservation_id or _identifier("reservation")

        with transaction(self.connection, "IMMEDIATE"):
            old = self.connection.execute(
                """
                SELECT request_id, unit, state, expires_at_ms
                  FROM quota_reservations
                 WHERE reservation_id = ?
                """,
                (old_reservation_id,),
            ).fetchone()
            if old is None:
                return QuotaReservationResult(QuotaReservationStatus.NOT_FOUND, None, None, None)
            if old["request_id"] != request_id or old["state"] != "ACTIVE":
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)
            if old["unit"] != unit:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNIT_MISMATCH, None, None, None
                )
            if int(old["expires_at_ms"]) > now_ms:
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)

            scope = self.connection.execute(
                """
                SELECT state, unit, last_known_remaining_units,
                       configured_floor_units, balance_as_of_ms
                  FROM quota_scopes WHERE quota_scope_id = ?
                """,
                (quota_scope_id,),
            ).fetchone()
            if scope is None:
                return QuotaReservationResult(QuotaReservationStatus.NOT_FOUND, None, None, None)
            if scope["state"] != "HEALTHY":
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)
            if scope["unit"] != unit:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNIT_MISMATCH, None, None, None
                )
            if scope["last_known_remaining_units"] is None:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNKNOWN_BALANCE, None, None, None
                )

            committed_units = int(
                self.connection.execute(
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
                     WHERE quota_scope_id = ? AND reservation_id <> ?
                    """,
                    (
                        scope["balance_as_of_ms"],
                        scope["balance_as_of_ms"],
                        quota_scope_id,
                        old_reservation_id,
                    ),
                ).fetchone()[0]
            )
            available = (
                int(scope["last_known_remaining_units"])
                - int(scope["configured_floor_units"])
                - committed_units
            )
            if available < amount_units:
                return QuotaReservationResult(
                    QuotaReservationStatus.EXHAUSTED,
                    None,
                    max(0, available),
                    max(0, available),
                )

            settled = self.connection.execute(
                """
                UPDATE quota_reservations
                   SET state = 'RECONCILED', actual_units = 0, reconciled_at_ms = ?
                 WHERE reservation_id = ? AND request_id = ? AND state = 'ACTIVE'
                   AND expires_at_ms <= ?
                """,
                (now_ms, old_reservation_id, request_id, now_ms),
            )
            if settled.rowcount != 1:
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)
            self.connection.execute(
                """
                INSERT INTO quota_reservations(
                    reservation_id, request_id, quota_scope_id, amount_units, unit,
                    state, created_at_ms, expires_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
                """,
                (
                    candidate_id,
                    request_id,
                    quota_scope_id,
                    amount_units,
                    unit,
                    now_ms,
                    expires_at_ms,
                    _json(metadata),
                ),
            )
            return QuotaReservationResult(
                QuotaReservationStatus.RESERVED,
                candidate_id,
                available,
                available - amount_units,
            )

    def consume_approval(
        self,
        *,
        approval_id: str,
        session_id: str,
        service_id: str,
        operation: str,
        request_fingerprint: bytes,
        pool_id: str | None,
        estimated_cost_units: int | None,
        cost_unit: str | None,
        now_ms: int,
    ) -> ApprovalConsumeResult:
        """Consume a one-use or bounded-use approval with full request binding."""

        if estimated_cost_units is not None and estimated_cost_units < 0:
            raise ValueError("estimated_cost_units must be non-negative")
        with transaction(self.connection, "IMMEDIATE"):
            row = self.connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                return ApprovalConsumeResult(ApprovalConsumeStatus.NOT_FOUND)

            maximum_uses = int(row["maximum_uses"])
            uses_consumed = int(row["uses_consumed"])
            if row["state"] != "APPROVED" or uses_consumed >= maximum_uses:
                return ApprovalConsumeResult(
                    ApprovalConsumeStatus.INACTIVE, uses_consumed, maximum_uses
                )
            if int(row["expires_at_ms"]) <= now_ms:
                self.connection.execute(
                    "UPDATE approvals SET state = 'EXPIRED' WHERE approval_id = ?",
                    (approval_id,),
                )
                return ApprovalConsumeResult(
                    ApprovalConsumeStatus.EXPIRED, uses_consumed, maximum_uses
                )

            stored_fingerprint = bytes(row["request_fingerprint"])
            bindings_match = (
                row["session_id"] == session_id
                and row["service_id"] == service_id
                and row["operation"] == operation
                and row["pool_id"] == pool_id
                and hmac.compare_digest(stored_fingerprint, request_fingerprint)
            )
            if not bindings_match:
                return ApprovalConsumeResult(
                    ApprovalConsumeStatus.BINDING_MISMATCH,
                    uses_consumed,
                    maximum_uses,
                )

            maximum_cost = row["maximum_cost_units"]
            if maximum_cost is not None:
                if (
                    estimated_cost_units is None
                    or cost_unit != row["cost_unit"]
                    or estimated_cost_units > int(maximum_cost)
                ):
                    return ApprovalConsumeResult(
                        ApprovalConsumeStatus.COST_EXCEEDED,
                        uses_consumed,
                        maximum_uses,
                    )

            next_uses = uses_consumed + 1
            next_state = "CONSUMED" if next_uses >= maximum_uses else "APPROVED"
            cursor = self.connection.execute(
                """
                UPDATE approvals
                   SET uses_consumed = ?, state = ?, consumed_at_ms = ?
                 WHERE approval_id = ? AND state = 'APPROVED'
                   AND uses_consumed = ?
                """,
                (next_uses, next_state, now_ms, approval_id, uses_consumed),
            )
            if cursor.rowcount != 1:
                return ApprovalConsumeResult(
                    ApprovalConsumeStatus.INACTIVE, uses_consumed, maximum_uses
                )
            return ApprovalConsumeResult(ApprovalConsumeStatus.CONSUMED, next_uses, maximum_uses)
