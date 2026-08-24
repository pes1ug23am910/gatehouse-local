"""Race-safe repository helpers for security-critical state transitions."""

from __future__ import annotations

import hmac
import json
import sqlite3
import uuid
from dataclasses import dataclass
from enum import StrEnum

from gatehouse.core.provider_numbers import (
    MAX_PROVIDER_FIXED_POINT_CHARS,
    SQLITE_INT64_MAX,
    parse_canonical_provider_number,
    project_routing_units,
    require_sqlite_int64,
)

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


@dataclass(frozen=True, slots=True)
class BalanceAuthority:
    """A fresh quota projection proven to originate from one exact snapshot."""

    remaining_units: int
    balance_as_of_ms: int
    snapshot_id: str
    observation_kind: str
    source: str
    stale_at_ms: int | None


class BalanceAuthorityStatus(StrEnum):
    """Result of validating a quota scope's durable balance triplet."""

    VALID = "VALID"
    ABSENT = "ABSENT"
    STALE = "STALE"
    CORRUPT = "CORRUPT"


@dataclass(frozen=True, slots=True)
class BalanceAuthorityValidation:
    """A three-way balance result that retains data only for valid authority."""

    status: BalanceAuthorityStatus
    authority: BalanceAuthority | None = None

    def __post_init__(self) -> None:
        if (self.status is BalanceAuthorityStatus.VALID) != (self.authority is not None):
            raise ValueError("valid balance authority and status must be paired")


def validate_balance_authority(
    connection: sqlite3.Connection,
    *,
    quota_scope_id: object,
    unit: object,
    last_known_remaining_units: object,
    balance_as_of_ms: object,
    balance_snapshot_id: object,
    now_ms: int,
) -> BalanceAuthorityValidation:
    """Classify a durable balance triplet without normalizing or repairing it.

    The all-null triplet is intentionally absent. Any partially present or
    inconsistent authority is corrupt. Only a fully anchored canonical snapshot
    is valid and carries retained authority data.
    """

    if type(now_ms) is not int or not 0 <= now_ms <= SQLITE_INT64_MAX:
        raise ValueError("now_ms must be a nonnegative SQLite integer")
    if (
        last_known_remaining_units is None
        and balance_as_of_ms is None
        and balance_snapshot_id is None
    ):
        return BalanceAuthorityValidation(BalanceAuthorityStatus.ABSENT)
    if (
        type(quota_scope_id) is not str
        or not quota_scope_id
        or len(quota_scope_id) > 160
        or type(unit) is not str
        or not unit
        or len(unit) > 64
        or type(last_known_remaining_units) is not int
        or not 0 <= last_known_remaining_units <= SQLITE_INT64_MAX
        or type(balance_as_of_ms) is not int
        or not 0 <= balance_as_of_ms <= SQLITE_INT64_MAX
        or type(balance_snapshot_id) is not str
        or not balance_snapshot_id
        or len(balance_snapshot_id) > 160
    ):
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    snapshot = connection.execute(
        """
        SELECT snapshot_id, quota_scope_id, remaining_units, unit,
               captured_at_ms, observed_remaining_units_decimal,
               quota_dimension_id, credential_id, credential_generation,
               stale_at_ms, observation_kind, source, metadata_json
          FROM quota_snapshots
         WHERE snapshot_id = ?
        """,
        (balance_snapshot_id,),
    ).fetchone()
    if snapshot is None:
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    observed = snapshot["observed_remaining_units_decimal"]
    if (
        type(snapshot["snapshot_id"]) is not str
        or snapshot["snapshot_id"] != balance_snapshot_id
        or type(snapshot["quota_scope_id"]) is not str
        or snapshot["quota_scope_id"] != quota_scope_id
        or type(snapshot["unit"]) is not str
        or snapshot["unit"] != unit
        or type(snapshot["captured_at_ms"]) is not int
        or snapshot["captured_at_ms"] != balance_as_of_ms
        or type(snapshot["remaining_units"]) is not int
        or snapshot["remaining_units"] != last_known_remaining_units
        or type(observed) is not str
    ):
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    try:
        exact = parse_canonical_provider_number(
            observed,
            maximum_fixed_point_chars=MAX_PROVIDER_FIXED_POINT_CHARS,
        )
        projected = project_routing_units(exact)
    except (TypeError, ValueError):
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    if type(projected) is not int or projected != last_known_remaining_units:
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    dimension = connection.execute(
        """
        SELECT 1
          FROM quota_dimensions
         WHERE quota_dimension_id = ? AND quota_scope_id = ?
           AND native_unit = ? AND state = 'ACTIVE'
        """,
        (snapshot["quota_dimension_id"], quota_scope_id, unit),
    ).fetchone()
    if dimension is None:
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)

    observation_kind = snapshot["observation_kind"]
    stale_at_ms = snapshot["stale_at_ms"]
    source = snapshot["source"]
    if type(observation_kind) is not str or type(source) is not str or not source:
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    if observation_kind == "LEGACY":
        return BalanceAuthorityValidation(BalanceAuthorityStatus.STALE)
    if observation_kind == "SCRIPTED":
        scripted_scope = connection.execute(
            """
            SELECT 1
              FROM quota_scopes AS scope
              JOIN principals AS principal ON principal.principal_id = scope.principal_id
             WHERE scope.quota_scope_id = ?
               AND scope.metadata_json = '{"transport":"scripted","network":false}'
               AND principal.service_id = 'firecrawl'
            """,
            (quota_scope_id,),
        ).fetchone()
        if (
            snapshot["snapshot_id"] != "snapshot_gatehouse_scripted_no_network_v1"
            or source != "scripted-no-network-synthetic"
            or snapshot["metadata_json"]
            != '{"network":false,"synthetic":true,"transport":"scripted"}'
            or snapshot["credential_id"] is not None
            or snapshot["credential_generation"] is not None
            or stale_at_ms is not None
            or scripted_scope is None
        ):
            return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    elif observation_kind == "AUTHENTICATED":
        credential_id = snapshot["credential_id"]
        credential_generation = snapshot["credential_generation"]
        if (
            type(credential_id) is not str
            or not credential_id
            or type(credential_generation) is not int
            or credential_generation <= 0
            or type(stale_at_ms) is not int
            or stale_at_ms <= snapshot["captured_at_ms"]
        ):
            return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
        current_credential = connection.execute(
            """
            SELECT 1
              FROM credentials
             WHERE credential_id = ? AND quota_scope_id = ?
               AND generation = ? AND state IN ('HEALTHY', 'DRAINING')
            """,
            (credential_id, quota_scope_id, credential_generation),
        ).fetchone()
        if current_credential is None or now_ms >= stale_at_ms:
            return BalanceAuthorityValidation(BalanceAuthorityStatus.STALE)
    else:
        return BalanceAuthorityValidation(BalanceAuthorityStatus.CORRUPT)
    return BalanceAuthorityValidation(
        BalanceAuthorityStatus.VALID,
        BalanceAuthority(
            remaining_units=last_known_remaining_units,
            balance_as_of_ms=balance_as_of_ms,
            snapshot_id=balance_snapshot_id,
            observation_kind=observation_kind,
            source=source,
            stale_at_ms=stale_at_ms,
        ),
    )


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
        reconciliation: bool = False,
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
        if not isinstance(reconciliation, bool):
            raise ValueError("reconciliation must be boolean")
        if reconciliation and not exact_affinity:
            raise ValueError("reconciliation credential leases require exact affinity")
        if expires_at_ms <= now_ms:
            raise ValueError("lease expiration must be in the future")

        candidate_id = lease_id or _identifier("lease")
        lease_key = f"{credential_id}:{credential_generation}:dispatch:{owner_id}"
        stored_metadata = dict(metadata or {})
        stored_metadata.update(
            {
                "credential_id": credential_id,
                "credential_generation": credential_generation,
                "quota_scope_id": quota_scope_id,
                "pool_id": pool_id,
                "exact_affinity": exact_affinity,
                "credential_dispatch": True,
                "request_id": owner_id,
            }
        )

        with transaction(self.connection, "IMMEDIATE"):
            eligible = self.connection.execute(
                """
                SELECT qs.quota_scope_id, qs.unit, qs.last_known_remaining_units,
                       qs.balance_as_of_ms, qs.balance_snapshot_id
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
                   AND (
                       (? = 0 AND qs.state = 'HEALTHY')
                       OR (
                           ? = 1
                           AND qs.state NOT IN ('DISABLED', 'QUARANTINED')
                       )
                   )
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
                    int(reconciliation),
                    int(reconciliation),
                ),
            ).fetchone()
            if eligible is None:
                return LeaseResult(LeaseStatus.INELIGIBLE, None, None, None)
            authority = validate_balance_authority(
                self.connection,
                quota_scope_id=eligible["quota_scope_id"],
                unit=eligible["unit"],
                last_known_remaining_units=eligible["last_known_remaining_units"],
                balance_as_of_ms=eligible["balance_as_of_ms"],
                balance_snapshot_id=eligible["balance_snapshot_id"],
                now_ms=now_ms,
            )
            if authority.status is BalanceAuthorityStatus.CORRUPT or (
                authority.status is not BalanceAuthorityStatus.VALID and not reconciliation
            ):
                return LeaseResult(LeaseStatus.INELIGIBLE, None, None, None)

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

            already_owned = self.connection.execute(
                """
                SELECT lease_id, lease_key, owner_id, expires_at_ms
                  FROM leases
                 WHERE lease_type = 'provider-credential' AND state = 'ACTIVE'
                   AND owner_id = ?
                   AND json_extract(metadata_json, '$.credential_dispatch') = 1
                   AND json_extract(metadata_json, '$.credential_id') = ?
                   AND json_extract(metadata_json, '$.credential_generation') = ?
                  ORDER BY acquired_at_ms, lease_id
                 LIMIT 1
                """,
                (owner_id, credential_id, credential_generation),
            ).fetchone()
            if already_owned is not None:
                return LeaseResult(
                    status=LeaseStatus.ALREADY_OWNED,
                    lease_id=str(already_owned["lease_id"]),
                    owner_id=str(already_owned["owner_id"]),
                    expires_at_ms=int(already_owned["expires_at_ms"]),
                )

            exclusive = self.connection.execute(
                """
                SELECT lease_id, owner_id, expires_at_ms
                  FROM leases
                 WHERE lease_type = 'provider-credential' AND state = 'ACTIVE'
                   AND (
                       lease_key = ?
                       OR substr(lease_key, 1, length(?) + 1) = ? || ':'
                       OR json_extract(metadata_json, '$.credential_id') = ?
                   )
                   AND COALESCE(
                       json_extract(metadata_json, '$.credential_dispatch'), 0
                   ) != 1
                 ORDER BY acquired_at_ms, lease_id
                 LIMIT 1
                """,
                (credential_id, credential_id, credential_id, credential_id),
            ).fetchone()
            if exclusive is not None:
                return LeaseResult(
                    status=LeaseStatus.BUSY,
                    lease_id=str(exclusive["lease_id"]),
                    owner_id=str(exclusive["owner_id"]),
                    expires_at_ms=int(exclusive["expires_at_ms"]),
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

        amount_units = require_sqlite_int64(amount_units, field="amount_units", minimum=0)
        if amount_units == 0:
            raise ValueError("amount_units must be positive")
        if not unit:
            raise ValueError("unit is required")
        if expires_at_ms <= now_ms:
            raise ValueError("reservation expiration must be in the future")
        candidate_id = reservation_id or _identifier("reservation")

        with transaction(self.connection, "IMMEDIATE"):
            scope = self.connection.execute(
                """
                SELECT quota_scope_id, state, unit, last_known_remaining_units,
                       configured_floor_units, balance_as_of_ms,
                       balance_snapshot_id
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
            authority_validation = validate_balance_authority(
                self.connection,
                quota_scope_id=scope["quota_scope_id"],
                unit=scope["unit"],
                last_known_remaining_units=scope["last_known_remaining_units"],
                balance_as_of_ms=scope["balance_as_of_ms"],
                balance_snapshot_id=scope["balance_snapshot_id"],
                now_ms=now_ms,
            )
            if authority_validation.status in {
                BalanceAuthorityStatus.ABSENT,
                BalanceAuthorityStatus.STALE,
            }:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNKNOWN_BALANCE, None, None, None
                )
            if authority_validation.status is BalanceAuthorityStatus.CORRUPT:
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)
            authority = authority_validation.authority
            if authority is None:
                raise RuntimeError("valid balance authority is missing")

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
                        authority.balance_as_of_ms,
                        authority.balance_as_of_ms,
                        quota_scope_id,
                    ),
                ).fetchone()[0]
            )
            available = (
                authority.remaining_units - int(scope["configured_floor_units"]) - committed_units
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

        if actual_units is not None:
            actual_units = require_sqlite_int64(
                actual_units,
                field="actual_units",
                minimum=0,
            )
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

        amount_units = require_sqlite_int64(amount_units, field="amount_units", minimum=0)
        if amount_units == 0:
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
                SELECT quota_scope_id, state, unit, last_known_remaining_units,
                       configured_floor_units, balance_as_of_ms,
                       balance_snapshot_id
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
            authority_validation = validate_balance_authority(
                self.connection,
                quota_scope_id=scope["quota_scope_id"],
                unit=scope["unit"],
                last_known_remaining_units=scope["last_known_remaining_units"],
                balance_as_of_ms=scope["balance_as_of_ms"],
                balance_snapshot_id=scope["balance_snapshot_id"],
                now_ms=now_ms,
            )
            if authority_validation.status in {
                BalanceAuthorityStatus.ABSENT,
                BalanceAuthorityStatus.STALE,
            }:
                return QuotaReservationResult(
                    QuotaReservationStatus.UNKNOWN_BALANCE, None, None, None
                )
            if authority_validation.status is BalanceAuthorityStatus.CORRUPT:
                return QuotaReservationResult(QuotaReservationStatus.INELIGIBLE, None, None, None)
            authority = authority_validation.authority
            if authority is None:
                raise RuntimeError("valid balance authority is missing")

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
                        authority.balance_as_of_ms,
                        authority.balance_as_of_ms,
                        quota_scope_id,
                        old_reservation_id,
                    ),
                ).fetchone()[0]
            )
            available = (
                authority.remaining_units - int(scope["configured_floor_units"]) - committed_units
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
        policy_id: str | None = None,
        policy_rule_id: str | None = None,
        policy_version: str | None = None,
        now_ms: int,
    ) -> ApprovalConsumeResult:
        """Consume a one-use or bounded-use approval with full request binding."""

        if estimated_cost_units is not None:
            estimated_cost_units = require_sqlite_int64(
                estimated_cost_units,
                field="estimated_cost_units",
                minimum=0,
            )
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
            policy_bindings = (policy_id, policy_rule_id, policy_version)
            if any(value is not None for value in policy_bindings):
                if any(value is None for value in policy_bindings):
                    bindings_match = False
                else:
                    try:
                        metadata = json.loads(str(row["metadata_json"]))
                    except (TypeError, ValueError):
                        bindings_match = False
                    else:
                        bindings_match = (
                            bindings_match
                            and isinstance(metadata, dict)
                            and (
                                metadata.get("policy_id") == policy_id
                                and metadata.get("policy_rule_id") == policy_rule_id
                                and metadata.get("policy_version") == policy_version
                            )
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
