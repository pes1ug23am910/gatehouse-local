"""Crash-safe SQLite persistence for session and root-run authority."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.states import SESSION_TRANSITIONS, SessionState
from gatehouse.database.connection import transaction

from .models import RootRunRecord, RootRunState, SessionRecord
from .persistence import (
    SessionCreationRequest,
    SessionCreationRequestConflict,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
    session_request_digest,
)

_MAX_ACCOUNTING_JSON_BYTES = 4_096
_MAX_ACCOUNTING_ITEMS = 32
_MAX_ACCOUNTING_KEY_LENGTH = 64
_MAX_SIGNED_64 = (1 << 63) - 1

_SESSION_COLUMNS = """
    session_id, client_id, workspace_id, bootstrap_verifier,
    bootstrap_version, token_epoch, revocation_epoch, state,
    identity_assurance, policy_version, created_at_ms, last_seen_at_ms,
    disconnected_at_ms, reconnect_until_ms, absolute_expires_at_ms,
    revoked_at_ms, budget_json
"""

_ROOT_RUN_COLUMNS = """
    root_run_id, session_id, state, started_at_ms, ended_at_ms,
    budget_json, consumed_json
"""


def _text(row: sqlite3.Row, name: str, *, optional: bool = False) -> str | None:
    value: Any = row[name]
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"persisted {name} must be a non-empty string")
    return value


def _integer(row: sqlite3.Row, name: str, *, optional: bool = False) -> int | None:
    value: Any = row[name]
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"persisted {name} must be an integer")
    return int(value)


def _timestamp(row: sqlite3.Row, name: str, *, optional: bool = False) -> int | None:
    value = _integer(row, name, optional=optional)
    if value is None:
        return None
    return require_utc_ms(value)


def _blob(row: sqlite3.Row, name: str) -> bytes:
    value: Any = row[name]
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"persisted {name} must be binary")
    return bytes(value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("accounting JSON contains a duplicate key")
        value[key] = item
    return value


def _normalize_accounting(value: object, *, field: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ValueError(f"persisted {field} must be a JSON object")
    if len(value) > _MAX_ACCOUNTING_ITEMS:
        raise ValueError(f"persisted {field} contains too many entries")
    normalized: dict[str, int] = {}
    for key, amount in value.items():
        if not isinstance(key, str) or not key or len(key) > _MAX_ACCOUNTING_KEY_LENGTH:
            raise ValueError(f"persisted {field} contains an invalid unit")
        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or not 0 <= amount <= _MAX_SIGNED_64
        ):
            raise ValueError(f"persisted {field} contains an invalid amount")
        normalized[key] = amount
    return normalized


def _decode_accounting(raw: object, *, field: str) -> dict[str, int]:
    if not isinstance(raw, str):
        raise ValueError(f"persisted {field} must be JSON text")
    if len(raw.encode("utf-8")) > _MAX_ACCOUNTING_JSON_BYTES:
        raise ValueError(f"persisted {field} exceeds its size bound")
    try:
        decoded: object = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise ValueError(f"persisted {field} is invalid JSON") from error
    return _normalize_accounting(decoded, field=field)


def _encode_accounting(value: Mapping[str, int], *, field: str) -> str:
    normalized = _normalize_accounting(value, field=field)
    encoded = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    if len(encoded.encode("utf-8")) > _MAX_ACCOUNTING_JSON_BYTES:
        raise ValueError(f"persisted {field} exceeds its size bound")
    return encoded


def _session_from_row(row: sqlite3.Row) -> SessionRecord:
    session_id = _text(row, "session_id")
    client_id = _text(row, "client_id")
    workspace_id = _text(row, "workspace_id", optional=True)
    identity_assurance = _text(row, "identity_assurance")
    policy_version = _text(row, "policy_version")
    assert session_id is not None
    assert client_id is not None
    assert identity_assurance is not None
    assert policy_version is not None
    bootstrap_version = _integer(row, "bootstrap_version")
    token_epoch = _integer(row, "token_epoch")
    revocation_epoch = _integer(row, "revocation_epoch")
    created_at_ms = _timestamp(row, "created_at_ms")
    reconnect_until_ms = _timestamp(row, "reconnect_until_ms")
    absolute_expires_at_ms = _timestamp(row, "absolute_expires_at_ms")
    assert bootstrap_version is not None
    assert token_epoch is not None
    assert revocation_epoch is not None
    assert created_at_ms is not None
    assert reconnect_until_ms is not None
    assert absolute_expires_at_ms is not None
    return SessionRecord(
        session_id=session_id,
        client_id=client_id,
        workspace_id=workspace_id,
        bootstrap_verifier=_blob(row, "bootstrap_verifier"),
        bootstrap_version=bootstrap_version,
        token_epoch=token_epoch,
        revocation_epoch=revocation_epoch,
        state=SessionState(str(_text(row, "state"))),
        identity_assurance=identity_assurance,
        policy_version=policy_version,
        created_at_ms=created_at_ms,
        last_seen_at_ms=_timestamp(row, "last_seen_at_ms", optional=True),
        disconnected_at_ms=_timestamp(row, "disconnected_at_ms", optional=True),
        reconnect_until_ms=reconnect_until_ms,
        absolute_expires_at_ms=absolute_expires_at_ms,
        revoked_at_ms=_timestamp(row, "revoked_at_ms", optional=True),
        budget=_decode_accounting(row["budget_json"], field="budget_json"),
    )


def _root_run_from_row(row: sqlite3.Row) -> RootRunRecord:
    root_run_id = _text(row, "root_run_id")
    session_id = _text(row, "session_id")
    started_at_ms = _timestamp(row, "started_at_ms")
    assert root_run_id is not None
    assert session_id is not None
    assert started_at_ms is not None
    return RootRunRecord(
        root_run_id=root_run_id,
        session_id=session_id,
        state=RootRunState(str(_text(row, "state"))),
        started_at_ms=started_at_ms,
        ended_at_ms=_timestamp(row, "ended_at_ms", optional=True),
        budget=_decode_accounting(row["budget_json"], field="budget_json"),
        consumed=_decode_accounting(row["consumed_json"], field="consumed_json"),
    )


def _same_authority(expected: SessionRecord, replacement: SessionRecord) -> bool:
    return (
        replacement.session_id == expected.session_id
        and replacement.client_id == expected.client_id
        and replacement.workspace_id == expected.workspace_id
        and replacement.bootstrap_verifier == expected.bootstrap_verifier
        and replacement.bootstrap_version == expected.bootstrap_version
        and replacement.identity_assurance == expected.identity_assurance
        and replacement.policy_version == expected.policy_version
        and replacement.created_at_ms == expected.created_at_ms
        and replacement.absolute_expires_at_ms == expected.absolute_expires_at_ms
        and replacement.budget == expected.budget
    )


class SqliteSessionPersistence:
    """Persist session authority using short single-connection transactions.

    ``recovered_token_epoch`` is a one-shot handoff from ``recover_startup``.
    The first call to :meth:`begin_daemon_epoch` validates and adopts that
    already-advanced epoch instead of incrementing it again.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        recovered_token_epoch: int | None = None,
    ) -> None:
        if recovered_token_epoch is not None and (
            isinstance(recovered_token_epoch, bool)
            or not isinstance(recovered_token_epoch, int)
            or not 0 <= recovered_token_epoch <= _MAX_SIGNED_64
        ):
            raise ValueError("recovered token epoch must be non-negative")
        self.connection = connection
        self._recovered_token_epoch = recovered_token_epoch

    async def begin_daemon_epoch(self, *, now_ms: int, reconnect_grace_ms: int) -> int:
        require_utc_ms(now_ms)
        if (
            isinstance(reconnect_grace_ms, bool)
            or not isinstance(reconnect_grace_ms, int)
            or reconnect_grace_ms <= 0
        ):
            raise ValueError("reconnect grace must be positive")
        reconnect_until_ms = require_utc_ms(now_ms + reconnect_grace_ms)
        adopted_recovery = False
        with transaction(self.connection, "IMMEDIATE"):
            row = self.connection.execute(
                """
                SELECT token_epoch, daemon_state
                  FROM system_state WHERE singleton_id = 1
                """
            ).fetchone()
            if row is None:
                raise RuntimeError("database is missing the system_state singleton")
            current_epoch = _integer(row, "token_epoch")
            daemon_state = _text(row, "daemon_state")
            assert current_epoch is not None
            assert daemon_state is not None

            if self._recovered_token_epoch is not None:
                if current_epoch != self._recovered_token_epoch or daemon_state != "RECOVERING":
                    raise RuntimeError("recovered token epoch does not match startup recovery")
                epoch = current_epoch
                adopted_recovery = True
                self.connection.execute(
                    """
                    UPDATE sessions
                       SET reconnect_until_ms = MIN(
                               reconnect_until_ms,
                               absolute_expires_at_ms,
                               ?
                           )
                     WHERE state = 'DISCONNECTED'
                       AND token_epoch = ?
                       AND disconnected_at_ms = ?
                    """,
                    (reconnect_until_ms, epoch, now_ms),
                )
            else:
                epoch = current_epoch + 1
                if epoch > _MAX_SIGNED_64:
                    raise RuntimeError("token epoch exhausted its durable range")
                self.connection.execute(
                    """
                    UPDATE system_state
                       SET token_epoch = ?, daemon_state = 'RECOVERING',
                           last_started_at_ms = ?
                     WHERE singleton_id = 1
                    """,
                    (epoch, now_ms),
                )
                self.connection.execute(
                    """
                    UPDATE sessions
                       SET state = 'EXPIRED',
                           disconnected_at_ms = COALESCE(disconnected_at_ms, ?)
                     WHERE state IN ('CREATED', 'ACTIVE', 'DISCONNECTED', 'SUSPENDED')
                       AND absolute_expires_at_ms <= ?
                    """,
                    (now_ms, now_ms),
                )
                self.connection.execute(
                    """
                    UPDATE sessions
                       SET state = 'DISCONNECTED', token_epoch = ?,
                           disconnected_at_ms = ?,
                           reconnect_until_ms = MIN(absolute_expires_at_ms, ?)
                     WHERE state = 'ACTIVE' AND absolute_expires_at_ms > ?
                    """,
                    (epoch, now_ms, reconnect_until_ms, now_ms),
                )
        if adopted_recovery:
            self._recovered_token_epoch = None
        return epoch

    def _normalize_client_sessions_locked(
        self,
        *,
        client_id: str,
        now_ms: int,
        stale_after_ms: int,
        reconnect_grace_ms: int,
    ) -> None:
        stale_before_or_at_ms = now_ms - stale_after_ms
        self.connection.execute(
            """
            UPDATE sessions
               SET state = 'EXPIRED',
                   disconnected_at_ms = COALESCE(disconnected_at_ms, ?)
             WHERE client_id = ?
               AND state IN ('CREATED', 'ACTIVE', 'DISCONNECTED', 'SUSPENDED')
               AND absolute_expires_at_ms <= ?
            """,
            (now_ms, client_id, now_ms),
        )
        self.connection.execute(
            """
            UPDATE sessions
               SET state = 'EXPIRED', disconnected_at_ms = created_at_ms + ?
             WHERE client_id = ? AND state = 'CREATED'
               AND created_at_ms <= ?
            """,
            (stale_after_ms, client_id, stale_before_or_at_ms),
        )
        self.connection.execute(
            """
            UPDATE sessions
               SET state = 'DISCONNECTED',
                   disconnected_at_ms = COALESCE(last_seen_at_ms, created_at_ms) + ?,
                   reconnect_until_ms = MIN(
                       absolute_expires_at_ms,
                       COALESCE(last_seen_at_ms, created_at_ms) + ? + ?
                   )
             WHERE client_id = ? AND state = 'ACTIVE'
               AND COALESCE(last_seen_at_ms, created_at_ms) <= ?
            """,
            (
                stale_after_ms,
                stale_after_ms,
                reconnect_grace_ms,
                client_id,
                stale_before_or_at_ms,
            ),
        )
        self.connection.execute(
            """
            UPDATE sessions
               SET state = 'EXPIRED',
                   disconnected_at_ms = COALESCE(disconnected_at_ms, reconnect_until_ms)
             WHERE client_id = ? AND state = 'DISCONNECTED'
               AND reconnect_until_ms <= ?
            """,
            (client_id, now_ms),
        )

    def _client_has_blocking_runaway_locked(self, client_id: str) -> bool:
        return (
            self.connection.execute(
                """
                SELECT 1
                  FROM runaway_quarantines AS quarantine
                  JOIN sessions AS owner ON owner.session_id = quarantine.session_id
                 WHERE owner.client_id = ?
                   AND quarantine.state IN (
                       'OPEN', 'AUTHORIZED', 'DENIED', 'EXPIRED', 'EXHAUSTED'
                   )
                   AND NOT EXISTS (
                       SELECT 1
                         FROM runaway_quarantine_recoveries AS recovery
                        WHERE recovery.client_id = owner.client_id
                          AND recovery.quarantine_id = quarantine.quarantine_id
                          AND recovery.quarantine_generation = quarantine.generation
                   )
                 LIMIT 1
                """,
                (client_id,),
            ).fetchone()
            is not None
        )

    async def insert_session(
        self,
        session: SessionRecord,
        *,
        maximum_concurrent_runs: int | None,
        stale_after_ms: int,
        reconnect_grace_ms: int,
        block_on_runaway_quarantine: bool,
        creation_request: SessionCreationRequest | None = None,
    ) -> None:
        if maximum_concurrent_runs is not None and (
            isinstance(maximum_concurrent_runs, bool)
            or not isinstance(maximum_concurrent_runs, int)
            or maximum_concurrent_runs <= 0
        ):
            raise ValueError("maximum concurrent runs must be positive")
        if (
            isinstance(stale_after_ms, bool)
            or not isinstance(stale_after_ms, int)
            or stale_after_ms <= 0
            or isinstance(reconnect_grace_ms, bool)
            or not isinstance(reconnect_grace_ms, int)
            or reconnect_grace_ms <= 0
        ):
            raise ValueError("session liveness bounds must be positive")
        if block_on_runaway_quarantine and maximum_concurrent_runs is None:
            raise ValueError("runaway launch fencing requires a configured client profile")
        budget_json = _encode_accounting(session.budget, field="budget_json")
        now_ms = session.created_at_ms
        if self.connection.in_transaction:
            raise SessionCreationRequestConflict()
        with transaction(self.connection, "IMMEDIATE"):
            if creation_request is not None:
                existing = self.connection.execute(
                    "SELECT 1 FROM controlled_session_requests WHERE request_digest = ?",
                    (creation_request.request_digest,),
                ).fetchone()
                if existing is not None:
                    raise SessionCreationRequestConflict()
            self._normalize_client_sessions_locked(
                client_id=session.client_id,
                now_ms=now_ms,
                stale_after_ms=stale_after_ms,
                reconnect_grace_ms=reconnect_grace_ms,
            )
            if block_on_runaway_quarantine and self._client_has_blocking_runaway_locked(
                session.client_id
            ):
                raise SessionRunawayQuarantined("client profile has a blocking runaway quarantine")
            if maximum_concurrent_runs is not None:
                active_count = self.connection.execute(
                    """
                    SELECT COUNT(*)
                      FROM sessions
                     WHERE client_id = ?
                       AND state IN ('CREATED', 'ACTIVE', 'DISCONNECTED', 'SUSPENDED')
                    """,
                    (session.client_id,),
                ).fetchone()
                if active_count is None:
                    raise RuntimeError("session run admission count is unavailable")
                if int(active_count[0]) >= maximum_concurrent_runs:
                    raise SessionRunCapacityExceeded(
                        "client profile concurrent-run capacity is exhausted"
                    )
            self.connection.execute(
                """
                INSERT INTO sessions(
                    session_id, client_id, workspace_id, bootstrap_verifier,
                    bootstrap_version, token_epoch, revocation_epoch, state,
                    identity_assurance, policy_version, created_at_ms,
                    last_seen_at_ms, disconnected_at_ms, reconnect_until_ms,
                    absolute_expires_at_ms, revoked_at_ms, budget_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.client_id,
                    session.workspace_id,
                    session.bootstrap_verifier,
                    session.bootstrap_version,
                    session.token_epoch,
                    session.revocation_epoch,
                    session.state.value,
                    session.identity_assurance,
                    session.policy_version,
                    session.created_at_ms,
                    session.last_seen_at_ms,
                    session.disconnected_at_ms,
                    session.reconnect_until_ms,
                    session.absolute_expires_at_ms,
                    session.revoked_at_ms,
                    budget_json,
                ),
            )

            if creation_request is not None:
                try:
                    self.connection.execute(
                        """INSERT INTO controlled_session_requests(
                               request_digest, authority_digest, session_id, state,
                               created_at_ms, updated_at_ms
                           ) VALUES (?, ?, ?, 'BOUND', ?, ?)""",
                        (
                            creation_request.request_digest,
                            creation_request.authority_digest,
                            session.session_id,
                            now_ms,
                            now_ms,
                        ),
                    )
                except sqlite3.IntegrityError:
                    raise SessionCreationRequestConflict() from None

    async def cancel_session_request(self, request_id: str, *, now_ms: int) -> str | None:
        digest = session_request_digest(request_id)
        require_utc_ms(now_ms)
        if self.connection.in_transaction:
            raise SessionCreationRequestConflict()
        with transaction(self.connection, "IMMEDIATE"):
            row = self.connection.execute(
                "SELECT session_id FROM controlled_session_requests WHERE request_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                try:
                    self.connection.execute(
                        """INSERT INTO controlled_session_requests(
                               request_digest, state, created_at_ms, updated_at_ms
                           ) VALUES (?, 'CANCELLED', ?, ?)""",
                        (digest, now_ms, now_ms),
                    )
                except sqlite3.IntegrityError:
                    raise SessionCreationRequestConflict() from None
                return None
            self.connection.execute(
                """UPDATE controlled_session_requests SET state = 'CANCELLED',
                          updated_at_ms = MAX(updated_at_ms, ?)
                   WHERE request_digest = ?""",
                (now_ms, digest),
            )
            return _text(row, "session_id", optional=True)

    async def load_session(self, session_id: str) -> SessionRecord | None:
        row = self.connection.execute(
            f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE session_id = ?",  # noqa: S608
            (session_id,),
        ).fetchone()
        return None if row is None else _session_from_row(row)

    async def replace_session(
        self,
        *,
        expected: SessionRecord,
        replacement: SessionRecord,
    ) -> bool:
        if not _same_authority(expected, replacement):
            raise ValueError("session replacement cannot change durable authority")
        if replacement.token_epoch < expected.token_epoch:
            raise ValueError("session token epoch cannot move backwards")
        if replacement.revocation_epoch < expected.revocation_epoch:
            raise ValueError("session revocation epoch cannot move backwards")
        if replacement.state is not expected.state:
            SESSION_TRANSITIONS.require(expected.state, replacement.state)
        budget_json = _encode_accounting(replacement.budget, field="budget_json")
        with transaction(self.connection, "IMMEDIATE"):
            row = self.connection.execute(
                f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE session_id = ?",  # noqa: S608
                (expected.session_id,),
            ).fetchone()
            if row is None or _session_from_row(row) != expected:
                return False
            updated = self.connection.execute(
                """
                UPDATE sessions
                   SET client_id = ?, workspace_id = ?, bootstrap_verifier = ?,
                       bootstrap_version = ?, token_epoch = ?, revocation_epoch = ?,
                       state = ?, identity_assurance = ?, policy_version = ?,
                       created_at_ms = ?, last_seen_at_ms = ?, disconnected_at_ms = ?,
                       reconnect_until_ms = ?, absolute_expires_at_ms = ?,
                       revoked_at_ms = ?, budget_json = ?
                 WHERE session_id = ?
                """,
                (
                    replacement.client_id,
                    replacement.workspace_id,
                    replacement.bootstrap_verifier,
                    replacement.bootstrap_version,
                    replacement.token_epoch,
                    replacement.revocation_epoch,
                    replacement.state.value,
                    replacement.identity_assurance,
                    replacement.policy_version,
                    replacement.created_at_ms,
                    replacement.last_seen_at_ms,
                    replacement.disconnected_at_ms,
                    replacement.reconnect_until_ms,
                    replacement.absolute_expires_at_ms,
                    replacement.revoked_at_ms,
                    budget_json,
                    replacement.session_id,
                ),
            )
            return updated.rowcount == 1

    async def insert_root_run(
        self,
        root_run: RootRunRecord,
        *,
        client_id: str,
        maximum_concurrent_runs: int | None,
        now_ms: int,
        stale_after_ms: int,
        reconnect_grace_ms: int,
        block_on_runaway_quarantine: bool,
    ) -> None:
        if not client_id:
            raise ValueError("root-run client identifier is required")
        require_utc_ms(now_ms)
        if maximum_concurrent_runs is not None and (
            isinstance(maximum_concurrent_runs, bool)
            or not isinstance(maximum_concurrent_runs, int)
            or maximum_concurrent_runs <= 0
        ):
            raise ValueError("maximum concurrent runs must be positive")
        if (
            isinstance(stale_after_ms, bool)
            or not isinstance(stale_after_ms, int)
            or stale_after_ms <= 0
            or isinstance(reconnect_grace_ms, bool)
            or not isinstance(reconnect_grace_ms, int)
            or reconnect_grace_ms <= 0
        ):
            raise ValueError("session liveness bounds must be positive")
        if block_on_runaway_quarantine and maximum_concurrent_runs is None:
            raise ValueError("runaway launch fencing requires a configured client profile")
        budget_json = _encode_accounting(root_run.budget, field="budget_json")
        consumed_json = _encode_accounting(root_run.consumed, field="consumed_json")
        with transaction(self.connection, "IMMEDIATE"):
            self._normalize_client_sessions_locked(
                client_id=client_id,
                now_ms=now_ms,
                stale_after_ms=stale_after_ms,
                reconnect_grace_ms=reconnect_grace_ms,
            )
            owner = self.connection.execute(
                """
                SELECT 1 FROM sessions
                 WHERE session_id = ? AND client_id = ? AND state = 'ACTIVE'
                   AND absolute_expires_at_ms > ?
                """,
                (root_run.session_id, client_id, now_ms),
            ).fetchone()
            if owner is None:
                raise SessionRunCapacityExceeded("root-run owner is not active")
            if block_on_runaway_quarantine and self._client_has_blocking_runaway_locked(client_id):
                raise SessionRunawayQuarantined("client profile has a blocking runaway quarantine")
            if maximum_concurrent_runs is not None:
                active_count = self.connection.execute(
                    """
                    SELECT COUNT(*)
                      FROM root_runs AS root
                      JOIN sessions AS owner ON owner.session_id = root.session_id
                     WHERE owner.client_id = ? AND root.state = 'ACTIVE'
                       AND owner.state IN ('CREATED', 'ACTIVE', 'DISCONNECTED', 'SUSPENDED')
                    """,
                    (client_id,),
                ).fetchone()
                if active_count is None:
                    raise RuntimeError("root-run admission count is unavailable")
                if int(active_count[0]) >= maximum_concurrent_runs:
                    raise SessionRunCapacityExceeded(
                        "client profile concurrent-run capacity is exhausted"
                    )
            self.connection.execute(
                """
                INSERT INTO root_runs(
                    root_run_id, session_id, state, started_at_ms, ended_at_ms,
                    budget_json, consumed_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    root_run.root_run_id,
                    root_run.session_id,
                    root_run.state.value,
                    root_run.started_at_ms,
                    root_run.ended_at_ms,
                    budget_json,
                    consumed_json,
                ),
            )

    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None:
        row = self.connection.execute(
            f"SELECT {_ROOT_RUN_COLUMNS} FROM root_runs WHERE root_run_id = ?",  # noqa: S608
            (root_run_id,),
        ).fetchone()
        return None if row is None else _root_run_from_row(row)
