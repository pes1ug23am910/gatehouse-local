"""Retained, request-bound send evidence for fixed authenticated credit reads."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Literal

from gatehouse.core.clock import require_utc_ms
from gatehouse.providers.base import ProviderErrorClass

from .connection import transaction

_SCHEDULED_SOURCE = "scheduled-firecrawl-credit-observation"
_SOURCES = frozenset(
    {
        _SCHEDULED_SOURCE,
        "admin-credential-validation",
        "account-manual-refresh",
    }
)


class ObservationIntentConflict(RuntimeError):
    """A request was already sent or automatic observation has unresolved evidence."""


class ObservationOutcomeUnresolved(ObservationIntentConflict):
    """Automatic observation is blocked by a previous ambiguous exchange."""


@dataclass(frozen=True, slots=True)
class ObservationIntent:
    intent_id: str
    state: str


def _identifier(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 160
        or len(value.encode("utf-8")) > 160
        or any(c in value for c in "\x00\r\n")
    ):
        raise ValueError("observation intent identifier is invalid")
    return value


class SqliteObservationIntentStore:
    """Admit at most 100,000 retained intents without holding a transaction over I/O."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def has_unresolved(self, credential_id: str, credential_generation: int) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM provider_observation_intents "
            "WHERE credential_id = ? AND credential_generation = ? "
            "AND state IN ('SEND_INTENT', 'UNKNOWN') AND resolved_by_intent_id IS NULL LIMIT 1",
            (credential_id, credential_generation),
        ).fetchone()
        return row is not None

    def begin(
        self,
        *,
        intent_id: str,
        request_id: str,
        credential_id: str,
        credential_generation: int,
        principal_id: str,
        quota_scope_id: str,
        actor_id: str,
        source: str,
        now_ms: int,
    ) -> ObservationIntent:
        for value in (intent_id, request_id, credential_id, principal_id, quota_scope_id, actor_id):
            _identifier(value)
        require_utc_ms(now_ms)
        if type(credential_generation) is not int or not 1 <= credential_generation < (1 << 63):
            raise ValueError("observation intent generation is invalid")
        if source not in _SOURCES:
            raise ValueError("observation intent source is invalid")
        digest = hashlib.sha256(
            b"gatehouse:provider-observation-request:v1\x00" + request_id.encode("utf-8"),
        ).hexdigest()
        with transaction(self.connection, "IMMEDIATE"):
            if (
                self.connection.execute(
                    "SELECT 1 FROM provider_observation_intents WHERE request_digest = ?",
                    (digest,),
                ).fetchone()
                is not None
            ):
                raise ObservationIntentConflict("observation request already has send evidence")
            if source == _SCHEDULED_SOURCE and self.has_unresolved(
                credential_id,
                credential_generation,
            ):
                raise ObservationOutcomeUnresolved("credential observation outcome is unresolved")
            authority = self.connection.execute(
                "SELECT 1 FROM credentials AS c JOIN principals AS p "
                "ON p.principal_id = c.principal_id JOIN quota_scopes AS q "
                "ON q.quota_scope_id = c.quota_scope_id WHERE c.credential_id = ? "
                "AND c.generation = ? AND c.principal_id = ? AND c.quota_scope_id = ? "
                "AND q.principal_id = p.principal_id AND c.state = 'HEALTHY' "
                "AND p.service_id = 'firecrawl' AND p.enabled = 1 AND q.unit = 'credits' "
                "AND (c.expires_at_ms IS NULL OR c.expires_at_ms > ?)",
                (credential_id, credential_generation, principal_id, quota_scope_id, now_ms),
            ).fetchone()
            if authority is None:
                raise ObservationIntentConflict("observation credential authority changed")
            self.connection.execute(
                "INSERT INTO provider_observation_intents(intent_id, request_digest, "
                "credential_id, credential_generation, principal_id, quota_scope_id, actor_id, "
                "source, operation, state, created_at_ms, updated_at_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'firecrawl.account.credit_status', "
                "'SEND_INTENT', ?, ?)",
                (
                    intent_id,
                    digest,
                    credential_id,
                    credential_generation,
                    principal_id,
                    quota_scope_id,
                    actor_id,
                    source,
                    now_ms,
                    now_ms,
                ),
            )
        return ObservationIntent(intent_id, "SEND_INTENT")

    def fail(
        self,
        intent_id: str,
        *,
        state: Literal["FAILED", "UNKNOWN"],
        error_class: ProviderErrorClass,
        now_ms: int,
    ) -> None:
        _identifier(intent_id)
        require_utc_ms(now_ms)
        if state not in {"FAILED", "UNKNOWN"} or type(error_class) is not ProviderErrorClass:
            raise ValueError("observation intent failure is invalid")
        with transaction(self.connection, "IMMEDIATE"):
            updated = self.connection.execute(
                "UPDATE provider_observation_intents SET state = ?, error_class = ?, "
                "updated_at_ms = ? WHERE intent_id = ? AND state = 'SEND_INTENT'",
                (state, error_class.value, now_ms, intent_id),
            )
            if updated.rowcount != 1:
                raise ObservationIntentConflict("observation intent lost its completion fence")

    def succeed(
        self,
        intent_id: str,
        *,
        snapshot_id: str,
        audit_event_id: str,
        now_ms: int,
    ) -> None:
        for value in (intent_id, snapshot_id, audit_event_id):
            _identifier(value)
        require_utc_ms(now_ms)
        with transaction(self.connection, "IMMEDIATE"):
            current = self.connection.execute(
                "SELECT * FROM provider_observation_intents WHERE intent_id = ? "
                "AND state = 'SEND_INTENT'",
                (intent_id,),
            ).fetchone()
            if current is None:
                raise ObservationIntentConflict("observation intent lost its completion fence")
            evidence = self.connection.execute(
                "SELECT 1 FROM quota_snapshots AS s JOIN audit_events AS a ON a.event_id = ? "
                "WHERE s.snapshot_id = ? AND s.credential_id = ? AND s.credential_generation = ? "
                "AND s.quota_scope_id = ? AND s.source = ? "
                "AND s.observation_kind = 'AUTHENTICATED' "
                "AND s.captured_at_ms >= ? AND s.unit = 'credits' "
                "AND a.event_type = 'credential.provider_validated' AND a.service_id = 'firecrawl' "
                "AND a.operation = 'firecrawl.account.credit_status' AND a.preserve = 1 "
                "AND a.occurred_at_ms = s.captured_at_ms "
                "AND json_extract(a.payload_json, '$.observation_intent_id') = ? "
                "AND json_extract(a.payload_json, '$.snapshot_id') = s.snapshot_id "
                "AND json_extract(a.payload_json, '$.credential_id') = s.credential_id "
                "AND json_extract(a.payload_json, '$.credential_generation') "
                "= s.credential_generation "
                "AND json_extract(a.payload_json, '$.quota_scope_id') = s.quota_scope_id "
                "AND json_extract(a.payload_json, '$.source') = s.source "
                "AND json_extract(a.payload_json, '$.principal_id') = ? "
                "AND json_extract(a.payload_json, '$.actor_id') = ? "
                "AND json_extract(a.payload_json, '$.outcome') = 'authenticated'",
                (
                    audit_event_id,
                    snapshot_id,
                    str(current["credential_id"]),
                    int(current["credential_generation"]),
                    str(current["quota_scope_id"]),
                    str(current["source"]),
                    int(current["created_at_ms"]),
                    intent_id,
                    str(current["principal_id"]),
                    str(current["actor_id"]),
                ),
            ).fetchone()
            if evidence is None:
                raise ObservationIntentConflict("observation terminal evidence is not bound")
            updated = self.connection.execute(
                "UPDATE provider_observation_intents SET state = 'SUCCEEDED', snapshot_id = ?, "
                "audit_event_id = ?, updated_at_ms = ? "
                "WHERE intent_id = ? AND state = 'SEND_INTENT'",
                (snapshot_id, audit_event_id, now_ms, intent_id),
            )
            if updated.rowcount != 1:
                raise ObservationIntentConflict("observation intent lost its completion fence")
            if str(current["source"]) != _SCHEDULED_SOURCE:
                # A new explicit successful read permits future observations. It
                # never changes an interrupted request into a known outcome.
                self.connection.execute(
                    "UPDATE provider_observation_intents SET state = 'UNKNOWN', "
                    "resolved_by_intent_id = ?, updated_at_ms = ? "
                    "WHERE credential_id = ? AND credential_generation = ? AND ordinal < ? "
                    "AND state IN ('SEND_INTENT', 'UNKNOWN') AND resolved_by_intent_id IS NULL",
                    (
                        intent_id,
                        now_ms,
                        str(current["credential_id"]),
                        int(current["credential_generation"]),
                        int(current["ordinal"]),
                    ),
                )
