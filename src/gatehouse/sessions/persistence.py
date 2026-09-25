"""Persistence boundary for session state.

Replacements use compare-and-swap semantics so bootstrap exchange, revocation, and
heartbeat cannot silently overwrite one another.  The package's SQLite adapter is
implemented separately from this protocol so tests may still supply narrow fakes.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from .models import RootRunRecord, SessionRecord


class SessionRunCapacityExceeded(RuntimeError):
    """A configured client profile has no durable controlled-run slot."""


class SessionRunawayQuarantined(RuntimeError):
    """A client profile owns a blocking runaway quarantine."""


class SessionCreationRequestConflict(RuntimeError):
    """A request cannot mint again or has exhausted retained admission."""

    def __init__(self) -> None:
        super().__init__("controlled session request is already bound or unavailable")


class SessionCreationOutcomeUnresolved(RuntimeError):
    """A failed acknowledgement cannot establish the durable request outcome."""

    def __init__(self) -> None:
        super().__init__("controlled session request outcome is unresolved")


def session_request_digest(request_id: str) -> str:
    if type(request_id) is not str or re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        raise ValueError("controlled session request identifier is invalid")
    return hashlib.sha256(
        b"gatehouse:controlled-session-request:v1\x00" + request_id.encode("ascii")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class SessionCreationRequest:
    request_id: str
    authority_digest: str

    def __post_init__(self) -> None:
        session_request_digest(self.request_id)
        if (
            type(self.authority_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.authority_digest) is None
        ):
            raise ValueError("controlled session request authority is invalid")

    @property
    def request_digest(self) -> str:
        return session_request_digest(self.request_id)


class SessionPersistence(Protocol):
    async def begin_daemon_epoch(self, *, now_ms: int, reconnect_grace_ms: int) -> int:
        """Atomically increment the token epoch and disconnect active sessions."""

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
        """Atomically admit and insert a session under configured client limits."""

    async def cancel_session_request(self, request_id: str, *, now_ms: int) -> str | None:
        """Retain a permanent cancellation tombstone and return its mapped session."""

    async def load_session(self, session_id: str) -> SessionRecord | None:
        """Load one immutable session snapshot."""

    async def replace_session(
        self,
        *,
        expected: SessionRecord,
        replacement: SessionRecord,
    ) -> bool:
        """Replace only when the persisted row still equals ``expected``."""

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
        """Atomically admit a server-minted root under configured client limits."""

    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None:
        """Load one root run without weakening its session binding."""
