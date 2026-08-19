"""Persistence boundary for session state.

Replacements use compare-and-swap semantics so bootstrap exchange, revocation, and
heartbeat cannot silently overwrite one another.  The package's SQLite adapter is
implemented separately from this protocol so tests may still supply narrow fakes.
"""

from __future__ import annotations

from typing import Protocol

from .models import RootRunRecord, SessionRecord


class SessionPersistence(Protocol):
    async def begin_daemon_epoch(self, *, now_ms: int, reconnect_grace_ms: int) -> int:
        """Atomically increment the token epoch and disconnect active sessions."""

    async def insert_session(self, session: SessionRecord) -> None:
        """Insert a new session, rejecting duplicate identifiers."""

    async def load_session(self, session_id: str) -> SessionRecord | None:
        """Load one immutable session snapshot."""

    async def replace_session(
        self,
        *,
        expected: SessionRecord,
        replacement: SessionRecord,
    ) -> bool:
        """Replace only when the persisted row still equals ``expected``."""

    async def insert_root_run(self, root_run: RootRunRecord) -> None:
        """Insert a server-minted root run."""

    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None:
        """Load one root run without weakening its session binding."""
