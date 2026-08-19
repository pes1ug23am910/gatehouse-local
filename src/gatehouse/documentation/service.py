"""Transactional, versioned FTS index for explicitly supplied official docs."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from gatehouse.database.connection import transaction
from gatehouse.policy.targets import canonicalize_public_url

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_QUERY_TERM = re.compile(r"[\w-]{2,}", re.UNICODE)


class DocumentationError(RuntimeError):
    """Base error for local documentation operations."""


class DocumentationValidationError(DocumentationError):
    """A candidate document failed a pre-promotion contract check."""


@dataclass(frozen=True, slots=True)
class SourceRegistration:
    source_id: str
    service: str
    canonical_url: str
    trust_level: str
    update_interval_seconds: int


@dataclass(frozen=True, slots=True)
class DocumentVersion:
    source_id: str
    version_id: str
    digest_sha256: str
    retrieved_at_ms: int
    promoted_at_ms: int
    chunk_count: int


@dataclass(frozen=True, slots=True)
class SearchResult:
    service: str
    source_id: str
    version_id: str
    heading: str | None
    excerpt: str
    source_reference: str
    trust_level: str
    retrieved_at_ms: int
    rank: float


class DocumentationService:
    """Ingest supplied text; this component never fetches or trusts commands."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        identifier: Callable[[str], str] | None = None,
        maximum_document_characters: int = 5_000_000,
        maximum_chunks: int = 5_000,
        chunk_characters: int = 8_000,
    ) -> None:
        if min(maximum_document_characters, maximum_chunks, chunk_characters) <= 0:
            raise ValueError("documentation bounds must be positive")
        self._connection = connection
        self._identifier = identifier or (lambda prefix: f"{prefix}_{uuid.uuid4().hex}")
        self._maximum_document_characters = maximum_document_characters
        self._maximum_chunks = maximum_chunks
        self._chunk_characters = chunk_characters

    def register_source(
        self,
        *,
        service: str,
        canonical_url: str,
        trust_level: str = "official_provider_documentation",
        update_interval_seconds: int = 86_400,
        now_ms: int,
    ) -> SourceRegistration:
        if not service or not trust_level or update_interval_seconds <= 0:
            raise ValueError("source metadata is invalid")
        target = canonicalize_public_url(canonical_url)
        source_id = self._identifier("docsrc")
        with transaction(self._connection):
            self._connection.execute(
                """
                INSERT INTO documentation_sources(
                    source_id, service_id, canonical_url, trust_level,
                    update_interval_seconds, last_checked_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_id, canonical_url) DO UPDATE SET
                    trust_level = excluded.trust_level,
                    update_interval_seconds = excluded.update_interval_seconds,
                    enabled = 1,
                    last_checked_at_ms = excluded.last_checked_at_ms
                """,
                (
                    source_id,
                    service,
                    target.url,
                    trust_level,
                    update_interval_seconds,
                    now_ms,
                ),
            )
            row = self._connection.execute(
                """
                SELECT source_id, service_id, canonical_url, trust_level,
                       update_interval_seconds
                FROM documentation_sources
                WHERE service_id = ? AND canonical_url = ?
                """,
                (service, target.url),
            ).fetchone()
        assert row is not None
        return SourceRegistration(
            source_id=str(row["source_id"]),
            service=str(row["service_id"]),
            canonical_url=str(row["canonical_url"]),
            trust_level=str(row["trust_level"]),
            update_interval_seconds=int(row["update_interval_seconds"]),
        )

    def ingest_markdown(
        self,
        *,
        source_id: str,
        markdown: str,
        retrieved_at_ms: int,
        validate: Callable[[tuple[tuple[str | None, str], ...]], bool] | None = None,
    ) -> DocumentVersion:
        if not markdown or len(markdown) > self._maximum_document_characters:
            raise DocumentationValidationError("document is empty or exceeds its size bound")
        chunks = self._chunk(markdown)
        if not chunks or len(chunks) > self._maximum_chunks:
            raise DocumentationValidationError("document chunk count is outside its bound")
        if validate is not None and not validate(chunks):
            raise DocumentationValidationError("candidate document failed validation")
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        existing = self._existing_version(source_id, digest)
        if existing is not None:
            return existing

        version_id = self._identifier("docver")
        chunk_rows: list[tuple[str, str, int, str | None, str, str]] = []
        for ordinal, (heading, content) in enumerate(chunks):
            reference = f"{source_id}#chunk-{ordinal}"
            chunk_rows.append(
                (
                    self._identifier("docchunk"),
                    version_id,
                    ordinal,
                    heading,
                    content,
                    reference,
                )
            )
        with transaction(self._connection):
            source = self._connection.execute(
                "SELECT source_id FROM documentation_sources WHERE source_id = ? AND enabled = 1",
                (source_id,),
            ).fetchone()
            if source is None:
                raise DocumentationValidationError("documentation source is missing or disabled")
            self._connection.execute(
                """
                INSERT INTO documentation_versions(
                    version_id, source_id, digest_sha256, state, retrieved_at_ms
                ) VALUES (?, ?, ?, 'STAGED', ?)
                """,
                (version_id, source_id, digest, retrieved_at_ms),
            )
            self._connection.executemany(
                """
                INSERT INTO documentation_chunks(
                    chunk_id, version_id, ordinal, heading, content, source_reference
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                chunk_rows,
            )
            self._connection.executemany(
                """
                INSERT INTO documentation_chunks_fts(
                    chunk_id, heading, content, source_reference
                ) VALUES (?, ?, ?, ?)
                """,
                [(row[0], row[3] or "", row[4], row[5]) for row in chunk_rows],
            )
            self._connection.execute(
                """
                UPDATE documentation_versions
                SET state = 'SUPERSEDED'
                WHERE source_id = ? AND state = 'PROMOTED'
                """,
                (source_id,),
            )
            self._connection.execute(
                """
                UPDATE documentation_versions
                SET state = 'PROMOTED', promoted_at_ms = ?
                WHERE version_id = ? AND state = 'STAGED'
                """,
                (retrieved_at_ms, version_id),
            )
            self._connection.execute(
                "UPDATE documentation_sources SET last_checked_at_ms = ? WHERE source_id = ?",
                (retrieved_at_ms, source_id),
            )
        return DocumentVersion(
            source_id=source_id,
            version_id=version_id,
            digest_sha256=digest,
            retrieved_at_ms=retrieved_at_ms,
            promoted_at_ms=retrieved_at_ms,
            chunk_count=len(chunk_rows),
        )

    def search(self, *, service: str, query: str, limit: int = 10) -> tuple[SearchResult, ...]:
        if not 1 <= limit <= 50:
            raise ValueError("search limit must be between 1 and 50")
        terms = _QUERY_TERM.findall(query[:500])[:12]
        if not terms:
            return ()
        fts_query = " AND ".join(f'"{term.replace(chr(34), "")}"*' for term in terms)
        rows = self._connection.execute(
            """
            SELECT s.service_id, s.source_id, s.trust_level,
                   v.version_id, v.retrieved_at_ms,
                   c.heading, c.source_reference,
                   snippet(documentation_chunks_fts, 2, '[', ']', ' … ', 24) AS excerpt,
                   bm25(documentation_chunks_fts, 8.0, 2.0) AS rank
            FROM documentation_chunks_fts
            JOIN documentation_chunks c
              ON c.chunk_id = documentation_chunks_fts.chunk_id
            JOIN documentation_versions v ON v.version_id = c.version_id
            JOIN documentation_sources s ON s.source_id = v.source_id
            WHERE documentation_chunks_fts MATCH ?
              AND s.service_id = ? AND s.enabled = 1 AND v.state = 'PROMOTED'
            ORDER BY rank, c.ordinal
            LIMIT ?
            """,
            (fts_query, service, limit),
        ).fetchall()
        return tuple(
            SearchResult(
                service=str(row["service_id"]),
                source_id=str(row["source_id"]),
                version_id=str(row["version_id"]),
                heading=str(row["heading"]) if row["heading"] is not None else None,
                excerpt=str(row["excerpt"]),
                source_reference=str(row["source_reference"]),
                trust_level=str(row["trust_level"]),
                retrieved_at_ms=int(row["retrieved_at_ms"]),
                rank=float(row["rank"]),
            )
            for row in rows
        )

    def get_document(self, *, service: str, source_id: str) -> str | None:
        rows = self._connection.execute(
            """
            SELECT c.heading, c.content
            FROM documentation_chunks c
            JOIN documentation_versions v ON v.version_id = c.version_id
            JOIN documentation_sources s ON s.source_id = v.source_id
            WHERE s.service_id = ? AND s.source_id = ? AND s.enabled = 1
              AND v.state = 'PROMOTED'
            ORDER BY c.ordinal
            """,
            (service, source_id),
        ).fetchall()
        if not rows:
            return None
        sections = []
        for row in rows:
            heading = str(row["heading"]) if row["heading"] else None
            sections.append(f"## {heading}\n\n{row['content']}" if heading else str(row["content"]))
        return "\n\n".join(sections)

    def _existing_version(self, source_id: str, digest: str) -> DocumentVersion | None:
        row = self._connection.execute(
            """
            SELECT version_id, retrieved_at_ms, promoted_at_ms,
                   (SELECT COUNT(*) FROM documentation_chunks c
                    WHERE c.version_id = v.version_id) AS chunk_count
            FROM documentation_versions v
            WHERE source_id = ? AND digest_sha256 = ? AND state = 'PROMOTED'
            """,
            (source_id, digest),
        ).fetchone()
        if row is None:
            return None
        return DocumentVersion(
            source_id=source_id,
            version_id=str(row["version_id"]),
            digest_sha256=digest,
            retrieved_at_ms=int(row["retrieved_at_ms"]),
            promoted_at_ms=int(row["promoted_at_ms"]),
            chunk_count=int(row["chunk_count"]),
        )

    def _chunk(self, markdown: str) -> tuple[tuple[str | None, str], ...]:
        chunks: list[tuple[str | None, str]] = []
        heading: str | None = None
        buffer: list[str] = []
        length = 0

        def flush() -> None:
            nonlocal buffer, length
            content = "\n".join(buffer).strip()
            if content:
                for start in range(0, len(content), self._chunk_characters):
                    chunks.append((heading, content[start : start + self._chunk_characters]))
            buffer = []
            length = 0

        for line in markdown.splitlines():
            match = _HEADING.match(line)
            if match:
                flush()
                heading = match.group(2).strip()[:500]
                continue
            if length + len(line) + 1 > self._chunk_characters and buffer:
                flush()
            buffer.append(line)
            length += len(line) + 1
        flush()
        return tuple(chunks)
