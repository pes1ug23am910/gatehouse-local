from __future__ import annotations

from pathlib import Path

from gatehouse.database.migrations import open_migrated_database
from gatehouse.documentation import DocumentationService


def test_versioned_ingest_search_and_idempotence(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "docs.db")
    service = DocumentationService(connection)
    source = service.register_source(
        service="firecrawl",
        canonical_url="https://docs.firecrawl.dev/api-reference/search",
        now_ms=1_000,
    )
    markdown = "# Search\n\nSearch accepts a bounded limit.\n\n## Errors\n\nRate limits may retry."

    first = service.ingest_markdown(
        source_id=source.source_id,
        markdown=markdown,
        retrieved_at_ms=2_000,
    )
    duplicate = service.ingest_markdown(
        source_id=source.source_id,
        markdown=markdown,
        retrieved_at_ms=3_000,
    )
    results = service.search(service="firecrawl", query="bounded limit")

    assert duplicate.version_id == first.version_id
    assert results
    assert results[0].source_id == source.source_id
    assert "bounded" in results[0].excerpt.lower()
    assert service.get_document(service="firecrawl", source_id=source.source_id)
    connection.close()


def test_failed_candidate_validator_does_not_create_version(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "docs.db")
    service = DocumentationService(connection)
    source = service.register_source(
        service="firecrawl",
        canonical_url="https://docs.firecrawl.dev/api-reference/errors",
        now_ms=1_000,
    )

    from gatehouse.documentation.service import DocumentationValidationError

    try:
        service.ingest_markdown(
            source_id=source.source_id,
            markdown="# Errors\n\nCandidate content",
            retrieved_at_ms=2_000,
            validate=lambda _chunks: False,
        )
    except DocumentationValidationError:
        pass
    else:
        raise AssertionError("invalid candidate was promoted")

    count = connection.execute("SELECT COUNT(*) FROM documentation_versions").fetchone()[0]
    assert count == 0
    connection.close()
