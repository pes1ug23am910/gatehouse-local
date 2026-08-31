from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatehouse.config import load_client_profile, load_feed_set, load_workspace_policy
from gatehouse.core.clock import FixedUtcClock
from gatehouse.daemon import SqliteConfigurationCatalog
from gatehouse.database import open_migrated_database

ROOT = Path(__file__).parents[3]


def test_configuration_identities_survive_reopen_and_policy_uses_opaque_workspace(
    tmp_path: Path,
) -> None:
    path = tmp_path / "configuration.db"
    profile = load_client_profile(ROOT / "config" / "clients" / "company-watcher.example.yaml")
    policy = load_workspace_policy(ROOT / "config" / "policies" / "placement-schedule.example.yaml")
    feed = load_feed_set(ROOT / "config" / "feeds" / "placement-companies-primary.example.yaml")
    connection = open_migrated_database(path)
    first = SqliteConfigurationCatalog(
        connection,
        clock=FixedUtcClock(1_777_000_000_000),
    ).synchronize(clients=(profile,), policies=(policy,), feed_sets=(feed,))
    client_id = first.client_ids_by_name[profile.client.id]
    workspace_id = first.workspace_ids_by_name[policy.workspace.id]
    assert client_id.startswith("client_")
    assert workspace_id.startswith("ws_")
    assert first.policies_by_workspace_id[workspace_id].workspace_id == workspace_id
    persisted_feed = connection.execute(
        """
        SELECT workspace_id, policy_version, state, config_json
          FROM feed_sets WHERE feed_set_id = ?
        """,
        (feed.feed_set.id,),
    ).fetchone()
    assert persisted_feed is not None
    assert persisted_feed["workspace_id"] == workspace_id
    assert persisted_feed["policy_version"] == first.policies_by_workspace_id[workspace_id].version
    assert persisted_feed["state"] == "ACTIVE"
    assert json.loads(persisted_feed["config_json"]) == {
        "feed": feed.model_dump(mode="json", exclude_none=False)
    }
    connection.close()

    reopened = open_migrated_database(path)
    try:
        second = SqliteConfigurationCatalog(
            reopened,
            clock=FixedUtcClock(1_888_000_000_000),
        ).synchronize(clients=(profile,), policies=(policy,), feed_sets=(feed,))
        assert second.client_ids_by_name[profile.client.id] == client_id
        assert second.workspace_ids_by_name[policy.workspace.id] == workspace_id
        assert (
            second.workspace_ids_by_root[policy.workspace.canonical_root.casefold()] == workspace_id
        )
        assert reopened.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 1
        assert reopened.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0] == 1
        assert reopened.execute("SELECT COUNT(*) FROM feed_sets").fetchone()[0] == 1
    finally:
        reopened.close()


def test_configuration_catalog_rejects_unknown_feed_workspace_atomically(tmp_path: Path) -> None:
    path = tmp_path / "configuration.db"
    profile = load_client_profile(ROOT / "config" / "clients" / "company-watcher.example.yaml")
    policy = load_workspace_policy(ROOT / "config" / "policies" / "placement-schedule.example.yaml")
    feed = load_feed_set(ROOT / "config" / "feeds" / "placement-companies-primary.example.yaml")
    unknown_identity = feed.feed_set.model_copy(update={"workspace": "unknown-workspace"})
    unknown_feed = feed.model_copy(update={"feed_set": unknown_identity})
    connection = open_migrated_database(path)
    try:
        with pytest.raises(ValueError, match="unknown workspace"):
            SqliteConfigurationCatalog(connection).synchronize(
                clients=(profile,),
                policies=(policy,),
                feed_sets=(unknown_feed,),
            )
        assert connection.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM feed_sets").fetchone()[0] == 0
    finally:
        connection.close()


def test_configuration_catalog_does_not_rebind_existing_feed_workspace(tmp_path: Path) -> None:
    path = tmp_path / "configuration.db"
    policy = load_workspace_policy(ROOT / "config" / "policies" / "placement-schedule.example.yaml")
    feed = load_feed_set(ROOT / "config" / "feeds" / "placement-companies-primary.example.yaml")
    other_workspace = policy.workspace.model_copy(
        update={"id": "other-workspace", "canonical_root": r"E:\Projects\Other"}
    )
    other_policy = policy.model_copy(update={"workspace": other_workspace})
    moved_identity = feed.feed_set.model_copy(update={"workspace": "other-workspace"})
    moved_feed = feed.model_copy(update={"feed_set": moved_identity})
    connection = open_migrated_database(path)
    try:
        first = SqliteConfigurationCatalog(connection).synchronize(
            clients=(),
            policies=(policy,),
            feed_sets=(feed,),
        )
        original_workspace_id = first.workspace_ids_by_name[policy.workspace.id]

        with pytest.raises(RuntimeError, match="durable workspace binding"):
            SqliteConfigurationCatalog(connection).synchronize(
                clients=(),
                policies=(policy, other_policy),
                feed_sets=(moved_feed,),
            )
        assert (
            connection.execute(
                "SELECT workspace_id FROM feed_sets WHERE feed_set_id = ?",
                (feed.feed_set.id,),
            ).fetchone()[0]
            == original_workspace_id
        )
    finally:
        connection.close()


def test_configuration_catalog_retires_removed_feed_and_reactivates_same_binding(
    tmp_path: Path,
) -> None:
    path = tmp_path / "configuration.db"
    policy = load_workspace_policy(ROOT / "config" / "policies" / "placement-schedule.example.yaml")
    feed = load_feed_set(ROOT / "config" / "feeds" / "placement-companies-primary.example.yaml")
    connection = open_migrated_database(path)
    try:
        first = SqliteConfigurationCatalog(connection, clock=FixedUtcClock(100)).synchronize(
            clients=(),
            policies=(policy,),
            feed_sets=(feed,),
        )
        workspace_id = first.workspace_ids_by_name[policy.workspace.id]
        SqliteConfigurationCatalog(connection, clock=FixedUtcClock(200)).synchronize(
            clients=(),
            policies=(policy,),
            feed_sets=(),
        )
        assert tuple(
            connection.execute(
                "SELECT workspace_id, state, updated_at_ms FROM feed_sets WHERE feed_set_id = ?",
                (feed.feed_set.id,),
            ).fetchone()
        ) == (workspace_id, "RETIRED", 200)

        SqliteConfigurationCatalog(connection, clock=FixedUtcClock(300)).synchronize(
            clients=(),
            policies=(policy,),
            feed_sets=(feed,),
        )
        assert tuple(
            connection.execute(
                "SELECT workspace_id, state, updated_at_ms FROM feed_sets WHERE feed_set_id = ?",
                (feed.feed_set.id,),
            ).fetchone()
        ) == (workspace_id, "ACTIVE", 300)
    finally:
        connection.close()
