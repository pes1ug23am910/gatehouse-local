from __future__ import annotations

from pathlib import Path

from gatehouse.config import load_client_profile, load_workspace_policy
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
    connection = open_migrated_database(path)
    first = SqliteConfigurationCatalog(
        connection,
        clock=FixedUtcClock(1_777_000_000_000),
    ).synchronize(clients=(profile,), policies=(policy,))
    client_id = first.client_ids_by_name[profile.client.id]
    workspace_id = first.workspace_ids_by_name[policy.workspace.id]
    assert client_id.startswith("client_")
    assert workspace_id.startswith("ws_")
    assert first.policies_by_workspace_id[workspace_id].workspace_id == workspace_id
    connection.close()

    reopened = open_migrated_database(path)
    try:
        second = SqliteConfigurationCatalog(
            reopened,
            clock=FixedUtcClock(1_888_000_000_000),
        ).synchronize(clients=(profile,), policies=(policy,))
        assert second.client_ids_by_name[profile.client.id] == client_id
        assert second.workspace_ids_by_name[policy.workspace.id] == workspace_id
        assert (
            second.workspace_ids_by_root[policy.workspace.canonical_root.casefold()] == workspace_id
        )
        assert reopened.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 1
        assert reopened.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0] == 1
    finally:
        reopened.close()
