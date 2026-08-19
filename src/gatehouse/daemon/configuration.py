"""Strict runtime configuration discovery and durable identity synchronization."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from gatehouse.config import (
    ClientProfileConfig,
    FeedSetConfig,
    MainConfig,
    WorkspacePolicyConfig,
    load_client_profile,
    load_feed_set,
    load_main_config,
    load_workspace_policy,
)
from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock
from gatehouse.core.ids import ClientId, WorkspaceId
from gatehouse.database.connection import transaction
from gatehouse.policy import WorkspacePolicy, workspace_policy_from_config


@dataclass(frozen=True, slots=True)
class RuntimeConfiguration:
    main: MainConfig
    clients: tuple[ClientProfileConfig, ...]
    policies: tuple[WorkspacePolicyConfig, ...]
    feed_sets: tuple[FeedSetConfig, ...]


def _load_directory[ConfigT](
    directory: Path,
    loader: object,
) -> tuple[ConfigT, ...]:
    if not directory.exists():
        return ()
    if not directory.is_dir():
        raise ValueError(f"configuration path is not a directory: {directory.name}")
    loaded: list[ConfigT] = []
    for path in sorted(directory.glob("*.yaml")):
        loaded.append(loader(path))  # type: ignore[operator]
    return tuple(loaded)


def load_runtime_configuration(
    main_path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> RuntimeConfiguration:
    path = Path(main_path)
    root = path.parent
    configuration = RuntimeConfiguration(
        main=load_main_config(path, environment=environment),
        clients=_load_directory(root / "clients", load_client_profile),
        policies=_load_directory(root / "policies", load_workspace_policy),
        feed_sets=_load_directory(root / "feeds", load_feed_set),
    )
    client_names = [item.client.id for item in configuration.clients]
    workspace_names = [item.workspace.id for item in configuration.policies]
    canonical_roots = [item.workspace.canonical_root.casefold() for item in configuration.policies]
    feed_names = [item.feed_set.id for item in configuration.feed_sets]
    for label, values in (
        ("client", client_names),
        ("workspace", workspace_names),
        ("workspace root", canonical_roots),
        ("feed set", feed_names),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {label} configuration")
    return configuration


@dataclass(frozen=True, slots=True)
class SynchronizedConfiguration:
    clients_by_id: Mapping[str, ClientProfileConfig]
    client_ids_by_name: Mapping[str, str]
    policies_by_workspace_id: Mapping[str, WorkspacePolicy]
    workspace_ids_by_name: Mapping[str, str]
    workspace_ids_by_root: Mapping[str, str]


class SqliteConfigurationCatalog:
    """Give human-readable configuration immutable opaque database identities."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
    ) -> None:
        self._connection = connection
        self._clock = clock

    @staticmethod
    def _encoded(key: str, value: object) -> str:
        return json.dumps({key: value}, sort_keys=True, separators=(",", ":"))

    def _client_id(self, name: str) -> str:
        row = self._connection.execute(
            """
            SELECT client_id FROM clients
             WHERE json_extract(config_json, '$.profile.client.id') = ?
            """,
            (name,),
        ).fetchone()
        return str(row["client_id"]) if row is not None else str(ClientId.new(clock=self._clock))

    def _workspace_id(self, name: str, canonical_root: str) -> str:
        row = self._connection.execute(
            """
            SELECT workspace_id FROM workspaces
             WHERE json_extract(config_json, '$.policy.workspace.id') = ?
                OR canonical_root = ? COLLATE NOCASE
            """,
            (name, canonical_root),
        ).fetchone()
        return (
            str(row["workspace_id"]) if row is not None else str(WorkspaceId.new(clock=self._clock))
        )

    def synchronize(
        self,
        *,
        clients: Iterable[ClientProfileConfig],
        policies: Iterable[WorkspacePolicyConfig],
    ) -> SynchronizedConfiguration:
        client_items = tuple(clients)
        policy_items = tuple(policies)
        now = self._clock.now_ms()
        clients_by_id: dict[str, ClientProfileConfig] = {}
        client_ids_by_name: dict[str, str] = {}
        policies_by_workspace_id: dict[str, WorkspacePolicy] = {}
        workspace_ids_by_name: dict[str, str] = {}
        workspace_ids_by_root: dict[str, str] = {}
        with transaction(self._connection, "IMMEDIATE"):
            for profile in client_items:
                client_id = self._client_id(profile.client.id)
                encoded = self._encoded(
                    "profile",
                    profile.model_dump(mode="json", exclude_none=False),
                )
                self._connection.execute(
                    """
                    INSERT INTO clients(
                        client_id, display_name, kind, unattended, policy_profile,
                        enabled, config_json, created_at_ms, updated_at_ms
                    ) VALUES (?, ?, ?, ?, 'configured', 1, ?, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        display_name = excluded.display_name,
                        kind = excluded.kind,
                        unattended = excluded.unattended,
                        enabled = 1,
                        config_json = excluded.config_json,
                        updated_at_ms = excluded.updated_at_ms
                    """,
                    (
                        client_id,
                        profile.client.id,
                        profile.client.kind,
                        int(profile.client.unattended),
                        encoded,
                        now,
                        now,
                    ),
                )
                clients_by_id[client_id] = profile
                client_ids_by_name[profile.client.id] = client_id
            for policy_config in policy_items:
                name = policy_config.workspace.id
                canonical_root = policy_config.workspace.canonical_root
                workspace_id = self._workspace_id(name, canonical_root)
                encoded = self._encoded(
                    "policy",
                    policy_config.model_dump(mode="json", exclude_none=False),
                )
                self._connection.execute(
                    """
                    INSERT INTO workspaces(
                        workspace_id, display_name, canonical_root, enabled,
                        config_json, created_at_ms, updated_at_ms
                    ) VALUES (?, ?, ?, 1, ?, ?, ?)
                    ON CONFLICT(workspace_id) DO UPDATE SET
                        display_name = excluded.display_name,
                        canonical_root = excluded.canonical_root,
                        enabled = 1,
                        config_json = excluded.config_json,
                        updated_at_ms = excluded.updated_at_ms
                    """,
                    (workspace_id, name, canonical_root, encoded, now, now),
                )
                compiled = replace(
                    workspace_policy_from_config(policy_config),
                    workspace_id=workspace_id,
                )
                policies_by_workspace_id[workspace_id] = compiled
                workspace_ids_by_name[name] = workspace_id
                workspace_ids_by_root[canonical_root.casefold()] = workspace_id
        return SynchronizedConfiguration(
            clients_by_id=clients_by_id,
            client_ids_by_name=client_ids_by_name,
            policies_by_workspace_id=policies_by_workspace_id,
            workspace_ids_by_name=workspace_ids_by_name,
            workspace_ids_by_root=workspace_ids_by_root,
        )
