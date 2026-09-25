"""Strict runtime configuration discovery and durable identity synchronization."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from pydantic import BaseModel

from gatehouse.config import (
    ClientProfileConfig,
    ConfigLoadError,
    FeedSetConfig,
    MainConfig,
    WorkspacePolicyConfig,
    load_client_profile,
    load_feed_set,
    load_main_config,
    load_workspace_policy,
)
from gatehouse.config.loader import ConfigLoadStage, parse_main_config, parse_yaml_model
from gatehouse.config.security import (
    ConfigSecurityError,
    ConfigurationSnapshot,
    ScriptedConfigurationDocument,
    capture_configuration,
    require_snapshot_manifest_binding,
    scripted_sibling_path,
)
from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock
from gatehouse.core.ids import ClientId, WorkspaceId
from gatehouse.database.connection import transaction
from gatehouse.policy import WorkspacePolicy, workspace_policy_from_config
from gatehouse.providers.scripted import ScriptedManifestError, ScriptedProviderTransport
from gatehouse.watcher import RESERVED_POOL_ALIAS


@dataclass(frozen=True, slots=True)
class RuntimeConfiguration:
    main: MainConfig
    clients: tuple[ClientProfileConfig, ...]
    policies: tuple[WorkspacePolicyConfig, ...]
    feed_sets: tuple[FeedSetConfig, ...]
    snapshot: ConfigurationSnapshot | None = None


def validate_expected_config_digest(value: object) -> str:
    """Accept an exact caller-supplied digest without coercion or normalization."""

    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ConfigSecurityError(
            "expected configuration digest must be 64 lowercase hexadecimal characters"
        )
    return value


def require_configuration_snapshot_digest(
    snapshot: ConfigurationSnapshot | None,
    expected_config_digest: str,
) -> None:
    """Compare the captured bundle to the caller's expectation without recapture."""

    expected = validate_expected_config_digest(expected_config_digest)
    if snapshot is None:
        raise ConfigSecurityError("verified configuration snapshot is unavailable")
    observed = validate_expected_config_digest(snapshot.manifest_digest)
    if observed != expected:
        raise ConfigSecurityError("configuration snapshot does not match its expected digest")


def _parse_snapshot_directory[ConfigT: BaseModel](
    snapshot: ConfigurationSnapshot,
    directory: str,
    model_type: type[ConfigT],
) -> tuple[ConfigT, ...]:
    prefix = f"{directory}/"
    return tuple(
        parse_yaml_model(
            document.content,
            snapshot.main_path.parent / document.relative_path,
            model_type,
        )
        for document in snapshot.documents
        if document.relative_path.startswith(prefix)
    )


def _load_directory[ConfigT](directory: Path, loader: object) -> tuple[ConfigT, ...]:
    if not directory.exists():
        return ()
    if not directory.is_dir():
        raise ValueError(f"configuration path is not a directory: {directory.name}")
    return tuple(loader(path) for path in sorted(directory.glob("*.yaml")))  # type: ignore[operator]


def _load_content_configuration(
    main_path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> RuntimeConfiguration:
    """Retain content-only topology checks for initialization and diagnostics."""

    path = Path(main_path)
    root = path.parent
    return _validate_configuration(
        RuntimeConfiguration(
            main=load_main_config(path, environment=environment),
            clients=_load_directory(root / "clients", load_client_profile),
            policies=_load_directory(root / "policies", load_workspace_policy),
            feed_sets=_load_directory(root / "feeds", load_feed_set),
        )
    )


def _select_scripted_document(
    raw: bytes,
    path: Path,
    environment: Mapping[str, str],
) -> str | None:
    """Select from captured content only; state-path interpretation comes later."""

    main = parse_yaml_model(
        raw,
        path,
        MainConfig,
        expand_environment=True,
        environment=environment,
    )
    provider = main.firecrawl_workload
    return provider.scripted_responses_path if provider.mode == "scripted" else None


def _captured_main(snapshot: ConfigurationSnapshot) -> MainConfig:
    return parse_yaml_model(
        snapshot.document(snapshot.main_relative_path).content,
        snapshot.main_path,
        MainConfig,
        expand_environment=True,
        environment=dict(snapshot.bound_environment),
    )


def _scripted_attachment_for_main(
    main: MainConfig,
    snapshot: ConfigurationSnapshot,
) -> ScriptedConfigurationDocument | None:
    attachment = snapshot.scripted_document
    provider = main.firecrawl_workload
    if provider.mode != "scripted":
        if attachment is not None:
            raise ConfigSecurityError("configuration has an unexpected scripted attachment")
        return None
    if attachment is None or provider.scripted_responses_path is None:
        raise ConfigSecurityError("configuration scripted attachment is unavailable")
    expected_origin = scripted_sibling_path(snapshot.main_path, provider.scripted_responses_path)
    if (
        str(attachment.origin) != str(expected_origin)
        or attachment.relative_path != expected_origin.name
    ):
        raise ConfigSecurityError("configuration scripted attachment does not match its selection")
    return attachment


def require_scripted_snapshot_attachment(
    configuration: RuntimeConfiguration,
) -> ScriptedConfigurationDocument | None:
    """Recheck captured workload linkage before stock runtime effects."""

    snapshot = configuration.snapshot
    provider = configuration.main.firecrawl_workload
    if snapshot is None:
        if provider.mode == "scripted":
            raise ConfigSecurityError("scripted runtime requires a verified configuration snapshot")
        return None
    require_snapshot_manifest_binding(snapshot)
    captured = _captured_main(snapshot)
    expected = captured.firecrawl_workload
    if (
        provider.mode,
        provider.network_enabled,
        provider.scripted_responses_path,
    ) != (
        expected.mode,
        expected.network_enabled,
        expected.scripted_responses_path,
    ):
        raise ConfigSecurityError("runtime workload does not match its captured configuration")
    return _scripted_attachment_for_main(captured, snapshot)


def load_runtime_configuration(
    main_path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    expected_config_digest: str | None = None,
) -> RuntimeConfiguration:
    path = Path(main_path)
    try:
        expected = (
            validate_expected_config_digest(expected_config_digest)
            if expected_config_digest is not None
            else None
        )
        snapshot = capture_configuration(
            main_path,
            environment=environment,
            scripted_document_selector=_select_scripted_document,
        )
        if expected is not None:
            require_configuration_snapshot_digest(snapshot, expected)
        if not snapshot.matches_main_path(main_path):
            raise ConfigSecurityError("configuration origin does not match its capture")
        require_snapshot_manifest_binding(snapshot)
        main_document = snapshot.document(snapshot.main_relative_path)
        for document in snapshot.documents:
            if document.relative_path == snapshot.main_relative_path:
                continue
            directory, separator, filename = document.relative_path.partition("/")
            if (
                directory not in {"clients", "policies", "feeds"}
                or not separator
                or "/" in filename
                or not filename.endswith(".yaml")
            ):
                raise ConfigSecurityError("configuration document topology is invalid")
        attachment = _scripted_attachment_for_main(_captured_main(snapshot), snapshot)
    except ConfigSecurityError:
        raise ConfigLoadError(
            path,
            ConfigLoadStage.SECURITY,
            "configuration filesystem trust could not be verified",
        ) from None
    if attachment is not None:
        try:
            # Validate executable script content for config-validate as well.
            # This temporary parser result owns no I/O; composition creates its
            # own mutable response queues from the same captured bytes.
            ScriptedProviderTransport.from_bytes(attachment.content)
        except ScriptedManifestError:
            raise ConfigLoadError(
                path,
                ConfigLoadStage.VALIDATION,
                "scripted response manifest is invalid",
            ) from None
    configuration = RuntimeConfiguration(
        main=parse_main_config(
            main_document.content,
            config_path=snapshot.main_path,
            environment=dict(snapshot.bound_environment),
        ),
        clients=_parse_snapshot_directory(snapshot, "clients", ClientProfileConfig),
        policies=_parse_snapshot_directory(snapshot, "policies", WorkspacePolicyConfig),
        feed_sets=_parse_snapshot_directory(snapshot, "feeds", FeedSetConfig),
        snapshot=snapshot,
    )
    return _validate_configuration(configuration)


def _validate_configuration(configuration: RuntimeConfiguration) -> RuntimeConfiguration:
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
    configured_workspaces = set(workspace_names)
    for feed_set in configuration.feed_sets:
        if feed_set.feed_set.workspace not in configured_workspaces:
            raise ValueError("feed set references an unknown workspace")
    if (
        configuration.main.firecrawl_workload.mode == "scripted"
        and configuration.feed_sets
        and not any(
            profile.pools.bindings.get("firecrawl") == RESERVED_POOL_ALIAS
            for profile in configuration.clients
        )
    ):
        raise ValueError("scripted feed sets require a watcher-reserved client pool binding")
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
        feed_sets: Iterable[FeedSetConfig],
    ) -> SynchronizedConfiguration:
        client_items = tuple(clients)
        policy_items = tuple(policies)
        feed_items = tuple(feed_sets)
        feed_ids = tuple(str(item.feed_set.id) for item in feed_items)
        if len(feed_ids) != len(set(feed_ids)):
            raise ValueError("duplicate feed set configuration")
        encoded_feed_ids = json.dumps(feed_ids, separators=(",", ":"))
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
            for feed_config in feed_items:
                feed_set_id = str(feed_config.feed_set.id)
                workspace_name = str(feed_config.feed_set.workspace)
                feed_workspace_id = workspace_ids_by_name.get(workspace_name)
                if feed_workspace_id is None:
                    raise ValueError("feed set references an unknown workspace")
                policy = policies_by_workspace_id[feed_workspace_id]
                if policy.service != "firecrawl":
                    raise ValueError("feed set workspace must use the Firecrawl policy")
                existing = self._connection.execute(
                    "SELECT workspace_id FROM feed_sets WHERE feed_set_id = ?",
                    (feed_set_id,),
                ).fetchone()
                if existing is not None and str(existing["workspace_id"]) != feed_workspace_id:
                    raise RuntimeError("feed set conflicts with its durable workspace binding")
                encoded = self._encoded(
                    "feed",
                    feed_config.model_dump(mode="json", exclude_none=False),
                )
                self._connection.execute(
                    """
                    INSERT INTO feed_sets(
                        feed_set_id, workspace_id, policy_version, state,
                        config_json, created_at_ms, updated_at_ms
                    ) VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
                    ON CONFLICT(feed_set_id) DO UPDATE SET
                        policy_version = excluded.policy_version,
                        state = 'ACTIVE',
                        config_json = excluded.config_json,
                        updated_at_ms = excluded.updated_at_ms
                    """,
                    (
                        feed_set_id,
                        feed_workspace_id,
                        policy.version,
                        encoded,
                        now,
                        now,
                    ),
                )
            self._connection.execute(
                """
                UPDATE feed_sets
                   SET state = 'RETIRED', updated_at_ms = ?
                 WHERE state != 'RETIRED'
                   AND feed_set_id NOT IN (
                       SELECT CAST(value AS TEXT) FROM json_each(?)
                   )
                """,
                (now, encoded_feed_ids),
            )
        return SynchronizedConfiguration(
            clients_by_id=clients_by_id,
            client_ids_by_name=client_ids_by_name,
            policies_by_workspace_id=policies_by_workspace_id,
            workspace_ids_by_name=workspace_ids_by_name,
            workspace_ids_by_root=workspace_ids_by_root,
        )
