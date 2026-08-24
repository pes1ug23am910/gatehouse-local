from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from gatehouse.config import ClientProfileConfig, MainConfig, WorkspacePolicyConfig
from gatehouse.daemon.composition import _control_authorities, _scheduler_limits
from gatehouse.daemon.configuration import RuntimeConfiguration, SynchronizedConfiguration
from gatehouse.policy import workspace_policy_from_config

ROOT = Path(__file__).resolve().parents[3]
CONFIG_ROOT = ROOT / "config"


def _document(relative_path: str) -> dict[str, object]:
    loaded = yaml.safe_load((CONFIG_ROOT / relative_path).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _main() -> MainConfig:
    return MainConfig.model_validate(_document("config.example.yaml"))


def _profile(name: str, *, workspaces: list[str] | None) -> ClientProfileConfig:
    document = deepcopy(_document("clients/company-watcher.example.yaml"))
    client = document["client"]
    assert isinstance(client, dict)
    client["id"] = name
    if workspaces is None:
        del document["workspaces"]
    else:
        document["workspaces"] = {"allow": workspaces}
    return ClientProfileConfig.model_validate(document)


def _policy(name: str, root: Path) -> WorkspacePolicyConfig:
    document = deepcopy(_document("policies/placement-schedule.example.yaml"))
    workspace = document["workspace"]
    assert isinstance(workspace, dict)
    workspace["id"] = name
    workspace["canonical_root"] = str(root)
    return WorkspacePolicyConfig.model_validate(document)


def _synchronized(
    profiles: tuple[ClientProfileConfig, ...],
    policies: tuple[WorkspacePolicyConfig, ...],
) -> SynchronizedConfiguration:
    client_ids = {
        profile.client.id: f"client_{index:026d}" for index, profile in enumerate(profiles, 1)
    }
    workspace_ids = {
        policy.workspace.id: f"ws_{index:026d}" for index, policy in enumerate(policies, 1)
    }
    compiled = {
        workspace_ids[policy.workspace.id]: replace(
            workspace_policy_from_config(policy),
            workspace_id=workspace_ids[policy.workspace.id],
        )
        for policy in policies
    }
    return SynchronizedConfiguration(
        clients_by_id={client_ids[item.client.id]: item for item in profiles},
        client_ids_by_name=client_ids,
        policies_by_workspace_id=compiled,
        workspace_ids_by_name=workspace_ids,
        workspace_ids_by_root={
            policy.workspace.canonical_root.casefold(): workspace_ids[policy.workspace.id]
            for policy in policies
        },
    )


def _runtime(
    profiles: tuple[ClientProfileConfig, ...],
    policies: tuple[WorkspacePolicyConfig, ...],
) -> RuntimeConfiguration:
    return RuntimeConfiguration(main=_main(), clients=profiles, policies=policies, feed_sets=())


def test_distinct_agent_clients_share_only_the_explicit_workspace_binding(tmp_path: Path) -> None:
    placement_root = (tmp_path / "placement").resolve()
    unrelated_root = (tmp_path / "unrelated").resolve()
    placement_root.mkdir()
    unrelated_root.mkdir()
    profiles = (
        _profile("agent-alpha", workspaces=["placement-schedule"]),
        _profile("agent-beta", workspaces=["placement-schedule"]),
    )
    policies = (
        _policy("placement-schedule", placement_root),
        _policy("unrelated-project", unrelated_root),
    )

    authorities = _control_authorities(
        _runtime(profiles, policies),
        _synchronized(profiles, policies),
    )

    assert set(authorities) == {
        ("agent-alpha", "placement-schedule"),
        ("agent-beta", "placement-schedule"),
    }
    assert {item.canonical_root for item in authorities.values()} == {str(placement_root)}
    assert {item.maximum_concurrent_runs for item in authorities.values()} == {1}

    synchronized = _synchronized(profiles, policies)
    scheduler_limits = _scheduler_limits(_runtime(profiles, policies), synchronized)
    assert {
        client_id: (limits.maximum_in_flight, limits.maximum_queued)
        for client_id, limits in scheduler_limits.clients.items()
    } == {client_id: (4, 5) for client_id in synchronized.clients_by_id}


def test_legacy_client_without_workspace_allowlist_mints_no_launch_authority(
    tmp_path: Path,
) -> None:
    root = (tmp_path / "placement").resolve()
    root.mkdir()
    profiles = (_profile("legacy-client", workspaces=None),)
    policies = (_policy("placement-schedule", root),)

    assert (
        _control_authorities(
            _runtime(profiles, policies),
            _synchronized(profiles, policies),
        )
        == {}
    )


def test_explicit_binding_fails_closed_for_unknown_workspace(tmp_path: Path) -> None:
    root = (tmp_path / "placement").resolve()
    root.mkdir()
    profiles = (_profile("agent-alpha", workspaces=["missing-workspace"]),)
    policies = (_policy("placement-schedule", root),)

    with pytest.raises(RuntimeError, match="unknown workspace"):
        _control_authorities(
            _runtime(profiles, policies),
            _synchronized(profiles, policies),
        )


def test_explicit_binding_fails_closed_when_canonical_root_does_not_exist(
    tmp_path: Path,
) -> None:
    profiles = (_profile("agent-alpha", workspaces=["placement-schedule"]),)
    policies = (_policy("placement-schedule", tmp_path / "missing"),)

    with pytest.raises(ValueError, match="canonical workspace directory"):
        _control_authorities(
            _runtime(profiles, policies),
            _synchronized(profiles, policies),
        )
