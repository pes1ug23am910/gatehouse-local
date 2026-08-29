from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

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
    load_yaml_model,
    parse_duration_ms,
    parse_size_bytes,
)
from gatehouse.config.loader import ConfigLoadStage
from gatehouse.config.models import PolicyDecision

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "config"


def read_example(relative_path: str) -> dict[str, object]:
    with (CONFIG_ROOT / relative_path).open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    assert isinstance(document, dict)
    return document


def test_all_supplied_configuration_examples_validate() -> None:
    main = load_main_config(
        CONFIG_ROOT / "config.example.yaml",
        environment={
            "LOCALAPPDATA": r"C:\Users\example\AppData\Local",
            "APPDATA": r"C:\Users\example\AppData\Roaming",
        },
    )
    client = load_client_profile(CONFIG_ROOT / "clients" / "company-watcher.example.yaml")
    feed = load_feed_set(CONFIG_ROOT / "feeds" / "placement-companies-primary.example.yaml")
    policy = load_workspace_policy(CONFIG_ROOT / "policies" / "placement-schedule.example.yaml")

    assert main.sessions.access_token_ttl == 10 * 60 * 1_000
    assert main.sessions.maximum_active_access_tokens_per_session == 1
    assert main.sessions.maximum_bootstrap_exchanges_per_window == 8
    assert main.sessions.bootstrap_exchange_window == 60_000
    assert main.retention.database_size_cap == 2 * (1 << 30)
    assert main.retention.maintenance_interval == 15 * 60 * 1_000
    assert main.server.agent.host == "127.0.0.1"
    assert len(main.concurrency.service_limits) == 1
    assert main.provider.mode == "disabled"
    assert main.provider.network_enabled is False
    assert main.firecrawl_workload.mode == "disabled"
    assert main.firecrawl_observer.mode == "disabled"
    assert main.firecrawl_observer.network_enabled is False
    assert main.runaway_detection.aggregate_requests == 20
    assert client.client.unattended is True
    assert client.workspaces is not None
    assert client.workspaces.allow == ["placement-schedule"]
    assert client.pools.emergency_access is False
    assert feed.crawl.allow_external_links is False
    assert policy.workspace.canonical_root == r"E:\Projects\Placement-Schedule"
    assert policy.default_decision is PolicyDecision.ASK
    targeted = policy.purposes["career_discovery"].root["scrape"]
    bounded = policy.purposes["multi_page_job_extraction"].root["crawl"]
    assert targeted.decision is PolicyDecision.ALLOW
    assert targeted.constraints.targeted_only is True
    assert bounded.decision is PolicyDecision.ALLOW
    assert bounded.constraints.enforce_limits is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("250ms", 250),
        ("30s", 30_000),
        ("10m", 600_000),
        ("4h", 14_400_000),
        ("7d", 604_800_000),
        ("0.5s", 500),
        (100, 100),
    ],
)
def test_duration_parser(value: object, expected: int) -> None:
    assert parse_duration_ms(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("250MiB", 250 * (1 << 20)),
        ("2GiB", 2 * (1 << 30)),
        ("1GB", 1_000_000_000),
        (512, 512),
    ],
)
def test_size_parser(value: object, expected: int) -> None:
    assert parse_size_bytes(value) == expected


@pytest.mark.parametrize("value", [True, 0, "", "1", "1fortnight", "0.1ms"])
def test_duration_parser_rejects_ambiguous_or_unbounded_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_duration_ms(value)


def test_unknown_top_level_and_nested_fields_are_rejected() -> None:
    document = read_example("config.example.yaml")
    document["unexpected"] = True
    with pytest.raises(ValidationError):
        MainConfig.model_validate(document)

    nested = read_example("config.example.yaml")
    server = nested["server"]
    assert isinstance(server, dict)
    agent = server["agent"]
    assert isinstance(agent, dict)
    agent["unexpected"] = True
    with pytest.raises(ValidationError):
        MainConfig.model_validate(nested)


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "192.168.1.2", "localhost", "127.0.0.2", "::1"],  # noqa: S104
)
def test_listener_must_be_a_loopback_ip_literal(host: str) -> None:
    document = read_example("config.example.yaml")
    server = document["server"]
    assert isinstance(server, dict)
    agent = server["agent"]
    assert isinstance(agent, dict)
    agent["host"] = host

    with pytest.raises(ValidationError, match="127.0.0.1"):
        MainConfig.model_validate(document)


def test_database_busy_timeout_is_capped_at_frozen_contract() -> None:
    document = read_example("config.example.yaml")
    database = document["database"]
    assert isinstance(database, dict)
    database["busy_timeout_ms"] = 5_001

    with pytest.raises(ValidationError):
        MainConfig.model_validate(document)


def test_main_loader_canonicalizes_relative_database_path_from_config_directory(
    tmp_path: Path,
) -> None:
    document = read_example("config.example.yaml")
    database = document["database"]
    assert isinstance(database, dict)
    database["path"] = "state/gatehouse.db"
    config_path = tmp_path / "nested" / "config.yaml"
    config_path.parent.mkdir()
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    loaded = load_main_config(config_path)

    assert Path(loaded.database.path) == (config_path.parent / "state/gatehouse.db").resolve()


@pytest.mark.skipif(os.name != "nt", reason="Windows path rooting is Windows-specific")
@pytest.mark.parametrize("database_path", (r"C:state\gatehouse.db", r"\state\gatehouse.db"))
def test_main_loader_rejects_drive_or_root_relative_database_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    database_path: str,
) -> None:
    document = read_example("config.example.yaml")
    database = document["database"]
    assert isinstance(database, dict)
    database["path"] = database_path
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    def unexpected_drive_probe(_root: str) -> int:
        raise AssertionError("ambiguous paths must fail before a drive probe")

    monkeypatch.setattr(
        "gatehouse.state_security._windows_drive_type",
        unexpected_drive_probe,
    )

    with pytest.raises(
        ConfigLoadError,
        match="^configuration validation failed for config.yaml: database state path is unsafe$",
    ):
        load_main_config(config_path)

    assert not (tmp_path / "state").exists()


def test_agent_and_admin_listeners_must_use_different_ports() -> None:
    document = read_example("config.example.yaml")
    server = document["server"]
    assert isinstance(server, dict)
    agent = server["agent"]
    admin = server["admin"]
    assert isinstance(agent, dict) and isinstance(admin, dict)
    admin["port"] = agent["port"]

    with pytest.raises(ValidationError, match="distinct ports"):
        MainConfig.model_validate(document)


def test_session_reconnect_grace_must_exceed_heartbeat_interval() -> None:
    document = read_example("config.example.yaml")
    sessions = document["sessions"]
    assert isinstance(sessions, dict)
    sessions["reconnect_grace"] = sessions["heartbeat_interval"]

    with pytest.raises(ValidationError, match="reconnect grace must exceed heartbeat interval"):
        MainConfig.model_validate(document)


def test_aggregate_runaway_threshold_cannot_be_below_identical_threshold() -> None:
    document = read_example("config.example.yaml")
    runaway = document["runaway_detection"]
    assert isinstance(runaway, dict)
    runaway["identical_requests"] = 5
    runaway["aggregate_requests"] = 4

    with pytest.raises(ValidationError, match="aggregate runaway threshold"):
        MainConfig.model_validate(document)


@pytest.mark.parametrize("interval", ("59s", "25h"))
def test_retention_maintenance_interval_is_explicitly_bounded(interval: str) -> None:
    document = read_example("config.example.yaml")
    retention = document["retention"]
    assert isinstance(retention, dict)
    retention["maintenance_interval"] = interval

    with pytest.raises(ValidationError, match="retention maintenance interval"):
        MainConfig.model_validate(document)


def test_session_heartbeat_interval_is_capped_for_bounded_mcp_maintenance() -> None:
    document = read_example("config.example.yaml")
    sessions = document["sessions"]
    assert isinstance(sessions, dict)
    sessions["heartbeat_interval"] = "301s"
    sessions["stale_after"] = "600s"
    sessions["reconnect_grace"] = "900s"

    with pytest.raises(ValidationError, match="heartbeat interval must not exceed 300 seconds"):
        MainConfig.model_validate(document)


def test_session_heartbeat_interval_has_mcp_compatible_minimum() -> None:
    document = read_example("config.example.yaml")
    sessions = document["sessions"]
    assert isinstance(sessions, dict)
    sessions["heartbeat_interval"] = "999ms"

    with pytest.raises(ValidationError, match="heartbeat interval must be at least 1 second"):
        MainConfig.model_validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maximum_active_access_tokens_per_session", 0),
        ("maximum_active_access_tokens_per_session", 5),
        ("maximum_bootstrap_exchanges_per_window", 0),
        ("maximum_bootstrap_exchanges_per_window", 121),
        ("bootstrap_exchange_window", "999ms"),
        ("bootstrap_exchange_window", "301s"),
    ],
)
def test_session_exchange_limits_are_bounded(field: str, value: object) -> None:
    document = read_example("config.example.yaml")
    sessions = document["sessions"]
    assert isinstance(sessions, dict)
    sessions[field] = value

    with pytest.raises(ValidationError):
        MainConfig.model_validate(document)


@pytest.mark.parametrize(("global_capacity", "per_session"), [(1, 2), (4, 4)])
def test_per_session_token_capacity_preserves_global_capacity_for_a_peer(
    global_capacity: int,
    per_session: int,
) -> None:
    document = read_example("config.example.yaml")
    sessions = document["sessions"]
    concurrency = document["concurrency"]
    assert isinstance(sessions, dict) and isinstance(concurrency, dict)
    sessions["maximum_active_access_tokens_per_session"] = per_session
    concurrency["maximum_connected_clients"] = global_capacity
    concurrency["global_in_flight"] = 1
    firecrawl = concurrency["firecrawl"]
    assert isinstance(firecrawl, dict)
    firecrawl["maximum_in_flight"] = 1
    firecrawl["maximum_per_quota_scope"] = 1

    with pytest.raises(ValidationError, match="access-token capacity"):
        MainConfig.model_validate(document)


def test_provider_modes_require_explicit_non_network_script_or_double_opt_in() -> None:
    document = read_example("config.example.yaml")
    document["provider"] = {
        "mode": "scripted",
        "network_enabled": False,
        "scripted_responses_path": r"C:\Gatehouse\script.json",
    }
    scripted = MainConfig.model_validate(document)
    assert scripted.provider.mode == "scripted"

    document["provider"] = {"mode": "scripted", "network_enabled": True}
    with pytest.raises(ValidationError, match="scripted"):
        MainConfig.model_validate(document)

    document["provider"] = {"mode": "live", "network_enabled": False}
    with pytest.raises(ValidationError, match="live"):
        MainConfig.model_validate(document)

    document["provider"] = {"mode": "live", "network_enabled": True}
    assert MainConfig.model_validate(document).provider.mode == "live"


def test_provider_scoped_workload_and_observer_switches_are_independent() -> None:
    document = read_example("config.example.yaml")
    providers = document["providers"]
    assert isinstance(providers, dict)
    firecrawl = providers["firecrawl"]
    assert isinstance(firecrawl, dict)
    firecrawl["workload"] = {"mode": "live", "network_enabled": True}

    workload_only = MainConfig.model_validate(document)
    assert workload_only.firecrawl_workload.mode == "live"
    assert workload_only.firecrawl_observer.mode == "disabled"

    firecrawl["observer"] = {
        "mode": "live",
        "network_enabled": True,
        "interval": "15m",
        "freshness_ttl": "30m",
        "request_timeout": "10s",
        "maximum_accounts_per_cycle": 20,
        "maximum_concurrency": 1,
    }
    both = MainConfig.model_validate(document)
    assert both.firecrawl_workload.network_enabled is True
    assert both.firecrawl_observer.network_enabled is True


def test_provider_observer_requires_explicit_network_and_bounds() -> None:
    document = read_example("config.example.yaml")
    providers = document["providers"]
    assert isinstance(providers, dict)
    firecrawl = providers["firecrawl"]
    assert isinstance(firecrawl, dict)
    observer = firecrawl["observer"]
    assert isinstance(observer, dict)
    observer["mode"] = "live"

    with pytest.raises(ValidationError, match="requires explicit networking"):
        MainConfig.model_validate(document)

    observer["network_enabled"] = True
    observer["request_timeout"] = "61s"
    with pytest.raises(ValidationError, match="cannot exceed 60 seconds"):
        MainConfig.model_validate(document)


def test_unimplemented_provider_switches_fail_closed() -> None:
    document = read_example("config.example.yaml")
    providers = document["providers"]
    assert isinstance(providers, dict)
    providers["github"] = {
        "workload": {"mode": "live", "network_enabled": True},
    }

    with pytest.raises(ValidationError, match="github provider operations are not implemented"):
        MainConfig.model_validate(document)


def test_legacy_and_scoped_firecrawl_workload_settings_cannot_conflict() -> None:
    document = read_example("config.example.yaml")
    document["provider"] = {"mode": "live", "network_enabled": True}
    providers = document["providers"]
    assert isinstance(providers, dict)
    firecrawl = providers["firecrawl"]
    assert isinstance(firecrawl, dict)
    firecrawl["workload"] = {
        "mode": "scripted",
        "network_enabled": False,
        "scripted_responses_path": r"C:\Gatehouse\script.json",
    }

    with pytest.raises(ValidationError, match="settings conflict"):
        MainConfig.model_validate(document)


def test_unattended_client_cannot_use_interactive_approval() -> None:
    document = read_example("clients/company-watcher.example.yaml")
    client = document["client"]
    assert isinstance(client, dict)
    client["approval_mode"] = "dashboard"

    with pytest.raises(ValidationError, match="unattended"):
        ClientProfileConfig.model_validate(document)


def test_client_workspace_bindings_are_explicit_unique_and_legacy_omission_is_fail_closed() -> None:
    document = read_example("clients/company-watcher.example.yaml")
    workspaces = document["workspaces"]
    assert isinstance(workspaces, dict)
    workspaces["allow"] = ["placement-schedule", "placement-schedule"]

    with pytest.raises(ValidationError, match="workspace bindings must be unique"):
        ClientProfileConfig.model_validate(document)

    legacy = read_example("clients/company-watcher.example.yaml")
    del legacy["workspaces"]
    parsed = ClientProfileConfig.model_validate(legacy)
    assert parsed.workspaces is None


def test_client_cannot_persist_emergency_pool_access_or_binding() -> None:
    document = read_example("clients/company-watcher.example.yaml")
    pools = document["pools"]
    assert isinstance(pools, dict)
    pools["emergency_access"] = True
    with pytest.raises(ValidationError):
        ClientProfileConfig.model_validate(document)

    document = read_example("clients/company-watcher.example.yaml")
    pools = document["pools"]
    assert isinstance(pools, dict)
    service_key = next(key for key in pools if key != "emergency_access")
    pools[service_key] = "emergency-locked"
    with pytest.raises(ValidationError, match="emergency pool"):
        ClientProfileConfig.model_validate(document)


def test_workspace_policy_cannot_select_emergency_pool_by_default() -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["default_pool"] = "emergency-locked"

    with pytest.raises(ValidationError, match="emergency pool"):
        WorkspacePolicyConfig.model_validate(document)


def test_feed_rejects_invalid_regex_and_duplicate_schedule_days() -> None:
    document = read_example("feeds/placement-companies-primary.example.yaml")
    targets = document["allowed_targets"]
    assert isinstance(targets, list) and isinstance(targets[0], dict)
    targets[0]["path_regex"] = "["
    with pytest.raises(ValidationError, match="path_regex"):
        FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    schedule = document["schedule"]
    assert isinstance(schedule, dict)
    windows = schedule["windows"]
    assert isinstance(windows, list) and isinstance(windows[0], dict)
    windows[0]["days"] = ["mon", "mon"]
    with pytest.raises(ValidationError, match="unique"):
        FeedSetConfig.model_validate(document)


def test_yaml_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")

    with pytest.raises(ConfigLoadError) as captured:
        load_yaml_model(path, MainConfig)

    assert captured.value.stage.value == "yaml"


def test_yaml_loader_rejects_unsafe_tags(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text("value: !!python/object/apply:builtins.str [unsafe]\n", encoding="utf-8")

    with pytest.raises(ConfigLoadError) as captured:
        load_yaml_model(path, MainConfig)

    assert captured.value.stage.value == "yaml"


def test_config_load_error_redacts_credential_shaped_paths_and_summaries() -> None:
    path_token = "fc-" + "abcdefghijklmnopqrstuvwxyz123456"
    summary_token = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"

    error = ConfigLoadError(
        Path(f"{path_token}.yaml"),
        ConfigLoadStage.READ,
        f"unavailable near {summary_token}",
    )

    rendered = str(error)
    assert path_token not in rendered
    assert summary_token not in rendered
    assert "[REDACTED:firecrawl_token]" in rendered
    assert "[REDACTED:generic_sk_token]" in rendered


def test_yaml_loader_rejects_anchors_and_aliases(tmp_path: Path) -> None:
    path = tmp_path / "alias.yaml"
    path.write_text("value: &shared [1, 2]\ncopy: *shared\n", encoding="utf-8")

    with pytest.raises(ConfigLoadError, match="anchors and aliases"):
        load_yaml_model(path, MainConfig)


def test_environment_expansion_is_allowlisted_and_required(tmp_path: Path) -> None:
    source = CONFIG_ROOT / "config.example.yaml"
    path = tmp_path / "config.yaml"
    path.write_bytes(source.read_bytes())

    with pytest.raises(ConfigLoadError, match="not defined"):
        load_main_config(path, environment={})

    text = source.read_text(encoding="utf-8").replace("%LOCALAPPDATA%", "%UNSAFE_PATH%")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigLoadError, match="not allowed"):
        load_main_config(path, environment={"UNSAFE_PATH": r"C:\Temp"})


def test_strict_models_do_not_coerce_string_booleans() -> None:
    document = deepcopy(read_example("feeds/placement-companies-primary.example.yaml"))
    crawl = document["crawl"]
    assert isinstance(crawl, dict)
    crawl["allow_subdomains"] = "false"

    with pytest.raises(ValidationError):
        FeedSetConfig.model_validate(document)
