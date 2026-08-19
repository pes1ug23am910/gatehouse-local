from __future__ import annotations

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
    assert main.retention.database_size_cap == 2 * (1 << 30)
    assert main.server.agent.host == "127.0.0.1"
    assert len(main.concurrency.service_limits) == 1
    assert main.provider.mode == "disabled"
    assert main.provider.network_enabled is False
    assert client.client.unattended is True
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
    ["0.0.0.0", "192.168.1.2", "localhost"],  # noqa: S104
)
def test_listener_must_be_a_loopback_ip_literal(host: str) -> None:
    document = read_example("config.example.yaml")
    server = document["server"]
    assert isinstance(server, dict)
    agent = server["agent"]
    assert isinstance(agent, dict)
    agent["host"] = host

    with pytest.raises(ValidationError, match="loopback"):
        MainConfig.model_validate(document)


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


def test_unattended_client_cannot_use_interactive_approval() -> None:
    document = read_example("clients/company-watcher.example.yaml")
    client = document["client"]
    assert isinstance(client, dict)
    client["approval_mode"] = "dashboard"

    with pytest.raises(ValidationError, match="unattended"):
        ClientProfileConfig.model_validate(document)


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
