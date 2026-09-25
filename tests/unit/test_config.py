from __future__ import annotations

import os
from copy import deepcopy
from io import BytesIO
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
from gatehouse.config.loader import ConfigLoadStage, parse_main_config, parse_yaml_model
from gatehouse.config.models import (
    FIXED_POLICY_SENSITIVE_CLASSIFICATIONS,
    PolicyDecision,
    PolicyDecisionConfig,
)

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
    assert main.reconciliation.maximum_snapshot_age == 30 * 60 * 1_000
    assert main.reconciliation.maximum_batch_duration == 30_000
    assert main.reconciliation.maximum_scopes_per_batch == 20
    assert main.reconciliation.absolute_credit_tolerance == 5
    assert main.server.agent.host == "127.0.0.1"
    assert len(main.concurrency.service_limits) == 1
    assert main.provider.mode == "disabled"
    assert main.provider.network_enabled is False
    assert main.firecrawl_workload.mode == "disabled"
    assert main.firecrawl_observer.mode == "disabled"
    assert main.firecrawl_observer.network_enabled is False
    assert main.runaway_detection.aggregate_requests == 20
    assert main.routing.maximum_total_provider_attempts == 1
    assert main.routing.maximum_route_candidates == 32
    assert client.client.unattended is True
    assert client.workspaces is not None
    assert client.workspaces.allow == ["placement-schedule"]
    assert client.pools.emergency_access is False
    assert feed.feed_set.workspace == "placement-schedule"
    assert [target.operation for target in feed.targets] == ["scrape", "map"]
    assert feed.targets[1].model_dump(mode="json")["limit"] == 25
    assert feed.crawl.allow_external_links is False
    assert policy.workspace.canonical_root == r"E:\Projects\Placement-Schedule"
    assert policy.default_decision is PolicyDecision.ASK
    targeted = policy.purposes["career_discovery"].root["scrape"]
    bounded = policy.purposes["multi_page_job_extraction"].root["crawl"]
    assert targeted.decision is PolicyDecision.ALLOW
    assert targeted.constraints.targeted_only is True
    assert bounded.decision is PolicyDecision.ALLOW
    assert bounded.constraints.enforce_limits is True


@pytest.mark.parametrize("value", [True, False, 0, -1, 2, 32, "1", 1.0, None])
def test_total_provider_attempt_limit_only_accepts_integer_one(value: object) -> None:
    document = read_example("config.example.yaml")
    document["routing"] = {"maximum_total_provider_attempts": value}
    with pytest.raises(ValidationError):
        MainConfig.model_validate(document)


@pytest.mark.parametrize("value", [True, False, 0, -1, 33, "1", 1.0, None])
def test_route_candidate_limit_rejects_invalid_bounds(value: object) -> None:
    document = read_example("config.example.yaml")
    document["routing"] = {"maximum_route_candidates": value}
    with pytest.raises(ValidationError):
        MainConfig.model_validate(document)


@pytest.mark.parametrize("value", [1, 8, 32])
def test_routing_limits_are_independent_of_provider_network_switches(value: int) -> None:
    document = read_example("config.example.yaml")
    document["routing"] = {
        "maximum_total_provider_attempts": 1,
        "maximum_route_candidates": value,
    }
    main = MainConfig.model_validate(document)
    assert main.routing.maximum_route_candidates == value
    assert main.routing.maximum_total_provider_attempts == 1
    assert main.firecrawl_workload.mode == "disabled"
    assert main.firecrawl_observer.mode == "disabled"


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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("quick_interval", "59s", "quick reconciliation interval"),
        ("quick_interval", "31d", "quick reconciliation interval"),
        ("full_interval", "366d", "full reconciliation interval"),
        ("maximum_snapshot_age", "59s", "reconciliation snapshot age"),
        ("maximum_snapshot_age", "31d", "reconciliation snapshot age"),
        ("maximum_batch_duration", "99ms", "reconciliation batch duration"),
        ("maximum_batch_duration", "61s", "reconciliation batch duration"),
    ],
)
def test_reconciliation_time_bounds_are_explicit(
    field: str,
    value: object,
    message: str,
) -> None:
    document = read_example("config.example.yaml")
    reconciliation = document["reconciliation"]
    assert isinstance(reconciliation, dict)
    reconciliation[field] = value

    with pytest.raises(ValidationError, match=message):
        MainConfig.model_validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maximum_scopes_per_batch", 0),
        ("maximum_scopes_per_batch", 1_001),
        ("absolute_credit_tolerance", 1.5),
        ("absolute_credit_tolerance", -1),
        ("consecutive_mismatches", 1_001),
    ],
)
def test_reconciliation_count_and_integer_tolerance_bounds(
    field: str,
    value: object,
) -> None:
    document = read_example("config.example.yaml")
    reconciliation = document["reconciliation"]
    assert isinstance(reconciliation, dict)
    reconciliation[field] = value

    with pytest.raises(ValidationError):
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


@pytest.mark.parametrize(
    "relative_path",
    [
        "config/policies/placement-schedule.example.yaml",
        "src/gatehouse/config/templates/placement-schedule.yaml",
    ],
)
def test_policy_examples_use_the_fixed_disabled_profile(relative_path: str) -> None:
    policy = load_workspace_policy(PROJECT_ROOT / relative_path)

    assert len(policy.hard_denies) == 3
    assert policy.credit_discipline.cross_session_public_coalescing is False
    assert policy.credit_discipline.cache_completed_public_reads == "disabled"
    assert all(
        rule.constraints.enforce_limits is True
        for purpose in policy.purposes.values()
        for rule in purpose.root.values()
    )


def test_fixed_hard_deny_profile_accepts_rule_and_classification_order_changes() -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    rules = document["hard_denies"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    classifications = rules[0]["data_classifications_any"]
    assert isinstance(classifications, list)
    classifications.reverse()
    rules.reverse()

    policy = WorkspacePolicyConfig.model_validate(document)

    sensitive = next(rule for rule in policy.hard_denies if rule.id == "no-sensitive-payloads")
    assert frozenset(sensitive.data_classifications_any or ()) == (
        FIXED_POLICY_SENSITIVE_CLASSIFICATIONS
    )


@pytest.mark.parametrize("count", [0, 1, 2, 4])
def test_fixed_hard_deny_profile_requires_exactly_three_rules(count: int) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    rules = document["hard_denies"]
    assert isinstance(rules, list)
    document["hard_denies"] = (rules * 2)[:count]

    with pytest.raises(ValidationError):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize(
    ("rule_index", "changes"),
    [
        (0, {"id": "custom-sensitive-deny"}),
        (0, {"data_classifications_any": ["public_web"]}),
        (0, {"operation": "search"}),
        (0, {"operation": "crawl", "when": {"crawl_entire_domain": True}}),
        (1, {"id": "no-sensitive-payloads"}),
        (1, {"operation": "scrape"}),
        (1, {"when": None}),
        (1, {"when": {"crawl_entire_domain": False}}),
        (1, {"when": {"crawl_entire_domain": True, "allow_external_links": True}}),
        (1, {"data_classifications_any": ["public_web"]}),
        (2, {"operation": "firecrawl.crawl.start"}),
        (2, {"when": {"allow_external_links": False}}),
        (2, {"when": {"crawl_entire_domain": True}}),
    ],
)
def test_fixed_hard_deny_profile_rejects_custom_rules(
    rule_index: int,
    changes: dict[str, object],
) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    rules = document["hard_denies"]
    assert isinstance(rules, list) and isinstance(rules[rule_index], dict)
    rules[rule_index].update(changes)

    with pytest.raises(ValidationError):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize("change", ["remove", "add", "duplicate"])
def test_fixed_hard_deny_profile_rejects_classification_changes(change: str) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    rules = document["hard_denies"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    classifications = rules[0]["data_classifications_any"]
    assert isinstance(classifications, list)
    if change == "remove":
        classifications.remove("resume")
    elif change == "add":
        classifications.append("public_web")
    else:
        classifications.append("resume")

    with pytest.raises(ValidationError):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize(
    "shorthand", ["allow", "allow_targeted", "allow_with_limits", "ask", "deny"]
)
def test_policy_shorthands_always_enforce_limits(shorthand: str) -> None:
    rule = PolicyDecisionConfig.model_validate(shorthand)

    assert rule.constraints.enforce_limits is True


def test_allow_shorthands_normalize_to_the_same_mandatory_limits() -> None:
    plain = PolicyDecisionConfig.model_validate("allow")
    bounded = PolicyDecisionConfig.model_validate("allow_with_limits")
    explicit = PolicyDecisionConfig.model_validate(
        {"decision": PolicyDecision.ALLOW, "constraints": {"enforce_limits": True}}
    )

    assert plain == bounded == explicit


@pytest.mark.parametrize("decision", ["allow", "ALLOW", "ask", "ASK", "deny", "DENY"])
def test_explicit_policy_decision_strings_match_shorthand(decision: str) -> None:
    explicit = PolicyDecisionConfig.model_validate({"decision": decision})

    assert explicit == PolicyDecisionConfig.model_validate(decision.lower())


@pytest.mark.parametrize("decision", ["ask", "ASK", "deny", "DENY"])
def test_targeted_constraint_cannot_weaken_or_repeat_non_allow_decision(decision: str) -> None:
    with pytest.raises(ValidationError, match="targeted_only"):
        PolicyDecisionConfig.model_validate(
            {"decision": decision, "constraints": {"targeted_only": True}}
        )


@pytest.mark.parametrize(
    "rule",
    ["allow_targeted", {"decision": "ALLOW", "constraints": {"targeted_only": True}}],
)
def test_search_rejects_targeted_only_without_a_typed_target(rule: object) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["purposes"] = {"career_discovery": {"search": rule}}

    with pytest.raises(ValidationError, match="targeted_only"):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize("operation", ["scrape", "map", "crawl"])
def test_targeted_allow_is_supported_for_targeted_operation_families(operation: str) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["purposes"] = {"career_discovery": {operation: "allow_targeted"}}

    policy = WorkspacePolicyConfig.model_validate(document)

    assert policy.purposes["career_discovery"].root[operation].constraints.targeted_only


@pytest.mark.parametrize("value", [False, 0, 1, 0.0, 1.0, "true", "false", None])
def test_policy_cannot_disable_or_coerce_mandatory_limits(value: object) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["purposes"] = {
        "career_discovery": {
            "search": {
                "decision": PolicyDecision.ALLOW,
                "constraints": {"enforce_limits": value},
            }
        }
    }

    with pytest.raises(ValidationError, match="enforce_limits"):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("duplicate_in_flight", "deny"),
        ("duplicate_in_flight", False),
        ("duplicate_in_flight", None),
        ("cross_session_public_coalescing", True),
        ("cross_session_public_coalescing", 0),
        ("cross_session_public_coalescing", 1),
        ("cross_session_public_coalescing", 0.0),
        ("cross_session_public_coalescing", 1.0),
        ("cross_session_public_coalescing", "false"),
        ("cross_session_public_coalescing", None),
        ("cache_completed_public_reads", "policy_controlled"),
        ("cache_completed_public_reads", "enabled"),
        ("cache_completed_public_reads", True),
        ("cache_completed_public_reads", None),
        ("broad_crawl_without_narrow_attempt", "allow"),
        ("broad_crawl_without_narrow_attempt", "allow_after_narrow_attempt"),
        ("broad_crawl_without_narrow_attempt", False),
        ("broad_crawl_without_narrow_attempt", None),
    ],
)
def test_policy_rejects_unsupported_credit_discipline(field: str, value: object) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    discipline = document["credit_discipline"]
    assert isinstance(discipline, dict)
    discipline[field] = value

    with pytest.raises(ValidationError, match=field):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize(
    "operation",
    [
        "unknown",
        "firecrawl.search",
        "crawl.start",
        "crawl.status",
        "firecrawl.account.credit_status",
    ],
)
def test_policy_rejects_unsupported_purpose_operation_names(operation: str) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["purposes"] = {"career_discovery": {operation: "allow"}}

    with pytest.raises(ValidationError, match="operation families"):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize("count", [0, 65])
def test_policy_purpose_count_is_bounded(count: int) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["purposes"] = {f"purpose_{index}": {"search": "allow"} for index in range(count)}

    with pytest.raises(ValidationError):
        WorkspacePolicyConfig.model_validate(document)


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_policy_credit_limit_must_be_finite(value: float) -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    limits = document["limits"]
    assert isinstance(limits, dict)
    limits["credits_per_root_run"] = value
    with pytest.raises(ValidationError, match="credits_per_root_run"):
        WorkspacePolicyConfig.model_validate(document)


def test_policy_accepts_the_maximum_purpose_count_and_all_supported_families() -> None:
    document = read_example("policies/placement-schedule.example.yaml")
    document["purposes"] = {
        f"purpose_{index}": {"search": "allow", "scrape": "ask", "map": "deny", "crawl": "deny"}
        for index in range(64)
    }

    policy = WorkspacePolicyConfig.model_validate(document)

    assert len(policy.purposes) == 64


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


def test_feed_requires_bounded_authorized_concrete_targets() -> None:
    document = read_example("feeds/placement-companies-primary.example.yaml")
    identity = document["feed_set"]
    assert isinstance(identity, dict)
    identity.pop("workspace")
    with pytest.raises(ValidationError, match="workspace"):
        FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    concrete = document["targets"]
    assert isinstance(concrete, list) and isinstance(concrete[0], dict)
    concrete[0]["operation"] = "crawl"
    with pytest.raises(ValidationError):
        FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    concrete = document["targets"]
    assert isinstance(concrete, list) and isinstance(concrete[0], dict)
    concrete[0]["limit"] = 1
    with pytest.raises(ValidationError):
        FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    concrete = document["targets"]
    assert isinstance(concrete, list) and isinstance(concrete[1], dict)
    concrete[1].pop("limit")
    with pytest.raises(ValidationError, match="limit"):
        FeedSetConfig.model_validate(document)

    for invalid_limit in (0, 101):
        document = read_example("feeds/placement-companies-primary.example.yaml")
        concrete = document["targets"]
        assert isinstance(concrete, list) and isinstance(concrete[1], dict)
        concrete[1]["limit"] = invalid_limit
        with pytest.raises(ValidationError, match="limit"):
            FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    concrete = document["targets"]
    assert isinstance(concrete, list) and isinstance(concrete[1], dict)
    concrete[1]["limit"] = 13
    concrete.append(
        {
            "operation": "map",
            "url": "https://jobs.example-ats.com/company-name/internships",
            "limit": 13,
        }
    )
    with pytest.raises(ValidationError, match="aggregate map result limit"):
        FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    concrete = document["targets"]
    assert isinstance(concrete, list) and isinstance(concrete[0], dict)
    concrete[0]["url"] = "https://careers.example.com/private"
    with pytest.raises(ValidationError, match="outside the feed-set allowlist"):
        FeedSetConfig.model_validate(document)

    document = read_example("feeds/placement-companies-primary.example.yaml")
    budgets = document["budgets"]
    assert isinstance(budgets, dict)
    budgets["maximum_requests_per_run"] = 1
    with pytest.raises(ValidationError, match="exceed the per-run request budget"):
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


def test_h3_content_loader_reads_only_limit_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[int] = []

    class BoundedStream(BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            assert size is not None
            requested.append(size)
            assert size == 17
            return super().read(size)

    stream = BoundedStream(b"x" * 100)
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: stream)

    with pytest.raises(ConfigLoadError, match="size limit"):
        load_yaml_model(Path("synthetic.yaml"), MainConfig, maximum_bytes=16)

    assert requested == [17]
    assert stream.closed


@pytest.mark.parametrize("maximum", [True, False, 0, -1, 1.0, "1", None, 1_048_577])
def test_h3_content_byte_limits_reject_invalid_values_before_io(
    maximum: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid bounds must not open a file")

    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(ValueError, match="maximum_bytes"):
        load_yaml_model("synthetic.yaml", MainConfig, maximum_bytes=maximum)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("payload", "stage"),
    [
        (b"\xff", ConfigLoadStage.DECODE),
        (b"schema_version: 1\nschema_version: 1\n", ConfigLoadStage.YAML),
        (b"value: &shared [1]\ncopy: *shared\n", ConfigLoadStage.YAML),
        (b"value: !!python/object/apply:builtins.str [unsafe]\n", ConfigLoadStage.YAML),
        (b"[]", ConfigLoadStage.YAML),
    ],
)
def test_h3_captured_byte_parser_keeps_yaml_rejections(
    payload: bytes, stage: ConfigLoadStage, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("captured bytes must not reopen a path")

    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(ConfigLoadError) as captured:
        parse_yaml_model(payload, Path("synthetic.yaml"), MainConfig)
    assert captured.value.stage is stage


def test_h3_captured_main_uses_origin_and_explicit_environment_without_yaml_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = read_example("config.example.yaml")
    database = document["database"]
    assert isinstance(database, dict)
    database["path"] = "state/local.sqlite3"
    payload = yaml.safe_dump(document).encode("utf-8")
    origin = tmp_path / "captured" / "config.yaml"

    def forbidden_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("captured YAML must not be reopened")

    monkeypatch.setattr(Path, "open", forbidden_open)
    configuration = parse_main_config(payload, config_path=origin, environment={})

    assert configuration.database.path == str((origin.parent / "state/local.sqlite3").resolve())
    assert configuration.routing.maximum_total_provider_attempts == 1


def test_h3_captured_main_does_not_resolve_its_configuration_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = read_example("config.example.yaml")
    database = document["database"]
    assert isinstance(database, dict)
    database["path"] = "state/local.sqlite3"
    payload = yaml.safe_dump(document).encode("utf-8")
    origin = tmp_path / "captured" / "config.yaml"
    original_resolve = Path.resolve

    def resolve(path: Path, strict: bool = False) -> Path:
        assert path != origin, "a verified configuration origin must not be resolved again"
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve)
    configuration = parse_main_config(payload, config_path=origin, environment={})
    assert configuration.database.path == str((origin.parent / "state/local.sqlite3").resolve())
