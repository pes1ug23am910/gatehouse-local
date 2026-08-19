"""Strict Pydantic v2 models for every shipped configuration example."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from enum import StrEnum
from pathlib import PureWindowsPath
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    RootModel,
    StringConstraints,
    field_validator,
    model_validator,
)

from .parsing import DurationMs, SizeBytes

Identifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$",
        strip_whitespace=True,
    ),
]
SymbolName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$",
        strip_whitespace=True,
    ),
]
OperationName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=80,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$",
        strip_whitespace=True,
    ),
]
CapabilityName = OperationName
TimezoneName = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=100,
        pattern=r"^[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9._+-]+)+$",
        strip_whitespace=True,
    ),
]
TimeOfDay = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$"),
]

EMERGENCY_POOL_ID = "emergency-locked"


class StrictConfigModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        str_strip_whitespace=True,
    )


class InstallationConfig(StrictConfigModel):
    name: Identifier
    timezone: TimezoneName


class ListenerConfig(StrictConfigModel):
    host: str
    port: int = Field(ge=1, le=65_535)

    @field_validator("host")
    @classmethod
    def validate_loopback_host(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("listener host must be a loopback IP literal") from error
        if not address.is_loopback:
            raise ValueError("listener host must be loopback-only")
        return address.compressed


class ServerConfig(StrictConfigModel):
    agent: ListenerConfig
    admin: ListenerConfig

    @model_validator(mode="after")
    def validate_listener_separation(self) -> Self:
        if self.agent.port == self.admin.port:
            raise ValueError("agent and admin listeners must use distinct ports")
        return self


class DatabaseConfig(StrictConfigModel):
    path: str = Field(min_length=1, max_length=32_767)
    journal_mode: Literal["WAL"]
    synchronous: Literal["FULL"]
    busy_timeout_ms: int = Field(gt=0, le=300_000)

    @field_validator("path")
    @classmethod
    def validate_database_path(cls, value: str) -> str:
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("database path contains a forbidden character")
        return value


class SessionsConfig(StrictConfigModel):
    access_token_ttl: DurationMs
    interactive_absolute_ttl: DurationMs
    unattended_absolute_ttl: DurationMs
    heartbeat_interval: DurationMs
    stale_after: DurationMs
    reconnect_grace: DurationMs

    @model_validator(mode="after")
    def validate_session_timing(self) -> Self:
        if self.heartbeat_interval < 1_000:
            raise ValueError("heartbeat interval must be at least 1 second")
        if self.heartbeat_interval > 300_000:
            raise ValueError("heartbeat interval must not exceed 300 seconds")
        if self.stale_after <= self.heartbeat_interval:
            raise ValueError("stale_after must exceed heartbeat_interval")
        if self.reconnect_grace <= self.heartbeat_interval:
            raise ValueError("reconnect grace must exceed heartbeat interval")
        minimum_lifetime = min(self.interactive_absolute_ttl, self.unattended_absolute_ttl)
        if self.access_token_ttl >= minimum_lifetime:
            raise ValueError("access_token_ttl must be shorter than session lifetimes")
        if self.reconnect_grace >= minimum_lifetime:
            raise ValueError("reconnect_grace must be shorter than session lifetimes")
        return self


class ApprovalsConfig(StrictConfigModel):
    default_ttl: DurationMs
    unattended_behavior: Literal["deny"]
    windows_notification: bool
    terminal_prompt: Literal[False]


class PerSessionConcurrencyConfig(StrictConfigModel):
    maximum_in_flight: int = Field(gt=0)
    maximum_queued: int = Field(gt=0)


class ServiceConcurrencyConfig(StrictConfigModel):
    maximum_in_flight: int = Field(gt=0)
    maximum_per_quota_scope: int = Field(gt=0)
    interactive_queue_depth: int = Field(gt=0)
    system_reserved_queue_depth: int = Field(gt=0)
    queue_ttl: DurationMs
    watcher_reserved_in_flight: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_service_capacity(self) -> Self:
        if self.maximum_per_quota_scope > self.maximum_in_flight:
            raise ValueError("per-quota concurrency cannot exceed service concurrency")
        if self.watcher_reserved_in_flight > self.maximum_in_flight:
            raise ValueError("reserved capacity cannot exceed service concurrency")
        return self


class ConcurrencyConfig(BaseModel):
    __pydantic_extra__: dict[str, ServiceConcurrencyConfig] = Field(init=False)

    model_config = ConfigDict(
        extra="allow",
        strict=True,
        frozen=True,
        validate_default=True,
        str_strip_whitespace=True,
    )

    maximum_connected_clients: int = Field(gt=0)
    global_in_flight: int = Field(gt=0)
    global_queue_depth: int = Field(gt=0)
    per_session: PerSessionConcurrencyConfig

    @model_validator(mode="after")
    def validate_global_capacity(self) -> Self:
        if self.global_in_flight > self.maximum_connected_clients:
            raise ValueError("global in-flight limit cannot exceed connected clients")
        extras = self.__pydantic_extra__ or {}
        if not extras:
            raise ValueError("at least one service concurrency profile is required")
        for service_id, limits in extras.items():
            if re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", service_id) is None:
                raise ValueError("service concurrency keys must be identifiers")
            if limits.maximum_in_flight > self.global_in_flight:
                raise ValueError("service concurrency cannot exceed global concurrency")
            combined_queue = limits.interactive_queue_depth + limits.system_reserved_queue_depth
            if combined_queue > self.global_queue_depth:
                raise ValueError("service queues cannot exceed the global queue depth")
        return self

    @property
    def service_limits(self) -> Mapping[str, ServiceConcurrencyConfig]:
        return self.__pydantic_extra__ or {}


class RunawayDetectionConfig(StrictConfigModel):
    identical_requests: int = Field(gt=1)
    window: DurationMs
    cooldown: DurationMs

    @model_validator(mode="after")
    def validate_cooldown(self) -> Self:
        if self.cooldown < self.window:
            raise ValueError("runaway cooldown must not be shorter than its window")
        return self


class RetentionConfig(StrictConfigModel):
    detailed_metadata_age: DurationMs
    database_size_cap: SizeBytes
    debug_excerpt_age: DurationMs
    debug_excerpt_size_cap: SizeBytes
    daily_aggregate_age: DurationMs

    @model_validator(mode="after")
    def validate_retention_bounds(self) -> Self:
        if self.debug_excerpt_age > self.detailed_metadata_age:
            raise ValueError("debug retention cannot exceed detailed metadata retention")
        if self.debug_excerpt_size_cap > self.database_size_cap:
            raise ValueError("debug storage cap cannot exceed the database cap")
        return self


class ReconciliationConfig(StrictConfigModel):
    quick_interval: DurationMs
    full_interval: DurationMs
    absolute_credit_tolerance: float = Field(ge=0)
    relative_tolerance: float = Field(ge=0, le=1)
    consecutive_mismatches: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_intervals(self) -> Self:
        if self.full_interval < self.quick_interval:
            raise ValueError("full reconciliation cannot be more frequent than quick checks")
        return self


class WatchdogConfig(StrictConfigModel):
    interval: DurationMs
    readiness_timeout: DurationMs
    maximum_restarts: int = Field(gt=0)
    restart_window: DurationMs
    crash_loop_cooldown: DurationMs

    @model_validator(mode="after")
    def validate_watchdog_timing(self) -> Self:
        if self.readiness_timeout >= self.restart_window:
            raise ValueError("readiness timeout must be shorter than the restart window")
        return self


class ProviderRuntimeConfig(StrictConfigModel):
    """Explicit provider transport mode; networking never follows from defaults."""

    mode: Literal["disabled", "scripted", "live"] = "disabled"
    network_enabled: bool = False
    scripted_responses_path: str | None = Field(
        default=None,
        min_length=1,
        max_length=32_767,
    )

    @field_validator("scripted_responses_path")
    @classmethod
    def validate_script_path(cls, value: str | None) -> str | None:
        if value is not None and any(character in value for character in "\x00\n\r"):
            raise ValueError("scripted response path contains a forbidden character")
        return value

    @model_validator(mode="after")
    def validate_mode_boundary(self) -> Self:
        if self.mode == "disabled":
            if self.network_enabled or self.scripted_responses_path is not None:
                raise ValueError("disabled provider mode cannot enable a transport")
        elif self.mode == "scripted":
            if self.network_enabled:
                raise ValueError("scripted provider mode cannot enable networking")
            if self.scripted_responses_path is None:
                raise ValueError("scripted provider mode requires a response manifest")
        elif not self.network_enabled or self.scripted_responses_path is not None:
            raise ValueError("live provider mode requires explicit networking and no script")
        return self


class MainConfig(StrictConfigModel):
    schema_version: Literal[1]
    installation: InstallationConfig
    server: ServerConfig
    database: DatabaseConfig
    sessions: SessionsConfig
    approvals: ApprovalsConfig
    concurrency: ConcurrencyConfig
    runaway_detection: RunawayDetectionConfig
    retention: RetentionConfig
    reconciliation: ReconciliationConfig
    watchdog: WatchdogConfig
    provider: ProviderRuntimeConfig = ProviderRuntimeConfig()


class ClientIdentityConfig(StrictConfigModel):
    id: Identifier
    kind: Literal["interactive", "system", "unattributed"]
    unattended: bool
    approval_mode: Literal["dashboard", "deny_on_ask", "denied"]
    default_priority: SymbolName
    maximum_concurrent_runs: int = Field(gt=0)
    maximum_in_flight: int = Field(gt=0)
    maximum_queued: int = Field(gt=0)
    maximum_run_duration: DurationMs

    @model_validator(mode="after")
    def validate_approval_behavior(self) -> Self:
        if self.unattended and self.approval_mode != "deny_on_ask":
            raise ValueError("unattended clients must deny approval-requiring work")
        if self.kind == "system" and not self.unattended:
            raise ValueError("system clients must be unattended")
        if self.kind == "interactive" and self.unattended:
            raise ValueError("interactive clients cannot be unattended")
        if self.kind == "unattributed" and self.approval_mode != "denied":
            raise ValueError("unattributed clients cannot request approvals")
        return self


class CapabilityConfig(StrictConfigModel):
    allow: list[CapabilityName] = Field(min_length=1)

    @field_validator("allow")
    @classmethod
    def validate_unique_capabilities(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("capabilities must be unique")
        return value


class ClientPoolBindings(StrictConfigModel):
    emergency_access: Literal[False]
    bindings: dict[Identifier, Identifier]

    @model_validator(mode="before")
    @classmethod
    def collect_bindings(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise TypeError("pool bindings must be an object")
        if "bindings" in value:
            if set(value) - {"bindings", "emergency_access"}:
                raise ValueError("normalized pool bindings contain unknown fields")
            return value

        if "emergency_access" not in value:
            raise ValueError("emergency_access must be declared explicitly")
        return {
            "emergency_access": value["emergency_access"],
            "bindings": {key: item for key, item in value.items() if key != "emergency_access"},
        }

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if not self.bindings:
            raise ValueError("at least one service pool binding is required")
        if EMERGENCY_POOL_ID in self.bindings.values():
            raise ValueError("the emergency pool cannot be a persistent default binding")
        return self


class LeaseConfig(StrictConfigModel):
    heartbeat_interval: DurationMs
    stale_after: DurationMs

    @model_validator(mode="after")
    def validate_lease_timing(self) -> Self:
        if self.stale_after <= self.heartbeat_interval:
            raise ValueError("lease stale_after must exceed heartbeat_interval")
        return self


class ClientProfileConfig(StrictConfigModel):
    schema_version: Literal[1]
    client: ClientIdentityConfig
    capabilities: CapabilityConfig
    pools: ClientPoolBindings
    lease: LeaseConfig


class FeedSetIdentityConfig(StrictConfigModel):
    id: Identifier
    display_name: str = Field(min_length=1, max_length=200)


class AllowedTargetConfig(StrictConfigModel):
    host: str = Field(min_length=1, max_length=253)
    path_regex: str = Field(min_length=1, max_length=1_000)
    operations: list[OperationName] = Field(min_length=1)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        normalized = value.rstrip(".").lower()
        if (
            re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",
                normalized,
            )
            is None
        ):
            raise ValueError("target host must be a valid DNS hostname")
        return normalized

    @field_validator("path_regex")
    @classmethod
    def validate_path_regex(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError("path_regex must compile successfully") from error
        return value

    @field_validator("operations")
    @classmethod
    def validate_unique_operations(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("target operations must be unique")
        return value


class CrawlConfig(StrictConfigModel):
    maximum_pages: int = Field(gt=0, le=10_000)
    maximum_depth: int = Field(ge=0, le=100)
    allow_external_links: Literal[False]
    allow_subdomains: bool
    ignore_query_parameters: bool


DayName = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


class ScheduleWindowConfig(StrictConfigModel):
    days: list[DayName] = Field(min_length=1)
    start: TimeOfDay
    end: TimeOfDay

    @field_validator("days")
    @classmethod
    def validate_unique_days(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("schedule days must be unique")
        return value

    @model_validator(mode="after")
    def validate_nonempty_window(self) -> Self:
        if self.start == self.end:
            raise ValueError("schedule window start and end must differ")
        return self


class ScheduleConfig(StrictConfigModel):
    timezone: TimezoneName
    windows: list[ScheduleWindowConfig] = Field(min_length=1)
    early_start_grace: DurationMs
    late_start_grace: DurationMs


class FeedBudgetsConfig(StrictConfigModel):
    maximum_requests_per_run: int = Field(gt=0)
    maximum_credits_per_run: float = Field(gt=0)
    maximum_duration: DurationMs


class FeedSetConfig(StrictConfigModel):
    schema_version: Literal[1]
    feed_set: FeedSetIdentityConfig
    allowed_targets: list[AllowedTargetConfig] = Field(min_length=1)
    crawl: CrawlConfig
    schedule: ScheduleConfig
    budgets: FeedBudgetsConfig

    @model_validator(mode="after")
    def validate_unique_targets(self) -> Self:
        identities = [(target.host, target.path_regex) for target in self.allowed_targets]
        if len(identities) != len(set(identities)):
            raise ValueError("allowed targets must be unique")
        return self


class WorkspaceConfig(StrictConfigModel):
    id: Identifier
    canonical_root: str = Field(min_length=3, max_length=32_767)

    @field_validator("canonical_root")
    @classmethod
    def validate_windows_absolute_path(cls, value: str) -> str:
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("workspace path contains a forbidden character")
        path = PureWindowsPath(value)
        if not path.is_absolute() or not path.drive:
            raise ValueError("workspace path must be an absolute Windows path")
        if ".." in path.parts:
            raise ValueError("workspace path cannot contain parent traversal")
        return str(path)


class HardDenyWhenConfig(StrictConfigModel):
    crawl_entire_domain: bool | None = None
    allow_external_links: bool | None = None

    @model_validator(mode="after")
    def validate_condition(self) -> Self:
        if self.crawl_entire_domain is None and self.allow_external_links is None:
            raise ValueError("hard-deny condition must contain a predicate")
        return self


class HardDenyConfig(StrictConfigModel):
    id: Identifier
    data_classifications_any: list[SymbolName] | None = None
    operation: OperationName | None = None
    when: HardDenyWhenConfig | None = None

    @model_validator(mode="after")
    def validate_rule_predicate(self) -> Self:
        if self.data_classifications_any is None and self.operation is None:
            raise ValueError("hard-deny rule must contain a predicate")
        if self.data_classifications_any is not None:
            if not self.data_classifications_any:
                raise ValueError("data classification list cannot be empty")
            if len(self.data_classifications_any) != len(set(self.data_classifications_any)):
                raise ValueError("data classifications must be unique")
        if self.when is not None and self.operation is None:
            raise ValueError("operation is required when a request predicate is present")
        return self


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"


def _normalize_policy_decision(value: Any) -> Any:
    if isinstance(value, PolicyDecision):
        return value
    if isinstance(value, str):
        try:
            return PolicyDecision(value.upper())
        except ValueError:
            return value
    return value


NormalizedPolicyDecision = Annotated[
    PolicyDecision,
    BeforeValidator(_normalize_policy_decision),
]


class PolicyConstraintsConfig(StrictConfigModel):
    targeted_only: bool = False
    enforce_limits: bool = False


class PolicyDecisionConfig(StrictConfigModel):
    decision: PolicyDecision
    constraints: PolicyConstraintsConfig = Field(default_factory=PolicyConstraintsConfig)

    @model_validator(mode="before")
    @classmethod
    def normalize_shorthand(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        normalized = {
            "allow": {
                "decision": PolicyDecision.ALLOW,
                "constraints": {},
            },
            "allow_targeted": {
                "decision": PolicyDecision.ALLOW,
                "constraints": {"targeted_only": True},
            },
            "allow_with_limits": {
                "decision": PolicyDecision.ALLOW,
                "constraints": {"enforce_limits": True},
            },
            "ask": {
                "decision": PolicyDecision.ASK,
                "constraints": {},
            },
            "deny": {
                "decision": PolicyDecision.DENY,
                "constraints": {},
            },
        }
        if value not in normalized:
            raise ValueError("policy decision shorthand is not recognized")
        return normalized[value]


class PurposeOperationPolicy(RootModel[dict[OperationName, PolicyDecisionConfig]]):
    model_config = ConfigDict(strict=True, frozen=True)

    @model_validator(mode="after")
    def validate_nonempty(self) -> Self:
        if not self.root:
            raise ValueError("purpose policy must define at least one operation")
        return self


class PolicyLimitsConfig(StrictConfigModel):
    search_results: int = Field(gt=0)
    map_results: int = Field(gt=0)
    crawl_pages: int = Field(gt=0)
    crawl_depth: int = Field(ge=0)
    requests_per_root_run: int = Field(gt=0)
    credits_per_root_run: float = Field(gt=0)


class CreditDisciplineConfig(StrictConfigModel):
    duplicate_in_flight: Literal["return_original"]
    cross_session_public_coalescing: bool
    cache_completed_public_reads: Literal["policy_controlled"]
    broad_crawl_without_narrow_attempt: Literal["deny"]


class WorkspacePolicyConfig(StrictConfigModel):
    schema_version: Literal[1]
    workspace: WorkspaceConfig
    service: Identifier
    default_decision: NormalizedPolicyDecision
    default_pool: Identifier
    hard_denies: list[HardDenyConfig] = Field(min_length=1)
    purposes: dict[SymbolName, PurposeOperationPolicy]
    limits: PolicyLimitsConfig
    credit_discipline: CreditDisciplineConfig

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if self.default_pool == EMERGENCY_POOL_ID:
            raise ValueError("the emergency pool cannot be selected by default")
        if not self.purposes:
            raise ValueError("workspace policy must define at least one purpose")
        rule_ids = [rule.id for rule in self.hard_denies]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("hard-deny rule IDs must be unique")
        return self
