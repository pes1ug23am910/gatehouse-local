"""Code-owned provider identities, operations, quota dimensions, and auth policy."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from urllib.parse import urlsplit

from gatehouse.providers.base import CredentialRole, ProviderRequest


class AuthenticationStrategy(StrEnum):
    """Secret injection strategy selected by provider code, never configuration."""

    BEARER = "BEARER"


class ProviderImplementationState(StrEnum):
    """Whether a descriptor is dispatch-capable in this build."""

    ACTIVE = "ACTIVE"
    FOUNDATION_ONLY = "FOUNDATION_ONLY"


class RequestBodyPolicy(StrEnum):
    """Whether a typed provider operation accepts a JSON object body."""

    FORBIDDEN = "FORBIDDEN"
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"


class QuotaCounterKind(StrEnum):
    """Provider-native counter semantics without unit conversion."""

    BALANCE = "BALANCE"
    USAGE = "USAGE"
    RATE_LIMIT = "RATE_LIMIT"


class ResetWindowKind(StrEnum):
    """Provider-native reset behavior for a quota dimension."""

    NONE = "NONE"
    FIXED = "FIXED"
    ROLLING = "ROLLING"
    PROVIDER_DEFINED = "PROVIDER_DEFINED"


class ProviderContractError(ValueError):
    """A request does not match the code-owned provider contract."""


@dataclass(frozen=True, slots=True)
class QuotaDimensionSpec:
    """One exact provider-native quota dimension."""

    name: str
    native_unit: str
    counter_kind: QuotaCounterKind
    reset_window_kind: ResetWindowKind

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 100:
            raise ValueError("quota dimension name is invalid")
        if not self.native_unit or len(self.native_unit) > 100:
            raise ValueError("quota dimension native unit is invalid")


@dataclass(frozen=True, slots=True)
class ProviderOperationPolicy:
    """Fixed method, path, role, and response policy for one typed operation."""

    name: str
    method: str
    path_pattern: str
    allowed_credential_roles: frozenset[CredentialRole]
    body_policy: RequestBodyPolicy
    target_url_fields: tuple[str, ...] = ()
    allowed_query_parameters: frozenset[str] = field(default_factory=frozenset)
    exact_response_numbers: bool = False
    discard_error_body: bool = False

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in {"GET", "POST", "DELETE"}:
            raise ValueError("provider operation method is unsupported")
        if not self.name or "." not in self.name:
            raise ValueError("provider operation name must be provider-qualified")
        if not self.path_pattern.startswith(r"/"):
            raise ValueError("provider operation path pattern must be relative")
        try:
            re.compile(self.path_pattern)
        except re.error:
            raise ValueError("provider operation path pattern is invalid") from None
        if not self.allowed_credential_roles:
            raise ValueError("provider operation requires at least one credential role")
        normalized_roles = frozenset(CredentialRole(role) for role in self.allowed_credential_roles)
        if any(not field_name or len(field_name) > 100 for field_name in self.target_url_fields):
            raise ValueError("provider target field is invalid")
        if any(
            not parameter or len(parameter) > 100 for parameter in self.allowed_query_parameters
        ):
            raise ValueError("provider query parameter is invalid")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "allowed_credential_roles", normalized_roles)

    def accepts_path(self, path: str) -> bool:
        return re.fullmatch(self.path_pattern, path, flags=re.ASCII) is not None


@dataclass(frozen=True, slots=True)
class ProviderDescriptor:
    """A provider boundary whose security-sensitive details are fixed in code."""

    provider_id: str
    implementation_state: ProviderImplementationState
    origin: str | None
    host: str | None
    authentication: AuthenticationStrategy | None
    operations: Mapping[str, ProviderOperationPolicy]
    quota_dimensions: tuple[QuotaDimensionSpec, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.provider_id
            or len(self.provider_id) > 64
            or not self.provider_id.isascii()
            or not all(
                character.islower() or character.isdigit() or character == "-"
                for character in self.provider_id
            )
        ):
            raise ValueError("provider identifier is invalid")
        state = ProviderImplementationState(self.implementation_state)
        active_fields = (self.origin, self.host, self.authentication)
        if state is ProviderImplementationState.ACTIVE:
            if any(value is None for value in active_fields) or not self.operations:
                raise ValueError("active provider descriptor is incomplete")
            assert self.origin is not None
            assert self.host is not None
            parsed = urlsplit(self.origin)
            if (
                parsed.scheme != "https"
                or parsed.hostname != self.host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("provider origin must be a fixed HTTPS origin")
        elif any(value is not None for value in active_fields) or self.operations:
            raise ValueError("foundation-only providers cannot dispatch operations")
        operations = dict(self.operations)
        if any(name != policy.name for name, policy in operations.items()):
            raise ValueError("provider operation registry key is inconsistent")
        prefix = f"{self.provider_id}."
        if any(not name.startswith(prefix) for name in operations):
            raise ValueError("provider operation belongs to another provider")
        dimension_names = [dimension.name for dimension in self.quota_dimensions]
        if len(dimension_names) != len(set(dimension_names)):
            raise ValueError("provider quota dimension names must be unique")
        object.__setattr__(self, "implementation_state", state)
        object.__setattr__(self, "operations", MappingProxyType(operations))

    def operation(self, name: str) -> ProviderOperationPolicy:
        try:
            return self.operations[name]
        except KeyError:
            raise ProviderContractError("provider operation is not supported") from None

    def validate_request(self, request: ProviderRequest) -> ProviderOperationPolicy:
        if self.implementation_state is not ProviderImplementationState.ACTIVE:
            raise ProviderContractError("provider dispatch is not implemented")
        if request.provider_id != self.provider_id:
            raise ProviderContractError("request belongs to a different provider")
        policy = self.operation(request.operation)
        if request.method != policy.method or not policy.accepts_path(request.path):
            raise ProviderContractError("request does not match the typed provider operation")
        if request.credential_role not in policy.allowed_credential_roles:
            raise ProviderContractError("credential role is not permitted for the operation")
        query_names = frozenset(request.query)
        if not query_names.issubset(policy.allowed_query_parameters):
            raise ProviderContractError("provider query parameter is not permitted")
        if policy.body_policy is RequestBodyPolicy.FORBIDDEN and request.json_body is not None:
            raise ProviderContractError("provider operation forbids a request body")
        if policy.body_policy is RequestBodyPolicy.REQUIRED and request.json_body is None:
            raise ProviderContractError("provider operation requires a request body")
        return policy


class ProviderRegistry:
    """Immutable provider catalog used by transport and composition boundaries."""

    def __init__(self, descriptors: Iterable[ProviderDescriptor]) -> None:
        values: dict[str, ProviderDescriptor] = {}
        for descriptor in descriptors:
            if descriptor.provider_id in values:
                raise ValueError("provider descriptor is duplicated")
            values[descriptor.provider_id] = descriptor
        if not values:
            raise ValueError("provider registry cannot be empty")
        self._descriptors = MappingProxyType(values)

    @property
    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._descriptors))

    def descriptor(self, provider_id: str) -> ProviderDescriptor:
        try:
            return self._descriptors[provider_id]
        except KeyError:
            raise ProviderContractError("provider is not registered") from None


_WORKLOAD = frozenset({CredentialRole.WORKLOAD})
_FIRECRAWL_OBSERVATION = frozenset({CredentialRole.WORKLOAD, CredentialRole.OBSERVER})

FIRECRAWL_DESCRIPTOR = ProviderDescriptor(
    provider_id="firecrawl",
    implementation_state=ProviderImplementationState.ACTIVE,
    origin="https://api.firecrawl.dev",
    host="api.firecrawl.dev",
    authentication=AuthenticationStrategy.BEARER,
    operations={
        "firecrawl.search": ProviderOperationPolicy(
            name="firecrawl.search",
            method="POST",
            path_pattern=r"/v2/search",
            allowed_credential_roles=_WORKLOAD,
            body_policy=RequestBodyPolicy.REQUIRED,
        ),
        "firecrawl.scrape": ProviderOperationPolicy(
            name="firecrawl.scrape",
            method="POST",
            path_pattern=r"/v2/scrape",
            allowed_credential_roles=_WORKLOAD,
            body_policy=RequestBodyPolicy.REQUIRED,
            target_url_fields=("url",),
        ),
        "firecrawl.map": ProviderOperationPolicy(
            name="firecrawl.map",
            method="POST",
            path_pattern=r"/v2/map",
            allowed_credential_roles=_WORKLOAD,
            body_policy=RequestBodyPolicy.REQUIRED,
            target_url_fields=("url",),
        ),
        "firecrawl.crawl.start": ProviderOperationPolicy(
            name="firecrawl.crawl.start",
            method="POST",
            path_pattern=r"/v2/crawl",
            allowed_credential_roles=_WORKLOAD,
            body_policy=RequestBodyPolicy.REQUIRED,
            target_url_fields=("url",),
        ),
        "firecrawl.crawl.status": ProviderOperationPolicy(
            name="firecrawl.crawl.status",
            method="GET",
            path_pattern=r"/v2/crawl/[A-Za-z0-9_-]{1,128}",
            allowed_credential_roles=_WORKLOAD,
            body_policy=RequestBodyPolicy.FORBIDDEN,
        ),
        "firecrawl.crawl.cancel": ProviderOperationPolicy(
            name="firecrawl.crawl.cancel",
            method="DELETE",
            path_pattern=r"/v2/crawl/[A-Za-z0-9_-]{1,128}",
            allowed_credential_roles=_WORKLOAD,
            body_policy=RequestBodyPolicy.FORBIDDEN,
        ),
        "firecrawl.account.credit_status": ProviderOperationPolicy(
            name="firecrawl.account.credit_status",
            method="GET",
            path_pattern=r"/v2/team/credit-usage",
            allowed_credential_roles=_FIRECRAWL_OBSERVATION,
            body_policy=RequestBodyPolicy.FORBIDDEN,
            exact_response_numbers=True,
            discard_error_body=True,
        ),
    },
    quota_dimensions=(
        QuotaDimensionSpec(
            name="account_credits",
            native_unit="credits",
            counter_kind=QuotaCounterKind.BALANCE,
            reset_window_kind=ResetWindowKind.PROVIDER_DEFINED,
        ),
    ),
)

FOUNDATION_PROVIDER_IDS = frozenset(
    {"firecrawl", "github", "openrouter", "gemini", "xai", "jarvislabs"}
)
DEFAULT_PROVIDER_REGISTRY = ProviderRegistry((FIRECRAWL_DESCRIPTOR,))
