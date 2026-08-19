"""Named-pool routing, quota reservation, retry, and resource-affinity primitives."""

from .affinity import (
    InMemoryResourceAffinityStore,
    ResourceAffinity,
    ResourceAffinityConflictError,
    ResourceAffinityStore,
    SqliteResourceAffinityStore,
)
from .catalog import SqliteRoutingCatalog
from .leases import (
    CredentialDispatchLease,
    CredentialLeaseManager,
    CredentialLeaseRepository,
    CredentialLeaseUnavailableError,
)
from .models import (
    NamedPool,
    PoolMember,
    PoolSelectionStrategy,
    QuotaScopeSnapshot,
    QuotaScopeState,
    RouteCandidate,
    RoutingCredential,
    RoutingPlan,
)
from .quota import (
    QuotaReservation,
    QuotaReservationManager,
    QuotaReservationRepository,
    QuotaUnavailableError,
    ReservationGrant,
    ReservationState,
)
from .retry import (
    BreakerKey,
    BreakerScopeType,
    CircuitBreakerPermit,
    CircuitBreakerPolicy,
    CircuitBreakerRegistry,
    CircuitBreakerSnapshot,
    RetryAction,
    RetryDecision,
    RetryPolicy,
)
from .router import (
    AffinityUnavailableError,
    NamedPoolRouter,
    NoEligibleCredentialError,
    NoEligiblePoolError,
    RoutingError,
)

__all__ = [
    "AffinityUnavailableError",
    "BreakerKey",
    "BreakerScopeType",
    "CircuitBreakerPermit",
    "CircuitBreakerPolicy",
    "CircuitBreakerRegistry",
    "CircuitBreakerSnapshot",
    "CredentialDispatchLease",
    "CredentialLeaseManager",
    "CredentialLeaseRepository",
    "CredentialLeaseUnavailableError",
    "InMemoryResourceAffinityStore",
    "NamedPool",
    "NamedPoolRouter",
    "NoEligibleCredentialError",
    "NoEligiblePoolError",
    "PoolMember",
    "PoolSelectionStrategy",
    "QuotaReservation",
    "QuotaReservationManager",
    "QuotaReservationRepository",
    "QuotaScopeSnapshot",
    "QuotaScopeState",
    "QuotaUnavailableError",
    "ReservationGrant",
    "ReservationState",
    "ResourceAffinity",
    "ResourceAffinityConflictError",
    "ResourceAffinityStore",
    "RetryAction",
    "RetryDecision",
    "RetryPolicy",
    "RouteCandidate",
    "RoutingCredential",
    "RoutingError",
    "RoutingPlan",
    "SqliteResourceAffinityStore",
    "SqliteRoutingCatalog",
]
