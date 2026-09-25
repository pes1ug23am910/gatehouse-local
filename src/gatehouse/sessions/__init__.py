"""Session capabilities, access-token authentication, and root-run ownership."""

from gatehouse.core.states import SessionState

from .environment import (
    LONG_LIVED_ENVIRONMENT_VARIABLES,
    PROVIDER_SECRET_VARIABLES,
    EnvironmentValidationError,
    build_child_environment,
    build_long_lived_environment,
)
from .manager import (
    AccessPrincipal,
    AccessTokenCapacityExceeded,
    BootstrapCapabilityError,
    BootstrapExchangeRateLimited,
    CrossSessionRootRun,
    InvalidAccessToken,
    IssuedAccessToken,
    LaunchedSession,
    RootRunNotFound,
    SessionManager,
    SessionUnavailable,
)
from .models import RootRunRecord, RootRunState, SessionRecord
from .persistence import (
    SessionCreationOutcomeUnresolved,
    SessionCreationRequest,
    SessionCreationRequestConflict,
    SessionPersistence,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
)
from .sqlite import SqliteSessionPersistence

__all__ = [
    "AccessPrincipal",
    "AccessTokenCapacityExceeded",
    "BootstrapCapabilityError",
    "BootstrapExchangeRateLimited",
    "CrossSessionRootRun",
    "EnvironmentValidationError",
    "InvalidAccessToken",
    "IssuedAccessToken",
    "LaunchedSession",
    "LONG_LIVED_ENVIRONMENT_VARIABLES",
    "PROVIDER_SECRET_VARIABLES",
    "RootRunNotFound",
    "RootRunRecord",
    "RootRunState",
    "SessionManager",
    "SessionCreationRequest",
    "SessionCreationOutcomeUnresolved",
    "SessionCreationRequestConflict",
    "SessionPersistence",
    "SessionRunCapacityExceeded",
    "SessionRecord",
    "SessionRunawayQuarantined",
    "SessionState",
    "SessionUnavailable",
    "SqliteSessionPersistence",
    "build_child_environment",
    "build_long_lived_environment",
]
