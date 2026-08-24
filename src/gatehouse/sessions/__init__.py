"""Session capabilities, access-token authentication, and root-run ownership."""

from gatehouse.core.states import SessionState

from .environment import PROVIDER_SECRET_VARIABLES, build_child_environment
from .manager import (
    AccessPrincipal,
    AccessTokenCapacityExceeded,
    BootstrapCapabilityError,
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
    SessionPersistence,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
)
from .sqlite import SqliteSessionPersistence

__all__ = [
    "AccessPrincipal",
    "AccessTokenCapacityExceeded",
    "BootstrapCapabilityError",
    "CrossSessionRootRun",
    "InvalidAccessToken",
    "IssuedAccessToken",
    "LaunchedSession",
    "PROVIDER_SECRET_VARIABLES",
    "RootRunNotFound",
    "RootRunRecord",
    "RootRunState",
    "SessionManager",
    "SessionPersistence",
    "SessionRunCapacityExceeded",
    "SessionRecord",
    "SessionRunawayQuarantined",
    "SessionState",
    "SessionUnavailable",
    "SqliteSessionPersistence",
    "build_child_environment",
]
