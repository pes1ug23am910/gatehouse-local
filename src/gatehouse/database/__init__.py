"""Crash-safe SQLite persistence primitives for Gatehouse."""

from .audit import AuditBufferFullError, AuditEvent, BoundedAuditWriter
from .connection import (
    DEFAULT_BUSY_TIMEOUT_MS,
    DatabaseConfigurationError,
    DatabaseError,
    IntegrityReport,
    TransactionNestingError,
    connect_database,
    inspect_integrity,
    transaction,
)
from .migrations import (
    MIGRATIONS,
    Migration,
    MigrationDriftError,
    MigrationError,
    MigrationOrderError,
    apply_migrations,
    open_migrated_database,
)
from .recovery import AsyncCheckpointRecoveryError, RecoveryReport, recover_startup
from .repository import (
    ApprovalConsumeResult,
    ApprovalConsumeStatus,
    GatehouseRepository,
    LeaseResult,
    LeaseStatus,
    QuotaReservationResult,
    QuotaReservationStatus,
)
from .retention import (
    RetentionPolicy,
    RetentionReport,
    apply_retention,
    checkpoint_wal,
    database_footprint,
)

__all__ = [
    "ApprovalConsumeResult",
    "ApprovalConsumeStatus",
    "AsyncCheckpointRecoveryError",
    "AuditBufferFullError",
    "AuditEvent",
    "BoundedAuditWriter",
    "DEFAULT_BUSY_TIMEOUT_MS",
    "DatabaseConfigurationError",
    "DatabaseError",
    "GatehouseRepository",
    "IntegrityReport",
    "LeaseResult",
    "LeaseStatus",
    "MIGRATIONS",
    "Migration",
    "MigrationDriftError",
    "MigrationError",
    "MigrationOrderError",
    "QuotaReservationResult",
    "QuotaReservationStatus",
    "RecoveryReport",
    "RetentionPolicy",
    "RetentionReport",
    "TransactionNestingError",
    "apply_migrations",
    "apply_retention",
    "checkpoint_wal",
    "connect_database",
    "database_footprint",
    "inspect_integrity",
    "open_migrated_database",
    "recover_startup",
    "transaction",
]
