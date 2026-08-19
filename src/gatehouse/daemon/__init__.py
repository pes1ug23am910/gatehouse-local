"""Daemon application composition and loopback serving."""

from .composition import (
    DEFAULT_DRAIN_TIMEOUT_MS,
    DEFAULT_SCHEDULER_PUMP_INTERVAL_MS,
    InstallationStatePaths,
    StockDaemon,
    compose_stock_daemon,
    installation_state_paths,
    pump_scheduler_until_shutdown,
    run_stock_daemon,
)
from .configuration import (
    RuntimeConfiguration,
    SqliteConfigurationCatalog,
    SynchronizedConfiguration,
    load_runtime_configuration,
)
from .health import RuntimeHealthProbe
from .lease import (
    DEFAULT_INSTALLATION_DAEMON_LEASE_FACTORY,
    DaemonAlreadyRunningError,
    FileInstallationDaemonLeaseFactory,
    InstallationDaemonLease,
    InstallationDaemonLeaseFactory,
)
from .provider import ScriptedRouteAuthority, synchronize_scripted_routes
from .runtime import (
    DaemonApplications,
    DaemonSettings,
    create_daemon_applications,
    serve,
)

__all__ = [
    "DaemonApplications",
    "DaemonAlreadyRunningError",
    "DaemonSettings",
    "DEFAULT_DRAIN_TIMEOUT_MS",
    "DEFAULT_INSTALLATION_DAEMON_LEASE_FACTORY",
    "DEFAULT_SCHEDULER_PUMP_INTERVAL_MS",
    "InstallationStatePaths",
    "FileInstallationDaemonLeaseFactory",
    "InstallationDaemonLease",
    "InstallationDaemonLeaseFactory",
    "RuntimeHealthProbe",
    "ScriptedRouteAuthority",
    "synchronize_scripted_routes",
    "RuntimeConfiguration",
    "SqliteConfigurationCatalog",
    "StockDaemon",
    "SynchronizedConfiguration",
    "create_daemon_applications",
    "compose_stock_daemon",
    "installation_state_paths",
    "load_runtime_configuration",
    "pump_scheduler_until_shutdown",
    "run_stock_daemon",
    "serve",
]
