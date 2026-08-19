"""Concrete, restart-safe composition for the installed Gatehouse daemon."""

from __future__ import annotations

import asyncio
import hashlib
import math
import signal
import sqlite3
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from gatehouse import __version__
from gatehouse.admin import (
    AdminAuthManager,
    ControlDaemonStatus,
    ControlLaunchAuthority,
    LocalControlService,
    SqliteApprovalAdminService,
    create_local_control_router,
    provision_control_capability,
)
from gatehouse.api import GatehouseAgentOperations
from gatehouse.config import ClientProfileConfig
from gatehouse.core.admission import RuntimeAdmissionController
from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock
from gatehouse.core.ids import ClientId, RootRunId, SessionId, WorkspaceId
from gatehouse.credentials import (
    DpapiCurrentUserKeyStore,
    InMemoryKeyStore,
    derive_installation_key,
    load_or_create_installation_key,
)
from gatehouse.credentials.installation import DataProtector
from gatehouse.database import (
    GatehouseRepository,
    checkpoint_wal,
    inspect_integrity,
    open_migrated_database,
    recover_startup,
    transaction,
)
from gatehouse.documentation import DocumentationService
from gatehouse.feedback import FeedbackService
from gatehouse.fingerprint import FingerprintService, RunawayDetector, SingleFlightCoordinator
from gatehouse.invocations import (
    DefaultFingerprintGateway,
    DefaultSensitiveInspector,
    FirecrawlOperationGateway,
    InvocationCoordinator,
    InvocationRequest,
    InvocationSession,
    SqliteBudgetGateway,
    SqliteInvocationRepository,
)
from gatehouse.jobs import (
    CoordinatorJobObservationGateway,
    JobSupervisor,
    SqliteJobSessionResolver,
    SqliteJobSettlementGateway,
    SqliteJobStore,
)
from gatehouse.policy import (
    ClientClass,
    Decision,
    PolicyContext,
    PolicyEngine,
    PolicyResult,
    WorkspacePolicy,
)
from gatehouse.providers import (
    HttpxProviderTransport,
    ProviderRequest,
    ProviderResponse,
    ScriptedProviderTransport,
)
from gatehouse.routing import (
    CircuitBreakerRegistry,
    CredentialLeaseManager,
    QuotaReservationManager,
    ResourceAffinityStore,
    SqliteResourceAffinityStore,
    SqliteRoutingCatalog,
)
from gatehouse.scheduler import (
    BoundedFairScheduler,
    PriorityClass,
    SchedulerLimits,
    ServiceLimits,
)
from gatehouse.sessions import InvalidAccessToken, SessionManager, SqliteSessionPersistence

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
    InstallationDaemonLease,
    InstallationDaemonLeaseFactory,
)
from .provider import synchronize_scripted_routes, validate_live_route_credentials
from .runtime import DaemonApplications, DaemonSettings, create_daemon_applications, serve

DEFAULT_SCHEDULER_PUMP_INTERVAL_MS = 250
DEFAULT_DRAIN_TIMEOUT_MS = 5_000
_DRAIN_POLL_INTERVAL_SECONDS = 0.01


class _ClosableProviderTransport(Protocol):
    async def send(self, request: ProviderRequest) -> ProviderResponse: ...

    async def aclose(self) -> None: ...


class _PumpableScheduler(Protocol):
    async def pump(self) -> int: ...


type ServeApplications = Callable[
    [DaemonApplications, DaemonSettings, asyncio.Event], Awaitable[None]
]


class _ListenerLifecycleSignal(asyncio.Event):
    """Route listener-facing ``set`` to drain while ``wait`` observes final stop."""

    def __init__(
        self,
        *,
        drain_request: asyncio.Event,
        listener_stop: asyncio.Event,
    ) -> None:
        super().__init__()
        self._drain_request = drain_request
        self._listener_stop = listener_stop

    def is_set(self) -> bool:
        return self._listener_stop.is_set()

    def set(self) -> None:
        self._drain_request.set()

    def clear(self) -> None:
        self._listener_stop.clear()

    async def wait(self) -> Literal[True]:
        await self._listener_stop.wait()
        return True


@dataclass(frozen=True, slots=True)
class InstallationStatePaths:
    """Stable installation-local paths shared with same-user clients."""

    installation_key: Path
    control_capability: Path
    control_verifier: Path
    credentials: Path
    daemon_lease: Path


def installation_state_paths(database_path: str | Path) -> InstallationStatePaths:
    root = Path(database_path).resolve().parent
    return InstallationStatePaths(
        installation_key=root / "installation-key.dpapi",
        control_capability=root / "control-capability.dpapi",
        control_verifier=root / "control-capability.verifier",
        credentials=root / "credentials",
        daemon_lease=root / "gatehoused.lock",
    )


def _resolved_path(path: str | Path) -> Path:
    return Path(path).resolve()


class _ConfiguredPolicyGateway:
    def __init__(self, policies: Mapping[str, WorkspacePolicy]) -> None:
        engines: dict[str, PolicyEngine] = {}
        for workspace_id, policy in policies.items():
            engines[workspace_id] = PolicyEngine(policy)
        self._engines = MappingProxyType(engines)

    def evaluate(self, context: PolicyContext) -> PolicyResult:
        engine = self._engines.get(context.workspace_id)
        if engine is not None:
            return engine.evaluate(context)
        return PolicyResult(
            decision=Decision.DENY,
            rule_id="workspace-unconfigured",
            reason_code="workspace_not_authorized",
            policy_id="unconfigured",
            policy_version="unavailable",
        )


class _CoordinatorSessionGateway:
    """Rebuild coordinator authority from the same durable session/config facts."""

    def __init__(
        self,
        *,
        sessions: SessionManager,
        synchronized: SynchronizedConfiguration,
    ) -> None:
        self._sessions = sessions
        self._clients = synchronized.clients_by_id
        self._policies = synchronized.policies_by_workspace_id

    async def authenticate(self, request: InvocationRequest) -> InvocationSession:
        token = request.access_token
        if token is None:
            raise InvalidAccessToken("invocation access token is required")
        principal = await self._sessions.authenticate(token)
        root_run = await self._sessions.resolve_root_run(
            access_token=token,
            root_run_id=str(request.root_run_id),
        )
        if principal.workspace_id is None:
            raise InvalidAccessToken("an attributed workspace is required")
        try:
            session_id = SessionId(principal.session_id)
            client_id = ClientId(principal.client_id)
            workspace_id = WorkspaceId(principal.workspace_id)
        except (TypeError, ValueError) as error:
            raise InvalidAccessToken("session authority is invalid") from error
        profile = self._clients.get(str(client_id))
        policy = self._policies.get(str(workspace_id))
        if (
            profile is None
            or policy is None
            or policy.version != principal.policy_version
            or root_run.session_id != str(session_id)
        ):
            raise InvalidAccessToken("session configuration is unavailable")
        try:
            priority = PriorityClass(profile.client.default_priority.upper())
        except ValueError as error:
            raise InvalidAccessToken("session priority is invalid") from error
        request_ceiling = root_run.budget.get("requests", policy.maximum_requests_per_root_run)
        credit_ceiling = root_run.budget.get(
            "credits", math.floor(policy.maximum_credits_per_root_run)
        )
        return InvocationSession(
            session_id=session_id,
            client_id=client_id,
            root_run_id=RootRunId(root_run.root_run_id),
            workspace_id=workspace_id,
            client_class=(
                ClientClass.UNATTENDED if profile.client.unattended else ClientClass.INTERACTIVE
            ),
            allowed_capabilities=frozenset(profile.capabilities.allow),
            pool_bindings=profile.pools.bindings,
            request_count_remaining=max(0, request_ceiling - root_run.consumed.get("requests", 0)),
            credit_budget_remaining_units=max(
                0, credit_ceiling - root_run.consumed.get("credits", 0)
            ),
            priority=priority,
        )


class _ControlHealthAdapter:
    def __init__(self, health: RuntimeHealthProbe) -> None:
        self._health = health

    async def readiness(self) -> ControlDaemonStatus:
        snapshot = await self._health.readiness()
        return ControlDaemonStatus(**snapshot.model_dump(mode="python"))


def _policy_version(synchronized: SynchronizedConfiguration) -> str:
    versions = sorted(policy.version for policy in synchronized.policies_by_workspace_id.values())
    if not versions:
        return "unconfigured"
    if len(versions) == 1:
        return versions[0]
    digest = hashlib.sha256("\x00".join(versions).encode("ascii")).hexdigest()[:16]
    return f"set-{digest}"


def _daemon_settings(configuration: RuntimeConfiguration) -> DaemonSettings:
    agent = configuration.main.server.agent
    admin = configuration.main.server.admin
    if agent.host != "127.0.0.1" or admin.host != "127.0.0.1":
        raise ValueError("Gatehouse v1 listeners require IPv4 loopback")
    return DaemonSettings(agent_port=agent.port, admin_port=admin.port)


def _scheduler_limits(configuration: RuntimeConfiguration) -> SchedulerLimits:
    configured = configuration.main.concurrency
    services = {
        service: ServiceLimits(
            maximum_in_flight=limits.maximum_in_flight,
            maximum_queued=(limits.interactive_queue_depth + limits.system_reserved_queue_depth),
            reserved_system_in_flight=limits.watcher_reserved_in_flight,
            reserved_system_queue=limits.system_reserved_queue_depth,
            maximum_per_quota_scope=limits.maximum_per_quota_scope,
        )
        for service, limits in configured.service_limits.items()
    }
    return SchedulerLimits(
        global_maximum_in_flight=configured.global_in_flight,
        global_maximum_queued=configured.global_queue_depth,
        per_session_maximum_in_flight=configured.per_session.maximum_in_flight,
        per_session_maximum_queued=configured.per_session.maximum_queued,
        services=services,
        reserved_system_in_flight=min(
            configured.global_in_flight,
            sum(item.reserved_system_in_flight for item in services.values()),
        ),
        reserved_system_queue=min(
            configured.global_queue_depth,
            sum(item.reserved_system_queue for item in services.values()),
        ),
    )


def _scripted_pool_aliases(configuration: RuntimeConfiguration) -> tuple[str, ...]:
    aliases = {
        profile.pools.bindings["firecrawl"]
        for profile in configuration.clients
        if "firecrawl" in profile.pools.bindings
    }
    aliases.update(
        policy.default_pool for policy in configuration.policies if policy.service == "firecrawl"
    )
    return tuple(sorted(aliases))


def _control_authorities(
    configuration: RuntimeConfiguration,
    synchronized: SynchronizedConfiguration,
) -> Mapping[tuple[str, str], ControlLaunchAuthority]:
    result: dict[tuple[str, str], ControlLaunchAuthority] = {}
    profiles_by_name: dict[str, ClientProfileConfig] = {
        profile.client.id: profile for profile in configuration.clients
    }
    for client_name, client_id in synchronized.client_ids_by_name.items():
        profile = profiles_by_name[client_name]
        for workspace_name, workspace_id in synchronized.workspace_ids_by_name.items():
            policy = synchronized.policies_by_workspace_id[workspace_id]
            if policy.service not in profile.pools.bindings:
                continue
            result[(client_name, workspace_name)] = ControlLaunchAuthority(
                client_name=client_name,
                workspace_name=workspace_name,
                client_id=ClientId(client_id),
                workspace_id=WorkspaceId(workspace_id),
                unattended=profile.client.unattended,
                policy_version=policy.version,
                absolute_ttl_ms=(
                    configuration.main.sessions.unattended_absolute_ttl
                    if profile.client.unattended
                    else configuration.main.sessions.interactive_absolute_ttl
                ),
                budget={
                    "requests": policy.maximum_requests_per_root_run,
                    "credits": math.floor(policy.maximum_credits_per_root_run),
                },
            )
    return MappingProxyType(result)


async def _provider_transport(
    configuration: RuntimeConfiguration,
    *,
    config_path: Path,
    connection: sqlite3.Connection,
    state_paths: InstallationStatePaths,
    clock: UtcMsClock,
) -> _ClosableProviderTransport:
    provider = configuration.main.provider
    if provider.mode == "disabled":
        return HttpxProviderTransport(
            key_store=InMemoryKeyStore(),
            network_enabled=False,
        )
    if provider.mode == "scripted":
        aliases = _scripted_pool_aliases(configuration)
        synchronize_scripted_routes(connection, pool_aliases=aliases, clock=clock)
        assert provider.scripted_responses_path is not None
        manifest = Path(provider.scripted_responses_path)
        if not manifest.is_absolute():
            manifest = config_path.parent / manifest
        return ScriptedProviderTransport.from_path(manifest)
    # Pydantic validation requires both explicit live mode and network_enabled=true.
    if provider.mode != "live" or not provider.network_enabled:
        raise RuntimeError("live provider networking was not explicitly enabled")
    key_store = DpapiCurrentUserKeyStore(state_paths.credentials)
    await validate_live_route_credentials(
        connection,
        key_store=key_store,
    )
    return HttpxProviderTransport(
        key_store=key_store,
        network_enabled=True,
    )


def _set_system_state(
    connection: sqlite3.Connection,
    state: str,
    *,
    now_ms: int,
    clean: bool = False,
) -> None:
    with transaction(connection, "IMMEDIATE"):
        if clean:
            connection.execute(
                """
                UPDATE system_state
                   SET daemon_state = ?, last_clean_shutdown_at_ms = ?
                 WHERE singleton_id = 1
                """,
                (state, now_ms),
            )
        else:
            connection.execute(
                "UPDATE system_state SET daemon_state = ? WHERE singleton_id = 1",
                (state,),
            )


@dataclass(slots=True)
class StockDaemon:
    applications: DaemonApplications
    settings: DaemonSettings
    shutdown_event: asyncio.Event
    scheduler: BoundedFairScheduler
    job_supervisor: JobSupervisor
    admission: RuntimeAdmissionController
    health: RuntimeHealthProbe
    connection: sqlite3.Connection
    transport: _ClosableProviderTransport
    _clock: UtcMsClock
    _lease: InstallationDaemonLease
    _operational_status: str
    _operational_degraded_components: tuple[str, ...] = ()
    _closed: bool = False
    _failed: bool = False

    def mark_recovery_complete(self) -> None:
        if self._closed or self._failed:
            return
        if self.health.status != "RECOVERING":
            raise RuntimeError("daemon recovery can only complete once")
        _set_system_state(
            self.connection,
            self._operational_status,
            now_ms=self._clock.now_ms(),
        )
        self.admission.begin_accepting()
        self.health.transition(
            self._operational_status,
            degraded_components=self._operational_degraded_components,
        )

    def mark_draining(self) -> None:
        if self._closed or self._failed or self.health.status in {"DRAINING", "STOPPED"}:
            return
        self.admission.begin_draining()
        self.health.transition("DRAINING")
        _set_system_state(
            self.connection,
            "DRAINING",
            now_ms=self._clock.now_ms(),
        )

    def mark_failed_closed(self) -> None:
        if self._closed or self._failed:
            return
        self._failed = True
        self.admission.fail_closed()
        self.health.transition(
            "FAILED_CLOSED",
            degraded_components=("runtime_task",),
        )
        _set_system_state(
            self.connection,
            "FAILED_CLOSED",
            now_ms=self._clock.now_ms(),
        )

    async def close(self) -> None:
        if self._closed:
            return
        try:
            self.mark_draining()
            self.shutdown_event.set()
            await self.transport.aclose()
            if not self._failed:
                self.health.transition("STOPPED")
                _set_system_state(
                    self.connection,
                    "STOPPED",
                    now_ms=self._clock.now_ms(),
                    clean=True,
                )
            checkpoint_wal(self.connection, mode="TRUNCATE")
        finally:
            try:
                self.admission.stop()
            finally:
                try:
                    self.connection.close()
                finally:
                    try:
                        self._lease.release()
                    finally:
                        self._closed = True


async def compose_stock_daemon(
    configuration: RuntimeConfiguration,
    *,
    config_path: str | Path,
    clock: UtcMsClock = SYSTEM_UTC_CLOCK,
    protector: DataProtector | None = None,
    lease_factory: InstallationDaemonLeaseFactory = (DEFAULT_INSTALLATION_DAEMON_LEASE_FACTORY),
) -> StockDaemon:
    """Compose all stock adapters after one migration/integrity/recovery sequence."""

    path = _resolved_path(config_path)
    settings = _daemon_settings(configuration)
    connection: sqlite3.Connection | None = None
    provider_transport: _ClosableProviderTransport | None = None
    daemon_lease: InstallationDaemonLease | None = None
    try:
        state_paths = installation_state_paths(configuration.main.database.path)
        daemon_lease = lease_factory.acquire(state_paths.daemon_lease)
        connection = open_migrated_database(
            configuration.main.database.path,
            busy_timeout_ms=configuration.main.database.busy_timeout_ms,
        )
        integrity = inspect_integrity(connection, full=False)
        if not integrity.ok:
            raise RuntimeError("database integrity verification failed")
        started_at_ms = clock.now_ms()
        recovery = recover_startup(connection, now_ms=started_at_ms)
        synchronized = SqliteConfigurationCatalog(connection, clock=clock).synchronize(
            clients=configuration.clients,
            policies=configuration.policies,
        )
        master_key = load_or_create_installation_key(
            state_paths.installation_key,
            protector=protector,
        )
        control_verifier = provision_control_capability(
            protected_path=state_paths.control_capability,
            verifier_path=state_paths.control_verifier,
            protector=protector,
        )
        session_persistence = SqliteSessionPersistence(
            connection,
            recovered_token_epoch=recovery.token_epoch,
        )
        sessions = await SessionManager.start(
            persistence=session_persistence,
            verifier_key=derive_installation_key(master_key, "session-verifier"),
            now_ms=clock.now_ms,
            access_token_ttl_ms=configuration.main.sessions.access_token_ttl,
            reconnect_grace_ms=configuration.main.sessions.reconnect_grace,
            stale_after_ms=configuration.main.sessions.stale_after,
            maximum_access_tokens=configuration.main.concurrency.maximum_connected_clients,
        )
        health = RuntimeHealthProbe(
            version=__version__,
            schema_version=integrity.schema_version,
            policy_version=_policy_version(synchronized),
            now_ms=clock.now_ms,
            started_at_ms=started_at_ms,
        )
        admin_auth = AdminAuthManager(
            verifier_key=derive_installation_key(master_key, "admin-verifier"),
            now_ms=clock.now_ms,
        )
        approval_admin = SqliteApprovalAdminService(
            connection,
            action_token_key=derive_installation_key(master_key, "approval-action"),
            now_ms=clock.now_ms,
            approval_ttl_ms=configuration.main.approvals.default_ttl,
        )
        provider_transport = await _provider_transport(
            configuration,
            config_path=path,
            connection=connection,
            state_paths=state_paths,
            clock=clock,
        )
        breakers = CircuitBreakerRegistry()
        routing = SqliteRoutingCatalog(connection, circuit_breakers=breakers)
        if (
            configuration.main.provider.mode != "disabled"
            and routing.validate(now_ms=clock.now_ms()) <= 0
        ):
            raise RuntimeError("provider mode has no valid routing pools")
        repository = GatehouseRepository(connection)
        affinities: ResourceAffinityStore = SqliteResourceAffinityStore(connection)
        scheduler = BoundedFairScheduler(
            limits=_scheduler_limits(configuration),
            now_ms=clock.now_ms,
        )
        jobs = SqliteJobStore(connection)
        await jobs.recover_orphaned_resources(
            maximum_runtime_ms_by_client_id={
                client_id: int(profile.client.maximum_run_duration)
                for client_id, profile in synchronized.clients_by_id.items()
            },
            now_ms=clock.now_ms(),
        )
        jobs.validate_startup_integrity(
            supported_operation_resource_types={"firecrawl.crawl.start": "crawl"}
        )
        budgets = SqliteBudgetGateway(connection, now_ms=clock.now_ms)
        coordinator = InvocationCoordinator(
            clock=clock,
            sessions=_CoordinatorSessionGateway(
                sessions=sessions,
                synchronized=synchronized,
            ),
            operations=FirecrawlOperationGateway(),
            fingerprints=DefaultFingerprintGateway(
                FingerprintService(derive_installation_key(master_key, "request-fingerprint"))
            ),
            sensitive=DefaultSensitiveInspector(),
            policy=_ConfiguredPolicyGateway(synchronized.policies_by_workspace_id),
            approvals=approval_admin,
            budgets=budgets,
            router=routing,
            quota=QuotaReservationManager(repository),
            scheduler=scheduler,
            credential_leases=CredentialLeaseManager(repository),
            repository=SqliteInvocationRepository(connection),
            transport=provider_transport,
            affinities=affinities,
            circuit_breakers=breakers,
            singleflight=SingleFlightCoordinator(
                maximum_groups=configuration.main.concurrency.global_queue_depth,
                maximum_waiters_per_group=(
                    configuration.main.concurrency.per_session.maximum_queued
                ),
            ),
            runaway=RunawayDetector(
                threshold=configuration.main.runaway_detection.identical_requests,
                window_ms=configuration.main.runaway_detection.window,
                cooldown_ms=configuration.main.runaway_detection.cooldown,
            ),
        )
        job_supervisor = JobSupervisor(
            store=jobs,
            gateway=CoordinatorJobObservationGateway(
                coordinator=coordinator,
                sessions=SqliteJobSessionResolver(
                    connection,
                    client_profiles=synchronized.clients_by_id,
                ),
                clock=clock,
            ),
            settlements=SqliteJobSettlementGateway(
                connection,
                quota=repository,
                budgets=budgets,
                clock=clock,
            ),
            clock=clock,
        )
        agent_operations = GatehouseAgentOperations(
            coordinator=coordinator,
            root_runs=session_persistence,
            client_profiles=synchronized.clients_by_id,
            workspace_policies=synchronized.policies_by_workspace_id,
            jobs=jobs,
            affinities=affinities,
            documentation=DocumentationService(connection),
            feedback=FeedbackService(connection),
            clock=clock,
        )
        admission = RuntimeAdmissionController()
        applications = create_daemon_applications(
            sessions=sessions,
            operations=agent_operations,
            health=health,
            admin_auth=admin_auth,
            admin_backend=approval_admin,
            now_ms=clock.now_ms,
            settings=settings,
            session_heartbeat_interval_ms=configuration.main.sessions.heartbeat_interval,
            admission=admission,
        )
        shutdown_event = asyncio.Event()
        daemon = StockDaemon(
            applications=applications,
            settings=settings,
            shutdown_event=shutdown_event,
            scheduler=scheduler,
            job_supervisor=job_supervisor,
            admission=admission,
            health=health,
            connection=connection,
            transport=provider_transport,
            _clock=clock,
            _lease=daemon_lease,
            _operational_status=(
                "DEGRADED_NO_PROVIDER"
                if configuration.main.provider.mode == "disabled"
                else "READY"
            ),
            _operational_degraded_components=(
                ("provider_network",) if configuration.main.provider.mode == "disabled" else ()
            ),
        )
        control = LocalControlService(
            sessions=sessions,
            admin_auth=admin_auth,
            health=_ControlHealthAdapter(health),
            launch_authorities=_control_authorities(configuration, synchronized),
            shutdown=shutdown_event,
            mark_draining=daemon.mark_draining,
            admission=admission,
        )
        applications.admin.include_router(
            create_local_control_router(
                capability=control_verifier,
                service=control,
            )
        )
        return daemon
    except BaseException:
        try:
            if provider_transport is not None:
                with suppress(BaseException):
                    await provider_transport.aclose()
        finally:
            try:
                if connection is not None:
                    with suppress(Exception):
                        _set_system_state(
                            connection,
                            "FAILED_CLOSED",
                            now_ms=clock.now_ms(),
                        )
                    with suppress(Exception):
                        checkpoint_wal(connection, mode="TRUNCATE")
                    with suppress(Exception):
                        connection.close()
            finally:
                if daemon_lease is not None:
                    with suppress(Exception):
                        daemon_lease.release()
        raise


async def pump_scheduler_until_shutdown(
    scheduler: _PumpableScheduler,
    shutdown_event: asyncio.Event,
    *,
    interval_ms: int = DEFAULT_SCHEDULER_PUMP_INTERVAL_MS,
) -> None:
    """Own the daemon's sole periodic scheduler expiry/dispatch pump."""

    if isinstance(interval_ms, bool) or not 10 <= interval_ms <= 10_000:
        raise ValueError("scheduler pump interval is outside its bound")
    while not shutdown_event.is_set():
        try:
            await asyncio.wait_for(
                shutdown_event.wait(),
                timeout=interval_ms / 1_000,
            )
        except TimeoutError:
            await scheduler.pump()


async def _default_serve(
    applications: DaemonApplications,
    settings: DaemonSettings,
    shutdown_event: asyncio.Event,
) -> None:
    await serve(applications, settings, shutdown_event=shutdown_event)


async def _serve_composed(
    daemon: StockDaemon,
    *,
    serve_applications: ServeApplications,
    scheduler_pump_interval_ms: int,
    drain_timeout_ms: int,
) -> None:
    if isinstance(drain_timeout_ms, bool) or not 10 <= drain_timeout_ms <= 60_000:
        raise ValueError("daemon drain timeout is outside its bound")

    # No externally visible READY state is possible until one complete durable
    # supervisor pass has reconciled every job that is locally due at startup.
    await daemon.job_supervisor.run_once()
    if daemon.shutdown_event.is_set():
        daemon.mark_draining()
        return
    daemon.mark_recovery_complete()

    runtime_stop = asyncio.Event()
    supervisor_stop = asyncio.Event()
    listener_signal = _ListenerLifecycleSignal(
        drain_request=daemon.shutdown_event,
        listener_stop=runtime_stop,
    )

    async def invoke_serve() -> None:
        await serve_applications(
            daemon.applications,
            daemon.settings,
            listener_signal,
        )

    serving: asyncio.Task[None] = asyncio.create_task(
        invoke_serve(),
        name="gatehouse-loopback-listeners",
    )
    pumping: asyncio.Task[None] = asyncio.create_task(
        pump_scheduler_until_shutdown(
            daemon.scheduler,
            runtime_stop,
            interval_ms=scheduler_pump_interval_ms,
        ),
        name="gatehouse-scheduler-pump",
    )
    supervising: asyncio.Task[None] = asyncio.create_task(
        daemon.job_supervisor.run(supervisor_stop),
        name="gatehouse-job-supervisor",
    )
    drain_requested: asyncio.Task[bool] = asyncio.create_task(
        daemon.shutdown_event.wait(),
        name="gatehouse-drain-request",
    )
    required = (serving, pumping, supervising)
    cancelled_by_lifecycle: set[asyncio.Task[None]] = set()
    failure: BaseException | None = None
    deadline: float | None = None

    def completed_failure(
        task: asyncio.Task[None],
        *,
        clean_exit_allowed: bool,
    ) -> BaseException | None:
        if not task.done():
            return None
        if task.cancelled():
            return asyncio.CancelledError("required daemon runtime task was cancelled")
        exception = task.exception()
        if exception is not None:
            return exception
        if not clean_exit_allowed:
            return RuntimeError("a required daemon runtime task exited unexpectedly")
        return None

    def remaining_seconds() -> float:
        assert deadline is not None
        return max(0.0, deadline - asyncio.get_running_loop().time())

    try:
        done, _ = await asyncio.wait(
            {*required, drain_requested},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not daemon.shutdown_event.is_set():
            completed = next(task for task in required if task in done)
            failure = completed_failure(completed, clean_exit_allowed=False)
            assert failure is not None
            daemon.mark_failed_closed()
            daemon.shutdown_event.set()
            raise RuntimeError("a required daemon runtime task failed") from failure

        daemon.mark_draining()
        deadline = asyncio.get_running_loop().time() + drain_timeout_ms / 1_000

        # A test/application listener may return immediately after requesting
        # drain.  That clean exit is acceptable; faults and cancellations are not.
        for task in required:
            if task not in done:
                continue
            candidate = completed_failure(
                task,
                clean_exit_allowed=task is serving,
            )
            if candidate is not None:
                failure = candidate
                break

        if failure is None:
            supervisor_stop.set()
            try:
                await asyncio.wait_for(
                    asyncio.shield(supervising),
                    timeout=remaining_seconds(),
                )
            except TimeoutError:
                pass
            except BaseException as error:
                failure = error

        # Once the periodic loop has finished, make one final, non-overlapping
        # reconciliation pass for cancellation intent or due work that arrived
        # while admission was closing.
        if failure is None and supervising.done() and not supervising.cancelled():
            supervisor_error = supervising.exception()
            if supervisor_error is not None:
                failure = supervisor_error
            elif remaining_seconds() > 0:
                try:
                    await asyncio.wait_for(
                        daemon.job_supervisor.run_once(),
                        timeout=remaining_seconds(),
                    )
                except TimeoutError:
                    pass
                except BaseException as error:
                    failure = error

        # Existing queued/in-flight provider work keeps the scheduler pump and
        # listeners alive, but never extends shutdown beyond the declared bound.
        while failure is None and remaining_seconds() > 0:
            serving_error = completed_failure(serving, clean_exit_allowed=True)
            pumping_error = completed_failure(pumping, clean_exit_allowed=False)
            if serving_error is not None or pumping_error is not None:
                failure = serving_error or pumping_error
                break
            await daemon.scheduler.pump()
            snapshot = await daemon.scheduler.snapshot()
            if snapshot.queued_total == 0 and snapshot.running_total == 0:
                break
            await asyncio.sleep(min(_DRAIN_POLL_INTERVAL_SECONDS, remaining_seconds()))
    finally:
        runtime_stop.set()
        supervisor_stop.set()
        drain_requested.cancel()
        if deadline is None:
            deadline = asyncio.get_running_loop().time() + drain_timeout_ms / 1_000
        pending = {task for task in required if not task.done()}
        if pending and remaining_seconds() > 0:
            _, pending = await asyncio.wait(
                pending,
                timeout=remaining_seconds(),
            )
        for task in pending:
            cancelled_by_lifecycle.add(task)
            task.cancel()
        results = await asyncio.gather(*required, return_exceptions=True)
        await asyncio.gather(drain_requested, return_exceptions=True)

        if failure is None:
            for task, result in zip(required, results, strict=True):
                if not isinstance(result, BaseException):
                    continue
                if isinstance(result, asyncio.CancelledError) and task in cancelled_by_lifecycle:
                    continue
                failure = result
                break
        if failure is not None:
            daemon.mark_failed_closed()
            raise RuntimeError("a required daemon runtime task failed") from failure


def _health_only_app(health: RuntimeHealthProbe, *, title: str) -> FastAPI:
    app = FastAPI(title=title, docs_url=None, redoc_url=None)

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        snapshot = await health.readiness()
        return JSONResponse(
            status_code=503,
            content=snapshot.model_dump(mode="json", exclude={"ready"}),
        )

    return app


@contextmanager
def _coordinated_signals(shutdown_event: asyncio.Event) -> Iterator[None]:
    loop = asyncio.get_running_loop()
    installed_loop: list[signal.Signals] = []
    installed_fallback: dict[signal.Signals, Any] = {}

    def request_shutdown(_signum: int | None = None, _frame: object = None) -> None:
        loop.call_soon_threadsafe(shutdown_event.set)

    for item in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(item, request_shutdown)
        except (NotImplementedError, RuntimeError):
            try:
                installed_fallback[item] = signal.getsignal(item)
                signal.signal(item, request_shutdown)
            except (OSError, ValueError):
                installed_fallback.pop(item, None)
        else:
            installed_loop.append(item)
    try:
        yield
    finally:
        for item in installed_loop:
            loop.remove_signal_handler(item)
        for item, previous in installed_fallback.items():
            signal.signal(item, previous)


async def run_stock_daemon(
    config_path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    clock: UtcMsClock = SYSTEM_UTC_CLOCK,
    protector: DataProtector | None = None,
    serve_applications: ServeApplications = _default_serve,
    scheduler_pump_interval_ms: int = DEFAULT_SCHEDULER_PUMP_INTERVAL_MS,
    drain_timeout_ms: int = DEFAULT_DRAIN_TIMEOUT_MS,
    install_signal_handlers: bool = True,
    lease_factory: InstallationDaemonLeaseFactory = (DEFAULT_INSTALLATION_DAEMON_LEASE_FACTORY),
) -> int:
    """Load, compose, serve, and cleanly stop the installed daemon."""

    configuration = load_runtime_configuration(config_path, environment=environment)
    settings = _daemon_settings(configuration)
    try:
        daemon = await compose_stock_daemon(
            configuration,
            config_path=config_path,
            clock=clock,
            protector=protector,
            lease_factory=lease_factory,
        )
    except DaemonAlreadyRunningError:
        # The owning daemon already exposes health. Starting even health-only
        # listeners here would violate installation-wide single ownership.
        return 1
    except Exception:
        health = RuntimeHealthProbe(
            version=__version__,
            schema_version=0,
            policy_version="unavailable",
            now_ms=clock.now_ms,
            started_at_ms=clock.now_ms(),
        )
        health.transition(
            "FAILED_CLOSED",
            degraded_components=("runtime_composition",),
        )
        applications = DaemonApplications(
            agent=_health_only_app(health, title="Gatehouse Agent Health"),
            admin=_health_only_app(health, title="Gatehouse Admin Health"),
        )
        shutdown_event = asyncio.Event()
        context = _coordinated_signals(shutdown_event) if install_signal_handlers else nullcontext()
        with context:
            await serve_applications(applications, settings, shutdown_event)
        return 1

    context = (
        _coordinated_signals(daemon.shutdown_event) if install_signal_handlers else nullcontext()
    )
    try:
        with context:
            try:
                await _serve_composed(
                    daemon,
                    serve_applications=serve_applications,
                    scheduler_pump_interval_ms=scheduler_pump_interval_ms,
                    drain_timeout_ms=drain_timeout_ms,
                )
            except Exception:
                daemon.mark_failed_closed()
                return 1
        return 0
    finally:
        await daemon.close()
