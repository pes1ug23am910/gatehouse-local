"""Composition and serving primitives for the two loopback HTTP realms."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

import uvicorn
from fastapi import FastAPI

from gatehouse.admin import AdminAuthManager, AdminBackend
from gatehouse.admin.audit_view import SqliteAuditView
from gatehouse.api import (
    AgentOperations,
    HealthProbe,
    SessionAuthority,
    create_admin_app,
    create_agent_app,
)
from gatehouse.api.agent import AgentAdmission
from gatehouse.database.lifecycle_diagnostics import LifecycleJournal


@dataclass(frozen=True, slots=True)
class DaemonSettings:
    agent_port: int = 47_621
    admin_port: int = 47_622
    host: str = "127.0.0.1"
    maximum_agent_body_bytes: int = 64 * 1_024
    maximum_admin_body_bytes: int = 32 * 1_024
    maximum_wait_ms: int = 30_000
    total_body_timeout_ms: int = 10_000
    inter_chunk_timeout_ms: int = 2_000
    maximum_listener_concurrency: int = 128
    listener_backlog: int = 128
    keep_alive_timeout_seconds: int = 5

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Gatehouse v1 listeners must bind to 127.0.0.1")
        if not 1 <= self.agent_port <= 65_535 or not 1 <= self.admin_port <= 65_535:
            raise ValueError("listener ports are invalid")
        if self.agent_port == self.admin_port:
            raise ValueError("agent and admin listeners require distinct ports")
        if (
            type(self.maximum_agent_body_bytes) is not int
            or type(self.maximum_admin_body_bytes) is not int
            or not 1 <= self.maximum_agent_body_bytes <= 16 * 1_024 * 1_024
            or not 1 <= self.maximum_admin_body_bytes <= 16 * 1_024 * 1_024
        ):
            raise ValueError("request-body bounds must be positive")
        if not 1 <= self.maximum_wait_ms <= 60_000:
            raise ValueError("maximum_wait_ms is outside its bound")
        if (
            min(
                self.total_body_timeout_ms,
                self.inter_chunk_timeout_ms,
                self.maximum_listener_concurrency,
                self.listener_backlog,
                self.keep_alive_timeout_seconds,
            )
            <= 0
            or self.inter_chunk_timeout_ms > self.total_body_timeout_ms
            or self.total_body_timeout_ms > 60_000
            or self.inter_chunk_timeout_ms > 10_000
            or self.maximum_listener_concurrency > 10_000
            or self.listener_backlog > 10_000
            or self.keep_alive_timeout_seconds > 60
        ):
            raise ValueError("listener admission bounds are invalid")


@dataclass(frozen=True, slots=True)
class DaemonApplications:
    agent: FastAPI
    admin: FastAPI

    def __post_init__(self) -> None:
        if self.agent is self.admin:
            raise ValueError("agent and admin realms must use separate applications")


class _ServingServer(Protocol):
    should_exit: bool

    async def serve(self) -> None: ...


class _CoordinatedUvicornServer(uvicorn.Server):
    """Leave process signal ownership to the one composition lifecycle."""

    @contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def create_daemon_applications(
    *,
    sessions: SessionAuthority,
    operations: AgentOperations,
    health: HealthProbe,
    admin_auth: AdminAuthManager,
    admin_backend: AdminBackend,
    now_ms: Callable[[], int],
    settings: DaemonSettings | None = None,
    session_heartbeat_interval_ms: int = 30_000,
    admission: AgentAdmission | None = None,
    audit_view: SqliteAuditView | None = None,
    lifecycle_journal: LifecycleJournal | None = None,
) -> DaemonApplications:
    settings = settings or DaemonSettings()
    return DaemonApplications(
        agent=create_agent_app(
            sessions=sessions,
            operations=operations,
            health=health,
            now_ms=now_ms,
            allowed_hosts=(
                f"127.0.0.1:{settings.agent_port}",
                f"localhost:{settings.agent_port}",
            ),
            maximum_body_bytes=settings.maximum_agent_body_bytes,
            total_body_timeout_ms=settings.total_body_timeout_ms,
            inter_chunk_timeout_ms=settings.inter_chunk_timeout_ms,
            maximum_wait_ms=settings.maximum_wait_ms,
            session_heartbeat_interval_ms=session_heartbeat_interval_ms,
            admission=admission,
        ),
        admin=create_admin_app(
            auth=admin_auth,
            backend=admin_backend,
            now_ms=now_ms,
            allowed_hosts=(
                f"127.0.0.1:{settings.admin_port}",
                f"localhost:{settings.admin_port}",
            ),
            maximum_body_bytes=settings.maximum_admin_body_bytes,
            total_body_timeout_ms=settings.total_body_timeout_ms,
            inter_chunk_timeout_ms=settings.inter_chunk_timeout_ms,
            audit_view=audit_view,
            lifecycle_journal=lifecycle_journal,
        ),
    )


async def serve(
    applications: DaemonApplications,
    settings: DaemonSettings,
    *,
    shutdown_event: asyncio.Event | None = None,
    server_factory: Callable[[uvicorn.Config], _ServingServer] = _CoordinatedUvicornServer,
) -> None:
    """Retain both listener tasks until their cooperative shutdown finishes.

    Cancellation signals ``should_exit`` and waits without cancelling a listener
    task: interrupting Uvicorn's coroutine can bypass its internal cleanup. The
    composed lifecycle owns the deadline and retains resources while this outer
    task remains pending. This does not certify native cleanup after a server's
    own early-startup or partial-setup failure.
    """

    agent = server_factory(
        uvicorn.Config(
            applications.agent,
            host=settings.host,
            port=settings.agent_port,
            access_log=False,
            limit_concurrency=settings.maximum_listener_concurrency,
            backlog=settings.listener_backlog,
            timeout_keep_alive=settings.keep_alive_timeout_seconds,
        )
    )
    admin = server_factory(
        uvicorn.Config(
            applications.admin,
            host=settings.host,
            port=settings.admin_port,
            access_log=False,
            limit_concurrency=settings.maximum_listener_concurrency,
            backlog=settings.listener_backlog,
            timeout_keep_alive=settings.keep_alive_timeout_seconds,
        )
    )
    owned: list[asyncio.Task[Any]] = []
    shutdown_task: asyncio.Task[bool] | None = None
    launch_gate = asyncio.Event()
    launch_granted = False
    failure: BaseException | None = None

    async def listener(server: _ServingServer) -> None:
        await launch_gate.wait()
        if launch_granted:
            await server.serve()

    def own[ResultT](work: Coroutine[Any, Any, ResultT], *, name: str) -> asyncio.Task[ResultT]:
        try:
            task = asyncio.create_task(work, name=name)
        except BaseException:
            work.close()
            raise
        owned.append(task)
        return task

    def observe(task: asyncio.Task[Any]) -> None:
        nonlocal failure
        if task.cancelled():
            if task is not shutdown_task and failure is None:
                failure = asyncio.CancelledError()
        else:
            error = task.exception()
            if error is not None and failure is None:
                failure = error

    try:
        own(listener(agent), name="gatehouse-agent-listener")
        own(listener(admin), name="gatehouse-admin-listener")
        if shutdown_event is not None:
            shutdown_task = own(shutdown_event.wait(), name="gatehouse-shutdown-signal")
        # No listener delegate can start until every immediate task is retained.
        launch_granted = True
        launch_gate.set()
        done, _ = await asyncio.wait(owned, return_when=asyncio.FIRST_COMPLETED)
        for task in owned:
            if task in done:
                observe(task)
    except BaseException as error:
        failure = error
    finally:
        for server in (agent, admin):
            try:
                server.should_exit = True
            except BaseException as error:
                if failure is None:
                    failure = error
        if shutdown_task is not None and not shutdown_task.done():
            shutdown_task.cancel()
        # On partial task creation failure, release the wrappers without ever
        # entering server.serve(). There are at most three owned tasks.
        launch_gate.set()
        while pending := {task for task in owned if not task.done()}:
            try:
                done, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            except asyncio.CancelledError as error:
                if failure is None:
                    failure = error
                continue
            for task in owned:
                if task in done:
                    observe(task)
        # Retain all references and retrieve late exceptions, including tasks
        # that finished before entry to this cleanup loop. Repeated cancellation
        # never propagates into listener tasks or loses the outer ownership fence.
        for task in owned:
            observe(task)
    if failure is not None:
        raise failure
