"""Composition and serving primitives for the two loopback HTTP realms."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

import uvicorn
from fastapi import FastAPI

from gatehouse.admin import AdminAuthManager, AdminBackend
from gatehouse.api import (
    AgentOperations,
    HealthProbe,
    SessionAuthority,
    create_admin_app,
    create_agent_app,
)
from gatehouse.api.agent import AgentAdmission


@dataclass(frozen=True, slots=True)
class DaemonSettings:
    agent_port: int = 47_621
    admin_port: int = 47_622
    host: str = "127.0.0.1"
    maximum_agent_body_bytes: int = 64 * 1_024
    maximum_admin_body_bytes: int = 32 * 1_024
    maximum_wait_ms: int = 30_000

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Gatehouse v1 listeners must bind to 127.0.0.1")
        if not 1 <= self.agent_port <= 65_535 or not 1 <= self.admin_port <= 65_535:
            raise ValueError("listener ports are invalid")
        if self.agent_port == self.admin_port:
            raise ValueError("agent and admin listeners require distinct ports")
        if min(self.maximum_agent_body_bytes, self.maximum_admin_body_bytes) <= 0:
            raise ValueError("request-body bounds must be positive")
        if not 1 <= self.maximum_wait_ms <= 60_000:
            raise ValueError("maximum_wait_ms is outside its bound")


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
        ),
    )


async def serve(
    applications: DaemonApplications,
    settings: DaemonSettings,
    *,
    shutdown_event: asyncio.Event | None = None,
    server_factory: Callable[[uvicorn.Config], _ServingServer] = _CoordinatedUvicornServer,
) -> None:
    """Serve two listeners and always stop the peer when either one exits."""

    agent = server_factory(
        uvicorn.Config(
            applications.agent,
            host=settings.host,
            port=settings.agent_port,
            access_log=False,
        )
    )
    admin = server_factory(
        uvicorn.Config(
            applications.admin,
            host=settings.host,
            port=settings.admin_port,
            access_log=False,
        )
    )
    server_tasks = (
        asyncio.create_task(agent.serve(), name="gatehouse-agent-listener"),
        asyncio.create_task(admin.serve(), name="gatehouse-admin-listener"),
    )
    waiters: set[asyncio.Task[object]] = set(server_tasks)
    shutdown_task: asyncio.Task[object] | None = None
    if shutdown_event is not None:
        shutdown_task = asyncio.create_task(
            shutdown_event.wait(),
            name="gatehouse-shutdown-signal",
        )
        waiters.add(shutdown_task)
    done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    agent.should_exit = True
    admin.should_exit = True
    if shutdown_task is not None and shutdown_task not in done:
        shutdown_task.cancel()
    results = await asyncio.gather(*server_tasks, return_exceptions=True)
    for task in done:
        if task is shutdown_task:
            continue
        exception = task.exception()
        if exception is not None:
            raise exception
    for result in results:
        if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
            raise result
