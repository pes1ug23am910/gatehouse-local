"""One-shot Task Scheduler entry point for the local watchdog."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx
from platformdirs import user_config_path

from gatehouse.config import ConfigLoadError, load_main_config
from gatehouse.core.stdio import ensure_standard_streams
from gatehouse.database.migrations import open_migrated_database
from gatehouse.watchdog.controller import (
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)

HealthProbe = Callable[[], Awaitable[ProbeResult]]


@dataclass(frozen=True, slots=True)
class WatchdogRuntimeSettings:
    """Validated process settings shared by probing and restart."""

    config_path: Path
    database_path: Path
    agent_port: int
    readiness_timeout_seconds: float
    restart_policy: RestartPolicy

    def __post_init__(self) -> None:
        if not 1 <= self.agent_port <= 65_535:
            raise ValueError("agent port must be between 1 and 65535")
        if self.readiness_timeout_seconds <= 0:
            raise ValueError("readiness timeout must be positive")


def _default_config_path(
    environment: Mapping[str, str] | None = None,
) -> Path:
    source = environment if environment is not None else os.environ
    normalized = {str(key).upper(): str(value) for key, value in source.items()}
    appdata = normalized.get("APPDATA")
    if appdata:
        return Path(appdata) / "Gatehouse" / "config.yaml"
    return user_config_path("Gatehouse", roaming=True) / "config.yaml"


def _load_runtime_settings(
    config_path: Path,
    *,
    database_path: Path | None = None,
    agent_port: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> WatchdogRuntimeSettings:
    configuration = load_main_config(config_path, environment=environment)
    return WatchdogRuntimeSettings(
        config_path=config_path,
        database_path=database_path or Path(configuration.database.path),
        agent_port=(configuration.server.agent.port if agent_port is None else agent_port),
        readiness_timeout_seconds=configuration.watchdog.readiness_timeout / 1_000,
        restart_policy=RestartPolicy(
            maximum_restarts=configuration.watchdog.maximum_restarts,
            restart_window_ms=configuration.watchdog.restart_window,
            crash_loop_cooldown_ms=configuration.watchdog.crash_loop_cooldown,
        ),
    )


async def _probe(
    settings: WatchdogRuntimeSettings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ProbeResult:
    base_url = f"http://127.0.0.1:{settings.agent_port}"
    try:
        async with httpx.AsyncClient(
            timeout=settings.readiness_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            live = await client.get(f"{base_url}/health/live")
            if live.status_code != 200:
                return ProbeResult(
                    live=False,
                    ready=False,
                    detail=f"liveness_http_{live.status_code}",
                )
            ready = await client.get(f"{base_url}/health/ready")
            state: str | None = None
            try:
                payload = ready.json()
                candidate = payload.get("status") if isinstance(payload, dict) else None
                state = candidate.strip().upper() if isinstance(candidate, str) else None
            except ValueError:
                pass
            return ProbeResult(
                live=True,
                ready=ready.status_code == 200,
                daemon_state=state,
                detail=None if state is not None else "readiness_state_unavailable",
            )
    except httpx.HTTPError:
        return ProbeResult(live=False, ready=False, detail="connection_failed")


def _locate_daemon_executable() -> Path | None:
    executable_name = "gatehoused.exe" if os.name == "nt" else "gatehoused"
    adjacent = Path(sys.executable).with_name(executable_name)
    if adjacent.is_file():
        return adjacent
    discovered = shutil.which(executable_name)
    return Path(discovered) if discovered is not None else None


async def _spawn_daemon(arguments: tuple[str, ...]) -> asyncio.subprocess.Process:
    if os.name == "nt":
        creation_flags = (
            subprocess.CREATE_NO_WINDOW
            | subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
        )
        return await asyncio.create_subprocess_exec(  # noqa: S603
            *arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
    return await asyncio.create_subprocess_exec(  # noqa: S603
        *arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


async def _restart(
    settings: WatchdogRuntimeSettings,
    *,
    daemon_executable: Path | None = None,
    probe: HealthProbe | None = None,
) -> bool:
    executable = daemon_executable or _locate_daemon_executable()
    if executable is None or not executable.is_file():
        return False
    arguments = (str(executable), "--config", str(settings.config_path))
    try:
        process = await _spawn_daemon(arguments)
    except OSError:
        return False

    health_probe = probe or (lambda: _probe(settings))
    deadline = time.monotonic() + settings.readiness_timeout_seconds
    while True:
        if process.returncode is not None:
            return False
        if (await health_probe()).live:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(0.5, remaining))


async def _run(settings: WatchdogRuntimeSettings) -> WatchdogOutcome:
    connection = open_migrated_database(settings.database_path)
    try:
        controller = WatchdogController(
            connection=connection,
            probe=lambda: _probe(settings),
            restart=lambda: _restart(settings),
            owner_id=f"watchdog_{uuid.uuid4().hex}",
            policy=settings.restart_policy,
        )
        return await controller.run_once(now_ms=int(time.time() * 1_000))
    finally:
        connection.close()


def _settings_json(settings: WatchdogRuntimeSettings) -> str:
    return json.dumps(
        {
            "agent_port": settings.agent_port,
            "config_path": str(settings.config_path),
            "database_path": str(settings.database_path),
            "readiness_timeout_seconds": settings.readiness_timeout_seconds,
            "restart_policy": {
                "crash_loop_cooldown_ms": settings.restart_policy.crash_loop_cooldown_ms,
                "maximum_restarts": settings.restart_policy.maximum_restarts,
                "restart_window_ms": settings.restart_policy.restart_window_ms,
            },
        },
        sort_keys=True,
    )


def _outcome_exit_code(outcome: WatchdogOutcome) -> int:
    successful = {
        WatchdogOutcome.HEALTHY,
        WatchdogOutcome.LEASE_BUSY,
        WatchdogOutcome.LIVE_DEGRADED,
        WatchdogOutcome.RESTARTED,
    }
    return 0 if outcome in successful else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one bounded Gatehouse health check")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one check (the only v1 mode; accepted for Task Scheduler clarity)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_default_config_path(),
        help="Path to the validated Gatehouse main configuration",
    )
    parser.add_argument(
        "--database",
        type=Path,
        help="Override the watchdog accounting database from the main configuration",
    )
    parser.add_argument(
        "--agent-port",
        type=int,
        help="Override the agent health-check port from the main configuration",
    )
    parser.add_argument(
        "--print-settings",
        action="store_true",
        help="Print resolved non-secret watchdog settings as JSON and exit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    ensure_standard_streams()
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        settings = _load_runtime_settings(
            arguments.config,
            database_path=arguments.database,
            agent_port=arguments.agent_port,
        )
    except (ConfigLoadError, ValueError) as error:
        parser.error(str(error))
    if arguments.print_settings:
        print(_settings_json(settings))
        return
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    outcome = asyncio.run(_run(settings))
    print(outcome.value)
    raise SystemExit(_outcome_exit_code(outcome))


if __name__ == "__main__":
    main()
