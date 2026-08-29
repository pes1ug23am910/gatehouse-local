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
from gatehouse.database.migrations import open_compatible_database
from gatehouse.sessions import build_long_lived_environment
from gatehouse.state_security import (
    StateDirectorySecurityError,
    secure_database_state,
    validate_state_path_ancestry,
)
from gatehouse.watchdog.controller import (
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)

HealthProbe = Callable[[], Awaitable[ProbeResult]]
_OWNED_CHILD_STOP_TIMEOUT_SECONDS = 1.0
_READINESS_STATES = frozenset(
    {
        "RECOVERING",
        "READY",
        "DEGRADED_READ_ONLY",
        "DEGRADED_NO_PROVIDER",
        "DRAINING",
        "FAILED_CLOSED",
        "STOPPED",
    }
)


@dataclass(frozen=True, slots=True)
class WatchdogRuntimeSettings:
    """Validated process settings shared by probing and restart."""

    config_path: Path
    database_path: Path
    agent_port: int
    readiness_timeout_seconds: float
    restart_policy: RestartPolicy
    allow_provider_disabled_state: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.agent_port <= 65_535:
            raise ValueError("agent port must be between 1 and 65535")
        if self.readiness_timeout_seconds <= 0:
            raise ValueError("readiness timeout must be positive")
        if type(self.allow_provider_disabled_state) is not bool:
            raise ValueError("disabled provider-state acceptance must be Boolean")


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
    resolved_database = Path(configuration.database.path)
    if database_path is not None:
        try:
            validated_database = validate_state_path_ancestry(database_path)
            resolved_database = validated_database.resolve(strict=False)
            validate_state_path_ancestry(resolved_database)
        except (OSError, StateDirectorySecurityError):
            raise ValueError("watchdog database path is unsafe") from None
    return WatchdogRuntimeSettings(
        config_path=config_path,
        database_path=resolved_database,
        agent_port=(configuration.server.agent.port if agent_port is None else agent_port),
        readiness_timeout_seconds=configuration.watchdog.readiness_timeout / 1_000,
        restart_policy=RestartPolicy(
            maximum_restarts=configuration.watchdog.maximum_restarts,
            restart_window_ms=configuration.watchdog.restart_window,
            crash_loop_cooldown_ms=configuration.watchdog.crash_loop_cooldown,
        ),
        allow_provider_disabled_state=(configuration.firecrawl_workload.mode == "disabled"),
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
            try:
                live = await client.get(f"{base_url}/health/live")
            except httpx.HTTPError:
                return ProbeResult(live=False, ready=False, detail="connection_failed")
            if live.status_code != 200:
                return ProbeResult(
                    live=False,
                    ready=False,
                    detail=f"liveness_http_{live.status_code}",
                )
            try:
                ready = await client.get(f"{base_url}/health/ready")
            except httpx.HTTPError:
                return ProbeResult(
                    live=True,
                    ready=False,
                    detail="readiness_connection_failed",
                )
            state: str | None = None
            try:
                payload = ready.json()
                candidate = payload.get("status") if isinstance(payload, dict) else None
                state = candidate.strip().upper() if isinstance(candidate, str) else None
            except ValueError:
                pass
            readiness_contract_valid = state in _READINESS_STATES and ready.status_code == (
                200 if state == "READY" else 503
            )
            readiness_matches = readiness_contract_valid and state == "READY"
            detail = None
            if state is None:
                detail = "readiness_state_unavailable"
            elif state not in _READINESS_STATES:
                detail = "readiness_state_unrecognized"
            elif not readiness_contract_valid:
                detail = "readiness_status_mismatch"
            return ProbeResult(
                live=True,
                ready=readiness_matches,
                daemon_state=state,
                detail=detail,
                readiness_status_code=ready.status_code,
                readiness_contract_valid=readiness_contract_valid,
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
    environment = build_long_lived_environment(os.environ)
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
            env=environment,
            creationflags=creation_flags,
        )
    return await asyncio.create_subprocess_exec(  # noqa: S603
        *arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
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
    accepted = False
    try:
        while True:
            if _process_has_exited(process):
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                async with asyncio.timeout(remaining):
                    observed = await health_probe()
            except TimeoutError:
                return False
            if _process_has_exited(process):
                return False
            if observed.live and observed.daemon_state == "FAILED_CLOSED":
                return False
            ready_contract = (
                observed.ready
                and observed.daemon_state == "READY"
                and observed.readiness_status_code == 200
                and observed.readiness_contract_valid
            )
            disabled_contract = (
                not observed.ready
                and settings.allow_provider_disabled_state
                and observed.daemon_state == "DEGRADED_NO_PROVIDER"
                and observed.readiness_status_code == 503
                and observed.readiness_contract_valid
            )
            if observed.live and (ready_contract or disabled_contract):
                accepted = True
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(0.5, remaining))
    finally:
        if not accepted and process.returncode is None:
            await _terminate_owned_process(process)


def _process_has_exited(process: asyncio.subprocess.Process) -> bool:
    """Read child state afresh across await points without stale narrowing."""

    return process.returncode is not None


async def _terminate_owned_process(process: asyncio.subprocess.Process) -> None:
    """Bound cleanup of only the child returned by this restart attempt."""

    if process.returncode is not None:
        return
    try:
        process.terminate()
    except BaseException:
        return
    try:
        await asyncio.wait_for(
            process.wait(),
            timeout=_OWNED_CHILD_STOP_TIMEOUT_SECONDS,
        )
        return
    except TimeoutError:
        try:
            process.kill()
        except BaseException:
            return
    except BaseException:
        return
    try:
        await asyncio.wait_for(
            process.wait(),
            timeout=_OWNED_CHILD_STOP_TIMEOUT_SECONDS,
        )
    except BaseException:
        return


async def _run(settings: WatchdogRuntimeSettings) -> WatchdogOutcome:
    secure_database_state(settings.database_path, must_exist=True)
    connection = open_compatible_database(settings.database_path)
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
            "allow_provider_disabled_state": settings.allow_provider_disabled_state,
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


def _parser(*, environment: Mapping[str, str] | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one bounded Gatehouse health check")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one check (the only v1 mode; accepted for Task Scheduler clarity)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_default_config_path(environment),
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


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> None:
    ensure_standard_streams()
    source = os.environ if environment is None else environment
    runtime_environment = build_long_lived_environment(source)
    if environment is None:
        os.environ.clear()
        os.environ.update(runtime_environment)
    parser = _parser(environment=runtime_environment)
    arguments = parser.parse_args(argv)
    try:
        settings = _load_runtime_settings(
            arguments.config,
            database_path=arguments.database,
            agent_port=arguments.agent_port,
            environment=runtime_environment,
        )
    except (ConfigLoadError, ValueError) as error:
        parser.error(str(error))
    if arguments.print_settings:
        print(_settings_json(settings))
        return
    outcome = asyncio.run(_run(settings))
    print(outcome.value)
    raise SystemExit(_outcome_exit_code(outcome))


if __name__ == "__main__":
    main()
