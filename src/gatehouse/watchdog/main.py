"""One-shot Task Scheduler entry point for the local watchdog."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn

import httpx
from platformdirs import user_config_path

from gatehouse.admin.control import CONTROL_CAPABILITY_HEADER, ControlDaemonStatus
from gatehouse.admin.control_capability import load_control_capability
from gatehouse.config import ConfigLoadError
from gatehouse.config.security import ConfigSecurityError
from gatehouse.core.stdio import ensure_standard_streams
from gatehouse.daemon.composition import installation_state_paths
from gatehouse.daemon.configuration import (
    load_runtime_configuration,
    require_configuration_snapshot_digest,
    validate_expected_config_digest,
)
from gatehouse.daemon_executable import select_adjacent_daemon_path
from gatehouse.database.migrations import open_compatible_database
from gatehouse.sessions import EnvironmentValidationError, build_long_lived_environment
from gatehouse.state_security import (
    StateDirectorySecurityError,
    secure_database_state,
    validate_state_path_ancestry,
)
from gatehouse.watchdog.controller import (
    ProbeAttestation,
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)

HealthProbe = Callable[[], Awaitable[ProbeResult]]
CapabilityLoader = Callable[[Path], str]
_OWNED_CHILD_STOP_TIMEOUT_SECONDS = 1.0
_PROBE_CLOSE_TIMEOUT_SECONDS = 1.0
_MAXIMUM_CONTROL_RESPONSE_BYTES = 64 * 1_024
_MAXIMUM_PROBE_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class WatchdogRuntimeSettings:
    """Validated process settings shared by probing and restart."""

    config_path: Path
    database_path: Path
    agent_port: int
    admin_port: int
    readiness_timeout_seconds: float
    restart_policy: RestartPolicy
    expected_config_digest: str
    environment: Mapping[str, str]
    allow_provider_disabled_state: bool = False

    def __post_init__(self) -> None:
        validate_expected_config_digest(self.expected_config_digest)
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(build_long_lived_environment(self.environment)),
        )
        if type(self.agent_port) is not int or not 1 <= self.agent_port <= 65_535:
            raise ValueError("agent port must be between 1 and 65535")
        if type(self.admin_port) is not int or not 1 <= self.admin_port <= 65_535:
            raise ValueError("admin port must be between 1 and 65535")
        if (
            type(self.readiness_timeout_seconds) not in (int, float)
            or not 0 < self.readiness_timeout_seconds <= _MAXIMUM_PROBE_TIMEOUT_SECONDS
            or not math.isfinite(self.readiness_timeout_seconds)
        ):
            raise ValueError("readiness timeout must be finite, positive and at most 60 seconds")
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
    config_path: str | Path,
    *,
    expected_config_digest: str,
    database_path: Path | None = None,
    agent_port: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> WatchdogRuntimeSettings:
    expected = validate_expected_config_digest(expected_config_digest)
    runtime_environment = build_long_lived_environment(
        os.environ if environment is None else environment
    )
    runtime = load_runtime_configuration(
        config_path,
        environment=runtime_environment,
        expected_config_digest=expected,
    )
    snapshot = runtime.snapshot
    if snapshot is None or not snapshot.matches_main_path(config_path):
        raise ConfigSecurityError("verified configuration snapshot is unavailable")
    require_configuration_snapshot_digest(snapshot, expected)
    configuration = runtime.main
    resolved_database = Path(configuration.database.path)
    if database_path is not None:
        try:
            validated_database = validate_state_path_ancestry(database_path)
            override_database = validated_database.resolve(strict=False)
            validate_state_path_ancestry(override_database)
        except (OSError, StateDirectorySecurityError):
            raise ValueError("watchdog database path is unsafe") from None
        if override_database != resolved_database:
            raise ValueError("watchdog database override differs from the verified configuration")
    if agent_port is not None and agent_port != configuration.server.agent.port:
        raise ValueError("watchdog agent port override differs from the verified configuration")
    return WatchdogRuntimeSettings(
        config_path=snapshot.main_path,
        database_path=resolved_database,
        agent_port=configuration.server.agent.port,
        admin_port=configuration.server.admin.port,
        readiness_timeout_seconds=configuration.watchdog.readiness_timeout / 1_000,
        restart_policy=RestartPolicy(
            maximum_restarts=configuration.watchdog.maximum_restarts,
            restart_window_ms=configuration.watchdog.restart_window,
            crash_loop_cooldown_ms=configuration.watchdog.crash_loop_cooldown,
        ),
        expected_config_digest=expected,
        environment=runtime_environment,
        allow_provider_disabled_state=(
            configuration.firecrawl_workload.mode == "disabled"
            and configuration.firecrawl_observer.mode == "disabled"
        ),
    )


def _require_probe_time(deadline: float) -> None:
    if asyncio.get_running_loop().time() >= deadline:
        raise TimeoutError("watchdog probe deadline expired")


async def _close_probe_resource(
    resource: httpx.Response | httpx.AsyncClient,
    deadline: float,
) -> None:
    if resource.is_closed:
        return
    close_deadline = min(
        deadline,
        asyncio.get_running_loop().time() + _PROBE_CLOSE_TIMEOUT_SECONDS,
    )
    async with asyncio.timeout_at(close_deadline):
        await resource.aclose()
    _require_probe_time(close_deadline)


@asynccontextmanager
async def _owned_probe_resource(
    resource: httpx.Response | httpx.AsyncClient,
    deadline: float,
) -> AsyncIterator[None]:
    """Attempt bounded closure without replacing an active interruption."""

    try:
        yield
    except BaseException:
        try:
            await _close_probe_resource(resource, deadline)
        except BaseException:  # noqa: S110 - preserve the active primary failure
            # Preserve the original failure; no cleanup success is inferred.
            pass
        raise
    else:
        await _close_probe_resource(resource, deadline)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("control status contains duplicate members")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise ValueError("control status contains a nonfinite number")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("control status contains a nonfinite number")
    return parsed


async def _read_control_status(response: httpx.Response) -> dict[str, object]:
    media = response.headers.get_list("content-type")
    encoding = response.headers.get_list("content-encoding")
    lengths = response.headers.get_list("content-length")
    if (
        len(media) != 1
        or len(media[0]) > 128
        or re.fullmatch(
            r'application/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?',
            media[0].strip(),
            re.IGNORECASE,
        )
        is None
        or (encoding and (len(encoding) != 1 or encoding[0].strip().lower() != "identity"))
        or (
            lengths
            and (
                len(lengths) != 1
                or re.fullmatch(r"[0-9]{1,10}", lengths[0]) is None
                or int(lengths[0]) > _MAXIMUM_CONTROL_RESPONSE_BYTES
            )
        )
    ):
        raise ValueError("control status representation is invalid")
    body = bytearray()
    # Raw iteration avoids decoding compressed bodies or accepting prebuffered input.
    async for chunk in response.aiter_raw():
        if type(chunk) is not bytes or len(chunk) > _MAXIMUM_CONTROL_RESPONSE_BYTES - len(body):
            raise ValueError("control status body exceeds its limit")
        body.extend(chunk)
    payload = json.loads(
        body.decode("utf-8"),
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
        parse_float=_finite_json_float,
    )
    if type(payload) is not dict:
        raise ValueError("control status must be an object")
    return payload


async def _probe(
    settings: WatchdogRuntimeSettings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    capability_loader: CapabilityLoader | None = None,
) -> ProbeResult:
    live = False
    agent_status_code: int | None = None
    control_status_code: int | None = None
    deadline = asyncio.get_running_loop().time() + settings.readiness_timeout_seconds

    def result(
        attestation: ProbeAttestation = ProbeAttestation.UNVERIFIED,
        *,
        status: ControlDaemonStatus | None = None,
    ) -> ProbeResult:
        return ProbeResult(
            live=live,
            ready=status.ready if status is not None else False,
            daemon_state=status.status if status is not None else None,
            agent_status_code=agent_status_code,
            control_status_code=control_status_code,
            attestation=attestation,
        )

    async def collect(client: httpx.AsyncClient) -> ProbeResult:
        nonlocal live, agent_status_code, control_status_code
        agent_refused = False
        try:
            response = await client.send(
                client.build_request(
                    "GET",
                    f"http://127.0.0.1:{settings.agent_port}/health/live",
                    headers={"accept-encoding": "identity"},
                ),
                stream=True,
            )
        except httpx.ConnectError:
            agent_refused = True
        else:
            live = True
            agent_status_code = response.status_code
            async with _owned_probe_resource(response, deadline):
                _require_probe_time(deadline)
                # Presence uses headers only; no liveness body is consumed.

        loader = load_control_capability if capability_loader is None else capability_loader
        capability = loader(installation_state_paths(settings.database_path).control_capability)
        if type(capability) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", capability) is None:
            raise ValueError("control capability is unavailable")
        _require_probe_time(deadline)
        try:
            response = await client.send(
                client.build_request(
                    "GET",
                    f"http://127.0.0.1:{settings.admin_port}/v1/control/status",
                    headers={
                        CONTROL_CAPABILITY_HEADER: capability,
                        "accept": "application/json",
                        "accept-encoding": "identity",
                    },
                ),
                stream=True,
            )
        except httpx.ConnectError:
            return result(
                ProbeAttestation.NO_RESPONDER
                if agent_refused and not live
                else ProbeAttestation.UNVERIFIED,
            )
        live = True
        control_status_code = response.status_code
        async with _owned_probe_resource(response, deadline):
            _require_probe_time(deadline)
            if response.status_code != 200:
                return result()
            payload = await _read_control_status(response)
            digest = ControlDaemonStatus.validate_config_digest(payload.get("config_digest"))
            if digest is None:
                return result()
            if digest != settings.expected_config_digest:
                return result(ProbeAttestation.MISMATCH)
            status = ControlDaemonStatus.model_validate(payload)
            matched = result(ProbeAttestation.MATCHED, status=status)
            return matched if matched.has_matched_status() else result()

    try:
        async with asyncio.timeout_at(deadline):
            client = httpx.AsyncClient(
                timeout=settings.readiness_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            )
            async with _owned_probe_resource(client, deadline):
                observed = await collect(client)
            _require_probe_time(deadline)
            return observed
    except Exception:
        # Transport, authority, parser and closure failures share a fixed outcome.
        # CancelledError and other control-flow interruptions still propagate.
        return result()


def _locate_daemon_executable(requested: Path | None = None) -> Path | None:
    try:
        interpreter = sys.executable
        if requested is not None and type(requested) is not type(Path()):
            return None
        selected = select_adjacent_daemon_path(
            interpreter,
            requested_executable=None if requested is None else str(requested),
            platform=os.name,
        )
        candidate = Path(selected)
        return candidate if candidate.is_file() is True else None
    except Exception:
        # All ordinary selection/availability failures have one fixed refusal.
        # This pathname check does not attest native identity or runtime trust.
        return None


async def _spawn_daemon(
    arguments: tuple[str, ...],
    *,
    environment: Mapping[str, str],
) -> asyncio.subprocess.Process:
    environment = build_long_lived_environment(environment)
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
    executable = _locate_daemon_executable(daemon_executable)
    if executable is None:
        return False
    arguments = (
        str(executable),
        "--config",
        str(settings.config_path),
        "--expected-config-digest",
        settings.expected_config_digest,
    )
    try:
        process = await _spawn_daemon(arguments, environment=settings.environment)
    except (OSError, EnvironmentValidationError):
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
            if time.monotonic() >= deadline:
                return False
            if observed.has_matched_status():
                if observed.daemon_state == "FAILED_CLOSED":
                    return False
                if observed.ready or (
                    settings.allow_provider_disabled_state
                    and observed.daemon_state == "DEGRADED_NO_PROVIDER"
                ):
                    accepted = True
                    return True
            elif not observed.has_no_responder():
                return False
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
            allow_provider_disabled_state=settings.allow_provider_disabled_state,
        )
        return await controller.run_once(now_ms=int(time.time() * 1_000))
    finally:
        connection.close()


def _settings_json(settings: WatchdogRuntimeSettings) -> str:
    return json.dumps(
        {
            "agent_port": settings.agent_port,
            "admin_port": settings.admin_port,
            "config_path": str(settings.config_path),
            "expected_config_digest": settings.expected_config_digest,
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
        WatchdogOutcome.PROVIDERS_DISABLED,
        WatchdogOutcome.RESTARTED,
    }
    return 0 if outcome in successful else 1


class _WatchdogArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        super().error("watchdog startup arguments are invalid")


class _ExpectedConfigDigestAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error("watchdog startup arguments are invalid")
        try:
            expected = validate_expected_config_digest(values)
        except ConfigSecurityError:
            parser.error("watchdog startup arguments are invalid")
        else:
            setattr(namespace, self.dest, expected)


def _parser(*, environment: Mapping[str, str] | None = None) -> argparse.ArgumentParser:
    parser = _WatchdogArgumentParser(
        description="Run one bounded Gatehouse health check",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one check (the only v1 mode; accepted for Task Scheduler clarity)",
    )
    parser.add_argument(
        "--config",
        default=str(_default_config_path(environment)),
        help="Path to the validated Gatehouse main configuration",
    )
    parser.add_argument(
        "--expected-config-digest",
        required=True,
        action=_ExpectedConfigDigestAction,
        help="expected trusted configuration bundle digest (64 lowercase hexadecimal characters)",
    )
    parser.add_argument(
        "--database",
        type=Path,
        help="Assert the database path matches the verified configuration",
    )
    parser.add_argument(
        "--agent-port",
        type=int,
        help="Assert the agent port matches the verified configuration",
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
    try:
        runtime_environment = build_long_lived_environment(source)
    except EnvironmentValidationError:
        _WatchdogArgumentParser(prog="gatehouse-watchdog").exit(
            2,
            f"gatehouse-watchdog: error: {EnvironmentValidationError()}\n",
        )
    parser = _parser(environment=runtime_environment)
    arguments = parser.parse_args(argv)
    try:
        settings = _load_runtime_settings(
            arguments.config,
            expected_config_digest=arguments.expected_config_digest,
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
