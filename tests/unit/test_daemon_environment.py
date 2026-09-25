"""Long-lived environment enforcement through fake production process adapters."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import cast

import pytest
from typer.testing import CliRunner

from gatehouse.cli import local
from gatehouse.cli import main as cli_main
from gatehouse.cli.contracts import CliUnavailable, InteractiveSecretReader, UnavailableCliBackend
from gatehouse.daemon import main as daemon_main
from gatehouse.sessions.environment import EnvironmentValidationError
from gatehouse.watchdog import main as watchdog
from gatehouse.watchdog.controller import RestartPolicy

ERROR = "long-lived process environment is invalid"
CANARY = "synthetic-environment-detail-never-rendered"
ARGUMENTS = ("C:\\Synthetic\\gatehoused.exe", "--config", "C:\\Synthetic\\config.yaml")
EXPECTED = {"APPDATA": "C:\\Synthetic\\Roaming", "LOCALAPPDATA": "", "PATH": ""}


def _forbidden(*args: object, **kwargs: object) -> None:
    del args, kwargs
    raise AssertionError("environment refusal reached discovery or an external effect")


class _Unrenderable:
    def __str__(self) -> str:
        raise AssertionError("an excluded environment value was inspected")


def _valid_environment() -> dict[str, str]:
    return {
        "appdata": EXPECTED["APPDATA"],
        "LOCALAPPDATA": "",
        "Path": "",
        "PYTHONPATH": CANARY,
        "FIRECRAWL_API_KEY": CANARY,
        "GATEHOUSE_SESSION_BOOTSTRAP": CANARY,
        "IGNORED": cast(str, _Unrenderable()),
    }


def _invalid_environment(defect: str) -> dict[str, str]:
    if defect == "malformed":
        return {"APPDATA": CANARY + "\x00"}
    if defect == "oversize":
        return {"APPDATA": "x" * 8_193}
    if defect == "duplicate":
        return {"APPDATA": CANARY, "appdata": CANARY}
    raise AssertionError("unrecognized synthetic defect")


def _settings(environment: Mapping[str, str]) -> watchdog.WatchdogRuntimeSettings:
    return watchdog.WatchdogRuntimeSettings(
        config_path=Path("C:/Synthetic/config.yaml"),
        database_path=Path("C:/Synthetic/state/gatehouse.db"),
        agent_port=48_101,
        admin_port=48_102,
        readiness_timeout_seconds=1.0,
        restart_policy=RestartPolicy(),
        expected_config_digest="a" * 64,
        environment=environment,
    )


@pytest.mark.parametrize("platform", ["nt", "posix"])
@pytest.mark.parametrize("action", ["run", "start"])
def test_native_daemon_adapter_preserves_capture_and_copies_each_process_environment(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    action: str,
) -> None:
    source = _valid_environment()
    runner = local.NativeDaemonProcessRunner(environment=source)
    source["appdata"] = "C:\\Synthetic\\Changed"
    source["INJECTED"] = CANARY
    assert isinstance(runner._environment, MappingProxyType)
    assert dict(runner._environment) == EXPECTED
    with pytest.raises(TypeError):
        cast(dict[str, str], runner._environment)["APPDATA"] = CANARY

    environments: list[dict[str, str]] = []
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    child = SimpleNamespace(returncode=17)

    def spawn(arguments: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        environment = kwargs["env"]
        assert type(environment) is dict and environment == EXPECTED
        environments.append(cast(dict[str, str], environment))
        calls.append((arguments, dict(kwargs)))
        cast(dict[str, str], environment)["ADAPTER_MUTATION"] = CANARY
        return child

    monkeypatch.setattr(local, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(
        local,
        "subprocess",
        SimpleNamespace(
            run=spawn,
            Popen=spawn,
            DEVNULL=-3,
            CREATE_NO_WINDOW=1,
            DETACHED_PROCESS=2,
            CREATE_NEW_PROCESS_GROUP=4,
        ),
    )
    for _ in range(2):
        result = runner.run(ARGUMENTS) if action == "run" else runner.start(ARGUMENTS)
        assert result == 17 if action == "run" else result is child
    assert environments[0] is not environments[1]
    assert dict(runner._environment) == EXPECTED
    assert [arguments for arguments, _ in calls] == [ARGUMENTS, ARGUMENTS]
    for _, options in calls:
        assert options.get("shell", False) is False
        if action == "run":
            assert options["check"] is False
        else:
            assert options["stdin"] == options["stdout"] == options["stderr"] == -3
            assert (
                options["creationflags"] == 7
                if platform == "nt"
                else options["start_new_session"] is True
            )


@pytest.mark.parametrize("consumer", ["native", "backend", "settings", "watchdog_load"])
@pytest.mark.parametrize("defect", ["malformed", "oversize", "duplicate"])
def test_environment_construction_refuses_before_default_path_capture_or_process_setup(
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
    defect: str,
) -> None:
    monkeypatch.setattr(local, "default_config_path", _forbidden)
    monkeypatch.setattr(watchdog, "load_runtime_configuration", _forbidden)
    environment = _invalid_environment(defect)
    if consumer == "backend":
        monkeypatch.setattr(local, "NativeDaemonProcessRunner", _forbidden)
    with pytest.raises(EnvironmentValidationError) as caught:
        if consumer == "native":
            local.NativeDaemonProcessRunner(environment=environment)
        elif consumer == "backend":
            local.LocalCliBackend(environment=environment)
        elif consumer == "settings":
            _settings(environment)
        else:
            watchdog._load_runtime_settings(
                "C:/Synthetic/config.yaml",
                expected_config_digest="a" * 64,
                environment=environment,
            )
    assert str(caught.value) == ERROR
    assert CANARY not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_watchdog_settings_freeze_only_the_validated_environment() -> None:
    source = _valid_environment()
    settings = _settings(source)
    source.clear()
    assert isinstance(settings.environment, MappingProxyType)
    assert dict(settings.environment) == EXPECTED
    with pytest.raises(TypeError):
        cast(dict[str, str], settings.environment)["APPDATA"] = CANARY


def test_local_backend_forwards_the_same_frozen_expansion_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _valid_environment()
    observed: list[dict[str, str]] = []

    def default_path(*, environment: Mapping[str, str]) -> Path:
        observed.append(dict(environment))
        return Path("C:/Synthetic/config.yaml")

    monkeypatch.setattr(local, "default_config_path", default_path)
    backend = local.LocalCliBackend(environment=source)
    source.clear()
    assert observed == [EXPECTED]
    assert dict(backend._environment) == EXPECTED
    assert isinstance(backend._environment, MappingProxyType)
    runner = backend._daemon_processes
    assert isinstance(runner, local.NativeDaemonProcessRunner)
    assert dict(runner._environment) == EXPECTED


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", ["nt", "posix"])
async def test_watchdog_spawn_enforces_environment_at_actual_subprocess_boundary(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
) -> None:
    settings = _settings(_valid_environment())
    environments: list[dict[str, str]] = []
    child = SimpleNamespace(returncode=None)

    async def spawn(*arguments: str, **kwargs: object) -> SimpleNamespace:
        assert arguments == ARGUMENTS
        environment = kwargs["env"]
        assert type(environment) is dict and environment == EXPECTED
        environments.append(cast(dict[str, str], environment))
        cast(dict[str, str], environment)["ADAPTER_MUTATION"] = CANARY
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == -3
        assert kwargs.get("shell", False) is False
        assert (
            kwargs["creationflags"] == 7
            if platform == "nt"
            else kwargs["start_new_session"] is True
        )
        return child

    monkeypatch.setattr(watchdog, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(
        watchdog,
        "subprocess",
        SimpleNamespace(
            DEVNULL=-3,
            CREATE_NO_WINDOW=1,
            DETACHED_PROCESS=2,
            CREATE_NEW_PROCESS_GROUP=4,
        ),
    )
    monkeypatch.setattr(watchdog, "asyncio", SimpleNamespace(create_subprocess_exec=spawn))
    assert await watchdog._spawn_daemon(ARGUMENTS, environment=settings.environment) is cast(
        object, child
    )
    assert await watchdog._spawn_daemon(ARGUMENTS, environment=settings.environment) is cast(
        object, child
    )
    assert environments[0] is not environments[1]
    assert dict(settings.environment) == EXPECTED


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", ["nt", "posix"])
@pytest.mark.parametrize("defect", ["malformed", "oversize", "duplicate"])
async def test_watchdog_spawn_rejects_invalid_supplied_environment_before_process_call(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    defect: str,
) -> None:
    monkeypatch.setattr(watchdog, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(watchdog, "asyncio", SimpleNamespace(create_subprocess_exec=_forbidden))
    with pytest.raises(EnvironmentValidationError, match=ERROR):
        await watchdog._spawn_daemon(ARGUMENTS, environment=_invalid_environment(defect))


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupted", [False, True])
async def test_watchdog_restart_refuses_environment_error_but_preserves_interruption(
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    settings = _settings(EXPECTED)
    monkeypatch.setattr(
        watchdog, "_locate_daemon_executable", lambda _requested: Path(ARGUMENTS[0])
    )
    monkeypatch.setattr(watchdog, "_probe", _forbidden)
    failure = KeyboardInterrupt(CANARY) if interrupted else EnvironmentValidationError()

    async def refused(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise failure

    monkeypatch.setattr(watchdog, "_spawn_daemon", refused)
    if interrupted:
        with pytest.raises(KeyboardInterrupt) as caught:
            await watchdog._restart(settings)
        assert caught.value is failure
    else:
        assert await watchdog._restart(settings) is False


@pytest.mark.parametrize("module", [daemon_main, watchdog], ids=["daemon", "watchdog"])
@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("defect", ["malformed", "oversize", "duplicate"])
def test_entrypoint_environment_refusal_precedes_parser_discovery_and_effects(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module: object,
    ambient: bool,
    defect: str,
) -> None:
    class GuardedEnvironment(dict[str, str]):
        def clear(self) -> None:
            _forbidden()

        def update(self, *args: object, **kwargs: object) -> None:
            _forbidden(*args, **kwargs)

    environment = GuardedEnvironment(_invalid_environment(defect))
    entrypoint = cast(SimpleNamespace, module)
    monkeypatch.setattr(entrypoint, "ensure_standard_streams", lambda: None)
    monkeypatch.setattr(entrypoint, "os", SimpleNamespace(environ=environment))
    monkeypatch.setattr(entrypoint, "_parser", _forbidden)
    if module is daemon_main:
        monkeypatch.setattr(entrypoint, "default_config_path", _forbidden)
        monkeypatch.setattr(entrypoint, "run_stock_daemon", _forbidden)
    else:
        monkeypatch.setattr(entrypoint, "_default_config_path", _forbidden)
        monkeypatch.setattr(entrypoint, "_load_runtime_settings", _forbidden)
        monkeypatch.setattr(entrypoint, "_run", _forbidden)
    with pytest.raises(SystemExit) as caught:
        entrypoint.main(["--config", CANARY], environment=None if ambient else environment)
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert output.out == "" and ERROR in output.err and CANARY not in output.err


@pytest.mark.parametrize("module", [daemon_main, watchdog], ids=["daemon", "watchdog"])
def test_entrypoint_environment_capture_preserves_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
    module: object,
) -> None:
    entrypoint = cast(SimpleNamespace, module)
    failure = KeyboardInterrupt(CANARY)

    def interrupted(_environment: Mapping[str, str]) -> dict[str, str]:
        raise failure

    monkeypatch.setattr(entrypoint, "ensure_standard_streams", lambda: None)
    monkeypatch.setattr(entrypoint, "build_long_lived_environment", interrupted)
    monkeypatch.setattr(entrypoint, "_parser", _forbidden)
    with pytest.raises(KeyboardInterrupt) as caught:
        entrypoint.main([], environment={})
    assert caught.value is failure


@pytest.mark.parametrize("defect", ["malformed", "oversize", "duplicate"])
@pytest.mark.parametrize(
    "command",
    [
        ["status"],
        ["--config", CANARY, "config", "init"],
        [
            "credentials",
            "provision",
            "--mutation-id",
            "synthetic",
            "--principal-id",
            "synthetic",
            "--quota-scope-id",
            "synthetic",
            "--pool-id",
            "synthetic",
            "--alias",
            "synthetic",
        ],
    ],
    ids=["status", "config_init", "credential_prompt"],
)
def test_cli_factory_invalid_environment_is_import_safe_and_refuses_before_command_effects(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
    command: list[str],
) -> None:
    monkeypatch.setattr(local, "default_config_path", _forbidden)
    monkeypatch.setattr(UnavailableCliBackend, "set_config_path", _forbidden)
    monkeypatch.setattr(UnavailableCliBackend, "config_init", _forbidden)
    monkeypatch.setattr(UnavailableCliBackend, "status", _forbidden)
    monkeypatch.setattr(InteractiveSecretReader, "read_secret", _forbidden)
    monkeypatch.setattr(local.NativeProcessRunner, "run", _forbidden)
    app = cli_main._create_default_cli_app(environment=_invalid_environment(defect))
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 2
    assert ERROR in result.output and CANARY not in result.output


def test_cli_factory_preserves_environment_capture_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = KeyboardInterrupt(CANARY)

    def interrupted(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise failure

    monkeypatch.setattr(cli_main, "LocalCliBackend", interrupted)
    with pytest.raises(KeyboardInterrupt) as caught:
        cli_main._create_default_cli_app(environment={})
    assert caught.value is failure


@pytest.mark.parametrize("action", ["run", "start"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_native_process_errors_keep_existing_refusal_and_interruption_behavior(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    interrupted: bool,
) -> None:
    runner = local.NativeDaemonProcessRunner(environment=EXPECTED)
    failure = KeyboardInterrupt(CANARY) if interrupted else OSError(CANARY)

    def failed(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise failure

    monkeypatch.setattr(local, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(local, "subprocess", SimpleNamespace(run=failed, Popen=failed, DEVNULL=-3))
    if interrupted:
        with pytest.raises(KeyboardInterrupt) as caught:
            runner.run(ARGUMENTS) if action == "run" else runner.start(ARGUMENTS)
        assert caught.value is failure
    else:
        with pytest.raises(CliUnavailable) as unavailable:
            runner.run(ARGUMENTS) if action == "run" else runner.start(ARGUMENTS)
        assert str(unavailable.value) == "the installed Gatehouse daemon could not be started"
