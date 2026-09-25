"""Consumer handoff contracts with explicit in-memory configuration/process adapters."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

from gatehouse.admin.control import CONTROL_CAPABILITY_HEADER, CONTROL_CONFIG_DIGEST_HEADER
from gatehouse.cli import local, operator
from gatehouse.cli.contracts import CliUnavailable, ControlledLaunch
from gatehouse.config import MainConfig
from gatehouse.config.security import ConfigSecurityError, ConfigurationSnapshot
from gatehouse.daemon.configuration import (
    RuntimeConfiguration,
    require_configuration_snapshot_digest,
)
from gatehouse.daemon.main import _parser as daemon_parser

CONFIG = Path(r"C:\synthetic\config\config.yaml")
EXECUTABLE = Path(r"C:\synthetic\bin\gatehoused.exe")
INTERPRETER = r"C:\synthetic\bin\pythonw.exe"
ENVIRONMENT = {"APPDATA": r"C:\synthetic\roaming", "LOCALAPPDATA": r"C:\synthetic\local"}


def _runtime(
    digest: str, *, workload: str = "disabled", observer: str = "disabled"
) -> RuntimeConfiguration:
    # Only the consumer-visible model fields are supplied. This is not native trust evidence.
    main = SimpleNamespace(
        schema_version=1,
        server=SimpleNamespace(
            agent=SimpleNamespace(host="127.0.0.1", port=47621),
            admin=SimpleNamespace(host="127.0.0.1", port=47622),
        ),
        database=SimpleNamespace(path=r"C:\synthetic\state\gatehouse.db"),
        watchdog=SimpleNamespace(readiness_timeout=1000),
        firecrawl_workload=SimpleNamespace(mode=workload),
        firecrawl_observer=SimpleNamespace(mode=observer),
    )
    snapshot = ConfigurationSnapshot(CONFIG, "config.yaml", (), digest, tuple(ENVIRONMENT.items()))
    return RuntimeConfiguration(cast(MainConfig, main), (), (), (), snapshot)


class _Capture:
    def __init__(self) -> None:
        self.content = b"synthetic configuration revision one"
        self.calls: list[tuple[str | Path, dict[str, str], str | None]] = []
        self.workload = "disabled"
        self.observer = "disabled"
        self.substitute: RuntimeConfiguration | None = None

    def digest(self, environment: Mapping[str, str]) -> str:
        # The fake snapshot revision binds synthetic bytes and expansion inputs.
        bindings = tuple((key, environment.get(key)) for key in ("APPDATA", "LOCALAPPDATA"))
        return hashlib.sha256(self.content + repr(bindings).encode("utf-8")).hexdigest()

    def __call__(
        self,
        path: str | Path,
        *,
        environment: Mapping[str, str],
        expected_config_digest: str | None = None,
    ) -> RuntimeConfiguration:
        self.calls.append((path, dict(environment), expected_config_digest))
        if self.substitute is not None:
            return self.substitute
        runtime = _runtime(self.digest(environment), workload=self.workload, observer=self.observer)
        if expected_config_digest is not None:
            require_configuration_snapshot_digest(runtime.snapshot, expected_config_digest)
        return runtime


class _Child:
    def __init__(self) -> None:
        self.exit_code: int | None = None
        self.terminated = False
        self.terminate_calls = 0
        self.waited: list[float] = []

    def poll(self) -> int | None:
        return self.exit_code

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.terminated = True
        self.exit_code = 1

    def wait(self, timeout: float) -> int:
        self.waited.append(timeout)
        assert timeout == 1.0
        assert self.exit_code is not None
        return self.exit_code


class _Processes:
    def __init__(self) -> None:
        self.arguments: list[tuple[str, ...]] = []
        self.child = _Child()

    def run(self, arguments: Sequence[str]) -> int:
        self.arguments.append(tuple(arguments))
        return 0

    def start(self, arguments: Sequence[str]) -> _Child:
        self.arguments.append(tuple(arguments))
        return self.child


def _backend(
    monkeypatch: pytest.MonkeyPatch,
    capture: _Capture,
    *,
    environment: Mapping[str, str] | None = None,
) -> tuple[local.LocalCliBackend, _Processes]:
    processes = _Processes()
    monkeypatch.setattr(local, "load_runtime_configuration", capture)
    monkeypatch.setattr(operator, "load_runtime_configuration", capture)
    monkeypatch.setattr(
        local,
        "sys",
        SimpleNamespace(executable=INTERPRETER),
    )
    monkeypatch.setattr(local, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(Path, "is_file", lambda path: path == EXECUTABLE)
    backend = local.LocalCliBackend(
        config_path=CONFIG,
        environment=ENVIRONMENT if environment is None else environment,
        daemon_processes=processes,
        daemon_executable=EXECUTABLE,
        capability_loader=lambda _: "c" * 43,
        transport_factory=lambda: httpx.MockTransport(lambda _: httpx.Response(200)),
        sleep=lambda _: None,
    )
    return backend, processes


def _status(state: str, ready: bool, *, config_digest: str) -> local.JsonObject:
    return {
        "status": state,
        "ready": ready,
        "version": "synthetic",
        "schema_version": 16,
        "policy_version": "synthetic",
        "uptime_seconds": 0,
        "degraded_components": [],
        "config_digest": config_digest,
    }


@pytest.mark.parametrize("action", ("run", "start"))
@pytest.mark.parametrize("expected", (None, 1, "", "a" * 63, "A" * 64, "a" * 64 + "\n"))
def test_launch_rejects_invalid_expectation_before_capture_or_effects(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    expected: object,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    monkeypatch.setattr(local.LocalCliBackend, "_control_status", lambda _: pytest.fail("control"))
    with pytest.raises(CliUnavailable, match="expected configuration digest"):
        getattr(backend, f"daemon_{action}")(expected_config_digest=expected)
    assert capture.calls == []
    assert processes.arguments == []


@pytest.mark.parametrize("change", ("bytes", "environment"))
def test_validate_then_launch_rejects_changed_snapshot_before_control(
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    validated = backend.config_validate(explain=False)
    snapshot = cast(dict[str, str], validated["snapshot"])
    expected = snapshot["digest"]
    if change == "bytes":
        capture.content = b"synthetic configuration revision two"
    else:
        backend, processes = _backend(
            monkeypatch,
            capture,
            environment={**ENVIRONMENT, "APPDATA": r"C:\synthetic\other"},
        )
    monkeypatch.setattr(local.LocalCliBackend, "_control_status", lambda _: pytest.fail("control"))
    with pytest.raises(CliUnavailable):
        backend.daemon_start(expected_config_digest=expected)
    assert len(capture.calls) == 2
    assert capture.calls[-1][2] == expected
    assert processes.arguments == []


def test_validate_fresh_capture_forward_and_child_expectation_are_continuous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    supplied_environment = {**ENVIRONMENT, "PATH": r"C:\synthetic\bin", "FAKE_SECRET": "excluded"}
    backend, processes = _backend(monkeypatch, capture, environment=supplied_environment)
    expected = cast(dict[str, str], backend.config_validate(explain=False)["snapshot"])["digest"]
    supplied_environment["APPDATA"] = r"C:\synthetic\changed-after-construction"
    assert backend.daemon_run(expected_config_digest=expected)["exit_code"] == 0
    arguments = processes.arguments[0]
    parsed = daemon_parser(environment=ENVIRONMENT).parse_args(arguments[1:])
    assert parsed.expected_config_digest == expected
    assert parsed.config == str(CONFIG)
    assert len(capture.calls) == 2
    assert capture.calls[0][2] is None
    assert capture.calls[1][2] == expected
    assert capture.calls[0][1] == capture.calls[1][1]
    assert "FAKE_SECRET" not in capture.calls[1][1]
    child_snapshot = capture(CONFIG, environment=capture.calls[1][1]).snapshot
    require_configuration_snapshot_digest(child_snapshot, parsed.expected_config_digest)
    capture.content = b"changed between parent capture and child capture"
    with pytest.raises(ConfigSecurityError, match="expected digest"):
        require_configuration_snapshot_digest(
            capture(CONFIG, environment=capture.calls[1][1]).snapshot,
            parsed.expected_config_digest,
        )


@pytest.mark.parametrize("defect", ("missing", "digest", "origin"))
def test_consumer_rechecks_substituted_loader_snapshot_before_control(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    capture = _Capture()
    expected = capture.digest(ENVIRONMENT)
    runtime = _runtime(expected)
    snapshot = runtime.snapshot
    assert snapshot is not None
    if defect == "missing":
        runtime = replace(runtime, snapshot=None)
    elif defect == "digest":
        runtime = replace(runtime, snapshot=replace(snapshot, manifest_digest="b" * 64))
    else:
        runtime = replace(
            runtime, snapshot=replace(snapshot, main_path=CONFIG.with_name("other.yaml"))
        )
    capture.substitute = runtime
    backend, processes = _backend(monkeypatch, capture)
    monkeypatch.setattr(local.LocalCliBackend, "_control_status", lambda _: pytest.fail("control"))
    with pytest.raises(CliUnavailable):
        backend.daemon_start(expected_config_digest=expected)
    assert processes.arguments == []


def test_raw_config_spelling_reaches_capture_without_path_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    raw = r"C:\synthetic\config\.\config.yaml"
    backend.set_config_path(raw)
    with pytest.raises(CliUnavailable):
        backend.daemon_run(expected_config_digest=capture.digest(ENVIRONMENT))
    assert capture.calls[0][0] == raw
    assert processes.arguments == []


@pytest.mark.parametrize(
    "state,ready",
    (
        ("READY", True),
        ("READY", False),
        ("DEGRADED_NO_PROVIDER", False),
        ("DEGRADED_NO_PROVIDER", True),
        ("FAILED_CLOSED", False),
        ("FAILED_CLOSED", True),
        ("DEGRADED_READ_ONLY", False),
        ("DRAINING", False),
        ("STOPPED", False),
    ),
)
@pytest.mark.parametrize(
    "workload,observer",
    (
        ("disabled", "disabled"),
        ("live", "disabled"),
        ("disabled", "live"),
    ),
)
@pytest.mark.parametrize("already_running", (False, True))
def test_startup_accepts_only_consistent_ready_or_fully_disabled_state(
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    ready: bool,
    workload: str,
    observer: str,
    already_running: bool,
) -> None:
    capture = _Capture()
    capture.workload, capture.observer = workload, observer
    backend, processes = _backend(monkeypatch, capture)
    calls = 0

    def control(instance: local.LocalCliBackend) -> local.JsonObject:
        nonlocal calls
        calls += 1
        settings = instance._settings()
        if not already_running and calls == 1:
            raise local._LoopbackRequestError("synthetic unavailable")
        return _status(state, ready, config_digest=settings.config_digest)

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    monkeypatch.setattr(local.LocalCliBackend, "_agent_live", lambda _: False)
    accepted = (state == "READY" and ready) or (
        state == "DEGRADED_NO_PROVIDER" and not ready and workload == observer == "disabled"
    )
    if accepted:
        result = backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
        assert result["started"] is (not already_running)
        assert result["ready"] is ready
    else:
        with pytest.raises(CliUnavailable, match="startup state"):
            backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
    assert len(capture.calls) == 1
    assert processes.child.terminated is (not accepted and not already_running)


def test_operation_snapshot_and_capability_cache_expire_between_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, _ = _backend(monkeypatch, capture)
    loaded: list[Path] = []

    def capability(path: Path) -> str:
        loaded.append(path)
        return "c" * 43

    monkeypatch.setattr(backend, "_capability_loader", capability)
    monkeypatch.setattr(
        local,
        "installation_state_paths",
        lambda _: SimpleNamespace(
            control_capability=Path(r"C:\synthetic\state\control-capability.dpapi")
        ),
    )

    def control(instance: local.LocalCliBackend) -> local.JsonObject:
        first = instance._settings()
        assert instance._capability() == instance._capability()
        capture.content = b"changed during control operation"
        assert instance._settings() is first
        return _status("READY", True, config_digest=first.config_digest)

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    backend.daemon_status()
    backend.daemon_status()
    assert len(capture.calls) == 2
    assert len(loaded) == 2
    assert backend._configuration_context.get() is None


def test_native_daemon_adapter_uses_the_same_frozen_environment_as_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    source = {**ENVIRONMENT, "PATH": r"C:\synthetic\bin", "FAKE_SECRET": "excluded"}
    observed: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def run(arguments: tuple[str, ...], *, check: bool, env: Mapping[str, str]) -> object:
        assert check is False
        observed.append((arguments, dict(env)))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(local, "load_runtime_configuration", capture)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        local,
        "sys",
        SimpleNamespace(executable=INTERPRETER),
    )
    monkeypatch.setattr(local, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(Path, "is_file", lambda path: path == EXECUTABLE)
    backend = local.LocalCliBackend(
        config_path=CONFIG,
        environment=source,
        daemon_executable=EXECUTABLE,
    )
    expected = capture.digest(source)
    source["APPDATA"] = r"C:\synthetic\changed"
    assert backend.daemon_run(expected_config_digest=expected)["exit_code"] == 0
    assert observed[0][1] == capture.calls[0][1]
    assert "FAKE_SECRET" not in observed[0][1]
    assert observed[0][0][-2:] == ("--expected-config-digest", expected)


@pytest.mark.parametrize("already_running", (False, True))
def test_startup_rejects_readiness_returned_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
    already_running: bool,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    now = [0.0]
    calls = 0
    monkeypatch.setattr(backend, "_monotonic", lambda: now[0])

    def control(instance: local.LocalCliBackend) -> local.JsonObject:
        nonlocal calls
        calls += 1
        if not already_running and calls == 1:
            raise local._LoopbackRequestError("synthetic unavailable")
        now[0] = 1.01
        return _status("READY", True, config_digest=instance._settings().config_digest)

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    monkeypatch.setattr(local.LocalCliBackend, "_agent_live", lambda _: False)
    with pytest.raises(CliUnavailable, match="in time"):
        backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
    assert processes.child.terminated is (not already_running)


def test_startup_checks_budget_before_another_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    now = [0.0]
    calls = 0
    monkeypatch.setattr(backend, "_monotonic", lambda: now[0])
    monkeypatch.setattr(backend, "_sleep", lambda _: now.__setitem__(0, 1.01))

    def control(instance: local.LocalCliBackend) -> local.JsonObject:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise local._LoopbackRequestError("synthetic unavailable")
        assert calls == 2
        return _status("RECOVERING", False, config_digest=instance._settings().config_digest)

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    monkeypatch.setattr(local.LocalCliBackend, "_agent_live", lambda _: False)
    with pytest.raises(CliUnavailable, match="in time"):
        backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
    assert calls == 2
    assert processes.child.terminated


def test_startup_caps_http_phase_timeouts_to_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, _ = _backend(monkeypatch, capture)
    now = [0.0]
    observed: list[dict[str, float]] = []
    monkeypatch.setattr(backend, "_monotonic", lambda: now[0])
    monkeypatch.setattr(
        local,
        "installation_state_paths",
        lambda _: SimpleNamespace(control_capability=Path(r"C:\synthetic\control.dpapi")),
    )

    def response(request: httpx.Request) -> httpx.Response:
        observed.append(request.extensions["timeout"])
        now[0] = 0.75
        if len(observed) == 1:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"status": "live"})

    monkeypatch.setattr(backend, "_transport_factory", lambda: httpx.MockTransport(response))
    with pytest.raises(CliUnavailable, match="control authentication"):
        backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
    assert len(observed) == 2
    assert all(value == 1.0 for value in observed[0].values())
    assert all(value == 0.25 for value in observed[1].values())


def test_failed_start_reports_unconfirmed_owned_child_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    calls = 0
    waited: list[float] = []

    def control(instance: local.LocalCliBackend) -> local.JsonObject:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise local._LoopbackRequestError("synthetic unavailable")
        return _status("FAILED_CLOSED", False, config_digest=instance._settings().config_digest)

    def wait(timeout: float) -> int:
        waited.append(timeout)
        raise subprocess.TimeoutExpired("synthetic-owned-child", timeout)

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    monkeypatch.setattr(local.LocalCliBackend, "_agent_live", lambda _: False)
    monkeypatch.setattr(processes.child, "terminate", lambda: None)
    monkeypatch.setattr(processes.child, "wait", wait)
    with pytest.raises(CliUnavailable, match="owned daemon child exit could not be confirmed"):
        backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
    assert waited == [1.0]
    assert processes.child.poll() is None


_ATTESTATION_FAILURE = (
    "the Gatehouse daemon configuration does not match the verified configuration"
)


def _startup_responses(
    monkeypatch: pytest.MonkeyPatch,
    bodies: list[local.JsonObject],
    *,
    already_running: bool,
) -> list[str]:
    probes: list[str] = []
    pending = list(bodies)

    def control(_: local.LocalCliBackend) -> local.JsonObject:
        probes.append("control")
        if not already_running and len(probes) == 1:
            raise local._LoopbackRequestError("synthetic unavailable")
        assert pending, "unexpected retry after an authenticated response"
        return pending.pop(0)

    def live(_: local.LocalCliBackend) -> bool:
        assert not already_running, "an authenticated responder must not become absent"
        assert probes == ["control"]
        probes.append("live")
        return False

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    monkeypatch.setattr(local.LocalCliBackend, "_agent_live", live)
    monkeypatch.setattr(
        local.LocalCliBackend,
        "_control_request",
        lambda *args, **kwargs: pytest.fail("startup must not mutate a remote daemon"),
    )
    return probes


@pytest.mark.parametrize(
    "defect",
    (
        "missing",
        "null",
        "bool",
        "number",
        "uppercase",
        "leading_space",
        "trailing_space",
        "newline",
        "short",
        "long",
        "nonhex",
        "mismatch",
    ),
)
@pytest.mark.parametrize("already_running", (False, True))
def test_startup_refuses_unattested_control_status_without_fallback_or_retry(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
    already_running: bool,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    expected = capture.digest(ENVIRONMENT)
    invalid: dict[str, object] = {
        "null": None,
        "bool": True,
        "number": 7,
        "uppercase": expected.upper(),
        "leading_space": " " + expected,
        "trailing_space": expected + " ",
        "newline": expected + "\n",
        "short": expected[:-1],
        "long": expected + "0",
        "nonhex": "z" * 64,
        "mismatch": "b" * 64,
    }
    body = dict(_status("READY", True, config_digest=expected))
    if defect == "missing":
        del body["config_digest"]
    else:
        body["config_digest"] = invalid[defect]  # type: ignore[assignment]
    probes = _startup_responses(monkeypatch, [body], already_running=already_running)

    with pytest.raises(CliUnavailable) as raised:
        backend.daemon_start(expected_config_digest=expected)

    assert str(raised.value) == _ATTESTATION_FAILURE
    assert expected not in str(raised.value)
    assert probes == (["control"] if already_running else ["control", "live", "control"])
    assert len(capture.calls) == 1
    assert len(processes.arguments) == (0 if already_running else 1)
    assert processes.child.terminate_calls == (0 if already_running else 1)
    assert processes.child.waited == ([] if already_running else [1.0])
    assert backend._configuration_context.get() is None


@pytest.mark.parametrize("state", ("DEGRADED_NO_PROVIDER", "RECOVERING"))
@pytest.mark.parametrize("already_running", (False, True))
def test_startup_digest_refusal_precedes_disabled_or_recovering_state(
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    already_running: bool,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    probes = _startup_responses(
        monkeypatch,
        [_status(state, False, config_digest="b" * 64)],
        already_running=already_running,
    )
    with pytest.raises(CliUnavailable) as raised:
        backend.daemon_start(expected_config_digest=capture.digest(ENVIRONMENT))
    assert str(raised.value) == _ATTESTATION_FAILURE
    assert probes == (["control"] if already_running else ["control", "live", "control"])
    assert processes.child.terminate_calls == (0 if already_running else 1)
    assert processes.child.waited == ([] if already_running else [1.0])


@pytest.mark.parametrize("matching_ready", (False, True))
def test_owned_startup_rechecks_attestation_after_matching_recovery(
    monkeypatch: pytest.MonkeyPatch,
    matching_ready: bool,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    expected = capture.digest(ENVIRONMENT)
    probes = _startup_responses(
        monkeypatch,
        [
            _status("RECOVERING", False, config_digest=expected),
            _status("READY", True, config_digest=expected if matching_ready else "b" * 64),
        ],
        already_running=False,
    )
    if matching_ready:
        result = backend.daemon_start(expected_config_digest=expected)
        assert result["started"] is True
        assert result["config_digest"] == expected
    else:
        with pytest.raises(CliUnavailable) as raised:
            backend.daemon_start(expected_config_digest=expected)
        assert str(raised.value) == _ATTESTATION_FAILURE
    assert probes == ["control", "live", "control", "control"]
    assert len(processes.arguments) == 1
    assert processes.child.terminate_calls == (0 if matching_ready else 1)
    assert processes.child.waited == ([] if matching_ready else [1.0])


@pytest.mark.parametrize("matching_digest", (False, True))
def test_existing_malformed_startup_response_never_becomes_spawn_fallback(
    monkeypatch: pytest.MonkeyPatch,
    matching_digest: bool,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    expected = capture.digest(ENVIRONMENT)
    body: local.JsonObject = {
        "config_digest": expected if matching_digest else "b" * 64,
        "status": "SYNTHETIC_UNTRUSTED_RESPONSE",
        "ready": "SYNTHETIC_UNTRUSTED_RESPONSE",
    }
    probes = _startup_responses(monkeypatch, [body], already_running=True)
    with pytest.raises(CliUnavailable) as raised:
        backend.daemon_start(expected_config_digest=expected)
    assert str(raised.value) == (
        "the Gatehouse daemon startup response is invalid"
        if matching_digest
        else _ATTESTATION_FAILURE
    )
    assert probes == ["control"]
    assert processes.arguments == []
    assert processes.child.terminate_calls == 0


def test_startup_attestation_uses_operation_capture_and_recaptures_next_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, processes = _backend(monkeypatch, capture)
    first_digest = capture.digest(ENVIRONMENT)

    def control(instance: local.LocalCliBackend) -> local.JsonObject:
        captured = instance._settings()
        capture.content = b"changed during the authenticated status request"
        assert instance._settings() is captured
        return _status("READY", True, config_digest=first_digest)

    monkeypatch.setattr(local.LocalCliBackend, "_control_status", control)
    monkeypatch.setattr(
        local.LocalCliBackend, "_agent_live", lambda _: pytest.fail("live fallback")
    )
    assert (
        backend.daemon_start(expected_config_digest=first_digest)["config_digest"] == first_digest
    )
    second_digest = capture.digest(ENVIRONMENT)
    assert second_digest != first_digest
    with pytest.raises(CliUnavailable) as raised:
        backend.daemon_start(expected_config_digest=second_digest)
    assert str(raised.value) == _ATTESTATION_FAILURE
    assert len(capture.calls) == 2
    assert processes.arguments == []
    assert processes.child.terminate_calls == 0


def _prepare_owned_launch(
    monkeypatch: pytest.MonkeyPatch,
    backend: local.LocalCliBackend,
) -> ControlledLaunch:
    workspace = Path(r"C:\synthetic\workspace")
    monkeypatch.setattr(local, "canonical_existing_directory", lambda _: workspace)
    monkeypatch.setattr(Path, "resolve", lambda path, **_: path)
    monkeypatch.setattr(Path, "is_dir", lambda path: path == workspace)
    monkeypatch.setattr(
        local,
        "installation_state_paths",
        lambda _: SimpleNamespace(control_capability=Path(r"C:\synthetic\control.dpapi")),
    )

    def mint(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "http://127.0.0.1:47622/v2/control/sessions"
        assert request.headers[CONTROL_CAPABILITY_HEADER] == "c" * 43
        assert request.headers[CONTROL_CONFIG_DIGEST_HEADER] == backend._settings().config_digest
        assert json.loads(request.content) == {
            "request_id": json.loads(request.content)["request_id"],
            "client": "synthetic",
            "workspace": "synthetic",
            "working_directory": str(workspace),
            "non_interactive": False,
        }
        return httpx.Response(
            201,
            json={
                "session_id": "ses_owned",
                "bootstrap_capability": "b" * 43,
                "working_directory": str(workspace),
            },
        )

    # A refused second prepare must restore the transport already owning cleanup.
    with monkeypatch.context() as mint_context:
        mint_context.setattr(backend, "_transport_factory", lambda: httpx.MockTransport(mint))
        return backend.prepare_launch(
            client="synthetic",
            workspace="synthetic",
            non_interactive=False,
            command=("synthetic-client",),
        )


def test_launch_cleanup_retains_original_endpoint_and_capability_after_config_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, _ = _backend(monkeypatch, capture)
    expected = capture.digest(ENVIRONMENT)
    launch = _prepare_owned_launch(monkeypatch, backend)
    backend.set_config_path(CONFIG.with_name("changed.yaml"))
    monkeypatch.setattr(
        backend, "_capability_loader", lambda _: pytest.fail("recaptured capability")
    )
    monkeypatch.setattr(
        local, "load_runtime_configuration", lambda *a, **k: pytest.fail("recapture")
    )
    observed: list[httpx.Request] = []

    def response(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert request.url.port == 47622
        assert request.url.path == "/v2/control/sessions/ses_owned/revoke"
        assert request.headers[CONTROL_CAPABILITY_HEADER] == "c" * 43
        assert request.headers[CONTROL_CONFIG_DIGEST_HEADER] == expected
        return httpx.Response(200, json={"session_id": "ses_owned", "state": "REVOKED"})

    monkeypatch.setattr(backend, "_transport_factory", lambda: httpx.MockTransport(response))
    backend.cleanup_launch(launch, revoke=True)
    assert len(capture.calls) == 1
    assert len(observed) == 1
    assert backend._configuration_context.get() is None
    with pytest.raises(CliUnavailable, match="owned controlled launch"):
        backend.cleanup_launch(launch, revoke=True)


def test_unknown_session_request_cleanup_retains_exact_captured_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    backend, _ = _backend(monkeypatch, capture)
    expected = capture.digest(ENVIRONMENT)
    workspace = Path(r"C:\synthetic\workspace")
    monkeypatch.setattr(local, "canonical_existing_directory", lambda _: workspace)
    monkeypatch.setattr(Path, "resolve", lambda path, **_: path)
    monkeypatch.setattr(Path, "is_dir", lambda path: path == workspace)
    monkeypatch.setattr(
        local,
        "installation_state_paths",
        lambda _: SimpleNamespace(control_capability=Path(r"C:\synthetic\control.dpapi")),
    )
    request_ids: list[str] = []
    attempts = 0

    def response(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        assert request.url.port == 47622
        assert request.headers[CONTROL_CAPABILITY_HEADER] == "c" * 43
        assert request.headers[CONTROL_CONFIG_DIGEST_HEADER] == expected
        payload = json.loads(request.content)
        if request.url.path == "/v2/control/sessions":
            request_ids.append(payload["request_id"])
            raise httpx.ReadError("synthetic lost response")
        assert request.url.path == "/v2/control/session-requests/cancel"
        assert payload == {"request_id": request_ids[0]}
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, json={})
        return httpx.Response(
            200,
            json={
                "request_id": request_ids[0],
                "state": "CANCELLED",
                "session_id": None,
            },
        )

    monkeypatch.setattr(backend, "_transport_factory", lambda: httpx.MockTransport(response))
    with pytest.raises(CliUnavailable, match="cleanup is pending"):
        backend.prepare_launch(
            client="synthetic",
            workspace="synthetic",
            non_interactive=False,
            command=("synthetic-client",),
        )
    backend.set_config_path(CONFIG.with_name("changed.yaml"))
    monkeypatch.setattr(
        backend, "_capability_loader", lambda _: pytest.fail("recaptured capability")
    )
    monkeypatch.setattr(
        local, "load_runtime_configuration", lambda *a, **k: pytest.fail("recapture")
    )
    backend.retry_pending_session_cleanup()
    assert attempts == 2 and len(request_ids) == 1
    assert len(capture.calls) == 1
    assert backend._owned_launch is None


@pytest.mark.parametrize("refused_status", (403, 503))
def test_launch_cleanup_refuses_foreign_handle_and_retains_failed_cleanup_for_retry(
    monkeypatch: pytest.MonkeyPatch,
    refused_status: int,
) -> None:
    capture = _Capture()
    backend, _ = _backend(monkeypatch, capture)
    expected = capture.digest(ENVIRONMENT)
    launch = _prepare_owned_launch(monkeypatch, backend)
    observed: list[httpx.Request] = []

    def response(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert request.url.path == "/v2/control/sessions/ses_owned/revoke"
        assert request.headers[CONTROL_CONFIG_DIGEST_HEADER] == expected
        if len(observed) == 1:
            capture.content = b"changed after cleanup attestation was refused"
            return httpx.Response(refused_status, json={})
        return httpx.Response(200, json={"session_id": "ses_owned", "state": "REVOKED"})

    monkeypatch.setattr(backend, "_transport_factory", lambda: httpx.MockTransport(response))
    with pytest.raises(CliUnavailable, match="owned controlled launch"):
        backend.cleanup_launch(replace(launch), revoke=True)
    assert observed == []
    with pytest.raises(CliUnavailable, match="could not be cleaned up"):
        backend.cleanup_launch(launch, revoke=True)
    backend.set_config_path(CONFIG.with_name("changed.yaml"))
    with pytest.raises(CliUnavailable, match="cleanup is pending"):
        _prepare_owned_launch(monkeypatch, backend)
    assert len(capture.calls) == 1
    backend.cleanup_launch(launch, revoke=True)
    assert len(observed) == 2
