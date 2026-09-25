"""Watchdog handoff checks with explicit in-memory configuration and child adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from gatehouse.config import MainConfig
from gatehouse.config.security import ConfigSecurityError, ConfigurationSnapshot
from gatehouse.daemon.configuration import RuntimeConfiguration
from gatehouse.daemon.main import _parser as daemon_parser
from gatehouse.watchdog import ProbeResult
from gatehouse.watchdog import main as watchdog
from gatehouse.watchdog.controller import ProbeAttestation

CONFIG = Path(r"C:\synthetic\config\config.yaml")
DIGEST = "a" * 64
ENVIRONMENT = {"APPDATA": r"C:\synthetic\roaming", "LOCALAPPDATA": r"C:\synthetic\local"}


def _runtime() -> RuntimeConfiguration:
    main = SimpleNamespace(
        server=SimpleNamespace(
            agent=SimpleNamespace(port=47621),
            admin=SimpleNamespace(port=47622),
        ),
        database=SimpleNamespace(path=r"C:\synthetic\state\gatehouse.db"),
        watchdog=SimpleNamespace(
            readiness_timeout=1000,
            maximum_restarts=5,
            restart_window=60000,
            crash_loop_cooldown=300000,
        ),
        firecrawl_workload=SimpleNamespace(mode="disabled"),
        firecrawl_observer=SimpleNamespace(mode="disabled"),
    )
    snapshot = ConfigurationSnapshot(CONFIG, "config.yaml", (), DIGEST, tuple(ENVIRONMENT.items()))
    return RuntimeConfiguration(cast(MainConfig, main), (), (), (), snapshot)


def _install_capture(
    monkeypatch: pytest.MonkeyPatch,
    runtime: RuntimeConfiguration,
) -> list[tuple[str | Path, dict[str, str], str]]:
    calls: list[tuple[str | Path, dict[str, str], str]] = []

    def capture(
        path: str | Path,
        *,
        environment: Mapping[str, str],
        expected_config_digest: str,
    ) -> RuntimeConfiguration:
        calls.append((path, dict(environment), expected_config_digest))
        return runtime

    monkeypatch.setattr(watchdog, "load_runtime_configuration", capture)
    return calls


@pytest.mark.parametrize("expected", (None, 1, "", "A" * 64, "a" * 63, "a" * 64 + "\n"))
def test_settings_reject_bad_expectation_before_capture(
    monkeypatch: pytest.MonkeyPatch,
    expected: object,
) -> None:
    calls = _install_capture(monkeypatch, _runtime())
    with pytest.raises(ConfigSecurityError, match="expected configuration digest"):
        watchdog._load_runtime_settings(
            CONFIG,
            expected_config_digest=cast(str, expected),
            environment=ENVIRONMENT,
        )
    assert calls == []


@pytest.mark.parametrize("defect", ("missing", "digest", "origin", "raw_alias"))
def test_settings_reject_snapshot_defects_before_state_or_process(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    runtime = _runtime()
    snapshot = runtime.snapshot
    assert snapshot is not None
    path: str | Path = CONFIG
    if defect == "missing":
        runtime = replace(runtime, snapshot=None)
    elif defect == "digest":
        runtime = replace(runtime, snapshot=replace(snapshot, manifest_digest="b" * 64))
    elif defect == "origin":
        runtime = replace(
            runtime, snapshot=replace(snapshot, main_path=CONFIG.with_name("other.yaml"))
        )
    else:
        path = r"C:\synthetic\config\.\config.yaml"
    calls = _install_capture(monkeypatch, runtime)
    monkeypatch.setattr(watchdog, "secure_database_state", lambda *a, **k: pytest.fail("state"))
    monkeypatch.setattr(watchdog, "_run", lambda *a, **k: pytest.fail("runtime"))
    with pytest.raises(SystemExit) as caught:
        watchdog.main(
            ["--config", str(path), "--expected-config-digest", DIGEST],
            environment=ENVIRONMENT,
        )
    assert caught.value.code == 2
    assert calls == [(path, ENVIRONMENT, DIGEST)] or calls == [(str(path), ENVIRONMENT, DIGEST)]


@pytest.mark.parametrize(
    "arguments",
    (
        [],
        ["--expected-config-digest", "SECRET-CANARY"],
        ["--expected-config-digest", DIGEST, "--expected-config-digest", DIGEST],
    ),
)
def test_parser_rejects_missing_invalid_or_duplicate_digest_without_echo(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        watchdog._parser(environment=ENVIRONMENT).parse_args(arguments)
    assert caught.value.code == 2
    assert "SECRET-CANARY" not in capsys.readouterr().err


@pytest.mark.parametrize("override", ("port", "database"))
def test_override_cannot_diverge_from_digest_bound_child_configuration(
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    _install_capture(monkeypatch, _runtime())
    monkeypatch.setattr(watchdog, "validate_state_path_ancestry", lambda path: Path(path))
    monkeypatch.setattr(Path, "resolve", lambda path, **_: path)
    options: dict[str, object] = (
        {"agent_port": 47623}
        if override == "port"
        else {
            "database_path": Path(r"C:\synthetic\other\gatehouse.db"),
        }
    )
    with pytest.raises(ValueError, match="differs from the verified configuration"):
        watchdog._load_runtime_settings(
            CONFIG,
            expected_config_digest=DIGEST,
            environment=ENVIRONMENT,
            **options,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_watchdog_forwards_expected_digest_and_frozen_environment_to_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_capture(monkeypatch, _runtime())
    supplied = {**ENVIRONMENT, "FAKE_SECRET": "excluded"}
    settings = watchdog._load_runtime_settings(
        CONFIG,
        expected_config_digest=DIGEST,
        environment=supplied,
    )
    assert settings.agent_port == 47621 and settings.admin_port == 47622
    supplied["APPDATA"] = r"C:\synthetic\changed"
    observed: list[tuple[tuple[str, ...], dict[str, str]]] = []
    child = SimpleNamespace(returncode=None)

    async def spawn(arguments: tuple[str, ...], *, environment: Mapping[str, str]) -> object:
        observed.append((arguments, dict(environment)))
        return child

    async def ready() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    monkeypatch.setattr(watchdog, "_spawn_daemon", spawn)
    monkeypatch.setattr(
        watchdog,
        "sys",
        SimpleNamespace(executable=r"C:\synthetic\bin\pythonw.exe"),
    )
    monkeypatch.setattr(watchdog, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(Path, "is_file", lambda _: True)
    assert await watchdog._restart(
        settings,
        daemon_executable=Path(r"C:\synthetic\bin\gatehoused.exe"),
        probe=ready,
    )
    assert len(calls) == 1
    parsed = daemon_parser(environment=ENVIRONMENT).parse_args(observed[0][0][1:])
    assert parsed.expected_config_digest == DIGEST
    assert parsed.config == str(CONFIG)
    assert observed[0][1] == calls[0][1] == ENVIRONMENT
    with pytest.raises(TypeError):
        settings.environment["APPDATA"] = "changed"  # type: ignore[index]


def test_watchdog_requires_both_channels_disabled_for_disabled_startup_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    cast(SimpleNamespace, runtime.main).firecrawl_observer.mode = "live"
    _install_capture(monkeypatch, runtime)
    settings = watchdog._load_runtime_settings(
        CONFIG,
        expected_config_digest=DIGEST,
        environment=ENVIRONMENT,
    )
    assert not settings.allow_provider_disabled_state
