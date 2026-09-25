"""Adjacent path selection with pure strings and fake process/metadata adapters."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Never, cast

import pytest

from gatehouse import daemon_executable as selection
from gatehouse.cli import local
from gatehouse.cli.contracts import CliUnavailable
from gatehouse.watchdog import main as watchdog
from gatehouse.watchdog.controller import ProbeAttestation, ProbeResult

ERROR = "the adjacent daemon entry point is unavailable"
INTERPRETER = r"C:\Synthetic\Runtime\Scripts\pythonw.exe"
DAEMON = r"C:\Synthetic\Runtime\Scripts\gatehoused.exe"
CONFIG = Path(r"C:\Synthetic\Configuration\config.yaml")
DIGEST = "a" * 64


class _Text(str):
    pass


def _select(
    interpreter: object = INTERPRETER, *, requested: object = None, platform: object = "nt"
) -> str:
    return selection.select_adjacent_daemon_path(
        cast(str, interpreter),
        requested_executable=cast(str | None, requested),
        platform=cast(str, platform),
    )


def _invalid(
    interpreter: object = INTERPRETER, *, requested: object = None, platform: object = "nt"
) -> None:
    with pytest.raises(ValueError) as caught:
        _select(interpreter, requested=requested, platform=platform)
    assert str(caught.value) == ERROR
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize(
    "platform,explicit", [("nt", False), ("nt", True), ("posix", False), ("posix", True)]
)
def test_selector_returns_only_the_exact_adjacent_platform_launcher(
    platform: str, explicit: bool
) -> None:
    interpreter = INTERPRETER if platform == "nt" else "/opt/gatehouse/bin/python3.14"
    expected = DAEMON if platform == "nt" else "/opt/gatehouse/bin/gatehoused"
    assert (
        _select(
            interpreter,
            requested=expected if explicit else None,
            platform=platform,
        )
        == expected
    )


def test_selector_requires_an_exact_supported_platform() -> None:
    for platform in (None, True, 1, "", "windows", "NT", "linux", _Text("nt")):
        _invalid(platform=platform)


@pytest.mark.parametrize(
    "defect",
    [
        "types",
        "absolute",
        "components",
        "spaces_and_dots",
        "controls",
        "windows_chars",
        "devices",
        "length",
    ],
)
def test_selector_rejects_ambiguous_or_malformed_interpreter_bindings(defect: str) -> None:
    cases: Sequence[tuple[object, str]]
    if defect == "types":
        cases = [(value, "nt") for value in (None, True, 1, b"python.exe", _Text(INTERPRETER))]
    elif defect == "absolute":
        cases = [
            ("python.exe", "nt"),
            (r"C:python.exe", "nt"),
            (r"\Runtime\python.exe", "nt"),
            (r"c:\Runtime\python.exe", "nt"),
            (r"\\server\share\python.exe", "nt"),
            (r"\\?\C:\Runtime\python.exe", "nt"),
            (r"\\.\C:\Runtime\python.exe", "nt"),
            ("bin/python", "posix"),
            ("//opt/bin/python", "posix"),
            (INTERPRETER, "posix"),
        ]
    elif defect == "components":
        cases = [
            (value, "nt")
            for value in (
                "C:\\Runtime\\\\python.exe",
                r"C:\Runtime\.\python.exe",
                r"C:\Runtime\..\python.exe",
                "C:\\Runtime\\",
            )
        ] + [
            (value, "posix")
            for value in ("/opt//python", "/opt/./python", "/opt/../python", "/opt/")
        ]
    elif defect == "spaces_and_dots":
        cases = [
            ("C:\\" + name + r"\python.exe", "nt") for name in (" Runtime", "Runtime ", "Runtime.")
        ] + [("/" + name + "/python", "posix") for name in (" opt", "opt ", "opt.")]
    elif defect == "controls":
        cases = [
            (prefix + "runtime" + character + separator + "python", platform)
            for platform, prefix, separator in (("nt", "C:\\", "\\"), ("posix", "/", "/"))
            for character in ("\x00", "\n", "\r", "\t", "\x7f", "\u0085", "\u2028", "\ud800")
        ]
    elif defect == "windows_chars":
        cases = [
            ("C:\\Runtime" + character + r"\python.exe", "nt") for character in '<>:"/|?*%~'
        ] + [("/opt/back\\slash/python", "posix")]
    elif defect == "devices":
        cases = [
            ("C:\\" + name + r"\python.exe", "nt")
            for name in (
                "CON",
                "prn",
                "AUX.data",
                "nul",
                "CLOCK$",
                "COM1",
                "COM9",
                "LPT1",
                "lpt9",
                "CONIN$",
                "CONOUT$",
                "CONIN$.data",
                "CONOUT$.data",
                "CON .data",
                "COM1 .data",
                "lpt9  .data",
                "COM¹",
                "COM².txt",
                "COM³",
                "LPT¹",
                "LPT²",
                "LPT³.txt",
            )
        ]
    else:
        cases = [
            ("C:\\" + "d\\" * 128 + "p" * 4_096, "nt"),
            ("/" + "d/" * 128 + "p" * 4_096, "posix"),
        ]
    for interpreter, platform in cases:
        _invalid(interpreter, platform=platform)


@pytest.mark.parametrize("defect", ["types", "foreign_parent", "wrong_name", "ambiguous"])
def test_explicit_launcher_is_an_exact_adjacent_assertion(defect: str) -> None:
    requested_values: tuple[object, ...]
    if defect == "types":
        requested_values = (True, 1, DAEMON.encode("utf-8"), _Text(DAEMON), Path(DAEMON))
    elif defect == "foreign_parent":
        requested_values = (
            r"D:\Synthetic\Runtime\Scripts\gatehoused.exe",
            r"C:\Synthetic\Runtime\Scripts-other\gatehoused.exe",
            r"C:\Synthetic\Runtime\Scripts\child\gatehoused.exe",
        )
    elif defect == "wrong_name":
        requested_values = (DAEMON.replace("gatehoused.exe", "python.exe"), DAEMON + ".exe")
    else:
        requested_values = (
            "gatehoused.exe",
            r"C:\Synthetic\Runtime\Scripts\.\gatehoused.exe",
            DAEMON.replace("Runtime", "runtime"),
            " " + DAEMON,
            DAEMON + " ",
        )
    for requested in requested_values:
        _invalid(requested=requested)


def _long_interpreter(platform: str, *, overflow: bool = False) -> str:
    if platform == "nt":
        root, separator, second, filename = "C:\\", "\\", 204, "pythonw.exe"
        if overflow:
            second += 3
    else:
        root, separator, second, filename = "/", "/", 210, "python313"
        if overflow:
            second += 9
            filename = "p"
    parts = ["a" * 255, "b" * second, *(["c" * 200] * 18), filename]
    return root + separator.join(parts)


@pytest.mark.parametrize(
    "boundary",
    [
        "windows_length",
        "posix_length",
        "component",
        "component_count",
        "unicode",
        "derived_overflow",
    ],
)
def test_selector_enforces_input_and_derived_path_bounds(boundary: str) -> None:
    if boundary in ("windows_length", "posix_length"):
        platform = "nt" if boundary == "windows_length" else "posix"
        interpreter = _long_interpreter(platform)
        assert len(interpreter) <= 4_096
        selected = _select(interpreter, platform=platform)
        assert len(selected) == 4_096
        assert _select(interpreter, requested=selected, platform=platform) == selected
        _invalid(interpreter, requested=selected + "x", platform=platform)
    elif boundary == "component":
        for platform, root, separator in (("nt", "C:\\", "\\"), ("posix", "/", "/")):
            interpreter = root + "d" * 255 + separator + "python"
            assert _select(interpreter, platform=platform).startswith(root + "d" * 255 + separator)
            _invalid(root + "d" * 256 + separator + "python", platform=platform)
    elif boundary == "component_count":
        for platform, root, separator in (("nt", "C:\\", "\\"), ("posix", "/", "/")):
            interpreter = root + ("d" + separator) * 127 + "python"
            assert _select(interpreter, platform=platform).startswith(root)
            _invalid(root + ("d" + separator) * 128 + "python", platform=platform)
    elif boundary == "unicode":
        assert _select(r"C:\Runtime Ω\python.exe") == r"C:\Runtime Ω\gatehoused.exe"
        assert (
            _select("/opt/Runtime Ω%~:[]/python", platform="posix")
            == "/opt/Runtime Ω%~:[]/gatehoused"
        )
    else:
        for platform in ("nt", "posix"):
            interpreter = _long_interpreter(platform, overflow=True)
            assert len(interpreter) == 4_096
            _invalid(interpreter, platform=platform)


def test_selector_is_pure_and_does_not_consult_ambient_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> Never:
        raise AssertionError("selector attempted an ambient lookup or external effect")

    assert not {"os", "sys", "pathlib"}.intersection(vars(selection))
    for name in ("open", "Path", "getenv", "which", "getcwd", "resolve"):
        monkeypatch.setattr(selection, name, forbidden, raising=False)
    assert _select() == DAEMON


class _Interpreter:
    def __init__(self) -> None:
        self.reads = 0

    @property
    def executable(self) -> str:
        self.reads += 1
        return INTERPRETER


class _Child:
    returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> Never:
        raise AssertionError("this test did not authorize a cleanup effect")


def _consumer(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    *,
    availability: object = True,
    requested: object = None,
    existing: bool = False,
) -> tuple[
    Callable[[], Awaitable[object]], _Interpreter, list[str], list[tuple[str, ...]], list[str]
]:
    module = watchdog if kind == "watchdog" else local
    interpreter = _Interpreter()
    monkeypatch.setattr(module, "sys", interpreter)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    checked: list[str] = []
    spawned: list[tuple[str, ...]] = []
    probes: list[str] = []

    def is_file(path: Path) -> object:
        checked.append(str(path))
        assert str(path) == DAEMON
        if isinstance(availability, Exception):
            raise availability
        return availability

    monkeypatch.setattr(Path, "is_file", is_file)
    settings = SimpleNamespace(
        config_path=CONFIG,
        config_digest=DIGEST,
        expected_config_digest=DIGEST,
        readiness_timeout_seconds=1.0,
        allow_provider_disabled_state=False,
        environment={},
    )

    def run(arguments: Sequence[str]) -> int:
        spawned.append(tuple(arguments))
        return 0

    def start(arguments: Sequence[str]) -> _Child:
        spawned.append(tuple(arguments))
        return _Child()

    async def spawn(arguments: Sequence[str], *, environment: Mapping[str, str]) -> _Child:
        assert environment == {}
        spawned.append(tuple(arguments))
        return _Child()

    async def probe() -> ProbeResult:
        probes.append("owned_ready")
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    if kind == "watchdog":
        monkeypatch.setattr(watchdog, "_spawn_daemon", spawn)

        async def invoke() -> object:
            return await watchdog._restart(
                cast(watchdog.WatchdogRuntimeSettings, settings),
                daemon_executable=cast(Path | None, requested),
                probe=probe,
            )
    else:
        monkeypatch.setattr(local.LocalCliBackend, "_settings", lambda self, **kwargs: settings)

        def status(self: local.LocalCliBackend) -> dict[str, object]:
            probes.append("control")
            if not existing and len(probes) == 1:
                raise local._LoopbackRequestError("synthetic absence")
            return {
                "status": "READY",
                "ready": True,
                "version": "synthetic",
                "schema_version": 16,
                "policy_version": "synthetic",
                "uptime_seconds": 0,
                "degraded_components": [],
                "config_digest": DIGEST,
            }

        monkeypatch.setattr(local.LocalCliBackend, "_control_status", status)
        monkeypatch.setattr(local.LocalCliBackend, "_agent_live", lambda self: False)
        backend = local.LocalCliBackend(
            config_path=CONFIG,
            environment={},
            daemon_executable=cast(Path | None, requested),
            daemon_processes=cast(local.DaemonProcessRunner, SimpleNamespace(run=run, start=start)),
        )

        async def invoke() -> object:
            action = backend.daemon_run if kind == "cli_run" else backend.daemon_start
            return action(expected_config_digest=DIGEST)

    return invoke, interpreter, checked, spawned, probes


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["cli_run", "cli_start", "watchdog"])
@pytest.mark.parametrize("failure", ["missing", "metadata_error"])
async def test_consumers_refuse_unavailable_adjacent_launcher_without_spawning(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    failure: str,
) -> None:
    available_values = (
        (False, None, 1, "yes")
        if failure == "missing"
        else (PermissionError("synthetic untrusted detail"),)
    )
    for available in available_values:
        invoke, interpreter, checked, spawned, probes = _consumer(
            monkeypatch,
            kind,
            availability=available,
        )
        if kind == "watchdog":
            assert await invoke() is False
            assert probes == []
        else:
            with pytest.raises(CliUnavailable) as caught:
                await invoke()
            assert str(caught.value) == "the installed gatehoused entry point was not found"
        assert interpreter.reads == 1
        assert checked == [DAEMON] and spawned == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["cli_run", "cli_start", "watchdog"])
async def test_consumers_refuse_foreign_or_untyped_override_before_metadata_or_spawn(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    PathSubclass = cast(type[Path], type("PathSubclass", (type(Path()),), {}))

    for requested in (
        Path(r"C:\Foreign\gatehoused.exe"),
        DAEMON,
        "",
        False,
        0,
        PathSubclass(DAEMON),
    ):
        invoke, interpreter, checked, spawned, _ = _consumer(
            monkeypatch,
            kind,
            requested=requested,
        )
        if kind == "watchdog":
            assert await invoke() is False
        else:
            with pytest.raises(CliUnavailable, match="installed gatehoused entry point"):
                await invoke()
        assert interpreter.reads == 1
        assert checked == [] and spawned == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["cli_run", "watchdog"])
async def test_default_adjacent_selection_preserves_digest_and_owned_child_contract(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    invoke, interpreter, checked, spawned, probes = _consumer(monkeypatch, kind)
    result = await invoke()
    if kind == "watchdog":
        assert result is True
    else:
        assert result == {"action": "run", "exit_code": 0}
    assert interpreter.reads == 1 and checked == [DAEMON]
    assert spawned == [(DAEMON, "--config", str(CONFIG), "--expected-config-digest", DIGEST)]
    assert probes == (["owned_ready"] if kind == "watchdog" else [])


@pytest.mark.asyncio
async def test_existing_matched_daemon_does_not_require_launch_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for requested in (None, Path(r"C:\Foreign\gatehoused.exe"), False):
        invoke, interpreter, checked, spawned, probes = _consumer(
            monkeypatch,
            "cli_start",
            availability=False,
            requested=requested,
            existing=True,
        )
        result = cast(Mapping[str, object], await invoke())
        assert result["started"] is False and result["config_digest"] == DIGEST
        assert interpreter.reads == 0 and checked == [] and spawned == []
        assert probes == ["control"]


@pytest.mark.parametrize("kind", ["cli", "watchdog"])
def test_launcher_lookup_preserves_control_flow_interruptions(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    module = local if kind == "cli" else watchdog
    interpreter = _Interpreter()
    monkeypatch.setattr(module, "sys", interpreter)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))

    def interrupted(path: Path) -> Never:
        assert str(path) == DAEMON
        raise KeyboardInterrupt("synthetic interruption")

    monkeypatch.setattr(Path, "is_file", interrupted)
    with pytest.raises(KeyboardInterrupt, match="synthetic interruption"):
        module._locate_daemon_executable()
    assert interpreter.reads == 1
