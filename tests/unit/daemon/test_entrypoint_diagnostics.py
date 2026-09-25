from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from gatehouse.config.loader import ConfigLoadError, ConfigLoadStage
from gatehouse.daemon import main as daemon_main

_CANARY = "synthetic-private-startup-detail-294781"
_ARGUMENTS = ["--config", r"C:\Synthetic\config.yaml", "--expected-config-digest", "a" * 64]


@pytest.mark.parametrize(
    "failure",
    ("configuration", "runtime", "keyboard", "system_exit", "cancelled"),
)
def test_entrypoint_failure_is_fixed_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    async def rejected(*args: object, **kwargs: object) -> int:
        if failure == "configuration":
            raise ConfigLoadError(Path(_CANARY), ConfigLoadStage.SECURITY, _CANARY)
        if failure == "keyboard":
            raise KeyboardInterrupt(_CANARY)
        if failure == "system_exit":
            raise SystemExit(_CANARY)
        if failure == "cancelled":
            raise asyncio.CancelledError(_CANARY)
        raise RuntimeError(_CANARY)

    monkeypatch.setattr(daemon_main, "run_stock_daemon", rejected)
    with pytest.raises(SystemExit) as result:
        daemon_main.main(_ARGUMENTS, environment={})
    assert (
        result.value.code
        == {
            "configuration": 2,
            "runtime": 1,
            "keyboard": 130,
            "system_exit": 1,
            "cancelled": 130,
        }[failure]
    )
    assert result.value.__context__ is None
    captured = capsys.readouterr()
    assert _CANARY not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert "gatehoused:" in captured.err


@pytest.mark.parametrize("code", (0, 1))
def test_runtime_failure_result_has_explicit_fixed_signal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    code: int,
) -> None:
    async def completed(*args: object, **kwargs: object) -> int:
        return code

    monkeypatch.setattr(daemon_main, "run_stock_daemon", completed)
    if code:
        with pytest.raises(SystemExit) as result:
            daemon_main.main(_ARGUMENTS, environment={})
        assert result.value.code == 1
        assert capsys.readouterr().err == "gatehoused: daemon failed closed\n"
    else:
        daemon_main.main(_ARGUMENTS, environment={})
        captured = capsys.readouterr()
        assert not captured.out and not captured.err
