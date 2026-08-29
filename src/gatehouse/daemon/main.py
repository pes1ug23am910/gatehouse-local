"""Installed ``gatehoused`` entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Mapping, Sequence
from pathlib import Path

from gatehouse.config import ConfigLoadError
from gatehouse.core.stdio import ensure_standard_streams
from gatehouse.sessions import build_long_lived_environment

from .composition import run_stock_daemon


def default_config_path(*, environment: Mapping[str, str] | None = None) -> Path:
    source = os.environ if environment is None else environment
    appdata = source.get("APPDATA")
    if appdata:
        return Path(appdata) / "Gatehouse" / "config.yaml"
    return Path.home() / "AppData" / "Roaming" / "Gatehouse" / "config.yaml"


def _parser(*, environment: Mapping[str, str] | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gatehoused")
    parser.add_argument(
        "--config",
        type=Path,
        default=default_config_path(environment=environment),
        help="absolute path to the strict Gatehouse configuration file",
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
        code = asyncio.run(
            run_stock_daemon(
                arguments.config,
                environment=runtime_environment,
            )
        )
    except ConfigLoadError as error:
        parser.error(str(error))
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
