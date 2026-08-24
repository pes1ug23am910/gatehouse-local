"""Installed ``gatehoused`` entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence
from pathlib import Path

from gatehouse.core.stdio import ensure_standard_streams

from .composition import run_stock_daemon


def default_config_path(*, environment: dict[str, str] | None = None) -> Path:
    source = os.environ if environment is None else environment
    appdata = source.get("APPDATA")
    if appdata:
        return Path(appdata) / "Gatehouse" / "config.yaml"
    return Path.home() / "AppData" / "Roaming" / "Gatehouse" / "config.yaml"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gatehoused")
    parser.add_argument(
        "--config",
        type=Path,
        default=default_config_path(),
        help="absolute path to the strict Gatehouse configuration file",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    ensure_standard_streams()
    arguments = _parser().parse_args(argv)
    code = asyncio.run(run_stock_daemon(arguments.config))
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
