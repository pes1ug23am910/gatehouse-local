"""Installed ``gatehoused`` entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn

from gatehouse.config import ConfigLoadError
from gatehouse.config.security import ConfigSecurityError
from gatehouse.core.stdio import ensure_standard_streams
from gatehouse.sessions import EnvironmentValidationError, build_long_lived_environment

from .composition import run_stock_daemon
from .configuration import validate_expected_config_digest


class _DaemonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # Argument errors must not echo untrusted option values.
        super().error("daemon startup arguments are invalid")


class _ExpectedConfigDigestAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error("daemon startup arguments are invalid")
        try:
            expected = validate_expected_config_digest(values)
        except ConfigSecurityError:
            pass
        else:
            setattr(namespace, self.dest, expected)
            return
        parser.error("daemon startup arguments are invalid")


def default_config_path(*, environment: Mapping[str, str] | None = None) -> Path:
    source = os.environ if environment is None else environment
    appdata = source.get("APPDATA")
    if appdata:
        return Path(appdata) / "Gatehouse" / "config.yaml"
    return Path.home() / "AppData" / "Roaming" / "Gatehouse" / "config.yaml"


def _parser(*, environment: Mapping[str, str] | None = None) -> argparse.ArgumentParser:
    parser = _DaemonArgumentParser(prog="gatehoused", allow_abbrev=False)
    parser.add_argument(
        "--config",
        default=str(default_config_path(environment=environment)),
        help="absolute path to the strict Gatehouse configuration file",
    )
    parser.add_argument(
        "--expected-config-digest",
        required=True,
        action=_ExpectedConfigDigestAction,
        help="expected trusted configuration bundle digest (64 lowercase hexadecimal characters)",
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
        _DaemonArgumentParser(prog="gatehoused").exit(
            2,
            f"gatehoused: error: {EnvironmentValidationError()}\n",
        )
    if environment is None:
        os.environ.clear()
        os.environ.update(runtime_environment)
    parser = _parser(environment=runtime_environment)
    arguments = parser.parse_args(argv)
    exit_code = 1
    exit_message: str | None = None
    code = 1
    try:
        code = asyncio.run(
            run_stock_daemon(
                arguments.config,
                environment=runtime_environment,
                expected_config_digest=arguments.expected_config_digest,
            )
        )
    except ConfigLoadError:
        exit_code = 2
        exit_message = "gatehoused: configuration startup was refused\n"
    except KeyboardInterrupt:
        exit_code = 130
        exit_message = "gatehoused: interrupted\n"
    except asyncio.CancelledError:
        exit_code = 130
        exit_message = "gatehoused: interrupted\n"
    except SystemExit:
        exit_message = "gatehoused: daemon failed closed\n"
    except Exception:
        exit_message = "gatehoused: daemon failed closed\n"
    if exit_message is not None:
        parser.exit(exit_code, exit_message)
    if code:
        parser.exit(1, "gatehoused: daemon failed closed\n")


if __name__ == "__main__":
    main()
