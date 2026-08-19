"""Typer entry point for bounded local administration and controlled launches."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated

import typer

from gatehouse.sessions import build_child_environment

from .contracts import (
    BrowserOpener,
    CliBackend,
    CliUnavailable,
    NativeBrowserOpener,
    ProcessRunner,
)
from .local import LocalCliBackend, NativeProcessRunner


def _print_json(value: object) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _failure(exception: CliUnavailable) -> typer.Exit:
    typer.echo(str(exception), err=True)
    return typer.Exit(code=2)


def _require_human_confirmation(
    *,
    approval_id: str,
    confirmation: str | None,
    unattended: bool,
) -> None:
    if unattended:
        raise typer.BadParameter("unattended clients cannot perform approval actions")
    if confirmation != approval_id:
        raise typer.BadParameter(
            "pass --confirm-human with the exact approval identifier; no terminal prompt is used"
        )


def create_cli_app(
    *,
    backend: CliBackend,
    processes: ProcessRunner,
    browser: BrowserOpener,
    base_environment: Mapping[str, str] | None = None,
) -> typer.Typer:
    root = typer.Typer(help="Local Gatehouse control and controlled-launch CLI.")
    daemon = typer.Typer(help="Run and control the local daemon.")
    approvals = typer.Typer(help="Review request-bound human approvals.")
    policy = typer.Typer(help="Explain policy without executing a request.")
    docs = typer.Typer(help="Search and read the local documentation index.")
    feedback = typer.Typer(help="Submit bounded advisory feedback.")
    root.add_typer(daemon, name="daemon")
    root.add_typer(approvals, name="approvals")
    root.add_typer(policy, name="policy")
    root.add_typer(docs, name="docs")
    root.add_typer(feedback, name="feedback")

    @root.callback()
    def configure(
        config: Annotated[
            Path | None,
            typer.Option(
                "--config",
                help="Path to the strict Gatehouse configuration file.",
            ),
        ] = None,
    ) -> None:
        if config is None:
            return
        try:
            backend.set_config_path(config)
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    def call(action: str) -> Mapping[str, object]:
        try:
            if action == "run":
                return backend.daemon_run()
            if action == "start":
                return backend.daemon_start()
            if action == "stop":
                return backend.daemon_stop()
            return backend.daemon_status()
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @root.command("status")
    def status() -> None:
        try:
            _print_json(backend.status())
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @daemon.command("run")
    def daemon_run() -> None:
        _print_json(call("run"))

    @daemon.command("start")
    def daemon_start() -> None:
        _print_json(call("start"))

    @daemon.command("stop")
    def daemon_stop() -> None:
        _print_json(call("stop"))

    @daemon.command("status")
    def daemon_status() -> None:
        _print_json(call("status"))

    @root.command(
        "run",
        context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    )
    def controlled_run(
        context: typer.Context,
        client: Annotated[str, typer.Argument(help="Configured client profile")],
        workspace: Annotated[str, typer.Option("--workspace")],
        non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
    ) -> None:
        command: Sequence[str] = tuple(context.args)
        launch = None
        try:
            launch = backend.prepare_launch(
                client=client,
                workspace=workspace,
                non_interactive=non_interactive,
                command=command,
            )
            source = dict(os.environ if base_environment is None else base_environment)
            clean_environment = build_child_environment(source, launch.environment)
            exit_code = processes.run(launch, environment=clean_environment)
        except CliUnavailable as exc:
            if launch is not None:
                try:
                    backend.cleanup_launch(launch, revoke=True)
                except CliUnavailable:
                    pass
            raise _failure(exc) from exc
        except BaseException:
            if launch is not None:
                try:
                    backend.cleanup_launch(launch, revoke=True)
                except CliUnavailable:
                    pass
            raise
        try:
            backend.cleanup_launch(launch, revoke=exit_code != 0)
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        raise typer.Exit(code=exit_code)

    @approvals.command("list")
    def approval_list() -> None:
        try:
            _print_json(list(backend.approval_list()))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    def act(
        approval_id: str,
        decision: str,
        confirmation: str | None,
        unattended: bool,
    ) -> None:
        _require_human_confirmation(
            approval_id=approval_id,
            confirmation=confirmation,
            unattended=unattended,
        )
        try:
            _print_json(backend.approval_action(approval_id, decision))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @approvals.command("approve")
    def approval_approve(
        approval_id: Annotated[str, typer.Argument()],
        confirm_human: Annotated[str | None, typer.Option("--confirm-human")] = None,
        unattended: Annotated[bool, typer.Option("--unattended", hidden=True)] = False,
    ) -> None:
        act(approval_id, "approve", confirm_human, unattended)

    @approvals.command("deny")
    def approval_deny(
        approval_id: Annotated[str, typer.Argument()],
        confirm_human: Annotated[str | None, typer.Option("--confirm-human")] = None,
        unattended: Annotated[bool, typer.Option("--unattended", hidden=True)] = False,
    ) -> None:
        act(approval_id, "deny", confirm_human, unattended)

    @policy.command("explain")
    def policy_explain(
        client: Annotated[str, typer.Option("--client")],
        workspace: Annotated[str, typer.Option("--workspace")],
        service: Annotated[str, typer.Option("--service")],
        operation: Annotated[str, typer.Option("--operation")],
    ) -> None:
        try:
            _print_json(
                backend.policy_explain(
                    client=client,
                    workspace=workspace,
                    service=service,
                    operation=operation,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @docs.command("search")
    def docs_search(
        service: Annotated[str, typer.Argument()],
        query: Annotated[str, typer.Argument()],
        client: Annotated[str, typer.Option("--client")],
        workspace: Annotated[str, typer.Option("--workspace")],
        non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
    ) -> None:
        try:
            _print_json(
                list(
                    backend.docs_search(
                        service,
                        query,
                        client=client,
                        workspace=workspace,
                        non_interactive=non_interactive,
                    )
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @docs.command("get")
    def docs_get(
        service: Annotated[str, typer.Argument()],
        document: Annotated[str, typer.Argument()],
        client: Annotated[str, typer.Option("--client")],
        workspace: Annotated[str, typer.Option("--workspace")],
        non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
    ) -> None:
        try:
            _print_json(
                backend.docs_get(
                    service,
                    document,
                    client=client,
                    workspace=workspace,
                    non_interactive=non_interactive,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @feedback.command("submit")
    def feedback_submit(
        category: Annotated[str, typer.Option("--category")],
        severity: Annotated[str, typer.Option("--severity")],
        component: Annotated[str, typer.Option("--component")],
        summary: Annotated[str, typer.Option("--summary")],
        client: Annotated[str, typer.Option("--client")],
        workspace: Annotated[str, typer.Option("--workspace")],
        non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
    ) -> None:
        try:
            _print_json(
                backend.feedback_submit(
                    category=category,
                    severity=severity,
                    component=component,
                    summary=summary,
                    client=client,
                    workspace=workspace,
                    non_interactive=non_interactive,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @root.command("dashboard")
    def dashboard() -> None:
        try:
            url = backend.dashboard_login_url()
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        if not browser.open(url):
            raise typer.Exit(code=1)

    return root


app = create_cli_app(
    backend=LocalCliBackend(),
    processes=NativeProcessRunner(),
    browser=NativeBrowserOpener(),
)
