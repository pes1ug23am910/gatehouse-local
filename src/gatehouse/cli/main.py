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
    InteractiveSecretReader,
    NativeBrowserOpener,
    ProcessRunner,
    SecretReader,
)
from .local import LocalCliBackend, NativeProcessRunner

_MAXIMUM_SECRET_BYTES = 16 * 1_024


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


def _zero_secret(secret: bytearray) -> None:
    secret[:] = b"\x00" * len(secret)


def create_cli_app(
    *,
    backend: CliBackend,
    processes: ProcessRunner,
    browser: BrowserOpener,
    secret_reader: SecretReader | None = None,
    base_environment: Mapping[str, str] | None = None,
) -> typer.Typer:
    hidden_secrets = secret_reader or InteractiveSecretReader()
    root = typer.Typer(help="Local Gatehouse control and controlled-launch CLI.")
    daemon = typer.Typer(help="Run and control the local daemon.")
    approvals = typer.Typer(help="Review request-bound human approvals.")
    policy = typer.Typer(help="Explain policy without executing a request.")
    docs = typer.Typer(help="Search and read the local documentation index.")
    feedback = typer.Typer(help="Submit bounded advisory feedback.")
    credentials = typer.Typer(help="Administer credential lifecycle state.")
    emergency = typer.Typer(help="Manually administer emergency credential unlocks.")
    root.add_typer(daemon, name="daemon")
    root.add_typer(approvals, name="approvals")
    root.add_typer(policy, name="policy")
    root.add_typer(docs, name="docs")
    root.add_typer(feedback, name="feedback")
    root.add_typer(credentials, name="credentials")
    root.add_typer(emergency, name="emergency")

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

    @credentials.command("provision")
    def credential_provision(
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        principal_id: Annotated[str, typer.Option("--principal-id")],
        quota_scope_id: Annotated[str, typer.Option("--quota-scope-id")],
        pool_id: Annotated[str, typer.Option("--pool-id")],
        alias: Annotated[str, typer.Option("--alias")],
        expires_at_ms: Annotated[int | None, typer.Option("--expires-at-ms")] = None,
        exclusive_usage: Annotated[
            bool,
            typer.Option("--exclusive-usage/--shared-usage"),
        ] = True,
    ) -> None:
        secret: bytearray | None = None
        try:
            secret = hidden_secrets.read_secret(
                "Credential secret: ",
                maximum_bytes=_MAXIMUM_SECRET_BYTES,
            )
            _print_json(
                backend.credential_provision(
                    secret,
                    mutation_id=mutation_id,
                    principal_id=principal_id,
                    quota_scope_id=quota_scope_id,
                    pool_id=pool_id,
                    alias=alias,
                    expires_at_ms=expires_at_ms,
                    exclusive_usage=exclusive_usage,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        finally:
            if secret is not None:
                _zero_secret(secret)

    @credentials.command("list")
    def credential_list(
        limit: Annotated[int, typer.Option("--limit", min=1, max=100)] = 50,
    ) -> None:
        try:
            _print_json(list(backend.credential_list(limit=limit)))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @credentials.command("rotate")
    def credential_rotate(
        credential_id: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        expires_at_ms: Annotated[int | None, typer.Option("--expires-at-ms")] = None,
    ) -> None:
        secret: bytearray | None = None
        try:
            secret = hidden_secrets.read_secret(
                "Replacement credential secret: ",
                maximum_bytes=_MAXIMUM_SECRET_BYTES,
            )
            _print_json(
                backend.credential_rotate(
                    credential_id,
                    secret,
                    mutation_id=mutation_id,
                    expires_at_ms=expires_at_ms,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        finally:
            if secret is not None:
                _zero_secret(secret)

    def change_credential_state(
        credential_id: str,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> None:
        try:
            _print_json(
                backend.credential_change_state(
                    credential_id,
                    mutation_id=mutation_id,
                    action=action,
                    reason=reason,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @credentials.command("disable")
    def credential_disable(
        credential_id: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        change_credential_state(credential_id, mutation_id, "disable", reason)

    @credentials.command("quarantine")
    def credential_quarantine(
        credential_id: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        change_credential_state(credential_id, mutation_id, "quarantine", reason)

    @credentials.command("retire")
    def credential_retire(
        credential_id: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        change_credential_state(credential_id, mutation_id, "retire", reason)

    @emergency.command("unlock")
    def emergency_unlock(
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        service: Annotated[str, typer.Option("--service")],
        pool_id: Annotated[str, typer.Option("--pool-id")],
        session_id: Annotated[str, typer.Option("--session-id")],
        root_run_id: Annotated[str, typer.Option("--root-run-id")],
        alias: Annotated[str, typer.Option("--alias")],
        reason: Annotated[str, typer.Option("--reason")],
        duration_ms: Annotated[int, typer.Option("--duration-ms")],
        maximum_requests: Annotated[int, typer.Option("--maximum-requests")],
        maximum_credits: Annotated[int, typer.Option("--maximum-credits")],
    ) -> None:
        secret: bytearray | None = None
        try:
            secret = hidden_secrets.read_secret(
                "Emergency credential secret: ",
                maximum_bytes=_MAXIMUM_SECRET_BYTES,
            )
            _print_json(
                backend.emergency_unlock(
                    secret,
                    mutation_id=mutation_id,
                    service=service,
                    pool_id=pool_id,
                    session_id=session_id,
                    root_run_id=root_run_id,
                    alias=alias,
                    reason=reason,
                    duration_ms=duration_ms,
                    maximum_requests=maximum_requests,
                    maximum_credits=maximum_credits,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        finally:
            if secret is not None:
                _zero_secret(secret)

    @emergency.command("list")
    def emergency_list(
        limit: Annotated[int, typer.Option("--limit", min=1, max=100)] = 50,
    ) -> None:
        try:
            _print_json(list(backend.emergency_list(limit=limit)))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @emergency.command("cancel")
    def emergency_cancel(
        unlock_id: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        try:
            _print_json(
                backend.emergency_cancel(
                    unlock_id,
                    mutation_id=mutation_id,
                    reason=reason,
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
