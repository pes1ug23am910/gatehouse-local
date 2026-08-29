"""Typer entry point for bounded local administration and controlled launches."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Literal

import typer

from gatehouse.feedback import FeedbackCategory, FeedbackComponent, FeedbackSeverity
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
_MAXIMUM_ACCOUNT_PRIORITY = 1_000_000


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
    subject: str = "approval identifier",
) -> None:
    if unattended:
        raise typer.BadParameter("unattended clients cannot perform approval actions")
    if confirmation != approval_id:
        raise typer.BadParameter(
            f"pass --confirm-human with the exact {subject}; no terminal prompt is used"
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
    configuration = typer.Typer(help="Initialize and validate local configuration.")
    daemon = typer.Typer(help="Run and control the local daemon.")
    approvals = typer.Typer(help="Review request-bound human approvals.")
    policy = typer.Typer(help="Explain policy without executing a request.")
    docs = typer.Typer(help="Search and read the local documentation index.")
    feedback = typer.Typer(help="Submit bounded advisory feedback.")
    accounts = typer.Typer(help="Administer provider accounts held in central custody.")
    account_observation = typer.Typer(
        help=(
            "Toggle scheduled observation for one account; provider observer networking "
            "remains separately gated."
        )
    )
    credentials = typer.Typer(help="Administer credential lifecycle state.")
    emergency = typer.Typer(help="Manually administer emergency credential unlocks.")
    root.add_typer(configuration, name="config")
    root.add_typer(daemon, name="daemon")
    root.add_typer(approvals, name="approvals")
    root.add_typer(policy, name="policy")
    root.add_typer(docs, name="docs")
    root.add_typer(feedback, name="feedback")
    root.add_typer(accounts, name="accounts")
    root.add_typer(credentials, name="credentials")
    root.add_typer(emergency, name="emergency")
    accounts.add_typer(account_observation, name="observe")

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

    @configuration.command("init")
    def config_init() -> None:
        try:
            _print_json(backend.config_init())
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @configuration.command("validate")
    def config_validate(
        explain: Annotated[
            bool,
            typer.Option(
                "--explain",
                help="Include sanitized resolved paths and operating modes.",
            ),
        ] = False,
    ) -> None:
        try:
            _print_json(backend.config_validate(explain=explain))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @root.command("diagnose")
    def diagnose(
        support_bundle: Annotated[
            Path | None,
            typer.Option(
                "--support-bundle",
                help="Write a bounded, sanitized JSON support bundle to a new file.",
            ),
        ] = None,
    ) -> None:
        try:
            result = backend.diagnose(support_bundle=support_bundle)
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        _print_json(result)
        if result.get("ok") is not True:
            raise typer.Exit(code=1)

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
            # The child has exited, so no process remains that can safely re-adopt
            # this authority. Revoke the durable run slot on every clean return.
            backend.cleanup_launch(launch, revoke=True)
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
        category: Annotated[FeedbackCategory, typer.Option("--category")],
        severity: Annotated[FeedbackSeverity, typer.Option("--severity")],
        component: Annotated[FeedbackComponent, typer.Option("--component")],
        summary: Annotated[str, typer.Option("--summary")],
        client: Annotated[str, typer.Option("--client")],
        workspace: Annotated[str, typer.Option("--workspace")],
        non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
    ) -> None:
        try:
            _print_json(
                backend.feedback_submit(
                    category=category.value,
                    severity=severity.value,
                    component=component.value,
                    summary=summary,
                    client=client,
                    workspace=workspace,
                    non_interactive=non_interactive,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @accounts.command("add")
    def account_add(
        provider: Annotated[Literal["firecrawl"], typer.Option("--provider")],
        provider_team_id: Annotated[str, typer.Option("--team-id")],
        alias: Annotated[str, typer.Option("--alias")],
        pool: Annotated[str, typer.Option("--pool")],
        priority: Annotated[
            int,
            typer.Option("--priority", min=0, max=_MAXIMUM_ACCOUNT_PRIORITY),
        ],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        expires_at_ms: Annotated[int | None, typer.Option("--expires-at-ms")] = None,
    ) -> None:
        secret: bytearray | None = None
        try:
            secret = hidden_secrets.read_secret(
                "Firecrawl account secret: ",
                maximum_bytes=_MAXIMUM_SECRET_BYTES,
            )
            _print_json(
                backend.account_add(
                    secret,
                    provider=provider,
                    provider_team_id=provider_team_id,
                    alias=alias,
                    pool_alias=pool,
                    priority=priority,
                    mutation_id=mutation_id,
                    expires_at_ms=expires_at_ms,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc
        finally:
            if secret is not None:
                _zero_secret(secret)

    @accounts.command("list")
    def account_list(
        limit: Annotated[int, typer.Option("--limit", min=1, max=100)] = 50,
    ) -> None:
        try:
            _print_json(list(backend.account_list(limit=limit)))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @accounts.command("status")
    def account_status(alias: Annotated[str, typer.Argument()]) -> None:
        try:
            _print_json(backend.account_status(alias))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @accounts.command("refresh")
    def account_refresh(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
    ) -> None:
        """Request one bounded refresh through the separately gated observer transport."""

        try:
            _print_json(backend.account_refresh(alias, mutation_id=mutation_id))
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @accounts.command("rotate")
    def account_rotate(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        expires_at_ms: Annotated[int | None, typer.Option("--expires-at-ms")] = None,
    ) -> None:
        secret: bytearray | None = None
        try:
            secret = hidden_secrets.read_secret(
                "Replacement Firecrawl account secret: ",
                maximum_bytes=_MAXIMUM_SECRET_BYTES,
            )
            _print_json(
                backend.account_rotate(
                    alias,
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

    def change_account_state(
        alias: str,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> None:
        try:
            _print_json(
                backend.account_change_state(
                    alias,
                    mutation_id=mutation_id,
                    action=action,
                    reason=reason,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @accounts.command("disable")
    def account_disable(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        change_account_state(alias, mutation_id, "disable", reason)

    @accounts.command("recover")
    def account_recover(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        change_account_state(alias, mutation_id, "recover", reason)

    @accounts.command("remove")
    def account_remove(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
        confirm_human: Annotated[str | None, typer.Option("--confirm-human")] = None,
        unattended: Annotated[bool, typer.Option("--unattended", hidden=True)] = False,
    ) -> None:
        _require_human_confirmation(
            approval_id=alias,
            confirmation=confirm_human,
            unattended=unattended,
            subject="account alias",
        )
        change_account_state(alias, mutation_id, "remove", reason)

    def change_account_observation(
        alias: str,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> None:
        try:
            _print_json(
                backend.account_observation_change(
                    alias,
                    mutation_id=mutation_id,
                    action=action,
                    reason=reason,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

    @account_observation.command("enable")
    def account_observation_enable(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        """Enable scheduling without granting live or network permission."""

        change_account_observation(alias, mutation_id, "enable", reason)

    @account_observation.command("disable")
    def account_observation_disable(
        alias: Annotated[str, typer.Argument()],
        mutation_id: Annotated[str, typer.Option("--mutation-id")],
        reason: Annotated[str, typer.Option("--reason")],
    ) -> None:
        """Disable scheduled observation for the selected account."""

        change_account_observation(alias, mutation_id, "disable", reason)

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

    @credentials.command("validate")
    def credential_validate(
        credential_id: Annotated[str, typer.Argument()],
        expected_generation: Annotated[int, typer.Option("--generation", min=1)],
    ) -> None:
        try:
            _print_json(
                backend.credential_validate(
                    credential_id,
                    expected_generation=expected_generation,
                )
            )
        except CliUnavailable as exc:
            raise _failure(exc) from exc

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
