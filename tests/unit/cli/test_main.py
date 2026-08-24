from __future__ import annotations

import getpass
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from gatehouse.cli.contracts import (
    CliUnavailable,
    ControlledLaunch,
    InteractiveSecretReader,
    SecretReader,
    UnavailableCliBackend,
)
from gatehouse.cli.main import create_cli_app

_SECRET_CANARY = "FAKE-CLI-LIFECYCLE-CANARY-NOT-A-REAL-KEY-123456"


class FakeBackend(UnavailableCliBackend):
    def __init__(self) -> None:
        self.actions: list[tuple[str, str]] = []
        self.launches: list[tuple[str, str, bool, tuple[str, ...]]] = []
        self.cleanups: list[tuple[str, bool]] = []
        self.config_paths: list[Path] = []
        self.admin_calls: list[tuple[str, dict[str, object]]] = []
        self.secret_buffers: list[bytearray] = []
        self.secret_snapshots: list[bytes] = []
        self.fail_secret_action = False

    def set_config_path(self, config_path: Path) -> None:
        self.config_paths.append(config_path)

    def status(self) -> Mapping[str, object]:
        return {"status": "ready"}

    def daemon_run(self) -> Mapping[str, object]:
        return {"action": "run"}

    def daemon_start(self) -> Mapping[str, object]:
        return {"action": "start"}

    def daemon_stop(self) -> Mapping[str, object]:
        return {"action": "stop"}

    def daemon_status(self) -> Mapping[str, object]:
        return {"status": "ready"}

    def prepare_launch(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
        command: Sequence[str],
    ) -> ControlledLaunch:
        command_tuple = tuple(command)
        self.launches.append((client, workspace, non_interactive, command_tuple))
        return ControlledLaunch(
            session_id="ses_one",
            argv=command_tuple,
            working_directory=Path.cwd().resolve(),
            environment={
                "GATEHOUSE_AGENT_URL": "http://127.0.0.1:47621",
                "GATEHOUSE_SESSION_ID": "ses_one",
                "GATEHOUSE_SESSION_BOOTSTRAP": "b" * 43,
            },
        )

    def cleanup_launch(self, launch: ControlledLaunch, *, revoke: bool) -> None:
        self.cleanups.append((launch.session_id, revoke))

    def approval_list(self) -> Sequence[Mapping[str, object]]:
        return ({"approval_id": "approval-one"},)

    def approval_action(self, approval_id: str, decision: str) -> Mapping[str, object]:
        self.actions.append((approval_id, decision))
        return {"approval_id": approval_id, "state": decision.upper()}

    def policy_explain(
        self,
        *,
        client: str,
        workspace: str,
        service: str,
        operation: str,
    ) -> Mapping[str, object]:
        return {
            "client": client,
            "workspace": workspace,
            "service": service,
            "operation": operation,
            "decision": "ALLOW",
        }

    def docs_search(
        self,
        service: str,
        query: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Sequence[Mapping[str, object]]:
        del client, workspace, non_interactive
        return ({"service": service, "excerpt": query},)

    def docs_get(
        self,
        service: str,
        document: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]:
        del client, workspace, non_interactive
        return {"service": service, "document": document}

    def feedback_submit(
        self,
        *,
        category: str,
        severity: str,
        component: str,
        summary: str,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]:
        del client, workspace, non_interactive
        return {
            "feedback_id": "feedback-one",
            "category": category,
            "severity": severity,
            "component": component,
            "summary": summary,
        }

    def dashboard_login_url(self) -> str:
        return "http://127.0.0.1:47622/login?code=one-use"

    @staticmethod
    def _account_status(alias: str = "primary") -> Mapping[str, object]:
        return {
            "alias": alias,
            "state": "HEALTHY",
            "remaining_decimal": "17.25",
            "plan_decimal": "100",
            "unit": "credits",
            "observed_at_ms": 1_000,
            "staleness_ms": 50,
            "stale": False,
            "source": "firecrawl-credit-usage",
        }

    def account_add(
        self,
        secret: bytearray,
        *,
        provider: str,
        provider_team_id: str,
        alias: str,
        pool_alias: str,
        priority: int,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        self.secret_buffers.append(secret)
        self.secret_snapshots.append(bytes(secret))
        self.admin_calls.append(
            (
                "account-add",
                {
                    "provider": provider,
                    "provider_team_id": provider_team_id,
                    "alias": alias,
                    "pool_alias": pool_alias,
                    "priority": priority,
                    "mutation_id": mutation_id,
                    "expires_at_ms": expires_at_ms,
                },
            )
        )
        if self.fail_secret_action:
            raise CliUnavailable("synthetic backend failure")
        return {"alias": alias, "action": "add", "state": "UNKNOWN"}

    def account_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        self.admin_calls.append(("account-list", {"limit": limit}))
        return (self._account_status(),)

    def account_status(self, alias: str) -> Mapping[str, object]:
        self.admin_calls.append(("account-status", {"alias": alias}))
        return self._account_status(alias)

    def account_rotate(
        self,
        alias: str,
        secret: bytearray,
        *,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        self.secret_buffers.append(secret)
        self.secret_snapshots.append(bytes(secret))
        self.admin_calls.append(
            (
                "account-rotate",
                {
                    "alias": alias,
                    "mutation_id": mutation_id,
                    "expires_at_ms": expires_at_ms,
                },
            )
        )
        if self.fail_secret_action:
            raise CliUnavailable("synthetic backend failure")
        return {"alias": alias, "action": "rotate", "state": "HEALTHY"}

    def account_change_state(
        self,
        alias: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        self.admin_calls.append(
            (
                f"account-{action}",
                {
                    "alias": alias,
                    "mutation_id": mutation_id,
                    "action": action,
                    "reason": reason,
                },
            )
        )
        return {"alias": alias, "action": action, "state": action.upper()}

    def account_refresh(
        self,
        alias: str,
        *,
        mutation_id: str,
    ) -> Mapping[str, object]:
        self.admin_calls.append(("account-refresh", {"alias": alias, "mutation_id": mutation_id}))
        return self._account_status(alias)

    def account_observation_change(
        self,
        alias: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        self.admin_calls.append(
            (
                f"account-observe-{action}",
                {
                    "alias": alias,
                    "mutation_id": mutation_id,
                    "action": action,
                    "reason": reason,
                },
            )
        )
        return {"alias": alias, "action": action, "enabled": action == "enable"}

    def _secret_call(
        self,
        action: str,
        secret: bytearray,
        metadata: dict[str, object],
    ) -> Mapping[str, object]:
        self.secret_buffers.append(secret)
        self.secret_snapshots.append(bytes(secret))
        self.admin_calls.append((action, metadata))
        if self.fail_secret_action:
            raise CliUnavailable("synthetic backend failure")
        return {"action": action, "state": "HEALTHY"}

    def credential_provision(
        self,
        secret: bytearray,
        *,
        mutation_id: str,
        principal_id: str,
        quota_scope_id: str,
        pool_id: str,
        alias: str,
        expires_at_ms: int | None,
        exclusive_usage: bool,
    ) -> Mapping[str, object]:
        return self._secret_call(
            "provision",
            secret,
            {
                "mutation_id": mutation_id,
                "principal_id": principal_id,
                "quota_scope_id": quota_scope_id,
                "pool_id": pool_id,
                "alias": alias,
                "expires_at_ms": expires_at_ms,
                "exclusive_usage": exclusive_usage,
            },
        )

    def credential_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        self.admin_calls.append(("credential-list", {"limit": limit}))
        return (
            {
                "credential_id": "cred_one",
                "service": "firecrawl",
                "alias": "primary",
                "state": "HEALTHY",
                "generation": 1,
            },
        )

    def credential_rotate(
        self,
        credential_id: str,
        secret: bytearray,
        *,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        return self._secret_call(
            "rotate",
            secret,
            {
                "credential_id": credential_id,
                "mutation_id": mutation_id,
                "expires_at_ms": expires_at_ms,
            },
        )

    def credential_validate(
        self,
        credential_id: str,
        *,
        expected_generation: int,
    ) -> Mapping[str, object]:
        metadata: dict[str, object] = {
            "credential_id": credential_id,
            "expected_generation": expected_generation,
        }
        self.admin_calls.append(("validate", metadata))
        return {
            "credential_id": credential_id,
            "generation": expected_generation,
            "state": "authenticated",
            "remaining_units": 17,
            "plan_total_units": 100,
            "observed_remaining_units_decimal": "17",
            "observed_plan_total_units_decimal": "100",
        }

    def credential_change_state(
        self,
        credential_id: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        metadata: dict[str, object] = {
            "credential_id": credential_id,
            "mutation_id": mutation_id,
            "action": action,
            "reason": reason,
        }
        self.admin_calls.append((action, metadata))
        return {"action": action, "state": action.upper()}

    def emergency_unlock(
        self,
        secret: bytearray,
        *,
        mutation_id: str,
        service: str,
        pool_id: str,
        session_id: str,
        root_run_id: str,
        alias: str,
        reason: str,
        duration_ms: int,
        maximum_requests: int,
        maximum_credits: int,
    ) -> Mapping[str, object]:
        return self._secret_call(
            "unlock",
            secret,
            {
                "mutation_id": mutation_id,
                "service": service,
                "pool_id": pool_id,
                "session_id": session_id,
                "root_run_id": root_run_id,
                "alias": alias,
                "reason": reason,
                "duration_ms": duration_ms,
                "maximum_requests": maximum_requests,
                "maximum_credits": maximum_credits,
                "maximum_concurrency": 1,
            },
        )

    def emergency_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        self.admin_calls.append(("emergency-list", {"limit": limit}))
        return ({"unlock_id": "unl_one", "state": "ACTIVE"},)

    def emergency_cancel(
        self,
        unlock_id: str,
        *,
        mutation_id: str,
        reason: str,
    ) -> Mapping[str, object]:
        metadata: dict[str, object] = {
            "unlock_id": unlock_id,
            "mutation_id": mutation_id,
            "reason": reason,
        }
        self.admin_calls.append(("cancel", metadata))
        return {"unlock_id": unlock_id, "action": "cancel", "state": "CANCELLED"}


class FakeSecretReader(SecretReader):
    def __init__(self, values: Sequence[bytes]) -> None:
        self._values = iter(values)
        self.prompts: list[tuple[str, int]] = []
        self.buffers: list[bytearray] = []

    def read_secret(self, prompt: str, *, maximum_bytes: int) -> bytearray:
        self.prompts.append((prompt, maximum_bytes))
        value = bytearray(next(self._values))
        self.buffers.append(value)
        return value


class FakeProcesses:
    def __init__(self) -> None:
        self.environment: Mapping[str, str] | None = None
        self.launch: ControlledLaunch | None = None
        self.exit_code = 0

    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int:
        self.launch = launch
        self.environment = environment
        return self.exit_code


class FakeBrowser:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def open(self, url: str) -> bool:
        self.urls.append(url)
        return True


def app_fixture() -> tuple[typer.Typer, FakeBackend, FakeProcesses, FakeBrowser]:
    backend = FakeBackend()
    processes = FakeProcesses()
    browser = FakeBrowser()
    app = create_cli_app(
        backend=backend,
        processes=processes,
        browser=browser,
        base_environment={
            "Path": "C:\\Windows",
            "FUTURE_SERVICE_API_KEY": _SECRET_CANARY,
        },
    )
    return app, backend, processes, browser


def test_all_daemon_commands_and_status_are_registered() -> None:
    app, _, _, _ = app_fixture()
    runner = CliRunner()
    for command in ("run", "start", "stop", "status"):
        result = runner.invoke(app, ["daemon", command])
        assert result.exit_code == 0
    status = runner.invoke(app, ["status"])
    assert status.exit_code == 0
    assert '"status": "ready"' in status.stdout


def test_controlled_launch_uses_clean_child_environment() -> None:
    app, backend, processes, _ = app_fixture()
    result = CliRunner().invoke(
        app,
        [
            "run",
            "editor-one",
            "--workspace",
            "workspace-one",
            "--",
            "worker.exe",
            "--bounded",
        ],
    )
    assert result.exit_code == 0
    assert backend.launches == [("editor-one", "workspace-one", False, ("worker.exe", "--bounded"))]
    assert processes.environment is not None
    assert "FUTURE_SERVICE_API_KEY" not in processes.environment
    assert processes.launch is not None
    assert processes.launch.working_directory == Path.cwd().resolve()
    assert _SECRET_CANARY not in repr(processes.launch.argv)
    assert _SECRET_CANARY not in repr(dict(processes.environment))
    assert processes.environment["GATEHOUSE_SESSION_BOOTSTRAP"] == "b" * 43
    assert backend.cleanups == [("ses_one", False)]


def test_approval_fallback_never_prompts_and_requires_exact_human_confirmation() -> None:
    app, backend, _, _ = app_fixture()
    runner = CliRunner()
    missing = runner.invoke(app, ["approvals", "approve", "approval-one"])
    assert missing.exit_code != 0
    assert backend.actions == []

    unattended = runner.invoke(
        app,
        [
            "approvals",
            "approve",
            "approval-one",
            "--confirm-human",
            "approval-one",
            "--unattended",
        ],
    )
    assert unattended.exit_code != 0
    assert backend.actions == []

    approved = runner.invoke(
        app,
        [
            "approvals",
            "approve",
            "approval-one",
            "--confirm-human",
            "approval-one",
        ],
    )
    assert approved.exit_code == 0
    assert backend.actions == [("approval-one", "approve")]
    assert "Would you like" not in approved.stdout


def test_failed_controlled_child_revokes_its_session() -> None:
    app, backend, processes, _ = app_fixture()
    processes.exit_code = 9
    result = CliRunner().invoke(
        app,
        [
            "run",
            "editor-one",
            "--workspace",
            "workspace-one",
            "--",
            "worker.exe",
        ],
    )
    assert result.exit_code == 9
    assert backend.cleanups == [("ses_one", True)]


def test_policy_docs_feedback_and_dashboard_commands_use_injected_clients() -> None:
    app, _, _, browser = app_fixture()
    runner = CliRunner()
    explain = runner.invoke(
        app,
        [
            "policy",
            "explain",
            "--client",
            "editor-one",
            "--workspace",
            "workspace-one",
            "--service",
            "firecrawl",
            "--operation",
            "search",
        ],
    )
    assert explain.exit_code == 0
    assert '"decision": "ALLOW"' in explain.stdout
    assert (
        runner.invoke(
            app,
            [
                "docs",
                "search",
                "firecrawl",
                "rate limit",
                "--client",
                "editor-one",
                "--workspace",
                "workspace-one",
            ],
        ).exit_code
        == 0
    )
    feedback = runner.invoke(
        app,
        [
            "feedback",
            "submit",
            "--category",
            "contract",
            "--severity",
            "medium",
            "--component",
            "firecrawl.search",
            "--summary",
            "Unexpected field",
            "--client",
            "editor-one",
            "--workspace",
            "workspace-one",
        ],
    )
    assert feedback.exit_code == 0
    assert runner.invoke(app, ["dashboard"]).exit_code == 0
    assert browser.urls == ["http://127.0.0.1:47622/login?code=one-use"]


def test_config_option_is_forwarded_without_loading_it_in_the_cli_shell(tmp_path: Path) -> None:
    app, backend, _, _ = app_fixture()
    path = tmp_path / "custom.yaml"
    result = CliRunner().invoke(app, ["--config", str(path), "status"])
    assert result.exit_code == 0
    assert backend.config_paths == [path]


def _admin_app(
    secrets: Sequence[bytes],
) -> tuple[typer.Typer, FakeBackend, FakeSecretReader]:
    backend = FakeBackend()
    reader = FakeSecretReader(secrets)
    app = create_cli_app(
        backend=backend,
        processes=FakeProcesses(),
        browser=FakeBrowser(),
        secret_reader=reader,
        base_environment={"SERVICE_API_KEY": _SECRET_CANARY},
    )
    return app, backend, reader


def test_account_add_and_rotate_use_only_hidden_reader_and_zero_secret_buffers() -> None:
    canary = _SECRET_CANARY.encode()
    app, backend, reader = _admin_app((canary, canary))
    runner = CliRunner()

    added = runner.invoke(
        app,
        [
            "accounts",
            "add",
            "--provider",
            "firecrawl",
            "--team-id",
            "team-primary",
            "--alias",
            "primary",
            "--pool",
            "interactive-default",
            "--priority",
            "10",
            "--mutation-id",
            "mut_account_add",
        ],
    )
    rotated = runner.invoke(
        app,
        [
            "accounts",
            "rotate",
            "primary",
            "--mutation-id",
            "mut_account_rotate",
            "--expires-at-ms",
            "9000",
        ],
    )

    assert added.exit_code == rotated.exit_code == 0
    assert backend.secret_snapshots == [canary, canary]
    assert all(buffer == bytearray(len(buffer)) for buffer in reader.buffers)
    assert all(buffer == bytearray(len(buffer)) for buffer in backend.secret_buffers)
    assert [prompt for prompt, _ in reader.prompts] == [
        "Firecrawl account secret: ",
        "Replacement Firecrawl account secret: ",
    ]
    assert [action for action, _ in backend.admin_calls] == [
        "account-add",
        "account-rotate",
    ]
    assert _SECRET_CANARY not in added.output + rotated.output


@pytest.mark.parametrize("option", ["--secret", "--api-key", "--key-file"])
def test_account_secret_cannot_be_supplied_by_cli_option(option: str) -> None:
    app, backend, reader = _admin_app((b"unused",))
    result = CliRunner().invoke(
        app,
        [
            "accounts",
            "add",
            "--provider",
            "firecrawl",
            "--team-id",
            "team-primary",
            "--alias",
            "primary",
            "--pool",
            "interactive-default",
            "--priority",
            "10",
            "--mutation-id",
            "mut_account_add",
            option,
            _SECRET_CANARY,
        ],
    )

    assert result.exit_code != 0
    assert reader.prompts == []
    assert backend.admin_calls == []
    assert _SECRET_CANARY not in result.output
    assert _SECRET_CANARY not in repr(result.exception)


def test_account_metadata_commands_are_secret_free_and_remove_requires_confirmation() -> None:
    app, backend, reader = _admin_app(())
    runner = CliRunner()

    listed = runner.invoke(app, ["accounts", "list", "--limit", "5"])
    status = runner.invoke(app, ["accounts", "status", "primary"])
    disabled = runner.invoke(
        app,
        [
            "accounts",
            "disable",
            "primary",
            "--mutation-id",
            "mut_disable",
            "--reason",
            "operator request",
        ],
    )
    recovered = runner.invoke(
        app,
        [
            "accounts",
            "recover",
            "primary",
            "--mutation-id",
            "mut_recover",
            "--reason",
            "operator verified recovery",
        ],
    )
    refreshed = runner.invoke(
        app,
        [
            "accounts",
            "refresh",
            "primary",
            "--mutation-id",
            "mut_refresh",
        ],
    )
    observations = [
        runner.invoke(
            app,
            [
                "accounts",
                "observe",
                action,
                "primary",
                "--mutation-id",
                f"mut_observe_{action}",
                "--reason",
                "operator request",
            ],
        )
        for action in ("enable", "disable")
    ]
    unconfirmed = runner.invoke(
        app,
        [
            "accounts",
            "remove",
            "primary",
            "--mutation-id",
            "mut_remove",
            "--reason",
            "operator request",
        ],
    )
    removed = runner.invoke(
        app,
        [
            "accounts",
            "remove",
            "primary",
            "--mutation-id",
            "mut_remove",
            "--reason",
            "operator request",
            "--confirm-human",
            "primary",
        ],
    )

    assert listed.exit_code == status.exit_code == disabled.exit_code == recovered.exit_code == 0
    assert refreshed.exit_code == 0
    assert all(result.exit_code == 0 for result in observations)
    assert unconfirmed.exit_code != 0
    assert removed.exit_code == 0
    assert reader.prompts == []
    assert [action for action, _ in backend.admin_calls] == [
        "account-list",
        "account-status",
        "account-disable",
        "account-recover",
        "account-refresh",
        "account-observe-enable",
        "account-observe-disable",
        "account-remove",
    ]
    rendered = (
        listed.output
        + status.output
        + disabled.output
        + recovered.output
        + refreshed.output
        + "".join(result.output for result in observations)
        + removed.output
    )
    assert _SECRET_CANARY not in rendered
    assert "credential_id" not in rendered
    assert "quota_scope_id" not in rendered


def test_secret_commands_use_only_injected_hidden_reader_and_zero_every_buffer() -> None:
    canary = _SECRET_CANARY.encode()
    app, backend, reader = _admin_app((canary, canary, canary))
    runner = CliRunner()

    provision = runner.invoke(
        app,
        [
            "credentials",
            "provision",
            "--mutation-id",
            "mut_provision",
            "--principal-id",
            "principal_one",
            "--quota-scope-id",
            "quota_one",
            "--pool-id",
            "pool_one",
            "--alias",
            "primary",
            "--exclusive-usage",
        ],
    )
    rotate = runner.invoke(
        app,
        [
            "credentials",
            "rotate",
            "cred_one",
            "--mutation-id",
            "mut_rotate",
            "--expires-at-ms",
            "9000",
        ],
    )
    emergency = runner.invoke(
        app,
        [
            "emergency",
            "unlock",
            "--mutation-id",
            "mut_unlock",
            "--service",
            "firecrawl",
            "--pool-id",
            "emergency-locked",
            "--session-id",
            "ses_one",
            "--root-run-id",
            "run_one",
            "--alias",
            "break-glass",
            "--reason",
            "manual incident recovery",
            "--duration-ms",
            "60000",
            "--maximum-requests",
            "2",
            "--maximum-credits",
            "5",
        ],
    )

    assert provision.exit_code == rotate.exit_code == emergency.exit_code == 0
    assert backend.secret_snapshots == [canary, canary, canary]
    assert all(buffer == bytearray(len(buffer)) for buffer in reader.buffers)
    assert all(buffer == bytearray(len(buffer)) for buffer in backend.secret_buffers)
    combined_output = provision.stdout + rotate.stdout + emergency.stdout
    assert _SECRET_CANARY not in combined_output
    assert '"maximum_concurrency": 1' not in combined_output
    assert [prompt for prompt, _ in reader.prompts] == [
        "Credential secret: ",
        "Replacement credential secret: ",
        "Emergency credential secret: ",
    ]


@pytest.mark.parametrize(
    "command",
    [
        [
            "credentials",
            "provision",
            "--mutation-id",
            "mut_failure",
            "--principal-id",
            "principal_one",
            "--quota-scope-id",
            "quota_one",
            "--pool-id",
            "pool_one",
            "--alias",
            "primary",
        ],
        [
            "credentials",
            "rotate",
            "cred_one",
            "--mutation-id",
            "mut_rotate_failure",
        ],
        [
            "emergency",
            "unlock",
            "--mutation-id",
            "mut_unlock_failure",
            "--service",
            "firecrawl",
            "--pool-id",
            "emergency-locked",
            "--session-id",
            "ses_one",
            "--root-run-id",
            "run_one",
            "--alias",
            "break-glass",
            "--reason",
            "manual incident recovery",
            "--duration-ms",
            "60000",
            "--maximum-requests",
            "2",
            "--maximum-credits",
            "5",
        ],
    ],
    ids=("provision", "rotate", "emergency"),
)
def test_secret_buffer_is_zeroed_when_backend_rejects_the_command(
    command: list[str],
) -> None:
    canary = _SECRET_CANARY.encode()
    app, backend, reader = _admin_app((canary,))
    backend.fail_secret_action = True

    assert _SECRET_CANARY not in "\0".join(command)
    result = CliRunner().invoke(app, command)

    assert result.exit_code == 2
    assert reader.buffers[0] == bytearray(len(canary))
    assert _SECRET_CANARY not in result.output
    assert _SECRET_CANARY not in repr(result.exception)


@pytest.mark.parametrize("option", ["--secret", "--api-key"])
def test_secret_or_api_key_cannot_be_supplied_by_argv(option: str) -> None:
    app, backend, reader = _admin_app((b"unused",))
    result = CliRunner().invoke(
        app,
        [
            "credentials",
            "provision",
            "--mutation-id",
            "mut_one",
            "--principal-id",
            "principal_one",
            "--quota-scope-id",
            "quota_one",
            "--pool-id",
            "pool_one",
            "--alias",
            "primary",
            option,
            _SECRET_CANARY,
        ],
    )

    assert result.exit_code != 0
    assert reader.prompts == []
    assert backend.admin_calls == []
    assert _SECRET_CANARY not in result.output
    assert _SECRET_CANARY not in repr(result.exception)


def test_state_and_emergency_metadata_commands_never_read_a_secret() -> None:
    app, backend, reader = _admin_app(())
    runner = CliRunner()

    for action in ("disable", "quarantine", "retire"):
        result = runner.invoke(
            app,
            [
                "credentials",
                action,
                "cred_one",
                "--mutation-id",
                f"mut_{action}",
                "--reason",
                "operator request",
            ],
        )
        assert result.exit_code == 0

    credentials = runner.invoke(app, ["credentials", "list", "--limit", "5"])
    validated = runner.invoke(
        app,
        ["credentials", "validate", "cred_one", "--generation", "3"],
    )
    listed = runner.invoke(app, ["emergency", "list", "--limit", "7"])
    cancelled = runner.invoke(
        app,
        [
            "emergency",
            "cancel",
            "unl_one",
            "--mutation-id",
            "mut_cancel",
            "--reason",
            "incident resolved",
        ],
    )
    assert credentials.exit_code == validated.exit_code == listed.exit_code == 0
    assert cancelled.exit_code == 0
    assert _SECRET_CANARY not in credentials.output
    assert json.loads(credentials.output) == [
        {
            "alias": "primary",
            "credential_id": "cred_one",
            "generation": 1,
            "service": "firecrawl",
            "state": "HEALTHY",
        }
    ]
    assert json.loads(validated.output) == {
        "credential_id": "cred_one",
        "generation": 3,
        "observed_plan_total_units_decimal": "100",
        "observed_remaining_units_decimal": "17",
        "plan_total_units": 100,
        "remaining_units": 17,
        "state": "authenticated",
    }
    assert reader.prompts == []
    assert [action for action, _ in backend.admin_calls] == [
        "disable",
        "quarantine",
        "retire",
        "credential-list",
        "validate",
        "emergency-list",
        "cancel",
    ]


def test_native_secret_reader_refuses_redirected_stdin_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    class NonInteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return False

    def forbidden_getpass(*args: object, **kwargs: object) -> str:
        nonlocal called
        del args, kwargs
        called = True
        return "must-not-be-read"

    monkeypatch.setattr("gatehouse.cli.contracts.sys.stdin", NonInteractiveInput())
    monkeypatch.setattr("gatehouse.cli.contracts.getpass.getpass", forbidden_getpass)
    with pytest.raises(CliUnavailable, match="interactive terminal"):
        InteractiveSecretReader().read_secret("Secret: ", maximum_bytes=32)
    assert not called


def test_native_secret_reader_turns_getpass_echo_fallback_into_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InteractiveStream:
        @staticmethod
        def isatty() -> bool:
            return True

    def echo_fallback(*args: object, **kwargs: object) -> str:
        del args, kwargs
        raise getpass.GetPassWarning("password input may be echoed")

    monkeypatch.setattr("gatehouse.cli.contracts.sys.stdin", InteractiveStream())
    monkeypatch.setattr("gatehouse.cli.contracts.sys.stderr", InteractiveStream())
    monkeypatch.setattr("gatehouse.cli.contracts.getpass.getpass", echo_fallback)
    with pytest.raises(CliUnavailable, match="hidden secret input"):
        InteractiveSecretReader().read_secret("Secret: ", maximum_bytes=32)


def test_windows_native_secret_reader_builds_only_a_mutable_full_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return True

        @staticmethod
        def fileno() -> int:
            return 0

    class InteractiveError:
        def __init__(self) -> None:
            self.output = ""

        @staticmethod
        def isatty() -> bool:
            return True

        def write(self, value: str) -> int:
            self.output += value
            return len(value)

        @staticmethod
        def flush() -> None:
            return None

    characters = iter([*"secrex", "\b", "t", "\r"])
    error_stream = InteractiveError()

    def forbidden_getpass(*args: object, **kwargs: object) -> str:
        del args, kwargs
        raise AssertionError("Windows native input fell back to immutable getpass")

    monkeypatch.setattr("gatehouse.cli.contracts._WINDOWS_NATIVE_CONSOLE", True)
    monkeypatch.setattr("gatehouse.cli.contracts.sys.stdin", InteractiveInput())
    monkeypatch.setattr("gatehouse.cli.contracts.sys.stderr", error_stream)
    monkeypatch.setattr("gatehouse.cli.contracts._read_windows_codepoint", lambda: next(characters))
    monkeypatch.setattr("gatehouse.cli.contracts.getpass.getpass", forbidden_getpass)

    secret = InteractiveSecretReader().read_secret("Secret: ", maximum_bytes=32)

    assert secret == bytearray(b"secret")
    assert error_stream.output == "Secret: \n"


def test_windows_native_secret_reader_zeroes_before_sanitizing_unexpected_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "WINDOWS-READER-FAILURE-CANARY-1234567890"

    class InteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return True

        @staticmethod
        def fileno() -> int:
            return 0

    class InteractiveError:
        @staticmethod
        def isatty() -> bool:
            return True

        @staticmethod
        def write(value: str) -> int:
            return len(value)

        @staticmethod
        def flush() -> None:
            return None

    characters = iter("secret")

    def failing_codepoint() -> str:
        try:
            return next(characters)
        except StopIteration:
            raise RuntimeError(canary) from None

    monkeypatch.setattr("gatehouse.cli.contracts._WINDOWS_NATIVE_CONSOLE", True)
    monkeypatch.setattr("gatehouse.cli.contracts.sys.stdin", InteractiveInput())
    monkeypatch.setattr("gatehouse.cli.contracts.sys.stderr", InteractiveError())
    monkeypatch.setattr("gatehouse.cli.contracts._read_windows_codepoint", failing_codepoint)

    with pytest.raises(CliUnavailable, match="hidden secret input") as captured:
        InteractiveSecretReader().read_secret("Secret: ", maximum_bytes=32)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert canary not in repr(captured.value)
