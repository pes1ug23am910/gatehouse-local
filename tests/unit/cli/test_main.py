from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import typer
from typer.testing import CliRunner

from gatehouse.cli.contracts import (
    ControlledLaunch,
    UnavailableCliBackend,
)
from gatehouse.cli.main import create_cli_app


class FakeBackend(UnavailableCliBackend):
    def __init__(self) -> None:
        self.actions: list[tuple[str, str]] = []
        self.launches: list[tuple[str, str, bool, tuple[str, ...]]] = []
        self.cleanups: list[tuple[str, bool]] = []
        self.config_paths: list[Path] = []

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
            "FUTURE_SERVICE_API_KEY": "must-not-propagate",
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
