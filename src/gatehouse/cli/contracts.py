"""Injectable side-effect contracts for the human-facing CLI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Never, Protocol


class CliUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ControlledLaunch:
    session_id: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("a controlled launch requires a session identifier")
        if not self.argv or any(not part for part in self.argv):
            raise ValueError("a controlled launch requires a non-empty argument vector")
        environment = dict(self.environment)
        expected = {
            "GATEHOUSE_AGENT_URL",
            "GATEHOUSE_SESSION_BOOTSTRAP",
            "GATEHOUSE_SESSION_ID",
        }
        if set(environment) != expected or environment["GATEHOUSE_SESSION_ID"] != self.session_id:
            raise ValueError("controlled launch metadata must contain only exact session authority")
        if any(not value for value in environment.values()):
            raise ValueError("controlled launch metadata values cannot be empty")
        object.__setattr__(self, "environment", MappingProxyType(environment))


class CliBackend(Protocol):
    def set_config_path(self, config_path: Path) -> None: ...

    def status(self) -> Mapping[str, object]: ...

    def daemon_run(self) -> Mapping[str, object]: ...

    def daemon_start(self) -> Mapping[str, object]: ...

    def daemon_stop(self) -> Mapping[str, object]: ...

    def daemon_status(self) -> Mapping[str, object]: ...

    def prepare_launch(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
        command: Sequence[str],
    ) -> ControlledLaunch: ...

    def cleanup_launch(self, launch: ControlledLaunch, *, revoke: bool) -> None: ...

    def approval_list(self) -> Sequence[Mapping[str, object]]: ...

    def approval_action(self, approval_id: str, decision: str) -> Mapping[str, object]: ...

    def policy_explain(
        self,
        *,
        client: str,
        workspace: str,
        service: str,
        operation: str,
    ) -> Mapping[str, object]: ...

    def docs_search(
        self,
        service: str,
        query: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Sequence[Mapping[str, object]]: ...

    def docs_get(
        self,
        service: str,
        document: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]: ...

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
    ) -> Mapping[str, object]: ...

    def dashboard_login_url(self) -> str: ...


class ProcessRunner(Protocol):
    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int: ...


class BrowserOpener(Protocol):
    def open(self, url: str) -> bool: ...


class UnavailableCliBackend:
    def _unavailable(self) -> Never:
        raise CliUnavailable("the daemon control client has not been composed")

    def set_config_path(self, config_path: Path) -> None:
        del config_path
        self._unavailable()

    def status(self) -> Mapping[str, object]:
        self._unavailable()

    def daemon_run(self) -> Mapping[str, object]:
        self._unavailable()

    def daemon_start(self) -> Mapping[str, object]:
        self._unavailable()

    def daemon_stop(self) -> Mapping[str, object]:
        self._unavailable()

    def daemon_status(self) -> Mapping[str, object]:
        self._unavailable()

    def prepare_launch(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
        command: Sequence[str],
    ) -> ControlledLaunch:
        del client, workspace, non_interactive, command
        self._unavailable()

    def cleanup_launch(self, launch: ControlledLaunch, *, revoke: bool) -> None:
        del launch, revoke
        self._unavailable()

    def approval_list(self) -> Sequence[Mapping[str, object]]:
        self._unavailable()

    def approval_action(self, approval_id: str, decision: str) -> Mapping[str, object]:
        del approval_id, decision
        self._unavailable()

    def policy_explain(
        self,
        *,
        client: str,
        workspace: str,
        service: str,
        operation: str,
    ) -> Mapping[str, object]:
        del client, workspace, service, operation
        self._unavailable()

    def docs_search(
        self,
        service: str,
        query: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Sequence[Mapping[str, object]]:
        del service, query, client, workspace, non_interactive
        self._unavailable()

    def docs_get(
        self,
        service: str,
        document: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]:
        del service, document, client, workspace, non_interactive
        self._unavailable()

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
        del category, severity, component, summary, client, workspace, non_interactive
        self._unavailable()

    def dashboard_login_url(self) -> str:
        self._unavailable()


class UnavailableProcessRunner:
    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int:
        del launch, environment
        raise CliUnavailable("the controlled process runner has not been composed")


class NativeBrowserOpener:
    def open(self, url: str) -> bool:
        import webbrowser

        return webbrowser.open(url, new=2, autoraise=True)
