"""Injectable side-effect contracts for the human-facing CLI."""

from __future__ import annotations

import getpass
import sys
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Never, Protocol

_WINDOWS_NATIVE_CONSOLE = sys.platform == "win32"


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

    def credential_list(self, *, limit: int) -> Sequence[Mapping[str, object]]: ...

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
    ) -> Mapping[str, object]: ...

    def credential_rotate(
        self,
        credential_id: str,
        secret: bytearray,
        *,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]: ...

    def credential_change_state(
        self,
        credential_id: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]: ...

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
    ) -> Mapping[str, object]: ...

    def emergency_list(self, *, limit: int) -> Sequence[Mapping[str, object]]: ...

    def emergency_cancel(
        self,
        unlock_id: str,
        *,
        mutation_id: str,
        reason: str,
    ) -> Mapping[str, object]: ...


class ProcessRunner(Protocol):
    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int: ...


class BrowserOpener(Protocol):
    def open(self, url: str) -> bool: ...


class SecretReader(Protocol):
    """Read one bounded secret from an interactive hidden terminal."""

    def read_secret(self, prompt: str, *, maximum_bytes: int) -> bytearray: ...


class InteractiveSecretReader:
    """Native no-echo reader with no redirected-stdin fallback."""

    def read_secret(self, prompt: str, *, maximum_bytes: int) -> bytearray:
        if maximum_bytes <= 0:
            raise ValueError("secret input bound must be positive")
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise CliUnavailable("an interactive terminal is required for secret input")
        if _WINDOWS_NATIVE_CONSOLE and callable(getattr(sys.stdin, "fileno", None)):
            return _read_windows_secret(prompt, maximum_bytes=maximum_bytes)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass(prompt=prompt, stream=sys.stderr)
        except getpass.GetPassWarning as error:
            raise CliUnavailable("hidden secret input is unavailable") from error
        except (EOFError, KeyboardInterrupt) as error:
            raise CliUnavailable("secret input was cancelled") from error
        encoded = bytearray(value.encode("utf-8"))
        del value
        if not encoded or len(encoded) > maximum_bytes:
            encoded[:] = b"\x00" * len(encoded)
            raise CliUnavailable("secret input is outside the allowed size")
        return encoded


def _read_windows_secret(prompt: str, *, maximum_bytes: int) -> bytearray:
    """Read a Windows console one code point at a time into zeroable storage."""

    value = bytearray()
    encoded_lengths: list[int] = []
    overflowed = False
    cancelled = False
    unavailable = False
    unexpected_failure = False
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        while True:
            try:
                character = _read_windows_codepoint()
            except OSError:
                unavailable = True
                break
            if character in {"\r", "\n"}:
                break
            if character == "\x03":
                cancelled = True
                break
            if character in {"\x00", "\xe0"}:
                # Consume the second code unit of a function/navigation key.
                try:
                    _read_windows_codepoint()
                except OSError:
                    unavailable = True
                    break
                continue
            if character == "\b":
                if encoded_lengths and not overflowed:
                    del value[-encoded_lengths.pop() :]
                continue
            code_unit = ord(character)
            if 0xD800 <= code_unit <= 0xDBFF:
                try:
                    trailing = _read_windows_codepoint()
                except OSError:
                    unavailable = True
                    break
                trailing_unit = ord(trailing)
                if not 0xDC00 <= trailing_unit <= 0xDFFF:
                    unavailable = True
                    break
                character = chr(0x10000 + ((code_unit - 0xD800) << 10) + (trailing_unit - 0xDC00))
            elif 0xDC00 <= code_unit <= 0xDFFF:
                unavailable = True
                break
            character_bytes = character.encode("utf-8")
            if not overflowed:
                value.extend(character_bytes)
                encoded_lengths.append(len(character_bytes))
                if len(value) > maximum_bytes:
                    value[:] = b"\x00" * len(value)
                    value.clear()
                    encoded_lengths.clear()
                    overflowed = True
            character_bytes = b""
            character = ""
    except BaseException:
        unexpected_failure = True
    finally:
        try:
            sys.stderr.write("\n")
            sys.stderr.flush()
        except BaseException:
            unexpected_failure = True
    if unexpected_failure or cancelled or unavailable or overflowed or not value:
        value[:] = b"\x00" * len(value)
        value.clear()
        encoded_lengths.clear()
        if unexpected_failure:
            raise CliUnavailable("hidden secret input is unavailable") from None
        if cancelled:
            raise CliUnavailable("secret input was cancelled") from None
        if unavailable:
            raise CliUnavailable("hidden secret input is unavailable") from None
        raise CliUnavailable("secret input is outside the allowed size") from None
    return value


def _read_windows_codepoint() -> str:
    import msvcrt

    return msvcrt.getwch()


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

    def credential_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        del limit
        self._unavailable()

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
        del (
            secret,
            mutation_id,
            principal_id,
            quota_scope_id,
            pool_id,
            alias,
            expires_at_ms,
            exclusive_usage,
        )
        self._unavailable()

    def credential_rotate(
        self,
        credential_id: str,
        secret: bytearray,
        *,
        mutation_id: str,
        expires_at_ms: int | None,
    ) -> Mapping[str, object]:
        del credential_id, secret, mutation_id, expires_at_ms
        self._unavailable()

    def credential_change_state(
        self,
        credential_id: str,
        *,
        mutation_id: str,
        action: str,
        reason: str,
    ) -> Mapping[str, object]:
        del credential_id, mutation_id, action, reason
        self._unavailable()

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
        del (
            secret,
            mutation_id,
            service,
            pool_id,
            session_id,
            root_run_id,
            alias,
            reason,
            duration_ms,
            maximum_requests,
            maximum_credits,
        )
        self._unavailable()

    def emergency_list(self, *, limit: int) -> Sequence[Mapping[str, object]]:
        del limit
        self._unavailable()

    def emergency_cancel(
        self,
        unlock_id: str,
        *,
        mutation_id: str,
        reason: str,
    ) -> Mapping[str, object]:
        del unlock_id, mutation_id, reason
        self._unavailable()


class UnavailableProcessRunner:
    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int:
        del launch, environment
        raise CliUnavailable("the controlled process runner has not been composed")


class NativeBrowserOpener:
    def open(self, url: str) -> bool:
        import webbrowser

        return webbrowser.open(url, new=2, autoraise=True)
