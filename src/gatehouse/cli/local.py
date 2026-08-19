"""Production loopback clients and process adapters for the installed CLI."""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Protocol, cast
from urllib.parse import quote, urlencode

import httpx

from gatehouse.admin.control import CONTROL_CAPABILITY_HEADER
from gatehouse.admin.control_capability import (
    ControlCapabilityStorageError,
    load_control_capability,
)
from gatehouse.admin.models import ApprovalView
from gatehouse.api.admin import ADMIN_COOKIE_NAME, CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from gatehouse.api.contracts import PolicyExplainRequest, PolicyExplainResponse
from gatehouse.config import ConfigLoadError, load_main_config
from gatehouse.core.errors import JsonValue
from gatehouse.daemon.composition import installation_state_paths
from gatehouse.daemon.main import default_config_path

from .contracts import CliUnavailable, ControlledLaunch

_MAXIMUM_REQUEST_BYTES = 64 * 1_024
_MAXIMUM_RESPONSE_BYTES = 4 * 1_024 * 1_024
_DEFAULT_TIMEOUT_SECONDS = 35.0
_CONTROL_CAPABILITY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_APPROVAL_PUBLIC_FIELDS = (
    "approval_id",
    "session_id",
    "client_id",
    "workspace_id",
    "service",
    "operation",
    "request_fingerprint",
    "target_summary",
    "pool",
    "maximum_estimated_cost",
    "maximum_uses",
    "expires_at_ms",
    "state",
)
_POLICY_OPERATION_CAPABILITIES = MappingProxyType(
    {
        "search": "firecrawl.search",
        "scrape": "firecrawl.scrape",
        "map": "firecrawl.map",
        "crawl": "firecrawl.crawl.start",
    }
)

type TransportFactory = Callable[[], httpx.BaseTransport]
type CapabilityLoader = Callable[[Path], str]
type JsonObject = dict[str, JsonValue]


class _LoopbackRequestError(RuntimeError):
    """Internal sanitized transport/protocol failure."""


class DaemonChild(Protocol):
    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...


class DaemonProcessRunner(Protocol):
    def run(self, arguments: Sequence[str]) -> int: ...

    def start(self, arguments: Sequence[str]) -> DaemonChild: ...


class NativeDaemonProcessRunner:
    """Start the installed daemon without a shell or inherited console handles."""

    def run(self, arguments: Sequence[str]) -> int:
        try:
            completed = subprocess.run(  # noqa: S603
                tuple(arguments),
                check=False,
            )
        except OSError as error:
            raise CliUnavailable("the installed Gatehouse daemon could not be started") from error
        return completed.returncode

    def start(self, arguments: Sequence[str]) -> DaemonChild:
        try:
            if os.name == "nt":
                return subprocess.Popen(  # noqa: S603
                    tuple(arguments),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        | subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP
                    ),
                )
            return subprocess.Popen(  # noqa: S603
                tuple(arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise CliUnavailable("the installed Gatehouse daemon could not be started") from error


class NativeProcessRunner:
    """Run one explicitly requested controlled child without shell interpretation."""

    def run(self, launch: ControlledLaunch, *, environment: Mapping[str, str]) -> int:
        try:
            completed = subprocess.run(  # noqa: S603
                launch.argv,
                env=dict(environment),
                check=False,
            )
        except OSError as error:
            raise CliUnavailable("the controlled client process could not be started") from error
        return completed.returncode


@dataclass(frozen=True, slots=True)
class _LocalSettings:
    config_path: Path
    database_path: Path
    agent_url: str
    admin_url: str
    readiness_timeout_seconds: float


class _BoundedJsonClient:
    """Small synchronous JSON client with fixed local-only transport policy."""

    __slots__ = (
        "_client",
        "_maximum_request_bytes",
        "_maximum_response_bytes",
    )

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float,
        maximum_request_bytes: int,
        maximum_response_bytes: int,
        transport_factory: TransportFactory | None,
    ) -> None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("CLI HTTP timeout must be between zero and 60 seconds")
        if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
            raise ValueError("CLI HTTP body limits must be positive")
        transport = transport_factory() if transport_factory is not None else None
        self._client = httpx.Client(
            base_url=base_url,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
            transport=transport,
        )
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes

    @property
    def cookies(self) -> httpx.Cookies:
        return self._client.cookies

    def __enter__(self) -> _BoundedJsonClient:
        self._client.__enter__()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._client.__exit__(exception_type, exception, traceback)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
    ) -> tuple[int, JsonObject]:
        encoded: bytes | None = None
        if payload is not None:
            try:
                encoded = json.dumps(
                    dict(payload),
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise _LoopbackRequestError("request body is not valid JSON") from error
            if len(encoded) > self._maximum_request_bytes:
                raise _LoopbackRequestError("request body exceeds the configured limit")
        request_headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        if headers is not None:
            request_headers.update(headers)
        try:
            with self._client.stream(
                method,
                path,
                content=encoded,
                headers=request_headers,
                params=query,
            ) as response:
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        declared_length = int(declared)
                    except ValueError as error:
                        raise _LoopbackRequestError("response content length is invalid") from error
                    if not 0 <= declared_length <= self._maximum_response_bytes:
                        raise _LoopbackRequestError("response body exceeds the configured limit")
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > self._maximum_response_bytes:
                        raise _LoopbackRequestError("response body exceeds the configured limit")
                content_type = response.headers.get("content-type", "")
                if content_type.partition(";")[0].strip().casefold() != "application/json":
                    raise _LoopbackRequestError("response is not JSON")
                try:
                    decoded = json.loads(content.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise _LoopbackRequestError("response JSON is invalid") from error
                if not isinstance(decoded, dict) or any(
                    not isinstance(key, str) for key in decoded
                ):
                    raise _LoopbackRequestError("response JSON root is not an object")
                return response.status_code, cast(JsonObject, decoded)
        except httpx.HTTPError as error:
            raise _LoopbackRequestError("loopback request failed") from error


def _required_identifier(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise _LoopbackRequestError(f"{label} is invalid")
    return value


def _required_string(
    value: object,
    *,
    label: str,
    minimum: int = 1,
    maximum: int = 1_000,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise _LoopbackRequestError(f"{label} is invalid")
    return value


def _required_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _LoopbackRequestError(f"{label} is invalid")
    return value


def _success(
    result: tuple[int, JsonObject],
    *,
    expected: frozenset[int] = frozenset({200}),
    action: str,
) -> JsonObject:
    status, body = result
    if status not in expected:
        raise _LoopbackRequestError(f"{action} was rejected")
    return body


def _loopback_url(host: str, port: int) -> str:
    # Stock composition binds only this literal; rejecting other loopback aliases
    # keeps proxy/DNS behavior completely outside the CLI trust boundary.
    if host != "127.0.0.1":
        raise CliUnavailable("Gatehouse v1 requires the numeric loopback host 127.0.0.1")
    return f"http://127.0.0.1:{port}"


def _locate_daemon_executable() -> Path | None:
    name = "gatehoused.exe" if os.name == "nt" else "gatehoused"
    adjacent = Path(sys.executable).with_name(name)
    if adjacent.is_file():
        return adjacent
    located = shutil.which(name)
    return Path(located) if located is not None else None


class LocalCliBackend:
    """DPAPI-authenticated local control plus short-lived typed API sessions."""

    __slots__ = (
        "_capability_loader",
        "_config_path",
        "_control_capability",
        "_daemon_executable",
        "_daemon_processes",
        "_environment",
        "_maximum_request_bytes",
        "_maximum_response_bytes",
        "_monotonic",
        "_settings_cache",
        "_sleep",
        "_timeout_seconds",
        "_transport_factory",
    )

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        environment: Mapping[str, str] | None = None,
        transport_factory: TransportFactory | None = None,
        capability_loader: CapabilityLoader = load_control_capability,
        daemon_processes: DaemonProcessRunner | None = None,
        daemon_executable: Path | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        maximum_request_bytes: int = _MAXIMUM_REQUEST_BYTES,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("CLI timeout must be between zero and 60 seconds")
        if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
            raise ValueError("CLI HTTP body limits must be positive")
        source = os.environ if environment is None else environment
        self._environment = {str(key): str(value) for key, value in source.items()}
        self._config_path = (
            Path(config_path)
            if config_path is not None
            else default_config_path(environment=dict(self._environment))
        )
        self._transport_factory = transport_factory
        self._capability_loader = capability_loader
        self._daemon_processes = daemon_processes or NativeDaemonProcessRunner()
        self._daemon_executable = daemon_executable
        self._timeout_seconds = timeout_seconds
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes
        self._monotonic = monotonic
        self._sleep = sleep
        self._settings_cache: _LocalSettings | None = None
        self._control_capability: str | None = None

    def set_config_path(self, config_path: Path) -> None:
        raw = str(config_path)
        if not raw or any(character in raw for character in "\x00\n\r"):
            raise CliUnavailable("the Gatehouse configuration path is invalid")
        self._config_path = Path(config_path)
        self._settings_cache = None
        self._control_capability = None

    def _settings(self) -> _LocalSettings:
        cached = self._settings_cache
        if cached is not None:
            return cached
        try:
            configuration = load_main_config(
                self._config_path,
                environment=self._environment,
            )
            agent_url = _loopback_url(
                configuration.server.agent.host,
                configuration.server.agent.port,
            )
            admin_url = _loopback_url(
                configuration.server.admin.host,
                configuration.server.admin.port,
            )
        except ConfigLoadError as error:
            raise CliUnavailable(str(error)) from error
        except ValueError as error:
            raise CliUnavailable("the Gatehouse configuration is invalid") from error
        cached = _LocalSettings(
            config_path=self._config_path.resolve(),
            database_path=Path(configuration.database.path),
            agent_url=agent_url,
            admin_url=admin_url,
            readiness_timeout_seconds=configuration.watchdog.readiness_timeout / 1_000,
        )
        self._settings_cache = cached
        return cached

    def _http(self, base_url: str) -> _BoundedJsonClient:
        return _BoundedJsonClient(
            base_url=base_url,
            timeout_seconds=self._timeout_seconds,
            maximum_request_bytes=self._maximum_request_bytes,
            maximum_response_bytes=self._maximum_response_bytes,
            transport_factory=self._transport_factory,
        )

    def _capability(self) -> str:
        if self._control_capability is not None:
            return self._control_capability
        path = installation_state_paths(self._settings().database_path).control_capability
        try:
            capability = self._capability_loader(path)
        except (ControlCapabilityStorageError, OSError, RuntimeError, ValueError) as error:
            raise _LoopbackRequestError("local control capability is unavailable") from error
        if (
            not isinstance(capability, str)
            or _CONTROL_CAPABILITY_PATTERN.fullmatch(capability) is None
        ):
            raise _LoopbackRequestError("local control capability is invalid")
        self._control_capability = capability
        return capability

    def _control_request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
    ) -> tuple[int, JsonObject]:
        settings = self._settings()
        capability = self._capability()
        with self._http(settings.admin_url) as client:
            return client.request(
                method,
                path,
                payload=payload,
                headers={CONTROL_CAPABILITY_HEADER: capability},
            )

    def _control_status(self) -> JsonObject:
        return _success(
            self._control_request("GET", "/v1/control/status"),
            action="daemon status request",
        )

    def _agent_live(self) -> bool:
        try:
            with self._http(self._settings().agent_url) as client:
                status, body = client.request("GET", "/health/live")
            return status == 200 and body.get("status") == "live"
        except _LoopbackRequestError:
            return False

    @staticmethod
    def _status_view(
        body: Mapping[str, JsonValue],
        *,
        ready: bool | None = None,
    ) -> JsonObject:
        readiness = body.get("ready") if ready is None else ready
        if not isinstance(readiness, bool):
            raise _LoopbackRequestError("daemon readiness is invalid")
        status = _required_string(body.get("status"), label="daemon status", maximum=64)
        version = _required_string(body.get("version"), label="daemon version", maximum=64)
        schema_version = _required_integer(body.get("schema_version"), label="schema version")
        policy_version = _required_string(
            body.get("policy_version"),
            label="policy version",
            maximum=160,
        )
        uptime = _required_integer(body.get("uptime_seconds"), label="daemon uptime")
        degraded = body.get("degraded_components")
        if not isinstance(degraded, list) or any(not isinstance(item, str) for item in degraded):
            raise _LoopbackRequestError("degraded component list is invalid")
        return {
            "ready": readiness,
            "status": status,
            "version": version,
            "schema_version": schema_version,
            "policy_version": policy_version,
            "uptime_seconds": uptime,
            "degraded_components": degraded,
        }

    def status(self) -> Mapping[str, object]:
        try:
            with self._http(self._settings().agent_url) as client:
                status, body = client.request("GET", "/health/ready")
            if status not in {200, 503}:
                raise _LoopbackRequestError("readiness request was rejected")
            return self._status_view(body, ready=status == 200)
        except _LoopbackRequestError:
            if not self._agent_live():
                return {"ready": False, "status": "STOPPED"}
            raise CliUnavailable("the local Gatehouse readiness response is invalid") from None

    def _daemon_arguments(self) -> tuple[str, ...]:
        executable = self._daemon_executable or _locate_daemon_executable()
        if executable is None or not executable.is_file():
            raise CliUnavailable("the installed gatehoused entry point was not found")
        return (str(executable), "--config", str(self._settings().config_path))

    def daemon_run(self) -> Mapping[str, object]:
        code = self._daemon_processes.run(self._daemon_arguments())
        return {"action": "run", "exit_code": code}

    def daemon_start(self) -> Mapping[str, object]:
        try:
            existing = self._status_view(self._control_status())
        except _LoopbackRequestError:
            if self._agent_live():
                raise CliUnavailable(
                    "a process is listening on the Gatehouse port but failed control authentication"
                ) from None
        else:
            return {"action": "start", "started": False, **existing}

        child = self._daemon_processes.start(self._daemon_arguments())
        deadline = self._monotonic() + self._settings().readiness_timeout_seconds
        while True:
            if child.poll() is not None:
                raise CliUnavailable("the Gatehouse daemon exited before becoming ready")
            try:
                ready = self._status_view(self._control_status())
            except _LoopbackRequestError:
                pass
            else:
                return {"action": "start", "started": True, **ready}
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                with suppress(OSError):
                    child.terminate()
                raise CliUnavailable("the Gatehouse daemon did not become ready in time")
            self._sleep(min(0.1, remaining))

    def daemon_stop(self) -> Mapping[str, object]:
        try:
            self._control_status()
        except _LoopbackRequestError as error:
            if not self._agent_live():
                return {"action": "stop", "stopped": False, "status": "STOPPED"}
            raise CliUnavailable(
                "the live Gatehouse daemon failed local control authentication"
            ) from error
        try:
            _success(
                self._control_request("POST", "/v1/control/drain"),
                action="daemon stop request",
            )
        except _LoopbackRequestError as error:
            raise CliUnavailable("the Gatehouse daemon rejected the authenticated stop") from error
        deadline = self._monotonic() + self._settings().readiness_timeout_seconds
        while self._agent_live():
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise CliUnavailable("the Gatehouse daemon did not stop in time")
            self._sleep(min(0.1, remaining))
        return {"action": "stop", "stopped": True, "status": "STOPPED"}

    def daemon_status(self) -> Mapping[str, object]:
        try:
            view = self._status_view(self._control_status())
        except _LoopbackRequestError as error:
            if not self._agent_live():
                return {"ready": False, "status": "STOPPED"}
            raise CliUnavailable(
                "the live Gatehouse daemon failed local control authentication"
            ) from error
        return view

    def _launch_session(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> tuple[str, str]:
        try:
            body = _success(
                self._control_request(
                    "POST",
                    "/v1/control/sessions",
                    payload={
                        "client": client,
                        "workspace": workspace,
                        "non_interactive": non_interactive,
                    },
                ),
                expected=frozenset({201}),
                action="controlled session launch",
            )
            session_id = _required_identifier(body.get("session_id"), label="session identifier")
            bootstrap = _required_string(
                body.get("bootstrap_capability"),
                label="session bootstrap",
                minimum=40,
                maximum=128,
            )
        except _LoopbackRequestError as error:
            raise CliUnavailable("the daemon rejected the configured client session") from error
        return session_id, bootstrap

    def prepare_launch(
        self,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
        command: Sequence[str],
    ) -> ControlledLaunch:
        arguments = tuple(command)
        if not arguments or any(not argument for argument in arguments):
            raise CliUnavailable("a controlled launch requires a command")
        session_id, bootstrap = self._launch_session(
            client=client,
            workspace=workspace,
            non_interactive=non_interactive,
        )
        return ControlledLaunch(
            session_id=session_id,
            argv=arguments,
            environment={
                "GATEHOUSE_AGENT_URL": self._settings().agent_url,
                "GATEHOUSE_SESSION_BOOTSTRAP": bootstrap,
                "GATEHOUSE_SESSION_ID": session_id,
            },
        )

    def _cleanup_session(self, session_id: str, *, revoke: bool) -> None:
        try:
            segment = quote(
                _required_identifier(session_id, label="session identifier"),
                safe="",
            )
            action = "revoke" if revoke else "disconnect"
            body = _success(
                self._control_request(
                    "POST",
                    f"/v1/control/sessions/{segment}/{action}",
                ),
                action="controlled session cleanup",
            )
            if body.get("session_id") != session_id:
                raise _LoopbackRequestError("session cleanup response is invalid")
            expected = "REVOKED" if revoke else "DISCONNECTED"
            if body.get("state") != expected:
                raise _LoopbackRequestError("session cleanup state is invalid")
        except _LoopbackRequestError as error:
            raise CliUnavailable("the controlled session could not be cleaned up") from error

    def cleanup_launch(self, launch: ControlledLaunch, *, revoke: bool) -> None:
        self._cleanup_session(launch.session_id, revoke=revoke)

    def _mint_admin_code(self) -> str:
        try:
            body = _success(
                self._control_request("POST", "/v1/control/admin/login-code"),
                action="admin login-code request",
            )
            code = _required_string(
                body.get("code"),
                label="admin login code",
                minimum=40,
                maximum=128,
            )
            _required_integer(body.get("expires_at_ms"), label="admin login-code expiry")
            return code
        except _LoopbackRequestError as error:
            raise CliUnavailable("the daemon could not create an admin login code") from error

    @contextmanager
    def _admin_session(self) -> Iterator[tuple[_BoundedJsonClient, str]]:
        code = self._mint_admin_code()
        with self._http(self._settings().admin_url) as client:
            try:
                login = _success(
                    client.request(
                        "POST",
                        "/v1/admin/login/exchange",
                        payload={"code": code},
                    ),
                    action="admin login exchange",
                )
                csrf = _required_string(
                    login.get("csrf_token"),
                    label="admin CSRF token",
                    minimum=32,
                    maximum=256,
                )
                _required_identifier(
                    login.get("admin_session_id"),
                    label="admin session identifier",
                )
                _required_integer(
                    login.get("idle_expires_at_ms"),
                    label="admin idle expiry",
                )
                _required_integer(
                    login.get("absolute_expires_at_ms"),
                    label="admin absolute expiry",
                )
                try:
                    admin_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
                    csrf_cookie = client.cookies.get(CSRF_COOKIE_NAME)
                except httpx.CookieConflict as error:
                    raise _LoopbackRequestError("admin login cookies are ambiguous") from error
                if (
                    not isinstance(admin_cookie, str)
                    or not 32 <= len(admin_cookie) <= 512
                    or not isinstance(csrf_cookie, str)
                    or not hmac.compare_digest(csrf, csrf_cookie)
                ):
                    raise _LoopbackRequestError("admin login cookies are invalid")
            except _LoopbackRequestError as error:
                raise CliUnavailable("the admin login exchange failed") from error
            yielded_cleanly = False
            try:
                yield client, csrf
                yielded_cleanly = True
            finally:
                try:
                    _success(
                        client.request(
                            "POST",
                            "/v1/admin/logout",
                            headers={
                                CSRF_HEADER_NAME: csrf,
                                "Origin": self._settings().admin_url,
                            },
                        ),
                        action="admin logout",
                    )
                except _LoopbackRequestError as error:
                    if yielded_cleanly:
                        raise CliUnavailable("the admin session could not be revoked") from error

    @staticmethod
    def _approval_view(item: object) -> JsonObject:
        try:
            approval = ApprovalView.model_validate(item)
        except (TypeError, ValueError) as error:
            raise _LoopbackRequestError("approval list response is invalid") from error
        dumped = approval.model_dump(mode="json", exclude={"action_token"})
        return {name: cast(JsonValue, dumped[name]) for name in _APPROVAL_PUBLIC_FIELDS}

    def approval_list(self) -> Sequence[Mapping[str, object]]:
        try:
            with self._admin_session() as (client, _):
                body = _success(
                    client.request(
                        "GET",
                        "/v1/admin/approvals",
                        query={"limit": "50"},
                    ),
                    action="approval list request",
                )
                approvals = body.get("approvals")
                if not isinstance(approvals, list):
                    raise _LoopbackRequestError("approval list response is invalid")
                return tuple(self._approval_view(item) for item in approvals)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the daemon returned an invalid approval list") from error

    def approval_action(self, approval_id: str, decision: str) -> Mapping[str, object]:
        if decision not in {"approve", "deny"}:
            raise CliUnavailable("the approval decision is invalid")
        try:
            segment = quote(_required_identifier(approval_id, label="approval identifier"), safe="")
            with self._admin_session() as (client, csrf):
                approval = _success(
                    client.request("GET", f"/v1/admin/approvals/{segment}"),
                    action="approval detail request",
                )
                try:
                    validated = ApprovalView.model_validate(approval)
                except (TypeError, ValueError) as error:
                    raise _LoopbackRequestError("approval detail response is invalid") from error
                if validated.approval_id != approval_id:
                    raise _LoopbackRequestError("approval detail identifier does not match")
                action_token = _required_string(
                    validated.action_token,
                    label="approval action token",
                    minimum=32,
                    maximum=256,
                )
                fingerprint = _required_string(
                    validated.request_fingerprint,
                    label="approval request fingerprint",
                    minimum=16,
                    maximum=256,
                )
                maximum_cost = _required_integer(
                    validated.maximum_estimated_cost,
                    label="approval maximum cost",
                )
                if validated.maximum_uses != 1:
                    raise _LoopbackRequestError("approval use bound is invalid")
                result = _success(
                    client.request(
                        "POST",
                        f"/v1/admin/approvals/{segment}/{decision}",
                        payload={
                            "action_token": action_token,
                            "request_fingerprint": fingerprint,
                            "maximum_estimated_cost": maximum_cost,
                            "maximum_uses": 1,
                        },
                        headers={
                            CSRF_HEADER_NAME: csrf,
                            "Origin": self._settings().admin_url,
                        },
                    ),
                    action="approval decision request",
                )
                returned_id = _required_identifier(
                    result.get("approval_id"),
                    label="approval result identifier",
                )
                state = _required_string(
                    result.get("state"),
                    label="approval result state",
                    maximum=64,
                )
                acted_at_ms = _required_integer(
                    result.get("acted_at_ms"),
                    label="approval action time",
                )
                if returned_id != approval_id:
                    raise _LoopbackRequestError("approval result identifier does not match")
                expected_state = {"approve": "APPROVED", "deny": "DENIED"}[decision]
                if state != expected_state:
                    raise _LoopbackRequestError("approval result state does not match decision")
                return {
                    "approval_id": returned_id,
                    "state": state,
                    "acted_at_ms": acted_at_ms,
                }
        except _LoopbackRequestError as error:
            raise CliUnavailable("the approval action failed") from error

    def policy_explain(
        self,
        *,
        client: str,
        workspace: str,
        service: str,
        operation: str,
    ) -> Mapping[str, object]:
        capability = _POLICY_OPERATION_CAPABILITIES.get(operation)
        if service != "firecrawl" or capability is None:
            raise CliUnavailable("the policy explanation request is not a supported operation")
        try:
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=False,
                required_capability=None,
            ) as (agent, access_token, session_id):
                root_run_id = self._create_agent_root_run(
                    agent,
                    access_token=access_token,
                    expected_session_id=session_id,
                )
                request = PolicyExplainRequest.model_validate(
                    {
                        "service": "firecrawl",
                        "operation": operation,
                        "context": {"root_run_id": root_run_id},
                    }
                )
                body = _success(
                    agent.request(
                        "POST",
                        "/v1/policy/explain",
                        payload=request.model_dump(mode="json"),
                        headers=self._bearer(access_token),
                    ),
                    action="policy explanation",
                )
                try:
                    explained = PolicyExplainResponse.model_validate(body)
                except (TypeError, ValueError) as error:
                    raise _LoopbackRequestError("policy explanation response is invalid") from error
                authority = explained.authority
                if (
                    authority.client != client
                    or authority.workspace != workspace
                    or authority.session_id != session_id
                    or authority.root_run_id != root_run_id
                    or explained.service != service
                    or explained.operation != operation
                ):
                    raise _LoopbackRequestError(
                        "policy explanation response does not match authority"
                    )
                return cast(Mapping[str, object], explained.model_dump(mode="json"))
        except _LoopbackRequestError as error:
            raise CliUnavailable("the policy explanation failed") from error

    @contextmanager
    def _agent_session(
        self,
        *,
        client_name: str,
        workspace: str,
        non_interactive: bool,
        required_capability: str | None,
    ) -> Iterator[tuple[_BoundedJsonClient, str, str]]:
        session_id, bootstrap = self._launch_session(
            client=client_name,
            workspace=workspace,
            non_interactive=non_interactive,
        )
        yielded_cleanly = False
        try:
            with self._http(self._settings().agent_url) as agent:
                try:
                    exchange = _success(
                        agent.request(
                            "POST",
                            "/v1/sessions/exchange",
                            payload={
                                "session_id": session_id,
                                "bootstrap_capability": bootstrap,
                                "client_nonce": secrets.token_urlsafe(24),
                            },
                        ),
                        action="session exchange",
                    )
                    access_token = _required_string(
                        exchange.get("access_token"),
                        label="session access token",
                        minimum=40,
                        maximum=512,
                    )
                    capabilities = exchange.get("capabilities")
                    session = exchange.get("session")
                    if (
                        exchange.get("token_type") != "Bearer"
                        or not isinstance(capabilities, list)
                        or any(not isinstance(item, str) for item in capabilities)
                        or (
                            required_capability is not None
                            and required_capability not in capabilities
                        )
                        or not isinstance(session, dict)
                        or session.get("session_id") != session_id
                        or session.get("state") != "ACTIVE"
                    ):
                        raise _LoopbackRequestError("session exchange response is invalid")
                except _LoopbackRequestError as error:
                    raise CliUnavailable(
                        "the controlled API session could not be adopted"
                    ) from error
                yield agent, access_token, session_id
                yielded_cleanly = True
        finally:
            try:
                self._cleanup_session(session_id, revoke=True)
            except CliUnavailable:
                if yielded_cleanly:
                    raise

    @staticmethod
    def _bearer(access_token: str) -> Mapping[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def _create_agent_root_run(
        self,
        agent: _BoundedJsonClient,
        *,
        access_token: str,
        expected_session_id: str,
    ) -> str:
        body = _success(
            agent.request(
                "POST",
                "/v1/root-runs",
                payload={},
                headers=self._bearer(access_token),
            ),
            expected=frozenset({201}),
            action="root-run creation",
        )
        if set(body) != {
            "root_run_id",
            "session_id",
            "state",
            "started_at_ms",
            "budget",
        }:
            raise _LoopbackRequestError("root-run response is invalid")
        root_run_id = _required_identifier(
            body.get("root_run_id"),
            label="root-run identifier",
        )
        session_id = _required_identifier(
            body.get("session_id"),
            label="root-run session identifier",
        )
        _required_integer(body.get("started_at_ms"), label="root-run start time")
        budget = body.get("budget")
        if (
            session_id != expected_session_id
            or body.get("state") != "ACTIVE"
            or not isinstance(budget, dict)
            or len(budget) > 32
            or any(
                not isinstance(key, str)
                or not 1 <= len(key) <= 64
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for key, value in budget.items()
            )
        ):
            raise _LoopbackRequestError("root-run response is invalid")
        return root_run_id

    def docs_search(
        self,
        service: str,
        query: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Sequence[Mapping[str, object]]:
        try:
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=non_interactive,
                required_capability="docs.search",
            ) as (agent, access_token, _):
                body = _success(
                    agent.request(
                        "POST",
                        "/v1/docs/search",
                        payload={"service": service, "query": query, "limit": 10},
                        headers=self._bearer(access_token),
                    ),
                    action="documentation search",
                )
                results = body.get("results")
                if not isinstance(results, list) or any(
                    not isinstance(item, dict) for item in results
                ):
                    raise _LoopbackRequestError("documentation search response is invalid")
                return tuple(cast(dict[str, object], item) for item in results)
        except _LoopbackRequestError as error:
            raise CliUnavailable("the documentation search failed") from error

    def docs_get(
        self,
        service: str,
        document: str,
        *,
        client: str,
        workspace: str,
        non_interactive: bool,
    ) -> Mapping[str, object]:
        try:
            service_segment = quote(_required_identifier(service, label="service"), safe="")
            document_segment = quote(
                _required_identifier(document, label="document"),
                safe="",
            )
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=non_interactive,
                required_capability="docs.get",
            ) as (agent, access_token, _):
                body = _success(
                    agent.request(
                        "GET",
                        f"/v1/docs/{service_segment}/{document_segment}",
                        headers=self._bearer(access_token),
                    ),
                    action="documentation retrieval",
                )
                returned_service = _required_string(
                    body.get("service"), label="documentation service", maximum=64
                )
                returned_document = _required_identifier(
                    body.get("document"), label="documentation identifier"
                )
                content = _required_string(
                    body.get("content"),
                    label="documentation content",
                    maximum=self._maximum_response_bytes,
                )
                if returned_service != service or returned_document != document:
                    raise _LoopbackRequestError("documentation response does not match request")
                return {
                    "service": returned_service,
                    "document": returned_document,
                    "content": content,
                }
        except _LoopbackRequestError as error:
            raise CliUnavailable("the documentation request failed") from error

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
        try:
            with self._agent_session(
                client_name=client,
                workspace=workspace,
                non_interactive=non_interactive,
                required_capability="feedback.submit",
            ) as (agent, access_token, _):
                body = _success(
                    agent.request(
                        "POST",
                        "/v1/feedback",
                        payload={
                            "category": category,
                            "severity": severity,
                            "component": component,
                            "summary": summary,
                        },
                        headers=self._bearer(access_token),
                    ),
                    action="feedback submission",
                )
                feedback_id = _required_identifier(
                    body.get("feedback_id"), label="feedback identifier"
                )
                state = _required_string(body.get("state"), label="feedback state", maximum=64)
                returned_summary = _required_string(
                    body.get("summary"), label="feedback summary", maximum=1_000
                )
                created_at_ms = _required_integer(
                    body.get("created_at_ms"), label="feedback creation time"
                )
                return {
                    "feedback_id": feedback_id,
                    "state": state,
                    "summary": returned_summary,
                    "created_at_ms": created_at_ms,
                }
        except _LoopbackRequestError as error:
            raise CliUnavailable("the feedback submission failed") from error

    def dashboard_login_url(self) -> str:
        code = self._mint_admin_code()
        return f"{self._settings().admin_url}/login?{urlencode({'code': code})}"
