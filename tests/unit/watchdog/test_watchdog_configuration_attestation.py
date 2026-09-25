"""Watchdog response and restart authority using only in-memory adapters."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

from gatehouse.admin.control import CONTROL_CAPABILITY_HEADER, CONTROL_CONFIG_DIGEST_HEADER
from gatehouse.watchdog import main as watchdog
from gatehouse.watchdog.controller import (
    ProbeAttestation,
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)

DIGEST = "0123456789abcdef" * 4
CAPABILITY = "c" * 43
DATABASE = Path(r"C:\synthetic\state\gatehouse.db")
CAPABILITY_PATH = Path(r"C:\synthetic\state\control-capability.dpapi")
CANARY = "SYNTHETIC_UNTRUSTED_RESPONSE_DETAIL"


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> watchdog.WatchdogRuntimeSettings:
    def state_paths(path: Path) -> SimpleNamespace:
        assert path == DATABASE
        return SimpleNamespace(control_capability=CAPABILITY_PATH)

    monkeypatch.setattr(watchdog, "installation_state_paths", state_paths)
    return watchdog.WatchdogRuntimeSettings(
        config_path=Path(r"C:\synthetic\config\config.yaml"),
        database_path=DATABASE,
        agent_port=48_101,
        admin_port=48_102,
        readiness_timeout_seconds=1.0,
        restart_policy=RestartPolicy(),
        expected_config_digest=DIGEST,
        environment={},
    )


def _capability(path: Path) -> str:
    assert path == CAPABILITY_PATH
    return CAPABILITY


def _status(state: str = "READY", *, digest: str = DIGEST) -> dict[str, object]:
    return {
        "ready": state == "READY",
        "status": state,
        "version": "synthetic",
        "schema_version": 16,
        "policy_version": "synthetic",
        "uptime_seconds": 0,
        "degraded_components": [],
        "config_digest": digest,
    }


class _Stream(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: tuple[bytes, ...] = (),
        *,
        forbid_read: bool = False,
        read_error: Exception | None = None,
        close_error: Exception | None = None,
        close_delay: float = 0.0,
        entered: asyncio.Event | None = None,
        release: asyncio.Event | None = None,
    ) -> None:
        self.chunks = chunks
        self.forbid_read = forbid_read
        self.read_error = read_error
        self.close_error = close_error
        self.close_delay = close_delay
        self.entered = entered
        self.release = release
        self.read_calls = 0
        self.close_calls = 0
        self.read_cancelled = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.read_calls += 1
        assert not self.forbid_read, "public liveness body must not be consumed"
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.read_cancelled = True
                raise
        for chunk in self.chunks:
            yield chunk
        if self.read_error is not None:
            raise self.read_error

    async def aclose(self) -> None:
        self.close_calls += 1
        if self.close_delay:
            await asyncio.sleep(self.close_delay)
        if self.close_error is not None:
            raise self.close_error


class _Transport(httpx.MockTransport):
    def __init__(
        self,
        respond: Callable[[httpx.Request], httpx.Response],
        *,
        close_error: Exception | None = None,
        close_delay: float = 0.0,
        control_delay: float = 0.0,
    ) -> None:
        super().__init__(respond)
        self.requests: list[httpx.Request] = []
        self.close_error = close_error
        self.close_delay = close_delay
        self.control_delay = control_delay
        self.close_calls = 0
        self.control_cancelled = False
        self.close_cancelled = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.method == "GET"
        assert request.url.host == "127.0.0.1"
        assert CONTROL_CONFIG_DIGEST_HEADER not in request.headers
        if request.url.path == "/health/live":
            assert request.url.port == 48_101
            assert CONTROL_CAPABILITY_HEADER not in request.headers
        else:
            assert str(request.url) == "http://127.0.0.1:48102/v1/control/status"
            assert request.headers.get_list(CONTROL_CAPABILITY_HEADER) == [CAPABILITY]
            assert request.headers["accept-encoding"] == "identity"
            if self.control_delay:
                try:
                    await asyncio.sleep(self.control_delay)
                except asyncio.CancelledError:
                    self.control_cancelled = True
                    raise
        return await super().handle_async_request(request)

    async def aclose(self) -> None:
        self.close_calls += 1
        if self.close_delay:
            try:
                await asyncio.sleep(self.close_delay)
            except asyncio.CancelledError:
                self.close_cancelled = True
                raise
        if self.close_error is not None:
            raise self.close_error


def _transport(
    raw: bytes | None = None,
    *,
    state: str = "READY",
    agent_status: int = 200,
    control_status: int = 200,
    headers: Mapping[str, str] | None = None,
    live_stream: _Stream | None = None,
    control_stream: _Stream | None = None,
) -> tuple[_Transport, _Stream, _Stream]:
    live = live_stream or _Stream(forbid_read=True)
    control = control_stream or _Stream(
        (json.dumps(_status(state)).encode("utf-8") if raw is None else raw,)
    )

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/live":
            return httpx.Response(agent_status, stream=live)
        return httpx.Response(
            control_status,
            stream=control,
            headers={"content-type": "application/json"} if headers is None else headers,
        )

    return _Transport(respond), live, control


async def _no_restart(
    result: ProbeResult,
    expected: WatchdogOutcome,
    *,
    allow_disabled: bool = False,
) -> None:
    class NoDatabase:
        def execute(self, *args: object, **kwargs: object) -> object:
            pytest.fail("unverified/live response reached restart accounting")

    async def probe() -> ProbeResult:
        return result

    async def restart() -> bool:
        pytest.fail("unverified/live responder was restarted")

    outcome = await WatchdogController(
        connection=cast(sqlite3.Connection, NoDatabase()),
        probe=probe,
        restart=restart,
        owner_id="watchdog-synthetic",
        allow_provider_disabled_state=allow_disabled,
    ).run_once(now_ms=1_000)
    assert outcome is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ("READY", "RECOVERING", "DEGRADED_NO_PROVIDER", "FAILED_CLOSED"))
async def test_probe_uses_captured_ports_and_authenticated_coherent_status(
    settings: watchdog.WatchdogRuntimeSettings,
    state: str,
) -> None:
    headers = (
        {"content-type": "application/json; charset=UTF-8"}
        if state == "RECOVERING"
        else {
            "content-type": "application/json",
            "content-encoding": "identity",
        }
    )
    transport, live, control = _transport(state=state, headers=headers)
    result = await watchdog._probe(settings, transport=transport, capability_loader=_capability)
    assert result.attestation is ProbeAttestation.MATCHED
    assert result.live is True and result.ready is (state == "READY")
    assert result.daemon_state == state
    assert result.agent_status_code == result.control_status_code == 200
    assert [request.url.path for request in transport.requests] == [
        "/health/live",
        "/v1/control/status",
    ]
    assert live.read_calls == 0
    assert live.close_calls == control.close_calls == transport.close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "defect",
    (
        "missing_digest",
        "null_digest",
        "number_digest",
        "uppercase_digest",
        "space_digest",
        "short_digest",
        "mismatch_digest",
        "non_object",
        "invalid_json",
        "duplicate_key",
        "nan",
        "infinity",
        "overflow_float",
        "wrong_ready_type",
        "incoherent_ready",
        "lowercase_state",
        "unknown_state",
        "http_503",
        "missing_media",
        "wrong_media",
        "encoded",
    ),
)
async def test_probe_rejects_untrusted_control_status_without_restart(
    settings: watchdog.WatchdogRuntimeSettings,
    defect: str,
) -> None:
    body = _status()
    headers: Mapping[str, str] = {"content-type": "application/json"}
    control_status = 200
    if defect == "missing_digest":
        del body["config_digest"]
    elif defect in {
        "null_digest",
        "number_digest",
        "uppercase_digest",
        "space_digest",
        "short_digest",
        "mismatch_digest",
    }:
        body["config_digest"] = {
            "null_digest": None,
            "number_digest": 7,
            "uppercase_digest": DIGEST.upper(),
            "space_digest": " " + DIGEST,
            "short_digest": DIGEST[:-1],
            "mismatch_digest": "b" * 64,
        }[defect]
    elif defect == "wrong_ready_type":
        body["ready"] = 1
    elif defect == "incoherent_ready":
        body["ready"] = False
    elif defect == "lowercase_state":
        body["status"] = "ready"
    elif defect == "unknown_state":
        body["status"] = CANARY
    elif defect == "http_503":
        control_status = 503
    elif defect == "missing_media":
        headers = {}
    elif defect == "wrong_media":
        headers = {"content-type": "text/plain"}
    elif defect == "encoded":
        headers = {"content-type": "application/json", "content-encoding": "gzip"}
    raw = json.dumps(body).encode("utf-8")
    if defect == "non_object":
        raw = b"[]"
    elif defect == "invalid_json":
        raw = b"{" + CANARY.encode("ascii")
    elif defect == "duplicate_key":
        raw = raw[:-1] + b',"ready":true}'
    elif defect in {"nan", "infinity", "overflow_float"}:
        nonfinite = {"nan": b"NaN", "infinity": b"Infinity", "overflow_float": b"1e10000"}[defect]
        raw = raw.replace(b'"uptime_seconds": 0', b'"uptime_seconds": ' + nonfinite)
    transport, live, _ = _transport(raw, headers=headers, control_status=control_status)
    result = await watchdog._probe(settings, transport=transport, capability_loader=_capability)
    mismatch = defect == "mismatch_digest"
    assert result.attestation is (
        ProbeAttestation.MISMATCH if mismatch else ProbeAttestation.UNVERIFIED
    )
    assert result.live is True and result.ready is False
    assert live.read_calls == 0 and live.close_calls == 1
    assert CANARY not in repr(result)
    await _no_restart(
        result, WatchdogOutcome.CONFIG_MISMATCH if mismatch else WatchdogOutcome.CONFIG_UNVERIFIED
    )


@pytest.mark.asyncio
async def test_valid_digest_mismatch_precedes_invalid_readiness_fields(
    settings: watchdog.WatchdogRuntimeSettings,
) -> None:
    transport, _, _ = _transport(
        json.dumps(
            {
                "config_digest": "b" * 64,
                "ready": CANARY,
                "status": CANARY,
            }
        ).encode("utf-8")
    )
    result = await watchdog._probe(settings, transport=transport, capability_loader=_capability)
    assert result.attestation is ProbeAttestation.MISMATCH
    assert CANARY not in repr(result)
    await _no_restart(result, WatchdogOutcome.CONFIG_MISMATCH)


@pytest.mark.asyncio
@pytest.mark.parametrize("over_limit", (False, True))
async def test_control_body_limit_applies_to_raw_stream_before_acceptance(
    settings: watchdog.WatchdogRuntimeSettings,
    over_limit: bool,
) -> None:
    raw = json.dumps(_status()).encode("utf-8")
    raw += b" " * (65_536 - len(raw) + over_limit)
    stream = _Stream((raw[:32_768], raw[32_768:]))
    transport, live, _ = _transport(control_stream=stream)
    result = await watchdog._probe(settings, transport=transport, capability_loader=_capability)
    assert result.attestation is (
        ProbeAttestation.UNVERIFIED if over_limit else ProbeAttestation.MATCHED
    )
    assert result.live is True and result.ready is (not over_limit)
    assert stream.close_calls == live.close_calls == transport.close_calls == 1
    if over_limit:
        await _no_restart(result, WatchdogOutcome.CONFIG_UNVERIFIED)


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ("body", "live_close", "control_close", "client_close"))
@pytest.mark.parametrize("error_type", (RuntimeError, httpx.ReadError))
async def test_any_received_response_remains_live_across_body_or_close_failure(
    settings: watchdog.WatchdogRuntimeSettings,
    where: str,
    error_type: type[Exception],
) -> None:
    error = error_type(CANARY)
    live = _Stream(forbid_read=True, close_error=error if where == "live_close" else None)
    control = _Stream(
        (json.dumps(_status()).encode("utf-8"),),
        read_error=error if where == "body" else None,
        close_error=error if where == "control_close" else None,
    )
    transport, _, _ = _transport(live_stream=live, control_stream=control)
    transport.close_error = error if where == "client_close" else None
    result = await watchdog._probe(settings, transport=transport, capability_loader=_capability)
    assert result.live is True and result.ready is False
    assert result.attestation is ProbeAttestation.UNVERIFIED
    assert CANARY not in repr(result)
    assert live.read_calls == 0 and live.close_calls == 1
    assert control.close_calls <= 1 and transport.close_calls == 1
    await _no_restart(result, WatchdogOutcome.CONFIG_UNVERIFIED)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    (
        "both_refused",
        "agent_refused",
        "control_refused",
        "agent_503",
        "connect_timeout",
        "protocol_error",
    ),
)
async def test_only_two_explicit_connection_refusals_are_restart_eligible_absence(
    settings: watchdog.WatchdogRuntimeSettings,
    case: str,
) -> None:
    live = _Stream(forbid_read=True)
    control = _Stream((json.dumps(_status()).encode("utf-8"),))

    def respond(request: httpx.Request) -> httpx.Response:
        public = request.url.path == "/health/live"
        if (
            case == "both_refused"
            or (case == "agent_refused" and public)
            or (case == "control_refused" and not public)
        ):
            raise httpx.ConnectError(CANARY, request=request)
        if case == "connect_timeout" and public:
            raise httpx.ConnectTimeout(CANARY, request=request)
        if case == "protocol_error" and public:
            raise httpx.RemoteProtocolError(CANARY, request=request)
        return httpx.Response(
            503 if case == "agent_503" and public else 200,
            stream=live if public else control,
            headers={"content-type": "application/json"},
        )

    transport = _Transport(respond)
    result = await watchdog._probe(settings, transport=transport, capability_loader=_capability)
    assert result.ready is False
    assert CANARY not in repr(result)
    assert result.attestation is (
        ProbeAttestation.NO_RESPONDER if case == "both_refused" else ProbeAttestation.UNVERIFIED
    )
    if case == "both_refused":
        assert result.live is False
        assert [request.url.path for request in transport.requests] == [
            "/health/live",
            "/v1/control/status",
        ]
    else:
        await _no_restart(result, WatchdogOutcome.CONFIG_UNVERIFIED)
    assert transport.close_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("defect", ("failure", "short", "non_ascii"))
@pytest.mark.parametrize("agent_refused", (False, True))
async def test_capability_failure_never_becomes_no_responder(
    settings: watchdog.WatchdogRuntimeSettings,
    defect: str,
    agent_refused: bool,
) -> None:
    transport, live, _ = _transport()
    if agent_refused:

        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(CANARY, request=request)

        transport = _Transport(refuse)
    loads: list[Path] = []

    def load(path: Path) -> str:
        loads.append(path)
        if defect == "failure":
            raise RuntimeError(CANARY)
        return "short" if defect == "short" else "é" * 43

    result = await watchdog._probe(settings, transport=transport, capability_loader=load)
    assert loads == [CAPABILITY_PATH]
    assert [request.url.path for request in transport.requests] == ["/health/live"]
    assert result.live is (not agent_refused)
    assert result.attestation is ProbeAttestation.UNVERIFIED
    assert live.read_calls == 0 and live.close_calls == (0 if agent_refused else 1)
    assert transport.close_calls == 1
    assert CANARY not in repr(result)
    await _no_restart(result, WatchdogOutcome.CONFIG_UNVERIFIED)


@pytest.mark.parametrize("timeout", (False, 0, -1, float("nan"), float("inf"), 60.01))
def test_probe_deadline_is_finite_positive_and_bounded(
    settings: watchdog.WatchdogRuntimeSettings,
    timeout: object,
) -> None:
    with pytest.raises(ValueError):
        replace(settings, readiness_timeout_seconds=timeout)  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ("across_requests", "client_close"))
async def test_one_probe_deadline_includes_both_requests_and_client_close(
    settings: watchdog.WatchdogRuntimeSettings,
    where: str,
) -> None:
    live = _Stream(forbid_read=True, close_delay=0.06 if where == "across_requests" else 0)
    transport, _, _ = _transport(live_stream=live)
    transport.control_delay = 0.06 if where == "across_requests" else 0
    transport.close_delay = 0.2 if where == "client_close" else 0
    result = await asyncio.wait_for(
        watchdog._probe(
            replace(settings, readiness_timeout_seconds=0.1),
            transport=transport,
            capability_loader=_capability,
        ),
        timeout=1,
    )
    assert result.live is True and result.ready is False
    assert result.attestation is ProbeAttestation.UNVERIFIED
    assert live.read_calls == 0 and live.close_calls == 1
    assert transport.control_cancelled if where == "across_requests" else transport.close_cancelled
    await _no_restart(result, WatchdogOutcome.CONFIG_UNVERIFIED)


@pytest.mark.asyncio
async def test_external_probe_cancellation_propagates_after_owned_stream_cleanup(
    settings: watchdog.WatchdogRuntimeSettings,
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()
    stream = _Stream((json.dumps(_status()).encode("utf-8"),), entered=entered, release=release)
    transport, live, _ = _transport(control_stream=stream)
    task = asyncio.create_task(
        watchdog._probe(
            settings,
            transport=transport,
            capability_loader=_capability,
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
        assert stream.read_cancelled
        assert stream.close_calls == live.close_calls == transport.close_calls == 1
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("attestation", (ProbeAttestation.UNVERIFIED, ProbeAttestation.MISMATCH))
@pytest.mark.parametrize("live,ready", ((False, False), (True, True)))
async def test_classification_precedes_healthy_or_dead_restart_flags(
    attestation: ProbeAttestation,
    live: bool,
    ready: bool,
) -> None:
    result = ProbeResult(
        live=live,
        ready=ready,
        daemon_state="READY",
        agent_status_code=200,
        control_status_code=200,
        attestation=attestation,
    )
    expected = (
        WatchdogOutcome.CONFIG_MISMATCH
        if attestation is ProbeAttestation.MISMATCH
        else WatchdogOutcome.CONFIG_UNVERIFIED
    )
    await _no_restart(result, expected)
    assert watchdog._outcome_exit_code(expected) == 1
    assert ProbeResult(live=True, ready=True).attestation is ProbeAttestation.UNVERIFIED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    (
        "live",
        "ready",
        "agent_status_code",
        "control_status_code",
        "daemon_state",
    ),
)
async def test_controller_rejects_fabricated_no_responder_facts_before_database(field: str) -> None:
    fields: dict[str, object] = {
        "live": False,
        "ready": False,
        "attestation": ProbeAttestation.NO_RESPONDER,
    }
    fields[field] = {
        "live": True,
        "ready": True,
        "agent_status_code": 200,
        "control_status_code": 200,
        "daemon_state": "READY",
    }[field]
    await _no_restart(ProbeResult(**fields), WatchdogOutcome.CONFIG_UNVERIFIED)  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "defect",
    (
        "ready_type",
        "live_type",
        "ready_flag",
        "control_status",
        "control_status_type",
        "agent_status",
        "state",
    ),
)
async def test_controller_revalidates_injected_matched_probe_coherence(defect: str) -> None:
    fields: dict[str, object] = {
        "live": True,
        "ready": True,
        "daemon_state": "READY",
        "agent_status_code": 200,
        "control_status_code": 200,
        "attestation": ProbeAttestation.MATCHED,
    }
    name, value = {
        "ready_type": ("ready", 1),
        "live_type": ("live", 1),
        "ready_flag": ("ready", False),
        "control_status": ("control_status_code", 503),
        "agent_status": ("agent_status_code", 503),
        "control_status_type": ("control_status_code", 200.0),
        "state": ("daemon_state", "ready"),
    }[defect]
    fields[name] = value
    await _no_restart(ProbeResult(**fields), WatchdogOutcome.CONFIG_UNVERIFIED)  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state,allow_disabled,expected",
    (
        ("READY", False, WatchdogOutcome.HEALTHY),
        ("DEGRADED_NO_PROVIDER", True, WatchdogOutcome.PROVIDERS_DISABLED),
        ("DEGRADED_NO_PROVIDER", False, WatchdogOutcome.LIVE_DEGRADED),
        ("FAILED_CLOSED", False, WatchdogOutcome.FAILED_CLOSED),
        ("RECOVERING", False, WatchdogOutcome.LIVE_DEGRADED),
        ("DEGRADED_READ_ONLY", False, WatchdogOutcome.LIVE_DEGRADED),
        ("DRAINING", False, WatchdogOutcome.LIVE_DEGRADED),
        ("STOPPED", False, WatchdogOutcome.LIVE_DEGRADED),
    ),
)
async def test_only_matched_ready_or_explicitly_disabled_state_is_successful(
    state: str,
    allow_disabled: bool,
    expected: WatchdogOutcome,
) -> None:
    result = ProbeResult(
        live=True,
        ready=state == "READY",
        daemon_state=state,
        agent_status_code=200,
        control_status_code=200,
        attestation=ProbeAttestation.MATCHED,
    )
    await _no_restart(result, expected, allow_disabled=allow_disabled)
    assert watchdog._outcome_exit_code(expected) == (
        0 if expected in {WatchdogOutcome.HEALTHY, WatchdogOutcome.PROVIDERS_DISABLED} else 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attestation",
    (
        ProbeAttestation.UNVERIFIED,
        ProbeAttestation.MISMATCH,
        pytest.param(ProbeAttestation.MATCHED, id="late_matched"),
    ),
)
async def test_restart_refusal_terminates_only_its_owned_child_without_retry(
    settings: watchdog.WatchdogRuntimeSettings,
    monkeypatch: pytest.MonkeyPatch,
    attestation: ProbeAttestation,
) -> None:
    executable = Path(r"C:\synthetic\bin\gatehoused.exe")
    probes: list[str] = []
    spawned: list[tuple[str, ...]] = []
    now = [0.0]
    if attestation is ProbeAttestation.MATCHED:
        # Change only the watchdog binding; event-loop and runner clocks stay real.
        monkeypatch.setattr(watchdog, "time", SimpleNamespace(monotonic=lambda: now[0]))

    class Child:
        returncode: int | None = None
        terminate_calls = 0
        wait_calls = 0

        def terminate(self) -> None:
            self.terminate_calls += 1
            self.returncode = -15

        def kill(self) -> None:
            pytest.fail("confirmed owned exit must not escalate to kill")

        async def wait(self) -> int:
            self.wait_calls += 1
            assert self.returncode == -15
            return self.returncode

    child = Child()

    async def spawn(arguments: tuple[str, ...], *, environment: Mapping[str, str]) -> Child:
        assert dict(environment) == {}
        spawned.append(arguments)
        return child

    async def probe() -> ProbeResult:
        probes.append("probe")
        if attestation is ProbeAttestation.MATCHED:
            now[0] = settings.readiness_timeout_seconds + 0.01
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            agent_status_code=200,
            control_status_code=200,
            attestation=attestation,
        )

    monkeypatch.setattr(
        watchdog,
        "sys",
        SimpleNamespace(executable=r"C:\synthetic\bin\pythonw.exe"),
    )
    monkeypatch.setattr(watchdog, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(Path, "is_file", lambda path: path == executable)
    monkeypatch.setattr(watchdog, "_spawn_daemon", spawn)
    assert not await watchdog._restart(settings, daemon_executable=executable, probe=probe)
    assert spawned == [
        (str(executable), "--config", str(settings.config_path), "--expected-config-digest", DIGEST)
    ]
    assert probes == ["probe"]
    assert child.terminate_calls == child.wait_calls == 1
