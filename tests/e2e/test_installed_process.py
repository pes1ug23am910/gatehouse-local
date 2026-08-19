"""Opt-in proof for the separately installed Gatehouse wheel.

Set ``GATEHOUSE_E2E_BIN_DIR`` to the ``Scripts`` directory of a clean virtual
environment containing the built wheel, then run this file explicitly.  The
test intentionally imports no Gatehouse production modules from the checkout.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult

_BIN_DIRECTORY_ENVIRONMENT = "GATEHOUSE_E2E_BIN_DIR"
_CHECKOUT_ROOT = Path(__file__).parents[2]
_OPT_IN_BIN_DIRECTORY = os.environ.get(_BIN_DIRECTORY_ENVIRONMENT)

pytestmark = [
    pytest.mark.skipif(
        os.name != "nt",
        reason="the installed Gatehouse process proof requires Windows DPAPI",
    ),
    pytest.mark.skipif(
        not _OPT_IN_BIN_DIRECTORY,
        reason=f"set {_BIN_DIRECTORY_ENVIRONMENT} to a clean wheel installation",
    ),
]


def _entry_point(bin_directory: Path, name: str) -> Path:
    path = (bin_directory / f"{name}.exe").resolve()
    assert path.is_file(), f"installed entry point is missing: {path}"
    return path


def _sanitized_environment() -> dict[str, str]:
    forbidden_suffixes = (
        "_API_KEY",
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PRIVATE_KEY",
    )
    forbidden_names = {
        "FIRECRAWL_API_KEY",
        "GATEHOUSE_ACCESS_TOKEN",
        "GATEHOUSE_AGENT_URL",
        "GATEHOUSE_SESSION_BOOTSTRAP",
        "GATEHOUSE_SESSION_ID",
        "PYTHONHOME",
        "PYTHONPATH",
        "VIRTUAL_ENV",
    }
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() not in forbidden_names and not name.upper().endswith(forbidden_suffixes)
    }


def _replace_once(source: str, old: str, new: str) -> str:
    assert source.count(old) == 1, f"expected one configuration fragment: {old!r}"
    return source.replace(old, new, 1)


def _free_loopback_port(*, excluding: frozenset[int] = frozenset()) -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = int(candidate.getsockname()[1])
        if port not in excluding:
            return port


def _write_scripted_manifest(manifest_path: Path, *, resumed: bool) -> None:
    responses: dict[str, list[dict[str, object]]] = {
        "firecrawl.crawl.status": [
            {
                "status_code": 200,
                "data": (
                    {"status": "completed", "creditsUsed": 3} if resumed else {"status": "scraping"}
                ),
            }
        ]
    }
    if not resumed:
        responses.update(
            {
                "firecrawl.search": [
                    {
                        "status_code": 200,
                        "data": {
                            "success": True,
                            "data": [],
                            "creditsUsed": 1,
                        },
                    }
                ],
                "firecrawl.crawl.start": [
                    {
                        "status_code": 200,
                        "data": {
                            "success": True,
                            "id": "provider-crawl-installed-e2e",
                        },
                    }
                ],
            }
        )
    manifest_path.write_text(
        json.dumps(
            {"schema_version": 1, "responses": responses},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def _write_runtime_files(
    tmp_path: Path,
    *,
    agent_port: int,
    admin_port: int,
) -> tuple[Path, Path, Path]:
    config_source = _CHECKOUT_ROOT / "config"
    database_path = (tmp_path / "state" / "gatehouse.db").resolve()
    manifest_path = (tmp_path / "scripted-responses.json").resolve()
    _write_scripted_manifest(manifest_path, resumed=False)

    configuration = (config_source / "config.example.yaml").read_text(encoding="utf-8")
    configuration = _replace_once(
        configuration,
        "server:\n  agent: { host: 127.0.0.1, port: 47621 }\n"
        "  admin: { host: 127.0.0.1, port: 47622 }",
        "server:\n"
        f"  agent: {{ host: 127.0.0.1, port: {agent_port} }}\n"
        f"  admin: {{ host: 127.0.0.1, port: {admin_port} }}",
    )
    configuration = _replace_once(
        configuration,
        r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
        f"'{database_path.as_posix()}'",
    )
    configuration = _replace_once(
        configuration,
        "  heartbeat_interval: 30s\n  stale_after: 120s\n  reconnect_grace: 30m",
        "  heartbeat_interval: 1s\n  stale_after: 5s\n  reconnect_grace: 2m",
    )
    configuration = _replace_once(
        configuration,
        "provider:\n  mode: disabled\n  network_enabled: false",
        "provider:\n"
        "  mode: scripted\n"
        "  network_enabled: false\n"
        f"  scripted_responses_path: '{manifest_path.as_posix()}'",
    )
    config_path = (tmp_path / "config.yaml").resolve()
    config_path.write_text(configuration, encoding="utf-8")

    clients = tmp_path / "clients"
    policies = tmp_path / "policies"
    clients.mkdir()
    policies.mkdir()
    profile = (config_source / "clients" / "company-watcher.example.yaml").read_text(
        encoding="utf-8"
    )
    profile = _replace_once(profile, "id: company-watcher", "id: editor-one")
    profile = _replace_once(profile, "kind: system", "kind: interactive")
    profile = _replace_once(profile, "unattended: true", "unattended: false")
    profile = _replace_once(profile, "approval_mode: deny_on_ask", "approval_mode: dashboard")
    profile = _replace_once(
        profile,
        "default_priority: system_reserved",
        "default_priority: interactive",
    )
    profile = _replace_once(
        profile,
        "    - watcher.scan_feed_set\n"
        "    - watcher.get_cursor\n"
        "    - watcher.commit_cursor\n"
        "    - watcher.get_previous_summary",
        "    - firecrawl.search\n"
        "    - firecrawl.crawl.start\n"
        "    - firecrawl.crawl.status\n"
        "    - firecrawl.crawl.cancel\n"
        "    - jobs.status\n"
        "    - jobs.await\n"
        "    - jobs.cancel\n"
        "    - feedback.submit",
    )
    profile = _replace_once(
        profile,
        "firecrawl: watcher-reserved",
        "firecrawl: interactive-default",
    )
    (clients / "editor-one.yaml").write_text(profile, encoding="utf-8")
    (policies / "placement-schedule.yaml").write_text(
        (config_source / "policies" / "placement-schedule.example.yaml").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    return config_path, database_path, manifest_path


def _run(
    arguments: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    timeout_seconds: float = 20.0,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        arguments,
        cwd=cwd,
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        input=input_text,
        timeout=timeout_seconds,
    )


def _verify_clean_wheel_install(
    bin_directory: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
) -> None:
    python = _entry_point(bin_directory, "python")
    probe = _run(
        (
            str(python),
            "-c",
            "import importlib.metadata as m, gatehouse; "
            "print(m.version('gatehouse-local')); print(gatehouse.__file__)",
        ),
        environment=environment,
        cwd=cwd,
    )
    assert probe.returncode == 0, probe.stderr
    lines = probe.stdout.splitlines()
    assert len(lines) == 2
    assert lines[0] == "0.0.1"
    installed_module = Path(lines[1]).resolve()
    assert installed_module.is_relative_to(bin_directory.parent.resolve())
    assert not installed_module.is_relative_to((_CHECKOUT_ROOT / "src").resolve())


def _start_daemon(
    executable: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    run_number: int,
) -> tuple[subprocess.Popen[bytes], Path, Path]:
    stdout_path = cwd / f"gatehoused-{run_number}.stdout.log"
    stderr_path = cwd / f"gatehoused-{run_number}.stderr.log"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(  # noqa: S603
            (str(executable), "--config", str(config_path)),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    return process, stdout_path, stderr_path


def _logs(stdout_path: Path, stderr_path: Path) -> str:
    return (
        f"stdout:\n{stdout_path.read_text(encoding='utf-8', errors='replace')}\n"
        f"stderr:\n{stderr_path.read_text(encoding='utf-8', errors='replace')}"
    )


def _cli_json(
    gatehouse: Path,
    config_path: Path,
    *arguments: str,
    environment: Mapping[str, str],
    cwd: Path,
) -> dict[str, object]:
    completed = _run(
        (str(gatehouse), "--config", str(config_path), *arguments),
        environment=environment,
        cwd=cwd,
    )
    assert completed.returncode == 0, completed.stderr
    decoded = json.loads(completed.stdout)
    assert isinstance(decoded, dict)
    assert all(isinstance(key, str) for key in decoded)
    return cast(dict[str, object], decoded)


def _wait_until_ready(
    process: subprocess.Popen[bytes],
    gatehouse: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, object]:
    deadline = time.monotonic() + 35.0
    last_status: dict[str, object] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(
                f"gatehoused exited with {process.returncode}\n{_logs(stdout_path, stderr_path)}"
            )
        try:
            last_status = _cli_json(
                gatehouse,
                config_path,
                "status",
                environment=environment,
                cwd=cwd,
            )
        except (AssertionError, json.JSONDecodeError, subprocess.TimeoutExpired):
            time.sleep(0.1)
            continue
        if last_status.get("ready") is True and last_status.get("status") == "READY":
            return last_status
        time.sleep(0.1)
    pytest.fail(
        f"gatehoused did not become ready; last status={last_status!r}\n"
        f"{_logs(stdout_path, stderr_path)}"
    )


def _verify_health_script(
    agent_port: int,
    *,
    environment: Mapping[str, str],
    cwd: Path,
) -> None:
    powershell = shutil.which("pwsh.exe") or shutil.which("pwsh")
    assert powershell is not None, "PowerShell 7 is required for the Windows release proof"
    completed = _run(
        (
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_CHECKOUT_ROOT / "scripts" / "health-check.ps1"),
            "-AgentPort",
            str(agent_port),
            "-TimeoutSeconds",
            "5",
            "-RequireReady",
        ),
        environment=environment,
        cwd=cwd,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def _verify_auxiliary_entry_points(
    gatehouse_notifier: Path,
    gatehouse_watchdog: Path,
    config_path: Path,
    database_path: Path,
    agent_port: int,
    admin_port: int,
    *,
    environment: Mapping[str, str],
    cwd: Path,
) -> None:
    settings = _run(
        (
            str(gatehouse_watchdog),
            "--config",
            str(config_path),
            "--print-settings",
        ),
        environment=environment,
        cwd=cwd,
    )
    assert settings.returncode == 0, settings.stderr
    decoded_settings = json.loads(settings.stdout)
    assert decoded_settings["agent_port"] == agent_port
    assert Path(decoded_settings["config_path"]).resolve() == config_path
    assert Path(decoded_settings["database_path"]).resolve() == database_path

    watchdog = _run(
        (str(gatehouse_watchdog), "--config", str(config_path), "--once"),
        environment=environment,
        cwd=cwd,
    )
    assert watchdog.returncode == 0, watchdog.stderr or watchdog.stdout
    assert watchdog.stdout.strip() == "healthy"

    notification = _run(
        (str(gatehouse_notifier),),
        environment=environment,
        cwd=cwd,
        input_text=json.dumps(
            {
                "kind": "incident",
                "requesting_client": "installed-process-e2e",
                "service": "gatehouse",
                "operation": "release-proof",
                "severity": "low",
                "dashboard_url": f"http://127.0.0.1:{admin_port}/dashboard",
            },
            separators=(",", ":"),
        )
        + "\n",
    )
    assert notification.returncode == 0, notification.stderr
    assert notification.stdout == ""


def _stop_cleanly(
    process: subprocess.Popen[bytes],
    gatehouse: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, object]:
    result = _cli_json(
        gatehouse,
        config_path,
        "daemon",
        "stop",
        environment=environment,
        cwd=cwd,
    )
    try:
        exit_code = process.wait(timeout=35)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
        pytest.fail(f"gatehoused did not stop after drain\n{_logs(stdout_path, stderr_path)}")
    assert result == {"action": "stop", "status": "STOPPED", "stopped": True}
    assert exit_code == 0, _logs(stdout_path, stderr_path)
    return result


def _terminate_if_running(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _tool_payload(result: CallToolResult) -> dict[str, object]:
    structured = result.structuredContent
    if isinstance(structured, dict) and all(isinstance(key, str) for key in structured):
        return cast(dict[str, object], structured)
    for block in result.content:
        text = getattr(block, "text", None)
        if not isinstance(text, str):
            continue
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict) and all(isinstance(key, str) for key in decoded):
            return cast(dict[str, object], decoded)
    raise AssertionError("MCP tool did not return a JSON object")


async def _exercise_controlled_mcp_across_restart(
    gatehouse: Path,
    gatehouse_mcp: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    restart_daemon: Callable[[str], Awaitable[None]],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    parameters = StdioServerParameters(
        command=str(gatehouse),
        args=[
            "--config",
            str(config_path),
            "run",
            "editor-one",
            "--workspace",
            "placement-schedule",
            "--",
            str(gatehouse_mcp),
        ],
        env=dict(environment),
        cwd=cwd,
    )
    stderr_path = cwd / "controlled-mcp.stderr.log"
    with stderr_path.open("w", encoding="utf-8") as stderr:
        async with stdio_client(parameters, errlog=stderr) as (read, write):
            async with ClientSession(
                read,
                write,
                read_timeout_seconds=timedelta(seconds=30),
            ) as session:
                initialized = await session.initialize()
                assert initialized.serverInfo.name
                tools = await session.list_tools()
                names = [tool.name for tool in tools.tools]
                assert names.count("firecrawl_search") == 1
                assert names.count("firecrawl_crawl_start") == 1
                assert names.count("gatehouse_job_status") == 1
                result = await session.call_tool(
                    "firecrawl_search",
                    {
                        "query": "graduate software roles",
                        "purpose": "career_discovery",
                        "data_classification": ["public_web_query"],
                        "limit": 5,
                        "include_content": False,
                    },
                    read_timeout_seconds=timedelta(seconds=30),
                )
                assert result.isError is not True
                payload = _tool_payload(result)
                assert payload["state"] == "SUCCEEDED"
                assert payload["service"] == "firecrawl"
                assert payload["operation"] == "search"
                crawl_result = await session.call_tool(
                    "firecrawl_crawl_start",
                    {
                        "url": "https://example.com/jobs",
                        "include_paths": ["^/jobs"],
                        "maximum_pages": 2,
                        "maximum_depth": 1,
                        "maximum_concurrency": 1,
                        "data_classification": ["public_job_data"],
                    },
                    read_timeout_seconds=timedelta(seconds=30),
                )
                assert crawl_result.isError is not True
                crawl = _tool_payload(crawl_result)
                assert crawl["state"] == "SUCCEEDED"
                job_id = crawl.get("job_id")
                assert isinstance(job_id, str)

                await restart_daemon(job_id)
                job_result = await session.call_tool(
                    "gatehouse_job_status",
                    {"job_id": job_id},
                    read_timeout_seconds=timedelta(seconds=30),
                )
                assert job_result.isError is not True
                job = _tool_payload(job_result)
                assert job["job_id"] == job_id
                assert job["state"] == "SUCCEEDED"
                assert job["terminal"] is True

                feedback_result = await session.call_tool(
                    "gatehouse_feedback_submit",
                    {
                        "category": "process_e2e",
                        "severity": "low",
                        "component": "mcp_readoption",
                        "summary": "Long-lived MCP session re-adopted after daemon restart.",
                    },
                    read_timeout_seconds=timedelta(seconds=30),
                )
                assert feedback_result.isError is not True
                feedback = _tool_payload(feedback_result)
                assert feedback["state"] == "NEW"
                return payload, crawl, job, feedback


def _durable_usage(
    database_path: Path,
    *,
    expected_session: tuple[str, int],
    expected_total_credits: int,
) -> dict[str, object]:
    connection = sqlite3.connect(database_path)
    try:
        invocation_rows = connection.execute(
            """
            SELECT request_id, root_run_id, state, actual_cost_units
              FROM invocations
             WHERE service_id = 'firecrawl' AND operation = 'firecrawl.search'
             ORDER BY received_at_ms, request_id
            """
        ).fetchall()
        assert len(invocation_rows) == 1
        request_id, root_run_id, state, actual_cost = invocation_rows[0]
        assert state == "SUCCEEDED"
        assert actual_cost == 1

        attempts = connection.execute(
            """
            SELECT state, actual_cost_units
              FROM attempts
             WHERE request_id = ?
             ORDER BY ordinal
            """,
            (request_id,),
        ).fetchall()
        assert attempts == [("SUCCEEDED", 1)]

        quota = connection.execute(
            """
            SELECT state, actual_units
              FROM quota_reservations
             WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall()
        assert quota == [("RECONCILED", 1)]

        budget = connection.execute(
            """
            SELECT state, actual_units
              FROM budget_reservations
             WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall()
        assert budget == [("RECONCILED", 1)]

        root = connection.execute(
            "SELECT session_id, consumed_json FROM root_runs WHERE root_run_id = ?",
            (root_run_id,),
        ).fetchone()
        assert root is not None
        consumed = json.loads(str(root[1]))
        assert isinstance(consumed, dict)
        assert consumed.get("credits") == expected_total_credits

        session = connection.execute(
            "SELECT state, token_epoch FROM sessions WHERE session_id = ?",
            (root[0],),
        ).fetchone()
        assert session == expected_session
        return {
            "request_id": str(request_id),
            "root_run_id": str(root_run_id),
            "session_id": str(root[0]),
        }
    finally:
        connection.close()


def _crawl_checkpoint(database_path: Path, *, job_id: str, terminal: bool) -> str:
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            """
            SELECT request_id, state, provider_job_id
              FROM jobs
             WHERE job_id = ?
            """,
            (job_id,),
        ).fetchone()
        assert row is not None
        request_id, state, provider_job_id = row
        assert provider_job_id == "provider-crawl-installed-e2e"
        if not terminal:
            assert state in {"CREATED", "RUNNING"}
            return str(request_id)

        assert state == "SUCCEEDED"
        assert connection.execute(
            """
            SELECT state, actual_units
              FROM quota_reservations
             WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall() == [("RECONCILED", 3)]
        assert connection.execute(
            """
            SELECT state, actual_units
              FROM budget_reservations
             WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall() == [("RECONCILED", 3)]
        assert connection.execute(
            """
            SELECT state, provider_resource_id
              FROM external_resources
             WHERE creating_request_id = ?
            """,
            (request_id,),
        ).fetchall() == [("ACTIVE", "provider-crawl-installed-e2e")]
        return str(request_id)
    finally:
        connection.close()


def _wait_until_crawl_poll_is_due(database_path: Path, *, job_id: str) -> None:
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            "SELECT next_poll_at_ms FROM jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None and row[0] is not None
    wait_seconds = max(0.0, (int(row[0]) - int(time.time() * 1_000)) / 1_000)
    assert wait_seconds <= 31.0
    if wait_seconds > 0:
        time.sleep(wait_seconds + 0.25)


def _system_state(database_path: Path) -> tuple[int, str, int | None]:
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            """
            SELECT token_epoch, daemon_state, last_clean_shutdown_at_ms
              FROM system_state
             WHERE singleton_id = 1
            """
        ).fetchone()
        assert row is not None
        return int(row[0]), str(row[1]), None if row[2] is None else int(row[2])
    finally:
        connection.close()


def _wait_for_session_reactivation(
    database_path: Path,
    *,
    session_id: str,
    token_epoch: int,
) -> None:
    deadline = time.monotonic() + 10.0
    last_state: tuple[str, int] | None = None
    while time.monotonic() < deadline:
        connection = sqlite3.connect(database_path)
        try:
            row = connection.execute(
                "SELECT state, token_epoch FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is not None:
            last_state = (str(row[0]), int(row[1]))
            if last_state == ("ACTIVE", token_epoch):
                return
        time.sleep(0.05)
    raise AssertionError(
        "idle MCP session did not proactively re-adopt before its next tool call; "
        f"last state was {last_state!r}"
    )


def _assert_same_session_readopted(
    database_path: Path,
    *,
    session_id: str,
    root_run_id: str,
    feedback_id: object,
) -> None:
    assert isinstance(feedback_id, str) and feedback_id
    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute(
            "SELECT state, token_epoch FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone() == ("DISCONNECTED", 2)
        assert connection.execute(
            "SELECT session_id, state FROM feedback WHERE feedback_id = ?",
            (feedback_id,),
        ).fetchone() == (session_id, "NEW")
        assert connection.execute(
            "SELECT root_run_id FROM root_runs WHERE session_id = ?",
            (session_id,),
        ).fetchall() == [(root_run_id,)]
    finally:
        connection.close()


def test_installed_wheel_daemon_cli_mcp_restart_and_durable_accounting(
    tmp_path: Path,
) -> None:
    assert _OPT_IN_BIN_DIRECTORY is not None
    bin_directory = Path(_OPT_IN_BIN_DIRECTORY).resolve()
    assert bin_directory.is_dir(), f"installed bin directory is missing: {bin_directory}"
    gatehouse = _entry_point(bin_directory, "gatehouse")
    gatehoused = _entry_point(bin_directory, "gatehoused")
    gatehouse_mcp = _entry_point(bin_directory, "gatehouse-mcp")
    gatehouse_notifier = _entry_point(bin_directory, "gatehouse-notifier")
    gatehouse_watchdog = _entry_point(bin_directory, "gatehouse-watchdog")
    environment = _sanitized_environment()
    _verify_clean_wheel_install(
        bin_directory,
        environment=environment,
        cwd=tmp_path,
    )

    agent_port = _free_loopback_port()
    admin_port = _free_loopback_port(excluding=frozenset({agent_port}))
    config_path, database_path, manifest_path = _write_runtime_files(
        tmp_path,
        agent_port=agent_port,
        admin_port=admin_port,
    )

    daemon: subprocess.Popen[bytes] | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    first_usage_holder: list[dict[str, object]] = []
    crawl_request_holder: list[str] = []
    crawl_job_holder: list[str] = []
    first_clean_at_holder: list[int] = []
    try:
        daemon, stdout_path, stderr_path = _start_daemon(
            gatehoused,
            config_path,
            environment=environment,
            cwd=tmp_path,
            run_number=1,
        )
        first_status = _wait_until_ready(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        assert first_status["ready"] is True
        assert _system_state(database_path)[:2] == (1, "READY")
        _verify_health_script(agent_port, environment=environment, cwd=tmp_path)
        _verify_auxiliary_entry_points(
            gatehouse_notifier,
            gatehouse_watchdog,
            config_path,
            database_path,
            agent_port,
            admin_port,
            environment=environment,
            cwd=tmp_path,
        )

        def restart_while_mcp_is_alive(*, crawl_job_id: str) -> None:
            nonlocal daemon, stdout_path, stderr_path
            assert daemon is not None
            assert stdout_path is not None
            assert stderr_path is not None
            _stop_cleanly(
                daemon,
                gatehouse,
                config_path,
                environment=environment,
                cwd=tmp_path,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
            daemon = None
            first_epoch, first_stopped_state, first_clean_at = _system_state(database_path)
            assert (first_epoch, first_stopped_state) == (1, "STOPPED")
            assert first_clean_at is not None
            first_clean_at_holder.append(first_clean_at)
            first_usage_holder.append(
                _durable_usage(
                    database_path,
                    expected_session=("ACTIVE", 1),
                    expected_total_credits=1,
                )
            )
            crawl_job_holder.append(crawl_job_id)
            crawl_request_holder.append(
                _crawl_checkpoint(
                    database_path,
                    job_id=crawl_job_id,
                    terminal=False,
                )
            )
            _write_scripted_manifest(manifest_path, resumed=True)
            _wait_until_crawl_poll_is_due(database_path, job_id=crawl_job_id)

            daemon, stdout_path, stderr_path = _start_daemon(
                gatehoused,
                config_path,
                environment=environment,
                cwd=tmp_path,
                run_number=2,
            )
            second_status = _wait_until_ready(
                daemon,
                gatehouse,
                config_path,
                environment=environment,
                cwd=tmp_path,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
            assert second_status["ready"] is True
            assert _system_state(database_path)[:2] == (2, "READY")
            first_session_id = first_usage_holder[0]["session_id"]
            assert isinstance(first_session_id, str)
            _wait_for_session_reactivation(
                database_path,
                session_id=first_session_id,
                token_epoch=2,
            )

        async def restart_with_created_job(crawl_job_id: str) -> None:
            await asyncio.to_thread(
                restart_while_mcp_is_alive,
                crawl_job_id=crawl_job_id,
            )

        invocation, crawl, recovered_job, feedback = asyncio.run(
            _exercise_controlled_mcp_across_restart(
                gatehouse,
                gatehouse_mcp,
                config_path,
                environment=environment,
                cwd=tmp_path,
                restart_daemon=restart_with_created_job,
            )
        )
        assert len(first_usage_holder) == 1
        assert len(crawl_job_holder) == 1
        assert len(crawl_request_holder) == 1
        assert len(first_clean_at_holder) == 1
        first_usage = first_usage_holder[0]
        assert invocation["request_id"] == first_usage["request_id"]
        assert crawl["job_id"] == crawl_job_holder[0]
        assert crawl["request_id"] == crawl_request_holder[0]
        assert recovered_job["job_id"] == crawl_job_holder[0]
        assert (
            _crawl_checkpoint(
                database_path,
                job_id=crawl_job_holder[0],
                terminal=True,
            )
            == crawl_request_holder[0]
        )
        _assert_same_session_readopted(
            database_path,
            session_id=cast(str, first_usage["session_id"]),
            root_run_id=cast(str, first_usage["root_run_id"]),
            feedback_id=feedback["feedback_id"],
        )
        assert (
            _durable_usage(
                database_path,
                expected_session=("DISCONNECTED", 2),
                expected_total_credits=4,
            )
            == first_usage
        )

        assert daemon is not None
        assert stdout_path is not None
        assert stderr_path is not None
        _stop_cleanly(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        daemon = None
        second_epoch, second_stopped_state, second_clean_at = _system_state(database_path)
        assert (second_epoch, second_stopped_state) == (2, "STOPPED")
        assert second_clean_at is not None
        assert second_clean_at >= first_clean_at_holder[0]
    finally:
        _terminate_if_running(daemon)
