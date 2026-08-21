"""Opt-in proof for the separately installed Gatehouse wheel.

Set ``GATEHOUSE_E2E_BIN_DIR`` to the ``Scripts`` directory of a clean virtual
environment containing the built wheel, then run this file explicitly.  The
test intentionally imports no Gatehouse production modules from the checkout.
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from ctypes import wintypes
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

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


_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_ERROR_BROKEN_PIPE = 109
_ERROR_INVALID_HANDLE = 6
_ERROR_OPERATION_ABORTED = 995
_CONPTY_TRANSCRIPT_LIMIT_BYTES = 4 * 1024 * 1024


class _Coord(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _StartupInfoW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoExW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _StartupInfoW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


@dataclass(slots=True)
class _ConptyResult:
    returncode: int
    process_id: int
    transcript: bytearray


class _SecretSurfaceViolation(RuntimeError):
    """A synthetic canary reached a surface that must remain redacted."""


def _zero_mutable(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _assert_secret_absent_from_text(secret: bytearray, text: str) -> None:
    encoded = bytearray(text, "utf-8")
    try:
        if secret in encoded:
            raise _SecretSurfaceViolation("synthetic secret reached a forbidden text surface")
    finally:
        _zero_mutable(encoded)


def _win32_error(operation: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(error, f"{operation} failed with Win32 error {error}")


def _configure_conpty_api(kernel32: Any) -> None:
    kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.CreatePipe.restype = wintypes.BOOL
    kernel32.CreatePseudoConsole.argtypes = [
        _Coord,
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    kernel32.CreatePseudoConsole.restype = ctypes.c_long
    kernel32.ClosePseudoConsole.argtypes = [ctypes.c_void_p]
    kernel32.ClosePseudoConsole.restype = None
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfoW),
        ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL


def _close_win32_handle(kernel32: Any, handle: object) -> None:
    value = getattr(handle, "value", handle)
    if value not in {None, 0, -1}:
        kernel32.CloseHandle(handle)


def _terminate_process_and_wait(kernel32: Any, process_handle: object) -> None:
    """Boundedly terminate one exact process handle and prove it became signaled."""

    status = int(kernel32.WaitForSingleObject(process_handle, 0))
    if status == _WAIT_OBJECT_0:
        return
    if status != _WAIT_TIMEOUT:
        raise _win32_error("WaitForSingleObject(pre-termination)")

    last_termination_error = 0
    for wait_ms in (1_000, 5_000):
        terminated = bool(kernel32.TerminateProcess(process_handle, 1))
        if not terminated:
            last_termination_error = ctypes.get_last_error()
        status = int(kernel32.WaitForSingleObject(process_handle, wait_ms))
        if status == _WAIT_OBJECT_0:
            return
        if status != _WAIT_TIMEOUT:
            raise _win32_error("WaitForSingleObject(post-termination)")
    if last_termination_error:
        raise OSError(
            last_termination_error,
            f"TerminateProcess failed with Win32 error {last_termination_error}",
        )
    raise RuntimeError("terminated ConPTY launcher did not reach WAIT_OBJECT_0")


def _run_conpty_hidden_secret(
    arguments: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    expected_prompt: bytes,
    secret: bytearray,
    forbidden_secrets: tuple[bytearray, ...],
    timeout_seconds: float = 30.0,
) -> _ConptyResult:
    """Run a Windows child on a real pseudoconsole and enter one hidden secret."""

    assert os.name == "nt"
    assert arguments and Path(arguments[0]).is_file()
    assert expected_prompt
    assert secret
    assert any(candidate is secret for candidate in forbidden_secrets)
    command_line = subprocess.list2cmdline(arguments)
    environment_text = (
        "\0".join(
            f"{name}={value}"
            for name, value in sorted(environment.items(), key=lambda item: item[0].casefold())
        )
        + "\0"
    )
    for candidate in forbidden_secrets:
        _assert_secret_absent_from_text(candidate, command_line)
        _assert_secret_absent_from_text(candidate, environment_text)

    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_conpty_api(kernel32)

    input_read = wintypes.HANDLE()
    input_write = wintypes.HANDLE()
    output_read = wintypes.HANDLE()
    output_write = wintypes.HANDLE()
    pseudo_console = ctypes.c_void_p()
    attribute_size = ctypes.c_size_t()
    attribute_buffer: ctypes.Array[ctypes.c_char] | None = None
    startup = _StartupInfoExW()
    process_information = _ProcessInformation()
    transcript = bytearray()
    prompt_seen = threading.Event()
    reader_errors: list[int] = []
    transcript_overflow = threading.Event()
    transcript_secret_seen = threading.Event()
    reader: threading.Thread | None = None
    write_buffer: bytearray | None = None
    process_created = False
    pseudo_console_created = False
    attribute_list_initialized = False
    input_read_open = False
    input_write_open = False
    output_read_open = False
    output_write_open = False
    process_waited = False
    cleanup_failure: BaseException | None = None
    returncode: int | None = None

    def drain_output() -> None:
        read_buffer = (ctypes.c_ubyte * 4096)()
        bytes_read = wintypes.DWORD()
        while True:
            if not kernel32.ReadFile(
                output_read,
                read_buffer,
                len(read_buffer),
                ctypes.byref(bytes_read),
                None,
            ):
                error = ctypes.get_last_error()
                if error not in {
                    _ERROR_BROKEN_PIPE,
                    _ERROR_INVALID_HANDLE,
                    _ERROR_OPERATION_ABORTED,
                }:
                    reader_errors.append(error)
                return
            count = int(bytes_read.value)
            if count == 0:
                return
            chunk = bytearray(read_buffer[:count])
            ctypes.memset(read_buffer, 0, ctypes.sizeof(read_buffer))
            try:
                available = _CONPTY_TRANSCRIPT_LIMIT_BYTES - len(transcript)
                if len(chunk) > available:
                    transcript.extend(memoryview(chunk)[: max(0, available)])
                    transcript_overflow.set()
                elif not transcript_overflow.is_set():
                    transcript.extend(chunk)
                normalized = _ansi_normalized_transcript(transcript)
                try:
                    if any(
                        candidate in transcript or candidate in normalized
                        for candidate in forbidden_secrets
                    ):
                        transcript_secret_seen.set()
                    if expected_prompt in transcript or expected_prompt in normalized:
                        prompt_seen.set()
                finally:
                    _zero_mutable(normalized)
            finally:
                _zero_mutable(chunk)

    try:
        # These pipe ends belong to the pseudoconsole host. CreateProcessW does
        # not inherit them as redirected stdio; the child attaches to HPCON and
        # therefore takes the production isatty()/msvcrt.getwch() path.
        if not kernel32.CreatePipe(
            ctypes.byref(input_read),
            ctypes.byref(input_write),
            None,
            0,
        ):
            raise _win32_error("CreatePipe(input)")
        input_read_open = True
        input_write_open = True
        if not kernel32.CreatePipe(
            ctypes.byref(output_read),
            ctypes.byref(output_write),
            None,
            0,
        ):
            raise _win32_error("CreatePipe(output)")
        output_read_open = True
        output_write_open = True

        hresult = int(
            kernel32.CreatePseudoConsole(
                _Coord(4096, 80),
                input_read,
                output_write,
                0,
                ctypes.byref(pseudo_console),
            )
        )
        if hresult < 0:
            raise OSError(hresult, "CreatePseudoConsole failed")
        pseudo_console_created = True
        _close_win32_handle(kernel32, input_read)
        input_read_open = False
        _close_win32_handle(kernel32, output_write)
        output_write_open = False

        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attribute_size))
        if int(attribute_size.value) <= 0:
            raise _win32_error("InitializeProcThreadAttributeList(size)")
        attribute_buffer = ctypes.create_string_buffer(int(attribute_size.value))
        startup.lpAttributeList = ctypes.cast(attribute_buffer, ctypes.c_void_p)
        if not kernel32.InitializeProcThreadAttributeList(
            startup.lpAttributeList,
            1,
            0,
            ctypes.byref(attribute_size),
        ):
            raise _win32_error("InitializeProcThreadAttributeList")
        attribute_list_initialized = True
        if not kernel32.UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            _PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            pseudo_console,
            ctypes.sizeof(pseudo_console),
            None,
            None,
        ):
            raise _win32_error("UpdateProcThreadAttribute")

        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags |= _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = None
        startup.StartupInfo.hStdOutput = None
        startup.StartupInfo.hStdError = None
        command_buffer = ctypes.create_unicode_buffer(command_line)
        environment_buffer = ctypes.create_unicode_buffer(environment_text)
        if not kernel32.CreateProcessW(
            arguments[0],
            command_buffer,
            None,
            None,
            False,
            _EXTENDED_STARTUPINFO_PRESENT | _CREATE_UNICODE_ENVIRONMENT,
            ctypes.cast(environment_buffer, ctypes.c_void_p),
            str(cwd),
            ctypes.byref(startup.StartupInfo),
            ctypes.byref(process_information),
        ):
            raise _win32_error("CreateProcessW")
        process_created = True

        _close_win32_handle(kernel32, process_information.hThread)
        process_information.hThread = None

        reader = threading.Thread(
            target=drain_output,
            name="gatehouse-installed-conpty-drain",
            daemon=True,
        )
        reader.start()
        prompt_deadline = time.monotonic() + min(20.0, timeout_seconds)
        while not prompt_seen.wait(timeout=0.05):
            wait_status = int(kernel32.WaitForSingleObject(process_information.hProcess, 0))
            if wait_status == _WAIT_OBJECT_0 or time.monotonic() >= prompt_deadline:
                raise AssertionError(
                    "installed credential command did not reach its hidden prompt "
                    f"(process_exited={wait_status == _WAIT_OBJECT_0}, "
                    f"transcript_bytes={len(transcript)}, "
                    f"reader_error_count={len(reader_errors)})"
                )
        assert not transcript_overflow.is_set(), "ConPTY transcript exceeded its bounded buffer"

        write_buffer = bytearray(secret)
        write_buffer.append(13)
        write_array = (ctypes.c_ubyte * len(write_buffer)).from_buffer(write_buffer)
        bytes_written = wintypes.DWORD()
        if not kernel32.WriteFile(
            input_write,
            write_array,
            len(write_buffer),
            ctypes.byref(bytes_written),
            None,
        ):
            raise _win32_error("WriteFile(ConPTY input)")
        if int(bytes_written.value) != len(write_buffer):
            raise AssertionError("ConPTY accepted only part of the hidden terminal input")
        _zero_mutable(write_buffer)
        write_buffer = None

        wait_status = int(
            kernel32.WaitForSingleObject(
                process_information.hProcess,
                max(1, int(timeout_seconds * 1_000)),
            )
        )
        if wait_status == _WAIT_TIMEOUT:
            raise TimeoutError("installed credential command exceeded its bounded timeout")
        if wait_status != _WAIT_OBJECT_0:
            raise _win32_error("WaitForSingleObject")
        process_waited = True
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(
            process_information.hProcess,
            ctypes.byref(exit_code),
        ):
            raise _win32_error("GetExitCodeProcess")
        returncode = int(exit_code.value)
    finally:
        if write_buffer is not None:
            _zero_mutable(write_buffer)
        if process_created and not process_waited:
            try:
                _terminate_process_and_wait(kernel32, process_information.hProcess)
                process_waited = True
            except (OSError, RuntimeError) as error:
                cleanup_failure = error
        if input_write_open:
            _close_win32_handle(kernel32, input_write)
            input_write_open = False
        if pseudo_console_created:
            kernel32.ClosePseudoConsole(pseudo_console)
            pseudo_console_created = False
        if reader is not None:
            reader.join(timeout=5)
            if reader.is_alive() and output_read_open:
                _close_win32_handle(kernel32, output_read)
                output_read_open = False
                reader.join(timeout=5)
        if input_read_open:
            _close_win32_handle(kernel32, input_read)
        if output_write_open:
            _close_win32_handle(kernel32, output_write)
        if output_read_open:
            _close_win32_handle(kernel32, output_read)
        if process_created and process_waited:
            final_wait = int(kernel32.WaitForSingleObject(process_information.hProcess, 0))
            if final_wait != _WAIT_OBJECT_0 and cleanup_failure is None:
                cleanup_failure = RuntimeError(
                    "ConPTY launcher was not signaled during final cleanup"
                )
        if process_created:
            _close_win32_handle(kernel32, process_information.hThread)
            _close_win32_handle(kernel32, process_information.hProcess)
        if attribute_list_initialized:
            kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
        if transcript_secret_seen.is_set() or any(
            candidate in transcript for candidate in forbidden_secrets
        ):
            _zero_mutable(transcript)
            raise _SecretSurfaceViolation("synthetic secret reached the pseudoconsole transcript")
        if cleanup_failure is not None:
            raise cleanup_failure

    assert reader is not None and not reader.is_alive(), "ConPTY drain thread did not stop"
    assert not reader_errors, "ConPTY output drain failed"
    assert not transcript_overflow.is_set(), "ConPTY transcript exceeded its bounded buffer"
    assert returncode is not None
    return _ConptyResult(
        returncode=returncode,
        process_id=int(process_information.dwProcessId),
        transcript=transcript,
    )


def _entry_point(bin_directory: Path, name: str) -> Path:
    path = (bin_directory / f"{name}.exe").resolve()
    assert path.is_file(), f"installed entry point is missing: {path}"
    return path


def _sanitized_environment(temporary_directory: Path) -> dict[str, str]:
    # Read only explicitly required, non-secret Windows runtime locations. Do
    # not enumerate the ambient environment or inherit proxy/provider settings.
    allowed_names = (
        "APPDATA",
        "COMSPEC",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "SYSTEMROOT",
        "WINDIR",
    )
    environment = {
        name: value
        for name in allowed_names
        if (value := os.environ.get(name)) is not None and value
    }
    environment["PYTHONUTF8"] = "1"
    environment["TEMP"] = str(temporary_directory.resolve())
    environment["TMP"] = str(temporary_directory.resolve())
    return environment


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
    scripted: bool = True,
) -> tuple[Path, Path, Path]:
    config_source = _CHECKOUT_ROOT / "config"
    database_path = (tmp_path / "state" / "gatehouse.db").resolve()
    manifest_path = (tmp_path / "scripted-responses.json").resolve()
    if scripted:
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
    if scripted:
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
    forbidden_secrets: tuple[bytearray, ...] = (),
) -> dict[str, object]:
    completed = _run(
        (str(gatehouse), "--config", str(config_path), *arguments),
        environment=environment,
        cwd=cwd,
    )
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, completed.stdout)
        _assert_secret_absent_from_text(secret, completed.stderr)
    assert completed.returncode == 0, completed.stderr
    decoded = json.loads(completed.stdout)
    assert isinstance(decoded, dict)
    assert all(isinstance(key, str) for key in decoded)
    return cast(dict[str, object], decoded)


def _cli_json_list(
    gatehouse: Path,
    config_path: Path,
    *arguments: str,
    environment: Mapping[str, str],
    cwd: Path,
    forbidden_secrets: tuple[bytearray, ...] = (),
) -> list[dict[str, object]]:
    completed = _run(
        (str(gatehouse), "--config", str(config_path), *arguments),
        environment=environment,
        cwd=cwd,
    )
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, completed.stdout)
        _assert_secret_absent_from_text(secret, completed.stderr)
    assert completed.returncode == 0, completed.stderr
    decoded = json.loads(completed.stdout)
    assert isinstance(decoded, list)
    assert all(
        isinstance(item, dict) and all(isinstance(key, str) for key in item) for item in decoded
    )
    return cast(list[dict[str, object]], decoded)


_ANSI_ESCAPE = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CREDENTIAL_MUTATION_RESULT_FIELDS = frozenset(
    {
        "mutation_id",
        "credential_id",
        "action",
        "state",
        "generation",
        "alias",
        "principal_id",
        "principal_alias",
        "quota_scope_id",
        "quota_scope_alias",
        "pool_id",
        "pool_alias",
        "expires_at_ms",
        "acted_at_ms",
        "audit_event_id",
    }
)
_CREDENTIAL_SUMMARY_FIELDS = frozenset(
    {
        "credential_id",
        "service",
        "alias",
        "principal_id",
        "quota_scope_id",
        "state",
        "generation",
        "exclusive_usage",
        "principal_alias",
        "quota_scope_alias",
        "pool_ids",
        "pool_aliases",
        "active_lease_count",
        "created_at_ms",
        "expires_at_ms",
        "last_used_at_ms",
        "last_local_action",
    }
)


def _ansi_normalized_transcript(transcript: bytearray) -> bytearray:
    normalized = bytearray()
    view = memoryview(transcript)
    try:
        cursor = 0
        for match in _ANSI_ESCAPE.finditer(cast(bytes, transcript)):
            normalized.extend(view[cursor : match.start()])
            cursor = match.end()
        normalized.extend(view[cursor:])
        return normalized
    except BaseException:
        _zero_mutable(normalized)
        raise
    finally:
        view.release()


def _conpty_json(
    result: _ConptyResult,
    *,
    forbidden_secrets: tuple[bytearray, ...],
) -> dict[str, object]:
    normalized = _ansi_normalized_transcript(result.transcript)
    try:
        for secret in forbidden_secrets:
            if secret in normalized:
                raise _SecretSurfaceViolation("hidden synthetic secret reached CLI output")
        assert result.returncode == 0, "installed credential command failed"
        text = normalized.decode("utf-8", errors="replace").replace("\r", "")
    finally:
        _zero_mutable(normalized)
    start = text.find("{")
    end = text.rfind("}")
    assert start >= 0 and end >= start, "installed credential command returned no JSON object"
    decoded = json.loads(text[start : end + 1])
    assert isinstance(decoded, dict)
    assert all(isinstance(key, str) for key in decoded)
    return cast(dict[str, object], decoded)


def _credential_summary(
    summaries: list[dict[str, object]],
    credential_id: str,
) -> dict[str, object]:
    matches = [item for item in summaries if item.get("credential_id") == credential_id]
    assert len(matches) == 1
    summary = matches[0]
    assert set(summary) == _CREDENTIAL_SUMMARY_FIELDS
    return summary


def _seed_disabled_route_authority(database_path: Path) -> tuple[str, str, str]:
    """Seed non-secret catalog authority while the disabled daemon is stopped."""

    principal_id = "prn_00000000000000000000000001"
    quota_scope_id = "quota_00000000000000000000000001"
    pool_id = "pool_00000000000000000000000001"
    now_ms = int(time.time() * 1_000)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        assert connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM quota_scopes").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM pool_members").fetchone()[0] == 0
        assert connection.execute("SELECT alias FROM pools ORDER BY alias").fetchall() == [
            ("emergency-locked",)
        ]
        connection.execute(
            """
            INSERT INTO principals(
                principal_id, service_id, alias, enabled, metadata_json,
                created_at_ms, updated_at_ms
            ) VALUES (?, 'firecrawl', 'installed-gate-a-no-network', 1,
                      '{"fixture":"installed-gate-a","network":false}', ?, ?)
            """,
            (principal_id, now_ms, now_ms),
        )
        connection.execute(
            """
            INSERT INTO quota_scopes(
                quota_scope_id, principal_id, alias, state, unit,
                last_known_remaining_units, configured_floor_units,
                metadata_json, balance_as_of_ms
            ) VALUES (?, ?, 'installed-gate-a-no-network', 'HEALTHY', 'credits',
                      100, 0, '{"fixture":"installed-gate-a","network":false}', ?)
            """,
            (quota_scope_id, principal_id, now_ms),
        )
        connection.execute(
            """
            INSERT INTO pools(
                pool_id, service_id, alias, state, selection_strategy,
                automatic_use, config_json
            ) VALUES (?, 'firecrawl', 'interactive-default', 'ACTIVE', 'pinned', 1,
                      '{"automatic_failover_within_pool":false,"network":false}')
            """,
            (pool_id,),
        )
        connection.execute(
            """
            INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
            VALUES (?, ?, 1, 1, 1)
            """,
            (pool_id, quota_scope_id),
        )
        connection.commit()
    finally:
        connection.close()
    return principal_id, quota_scope_id, pool_id


_INSTALLED_DPAPI_DIGEST_PROBE = """
import asyncio
import hashlib
import hmac
import json
import sys

from gatehouse.credentials import DpapiCurrentUserKeyStore


async def main():
    store = DpapiCurrentUserKeyStore(sys.argv[1])
    generation = int(sys.argv[3])
    metadata = await store.list_metadata()
    matches = [item for item in metadata if item.credential_id == sys.argv[2]]
    metadata_matched = (
        len(matches) == 1
        and matches[0].generation == generation
        and matches[0].secret_reference == sys.argv[5]
    )
    matched = False
    if metadata_matched:
        lease = await store.open_lease(
            sys.argv[2],
            "installed Gate A custody digest proof",
            expected_generation=generation,
            ttl_seconds=1,
        )
        async with lease as secret:
            matched = hmac.compare_digest(
                hashlib.sha256(secret).hexdigest(),
                sys.argv[4],
            )
    print(
        json.dumps(
            {"matched": matched, "metadata_matched": metadata_matched},
            separators=(",", ":"),
        )
    )


asyncio.run(main())
"""


def _verify_installed_dpapi_digest(
    python: Path,
    database_path: Path,
    credentials_directory: Path,
    *,
    credential_id: str,
    generation: int,
    expected_digest: str,
    forbidden_secrets: tuple[bytearray, ...],
    environment: Mapping[str, str],
    cwd: Path,
) -> None:
    expected_reference = (
        "dpapi-current-user://" + hashlib.sha256(credential_id.encode("utf-8")).hexdigest()
    )
    connection = sqlite3.connect(database_path)
    try:
        custody_row = connection.execute(
            """
            SELECT secret_backend, secret_reference, generation
              FROM credentials
             WHERE credential_id = ?
            """,
            (credential_id,),
        ).fetchone()
    finally:
        connection.close()
    assert custody_row == ("dpapi-current-user", expected_reference, generation)

    arguments = (
        str(python),
        "-c",
        _INSTALLED_DPAPI_DIGEST_PROBE,
        str(credentials_directory),
        credential_id,
        str(generation),
        expected_digest,
        expected_reference,
    )
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, subprocess.list2cmdline(arguments))
        _assert_secret_absent_from_text(
            secret,
            "\0".join(f"{name}={value}" for name, value in environment.items()),
        )
    completed = _run(
        arguments,
        environment=environment,
        cwd=cwd,
    )
    stdout = bytearray(completed.stdout, "utf-8")
    stderr = bytearray(completed.stderr, "utf-8")
    try:
        for secret in forbidden_secrets:
            if secret in stdout or secret in stderr:
                raise _SecretSurfaceViolation(
                    "synthetic secret reached installed DPAPI probe output"
                )
        assert completed.returncode == 0, "installed DPAPI digest probe failed"
        decoded = json.loads(stdout.decode("utf-8"))
        assert decoded == {"matched": True, "metadata_matched": True}
    finally:
        _zero_mutable(stdout)
        _zero_mutable(stderr)


def _assert_secret_absent_from_tree(root: Path, secret: bytearray) -> None:
    for path in sorted(root.rglob("*")):
        _assert_secret_absent_from_text(secret, str(path))
        if not path.is_file():
            continue
        content = bytearray(path.read_bytes())
        try:
            if secret in content:
                raise _SecretSurfaceViolation("synthetic secret persisted in the runtime tree")
        finally:
            _zero_mutable(content)


def _assert_no_provider_activity(database_path: Path) -> None:
    connection = sqlite3.connect(database_path)
    try:
        counts = {
            "invocations": int(
                connection.execute("SELECT COUNT(*) FROM invocations").fetchone()[0]
            ),
            "attempts": int(connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]),
            "external_resources": int(
                connection.execute("SELECT COUNT(*) FROM external_resources").fetchone()[0]
            ),
        }
    finally:
        connection.close()
    assert counts == {"invocations": 0, "attempts": 0, "external_resources": 0}


def _synthetic_canary(label: bytes) -> bytearray:
    assert label and label.isalnum()
    random_suffix = bytearray(secrets.token_hex(24), "ascii")
    canary = bytearray(b"FAKE-GATEHOUSE-INSTALLED-")
    try:
        canary.extend(label)
        canary.extend(b"-")
        canary.extend(random_suffix)
        return canary
    finally:
        _zero_mutable(random_suffix)


def _wait_until_ready(
    process: subprocess.Popen[bytes],
    gatehouse: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    forbidden_secrets: tuple[bytearray, ...] = (),
    expected_status: str = "READY",
    expected_ready: bool = True,
) -> dict[str, object]:
    deadline = time.monotonic() + 35.0
    last_status: dict[str, object] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            diagnostics = _logs(stdout_path, stderr_path)
            for secret in forbidden_secrets:
                _assert_secret_absent_from_text(secret, diagnostics)
            pytest.fail(f"gatehoused exited with {process.returncode}\n{diagnostics}")
        try:
            last_status = _cli_json(
                gatehouse,
                config_path,
                "status",
                environment=environment,
                cwd=cwd,
                forbidden_secrets=forbidden_secrets,
            )
        except (AssertionError, json.JSONDecodeError, subprocess.TimeoutExpired):
            time.sleep(0.1)
            continue
        if (
            last_status.get("ready") is expected_ready
            and last_status.get("status") == expected_status
        ):
            return last_status
        time.sleep(0.1)
    diagnostics = _logs(stdout_path, stderr_path)
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, diagnostics)
    pytest.fail(f"gatehoused did not become ready; last status={last_status!r}\n{diagnostics}")


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
    forbidden_secrets: tuple[bytearray, ...] = (),
) -> dict[str, object]:
    result = _cli_json(
        gatehouse,
        config_path,
        "daemon",
        "stop",
        environment=environment,
        cwd=cwd,
        forbidden_secrets=forbidden_secrets,
    )
    try:
        exit_code = process.wait(timeout=35)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
        diagnostics = _logs(stdout_path, stderr_path)
        for secret in forbidden_secrets:
            _assert_secret_absent_from_text(secret, diagnostics)
        pytest.fail(f"gatehoused did not stop after drain\n{diagnostics}")
    assert result == {"action": "stop", "status": "STOPPED", "stopped": True}
    diagnostics = _logs(stdout_path, stderr_path)
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, diagnostics)
    assert exit_code == 0, diagnostics
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


async def _assert_controlled_mcp_surface_excludes_secrets(
    gatehouse: Path,
    gatehouse_mcp: Path,
    config_path: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    forbidden_secrets: tuple[bytearray, ...],
) -> None:
    """List installed MCP tools while custody is active, without invoking one."""

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
    command_line = subprocess.list2cmdline((parameters.command, *parameters.args))
    environment_text = "\0".join(
        f"{name}={value}"
        for name, value in sorted(environment.items(), key=lambda item: item[0].casefold())
    )
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, command_line)
        _assert_secret_absent_from_text(secret, environment_text)
    stderr_path = cwd / "credential-canary-mcp.stderr.log"
    with stderr_path.open("w", encoding="utf-8") as stderr:
        async with stdio_client(parameters, errlog=stderr) as (read, write):
            async with ClientSession(
                read,
                write,
                read_timeout_seconds=timedelta(seconds=30),
            ) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                names = {tool.name for tool in tools.tools}
                assert "firecrawl_search" in names
                assert "firecrawl_crawl_start" in names
                assert "gatehouse_job_status" in names
                assert not any(
                    marker in name.casefold()
                    for name in names
                    for marker in ("credential", "secret", "emergency")
                )
                surface = repr((initialized, tools))
                for secret in forbidden_secrets:
                    _assert_secret_absent_from_text(secret, surface)
    stderr_text = stderr_path.read_text(encoding="utf-8")
    for secret in forbidden_secrets:
        _assert_secret_absent_from_text(secret, stderr_text)


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
        ).fetchall() == [("COMPLETED", "provider-crawl-installed-e2e")]
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
    environment = _sanitized_environment(tmp_path)
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


def test_installed_wheel_hidden_cli_dpapi_lifecycle_across_restart(
    tmp_path: Path,
) -> None:
    """Prove the installed disabled-provider lifecycle without a secret side channel."""

    assert _OPT_IN_BIN_DIRECTORY is not None
    bin_directory = Path(_OPT_IN_BIN_DIRECTORY).resolve()
    assert bin_directory.is_dir(), f"installed bin directory is missing: {bin_directory}"
    gatehouse = _entry_point(bin_directory, "gatehouse")
    gatehoused = _entry_point(bin_directory, "gatehoused")
    gatehouse_mcp = _entry_point(bin_directory, "gatehouse-mcp")
    python = _entry_point(bin_directory, "python")
    environment = _sanitized_environment(tmp_path)
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
        scripted=False,
    )
    configuration = config_path.read_text(encoding="utf-8")
    configuration_before = config_path.read_bytes()
    assert "provider:\n  mode: disabled\n  network_enabled: false\n" in configuration
    assert "mode: scripted" not in configuration
    assert "mode: live" not in configuration
    assert not manifest_path.exists()
    credentials_directory = database_path.parent / "credentials"

    original_secret = _synthetic_canary(b"PROVISION")
    replacement_secret = _synthetic_canary(b"ROTATION")
    original_digest = hashlib.sha256(original_secret).hexdigest()
    replacement_digest = hashlib.sha256(replacement_secret).hexdigest()
    forbidden_secrets = (original_secret, replacement_secret)
    transcripts: list[bytearray] = []
    daemon: subprocess.Popen[bytes] | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    try:
        daemon, stdout_path, stderr_path = _start_daemon(
            gatehoused,
            config_path,
            environment=environment,
            cwd=tmp_path,
            run_number=100,
        )
        _wait_until_ready(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
            expected_status="DEGRADED_NO_PROVIDER",
            expected_ready=False,
        )
        _stop_cleanly(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert daemon.poll() == 0
        daemon = None
        # Disabled mode deliberately creates no provider route. Seed only the
        # non-secret catalog authority that the admin lifecycle validates, and
        # do so while no daemon owns the database.
        principal_id, quota_scope_id, pool_id = _seed_disabled_route_authority(database_path)

        daemon, stdout_path, stderr_path = _start_daemon(
            gatehoused,
            config_path,
            environment=environment,
            cwd=tmp_path,
            run_number=101,
        )
        _wait_until_ready(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
            expected_status="DEGRADED_NO_PROVIDER",
            expected_ready=False,
        )

        provision_process = _run_conpty_hidden_secret(
            (
                str(gatehouse),
                "--config",
                str(config_path),
                "credentials",
                "provision",
                "--mutation-id",
                "installed-gate-a-provision",
                "--principal-id",
                principal_id,
                "--quota-scope-id",
                quota_scope_id,
                "--pool-id",
                pool_id,
                "--alias",
                "installed-gate-a-primary",
            ),
            environment=environment,
            cwd=tmp_path,
            # ConPTY does not serialize a terminal's final blank cell.
            expected_prompt=b"Credential secret:",
            secret=original_secret,
            forbidden_secrets=forbidden_secrets,
        )
        transcripts.append(provision_process.transcript)
        assert provision_process.process_id > 0
        provisioned = _conpty_json(
            provision_process,
            forbidden_secrets=forbidden_secrets,
        )
        assert set(provisioned) == _CREDENTIAL_MUTATION_RESULT_FIELDS
        assert provisioned["mutation_id"] == "installed-gate-a-provision"
        assert provisioned["action"] == "provision"
        assert provisioned["state"] == "HEALTHY"
        assert provisioned["generation"] == 1
        assert provisioned["alias"] == "installed-gate-a-primary"
        assert provisioned["principal_id"] == principal_id
        assert provisioned["quota_scope_id"] == quota_scope_id
        assert provisioned["pool_id"] == pool_id
        credential_id = provisioned["credential_id"]
        assert isinstance(credential_id, str) and credential_id

        summaries = _cli_json_list(
            gatehouse,
            config_path,
            "credentials",
            "list",
            "--limit",
            "10",
            environment=environment,
            cwd=tmp_path,
            forbidden_secrets=forbidden_secrets,
        )
        first_summary = _credential_summary(summaries, credential_id)
        assert first_summary["service"] == "firecrawl"
        assert first_summary["alias"] == "installed-gate-a-primary"
        assert first_summary["state"] == "HEALTHY"
        assert first_summary["generation"] == 1
        assert first_summary["exclusive_usage"] is True
        assert first_summary["active_lease_count"] == 0
        pool_ids = first_summary["pool_ids"]
        pool_aliases = first_summary["pool_aliases"]
        assert isinstance(pool_ids, list) and pool_id in pool_ids
        assert isinstance(pool_aliases, list) and "interactive-default" in pool_aliases
        status = _cli_json(
            gatehouse,
            config_path,
            "status",
            environment=environment,
            cwd=tmp_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert status["ready"] is False
        assert status["status"] == "DEGRADED_NO_PROVIDER"
        assert status["degraded_components"] == ["provider_network"]
        asyncio.run(
            _assert_controlled_mcp_surface_excludes_secrets(
                gatehouse,
                gatehouse_mcp,
                config_path,
                environment=environment,
                cwd=tmp_path,
                forbidden_secrets=forbidden_secrets,
            )
        )

        _stop_cleanly(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert daemon.poll() == 0
        daemon = None

        daemon, stdout_path, stderr_path = _start_daemon(
            gatehoused,
            config_path,
            environment=environment,
            cwd=tmp_path,
            run_number=102,
        )
        _wait_until_ready(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
            expected_status="DEGRADED_NO_PROVIDER",
            expected_ready=False,
        )
        restarted_summaries = _cli_json_list(
            gatehouse,
            config_path,
            "credentials",
            "list",
            "--limit",
            "10",
            environment=environment,
            cwd=tmp_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert _credential_summary(restarted_summaries, credential_id) == first_summary
        _verify_installed_dpapi_digest(
            python,
            database_path,
            credentials_directory,
            credential_id=credential_id,
            generation=1,
            expected_digest=original_digest,
            forbidden_secrets=forbidden_secrets,
            environment=environment,
            cwd=tmp_path,
        )

        rotation_process = _run_conpty_hidden_secret(
            (
                str(gatehouse),
                "--config",
                str(config_path),
                "credentials",
                "rotate",
                credential_id,
                "--mutation-id",
                "installed-gate-a-rotation",
            ),
            environment=environment,
            cwd=tmp_path,
            expected_prompt=b"Replacement credential secret:",
            secret=replacement_secret,
            forbidden_secrets=forbidden_secrets,
        )
        transcripts.append(rotation_process.transcript)
        assert rotation_process.process_id > 0
        rotated = _conpty_json(
            rotation_process,
            forbidden_secrets=forbidden_secrets,
        )
        assert set(rotated) == _CREDENTIAL_MUTATION_RESULT_FIELDS
        assert rotated["mutation_id"] == "installed-gate-a-rotation"
        assert rotated["action"] == "rotate"
        assert rotated["state"] == "HEALTHY"
        assert rotated["generation"] == 2
        assert rotated["alias"] == "installed-gate-a-primary"
        successor_id = rotated["credential_id"]
        assert isinstance(successor_id, str) and successor_id
        assert successor_id != credential_id

        rotated_summaries = _cli_json_list(
            gatehouse,
            config_path,
            "credentials",
            "list",
            "--limit",
            "10",
            environment=environment,
            cwd=tmp_path,
            forbidden_secrets=forbidden_secrets,
        )
        predecessor = _credential_summary(rotated_summaries, credential_id)
        successor = _credential_summary(rotated_summaries, successor_id)
        assert predecessor["state"] == "DRAINING"
        assert predecessor["generation"] == 1
        assert predecessor["alias"] != "installed-gate-a-primary"
        assert successor["state"] == "HEALTHY"
        assert successor["generation"] == 2
        assert successor["alias"] == "installed-gate-a-primary"
        assert successor["active_lease_count"] == 0

        _stop_cleanly(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert daemon.poll() == 0
        daemon = None

        daemon, stdout_path, stderr_path = _start_daemon(
            gatehoused,
            config_path,
            environment=environment,
            cwd=tmp_path,
            run_number=103,
        )
        _wait_until_ready(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
            expected_status="DEGRADED_NO_PROVIDER",
            expected_ready=False,
        )
        final_summaries = _cli_json_list(
            gatehouse,
            config_path,
            "credentials",
            "list",
            "--limit",
            "10",
            environment=environment,
            cwd=tmp_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert _credential_summary(final_summaries, credential_id)["state"] == "DRAINING"
        final_successor = _credential_summary(final_summaries, successor_id)
        assert final_successor["state"] == "HEALTHY"
        assert final_successor["generation"] == 2
        _verify_installed_dpapi_digest(
            python,
            database_path,
            credentials_directory,
            credential_id=successor_id,
            generation=2,
            expected_digest=replacement_digest,
            forbidden_secrets=forbidden_secrets,
            environment=environment,
            cwd=tmp_path,
        )

        _stop_cleanly(
            daemon,
            gatehouse,
            config_path,
            environment=environment,
            cwd=tmp_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            forbidden_secrets=forbidden_secrets,
        )
        assert daemon.poll() == 0
        daemon = None
        assert config_path.read_bytes() == configuration_before
        assert not manifest_path.exists()
        _assert_no_provider_activity(database_path)
    finally:
        try:
            _terminate_if_running(daemon)
            for secret in forbidden_secrets:
                _assert_secret_absent_from_tree(tmp_path, secret)
                for transcript in transcripts:
                    if secret in transcript:
                        raise _SecretSurfaceViolation(
                            "synthetic secret reached installed CLI output"
                        )
        finally:
            for transcript in transcripts:
                _zero_mutable(transcript)
            _zero_mutable(original_secret)
            _zero_mutable(replacement_secret)
