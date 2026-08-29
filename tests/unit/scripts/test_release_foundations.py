from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tomllib
import zipfile
from pathlib import Path

import pytest

import scripts.check_publication_hygiene as publication_hygiene
from scripts.audit_release_wheel import (
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    WheelAuditError,
    audit_wheel,
)

ROOT = Path(__file__).parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
SCRIPTS = ROOT / "scripts"


def _record_digest(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _write_synthetic_candidate(
    root: Path,
    *,
    source_payload: bytes = b'__version__ = "1.2.3"\n',
    source_requirements: tuple[str, ...] = ("anyio>=4.8,<5",),
    metadata_requirements: tuple[str, ...] = ("anyio<5,>=4.8",),
    metadata_headers: tuple[str, ...] = (),
    source_files: dict[str, bytes] | None = None,
    additional_payloads: dict[str, bytes] | None = None,
    dist_info: str = "gatehouse_local-1.2.3.dist-info",
    wheel_filename: str = "gatehouse_local-1.2.3-py3-none-any.whl",
    wheel_metadata: bytes = (
        b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    ),
) -> Path:
    (root / "src" / "gatehouse").mkdir(parents=True)
    (root / "src" / "gatehouse" / "__init__.py").write_bytes(source_payload)
    readme = b"# Synthetic Gatehouse candidate\n"
    (root / "README.md").write_bytes(readme)
    for name, payload in (source_files or {}).items():
        (root / name).write_bytes(payload)
    project = """
[project]
name = "gatehouse-local"
version = "1.2.3"
requires-python = ">=3.12,<4"
authors = [{{ name = "Yash Verma", email = "pes1ug23am910@pesu.pes.edu" }}]
dependencies = {dependencies}

[project.scripts]
gatehouse = "gatehouse.cli.main:app"
""".lstrip().format(dependencies=json.dumps(source_requirements))
    (root / "pyproject.toml").write_text(
        project,
        encoding="utf-8",
    )
    requires_dist = b"".join(
        f"Requires-Dist: {requirement}\n".encode() for requirement in metadata_requirements
    )
    extra_headers = b"".join(f"{header}\n".encode() for header in metadata_headers)
    payloads = {
        "gatehouse/__init__.py": b'__version__ = "1.2.3"\n',
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: gatehouse-local\n"
            b"Version: 1.2.3\n"
            b"Author-email: Yash Verma <pes1ug23am910@pesu.pes.edu>\n"
            b"Requires-Python: <4,>=3.12\n" + requires_dist + extra_headers + b"\n" + readme
        ),
        f"{dist_info}/WHEEL": wheel_metadata,
        f"{dist_info}/entry_points.txt": (
            b"[console_scripts]\ngatehouse = gatehouse.cli.main:app\n"
        ),
    }
    payloads.update(additional_payloads or {})
    record_name = f"{dist_info}/RECORD"
    record_buffer = io.StringIO(newline="")
    writer = csv.writer(record_buffer, lineterminator="\n")
    for name, payload in payloads.items():
        writer.writerow((name, f"sha256={_record_digest(payload)}", len(payload)))
    writer.writerow((record_name, "", ""))
    payloads[record_name] = record_buffer.getvalue().encode("utf-8")

    wheel = root / wheel_filename
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in payloads.items():
            archive.writestr(name, payload)
    return wheel


def _declare_archive_entry_size(wheel: Path, entry_suffix: str, size: int) -> None:
    payload = bytearray(wheel.read_bytes())
    offset = 0
    while True:
        offset = payload.find(b"PK\x01\x02", offset)
        if offset < 0:
            raise AssertionError(f"central-directory entry not found: {entry_suffix}")
        name_length = struct.unpack_from("<H", payload, offset + 28)[0]
        extra_length = struct.unpack_from("<H", payload, offset + 30)[0]
        comment_length = struct.unpack_from("<H", payload, offset + 32)[0]
        name_start = offset + 46
        name_end = name_start + name_length
        if payload[name_start:name_end].decode("utf-8").endswith(entry_suffix):
            struct.pack_into("<I", payload, offset + 24, size)
            wheel.write_bytes(payload)
            return
        offset = name_end + extra_length + comment_length


def test_supported_python_range_and_classifiers_match_ci_matrix() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["requires-python"] == ">=3.12,<4"
    classifiers = set(project["classifiers"])
    for minor in ("3.12", "3.13", "3.14"):
        assert f"Programming Language :: Python :: {minor}" in classifiers
    assert "Programming Language :: Python :: 3 :: Only" in classifiers
    assert "Operating System :: Microsoft :: Windows" in classifiers


def test_windows_ci_runs_every_declared_gate_on_all_supported_minors() -> None:
    workflow = (WORKFLOWS / "windows-ci.yml").read_text(encoding="utf-8")

    assert 'python-version: ["3.12", "3.13", "3.14"]' in workflow
    for command in (
        "pytest -p no:cacheprovider",
        "ruff check --no-cache .",
        "ruff format --check --no-cache .",
        "mypy --strict --no-incremental src tests scripts",
        "scripts/check_markdown_links.py",
        "scripts/check_publication_hygiene.py",
        "git diff --check",
    ):
        assert command in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert '".[dev]"' not in workflow
    for required in (
        "requirements/runtime-py$pythonDigits.txt",
        "requirements/gate-py$pythonDigits.txt",
        "https://pypi.org/simple",
        "--no-cache-dir",
        "--no-deps --only-binary=:all:",
        "--require-hashes",
        "--no-index",
        "verify_gate_toolchain.py",
        "requirements/runtime-wheelhouse.json",
        "requirements/gate-wheelhouse.json",
        "requirements/osv-runtime-snapshot.json",
        "requirements/osv-gate-tools-snapshot.json",
        "platform.python_version()",
        "pip check",
        "git status --porcelain=v1 --untracked-files=all",
    ):
        assert required in workflow
    assert workflow.index("python -I scripts/verify_gate_toolchain.py") < workflow.index(
        "python -I -m pip install --isolated"
    )


def test_workflow_actions_are_pinned_to_reviewed_full_commits() -> None:
    checkout = "3d3c42e5aac5ba805825da76410c181273ba90b1"
    setup_python = "5fda3b95a4ea91299a34e894583c3862153e4b97"

    for path in (WORKFLOWS / "windows-ci.yml", WORKFLOWS / "release-evidence.yml"):
        workflow = path.read_text(encoding="utf-8")
        assert f"actions/checkout@{checkout}" in workflow
        assert f"actions/setup-python@{setup_python}" in workflow
        assert re.search(r"actions/(?:checkout|setup-python)@v\d", workflow) is None


def test_release_workflow_and_script_are_non_publishing_and_index_disabled_at_install() -> None:
    workflow = (WORKFLOWS / "release-evidence.yml").read_text(encoding="utf-8")
    script = (SCRIPTS / "verify-release-candidate.ps1").read_text(encoding="utf-8")
    combined = f"{workflow}\n{script}".casefold()

    assert "build-wheel-offline.ps1" in workflow
    assert "verify-release-candidate.ps1" in workflow
    assert 'python-version: ["3.12", "3.13", "3.14"]' in workflow
    assert '$runtimeLock = "requirements/runtime-py$pythonDigits.txt"' in workflow
    assert '$gateLock = "requirements/gate-py$pythonDigits.txt"' in workflow
    assert '".[dev]"' not in workflow
    assert "--require-hashes" in workflow
    assert "--no-cache-dir --no-index --no-deps" in workflow
    assert "--only-binary=:all:" in workflow
    assert "verify_gate_toolchain.py" in workflow
    assert "requirements/osv-gate-tools-snapshot.json" in workflow
    assert "git status --porcelain=v1 --untracked-files=all" in workflow
    assert workflow.index("python -I scripts/verify_gate_toolchain.py") < workflow.index(
        "python -I -m pip install --isolated"
    )
    assert "verify_release_supply_chain.py" in script
    assert '"--require-hashes"' in script
    assert '"--requirement"' in script and "$runtimeLockPath" in script
    assert '"--no-deps"' in script and "$candidateInstallPath" in script
    assert "gatehouse-local @ $candidateUri --hash=sha256:$candidateSha256" in script
    assert "osv-runtime-snapshot.json" in script
    assert "gatehouse.cdx.json" in script
    assert "core.excludesFile=/dev/null" in script
    assert "core.excludesFile=NUL" not in script
    assert 'SetEnvironmentVariable("PIP_NO_INDEX", "1"' in script
    assert '"--no-index"' in script
    assert '"--only-binary=:all:"' in script
    assert ".local\\release-evidence" in script
    assert "publication_authorized = $false" in script
    for forbidden in (
        "twine upload",
        "gh release",
        "upload-artifact",
        "invoke-webrequest",
        "start-bitstransfer",
        "curl.exe",
    ):
        assert forbidden not in combined


def test_release_evidence_files_are_create_only_and_inputs_are_rechecked() -> None:
    script = (SCRIPTS / "verify-release-candidate.ps1").read_text(encoding="utf-8")

    assert "[System.IO.FileMode]::CreateNew" in script
    assert "[System.IO.FileShare]::None" in script
    assert "candidate-install.txt" in script
    assert script.count("Assert-WheelhouseState") >= 4
    assert script.count("Assert-FileSha256") >= 4
    assert "--python-full-version" in script


def test_installed_process_failure_still_runs_both_residue_checks_before_rethrow() -> None:
    script = (SCRIPTS / "verify-release-candidate.ps1").read_text(encoding="utf-8")

    failure_capture = script.index("$installedProcessFailure = $_")
    process_check = script.index("Get-CimInstance Win32_Process", failure_capture)
    task_check = script.index("$taskStateAfter = Get-GatehouseTaskState", process_check)
    original_rethrow = script.index(
        "$PSCmdlet.ThrowTerminatingError($installedProcessFailure)",
        task_check,
    )

    assert failure_capture < process_check < task_check < original_rethrow
    assert "Additional release-test residue failure" in script[task_check:original_rethrow]


def test_wheel_audit_accepts_exact_record_metadata_and_source(tmp_path: Path) -> None:
    wheel = _write_synthetic_candidate(tmp_path)

    result = audit_wheel(wheel, tmp_path)

    assert result["entry_points_verified"] == 1
    assert result["package_files_byte_matched"] == 1
    assert result["python_sources_byte_matched"] == 1
    assert result["version"] == "1.2.3"


def test_wheel_audit_rejects_source_byte_drift(tmp_path: Path) -> None:
    wheel = _write_synthetic_candidate(tmp_path, source_payload=b"drifted = True\n")

    with pytest.raises(WheelAuditError, match="byte-match"):
        audit_wheel(wheel, tmp_path)


def test_wheel_audit_rejects_unaccounted_nonpackage_payload(tmp_path: Path) -> None:
    wheel = _write_synthetic_candidate(
        tmp_path,
        additional_payloads={
            "unexpected/credential.pem": (
                b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----\nopaque-private-material\n"
            )
        },
    )

    with pytest.raises(WheelAuditError, match="archive surface"):
        audit_wheel(wheel, tmp_path)


def test_wheel_audit_byte_matches_declared_top_level_license(tmp_path: Path) -> None:
    license_payload = b"Synthetic license text\n"
    wheel = _write_synthetic_candidate(
        tmp_path,
        metadata_headers=("License-File: LICENSE",),
        source_files={"LICENSE": license_payload},
        additional_payloads={
            "gatehouse_local-1.2.3.dist-info/licenses/LICENSE": license_payload,
        },
    )

    audit_wheel(wheel, tmp_path)


def test_wheel_audit_rejects_omitted_source_license_headers_and_payloads(
    tmp_path: Path,
) -> None:
    wheel = _write_synthetic_candidate(
        tmp_path,
        source_files={"LICENSE": b"Synthetic license text\n"},
    )

    with pytest.raises(WheelAuditError, match="headers differ"):
        audit_wheel(wheel, tmp_path)


def test_wheel_audit_rejects_unsafe_license_declaration(tmp_path: Path) -> None:
    wheel = _write_synthetic_candidate(
        tmp_path,
        metadata_headers=("License-File: ../LICENSE",),
    )

    with pytest.raises(WheelAuditError, match="unsafe License-File"):
        audit_wheel(wheel, tmp_path)


@pytest.mark.parametrize(
    ("wheel_filename", "dist_info", "message"),
    [
        (
            "evil-1.2.3-py3-none-any.whl",
            "gatehouse_local-1.2.3.dist-info",
            "wheel filename",
        ),
        (
            "gatehouse_local-1.2.3-py3-none-any.whl",
            "evil-1.2.3.dist-info",
            "dist-info root",
        ),
    ],
    ids=("filename", "dist-info-root"),
)
def test_wheel_audit_rejects_mismatched_archive_identity(
    tmp_path: Path,
    wheel_filename: str,
    dist_info: str,
    message: str,
) -> None:
    wheel = _write_synthetic_candidate(
        tmp_path,
        wheel_filename=wheel_filename,
        dist_info=dist_info,
    )

    with pytest.raises(WheelAuditError, match=message):
        audit_wheel(wheel, tmp_path)


@pytest.mark.parametrize(
    "wheel_metadata",
    [
        (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\nTag: cp312-cp312-win_amd64\n"
        ),
        (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            b"Root-Is-Purelib: false\nTag: py3-none-any\n"
        ),
    ],
    ids=("additional-tag", "additional-purelib-value"),
)
def test_wheel_audit_requires_exact_wheel_compatibility_headers(
    tmp_path: Path,
    wheel_metadata: bytes,
) -> None:
    wheel = _write_synthetic_candidate(tmp_path, wheel_metadata=wheel_metadata)

    with pytest.raises(WheelAuditError, match="Tag headers|Root-Is-Purelib"):
        audit_wheel(wheel, tmp_path)


def test_wheel_audit_rejects_oversized_declared_uncompressed_total(tmp_path: Path) -> None:
    wheel = _write_synthetic_candidate(tmp_path)
    _declare_archive_entry_size(
        wheel,
        ".dist-info/METADATA",
        MAX_TOTAL_UNCOMPRESSED_BYTES + 1,
    )

    with pytest.raises(WheelAuditError, match="total uncompressed byte ceiling"):
        audit_wheel(wheel, tmp_path)


def test_wheel_audit_normalizes_complete_dependency_requirement(tmp_path: Path) -> None:
    wheel = _write_synthetic_candidate(
        tmp_path,
        source_requirements=("AnyIO[Trio]>=4.8,<5; python_version < '3.14'",),
        metadata_requirements=('anyio[trio]<5,>=4.8; python_version < "3.14"',),
    )

    audit_wheel(wheel, tmp_path)


@pytest.mark.parametrize(
    ("source_requirement", "metadata_requirement"),
    [
        ("anyio>=4.8,<5", "anyio>=4.7,<5"),
        (
            "anyio>=4.8,<5; python_version < '3.14'",
            'anyio>=4.8,<5; python_version < "3.13"',
        ),
        ("anyio[trio]>=4.8,<5", "anyio>=4.8,<5"),
        (
            "anyio @ https://packages.invalid/anyio-4.8.whl",
            "anyio @ https://packages.invalid/anyio-4.9.whl",
        ),
    ],
    ids=("specifier", "marker", "extras", "url"),
)
def test_wheel_audit_rejects_dependency_component_drift(
    tmp_path: Path,
    source_requirement: str,
    metadata_requirement: str,
) -> None:
    wheel = _write_synthetic_candidate(
        tmp_path,
        source_requirements=(source_requirement,),
        metadata_requirements=(metadata_requirement,),
    )

    with pytest.raises(WheelAuditError, match="dependency requirements"):
        audit_wheel(wheel, tmp_path)


def _candidate_git_results(path: str) -> tuple[bytes, bytes]:
    return (b"", f"{path}\0".encode())


@pytest.mark.parametrize("path", ["tls/client.pem", "tls/client.key"])
def test_publication_hygiene_scans_sensitive_key_suffixes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    candidate = tmp_path / path
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----\nnot-real-key-material\n")
    git_results = iter(_candidate_git_results(path))

    def fake_git(_repository_root: Path, *_arguments: str) -> bytes:
        return next(git_results)

    monkeypatch.setattr(publication_hygiene, "_git", fake_git)

    with pytest.raises(publication_hygiene.HygieneError, match="private-key block"):
        publication_hygiene._check_candidate_tree(tmp_path)


def test_publication_hygiene_scans_arbitrary_extensionless_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "deployment-manifest"
    (tmp_path / path).write_bytes(b"# example-tool implementation note\n")
    git_results = iter(_candidate_git_results(path))

    def fake_git(_repository_root: Path, *_arguments: str) -> bytes:
        return next(git_results)

    monkeypatch.setattr(publication_hygiene, "_git", fake_git)
    monkeypatch.setattr(
        publication_hygiene,
        "_active_denylist",
        publication_hygiene.PrivateDenyList(
            comments=(re.compile(rb"(?im)^\s*#[^\r\n]*\bexample-tool\b"),),
        ),
    )

    with pytest.raises(publication_hygiene.HygieneError, match="private comment pattern"):
        publication_hygiene._check_candidate_tree(tmp_path)


def test_publication_hygiene_scans_staged_blob_when_worktree_copy_is_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "payload.py"
    object_id = "b" * 40
    staged_payload = b'API_TOKEN = "sk-' + (b"Z" * 32) + b'"\n'
    (tmp_path / path).write_text("value = 2\n", encoding="utf-8")
    git_results = iter(
        (
            f"100644 {object_id} 0\t{path}\0".encode(),
            b"",
        )
    )

    def fake_git(_repository_root: Path, *_arguments: str) -> bytes:
        return next(git_results)

    def fake_git_with_input(
        _repository_root: Path,
        request: bytes,
        *arguments: str,
    ) -> bytes:
        assert request == f"{object_id}\n".encode()
        assert arguments == ("cat-file", "--batch")
        return f"{object_id} blob {len(staged_payload)}\n".encode() + staged_payload + b"\n"

    monkeypatch.setattr(publication_hygiene, "_git", fake_git)
    monkeypatch.setattr(publication_hygiene, "_git_with_input", fake_git_with_input)

    with pytest.raises(publication_hygiene.HygieneError, match="generic sk token"):
        publication_hygiene._check_candidate_tree(tmp_path)


def test_publication_hygiene_scans_arbitrary_extensionless_history_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "a" * 40
    path = "deployment-manifest"
    payload = b"Generated with example-tool\n"

    def fake_git(_repository_root: Path, *arguments: str) -> bytes:
        if arguments[-1] == "--format=%B":
            return b"ordinary commit\n"
        if arguments[-1] == "--format=%an <%ae>|%cn <%ce>":
            identity = publication_hygiene.REQUIRED_IDENTITY
            return f"{identity}|{identity}\n".encode()
        if "rev-list" in arguments:
            return f"{object_id} {path}\n".encode()
        raise AssertionError(f"unexpected git invocation: {arguments}")

    def fake_git_with_input(
        _repository_root: Path,
        request: bytes,
        *arguments: str,
    ) -> bytes:
        assert request == f"{object_id}\n".encode()
        assert arguments == ("cat-file", "--batch")
        return f"{object_id} blob {len(payload)}\n".encode() + payload + b"\n"

    monkeypatch.setattr(publication_hygiene, "_git", fake_git)
    monkeypatch.setattr(publication_hygiene, "_git_with_input", fake_git_with_input)
    monkeypatch.setattr(
        publication_hygiene,
        "_active_denylist",
        publication_hygiene.PrivateDenyList(
            content=(re.compile(rb"(?i)\bgenerated\s+with\s+example-tool\b"),),
        ),
    )

    with pytest.raises(publication_hygiene.HygieneError, match="private attribution pattern"):
        publication_hygiene._check_history(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="junction regression requires Windows")
def test_release_scripts_reject_reparse_ancestors_before_mutation(tmp_path: Path) -> None:
    command_shell = shutil.which("cmd.exe")
    powershell = shutil.which("pwsh.exe") or shutil.which("pwsh")
    assert command_shell is not None
    assert powershell is not None
    junction_target = tmp_path / "junction-target"
    junction_target.mkdir()
    junction = tmp_path / "junction"
    subprocess.run(  # noqa: S603 - fixed Windows shell creates one isolated test junction
        [command_shell, "/d", "/c", "mklink", "/J", str(junction), str(junction_target)],
        check=True,
        capture_output=True,
    )
    candidate = tmp_path / "candidate.whl"
    candidate.write_bytes(b"synthetic candidate")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()

    verify = subprocess.run(  # noqa: S603 - fixed PowerShell runs the audited local script
        [
            powershell,
            "-NoProfile",
            "-File",
            str(SCRIPTS / "verify-release-candidate.ps1"),
            "-CandidateWheel",
            str(candidate),
            "-RuntimeWheelhouse",
            str(wheelhouse),
            "-CleanEnvironment",
            str(junction / "clean-environment"),
            "-EvidenceDirectory",
            str(tmp_path / "evidence"),
            "-WhatIf",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    build = subprocess.run(  # noqa: S603 - fixed PowerShell runs the audited local script
        [
            powershell,
            "-NoProfile",
            "-File",
            str(SCRIPTS / "build-wheel-offline.ps1"),
            "-Wheelhouse",
            str(wheelhouse),
            "-OutputDirectory",
            str(junction / "output"),
            "-BuildEnvironment",
            str(tmp_path / "build-environment"),
            "-WhatIf",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    for completed in (verify, build):
        rendered = f"{completed.stdout}\n{completed.stderr}"
        assert completed.returncode != 0
        assert "reparse point" in rendered
        assert str(junction_target) not in rendered
    assert not (junction_target / "clean-environment").exists()
    assert not (junction_target / "output").exists()
