from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch
from urllib.error import URLError

import pytest
from packaging.tags import parse_tag
from packaging.utils import canonicalize_name, parse_wheel_filename

import scripts.refresh_release_vulnerability_snapshot as snapshot_refresh
import scripts.verify_release_supply_chain as supply_chain
from scripts.verify_release_supply_chain import (
    MAX_METADATA_BYTES,
    SupplyChainError,
    _read_bounded,
    _tag_is_compatible,
    verify_gate_toolchain,
    verify_supply_chain,
)

ROOT = Path(__file__).parents[3]
FIXED_NOW = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _write_wheel(
    path: Path,
    *,
    name: str,
    version: str,
    requirements: tuple[str, ...] = (),
) -> None:
    metadata = (
        "Metadata-Version: 2.4\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        "Requires-Python: >=3.12,<4\n"
        + "".join(f"Requires-Dist: {requirement}\n" for requirement in requirements)
        + "\n"
    ).encode()
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{dist_info}/METADATA", metadata)


def _write_fixture(root: Path) -> dict[str, Path]:
    requirements = root / "requirements"
    wheelhouse = root / "wheelhouse"
    requirements.mkdir(parents=True)
    wheelhouse.mkdir()
    (root / "pyproject.toml").write_text(
        """
[project]
name = "gatehouse-local"
version = "1.2.3"
requires-python = ">=3.12,<4"
dependencies = ["alpha>=1"]
""".lstrip(),
        encoding="utf-8",
    )
    candidate = root / "gatehouse_local-1.2.3-py3-none-any.whl"
    _write_wheel(candidate, name="gatehouse-local", version="1.2.3")

    wheels: list[dict[str, object]] = []
    locked: list[tuple[str, str, str]] = []
    for filename, name, version, dependencies in (
        ("alpha-1.0-py3-none-any.whl", "alpha", "1.0", ("beta>=2",)),
        ("beta-2.0-py3-none-any.whl", "beta", "2.0", ()),
    ):
        path = wheelhouse / filename
        _write_wheel(path, name=name, version=version, requirements=dependencies)
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        locked.append((name, version, digest))
        wheels.append(
            {
                "filename": filename,
                "name": name,
                "python_minors": ["3.12", "3.13", "3.14"],
                "sha256": digest,
                "size_bytes": len(payload),
                "version": version,
            }
        )

    runtime_lock = requirements / "runtime-py312.txt"
    runtime_lock.write_text(
        "# Exact synthetic runtime artifacts.\n"
        + "".join(
            f"{name}=={version} --hash=sha256:{digest}\n" for name, version, digest in locked
        ),
        encoding="utf-8",
        newline="\n",
    )
    lock_digest = hashlib.sha256(runtime_lock.read_bytes()).hexdigest()
    targets = {
        minor: {
            "abi": f"cp{minor.replace('.', '')}",
            "implementation": "cp",
            "lock_path": f"requirements/runtime-py{minor.replace('.', '')}.txt",
            "lock_sha256": lock_digest,
            "platform": "win_amd64",
        }
        for minor in ("3.12", "3.13", "3.14")
    }
    manifest = requirements / "runtime-wheelhouse.json"
    manifest.write_bytes(
        _canonical_json(
            {
                "review": {
                    "artifact_index": "https://pypi.org/simple",
                    "reviewed_at_utc": "2026-08-28T19:54:47Z",
                },
                "schema_version": 1,
                "targets": targets,
                "wheels": wheels,
            }
        )
    )
    snapshot = requirements / "osv-runtime-snapshot.json"
    snapshot.write_bytes(
        _canonical_json(
            {
                "packages": [
                    {"name": name, "version": version, "vulnerability_ids": []}
                    for name, version, _digest in locked
                ],
                "queried_at_utc": "2026-08-28T19:54:47Z",
                "schema_version": 1,
                "source": {
                    "ecosystem": "PyPI",
                    "endpoint": "https://api.osv.dev/v1/querybatch",
                    "name": "OSV",
                },
                "valid_until_utc": "2026-09-04T19:54:47Z",
            }
        )
    )
    return {
        "candidate": candidate,
        "lock": runtime_lock,
        "manifest": manifest,
        "snapshot": snapshot,
        "wheelhouse": wheelhouse,
    }


def _write_gate_fixture(root: Path) -> dict[str, Path]:
    requirements = root / "requirements"
    wheelhouse = root / "gate-wheelhouse"
    wheelhouse.mkdir()
    wheels: list[dict[str, object]] = []
    locked: list[tuple[str, str, str]] = []
    for filename, name, version, dependencies in (
        ("builder-1.0-py3-none-any.whl", "builder", "1.0", ("alpha>=1",)),
        ("tool-3.0-py3-none-any.whl", "tool", "3.0", ("builder>=1",)),
    ):
        path = wheelhouse / filename
        _write_wheel(path, name=name, version=version, requirements=dependencies)
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        locked.append((name, version, digest))
        wheels.append(
            {
                "filename": filename,
                "name": name,
                "python_minors": ["3.12", "3.13", "3.14"],
                "sha256": digest,
                "size_bytes": len(payload),
                "version": version,
            }
        )

    gate_lock = requirements / "gate-py312.txt"
    gate_lock.write_text(
        "# Exact synthetic gate artifacts.\n"
        + "".join(
            f"{name}=={version} --hash=sha256:{digest}\n" for name, version, digest in locked
        ),
        encoding="utf-8",
        newline="\n",
    )
    lock_digest = hashlib.sha256(gate_lock.read_bytes()).hexdigest()
    targets = {
        minor: {
            "abi": f"cp{minor.replace('.', '')}",
            "implementation": "cp",
            "lock_path": f"requirements/gate-py{minor.replace('.', '')}.txt",
            "lock_sha256": lock_digest,
            "platform": "win_amd64",
        }
        for minor in ("3.12", "3.13", "3.14")
    }
    manifest = requirements / "gate-wheelhouse.json"
    manifest.write_bytes(
        _canonical_json(
            {
                "review": {
                    "artifact_index": "https://pypi.org/simple",
                    "reviewed_at_utc": "2026-08-28T19:54:47Z",
                },
                "schema_version": 1,
                "targets": targets,
                "wheels": wheels,
            }
        )
    )
    snapshot = requirements / "osv-gate-tools-snapshot.json"
    snapshot.write_bytes(
        _canonical_json(
            {
                "packages": [
                    {"name": name, "version": version, "vulnerability_ids": []}
                    for name, version, _digest in locked
                ],
                "queried_at_utc": "2026-08-28T19:54:47Z",
                "schema_version": 1,
                "source": {
                    "ecosystem": "PyPI",
                    "endpoint": "https://api.osv.dev/v1/querybatch",
                    "name": "OSV",
                },
                "valid_until_utc": "2026-09-04T19:54:47Z",
            }
        )
    )
    roots = requirements / "quality-roots.in"
    roots.write_text("tool==3.0\n", encoding="utf-8", newline="\n")
    return {
        "lock": gate_lock,
        "manifest": manifest,
        "roots": roots,
        "snapshot": snapshot,
        "wheelhouse": wheelhouse,
    }


def _verify(
    paths: dict[str, Path],
    root: Path,
    sbom: Path,
    *,
    python_full_version: str = "3.12.9",
) -> dict[str, object]:
    return verify_supply_chain(
        repository_root=root,
        candidate_wheel=paths["candidate"],
        wheelhouse=paths["wheelhouse"],
        runtime_lock=paths["lock"],
        wheelhouse_manifest=paths["manifest"],
        vulnerability_snapshot=paths["snapshot"],
        python_minor="3.12",
        python_full_version=python_full_version,
        sbom_output=sbom,
        now=FIXED_NOW,
    )


def _verify_gate(
    runtime: dict[str, Path],
    gate: dict[str, Path],
    root: Path,
    output: Path,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        verify_gate_toolchain(
            repository_root=root,
            runtime_wheelhouse=runtime["wheelhouse"],
            runtime_lock=runtime["lock"],
            runtime_manifest=runtime["manifest"],
            runtime_vulnerability_snapshot=runtime["snapshot"],
            gate_wheelhouse=gate["wheelhouse"],
            gate_lock=gate["lock"],
            gate_manifest=gate["manifest"],
            gate_vulnerability_snapshot=gate["snapshot"],
            gate_roots=gate["roots"],
            python_minor="3.12",
            python_full_version="3.12.9",
            output=output,
            now=FIXED_NOW,
        ),
    )


def _mutate_json(path: Path, change: Callable[[dict[str, Any]], None]) -> None:
    value: dict[str, Any] = json.loads(path.read_bytes())
    change(value)
    path.write_bytes(_canonical_json(value))


def test_supply_chain_gate_is_offline_exact_and_deterministic(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)

    first = _verify(paths, tmp_path, tmp_path / "first.cdx.json")
    second = _verify(paths, tmp_path, tmp_path / "second.cdx.json")

    assert first == second
    assert first["runtime_packages"] == 2
    assert first["status"] == "passed_offline_supply_chain_gate"
    assert first["vulnerability_scan"] == {
        "packages_scanned": 2,
        "queried_at_utc": "2026-08-28T19:54:47Z",
        "source": "OSV",
        "status": "passed_no_known_vulnerabilities",
        "valid_until_utc": "2026-09-04T19:54:47Z",
    }
    assert (tmp_path / "first.cdx.json").read_bytes() == (tmp_path / "second.cdx.json").read_bytes()


def test_gate_toolchain_verifies_runtime_and_tools_as_separate_scopes(tmp_path: Path) -> None:
    runtime = _write_fixture(tmp_path)
    gate = _write_gate_fixture(tmp_path)

    result = _verify_gate(runtime, gate, tmp_path, tmp_path / "gate-evidence.json")

    assert result["status"] == "passed_offline_runtime_and_gate_toolchain"
    assert result["runtime"]["packages"] == 2
    assert result["gate_tools"]["packages"] == 2
    assert result["runtime"]["vulnerability_scan"]["packages_scanned"] == 2
    assert result["gate_tools"]["vulnerability_scan"]["packages_scanned"] == 2


def test_gate_toolchain_rejects_incomplete_gate_advisory_scope(tmp_path: Path) -> None:
    runtime = _write_fixture(tmp_path)
    gate = _write_gate_fixture(tmp_path)
    _mutate_json(gate["snapshot"], lambda value: value["packages"].pop())

    with pytest.raises(SupplyChainError, match="exact gate-tool lock"):
        _verify_gate(runtime, gate, tmp_path, tmp_path / "gate-evidence.json")


def test_gate_toolchain_rejects_missing_active_windows_dependency(tmp_path: Path) -> None:
    runtime = _write_fixture(tmp_path)
    gate = _write_gate_fixture(tmp_path)
    builder = gate["wheelhouse"] / "builder-1.0-py3-none-any.whl"
    _write_wheel(builder, name="builder", version="1.0", requirements=("missing>=1",))
    digest = hashlib.sha256(builder.read_bytes()).hexdigest()
    lock_lines = gate["lock"].read_text(encoding="utf-8").splitlines()
    lock_lines = [
        f"builder==1.0 --hash=sha256:{digest}" if line.startswith("builder==") else line
        for line in lock_lines
    ]
    gate["lock"].write_text("\n".join(lock_lines) + "\n", encoding="utf-8", newline="\n")
    lock_digest = hashlib.sha256(gate["lock"].read_bytes()).hexdigest()

    def update_manifest(value: dict[str, Any]) -> None:
        for wheel in value["wheels"]:
            if wheel["name"] == "builder":
                wheel["sha256"] = digest
                wheel["size_bytes"] = builder.stat().st_size
        for target in value["targets"].values():
            target["lock_sha256"] = lock_digest

    _mutate_json(gate["manifest"], update_manifest)

    with pytest.raises(SupplyChainError, match="active gate dependency is absent"):
        _verify_gate(runtime, gate, tmp_path, tmp_path / "gate-evidence.json")


def test_windows_platform_independent_wheel_tag_is_compatible() -> None:
    tags = parse_tag("py3-none-win_amd64")

    assert tags and all(_tag_is_compatible(tag, "3.14") for tag in tags)


def test_supply_chain_gate_rejects_unreviewed_wheelhouse_surface(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    (paths["wheelhouse"] / "unreviewed.whl").write_bytes(b"not reviewed")

    with pytest.raises(SupplyChainError, match="differs from the exact manifest"):
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")


def test_supply_chain_gate_fails_when_advisory_data_is_unavailable(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    paths["snapshot"].unlink()

    with pytest.raises(SupplyChainError, match="vulnerability snapshot is unavailable"):
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")


def test_supply_chain_gate_rejects_unhashed_runtime_requirement(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    paths["lock"].write_bytes(b"alpha==1.0\n")

    with pytest.raises(SupplyChainError, match="unhashed or malformed"):
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")


def test_bounded_reader_rechecks_the_open_file_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "growing-input"
    candidate.write_bytes(b"12345")
    real_lstat = Path.lstat

    def stale_lstat(path: Path) -> os.stat_result:
        details = real_lstat(path)
        if path == candidate:
            fields = list(details)
            fields[6] = 4
            return os.stat_result(fields)
        return details

    monkeypatch.setattr(Path, "lstat", stale_lstat)

    with pytest.raises(SupplyChainError, match="exceeds its byte ceiling"):
        _read_bounded(candidate, ceiling=4, label="synthetic input")


def test_supply_chain_gate_rejects_oversized_candidate_metadata(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    candidate = paths["candidate"]
    metadata = (
        b"Metadata-Version: 2.4\nName: gatehouse-local\nVersion: 1.2.3\n"
        + b"X-Padding: "
        + b"x" * MAX_METADATA_BYTES
        + b"\n"
    )
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("gatehouse_local-1.2.3.dist-info/METADATA", metadata)

    with pytest.raises(SupplyChainError, match="METADATA exceeds the byte ceiling"):
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")


def test_supply_chain_gate_inspects_the_exact_hashed_wheel_bytes(
    tmp_path: Path,
) -> None:
    paths = _write_fixture(tmp_path)
    with patch(
        "scripts.verify_release_supply_chain.zipfile.ZipFile",
        wraps=zipfile.ZipFile,
    ) as zip_file:
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")

    assert [isinstance(call.args[0], io.BytesIO) for call in zip_file.call_args_list] == [
        True,
        True,
        True,
    ]


def test_supply_chain_gate_bounds_archive_members_and_expansion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    member_paths = _write_fixture(tmp_path / "members")
    with zipfile.ZipFile(member_paths["candidate"], "a") as archive:
        archive.writestr("extra.txt", b"")
    monkeypatch.setattr(supply_chain, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(SupplyChainError, match="member-count ceiling"):
        _verify(member_paths, tmp_path / "members", tmp_path / "members.cdx.json")

    expansion_paths = _write_fixture(tmp_path / "expansion")
    monkeypatch.setattr(supply_chain, "MAX_ARCHIVE_MEMBERS", 4096)
    monkeypatch.setattr(supply_chain, "MAX_ARCHIVE_UNCOMPRESSED_BYTES", 32)
    with pytest.raises(SupplyChainError, match="uncompressed byte ceiling"):
        _verify(expansion_paths, tmp_path / "expansion", tmp_path / "expansion.cdx.json")


def test_supply_chain_gate_uses_the_actual_python_patch_for_markers(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    alpha = paths["wheelhouse"] / "alpha-1.0-py3-none-any.whl"
    _write_wheel(
        alpha,
        name="alpha",
        version="1.0",
        requirements=("beta>=2; python_full_version >= '3.12.1'",),
    )
    digest = hashlib.sha256(alpha.read_bytes()).hexdigest()
    lock_lines = paths["lock"].read_text(encoding="utf-8").splitlines()
    lock_lines = [
        f"alpha==1.0 --hash=sha256:{digest}" if line.startswith("alpha==") else line
        for line in lock_lines
    ]
    paths["lock"].write_text("\n".join(lock_lines) + "\n", encoding="utf-8", newline="\n")
    lock_digest = hashlib.sha256(paths["lock"].read_bytes()).hexdigest()

    def update_manifest(value: dict[str, Any]) -> None:
        for wheel in value["wheels"]:
            if wheel["name"] == "alpha":
                wheel["sha256"] = digest
                wheel["size_bytes"] = alpha.stat().st_size
        for target in value["targets"].values():
            target["lock_sha256"] = lock_digest

    _mutate_json(paths["manifest"], update_manifest)

    _verify(
        paths,
        tmp_path,
        tmp_path / "active.cdx.json",
        python_full_version="3.12.9",
    )
    with pytest.raises(SupplyChainError, match="unreachable extra packages"):
        _verify(
            paths,
            tmp_path,
            tmp_path / "inactive.cdx.json",
            python_full_version="3.12.0",
        )


def test_supply_chain_gate_rejects_reparse_input_before_resolution(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    linked_candidate = tmp_path / "linked-candidate.whl"
    try:
        linked_candidate.symlink_to(paths["candidate"])
    except OSError:
        pytest.skip("symbolic links are not available to this test account")
    paths["candidate"] = linked_candidate

    with pytest.raises(SupplyChainError, match="crosses a reparse point"):
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")


def test_supply_chain_gate_never_follows_a_dangling_output_link(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    target = tmp_path / "uncreated-target.cdx.json"
    output = tmp_path / "linked-output.cdx.json"
    try:
        output.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not available to this test account")

    with pytest.raises(SupplyChainError, match="crosses a reparse point"):
        _verify(paths, tmp_path, output)
    assert not target.exists()


def test_supply_chain_sbom_uses_create_only_file_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _write_fixture(tmp_path)
    output = tmp_path / "result.cdx.json"
    modes: list[str] = []
    real_open = Path.open

    def tracked_open(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if path == output:
            modes.append(mode)
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked_open)

    _verify(paths, tmp_path, output)

    assert modes[0] == "xb"
    assert "wb" not in modes


@pytest.mark.skipif(os.name != "nt", reason="junction regression requires Windows")
def test_direct_supply_chain_gate_rejects_a_junction_ancestor(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path / "source")
    command_shell = shutil.which("cmd.exe")
    assert command_shell is not None
    junction = tmp_path / "candidate-junction"
    subprocess.run(  # noqa: S603 - fixed Windows shell creates one isolated test junction
        [
            command_shell,
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(paths["candidate"].parent),
        ],
        check=True,
        capture_output=True,
    )
    paths["candidate"] = junction / paths["candidate"].name

    with pytest.raises(SupplyChainError, match="crosses a reparse point"):
        _verify(paths, tmp_path / "source", tmp_path / "result.cdx.json")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value["packages"].pop(), "does not cover the exact runtime lock"),
        (
            lambda value: value.update(
                {
                    "queried_at_utc": "2026-08-20T00:00:00Z",
                    "valid_until_utc": "2026-08-27T00:00:00Z",
                }
            ),
            "snapshot is stale",
        ),
        (
            lambda value: value["packages"][0].update(
                {"vulnerability_ids": ["GHSA-AAAA-BBBB-CCCC"]}
            ),
            "found an advisory",
        ),
    ],
    ids=("incomplete", "stale", "known-vulnerability"),
)
def test_supply_chain_vulnerability_gate_fails_closed(
    tmp_path: Path,
    change: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    paths = _write_fixture(tmp_path)
    _mutate_json(paths["snapshot"], change)

    with pytest.raises(SupplyChainError, match=message):
        _verify(paths, tmp_path, tmp_path / "result.cdx.json")


def test_tracked_locks_and_manifest_cover_each_python_minor_exactly() -> None:
    manifest = json.loads((ROOT / "requirements" / "runtime-wheelhouse.json").read_bytes())
    package_versions: dict[str, dict[str, str]] = {}
    target_filenames: dict[str, dict[str, str]] = {}
    for minor in ("3.12", "3.13", "3.14"):
        lock_path = ROOT / manifest["targets"][minor]["lock_path"]
        assert (
            hashlib.sha256(lock_path.read_bytes()).hexdigest()
            == manifest["targets"][minor]["lock_sha256"]
        )
        locked: dict[str, str] = {}
        hashes: dict[str, str] = {}
        for line in lock_path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            requirement, digest = line.split(" --hash=sha256:", maxsplit=1)
            name, version = requirement.split("==", maxsplit=1)
            assert canonicalize_name(name) == name
            assert len(digest) == 64 and digest == digest.casefold()
            locked[name] = version
            hashes[name] = digest
        selected = [wheel for wheel in manifest["wheels"] if minor in wheel["python_minors"]]
        wheels_by_name: dict[str, str] = {}
        for wheel in selected:
            parsed_name, parsed_version, _build, _tags = parse_wheel_filename(wheel["filename"])
            name = str(parsed_name)
            assert wheel["name"] == name
            assert wheel["version"] == str(parsed_version)
            assert wheel["sha256"] == hashes[name]
            wheels_by_name[name] = wheel["filename"]
        assert set(wheels_by_name) == set(locked)
        assert len(locked) == 42
        package_versions[minor] = locked
        target_filenames[minor] = wheels_by_name

    assert package_versions["3.12"] == package_versions["3.13"] == package_versions["3.14"]
    for package in ("cffi", "pydantic-core", "pywin32", "pyyaml", "rpds-py"):
        assert len({target_filenames[minor][package] for minor in target_filenames}) == 3


def test_tracked_gate_locks_manifest_and_advisories_cover_exact_tool_closure() -> None:
    runtime_names = {
        line.split("==", maxsplit=1)[0]
        for line in (ROOT / "requirements" / "runtime-py312.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    }
    manifest = json.loads((ROOT / "requirements" / "gate-wheelhouse.json").read_bytes())
    package_versions: dict[str, dict[str, str]] = {}
    target_filenames: dict[str, dict[str, str]] = {}
    for minor in ("3.12", "3.13", "3.14"):
        lock_path = ROOT / manifest["targets"][minor]["lock_path"]
        assert (
            hashlib.sha256(lock_path.read_bytes()).hexdigest()
            == manifest["targets"][minor]["lock_sha256"]
        )
        locked: dict[str, str] = {}
        hashes: dict[str, str] = {}
        for line in lock_path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            requirement, digest = line.split(" --hash=sha256:", maxsplit=1)
            name, version = requirement.split("==", maxsplit=1)
            assert canonicalize_name(name) == name
            assert len(digest) == 64 and digest == digest.casefold()
            locked[name] = version
            hashes[name] = digest
        selected = [wheel for wheel in manifest["wheels"] if minor in wheel["python_minors"]]
        wheels_by_name: dict[str, str] = {}
        for wheel in selected:
            parsed_name, parsed_version, _build, _tags = parse_wheel_filename(wheel["filename"])
            name = str(parsed_name)
            assert wheel["name"] == name
            assert wheel["version"] == str(parsed_version)
            assert wheel["sha256"] == hashes[name]
            wheels_by_name[name] = wheel["filename"]
        assert set(wheels_by_name) == set(locked)
        assert len(locked) == 21
        assert not set(locked) & runtime_names
        package_versions[minor] = locked
        target_filenames[minor] = wheels_by_name

    assert package_versions["3.12"] == package_versions["3.13"] == package_versions["3.14"]
    assert "colorama" in runtime_names
    assert "colorama" not in package_versions["3.14"]
    for package in ("coverage", "hypothesis", "librt", "mypy"):
        assert len({target_filenames[minor][package] for minor in target_filenames}) == 3

    gate_roots = {
        line.split("==", maxsplit=1)[0]
        for line in (ROOT / "requirements" / "quality-roots.in")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    }
    assert len(gate_roots) == 10
    assert gate_roots <= set(package_versions["3.14"])
    snapshot = json.loads((ROOT / "requirements" / "osv-gate-tools-snapshot.json").read_bytes())
    scanned = {package["name"]: package["version"] for package in snapshot["packages"]}
    assert scanned == package_versions["3.14"]
    assert all(not package["vulnerability_ids"] for package in snapshot["packages"])


class _FakeResponse:
    status = 200

    def __init__(self, payload: bytes, *, url: str = snapshot_refresh.OSV_ENDPOINT) -> None:
        self._payload = payload
        self._url = url

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def read(self, _ceiling: int) -> bytes:
        return self._payload

    def geturl(self) -> str:
        return self._url


def test_snapshot_refresh_uses_exact_osv_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "runtime.txt"
    lock.write_text("alpha==1.0 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    payload = json.dumps({"results": [{"vulns": [{"id": "GHSA-AAAA-BBBB-CCCC"}]}]}).encode()
    monkeypatch.setattr(
        snapshot_refresh,
        "urlopen",
        lambda request, timeout: _FakeResponse(payload),
    )

    result = snapshot_refresh.refresh_snapshot([lock], now=FIXED_NOW)

    assert result["packages"] == [
        {
            "name": "alpha",
            "version": "1.0",
            "vulnerability_ids": ["GHSA-AAAA-BBBB-CCCC"],
        }
    ]
    assert result["valid_until_utc"] == "2026-09-05T00:00:00Z"


def test_snapshot_refresh_fails_closed_when_osv_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "runtime.txt"
    lock.write_text("alpha==1.0 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")

    def unavailable(_request: object, *, timeout: int) -> _FakeResponse:
        assert timeout == 30
        raise URLError("offline")

    monkeypatch.setattr(snapshot_refresh, "urlopen", unavailable)

    with pytest.raises(snapshot_refresh.SnapshotRefreshError, match="advisory data is unavailable"):
        snapshot_refresh.refresh_snapshot([lock], now=FIXED_NOW)


def test_snapshot_refresh_rejects_a_redirected_advisory_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "runtime.txt"
    lock.write_text("alpha==1.0 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    payload = json.dumps({"results": [{}]}).encode()
    monkeypatch.setattr(
        snapshot_refresh,
        "urlopen",
        lambda request, timeout: _FakeResponse(payload, url="https://example.invalid/query"),
    )

    with pytest.raises(snapshot_refresh.SnapshotRefreshError, match="redirected away"):
        snapshot_refresh.refresh_snapshot([lock], now=FIXED_NOW)
