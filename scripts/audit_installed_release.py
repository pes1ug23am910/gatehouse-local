"""Verify a clean Gatehouse installation against its exact source checkout."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, NoReturn, cast

MAX_SOURCE_FILES = 4096


class InstalledAuditError(RuntimeError):
    """The installed candidate differs from its audited source or metadata."""


def _specifier_set(value: str) -> frozenset[str]:
    return frozenset(part.strip() for part in value.split(",") if part.strip())


def _fail(message: str) -> NoReturn:
    raise InstalledAuditError(message)


def _load_project(repository_root: Path) -> dict[str, Any]:
    try:
        configuration = tomllib.loads(
            (repository_root / "pyproject.toml").read_text(encoding="utf-8")
        )
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InstalledAuditError("could not read source project metadata") from exc
    project = configuration.get("project")
    if not isinstance(project, dict):
        _fail("pyproject.toml has no project table")
    return cast(dict[str, Any], project)


def audit_install(repository_root: Path) -> dict[str, object]:
    """Return a JSON-compatible installed-distribution evidence object."""

    repository_root = repository_root.resolve(strict=True)
    environment_root = Path(sys.prefix).resolve(strict=True)
    source_root = repository_root / "src" / "gatehouse"
    project = _load_project(repository_root)

    gatehouse = importlib.import_module("gatehouse")
    module_file = gatehouse.__file__
    if module_file is None:
        _fail("installed Gatehouse package has no filesystem origin")
    imported_path = Path(module_file).resolve(strict=True)
    if not imported_path.is_relative_to(environment_root):
        _fail("Gatehouse imported from outside the clean environment")
    if imported_path.is_relative_to(repository_root):
        _fail("Gatehouse imported from the source checkout")

    distribution = importlib.metadata.distribution(str(project["name"]))
    expected_version = str(project["version"])
    if distribution.version != expected_version:
        _fail("installed version differs from pyproject.toml")
    if _specifier_set(str(distribution.metadata["Requires-Python"])) != _specifier_set(
        str(project["requires-python"])
    ):
        _fail("installed Python range differs from pyproject.toml")

    declared_scripts = project.get("scripts")
    if not isinstance(declared_scripts, dict):
        _fail("source console-script metadata is malformed")
    expected_scripts = {str(key): str(value) for key, value in declared_scripts.items()}
    actual_scripts = {
        point.name: point.value
        for point in distribution.entry_points
        if point.group == "console_scripts"
    }
    if actual_scripts != expected_scripts:
        _fail("installed console scripts differ from pyproject.toml")

    scripts_directory = Path(sys.executable).resolve(strict=True).parent
    missing_scripts = [
        name for name in expected_scripts if not (scripts_directory / f"{name}.exe").is_file()
    ]
    if missing_scripts:
        _fail(f"installed console entry point is missing: {missing_scripts[0]}")

    source_files = [
        source
        for source in sorted(source_root.rglob("*"))
        if source.is_file()
        and "__pycache__" not in source.parts
        and source.suffix.casefold() != ".pyc"
    ]
    if len(source_files) > MAX_SOURCE_FILES:
        _fail("source package exceeds the installed-audit file-count ceiling")
    installed_root = imported_path.parent
    expected_relative_paths = {source.relative_to(source_root) for source in source_files}
    installed_relative_paths = {
        installed.relative_to(installed_root)
        for installed in installed_root.rglob("*")
        if installed.is_file()
        and "__pycache__" not in installed.parts
        and installed.suffix.casefold() != ".pyc"
    }
    if installed_relative_paths != expected_relative_paths:
        _fail("installed package file set differs from the checkout")
    for source in source_files:
        installed = installed_root / source.relative_to(source_root)
        try:
            matches = installed.read_bytes() == source.read_bytes()
        except OSError as exc:
            raise InstalledAuditError("installed package is missing a source file") from exc
        if not matches:
            _fail(f"installed source does not byte-match the checkout: {source.name}")

    return {
        "entry_points_verified": len(actual_scripts),
        "environment_root": str(environment_root),
        "imported_from": str(imported_path),
        "package_files_byte_matched": len(source_files),
        "python_sources_byte_matched": sum(
            source.suffix.casefold() == ".py" for source in source_files
        ),
        "version": distribution.version,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository_root", help="exact checkout used to build the installation")
    parser.add_argument("--output", help="optional JSON evidence path")
    arguments = parser.parse_args()
    try:
        result = audit_install(Path(cast(str, arguments.repository_root)))
    except (InstalledAuditError, OSError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"Installed release audit failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = cast(str | None, arguments.output)
    if output is not None:
        Path(output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
