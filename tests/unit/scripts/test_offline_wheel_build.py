from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "scripts" / "build-wheel-offline.ps1"
LOCK = ROOT / "requirements" / "build-wheel.txt"

EXPECTED_REQUIREMENTS = {
    "build": (
        "1.5.0",
        "13f3eecb844759ab66efec90ca17639bbf14dc06cb2fdf37a9010322d9c50a6f",
    ),
    "colorama": (
        "0.4.6",
        "4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6",
    ),
    "hatchling": (
        "1.32.0",
        "0e17c9c3b9aa7c625acc8d0f5b622f107d5049af9ecf5ada4de1aada5be7cdbc",
    ),
    "packaging": (
        "26.3",
        "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c",
    ),
    "pathspec": (
        "1.1.1",
        "a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189",
    ),
    "pluggy": (
        "1.6.0",
        "e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746",
    ),
    "pyproject-hooks": (
        "1.2.0",
        "9e5c6bfa8dcc30091c74b0cf803c81fdd29d94f01992a7707bc97babb1141913",
    ),
    "tomlkit": (
        "0.15.1",
        "177a05aece5a8ca5266fd3c448abb47b8d352f09d477d3ca8332db4d89b24304",
    ),
    "trove-classifiers": (
        "2026.6.1.19",
        "ab4c4ec93cc4a4e7815fa759906e05e6bb3f2fbd92ea0f897288c6a43efd15b3",
    ),
}


def _locked_requirements() -> dict[str, tuple[str, str]]:
    content = LOCK.read_text(encoding="utf-8").replace("\\\n", " ")
    entries: dict[str, tuple[str, str]] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(
            r"([a-z0-9-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})",
            stripped,
        )
        assert match is not None, f"unlocked or malformed build requirement: {stripped}"
        name, version, digest = match.groups()
        assert name not in entries
        entries[name] = (version, digest)
    return entries


def test_declared_backend_is_exactly_pinned() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert configuration["build-system"] == {
        "requires": ["hatchling==1.32.0"],
        "build-backend": "hatchling.build",
    }


def test_offline_build_requirements_are_complete_pins_with_exact_hashes() -> None:
    assert _locked_requirements() == EXPECTED_REQUIREMENTS


def test_offline_builder_disables_indexes_and_requires_locked_wheels() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    for required in (
        'SetEnvironmentVariable("PIP_CONFIG_FILE", "NUL"',
        'SetEnvironmentVariable("PIP_NO_INDEX", "1"',
        'SetEnvironmentVariable("PIP_ONLY_BINARY", ":all:"',
        'SetEnvironmentVariable("PIP_REQUIRE_HASHES", "1"',
        "--isolated",
        "--no-cache-dir",
        "--no-index",
        '"--only-binary=:all:"',
        "--require-hashes",
        "--no-isolation",
        "requirements\\build-wheel.txt",
    ):
        assert required in script

    for forbidden in ("Invoke-WebRequest", "Start-BitsTransfer", "curl.exe", "Remove-Item"):
        assert forbidden not in script


def test_offline_builder_refuses_environment_and_artifact_overwrite() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "Build environment already exists; refusing to reuse or overwrite it" in script
    assert "Output artifact already exists; refusing to overwrite it" in script
    assert "[CmdletBinding(SupportsShouldProcess)]" in script
    assert "-I -m venv" in script
    assert "finally" in script
    assert "savedPipEnvironment" in script
