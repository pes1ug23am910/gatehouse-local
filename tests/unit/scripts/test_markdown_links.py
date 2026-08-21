from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path
from types import ModuleType


def load_checker() -> ModuleType:
    script = Path(__file__).parents[3] / "scripts" / "check_markdown_links.py"
    spec = importlib.util.spec_from_file_location("check_markdown_links", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_relative_link_validation(tmp_path: Path) -> None:
    checker = load_checker()
    (tmp_path / "target.md").write_text("# Target", encoding="utf-8")
    source = tmp_path / "source.md"
    source.write_text("[ok](target.md)\n[missing](absent.md)", encoding="utf-8")

    assert checker.validate(tmp_path) == ["source.md: missing target: absent.md"]


def test_repository_validation_excludes_git_ignored_private_markdown(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run(  # noqa: S603 - fixed Git executable in an isolated temporary directory
        (git, "init", "--quiet", str(tmp_path)),
        check=True,
        capture_output=True,
    )
    (tmp_path / ".gitignore").write_text("private/\n", encoding="utf-8")
    (tmp_path / "public.md").write_text("[ok](target.md)", encoding="utf-8")
    (tmp_path / "target.md").write_text("# Target", encoding="utf-8")
    private = tmp_path / "private"
    private.mkdir()
    (private / "transcript.md").write_text("[missing](absent.md)", encoding="utf-8")

    checker = load_checker()
    assert checker.validate(tmp_path) == []
