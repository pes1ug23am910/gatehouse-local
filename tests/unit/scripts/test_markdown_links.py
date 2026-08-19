from __future__ import annotations

import importlib.util
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
