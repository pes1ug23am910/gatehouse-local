"""Validate repository-relative Markdown links without network access."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

LINK = re.compile(r"(?<!!)\[[^\]]*\]\((?P<target><[^>]+>|[^)\s]+)(?:\s+[^)]*)?\)")
IGNORED_DIRECTORIES = {".git", ".local", ".venv", "__pycache__"}


def markdown_files(root: Path) -> list[Path]:
    git = shutil.which("git")
    listed = (
        None
        if git is None
        else subprocess.run(  # noqa: S603 - fixed Git executable
            (
                git,
                "-c",
                f"safe.directory={root.resolve()}",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                "*.md",
            ),
            check=False,
            capture_output=True,
        )
    )
    if listed is not None and listed.returncode == 0:
        return sorted(
            root / Path(os.fsdecode(relative))
            for relative in listed.stdout.split(b"\0")
            if relative and (root / Path(os.fsdecode(relative))).is_file()
        )
    return sorted(
        path
        for path in root.rglob("*.md")
        if not any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts)
    )


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    resolved_root = root.resolve()
    for document in markdown_files(resolved_root):
        content = document.read_text(encoding="utf-8")
        for match in LINK.finditer(content):
            raw_target = match.group("target").strip("<>")
            parsed = urlsplit(raw_target)
            if parsed.scheme or raw_target.startswith("#"):
                continue
            relative = PurePosixPath(unquote(parsed.path))
            candidate = (document.parent / Path(*relative.parts)).resolve()
            try:
                candidate.relative_to(resolved_root)
            except ValueError:
                location = document.relative_to(root)
                failures.append(f"{location}: link escapes repository: {raw_target}")
                continue
            if not candidate.exists():
                failures.append(f"{document.relative_to(root)}: missing target: {raw_target}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    failures = validate(arguments.root)
    for failure in failures:
        print(failure)
    if failures:
        print(f"Markdown link check failed with {len(failures)} finding(s).")
        return 1
    print("Markdown link check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
