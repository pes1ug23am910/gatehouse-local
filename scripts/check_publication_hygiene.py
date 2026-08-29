"""Fail closed on private process material, authorship drift, or credential-shaped values."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

REQUIRED_IDENTITY = "Yash Verma <pes1ug23am910@pesu.pes.edu>"
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_CANDIDATE_PATHS = 200_000
MAX_HISTORY_BLOBS = 200_000

TEXT_SUFFIXES = {
    ".cfg",
    ".cmd",
    ".css",
    ".editorconfig",
    ".env",
    ".example",
    ".gitattributes",
    ".gitignore",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".psm1",
    ".py",
    ".pyi",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
CODE_COMMENT_SUFFIXES = {
    ".cmd",
    ".js",
    ".ps1",
    ".psm1",
    ".py",
    ".pyi",
    ".sh",
    ".sql",
    ".ts",
    ".yaml",
    ".yml",
}
SENSITIVE_SCAN_SUFFIXES = {
    ".asc",
    ".cer",
    ".crt",
    ".csr",
    ".der",
    ".gpg",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".p7b",
    ".p7c",
    ".pem",
    ".pfx",
}
SPECIAL_TEXT_NAMES = {"dockerfile", "license", "makefile"}
ARCHIVE_SUFFIXES = (".7z", ".gz", ".rar", ".tar", ".tgz", ".zip")
FORBIDDEN_PATH_PATTERNS = (
    re.compile(r"(^|/)(audits?|prompts?)(/|$)", re.IGNORECASE),
    re.compile(r"(^|/)progress\.md$", re.IGNORECASE),
    re.compile(
        r"(transcripts?|standing[-_ ]?orders?|session[-_ ]?handoffs?|"
        r"prompt[-_ ]?appendix|build[-_ ]?handover)",
        re.IGNORECASE,
    ),
)
ATTRIBUTION_PATTERNS = (
    ("co-author trailer", re.compile(rb"(?im)^\s*co-authored-by\s*:")),
    ("robot attribution", re.compile(bytes.fromhex("f09fa496"))),
)
HISTORY_MESSAGE_PATTERN = re.compile(rb"(?i)co-authored-by|generated with")
PRIVATE_DENYLIST_NAME = "publication-denylist"
PRIVATE_DENYLIST_KINDS = ("path", "content", "comment", "history")
SECRET_PATTERNS = (
    (
        "private-key block",
        re.compile(rb"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA) |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    (
        "repository token",
        re.compile(rb"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b", re.IGNORECASE),
    ),
    ("generic sk token", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE)),
    ("provider token", re.compile(rb"\bfc-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE)),
    (
        "bearer token",
        re.compile(rb"\bbearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}\b", re.IGNORECASE),
    ),
    ("AWS access-key identifier", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
)
SAFE_SECRET_MARKERS = (
    b"canary",
    b"dummy",
    b"example",
    b"fake",
    b"not-a-real",
    b"placeholder",
    b"redacted",
    b"sample",
    b"synthetic",
    b"unit-test",
)


class HygieneError(RuntimeError):
    """The candidate repository is not safe to publish."""


@dataclass(frozen=True)
class PrivateDenyList:
    """Optional deny patterns kept in the untracked ``.git/info`` directory."""

    paths: tuple[re.Pattern[str], ...] = ()
    content: tuple[re.Pattern[bytes], ...] = ()
    comments: tuple[re.Pattern[bytes], ...] = ()
    history: tuple[re.Pattern[bytes], ...] = ()


_active_denylist = PrivateDenyList()


def _fail(message: str) -> NoReturn:
    raise HygieneError(message)


def _git(repository_root: Path, *arguments: str) -> bytes:
    command = [
        "git",
        "-c",
        f"safe.directory={repository_root}",
        "-c",
        f"core.excludesFile={os.devnull}",
        *arguments,
    ]
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        _fail(f"git command failed while checking {arguments[0]}")
    return completed.stdout


def _git_with_input(repository_root: Path, payload: bytes, *arguments: str) -> bytes:
    command = [
        "git",
        "-c",
        f"safe.directory={repository_root}",
        "-c",
        f"core.excludesFile={os.devnull}",
        *arguments,
    ]
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
        input=payload,
    )
    if completed.returncode != 0:
        _fail(f"git command failed while checking {arguments[0]}")
    return completed.stdout


def _split_nul(payload: bytes) -> list[str]:
    return [item.decode("utf-8") for item in payload.split(b"\0") if item]


def _is_text_path(path: str) -> bool:
    pure = PurePosixPath(path)
    suffix = pure.suffix.casefold()
    return (
        not suffix
        or suffix in TEXT_SUFFIXES
        or suffix in SENSITIVE_SCAN_SUFFIXES
        or pure.name.casefold() in SPECIAL_TEXT_NAMES
    )


def _is_code_comment_path(path: str) -> bool:
    suffix = PurePosixPath(path).suffix.casefold()
    return not suffix or suffix in CODE_COMMENT_SUFFIXES


def _check_path(path: str, surface: str) -> None:
    normalized = path.replace("\\", "/")
    for pattern in (*FORBIDDEN_PATH_PATTERNS, *_active_denylist.paths):
        if pattern.search(normalized):
            _fail(f"{surface} contains private process path: {normalized}")
    if normalized.casefold().endswith(ARCHIVE_SUFFIXES):
        _fail(f"{surface} contains a packaged artifact: {normalized}")


def _check_content(payload: bytes, location: str, *, code_comments: bool) -> None:
    for label, pattern in ATTRIBUTION_PATTERNS:
        if pattern.search(payload):
            _fail(f"{label} found in {location}")
    for pattern in _active_denylist.content:
        if pattern.search(payload):
            _fail(f"private attribution pattern found in {location}")
    if code_comments and any(pattern.search(payload) for pattern in _active_denylist.comments):
        _fail(f"private comment pattern found in {location}")
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(payload):
            lowered = match.group(0).lower()
            if any(marker in lowered for marker in SAFE_SECRET_MARKERS):
                continue
            _fail(f"possible {label} found in {location}")


def _read_candidate(repository_root: Path, path: str) -> bytes:
    full_path = repository_root / PurePosixPath(path)
    try:
        size = full_path.stat().st_size
        if size > MAX_TEXT_BYTES:
            _fail(f"text candidate exceeds the review byte ceiling: {path}")
        return full_path.read_bytes()
    except OSError as exc:
        raise HygieneError(f"could not inspect candidate file: {path}") from exc


def _check_blob_batch(
    repository_root: Path,
    entries: list[tuple[str, str]],
    *,
    surface: str,
    require_blob: bool,
) -> int:
    if not entries:
        return 0
    batch_requests = b"".join(f"{object_id}\n".encode("ascii") for object_id, _ in entries)
    batch_output = _git_with_input(repository_root, batch_requests, "cat-file", "--batch")
    offset = 0
    checked = 0
    for object_id, path in entries:
        header_end = batch_output.find(b"\n", offset)
        if header_end < 0:
            _fail(f"{surface} batch response ended before its header")
        header = batch_output[offset:header_end].split()
        if len(header) != 3 or header[0].decode("ascii") != object_id:
            _fail(f"{surface} batch response did not match its request")
        object_type = header[1]
        size = int(header[2])
        offset = header_end + 1
        payload_end = offset + size
        if payload_end >= len(batch_output) or batch_output[payload_end : payload_end + 1] != b"\n":
            _fail(f"{surface} batch response ended before its payload")
        payload = batch_output[offset:payload_end]
        offset = payload_end + 1
        if object_type != b"blob":
            if require_blob:
                _fail(f"{surface} contains a non-blob file entry")
            continue
        if size > MAX_TEXT_BYTES:
            _fail(f"{surface} text blob exceeds the review byte ceiling")
        _check_content(
            payload,
            f"{surface}:{path}@{object_id}",
            code_comments=_is_code_comment_path(path),
        )
        checked += 1
    if offset != len(batch_output):
        _fail(f"{surface} batch response contained unexpected trailing data")
    return checked


def _check_candidate_tree(repository_root: Path) -> tuple[int, int, int]:
    index_rows = _split_nul(
        _git(
            repository_root,
            "-c",
            "core.quotepath=false",
            "ls-files",
            "-z",
            "--stage",
        )
    )
    if len(index_rows) > MAX_CANDIDATE_PATHS:
        _fail("candidate index exceeds the bounded path-review ceiling")
    index_paths: list[str] = []
    index_blobs: list[tuple[str, str]] = []
    for row in index_rows:
        match = re.fullmatch(
            r"(?P<mode>\d{6})\s+(?P<object>[0-9a-f]+)\s+(?P<stage>\d+)\t(?P<path>.+)",
            row,
        )
        if match is None:
            _fail("candidate index contains a malformed entry")
        mode = match.group("mode")
        path = match.group("path")
        if match.group("stage") != "0":
            _fail("candidate index contains an unresolved merge entry")
        if mode in {"120000", "160000"}:
            _fail("candidate index contains a symlink or submodule")
        if mode not in {"100644", "100755"}:
            _fail("candidate index contains an unsupported file mode")
        _check_path(path, "candidate tree")
        index_paths.append(path)
        if _is_text_path(path):
            index_blobs.append((match.group("object"), path))

    index_blob_count = _check_blob_batch(
        repository_root,
        index_blobs,
        surface="candidate index",
        require_blob=True,
    )
    untracked_paths = _split_nul(
        _git(
            repository_root,
            "-c",
            "core.quotepath=false",
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
        )
    )
    candidate_paths = set(index_paths)
    candidate_paths.update(untracked_paths)
    if len(candidate_paths) > MAX_CANDIDATE_PATHS:
        _fail("candidate tree exceeds the bounded path-review ceiling")

    worktree_files_scanned = 0
    untracked = set(untracked_paths)
    for path in sorted(candidate_paths):
        _check_path(path, "candidate tree")
        full_path = repository_root / PurePosixPath(path)
        try:
            mode = full_path.lstat().st_mode
        except FileNotFoundError:
            if path in untracked:
                _fail("candidate tree changed during inspection")
            continue
        except OSError as exc:
            raise HygieneError("could not inspect a candidate path") from exc
        if stat.S_ISLNK(mode):
            _fail("candidate working tree contains a symbolic link")
        if not stat.S_ISREG(mode):
            _fail("candidate working tree contains an unsupported file type")
        if _is_text_path(path):
            payload = _read_candidate(repository_root, path)
            _check_content(
                payload,
                f"candidate working tree:{path}",
                code_comments=_is_code_comment_path(path),
            )
            worktree_files_scanned += 1
    return len(candidate_paths), index_blob_count, worktree_files_scanned


def _check_history(repository_root: Path) -> tuple[int, int]:
    messages = _git(repository_root, "log", "--all", "--format=%B")
    if HISTORY_MESSAGE_PATTERN.search(messages) or any(
        pattern.search(messages) for pattern in _active_denylist.history
    ):
        _fail("commit history contains prohibited authorship or tool-attribution text")

    identities = (
        _git(
            repository_root,
            "log",
            "--all",
            "--format=%an <%ae>|%cn <%ce>",
        )
        .decode("utf-8")
        .splitlines()
    )
    expected = f"{REQUIRED_IDENTITY}|{REQUIRED_IDENTITY}"
    mismatches = sorted({identity for identity in identities if identity != expected})
    if mismatches:
        _fail(f"historical author/committer identity mismatch: {mismatches[0]}")

    object_rows = (
        _git(
            repository_root,
            "-c",
            "core.quotepath=false",
            "rev-list",
            "--objects",
            "--all",
        )
        .decode("utf-8")
        .splitlines()
    )
    if len(object_rows) > MAX_HISTORY_BLOBS:
        _fail("Git history exceeds the bounded object-review ceiling")
    checked_blobs: dict[str, str] = {}
    historical_paths = 0
    for row in object_rows:
        object_id, separator, path = row.partition(" ")
        if not separator or not path:
            continue
        historical_paths += 1
        _check_path(path, "history")
        if object_id in checked_blobs or not _is_text_path(path):
            continue
        checked_blobs[object_id] = path

    checked_count = _check_blob_batch(
        repository_root,
        list(checked_blobs.items()),
        surface="history",
        require_blob=False,
    )
    return historical_paths, checked_count


def load_private_denylist(repository_root: Path) -> PrivateDenyList:
    """Read optional ``kind: pattern`` lines from the repository's private info directory."""

    common_dir = _git(repository_root, "rev-parse", "--git-common-dir").decode("utf-8").strip()
    location = (repository_root / common_dir / "info" / PRIVATE_DENYLIST_NAME).resolve()
    if not location.is_file():
        return PrivateDenyList()
    buckets: dict[str, list[str]] = {kind: [] for kind in PRIVATE_DENYLIST_KINDS}
    lines = location.read_text(encoding="utf-8").splitlines()
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        kind, separator, expression = line.partition(":")
        kind, expression = kind.strip(), expression.strip()
        if not separator or not expression:
            _fail(f"private deny-list line {number} is malformed")
        if kind.startswith("wheel-"):
            continue
        if kind not in buckets:
            _fail(f"private deny-list line {number} has an unknown kind")
        buckets[kind].append(expression)
    try:
        return PrivateDenyList(
            paths=tuple(re.compile(item, re.IGNORECASE) for item in buckets["path"]),
            content=tuple(re.compile(item.encode("utf-8")) for item in buckets["content"]),
            comments=tuple(re.compile(item.encode("utf-8")) for item in buckets["comment"]),
            history=tuple(re.compile(item.encode("utf-8")) for item in buckets["history"]),
        )
    except re.error as exc:
        _fail(f"private deny-list contains an invalid pattern: {exc}")


def check_repository(repository_root: Path) -> dict[str, object]:
    """Return bounded hygiene evidence or raise ``HygieneError``."""

    global _active_denylist
    repository_root = repository_root.resolve(strict=True)
    if _git(repository_root, "rev-parse", "--is-inside-work-tree").strip() != b"true":
        _fail("target is not a Git working tree")
    _active_denylist = load_private_denylist(repository_root)
    candidate_count, candidate_index_blobs, candidate_worktree_files = _check_candidate_tree(
        repository_root
    )
    historical_paths, historical_blobs = _check_history(repository_root)
    head = _git(repository_root, "rev-parse", "HEAD").decode("ascii").strip()
    return {
        "candidate_paths_scanned": candidate_count,
        "candidate_index_blobs_scanned": candidate_index_blobs,
        "candidate_worktree_files_scanned": candidate_worktree_files,
        "head": head,
        "historical_paths_scanned": historical_paths,
        "historical_text_blobs_scanned": historical_blobs,
        "required_identity": REQUIRED_IDENTITY,
        "status": "passed",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        default=str(Path(__file__).parents[1]),
        help="repository checkout to inspect",
    )
    parser.add_argument("--output", help="optional JSON evidence path")
    arguments = parser.parse_args()
    try:
        result = check_repository(Path(cast(str, arguments.repository_root)))
    except (HygieneError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"Publication hygiene check failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = cast(str | None, arguments.output)
    if output is not None:
        Path(output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
