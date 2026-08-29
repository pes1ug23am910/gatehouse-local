"""Audit a Gatehouse wheel against its exact source checkout without installing it."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import json
import re
import stat
import sys
import tomllib
import zipfile
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4096
MAX_ENTRY_BYTES = 32 * 1024 * 1024

FORBIDDEN_PATH_PARTS = {
    ".git",
    ".local",
    ".pytest_cache",
    "__pycache__",
    "audits",
    "prompts",
    "tests",
}
FORBIDDEN_BASENAMES = {
    ".env",
    "agent_feedback.md",
    "audit_log.md",
    "context.md",
    "continue_prompt.md",
    "progress.md",
    "run_order.md",
    "session_handoff.md",
}
FORBIDDEN_SUFFIXES = (
    ".db",
    ".db-shm",
    ".db-wal",
    ".log",
    ".pyc",
    ".sqlite",
    ".sqlite3",
)
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b", re.IGNORECASE),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE),
    re.compile(rb"\bfc-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE),
)
SAFE_SECRET_MARKERS = (
    b"canary",
    b"dummy",
    b"example",
    b"fake",
    b"not-a-real",
    b"placeholder",
    b"redacted",
    b"synthetic",
)
LICENSE_SOURCE_NAME = re.compile(
    r"^(?:authors|copying|licen[cs]e|notice)(?:$|[._-].*)",
    re.IGNORECASE,
)


class WheelAuditError(RuntimeError):
    """The candidate wheel failed a release invariant."""


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def _fail(message: str) -> NoReturn:
    raise WheelAuditError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _record_digest(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_requirement(value: object, *, surface: str) -> Requirement:
    if not isinstance(value, str):
        _fail(f"{surface} contains a non-string dependency declaration")
    try:
        return Requirement(value)
    except InvalidRequirement as exc:
        raise WheelAuditError(f"{surface} contains a malformed dependency declaration") from exc


def _expected_requirements(project: dict[str, Any]) -> Counter[Requirement]:
    runtime_dependencies = project.get("dependencies")
    if not isinstance(runtime_dependencies, list):
        _fail("source runtime dependencies are malformed")
    expected = Counter(
        _parse_requirement(item, surface="source runtime dependencies")
        for item in runtime_dependencies
    )

    optional_dependencies = project.get("optional-dependencies", {})
    if not isinstance(optional_dependencies, dict):
        _fail("source optional dependencies are malformed")
    for raw_extra, declarations in optional_dependencies.items():
        if not isinstance(raw_extra, str) or not isinstance(declarations, list):
            _fail("source optional dependencies are malformed")
        extra = canonicalize_name(raw_extra)
        for declaration in declarations:
            requirement = _parse_requirement(
                declaration,
                surface=f"source optional dependency group {raw_extra!r}",
            )
            extra_marker = Marker(f'extra == "{extra}"')
            if requirement.marker is None:
                requirement.marker = extra_marker
            else:
                requirement.marker = Marker(f"({requirement.marker}) and ({extra_marker})")
            expected[requirement] += 1
    return expected


def _specifier_set(value: str) -> frozenset[str]:
    return frozenset(part.strip() for part in value.split(",") if part.strip())


def _load_project(repository_root: Path) -> dict[str, Any]:
    project_file = repository_root / "pyproject.toml"
    try:
        configuration = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise WheelAuditError("could not read the source project metadata") from exc
    project = configuration.get("project")
    if not isinstance(project, dict):
        _fail("pyproject.toml has no project table")
    return cast(dict[str, Any], project)


def _expected_wheel_identity(project: dict[str, Any]) -> tuple[str, str]:
    try:
        distribution = canonicalize_name(str(project["name"])).replace("-", "_")
        version = str(Version(str(project["version"])))
    except (InvalidVersion, KeyError) as exc:
        raise WheelAuditError("source wheel identity is malformed") from exc
    dist_info = f"{distribution}-{version}.dist-info"
    return dist_info, f"{distribution}-{version}-py3-none-any.whl"


def _load_private_wheel_denylist(repository_root: Path) -> tuple[frozenset[str], frozenset[str]]:
    """Read optional ``wheel-part``/``wheel-name`` lines kept outside the published tree."""

    location = repository_root / ".git" / "info" / "publication-denylist"
    if not location.is_file():
        return frozenset(), frozenset()
    parts: set[str] = set()
    names: set[str] = set()
    for raw_line in location.read_text(encoding="utf-8").splitlines():
        kind, separator, value = raw_line.strip().partition(":")
        if not separator or kind.startswith("#"):
            continue
        if kind.strip() == "wheel-part":
            parts.add(value.strip().casefold())
        elif kind.strip() == "wheel-name":
            names.add(value.strip().casefold())
    return frozenset(parts), frozenset(names)


def _validate_archive_path(
    info: zipfile.ZipInfo,
    private_parts: frozenset[str] = frozenset(),
    private_names: frozenset[str] = frozenset(),
) -> None:
    name = info.filename
    pure = PurePosixPath(name)
    _require(bool(name), "wheel contains an empty archive path")
    _require("\\" not in name, f"wheel path is not POSIX-normalized: {name}")
    _require(not pure.is_absolute(), f"wheel contains an absolute path: {name}")
    _require(
        all(part not in {"", ".", ".."} for part in pure.parts),
        f"wheel contains an unsafe path: {name}",
    )
    folded_parts = {part.casefold() for part in pure.parts}
    _require(
        not (folded_parts & (FORBIDDEN_PATH_PARTS | private_parts)),
        f"wheel contains a forbidden path: {name}",
    )
    _require(
        pure.name.casefold() not in FORBIDDEN_BASENAMES | private_names,
        f"wheel contains private process material: {name}",
    )
    _require(
        not pure.name.casefold().endswith(FORBIDDEN_SUFFIXES),
        f"wheel contains runtime state: {name}",
    )
    _require(not (info.flag_bits & 0x1), f"wheel contains an encrypted entry: {name}")
    _require(info.file_size <= MAX_ENTRY_BYTES, f"wheel entry exceeds the byte ceiling: {name}")
    unix_mode = info.external_attr >> 16
    _require(stat.S_IFMT(unix_mode) != stat.S_IFLNK, f"wheel contains a symlink: {name}")


def _scan_payload(name: str, payload: bytes) -> None:
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(payload):
            lowered = match.group(0).lower()
            if any(marker in lowered for marker in SAFE_SECRET_MARKERS):
                continue
            _fail(f"wheel contains a credential-shaped value in {name}")


def _verify_record(
    archive: zipfile.ZipFile,
    names: list[str],
    record_name: str,
) -> int:
    try:
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    except (KeyError, UnicodeDecodeError, csv.Error) as exc:
        raise WheelAuditError("wheel RECORD is missing or malformed") from exc
    _require(len(rows) == len(names), "wheel RECORD row count does not match archive entries")
    _require(all(len(row) == 3 for row in rows), "wheel RECORD contains a malformed row")
    paths = [row[0] for row in rows]
    _require(len(paths) == len(set(paths)), "wheel RECORD contains duplicate paths")
    _require(set(paths) == set(names), "wheel RECORD does not cover the exact archive")
    for path, encoded_hash, encoded_size in rows:
        if path == record_name:
            _require(not encoded_hash and not encoded_size, "wheel RECORD must not hash itself")
            continue
        payload = archive.read(path)
        _require(
            encoded_hash == f"sha256={_record_digest(payload)}",
            f"wheel RECORD hash mismatch: {path}",
        )
        _require(encoded_size == str(len(payload)), f"wheel RECORD size mismatch: {path}")
    return len(rows)


def _verify_package_files(
    archive: zipfile.ZipFile,
    names: list[str],
    repository_root: Path,
    dist_info: str,
    license_files: dict[str, bytes],
) -> tuple[int, int]:
    source_root = repository_root / "src" / "gatehouse"
    expected = {
        source.relative_to(repository_root / "src").as_posix(): source.read_bytes()
        for source in sorted(source_root.rglob("*"))
        if source.is_file()
        and "__pycache__" not in source.parts
        and source.suffix.casefold() != ".pyc"
    }
    control_files = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
    }
    expected_names = set(expected) | control_files | set(license_files)
    _require(
        set(names) == expected_names,
        "wheel archive surface contains an undeclared or missing file",
    )
    packaged = {name: archive.read(name) for name in expected}
    _require(packaged == expected, "wheel package files do not byte-match the checkout")
    installed_licenses = {name: archive.read(name) for name in license_files}
    _require(
        installed_licenses == license_files,
        "wheel license files do not byte-match the checkout",
    )
    python_sources = sum(name.endswith(".py") for name in expected)
    return len(expected), python_sources


def _declared_license_files(
    metadata: Any,
    *,
    dist_info: str,
    repository_root: Path,
) -> dict[str, bytes]:
    declared = metadata.get_all("License-File") or []
    _require(len(declared) <= 32, "wheel declares too many license files")
    declared_names: list[str] = []
    seen_declarations: set[str] = set()
    for item in declared:
        value = str(item)
        pure = PurePosixPath(value)
        _require(
            bool(value)
            and "\\" not in value
            and value == pure.as_posix()
            and not pure.is_absolute()
            and len(pure.parts) == 1
            and pure.name not in {"", ".", ".."},
            "wheel contains an unsafe License-File declaration",
        )
        folded = pure.name.casefold()
        _require(
            folded not in seen_declarations,
            "wheel contains duplicate License-File declarations",
        )
        seen_declarations.add(folded)
        declared_names.append(pure.name)

    try:
        recognized = sorted(
            path
            for path in repository_root.iterdir()
            if LICENSE_SOURCE_NAME.fullmatch(path.name) is not None
        )
    except OSError as exc:
        raise WheelAuditError("could not enumerate top-level license files") from exc
    _require(len(recognized) <= 32, "source declares too many top-level license files")
    source_names = {path.name for path in recognized}
    _require(
        set(declared_names) == source_names,
        "wheel License-File headers differ from top-level source licenses",
    )

    expected: dict[str, bytes] = {}
    for source in recognized:
        _require(
            source.is_file() and not source.is_symlink(),
            "source contains an unsafe top-level license file",
        )
        try:
            payload = source.read_bytes()
        except OSError as exc:
            raise WheelAuditError("could not read a declared top-level license file") from exc
        _require(
            len(payload) <= MAX_ENTRY_BYTES,
            "declared top-level license file exceeds the byte ceiling",
        )
        expected[f"{dist_info}/licenses/{source.name}"] = payload
    return expected


def _verify_metadata(
    archive: zipfile.ZipFile,
    names: list[str],
    repository_root: Path,
    project: dict[str, Any],
    expected_dist_info: str,
) -> tuple[str, int, dict[str, bytes]]:
    dist_info_roots = {
        PurePosixPath(name).parts[0]
        for name in names
        if len(PurePosixPath(name).parts) > 1
        and PurePosixPath(name).parts[0].endswith(".dist-info")
    }
    _require(
        dist_info_roots == {expected_dist_info},
        "wheel dist-info root differs from the normalized source identity",
    )
    metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
    _require(len(metadata_names) == 1, "wheel must contain exactly one dist-info METADATA file")
    metadata_name = metadata_names[0]
    dist_info = metadata_name.removesuffix("/METADATA")
    _require(
        dist_info == expected_dist_info,
        "wheel METADATA path differs from the normalized source identity",
    )
    required_dist_info = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
    }
    _require(required_dist_info <= set(names), "wheel is missing required dist-info files")

    metadata_bytes = archive.read(metadata_name)
    metadata = BytesParser(policy=policy.default).parsebytes(metadata_bytes)
    license_files = _declared_license_files(
        metadata,
        dist_info=dist_info,
        repository_root=repository_root,
    )
    expected_name = str(project["name"])
    expected_version = str(project["version"])
    expected_python = str(project["requires-python"])
    _require(
        _canonical_name(str(metadata["Name"])) == _canonical_name(expected_name),
        "wheel distribution name differs from pyproject.toml",
    )
    _require(str(metadata["Version"]) == expected_version, "wheel version differs from source")
    _require(
        _specifier_set(str(metadata["Requires-Python"])) == _specifier_set(expected_python),
        "wheel Python range differs from source",
    )

    authors = project.get("authors")
    if not isinstance(authors, list) or len(authors) != 1:
        _fail("source author metadata is ambiguous")
    author = authors[0]
    if not isinstance(author, dict):
        _fail("source author metadata is malformed")
    expected_author = f"{author.get('name')} <{author.get('email')}>"
    _require(str(metadata["Author-email"]) == expected_author, "wheel author metadata differs")

    metadata_requirements = metadata.get_all("Requires-Dist") or []
    expected_requirements = _expected_requirements(project)
    actual_requirements = Counter(
        _parse_requirement(str(item), surface="wheel metadata") for item in metadata_requirements
    )
    _require(
        actual_requirements == expected_requirements,
        "wheel dependency requirements differ from source",
    )

    optional_dependencies = cast(dict[str, object], project.get("optional-dependencies", {}))
    expected_extras = {canonicalize_name(extra) for extra in optional_dependencies}
    actual_extras = {
        canonicalize_name(str(extra)) for extra in (metadata.get_all("Provides-Extra") or [])
    }
    _require(
        actual_extras == expected_extras, "wheel optional-dependency groups differ from source"
    )

    readme = (repository_root / "README.md").read_bytes()
    _require(
        metadata_bytes.endswith(readme),
        "wheel long description does not byte-match README.md",
    )

    wheel_metadata = BytesParser(policy=policy.default).parsebytes(
        archive.read(f"{dist_info}/WHEEL")
    )
    purelib_headers = [str(value) for value in wheel_metadata.get_all("Root-Is-Purelib") or []]
    _require(
        purelib_headers == ["true"],
        "wheel must contain exactly one true Root-Is-Purelib header",
    )
    tag_headers = Counter(str(value) for value in wheel_metadata.get_all("Tag") or [])
    _require(
        tag_headers == Counter({"py3-none-any": 1}),
        "wheel Tag headers must be exactly py3-none-any",
    )

    parser = _CaseSensitiveConfigParser(interpolation=None)
    try:
        parser.read_string(archive.read(f"{dist_info}/entry_points.txt").decode("utf-8"))
        actual_scripts = dict(parser["console_scripts"])
    except (KeyError, UnicodeDecodeError, configparser.Error) as exc:
        raise WheelAuditError("wheel console-script metadata is malformed") from exc
    declared_scripts = project.get("scripts")
    if not isinstance(declared_scripts, dict):
        _fail("source console scripts are malformed")
    expected_scripts = {str(key): str(value) for key, value in declared_scripts.items()}
    _require(actual_scripts == expected_scripts, "wheel console scripts differ from source")
    return dist_info, len(actual_scripts), license_files


def audit_wheel(wheel: Path, repository_root: Path) -> dict[str, object]:
    """Return a JSON-compatible evidence object or raise ``WheelAuditError``."""

    wheel = wheel.resolve(strict=True)
    repository_root = repository_root.resolve(strict=True)
    artifact_size = wheel.stat().st_size
    _require(artifact_size <= MAX_WHEEL_BYTES, "candidate wheel exceeds the byte ceiling")
    artifact = wheel.read_bytes()
    project = _load_project(repository_root)
    private_parts, private_names = _load_private_wheel_denylist(repository_root)
    expected_dist_info, expected_filename = _expected_wheel_identity(project)
    _require(
        wheel.name == expected_filename,
        "candidate wheel filename differs from the normalized source identity and tag",
    )

    try:
        with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            _require(len(names) <= MAX_ARCHIVE_ENTRIES, "wheel exceeds the entry-count ceiling")
            _require(len(names) == len(set(names)), "wheel contains duplicate archive paths")
            _require(
                sum(info.file_size for info in infos) <= MAX_TOTAL_UNCOMPRESSED_BYTES,
                "wheel exceeds the total uncompressed byte ceiling",
            )
            for info in infos:
                _validate_archive_path(info, private_parts, private_names)
            _require(archive.testzip() is None, "wheel contains a corrupt archive entry")
            for info in infos:
                _scan_payload(info.filename, archive.read(info))
            dist_info, entry_point_count, license_files = _verify_metadata(
                archive,
                names,
                repository_root,
                project,
                expected_dist_info,
            )
            record_rows = _verify_record(archive, names, f"{dist_info}/RECORD")
            package_file_count, source_count = _verify_package_files(
                archive,
                names,
                repository_root,
                dist_info,
                license_files,
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise WheelAuditError("candidate is not a readable wheel archive") from exc

    return {
        "archive_entries": len(names),
        "entry_points_verified": entry_point_count,
        "path": str(wheel),
        "package_files_byte_matched": package_file_count,
        "python_sources_byte_matched": source_count,
        "record_rows_verified": record_rows,
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "size_bytes": artifact_size,
        "version": str(project["version"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", help="candidate wheel to audit")
    parser.add_argument(
        "--repository-root",
        default=str(Path(__file__).parents[1]),
        help="exact source checkout used to build the wheel",
    )
    parser.add_argument("--output", help="optional JSON evidence path")
    arguments = parser.parse_args()
    try:
        result = audit_wheel(
            Path(cast(str, arguments.wheel)),
            Path(cast(str, arguments.repository_root)),
        )
    except (OSError, KeyError, WheelAuditError) as exc:
        print(f"Release wheel audit failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = cast(str | None, arguments.output)
    if output is not None:
        Path(output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
