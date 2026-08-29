"""Verify reviewed offline runtime inputs, emit an SBOM, and gate vulnerabilities."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tomllib
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast
from urllib.parse import quote

try:
    from packaging.markers import default_environment
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
    from packaging.version import InvalidVersion, Version
except ModuleNotFoundError:
    # A fresh setup-python environment exposes packaging only through pip's trusted bootstrap copy.
    from pip._vendor.packaging.markers import default_environment
    from pip._vendor.packaging.requirements import (  # type: ignore[assignment]
        InvalidRequirement,
        Requirement,
    )
    from pip._vendor.packaging.specifiers import (  # type: ignore[assignment]
        InvalidSpecifier,
        SpecifierSet,
    )
    from pip._vendor.packaging.utils import (  # type: ignore[assignment]
        InvalidWheelFilename,
        canonicalize_name,
        parse_wheel_filename,
    )
    from pip._vendor.packaging.version import InvalidVersion, Version  # type: ignore[assignment]

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_LOCK_BYTES = 1024 * 1024
MAX_PROJECT_BYTES = 1024 * 1024
MAX_WHEELS = 512
MAX_WHEEL_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_WHEELHOUSE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES = 4096
MAX_SNAPSHOT_VALIDITY = timedelta(days=7)
MAX_CLOCK_SKEW = timedelta(minutes=5)
LOCK_ENTRY = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;]+) "
    r"--hash=sha256:(?P<sha256>[0-9a-f]{64})"
)
ROOT_ENTRY = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;]+)")
ADVISORY_ID = re.compile(r"[A-Z0-9][A-Z0-9._:-]{1,127}")
SUPPORTED_PYTHON_MINORS = {"3.12", "3.13", "3.14"}


class SupplyChainError(RuntimeError):
    """A reviewed release supply-chain invariant was not satisfied."""


@dataclass(frozen=True)
class LockedArtifact:
    name: str
    version: str
    sha256: str


@dataclass(frozen=True)
class WheelManifestEntry:
    filename: str
    name: str
    python_minors: tuple[str, ...]
    sha256: str
    size_bytes: int
    version: str


@dataclass(frozen=True)
class WheelComponent:
    filename: str
    name: str
    requires: tuple[Requirement, ...]
    sha256: str
    size_bytes: int
    uncompressed_size_bytes: int
    version: str


def _fail(message: str) -> NoReturn:
    raise SupplyChainError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_reparse_point(details: os.stat_result) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0) or 0)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(details.st_mode) or bool(attributes & reparse_flag)


def _absolute_without_reparse(
    path: Path,
    *,
    label: str,
    allow_missing_leaf: bool = False,
) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            details = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf:
                return absolute
            raise SupplyChainError(f"{label} is unavailable") from None
        except OSError as exc:
            raise SupplyChainError(f"could not inspect {label}") from exc
        _require(not _is_reparse_point(details), f"{label} crosses a reparse point")
    return absolute


def _resolve_input(path: Path, *, label: str) -> Path:
    absolute = _absolute_without_reparse(path, label=label)
    try:
        return absolute.resolve(strict=True)
    except OSError as exc:
        raise SupplyChainError(f"could not resolve {label}") from exc


def _read_bounded(path: Path, *, ceiling: int, label: str) -> bytes:
    try:
        initial = path.lstat()
        _require(stat.S_ISREG(initial.st_mode), f"{label} is not a regular file")
        _require(not _is_reparse_point(initial), f"{label} must not be a reparse point")
        _require(initial.st_size <= ceiling, f"{label} exceeds its byte ceiling")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            _require(os.path.samestat(initial, opened), f"{label} changed while opening")
            _require(stat.S_ISREG(opened.st_mode), f"{label} is not a regular file")
            _require(opened.st_size <= ceiling, f"{label} exceeds its byte ceiling")
            payload = stream.read(ceiling + 1)
            after = os.fstat(stream.fileno())
        _require(len(payload) <= ceiling, f"{label} exceeds its byte ceiling")
        _require(
            os.path.samestat(opened, after) and opened.st_size == after.st_size,
            f"{label} changed while reading",
        )
        _require(len(payload) == after.st_size, f"{label} changed while reading")
        return payload
    except OSError as exc:
        raise SupplyChainError(f"could not read {label}") from exc


def _zip_eocd(payload: bytes, *, label: str) -> tuple[int, int]:
    signature = b"PK\x05\x06"
    search_start = max(0, len(payload) - (65_535 + 22))
    offset = payload.rfind(signature, search_start)
    while offset >= 0:
        if offset + 22 <= len(payload):
            fields = struct.unpack_from("<4s4H2IH", payload, offset)
            comment_bytes = int(fields[-1])
            if offset + 22 + comment_bytes == len(payload):
                break
        offset = payload.rfind(signature, search_start, offset)
    _require(offset >= 0, f"{label} has no canonical ZIP end record")
    fields = struct.unpack_from("<4s4H2IH", payload, offset)
    (
        _signature,
        disk,
        directory_disk,
        disk_entries,
        entries,
        directory_bytes,
        directory_offset,
        _,
    ) = fields
    _require(disk == 0 and directory_disk == 0, f"{label} is a multi-disk archive")
    _require(disk_entries == entries, f"{label} has an inconsistent ZIP entry count")
    _require(entries not in {0, 0xFFFF}, f"{label} has an unsupported ZIP entry count")
    _require(entries <= MAX_ARCHIVE_MEMBERS, f"{label} exceeds the member-count ceiling")
    _require(
        directory_bytes not in {0xFFFFFFFF}
        and directory_bytes <= MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES,
        f"{label} central directory exceeds the byte ceiling",
    )
    _require(
        directory_offset != 0xFFFFFFFF and directory_offset + directory_bytes == offset,
        f"{label} has a malformed ZIP directory",
    )
    return int(entries), int(directory_bytes)


def _inspect_archive(
    payload: bytes,
    *,
    label: str,
) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo], int]:
    expected_entries, _directory_bytes = _zip_eocd(payload, label=label)
    archive: zipfile.ZipFile | None = None
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
        members = archive.infolist()
        _require(len(members) == expected_entries, f"{label} ZIP entry count differs")
        seen_names: set[str] = set()
        total_uncompressed = 0
        for member in members:
            name = member.filename
            try:
                encoded_name = name.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise SupplyChainError(f"{label} contains a malformed member name") from exc
            _require(
                0 < len(encoded_name) <= MAX_ARCHIVE_PATH_BYTES,
                f"{label} contains an overlong member path",
            )
            raw_parts = name.rstrip("/").split("/")
            _require(
                not name.startswith("/")
                and "\\" not in name
                and ":" not in name
                and "\x00" not in name
                and bool(raw_parts)
                and all(part not in {"", ".", ".."} for part in raw_parts)
                and not PurePosixPath(name).is_absolute(),
                f"{label} contains an unsafe member path",
            )
            normalized_name = name.rstrip("/").casefold()
            _require(normalized_name not in seen_names, f"{label} contains colliding member paths")
            seen_names.add(normalized_name)
            unix_mode = int(member.external_attr) >> 16
            file_type = stat.S_IFMT(unix_mode)
            _require(
                file_type in {0, stat.S_IFREG, stat.S_IFDIR},
                f"{label} contains a non-regular member",
            )
            _require(not (member.flag_bits & 0x1), f"{label} contains an encrypted member")
            _require(
                0 <= member.file_size <= MAX_ARCHIVE_ENTRY_BYTES,
                f"{label} member exceeds the uncompressed byte ceiling",
            )
            total_uncompressed += member.file_size
            _require(
                total_uncompressed <= MAX_ARCHIVE_UNCOMPRESSED_BYTES,
                f"{label} exceeds the uncompressed byte ceiling",
            )

        actual_uncompressed = 0
        for member in members:
            if member.is_dir():
                _require(member.file_size == 0, f"{label} directory member is malformed")
                continue
            member_bytes = 0
            with archive.open(member, "r") as stream:
                while chunk := stream.read(
                    min(1024 * 1024, MAX_ARCHIVE_ENTRY_BYTES - member_bytes + 1)
                ):
                    member_bytes += len(chunk)
                    _require(
                        member_bytes <= member.file_size,
                        f"{label} member expanded beyond its declared size",
                    )
            _require(member_bytes == member.file_size, f"{label} member size differs")
            actual_uncompressed += member_bytes
        _require(actual_uncompressed == total_uncompressed, f"{label} archive size differs")
        return archive, members, total_uncompressed
    except BaseException as exc:
        if archive is not None:
            archive.close()
        if isinstance(exc, SupplyChainError):
            raise
        if isinstance(exc, (NotImplementedError, OSError, RuntimeError, zipfile.BadZipFile)):
            raise SupplyChainError(f"{label} could not be safely inspected") from None
        raise


def _write_new(path: Path, payload: bytes, *, label: str) -> None:
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            written = stream.write(payload)
            if written != len(payload):
                raise OSError("short write")
    except FileExistsError:
        raise SupplyChainError(f"{label} already exists; refusing to overwrite it") from None
    except BaseException as exc:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        if isinstance(exc, OSError):
            raise SupplyChainError(f"could not write {label}") from exc
        raise


def _parse_canonical_json(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"{label} is not valid UTF-8 JSON") from exc
    _require(isinstance(parsed, dict), f"{label} must contain a JSON object")
    result = cast(dict[str, Any], parsed)
    _require(payload == _canonical_json(result), f"{label} is not canonical JSON")
    return result


def _load_canonical_json(path: Path, *, label: str) -> dict[str, Any]:
    payload = _read_bounded(path, ceiling=MAX_JSON_BYTES, label=label)
    return _parse_canonical_json(payload, label=label)


def _require_exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    _require(set(value) == expected, f"{label} has missing or unexpected fields")


def _parse_lock(
    path: Path,
    *,
    scope: str = "runtime",
) -> tuple[bytes, dict[str, LockedArtifact]]:
    label = f"{scope} lock"
    payload = _read_bounded(path, ceiling=MAX_LOCK_BYTES, label=label)
    try:
        content = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainError(f"{label} is not UTF-8") from exc
    _require("\r" not in content, f"{label} must use canonical LF line endings")
    entries: dict[str, LockedArtifact] = {}
    ordered_names: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = LOCK_ENTRY.fullmatch(stripped)
        _require(match is not None, f"{label} contains an unhashed or malformed requirement")
        assert match is not None
        name = canonicalize_name(match.group("name"))
        try:
            version = str(Version(match.group("version")))
        except InvalidVersion as exc:
            raise SupplyChainError(f"{label} contains an invalid version") from exc
        _require(name not in entries, f"{label} contains a duplicate distribution")
        entries[name] = LockedArtifact(
            name=name,
            version=version,
            sha256=match.group("sha256"),
        )
        ordered_names.append(name)
    _require(bool(entries), f"{label} contains no distributions")
    _require(len(entries) <= MAX_WHEELS, f"{label} exceeds the package-count ceiling")
    _require(ordered_names == sorted(ordered_names), f"{label} entries are not sorted")
    return payload, entries


def _parse_manifest(
    path: Path,
    *,
    python_minor: str,
    repository_root: Path,
    lock_path: Path,
    lock_payload: bytes,
    scope: str = "runtime",
) -> tuple[list[WheelManifestEntry], bytes]:
    label = f"{scope} wheelhouse manifest"
    manifest_payload = _read_bounded(
        path,
        ceiling=MAX_JSON_BYTES,
        label=label,
    )
    manifest = _parse_canonical_json(manifest_payload, label=label)
    _require_exact_keys(
        manifest,
        {"review", "schema_version", "targets", "wheels"},
        label=label,
    )
    _require(manifest["schema_version"] == 1, "unsupported wheelhouse manifest schema")
    review = manifest["review"]
    _require(isinstance(review, dict), "wheelhouse manifest review metadata is malformed")
    review_object = cast(dict[str, Any], review)
    _require_exact_keys(
        review_object,
        {"artifact_index", "reviewed_at_utc"},
        label="wheelhouse manifest review metadata",
    )
    _require(
        review_object["artifact_index"] == "https://pypi.org/simple",
        "wheelhouse manifest artifact index is not the reviewed PyPI index",
    )
    _parse_utc(str(review_object["reviewed_at_utc"]), label="manifest review time")

    targets = manifest["targets"]
    _require(isinstance(targets, dict), "wheelhouse manifest targets are malformed")
    target_map = cast(dict[str, Any], targets)
    _require(set(target_map) == SUPPORTED_PYTHON_MINORS, "wheelhouse target set is incomplete")
    target = target_map.get(python_minor)
    _require(isinstance(target, dict), "requested wheelhouse target is absent")
    target_object = cast(dict[str, Any], target)
    _require_exact_keys(
        target_object,
        {"abi", "implementation", "lock_path", "lock_sha256", "platform"},
        label="wheelhouse target",
    )
    digits = python_minor.replace(".", "")
    _require(target_object["abi"] == f"cp{digits}", "wheelhouse target ABI differs")
    _require(target_object["implementation"] == "cp", "wheelhouse target is not CPython")
    _require(target_object["platform"] == "win_amd64", "wheelhouse target is not Windows x64")
    try:
        relative_lock = lock_path.resolve(strict=True).relative_to(
            repository_root.resolve(strict=True)
        )
    except (OSError, ValueError) as exc:
        raise SupplyChainError(f"{scope} lock is not a tracked repository input") from exc
    _require(
        relative_lock.as_posix() == target_object["lock_path"],
        f"{scope} lock path differs from the reviewed manifest",
    )
    _require(
        _sha256(lock_payload) == target_object["lock_sha256"],
        f"{scope} lock hash differs from the reviewed manifest",
    )

    raw_wheels = manifest["wheels"]
    _require(isinstance(raw_wheels, list), "wheelhouse manifest wheel list is malformed")
    _require(len(raw_wheels) <= MAX_WHEELS * 3, "wheelhouse manifest is too large")
    entries: list[WheelManifestEntry] = []
    all_filenames: set[str] = set()
    for raw_entry in raw_wheels:
        _require(isinstance(raw_entry, dict), "wheelhouse manifest contains a malformed entry")
        entry = cast(dict[str, Any], raw_entry)
        _require_exact_keys(
            entry,
            {"filename", "name", "python_minors", "sha256", "size_bytes", "version"},
            label="wheelhouse manifest entry",
        )
        filename = entry["filename"]
        name = entry["name"]
        minors = entry["python_minors"]
        digest = entry["sha256"]
        size = entry["size_bytes"]
        version = entry["version"]
        _require(isinstance(filename, str) and Path(filename).name == filename, "unsafe wheel name")
        _require(filename.endswith(".whl"), "wheelhouse manifest contains a non-wheel artifact")
        _require(filename not in all_filenames, "wheelhouse manifest contains a duplicate filename")
        _require(isinstance(name, str) and canonicalize_name(name) == name, "noncanonical name")
        _require(
            isinstance(minors, list)
            and bool(minors)
            and minors == sorted(set(minors))
            and set(minors) <= SUPPORTED_PYTHON_MINORS,
            "wheelhouse manifest target list is malformed",
        )
        _require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "wheelhouse manifest contains an invalid SHA-256",
        )
        _require(
            isinstance(size, int) and 0 < size <= MAX_WHEEL_BYTES,
            "wheelhouse manifest contains an invalid wheel size",
        )
        try:
            normalized_version = str(Version(str(version)))
        except InvalidVersion as exc:
            raise SupplyChainError("wheelhouse manifest contains an invalid version") from exc
        all_filenames.add(filename)
        parsed = WheelManifestEntry(
            filename=filename,
            name=name,
            python_minors=tuple(cast(list[str], minors)),
            sha256=digest,
            size_bytes=size,
            version=normalized_version,
        )
        if python_minor in parsed.python_minors:
            entries.append(parsed)
    _require(bool(entries), "wheelhouse manifest has no wheels for the requested target")
    _require(len(entries) <= MAX_WHEELS, "target wheelhouse exceeds the entry-count ceiling")
    _require(
        [entry.filename for entry in entries] == sorted(entry.filename for entry in entries),
        "target wheelhouse manifest entries are not sorted",
    )
    return entries, manifest_payload


def _tag_is_compatible(tag: Any, python_minor: str) -> bool:
    digits = python_minor.replace(".", "")
    if tag.platform in {"any", "win_amd64"} and tag.abi == "none":
        return tag.interpreter in {"py3", f"py{digits}", f"cp{digits}"}
    if tag.platform != "win_amd64":
        return False
    if tag.interpreter == f"cp{digits}" and tag.abi in {f"cp{digits}", "abi3", "none"}:
        return True
    if tag.abi != "abi3" or not re.fullmatch(r"cp3\d+", tag.interpreter):
        return False
    return int(tag.interpreter.removeprefix("cp")) <= int(digits)


def _read_wheel_component(
    path: Path,
    expected: WheelManifestEntry,
    *,
    python_minor: str,
    python_full_version: str,
    scope: str = "runtime",
) -> WheelComponent:
    label = f"{scope} wheel"
    payload = _read_bounded(path, ceiling=MAX_WHEEL_BYTES, label=label)
    _require(len(payload) == expected.size_bytes, f"{label} size differs from the manifest")
    digest = _sha256(payload)
    _require(digest == expected.sha256, f"{label} hash differs from the manifest")
    try:
        filename_name, filename_version, _build, tags = parse_wheel_filename(path.name)
    except InvalidWheelFilename as exc:
        raise SupplyChainError(f"{label} filename is malformed") from exc
    _require(str(filename_name) == expected.name, f"{label} filename name differs")
    _require(str(filename_version) == expected.version, f"{label} filename version differs")
    _require(
        any(_tag_is_compatible(tag, python_minor) for tag in tags),
        f"{label} is incompatible with the reviewed target",
    )
    try:
        archive, members, uncompressed_size = _inspect_archive(payload, label=label)
        with archive:
            metadata_members = [
                member
                for member in members
                if re.fullmatch(r"[^/]+\.dist-info/METADATA", member.filename)
            ]
            _require(len(metadata_members) == 1, f"{label} must contain one METADATA file")
            metadata_info = metadata_members[0]
            _require(
                metadata_info.file_size <= MAX_METADATA_BYTES,
                f"{label} METADATA exceeds the byte ceiling",
            )
            metadata = BytesParser(policy=policy.default).parsebytes(archive.read(metadata_info))
    except SupplyChainError:
        raise
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise SupplyChainError(f"{label} metadata could not be inspected") from exc
    _require(
        canonicalize_name(str(metadata["Name"])) == expected.name,
        f"{label} METADATA name differs from the manifest",
    )
    try:
        metadata_version = str(Version(str(metadata["Version"])))
    except InvalidVersion as exc:
        raise SupplyChainError(f"{label} METADATA version is invalid") from exc
    _require(
        metadata_version == expected.version,
        f"{label} METADATA version differs from the manifest",
    )
    requires_python = metadata.get("Requires-Python")
    if requires_python is not None:
        try:
            compatible = Version(python_full_version) in SpecifierSet(str(requires_python))
        except (InvalidSpecifier, InvalidVersion) as exc:
            raise SupplyChainError(f"{label} has malformed Python compatibility metadata") from exc
        _require(compatible, f"{label} does not support the reviewed Python target")
    requirements: list[Requirement] = []
    for value in metadata.get_all("Requires-Dist") or []:
        try:
            requirement = Requirement(str(value))
        except InvalidRequirement as exc:
            raise SupplyChainError(f"{label} has malformed dependency metadata") from exc
        _require(requirement.url is None, f"{label} declares a direct-URL dependency")
        requirements.append(requirement)
    return WheelComponent(
        filename=path.name,
        name=expected.name,
        requires=tuple(requirements),
        sha256=digest,
        size_bytes=len(payload),
        uncompressed_size_bytes=uncompressed_size,
        version=expected.version,
    )


def _verify_wheelhouse(
    wheelhouse: Path,
    entries: list[WheelManifestEntry],
    lock: dict[str, LockedArtifact],
    *,
    python_minor: str,
    python_full_version: str,
    scope: str = "runtime",
) -> dict[str, WheelComponent]:
    label = f"{scope} wheelhouse"
    try:
        children = sorted(wheelhouse.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise SupplyChainError(f"could not enumerate the {label}") from exc
    expected_names = {entry.filename for entry in entries}
    actual_names = {child.name for child in children}
    _require(actual_names == expected_names, f"{label} differs from the exact manifest")
    by_name: dict[str, WheelComponent] = {}
    total_uncompressed = 0
    for entry in entries:
        component = _read_wheel_component(
            wheelhouse / entry.filename,
            entry,
            python_minor=python_minor,
            python_full_version=python_full_version,
            scope=scope,
        )
        _require(component.name not in by_name, f"{label} has duplicate distributions")
        by_name[component.name] = component
        total_uncompressed += component.uncompressed_size_bytes
        _require(
            total_uncompressed <= MAX_WHEELHOUSE_UNCOMPRESSED_BYTES,
            f"{label} exceeds the uncompressed byte ceiling",
        )
    _require(set(by_name) == set(lock), f"{scope} lock and wheelhouse package sets differ")
    for name, component in by_name.items():
        locked = lock[name]
        _require(
            component.version == locked.version,
            f"{scope} lock version differs from wheelhouse",
        )
        _require(
            component.sha256 == locked.sha256,
            f"{scope} lock hash differs from wheelhouse",
        )
    return by_name


def _normalize_target_python_version(python_minor: str, python_full_version: str) -> str:
    try:
        parsed = Version(python_full_version)
    except InvalidVersion as exc:
        raise SupplyChainError("target Python full version is invalid") from exc
    _require(
        len(parsed.release) >= 3
        and f"{parsed.release[0]}.{parsed.release[1]}" == python_minor
        and not parsed.is_prerelease
        and not parsed.is_devrelease
        and parsed.local is None,
        "target Python full version differs from the reviewed minor",
    )
    return str(parsed)


def _marker_environment(
    python_minor: str,
    python_full_version: str,
    *,
    extra: str,
) -> dict[str, str]:
    environment = cast(dict[str, str], dict(default_environment()))
    environment.update(
        {
            "extra": extra,
            "implementation_name": "cpython",
            "implementation_version": python_full_version,
            "os_name": "nt",
            "platform_machine": "AMD64",
            "platform_python_implementation": "CPython",
            "platform_system": "Windows",
            "python_full_version": python_full_version,
            "python_version": python_minor,
            "sys_platform": "win32",
        }
    )
    return environment


def _requirement_applies(
    requirement: Requirement,
    python_minor: str,
    python_full_version: str,
    *,
    extra: str,
) -> bool:
    if requirement.marker is None:
        return True
    return requirement.marker.evaluate(
        _marker_environment(python_minor, python_full_version, extra=extra)
    )


def _load_project_requirements(
    repository_root: Path,
    python_minor: str,
    python_full_version: str,
) -> tuple[str, str, list[Requirement]]:
    try:
        project_payload = _read_bounded(
            repository_root / "pyproject.toml",
            ceiling=MAX_PROJECT_BYTES,
            label="source project metadata",
        )
        configuration = tomllib.loads(project_payload.decode("utf-8"))
        project = configuration["project"]
    except (KeyError, OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChainError("source project metadata could not be read") from exc
    _require(isinstance(project, dict), "source project metadata is malformed")
    project_object = cast(dict[str, Any], project)
    try:
        name = canonicalize_name(str(project_object["name"]))
        version = str(Version(str(project_object["version"])))
        python_supported = Version(python_full_version) in SpecifierSet(
            str(project_object["requires-python"])
        )
    except (InvalidSpecifier, InvalidVersion, KeyError) as exc:
        raise SupplyChainError("source project compatibility metadata is malformed") from exc
    _require(python_supported, "source project does not support the reviewed Python target")
    raw_dependencies = project_object.get("dependencies")
    _require(isinstance(raw_dependencies, list), "source runtime dependencies are malformed")
    dependencies: list[Requirement] = []
    for value in cast(list[object], raw_dependencies):
        _require(isinstance(value, str), "source runtime dependency is not a string")
        try:
            requirement = Requirement(cast(str, value))
        except InvalidRequirement as exc:
            raise SupplyChainError("source runtime dependency is malformed") from exc
        _require(requirement.url is None, "source declares a direct-URL runtime dependency")
        dependencies.append(requirement)
    return name, version, dependencies


def _verify_dependency_closure(
    repository_root: Path,
    components: dict[str, WheelComponent],
    *,
    python_minor: str,
    python_full_version: str,
) -> tuple[str, str, dict[str, set[str]]]:
    project_name, project_version, direct = _load_project_requirements(
        repository_root,
        python_minor,
        python_full_version,
    )
    reachable: set[str] = set()
    requested_extras: dict[str, set[str]] = defaultdict(set)
    edges: dict[str, set[str]] = defaultdict(set)

    def activate(requirement: Requirement, parent: str) -> bool:
        name = canonicalize_name(requirement.name)
        component = components.get(name)
        _require(component is not None, "active dependency is absent from the runtime lock")
        assert component is not None
        _require(
            Version(component.version) in requirement.specifier,
            "locked dependency version does not satisfy package metadata",
        )
        edges[parent].add(name)
        changed = name not in reachable
        reachable.add(name)
        before = len(requested_extras[name])
        requested_extras[name].update(canonicalize_name(extra) for extra in requirement.extras)
        return changed or len(requested_extras[name]) != before

    changed = False
    for requirement in direct:
        if _requirement_applies(
            requirement,
            python_minor,
            python_full_version,
            extra="",
        ):
            changed = activate(requirement, project_name) or changed
    while changed:
        changed = False
        for name in sorted(reachable):
            component = components[name]
            contexts = {"", *requested_extras[name]}
            for requirement in component.requires:
                if any(
                    _requirement_applies(
                        requirement,
                        python_minor,
                        python_full_version,
                        extra=extra,
                    )
                    for extra in contexts
                ):
                    changed = activate(requirement, name) or changed
    unreachable = sorted(set(components) - reachable)
    _require(
        not unreachable,
        "runtime lock contains unreachable extra packages: " + ", ".join(unreachable[:8]),
    )
    for name in components:
        edges.setdefault(name, set())
    return project_name, project_version, edges


def _parse_gate_roots(path: Path) -> tuple[bytes, dict[str, Requirement]]:
    payload = _read_bounded(path, ceiling=MAX_LOCK_BYTES, label="gate roots")
    try:
        content = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainError("gate roots are not UTF-8") from exc
    _require("\r" not in content, "gate roots must use canonical LF line endings")
    roots: dict[str, Requirement] = {}
    ordered_names: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ROOT_ENTRY.fullmatch(stripped)
        _require(match is not None, "gate roots contain a malformed requirement")
        assert match is not None
        name = canonicalize_name(match.group("name"))
        _require(name == match.group("name"), "gate roots contain a noncanonical name")
        try:
            version = str(Version(match.group("version")))
            requirement = Requirement(f"{name}=={version}")
        except (InvalidRequirement, InvalidVersion) as exc:
            raise SupplyChainError("gate roots contain an invalid requirement") from exc
        _require(version == match.group("version"), "gate roots contain a noncanonical version")
        _require(name not in roots, "gate roots contain a duplicate distribution")
        roots[name] = requirement
        ordered_names.append(name)
    _require(bool(roots), "gate roots contain no distributions")
    _require(len(roots) <= MAX_WHEELS, "gate roots exceed the package-count ceiling")
    _require(ordered_names == sorted(ordered_names), "gate roots are not sorted")
    return payload, roots


def _verify_gate_dependency_closure(
    runtime_components: dict[str, WheelComponent],
    gate_components: dict[str, WheelComponent],
    roots: dict[str, Requirement],
    *,
    python_minor: str,
    python_full_version: str,
) -> None:
    combined = {**runtime_components, **gate_components}
    reachable: set[str] = set()
    requested_extras: dict[str, set[str]] = defaultdict(set)

    def activate(requirement: Requirement) -> bool:
        name = canonicalize_name(requirement.name)
        component = combined.get(name)
        _require(component is not None, "active gate dependency is absent from the exact locks")
        assert component is not None
        _require(
            Version(component.version) in requirement.specifier,
            "locked gate dependency version does not satisfy package metadata",
        )
        changed = name not in reachable
        reachable.add(name)
        before = len(requested_extras[name])
        requested_extras[name].update(canonicalize_name(extra) for extra in requirement.extras)
        return changed or len(requested_extras[name]) != before

    changed = False
    for name, requirement in roots.items():
        _require(name in gate_components, "gate root is absent from the gate-tool lock")
        changed = activate(requirement) or changed
    while changed:
        changed = False
        for name in sorted(reachable):
            component = combined[name]
            contexts = {"", *requested_extras[name]}
            for requirement in component.requires:
                if any(
                    _requirement_applies(
                        requirement,
                        python_minor,
                        python_full_version,
                        extra=extra,
                    )
                    for extra in contexts
                ):
                    changed = activate(requirement) or changed
    unreachable = sorted(set(gate_components) - reachable)
    _require(
        not unreachable,
        "gate-tool lock contains unreachable extra packages: " + ", ".join(unreachable[:8]),
    )


def _parse_utc(value: str, *, label: str) -> datetime:
    _require(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
        f"{label} is not canonical UTC",
    )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SupplyChainError(f"{label} is invalid") from exc


def _verify_vulnerability_snapshot(
    path: Path,
    components: dict[str, WheelComponent],
    *,
    now: datetime,
    scope: str = "runtime",
) -> tuple[dict[str, object], bytes]:
    label = f"{scope} vulnerability snapshot"
    snapshot_payload = _read_bounded(
        path,
        ceiling=MAX_JSON_BYTES,
        label=label,
    )
    snapshot = _parse_canonical_json(snapshot_payload, label=label)
    _require_exact_keys(
        snapshot,
        {"packages", "queried_at_utc", "schema_version", "source", "valid_until_utc"},
        label=label,
    )
    _require(snapshot["schema_version"] == 1, "unsupported vulnerability snapshot schema")
    source = snapshot["source"]
    _require(isinstance(source, dict), "vulnerability snapshot source is malformed")
    _require(
        source
        == {
            "ecosystem": "PyPI",
            "endpoint": "https://api.osv.dev/v1/querybatch",
            "name": "OSV",
        },
        "vulnerability snapshot source is not the reviewed OSV endpoint",
    )
    queried_at = _parse_utc(str(snapshot["queried_at_utc"]), label="snapshot query time")
    valid_until = _parse_utc(str(snapshot["valid_until_utc"]), label="snapshot expiry")
    _require(now.tzinfo is not None, "vulnerability verification clock is not timezone-aware")
    current = now.astimezone(UTC)
    _require(queried_at <= current + MAX_CLOCK_SKEW, "vulnerability snapshot is future-dated")
    _require(valid_until > queried_at, "vulnerability snapshot expiry is invalid")
    _require(
        valid_until - queried_at <= MAX_SNAPSHOT_VALIDITY,
        "vulnerability snapshot validity exceeds the policy ceiling",
    )
    _require(current <= valid_until, "vulnerability snapshot is stale")

    raw_packages = snapshot["packages"]
    _require(isinstance(raw_packages, list), "vulnerability snapshot package list is malformed")
    scanned: dict[str, str] = {}
    ordered_names: list[str] = []
    for raw_package in raw_packages:
        _require(isinstance(raw_package, dict), "vulnerability snapshot entry is malformed")
        package = cast(dict[str, Any], raw_package)
        _require_exact_keys(
            package,
            {"name", "version", "vulnerability_ids"},
            label="vulnerability snapshot package",
        )
        name = canonicalize_name(str(package["name"]))
        _require(name == package["name"], "vulnerability snapshot package name is noncanonical")
        try:
            version = str(Version(str(package["version"])))
        except InvalidVersion as exc:
            raise SupplyChainError("vulnerability snapshot package version is invalid") from exc
        ids = package["vulnerability_ids"]
        _require(
            isinstance(ids, list)
            and ids == sorted(set(ids))
            and all(isinstance(item, str) and ADVISORY_ID.fullmatch(item) for item in ids),
            "vulnerability snapshot advisory identifiers are malformed",
        )
        _require(name not in scanned, "vulnerability snapshot contains a duplicate package")
        scanned[name] = version
        ordered_names.append(name)
        if ids:
            _fail(f"vulnerability gate found an advisory for {name}: {ids[0]}")
    _require(ordered_names == sorted(ordered_names), "vulnerability snapshot is not sorted")
    expected = {name: component.version for name, component in components.items()}
    _require(scanned == expected, f"{label} does not cover the exact {scope} lock")
    return (
        {
            "packages_scanned": len(scanned),
            "queried_at_utc": snapshot["queried_at_utc"],
            "source": "OSV",
            "status": "passed_no_known_vulnerabilities",
            "valid_until_utc": snapshot["valid_until_utc"],
        },
        snapshot_payload,
    )


def _purl(name: str, version: str, *, package_type: str = "pypi") -> str:
    return f"pkg:{package_type}/{quote(name, safe='-._~')}@{quote(version, safe='-._~')}"


def _candidate_component(candidate_wheel: Path) -> tuple[str, str, int, str]:
    payload = _read_bounded(candidate_wheel, ceiling=MAX_WHEEL_BYTES, label="candidate wheel")
    try:
        name, version, _build, _tags = parse_wheel_filename(candidate_wheel.name)
        archive, members, _uncompressed_size = _inspect_archive(payload, label="candidate wheel")
        with archive:
            metadata_members = [
                item
                for item in members
                if re.fullmatch(r"[^/]+\.dist-info/METADATA", item.filename)
            ]
            _require(len(metadata_members) == 1, "candidate wheel must contain one METADATA file")
            metadata_info = metadata_members[0]
            _require(
                metadata_info.file_size <= MAX_METADATA_BYTES,
                "candidate wheel METADATA exceeds the byte ceiling",
            )
            metadata = BytesParser(policy=policy.default).parsebytes(archive.read(metadata_info))
    except SupplyChainError:
        raise
    except (InvalidWheelFilename, KeyError, OSError, zipfile.BadZipFile) as exc:
        raise SupplyChainError("candidate wheel identity could not be inspected") from exc
    normalized_name = str(name)
    normalized_version = str(version)
    _require(
        canonicalize_name(str(metadata["Name"])) == normalized_name,
        "candidate wheel name metadata differs from its filename",
    )
    _require(
        str(Version(str(metadata["Version"]))) == normalized_version,
        "candidate wheel version metadata differs from its filename",
    )
    return normalized_name, normalized_version, len(payload), _sha256(payload)


def _build_sbom(
    candidate_wheel: Path,
    components: dict[str, WheelComponent],
    edges: dict[str, set[str]],
    *,
    project_name: str,
    project_version: str,
    python_minor: str,
) -> tuple[dict[str, object], str]:
    candidate_name, candidate_version, candidate_size, candidate_sha = _candidate_component(
        candidate_wheel
    )
    _require(candidate_name == project_name, "candidate wheel differs from the source project name")
    _require(
        candidate_version == project_version,
        "candidate wheel differs from the source project version",
    )
    root_ref = _purl(project_name, project_version, package_type="generic")
    root_component: dict[str, object] = {
        "bom-ref": root_ref,
        "hashes": [{"alg": "SHA-256", "content": candidate_sha}],
        "name": project_name,
        "properties": [
            {"name": "gatehouse:candidate-filename", "value": candidate_wheel.name},
            {"name": "gatehouse:size-bytes", "value": str(candidate_size)},
            {"name": "gatehouse:target-python", "value": python_minor},
        ],
        "type": "application",
        "version": project_version,
    }
    libraries: list[dict[str, object]] = []
    refs: dict[str, str] = {}
    for name, component in sorted(components.items()):
        reference = _purl(name, component.version)
        refs[name] = reference
        libraries.append(
            {
                "bom-ref": reference,
                "hashes": [{"alg": "SHA-256", "content": component.sha256}],
                "name": name,
                "properties": [
                    {"name": "gatehouse:wheel-filename", "value": component.filename},
                    {"name": "gatehouse:size-bytes", "value": str(component.size_bytes)},
                    {"name": "gatehouse:target-python", "value": python_minor},
                ],
                "purl": reference,
                "scope": "required",
                "type": "library",
                "version": component.version,
            }
        )
    dependencies: list[dict[str, object]] = [
        {"dependsOn": sorted(refs[name] for name in edges[project_name]), "ref": root_ref}
    ]
    for name in sorted(components):
        dependencies.append(
            {"dependsOn": sorted(refs[child] for child in edges[name]), "ref": refs[name]}
        )
    return (
        {
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "components": libraries,
            "dependencies": dependencies,
            "metadata": {
                "component": root_component,
                "properties": [
                    {"name": "gatehouse:deterministic", "value": "true"},
                    {"name": "gatehouse:target-python", "value": python_minor},
                ],
                "tools": {
                    "components": [
                        {
                            "name": "Gatehouse release supply-chain verifier",
                            "type": "application",
                            "version": "1",
                        }
                    ]
                },
            },
            "specVersion": "1.6",
            "version": 1,
        },
        candidate_sha,
    )


def verify_supply_chain(
    *,
    repository_root: Path,
    candidate_wheel: Path,
    wheelhouse: Path,
    runtime_lock: Path,
    wheelhouse_manifest: Path,
    vulnerability_snapshot: Path,
    python_minor: str,
    python_full_version: str,
    sbom_output: Path,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify all offline release inputs and write a canonical deterministic SBOM."""

    _require(
        python_minor in SUPPORTED_PYTHON_MINORS,
        "requested Python minor is outside the reviewed target set",
    )
    python_full_version = _normalize_target_python_version(
        python_minor,
        python_full_version,
    )
    repository_root = _resolve_input(repository_root, label="repository root")
    wheelhouse = _resolve_input(wheelhouse, label="runtime wheelhouse")
    candidate_wheel = _resolve_input(candidate_wheel, label="candidate wheel")
    runtime_lock = _resolve_input(runtime_lock, label="runtime lock")
    wheelhouse_manifest = _resolve_input(
        wheelhouse_manifest,
        label="wheelhouse manifest",
    )
    vulnerability_snapshot = _resolve_input(
        vulnerability_snapshot,
        label="vulnerability snapshot",
    )
    sbom_output = _absolute_without_reparse(
        sbom_output,
        label="SBOM output",
        allow_missing_leaf=True,
    )
    lock_payload, locked = _parse_lock(runtime_lock)
    entries, manifest_payload = _parse_manifest(
        wheelhouse_manifest,
        python_minor=python_minor,
        repository_root=repository_root,
        lock_path=runtime_lock,
        lock_payload=lock_payload,
    )
    components = _verify_wheelhouse(
        wheelhouse,
        entries,
        locked,
        python_minor=python_minor,
        python_full_version=python_full_version,
    )
    project_name, project_version, edges = _verify_dependency_closure(
        repository_root,
        components,
        python_minor=python_minor,
        python_full_version=python_full_version,
    )
    vulnerability_result, vulnerability_payload = _verify_vulnerability_snapshot(
        vulnerability_snapshot,
        components,
        now=now or datetime.now(UTC),
    )
    sbom, candidate_sha256 = _build_sbom(
        candidate_wheel,
        components,
        edges,
        project_name=project_name,
        project_version=project_version,
        python_minor=python_minor,
    )
    sbom_payload = _canonical_json(sbom)
    _write_new(sbom_output, sbom_payload, label="SBOM output")
    verified_sbom = _load_canonical_json(sbom_output, label="generated SBOM")
    _require(verified_sbom == sbom, "generated SBOM did not verify deterministically")
    return {
        "candidate_sha256": candidate_sha256,
        "lock_sha256": _sha256(lock_payload),
        "manifest_sha256": _sha256(manifest_payload),
        "python_minor": python_minor,
        "python_full_version": python_full_version,
        "runtime_packages": len(components),
        "sbom_sha256": _sha256(sbom_payload),
        "status": "passed_offline_supply_chain_gate",
        "vulnerability_scan": vulnerability_result,
        "vulnerability_snapshot_sha256": _sha256(vulnerability_payload),
        "wheelhouse_wheels": len(components),
    }


def verify_gate_toolchain(
    *,
    repository_root: Path,
    runtime_wheelhouse: Path,
    runtime_lock: Path,
    runtime_manifest: Path,
    runtime_vulnerability_snapshot: Path,
    gate_wheelhouse: Path,
    gate_lock: Path,
    gate_manifest: Path,
    gate_vulnerability_snapshot: Path,
    gate_roots: Path,
    python_minor: str,
    python_full_version: str,
    output: Path,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify the separately reviewed runtime and gate-tool environments offline."""

    _require(
        python_minor in SUPPORTED_PYTHON_MINORS,
        "requested Python minor is outside the reviewed target set",
    )
    python_full_version = _normalize_target_python_version(
        python_minor,
        python_full_version,
    )
    repository_root = _resolve_input(repository_root, label="repository root")
    runtime_wheelhouse = _resolve_input(runtime_wheelhouse, label="runtime wheelhouse")
    runtime_lock = _resolve_input(runtime_lock, label="runtime lock")
    runtime_manifest = _resolve_input(runtime_manifest, label="runtime wheelhouse manifest")
    runtime_vulnerability_snapshot = _resolve_input(
        runtime_vulnerability_snapshot,
        label="runtime vulnerability snapshot",
    )
    gate_wheelhouse = _resolve_input(gate_wheelhouse, label="gate wheelhouse")
    gate_lock = _resolve_input(gate_lock, label="gate lock")
    gate_manifest = _resolve_input(gate_manifest, label="gate wheelhouse manifest")
    gate_vulnerability_snapshot = _resolve_input(
        gate_vulnerability_snapshot,
        label="gate vulnerability snapshot",
    )
    gate_roots = _resolve_input(gate_roots, label="gate roots")
    output = _absolute_without_reparse(
        output,
        label="gate-toolchain evidence",
        allow_missing_leaf=True,
    )

    runtime_lock_payload, runtime_locked = _parse_lock(runtime_lock, scope="runtime")
    runtime_entries, runtime_manifest_payload = _parse_manifest(
        runtime_manifest,
        python_minor=python_minor,
        repository_root=repository_root,
        lock_path=runtime_lock,
        lock_payload=runtime_lock_payload,
        scope="runtime",
    )
    runtime_components = _verify_wheelhouse(
        runtime_wheelhouse,
        runtime_entries,
        runtime_locked,
        python_minor=python_minor,
        python_full_version=python_full_version,
        scope="runtime",
    )
    _verify_dependency_closure(
        repository_root,
        runtime_components,
        python_minor=python_minor,
        python_full_version=python_full_version,
    )

    gate_lock_payload, gate_locked = _parse_lock(gate_lock, scope="gate-tool")
    gate_entries, gate_manifest_payload = _parse_manifest(
        gate_manifest,
        python_minor=python_minor,
        repository_root=repository_root,
        lock_path=gate_lock,
        lock_payload=gate_lock_payload,
        scope="gate-tool",
    )
    gate_components = _verify_wheelhouse(
        gate_wheelhouse,
        gate_entries,
        gate_locked,
        python_minor=python_minor,
        python_full_version=python_full_version,
        scope="gate-tool",
    )
    overlap = sorted(set(runtime_components) & set(gate_components))
    _require(
        not overlap,
        "runtime and gate-tool locks overlap: " + ", ".join(overlap[:8]),
    )
    gate_roots_payload, roots = _parse_gate_roots(gate_roots)
    _verify_gate_dependency_closure(
        runtime_components,
        gate_components,
        roots,
        python_minor=python_minor,
        python_full_version=python_full_version,
    )

    current = now or datetime.now(UTC)
    runtime_vulnerability_result, runtime_vulnerability_payload = _verify_vulnerability_snapshot(
        runtime_vulnerability_snapshot,
        runtime_components,
        now=current,
        scope="runtime",
    )
    gate_vulnerability_result, gate_vulnerability_payload = _verify_vulnerability_snapshot(
        gate_vulnerability_snapshot,
        gate_components,
        now=current,
        scope="gate-tool",
    )
    result: dict[str, object] = {
        "gate_tools": {
            "lock_sha256": _sha256(gate_lock_payload),
            "manifest_sha256": _sha256(gate_manifest_payload),
            "packages": len(gate_components),
            "roots_sha256": _sha256(gate_roots_payload),
            "vulnerability_scan": gate_vulnerability_result,
            "vulnerability_snapshot_sha256": _sha256(gate_vulnerability_payload),
            "wheelhouse_wheels": len(gate_components),
        },
        "python_full_version": python_full_version,
        "python_minor": python_minor,
        "runtime": {
            "lock_sha256": _sha256(runtime_lock_payload),
            "manifest_sha256": _sha256(runtime_manifest_payload),
            "packages": len(runtime_components),
            "vulnerability_scan": runtime_vulnerability_result,
            "vulnerability_snapshot_sha256": _sha256(runtime_vulnerability_payload),
            "wheelhouse_wheels": len(runtime_components),
        },
        "status": "passed_offline_runtime_and_gate_toolchain",
    }
    encoded = _canonical_json(result)
    _write_new(output, encoded, label="gate-toolchain evidence")
    verified = _load_canonical_json(output, label="generated gate-toolchain evidence")
    _require(
        verified == result, "generated gate-toolchain evidence did not verify deterministically"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--candidate-wheel", required=True)
    parser.add_argument("--wheelhouse", required=True)
    parser.add_argument("--runtime-lock", required=True)
    parser.add_argument("--wheelhouse-manifest", required=True)
    parser.add_argument("--vulnerability-snapshot", required=True)
    parser.add_argument("--python-minor", required=True)
    parser.add_argument("--python-full-version", required=True)
    parser.add_argument("--sbom-output", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    try:
        result = verify_supply_chain(
            repository_root=Path(cast(str, arguments.repository_root)),
            candidate_wheel=Path(cast(str, arguments.candidate_wheel)),
            wheelhouse=Path(cast(str, arguments.wheelhouse)),
            runtime_lock=Path(cast(str, arguments.runtime_lock)),
            wheelhouse_manifest=Path(cast(str, arguments.wheelhouse_manifest)),
            vulnerability_snapshot=Path(cast(str, arguments.vulnerability_snapshot)),
            python_minor=cast(str, arguments.python_minor),
            python_full_version=cast(str, arguments.python_full_version),
            sbom_output=Path(cast(str, arguments.sbom_output)),
        )
        encoded = _canonical_json(result)
        output = _absolute_without_reparse(
            Path(cast(str, arguments.output)),
            label="supply-chain evidence",
            allow_missing_leaf=True,
        )
        _write_new(output, encoded, label="supply-chain evidence")
    except (OSError, SupplyChainError, ValueError) as exc:
        print(f"Release supply-chain verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(encoded.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
