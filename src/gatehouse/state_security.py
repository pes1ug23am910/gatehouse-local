"""Private mutable-state directories with an explicit Windows owner DACL."""

from __future__ import annotations

import ctypes
import os
import stat
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

from gatehouse.state_windows import WindowsPrivateAcl as _WindowsPrivateAcl

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAXIMUM_PATH_ANCESTORS = 256
_MAXIMUM_DIRECTORY_PLAN_CHARACTERS = 8_388_608
_MAXIMUM_DEDICATED_STATE_ROOT_ENTRIES = 32
_DEDICATED_STATE_ROOT_FILES = frozenset(
    {
        "installation-key.dpapi",
        "control-capability.dpapi",
        "control-capability.verifier",
        "gatehoused.lock",
    }
)
_DEDICATED_STATE_ROOT_DIRECTORIES = frozenset({"credentials"})
_WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"|?*~')
_WINDOWS_RESERVED_COMPONENT_STEMS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
        *(f"COM{index}" for index in "¹²³"),
        *(f"LPT{index}" for index in "¹²³"),
    }
)
_DRIVE_FIXED = 3
_MAXIMUM_WINDOWS_DWORD = 0xFFFFFFFF
_MAXIMUM_FILESYSTEM_NAME_CHARACTERS = 32
_KNOWN_FILESYSTEM_KINDS = frozenset(
    {
        stat.S_IFREG,
        stat.S_IFDIR,
        stat.S_IFLNK,
        stat.S_IFCHR,
        stat.S_IFBLK,
        stat.S_IFIFO,
        stat.S_IFSOCK,
    }
)


class StateDirectorySecurityError(RuntimeError):
    """The mutable-state root cannot meet Gatehouse's private-directory policy."""


@dataclass(frozen=True, slots=True)
class StateVolumeFacts:
    """Fresh root-volume observations; callers must still admit every record."""

    drive_type: int
    filesystem: str


StateVolumeProbe = Callable[[str], StateVolumeFacts]


class _PrivateAclBackend(Protocol):
    def create_directory(self, path: Path) -> None: ...
    def secure(self, path: Path, *, is_directory: bool) -> None: ...


@lru_cache(maxsize=1)
def _windows_backend() -> _PrivateAclBackend:
    return _WindowsPrivateAcl()


@lru_cache(maxsize=1)
def _windows_drive_type_api() -> Any:
    kernel32: Any = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetDriveTypeW.restype = wintypes.UINT
    return kernel32.GetDriveTypeW


def _windows_drive_type(root: str) -> int:
    value = _windows_drive_type_api()(root)
    if type(value) is not int or not 0 <= value <= _MAXIMUM_WINDOWS_DWORD:
        raise ValueError("Windows returned invalid drive metadata")
    return value


@lru_cache(maxsize=1)
def _windows_volume_information_api() -> Any:
    kernel32: Any = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL
    return kernel32.GetVolumeInformationW


def _windows_volume_facts(root: str) -> StateVolumeFacts:
    """Read fresh bounded facts, without inspecting non-fixed filesystems."""

    drive_type = _windows_drive_type(root)
    if drive_type != _DRIVE_FIXED:
        return StateVolumeFacts(drive_type=drive_type, filesystem="")
    filesystem = ctypes.create_unicode_buffer(_MAXIMUM_FILESYSTEM_NAME_CHARACTERS + 1)
    result = _windows_volume_information_api()(
        root,
        None,
        0,
        None,
        None,
        None,
        filesystem,
        len(filesystem),
    )
    if type(result) is not int or result == 0:
        raise OSError("Windows volume information is unavailable")
    return StateVolumeFacts(drive_type=drive_type, filesystem=filesystem.value)


def _reject_unsafe_windows_components(path: Path) -> None:
    anchor = path.anchor.casefold()
    for component in path.parts:
        if component.casefold() == anchor:
            continue
        if (
            component.endswith((" ", "."))
            or any(ord(character) < 32 for character in component)
            or any(character in _WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for character in component)
            or component.split(".", 1)[0].rstrip(" .").upper() in _WINDOWS_RESERVED_COMPONENT_STEMS
        ):
            raise StateDirectorySecurityError("mutable state path uses an unsafe Windows component")


def _absolute_state_path(
    path: str | Path,
    *,
    _volume_probe: StateVolumeProbe | None = None,
) -> Path:
    candidate = Path(path)
    if os.name != "nt":
        return candidate.absolute()
    if not candidate.is_absolute() and (candidate.drive or candidate.root):
        raise StateDirectorySecurityError("mutable state path is ambiguously rooted")
    if str(candidate).startswith("\\\\") or candidate.drive.startswith("\\\\"):
        raise StateDirectorySecurityError("mutable state requires a local Windows drive")
    _reject_unsafe_windows_components(candidate)
    try:
        resolved = candidate.absolute()
    except (OSError, ValueError):
        raise StateDirectorySecurityError(
            "mutable state drive locality could not be verified"
        ) from None
    drive = resolved.drive
    if len(drive) != 2 or drive[1] != ":":
        raise StateDirectorySecurityError("mutable state requires a local Windows drive")
    _reject_unsafe_windows_components(resolved)
    try:
        probe = _windows_volume_facts if _volume_probe is None else _volume_probe
        facts = probe(f"{drive}\\")
        if (
            type(facts) is not StateVolumeFacts
            or type(facts.drive_type) is not int
            or not 0 <= facts.drive_type <= _MAXIMUM_WINDOWS_DWORD
            or type(facts.filesystem) is not str
        ):
            raise ValueError("mutable state volume facts are invalid")
    except Exception:
        raise StateDirectorySecurityError("mutable state volume could not be verified") from None
    if facts.drive_type != _DRIVE_FIXED:
        raise StateDirectorySecurityError("mutable state requires a fixed NTFS Windows drive")
    if (
        not 1 <= len(facts.filesystem) <= _MAXIMUM_FILESYSTEM_NAME_CHARACTERS
        or "\x00" in facts.filesystem
    ):
        raise StateDirectorySecurityError("mutable state volume could not be verified")
    if facts.filesystem != "NTFS":
        raise StateDirectorySecurityError("mutable state requires a fixed NTFS Windows drive")
    return resolved


def _selected_backend(override: _PrivateAclBackend | None) -> _PrivateAclBackend | None:
    if override is not None:
        return override
    if os.name != "nt":
        return None
    return _windows_backend()


def _selected_backend_for_operation(
    override: _PrivateAclBackend | None,
) -> _PrivateAclBackend | None:
    try:
        return _selected_backend(override)
    except (AttributeError, OSError, TypeError, ValueError):
        raise StateDirectorySecurityError(
            "mutable state permissions could not be secured"
        ) from None


def _checked_kind(path: Path) -> os.stat_result:
    try:
        details = path.lstat()
    except FileNotFoundError:
        raise
    except Exception:
        raise StateDirectorySecurityError(
            "mutable state object metadata could not be verified"
        ) from None
    try:
        mode = details.st_mode
        links = details.st_nlink
        attributes = details.st_file_attributes if os.name == "nt" else 0
        if (
            type(mode) is not int
            or not 0 <= mode <= 0xFFFF
            or stat.S_IFMT(mode) not in _KNOWN_FILESYSTEM_KINDS
            or type(attributes) is not int
            or not 0 <= attributes <= _MAXIMUM_WINDOWS_DWORD
            or type(links) is not int
            or not 1 <= links <= _MAXIMUM_WINDOWS_DWORD
        ):
            raise ValueError("mutable state object metadata is invalid")
    except Exception:
        raise StateDirectorySecurityError(
            "mutable state object metadata could not be verified"
        ) from None
    if stat.S_ISLNK(mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise StateDirectorySecurityError("mutable state cannot use a reparse point")
    if stat.S_ISREG(mode) and links != 1:
        raise StateDirectorySecurityError("mutable state cannot use a multiply linked file")
    return details


def _reject_reparse_ancestry(path: Path) -> None:
    current = path
    for _ in range(_MAXIMUM_PATH_ANCESTORS):
        try:
            _checked_kind(current)
        except FileNotFoundError:
            pass
        parent = current.parent
        if parent == current:
            return
        current = parent
    raise StateDirectorySecurityError("mutable state path exceeds its ancestry bound")


def validate_state_path_ancestry(
    path: str | Path,
    *,
    _volume_probe: StateVolumeProbe | None = None,
) -> Path:
    """Validate existing path components without creating or changing an ACL."""

    resolved = _absolute_state_path(path, _volume_probe=_volume_probe)
    if os.name != "nt":
        return resolved
    try:
        _reject_reparse_ancestry(resolved)
    except StateDirectorySecurityError:
        raise
    except OSError:
        raise StateDirectorySecurityError("mutable state path could not be verified") from None
    return resolved


def _directory_plan(root: Path, *, maximum_entries: int) -> list[tuple[Path, bool]]:
    pending = [root]
    observed = 0
    planned_characters = len(str(root))
    if planned_characters > _MAXIMUM_DIRECTORY_PLAN_CHARACTERS:
        raise StateDirectorySecurityError("mutable state directory exceeds its path-plan bound")
    plan = [(root, True)]
    while pending:
        directory = pending.pop()
        paths: list[Path] = []
        with os.scandir(directory) as entries:
            for entry in entries:
                observed += 1
                if observed > maximum_entries:
                    raise StateDirectorySecurityError(
                        "mutable state directory exceeds its verification bound"
                    )
                path = Path(entry.path)
                path_characters = len(str(path))
                if path_characters > _MAXIMUM_DIRECTORY_PLAN_CHARACTERS - planned_characters:
                    raise StateDirectorySecurityError(
                        "mutable state directory exceeds its path-plan bound"
                    )
                planned_characters += path_characters
                paths.append(path)

        child_directories: list[Path] = []
        for path in sorted(
            paths, key=lambda candidate: (candidate.name.casefold(), candidate.name)
        ):
            details = _checked_kind(path)
            is_directory = stat.S_ISDIR(details.st_mode)
            if not is_directory and not stat.S_ISREG(details.st_mode):
                raise StateDirectorySecurityError(
                    "mutable state contains an unsupported filesystem object"
                )
            plan.append((path, is_directory))
            if is_directory:
                child_directories.append(path)
        pending.extend(reversed(child_directories))
    return plan


def secure_private_directory(
    path: str | Path,
    *,
    recursive: bool = False,
    maximum_entries: int = 16_384,
    must_exist: bool = False,
    _backend: _PrivateAclBackend | None = None,
    _volume_probe: StateVolumeProbe | None = None,
) -> Path:
    """Create and secure one directory without following managed reparse points.

    On Windows the owner must be the current process user. Inheritance is removed
    and replaced with one inheritable full-control ACE for that exact user SID.
    Other platforms retain their existing permission model for development use.
    """

    if isinstance(maximum_entries, bool) or not 1 <= maximum_entries <= 200_000:
        raise ValueError("mutable state verification bound is invalid")
    resolved = _absolute_state_path(path, _volume_probe=_volume_probe)
    try:
        backend = _selected_backend_for_operation(_backend)
        if backend is None:
            if must_exist and not resolved.is_dir():
                raise StateDirectorySecurityError("mutable state directory is unavailable")
            resolved.mkdir(parents=True, exist_ok=True)
            if not resolved.is_dir():
                raise StateDirectorySecurityError("mutable state root is not a directory")
            return resolved
        _reject_reparse_ancestry(resolved)
        try:
            details = _checked_kind(resolved)
        except FileNotFoundError:
            if must_exist:
                raise StateDirectorySecurityError(
                    "mutable state directory is unavailable"
                ) from None
            backend.create_directory(resolved)
            details = _checked_kind(resolved)
        if not stat.S_ISDIR(details.st_mode):
            raise StateDirectorySecurityError("mutable state root is not a directory")
        if recursive:
            plan = _directory_plan(
                resolved,
                maximum_entries=maximum_entries,
            )
        else:
            plan = [(resolved, True)]
        for planned_path, is_directory in plan:
            current = _checked_kind(planned_path)
            current_is_directory = stat.S_ISDIR(current.st_mode)
            if current_is_directory != is_directory or (
                not current_is_directory and not stat.S_ISREG(current.st_mode)
            ):
                raise StateDirectorySecurityError(
                    "mutable state changed during permission verification"
                )
            backend.secure(planned_path, is_directory=is_directory)
    except StateDirectorySecurityError:
        raise
    except OSError:
        raise StateDirectorySecurityError(
            "mutable state permissions could not be secured"
        ) from None
    return resolved


def secure_private_file(
    path: str | Path,
    *,
    _backend: _PrivateAclBackend | None = None,
    _volume_probe: StateVolumeProbe | None = None,
) -> bool:
    """Secure an existing regular state file; return false when it is absent."""

    resolved = _absolute_state_path(path, _volume_probe=_volume_probe)
    try:
        backend = _selected_backend_for_operation(_backend)
        if backend is None:
            return resolved.is_file()
        _reject_reparse_ancestry(resolved)
        try:
            details = _checked_kind(resolved)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(details.st_mode):
            raise StateDirectorySecurityError("mutable state file is not a regular file")
        backend.secure(resolved, is_directory=False)
    except StateDirectorySecurityError:
        raise
    except OSError:
        raise StateDirectorySecurityError(
            "mutable state permissions could not be secured"
        ) from None
    return True


def _preflight_dedicated_database_root(database: Path) -> None:
    """Prove ACL tightening cannot change an unrelated top-level object."""

    root = database.parent
    database_name = database.name
    reserved_names = _DEDICATED_STATE_ROOT_FILES | _DEDICATED_STATE_ROOT_DIRECTORIES
    if database_name.casefold() in reserved_names:
        raise StateDirectorySecurityError(
            "mutable state database name conflicts with a reserved object"
        )

    try:
        root_details = _checked_kind(root)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(root_details.st_mode):
        raise StateDirectorySecurityError("mutable state root is not a directory")

    allowed_files = set(_DEDICATED_STATE_ROOT_FILES)
    allowed_files.update(
        {
            database_name,
            *(f"{database_name}{suffix}" for suffix in ("-wal", "-shm", "-journal")),
        }
    )
    observed = 0
    with os.scandir(root) as entries:
        for entry in entries:
            observed += 1
            if observed > _MAXIMUM_DEDICATED_STATE_ROOT_ENTRIES:
                raise StateDirectorySecurityError(
                    "mutable state directory is not a dedicated Gatehouse root"
                )
            name = entry.name
            if name in allowed_files:
                expected_directory = False
            elif name in _DEDICATED_STATE_ROOT_DIRECTORIES:
                expected_directory = True
            else:
                raise StateDirectorySecurityError(
                    "mutable state directory is not a dedicated Gatehouse root"
                )
            details = _checked_kind(Path(entry.path))
            if expected_directory:
                valid_kind = stat.S_ISDIR(details.st_mode)
            else:
                valid_kind = stat.S_ISREG(details.st_mode)
            if not valid_kind:
                raise StateDirectorySecurityError(
                    "mutable state directory contains an invalid managed object"
                )


def secure_database_state(
    path: str | Path,
    *,
    must_exist: bool = False,
    _backend: _PrivateAclBackend | None = None,
    _volume_probe: StateVolumeProbe | None = None,
) -> Path:
    """Secure one dedicated SQLite state root and every known live sidecar."""

    database = _absolute_state_path(path, _volume_probe=_volume_probe)
    managed_files = (
        database,
        *(Path(f"{database}{suffix}") for suffix in ("-wal", "-shm", "-journal")),
    )
    try:
        backend = _selected_backend_for_operation(_backend)
        if must_exist:
            if backend is None:
                if not database.parent.is_dir():
                    raise StateDirectorySecurityError("mutable state directory is unavailable")
            else:
                _reject_reparse_ancestry(database.parent)
                try:
                    parent_details = _checked_kind(database.parent)
                except FileNotFoundError:
                    raise StateDirectorySecurityError(
                        "mutable state directory is unavailable"
                    ) from None
                if not stat.S_ISDIR(parent_details.st_mode):
                    raise StateDirectorySecurityError("mutable state directory is unavailable")

        existing_files: list[bool] = []
        for managed_file in managed_files:
            if backend is None:
                existing_files.append(managed_file.is_file())
                continue
            _reject_reparse_ancestry(managed_file)
            try:
                details = _checked_kind(managed_file)
            except FileNotFoundError:
                existing_files.append(False)
                continue
            if not stat.S_ISREG(details.st_mode):
                raise StateDirectorySecurityError("mutable state file is not a regular file")
            existing_files.append(True)
    except StateDirectorySecurityError:
        raise
    except OSError:
        raise StateDirectorySecurityError(
            "mutable state permissions could not be secured"
        ) from None
    if must_exist and not existing_files[0]:
        raise StateDirectorySecurityError("mutable state database is unavailable")
    if backend is not None:
        try:
            _preflight_dedicated_database_root(database)
        except StateDirectorySecurityError:
            raise
        except OSError:
            raise StateDirectorySecurityError(
                "mutable state directory could not be verified"
            ) from None
    secure_private_directory(
        database.parent,
        must_exist=must_exist,
        _backend=_backend,
        _volume_probe=_volume_probe,
    )
    for index, managed_file in enumerate(managed_files):
        secured = secure_private_file(
            managed_file,
            _backend=_backend,
            _volume_probe=_volume_probe,
        )
        if index == 0 and must_exist and not secured:
            raise StateDirectorySecurityError("mutable state database is unavailable")
    return database
