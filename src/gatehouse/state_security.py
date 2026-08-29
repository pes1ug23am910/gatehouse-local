"""Private mutable-state directories with an explicit Windows owner DACL."""

from __future__ import annotations

import ctypes
import os
import stat
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0x00
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERITED_ACE = 0x10
_FILE_ALL_ACCESS = 0x001F01FF
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_SDDL_REVISION_1 = 1
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
_DRIVE_REMOVABLE = 2
_DRIVE_FIXED = 3
_DRIVE_REMOTE = 4
_DRIVE_RAMDISK = 6
_LOCAL_MUTABLE_DRIVE_TYPES = frozenset({_DRIVE_REMOVABLE, _DRIVE_FIXED, _DRIVE_RAMDISK})


class StateDirectorySecurityError(RuntimeError):
    """The mutable-state root cannot meet Gatehouse's private-directory policy."""


class _PrivateAclBackend(Protocol):
    def secure(self, path: Path, *, is_directory: bool) -> None: ...


class _TokenUserRecord(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("attributes", wintypes.DWORD),
    ]


class _AclHeader(ctypes.Structure):
    _fields_ = [
        ("revision", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte),
        ("size", wintypes.WORD),
        ("ace_count", wintypes.WORD),
        ("reserved_two", wintypes.WORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("ace_type", ctypes.c_ubyte),
        ("ace_flags", ctypes.c_ubyte),
        ("ace_size", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("header", _AceHeader),
        ("mask", wintypes.DWORD),
        ("sid_start", wintypes.DWORD),
    ]


class _WindowsPrivateAcl:
    """Apply and independently verify one explicit current-user access rule."""

    def __init__(self) -> None:
        self._advapi: Any = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        self._kernel32: Any = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
        self._configure_signatures()
        self._user_sid = self._current_user_sid()

    def _configure_signatures(self) -> None:
        self._kernel32.GetCurrentProcess.argtypes = []
        self._kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p

        self._advapi.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self._advapi.OpenProcessToken.restype = wintypes.BOOL
        self._advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._advapi.GetTokenInformation.restype = wintypes.BOOL
        self._advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self._advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        self._advapi.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        self._advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        self._advapi.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
        self._advapi.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
        self._advapi.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
        self._advapi.GetAce.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi.GetAce.restype = wintypes.BOOL

    @staticmethod
    def _last_error() -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, "Windows private-state ACL operation failed")

    def _sid_string(self, sid: ctypes.c_void_p) -> str:
        rendered = wintypes.LPWSTR()
        if not self._advapi.ConvertSidToStringSidW(sid, ctypes.byref(rendered)):
            raise self._last_error()
        try:
            if not rendered.value:
                raise OSError("Windows returned an empty account identifier")
            return rendered.value
        finally:
            self._kernel32.LocalFree(rendered)

    def _current_user_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self._advapi.OpenProcessToken(
            self._kernel32.GetCurrentProcess(),
            _TOKEN_QUERY,
            ctypes.byref(token),
        ):
            raise self._last_error()
        try:
            required = wintypes.DWORD()
            self._advapi.GetTokenInformation(
                token,
                _TOKEN_USER,
                None,
                0,
                ctypes.byref(required),
            )
            if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or required.value == 0:
                raise self._last_error()
            buffer = ctypes.create_string_buffer(required.value)
            if not self._advapi.GetTokenInformation(
                token,
                _TOKEN_USER,
                buffer,
                required,
                ctypes.byref(required),
            ):
                raise self._last_error()
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUserRecord)).contents
            return self._sid_string(ctypes.c_void_p(token_user.sid))
        finally:
            self._kernel32.CloseHandle(token)

    def secure(self, path: Path, *, is_directory: bool) -> None:
        if self._owner_sid(path) != self._user_sid:
            raise OSError("private-state owner does not match the current Windows user")
        inheritance = "OICI" if is_directory else ""
        descriptor = ctypes.c_void_p()
        descriptor_size = wintypes.DWORD()
        sddl = f"D:P(A;{inheritance};FA;;;{self._user_sid})"
        if not self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            raise self._last_error()
        try:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not self._advapi.GetSecurityDescriptorDacl(
                descriptor,
                ctypes.byref(present),
                ctypes.byref(dacl),
                ctypes.byref(defaulted),
            ):
                raise self._last_error()
            if not present.value or not dacl.value:
                raise OSError("Windows returned an invalid private-state DACL")
            result = self._advapi.SetNamedSecurityInfoW(
                str(path),
                _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl,
                None,
            )
            if result:
                raise OSError(result, "Windows private-state DACL update failed")
        finally:
            self._kernel32.LocalFree(descriptor)
        self._verify(path, is_directory=is_directory)

    def _owner_sid(self, path: Path) -> str:
        owner = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = self._advapi.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if result:
            raise OSError(result, "Windows private-state owner verification failed")
        try:
            if not owner.value:
                raise OSError("Windows returned an invalid private-state owner")
            return self._sid_string(owner)
        finally:
            self._kernel32.LocalFree(descriptor)

    def _verify(self, path: Path, *, is_directory: bool) -> None:
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        result = self._advapi.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if result:
            raise OSError(result, "Windows private-state DACL verification failed")
        try:
            if not owner.value or self._sid_string(owner) != self._user_sid:
                raise OSError("private-state owner does not match the current Windows user")
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not self._advapi.GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                raise self._last_error()
            if not control.value & _SE_DACL_PROTECTED or not dacl.value:
                raise OSError("private-state DACL still permits inherited access")

            acl = ctypes.cast(dacl, ctypes.POINTER(_AclHeader)).contents
            if acl.ace_count != 1:
                raise OSError("private-state DACL contains unexpected access rules")
            ace_pointer = ctypes.c_void_p()
            if not self._advapi.GetAce(dacl, 0, ctypes.byref(ace_pointer)):
                raise self._last_error()
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
            expected_flags = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if is_directory else 0
            if (
                ace.header.ace_type != _ACCESS_ALLOWED_ACE_TYPE
                or ace.header.ace_flags & _INHERITED_ACE
                or ace.header.ace_flags != expected_flags
                or ace.mask != _FILE_ALL_ACCESS
            ):
                raise OSError("private-state DACL contains an unsafe access rule")
            sid_address = int(ace_pointer.value or 0) + _AccessAllowedAce.sid_start.offset
            if not sid_address or self._sid_string(ctypes.c_void_p(sid_address)) != self._user_sid:
                raise OSError("private-state DACL grants an unexpected account")
        finally:
            self._kernel32.LocalFree(descriptor)


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
    return int(_windows_drive_type_api()(root))


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


def _absolute_state_path(path: str | Path) -> Path:
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
        drive_type = _windows_drive_type(f"{drive}\\")
    except (AttributeError, OSError, TypeError, ValueError):
        raise StateDirectorySecurityError(
            "mutable state drive locality could not be verified"
        ) from None
    if drive_type not in _LOCAL_MUTABLE_DRIVE_TYPES:
        raise StateDirectorySecurityError("mutable state requires a local Windows drive")
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
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    if stat.S_ISLNK(details.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise StateDirectorySecurityError("mutable state cannot use a reparse point")
    if stat.S_ISREG(details.st_mode) and int(getattr(details, "st_nlink", 1)) != 1:
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


def validate_state_path_ancestry(path: str | Path) -> Path:
    """Validate existing path components without creating or changing an ACL."""

    resolved = _absolute_state_path(path)
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
) -> Path:
    """Create and secure one directory without following managed reparse points.

    On Windows the owner must be the current process user. Inheritance is removed
    and replaced with one inheritable full-control ACE for that exact user SID.
    Other platforms retain their existing permission model for development use.
    """

    if isinstance(maximum_entries, bool) or not 1 <= maximum_entries <= 200_000:
        raise ValueError("mutable state verification bound is invalid")
    resolved = _absolute_state_path(path)
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
            resolved.mkdir(parents=True, exist_ok=True)
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
) -> bool:
    """Secure an existing regular state file; return false when it is absent."""

    resolved = _absolute_state_path(path)
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
) -> Path:
    """Secure one dedicated SQLite state root and every known live sidecar."""

    database = _absolute_state_path(path)
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
    )
    for index, managed_file in enumerate(managed_files):
        secured = secure_private_file(managed_file, _backend=_backend)
        if index == 0 and must_exist and not secured:
            raise StateDirectorySecurityError("mutable state database is unavailable")
    return database
