"""Private Windows state creation and ACL changes under retained native ancestry."""

from __future__ import annotations

import ctypes
import re
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Protocol

_ERROR = "Windows private-state operation could not be verified"
_FULL_ACCESS = 0x001F01FF
_MUTATION_ACCESS = 0x000D0156 | 0x50000000
_OWNER_RIGHTS_SID = "S-1-3-4"
_TRUSTED_OS_SIDS = frozenset(
    {
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)
_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    | {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789¹²³"}
)


@dataclass(frozen=True, slots=True)
class StateAccessRule:
    sid: str
    mask: int
    flags: int
    kind: int


@dataclass(frozen=True, slots=True)
class StateObjectFacts:
    final_path: str
    volume_serial: int
    file_id: int
    directory: bool
    reparse: bool
    links: int
    drive_type: int
    filesystem: str
    owner_sid: str
    protected: bool
    rules: tuple[StateAccessRule, ...] | None


class StateFilesystem(Protocol):
    execution_sid: str

    def open_existing(
        self,
        path: str,
        *,
        writable: bool = False,
        exclusive: bool = False,
    ) -> object: ...
    def describe(self, handle: object) -> StateObjectFacts: ...
    def create_directory(self, path: str, *, owner_sid: str) -> None: ...
    def set_private_acl(self, handle: object, *, is_directory: bool, owner_sid: str) -> None: ...
    def close(self, handle: object) -> None: ...


def _sid(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 184
        and re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+){0,15}", value) is not None
    )


def _chain(path: Path) -> tuple[str, ...]:
    text = str(path)
    if not 4 <= len(text) <= 4096 or not text.isprintable():
        raise OSError(_ERROR)
    native = PureWindowsPath(text)
    if (
        not native.is_absolute()
        or len(native.drive) != 2
        or native.drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        or native.drive[1] != ":"
        or str(native) != text
    ):
        raise OSError(_ERROR)
    if not 2 <= len(native.parts) <= 256:
        raise OSError(_ERROR)
    for part in native.parts[1:]:
        if (
            not 1 <= len(part) <= 255
            or part in (".", "..")
            or part.startswith(" ")
            or part.endswith((" ", "."))
            or any(character in part for character in '<>:"/|?*~')
            or part.split(".", 1)[0].rstrip(" ").upper() in _RESERVED
        ):
            raise OSError(_ERROR)
    return tuple(str(item) for item in (*reversed(native.parents), native))


class WindowsPrivateAcl:
    """Use private creation and handle-bound ACL effects in the same-user v1 model.

    Ancestors are retained without delete sharing until the operation completes. Each
    existing ancestor must exclude mutation by untrusted principals. These checks do
    not isolate a hostile current user or trusted administrator, pin later consumer
    opens, or impose a preemptive deadline on synchronous Windows calls.
    """

    def __init__(self, *, filesystem: StateFilesystem | None = None) -> None:
        self._filesystem = NativeStateFilesystem() if filesystem is None else filesystem
        self._user_sid = self._filesystem.execution_sid
        if not _sid(self._user_sid):
            raise OSError(_ERROR)

    def _require(
        self,
        facts: StateObjectFacts,
        path: str,
        *,
        directory: bool,
        private: bool = False,
        allow_child_creation: bool = False,
    ) -> None:
        if (
            type(facts) is not StateObjectFacts
            or type(facts.final_path) is not str
            or facts.final_path != path
            or type(facts.volume_serial) is not int
            or not 0 <= facts.volume_serial <= 0xFFFFFFFF
            or type(facts.file_id) is not int
            or not 0 < facts.file_id <= 0xFFFFFFFFFFFFFFFF
            or type(facts.directory) is not bool
            or facts.directory is not directory
            or facts.reparse is not False
            or type(facts.links) is not int
            or not 1 <= facts.links <= 0xFFFFFFFF
            or (not directory and facts.links != 1)
            or type(facts.drive_type) is not int
            or facts.drive_type != 3
            or type(facts.filesystem) is not str
            or facts.filesystem != "NTFS"
            or not _sid(facts.owner_sid)
            or type(facts.protected) is not bool
            or type(facts.rules) is not tuple
            or len(facts.rules) > 128
        ):
            raise OSError(_ERROR)
        trusted = _TRUSTED_OS_SIDS | {self._user_sid}
        if facts.owner_sid not in trusted:
            raise OSError(_ERROR)
        # OWNER RIGHTS acts for this verified owner, never as a globally trusted SID.
        for rule in facts.rules:
            if (
                type(rule) is not StateAccessRule
                or not _sid(rule.sid)
                or type(rule.kind) is not int
                or rule.kind not in (0, 1)
                or type(rule.mask) is not int
                or not 0 <= rule.mask <= 0xFFFFFFFF
                or type(rule.flags) is not int
                or not 0 <= rule.flags <= 0x1F
                or (
                    rule.kind == 0
                    and not rule.flags & 0x08
                    and rule.sid not in trusted
                    and not (rule.sid == _OWNER_RIGHTS_SID and facts.owner_sid in trusted)
                    and rule.mask
                    & (
                        _MUTATION_ACCESS & ~0x06
                        if directory and allow_child_creation
                        else _MUTATION_ACCESS
                    )
                )
            ):
                raise OSError(_ERROR)
        if private and (
            facts.owner_sid != self._user_sid
            or not facts.protected
            or facts.rules
            != (
                StateAccessRule(
                    self._user_sid,
                    _FULL_ACCESS,
                    3 if directory else 0,
                    0,
                ),
            )
        ):
            raise OSError(_ERROR)

    @contextmanager
    def _handles(self) -> Iterator[list[object]]:
        handles: list[object] = []
        interrupted = False
        body_failed = False
        try:
            yield handles
        except Exception:
            body_failed = True
            raise
        except BaseException:
            interrupted = True
            raise
        finally:
            failed = False
            interruption: BaseException | None = None
            for handle in reversed(handles):
                try:
                    self._filesystem.close(handle)
                except Exception:
                    failed = True
                except BaseException as error:
                    if interruption is None:
                        interruption = error
            if interruption is not None and not interrupted:
                raise interruption
            if failed and not interrupted and not body_failed:
                raise OSError(_ERROR)

    def _open(
        self,
        path: str,
        handles: list[object],
        *,
        directory: bool,
        writable: bool = False,
        exclusive: bool = False,
        allow_child_creation: bool = False,
    ) -> tuple[object, StateObjectFacts]:
        handle = self._filesystem.open_existing(path, writable=writable, exclusive=exclusive)
        handles.append(handle)
        try:
            facts = self._filesystem.describe(handle)
        except FileNotFoundError:
            # Only an absent open permits creation; failed metadata never does.
            raise OSError(_ERROR) from None
        self._require(facts, path, directory=directory, allow_child_creation=allow_child_creation)
        return handle, facts

    def _recheck(self, ancestors: list[tuple[object, StateObjectFacts]]) -> None:
        for handle, original in ancestors:
            current = self._filesystem.describe(handle)
            self._require(current, original.final_path, directory=True, allow_child_creation=True)
            if current != original:
                raise OSError(_ERROR)

    def create_directory(self, path: Path) -> None:
        """Create a missing final directory; never adopt a creation collision.

        Every new component receives its private descriptor in CreateDirectoryW.
        A later failure can leave a private created prefix; no rollback is inferred.
        """
        try:
            chain = _chain(path)
            with self._handles() as handles:
                ancestors: list[tuple[object, StateObjectFacts]] = []
                for index, name in enumerate(chain):
                    if index == len(chain) - 1:
                        self._recheck(ancestors)
                        self._require(ancestors[-1][1], chain[index - 1], directory=True)
                        self._filesystem.create_directory(name, owner_sid=self._user_sid)
                        handle, facts = self._open(name, handles, directory=True)
                        self._require(facts, name, directory=True, private=True)
                    else:
                        try:
                            handle, facts = self._open(
                                name,
                                handles,
                                directory=True,
                                allow_child_creation=True,
                            )
                        except FileNotFoundError:
                            if not ancestors:
                                raise OSError(_ERROR) from None
                            self._recheck(ancestors)
                            self._require(ancestors[-1][1], chain[index - 1], directory=True)
                            self._filesystem.create_directory(name, owner_sid=self._user_sid)
                            handle, facts = self._open(name, handles, directory=True)
                            self._require(facts, name, directory=True, private=True)
                    ancestors.append((handle, facts))
                self._recheck(ancestors)
        except Exception:  # noqa: S110 - fixed refusal is raised outside the exception context
            pass
        else:
            return
        raise OSError(_ERROR) from None

    def secure(self, path: Path, *, is_directory: bool) -> None:
        """Check, change and verify the target using one non-following handle."""
        try:
            if type(is_directory) is not bool:
                raise OSError(_ERROR)
            chain = _chain(path)
            with self._handles() as handles:
                ancestors = [
                    self._open(name, handles, directory=True, allow_child_creation=True)
                    for name in chain[:-1]
                ]
                handle, before = self._open(
                    chain[-1],
                    handles,
                    directory=is_directory,
                    writable=True,
                    exclusive=is_directory,
                )
                if before.owner_sid != self._user_sid:
                    raise OSError(_ERROR)
                self._recheck(ancestors)
                self._filesystem.set_private_acl(
                    handle,
                    is_directory=is_directory,
                    owner_sid=self._user_sid,
                )
                after = self._filesystem.describe(handle)
                self._require(after, chain[-1], directory=is_directory, private=True)
                if (after.volume_serial, after.file_id) != (before.volume_serial, before.file_id):
                    raise OSError(_ERROR)
                self._recheck(ancestors)
        except Exception:  # noqa: S110 - fixed refusal is raised outside the exception context
            pass
        else:
            return
        raise OSError(_ERROR) from None


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("descriptor", ctypes.c_void_p),
        ("inherit_handle", wintypes.BOOL),
    ]


class NativeStateFilesystem:
    """Windows effects using the existing bounded native metadata/security reader."""

    def __init__(self, *, reader: Any = None) -> None:
        # Deferred import avoids config-loader/state-policy import cycles.
        if reader is None:
            from gatehouse.config.security import NativeConfigurationFilesystem

            reader = NativeConfigurationFilesystem()
        self._reader = reader
        self.execution_sid: str = reader.execution_sid
        self._api = reader._api
        self._object_api: Any = getattr(self._api, "ntdll", None)
        pointer = ctypes.c_void_p
        signatures = (
            (
                self._api.kernel32,
                "CreateDirectoryW",
                [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)],
                wintypes.BOOL,
            ),
            (
                self._api.advapi,
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                [
                    wintypes.LPCWSTR,
                    wintypes.DWORD,
                    ctypes.POINTER(pointer),
                    ctypes.POINTER(wintypes.DWORD),
                ],
                wintypes.BOOL,
            ),
            (
                self._api.advapi,
                "GetSecurityDescriptorDacl",
                [
                    pointer,
                    ctypes.POINTER(wintypes.BOOL),
                    ctypes.POINTER(pointer),
                    ctypes.POINTER(wintypes.BOOL),
                ],
                wintypes.BOOL,
            ),
            (
                self._api.advapi,
                "SetSecurityInfo",
                [
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    pointer,
                    pointer,
                    pointer,
                    pointer,
                ],
                wintypes.DWORD,
            ),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result

    def open_existing(
        self,
        path: str,
        *,
        writable: bool = False,
        exclusive: bool = False,
    ) -> object:
        from gatehouse.config.security import _NativeHandle

        access = 0x00020080 | (0x00040000 if writable else 0)
        # Explicit requested rights must all be granted for CreateFileW to succeed.
        # Ancestors and files permit readers/writers, never rename/delete.
        value = self._api.kernel32.CreateFileW(
            path,
            access,
            0 if exclusive else 3,
            None,
            3,
            0x02200000,
            None,
        )
        if value in {None, 0, -1, ctypes.c_void_p(-1).value}:
            code = self._api.error_code()
            if code in (2, 3):
                raise FileNotFoundError(_ERROR)
            raise OSError(_ERROR)
        return _NativeHandle(int(value), path)

    def describe(self, handle: object) -> StateObjectFacts:
        observed = self._reader.describe(handle)
        return StateObjectFacts(
            final_path=observed.final_path,
            volume_serial=observed.identity.volume_serial,
            file_id=observed.identity.file_id,
            directory=observed.is_directory,
            reparse=observed.reparse,
            links=observed.link_count,
            drive_type=observed.drive_type,
            filesystem=observed.filesystem,
            owner_sid=observed.owner_sid,
            protected=observed.dacl_protected,
            rules=None
            if observed.dacl is None
            else tuple(
                StateAccessRule(ace.sid, ace.mask, ace.flags, ace.kind) for ace in observed.dacl
            ),
        )

    @contextmanager
    def _descriptor(
        self,
        owner_sid: str,
        *,
        directory: bool,
    ) -> Iterator[tuple[ctypes.c_void_p, int]]:
        if not _sid(owner_sid):
            raise OSError(_ERROR)
        text = f"O:{owner_sid}D:P(A;{'OICI' if directory else ''};FA;;;{owner_sid})"
        descriptor = ctypes.c_void_p()
        size = wintypes.DWORD()
        if not self._api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text,
            1,
            ctypes.byref(descriptor),
            ctypes.byref(size),
        ):
            raise OSError(_ERROR)
        interrupted = False
        body_failed = False
        try:
            if not descriptor.value or not 20 <= size.value <= 65_536:
                raise OSError(_ERROR)
            yield descriptor, size.value
        except Exception:
            body_failed = True
            raise
        except BaseException:
            interrupted = True
            raise
        finally:
            try:
                failed = descriptor.value and self._api.kernel32.LocalFree(descriptor)
            except Exception:
                if not interrupted and not body_failed:
                    raise
            except BaseException:
                if not interrupted:
                    raise
            else:
                if failed and not interrupted and not body_failed:
                    raise OSError(_ERROR)

    def create_directory(self, path: str, *, owner_sid: str) -> None:
        with self._descriptor(owner_sid, directory=True) as (descriptor, _size):
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            if not self._api.kernel32.CreateDirectoryW(path, ctypes.byref(attributes)):
                raise OSError(_ERROR)

    def set_private_acl(self, handle: object, *, is_directory: bool, owner_sid: str) -> None:
        native = self._reader._handle(handle)
        with self._descriptor(owner_sid, directory=is_directory) as (descriptor, size):
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if (
                not self._api.advapi.GetSecurityDescriptorDacl(
                    descriptor,
                    ctypes.byref(present),
                    ctypes.byref(dacl),
                    ctypes.byref(defaulted),
                )
                or not present.value
                or defaulted.value
                or not dacl.value
            ):
                raise OSError(_ERROR)
            base = descriptor.value
            if base is None or not base <= dacl.value <= base + size - 8:
                raise OSError(_ERROR)
            # The Win32 SetSecurityInfo propagation helper changed an existing
            # child's protection flag even with MAXIMUM_ALLOWED. Apply this
            # bounded self-relative descriptor to the retained object directly.
            # DACL_SECURITY_INFORMATION leaves owner/group/SACL untouched.
            if self._object_api is None:
                self._object_api = ctypes.WinDLL("Ntdll.dll", use_last_error=True)
            setter = self._object_api.NtSetSecurityObject
            setter.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
            setter.restype = ctypes.c_int32
            status = setter(native.value, 4, descriptor)
            if type(status) is not int or status != 0:
                raise OSError(_ERROR)

    def close(self, handle: object) -> None:
        self._reader.close(handle)
