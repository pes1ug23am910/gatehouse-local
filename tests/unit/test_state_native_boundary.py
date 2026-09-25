"""Owned state operations through synthetic handle and security adapters."""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, TypedDict, cast

import pytest

from gatehouse.state_windows import (
    NativeStateFilesystem,
    StateAccessRule,
    StateObjectFacts,
    WindowsPrivateAcl,
)

USER = "S-1-5-21-100-200-300-1001"
OTHER = "S-1-5-21-100-200-300-1002"
SYSTEM = "S-1-5-18"
FULL = 0x001F01FF


def _facts(path: str, identity: int, *, directory: bool = True) -> StateObjectFacts:
    return StateObjectFacts(
        final_path=path,
        volume_serial=1,
        file_id=identity,
        directory=directory,
        reparse=False,
        links=1,
        drive_type=3,
        filesystem="NTFS",
        owner_sid=USER,
        protected=True,
        rules=(StateAccessRule(USER, FULL, 3 if directory else 0, 0),),
    )


class _FactsMutation(TypedDict, total=False):
    owner_sid: str
    reparse: bool
    directory: bool
    drive_type: int
    filesystem: str
    rules: tuple[StateAccessRule, ...] | None
    final_path: str
    file_id: int
    links: int


class FakeStateFilesystem:
    execution_sid = USER

    def __init__(self) -> None:
        self.objects = {
            "C:\\": replace(_facts("C:\\", 1), owner_sid=SYSTEM),
            r"C:\Trusted": _facts(r"C:\Trusted", 2),
        }
        self.handles: dict[int, StateObjectFacts] = {}
        self.opened: list[tuple[str, bool, int]] = []
        self.exclusive: list[str] = []
        self.closed: list[int] = []
        self.created: list[tuple[str, str]] = []
        self.secured: list[tuple[int, bool, str]] = []
        self.next_handle = 1
        self.fail_create: str | None = None
        self.change_after_secure = False
        self.close_failure = False
        self.interruption: BaseException | None = None
        self.close_interruption: BaseException | None = None
        self.describe_missing: str | None = None

    def open_existing(
        self,
        path: str,
        *,
        writable: bool = False,
        exclusive: bool = False,
    ) -> object:
        if path not in self.objects:
            raise FileNotFoundError("synthetic absence")
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = self.objects[path]
        self.opened.append((path, writable, handle))
        if exclusive:
            self.exclusive.append(path)
        return handle

    def describe(self, handle: object) -> StateObjectFacts:
        assert type(handle) is int
        if self.handles[handle].final_path == self.describe_missing:
            raise FileNotFoundError("synthetic metadata failure after open")
        return self.handles[handle]

    def create_directory(self, path: str, *, owner_sid: str) -> None:
        parent = str(PureWindowsPath(path).parent)
        assert any(record.final_path == parent for record in self.handles.values())
        assert path not in self.objects
        if path == self.fail_create:
            raise FileExistsError("synthetic collision")
        self.objects[path] = _facts(path, 100 + len(self.created))
        self.created.append((path, owner_sid))

    def set_private_acl(self, handle: object, *, is_directory: bool, owner_sid: str) -> None:
        assert type(handle) is int
        if self.interruption is not None:
            raise self.interruption
        record = self.handles[handle]
        self.secured.append((handle, is_directory, owner_sid))
        self.handles[handle] = replace(
            record,
            file_id=record.file_id + (1 if self.change_after_secure else 0),
            protected=True,
            rules=(StateAccessRule(owner_sid, FULL, 3 if is_directory else 0, 0),),
        )

    def close(self, handle: object) -> None:
        assert type(handle) is int
        self.closed.append(handle)
        del self.handles[handle]
        if self.close_interruption is not None:
            raise self.close_interruption
        if self.close_failure:
            raise OSError("synthetic close failure")


def _backend() -> tuple[WindowsPrivateAcl, FakeStateFilesystem]:
    filesystem = FakeStateFilesystem()
    return WindowsPrivateAcl(filesystem=filesystem), filesystem


@pytest.mark.parametrize(
    "owner",
    [
        USER,
        SYSTEM,
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ],
    ids=["user", "system", "administrators", "trusted-installer"],
)
@pytest.mark.parametrize("operation", ["create", "secure"])
def test_owner_rights_bind_trusted_ancestor_and_creation_parent(
    owner: str,
    operation: str,
) -> None:
    backend, filesystem = _backend()
    parent = r"C:\Trusted"
    filesystem.objects[parent] = replace(
        filesystem.objects[parent],
        owner_sid=owner,
        rules=(StateAccessRule("S-1-3-4", FULL, 3, 0),),
    )
    target = Path(r"C:\Trusted\state")
    if operation == "create":
        backend.create_directory(target)
        assert filesystem.created == [(str(target), USER)]
        assert filesystem.objects[str(target)].rules == (StateAccessRule(USER, FULL, 3, 0),)
    else:
        filesystem.objects[str(target)] = _facts(str(target), 3)
        backend.secure(target, is_directory=True)
        assert len(filesystem.secured) == 1
    assert not filesystem.handles and len(filesystem.closed) == 3


@pytest.mark.parametrize(
    "owner,grants",
    [
        (OTHER, ("S-1-3-4",)),
        ("S-1-3-4", ("S-1-3-4",)),
        ("malformed", ("S-1-3-4",)),
        (USER, ("S-1-3-4", OTHER)),
        (USER, ("S-1-3-4", "S-1-3-0")),
        (USER, ("S-1-3-0",)),
    ],
    ids=[
        "foreign-owner",
        "dynamic-owner",
        "malformed-owner",
        "foreign-grant",
        "creator-mixed",
        "creator-only",
    ],
)
@pytest.mark.parametrize("operation", ["create", "secure"])
def test_owner_rights_do_not_hide_foreign_ownership_or_other_mutation_grants(
    owner: str,
    grants: tuple[str, ...],
    operation: str,
) -> None:
    backend, filesystem = _backend()
    parent = r"C:\Trusted"
    filesystem.objects[parent] = replace(
        filesystem.objects[parent],
        owner_sid=owner,
        rules=tuple(StateAccessRule(sid, FULL, 3, 0) for sid in grants),
    )
    target = Path(r"C:\Trusted\state")
    if operation == "secure":
        filesystem.objects[str(target)] = _facts(str(target), 3)
    with pytest.raises(OSError):
        if operation == "create":
            backend.create_directory(target)
        else:
            backend.secure(target, is_directory=True)
    assert filesystem.created == [] and filesystem.secured == [] and not filesystem.handles


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("include_exact_owner", [False, True])
def test_owner_rights_cannot_satisfy_exact_private_state_postcondition(
    directory: bool,
    include_exact_owner: bool,
) -> None:
    backend, _filesystem = _backend()
    path = r"C:\Trusted\state"
    original = _facts(path, 3, directory=directory)
    rules = original.rules if include_exact_owner else ()
    assert rules is not None
    facts = replace(
        original,
        rules=(*rules, StateAccessRule("S-1-3-4", FULL, 3 if directory else 0, 0)),
    )
    with pytest.raises(OSError):
        backend._require(facts, path, directory=directory, private=True)


@pytest.mark.parametrize("directory", [False, True])
def test_securing_owned_target_replaces_owner_rights_with_exact_private_acl(
    directory: bool,
) -> None:
    backend, filesystem = _backend()
    target = r"C:\Trusted\state"
    filesystem.objects[target] = replace(
        _facts(target, 3, directory=directory),
        protected=False,
        rules=(StateAccessRule("S-1-3-4", FULL, 3 if directory else 0, 0),),
    )
    backend.secure(Path(target), is_directory=directory)
    assert filesystem.secured == [(3, directory, USER)] and not filesystem.handles


@pytest.mark.parametrize("new_owner", [SYSTEM, OTHER], ids=["trusted-drift", "foreign-drift"])
@pytest.mark.parametrize("operation", ["create", "secure"])
def test_owner_rights_owner_drift_on_retained_handle_refuses_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    new_owner: str,
    operation: str,
) -> None:
    backend, filesystem = _backend()
    parent = r"C:\Trusted"
    filesystem.objects[parent] = replace(
        filesystem.objects[parent],
        rules=(StateAccessRule("S-1-3-4", FULL, 3, 0),),
    )
    describe = filesystem.describe
    parent_reads = 0

    def changing_owner(handle: object) -> StateObjectFacts:
        nonlocal parent_reads
        facts = describe(handle)
        if facts.final_path == parent:
            parent_reads += 1
            if parent_reads > 1:
                return replace(facts, owner_sid=new_owner)
        return facts

    monkeypatch.setattr(filesystem, "describe", changing_owner)
    target = Path(r"C:\Trusted\state")
    if operation == "secure":
        filesystem.objects[str(target)] = _facts(str(target), 3)
    with pytest.raises(OSError):
        if operation == "create":
            backend.create_directory(target)
        else:
            backend.secure(target, is_directory=True)
    assert parent_reads == 2
    assert filesystem.created == [] and filesystem.secured == [] and not filesystem.handles


def test_missing_state_directories_are_private_at_creation_under_retained_ancestry() -> None:
    backend, filesystem = _backend()
    backend.create_directory(Path(r"C:\Trusted\new\state"))
    assert filesystem.created == [(r"C:\Trusted\new", USER), (r"C:\Trusted\new\state", USER)]
    assert filesystem.secured == []
    assert [path for path, _writable, _handle in filesystem.opened] == [
        "C:\\",
        r"C:\Trusted",
        r"C:\Trusted\new",
        r"C:\Trusted\new\state",
    ]
    assert filesystem.closed == [4, 3, 2, 1]
    assert not filesystem.handles
    for path, _owner in filesystem.created:
        assert filesystem.objects[path].protected
        assert filesystem.objects[path].rules == (StateAccessRule(USER, FULL, 3, 0),)


@pytest.mark.parametrize("directory", [False, True])
def test_existing_state_acl_changes_and_verifies_the_same_owned_handle(directory: bool) -> None:
    backend, filesystem = _backend()
    target = r"C:\Trusted\state"
    filesystem.objects[target] = _facts(target, 3, directory=directory)
    backend.secure(Path(target), is_directory=directory)
    assert filesystem.opened == [("C:\\", False, 1), (r"C:\Trusted", False, 2), (target, True, 3)]
    assert filesystem.secured == [(3, directory, USER)]
    assert filesystem.exclusive == ([target] if directory else [])
    assert filesystem.closed == [3, 2, 1] and not filesystem.handles


@pytest.mark.parametrize(
    "mutation",
    [
        {"owner_sid": OTHER},
        {"reparse": True},
        {"directory": False},
        {"drive_type": 4},
        {"filesystem": "ReFS"},
        {"rules": None},
        {"rules": (StateAccessRule(OTHER, 0x00000040, 0, 0),)},
        {"rules": (StateAccessRule(OTHER, 0x00040000, 0, 0),)},
        {"rules": (StateAccessRule(OTHER, 0x00080000, 0, 0),)},
        {"rules": (StateAccessRule(OTHER, 0x40000000, 0, 0),)},
        {"rules": (StateAccessRule(USER, FULL, 0, 9),)},
        {"final_path": r"C:\Another"},
        {"file_id": 0},
    ],
    ids=[
        "foreign_owner",
        "reparse",
        "not_directory",
        "remote",
        "not_ntfs",
        "null_dacl",
        "delete_child",
        "write_dacl",
        "write_owner",
        "generic_write",
        "unsupported_ace",
        "different_path",
        "invalid_identity",
    ],
)
@pytest.mark.parametrize("operation", ["create", "secure"])
def test_untrusted_ancestors_refuse_before_state_mutation(
    mutation: _FactsMutation, operation: str
) -> None:
    backend, filesystem = _backend()
    filesystem.objects[r"C:\Trusted"] = replace(filesystem.objects[r"C:\Trusted"], **mutation)
    target = Path(r"C:\Trusted\state")
    if operation == "secure":
        filesystem.objects[str(target)] = _facts(str(target), 3)
    with pytest.raises(OSError, match="private-state"):
        if operation == "create":
            backend.create_directory(target)
        else:
            backend.secure(target, is_directory=True)
    assert filesystem.created == [] and filesystem.secured == []
    assert not filesystem.handles


def test_read_only_untrusted_ancestor_ace_does_not_grant_mutation() -> None:
    backend, filesystem = _backend()
    parent = filesystem.objects[r"C:\Trusted"]
    filesystem.objects[r"C:\Trusted"] = replace(
        parent,
        rules=(
            *cast(tuple[StateAccessRule, ...], parent.rules),
            StateAccessRule(OTHER, 0x001200A9, 0, 0),
        ),
    )
    backend.create_directory(Path(r"C:\Trusted\state"))
    assert filesystem.created == [(r"C:\Trusted\state", USER)]


@pytest.mark.parametrize("mask", [2, 4, 6])
@pytest.mark.parametrize("operation", ["create", "secure"])
def test_existing_ancestor_child_creation_does_not_authorize_replacement(
    mask: int,
    operation: str,
) -> None:
    backend, filesystem = _backend()
    root = filesystem.objects["C:\\"]
    filesystem.objects["C:\\"] = replace(
        root,
        rules=(*cast(tuple[StateAccessRule, ...], root.rules), StateAccessRule(OTHER, mask, 0, 0)),
    )
    target = Path(r"C:\Trusted\state")
    if operation == "create":
        backend.create_directory(target)
        assert filesystem.created == [(str(target), USER)]
    else:
        filesystem.objects[str(target)] = _facts(str(target), 3)
        backend.secure(target, is_directory=True)
        assert len(filesystem.secured) == 1
    assert not filesystem.handles


@pytest.mark.parametrize("mask", [2, 4, 6])
@pytest.mark.parametrize("operation", ["create", "secure"])
def test_child_creation_rights_are_rejected_on_creation_parent_or_acl_target(
    mask: int,
    operation: str,
) -> None:
    backend, filesystem = _backend()
    target = Path(r"C:\Trusted\state")
    location = r"C:\Trusted" if operation == "create" else str(target)
    original = filesystem.objects.setdefault(location, _facts(location, 3))
    filesystem.objects[location] = replace(
        original,
        rules=(
            *cast(tuple[StateAccessRule, ...], original.rules),
            StateAccessRule(OTHER, mask, 0, 0),
        ),
    )
    with pytest.raises(OSError):
        if operation == "create":
            backend.create_directory(target)
        else:
            backend.secure(target, is_directory=True)
    assert filesystem.created == [] and filesystem.secured == []
    assert not filesystem.handles


@pytest.mark.parametrize(
    "mutation",
    [
        {"owner_sid": OTHER},
        {"reparse": True},
        {"links": 2},
        {"directory": True},
    ],
    ids=["owner", "reparse", "hardlink", "kind"],
)
def test_unsafe_existing_file_refuses_acl_mutation(mutation: _FactsMutation) -> None:
    backend, filesystem = _backend()
    path = r"C:\Trusted\state"
    filesystem.objects[path] = replace(_facts(path, 3, directory=False), **mutation)
    with pytest.raises(OSError, match="private-state"):
        backend.secure(Path(path), is_directory=False)
    assert filesystem.secured == [] and not filesystem.handles


def test_creation_collision_refuses_without_adoption_or_cleanup() -> None:
    backend, filesystem = _backend()
    filesystem.fail_create = r"C:\Trusted\new\state"
    with pytest.raises(OSError):
        backend.create_directory(Path(filesystem.fail_create))
    assert filesystem.created == [(r"C:\Trusted\new", USER)]
    assert r"C:\Trusted\new" in filesystem.objects
    assert not filesystem.handles and filesystem.secured == []


def test_create_operation_never_adopts_an_existing_final_directory() -> None:
    backend, filesystem = _backend()
    with pytest.raises(OSError, match="private-state"):
        backend.create_directory(Path(r"C:\Trusted"))
    assert filesystem.created == [] and filesystem.secured == [] and not filesystem.handles


def test_changed_identity_after_acl_application_is_not_reported_as_verified() -> None:
    backend, filesystem = _backend()
    filesystem.objects[r"C:\Trusted\state"] = _facts(r"C:\Trusted\state", 3)
    filesystem.change_after_secure = True
    with pytest.raises(OSError, match="private-state"):
        backend.secure(Path(r"C:\Trusted\state"), is_directory=True)
    assert len(filesystem.secured) == 1 and not filesystem.handles


def test_metadata_absence_after_open_is_not_treated_as_a_missing_directory() -> None:
    backend, filesystem = _backend()
    filesystem.describe_missing = r"C:\Trusted"
    with pytest.raises(OSError):
        backend.create_directory(Path(r"C:\Trusted\state"))
    assert filesystem.created == [] and not filesystem.handles


def test_handle_close_failure_does_not_report_success_and_attempts_all_closures() -> None:
    backend, filesystem = _backend()
    filesystem.close_failure = True
    with pytest.raises(OSError, match="private-state"):
        backend.create_directory(Path(r"C:\Trusted\state"))
    assert filesystem.closed == [3, 2, 1] and not filesystem.handles


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_cleanup_failure_does_not_replace_control_flow_interruption(
    interruption: type[BaseException],
) -> None:
    backend, filesystem = _backend()
    filesystem.objects[r"C:\Trusted\state"] = _facts(r"C:\Trusted\state", 3)
    signal = interruption("synthetic interruption")
    filesystem.interruption = signal
    filesystem.close_failure = True
    with pytest.raises(interruption) as caught:
        backend.secure(Path(r"C:\Trusted\state"), is_directory=True)
    assert caught.value is signal
    assert filesystem.closed == [3, 2, 1] and not filesystem.handles


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_control_flow_interruption_during_cleanup_propagates_after_other_closures(
    interruption: type[BaseException],
) -> None:
    backend, filesystem = _backend()
    signal = interruption("synthetic close interruption")
    filesystem.close_interruption = signal
    with pytest.raises(interruption) as caught:
        backend.create_directory(Path(r"C:\Trusted\state"))
    assert caught.value is signal
    assert filesystem.closed == [3, 2, 1] and not filesystem.handles


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_cleanup_interruption_is_not_suppressed_by_an_ordinary_body_error(
    interruption: type[BaseException],
) -> None:
    backend, filesystem = _backend()
    signal = interruption("synthetic close interruption")
    filesystem.describe_missing = r"C:\Trusted"
    filesystem.close_interruption = signal
    with pytest.raises(interruption) as caught:
        backend.create_directory(Path(r"C:\Trusted\state"))
    assert caught.value is signal
    assert filesystem.closed == [2, 1] and not filesystem.handles


def test_ordinary_native_failure_exposes_only_fixed_error_fields() -> None:
    backend, filesystem = _backend()
    filesystem.describe_missing = r"C:\Trusted"
    with pytest.raises(OSError) as caught:
        backend.create_directory(Path(r"C:\Trusted\state"))
    error = caught.value
    assert error.args == ("Windows private-state operation could not be verified",)
    assert error.__context__ is error.__cause__ is error.filename is None
    assert error.__dict__ == {}


@pytest.mark.parametrize(
    "path",
    [
        "state",
        r"C:state",
        r"\\server\share\state",
        r"C:\Trusted\..\state",
        r"C:\Trusted\NUL",
        "C:\\" + "a" * 4096,
    ],
)
def test_unsupported_paths_refuse_before_open_or_create(path: str) -> None:
    backend, filesystem = _backend()
    with pytest.raises(OSError, match="private-state"):
        backend.create_directory(Path(path))
    assert filesystem.opened == [] and filesystem.created == []


class _Call:
    def __init__(self, action: Callable[..., object]) -> None:
        self.action = action
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *arguments: Any) -> object:
        self.calls.append(arguments)
        return self.action(*arguments)


class _NativeReader:
    execution_sid = USER

    def __init__(self) -> None:
        self.descriptor = ctypes.create_string_buffer(128)
        self.create_result = 1
        self.set_result: object = 0
        self.free_result = 0
        self.interruption: BaseException | None = None
        self.free_interruption: BaseException | None = None
        self.dacl_offset = 32
        self.closed: list[object] = []
        self._api = SimpleNamespace(
            kernel32=SimpleNamespace(
                CreateFileW=_Call(lambda *arguments: 123),
                CreateDirectoryW=_Call(self._create),
                LocalFree=_Call(self._free),
            ),
            advapi=SimpleNamespace(
                ConvertStringSecurityDescriptorToSecurityDescriptorW=_Call(self._convert),
                GetSecurityDescriptorDacl=_Call(self._dacl),
                SetSecurityInfo=_Call(self._set),
            ),
            ntdll=SimpleNamespace(NtSetSecurityObject=_Call(self._set)),
            error_code=lambda: 5,
        )

    def _convert(self, _text: str, _revision: int, descriptor: Any, size: Any) -> int:
        descriptor._obj.value = ctypes.addressof(self.descriptor)
        size._obj.value = ctypes.sizeof(self.descriptor)
        return 1

    def _dacl(self, _descriptor: object, present: Any, dacl: Any, defaulted: Any) -> int:
        present._obj.value = 1
        defaulted._obj.value = 0
        dacl._obj.value = ctypes.addressof(self.descriptor) + self.dacl_offset
        return 1

    def _create(self, _path: str, attributes: Any) -> int:
        assert attributes._obj.descriptor == ctypes.addressof(self.descriptor)
        assert attributes._obj.length == ctypes.sizeof(attributes._obj)
        assert not attributes._obj.inherit_handle
        if self.interruption is not None:
            raise self.interruption
        return self.create_result

    def _set(self, *_arguments: object) -> object:
        if self.interruption is not None:
            raise self.interruption
        return self.set_result

    def _free(self, _pointer: object) -> int:
        if self.free_interruption is not None:
            raise self.free_interruption
        return self.free_result

    def _handle(self, handle: object) -> object:
        return handle

    def close(self, handle: object) -> None:
        self.closed.append(handle)


@pytest.mark.parametrize(
    "writable,exclusive,access,sharing",
    [
        (False, False, 0x00020080, 3),
        (True, False, 0x00060080, 3),
        (True, True, 0x00060080, 0),
    ],
)
def test_native_opens_do_not_follow_reparse_points_or_share_delete(
    writable: bool,
    exclusive: bool,
    access: int,
    sharing: int,
) -> None:
    reader = _NativeReader()
    native = NativeStateFilesystem(reader=reader)
    handle = native.open_existing(r"C:\Trusted\state", writable=writable, exclusive=exclusive)
    assert reader._api.kernel32.CreateFileW.calls == [
        (r"C:\Trusted\state", access, sharing, None, 3, 0x02200000, None),
    ]
    native.close(handle)
    assert reader.closed == [handle]


def test_native_create_supplies_noninheritable_security_attributes_at_creation() -> None:
    reader = _NativeReader()
    native = NativeStateFilesystem(reader=reader)
    native.create_directory(r"C:\Trusted\state", owner_sid=USER)
    conversion = reader._api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.calls
    assert conversion[0][:2] == (f"O:{USER}D:P(A;OICI;FA;;;{USER})", 1)
    assert len(reader._api.kernel32.CreateDirectoryW.calls) == 1
    assert len(reader._api.kernel32.LocalFree.calls) == 1
    assert reader._api.advapi.SetSecurityInfo.calls == []


@pytest.mark.parametrize("directory,flags", [(True, "OICI"), (False, "")])
def test_native_acl_effect_uses_only_the_supplied_handle(directory: bool, flags: str) -> None:
    reader = _NativeReader()
    native = NativeStateFilesystem(reader=reader)
    native.set_private_acl(SimpleNamespace(value=321), is_directory=directory, owner_sid=USER)
    conversion = reader._api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.calls
    assert conversion[0][0] == f"O:{USER}D:P(A;{flags};FA;;;{USER})"
    call = reader._api.ntdll.NtSetSecurityObject.calls[0]
    assert call[:2] == (321, 4)
    assert call[2].value == ctypes.addressof(reader.descriptor)
    assert reader._api.advapi.SetSecurityInfo.calls == []
    assert len(reader._api.kernel32.LocalFree.calls) == 1
    assert reader._api.kernel32.CreateDirectoryW.calls == []


@pytest.mark.parametrize("operation", ["create", "secure"])
def test_native_effect_failure_still_releases_descriptor(operation: str) -> None:
    reader = _NativeReader()
    native = NativeStateFilesystem(reader=reader)
    reader.create_result, reader.set_result = 0, 5
    with pytest.raises(OSError):
        if operation == "create":
            native.create_directory(r"C:\Trusted\state", owner_sid=USER)
        else:
            native.set_private_acl(SimpleNamespace(value=321), is_directory=True, owner_sid=USER)
    assert len(reader._api.kernel32.LocalFree.calls) == 1


@pytest.mark.parametrize("offset", [-1, 121, 128, 256])
def test_native_dacl_pointer_outside_descriptor_refuses_before_mutation(offset: int) -> None:
    reader = _NativeReader()
    reader.dacl_offset = offset
    native = NativeStateFilesystem(reader=reader)
    with pytest.raises(OSError):
        native.set_private_acl(SimpleNamespace(value=321), is_directory=True, owner_sid=USER)
    assert reader._api.advapi.SetSecurityInfo.calls == []
    assert len(reader._api.kernel32.LocalFree.calls) == 1


@pytest.mark.parametrize("status", [1, -1, 0xC0000022, None, True])
def test_native_descriptor_effect_requires_exact_success(status: object) -> None:
    reader = _NativeReader()
    reader.set_result = status
    native = NativeStateFilesystem(reader=reader)
    with pytest.raises(OSError):
        native.set_private_acl(SimpleNamespace(value=321), is_directory=True, owner_sid=USER)
    assert len(reader._api.ntdll.NtSetSecurityObject.calls) == 1
    assert reader._api.advapi.SetSecurityInfo.calls == []
    assert len(reader._api.kernel32.LocalFree.calls) == 1


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_native_descriptor_cleanup_does_not_replace_an_interruption(
    interruption: type[BaseException],
) -> None:
    reader = _NativeReader()
    signal = interruption("synthetic native interruption")
    reader.interruption, reader.free_result = signal, 1
    native = NativeStateFilesystem(reader=reader)
    with pytest.raises(interruption) as caught:
        native.create_directory(r"C:\Trusted\state", owner_sid=USER)
    assert caught.value is signal
    assert len(reader._api.kernel32.LocalFree.calls) == 1


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_native_cleanup_interruption_is_not_suppressed_by_an_ordinary_effect_error(
    interruption: type[BaseException],
) -> None:
    reader = _NativeReader()
    signal = interruption("synthetic native cleanup interruption")
    reader.create_result, reader.free_interruption = 0, signal
    native = NativeStateFilesystem(reader=reader)
    with pytest.raises(interruption) as caught:
        native.create_directory(r"C:\Trusted\state", owner_sid=USER)
    assert caught.value is signal
    assert len(reader._api.kernel32.LocalFree.calls) == 1
