from __future__ import annotations

import ctypes
import hashlib
import json
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, TypedDict, cast

import pytest

import gatehouse.config.security as security
from gatehouse.config.security import (
    AccessRule,
    ConfigSecurityError,
    FileIdentity,
    NativeConfigurationFilesystem,
    ObjectSecurity,
    capture_configuration,
)

USER = "S-1-5-21-1-2-3-1001"
SYSTEM = "S-1-5-18"
OTHER = "S-1-5-21-4-5-6-1002"
ROOT = r"C:\Trusted\Config"
MAIN = ROOT + r"\config.yaml"
FULL = 0x001F01FF


class _ObjectChanges(TypedDict, total=False):
    identity: FileIdentity
    owner_sid: str
    dacl: tuple[AccessRule, ...] | None
    dacl_protected: bool
    reparse: bool
    link_count: int
    is_directory: bool
    drive_type: int
    filesystem: str
    final_path: str
    last_write: int
    creation_time: int
    size: int


class FakeFilesystem:
    execution_sid = USER

    def __init__(self) -> None:
        self.objects: dict[str, ObjectSecurity] = {}
        self.contents: dict[str, bytes] = {}
        self.members: dict[str, list[str]] = {}
        self.opened: list[SimpleNamespace] = []
        self.closed: list[object] = []
        self.reads: list[str] = []
        self.on_read: Any = None
        self.after_describe: Any = None
        self.add("C:\\", directory=True, ancestor=True)
        self.add(r"C:\Trusted", directory=True, ancestor=True)
        self.add(ROOT, directory=True)
        self.add(MAIN, content=b"schema_version: 1\n")
        self.members[ROOT] = ["config.yaml"]

    def add(
        self,
        path: str,
        *,
        directory: bool = False,
        ancestor: bool = False,
        content: bytes = b"",
    ) -> None:
        owner = SYSTEM if ancestor else USER
        self.objects[path] = ObjectSecurity(
            identity=FileIdentity(volume_serial=7, file_id=len(self.objects) + 1),
            final_path=path,
            is_directory=directory,
            owner_sid=owner,
            dacl=(AccessRule(sid=owner, mask=FULL, flags=3 if directory else 0),),
            dacl_protected=not ancestor,
            size=len(content),
        )
        if directory:
            self.members[path] = []
        else:
            self.contents[path] = content

    def open_existing(self, path: str) -> object:
        if path not in self.objects:
            raise FileNotFoundError("synthetic unavailable path")
        handle = SimpleNamespace(path=path, number=len(self.opened))
        self.opened.append(handle)
        return handle

    def describe(self, handle: Any) -> ObjectSecurity:
        result = self.objects[handle.path]
        if self.after_describe is not None:
            self.after_describe(handle)
        return result

    def read(self, handle: Any, maximum_bytes: int) -> bytes:
        self.reads.append(handle.path)
        result = self.contents[handle.path][: maximum_bytes + 1]
        if self.on_read is not None:
            self.on_read(handle)
        return result

    def entries(self, handle: Any) -> Any:
        return iter(tuple(self.members[handle.path]))

    def close(self, handle: object) -> None:
        self.closed.append(handle)


def test_snapshot_captures_immutable_bytes_and_frozen_environment() -> None:
    backend = FakeFilesystem()
    environment = {"APPDATA": r"C:\Profiles\App", "UNRELATED": "must-not-be-captured"}

    snapshot = capture_configuration(MAIN, backend=backend, environment=environment)
    environment["APPDATA"] = r"C:\Changed"
    backend.contents[MAIN] = b"changed after capture"

    assert snapshot.main_relative_path == "config.yaml"
    assert snapshot.document("config.yaml").content == b"schema_version: 1\n"
    assert snapshot.bound_environment == (("APPDATA", r"C:\Profiles\App"),)
    assert snapshot.matches_main_path(MAIN)
    assert not snapshot.matches_main_path(ROOT + r"\other.yaml")
    assert len(snapshot.manifest_digest) == 64
    assert backend.reads == [MAIN]
    assert backend.closed == list(reversed(backend.opened))
    with pytest.raises(FrozenInstanceError):
        snapshot.manifest_digest = "changed"  # type: ignore[misc]
    with pytest.raises(ConfigSecurityError):
        snapshot.document("missing.yaml")


def test_snapshot_reads_only_main_and_direct_yaml_documents_in_sorted_order() -> None:
    backend = FakeFilesystem()
    for directory in ("clients", "policies", "feeds"):
        parent = ROOT + "\\" + directory
        backend.add(parent, directory=True)
        backend.members[ROOT].append(directory)
        backend.add(parent + r"\one.yaml", content=b"key: value\n")
        backend.members[parent] = ["ignored.txt", "one.yaml"]

    snapshot = capture_configuration(MAIN, backend=backend, environment={})

    assert tuple(document.relative_path for document in snapshot.documents) == (
        "clients/one.yaml",
        "config.yaml",
        "feeds/one.yaml",
        "policies/one.yaml",
    )
    assert len(backend.reads) == 4
    assert all("ignored" not in path for path in backend.reads)


@pytest.mark.parametrize(
    "changes",
    [
        {"owner_sid": OTHER},
        {"dacl": None},
        {"dacl_protected": False},
        {"dacl": ()},
        {"dacl": (AccessRule(sid=OTHER, mask=FULL),)},
        {"dacl": (AccessRule(sid=USER, mask=FULL, flags=16),)},
        {"dacl": (AccessRule(sid=USER, mask=FULL, kind=1),)},
        {"dacl": (AccessRule(sid=USER, mask=0x00120089),)},
        {"dacl": (AccessRule(sid=USER, mask=FULL), AccessRule(sid=OTHER, mask=1))},
        {"reparse": True},
        {"link_count": 2},
        {"is_directory": True},
        {"drive_type": 2},
        {"drive_type": 4},
        {"filesystem": "ReFS"},
        {"final_path": ROOT + r"\CONFIG.yaml"},
    ],
)
def test_untrusted_configuration_file_fails_before_read(changes: _ObjectChanges) -> None:
    backend = FakeFilesystem()
    backend.objects[MAIN] = replace(backend.objects[MAIN], **changes)

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})

    assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("mask", [16, 64, 256, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000])
def test_untrusted_ancestor_mutation_authority_is_rejected(mask: int) -> None:
    backend = FakeFilesystem()
    path = r"C:\Trusted"
    backend.objects[path] = replace(
        backend.objects[path],
        dacl=backend.objects[path].dacl + (AccessRule(sid=OTHER, mask=mask),),  # type: ignore[operator]
    )

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})

    assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


def test_system_owned_ancestors_can_grant_read_only_access() -> None:
    backend = FakeFilesystem()
    path = r"C:\Trusted"
    backend.objects[path] = replace(
        backend.objects[path],
        dacl=(AccessRule(sid=SYSTEM, mask=FULL), AccessRule(sid=OTHER, mask=0x00120089)),
    )

    assert capture_configuration(MAIN, backend=backend, environment={}).documents


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
def test_owner_rights_on_config_ancestor_bind_only_its_verified_owner(owner: str) -> None:
    backend = FakeFilesystem()
    path = r"C:\Trusted"
    backend.objects[path] = replace(
        backend.objects[path],
        owner_sid=owner,
        dacl=(AccessRule(sid="S-1-3-4", mask=FULL, flags=3),),
    )
    assert capture_configuration(MAIN, backend=backend, environment={}).documents
    assert backend.closed == list(reversed(backend.opened))


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
def test_owner_rights_cannot_hide_untrusted_config_ownership_or_other_mutation(
    owner: str,
    grants: tuple[str, ...],
) -> None:
    backend = FakeFilesystem()
    path = r"C:\Trusted"
    backend.objects[path] = replace(
        backend.objects[path],
        owner_sid=owner,
        dacl=tuple(AccessRule(sid=sid, mask=FULL, flags=3) for sid in grants),
    )
    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == [] and backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("path", [ROOT, MAIN], ids=["private-root", "private-file"])
@pytest.mark.parametrize("include_exact_owner", [False, True])
def test_owner_rights_never_replace_exact_private_configuration_acl(
    path: str,
    include_exact_owner: bool,
) -> None:
    backend = FakeFilesystem()
    original = backend.objects[path]
    rules = original.dacl if include_exact_owner else ()
    assert rules is not None
    backend.objects[path] = replace(
        original,
        dacl=(*rules, AccessRule("S-1-3-4", FULL, 3 if path == ROOT else 0)),
    )
    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == [] and backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("new_owner", [SYSTEM, OTHER], ids=["trusted-drift", "foreign-drift"])
def test_owner_rights_config_capture_rejects_changed_owner_on_retained_ancestor(
    new_owner: str,
) -> None:
    backend = FakeFilesystem()
    path = r"C:\Trusted"
    original = replace(
        backend.objects[path],
        owner_sid=USER,
        dacl=(AccessRule("S-1-3-4", FULL, 3),),
    )
    backend.objects[path] = original
    backend.on_read = lambda _: backend.objects.__setitem__(
        path,
        replace(original, owner_sid=new_owner),
    )
    with pytest.raises(ConfigSecurityError, match="changed during capture"):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == [MAIN]
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("mask", [2, 4, 6])
@pytest.mark.parametrize("location", ["C:\\", ROOT])
def test_child_creation_rights_are_allowed_only_outside_private_configuration(
    mask: int,
    location: str,
) -> None:
    backend = FakeFilesystem()
    original = backend.objects[location]
    assert original.dacl is not None
    backend.objects[location] = replace(
        original,
        dacl=(*original.dacl, AccessRule(sid=OTHER, mask=mask)),
    )
    if location == ROOT:
        with pytest.raises(ConfigSecurityError):
            capture_configuration(MAIN, backend=backend, environment={})
        assert backend.reads == []
    else:
        assert capture_configuration(MAIN, backend=backend, environment={}).documents
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize(
    "changes",
    [
        {"identity": FileIdentity(volume_serial=7, file_id=900)},
        {"identity": FileIdentity(volume_serial=8, file_id=4)},
        {"last_write": 99},
        {"owner_sid": OTHER},
        {"dacl_protected": False},
        {"reparse": True},
    ],
)
def test_same_content_replacement_or_security_change_during_read_is_rejected(
    changes: _ObjectChanges,
) -> None:
    backend = FakeFilesystem()
    backend.on_read = lambda _handle: backend.objects.__setitem__(
        MAIN, replace(backend.objects[MAIN], **changes)
    )

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})

    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("entry", ["clients", "new.txt"])
def test_root_membership_change_including_optional_directory_creation_is_rejected(
    entry: str,
) -> None:
    backend = FakeFilesystem()
    backend.on_read = lambda _handle: backend.members[ROOT].append(entry)

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})


@pytest.mark.parametrize("members", [["config.yaml", "CONFIG.yaml"], ["config.yaml", "Clients"]])
def test_case_aliases_are_rejected_without_following_them(members: list[str]) -> None:
    backend = FakeFilesystem()
    backend.members[ROOT] = members

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})

    assert backend.reads == []


def test_ignored_entries_also_consume_the_directory_enumeration_limit() -> None:
    backend = FakeFilesystem()
    backend.members[ROOT] += [f"ignored-{index}.txt" for index in range(128)]

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})

    assert backend.reads == []


def test_file_limit_is_checked_before_an_unbounded_read() -> None:
    backend = FakeFilesystem()
    backend.objects[MAIN] = replace(backend.objects[MAIN], size=1_048_577)

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})

    assert backend.reads == []


def test_short_read_does_not_produce_a_snapshot() -> None:
    backend = FakeFilesystem()
    backend.contents[MAIN] = b"short"

    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})


def test_manifest_binds_file_identity_and_expansion_context() -> None:
    first = capture_configuration(MAIN, backend=FakeFilesystem(), environment={})
    backend = FakeFilesystem()
    backend.objects[MAIN] = replace(
        backend.objects[MAIN], identity=FileIdentity(volume_serial=7, file_id=100)
    )
    other_identity = capture_configuration(MAIN, backend=backend, environment={})
    other_environment = capture_configuration(
        MAIN, backend=FakeFilesystem(), environment={"APPDATA": r"C:\Synthetic"}
    )

    assert (
        len(
            {
                first.manifest_digest,
                other_identity.manifest_digest,
                other_environment.manifest_digest,
            }
        )
        == 3
    )


@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\config.yaml",
        r"\\?\C:\Trusted\Config\config.yaml",
        r"C:config.yaml",
        r"\config.yaml",
        r"C:\Trusted\Config\config.yaml:stream",
        r"C:\Trusted\Config\config.yaml.",
        r"C:\Trusted\Config\NUL.yaml",
        r"C:\Trusted\CONFIG~1\config.yaml",
        r"C:\Trusted\..\Config\config.yaml",
    ],
)
def test_unsafe_lexical_paths_fail_without_native_or_filesystem_access(path: str) -> None:
    backend = FakeFilesystem()

    with pytest.raises(ConfigSecurityError):
        capture_configuration(path, backend=backend, environment={})

    assert backend.opened == []


def test_capture_failure_is_path_free_and_closes_every_handle() -> None:
    backend = FakeFilesystem()

    def fail(_handle: object) -> None:
        raise OSError("private account and configuration detail")

    backend.on_read = fail
    with pytest.raises(ConfigSecurityError) as captured:
        capture_configuration(MAIN, backend=backend, environment={})

    assert "private" not in str(captured.value)
    assert "Config" not in str(captured.value)
    assert backend.closed == list(reversed(backend.opened))


def _configuration_tree(main: PureWindowsPath) -> FakeFilesystem:
    backend = FakeFilesystem()
    backend.objects.clear()
    backend.contents.clear()
    backend.members.clear()
    for parent in reversed((main.parent, *main.parent.parents)):
        backend.add(str(parent), directory=True, ancestor=parent != main.parent)
    backend.add(str(main), content=b"synthetic")
    backend.members[str(main.parent)] = [main.name]
    return backend


@pytest.mark.parametrize("total", [64, 65])
def test_document_count_exact_limit_and_one_over(total: int) -> None:
    backend = FakeFilesystem()
    parent = ROOT + r"\clients"
    backend.add(parent, directory=True)
    backend.members[ROOT].append("clients")
    for index in range(total - 1):
        name = f"client-{index:02}.yaml"
        backend.members[parent].append(name)
        backend.add(parent + "\\" + name, content=b"synthetic")
    if total == 64:
        snapshot = capture_configuration(MAIN, backend=backend, environment={})
        assert len(snapshot.documents) == total
        assert len(backend.reads) == total
    else:
        with pytest.raises(ConfigSecurityError, match="document bound"):
            capture_configuration(MAIN, backend=backend, environment={})
        assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("total", [128, 129])
def test_directory_count_exact_limit_and_one_over(total: int) -> None:
    backend = FakeFilesystem()
    backend.members[ROOT] += [f"ignored-{index}.txt" for index in range(total - 1)]
    if total == 128:
        assert len(capture_configuration(MAIN, backend=backend, environment={}).documents) == 1
    else:
        with pytest.raises(ConfigSecurityError, match="entry bound"):
            capture_configuration(MAIN, backend=backend, environment={})
        assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("size", [1_048_576, 1_048_577])
def test_file_bytes_exact_limit_and_one_over(size: int) -> None:
    backend = FakeFilesystem()
    backend.contents[MAIN] = b"x" * size
    backend.objects[MAIN] = replace(backend.objects[MAIN], size=size)
    if size == 1_048_576:
        assert (
            len(capture_configuration(MAIN, backend=backend, environment={}).documents[0].content)
            == size
        )
    else:
        with pytest.raises(ConfigSecurityError, match="byte bound"):
            capture_configuration(MAIN, backend=backend, environment={})
        assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("extra", [0, 1])
def test_aggregate_bytes_exact_limit_and_one_over(extra: int) -> None:
    backend = FakeFilesystem()
    backend.contents[MAIN] = b"x" * extra
    backend.objects[MAIN] = replace(backend.objects[MAIN], size=extra)
    parent = ROOT + r"\clients"
    backend.add(parent, directory=True)
    backend.members[ROOT].append("clients")
    for index in range(4):
        name = f"{index}.yaml"
        backend.members[parent].append(name)
        backend.add(parent + "\\" + name, content=b"x" * 1_048_576)
    if not extra:
        snapshot = capture_configuration(MAIN, backend=backend, environment={})
        assert sum(len(document.content) for document in snapshot.documents) == 4_194_304
    else:
        with pytest.raises(ConfigSecurityError, match="byte bound"):
            capture_configuration(MAIN, backend=backend, environment={})
        assert MAIN not in backend.reads
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("count", [64, 65])
def test_ancestry_exact_limit_and_one_over(count: int) -> None:
    main = PureWindowsPath("C:\\", *["part"] * (count - 1), "config.yaml")
    backend = _configuration_tree(main)
    if count == 64:
        assert capture_configuration(str(main), backend=backend, environment={}).documents
        assert len(backend.opened) == count + 1
    else:
        with pytest.raises(ConfigSecurityError, match="ancestry"):
            capture_configuration(str(main), backend=backend, environment={})
        assert backend.opened == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("extra", [0, 1])
def test_aggregate_path_text_exact_limit_and_one_over(extra: int) -> None:
    root = PureWindowsPath("C:\\", "a" * 238, *["b" * 237] * 20, "c" * 238)
    main = root / ("configx.yaml" if extra else "config.yaml")
    paths = (root, *root.parents, main)
    assert sum(len(str(path)) for path in paths) == 65_536 + extra
    assert all(len(part) <= 255 for part in main.parts)
    backend = _configuration_tree(main)
    if not extra:
        assert capture_configuration(str(main), backend=backend, environment={}).documents
    else:
        with pytest.raises(ConfigSecurityError, match="aggregate bound"):
            capture_configuration(str(main), backend=backend, environment={})
        assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("extra", [0, 1])
def test_environment_text_exact_limit_and_one_over(extra: int) -> None:
    backend = FakeFilesystem()
    environment = {"APPDATA": "x" * (65_536 - len("APPDATA") + extra)}
    if not extra:
        snapshot = capture_configuration(MAIN, backend=backend, environment=environment)
        assert snapshot.bound_environment == tuple(environment.items())
    else:
        with pytest.raises(ConfigSecurityError, match="expansion context"):
            capture_configuration(MAIN, backend=backend, environment=environment)
        assert backend.opened == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize(
    "environment",
    [
        {"APPDATA": "x", "appdata": "y"},
        {"APPDATA": "x\x00"},
        {"LOCALAPPDATA": "x\n"},
        {"LOCALAPPDATA": "x\r"},
        {"APPDATA": 1},
    ],
)
def test_invalid_environment_is_rejected_before_capture(environment: Any) -> None:
    backend = FakeFilesystem()
    with pytest.raises(ConfigSecurityError, match="expansion context"):
        capture_configuration(MAIN, backend=backend, environment=environment)
    assert backend.opened == []


@pytest.mark.parametrize("path", ["C:\\", r"C:\Trusted", ROOT, MAIN])
def test_cross_volume_identity_is_rejected_without_document_reads(path: str) -> None:
    backend = FakeFilesystem()
    backend.objects[path] = replace(backend.objects[path], identity=FileIdentity(8, 999))
    with pytest.raises(ConfigSecurityError, match="volume"):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize(
    "changes",
    [
        {"identity": FileIdentity(7, 0)},
        {"identity": FileIdentity(-1, 4)},
        {"size": -1},
        {"owner_sid": "invalid"},
        {"dacl": (AccessRule(USER, -1),)},
        {"dacl": (AccessRule(USER, 0x100000000),)},
        {"dacl": (AccessRule(USER, FULL, flags=32),)},
        {"dacl": (AccessRule(USER, FULL, kind=2),)},
        {"dacl": (AccessRule("invalid", FULL),)},
    ],
)
def test_malformed_security_metadata_rejects_and_closes(changes: dict[str, Any]) -> None:
    backend = FakeFilesystem()
    backend.objects[MAIN] = replace(backend.objects[MAIN], **changes)
    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize(
    "target", [ROOT, ROOT + r"\clients", ROOT + r"\policies", ROOT + r"\feeds"]
)
@pytest.mark.parametrize(
    "changes",
    [
        {"owner_sid": SYSTEM},
        {"dacl_protected": False},
        {"reparse": True},
        {"dacl": (AccessRule(USER, FULL),)},
        {"is_directory": False},
    ],
)
def test_participating_directories_require_private_trust(
    target: str, changes: dict[str, Any]
) -> None:
    backend = FakeFilesystem()
    if target != ROOT:
        backend.add(target, directory=True)
        backend.members[ROOT].append(PureWindowsPath(target).name)
    backend.objects[target] = replace(backend.objects[target], **changes)
    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("phase", ["open", "describe", "entries", "read", "close"])
def test_every_acquired_handle_has_a_close_attempt_after_failure(phase: str) -> None:
    backend = FakeFilesystem()
    method = "open_existing" if phase == "open" else phase
    original = getattr(backend, method)

    def fail(*arguments: Any) -> Any:
        if phase == "open" and arguments[0] != MAIN:
            return original(*arguments)
        if phase == "close":
            original(*arguments)
        raise OSError("synthetic private failure detail")

    setattr(backend, method, fail)
    with pytest.raises(ConfigSecurityError) as captured:
        capture_configuration(MAIN, backend=backend, environment={})
    assert "private" not in str(captured.value)
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("target", ["C:\\", r"C:\Trusted", ROOT])
@pytest.mark.parametrize("changes", [{"last_write": 99}, {"size": 64}], ids=["timestamp", "size"])
def test_final_recheck_rejects_ancestor_or_root_drift(target: str, changes: _ObjectChanges) -> None:
    backend = FakeFilesystem()
    backend.on_read = lambda _handle: backend.objects.__setitem__(
        target, replace(backend.objects[target], **changes)
    )
    with pytest.raises(ConfigSecurityError, match="changed during capture"):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.closed == list(reversed(backend.opened))


def _sid_bytes(*subauthorities: int) -> bytes:
    return (
        bytes((1, len(subauthorities)))
        + (5).to_bytes(6, "big")
        + b"".join(value.to_bytes(4, "little") for value in subauthorities)
    )


class FakeWin32:
    """No OS bindings: pointers refer only to retained, test-owned allocations."""

    def __init__(self) -> None:
        self.kernel32 = self
        self.advapi = self
        self.ntdll = self
        self.error = 122
        self.token_open_ok = True
        self.token_first_ok = False
        self.token_second_ok = True
        self.token_capacity = 64
        self.token_returned = 64
        self.token_sid_offset = 16
        self.token_sid = _sid_bytes(21, 1, 2, 3, 1001)
        self.token_queries: list[tuple[int, int]] = []
        self.close_ok = True
        self.closed: list[int] = []
        self.free_ok = True
        self.freed: list[int] = []
        self.open_value: Any = 202
        self.opens: list[tuple[Any, ...]] = []
        self.buffer = ctypes.create_string_buffer(512)
        self.buffers: list[Any] = [self.buffer]
        self.base = ctypes.addressof(self.buffer)
        self.owner_offset = 32
        self.acl_offset = 96
        self.ace_offset = 104
        self.descriptor_length = len(self.buffer)
        self.security_result = 0
        self.descriptor_present = True
        self.dacl_present = True
        self.revision = 1
        self.control = 0x9004
        self.security_queries: list[tuple[int, int, int]] = []
        self.query_base = 0
        self.ace_ok = True
        self.ace_calls: list[int] = []
        cast(Any, self.buffer)[32 : 32 + len(self.token_sid)] = self.token_sid
        self.acl = security._AclHeader.from_buffer(self.buffer, 96)
        self.acl.revision, self.acl.size, self.acl.ace_count = 2, 44, 1
        self.ace = security._AceHeader.from_buffer(self.buffer, 104)
        self.ace.kind, self.ace.flags, self.ace.size = 0, 0, 36
        ctypes.c_uint32.from_buffer(self.buffer, 108).value = FULL
        cast(Any, self.buffer)[112 : 112 + len(self.token_sid)] = self.token_sid
        self.info_ok = True
        self.info = security._FileInformation()
        self.info.volume, self.info.index_low, self.info.links = 7, 4, 1
        self.info.size_low = 9
        self.info.created.low, self.info.written.low = 11, 12
        self.final_name = "\\\\?\\" + MAIN
        self.final_result: int | None = None
        self.volume_ok = True
        self.volume_serial = 7
        self.filesystem = "NTFS"
        self.drive_type = 3
        self.read_bytes = b"synthetic"
        self.read_offset = 0
        self.read_ok = True
        self.read_overcount = False
        self.read_sizes: list[int] = []
        self.batches: list[bytes] = []
        self.repeat_batch: bytes | None = None
        self.enumeration_error = 18
        self.enumerations: list[tuple[int, int]] = []

    def error_code(self) -> int:
        return self.error

    def GetCurrentProcess(self) -> int:
        return 101

    def OpenProcessToken(self, process: int, access: int, output: Any) -> bool:
        assert (process, access) == (101, 8)
        if self.token_open_ok:
            output._obj.value = 303
        return self.token_open_ok

    def GetTokenInformation(
        self, token: Any, kind: int, buffer: Any, size: int, required: Any
    ) -> bool:
        assert token.value == 303 and kind == 1
        self.token_queries.append((kind, size))
        if buffer is None:
            required._obj.value = self.token_capacity
            return self.token_first_ok
        self.buffers.append(buffer)
        required._obj.value = self.token_returned
        assert size == len(buffer)
        ctypes.c_void_p.from_buffer(buffer).value = ctypes.addressof(buffer) + self.token_sid_offset
        # Always write inside the allocation, even when the declared pointer is malformed.
        buffer[16 : 16 + len(self.token_sid)] = self.token_sid
        return self.token_second_ok

    def CloseHandle(self, handle: Any) -> bool:
        self.closed.append(int(getattr(handle, "value", handle)))
        return self.close_ok

    def CreateFileW(self, *arguments: Any) -> Any:
        self.opens.append(arguments)
        return self.open_value

    def NtQuerySecurityObject(
        self,
        handle: int,
        requested: int,
        buffer: Any,
        capacity: int,
        required: Any,
    ) -> int:
        self.security_queries.append((handle, requested, capacity))
        assert (handle, requested, capacity) == (202, 5, 65_536)
        assert len(buffer) == capacity
        self.buffers.append(buffer)
        self.query_base = ctypes.addressof(buffer)
        required._obj.value = self.descriptor_length
        if self.security_result == 0 and self.descriptor_present:
            buffer[: len(self.buffer)] = self.buffer.raw
            buffer[0:2] = bytes((self.revision, 0))
            buffer[2:4] = self.control.to_bytes(2, "little")
            buffer[4:8] = (self.owner_offset & 0xFFFFFFFF).to_bytes(4, "little")
            offset = self.acl_offset if self.dacl_present else 0
            buffer[16:20] = (offset & 0xFFFFFFFF).to_bytes(4, "little")
        return self.security_result

    def GetSecurityInfo(self, *arguments: Any) -> int:
        raise AssertionError("Win32 descriptor projection must not define admission")

    def GetSecurityDescriptorLength(self, descriptor: Any) -> int:
        raise AssertionError("native descriptor length must use the returned extent")

    def GetSecurityDescriptorControl(self, descriptor: Any, control: Any, revision: Any) -> bool:
        raise AssertionError("native protection must come from the returned header")

    def GetAce(self, acl: Any, index: int, output: Any) -> bool:
        assert acl.value == self.query_base + self.acl_offset
        self.ace_calls.append(index)
        output._obj.value = self.query_base + self.ace_offset
        return self.ace_ok

    def LocalFree(self, descriptor: Any) -> int | None:
        assert descriptor.value == self.base
        self.freed.append(descriptor.value)
        # A fake failure retains ownership; neither branch calls an OS allocator.
        return descriptor.value if not self.free_ok else None

    def GetFileInformationByHandle(self, handle: int, information: Any) -> bool:
        assert handle == 202
        ctypes.memmove(
            ctypes.addressof(information._obj),
            ctypes.addressof(self.info),
            ctypes.sizeof(self.info),
        )
        return self.info_ok

    def GetFinalPathNameByHandleW(self, handle: int, output: Any, capacity: int, flags: int) -> int:
        assert (handle, capacity, flags) == (202, 32_768, 0)
        output.value = self.final_name
        return len(self.final_name) if self.final_result is None else self.final_result

    def GetVolumeInformationByHandleW(
        self,
        handle: int,
        name: Any,
        name_size: int,
        serial: Any,
        maximum: Any,
        flags: Any,
        filesystem: Any,
        capacity: int,
    ) -> bool:
        assert (handle, name, name_size, capacity) == (202, None, 0, 64)
        serial._obj.value, maximum._obj.value, flags._obj.value = self.volume_serial, 255, 0
        filesystem.value = self.filesystem
        return self.volume_ok

    def GetDriveTypeW(self, root: str) -> int:
        assert root == "C:\\"
        return self.drive_type

    def ReadFile(self, handle: int, buffer: Any, size: int, count: Any, overlapped: Any) -> bool:
        assert handle == 202 and overlapped is None and size == len(buffer)
        self.read_sizes.append(size)
        data = self.read_bytes[self.read_offset : self.read_offset + size]
        buffer[: len(data)] = data
        self.read_offset += len(data)
        count._obj.value = size + 1 if self.read_overcount else len(data)
        return self.read_ok

    def GetFileInformationByHandleEx(self, handle: int, kind: int, buffer: Any, size: int) -> bool:
        assert handle == 202 and size == len(buffer) == 65_536
        self.enumerations.append((kind, size))
        data = self.batches.pop(0) if self.batches else self.repeat_batch
        if data is None:
            self.error = self.enumeration_error
            return False
        assert len(data) <= size
        buffer[: len(data)] = data
        return True


def _native(api: FakeWin32) -> tuple[NativeConfigurationFilesystem, object]:
    adapter = NativeConfigurationFilesystem(api=api)
    return adapter, adapter.open_existing(MAIN)


def _directory_batch(names: list[str]) -> bytes:
    output = bytearray()
    offset = security._DirectoryInformation.ea_size.offset + 4
    for index, name in enumerate(names):
        raw = name.encode("utf-16-le")
        record_size = (offset + len(raw) + 7) // 8 * 8
        header = security._DirectoryInformation()
        header.name_length = len(raw)
        header.next_offset = record_size if index < len(names) - 1 else 0
        record = bytes(header)[:offset] + raw
        output.extend(record + b"\x00" * (record_size - len(record)))
    return bytes(output)


def test_native_fake_identity_and_read_only_open_contract() -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    assert adapter.execution_sid == USER
    assert api.token_queries == [(1, 0), (1, 64)]
    assert api.closed == [303]
    assert api.opens == [(MAIN, 0x80000000, 1, None, 3, 0x02200000, None)]
    observed = adapter.describe(handle)
    assert observed == ObjectSecurity(
        FileIdentity(7, 4),
        MAIN,
        False,
        USER,
        (AccessRule(USER, FULL),),
        True,
        size=9,
        creation_time=11,
        last_write=12,
    )
    assert api.security_queries == [(202, 5, 65_536)]
    assert api.freed == []
    adapter.close(handle)
    assert api.closed == [303, 202]


@pytest.mark.parametrize("value", [None, 0, -1, ctypes.c_void_p(-1).value])
def test_native_open_rejects_invalid_fake_handle_values(value: Any) -> None:
    api = FakeWin32()
    api.open_value = value
    adapter = NativeConfigurationFilesystem(api=api)
    with pytest.raises(ConfigSecurityError, match="opened safely"):
        adapter.open_existing(MAIN)
    assert api.closed == [303]


@pytest.mark.parametrize(
    "changes",
    [
        {"token_open_ok": False},
        {"token_first_ok": True},
        {"error": 5},
        {"token_capacity": 0},
        {"token_capacity": 65_537},
        {"token_second_ok": False},
        {"token_returned": 65},
        {"token_returned": 0},
        {"token_returned": 16},
        {"token_returned": 43},
        {"token_sid_offset": -1},
        {"token_sid_offset": 64},
        {"token_sid": b"\x02" + _sid_bytes(21, 1, 2, 3, 1001)[1:]},
    ],
)
def test_native_identity_failure_closes_only_an_acquired_fake_token(
    changes: dict[str, Any],
) -> None:
    api = FakeWin32()
    for name, value in changes.items():
        setattr(api, name, value)
    with pytest.raises(ConfigSecurityError):
        NativeConfigurationFilesystem(api=api)
    assert api.closed == ([303] if api.token_open_ok else [])


def test_native_identity_close_failure_is_not_success() -> None:
    api = FakeWin32()
    api.close_ok = False
    with pytest.raises(ConfigSecurityError, match="identity"):
        NativeConfigurationFilesystem(api=api)
    assert api.closed == [303]


def test_native_descriptor_is_caller_owned_without_native_allocation_or_free() -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    api.free_ok = False
    assert adapter.describe(handle).dacl_protected
    assert api.security_queries == [(202, 5, 65_536)]
    assert api.freed == []
    assert api.buffer in api.buffers
    adapter.close(handle)


@pytest.mark.parametrize(
    "changes",
    [
        {"security_result": 5},
        {"descriptor_present": False},
        {"descriptor_length": 19},
        {"descriptor_length": 65_537},
        {"owner_offset": -1},
        {"owner_offset": 508},
        {"revision": 2},
        {"acl_offset": -1},
        {"acl_offset": 508},
        {"ace_ok": False},
        {"ace_offset": 100},
        {"ace_offset": 130},
    ],
)
def test_native_descriptor_failures_leave_only_caller_owned_memory(changes: dict[str, Any]) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    for name, value in changes.items():
        setattr(api, name, value)
    with pytest.raises(ConfigSecurityError):
        adapter.describe(handle)
    assert api.security_queries == [(202, 5, 65_536)]
    assert api.freed == []
    adapter.close(handle)
    assert api.closed == [303, 202]


@pytest.mark.parametrize(
    "target,field,value",
    [
        ("acl", "revision", 1),
        ("acl", "ace_count", 129),
        ("acl", "size", 7),
        ("acl", "size", 500),
        ("ace", "kind", 2),
        ("ace", "size", 15),
        ("ace", "size", 100),
    ],
)
def test_native_malformed_acl_and_ace_buffers_reject(target: str, field: str, value: int) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    setattr(getattr(api, target), field, value)
    with pytest.raises(ConfigSecurityError):
        adapter.describe(handle)
    assert api.freed == []
    adapter.close(handle)


@pytest.mark.parametrize("offset", [32, 112])
@pytest.mark.parametrize("revision,count", [(2, 5), (1, 16), (1, 15)])
def test_native_malformed_owner_and_ace_sid_buffers_reject(
    offset: int, revision: int, count: int
) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    cast(Any, api.buffer)[offset : offset + 2] = bytes((revision, count))
    if offset == 32 and count == 15:
        api.descriptor_length = 64
    with pytest.raises(ConfigSecurityError):
        adapter.describe(handle)
    assert api.freed == []
    adapter.close(handle)


@pytest.mark.parametrize("changes", [{"dacl_present": False}, {"control": 0x9000}])
def test_native_missing_acl_is_returned_without_fabricated_authority(
    changes: dict[str, Any],
) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    for name, value in changes.items():
        setattr(api, name, value)
    assert adapter.describe(handle).dacl is None
    assert api.freed == []
    adapter.close(handle)


@pytest.mark.parametrize(
    "changes",
    [
        {"info_ok": False},
        {"final_result": 0},
        {"final_result": 32_768},
        {"final_name": r"\\server\share\config.yaml"},
        {"volume_ok": False},
        {"volume_serial": 8},
    ],
)
def test_native_description_unavailable_metadata_rejects(changes: dict[str, Any]) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    for name, value in changes.items():
        setattr(api, name, value)
    with pytest.raises(ConfigSecurityError):
        adapter.describe(handle)
    assert api.freed == []
    adapter.close(handle)


@pytest.mark.parametrize("status", [1, -1, 0xC0000023, False, None])
def test_native_security_requires_exact_success_without_retry_or_projection(status: Any) -> None:
    api = FakeWin32()
    api.security_result = status
    adapter, handle = _native(api)
    try:
        with pytest.raises(ConfigSecurityError):
            adapter.describe(handle)
        assert api.security_queries == [(202, 5, 65_536)]
        assert api.ace_calls == [] and api.freed == []
    finally:
        adapter.close(handle)


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": 0},
        {"control": 0x1004},
        {"owner_offset": 0},
        {"owner_offset": 16},
        {"owner_offset": 33},
        {"acl_offset": 16},
        {"acl_offset": 97},
        {"descriptor_length": 20},
        {"descriptor_length": 59},
        {"descriptor_length": 139},
    ],
)
def test_native_relative_descriptor_header_and_returned_extent_bound_every_read(
    changes: dict[str, Any],
) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    for name, value in changes.items():
        setattr(api, name, value)
    try:
        with pytest.raises(ConfigSecurityError):
            adapter.describe(handle)
        assert api.security_queries == [(202, 5, 65_536)]
        assert api.freed == []
    finally:
        adapter.close(handle)


@pytest.mark.parametrize("extent", [140, 65_536])
@pytest.mark.parametrize("protected", [False, True])
def test_native_security_exact_extent_and_raw_protection_bit_are_authoritative(
    extent: int,
    protected: bool,
) -> None:
    api = FakeWin32()
    api.descriptor_length = extent
    api.control = 0x8004 | (0x1000 if protected else 0)
    adapter, handle = _native(api)
    try:
        observed = adapter.describe(handle)
        assert observed.owner_sid == USER
        assert observed.dacl == (AccessRule(USER, FULL),)
        assert observed.dacl_protected is protected
        assert api.security_queries == [(202, 5, 65_536)]
        assert api.freed == []
    finally:
        adapter.close(handle)


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_native_security_query_control_interruption_propagates_without_legacy_cleanup(
    interruption: type[BaseException],
) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    signal = interruption("synthetic-native-query-interruption")

    def interrupted(*_arguments: Any) -> int:
        raise signal

    cast(Any, api).NtQuerySecurityObject = interrupted
    try:
        with pytest.raises(interruption) as caught:
            adapter.describe(handle)
        assert caught.value is signal
        assert api.ace_calls == [] and api.freed == []
    finally:
        adapter.close(handle)


@pytest.mark.parametrize("failure", ["missing", "exception"])
def test_native_security_query_unavailability_has_fixed_error_without_legacy_fallback(
    failure: str,
) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)

    def failed(*_arguments: Any) -> int:
        raise RuntimeError("synthetic-private-native-query-detail")

    if failure == "missing":
        cast(Any, api).ntdll = object()
    else:
        cast(Any, api).NtQuerySecurityObject = failed
    try:
        with pytest.raises(ConfigSecurityError) as caught:
            adapter.describe(handle)
        assert caught.value.args == ("configuration object permissions are unavailable",)
        assert caught.value.__context__ is caught.value.__cause__ is None
        assert api.ace_calls == [] and api.freed == []
    finally:
        adapter.close(handle)


@pytest.mark.parametrize("size", [0, 65_536, 1_048_576, 1_048_577])
def test_native_read_eof_and_exact_limit_are_bounded(size: int) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    api.read_bytes = b"x" * size
    if size <= 1_048_576:
        assert adapter.read(handle, 1_048_576) == api.read_bytes
    else:
        with pytest.raises(ConfigSecurityError, match="byte bound"):
            adapter.read(handle, 1_048_576)
    assert len(api.read_sizes) <= 17
    assert all(0 < request <= 65_536 for request in api.read_sizes)
    assert sum(api.read_sizes) <= 1_048_577
    adapter.close(handle)


@pytest.mark.parametrize("bound", [0, -1, True, 1.5, 1_048_577])
def test_native_read_rejects_invalid_bounds_before_fake_api(bound: Any) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    with pytest.raises(ConfigSecurityError, match="read bound"):
        adapter.read(handle, bound)
    assert api.read_sizes == []
    adapter.close(handle)


@pytest.mark.parametrize("failure", ["read_ok", "read_overcount"])
def test_native_read_api_failure_or_overcount_rejects(failure: str) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    setattr(api, failure, failure != "read_ok")
    with pytest.raises(ConfigSecurityError, match="bounded read"):
        adapter.read(handle, 32)
    assert api.read_sizes == [33]
    adapter.close(handle)


def test_native_close_failure_is_reported_without_retry() -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    api.close_ok = False
    with pytest.raises(ConfigSecurityError, match="closed"):
        adapter.close(handle)
    assert api.closed == [303, 202]


@pytest.mark.parametrize("extra", [0, 1])
def test_native_directory_entries_dot_filter_and_raw_entry_bound(extra: int) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    names = [f"item-{index}.txt" for index in range(128 + extra)]
    api.batches = [_directory_batch([".", "..", *names])]
    if not extra:
        assert tuple(adapter.entries(handle)) == tuple(names)
        assert api.enumerations == [(15, 65_536), (14, 65_536)]
    else:
        with pytest.raises(ConfigSecurityError, match="entry bound"):
            tuple(adapter.entries(handle))
        assert api.enumerations == [(15, 65_536)]
    adapter.close(handle)


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "odd",
        "long",
        "utf16",
        "overlap",
        "misaligned",
        "outside",
        "truncated-header",
        "truncated-name",
    ],
)
def test_native_malformed_directory_buffers_reject(kind: str) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    data = bytearray(65_536)
    record = _directory_batch(["a"])
    data[: len(record)] = record
    header = security._DirectoryInformation.from_buffer(data)
    if kind in {"empty", "odd", "long"}:
        header.name_length = {"empty": 0, "odd": 1, "long": 512}[kind]
    elif kind == "utf16":
        data[68:70] = b"\x00\xd8"
    elif kind in {"overlap", "misaligned", "outside", "truncated-header"}:
        header.next_offset = {
            "overlap": 64,
            "misaligned": 73,
            "outside": 65_536,
            "truncated-header": 65_528,
        }[kind]
    else:
        header.next_offset = 65_456
        final = security._DirectoryInformation.from_buffer(data, 65_456)
        final.name_length = 20
    api.batches = [bytes(data)]
    with pytest.raises(ConfigSecurityError, match="directory"):
        tuple(adapter.entries(handle))
    assert api.enumerations == [(15, 65_536)]
    adapter.close(handle)


def test_native_directory_repeated_batches_cannot_loop_unboundedly() -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    api.repeat_batch = _directory_batch(["."])
    with pytest.raises(ConfigSecurityError, match="bound"):
        tuple(adapter.entries(handle))
    assert len(api.enumerations) == 131
    adapter.close(handle)


@pytest.mark.parametrize("error", [18, 5])
def test_native_directory_eof_is_distinct_from_failure(error: int) -> None:
    api = FakeWin32()
    adapter, handle = _native(api)
    api.enumeration_error = error
    if error == 18:
        assert tuple(adapter.entries(handle)) == ()
    else:
        with pytest.raises(ConfigSecurityError, match="enumeration failed"):
            tuple(adapter.entries(handle))
    assert api.enumerations == [(15, 65_536)]
    adapter.close(handle)


def test_native_identity_uses_valid_returned_extent_not_allocation_capacity() -> None:
    api = FakeWin32()
    api.token_returned = 44
    assert NativeConfigurationFilesystem(api=api).execution_sid == USER
    assert api.closed == [303]


@pytest.mark.parametrize("count", [15, 16])
def test_synthetic_sid_subauthority_exact_limit_and_one_over(count: int) -> None:
    raw = _sid_bytes(*range(count))
    buffer = ctypes.create_string_buffer(raw)
    base = ctypes.addressof(buffer)
    if count == 15:
        assert security._sid_at(base, base=base, length=len(raw)) == "S-1-5-" + "-".join(
            map(str, range(count))
        )
    else:
        with pytest.raises(ConfigSecurityError, match="identifier"):
            security._sid_at(base, base=base, length=len(raw))


def test_capture_rejects_oversized_return_despite_bounded_metadata() -> None:
    backend = FakeFilesystem()
    backend.objects[MAIN] = replace(backend.objects[MAIN], size=1_048_576)
    backend.contents[MAIN] = b"x" * 1_048_577
    with pytest.raises(ConfigSecurityError, match="bounded read"):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == [MAIN]
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("total", [128, 129])
def test_optional_directory_includes_ignored_members_in_bound(total: int) -> None:
    backend = FakeFilesystem()
    parent = ROOT + r"\clients"
    backend.add(parent, directory=True)
    backend.members[ROOT].append("clients")
    backend.members[parent] = [f"ignored-{index}.txt" for index in range(total)]
    if total == 128:
        assert len(capture_configuration(MAIN, backend=backend, environment={}).documents) == 1
    else:
        with pytest.raises(ConfigSecurityError, match="entry bound"):
            capture_configuration(MAIN, backend=backend, environment={})
        assert backend.reads == []
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("change", ["addition", "removal", "reordering"])
def test_consumed_directory_membership_recheck_ignores_only_order(change: str) -> None:
    backend = FakeFilesystem()
    parent = ROOT + r"\clients"
    backend.add(parent, directory=True)
    backend.members[ROOT].append("clients")
    backend.members[parent] = ["a.txt", "b.txt"]

    def mutate(_handle: object) -> None:
        if change == "addition":
            backend.members[parent].append("c.txt")
        elif change == "removal":
            backend.members[parent].pop()
        else:
            backend.members[parent].reverse()

    backend.on_read = mutate
    if change == "reordering":
        assert capture_configuration(MAIN, backend=backend, environment={}).documents
    else:
        with pytest.raises(ConfigSecurityError, match="membership changed"):
            capture_configuration(MAIN, backend=backend, environment={})
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("length", [32_767, 32_768])
def test_lexical_windows_path_text_exact_limit_and_one_over(length: int) -> None:
    # This is parser-only text, never an OS pathname or a captured tree.
    path = "C:\\" + "x" * (length - 3)
    if length == 32_767:
        assert str(security._absolute_lexical_path(path)) == path
    else:
        with pytest.raises(ConfigSecurityError, match="supported local path"):
            security._absolute_lexical_path(path)


SCRIPTED = ROOT + r"\responses.json"
SCRIPTED_BYTES = b'{"schema_version":1,"responses":{"firecrawl.search":[{"status_code":204}]}}'


def _scripted_filesystem() -> FakeFilesystem:
    backend = FakeFilesystem()
    backend.add(SCRIPTED, content=SCRIPTED_BYTES)
    backend.members[ROOT].append("responses.json")
    return backend


def _capture_scripted(backend: FakeFilesystem, spelling: str = "responses.json") -> Any:
    return capture_configuration(
        MAIN,
        backend=backend,
        environment={},
        scripted_document_selector=lambda _content, _origin, _environment: spelling,
    )


def test_scripted_capture_retains_typed_bytes_and_calls_selector_with_owned_handles() -> None:
    backend = _scripted_filesystem()
    environment = {"APPDATA": ROOT, "UNRELATED": "excluded"}
    calls: list[bytes] = []

    def selector(content: bytes, origin: Path, frozen: Any) -> str:
        calls.append(content)
        assert content == b"schema_version: 1\n"
        assert origin == Path(MAIN)
        assert dict(frozen) == {"APPDATA": ROOT}
        assert backend.closed == []
        assert MAIN in backend.reads
        with pytest.raises(TypeError):
            frozen["APPDATA"] = r"C:\Changed"
        return "responses.json"

    backend.on_read = lambda _handle: environment.__setitem__("APPDATA", r"C:\Changed")
    snapshot = capture_configuration(
        MAIN,
        backend=backend,
        environment=environment,
        scripted_document_selector=selector,
    )
    document = snapshot.scripted_document
    assert isinstance(document, security.ScriptedConfigurationDocument)
    assert document.relative_path == "responses.json"
    assert document.origin == Path(SCRIPTED)
    assert document.role == "firecrawl_scripted_responses"
    assert document.content == SCRIPTED_BYTES
    assert document.sha256 == hashlib.sha256(SCRIPTED_BYTES).hexdigest()
    assert document.identity == backend.objects[SCRIPTED].identity
    assert [item.relative_path for item in snapshot.documents] == ["config.yaml"]
    backend.contents[SCRIPTED] = b"changed after capture"
    assert document.content == SCRIPTED_BYTES
    assert len(calls) == 1
    assert backend.reads == [MAIN, SCRIPTED]
    assert backend.closed == list(reversed(backend.opened))
    with pytest.raises(FrozenInstanceError):
        document.origin = Path(r"C:\Changed")  # type: ignore[misc]


@pytest.mark.parametrize("spelling", ("responses.json", SCRIPTED))
def test_scripted_capture_accepts_only_the_exact_selected_sibling(spelling: str) -> None:
    backend = _scripted_filesystem()
    snapshot = _capture_scripted(backend, spelling)
    assert snapshot.scripted_document is not None
    assert snapshot.scripted_document.origin == Path(SCRIPTED)
    assert backend.reads == [MAIN, SCRIPTED]


@pytest.mark.parametrize(
    "spelling",
    (
        "",
        "../responses.json",
        r"sub\responses.json",
        r".\responses.json",
        r"C:responses.json",
        r"C:\Other\responses.json",
        r"C:\trusted\Config\responses.json",
        "responses.json:stream",
        "responses.json.",
        "NUL.json",
        "config.yaml",
        MAIN,
    ),
)
def test_scripted_capture_rejects_unsafe_selection_before_opening_it(spelling: str) -> None:
    backend = _scripted_filesystem()
    with pytest.raises(ConfigSecurityError):
        _capture_scripted(backend, spelling)
    assert SCRIPTED not in [handle.path for handle in backend.opened]
    assert SCRIPTED not in backend.reads
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("member", (None, "Responses.json"))
def test_scripted_capture_requires_exact_case_sensitive_root_membership(member: str | None) -> None:
    backend = _scripted_filesystem()
    backend.members[ROOT].remove("responses.json")
    if member is not None:
        backend.members[ROOT].append(member)
    with pytest.raises(ConfigSecurityError):
        _capture_scripted(backend)
    assert SCRIPTED not in [handle.path for handle in backend.opened]
    assert SCRIPTED not in backend.reads
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize(
    "changes",
    (
        {"owner_sid": OTHER},
        {"dacl": None},
        {"reparse": True},
        {"link_count": 2},
        {"is_directory": True},
        {"identity": FileIdentity(8, 901)},
    ),
)
def test_scripted_attachment_requires_file_trust_before_its_read(changes: dict[str, Any]) -> None:
    backend = _scripted_filesystem()
    backend.objects[SCRIPTED] = replace(backend.objects[SCRIPTED], **changes)
    with pytest.raises(ConfigSecurityError):
        _capture_scripted(backend)
    assert SCRIPTED not in backend.reads
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("change", ("identity", "scripted_metadata", "main_metadata", "membership"))
def test_scripted_read_rechecks_its_identity_and_all_previously_owned_objects(change: str) -> None:
    backend = _scripted_filesystem()

    def mutate(handle: Any) -> None:
        if handle.path != SCRIPTED:
            return
        if change == "membership":
            backend.members[ROOT].append("new.txt")
        else:
            target = MAIN if change == "main_metadata" else SCRIPTED
            changes = (
                {"identity": FileIdentity(7, 902)} if change == "identity" else {"last_write": 99}
            )
            backend.objects[target] = replace(backend.objects[target], **changes)

    backend.on_read = mutate
    with pytest.raises(ConfigSecurityError):
        _capture_scripted(backend)
    assert backend.reads == [MAIN, SCRIPTED]
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("bound", ("documents", "aggregate_bytes", "path_text"))
@pytest.mark.parametrize("over", (False, True))
def test_scripted_attachment_consumes_shared_capture_budgets(
    monkeypatch: pytest.MonkeyPatch,
    bound: str,
    over: bool,
) -> None:
    backend = _scripted_filesystem()
    name, required = {
        "documents": ("MAXIMUM_CONFIG_FILES", 2),
        "aggregate_bytes": (
            "MAXIMUM_AGGREGATE_BYTES",
            len(backend.contents[MAIN]) + len(SCRIPTED_BYTES),
        ),
        "path_text": ("MAXIMUM_PATH_TEXT", sum(len(path) for path in backend.objects)),
    }[bound]
    monkeypatch.setattr(security, name, required - int(over))
    if over:
        with pytest.raises(ConfigSecurityError):
            _capture_scripted(backend)
        assert SCRIPTED not in backend.reads
    else:
        assert _capture_scripted(backend).scripted_document is not None
        assert backend.reads == [MAIN, SCRIPTED]
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("size", (1_048_576, 1_048_577))
def test_scripted_attachment_obeys_the_existing_per_file_byte_limit(size: int) -> None:
    backend = _scripted_filesystem()
    backend.contents[SCRIPTED] = b"x" * size
    backend.objects[SCRIPTED] = replace(backend.objects[SCRIPTED], size=size)
    if size <= 1_048_576:
        assert len(_capture_scripted(backend).scripted_document.content) == size
    else:
        with pytest.raises(ConfigSecurityError):
            _capture_scripted(backend)
        assert SCRIPTED not in backend.reads
    assert backend.closed == list(reversed(backend.opened))


def test_scripted_attachment_identity_and_content_both_change_the_snapshot_digest() -> None:
    first = _capture_scripted(_scripted_filesystem())
    changed_identity = _scripted_filesystem()
    changed_identity.objects[SCRIPTED] = replace(
        changed_identity.objects[SCRIPTED],
        identity=FileIdentity(7, 903),
    )
    changed_content = _scripted_filesystem()
    changed_content.contents[SCRIPTED] = SCRIPTED_BYTES.replace(b"204", b"200")
    digests = {
        first.manifest_digest,
        _capture_scripted(changed_identity).manifest_digest,
        _capture_scripted(changed_content).manifest_digest,
    }
    assert len(digests) == 3


@pytest.mark.parametrize("ancestor", ["C:\\", r"C:\Trusted"], ids=["volume", "parent"])
@pytest.mark.parametrize("scripted", [False, True], ids=["ordinary", "scripted"])
@pytest.mark.parametrize(
    "changes",
    [{"last_write": 99}, {"size": 64}, {"last_write": 99, "size": 64}],
    ids=["timestamp", "size", "timestamp-and-size"],
)
def test_manifest_ignores_only_ancestor_timestamp_and_size_after_sibling_creation(
    ancestor: str, scripted: bool, changes: _ObjectChanges
) -> None:
    backend = _scripted_filesystem() if scripted else FakeFilesystem()

    def capture() -> security.ConfigurationSnapshot:
        return (
            cast(security.ConfigurationSnapshot, _capture_scripted(backend))
            if scripted
            else capture_configuration(MAIN, backend=backend, environment={})
        )

    first = capture()
    sibling = str(PureWindowsPath(ancestor) / "unrelated.log")
    backend.add(sibling, content=b"synthetic sibling activity")
    backend.members[ancestor].append("unrelated.log")
    backend.objects[ancestor] = replace(backend.objects[ancestor], **changes)
    second = capture()

    assert second.manifest_digest == first.manifest_digest
    assert second.manifest_bytes == first.manifest_bytes
    assert second.documents == first.documents
    assert sibling not in backend.reads
    for snapshot in (first, second):
        security.require_snapshot_manifest_binding(snapshot)
        for row in json.loads(snapshot.manifest_bytes)["objects"]:
            expected = json.loads(json.dumps(asdict(backend.objects[row["final_path"]])))
            if row["final_path"] in {"C:\\", r"C:\Trusted"}:
                expected.pop("last_write")
                expected.pop("size")
            assert row == expected


@pytest.mark.parametrize(
    "target",
    [ROOT, ROOT + r"\clients", MAIN, ROOT + r"\clients\one.yaml", SCRIPTED],
    ids=["private-root", "private-directory", "main", "client", "scripted"],
)
def test_manifest_retains_last_write_for_every_configuration_object(target: str) -> None:
    backend = _scripted_filesystem()
    client_directory = ROOT + r"\clients"
    client = client_directory + r"\one.yaml"
    backend.add(client_directory, directory=True)
    backend.add(client, content=b"synthetic: client\n")
    backend.members[ROOT].append("clients")
    backend.members[client_directory].append("one.yaml")
    first = _capture_scripted(backend)
    backend.objects[target] = replace(backend.objects[target], last_write=99)
    second = _capture_scripted(backend)

    assert first.manifest_digest != second.manifest_digest
    assert first.documents == second.documents
    security.require_snapshot_manifest_binding(second)
    rows = {row["final_path"]: row for row in json.loads(second.manifest_bytes)["objects"]}
    assert rows[target]["last_write"] == 99


@pytest.mark.parametrize(
    "target", [ROOT, ROOT + r"\clients"], ids=["private-root", "private-directory"]
)
def test_manifest_retains_size_for_private_configuration_directories(target: str) -> None:
    backend = FakeFilesystem()
    client_directory = ROOT + r"\clients"
    client = client_directory + r"\one.yaml"
    backend.add(client_directory, directory=True)
    backend.add(client, content=b"synthetic: client\n")
    backend.members[ROOT].append("clients")
    backend.members[client_directory].append("one.yaml")
    first = capture_configuration(MAIN, backend=backend, environment={})
    backend.objects[target] = replace(backend.objects[target], size=64)
    second = capture_configuration(MAIN, backend=backend, environment={})

    assert first.manifest_digest != second.manifest_digest
    assert first.documents == second.documents
    security.require_snapshot_manifest_binding(second)
    rows = {row["final_path"]: row for row in json.loads(second.manifest_bytes)["objects"]}
    assert rows[target]["size"] == 64
    for path in (MAIN, client):
        assert rows[path]["size"] == len(backend.contents[path])


@pytest.mark.parametrize("ancestor", ["C:\\", r"C:\Trusted"], ids=["volume", "parent"])
@pytest.mark.parametrize(
    "changes",
    [
        {"identity": FileIdentity(volume_serial=7, file_id=901)},
        {"owner_sid": USER},
        {"dacl": (AccessRule(SYSTEM, FULL, 3), AccessRule(USER, FULL, 3))},
        {"dacl_protected": True},
        {"creation_time": 55},
        {"link_count": 2},
    ],
    ids=["identity", "owner", "acl", "protection", "creation", "links"],
)
def test_manifest_retains_other_permitted_ancestor_changes(
    ancestor: str, changes: _ObjectChanges
) -> None:
    backend = FakeFilesystem()
    first = capture_configuration(MAIN, backend=backend, environment={})
    backend.objects[ancestor] = replace(backend.objects[ancestor], **changes)
    second = capture_configuration(MAIN, backend=backend, environment={})

    assert first.manifest_digest != second.manifest_digest
    assert first.documents == second.documents
    security.require_snapshot_manifest_binding(second)


@pytest.mark.parametrize("ancestor", ["C:\\", r"C:\Trusted"], ids=["volume", "parent"])
@pytest.mark.parametrize(
    "changes",
    [{"owner_sid": OTHER}, {"dacl": (AccessRule(OTHER, FULL, 3),)}],
    ids=["untrusted-owner", "untrusted-mutation"],
)
def test_ancestor_manifest_projection_does_not_admit_untrusted_replacement(
    ancestor: str, changes: _ObjectChanges
) -> None:
    backend = FakeFilesystem()
    capture_configuration(MAIN, backend=backend, environment={})
    backend.objects[ancestor] = replace(backend.objects[ancestor], **changes)
    with pytest.raises(ConfigSecurityError):
        capture_configuration(MAIN, backend=backend, environment={})
    assert backend.reads == [MAIN]


def test_scripted_selector_failure_is_path_free_and_closes_owned_handles() -> None:
    backend = _scripted_filesystem()

    def reject(*_arguments: object) -> None:
        raise ValueError("synthetic private selector detail")

    with pytest.raises(ConfigSecurityError) as captured:
        capture_configuration(
            MAIN,
            backend=backend,
            environment={},
            scripted_document_selector=reject,
        )
    assert "private selector detail" not in str(captured.value)
    assert SCRIPTED not in backend.reads
    assert backend.closed == list(reversed(backend.opened))


def test_scripted_selector_none_keeps_the_bare_content_capture_contract() -> None:
    backend = _scripted_filesystem()
    snapshot = capture_configuration(
        MAIN,
        backend=backend,
        environment={},
        scripted_document_selector=lambda _content, _origin, _environment: None,
    )
    assert snapshot.scripted_document is None
    assert backend.reads == [MAIN]
    assert backend.closed == list(reversed(backend.opened))


@pytest.mark.parametrize("operation", ("capture", "verify"))
@pytest.mark.parametrize("over", (False, True))
def test_canonical_manifest_byte_bound_is_enforced_during_capture_and_verification(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    over: bool,
) -> None:
    snapshot = _capture_scripted(_scripted_filesystem())
    assert hashlib.sha256(snapshot.manifest_bytes).hexdigest() == snapshot.manifest_digest
    monkeypatch.setattr(
        security, "MAXIMUM_MANIFEST_BYTES", len(snapshot.manifest_bytes) - int(over)
    )
    backend = _scripted_filesystem()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("oversized retained manifest must precede decoding and hashing")

    if operation == "verify" and over:
        monkeypatch.setattr(security, "json", SimpleNamespace(loads=forbidden, dumps=forbidden))
        monkeypatch.setattr(security, "hashlib", SimpleNamespace(sha256=forbidden))

    def exercise() -> None:
        if operation == "capture":
            assert _capture_scripted(backend).manifest_bytes == snapshot.manifest_bytes
        else:
            security.require_snapshot_manifest_binding(snapshot)

    if over:
        with pytest.raises(ConfigSecurityError):
            exercise()
    else:
        exercise()
    assert backend.closed == list(reversed(backend.opened))
