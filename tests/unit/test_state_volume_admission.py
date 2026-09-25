"""State admission with pure volume/path/metadata fakes; no native enforcement proof."""

from __future__ import annotations

import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, cast

import pytest

from gatehouse import state_security as security

ROOT = PureWindowsPath("C:/")
BASE = ROOT / "synthetic"
STATE = BASE / "state"
DATABASE = STATE / "gatehouse.db"
DIRECTORY = BASE / "created"
CANARY = "SYNTHETIC_UNTRUSTED_VOLUME_DETAIL"


def _fixture_path(value: str) -> Path:
    return cast(type[Path], cast(Any, security).Path)(value)


class _Integer(int):
    pass


class _Text(str):
    pass


def _metadata(*, directory: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=(stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600),
        st_file_attributes=0x10 if directory else 0,
        st_nlink=1,
    )


class _Tree:
    """Only ordinary object metadata exists; there are no contents or OS handles."""

    def __init__(self) -> None:
        self.nodes = {
            ROOT: _metadata(directory=True),
            BASE: _metadata(directory=True),
            STATE: _metadata(directory=True),
            DATABASE: _metadata(),
        }
        self.events: list[tuple[str, str]] = []
        self.secured: list[tuple[PureWindowsPath, bool]] = []

    def create_directory(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)

    def secure(self, path: PureWindowsPath, *, is_directory: bool) -> None:
        self.events.append(("acl", str(path)))
        self.secured.append((PureWindowsPath(path), is_directory))

    @contextmanager
    def scandir(self, path: PureWindowsPath) -> Iterator[Iterator[SimpleNamespace]]:
        directory = PureWindowsPath(path)
        self.events.append(("scandir", str(directory)))
        assert directory in self.nodes
        yield iter(
            SimpleNamespace(name=child.name, path=str(child))
            for child in tuple(self.nodes)
            if child != directory and child.parent == directory
        )


@pytest.fixture
def tree(monkeypatch: pytest.MonkeyPatch) -> _Tree:
    tree = _Tree()

    class FakePath(PureWindowsPath):
        def absolute(self) -> FakePath:
            return self if self.is_absolute() else FakePath(BASE / self)

        def lstat(self) -> SimpleNamespace:
            path = PureWindowsPath(self)
            tree.events.append(("lstat", str(path)))
            if path not in tree.nodes:
                raise FileNotFoundError
            return tree.nodes[path]

        def mkdir(self, *, parents: bool = False, exist_ok: bool = False) -> None:
            assert parents and exist_ok
            tree.events.append(("mkdir", str(self)))
            for path in (*reversed(self.parents), self):
                tree.nodes.setdefault(PureWindowsPath(path), _metadata(directory=True))

        def is_dir(self) -> bool:
            try:
                return stat.S_ISDIR(self.lstat().st_mode)
            except FileNotFoundError:
                return False

        def is_file(self) -> bool:
            try:
                return stat.S_ISREG(self.lstat().st_mode)
            except FileNotFoundError:
                return False

    def backend() -> _Tree:
        tree.events.append(("backend", ""))
        return tree

    def forbidden_native_volume(root: str) -> security.StateVolumeFacts:
        pytest.fail(f"unexpected native-volume path for synthetic root {root}")

    monkeypatch.setattr(security, "Path", FakePath)
    monkeypatch.setattr(security, "os", SimpleNamespace(name="nt", scandir=tree.scandir))
    monkeypatch.setattr(security, "_windows_backend", backend)
    monkeypatch.setattr(security, "_windows_volume_facts", forbidden_native_volume)
    return tree


def _probe(tree: _Tree) -> Callable[[str], security.StateVolumeFacts]:
    def probe(root: str) -> security.StateVolumeFacts:
        assert root == str(ROOT)
        tree.events.append(("volume", root))
        return security.StateVolumeFacts(3, "NTFS")

    return probe


def _call(
    entrypoint: str,
    *,
    probe: Callable[[str], security.StateVolumeFacts] | None,
) -> object:
    if entrypoint == "ancestry":
        return security.validate_state_path_ancestry(str(DIRECTORY), _volume_probe=probe)
    if entrypoint == "directory":
        return security.secure_private_directory(str(DIRECTORY), _volume_probe=probe)
    if entrypoint == "file":
        return security.secure_private_file(str(DATABASE), _volume_probe=probe)
    assert entrypoint == "database"
    return security.secure_database_state(str(DATABASE), must_exist=True, _volume_probe=probe)


def test_volume_facts_are_an_immutable_record() -> None:
    facts = security.StateVolumeFacts(3, "NTFS")
    assert facts.drive_type == 3 and facts.filesystem == "NTFS"
    with pytest.raises(FrozenInstanceError):
        facts.drive_type = 2  # type: ignore[misc]
    assert not hasattr(facts, "__dict__")


@pytest.mark.parametrize("entrypoint", ("ancestry", "directory", "file", "database"))
@pytest.mark.parametrize("failure", ("removable", "non_ntfs", "probe_exception"))
def test_every_entrypoint_admits_volume_before_backend_metadata_or_effects(
    tree: _Tree,
    entrypoint: str,
    failure: str,
) -> None:
    before = dict(tree.nodes)

    def probe(root: str) -> security.StateVolumeFacts:
        tree.events.append(("volume", root))
        if failure == "probe_exception":
            raise RuntimeError(CANARY)
        return (
            security.StateVolumeFacts(2, "NTFS")
            if failure == "removable"
            else security.StateVolumeFacts(3, "ReFS")
        )

    with pytest.raises(security.StateDirectorySecurityError) as caught:
        _call(entrypoint, probe=probe)
    assert CANARY not in str(caught.value)
    assert tree.events == [("volume", str(ROOT))]
    assert tree.nodes == before and tree.secured == []


@pytest.mark.parametrize(
    "case",
    (
        "unknown_drive",
        "missing_root",
        "remote",
        "optical",
        "ram_disk",
        "fat32",
        "lowercase_fs",
        "null_record",
        "duck_record",
        "mapping_record",
        "subclass_record",
        "bool_drive",
        "float_drive",
        "text_drive",
        "negative_drive",
        "oversized_drive",
        "subclass_drive",
        "bytes_fs",
        "subclass_fs",
    ),
)
def test_volume_record_and_fields_are_not_coerced(tree: _Tree, case: str) -> None:
    class DerivedFacts(security.StateVolumeFacts):
        pass

    facts: object = {
        "unknown_drive": security.StateVolumeFacts(0, "NTFS"),
        "missing_root": security.StateVolumeFacts(1, "NTFS"),
        "remote": security.StateVolumeFacts(4, "NTFS"),
        "optical": security.StateVolumeFacts(5, "NTFS"),
        "ram_disk": security.StateVolumeFacts(6, "NTFS"),
        "fat32": security.StateVolumeFacts(3, "FAT32"),
        "lowercase_fs": security.StateVolumeFacts(3, "ntfs"),
        "null_record": None,
        "duck_record": SimpleNamespace(drive_type=3, filesystem="NTFS"),
        "mapping_record": {"drive_type": 3, "filesystem": "NTFS"},
        "subclass_record": DerivedFacts(3, "NTFS"),
        "bool_drive": security.StateVolumeFacts(cast(int, True), "NTFS"),
        "float_drive": security.StateVolumeFacts(cast(int, 3.0), "NTFS"),
        "text_drive": security.StateVolumeFacts(cast(int, "3"), "NTFS"),
        "negative_drive": security.StateVolumeFacts(-1, "NTFS"),
        "oversized_drive": security.StateVolumeFacts(2**32, "NTFS"),
        "subclass_drive": security.StateVolumeFacts(_Integer(3), "NTFS"),
        "bytes_fs": security.StateVolumeFacts(3, cast(str, b"NTFS")),
        "subclass_fs": security.StateVolumeFacts(3, _Text("NTFS")),
    }[case]

    def probe(root: str) -> security.StateVolumeFacts:
        tree.events.append(("volume", root))
        return cast(security.StateVolumeFacts, facts)

    with pytest.raises(security.StateDirectorySecurityError):
        _call("ancestry", probe=probe)
    assert tree.events == [("volume", str(ROOT))]
    assert tree.secured == []


@pytest.mark.parametrize("entrypoint", ("ancestry", "directory", "file", "database"))
def test_fixed_ntfs_reaches_only_the_injected_ordinary_state_operations(
    tree: _Tree,
    entrypoint: str,
) -> None:
    result = _call(entrypoint, probe=_probe(tree))
    assert tree.events[0] == ("volume", str(ROOT))
    if entrypoint == "ancestry":
        assert result == DIRECTORY
        assert all(event[0] not in {"backend", "mkdir", "acl"} for event in tree.events)
    elif entrypoint == "directory":
        assert result == DIRECTORY
        assert tree.secured == [(DIRECTORY, True)]
        assert ("mkdir", str(DIRECTORY)) in tree.events
    elif entrypoint == "file":
        assert result is True
        assert tree.secured == [(DATABASE, False)]
    else:
        assert result == DATABASE
        assert tree.secured == [(STATE, True), (DATABASE, False)]
        assert [event for event in tree.events if event[0] == "volume"] == [
            ("volume", str(ROOT))
        ] * 6


def test_default_probe_reads_fresh_facts_for_each_admission(
    tree: _Tree,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def facts(root: str) -> security.StateVolumeFacts:
        calls.append(root)
        return security.StateVolumeFacts(3, "NTFS" if len(calls) == 1 else "ReFS")

    monkeypatch.setattr(security, "_windows_volume_facts", facts)
    assert _call("ancestry", probe=None) == DIRECTORY
    tree.events.clear()
    with pytest.raises(security.StateDirectorySecurityError):
        _call("ancestry", probe=None)
    assert calls == [str(ROOT), str(ROOT)]
    assert tree.events == []


def test_database_nested_admission_reuses_probe_but_never_cached_facts(tree: _Tree) -> None:
    calls: list[str] = []

    def probe(root: str) -> security.StateVolumeFacts:
        calls.append(root)
        return security.StateVolumeFacts(3, "NTFS" if len(calls) == 1 else "ReFS")

    with pytest.raises(security.StateDirectorySecurityError):
        _call("database", probe=probe)
    assert calls == [str(ROOT), str(ROOT)]
    assert tree.secured == []
    assert all(event[0] != "mkdir" for event in tree.events)


@pytest.mark.parametrize(
    "path",
    (
        r"C:state\gatehouse.db",
        r"\state\gatehouse.db",
        r"\\server\share\gatehouse.db",
        r"C:\synthetic\NUL\gatehouse.db",
    ),
)
def test_lexical_refusal_precedes_volume_probe(tree: _Tree, path: str) -> None:
    with pytest.raises(security.StateDirectorySecurityError):
        security.validate_state_path_ancestry(path, _volume_probe=_probe(tree))
    assert tree.events == []


@pytest.mark.parametrize(
    "field,value",
    (
        ("st_mode", None),
        ("st_mode", True),
        ("st_mode", 33152.0),
        ("st_mode", "33152"),
        ("st_mode", _Integer(33152)),
        ("st_mode", -1),
        ("st_mode", 2**16),
        ("st_mode", 0o600),
        ("st_mode", 0xF000),
        ("st_file_attributes", None),
        ("st_file_attributes", False),
        ("st_file_attributes", 0.0),
        ("st_file_attributes", "0"),
        ("st_file_attributes", _Integer(0)),
        ("st_file_attributes", -1),
        ("st_file_attributes", 2**32),
        ("st_nlink", None),
        ("st_nlink", True),
        ("st_nlink", 1.0),
        ("st_nlink", "1"),
        ("st_nlink", _Integer(1)),
        ("st_nlink", 0),
        ("st_nlink", -1),
        ("st_nlink", 2**32),
    ),
)
def test_object_metadata_requires_exact_bounded_integer_fields(
    tree: _Tree,
    field: str,
    value: object,
) -> None:
    setattr(tree.nodes[DATABASE], field, value)
    with pytest.raises(
        security.StateDirectorySecurityError, match="metadata could not be verified"
    ):
        security._checked_kind(_fixture_path(str(DATABASE)))
    assert tree.secured == []


@pytest.mark.parametrize("field", ("st_mode", "st_file_attributes", "st_nlink"))
def test_object_metadata_has_no_missing_field_defaults(tree: _Tree, field: str) -> None:
    delattr(tree.nodes[DATABASE], field)
    with pytest.raises(
        security.StateDirectorySecurityError, match="metadata could not be verified"
    ):
        security._checked_kind(_fixture_path(str(DATABASE)))


@pytest.mark.parametrize("entrypoint", ("ancestry", "directory", "file", "database"))
def test_bad_ancestor_metadata_precedes_creation_and_acl_effects(
    tree: _Tree, entrypoint: str
) -> None:
    delattr(tree.nodes[BASE], "st_file_attributes")
    with pytest.raises(
        security.StateDirectorySecurityError, match="metadata could not be verified"
    ):
        _call(entrypoint, probe=_probe(tree))
    assert tree.secured == []
    assert all(event[0] != "mkdir" for event in tree.events)


@pytest.mark.parametrize("defect", ("reparse", "symlink", "hardlink"))
def test_valid_metadata_does_not_exempt_existing_link_refusals(tree: _Tree, defect: str) -> None:
    details = tree.nodes[DATABASE]
    if defect == "reparse":
        details.st_file_attributes = 0x400
    elif defect == "symlink":
        details.st_mode = stat.S_IFLNK | 0o600
    else:
        details.st_nlink = 2
    with pytest.raises(security.StateDirectorySecurityError):
        security._checked_kind(_fixture_path(str(DATABASE)))
    assert tree.secured == []


@pytest.mark.parametrize("directory,links", ((False, 1), (True, 1), (True, 2)))
def test_ordinary_file_and_directory_metadata_remain_admissible(
    tree: _Tree,
    directory: bool,
    links: int,
) -> None:
    details = _metadata(directory=directory)
    details.st_nlink = links
    tree.nodes[DATABASE] = details
    assert cast(object, security._checked_kind(_fixture_path(str(DATABASE)))) is details


@pytest.mark.parametrize("defect", ("missing_attributes", "bad_links", "fifo", "reparse"))
def test_recursive_plan_rejects_bad_child_before_any_acl_effect(tree: _Tree, defect: str) -> None:
    child = STATE / "ordinary.txt"
    details = _metadata()
    if defect == "missing_attributes":
        del details.st_file_attributes
    elif defect == "bad_links":
        details.st_nlink = False
    elif defect == "fifo":
        details.st_mode = stat.S_IFIFO | 0o600
    else:
        details.st_file_attributes = 0x400
    tree.nodes[child] = details
    with pytest.raises(security.StateDirectorySecurityError):
        security.secure_private_directory(str(STATE), recursive=True, _volume_probe=_probe(tree))
    assert tree.secured == []


def test_recursive_ordinary_plan_rechecks_before_each_fake_acl(tree: _Tree) -> None:
    directory = STATE / "ordinary"
    child = directory / "entry.txt"
    tree.nodes[directory] = _metadata(directory=True)
    tree.nodes[child] = _metadata()
    assert (
        cast(
            object,
            security.secure_private_directory(
                str(STATE),
                recursive=True,
                _volume_probe=_probe(tree),
            ),
        )
        == STATE
    )
    assert set(tree.secured) == {
        (STATE, True),
        (DATABASE, False),
        (directory, True),
        (child, False),
    }
    for index, event in enumerate(tree.events):
        if event[0] == "acl":
            assert tree.events[index - 1] == ("lstat", event[1])


def test_non_windows_development_does_not_probe_volume_or_initialize_acl(
    tree: _Tree,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security, "os", SimpleNamespace(name="posix", scandir=tree.scandir))

    def forbidden(root: str) -> security.StateVolumeFacts:
        pytest.fail("non-Windows development unexpectedly inspected a Windows volume")

    assert (
        cast(object, security.secure_private_directory(str(DIRECTORY), _volume_probe=forbidden))
        == DIRECTORY
    )
    assert DIRECTORY in tree.nodes
    assert all(event[0] not in {"volume", "backend", "acl"} for event in tree.events)


def test_non_windows_metadata_does_not_require_windows_only_attributes(
    tree: _Tree,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security, "os", SimpleNamespace(name="posix", scandir=tree.scandir))
    delattr(tree.nodes[DATABASE], "st_file_attributes")
    assert (
        cast(object, security._checked_kind(_fixture_path(str(DATABASE)))) is tree.nodes[DATABASE]
    )
