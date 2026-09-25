from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from gatehouse import state_security
from gatehouse.config import ConfigLoadError, load_main_config
from gatehouse.config.security import ObjectSecurity
from gatehouse.daemon.composition import compose_stock_daemon
from gatehouse.daemon.configuration import RuntimeConfiguration
from gatehouse.daemon.lease import InstallationDaemonLease, InstallationDaemonLeaseFactory
from gatehouse.state_security import (
    StateDirectorySecurityError,
    StateVolumeFacts,
    secure_database_state,
    secure_private_directory,
    secure_private_file,
)


def _fixture_path(value: str) -> Path:
    return cast(type[Path], cast(Any, state_security).Path)(value)


@pytest.fixture
def fixed_ntfs_volume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake volume/ancestor facts; descendant metadata stays in this fresh test root."""

    ancestors = frozenset(tmp_path.parents)
    assert 0 < len(ancestors) <= 256

    def lstat(self: Path) -> os.stat_result:
        candidate = Path(self)
        if candidate in ancestors:
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700,
                    st_file_attributes=0x10,
                    st_nlink=1,
                ),
            )
        if candidate.is_relative_to(tmp_path):
            # Resolve this binding at call time so each test's later metadata
            # substitutions still exercise the production rechecks.
            return Path.lstat(candidate)
        raise AssertionError("state fixture path is outside its synthetic tree")

    StateFixturePath = cast(
        type[Path], type("StateFixturePath", (type(tmp_path),), {"lstat": lstat})
    )

    def probe(root: str) -> StateVolumeFacts:
        assert root == tmp_path.anchor
        return StateVolumeFacts(drive_type=3, filesystem="NTFS")

    monkeypatch.setattr("gatehouse.state_security._windows_volume_facts", probe)
    monkeypatch.setattr(state_security, "Path", StateFixturePath)


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_state_fixture_models_only_exact_lexical_ancestors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_lstat(path: Path) -> os.stat_result:
        pytest.fail("synthetic state ancestry reached host metadata")

    monkeypatch.setattr(Path, "lstat", forbidden_lstat)
    ancestors = tuple(tmp_path.parents)
    assert 0 < len(ancestors) <= 256
    for ancestor in ancestors:
        details = state_security._checked_kind(_fixture_path(str(ancestor)))
        assert details.st_mode == stat.S_IFDIR | 0o700
        assert details.st_file_attributes == 0x10
        assert details.st_nlink == 1


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_state_fixture_descendants_keep_dynamic_lstat_delegation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = tmp_path / "synthetic-entry"
    expected = {
        tmp_path: SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x10, st_nlink=1
        ),
        child: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_file_attributes=0, st_nlink=1),
    }
    calls: list[Path] = []

    def delegated_lstat(path: Path) -> os.stat_result:
        assert type(path) is type(tmp_path)
        calls.append(path)
        return cast(os.stat_result, expected[path])

    monkeypatch.setattr(Path, "lstat", delegated_lstat)
    for path, details in expected.items():
        assert cast(object, state_security._checked_kind(_fixture_path(str(path)))) is details
    assert calls == [tmp_path, child]


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_state_fixture_rejects_unrelated_paths_without_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_lstat(path: Path) -> os.stat_result:
        pytest.fail("unrelated state fixture path reached host metadata")

    monkeypatch.setattr(Path, "lstat", forbidden_lstat)
    unrelated = tmp_path.parent / (tmp_path.name + "-outside-fixture")
    with pytest.raises(AssertionError, match="^state fixture path is outside its synthetic tree$"):
        _fixture_path(str(unrelated)).lstat()


class _RecordingAcl:
    def __init__(self, *, failure: OSError | None = None) -> None:
        self.calls: list[tuple[Path, bool]] = []
        self.created: list[Path] = []
        self._failure = failure

    def create_directory(self, path: Path) -> None:
        self.created.append(path)
        path.mkdir(parents=True)

    def secure(self, path: Path, *, is_directory: bool) -> None:
        self.calls.append((path, is_directory))
        if self._failure is not None:
            raise self._failure


class _FailOnCallAcl:
    def __init__(self, *, call_number: int) -> None:
        self.calls: list[tuple[Path, bool]] = []
        self._call_number = call_number

    def create_directory(self, path: Path) -> None:
        path.mkdir(parents=True)

    def secure(self, path: Path, *, is_directory: bool) -> None:
        self.calls.append((path, is_directory))
        if len(self.calls) == self._call_number:
            raise OSError("synthetic late Windows ACL failure")


class _UnexpectedLeaseFactory:
    def __init__(self) -> None:
        self.calls: list[Path] = []

    def acquire(self, path: Path) -> InstallationDaemonLease:
        self.calls.append(path)
        raise AssertionError("the daemon lease must follow state-root verification")


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_missing_state_directory_uses_private_creation_backend(tmp_path: Path) -> None:
    root = tmp_path / "new" / "state"
    backend = _RecordingAcl()
    assert secure_private_directory(root, _backend=backend) == root.absolute()
    assert backend.created == [root.absolute()]
    assert backend.calls == [(root.absolute(), True)]


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_private_creation_refusal_precedes_named_creation_or_acl_application(
    tmp_path: Path,
) -> None:
    class RefusingCreation(_RecordingAcl):
        def create_directory(self, path: Path) -> None:
            self.created.append(path)
            raise OSError("synthetic private creation refusal")

    root = tmp_path / "new" / "state"
    backend = RefusingCreation()
    with pytest.raises(StateDirectorySecurityError, match="permissions could not be secured"):
        secure_private_directory(root, _backend=backend)
    assert backend.created == [root.absolute()]
    assert backend.calls == [] and not root.parent.exists()


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_recursive_policy_secures_root_directories_and_files(tmp_path: Path) -> None:
    root = tmp_path / "relocated-state"
    custody = root / "credentials" / "nested"
    custody.mkdir(parents=True)
    database = root / "gatehouse.db"
    ciphertext = custody / "credential.dpapi"
    database.write_bytes(b"database")
    ciphertext.write_bytes(b"ciphertext")
    backend = _RecordingAcl()

    secured = secure_private_directory(root, recursive=True, _backend=backend)

    assert secured == root.absolute()
    assert backend.calls[0] == (root.absolute(), True)
    assert backend.calls == [
        (root.absolute(), True),
        (root.absolute() / "credentials", True),
        (database.absolute(), False),
        (root.absolute() / "credentials" / "nested", True),
        (ciphertext.absolute(), False),
    ]


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_existing_file_policy_is_typed_and_absence_is_non_mutating(tmp_path: Path) -> None:
    state_file = tmp_path / "gatehouse.db"
    backend = _RecordingAcl()

    assert not secure_private_file(state_file, _backend=backend)
    state_file.write_bytes(b"database")
    assert secure_private_file(state_file, _backend=backend)
    assert backend.calls == [(state_file.absolute(), False)]


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_covers_live_sqlite_files_in_a_dedicated_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "relocated-state"
    root.mkdir()
    database = root / "gatehouse.db"
    wal = Path(f"{database}-wal")
    journal = Path(f"{database}-journal")
    for path in (database, wal, journal):
        path.write_bytes(b"state")
    backend = _RecordingAcl()

    secured = secure_database_state(database, must_exist=True, _backend=backend)

    assert secured == database.absolute()
    assert backend.calls == [
        (root.absolute(), True),
        (database.absolute(), False),
        (wal.absolute(), False),
        (journal.absolute(), False),
    ]


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_rejects_an_unmanaged_sibling_before_acl_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "shared-project"
    root.mkdir()
    database = root / "gatehouse.db"
    database.write_bytes(b"database")
    unmanaged = root / "operator-note.txt"
    unmanaged.write_bytes(b"unchanged")
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state directory is not a dedicated Gatehouse root$",
    ):
        secure_database_state(database, must_exist=True, _backend=backend)

    assert backend.calls == []
    assert database.read_bytes() == b"database"
    assert unmanaged.read_bytes() == b"unchanged"


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_rejects_case_variant_identity_before_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    database = root / "gatehouse.db"
    database.write_bytes(b"database")
    case_variant = tmp_path / "case-variant-sentinel"
    case_variant.write_bytes(b"unchanged")
    real_scandir = os.scandir

    class _SyntheticScandir:
        def __enter__(self) -> object:
            return iter(
                (
                    SimpleNamespace(name="gatehouse.db", path=str(database)),
                    SimpleNamespace(name="GATEHOUSE.DB", path=str(case_variant)),
                )
            )

        def __exit__(self, *_args: object) -> None:
            return None

    def scandir_with_case_variant(path: str | os.PathLike[str]) -> object:
        if Path(path) == root.absolute():
            return _SyntheticScandir()
        return real_scandir(path)

    monkeypatch.setattr("gatehouse.state_security.os.scandir", scandir_with_case_variant)
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state directory is not a dedicated Gatehouse root$",
    ):
        secure_database_state(database, must_exist=True, _backend=backend)

    assert backend.calls == []
    assert database.read_bytes() == b"database"
    assert case_variant.read_bytes() == b"unchanged"


@pytest.mark.parametrize(
    "database_name",
    ("credentials", "installation-key.dpapi", "control-capability.verifier"),
)
@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_rejects_reserved_database_names_before_acl_mutation(
    tmp_path: Path,
    database_name: str,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state database name conflicts with a reserved object$",
    ):
        secure_database_state(root / database_name, _backend=backend)

    assert backend.calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows component aliases are Windows-specific")
@pytest.mark.parametrize(
    "database_path",
    (
        Path(r"C:\Gatehouse\gatehoused.lock."),
        Path(r"C:\Gatehouse\installation-key.dpapi "),
        Path(r"C:\Gatehouse\database.db:alternate"),
        Path(r"C:\Gatehouse\NUL.db"),
        Path(r"C:\Gatehouse\NUL .db"),
        Path(r"C:\Gatehouse\COM¹.txt"),
        Path(r"C:\Gatehouse\GATEHO~1.LOC"),
    ),
)
def test_database_policy_rejects_windows_alias_components_before_acl_mutation(
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "gatehouse.state_security._windows_volume_facts",
        lambda _root: StateVolumeFacts(drive_type=3, filesystem="NTFS"),
    )
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state path uses an unsafe Windows component$",
    ):
        secure_database_state(database_path, _backend=backend)

    assert backend.calls == []


def test_database_policy_rejects_hard_linked_database_before_acl_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    database = root / "gatehouse.db"
    os.link(outside, database)
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state cannot use a multiply linked file$",
    ):
        secure_database_state(database, must_exist=True, _backend=backend)

    assert backend.calls == []
    assert os.path.samefile(outside, database)
    assert outside.read_bytes() == b"outside"


def test_database_policy_rejects_hard_linked_fixed_file_before_acl_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    fixed_file = root / "gatehoused.lock"
    os.link(outside, fixed_file)
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state cannot use a multiply linked file$",
    ):
        secure_database_state(root / "gatehouse.db", _backend=backend)

    assert backend.calls == []
    assert os.path.samefile(outside, fixed_file)
    assert outside.read_bytes() == b"outside"


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_does_not_create_a_required_missing_database(tmp_path: Path) -> None:
    database = tmp_path / "state" / "gatehouse.db"

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state directory is unavailable$",
    ):
        secure_database_state(
            database,
            must_exist=True,
            _backend=_RecordingAcl(),
        )

    assert not database.parent.exists()
    assert not database.exists()


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_does_not_secure_existing_parent_when_required_database_is_missing(
    tmp_path: Path,
) -> None:
    root = tmp_path / "existing-state"
    root.mkdir()
    sentinel = root / "operator-note.txt"
    sentinel.write_bytes(b"unchanged")
    database = root / "missing.db"
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state database is unavailable$",
    ):
        secure_database_state(database, must_exist=True, _backend=backend)

    assert backend.calls == []
    assert sentinel.read_bytes() == b"unchanged"
    assert not database.exists()


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_preflights_reparse_sidecar_before_any_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    database = root / "gatehouse.db"
    database.write_bytes(b"database")
    sidecar = Path(f"{database}-wal")
    sidecar.write_bytes(b"wal")
    original_lstat = Path.lstat

    def reparse_sidecar_lstat(path: Path) -> os.stat_result:
        if path.absolute() == sidecar.absolute():
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_file_attributes=0x0400,
                    st_nlink=1,
                ),
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", reparse_sidecar_lstat)
    backend = _RecordingAcl()

    with pytest.raises(StateDirectorySecurityError, match="reparse point"):
        secure_database_state(database, must_exist=True, _backend=backend)

    assert backend.calls == []


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_database_policy_preflights_nonregular_sidecar_before_any_acl_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    database = root / "gatehouse.db"
    database.write_bytes(b"database")
    Path(f"{database}-shm").mkdir()
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state file is not a regular file$",
    ):
        secure_database_state(database, must_exist=True, _backend=backend)

    assert backend.calls == []


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_reparse_state_root_is_rejected_before_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "state").absolute()
    root.mkdir()
    original_lstat = Path.lstat

    def reparse_lstat(path: Path) -> os.stat_result:
        if path.absolute() == root:
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700,
                    st_file_attributes=0x0400,
                    st_nlink=1,
                ),
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state cannot use a reparse point$",
    ):
        secure_private_directory(root, _backend=backend)

    assert backend.calls == []


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_symlink_mode_is_rejected_without_following_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "state").absolute()
    root.mkdir()
    original_lstat = Path.lstat

    def symlink_lstat(path: Path) -> os.stat_result:
        if path.absolute() == root:
            return cast(
                os.stat_result,
                SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0, st_nlink=1),
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", symlink_lstat)

    with pytest.raises(StateDirectorySecurityError, match="reparse point"):
        secure_private_directory(root, _backend=_RecordingAcl())


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_missing_relocated_root_rejects_reparse_ancestor_before_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirect = (tmp_path / "relocated-junction").absolute()
    redirect.mkdir()
    state = redirect / "missing-state"
    original_lstat = Path.lstat

    def reparse_ancestor_lstat(path: Path) -> os.stat_result:
        if path.absolute() == redirect:
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700,
                    st_file_attributes=0x0400,
                    st_nlink=1,
                ),
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", reparse_ancestor_lstat)
    backend = _RecordingAcl()

    with pytest.raises(StateDirectorySecurityError, match="reparse point"):
        secure_private_directory(state, _backend=backend)

    assert backend.calls == []
    assert not state.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows drive locality is Windows-specific")
@pytest.mark.parametrize(
    "unsafe_path",
    (
        Path(r"\\synthetic-server\synthetic-share\state\gatehouse.db"),
        Path(r"\\?\UNC\synthetic-server\synthetic-share\state\gatehouse.db"),
        Path(r"\\.\synthetic-share\state\gatehouse.db"),
    ),
)
def test_unc_and_device_share_state_paths_are_rejected_without_filesystem_access(
    unsafe_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_drive_probe(_root: str) -> int:
        raise AssertionError("UNC/device paths must fail before a drive probe")

    monkeypatch.setattr(
        "gatehouse.state_security._windows_volume_facts",
        unexpected_drive_probe,
    )
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state requires a local Windows drive$",
    ):
        secure_database_state(unsafe_path, _backend=backend)

    assert backend.calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows path rooting is Windows-specific")
@pytest.mark.parametrize(
    "ambiguous_path",
    (
        Path(r"C:state\gatehouse.db"),
        Path(r"\state\gatehouse.db"),
    ),
)
def test_drive_or_root_relative_state_paths_are_rejected_before_filesystem_access(
    ambiguous_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_drive_probe(_root: str) -> int:
        raise AssertionError("ambiguous paths must fail before a drive probe")

    monkeypatch.setattr(
        "gatehouse.state_security._windows_volume_facts",
        unexpected_drive_probe,
    )
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state path is ambiguously rooted$",
    ):
        secure_database_state(ambiguous_path, _backend=backend)

    assert backend.calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows drive locality is Windows-specific")
@pytest.mark.parametrize("drive_type", (0, 1, 4, 5))
def test_nonlocal_or_unverifiable_drive_type_fails_before_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drive_type: int,
) -> None:
    database = tmp_path / "state" / "gatehouse.db"
    monkeypatch.setattr(
        "gatehouse.state_security._windows_volume_facts",
        lambda _root: StateVolumeFacts(drive_type=drive_type, filesystem="NTFS"),
    )
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state requires a fixed NTFS Windows drive$",
    ):
        secure_database_state(database, _backend=backend)

    assert backend.calls == []
    assert not database.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows drive locality is Windows-specific")
def test_drive_locality_probe_failure_is_sanitized_and_nonmutating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "state" / "gatehouse.db"

    def unavailable_drive_probe(_root: str) -> int:
        raise OSError("synthetic mapped-drive detail")

    monkeypatch.setattr(
        "gatehouse.state_security._windows_volume_facts",
        unavailable_drive_probe,
    )

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state volume could not be verified$",
    ) as captured:
        secure_database_state(database, _backend=_RecordingAcl())

    assert "synthetic" not in str(captured.value)
    assert str(database) not in str(captured.value)
    assert not database.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="configuration reparse policy is Windows-specific")
@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_main_configuration_rejects_reparse_ancestor_before_canonicalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirect = (tmp_path / "configured-junction").absolute()
    redirect.mkdir()
    database = redirect / "missing-state" / "gatehouse.db"
    source = Path(__file__).parents[2] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        source.read_text(encoding="utf-8").replace(
            r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
            f"'{database.as_posix()}'",
        ),
        encoding="utf-8",
    )
    original_lstat = Path.lstat

    def configured_reparse_lstat(path: Path) -> os.stat_result:
        if path.absolute() == redirect:
            return cast(
                os.stat_result,
                SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700,
                    st_file_attributes=0x0400,
                    st_nlink=1,
                ),
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", configured_reparse_lstat)

    with pytest.raises(
        ConfigLoadError,
        match="^configuration validation failed for config.yaml: database state path is unsafe$",
    ):
        load_main_config(config_path)

    assert not database.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="configuration drive policy is Windows-specific")
def test_main_configuration_rejects_mapped_remote_drive_before_canonicalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "remote-shaped-state" / "gatehouse.db"
    source = Path(__file__).parents[2] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        source.read_text(encoding="utf-8").replace(
            r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
            f"'{database.as_posix()}'",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "gatehouse.state_security._windows_volume_facts",
        lambda _root: StateVolumeFacts(drive_type=4, filesystem="NTFS"),
    )

    with pytest.raises(
        ConfigLoadError,
        match="^configuration validation failed for config.yaml: database state path is unsafe$",
    ):
        load_main_config(config_path)

    assert not database.parent.exists()


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_acl_platform_failure_is_sanitized_and_typed(tmp_path: Path) -> None:
    root = tmp_path / "state"
    backend = _RecordingAcl(failure=OSError("synthetic sensitive account detail"))

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state permissions could not be secured$",
    ) as captured:
        secure_private_directory(root, _backend=backend)

    assert "synthetic" not in str(captured.value)
    assert str(root) not in str(captured.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL backend is Windows-specific")
@pytest.mark.parametrize("failure_type", (AttributeError, OSError, TypeError, ValueError))
@pytest.mark.parametrize("policy", ("directory", "file", "database"))
@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_acl_backend_construction_failure_is_sanitized_and_nonmutating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[Exception],
    policy: str,
) -> None:
    root = tmp_path / "sensitive-state"
    target = root / "gatehouse.db"

    def unavailable_backend() -> None:
        raise failure_type("synthetic Windows API and account detail")

    monkeypatch.setattr(
        "gatehouse.state_security._windows_backend",
        unavailable_backend,
    )

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state permissions could not be secured$",
    ) as captured:
        if policy == "directory":
            secure_private_directory(root)
        elif policy == "file":
            secure_private_file(target)
        else:
            secure_database_state(target)

    assert "synthetic" not in str(captured.value)
    assert str(root) not in str(captured.value)
    assert not root.exists()


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_recursive_verification_is_bounded(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir()
    (root / "one").write_bytes(b"1")
    (root / "two").write_bytes(b"2")

    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state directory exceeds its verification bound$",
    ):
        secure_private_directory(
            root,
            recursive=True,
            maximum_entries=1,
            _backend=backend,
        )

    assert backend.calls == []


@pytest.mark.parametrize(
    ("details", "message"),
    (
        (
            SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_file_attributes=0x0400,
                st_nlink=1,
            ),
            "mutable state cannot use a reparse point",
        ),
        (
            SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_file_attributes=0, st_nlink=1),
            "mutable state contains an unsupported filesystem object",
        ),
    ),
)
@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_recursive_policy_preflights_late_unsafe_entry_before_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    details: SimpleNamespace,
    message: str,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    (root / "a-safe").write_bytes(b"safe")
    unsafe = root / "z-unsafe"
    unsafe.write_bytes(b"unsafe")
    original_lstat = Path.lstat

    def unsafe_lstat(path: Path) -> os.stat_result:
        if path.absolute() == unsafe.absolute():
            return cast(os.stat_result, details)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", unsafe_lstat)
    backend = _RecordingAcl()

    with pytest.raises(StateDirectorySecurityError, match=f"^{message}$"):
        secure_private_directory(root, recursive=True, _backend=backend)

    assert backend.calls == []


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_recursive_policy_bounds_aggregate_path_plan_before_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    (root / "child").write_bytes(b"state")
    monkeypatch.setattr(
        "gatehouse.state_security._MAXIMUM_DIRECTORY_PLAN_CHARACTERS",
        len(str(root)),
    )
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state directory exceeds its path-plan bound$",
    ):
        secure_private_directory(root, recursive=True, _backend=backend)

    assert backend.calls == []


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_recursive_acl_application_failure_can_leave_a_hardened_prefix(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    first = root / "a-first"
    later = root / "z-later"
    first.write_bytes(b"first")
    later.write_bytes(b"later")
    backend = _FailOnCallAcl(call_number=2)

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state permissions could not be secured$",
    ) as captured:
        secure_private_directory(root, recursive=True, _backend=backend)

    assert backend.calls == [
        (root.absolute(), True),
        (first.absolute(), False),
    ]
    assert "synthetic" not in str(captured.value)


@pytest.mark.usefixtures("fixed_ntfs_volume")
def test_recursive_policy_rechecks_toctou_before_each_acl_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    changed = root / "a-changed"
    changed.write_bytes(b"state")
    original_lstat = Path.lstat
    changed_checks = 0

    def changing_lstat(path: Path) -> os.stat_result:
        nonlocal changed_checks
        if path.absolute() == changed.absolute():
            changed_checks += 1
            if changed_checks > 1:
                return cast(
                    os.stat_result,
                    SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o600,
                        st_file_attributes=0x0400,
                        st_nlink=1,
                    ),
                )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", changing_lstat)
    backend = _RecordingAcl()

    with pytest.raises(
        StateDirectorySecurityError,
        match="^mutable state cannot use a reparse point$",
    ):
        secure_private_directory(root, recursive=True, _backend=backend)

    assert changed_checks == 2
    assert backend.calls == [(root.absolute(), True)]


@pytest.mark.usefixtures("fixed_ntfs_volume")
async def test_relocated_state_acl_failure_precedes_lease_and_database_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).parents[2] / "config" / "config.example.yaml"
    main = load_main_config(source, environment={"LOCALAPPDATA": str(tmp_path / "default")})
    database_path = tmp_path / "relocated" / "dedicated-state" / "gatehouse.db"
    main = main.model_copy(
        update={
            "database": main.database.model_copy(update={"path": str(database_path)}),
        }
    )
    configuration = RuntimeConfiguration(main=main, clients=(), policies=(), feed_sets=())
    lease_factory = _UnexpectedLeaseFactory()
    observed: list[Path] = []

    def deny_state_root(path: str | Path, **_kwargs: object) -> Path:
        observed.append(Path(path))
        raise StateDirectorySecurityError("synthetic unsafe relocated root")

    monkeypatch.setattr(
        "gatehouse.daemon.composition.secure_database_state",
        deny_state_root,
    )

    with pytest.raises(StateDirectorySecurityError, match="unsafe relocated root"):
        await compose_stock_daemon(
            configuration,
            config_path=tmp_path / "config.yaml",
            lease_factory=cast(InstallationDaemonLeaseFactory, lease_factory),
        )

    assert observed == [database_path]
    assert lease_factory.calls == []
    assert not database_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="native DACL verification requires Windows")
def test_native_windows_policy_is_owner_only_protected_and_recursive(tmp_path: Path) -> None:
    root = tmp_path / "state"
    child = root / "credentials"
    child.mkdir(parents=True)
    state_file = child / "credential.dpapi"
    state_file.write_bytes(b"ciphertext")

    secure_private_directory(root, recursive=True)

    assert root.is_dir()
    assert child.is_dir()
    assert state_file.read_bytes() == b"ciphertext"
    for path, directory in ((root, True), (child, True), (state_file, False)):
        _assert_native_private_descriptor(path, directory=directory)


def _native_ancestor_refusal_category(facts: object, expected_path: str, user_sid: str) -> str:
    from gatehouse.state_windows import (
        _MUTATION_ACCESS,
        _TRUSTED_OS_SIDS,
        StateAccessRule,
        StateObjectFacts,
        _sid,
    )

    if type(facts) is not StateObjectFacts:
        return "facts"
    if facts.final_path != expected_path:
        return "path"
    if facts.reparse or not facts.directory or facts.links < 1:
        return "kind"
    if not 0 <= facts.volume_serial <= 0xFFFFFFFF or not 0 < facts.file_id <= 2**64 - 1:
        return "identity"
    if facts.drive_type != 3 or facts.filesystem != "NTFS":
        return "volume"
    trusted = _TRUSTED_OS_SIDS | {user_sid}
    if facts.owner_sid not in trusted:
        return "owner"
    if type(facts.rules) is not tuple or len(facts.rules) > 128:
        return "ace-shape"
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
        ):
            return "ace-shape"
    outsider_rules = [
        rule
        for rule in facts.rules
        if rule.kind == 0
        and not rule.flags & 0x08
        and rule.sid not in trusted
        and not (rule.sid == "S-1-3-4" and facts.owner_sid in trusted)
    ]
    mutators = [rule for rule in outsider_rules if rule.mask & _MUTATION_ACCESS & ~0x06]
    if mutators:
        if all(rule.sid == "S-1-3-0" for rule in mutators):
            return "creator-owner-mutation"
        return "outsider-mutation"
    if any(rule.mask & _MUTATION_ACCESS for rule in outsider_rules):
        return "outsider-add-child"
    return "policy"


@pytest.mark.parametrize(
    "owner,sids,category",
    [
        ("S-1-5-21-4-5-6-1002", ("S-1-3-4",), "owner"),
        ("S-1-5-21-1-2-3-1001", ("S-1-3-0",), "creator-owner-mutation"),
        ("S-1-5-21-1-2-3-1001", ("S-1-1-0",), "outsider-mutation"),
        ("S-1-5-21-1-2-3-1001", ("S-1-3-4", "S-1-1-0"), "outsider-mutation"),
    ],
)
def test_native_ancestor_refusal_categories_do_not_relax_special_sid_authority(
    owner: str,
    sids: tuple[str, ...],
    category: str,
) -> None:
    from gatehouse.state_windows import (
        StateAccessRule,
        StateFilesystem,
        StateObjectFacts,
        WindowsPrivateAcl,
    )

    user = "S-1-5-21-1-2-3-1001"
    path = r"C:\Synthetic"
    facts = StateObjectFacts(
        path,
        7,
        1,
        True,
        False,
        1,
        3,
        "NTFS",
        owner,
        True,
        tuple(StateAccessRule(sid, 0x001F01FF, 0, 0) for sid in sids),
    )
    policy = WindowsPrivateAcl(
        filesystem=cast(StateFilesystem, SimpleNamespace(execution_sid=user)),
    )
    with pytest.raises(OSError):
        policy._require(facts, path, directory=True, allow_child_creation=True)
    assert _native_ancestor_refusal_category(facts, path, user) == category


def _native_exact_ancestor_preflight(path: Path) -> tuple[tuple[int, str], ...]:
    """Metadata handles only; expose no names, descriptors, SIDs or file contents."""
    from gatehouse.state_windows import NativeStateFilesystem, WindowsPrivateAcl, _chain

    try:
        chain = _chain(path)
        native = NativeStateFilesystem()
        policy = WindowsPrivateAcl(filesystem=native)
    except Exception:
        return ((-1, "initialization"),)
    handles = []
    originals = []
    result: tuple[tuple[int, str], ...] = ()
    try:
        for index, component in enumerate(chain):
            try:
                handle = native.open_existing(component)
                handles.append((index, handle))
                facts = native.describe(handle)
            except Exception:
                result = ((index, "metadata"),)
                break
            try:
                policy._require(
                    facts,
                    component,
                    directory=True,
                    allow_child_creation=index < len(chain) - 1,
                )
            except Exception:
                result = (
                    (
                        index,
                        _native_ancestor_refusal_category(
                            facts,
                            component,
                            native.execution_sid,
                        ),
                    ),
                )
                break
            originals.append((index, handle, facts))
        if not result:
            for index, handle, original in originals:
                try:
                    unchanged = native.describe(handle) == original
                except Exception:
                    result = ((index, "metadata"),)
                    break
                if not unchanged:
                    result = ((index, "changed"),)
                    break
    finally:
        for index, handle in reversed(handles):
            try:
                native.close(handle)
            except Exception:
                if not result:
                    result = ((index, "close"),)
    return result


@pytest.mark.skipif(os.name != "nt", reason="native ancestor metadata requires Windows")
def test_native_windows_exact_ancestor_preflight_reports_only_index_and_category(
    tmp_path: Path,
) -> None:
    report = _native_exact_ancestor_preflight(tmp_path)
    assert report == (), "native state ancestry admission failed"


def _native_state_descriptor(path: Path) -> tuple[str, ObjectSecurity]:
    from gatehouse.config.security import NativeConfigurationFilesystem

    reader = NativeConfigurationFilesystem()
    handle = reader.open_existing(str(path))
    try:
        return reader.execution_sid, reader.describe(handle)
    finally:
        reader.close(handle)


def _native_stored_security_fingerprint(path: Path) -> tuple[bool, str]:
    """Compare only fixed flags and a digest of a bounded synthetic descriptor."""
    import ctypes
    import hashlib
    from ctypes import wintypes

    from gatehouse.config.security import _NativeHandle
    from gatehouse.state_windows import NativeStateFilesystem

    native = NativeStateFilesystem()
    query = ctypes.WinDLL("Ntdll.dll", use_last_error=True).NtQuerySecurityObject
    query.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query.restype = ctypes.c_int32
    handle = native.open_existing(str(path))
    try:
        buffer = ctypes.create_string_buffer(65_536)
        required = wintypes.DWORD()
        status = query(cast(_NativeHandle, handle).value, 5, buffer, 65_536, ctypes.byref(required))
        assert status == 0 and 20 <= required.value <= 65_536
        payload = buffer.raw[: required.value]
        control = int.from_bytes(payload[2:4], "little")
        assert control & 0x8000  # Native API guarantees a self-relative descriptor.
        return bool(control & 0x1000), hashlib.sha256(payload).hexdigest()
    finally:
        native.close(handle)


def _assert_native_private_descriptor(path: Path, *, directory: bool) -> None:
    from gatehouse.config.security import AccessRule

    user, observed = _native_state_descriptor(path)
    assert observed.owner_sid == user
    assert observed.dacl_protected
    assert observed.dacl == (AccessRule(user, 0x001F01FF, 3 if directory else 0, 0),)
    assert observed.is_directory is directory
    assert not observed.reparse
    assert observed.identity.file_id > 0


@pytest.mark.skipif(os.name != "nt", reason="native private creation requires Windows")
def test_native_windows_creation_supplies_private_descriptor_before_return(tmp_path: Path) -> None:
    from gatehouse.state_windows import NativeStateFilesystem

    native = NativeStateFilesystem()
    root = tmp_path / "native-private-create"
    native.create_directory(str(root), owner_sid=native.execution_sid)
    _assert_native_private_descriptor(root, directory=True)


@pytest.mark.skipif(os.name != "nt", reason="native protection transition requires Windows")
@pytest.mark.parametrize("operation", ["direct", "policy"])
def test_native_windows_existing_unprotected_target_becomes_exact_private_acl(
    tmp_path: Path,
    operation: str,
) -> None:
    import ctypes
    from ctypes import wintypes

    from gatehouse.state_windows import NativeStateFilesystem, _SecurityAttributes

    native = NativeStateFilesystem()
    root = tmp_path / "native-unprotected-target"
    descriptor, size = ctypes.c_void_p(), wintypes.DWORD()
    assert native._api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{native.execution_sid}D:(A;OICI;FA;;;{native.execution_sid})",
        1,
        ctypes.byref(descriptor),
        ctypes.byref(size),
    )
    try:
        assert descriptor.value and 20 <= size.value <= 65_536
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        assert native._api.kernel32.CreateDirectoryW(str(root), ctypes.byref(attributes))
    finally:
        assert not native._api.kernel32.LocalFree(descriptor)
    _user, before = _native_state_descriptor(root)
    assert not before.dacl_protected and _native_stored_security_fingerprint(root)[0] is False

    if operation == "direct":
        handle = native.open_existing(str(root), writable=True, exclusive=True)
        try:
            native.set_private_acl(handle, is_directory=True, owner_sid=native.execution_sid)
        finally:
            native.close(handle)
    else:
        secure_private_directory(root, must_exist=True)

    _assert_native_private_descriptor(root, directory=True)
    assert _native_stored_security_fingerprint(root)[0] is True
    _user, after = _native_state_descriptor(root)
    assert after.identity == before.identity and after.owner_sid == before.owner_sid


@pytest.mark.skipif(os.name != "nt", reason="native ACL propagation requires Windows")
@pytest.mark.parametrize("reader_kind", ["adapter", "stored"])
def test_native_windows_exclusive_directory_update_does_not_propagate(
    tmp_path: Path,
    reader_kind: str,
) -> None:
    import ctypes
    from ctypes import wintypes

    from gatehouse.state_windows import NativeStateFilesystem, _SecurityAttributes

    native = NativeStateFilesystem()
    root = tmp_path / "native-nonrecursive"
    native.create_directory(str(root), owner_sid=native.execution_sid)
    handle = native.open_existing(str(root), writable=True, exclusive=True)
    try:
        # A fixture-only noninheritable parent makes later propagation observable.
        native.set_private_acl(handle, is_directory=False, owner_sid=native.execution_sid)
    finally:
        native.close(handle)

    child = root / "read-only-child"
    descriptor, size = ctypes.c_void_p(), wintypes.DWORD()
    assert native._api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{native.execution_sid}D:(A;OICI;FR;;;{native.execution_sid})",
        1,
        ctypes.byref(descriptor),
        ctypes.byref(size),
    )
    try:
        assert descriptor.value and 20 <= size.value <= 65_536
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        assert native._api.kernel32.CreateDirectoryW(str(child), ctypes.byref(attributes))
    finally:
        assert not native._api.kernel32.LocalFree(descriptor)
    _user, before = _native_state_descriptor(child)
    assert not before.dacl_protected
    assert before.dacl and all(ace.mask != 0x001F01FF for ace in before.dacl)
    stored_before = _native_stored_security_fingerprint(child)
    assert stored_before[0] is False

    handle = native.open_existing(str(root), writable=True, exclusive=True)
    try:
        native.set_private_acl(handle, is_directory=True, owner_sid=native.execution_sid)
    finally:
        native.close(handle)
    if reader_kind == "stored":
        assert _native_stored_security_fingerprint(child) == stored_before, (
            "direct effect changed stored child security"
        )
    _assert_native_private_descriptor(root, directory=True)
    _user, after = _native_state_descriptor(child)
    if reader_kind == "stored":
        assert _native_stored_security_fingerprint(child) == stored_before
    else:
        assert (after.owner_sid, after.dacl_protected, after.dacl) == (
            before.owner_sid,
            before.dacl_protected,
            before.dacl,
        )
