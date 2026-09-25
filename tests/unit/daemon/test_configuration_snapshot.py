from __future__ import annotations

import hashlib
from collections.abc import Coroutine
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any, TypedDict, cast

import pytest
import yaml

from gatehouse.config import ConfigLoadError, MainConfig, security
from gatehouse.config.loader import ConfigLoadStage
from gatehouse.config.security import ConfigSecurityError, ConfigurationSnapshot
from gatehouse.daemon import composition, configuration
from gatehouse.providers.scripted import ScriptedProviderTransport

_CONFIG_ROOT = Path(__file__).parents[3] / "config"


@dataclass(frozen=True, slots=True)
class CapturedDocument:
    relative_path: str
    content: bytes


CapturedSnapshot = ConfigurationSnapshot


def _capture_documents(
    main_path: Path,
    documents: tuple[CapturedDocument | security.ConfigurationDocument, ...],
    environment: tuple[tuple[str, str], ...],
    *,
    scripted_bytes: bytes | None = None,
) -> ConfigurationSnapshot:
    """Produce real digest bindings over a wholly in-memory filesystem model."""

    root = PureWindowsPath(str(main_path)).parent
    contents = {str(root / document.relative_path): document.content for document in documents}
    if scripted_bytes is not None:
        contents[str(root / "responses.json")] = scripted_bytes
    directories = {parent for name in contents for parent in PureWindowsPath(name).parents}
    objects: dict[str, security.ObjectSecurity] = {}
    members: dict[str, list[str]] = {str(path): [] for path in directories}
    for path in sorted(directories, key=lambda item: (len(item.parts), str(item))):
        objects[str(path)] = security.ObjectSecurity(
            security.FileIdentity(7, len(objects) + 1),
            str(path),
            True,
            "S-1-5-21-1-2-3-1001",
            (security.AccessRule("S-1-5-21-1-2-3-1001", 0x001F01FF, flags=3),),
            True,
        )
        if path.parent != path:
            members[str(path.parent)].append(path.name)
    for name, content in contents.items():
        objects[name] = security.ObjectSecurity(
            security.FileIdentity(7, len(objects) + 1),
            name,
            False,
            "S-1-5-21-1-2-3-1001",
            (security.AccessRule("S-1-5-21-1-2-3-1001", 0x001F01FF),),
            True,
            size=len(content),
        )
        members[str(PureWindowsPath(name).parent)].append(PureWindowsPath(name).name)

    class InMemoryFilesystem:
        execution_sid = "S-1-5-21-1-2-3-1001"

        def open_existing(self, path: str) -> str:
            assert path in objects
            return path

        def describe(self, handle: object) -> security.ObjectSecurity:
            assert isinstance(handle, str)
            return objects[handle]

        def entries(self, handle: object) -> tuple[str, ...]:
            assert isinstance(handle, str)
            return tuple(members[handle])

        def read(self, handle: object, maximum_bytes: int) -> bytes:
            assert isinstance(handle, str)
            return contents[handle][: maximum_bytes + 1]

        def close(self, handle: object) -> None:
            assert isinstance(handle, str)
            assert handle in objects

    return security.capture_configuration(
        main_path,
        backend=InMemoryFilesystem(),
        environment=dict(environment),
        scripted_document_selector=(
            None if scripted_bytes is None else lambda _raw, _path, _env: "responses.json"
        ),
    )


def _snapshot(tmp_path: Path) -> CapturedSnapshot:
    sources = (
        ("config.yaml", "config.example.yaml"),
        ("clients/watcher.yaml", "clients/company-watcher.example.yaml"),
        ("policies/placement.yaml", "policies/placement-schedule.example.yaml"),
        ("feeds/placement.yaml", "feeds/placement-companies-primary.example.yaml"),
    )
    return _capture_documents(
        main_path=tmp_path / "captured" / "config.yaml",
        documents=tuple(
            CapturedDocument(relative, (_CONFIG_ROOT / source).read_bytes())
            for relative, source in sources
        ),
        environment=(
            ("APPDATA", str(tmp_path / "captured-roaming")),
            ("LOCALAPPDATA", str(tmp_path / "captured-local")),
        ),
    )


def _inject_snapshot(monkeypatch: pytest.MonkeyPatch, snapshot: CapturedSnapshot) -> list[Path]:
    captures: list[Path] = []

    def capture(path: str | Path, **_kwargs: object) -> ConfigurationSnapshot:
        captures.append(Path(path))
        return snapshot

    monkeypatch.setattr(configuration, "capture_configuration", capture)
    monkeypatch.setattr(
        "gatehouse.config.loader.validate_state_path_ancestry", lambda path: Path(path)
    )
    return captures


def _forbid_file_reopens(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        calls.append("filesystem reopen")
        raise AssertionError("captured configuration must not reopen YAML paths")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "glob", forbidden)
    return calls


def _forbid_state_effects(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        calls.append("state or runtime effect")
        raise AssertionError("configuration failure must precede runtime effects")

    for name in (
        "secure_database_state",
        "secure_private_file",
        "installation_state_paths",
        "open_migrated_database",
        "recover_startup",
        "DpapiCurrentUserKeyStore",
        "load_or_create_installation_key",
        "_provider_transport",
        "_observer_transport",
        "create_daemon_applications",
        "_health_only_app",
        "serve",
    ):
        monkeypatch.setattr(composition, name, forbidden)
    return calls


def test_h3_runtime_preserves_raw_origin_until_security_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_origin = "C:/synthetic/config/./config.yaml"
    origins: list[str | Path] = []

    def rejected(path: str | Path, **_kwargs: object) -> None:
        origins.append(path)
        raise ConfigSecurityError("configuration path is not permitted")

    monkeypatch.setattr(configuration, "capture_configuration", rejected)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(raw_origin)
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert origins == [raw_origin]


def test_h3_runtime_parses_one_snapshot_without_reopening_any_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    captures = _inject_snapshot(monkeypatch, snapshot)
    reopens = _forbid_file_reopens(monkeypatch)

    loaded = configuration.load_runtime_configuration(snapshot.main_path)

    assert captures == [snapshot.main_path]
    assert reopens == []
    assert loaded.snapshot is snapshot
    assert loaded.main.firecrawl_workload.mode == "disabled"
    assert loaded.main.firecrawl_observer.mode == "disabled"
    assert loaded.main.routing.maximum_total_provider_attempts == 1
    assert loaded.clients[0].client.id == "company-watcher"
    assert loaded.policies[0].workspace.id == "placement-schedule"
    assert loaded.policies[0].credit_discipline.cache_completed_public_reads == "disabled"
    assert loaded.feed_sets[0].feed_set.workspace == "placement-schedule"


def test_h3_runtime_expansion_uses_the_captured_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    later_environment = {
        "APPDATA": str(tmp_path / "later-roaming"),
        "LOCALAPPDATA": str(tmp_path / "later-local"),
    }

    loaded = configuration.load_runtime_configuration(
        snapshot.main_path, environment=later_environment
    )
    expected = tmp_path / "captured-local" / "Gatehouse" / "state" / "gatehouse.db"
    assert Path(loaded.main.database.path) == expected
    assert loaded.snapshot is snapshot
    assert dict(snapshot.bound_environment)["LOCALAPPDATA"] != later_environment["LOCALAPPDATA"]


def test_h3_runtime_accepts_captured_absent_optional_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    snapshot = replace(snapshot, documents=(snapshot.document(snapshot.main_relative_path),))
    snapshot = _capture_documents(
        snapshot.main_path, snapshot.documents, snapshot.bound_environment
    )
    _inject_snapshot(monkeypatch, snapshot)
    _forbid_file_reopens(monkeypatch)

    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    assert loaded.clients == () and loaded.policies == () and loaded.feed_sets == ()
    assert loaded.snapshot is snapshot


@pytest.mark.parametrize("directory", ["clients", "policies", "feeds"])
def test_h3_runtime_preserves_duplicate_identity_rejection(
    directory: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    original = next(
        document for document in snapshot.documents if document.relative_path.startswith(directory)
    )
    duplicate = replace(original, relative_path=f"{directory}/duplicate.yaml")
    snapshot = replace(snapshot, documents=(*snapshot.documents, duplicate))
    snapshot = _capture_documents(
        snapshot.main_path, snapshot.documents, snapshot.bound_environment
    )
    _inject_snapshot(monkeypatch, snapshot)
    _forbid_file_reopens(monkeypatch)

    with pytest.raises(ValueError, match="duplicate"):
        configuration.load_runtime_configuration(snapshot.main_path)


def test_h3_runtime_preserves_unknown_feed_workspace_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    source = snapshot.document("feeds/placement.yaml")
    feed = yaml.safe_load(source.content)
    feed["feed_set"]["workspace"] = "not-configured"
    modified = replace(source, content=yaml.safe_dump(feed).encode("utf-8"))
    snapshot = replace(
        snapshot,
        documents=tuple(
            modified if document.relative_path == source.relative_path else document
            for document in snapshot.documents
        ),
    )
    snapshot = _capture_documents(
        snapshot.main_path, snapshot.documents, snapshot.bound_environment
    )
    _inject_snapshot(monkeypatch, snapshot)

    with pytest.raises(ValueError, match="unknown workspace"):
        configuration.load_runtime_configuration(snapshot.main_path)


@pytest.mark.parametrize(
    "relative_path", ["unselected.yaml", "clients/nested/extra.yaml", "clients/not-yaml.txt"]
)
def test_h3_runtime_rejects_unexpected_snapshot_topology_before_parsing(
    relative_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    snapshot = replace(
        snapshot,
        documents=(
            *snapshot.documents,
            cast(
                security.ConfigurationDocument, CapturedDocument(relative_path, b"unexpected: true")
            ),
        ),
    )
    _inject_snapshot(monkeypatch, snapshot)
    parses: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        parses.append("parse")
        raise AssertionError("bad snapshot topology must fail before parsing")

    monkeypatch.setattr(configuration, "parse_main_config", forbidden)
    monkeypatch.setattr(configuration, "parse_yaml_model", forbidden)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(snapshot.main_path)
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert parses == []


@pytest.mark.asyncio
async def test_h3_capture_failure_precedes_all_state_and_listener_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def rejected(*_args: object, **_kwargs: object) -> None:
        raise ConfigSecurityError("private metadata must never be echoed")

    monkeypatch.setattr(configuration, "capture_configuration", rejected)
    effects = _forbid_state_effects(monkeypatch)
    with pytest.raises(ConfigLoadError) as captured:
        await composition.run_stock_daemon(
            tmp_path / "config.yaml",
            expected_config_digest="0" * 64,
            install_signal_handlers=False,
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert "private metadata" not in str(captured.value)
    assert effects == []


@pytest.mark.asyncio
async def test_h3_conflicting_composition_origin_fails_before_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    effects = _forbid_state_effects(monkeypatch)

    with pytest.raises(ConfigLoadError) as captured:
        await composition.compose_stock_daemon(loaded, config_path=tmp_path / "other.yaml")
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_snapshot", [False, True])
async def test_h3_stock_entry_rejects_unbound_configuration_before_state(
    missing_snapshot: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    if missing_snapshot:
        loaded = replace(loaded, snapshot=None)
    monkeypatch.setattr(composition, "load_runtime_configuration", lambda *_args, **_kwargs: loaded)
    effects = _forbid_state_effects(monkeypatch)
    selected = snapshot.main_path if missing_snapshot else tmp_path / "other.yaml"

    with pytest.raises(ConfigLoadError) as captured:
        await composition.run_stock_daemon(
            selected,
            expected_config_digest=snapshot.manifest_digest,
            install_signal_handlers=False,
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert effects == []


@pytest.mark.asyncio
async def test_h3_stock_entry_passes_the_captured_bundle_without_path_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    monkeypatch.setattr(composition, "load_runtime_configuration", lambda *_args, **_kwargs: loaded)
    effects = _forbid_state_effects(monkeypatch)
    reopens = _forbid_file_reopens(monkeypatch)
    received: list[configuration.RuntimeConfiguration] = []

    class ReachedComposition(BaseException):
        pass

    async def stop_before_state(
        runtime: configuration.RuntimeConfiguration, **kwargs: object
    ) -> None:
        received.append(runtime)
        assert composition._configuration_origin(runtime, cast(Path, kwargs["config_path"])) == (
            snapshot.main_path
        )
        raise ReachedComposition

    def forbidden_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("captured configuration origin must not be resolved again")

    monkeypatch.setattr(composition, "compose_stock_daemon", stop_before_state)
    monkeypatch.setattr(Path, "resolve", forbidden_resolution)
    with pytest.raises(ReachedComposition):
        await composition.run_stock_daemon(
            snapshot.main_path,
            expected_config_digest=snapshot.manifest_digest,
            install_signal_handlers=False,
        )
    assert received == [loaded]
    assert effects == reopens == []


class _DigestStringSubclass(str):
    pass


_INVALID_EXPECTATIONS = (
    pytest.param(None, id="none"),
    pytest.param("", id="empty"),
    pytest.param("a" * 63, id="short"),
    pytest.param("a" * 65, id="long"),
    pytest.param("A" * 64, id="uppercase"),
    pytest.param("g" * 64, id="nonhex"),
    pytest.param(" " + "a" * 64, id="leading-space"),
    pytest.param("a" * 64 + " ", id="trailing-space"),
    pytest.param("a" * 64 + "\n", id="trailing-newline"),
    pytest.param("\uff41" * 64, id="nonascii"),
    pytest.param(b"a" * 64, id="bytes"),
    pytest.param(True, id="bool"),
    pytest.param(0, id="integer"),
    pytest.param(_DigestStringSubclass("a" * 64), id="string-subclass"),
)


def _digest_contract_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifest_digest: str | None = None,
) -> tuple[CapturedSnapshot, list[str]]:
    """Use literal bytes and a parser stub, without templates or temporary paths."""

    snapshot = _capture_documents(
        main_path=Path(r"C:\synthetic\config.yaml"),
        documents=(CapturedDocument("config.yaml", b"synthetic-main-bytes"),),
        environment=(("APPDATA", r"C:\synthetic\captured-roaming"),),
    )
    if manifest_digest is not None:
        snapshot = replace(snapshot, manifest_digest=manifest_digest)
    events: list[str] = []
    original_document = CapturedSnapshot.document

    def capture(path: str | Path, **_kwargs: object) -> ConfigurationSnapshot:
        events.append("capture")
        assert str(path) == str(snapshot.main_path)
        return snapshot

    def document(bundle: CapturedSnapshot, relative_path: str) -> security.ConfigurationDocument:
        events.append("document")
        return original_document(bundle, relative_path)

    main = cast(
        MainConfig,
        SimpleNamespace(
            firecrawl_workload=SimpleNamespace(
                mode="disabled",
                network_enabled=False,
                scripted_responses_path=None,
            ),
            watchdog=SimpleNamespace(readiness_timeout=1_000),
        ),
    )

    def pure_parse(content: bytes, path: Path, model: object, **kwargs: object) -> MainConfig:
        events.append("pure_parse")
        assert content is snapshot.documents[0].content
        assert path is snapshot.main_path
        assert model is MainConfig
        assert kwargs == {
            "expand_environment": True,
            "environment": dict(snapshot.bound_environment),
        }
        return main

    def parse(content: bytes, **kwargs: object) -> MainConfig:
        events.append("parse")
        assert content is snapshot.documents[0].content
        assert kwargs["config_path"] is snapshot.main_path
        assert kwargs["environment"] == dict(snapshot.bound_environment)
        return main

    def forbidden(*_args: object, **_kwargs: object) -> None:
        events.append("forbidden")
        raise AssertionError("digest checks must precede parsing and runtime effects")

    monkeypatch.setattr(configuration, "capture_configuration", capture)
    monkeypatch.setattr(configuration, "parse_main_config", parse)
    # This digest-order fixture has literal non-YAML bytes. Real pure selection
    # and parsing are covered by the bound scripted and template fixtures.
    monkeypatch.setattr(configuration, "parse_yaml_model", pure_parse)
    monkeypatch.setattr(CapturedSnapshot, "document", document)
    monkeypatch.setattr(
        CapturedSnapshot,
        "matches_main_path",
        lambda bundle, path: str(path) == str(bundle.main_path),
    )
    for name in ("open", "read_bytes", "glob", "resolve"):
        monkeypatch.setattr(Path, name, forbidden)
    for name in (
        "compose_stock_daemon",
        "_daemon_settings",
        "RuntimeHealthProbe",
        "_health_only_app",
        "secure_database_state",
        "secure_private_directory",
        "secure_private_file",
        "installation_state_paths",
        "open_migrated_database",
        "recover_startup",
        "DpapiCurrentUserKeyStore",
        "load_or_create_installation_key",
        "provision_control_capability",
        "_provider_transport",
        "_observer_transport",
        "create_daemon_applications",
        "serve",
        "_coordinated_signals",
    ):
        monkeypatch.setattr(composition, name, forbidden)
    return snapshot, events


def _advance_stock_once(coroutine: Coroutine[Any, Any, object]) -> None:
    """Reach a pre-await rejection or sentinel; never construct or run an event loop."""

    try:
        coroutine.send(None)
    finally:
        coroutine.close()
    raise AssertionError("stock startup unexpectedly suspended")


@pytest.mark.parametrize("digest", ["0" * 64, "f" * 64, "0123456789abcdef" * 4])
def test_h3_expected_digest_accepts_exact_lowercase_hex(digest: str) -> None:
    assert configuration.validate_expected_config_digest(digest) is digest


@pytest.mark.parametrize("value", _INVALID_EXPECTATIONS)
def test_h3_expected_digest_rejects_without_coercion(value: object) -> None:
    with pytest.raises(ConfigSecurityError) as captured:
        configuration.validate_expected_config_digest(value)
    assert str(captured.value) == (
        "expected configuration digest must be 64 lowercase hexadecimal characters"
    )


@pytest.mark.parametrize("value", _INVALID_EXPECTATIONS[1:])
def test_h3_loader_rejects_malformed_expectation_before_capture(
    value: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(
            snapshot.main_path, expected_config_digest=cast(str, value)
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert events == []


@pytest.mark.parametrize("expected", [None, "a" * 64])
def test_h3_loader_keeps_one_captured_bundle_with_optional_expectation(
    expected: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch)
    later_environment = {"APPDATA": r"C:\synthetic\later-roaming"}
    loaded = configuration.load_runtime_configuration(
        snapshot.main_path,
        environment=later_environment,
        expected_config_digest=snapshot.manifest_digest if expected is not None else None,
    )
    assert loaded.snapshot is snapshot
    assert loaded.clients == () and loaded.policies == () and loaded.feed_sets == ()
    assert events == ["capture", "document", "document", "pure_parse", "parse"]


@pytest.mark.parametrize("observed", ["b" * 64, "A" * 64, "a" * 64 + "\n"])
def test_h3_loader_rejects_digest_before_document_access_or_parsing(
    observed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch, manifest_digest=observed)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(
            snapshot.main_path, expected_config_digest="a" * 64
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert observed not in str(captured.value)
    assert events == ["capture"]


@pytest.mark.parametrize("value", _INVALID_EXPECTATIONS)
def test_h3_stock_rejects_missing_or_malformed_digest_before_loading(
    value: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch)

    def forbidden_load(*_args: object, **_kwargs: object) -> None:
        events.append("load")
        raise AssertionError("invalid expectation must precede loading")

    monkeypatch.setattr(composition, "load_runtime_configuration", forbidden_load)

    class DigestArguments(TypedDict, total=False):
        expected_config_digest: str

    arguments: DigestArguments = (
        {} if value is None else {"expected_config_digest": cast(str, value)}
    )
    with pytest.raises(ConfigLoadError) as captured:
        _advance_stock_once(composition.run_stock_daemon(snapshot.main_path, **arguments))
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert events == []


@pytest.mark.parametrize("observed", ["b" * 64, "A" * 64, "a" * 64 + "\n"])
def test_h3_stock_mismatch_cannot_recapture_or_enter_health_fallback(
    observed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch, manifest_digest=observed)
    with pytest.raises(ConfigLoadError) as captured:
        _advance_stock_once(
            composition.run_stock_daemon(snapshot.main_path, expected_config_digest="a" * 64)
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert events == ["capture"]


def test_h3_stock_capture_failure_preserves_raw_origin_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _snapshot_value, events = _digest_contract_snapshot(monkeypatch)
    raw_origin = "C:/synthetic/config/./config.yaml"
    origins: list[str | Path] = []

    def reject_capture(path: str | Path, **_kwargs: object) -> None:
        events.append("capture")
        origins.append(path)
        raise ConfigSecurityError("FAKE-CAPTURE-DETAIL-NOT-FOR-DIAGNOSTICS")

    monkeypatch.setattr(configuration, "capture_configuration", reject_capture)
    with pytest.raises(ConfigLoadError) as captured:
        _advance_stock_once(
            composition.run_stock_daemon(raw_origin, expected_config_digest="a" * 64)
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert "FAKE-CAPTURE-DETAIL" not in str(captured.value)
    assert origins == [raw_origin]
    assert events == ["capture"]


@pytest.mark.parametrize("observed", [None, "b" * 64, "A" * 64])
def test_h3_stock_rechecks_substituted_loader_snapshot_before_composition(
    observed: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch, manifest_digest=observed or "a" * 64)
    loaded = configuration.RuntimeConfiguration(
        main=cast(MainConfig, object()),
        clients=(),
        policies=(),
        feed_sets=(),
        snapshot=None if observed is None else snapshot,
    )

    def substituted_load(path: str | Path, **kwargs: object) -> configuration.RuntimeConfiguration:
        events.append("load")
        assert path is snapshot.main_path
        assert kwargs["expected_config_digest"] == "a" * 64
        return loaded

    monkeypatch.setattr(composition, "load_runtime_configuration", substituted_load)
    with pytest.raises(ConfigLoadError) as captured:
        _advance_stock_once(
            composition.run_stock_daemon(snapshot.main_path, expected_config_digest="a" * 64)
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert events == ["load"]


def test_h3_stock_matching_expectation_hands_off_the_same_fresh_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, events = _digest_contract_snapshot(monkeypatch)
    received: list[configuration.RuntimeConfiguration] = []

    class ReachedComposition(BaseException):
        pass

    async def stop_before_state(
        runtime: configuration.RuntimeConfiguration, **kwargs: object
    ) -> None:
        events.append("compose")
        received.append(runtime)
        assert kwargs["config_path"] is snapshot.main_path
        raise ReachedComposition

    monkeypatch.setattr(composition, "_daemon_settings", lambda _runtime: object())
    monkeypatch.setattr(composition, "compose_stock_daemon", stop_before_state)
    with pytest.raises(ReachedComposition):
        _advance_stock_once(
            composition.run_stock_daemon(
                snapshot.main_path, expected_config_digest=snapshot.manifest_digest
            )
        )
    assert len(received) == 1
    assert received[0].snapshot is snapshot
    assert events == [
        "capture",
        "document",
        "document",
        "pure_parse",
        "parse",
        "document",
        "pure_parse",
        "compose",
    ]


_SCRIPTED_BYTES = b'{"schema_version":1,"responses":{"firecrawl.search":[{"status_code":204}]}}'


def _scripted_snapshot(
    tmp_path: Path,
    *,
    channel: str = "scoped",
    mode: str = "scripted",
    manifest: bytes = _SCRIPTED_BYTES,
) -> ConfigurationSnapshot:
    main_path = tmp_path / "captured" / "config.yaml"
    main = yaml.safe_load((_CONFIG_ROOT / "config.example.yaml").read_bytes())
    workload: dict[str, object] = {"mode": mode, "network_enabled": mode == "live"}
    if mode == "scripted":
        workload["scripted_responses_path"] = r"%APPDATA%\responses.json"
    if channel == "legacy":
        main["provider"] = workload
    else:
        main["providers"]["firecrawl"]["workload"] = workload
    return _capture_documents(
        main_path,
        (CapturedDocument("config.yaml", yaml.safe_dump(main).encode("utf-8")),),
        (("APPDATA", str(main_path.parent)), ("LOCALAPPDATA", str(tmp_path / "captured-local"))),
        scripted_bytes=manifest,
    )


@pytest.mark.parametrize("channel", ("legacy", "scoped"))
def test_scripted_loader_passes_code_owned_selection_and_uses_frozen_expansion_without_reopens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
) -> None:
    snapshot = _scripted_snapshot(tmp_path, channel=channel)
    _inject_snapshot(monkeypatch, snapshot)
    selections: list[str | None] = []

    def capture(path: str | Path, **kwargs: Any) -> ConfigurationSnapshot:
        assert Path(path) == snapshot.main_path
        selector = kwargs["scripted_document_selector"]
        assert callable(selector)
        selections.append(
            selector(
                snapshot.document(snapshot.main_relative_path).content,
                snapshot.main_path,
                dict(snapshot.bound_environment),
            )
        )
        return snapshot

    monkeypatch.setattr(configuration, "capture_configuration", capture)
    reopens = _forbid_file_reopens(monkeypatch)
    loaded = configuration.load_runtime_configuration(
        snapshot.main_path,
        environment={"APPDATA": str(tmp_path / "later")},
        expected_config_digest=snapshot.manifest_digest,
    )
    expected_origin = str(snapshot.main_path.parent / "responses.json")
    assert selections == [expected_origin]
    assert loaded.main.firecrawl_workload.scripted_responses_path == expected_origin
    assert loaded.snapshot is snapshot
    assert loaded.snapshot.scripted_document is not None
    assert loaded.snapshot.scripted_document.content == _SCRIPTED_BYTES
    assert reopens == []


@pytest.mark.parametrize(
    "defect",
    (
        "missing",
        "origin",
        "relative",
        "role",
        "sha",
        "mutable",
        "coherent_swap",
        "missing_binding",
        "altered_binding",
        "mutable_environment",
        "noncanonical_binding",
    ),
)
def test_scripted_loader_rejects_attachment_substitution_before_state_path_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    snapshot = _scripted_snapshot(tmp_path)
    attachment = snapshot.scripted_document
    assert attachment is not None
    if defect == "missing":
        snapshot = replace(snapshot, scripted_document=None)
    elif defect == "missing_binding":
        snapshot = replace(snapshot, manifest_bytes=b"")
    elif defect == "altered_binding":
        snapshot = replace(snapshot, manifest_bytes=snapshot.manifest_bytes + b" ")
    elif defect == "mutable_environment":
        snapshot = replace(snapshot, bound_environment=list(snapshot.bound_environment))  # type: ignore[arg-type]
    elif defect == "noncanonical_binding":
        raw = snapshot.manifest_bytes + b" "
        snapshot = replace(
            snapshot, manifest_bytes=raw, manifest_digest=hashlib.sha256(raw).hexdigest()
        )
    else:
        if defect == "coherent_swap":
            other = _SCRIPTED_BYTES.replace(b"204", b"200")
            updates: dict[str, Any] = {
                "content": other,
                "sha256": hashlib.sha256(other).hexdigest(),
            }
        else:
            malformed_updates: dict[str, dict[str, Any]] = {
                "origin": {"origin": snapshot.main_path.parent / "other.json"},
                "relative": {"relative_path": "other.json"},
                "role": {"role": "other"},
                "sha": {"sha256": "f" * 64},
                "mutable": {"content": bytearray(_SCRIPTED_BYTES)},
            }
            updates = malformed_updates[defect]
        snapshot = replace(snapshot, scripted_document=replace(attachment, **updates))
    _inject_snapshot(monkeypatch, snapshot)
    effects: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        effects.append("state path parsing")
        raise AssertionError("attachment admission must precede state path parsing")

    monkeypatch.setattr(configuration, "parse_main_config", forbidden)
    monkeypatch.setattr("gatehouse.config.loader.validate_state_path_ancestry", forbidden)
    reopens = _forbid_file_reopens(monkeypatch)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(
            snapshot.main_path,
            expected_config_digest=snapshot.manifest_digest,
        )
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert effects == reopens == []


@pytest.mark.parametrize("mode", ("disabled", "live"))
def test_non_scripted_loader_rejects_an_unexpected_captured_attachment_before_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    snapshot = _scripted_snapshot(tmp_path, mode=mode)
    _inject_snapshot(monkeypatch, snapshot)
    effects: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        effects.append("state path parsing")
        raise AssertionError("unexpected attachment must precede state path parsing")

    monkeypatch.setattr(configuration, "parse_main_config", forbidden)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(snapshot.main_path)
    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert effects == []


@pytest.mark.parametrize("defect", ("mode", "path", "network"))
def test_scripted_runtime_settings_substitution_cannot_enter_composition_or_health_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    snapshot = _scripted_snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    substitutions: dict[str, dict[str, object]] = {
        "mode": {"mode": "disabled"},
        "path": {"scripted_responses_path": str(snapshot.main_path.parent / "other.json")},
        "network": {"network_enabled": True},
    }
    workload = loaded.main.firecrawl_workload.model_copy(update=substitutions[defect])
    firecrawl = loaded.main.providers.firecrawl.model_copy(update={"workload": workload})
    providers = loaded.main.providers.model_copy(update={"firecrawl": firecrawl})
    substituted = replace(loaded, main=loaded.main.model_copy(update={"providers": providers}))
    effects = _forbid_state_effects(monkeypatch)
    monkeypatch.setattr(composition, "load_runtime_configuration", lambda *_a, **_k: substituted)
    reopens = _forbid_file_reopens(monkeypatch)
    for operation, expected in (
        (
            lambda: composition.compose_stock_daemon(substituted, config_path=snapshot.main_path),
            ConfigSecurityError,
        ),
        (
            lambda: composition.run_stock_daemon(
                snapshot.main_path,
                expected_config_digest=snapshot.manifest_digest,
                install_signal_handlers=False,
            ),
            ConfigLoadError,
        ),
    ):
        with pytest.raises(expected) as captured:
            _advance_stock_once(operation())
        if isinstance(captured.value, ConfigLoadError):
            assert captured.value.stage is ConfigLoadStage.SECURITY
    assert effects == reopens == []


def test_scripted_invalid_json_is_rejected_before_state_path_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _scripted_snapshot(tmp_path, manifest=b'{"schema_version":1,"responses":[]}')
    _inject_snapshot(monkeypatch, snapshot)
    effects: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        effects.append("state path parsing")
        raise AssertionError("script content validation must precede state path parsing")

    monkeypatch.setattr(configuration, "parse_main_config", forbidden)
    reopens = _forbid_file_reopens(monkeypatch)
    with pytest.raises(ConfigLoadError) as captured:
        configuration.load_runtime_configuration(snapshot.main_path)
    assert captured.value.stage is ConfigLoadStage.VALIDATION
    assert effects == reopens == []


@pytest.mark.asyncio
async def test_scripted_transport_prepared_from_bytes_is_closed_on_later_pre_state_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _scripted_snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    events: list[str] = []

    class StopBeforeState(Exception):
        pass

    class PreparedTransport:
        async def aclose(self) -> None:
            events.append("close")

    prepared = PreparedTransport()

    def build(raw: bytes) -> PreparedTransport:
        assert snapshot.scripted_document is not None
        assert raw is snapshot.scripted_document.content
        events.append("parse bytes")
        return prepared

    def stop(_configuration: object) -> None:
        events.append("settings")
        raise StopBeforeState

    monkeypatch.setattr(ScriptedProviderTransport, "from_bytes", staticmethod(build))
    monkeypatch.setattr(composition, "_daemon_settings", stop)
    effects = _forbid_state_effects(monkeypatch)
    reopens = _forbid_file_reopens(monkeypatch)
    with pytest.raises(StopBeforeState):
        await composition.compose_stock_daemon(loaded, config_path=snapshot.main_path)
    assert events == ["parse bytes", "settings", "close"]
    assert effects == reopens == []


@pytest.mark.asyncio
@pytest.mark.parametrize("supplied", (False, True))
async def test_scripted_route_composition_requires_the_prepared_transport_without_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    supplied: bool,
) -> None:
    snapshot = _scripted_snapshot(tmp_path)
    _inject_snapshot(monkeypatch, snapshot)
    loaded = configuration.load_runtime_configuration(snapshot.main_path)
    prepared = ScriptedProviderTransport.from_bytes(_SCRIPTED_BYTES)
    events: list[str] = []
    connection = object()

    def synchronize(observed: object, **_kwargs: object) -> None:
        assert observed is connection
        events.append("routes")

    monkeypatch.setattr(composition, "synchronize_scripted_routes", synchronize)
    reopens = _forbid_file_reopens(monkeypatch)
    try:
        arguments: dict[str, Any] = {
            "config_path": snapshot.main_path,
            "connection": connection,
            "state_paths": object(),
            "clock": object(),
            "scripted_transport": prepared if supplied else None,
        }
        if supplied:
            assert await composition._provider_transport(loaded, **arguments) is prepared
            assert events == ["routes"]
        else:
            with pytest.raises(ConfigSecurityError, match="not prepared"):
                await composition._provider_transport(loaded, **arguments)
            assert events == []
        assert reopens == []
    finally:
        await prepared.aclose()


@pytest.mark.parametrize("phase", ("raw", "expanded"))
def test_scripted_selector_rejects_outer_whitespace_without_normalizing_the_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    snapshot = _scripted_snapshot(tmp_path)
    main = yaml.safe_load(snapshot.document(snapshot.main_relative_path).content)
    environment = dict(snapshot.bound_environment)
    if phase == "raw":
        spelling = " responses.json"
    else:
        spelling = "%APPDATA%"
        environment["APPDATA"] = "responses.json "
    main["providers"]["firecrawl"]["workload"]["scripted_responses_path"] = spelling
    raw = yaml.safe_dump(main).encode("utf-8")
    reopens = _forbid_file_reopens(monkeypatch)
    with pytest.raises(ConfigLoadError) as captured:
        configuration._select_scripted_document(raw, snapshot.main_path, environment)
    assert captured.value.stage is ConfigLoadStage.VALIDATION
    assert reopens == []
