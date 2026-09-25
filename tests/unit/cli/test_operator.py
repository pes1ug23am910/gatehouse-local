from __future__ import annotations

import hashlib
import json
import platform
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.cli import operator
from gatehouse.cli.operator import (
    OperatorCommandError,
    create_support_bundle,
    diagnose_installation,
    initialize_configuration,
    validate_configuration,
)
from gatehouse.config import ConfigLoadError
from gatehouse.config import loader as config_loader
from gatehouse.config.loader import ConfigLoadStage, parse_main_config
from gatehouse.config.security import ConfigurationDocument, ConfigurationSnapshot, FileIdentity
from gatehouse.credentials.redaction import SecretScanner
from gatehouse.daemon.configuration import RuntimeConfiguration, _load_content_configuration
from gatehouse.database import connect_database, open_migrated_database

_SECRET_CANARY = "FAKE-OPERATOR-DIAGNOSTIC-CANARY-NOT-A-REAL-KEY-123456"
_IDENTIFIER_SHAPED_ALERT_CATEGORY = "session:private-user-123"


@pytest.fixture
def operator_content_state_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Content-only contracts use fresh scratch paths without native ancestry proof."""

    def fresh_path(path: str | Path) -> Path:
        candidate = Path(path)
        assert candidate.is_absolute() and ".." not in candidate.parts
        assert candidate.is_relative_to(tmp_path)
        return candidate

    monkeypatch.setattr(config_loader, "validate_state_path_ancestry", fresh_path)


@pytest.fixture
def support_bundle_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bundle content contract does not query the host's platform services."""

    monkeypatch.setattr(platform, "system", lambda: "Windows")


@pytest.fixture
def operator_configuration_snapshot(
    monkeypatch: pytest.MonkeyPatch, operator_content_state_path: None
) -> None:
    """Fake trust for marked operator content contracts, retaining all template documents."""

    del operator_content_state_path

    def capture(path: str | Path, *, environment: Mapping[str, str]) -> RuntimeConfiguration:
        origin = Path(path)
        runtime = _load_content_configuration(origin, environment=environment)
        relative_paths = (
            origin.name,
            "clients/company-watcher.yaml",
            "policies/placement-schedule.yaml",
            "feeds/placement-companies-primary.yaml",
        )
        documents = []
        for index, relative in enumerate(relative_paths, start=1):
            raw = (origin.parent / relative).read_bytes()
            documents.append(
                ConfigurationDocument(
                    relative,
                    raw,
                    FileIdentity(1, index),
                    hashlib.sha256(raw).hexdigest(),
                )
            )
        bindings = tuple(
            sorted(
                (key, value)
                for key, value in environment.items()
                if key in {"APPDATA", "LOCALAPPDATA"}
            )
        )
        digest = hashlib.sha256(
            repr(([(doc.relative_path, doc.sha256) for doc in documents], bindings)).encode(),
        ).hexdigest()
        snapshot = ConfigurationSnapshot(origin, origin.name, tuple(documents), digest, bindings)
        return replace(runtime, snapshot=snapshot)

    monkeypatch.setattr(operator, "load_runtime_configuration", capture)


def _h3_configuration(tmp_path: Path) -> RuntimeConfiguration:
    origin = tmp_path / "captured" / "config.yaml"
    raw = (Path(__file__).parents[3] / "config/config.example.yaml").read_bytes()
    main = parse_main_config(raw, config_path=origin, environment={"LOCALAPPDATA": str(tmp_path)})
    snapshot = ConfigurationSnapshot(origin, "config.yaml", (), "a" * 64, ())
    return RuntimeConfiguration(main=main, clients=(), policies=(), feed_sets=(), snapshot=snapshot)


@pytest.mark.parametrize("explain", [False, True])
@pytest.mark.usefixtures("operator_content_state_path")
def test_h3_validation_uses_verified_capture_before_resolving_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explain: bool
) -> None:
    configuration = _h3_configuration(tmp_path)
    assert configuration.snapshot is not None
    original = configuration.snapshot.main_path.as_posix()
    captured: list[str | Path] = []

    def verified(path: str | Path, *, environment: object) -> RuntimeConfiguration:
        captured.append(path)
        assert environment == {}
        return configuration

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("validation must not resolve input or use the content-only loader")

    monkeypatch.setattr(operator, "load_runtime_configuration", verified)
    monkeypatch.setattr(operator, "_load_content_configuration", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    result = validate_configuration(original, environment={}, explain=explain)

    assert captured == [original]
    assert result["status"] == "valid"
    assert result["snapshot"] == {"profile": "windows-fixed-ntfs-v1", "digest": "a" * 64}
    assert str(original) not in repr(result)
    if explain:
        paths = result["paths"]
        assert isinstance(paths, dict)
        assert paths["config"] == str(configuration.snapshot.main_path)
    else:
        assert "paths" not in result


def test_h3_validation_security_failure_is_detached_and_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = "fc-" + "abcdefghijklmnopqrstuvwxyz123456"

    def reject(*args: object, **kwargs: object) -> RuntimeConfiguration:
        raise ConfigLoadError(
            Path(f"{marker}.yaml"), ConfigLoadStage.SECURITY, "filesystem trust unavailable"
        ) from RuntimeError(marker)

    monkeypatch.setattr(operator, "load_runtime_configuration", reject)
    with pytest.raises(ConfigLoadError) as captured:
        validate_configuration(tmp_path / "config.yaml", environment={}, explain=True)

    assert captured.value.stage is ConfigLoadStage.SECURITY
    assert marker not in str(captured.value)
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None


@pytest.mark.usefixtures("operator_content_state_path")
def test_h3_validation_rejects_runtime_without_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = _h3_configuration(tmp_path)
    unbound = RuntimeConfiguration(main=configured.main, clients=(), policies=(), feed_sets=())
    monkeypatch.setattr(operator, "load_runtime_configuration", lambda *args, **kwargs: unbound)
    with pytest.raises(OperatorCommandError, match="snapshot"):
        validate_configuration(tmp_path / "config.yaml", environment={}, explain=True)


@pytest.mark.usefixtures("operator_content_state_path")
def test_h3_legacy_content_loading_remains_separate_from_trusted_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = _h3_configuration(tmp_path)
    calls: list[Path] = []

    def content(path: Path, *, environment: object) -> RuntimeConfiguration:
        calls.append(path)
        return configured

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("legacy diagnostics/init loader must not enter native trust")

    monkeypatch.setattr(operator, "_load_content_configuration", content)
    monkeypatch.setattr(operator, "load_runtime_configuration", forbidden)
    path = tmp_path / "config.yaml"
    assert operator._load_runtime(path, environment={}) is configured
    assert calls == [path]


def _initialize(tmp_path: Path) -> Path:
    config_path = tmp_path / "nested" / "installation" / "config.yaml"
    result = initialize_configuration(config_path)
    assert result["status"] == "initialized"
    return config_path


@pytest.mark.usefixtures("operator_configuration_snapshot")
def test_init_creates_a_complete_disabled_tree_and_never_overwrites(tmp_path: Path) -> None:
    config_path = _initialize(tmp_path)
    root = config_path.parent
    targets = {
        config_path,
        root / "clients" / "company-watcher.yaml",
        root / "policies" / "placement-schedule.yaml",
        root / "feeds" / "placement-companies-primary.yaml",
    }
    assert all(path.is_file() for path in targets)
    assert (root / "state").is_dir()

    loaded = validate_configuration(config_path, environment={}, explain=True)
    assert loaded["status"] == "valid"
    assert loaded["counts"] == {
        "client_profiles": 1,
        "workspace_policies": 1,
        "feed_sets": 1,
    }
    assert loaded["paths"]["database"] == str((root / "state" / "gatehouse.db").resolve())  # type: ignore[index]

    original = config_path.read_bytes()
    with pytest.raises(OperatorCommandError, match="refused to overwrite"):
        initialize_configuration(config_path)
    assert config_path.read_bytes() == original


def test_init_rolls_back_every_owned_path_when_topology_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "nested" / "installation" / "config.yaml"

    def reject_topology(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ConfigLoadError(
            config_path,
            ConfigLoadStage.VALIDATION,
            _SECRET_CANARY,
        )

    monkeypatch.setattr(operator, "_load_runtime", reject_topology)
    with pytest.raises(OperatorCommandError) as captured:
        initialize_configuration(config_path)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _SECRET_CANARY not in str(captured.value)
    assert not (tmp_path / "nested").exists()


def test_init_rolls_back_every_owned_path_after_base_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticInterruption(BaseException):
        pass

    config_path = tmp_path / "nested" / "installation" / "config.yaml"

    def interrupt_validation(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SyntheticInterruption

    monkeypatch.setattr(operator, "_load_runtime", interrupt_validation)

    with pytest.raises(SyntheticInterruption):
        initialize_configuration(config_path)

    assert not (tmp_path / "nested").exists()


@pytest.mark.usefixtures("operator_configuration_snapshot")
def test_validate_explain_returns_only_sanitized_paths_counts_and_modes(tmp_path: Path) -> None:
    config_path = _initialize(tmp_path)
    policy_path = config_path.parent / "policies" / "placement-schedule.yaml"
    source = policy_path.read_text(encoding="utf-8")
    policy_path.write_text(
        source.replace(
            "canonical_root: 'E:\\Projects\\Placement-Schedule'",
            f"canonical_root: 'E:\\{_SECRET_CANARY}'",
        ),
        encoding="utf-8",
    )

    result = validate_configuration(
        config_path,
        environment={"UNRELATED_PROVIDER_TOKEN": _SECRET_CANARY},
        explain=True,
    )

    rendered = repr(result)
    assert _SECRET_CANARY not in rendered
    assert "network_enabled" not in rendered
    assert set(result) == {"status", "schema_version", "counts", "paths", "modes", "snapshot"}
    assert result["modes"]["providers"]["firecrawl"] == {  # type: ignore[index]
        "workload": "disabled",
        "observer": "disabled",
    }


@pytest.mark.usefixtures("operator_configuration_snapshot")
def test_init_and_validate_redact_a_credential_shaped_path(tmp_path: Path) -> None:
    path_token = "fc-" + "abcdefghijklmnopqrstuvwxyz123456"
    config_path = tmp_path / path_token / "config.yaml"

    initialized = initialize_configuration(config_path)
    validated = validate_configuration(config_path, environment={}, explain=True)

    assert path_token not in repr(initialized)
    assert path_token not in repr(validated)
    assert "[REDACTED:firecrawl_token]" in repr(initialized)
    assert "[REDACTED:firecrawl_token]" in repr(validated)


@pytest.mark.usefixtures("operator_content_state_path")
def test_diagnose_missing_database_is_sanitized_and_does_not_create_it(tmp_path: Path) -> None:
    config_path = _initialize(tmp_path)
    database_path = config_path.parent / "state" / "gatehouse.db"

    result = diagnose_installation(
        config_path,
        environment={"FIRECRAWL_API_KEY": _SECRET_CANARY},
    )

    assert result["ok"] is False
    assert result["categories"]["config"]["status"] == "ok"  # type: ignore[index]
    assert result["categories"]["schema"] == {  # type: ignore[index]
        "status": "unavailable",
        "failure_category": "database_unavailable",
    }
    assert result["degraded_components"] == ["database"]
    assert not database_path.exists()
    assert _SECRET_CANARY not in repr(result)


@pytest.mark.usefixtures("operator_configuration_snapshot")
def test_invalid_document_values_never_enter_validation_or_diagnostic_errors(
    tmp_path: Path,
) -> None:
    config_path = _initialize(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write(f"unexpected_secret: {_SECRET_CANARY}\n")

    with pytest.raises(ConfigLoadError) as captured:
        validate_configuration(config_path, environment={}, explain=True)
    diagnosis = diagnose_installation(config_path, environment={})

    assert _SECRET_CANARY not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _SECRET_CANARY not in repr(diagnosis)
    assert diagnosis["categories"]["config"] == {  # type: ignore[index]
        "status": "failed",
        "failure_category": "configuration_validation",
    }


@pytest.mark.usefixtures("operator_content_state_path")
def test_diagnose_checks_current_database_read_only_and_reports_basic_counts(
    tmp_path: Path,
) -> None:
    config_path = _initialize(tmp_path)
    database_path = config_path.parent / "state" / "gatehouse.db"
    connection = open_migrated_database(database_path)
    connection.close()
    before = database_path.read_bytes()
    before_paths = {path.name for path in database_path.parent.glob("gatehouse.db*")}

    result = diagnose_installation(config_path, environment={})

    assert result["ok"] is True
    assert result["categories"]["schema"]["status"] == "ok"  # type: ignore[index]
    assert result["categories"]["integrity"] == {  # type: ignore[index]
        "status": "ok",
        "failure_category": None,
        "foreign_key_violations_detected": 0,
        "foreign_key_results_truncated": False,
    }
    assert result["categories"]["alerts"] == {"status": "ok"}  # type: ignore[index]
    assert result["listeners"] == {
        "agent": {"host": "127.0.0.1", "port": 47621},
        "admin": {"host": "127.0.0.1", "port": 47622},
    }
    assert result["lease"] == {"file_present": False, "owner": "not_exposed"}
    assert result["recent_alert_categories"] == []
    assert result["counts"] == {
        "client_profiles": 1,
        "workspace_policies": 1,
        "feed_sets": 1,
        "stored_clients": 0,
        "stored_workspaces": 0,
        "stored_feed_sets": 0,
        "credential_metadata": 0,
        "open_high_severity_alerts": 0,
    }
    assert database_path.read_bytes() == before
    assert {path.name for path in database_path.parent.glob("gatehouse.db*")} == before_paths


@pytest.mark.usefixtures("operator_content_state_path")
def test_diagnose_reports_migration_drift_without_repairing_it(tmp_path: Path) -> None:
    config_path = _initialize(tmp_path)
    database_path = config_path.parent / "state" / "gatehouse.db"
    connection = open_migrated_database(database_path)
    connection.execute("UPDATE schema_migrations SET checksum_sha256 = '0' WHERE version = 1")
    connection.close()

    result = diagnose_installation(config_path, environment={})

    assert result["ok"] is False
    assert result["categories"]["schema"]["failure_category"] == "schema_incompatible"  # type: ignore[index]
    reopened = connect_database(database_path, read_only=True)
    try:
        assert (
            reopened.execute(
                "SELECT checksum_sha256 FROM schema_migrations WHERE version = 1"
            ).fetchone()[0]
            == "0"
        )
    finally:
        reopened.close()


@pytest.mark.usefixtures("operator_content_state_path")
def test_diagnose_converts_query_budget_exhaustion_to_stable_categories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _initialize(tmp_path)
    database_path = config_path.parent / "state" / "gatehouse.db"
    connection = open_migrated_database(database_path)
    connection.close()
    monkeypatch.setattr(operator, "_DATABASE_PROGRESS_GRANULARITY", 1)
    monkeypatch.setattr(operator, "_DATABASE_PROGRESS_CALLBACK_LIMIT", 0)

    result = diagnose_installation(config_path, environment={})

    assert result["ok"] is False
    assert result["categories"]["schema"]["failure_category"] == "schema_check_unavailable"  # type: ignore[index]
    assert result["categories"]["integrity"]["failure_category"] == (  # type: ignore[index]
        "integrity_check_unavailable"
    )


@pytest.mark.usefixtures("operator_content_state_path")
def test_diagnose_bounds_and_sanitizes_recent_alert_categories(tmp_path: Path) -> None:
    config_path = _initialize(tmp_path)
    database_path = config_path.parent / "state" / "gatehouse.db"
    connection = open_migrated_database(database_path)
    connection.execute(
        """
        INSERT INTO alerts(
            alert_id, severity, category, state, title, summary,
            created_at_ms, preserve, metadata_json
        ) VALUES ('alert_test', 'HIGH', ?, 'OPEN', 'safe', 'safe', 1234, 1, '{}')
        """,
        (_SECRET_CANARY,),
    )
    connection.execute(
        """
        INSERT INTO alerts(
            alert_id, severity, category, state, title, summary,
            created_at_ms, preserve, metadata_json
        ) VALUES ('alert_private', 'LOW', ?, 'CLOSED', 'safe', 'safe', 1235, 0, '{}')
        """,
        (_IDENTIFIER_SHAPED_ALERT_CATEGORY,),
    )
    oversized_text = "x" * (256 * 1_024)
    connection.execute(
        """
        INSERT INTO alerts(
            alert_id, severity, category, state, title, summary,
            created_at_ms, preserve, metadata_json
        ) VALUES ('alert_corrupt', ?, ?, ?, 'safe', 'safe', ?, 0, '{}')
        """,
        (oversized_text, oversized_text, oversized_text, "9" * 5_000),
    )
    connection.commit()
    connection.close()

    result = diagnose_installation(
        config_path,
        environment={},
        scanner=SecretScanner(canaries=(_SECRET_CANARY,)),
    )

    assert _SECRET_CANARY not in repr(result)
    assert _IDENTIFIER_SHAPED_ALERT_CATEGORY not in repr(result)
    assert result["recent_alert_categories"] == [
        {
            "category": "unclassified",
            "severity": "LOW",
            "state": "CLOSED",
            "latest_created_at_ms": 1235,
            "occurrence_count": 1,
        },
        {
            "category": "redacted",
            "severity": "HIGH",
            "state": "OPEN",
            "latest_created_at_ms": 1234,
            "occurrence_count": 1,
        },
        {
            "category": "unclassified",
            "severity": "unknown",
            "state": "unknown",
            "latest_created_at_ms": 0,
            "occurrence_count": 1,
        },
    ]
    assert oversized_text[:128] not in repr(result)
    assert result["degraded_components"] == ["alerts"]


@pytest.mark.usefixtures("operator_content_state_path", "support_bundle_platform")
def test_support_bundle_is_bounded_sanitized_and_create_only(tmp_path: Path) -> None:
    config_path = _initialize(tmp_path)
    database_path = config_path.parent / "state" / "gatehouse.db"
    connection = open_migrated_database(database_path)
    connection.execute(
        """
        INSERT INTO alerts(
            alert_id, severity, category, state, title, summary,
            created_at_ms, preserve, metadata_json
        ) VALUES ('alert_test', 'LOW', ?, 'CLOSED', 'safe', 'safe', 1234, 0, '{}')
        """,
        (_SECRET_CANARY,),
    )
    connection.execute(
        """
        INSERT INTO alerts(
            alert_id, severity, category, state, title, summary,
            created_at_ms, preserve, metadata_json
        ) VALUES ('alert_private', 'LOW', ?, 'CLOSED', 'safe', 'safe', 1235, 0, '{}')
        """,
        (_IDENTIFIER_SHAPED_ALERT_CATEGORY,),
    )
    connection.commit()
    connection.close()
    output = tmp_path / "support.json"
    scanner = SecretScanner(canaries=(_SECRET_CANARY,))

    result = create_support_bundle(
        config_path,
        output,
        environment={"UNRELATED_API_KEY": _SECRET_CANARY},
        scanner=scanner,
    )
    raw = output.read_bytes()
    payload = json.loads(raw)

    assert len(raw) <= 64 * 1_024
    assert _SECRET_CANARY.encode() not in raw
    assert _IDENTIFIER_SHAPED_ALERT_CATEGORY.encode() not in raw
    assert payload["kind"] == "gatehouse_sanitized_support_bundle"
    assert "paths" not in payload["diagnosis"]
    assert {item["category"] for item in payload["diagnosis"]["recent_alert_categories"]} == {
        "redacted",
        "unclassified",
    }
    assert result["support_bundle"] == {
        "path": str(output.resolve()),
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    with pytest.raises(OperatorCommandError, match="already exists"):
        create_support_bundle(config_path, output, environment={}, scanner=scanner)
    assert output.read_bytes() == raw


@pytest.mark.usefixtures("operator_content_state_path", "support_bundle_platform")
def test_support_bundle_removes_a_partial_artifact_after_base_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticInterruption(BaseException):
        pass

    def interrupt_fsync(_file_descriptor: int) -> None:
        raise SyntheticInterruption

    config_path = _initialize(tmp_path)
    output = tmp_path / "interrupted-support.json"
    monkeypatch.setattr("gatehouse.cli.operator.os.fsync", interrupt_fsync)

    with pytest.raises(SyntheticInterruption):
        create_support_bundle(config_path, output, environment={})

    assert not output.exists()
