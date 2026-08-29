"""Offline, sanitized configuration and persistence diagnostics for operators."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import sys
from collections.abc import Callable, Mapping
from contextlib import suppress
from importlib.resources import files
from pathlib import Path

from gatehouse import __version__
from gatehouse.config import ConfigLoadError
from gatehouse.credentials.redaction import SecretDetectedError, SecretScanner
from gatehouse.daemon.configuration import RuntimeConfiguration, load_runtime_configuration
from gatehouse.database.connection import connect_database
from gatehouse.database.migrations import (
    MIGRATIONS,
    MigrationError,
    verify_migration_compatibility,
)

_TEMPLATE_PACKAGE = "gatehouse.config.templates"
_MAXIMUM_TEMPLATE_BYTES = 1_048_576
_DATABASE_PROGRESS_GRANULARITY = 1_000
_DATABASE_PROGRESS_CALLBACK_LIMIT = 2_000
_MAXIMUM_FOREIGN_KEY_RESULTS = 100
_MAXIMUM_RECENT_ALERT_CATEGORIES = 20
_MAXIMUM_SUPPORT_BUNDLE_BYTES = 64 * 1_024
_SAFE_ALERT_CATEGORIES = frozenset(
    {
        "quota_reconciliation_mismatch",
        "watchdog_restart",
    }
)
_ALERT_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_ALERT_STATES = frozenset({"OPEN", "ACKNOWLEDGED", "RESOLVED", "CLOSED"})
_PROVIDER_NAMES = ("firecrawl", "github", "openrouter", "gemini", "xai", "jarvislabs")
_TEMPLATE_TARGETS = (
    ("config.yaml", None),
    ("company-watcher.yaml", "clients"),
    ("placement-schedule.yaml", "policies"),
    ("placement-companies-primary.yaml", "feeds"),
)


class OperatorCommandError(RuntimeError):
    """A sanitized, actionable failure from an offline operator command."""


def _resolved_config_path(config_path: str | Path) -> Path:
    raw = str(config_path)
    if not raw or any(character in raw for character in "\x00\n\r"):
        raise OperatorCommandError("configuration path is invalid")
    return Path(config_path).resolve(strict=False)


def _template_bytes(name: str) -> bytes:
    try:
        with files(_TEMPLATE_PACKAGE).joinpath(name).open("rb") as stream:
            payload = stream.read(_MAXIMUM_TEMPLATE_BYTES + 1)
    except (OSError, TypeError) as error:
        raise OperatorCommandError("packaged configuration template is unavailable") from error
    if not payload or len(payload) > _MAXIMUM_TEMPLATE_BYTES:
        raise OperatorCommandError("packaged configuration template is invalid")
    return payload


def _directory_plan(root: Path) -> tuple[Path, ...]:
    missing_ancestors: list[Path] = []
    cursor = root
    while not cursor.exists():
        missing_ancestors.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            raise OperatorCommandError("configuration root is unavailable")
        cursor = parent
    if not cursor.is_dir():
        raise OperatorCommandError("configuration initialization path conflicts with a file")

    ordered = list(reversed(missing_ancestors))
    ordered.extend((root / "clients", root / "policies", root / "feeds", root / "state"))
    return tuple(ordered)


def initialize_configuration(config_path: str | Path) -> Mapping[str, object]:
    """Create one coherent, disabled-by-default configuration tree without overwrites."""

    resolved = _resolved_config_path(config_path)
    scanner = SecretScanner()
    root = resolved.parent
    targets = tuple(
        (
            resolved if directory is None else root / directory / template_name,
            _template_bytes(template_name),
        )
        for template_name, directory in _TEMPLATE_TARGETS
    )
    directories = _directory_plan(root)

    conflicting_directory = next(
        (path for path in directories if path.exists() and not path.is_dir()), None
    )
    if conflicting_directory is not None:
        raise OperatorCommandError("configuration initialization path conflicts with a file")
    if any(path.exists() for path, _ in targets):
        raise OperatorCommandError(
            "configuration initialization refused to overwrite an existing file"
        )

    created_directories: list[Path] = []
    created_files: list[Path] = []

    def roll_back_owned_paths() -> None:
        for path in reversed(created_files):
            with suppress(BaseException):
                path.unlink()
        for path in reversed(created_directories):
            with suppress(BaseException):
                path.rmdir()

    failed = False
    try:
        for directory in directories:
            if directory.exists():
                continue
            directory.mkdir()
            created_directories.append(directory)
        for target, payload in targets:
            with target.open("xb") as stream:
                created_files.append(target)
                stream.write(payload)
        _load_runtime(resolved, environment={})
    except (ConfigLoadError, OSError, RuntimeError):
        roll_back_owned_paths()
        failed = True
    except BaseException:
        roll_back_owned_paths()
        raise

    if failed:
        raise OperatorCommandError("configuration initialization could not be completed")

    return {
        "status": "initialized",
        "config_path": scanner.redact_text(str(resolved)),
        "config_root": scanner.redact_text(str(root)),
        "created_file_count": len(created_files),
        "created_directory_count": len(created_directories),
    }


def _provider_modes(configuration: RuntimeConfiguration) -> dict[str, object]:
    modes: dict[str, object] = {}
    for provider_name in _PROVIDER_NAMES:
        channels = getattr(configuration.main.providers, provider_name)
        workload = (
            configuration.main.firecrawl_workload
            if provider_name == "firecrawl"
            else channels.workload
        )
        modes[provider_name] = {
            "workload": workload.mode,
            "observer": channels.observer.mode,
        }
    return modes


def _configuration_counts(configuration: RuntimeConfiguration) -> dict[str, int]:
    return {
        "client_profiles": len(configuration.clients),
        "workspace_policies": len(configuration.policies),
        "feed_sets": len(configuration.feed_sets),
    }


def _load_runtime(
    config_path: Path,
    *,
    environment: Mapping[str, str],
) -> RuntimeConfiguration:
    try:
        return load_runtime_configuration(config_path, environment=environment)
    except ConfigLoadError as error:
        failure: ConfigLoadError | OperatorCommandError = ConfigLoadError(
            error.path,
            error.stage,
            error.summary,
        )
    except (OSError, RuntimeError, ValueError):
        failure = OperatorCommandError("configuration topology validation failed")
    raise failure


def validate_configuration(
    config_path: str | Path,
    *,
    environment: Mapping[str, str],
    explain: bool,
) -> Mapping[str, object]:
    """Load the exact daemon configuration surface and return only safe summaries."""

    resolved = _resolved_config_path(config_path)
    configuration = _load_runtime(resolved, environment=environment)
    result: dict[str, object] = {
        "status": "valid",
        "schema_version": configuration.main.schema_version,
        "counts": _configuration_counts(configuration),
    }
    if explain:
        scanner = SecretScanner()
        result.update(
            {
                "paths": {
                    "config": scanner.redact_text(str(resolved)),
                    "config_root": scanner.redact_text(str(resolved.parent)),
                    "database": scanner.redact_text(configuration.main.database.path),
                    "clients": scanner.redact_text(str(resolved.parent / "clients")),
                    "policies": scanner.redact_text(str(resolved.parent / "policies")),
                    "feeds": scanner.redact_text(str(resolved.parent / "feeds")),
                    "state": scanner.redact_text(str(resolved.parent / "state")),
                },
                "modes": {
                    "database": {
                        "journal": configuration.main.database.journal_mode,
                        "synchronous": configuration.main.database.synchronous,
                    },
                    "providers": _provider_modes(configuration),
                },
            }
        )
    return result


def _run_with_step_limit[ResultT](
    connection: sqlite3.Connection,
    operation: Callable[[], ResultT],
) -> ResultT:
    callbacks = 0

    def progress() -> int:
        nonlocal callbacks
        callbacks += 1
        return int(callbacks > _DATABASE_PROGRESS_CALLBACK_LIMIT)

    connection.set_progress_handler(progress, _DATABASE_PROGRESS_GRANULARITY)
    try:
        return operation()
    finally:
        connection.set_progress_handler(None, 0)


def _configuration_failure_category(error: ConfigLoadError) -> str:
    return f"configuration_{error.stage.value}"


def _base_diagnosis(config_path: Path, *, scanner: SecretScanner) -> dict[str, object]:
    return {
        "ok": False,
        "paths": {"config": scanner.redact_text(str(config_path))},
        "categories": {
            "config": {"status": "not_run"},
            "schema": {"status": "not_run"},
            "integrity": {"status": "not_run"},
            "alerts": {"status": "not_run"},
        },
        "counts": {},
        "listeners": {},
        "lease": {"file_present": False, "owner": "not_exposed"},
        "recent_alert_categories": [],
        "recent_alert_categories_truncated": False,
        "degraded_components": [],
    }


def _safe_alert_token(
    value: object,
    *,
    scanner: SecretScanner,
    allowed: frozenset[str] | None = None,
) -> str:
    if isinstance(value, bytes):
        try:
            text = value.decode("ascii", "strict")
        except UnicodeDecodeError:
            return "unknown" if allowed is not None else "unclassified"
    else:
        text = str(value)
    if len(text) > 64 or scanner.scan_text(text, location="diagnostics.alert"):
        return "redacted"
    if allowed is not None:
        return text if text in allowed else "unknown"
    normalized = text.casefold()
    return normalized if normalized in _SAFE_ALERT_CATEGORIES else "unclassified"


def _recent_alert_categories(
    connection: sqlite3.Connection,
    *,
    scanner: SecretScanner,
) -> tuple[list[dict[str, object]], bool]:
    rows = connection.execute(
        """
        SELECT substr(CAST(category AS BLOB), 1, 65) AS category_prefix,
               length(CAST(category AS BLOB)) AS category_length,
               substr(CAST(severity AS BLOB), 1, 65) AS severity_prefix,
               length(CAST(severity AS BLOB)) AS severity_length,
               substr(CAST(state AS BLOB), 1, 65) AS state_prefix,
               length(CAST(state AS BLOB)) AS state_length,
               MAX(CASE WHEN typeof(created_at_ms) = 'integer'
                        THEN created_at_ms ELSE 0 END) AS latest_created_at_ms,
               COUNT(*) AS occurrence_count
          FROM alerts
         GROUP BY category_prefix, category_length,
                  severity_prefix, severity_length,
                  state_prefix, state_length
         ORDER BY latest_created_at_ms DESC, category_prefix
         LIMIT ?
        """,
        (_MAXIMUM_RECENT_ALERT_CATEGORIES + 1,),
    ).fetchall()
    truncated = len(rows) > _MAXIMUM_RECENT_ALERT_CATEGORIES
    summaries: list[dict[str, object]] = []
    for row in rows[:_MAXIMUM_RECENT_ALERT_CATEGORIES]:
        category = (
            "unclassified"
            if int(row["category_length"]) > 64
            else _safe_alert_token(row["category_prefix"], scanner=scanner)
        )
        severity = (
            "unknown"
            if int(row["severity_length"]) > 64
            else _safe_alert_token(
                row["severity_prefix"], scanner=scanner, allowed=_ALERT_SEVERITIES
            )
        )
        state = (
            "unknown"
            if int(row["state_length"]) > 64
            else _safe_alert_token(row["state_prefix"], scanner=scanner, allowed=_ALERT_STATES)
        )
        summaries.append(
            {
                "category": category,
                "severity": severity,
                "state": state,
                "latest_created_at_ms": max(0, int(row["latest_created_at_ms"])),
                "occurrence_count": max(0, int(row["occurrence_count"])),
            }
        )
    return summaries, truncated


def diagnose_installation(
    config_path: str | Path,
    *,
    environment: Mapping[str, str],
    scanner: SecretScanner | None = None,
) -> Mapping[str, object]:
    """Inspect local configuration and SQLite state without migration or network access."""

    resolved = _resolved_config_path(config_path)
    active_scanner = scanner or SecretScanner()
    result = _base_diagnosis(resolved, scanner=active_scanner)
    categories = result["categories"]
    counts = result["counts"]
    degraded = result["degraded_components"]
    assert isinstance(categories, dict)
    assert isinstance(counts, dict)
    assert isinstance(degraded, list)

    try:
        configuration = _load_runtime(resolved, environment=environment)
    except ConfigLoadError as error:
        categories["config"] = {
            "status": "failed",
            "failure_category": _configuration_failure_category(error),
        }
        categories["schema"] = {
            "status": "not_run",
            "failure_category": "configuration_unavailable",
        }
        categories["integrity"] = {
            "status": "not_run",
            "failure_category": "configuration_unavailable",
        }
        degraded.append("configuration")
        return result
    except OperatorCommandError:
        categories["config"] = {
            "status": "failed",
            "failure_category": "configuration_topology",
        }
        categories["schema"] = {
            "status": "not_run",
            "failure_category": "configuration_unavailable",
        }
        categories["integrity"] = {
            "status": "not_run",
            "failure_category": "configuration_unavailable",
        }
        degraded.append("configuration")
        return result

    categories["config"] = {
        "status": "ok",
        "schema_version": configuration.main.schema_version,
    }
    counts.update(_configuration_counts(configuration))
    result["listeners"] = {
        "agent": {
            "host": configuration.main.server.agent.host,
            "port": configuration.main.server.agent.port,
        },
        "admin": {
            "host": configuration.main.server.admin.host,
            "port": configuration.main.server.admin.port,
        },
    }
    database_path = Path(configuration.main.database.path)
    paths = result["paths"]
    assert isinstance(paths, dict)
    paths["database"] = active_scanner.redact_text(str(database_path))
    result["lease"] = {
        "file_present": (database_path.parent / "gatehoused.lock").is_file(),
        "owner": "not_exposed",
    }

    if not database_path.is_file():
        categories["schema"] = {
            "status": "unavailable",
            "failure_category": "database_unavailable",
        }
        categories["integrity"] = {
            "status": "not_run",
            "failure_category": "database_unavailable",
        }
        categories["alerts"] = {
            "status": "not_run",
            "failure_category": "database_unavailable",
        }
        degraded.append("database")
        return result

    try:
        sidecars_exist = any(
            Path(f"{database_path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")
        )
        connection = connect_database(
            database_path,
            busy_timeout_ms=configuration.main.database.busy_timeout_ms,
            read_only=True,
            immutable=not sidecars_exist,
        )
    except (OSError, RuntimeError, sqlite3.Error, ValueError):
        categories["schema"] = {
            "status": "unavailable",
            "failure_category": "database_unavailable",
        }
        categories["integrity"] = {
            "status": "not_run",
            "failure_category": "database_unavailable",
        }
        categories["alerts"] = {
            "status": "not_run",
            "failure_category": "database_unavailable",
        }
        degraded.append("database")
        return result

    schema_ok = False
    try:

        def verify_schema() -> int:
            row = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()
            if row is None or int(row[0]) != len(MIGRATIONS):
                raise MigrationError("migration ledger size differs")
            return verify_migration_compatibility(connection)

        try:
            schema_version = _run_with_step_limit(connection, verify_schema)
        except MigrationError:
            categories["schema"] = {
                "status": "failed",
                "failure_category": "schema_incompatible",
                "expected_version": MIGRATIONS[-1].version if MIGRATIONS else 0,
            }
            degraded.append("schema")
        except (RuntimeError, sqlite3.Error, TypeError, ValueError):
            categories["schema"] = {
                "status": "unavailable",
                "failure_category": "schema_check_unavailable",
                "expected_version": MIGRATIONS[-1].version if MIGRATIONS else 0,
            }
            degraded.append("schema")
        else:
            schema_ok = True
            categories["schema"] = {
                "status": "ok",
                "version": schema_version,
                "expected_version": MIGRATIONS[-1].version if MIGRATIONS else 0,
            }

        def check_integrity() -> tuple[bool, int, bool]:
            quick_rows = connection.execute("PRAGMA quick_check(1)").fetchmany(2)
            quick_ok = len(quick_rows) == 1 and str(quick_rows[0][0]).casefold() == "ok"
            foreign_rows = connection.execute("PRAGMA foreign_key_check").fetchmany(
                _MAXIMUM_FOREIGN_KEY_RESULTS + 1
            )
            return (
                quick_ok and not foreign_rows,
                min(len(foreign_rows), _MAXIMUM_FOREIGN_KEY_RESULTS),
                len(foreign_rows) > _MAXIMUM_FOREIGN_KEY_RESULTS,
            )

        try:
            integrity_ok, violation_count, truncated = _run_with_step_limit(
                connection, check_integrity
            )
        except (RuntimeError, sqlite3.Error, TypeError, ValueError):
            categories["integrity"] = {
                "status": "unavailable",
                "failure_category": "integrity_check_unavailable",
            }
            degraded.append("integrity")
        else:
            categories["integrity"] = {
                "status": "ok" if integrity_ok else "failed",
                "failure_category": None if integrity_ok else "integrity_failed",
                "foreign_key_violations_detected": violation_count,
                "foreign_key_results_truncated": truncated,
            }
            if not integrity_ok:
                degraded.append("integrity")

        if schema_ok:

            def database_counts() -> tuple[int, int, int, int, int]:
                row = connection.execute(
                    """
                    SELECT (SELECT COUNT(*) FROM clients),
                           (SELECT COUNT(*) FROM workspaces),
                           (SELECT COUNT(*) FROM feed_sets),
                           (SELECT COUNT(*) FROM credentials),
                           (SELECT COUNT(*) FROM alerts
                             WHERE severity IN ('HIGH', 'CRITICAL')
                               AND state NOT IN ('RESOLVED', 'CLOSED'))
                    """
                ).fetchone()
                if row is None:
                    raise sqlite3.DatabaseError("count summary is unavailable")
                return tuple(int(row[index]) for index in range(5))  # type: ignore[return-value]

            try:
                stored_clients, stored_workspaces, stored_feeds, credentials, alerts = (
                    _run_with_step_limit(connection, database_counts)
                )
            except (RuntimeError, sqlite3.Error, TypeError, ValueError):
                degraded.append("database_counts")
            else:
                counts.update(
                    {
                        "stored_clients": stored_clients,
                        "stored_workspaces": stored_workspaces,
                        "stored_feed_sets": stored_feeds,
                        "credential_metadata": credentials,
                        "open_high_severity_alerts": alerts,
                    }
                )
                if alerts:
                    degraded.append("alerts")

            try:
                recent_alerts, alerts_truncated = _run_with_step_limit(
                    connection,
                    lambda: _recent_alert_categories(connection, scanner=active_scanner),
                )
            except (RuntimeError, sqlite3.Error, TypeError, ValueError):
                categories["alerts"] = {
                    "status": "unavailable",
                    "failure_category": "alert_diagnostics_unavailable",
                }
                degraded.append("alert_diagnostics")
            else:
                categories["alerts"] = {"status": "ok"}
                result["recent_alert_categories"] = recent_alerts
                result["recent_alert_categories_truncated"] = alerts_truncated
        else:
            categories["alerts"] = {
                "status": "not_run",
                "failure_category": "schema_unavailable",
            }
    finally:
        with suppress(sqlite3.Error):
            connection.close()

    result["degraded_components"] = sorted(set(degraded))
    result["ok"] = not result["degraded_components"]
    return result


def create_support_bundle(
    config_path: str | Path,
    output_path: str | Path,
    *,
    environment: Mapping[str, str],
    scanner: SecretScanner | None = None,
) -> Mapping[str, object]:
    """Create a small JSON support artifact containing only allowlisted diagnostics."""

    active_scanner = scanner or SecretScanner()
    diagnosis = dict(
        diagnose_installation(
            config_path,
            environment=environment,
            scanner=active_scanner,
        )
    )
    output = _resolved_config_path(output_path)
    if output.suffix.casefold() != ".json":
        raise OperatorCommandError("support bundle output must use a .json suffix")
    if output.exists():
        raise OperatorCommandError("support bundle output already exists")
    if not output.parent.is_dir():
        raise OperatorCommandError("support bundle output directory is unavailable")

    payload = {
        "schema_version": 1,
        "kind": "gatehouse_sanitized_support_bundle",
        "gatehouse_version": __version__,
        "runtime": {
            "python": ".".join(str(part) for part in sys.version_info[:3]),
            "platform": platform.system() or "unknown",
        },
        "diagnosis": {
            key: diagnosis[key]
            for key in (
                "ok",
                "categories",
                "counts",
                "listeners",
                "lease",
                "recent_alert_categories",
                "recent_alert_categories_truncated",
                "degraded_components",
            )
        },
    }
    encoded = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAXIMUM_SUPPORT_BUNDLE_BYTES:
        raise OperatorCommandError("support bundle exceeded its size limit")
    try:
        active_scanner.assert_clean(encoded, location="support_bundle")
    except SecretDetectedError:
        raise OperatorCommandError("support bundle contains sensitive material") from None

    created = False
    try:
        with output.open("xb") as stream:
            created = True
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        with suppress(OSError):
            os.chmod(output, 0o600)
    except OSError:
        if created:
            with suppress(BaseException):
                output.unlink()
        raise OperatorCommandError("support bundle could not be written") from None
    except BaseException:
        if created:
            with suppress(BaseException):
                output.unlink()
        raise

    diagnosis["support_bundle"] = {
        "path": active_scanner.redact_text(str(output)),
        "size_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    return diagnosis
