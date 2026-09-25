from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.database.connection import (
    DatabaseConfigurationError,
    _connect_existing_database_without_write_configuration,
    connect_database,
)
from gatehouse.database.migrations import open_compatible_database, open_migrated_database


def assert_security_options(connection: sqlite3.Connection) -> None:
    assert connection.getconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE) is True
    assert connection.getconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA) is False
    assert connection.getconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION) is False
    assert connection.execute("PRAGMA trusted_schema").fetchone()[0] == 0


@pytest.mark.parametrize("mode", ("new", "existing", "read_only", "immutable", "compatible"))
def test_every_database_open_path_applies_defensive_options(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "synthetic.sqlite3"
    with_closing = open_migrated_database(path)
    assert_security_options(with_closing)
    with_closing.close()
    before = path.read_bytes()
    if mode == "existing":
        connection = _connect_existing_database_without_write_configuration(path)
    elif mode == "compatible":
        connection = open_compatible_database(path)
    else:
        connection = connect_database(
            path,
            read_only=mode in {"read_only", "immutable"},
            immutable=mode == "immutable",
        )
    try:
        assert_security_options(connection)
    finally:
        connection.close()
    if mode in {"read_only", "immutable"}:
        assert path.read_bytes() == before


def test_schema_cannot_invoke_application_functions() -> None:
    connection = connect_database(":memory:")
    calls: list[int] = []

    def callback() -> int:
        calls.append(1)
        return 1

    try:
        connection.create_function("synthetic_callback", 0, callback)
        connection.execute("CREATE VIEW injected AS SELECT synthetic_callback()")
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("SELECT * FROM injected").fetchall()
        assert calls == []
    finally:
        connection.close()


def test_defensive_mode_prevents_direct_schema_corruption() -> None:
    connection = connect_database(":memory:")
    try:
        connection.execute("CREATE TABLE kept(value INTEGER)")
        connection.execute("PRAGMA writable_schema=ON")
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM sqlite_schema WHERE name='kept'")
        assert connection.execute("SELECT COUNT(*) FROM kept").fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError, match="not authorized"):
            connection.execute("SELECT load_extension('synthetic-not-a-library')")
    finally:
        connection.close()


@pytest.mark.parametrize(
    "factory", (connect_database, _connect_existing_database_without_write_configuration)
)
@pytest.mark.parametrize("failure", ("unsupported", "not_applied"))
def test_unavailable_security_options_close_before_sql(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    factory: object,
    failure: str,
) -> None:
    class RefusingConnection:
        closed = False
        row_factory: object = None

        def setconfig(self, option: int, enable: bool) -> None:
            if failure == "unsupported":
                raise sqlite3.NotSupportedError("synthetic internal diagnostic")

        def getconfig(self, option: int) -> bool:
            return option != sqlite3.SQLITE_DBCONFIG_DEFENSIVE

        def execute(self, statement: str) -> None:
            pytest.fail("SQL executed before required connection security was established")

        def close(self) -> None:
            self.closed = True

    connection = RefusingConnection()
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: connection)
    assert callable(factory)
    with pytest.raises(DatabaseConfigurationError) as failure_info:
        factory(tmp_path / "synthetic.sqlite3")
    assert str(failure_info.value) == "SQLite defensive settings are unavailable"
    assert failure_info.value.__context__ is None
    assert connection.closed
