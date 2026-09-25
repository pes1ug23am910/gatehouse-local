from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import cast

import pytest

from gatehouse.sessions import (
    EnvironmentValidationError,
    build_child_environment,
    build_long_lived_environment,
)


def test_child_environment_strips_provider_secrets_case_insensitively() -> None:
    result = build_child_environment(
        {
            "Path": "C:\\Windows",
            "firecrawl_api_key": "fc-secret",
            "SOURCE_CONTROL_TOKEN": "source-control-secret",
            "SERVICE_PASSWORD": "password-secret",
            "GATEHOUSE_ACCESS_TOKEN": "must-not-propagate",
            "GATEHOUSE_SESSION_BOOTSTRAP": "stale",
        },
        {
            "GATEHOUSE_SESSION_BOOTSTRAP": "fresh-bootstrap",
            "GATEHOUSE_SESSION_ID": "ses_new",
        },
    )

    assert result["Path"] == "C:\\Windows"
    assert result["GATEHOUSE_SESSION_BOOTSTRAP"] == "fresh-bootstrap"
    assert result["GATEHOUSE_SESSION_ID"] == "ses_new"
    assert all(
        name.upper()
        not in {
            "FIRECRAWL_API_KEY",
            "SOURCE_CONTROL_TOKEN",
            "SERVICE_PASSWORD",
        }
        for name in result
    )
    assert "GATEHOUSE_ACCESS_TOKEN" not in result


def test_child_environment_rejects_reintroducing_a_secret() -> None:
    with pytest.raises(ValueError, match="forbidden child environment"):
        build_child_environment({}, {"Future_Service_Api_Key": "secret"})


def test_long_lived_environment_is_an_allowlist_not_a_secret_denylist() -> None:
    result = build_long_lived_environment(
        {
            "Path": "C:\\Windows",
            "appdata": "C:\\Users\\test\\AppData\\Roaming",
            "FIRECRAWL_API_KEY": "provider-secret",
            "AWS_ACCESS_KEY_ID": "cloud-identifier",
            "UNRELATED_VALUE": "do-not-retain",
            "PYTHONPATH": "untrusted-import-root",
        }
    )

    assert result == {
        "APPDATA": "C:\\Users\\test\\AppData\\Roaming",
        "PATH": "C:\\Windows",
    }


_ENVIRONMENT_ERROR = "long-lived process environment is invalid"


class _Text(str):
    def __str__(self) -> str:
        raise AssertionError("unexpected text coercion")

    def encode(self, *args: object, **kwargs: object) -> bytes:
        raise AssertionError("unexpected subclass encoding")


class _Untouched:
    def __str__(self) -> str:
        raise AssertionError("unexpected value coercion")

    def __len__(self) -> int:
        raise AssertionError("unexpected value inspection")

    def encode(self, *args: object, **kwargs: object) -> bytes:
        raise AssertionError("unexpected value encoding")


class _Items:
    def __init__(self, pairs: Sequence[tuple[object, object]]) -> None:
        self.pairs = pairs
        self.reads = 0

    def items(self) -> Iterator[tuple[object, object]]:
        for pair in self.pairs:
            self.reads += 1
            yield pair


def _build(base: object) -> dict[str, str]:
    return build_long_lived_environment(cast(Mapping[str, str], base))


def _refused(base: object) -> EnvironmentValidationError:
    with pytest.raises(EnvironmentValidationError) as caught:
        _build(base)
    error = caught.value
    assert isinstance(error, ValueError)
    assert error.args == (_ENVIRONMENT_ERROR,)
    assert str(error) == _ENVIRONMENT_ERROR
    assert error.__cause__ is None and error.__context__ is None
    assert error.__dict__ == {}
    return error


def test_long_lived_environment_preserves_empty_bindings_and_sorted_exact_values() -> None:
    source = {"TEMP": "", "path": "  literal;value  ", "LOCALAPPDATA": "", "appdata": ""}
    result = _build(source)
    assert list(result.items()) == [
        ("APPDATA", ""),
        ("LOCALAPPDATA", ""),
        ("PATH", "  literal;value  "),
        ("TEMP", ""),
    ]
    assert _build(result) == result


def test_long_lived_environment_owns_its_result_without_mutating_the_source() -> None:
    source = {"appdata": "original", "PATH": "original-path"}
    result = _build(source)
    source["appdata"] = "changed"
    assert result == {"APPDATA": "original", "PATH": "original-path"}
    result["PATH"] = "child-change"
    assert source == {"appdata": "changed", "PATH": "original-path"}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("values", [("one", "two"), ("same", "same"), ("", "")])
def test_long_lived_environment_rejects_duplicate_canonical_names(
    reverse: bool,
    values: tuple[str, str],
) -> None:
    pairs = [("APPDATA", values[0]), ("appdata", values[1])]
    _refused(_Items(list(reversed(pairs)) if reverse else pairs))


@pytest.mark.parametrize(
    "name",
    [None, True, 1, b"PATH", _Text("PATH"), _Untouched()],
    ids=["none", "boolean", "integer", "bytes", "text_subclass", "opaque_object"],
)
def test_long_lived_environment_rejects_untyped_names_without_coercion(name: object) -> None:
    _refused(_Items([(name, _Untouched())]))


@pytest.mark.parametrize(
    "value",
    [None, True, 1, b"value", _Text("value"), _Untouched()],
    ids=["none", "boolean", "integer", "bytes", "text_subclass", "opaque_object"],
)
def test_long_lived_environment_rejects_untyped_retained_values(value: object) -> None:
    _refused(_Items([("APPDATA", value)]))


def test_long_lived_environment_never_inspects_excluded_values_or_unicode_aliases() -> None:
    result = _build(
        _Items(
            [
                ("UNRELATED", _Untouched()),
                ("PYTHONPATH", _Untouched()),
                ("FIRECRAWL_API_KEY", _Text("must not encode")),
                ("\u017fy\u017ftemroot", _Untouched()),
                ("u\u017fer", _Untouched()),
                ("w\u0131nd\u0131r", _Untouched()),
                ("\U0001f642", _Untouched()),
                ("IGNORED_ENCODING", "\ud800"),
                ("IGNORED_LENGTH", "x" * 8193),
                ("IGNORED_NUL", "bad\x00value"),
                ("PATH", "kept"),
            ]
        )
    )
    assert result == {"PATH": "kept"}


@pytest.mark.parametrize("name", ["", "a" * 257, "bad\x00name", "bad\rname", "bad\nname", "\ud800"])
def test_long_lived_environment_rejects_invalid_names_before_excluding_them(name: str) -> None:
    _refused(_Items([(name, _Untouched())]))


def test_long_lived_environment_accepts_the_exact_name_character_limit() -> None:
    assert _build(_Items([("a" * 256, _Untouched()), ("\U0001f642" * 256, _Untouched())])) == {}


@pytest.mark.parametrize("value", ["bad\x00value", "bad\rvalue", "bad\nvalue", "\ud800", "\udfff"])
def test_long_lived_environment_refuses_invalid_retained_values(value: str) -> None:
    _refused({"TEMP": value})


@pytest.mark.parametrize("character,count", [("a", 8192), ("\u03a9", 4096), ("\U0001f642", 2048)])
def test_long_lived_environment_enforces_retained_value_utf8_byte_limit(
    character: str,
    count: int,
) -> None:
    value = character * count
    assert len(value.encode("utf-8")) == 8192
    assert _build({"TEMP": value}) == {"TEMP": value}
    _refused({"TEMP": value + "a"})


def test_long_lived_environment_enforces_source_name_utf8_budget() -> None:
    pairs = [("\U0001f642" * 256, _Untouched())] * 64
    assert sum(len(name.encode("utf-8")) for name, _value in pairs) == 65536
    assert _build(_Items(pairs)) == {}
    _refused(_Items([*pairs, ("x", _Untouched())]))


def test_long_lived_environment_enforces_complete_output_utf8_budget() -> None:
    source = {"APPDATA": "a" * 8192, "HOME": "b" * 8192, "TEMP": "c" * 8192, "TMP": "d" * 8165}
    size = 1 + sum(
        len(name.encode("utf-8")) + len(value.encode("utf-8")) + 2 for name, value in source.items()
    )
    assert size == 32768
    assert _build(source) == source
    source["TMP"] += "d"
    _refused(source)


def test_long_lived_environment_counts_excluded_source_entries_and_stops_at_overflow() -> None:
    source = _Items([("IGNORED", _Untouched())] * 512)
    assert _build(source) == {} and source.reads == 512

    class Endless:
        reads = 0

        def items(self) -> Iterator[tuple[str, object]]:
            while True:
                self.reads += 1
                assert self.reads <= 513
                yield "IGNORED", _Untouched()

    endless = Endless()
    _refused(endless)
    assert endless.reads == 513


@pytest.mark.parametrize("stage", ["items", "iteration", "pair"])
def test_long_lived_environment_sanitizes_ordinary_mapping_failures(stage: str) -> None:
    class Broken:
        def items(self) -> Iterator[object]:
            if stage == "items":
                raise RuntimeError("synthetic-private-detail")
            return self.iterate()

        def iterate(self) -> Iterator[object]:
            yield "APPDATA", "partial"
            if stage == "iteration":
                raise RuntimeError("synthetic-private-detail")
            yield ("synthetic-private-detail",)

    error = _refused(Broken())
    assert "synthetic-private-detail" not in repr(error)


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize("stage", ["items", "iteration"])
def test_long_lived_environment_propagates_control_flow_interruptions(
    interruption: type[BaseException],
    stage: str,
) -> None:
    signal = interruption("synthetic interruption")

    class Interrupted:
        def items(self) -> Iterator[tuple[str, str]]:
            if stage == "items":
                raise signal
            return self.iterate()

        def iterate(self) -> Iterator[tuple[str, str]]:
            yield "APPDATA", "partial"
            raise signal

    with pytest.raises(interruption) as caught:
        _build(Interrupted())
    assert caught.value is signal
