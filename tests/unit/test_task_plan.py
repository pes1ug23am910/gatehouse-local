"""Pure disabled task definitions; no task registration or runtime-trust proof."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from functools import partial
from types import SimpleNamespace
from typing import Any, Never, cast

import pytest

from gatehouse import task_plan

INSTALLATION = "1" * 32
CREATION = "2" * 32
RUNTIME = r"C:\Synthetic\Runtime"
CONFIG = r"C:\Synthetic\Configuration\config.yaml"
OWNER = "S-1-5-21-1-2-3-4"
ERROR = "disabled task plan is invalid"


class _Text(str):
    pass


def _inputs() -> task_plan.TaskPlanInputs:
    return task_plan.TaskPlanInputs(
        installation_id=INSTALLATION,
        runtime_root=RUNTIME,
        pythonw_path=RUNTIME + r"\Scripts\pythonw.exe",
        runtime_review_digest="3" * 64,
        config_origin=CONFIG,
        config_digest="4" * 64,
        owner_sid=OWNER,
        config_environment=(
            ("APPDATA", r"C:\Synthetic\Roaming"),
            ("LOCALAPPDATA", r"C:\Synthetic\Local"),
        ),
    )


def _plan() -> task_plan.DisabledTaskPlan:
    return task_plan.build_disabled_task_plan(_inputs(), creation_id=CREATION)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _assert_invalid(action: Callable[[], object]) -> None:
    with pytest.raises(ValueError) as caught:
        action()
    assert str(caught.value) == ERROR
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def _change(field: str, value: object) -> task_plan.TaskPlanInputs:
    changes: dict[str, Any] = {field: value}
    if field == "runtime_root" and type(value) is str:
        changes["pythonw_path"] = value + r"\Scripts\pythonw.exe"
    return replace(_inputs(), **changes)


def _long_config(length: int) -> str:
    # Seven full components leave a bounded final filename at the 1024-byte edge.
    prefix = "C:\\" + ("a" * 128 + "\\") * 7
    return prefix + "b" * (length - len(prefix) - 5) + ".yaml"


def test_disabled_task_manifest_binds_exact_actions_and_unverified_dispositions() -> None:
    inputs = _inputs()
    plan = _plan()
    expected_inputs = {
        "installation_id": INSTALLATION,
        "runtime_root": RUNTIME,
        "pythonw_path": inputs.pythonw_path,
        "runtime_review_digest": "3" * 64,
        "config_origin": CONFIG,
        "config_digest": "4" * 64,
        "owner_sid": OWNER,
        "config_environment": [list(pair) for pair in inputs.config_environment],
    }
    tasks = []
    for role, module, extra, limit, repetition in (
        ("daemon", "gatehouse.daemon.main", [], 0, 0),
        ("watchdog", "gatehouse.watchdog.main", ["--once"], 300, 120),
    ):
        tasks.append(
            {
                "role": role,
                "path": "\\Gatehouse-" + INSTALLATION + "-" + role,
                "executable": inputs.pythonw_path,
                "working_directory": RUNTIME,
                "arguments": [
                    "-I",
                    "-B",
                    "-m",
                    module,
                    *extra,
                    "--config",
                    CONFIG,
                    "--expected-config-digest",
                    "4" * 64,
                ],
                "owner_sid": OWNER,
                "logon_type": "interactive_token",
                "run_level": "limited",
                "enabled": False,
                "allow_demand_start": False,
                "multiple_instances": "ignore_new",
                "execution_time_limit_seconds": limit,
                "trigger": {
                    "kind": "logon",
                    "owner_sid": OWNER,
                    "enabled": False,
                    "repetition_seconds": repetition,
                },
            }
        )
    expected = {
        "schema": "gatehouse.disabled_task_plan.v1",
        "inputs": expected_inputs,
        "creation_id": CREATION,
        "tasks": tasks,
        "native_registration": "unavailable",
        "runtime_trust": "unverified",
        "ownership": "unconfirmed",
        "environment_enforcement": "unverified",
    }
    assert type(plan) is task_plan.DisabledTaskPlan
    assert type(plan.manifest) is bytes and len(plan.manifest) <= 32_768
    assert plan.manifest == _canonical(expected)
    assert plan.digest == hashlib.sha256(plan.manifest).hexdigest()
    assert (
        cast(Callable[..., object], task_plan.validate_disabled_task_plan)(
            plan, expected_digest=plan.digest
        )
        is None
    )


def test_task_planning_is_deterministic_without_module_local_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> Never:
        raise AssertionError("task planning attempted an external effect")

    class Effects:
        def __getattr__(self, name: str) -> Callable[..., Never]:
            return forbidden

    before = _plan()
    for name in ("open", "Path", "getenv", "uuid4", "monotonic"):
        monkeypatch.setattr(task_plan, name, forbidden, raising=False)
    for name in ("os", "subprocess", "time", "uuid", "datetime"):
        monkeypatch.setattr(task_plan, name, Effects(), raising=False)
    after = _plan()
    assert after == before
    assert (
        cast(Callable[..., object], task_plan.validate_disabled_task_plan)(
            after, expected_digest=before.digest
        )
        is None
    )


@pytest.mark.parametrize("kind", ["inputs", "plan"])
def test_task_plan_values_are_frozen_and_slotted(kind: str) -> None:
    value, field, changed = (
        (_inputs(), "owner_sid", "S-1-5-21-9-8-7-6")
        if kind == "inputs"
        else (_plan(), "digest", "f" * 64)
    )
    assert not hasattr(value, "__dict__")
    with pytest.raises(FrozenInstanceError):
        setattr(value, field, changed)


@pytest.mark.parametrize(
    "binding",
    [
        "installation_id",
        "runtime_root",
        "pythonw_path",
        "runtime_review_digest",
        "config_origin",
        "config_digest",
        "owner_sid",
        "appdata",
        "localappdata",
        "creation_id",
    ],
)
def test_each_explicit_binding_changes_the_plan_digest(binding: str) -> None:
    original = _plan()
    inputs = _inputs()
    creation = CREATION
    replacements = {
        "installation_id": "5" * 32,
        # The original executable remains beneath both lexical roots.
        "runtime_root": r"C:\Synthetic",
        "pythonw_path": RUNTIME + r"\Alternate\pythonw.exe",
        "runtime_review_digest": "6" * 64,
        "config_origin": r"C:\Synthetic\Configuration\other.yml",
        "config_digest": "7" * 64,
        "owner_sid": "S-1-5-21-5-6-7-8",
    }
    if binding in replacements:
        changes: dict[str, Any] = {binding: replacements[binding]}
        inputs = replace(inputs, **changes)
    elif binding == "creation_id":
        creation = "8" * 32
    else:
        entries = list(inputs.config_environment)
        index = 0 if binding == "appdata" else 1
        entries[index] = (entries[index][0], None)
        inputs = replace(inputs, config_environment=tuple(entries))
    changed = task_plan.build_disabled_task_plan(inputs, creation_id=creation)
    assert changed.manifest != original.manifest and changed.digest != original.digest
    assert (
        cast(Callable[..., object], task_plan.validate_disabled_task_plan)(
            changed, expected_digest=changed.digest
        )
        is None
    )
    _assert_invalid(
        lambda: task_plan.validate_disabled_task_plan(changed, expected_digest=original.digest)
    )


@pytest.mark.parametrize(
    "field,bad_values",
    [
        ("installation_id", ("1" * 31, "1" * 33, "A" * 32, "z" * 32, None, True)),
        ("creation_id", ("2" * 31, "2" * 33, "A" * 32, _Text("2" * 32), b"2" * 32)),
        ("runtime_review_digest", ("3" * 63, "3" * 65, "A" * 64, "g" * 64, None)),
        ("config_digest", ("4" * 63, "4" * 64 + "\n", b"4" * 64, _Text("4" * 64))),
        ("pythonw_path", (None, 1, True, b"C:\\pythonw.exe", _Text(_inputs().pythonw_path))),
        ("config_origin", (None, 1, True, b"C:\\config.yaml", _Text(CONFIG))),
    ],
)
def test_task_inputs_reject_nonexact_scalar_bindings(
    field: str, bad_values: tuple[object, ...]
) -> None:
    for value in bad_values:
        inputs = _inputs() if field == "creation_id" else _change(field, value)
        creation = value if field == "creation_id" else CREATION
        _assert_invalid(
            partial(
                task_plan.build_disabled_task_plan,
                inputs,
                creation_id=cast(str, creation),
            )
        )


@pytest.mark.parametrize(
    "field,bad_values",
    [
        ("runtime_root", ("Synthetic\\Runtime", "C:relative", None, True, _Text(RUNTIME))),
        ("runtime_root", (r"c:\Synthetic\Runtime",)),
        ("runtime_root", ("C:\\",)),
        ("runtime_root", (r"\\server\share\Runtime",)),
        ("runtime_root", (r"\\?\C:\Synthetic", r"\\.\C:\Synthetic")),
        ("runtime_root", ("C:/Synthetic/Runtime",)),
        ("runtime_root", ("C:\\Synthetic\\\\Runtime",)),
        ("runtime_root", ("C:\\ Synthetic",)),
        ("runtime_root", ("C:\\Synthetic ",)),
        ("runtime_root", ("C:\\Synthetic.",)),
        ("runtime_root", (r"C:\.\Synthetic",)),
        ("runtime_root", (r"C:\..\Synthetic",)),
        (
            "runtime_root",
            tuple("C:\\Synthetic" + char + "Root" for char in "%~:'\"\n\r\t[]$é"),
        ),
        (
            "runtime_root",
            tuple(
                "C:\\" + name + ".data"
                for name in (
                    "CON",
                    "prn",
                    "AUX",
                    "nul",
                    "CLOCK$",
                    "COM1",
                    "COM9",
                    "LPT1",
                    "lpt9",
                    "CON ",
                    "COM1 ",
                    "lpt9  ",
                )
            ),
        ),
        ("runtime_root", ("C:\\" + "a" * 129,)),
        ("config_origin", (_long_config(1_025),)),
        ("config_origin", ("C:\\" + "d\\" * 32 + "config.yaml",)),
        ("config_origin", (r"C:\Synthetic\config.txt", r"C:\Synthetic\config.yaml.exe")),
        (
            "pythonw_path",
            (r"D:\Synthetic\Runtime\pythonw.exe", RUNTIME + r"-other\pythonw.exe", RUNTIME),
        ),
        ("pythonw_path", (RUNTIME + r"\python.exe", RUNTIME + r"\PythonW.exe")),
    ],
)
def test_task_paths_refuse_ambiguous_or_outside_lexical_forms(
    field: str, bad_values: tuple[object, ...]
) -> None:
    for value in bad_values:
        inputs = _change(field, value)
        _assert_invalid(partial(task_plan.build_disabled_task_plan, inputs, creation_id=CREATION))


@pytest.mark.parametrize("boundary", ["component", "path", "components", "punctuation_and_absence"])
def test_task_paths_accept_the_exact_supported_boundaries(boundary: str) -> None:
    inputs = _inputs()
    if boundary == "component":
        inputs = replace(inputs, config_origin="C:\\" + "a" * 123 + ".yaml")
    elif boundary == "path":
        inputs = replace(inputs, config_origin=_long_config(1_024))
    elif boundary == "components":
        inputs = replace(inputs, config_origin="C:\\" + "d\\" * 31 + "config.yaml")
    else:
        root = r"Z:\Runtime Alpha_1-2.3 (x64)@local+copy"
        inputs = replace(
            inputs,
            runtime_root=root,
            pythonw_path=root + r"\Scripts\pythonw.exe",
            config_origin=r"Z:\Config Alpha_1-2.3 (x64)@local+copy\settings.yml",
            owner_sid="S-1-5-21-4294967295-4294967295-4294967295-4294967295",
            config_environment=(("APPDATA", None), ("LOCALAPPDATA", None)),
        )
    plan = task_plan.build_disabled_task_plan(inputs, creation_id=CREATION)
    assert (
        cast(Callable[..., object], task_plan.validate_disabled_task_plan)(
            plan, expected_digest=plan.digest
        )
        is None
    )


@pytest.mark.parametrize(
    "bad_values",
    [
        ([list(pair) for pair in _inputs().config_environment],),
        (tuple(reversed(_inputs().config_environment)),),
        ((("APPDATA", None),), ()),
        ((("APPDATA", None), ("APPDATA", None)),),
        ((("APPDATA", None), ("PATH", None)),),
        ((["APPDATA", None], ["LOCALAPPDATA", None]),),
        tuple(
            (("APPDATA", value), ("LOCALAPPDATA", None))
            for value in ("", 1, True, b"C:\\data", _Text(r"C:\data"), "relative", "C:\\data\n")
        ),
        ((("APPDATA", _long_config(1_025)), ("LOCALAPPDATA", None)),),
    ],
)
def test_task_environment_requires_the_exact_ordered_expansion_pair(
    bad_values: tuple[object, ...],
) -> None:
    for value in bad_values:
        inputs = replace(
            _inputs(), config_environment=cast(tuple[tuple[str, str | None], ...], value)
        )
        _assert_invalid(partial(task_plan.build_disabled_task_plan, inputs, creation_id=CREATION))


@pytest.mark.parametrize(
    "bad_values",
    [
        ("S-1-5-32-1-2-3-4", "S-1-5-18", "s-1-5-21-1-2-3-4"),
        ("S-1-5-21-1-2-3", "S-1-5-21-1-2-3-4-5"),
        ("S-1-5-21-0-2-3-4", "S-1-5-21--1-2-3-4"),
        ("S-1-5-21-4294967296-2-3-4",),
        ("S-1-5-21-01-2-3-4", "S-1-5-21-1-2-3-04"),
        (None, True, 1, OWNER.encode("ascii"), _Text(OWNER)),
    ],
)
def test_task_owner_requires_an_exact_bounded_canonical_account_sid(
    bad_values: tuple[object, ...],
) -> None:
    for value in bad_values:
        inputs = replace(_inputs(), owner_sid=cast(str, value))
        _assert_invalid(partial(task_plan.build_disabled_task_plan, inputs, creation_id=CREATION))


@pytest.mark.parametrize("value", [None, {}, SimpleNamespace()])
def test_task_builder_refuses_untyped_input_records(value: object) -> None:
    _assert_invalid(
        lambda: task_plan.build_disabled_task_plan(
            cast(task_plan.TaskPlanInputs, value), creation_id=CREATION
        )
    )
    if value is None:
        uninitialized = object.__new__(task_plan.TaskPlanInputs)
        _assert_invalid(
            lambda: task_plan.build_disabled_task_plan(uninitialized, creation_id=CREATION)
        )


@pytest.mark.parametrize(
    "defect",
    [
        "whitespace",
        "key_order",
        "duplicate_key",
        "extra_field",
        "missing_field",
        "enabled",
        "arguments",
        "environment",
        "trust_claim",
        "task_order",
        "integer_bool",
        "bool_limit",
        "task_path",
        "trigger_enabled",
    ],
)
def test_task_validator_rejects_coherently_rehashed_noncanonical_or_changed_plans(
    defect: str,
) -> None:
    original = _plan()
    document = json.loads(original.manifest)
    if defect == "whitespace":
        raw = original.manifest + b" "
    elif defect == "key_order":
        raw = json.dumps(dict(reversed(tuple(document.items()))), separators=(",", ":")).encode(
            "ascii"
        )
    elif defect == "duplicate_key":
        raw = b'{"creation_id":"' + CREATION.encode("ascii") + b'",' + original.manifest[1:]
    else:
        if defect == "extra_field":
            document["unreviewed"] = False
        elif defect == "missing_field":
            del document["environment_enforcement"]
        elif defect == "enabled":
            document["tasks"][0]["enabled"] = True
        elif defect == "arguments":
            document["tasks"][1]["arguments"].append("--print-settings")
        elif defect == "environment":
            document["inputs"]["config_environment"].append(["PATH", r"C:\Unreviewed"])
        elif defect == "trust_claim":
            document["runtime_trust"] = "verified"
        elif defect == "task_order":
            document["tasks"].reverse()
        elif defect == "integer_bool":
            document["tasks"][0]["allow_demand_start"] = 0
        elif defect == "bool_limit":
            document["tasks"][0]["execution_time_limit_seconds"] = False
        elif defect == "task_path":
            document["tasks"][0]["path"] = "\\Gatehouse-foreign-daemon"
        elif defect == "trigger_enabled":
            document["tasks"][1]["trigger"]["enabled"] = True
        raw = _canonical(document)
    digest = hashlib.sha256(raw).hexdigest()
    changed = task_plan.DisabledTaskPlan(manifest=raw, digest=digest)
    _assert_invalid(lambda: task_plan.validate_disabled_task_plan(changed, expected_digest=digest))


@pytest.mark.parametrize(
    "defect", ["record_types", "manifest_bounds", "encoding_and_json", "expected_digest", "digest"]
)
def test_task_validator_rejects_malformed_untrusted_envelopes(
    defect: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan()
    if defect == "record_types":
        bad_plans: list[object] = [
            None,
            {},
            SimpleNamespace(manifest=plan.manifest, digest=plan.digest),
            object.__new__(task_plan.DisabledTaskPlan),
        ]
        bad_plans.extend(
            task_plan.DisabledTaskPlan(manifest=cast(bytes, value), digest=plan.digest)
            for value in (None, plan.manifest.decode("ascii"), bytearray(plan.manifest))
        )
        for candidate in bad_plans:
            _assert_invalid(
                partial(
                    task_plan.validate_disabled_task_plan,
                    cast(task_plan.DisabledTaskPlan, candidate),
                    expected_digest=plan.digest,
                )
            )
    elif defect == "manifest_bounds":

        def forbidden(*args: object, **kwargs: object) -> Never:
            raise AssertionError("out-of-bound manifest reached decoding or hashing")

        monkeypatch.setattr(task_plan, "json", SimpleNamespace(loads=forbidden, dumps=forbidden))
        monkeypatch.setattr(task_plan, "hashlib", SimpleNamespace(sha256=forbidden))
        for raw in (b"", b" " * 32_769):
            candidate = task_plan.DisabledTaskPlan(manifest=raw, digest=plan.digest)
            _assert_invalid(
                partial(
                    task_plan.validate_disabled_task_plan,
                    candidate,
                    expected_digest=plan.digest,
                )
            )
    elif defect == "encoding_and_json":
        for raw in (
            b"\xff",
            b"{",
            b"[]",
            b"null",
            b'{"number":NaN}',
            b'{"number":Infinity}',
            b"[" * 1_500 + b"0" + b"]" * 1_500,
            b'{"number":' + b"9" * 5_000 + b"}",
        ):
            digest = hashlib.sha256(raw).hexdigest()
            candidate = task_plan.DisabledTaskPlan(manifest=raw, digest=digest)
            _assert_invalid(
                partial(
                    task_plan.validate_disabled_task_plan,
                    candidate,
                    expected_digest=digest,
                )
            )
    elif defect == "expected_digest":
        for invalid_digest in (None, "A" * 64, "f" * 64, plan.digest + "\n", _Text(plan.digest)):
            _assert_invalid(
                partial(
                    task_plan.validate_disabled_task_plan,
                    plan,
                    expected_digest=cast(str, invalid_digest),
                )
            )
    else:
        for malformed_digest in (None, True, "A" * 64, "f" * 64, _Text(plan.digest)):
            candidate = task_plan.DisabledTaskPlan(
                manifest=plan.manifest, digest=cast(str, malformed_digest)
            )
            _assert_invalid(
                partial(
                    task_plan.validate_disabled_task_plan,
                    candidate,
                    expected_digest=plan.digest,
                )
            )
