"""Data-only disabled task plans; no native registration or ownership authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

_ERROR = "disabled task plan is invalid"
_MANIFEST_LIMIT = 32 * 1024
_INPUT_NAMES = frozenset(
    {
        "installation_id",
        "runtime_root",
        "pythonw_path",
        "runtime_review_digest",
        "config_origin",
        "config_digest",
        "owner_sid",
        "config_environment",
    }
)
_DOCUMENT_NAMES = frozenset(
    {
        "schema",
        "inputs",
        "creation_id",
        "tasks",
        "native_registration",
        "runtime_trust",
        "ownership",
        "environment_enforcement",
    }
)
_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)}
)


@dataclass(frozen=True, slots=True)
class TaskPlanInputs:
    """Supplied review bindings, without filesystem, token or environment attestation."""

    installation_id: str
    runtime_root: str
    pythonw_path: str
    runtime_review_digest: str
    config_origin: str
    config_digest: str
    owner_sid: str
    config_environment: tuple[tuple[str, str | None], ...]


@dataclass(frozen=True, slots=True)
class DisabledTaskPlan:
    """Immutable review artifact. A matching digest does not grant task authority."""

    manifest: bytes
    digest: str


def _hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


def _path(value: object) -> bool:
    # Validate raw spelling. Normalization could conceal traversal or aliases.
    if type(value) is not str or not 4 <= len(value) <= 1024:
        return False
    if re.fullmatch(r"[A-Z]:\\[A-Za-z0-9_ .()@+\\-]+", value) is None:
        return False
    components = value[3:].split("\\")
    if not 1 <= len(components) <= 32:
        return False
    for part in components:
        if (
            not 1 <= len(part) <= 128
            or part.startswith(" ")
            or part.endswith((" ", "."))
            or part in (".", "..")
            or part.split(".", 1)[0].rstrip(" ").upper() in _RESERVED
        ):
            return False
    return True


def _sid(value: object) -> bool:
    if type(value) is not str or not 16 <= len(value) <= 68:
        return False
    if re.fullmatch(r"S-1-5-21-(?:[1-9][0-9]{0,9}-){3}[1-9][0-9]{0,9}", value) is None:
        return False
    return all(int(part) <= 0xFFFFFFFF for part in value.split("-")[4:])


def _validate_inputs(inputs: TaskPlanInputs, creation_id: str) -> None:
    if (
        type(inputs) is not TaskPlanInputs
        or not all(hasattr(inputs, name) for name in _INPUT_NAMES)
        or not _hex(creation_id, 32)
    ):
        raise ValueError(_ERROR)
    if (
        not _hex(inputs.installation_id, 32)
        or not _hex(inputs.runtime_review_digest, 64)
        or not _hex(inputs.config_digest, 64)
        or not _sid(inputs.owner_sid)
        or not _path(inputs.runtime_root)
        or not _path(inputs.pythonw_path)
        or not _path(inputs.config_origin)
    ):
        raise ValueError(_ERROR)
    if (
        not inputs.pythonw_path.startswith(inputs.runtime_root + "\\")
        or inputs.pythonw_path.rsplit("\\", 1)[-1] != "pythonw.exe"
        or not inputs.config_origin.endswith((".yaml", ".yml"))
    ):
        raise ValueError(_ERROR)
    environment = inputs.config_environment
    if type(environment) is not tuple or len(environment) != 2:
        raise ValueError(_ERROR)
    for entry, name in zip(environment, ("APPDATA", "LOCALAPPDATA"), strict=True):
        if (
            type(entry) is not tuple
            or len(entry) != 2
            or type(entry[0]) is not str
            or entry[0] != name
            or (entry[1] is not None and not _path(entry[1]))
        ):
            raise ValueError(_ERROR)


def _task(inputs: TaskPlanInputs, role: str) -> dict[str, Any]:
    watchdog = role == "watchdog"
    arguments: tuple[str, ...] = ("-I", "-B", "-m", f"gatehouse.{role}.main")
    if watchdog:
        arguments += ("--once",)
    arguments += (
        "--config",
        inputs.config_origin,
        "--expected-config-digest",
        inputs.config_digest,
    )
    return {
        "role": role,
        "path": f"\\Gatehouse-{inputs.installation_id}-{role}",
        "executable": inputs.pythonw_path,
        "working_directory": inputs.runtime_root,
        "arguments": arguments,
        "owner_sid": inputs.owner_sid,
        "logon_type": "interactive_token",
        "run_level": "limited",
        "enabled": False,
        "allow_demand_start": False,
        "multiple_instances": "ignore_new",
        "execution_time_limit_seconds": 300 if watchdog else 0,
        "trigger": {
            "kind": "logon",
            "owner_sid": inputs.owner_sid,
            "enabled": False,
            "repetition_seconds": 120 if watchdog else 0,
        },
    }


def build_disabled_task_plan(inputs: TaskPlanInputs, *, creation_id: str) -> DisabledTaskPlan:
    """Build two disabled review intents without reading state or performing effects.

    The review digest and SID are caller assertions. Paths use a restricted ASCII
    syntax, not native resolution. Argument tuples are never rendered as a command
    string. Configuration expansion bindings are not a complete child environment.
    """
    _validate_inputs(inputs, creation_id)
    document = {
        "schema": "gatehouse.disabled_task_plan.v1",
        "inputs": asdict(inputs),
        "creation_id": creation_id,
        "tasks": (_task(inputs, "daemon"), _task(inputs, "watchdog")),
        "native_registration": "unavailable",
        "runtime_trust": "unverified",
        "ownership": "unconfirmed",
        "environment_enforcement": "unverified",
    }
    manifest = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if len(manifest) > _MANIFEST_LIMIT:
        raise ValueError(_ERROR)
    return DisabledTaskPlan(manifest=manifest, digest=hashlib.sha256(manifest).hexdigest())


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_ERROR)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(_ERROR)


def validate_disabled_task_plan(plan: DisabledTaskPlan, *, expected_digest: str) -> None:
    """Check exact canonical data consistency; never establish native authority."""
    if (
        type(plan) is not DisabledTaskPlan
        or not hasattr(plan, "manifest")
        or not hasattr(plan, "digest")
        or type(plan.manifest) is not bytes
        or not 1 <= len(plan.manifest) <= _MANIFEST_LIMIT
        or not _hex(plan.digest, 64)
        or not _hex(expected_digest, 64)
        or plan.digest != expected_digest
    ):
        raise ValueError(_ERROR)
    if hashlib.sha256(plan.manifest).hexdigest() != plan.digest:
        raise ValueError(_ERROR)
    invalid = False
    try:
        document = json.loads(
            plan.manifest.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        if type(document) is not dict or document.keys() != _DOCUMENT_NAMES:
            raise ValueError(_ERROR)
        bindings = document["inputs"]
        if type(bindings) is not dict or bindings.keys() != _INPUT_NAMES:
            raise ValueError(_ERROR)
        environment = bindings["config_environment"]
        if (
            type(environment) is not list
            or len(environment) != 2
            or any(type(entry) is not list or len(entry) != 2 for entry in environment)
        ):
            raise ValueError(_ERROR)
        bindings["config_environment"] = tuple(tuple(entry) for entry in environment)
        rebuilt = build_disabled_task_plan(
            TaskPlanInputs(**bindings), creation_id=document["creation_id"]
        )
        if rebuilt != plan:
            raise ValueError(_ERROR)
    except (ValueError, TypeError, RecursionError):
        invalid = True
    # Raise outside the handler to avoid retaining malformed input in a chained error.
    if invalid:
        raise ValueError(_ERROR)
