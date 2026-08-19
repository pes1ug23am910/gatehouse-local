"""Bounded heuristic inspection that reports classes, never matched values."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|password|passwd|secret)(?:$|[_-])",
    re.IGNORECASE,
)
_AUTHORIZATION_VALUE = re.compile(r"^(?:bearer|basic)\s+[A-Za-z0-9+/=_\-.]{8,}$", re.I)
_PEM_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_KEY_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*"
    r"[^\s,;]{8,}"
)
_TOKENISH = re.compile(r"^[A-Za-z0-9_\-./+=]{24,}$")


@dataclass(frozen=True, slots=True)
class InspectionResult:
    """Metadata-only findings suitable for policy and audit records."""

    denied: bool
    findings: tuple[str, ...]
    inspected_nodes: int
    inspected_characters: int
    complete: bool


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def inspect_sensitive_content(
    value: Any,
    *,
    maximum_nodes: int = 2_000,
    maximum_characters: int = 200_000,
    maximum_depth: int = 12,
) -> InspectionResult:
    """Inspect a JSON-like value with fail-closed resource limits."""

    findings: set[str] = set()
    nodes = 0
    characters = 0
    complete = True
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]

    while stack:
        item, depth, sensitive_context = stack.pop()
        nodes += 1
        if nodes > maximum_nodes or depth > maximum_depth:
            complete = False
            findings.add("inspection_limit_exceeded")
            break
        if isinstance(item, Mapping):
            for raw_key, child in item.items():
                key = str(raw_key)
                characters += len(key)
                key_sensitive = bool(_SENSITIVE_KEY.search(key))
                if key_sensitive:
                    findings.add("sensitive_field_name")
                stack.append((child, depth + 1, key_sensitive))
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            stack.extend((child, depth + 1, sensitive_context) for child in item)
        elif isinstance(item, (str, bytes, bytearray)):
            text = item.decode("utf-8", "replace") if not isinstance(item, str) else item
            characters += len(text)
            if characters > maximum_characters:
                complete = False
                findings.add("inspection_limit_exceeded")
                break
            if _PEM_PRIVATE_KEY.search(text):
                findings.add("private_key_material")
            if _AUTHORIZATION_VALUE.match(text.strip()):
                findings.add("authorization_value")
            if _KEY_ASSIGNMENT.search(text):
                findings.add("embedded_secret_assignment")
            if (
                sensitive_context
                and _TOKENISH.match(text.strip())
                and _entropy(text.strip()) >= 3.5
            ):
                findings.add("token_like_sensitive_value")

    return InspectionResult(
        denied=bool(findings),
        findings=tuple(sorted(findings)),
        inspected_nodes=min(nodes, maximum_nodes + 1),
        inspected_characters=min(characters, maximum_characters + 1),
        complete=complete,
    )
