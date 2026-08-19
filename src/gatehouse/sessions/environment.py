"""Construction of clean controlled-launch environments."""

from __future__ import annotations

from collections.abc import Mapping

PROVIDER_SECRET_VARIABLES = frozenset(
    {
        "FIRECRAWL_API_KEY",
        "GATEHOUSE_ACCESS_TOKEN",
    }
)

_SECRET_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PRIVATE_KEY")


def _is_secret_variable(name: str) -> bool:
    canonical = name.upper()
    return canonical in PROVIDER_SECRET_VARIABLES or any(
        canonical == suffix.removeprefix("_") or canonical.endswith(suffix)
        for suffix in _SECRET_SUFFIXES
    )


def build_child_environment(
    base: Mapping[str, str],
    additions: Mapping[str, str],
) -> dict[str, str]:
    """Copy an environment while removing provider secrets case-insensitively.

    ``additions`` is expected to carry only the scoped Gatehouse bootstrap metadata.
    It cannot be used to put a provider secret or an ordinary access token back into
    the child environment.
    """

    illegal = sorted(name for name in additions if _is_secret_variable(name))
    if illegal:
        raise ValueError(f"forbidden child environment variables: {', '.join(illegal)}")

    result = {name: value for name, value in base.items() if not _is_secret_variable(name)}
    addition_names = {name.upper() for name in additions}
    for existing in tuple(result):
        if existing.upper() in addition_names:
            del result[existing]
    result.update(additions)
    return result
