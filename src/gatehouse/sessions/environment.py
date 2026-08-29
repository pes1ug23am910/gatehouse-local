"""Construction of clean controlled-launch environments."""

from __future__ import annotations

from collections.abc import Mapping

PROVIDER_SECRET_VARIABLES = frozenset(
    {
        "FIRECRAWL_API_KEY",
        "GATEHOUSE_ACCESS_TOKEN",
    }
)

# Long-lived Gatehouse processes need only operating-system location, temporary
# directory, locale, and trust-store inputs. In particular, Python injection
# controls and arbitrary provider/tool variables are intentionally absent.
LONG_LIVED_ENVIRONMENT_VARIABLES = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
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


def build_long_lived_environment(base: Mapping[str, str]) -> dict[str, str]:
    """Build the minimal inherited environment for daemon/watchdog children.

    Names are normalized because Windows treats them case-insensitively. An
    invalid value is omitted instead of allowing an unrelated shell setting to
    make a security-critical child launch fail in a data-dependent way.
    """

    result: dict[str, str] = {}
    for name, value in base.items():
        canonical = str(name).upper()
        rendered = str(value)
        if canonical in LONG_LIVED_ENVIRONMENT_VARIABLES and rendered and "\x00" not in rendered:
            result[canonical] = rendered
    return result
