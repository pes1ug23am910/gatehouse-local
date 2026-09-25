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
_MAXIMUM_SOURCE_ENTRIES = 512
_MAXIMUM_NAME_CHARACTERS = 256
_MAXIMUM_SOURCE_NAME_BYTES = 65_536
_MAXIMUM_VALUE_BYTES = 8_192
_MAXIMUM_ENVIRONMENT_BYTES = 32_768


class EnvironmentValidationError(ValueError):
    """Fixed refusal without rejected environment names, values or exception details."""

    def __init__(self) -> None:
        super().__init__("long-lived process environment is invalid")


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
    """Return bounded, sorted daemon/watchdog inputs without inspecting excluded values.

    At most 512 source entries are accepted, with one further read to detect overflow.
    Names are exact strings of 1..256 characters, totaling at most 65,536 UTF-8 bytes.
    Only ASCII allowlisted names are retained and canonicalized to uppercase; duplicate
    retained names fail even when their values agree. Retained values are exact strings
    of at most 8,192 UTF-8 bytes, including empty strings. Names and retained values must
    encode strictly and contain no NUL, CR or LF.

    The 32,768-byte output budget counts UTF-8 names and values, two bytes per entry
    for '=' and NUL, and one final NUL. This is a source data bound, not a native
    environment-block or filesystem-trust guarantee. Mapping callbacks have no
    preemptive time bound. Ordinary failures expose one fixed error; interruptions
    propagate. No partially accepted environment is returned.
    """

    try:
        result: dict[str, str] = {}
        source_name_bytes = 0
        environment_bytes = 1
        for index, item in enumerate(base.items()):
            if index >= _MAXIMUM_SOURCE_ENTRIES:
                raise EnvironmentValidationError()
            name, value = item
            if (
                type(name) is not str
                or not 1 <= len(name) <= _MAXIMUM_NAME_CHARACTERS
                or any(character in name for character in "\x00\r\n")
            ):
                raise EnvironmentValidationError()
            source_name_bytes += len(name.encode("utf-8"))
            if source_name_bytes > _MAXIMUM_SOURCE_NAME_BYTES:
                raise EnvironmentValidationError()
            if not name.isascii():
                continue
            canonical = name.upper()
            if canonical not in LONG_LIVED_ENVIRONMENT_VARIABLES:
                continue
            if (
                canonical in result
                or type(value) is not str
                or len(value) > _MAXIMUM_VALUE_BYTES
                or any(character in value for character in "\x00\r\n")
            ):
                raise EnvironmentValidationError()
            value_bytes = len(value.encode("utf-8"))
            if value_bytes > _MAXIMUM_VALUE_BYTES:
                raise EnvironmentValidationError()
            environment_bytes += len(canonical) + value_bytes + 2
            if environment_bytes > _MAXIMUM_ENVIRONMENT_BYTES:
                raise EnvironmentValidationError()
            result[canonical] = value
        return dict(sorted(result.items()))
    except Exception:  # noqa: S110 - fixed refusal is raised outside the exception context
        pass
    # Raise outside the handler so even exception-context inspection remains fixed.
    raise EnvironmentValidationError() from None
