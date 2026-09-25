"""Pure adjacent launcher spelling selection; no native runtime trust assertion."""

from __future__ import annotations

_ERROR = "the adjacent daemon entry point is unavailable"
_PATH_LIMIT = 4096
_PART_LIMIT = 255
_PART_COUNT_LIMIT = 128
_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    | {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789¹²³"}
)


def _valid_path(value: object, platform: str) -> bool:
    if type(value) is not str or not 2 <= len(value) <= _PATH_LIMIT:
        return False
    if platform == "nt":
        if len(value) < 4 or value[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" or value[1:3] != ":\\":
            return False
        parts = value[3:].split("\\")
    else:
        if not value.startswith("/") or "\\" in value:
            return False
        parts = value[1:].split("/")
    if not 1 <= len(parts) <= _PART_COUNT_LIMIT:
        return False
    for part in parts:
        if (
            not 1 <= len(part) <= _PART_LIMIT
            or part in (".", "..")
            or part.startswith(" ")
            or part.endswith((" ", "."))
            or not part.isprintable()
        ):
            return False
        if platform == "nt" and (
            any(character in '<>:"/|?*%~' for character in part)
            or part.split(".", 1)[0].rstrip(" ").upper() in _RESERVED
        ):
            return False
    return True


def select_adjacent_daemon_path(
    interpreter_executable: str,
    *,
    requested_executable: str | None,
    platform: str,
) -> str:
    """Select one bounded lexical path without discovering or trusting its file."""

    if (
        type(platform) is not str
        or platform not in ("nt", "posix")
        or not _valid_path(interpreter_executable, platform)
    ):
        raise ValueError(_ERROR)
    separator, name = ("\\", "gatehoused.exe") if platform == "nt" else ("/", "gatehoused")
    selected = interpreter_executable.rsplit(separator, 1)[0] + separator + name
    if not _valid_path(selected, platform):
        raise ValueError(_ERROR)
    if requested_executable is not None and (
        not _valid_path(requested_executable, platform) or requested_executable != selected
    ):
        raise ValueError(_ERROR)
    return selected
