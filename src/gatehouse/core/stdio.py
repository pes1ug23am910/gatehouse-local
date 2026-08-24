"""Process standard-stream hardening for windowless Windows entry points."""

from __future__ import annotations

import os
import sys
from typing import Literal, TextIO, cast


def _null_stream(mode: Literal["r", "w"]) -> TextIO:
    return cast(TextIO, open(os.devnull, mode, encoding="utf-8"))  # noqa: SIM115


def _set_missing_original_stream(name: str, stream: TextIO) -> None:
    if getattr(sys, name) is None:
        setattr(sys, name, stream)


def ensure_standard_streams() -> None:
    """Replace absent ``pythonw`` standard streams with the null device."""

    if sys.stdin is None:
        sys.stdin = sys.__stdin__ or _null_stream("r")
    _set_missing_original_stream("__stdin__", sys.stdin)

    if sys.stdout is None:
        sys.stdout = sys.__stdout__ or _null_stream("w")
    _set_missing_original_stream("__stdout__", sys.stdout)

    if sys.stderr is None:
        sys.stderr = sys.__stderr__ or _null_stream("w")
    _set_missing_original_stream("__stderr__", sys.stderr)
