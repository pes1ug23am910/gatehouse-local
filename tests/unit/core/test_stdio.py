from __future__ import annotations

import sys
from typing import TextIO, cast

import pytest

from gatehouse.core.stdio import ensure_standard_streams


def test_missing_pythonw_standard_streams_are_replaced_with_null_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed: tuple[TextIO, TextIO, TextIO]
    with monkeypatch.context() as context:
        for name in (
            "stdin",
            "__stdin__",
            "stdout",
            "__stdout__",
            "stderr",
            "__stderr__",
        ):
            context.setattr(sys, name, None)

        ensure_standard_streams()

        installed = (
            cast(TextIO, sys.stdin),
            cast(TextIO, sys.stdout),
            cast(TextIO, sys.stderr),
        )
        assert sys.__stdin__ is installed[0]
        assert sys.__stdout__ is installed[1]
        assert sys.__stderr__ is installed[2]
        assert installed[0].read(0) == ""
        assert installed[1].write("discarded") == len("discarded")
        assert installed[2].write("discarded") == len("discarded")

    for stream in installed:
        stream.close()


def test_existing_standard_streams_are_preserved() -> None:
    before = (sys.stdin, sys.stdout, sys.stderr, sys.__stdin__, sys.__stdout__, sys.__stderr__)

    ensure_standard_streams()

    after = (sys.stdin, sys.stdout, sys.stderr, sys.__stdin__, sys.__stdout__, sys.__stderr__)
    assert after == before
