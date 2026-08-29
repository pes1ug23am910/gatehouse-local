"""Verify the exact runtime and gate-tool wheelhouses before quality gates execute."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.verify_release_supply_chain import (  # noqa: E402
    SupplyChainError,
    _canonical_json,
    verify_gate_toolchain,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--runtime-wheelhouse", required=True)
    parser.add_argument("--runtime-lock", required=True)
    parser.add_argument("--runtime-manifest", required=True)
    parser.add_argument("--runtime-vulnerability-snapshot", required=True)
    parser.add_argument("--gate-wheelhouse", required=True)
    parser.add_argument("--gate-lock", required=True)
    parser.add_argument("--gate-manifest", required=True)
    parser.add_argument("--gate-vulnerability-snapshot", required=True)
    parser.add_argument("--gate-roots", required=True)
    parser.add_argument("--python-minor", required=True)
    parser.add_argument("--python-full-version", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    try:
        result = verify_gate_toolchain(
            repository_root=Path(cast(str, arguments.repository_root)),
            runtime_wheelhouse=Path(cast(str, arguments.runtime_wheelhouse)),
            runtime_lock=Path(cast(str, arguments.runtime_lock)),
            runtime_manifest=Path(cast(str, arguments.runtime_manifest)),
            runtime_vulnerability_snapshot=Path(
                cast(str, arguments.runtime_vulnerability_snapshot)
            ),
            gate_wheelhouse=Path(cast(str, arguments.gate_wheelhouse)),
            gate_lock=Path(cast(str, arguments.gate_lock)),
            gate_manifest=Path(cast(str, arguments.gate_manifest)),
            gate_vulnerability_snapshot=Path(cast(str, arguments.gate_vulnerability_snapshot)),
            gate_roots=Path(cast(str, arguments.gate_roots)),
            python_minor=cast(str, arguments.python_minor),
            python_full_version=cast(str, arguments.python_full_version),
            output=Path(cast(str, arguments.output)),
        )
    except (OSError, SupplyChainError, ValueError) as exc:
        print(f"Gate toolchain verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(_canonical_json(result).decode("utf-8"), end="")


if __name__ == "__main__":
    main()
