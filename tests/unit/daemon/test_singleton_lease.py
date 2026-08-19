from __future__ import annotations

import os
from pathlib import Path

import pytest

from gatehouse.daemon.lease import (
    DaemonAlreadyRunningError,
    FileInstallationDaemonLeaseFactory,
)


class RecordingLockBackend:
    def __init__(self) -> None:
        self.held = False
        self.acquire_descriptors: list[int] = []
        self.release_descriptors: list[int] = []

    def try_acquire(self, descriptor: int) -> bool:
        os.fstat(descriptor)
        self.acquire_descriptors.append(descriptor)
        if self.held:
            return False
        self.held = True
        return True

    def release(self, descriptor: int) -> None:
        os.fstat(descriptor)
        self.release_descriptors.append(descriptor)
        self.held = False


def test_file_lease_is_exclusive_idempotent_and_reacquirable(tmp_path: Path) -> None:
    backend = RecordingLockBackend()
    factory = FileInstallationDaemonLeaseFactory(backend=backend)
    path = tmp_path / "nested" / "gatehoused.lock"

    first = factory.acquire(path)
    assert first.path == path.resolve()
    assert path.read_bytes() == b"\0"

    with pytest.raises(DaemonAlreadyRunningError):
        factory.acquire(path)

    first.release()
    first.release()
    replacement = factory.acquire(path)
    replacement.release()

    assert len(backend.acquire_descriptors) == 3
    assert len(backend.release_descriptors) == 2


def test_real_operating_system_lock_rejects_a_competing_handle(tmp_path: Path) -> None:
    path = tmp_path / "gatehoused.lock"
    first = FileInstallationDaemonLeaseFactory().acquire(path)
    try:
        with pytest.raises(DaemonAlreadyRunningError):
            FileInstallationDaemonLeaseFactory().acquire(path)
    finally:
        first.release()

    replacement = FileInstallationDaemonLeaseFactory().acquire(path)
    replacement.release()
