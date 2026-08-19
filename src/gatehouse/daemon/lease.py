"""Crash-safe installation-scoped ownership for the stock daemon."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Protocol, cast


class DaemonAlreadyRunningError(RuntimeError):
    """Raised when another process already owns an installation's daemon lease."""


class InstallationDaemonLease(Protocol):
    """A held installation lease that is released explicitly or at process exit."""

    @property
    def path(self) -> Path: ...

    def release(self) -> None: ...


class InstallationDaemonLeaseFactory(Protocol):
    """Acquire an exclusive, non-blocking lease for an installation path."""

    def acquire(self, path: Path) -> InstallationDaemonLease: ...


class _FileLockBackend(Protocol):
    def try_acquire(self, descriptor: int) -> bool: ...

    def release(self, descriptor: int) -> None: ...


class _PosixFileLockModule(Protocol):
    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, descriptor: int, operation: int) -> None: ...


def _is_lock_contention(error: OSError) -> bool:
    return error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(
        error, "winerror", None
    ) in {33, 36}


class _OperatingSystemFileLock:
    """One-byte Windows lock with a POSIX flock equivalent for development hosts."""

    def try_acquire(self, descriptor: int) -> bool:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                posix_lock = cast(_PosixFileLockModule, fcntl)
                posix_lock.flock(
                    descriptor,
                    posix_lock.LOCK_EX | posix_lock.LOCK_NB,
                )
        except OSError as error:
            if _is_lock_contention(error):
                return False
            raise
        return True

    def release(self, descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            posix_lock = cast(_PosixFileLockModule, fcntl)
            posix_lock.flock(descriptor, posix_lock.LOCK_UN)


class _HeldFileInstallationDaemonLease:
    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        backend: _FileLockBackend,
    ) -> None:
        self._path = path
        self._descriptor: int | None = descriptor
        self._backend = backend

    @property
    def path(self) -> Path:
        return self._path

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            self._backend.release(descriptor)
        finally:
            # Closing the descriptor is a second, OS-enforced release path if
            # explicit unlocking itself reports an error.
            os.close(descriptor)


class FileInstallationDaemonLeaseFactory:
    """Acquire a process-crash-safe lease without holding a database transaction."""

    def __init__(self, *, backend: _FileLockBackend | None = None) -> None:
        self._backend = backend or _OperatingSystemFileLock()

    def acquire(self, path: Path) -> InstallationDaemonLease:
        resolved = path.resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        descriptor = os.open(resolved, flags, 0o600)
        try:
            if os.fstat(descriptor).st_size == 0:
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, b"\0")
            if not self._backend.try_acquire(descriptor):
                raise DaemonAlreadyRunningError(
                    f"another Gatehouse daemon owns installation lease {resolved}"
                )
        except BaseException:
            os.close(descriptor)
            raise
        return _HeldFileInstallationDaemonLease(
            path=resolved,
            descriptor=descriptor,
            backend=self._backend,
        )


DEFAULT_INSTALLATION_DAEMON_LEASE_FACTORY = FileInstallationDaemonLeaseFactory()
