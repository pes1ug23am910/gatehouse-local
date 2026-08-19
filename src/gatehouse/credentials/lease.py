"""Time-bounded secret leases backed by zeroable mutable storage."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from .base import SecretLeaseExpiredError


def zero_bytearray(buffer: bytearray) -> None:
    """Best-effort overwrite of a mutable Python buffer in place."""

    if buffer:
        buffer[:] = b"\x00" * len(buffer)


class ZeroingSecretLease:
    """Expose secret bytes only through an async context manager.

    Python and HTTP libraries may create copies outside this object's control.
    This lease nevertheless bounds and overwrites the mutable copy that the
    KeyStore owns.  A daemon timer zeroes it even if a caller forgets to exit.
    """

    def __init__(
        self,
        *,
        credential_id: str,
        generation: int,
        purpose: str,
        secret_buffer: bytearray,
        ttl_seconds: float,
        monotonic: Callable[[], float] = time.monotonic,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        if not credential_id or not purpose:
            raise ValueError("credential_id and purpose are required")
        if generation <= 0:
            raise ValueError("generation must be positive")
        if ttl_seconds <= 0:
            zero_bytearray(secret_buffer)
            raise ValueError("ttl_seconds must be positive")

        self.credential_id = credential_id
        self.generation = generation
        self.purpose = purpose
        self._buffer = secret_buffer
        self._monotonic = monotonic
        self._expires_at = monotonic() + ttl_seconds
        self._on_close = on_close
        self._lock = threading.Lock()
        self._closed = False
        self._expired = False
        self._timer = threading.Timer(ttl_seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def expired(self) -> bool:
        with self._lock:
            return self._expired or self._monotonic() >= self._expires_at

    def _expire(self) -> None:
        self._close(expired=True, cancel_timer=False)

    def _close(self, *, expired: bool, cancel_timer: bool) -> None:
        callback: Callable[[], None] | None = None
        with self._lock:
            if self._closed:
                if expired:
                    self._expired = True
                return
            self._closed = True
            self._expired = expired or self._monotonic() >= self._expires_at
            zero_bytearray(self._buffer)
            callback = self._on_close
            self._on_close = None
        if cancel_timer:
            self._timer.cancel()
        if callback is not None:
            callback()

    async def __aenter__(self) -> memoryview:
        with self._lock:
            if self._closed or self._monotonic() >= self._expires_at:
                should_expire = not self._closed
            else:
                return memoryview(self._buffer).toreadonly()
        if should_expire:
            self._close(expired=True, cancel_timer=True)
        raise SecretLeaseExpiredError("secret lease is closed or expired")

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._close(expired=False, cancel_timer=True)
