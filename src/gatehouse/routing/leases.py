"""Short logical credential leases acquired before provider transport dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.ids import CredentialId, LeaseId, RequestId
from gatehouse.database.repository import LeaseResult

from .models import RouteCandidate


class CredentialLeaseRepository(Protocol):
    def acquire_lease(
        self,
        *,
        lease_type: str,
        lease_key: str,
        owner_id: str,
        now_ms: int,
        expires_at_ms: int,
        lease_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> LeaseResult: ...

    def release_lease(
        self,
        *,
        lease_id: str,
        owner_id: str,
        now_ms: int,
    ) -> bool: ...


class CredentialLeaseUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CredentialDispatchLease:
    lease_id: LeaseId
    credential_id: CredentialId
    request_id: RequestId
    generation: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        if self.generation <= 0:
            raise ValueError("credential generation must be positive")
        require_utc_ms(self.expires_at_ms)


class CredentialLeaseManager:
    def __init__(
        self,
        repository: CredentialLeaseRepository,
        *,
        id_factory: Callable[[], LeaseId] = LeaseId.new,
    ) -> None:
        self.repository = repository
        self._id_factory = id_factory

    def acquire(
        self,
        *,
        candidate: RouteCandidate,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
    ) -> CredentialDispatchLease:
        require_utc_ms(now_ms)
        require_utc_ms(expires_at_ms)
        if expires_at_ms <= now_ms:
            raise ValueError("credential lease expiration must be in the future")
        proposed_lease_id = self._id_factory()
        result = self.repository.acquire_lease(
            lease_type="provider-credential",
            lease_key=str(candidate.credential.credential_id),
            owner_id=str(request_id),
            now_ms=now_ms,
            expires_at_ms=expires_at_ms,
            lease_id=str(proposed_lease_id),
            metadata={
                "credential_generation": candidate.credential.generation,
                "pool_id": str(candidate.pool_id),
                "quota_scope_id": str(candidate.scope.quota_scope_id),
            },
        )
        if not result.acquired or result.lease_id is None or result.expires_at_ms is None:
            raise CredentialLeaseUnavailableError("credential is leased by another request")
        return CredentialDispatchLease(
            lease_id=LeaseId(result.lease_id),
            credential_id=candidate.credential.credential_id,
            request_id=request_id,
            generation=candidate.credential.generation,
            expires_at_ms=result.expires_at_ms,
        )

    def release(self, lease: CredentialDispatchLease, *, now_ms: int) -> bool:
        require_utc_ms(now_ms)
        return self.repository.release_lease(
            lease_id=str(lease.lease_id),
            owner_id=str(lease.request_id),
            now_ms=now_ms,
        )
