"""Concrete composition of approval reads and credential lifecycle mutations."""

from __future__ import annotations

from collections.abc import Sequence

from .lifecycle import SqliteCredentialLifecycleService
from .models import (
    AdminStatus,
    ApprovalActionResult,
    ApprovalDecision,
    ApprovalView,
    CredentialMutationResult,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    CredentialSummary,
    EmergencyUnlockCancelRequest,
    EmergencyUnlockRequest,
    EmergencyUnlockView,
    IncidentSummary,
    PoolSummary,
    ReconciliationSummary,
)
from .persistence import SqliteApprovalAdminService


class StockAdminBackend:
    """Expose one strict admin protocol without merging authentication realms."""

    def __init__(
        self,
        *,
        approvals: SqliteApprovalAdminService,
        credentials: SqliteCredentialLifecycleService,
    ) -> None:
        self._approvals = approvals
        self._credentials = credentials

    async def status(self) -> AdminStatus:
        return await self._approvals.status()

    async def list_approvals(self, *, limit: int) -> Sequence[ApprovalView]:
        return await self._approvals.list_approvals(limit=limit)

    async def get_approval(self, approval_id: str) -> ApprovalView | None:
        return await self._approvals.get_approval(approval_id)

    async def decide_approval(
        self,
        *,
        approval: ApprovalView,
        decision: ApprovalDecision,
        now_ms: int,
    ) -> ApprovalActionResult:
        return await self._approvals.decide_approval(
            approval=approval,
            decision=decision,
            now_ms=now_ms,
        )

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]:
        return await self._approvals.list_pools(limit=limit)

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]:
        return await self._approvals.list_credentials(limit=limit)

    async def provision_credential(
        self,
        request: CredentialProvisionRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult:
        return await self._credentials.provision_credential(request, secret, actor_id)

    async def rotate_credential(
        self,
        credential_id: str,
        request: CredentialRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult:
        return await self._credentials.rotate_credential(
            credential_id,
            request,
            secret,
            actor_id,
        )

    async def change_credential_state(
        self,
        credential_id: str,
        request: CredentialStateChangeRequest,
        actor_id: str,
    ) -> CredentialMutationResult:
        return await self._credentials.change_credential_state(
            credential_id,
            request,
            actor_id,
        )

    async def unlock_emergency(
        self,
        request: EmergencyUnlockRequest,
        secret: bytearray,
        actor_id: str,
    ) -> EmergencyUnlockView:
        return await self._credentials.unlock_emergency(request, secret, actor_id)

    async def cancel_emergency_unlock(
        self,
        unlock_id: str,
        request: EmergencyUnlockCancelRequest,
        actor_id: str,
    ) -> EmergencyUnlockView:
        return await self._credentials.cancel_emergency_unlock(
            unlock_id,
            request,
            actor_id,
        )

    async def list_emergency_unlocks(
        self,
        *,
        limit: int,
    ) -> Sequence[EmergencyUnlockView]:
        return await self._credentials.list_emergency_unlocks(limit=limit)

    async def list_incidents(self, *, limit: int) -> Sequence[IncidentSummary]:
        return await self._approvals.list_incidents(limit=limit)

    async def reconciliation(self) -> Sequence[ReconciliationSummary]:
        return await self._approvals.reconciliation()
