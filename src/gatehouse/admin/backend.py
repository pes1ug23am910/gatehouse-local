"""Concrete composition of approval reads and credential lifecycle mutations."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, cast

from gatehouse.database.runaway import (
    RunawayQuarantinePersistenceError,
    RunawayQuarantineRecord,
    SqliteRunawayQuarantineService,
)

from .lifecycle import SqliteCredentialLifecycleService
from .models import (
    AccountAddRequest,
    AccountLifecycleService,
    AccountMutationResult,
    AccountObservationChangeRequest,
    AccountObservationMutationResult,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    AccountStatus,
    AdminStatus,
    ApprovalActionResult,
    ApprovalDecision,
    ApprovalView,
    CredentialMutationResult,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    CredentialSummary,
    CredentialValidationRequest,
    CredentialValidationResult,
    EmergencyUnlockCancelRequest,
    EmergencyUnlockRequest,
    EmergencyUnlockView,
    IncidentSummary,
    PoolFailoverChangeRequest,
    PoolFailoverMutationResult,
    PoolSummary,
    ReconciliationSummary,
    RunawayBurstAuthorizeRequest,
    RunawayFreshRunRecoveryRequest,
    RunawayFreshRunRecoveryResult,
    RunawayQuarantineActionResult,
    RunawayQuarantineDenyRequest,
    RunawayQuarantineView,
)
from .persistence import SqliteApprovalAdminService
from .pools import SqlitePoolAdminService
from .provider_validation import (
    CredentialValidationUnavailable,
    SqliteCredentialValidationService,
)


class AccountLifecycleUnavailable(RuntimeError):
    """Account administration has not been composed for this daemon."""


class RunawayQuarantineUnavailable(RuntimeError):
    """Durable runaway quarantine administration has not been composed."""


class StockAdminBackend:
    """Expose one strict admin protocol without merging authentication realms."""

    def __init__(
        self,
        *,
        approvals: SqliteApprovalAdminService,
        credentials: SqliteCredentialLifecycleService,
        validation: SqliteCredentialValidationService | None = None,
        accounts: AccountLifecycleService | None = None,
        runaway_quarantines: SqliteRunawayQuarantineService | None = None,
        pools: SqlitePoolAdminService | None = None,
    ) -> None:
        self._approvals = approvals
        self._credentials = credentials
        self._validation = validation
        self._accounts = accounts
        self._runaway_quarantines = runaway_quarantines
        self._pools = pools

    async def change_pool_failover(
        self,
        alias: str,
        request: PoolFailoverChangeRequest,
        actor_id: str,
    ) -> PoolFailoverMutationResult:
        if self._pools is None:
            raise AccountLifecycleUnavailable("pool administration is not configured")
        return await self._pools.change_pool_failover(alias, request, actor_id)

    def _account_service(self) -> AccountLifecycleService:
        if self._accounts is None:
            raise AccountLifecycleUnavailable("account lifecycle is not configured")
        return self._accounts

    def _runaway_service(self) -> SqliteRunawayQuarantineService:
        if self._runaway_quarantines is None:
            raise RunawayQuarantineUnavailable("durable runaway quarantine is not configured")
        return self._runaway_quarantines

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

    async def list_runaway_quarantines(
        self,
        *,
        limit: int,
    ) -> Sequence[RunawayQuarantineView]:
        records = await self._runaway_service().list_quarantines(limit=limit)
        return tuple(self._runaway_view(record) for record in records)

    async def get_runaway_quarantine(
        self,
        quarantine_id: str,
    ) -> RunawayQuarantineView | None:
        record = await self._runaway_service().get_quarantine(quarantine_id)
        return None if record is None else self._runaway_view(record)

    async def authorize_runaway_burst(
        self,
        quarantine_id: str,
        request: RunawayBurstAuthorizeRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult:
        result = await self._runaway_service().authorize(
            quarantine_id=quarantine_id,
            expected_generation=request.expected_generation,
            action_token=request.action_token,
            actor_id=actor_id,
            reason=request.reason,
            duration_ms=request.duration_ms,
            maximum_requests=request.maximum_requests,
            maximum_credits=request.maximum_credits,
            maximum_concurrency=request.maximum_concurrency,
            operations=request.operations,
            now_ms=now_ms,
        )
        return RunawayQuarantineActionResult(
            quarantine_id=result.quarantine_id,
            state="AUTHORIZED",
            generation=result.generation,
            acted_at_ms=result.acted_at_ms,
            audit_event_id=result.audit_event_id,
        )

    async def deny_runaway_quarantine(
        self,
        quarantine_id: str,
        request: RunawayQuarantineDenyRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult:
        result = await self._runaway_service().deny(
            quarantine_id=quarantine_id,
            expected_generation=request.expected_generation,
            action_token=request.action_token,
            actor_id=actor_id,
            reason=request.reason,
            now_ms=now_ms,
        )
        return RunawayQuarantineActionResult(
            quarantine_id=result.quarantine_id,
            state="DENIED",
            generation=result.generation,
            acted_at_ms=result.acted_at_ms,
            audit_event_id=result.audit_event_id,
        )

    async def recover_runaway_for_fresh_run(
        self,
        quarantine_id: str,
        request: RunawayFreshRunRecoveryRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayFreshRunRecoveryResult:
        result = await self._runaway_service().recover_for_fresh_run(
            quarantine_id=quarantine_id,
            expected_generation=request.expected_generation,
            action_token=request.action_token,
            actor_id=actor_id,
            reason=request.reason,
            confirmation=request.confirmation,
            now_ms=now_ms,
        )
        if result.quarantine_state.value == "AUTHORIZED":
            raise RunawayQuarantinePersistenceError(
                "fresh-run recovery retained an active authorization"
            )
        return RunawayFreshRunRecoveryResult(
            recovery_id=result.recovery_id,
            quarantine_id=result.quarantine_id,
            quarantine_state=cast(
                Literal["OPEN", "DENIED", "EXPIRED", "EXHAUSTED"],
                result.quarantine_state.value,
            ),
            generation=result.generation,
            client_id=result.client_id,
            session_id=result.session_id,
            root_run_id=result.root_run_id,
            recovered_at_ms=result.recovered_at_ms,
            audit_event_id=result.audit_event_id,
        )

    @staticmethod
    def _runaway_view(record: RunawayQuarantineRecord) -> RunawayQuarantineView:
        return RunawayQuarantineView(
            quarantine_id=record.quarantine_id,
            session_id=record.session_id,
            client_id=record.client_id,
            workspace_id=record.workspace_id,
            root_run_id=record.root_run_id,
            service=record.service_id,
            state=record.state.value,
            trigger=record.trigger.value,
            trigger_operation=record.trigger_operation,
            generation=record.generation,
            opened_at_ms=record.opened_at_ms,
            updated_at_ms=record.updated_at_ms,
            decided_at_ms=record.decided_at_ms,
            expires_at_ms=record.expires_at_ms,
            maximum_requests=record.maximum_requests,
            remaining_requests=record.remaining_requests,
            maximum_credits=record.maximum_credits,
            remaining_credits=record.remaining_credits,
            maximum_concurrency=record.maximum_concurrency,
            active_concurrency=record.active_concurrency,
            operations=record.operations,
            fresh_run_recovery_id=record.fresh_run_recovery_id,
            fresh_run_recovered_at_ms=record.fresh_run_recovered_at_ms,
            action_token=record.action_token,
        )

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]:
        return await self._approvals.list_pools(limit=limit)

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]:
        return await self._approvals.list_credentials(limit=limit)

    async def add_account(
        self,
        request: AccountAddRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        return await self._account_service().add_account(request, secret, actor_id)

    async def list_accounts(self, *, limit: int) -> Sequence[AccountStatus]:
        return await self._account_service().list_accounts(limit=limit)

    async def get_account_status(self, alias: str) -> AccountStatus | None:
        return await self._account_service().get_account_status(alias)

    async def rotate_account(
        self,
        alias: str,
        request: AccountRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        return await self._account_service().rotate_account(alias, request, secret, actor_id)

    async def change_account_state(
        self,
        alias: str,
        request: AccountStateChangeRequest,
        actor_id: str,
    ) -> AccountMutationResult:
        return await self._account_service().change_account_state(alias, request, actor_id)

    async def refresh_account(
        self,
        alias: str,
        request: AccountRefreshRequest,
        actor_id: str,
    ) -> AccountStatus:
        return await self._account_service().refresh_account(alias, request, actor_id)

    async def change_account_observation(
        self,
        alias: str,
        request: AccountObservationChangeRequest,
        actor_id: str,
    ) -> AccountObservationMutationResult:
        return await self._account_service().change_account_observation(alias, request, actor_id)

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

    async def validate_credential(
        self,
        credential_id: str,
        request: CredentialValidationRequest,
        actor_id: str,
    ) -> CredentialValidationResult:
        if self._validation is None:
            raise CredentialValidationUnavailable("credential validation is not configured")
        return await self._validation.validate_credential(
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
