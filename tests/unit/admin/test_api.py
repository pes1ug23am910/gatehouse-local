from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from typing import Literal
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.types import ASGIApp, Message, Scope

from gatehouse.admin import (
    AccountAddRequest,
    AccountMutationResult,
    AccountObservationChangeRequest,
    AccountObservationMutationResult,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    AccountStatus,
    AdminAuthManager,
    AdminStatus,
    ApprovalActionResult,
    ApprovalDecision,
    ApprovalView,
    CredentialMutationResult,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    CredentialSummary,
    CredentialValidationBusy,
    CredentialValidationError,
    CredentialValidationPersistenceError,
    CredentialValidationProviderFailure,
    CredentialValidationRequest,
    CredentialValidationResult,
    CredentialValidationUnavailable,
    EmergencyUnlockCancelRequest,
    EmergencyUnlockRequest,
    EmergencyUnlockView,
    IncidentSummary,
    PoolSummary,
    ReconciliationSummary,
    RunawayBurstAuthorizeRequest,
    RunawayQuarantineActionResult,
    RunawayQuarantineDenyRequest,
    RunawayQuarantineView,
)
from gatehouse.api.admin import (
    ADMIN_COOKIE_NAME,
    COMMAND_HEADER_NAME,
    CSRF_HEADER_NAME,
    LOCAL_ACCOUNT_OPERATOR_ACTOR_ID,
    MAXIMUM_COMMAND_BYTES,
    MAXIMUM_SECRET_BYTES,
    create_admin_app,
)
from gatehouse.providers import ProviderErrorClass

_SECRET_CANARY = "FAKE-ADMIN-INGRESS-CANARY-1234567890"
_SERIALIZED_RESPONSE_ALIAS = "synthetic-response-boundary-seed"
_SERIALIZED_RESPONSE_SECRET = f'{_SERIALIZED_RESPONSE_ALIAS}","principal_id":"'.encode()


class _InstrumentedReceive:
    def __init__(self, chunks: Sequence[bytes]) -> None:
        selected = tuple(chunks) or (b"",)
        self._messages: list[Message] = [
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(selected) - 1,
            }
            for index, chunk in enumerate(selected)
        ]
        self.read_count = 0

    async def __call__(self) -> Message:
        self.read_count += 1
        if self._messages:
            return self._messages.pop(0)
        return {"type": "http.disconnect"}


async def _asgi_post(
    app: ASGIApp,
    path: str,
    *,
    headers: dict[str, str],
    chunks: Sequence[bytes],
) -> tuple[int, dict[str, str], bytes, int]:
    receive = _InstrumentedReceive(chunks)
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (name.casefold().encode("latin-1"), value.encode("latin-1"))
            for name, value in {"Host": "testserver", **headers}.items()
        ],
        "client": ("127.0.0.1", 50_000),
        "server": ("testserver", 80),
        "state": {},
        "extensions": {},
    }
    await app(scope, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    response_headers = {
        name.decode("latin-1").casefold(): value.decode("latin-1")
        for name, value in start.get("headers", ())
    }
    response_body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    return int(start["status"]), response_headers, response_body, receive.read_count


async def _asgi_post_following_normalization(
    app: ASGIApp,
    path: str,
    *,
    headers: dict[str, str],
    chunks: Sequence[bytes],
) -> tuple[int, bytes, int]:
    status, response_headers, response_body, reads = await _asgi_post(
        app,
        path,
        headers=headers,
        chunks=chunks,
    )
    if status not in {307, 308}:
        return status, response_body, reads
    normalized_path = urlsplit(response_headers["location"]).path
    status, _, response_body, normalized_reads = await _asgi_post(
        app,
        normalized_path,
        headers=headers,
        chunks=chunks,
    )
    return status, response_body, reads + normalized_reads


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000

    def __call__(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class DeterministicRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, count: int) -> bytes:
        self.counter += 1
        return bytes([self.counter % 251 + 1]) * count


def pending_approval() -> ApprovalView:
    return ApprovalView(
        approval_id="approval-one",
        session_id="ses_one",
        client_id="editor-one",
        workspace_id="workspace-one",
        service="firecrawl",
        operation="crawl.start",
        request_fingerprint="hmac:v1:c1:fingerprint",
        target_summary="careers.example.test/jobs",
        pool="interactive-default",
        maximum_estimated_cost=25,
        expires_at_ms=20_000,
        state="PENDING",
        action_token="t" * 32,
    )


def open_runaway_quarantine() -> RunawayQuarantineView:
    return RunawayQuarantineView(
        quarantine_id="rqu_one",
        session_id="ses_one",
        client_id="editor-one",
        workspace_id="workspace-one",
        root_run_id="run_one",
        service="firecrawl",
        state="OPEN",
        trigger="AGGREGATE_BURST",
        trigger_operation="firecrawl.search",
        generation=1,
        opened_at_ms=900,
        updated_at_ms=900,
        active_concurrency=0,
        operations=(),
        action_token="q" * 32,
    )


class FakeAdminBackend:
    def __init__(self) -> None:
        self.approval = pending_approval()
        self.runaway_quarantine = open_runaway_quarantine()
        self.decisions: list[ApprovalDecision] = []
        self.runaway_actions: list[str] = []
        self.account_calls: list[tuple[str, str, str]] = []
        self.credential_calls: list[tuple[str, str, str]] = []
        self.emergency_calls: list[tuple[str, str, str]] = []
        self.secret_buffers: list[bytearray] = []
        self.validation_failure: CredentialValidationError | None = None
        self.validation_result_update: dict[str, object] = {}
        self.fail_secret_mutation = False
        self.reflect_secret_mutation = False
        self.reflect_serialized_secret_mutation = False
        self.emergency = self._emergency_view(action="unlock", state="ACTIVE")

    @staticmethod
    def _account_result(
        *,
        alias: str,
        action: Literal["add", "rotate", "disable", "recover", "remove"],
        state: str,
        generation: int,
    ) -> AccountMutationResult:
        return AccountMutationResult(
            alias=alias,
            action=action,
            state=state,
            pool_alias="interactive-default",
            priority=10,
            generation=generation,
            acted_at_ms=1_500,
            audit_event_id="evt_account_01K32J0B80E4G7P6H9Q2R5T8VW",
        )

    @staticmethod
    def _account_status(alias: str = "primary") -> AccountStatus:
        return AccountStatus(
            alias=alias,
            state="HEALTHY",
            remaining_decimal="750.25",
            plan_decimal="1000",
            unit="credits",
            observed_at_ms=1_400,
            staleness_ms=100,
            stale=False,
            source="firecrawl-credit-usage",
        )

    @staticmethod
    def _credential_result(
        *,
        mutation_id: str,
        action: Literal["provision", "rotate", "disable", "quarantine", "retire"],
        state: str,
        generation: int,
    ) -> CredentialMutationResult:
        return CredentialMutationResult(
            mutation_id=mutation_id,
            credential_id="cred_01K32J0B80E4G7P6H9Q2R5T8VW",
            action=action,
            state=state,
            generation=generation,
            alias="primary",
            principal_id="prn_01K32J0B80E4G7P6H9Q2R5T8VW",
            principal_alias="primary-principal",
            quota_scope_id="quota_01K32J0B80E4G7P6H9Q2R5T8VW",
            quota_scope_alias="primary-quota",
            pool_id="pool_01K32J0B80E4G7P6H9Q2R5T8VW",
            pool_alias="interactive-default",
            expires_at_ms=50_000,
            acted_at_ms=1_500,
            audit_event_id="evt_01K32J0B80E4G7P6H9Q2R5T8VW",
        )

    @staticmethod
    def _emergency_view(
        *,
        action: Literal["unlock", "cancel"],
        state: str,
    ) -> EmergencyUnlockView:
        return EmergencyUnlockView(
            mutation_id="mut_emergency",
            unlock_id="unlock_01K32J0B80E4G7P6H9Q2R5T8VW",
            credential_id="cred_emergency_01K32J0B80E4G7P6H9Q2R5T8VW",
            action=action,
            state=state,
            generation=1,
            service="firecrawl",
            alias="manual-emergency",
            principal_id="prn_emergency_01K32J0B80E4G7P6H9Q2R5T8VW",
            principal_alias="emergency-principal",
            quota_scope_id="quota_emergency_01K32J0B80E4G7P6H9Q2R5T8VW",
            quota_scope_alias="emergency-quota",
            pool_id="pool_emergency_01K32J0B80E4G7P6H9Q2R5T8VW",
            pool_alias="emergency-locked",
            session_id="ses_01K32J0B80E4G7P6H9Q2R5T8VW",
            root_run_id="run_01K32J0B80E4G7P6H9Q2R5T8VW",
            expires_at_ms=61_000,
            remaining_requests=3,
            remaining_credits=5,
            remaining_concurrency=1 if state == "ACTIVE" else 0,
            acted_at_ms=1_000,
            audit_event_id="evt_emergency_01K32J0B80E4G7P6H9Q2R5T8VW",
        )

    @staticmethod
    def _validation_result() -> CredentialValidationResult:
        return CredentialValidationResult(
            credential_id="cred_one",
            generation=3,
            service="firecrawl",
            principal_id="prn_one",
            quota_scope_id="quota_one",
            state="authenticated",
            snapshot_id="snapshot_one",
            unit="credits",
            remaining_units=750,
            plan_total_units=1_000,
            observed_remaining_units_decimal="750",
            observed_plan_total_units_decimal="1000",
            captured_at_ms=1_500,
            audit_event_id="evt_validation_one",
        )

    async def status(self) -> AdminStatus:
        return AdminStatus(
            service_state="READY",
            uptime_seconds=10,
            active_sessions=2,
            in_flight_requests=1,
            queued_requests=3,
            pending_approvals=1,
            high_severity_incidents=0,
        )

    async def list_approvals(self, *, limit: int) -> Sequence[ApprovalView]:
        return (self.approval,)[:limit]

    async def get_approval(self, approval_id: str) -> ApprovalView | None:
        return self.approval if approval_id == self.approval.approval_id else None

    async def decide_approval(
        self,
        *,
        approval: ApprovalView,
        decision: ApprovalDecision,
        now_ms: int,
    ) -> ApprovalActionResult:
        self.decisions.append(decision)
        state = "APPROVED" if decision is ApprovalDecision.APPROVE else "DENIED"
        self.approval = approval.model_copy(update={"state": state})
        return ApprovalActionResult(
            approval_id=approval.approval_id,
            state=state,
            acted_at_ms=now_ms,
        )

    async def list_runaway_quarantines(
        self,
        *,
        limit: int,
    ) -> Sequence[RunawayQuarantineView]:
        return (self.runaway_quarantine,)[:limit]

    async def get_runaway_quarantine(
        self,
        quarantine_id: str,
    ) -> RunawayQuarantineView | None:
        return (
            self.runaway_quarantine
            if quarantine_id == self.runaway_quarantine.quarantine_id
            else None
        )

    async def authorize_runaway_burst(
        self,
        quarantine_id: str,
        request: RunawayBurstAuthorizeRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult:
        del actor_id
        self.runaway_actions.append("authorize")
        self.runaway_quarantine = self.runaway_quarantine.model_copy(
            update={
                "state": "AUTHORIZED",
                "generation": request.expected_generation + 1,
                "updated_at_ms": now_ms,
                "decided_at_ms": now_ms,
                "expires_at_ms": now_ms + request.duration_ms,
                "maximum_requests": request.maximum_requests,
                "remaining_requests": request.maximum_requests,
                "maximum_credits": request.maximum_credits,
                "remaining_credits": request.maximum_credits,
                "maximum_concurrency": request.maximum_concurrency,
                "operations": request.operations,
            }
        )
        return RunawayQuarantineActionResult(
            quarantine_id=quarantine_id,
            state="AUTHORIZED",
            generation=request.expected_generation + 1,
            acted_at_ms=now_ms,
            audit_event_id="evt_runaway_authorized",
        )

    async def deny_runaway_quarantine(
        self,
        quarantine_id: str,
        request: RunawayQuarantineDenyRequest,
        actor_id: str,
        now_ms: int,
    ) -> RunawayQuarantineActionResult:
        del actor_id
        self.runaway_actions.append("deny")
        self.runaway_quarantine = self.runaway_quarantine.model_copy(
            update={
                "state": "DENIED",
                "generation": request.expected_generation + 1,
                "updated_at_ms": now_ms,
                "decided_at_ms": now_ms,
            }
        )
        return RunawayQuarantineActionResult(
            quarantine_id=quarantine_id,
            state="DENIED",
            generation=request.expected_generation + 1,
            acted_at_ms=now_ms,
            audit_event_id="evt_runaway_denied",
        )

    async def list_pools(self, *, limit: int) -> Sequence[PoolSummary]:
        return (
            PoolSummary(
                pool_id="interactive-default",
                service="firecrawl",
                state="READY",
                eligible_credentials=1,
                in_flight=0,
            ),
        )[:limit]

    async def list_credentials(self, *, limit: int) -> Sequence[CredentialSummary]:
        return (
            CredentialSummary(
                credential_id="credential-one",
                service="firecrawl",
                alias="primary-account",
                principal_id="principal-one",
                principal_alias="Primary principal",
                quota_scope_id="quota-one",
                quota_scope_alias="Primary quota",
                state="HEALTHY",
                generation=3,
                expires_at_ms=50_000,
                exclusive_usage=True,
                pool_ids=("pool-one",),
                pool_aliases=("interactive-default",),
                active_lease_count=1,
                created_at_ms=100,
                last_used_at_ms=900,
                last_local_action="rotate",
            ),
        )[:limit]

    async def add_account(
        self,
        request: AccountAddRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        self.secret_buffers.append(secret)
        self.account_calls.append(("add", request.alias, actor_id))
        if self.fail_secret_mutation:
            raise RuntimeError(f"unsafe backend exception {_SECRET_CANARY}")
        result = self._account_result(
            alias=request.alias,
            action="add",
            state="UNKNOWN",
            generation=1,
        ).model_copy(update={"pool_alias": request.pool_alias, "priority": request.priority})
        if self.reflect_secret_mutation:
            reflected = secret.decode("utf-8")
            secret[:] = b"\x00" * len(secret)
            return result.model_copy(update={"audit_event_id": reflected})
        return result

    async def list_accounts(self, *, limit: int) -> Sequence[AccountStatus]:
        self.account_calls.append(("list", str(limit), "read"))
        return (self._account_status(),)[:limit]

    async def get_account_status(self, alias: str) -> AccountStatus | None:
        self.account_calls.append(("status", alias, "read"))
        return self._account_status(alias) if alias == "primary" else None

    async def rotate_account(
        self,
        alias: str,
        request: AccountRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        self.secret_buffers.append(secret)
        self.account_calls.append(("rotate", alias, actor_id))
        if self.fail_secret_mutation:
            raise RuntimeError(f"unsafe backend exception {_SECRET_CANARY}")
        result = self._account_result(
            alias=alias,
            action="rotate",
            state="HEALTHY",
            generation=2,
        )
        if self.reflect_secret_mutation:
            reflected = secret.decode("utf-8")
            secret[:] = b"\x00" * len(secret)
            return result.model_copy(update={"audit_event_id": reflected})
        return result

    async def change_account_state(
        self,
        alias: str,
        request: AccountStateChangeRequest,
        actor_id: str,
    ) -> AccountMutationResult:
        self.account_calls.append((request.action, alias, actor_id))
        return self._account_result(
            alias=alias,
            action=request.action,
            state={
                "disable": "DISABLED",
                "recover": "UNKNOWN",
                "remove": "REMOVED",
            }[request.action],
            generation=2,
        )

    async def refresh_account(
        self,
        alias: str,
        request: AccountRefreshRequest,
        actor_id: str,
    ) -> AccountStatus:
        self.account_calls.append(("refresh", alias, actor_id))
        assert request.mutation_id
        return self._account_status(alias)

    async def change_account_observation(
        self,
        alias: str,
        request: AccountObservationChangeRequest,
        actor_id: str,
    ) -> AccountObservationMutationResult:
        self.account_calls.append((f"observe-{request.action}", alias, actor_id))
        return AccountObservationMutationResult(
            alias=alias,
            action=request.action,
            enabled=request.action == "enable",
            acted_at_ms=1_500,
            audit_event_id="evt_observation_01K32J0B80E4G7P6H9Q2R5T8VW",
        )

    async def list_incidents(self, *, limit: int) -> Sequence[IncidentSummary]:
        return (
            IncidentSummary(
                incident_id="incident-one",
                severity="high",
                category="reconciliation",
                summary="Usage requires review",
                state="OPEN",
                created_at_ms=500,
            ),
        )[:limit]

    async def reconciliation(self) -> Sequence[ReconciliationSummary]:
        return (
            ReconciliationSummary(
                service="firecrawl",
                state="CURRENT",
                last_completed_at_ms=900,
                unresolved_reservations=0,
                ledger_mismatch_count=0,
            ),
        )

    async def provision_credential(
        self,
        request: CredentialProvisionRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult:
        self.secret_buffers.append(secret)
        self.credential_calls.append(("provision", request.mutation_id, actor_id))
        if self.fail_secret_mutation:
            raise RuntimeError(f"unsafe backend exception {_SECRET_CANARY}")
        result = self._credential_result(
            mutation_id=request.mutation_id,
            action="provision",
            state="HEALTHY",
            generation=1,
        )
        if self.reflect_secret_mutation:
            reflected = secret.decode("utf-8")
            secret[:] = b"\x00" * len(secret)
            return result.model_copy(update={"audit_event_id": reflected})
        if self.reflect_serialized_secret_mutation:
            return result.model_copy(update={"alias": _SERIALIZED_RESPONSE_ALIAS})
        return result

    async def rotate_credential(
        self,
        credential_id: str,
        request: CredentialRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult:
        self.secret_buffers.append(secret)
        self.credential_calls.append(("rotate", credential_id, actor_id))
        if self.fail_secret_mutation:
            raise RuntimeError(f"unsafe backend exception {_SECRET_CANARY}")
        result = self._credential_result(
            mutation_id=request.mutation_id,
            action="rotate",
            state="HEALTHY",
            generation=2,
        )
        if self.reflect_secret_mutation:
            reflected = secret.decode("utf-8")
            secret[:] = b"\x00" * len(secret)
            return result.model_copy(update={"audit_event_id": reflected})
        if self.reflect_serialized_secret_mutation:
            return result.model_copy(update={"alias": _SERIALIZED_RESPONSE_ALIAS})
        return result

    async def change_credential_state(
        self,
        credential_id: str,
        request: CredentialStateChangeRequest,
        actor_id: str,
    ) -> CredentialMutationResult:
        self.credential_calls.append((request.action, credential_id, actor_id))
        return self._credential_result(
            mutation_id=request.mutation_id,
            action=request.action,
            state={
                "disable": "DISABLED",
                "quarantine": "QUARANTINED",
                "retire": "RETIRED",
            }[request.action],
            generation=2,
        )

    async def validate_credential(
        self,
        credential_id: str,
        request: CredentialValidationRequest,
        actor_id: str,
    ) -> CredentialValidationResult:
        self.credential_calls.append(("validate", credential_id, actor_id))
        if self.validation_failure is not None:
            raise self.validation_failure
        return self._validation_result().model_copy(
            update={
                "credential_id": credential_id,
                "generation": request.expected_generation,
                **self.validation_result_update,
            }
        )

    async def unlock_emergency(
        self,
        request: EmergencyUnlockRequest,
        secret: bytearray,
        actor_id: str,
    ) -> EmergencyUnlockView:
        self.secret_buffers.append(secret)
        self.emergency_calls.append(("unlock", request.mutation_id, actor_id))
        if self.fail_secret_mutation:
            raise RuntimeError(f"unsafe backend exception {_SECRET_CANARY}")
        self.emergency = self._emergency_view(action="unlock", state="ACTIVE")
        if self.reflect_secret_mutation:
            reflected = secret.decode("utf-8")
            secret[:] = b"\x00" * len(secret)
            self.emergency = self.emergency.model_copy(update={"audit_event_id": reflected})
        if self.reflect_serialized_secret_mutation:
            self.emergency = self.emergency.model_copy(update={"alias": _SERIALIZED_RESPONSE_ALIAS})
        return self.emergency

    async def cancel_emergency_unlock(
        self,
        unlock_id: str,
        request: EmergencyUnlockCancelRequest,
        actor_id: str,
    ) -> EmergencyUnlockView:
        self.emergency_calls.append(("cancel", unlock_id, actor_id))
        self.emergency = self._emergency_view(action="cancel", state="CANCELLED")
        return self.emergency

    async def list_emergency_unlocks(self, *, limit: int) -> Sequence[EmergencyUnlockView]:
        return (self.emergency,)[:limit]


def make_client(
    *,
    raise_server_exceptions: bool = True,
    maximum_body_bytes: int = 32 * 1_024,
) -> tuple[TestClient, AdminAuthManager, FakeAdminBackend, FakeClock]:
    clock = FakeClock()
    auth = AdminAuthManager(
        verifier_key=b"k" * 32,
        now_ms=clock,
        random_bytes=DeterministicRandom(),
        login_code_ttl_ms=100,
        idle_ttl_ms=200,
        absolute_ttl_ms=1_000,
    )
    backend = FakeAdminBackend()
    app = create_admin_app(
        auth=auth,
        backend=backend,
        now_ms=clock,
        allowed_hosts=("testserver",),
        maximum_body_bytes=maximum_body_bytes,
    )
    return (
        TestClient(app, raise_server_exceptions=raise_server_exceptions),
        auth,
        backend,
        clock,
    )


def login(client: TestClient, auth: AdminAuthManager) -> str:
    code = asyncio.run(auth.mint_login_code())
    response = client.post("/v1/admin/login/exchange", json={"code": code.code})
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    admin_cookie = next(value for value in cookies if value.startswith("gatehouse_admin="))
    assert "HttpOnly" in admin_cookie
    assert "SameSite=strict" in admin_cookie
    return str(response.json()["csrf_token"])


def approval_body() -> dict[str, object]:
    approval = pending_approval()
    return {
        "action_token": approval.action_token,
        "request_fingerprint": approval.request_fingerprint,
        "maximum_estimated_cost": approval.maximum_estimated_cost,
        "maximum_uses": 1,
    }


def runaway_authorization_body() -> dict[str, object]:
    quarantine = open_runaway_quarantine()
    return {
        "action_token": quarantine.action_token,
        "expected_generation": quarantine.generation,
        "reason": "Explicit bounded personal-use authorization",
        "duration_ms": 300_000,
        "maximum_requests": 10,
        "maximum_credits": 25,
        "maximum_concurrency": 2,
        "operations": ["firecrawl.search"],
    }


def command_header(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def mutation_headers(
    csrf: str,
    command: dict[str, object],
    *,
    content_type: str | None = None,
) -> dict[str, str]:
    headers = {
        CSRF_HEADER_NAME: csrf,
        "Origin": "http://testserver",
        COMMAND_HEADER_NAME: command_header(command),
    }
    if content_type is not None:
        headers["Content-Type"] = content_type
    return headers


def provision_command() -> dict[str, object]:
    return {
        "mutation_id": "mut_provision",
        "principal_id": "prn_01K32J0B80E4G7P6H9Q2R5T8VW",
        "quota_scope_id": "quota_01K32J0B80E4G7P6H9Q2R5T8VW",
        "pool_id": "pool_01K32J0B80E4G7P6H9Q2R5T8VW",
        "alias": "primary",
        "expires_at_ms": 50_000,
        "exclusive_usage": True,
    }


def account_add_command() -> dict[str, object]:
    return {
        "mutation_id": "mut_account_add",
        "provider": "firecrawl",
        "provider_team_id": "team-primary",
        "alias": "primary",
        "pool_alias": "interactive-default",
        "priority": 10,
        "expires_at_ms": 50_000,
    }


def emergency_command() -> dict[str, object]:
    return {
        "mutation_id": "mut_emergency",
        "service": "firecrawl",
        "pool_id": "pool_emergency_01K32J0B80E4G7P6H9Q2R5T8VW",
        "session_id": "ses_01K32J0B80E4G7P6H9Q2R5T8VW",
        "root_run_id": "run_01K32J0B80E4G7P6H9Q2R5T8VW",
        "alias": "manual-emergency",
        "reason": "bounded incident recovery",
        "duration_ms": 60_000,
        "maximum_requests": 3,
        "maximum_credits": 5,
        "maximum_concurrency": 1,
    }


def lifecycle_mutation_commands() -> tuple[tuple[str, dict[str, object]], ...]:
    return (
        ("/v1/admin/credentials", provision_command()),
        (
            "/v1/admin/credentials/cred_one/rotate",
            {"mutation_id": "mut_rotate", "expires_at_ms": None},
        ),
        (
            "/v1/admin/credentials/cred_one/validate",
            {"expected_generation": 3},
        ),
        (
            "/v1/admin/credentials/cred_one/disable",
            {"mutation_id": "mut_disable", "action": "disable", "reason": "operator"},
        ),
        (
            "/v1/admin/credentials/cred_one/quarantine",
            {
                "mutation_id": "mut_quarantine",
                "action": "quarantine",
                "reason": "operator",
            },
        ),
        (
            "/v1/admin/credentials/cred_one/retire",
            {"mutation_id": "mut_retire", "action": "retire", "reason": "operator"},
        ),
        ("/v1/admin/emergency-unlocks", emergency_command()),
        (
            "/v1/admin/emergency-unlocks/unlock_one/cancel",
            {"mutation_id": "mut_cancel", "reason": "operator"},
        ),
    )


def test_one_use_login_cookie_and_admin_realm_separation() -> None:
    client, auth, _, _ = make_client()
    code = asyncio.run(auth.mint_login_code())
    first = client.post("/v1/admin/login/exchange", json={"code": code.code})
    assert first.status_code == 200
    replay = client.post("/v1/admin/login/exchange", json={"code": code.code})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "invalid_session"

    status = client.get("/v1/admin/status")
    assert status.status_code == 200
    agent_token = client.get(
        "/v1/admin/status",
        headers={"Authorization": "Bearer " + "agent-access-token"},
    )
    assert agent_token.status_code == 401


def test_csrf_and_request_binding_protect_approval_mutations() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    missing_csrf = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={"Origin": "http://testserver"},
        json=approval_body(),
    )
    assert missing_csrf.status_code == 401
    assert backend.decisions == []

    mismatched = approval_body()
    mismatched["maximum_estimated_cost"] = 24
    rejected = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://testserver"},
        json=mismatched,
    )
    assert rejected.status_code == 403
    assert backend.decisions == []

    approved = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://testserver"},
        json=approval_body(),
    )
    assert approved.status_code == 200
    assert approved.json()["state"] == "APPROVED"
    assert backend.decisions == [ApprovalDecision.APPROVE]

    replay = client.post(
        "/v1/admin/approvals/approval-one/approve",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://testserver"},
        json=approval_body(),
    )
    assert replay.status_code == 409


def test_runaway_authority_is_admin_only_fenced_and_machine_readable() -> None:
    client, auth, backend, _ = make_client()
    unauthenticated = client.get("/v1/admin/runaway-quarantines")
    assert unauthenticated.status_code == 401
    csrf = login(client, auth)

    listed = client.get("/v1/admin/runaway-quarantines")
    assert listed.status_code == 200
    projection = listed.json()["runaway_quarantines"][0]
    assert projection["quarantine_id"] == "rqu_one"
    assert projection["session_id"] == "ses_one"
    assert projection["root_run_id"] == "run_one"
    assert projection["state"] == "OPEN"
    assert "api_key" not in listed.text.casefold()

    missing_csrf = client.post(
        "/v1/admin/runaway-quarantines/rqu_one/authorize",
        headers={"Origin": "http://testserver"},
        json=runaway_authorization_body(),
    )
    assert missing_csrf.status_code == 401
    assert backend.runaway_actions == []

    stale = runaway_authorization_body()
    stale["expected_generation"] = 2
    rejected = client.post(
        "/v1/admin/runaway-quarantines/rqu_one/authorize",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://testserver"},
        json=stale,
    )
    assert rejected.status_code == 403
    assert backend.runaway_actions == []

    authorized = client.post(
        "/v1/admin/runaway-quarantines/rqu_one/authorize",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://testserver"},
        json=runaway_authorization_body(),
    )
    assert authorized.status_code == 200
    assert authorized.json() == {
        "quarantine_id": "rqu_one",
        "state": "AUTHORIZED",
        "generation": 2,
        "acted_at_ms": 1_000,
        "audit_event_id": "evt_runaway_authorized",
    }
    assert backend.runaway_actions == ["authorize"]


def test_dashboard_can_authorize_and_deny_bursts_without_terminal_access() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Runaway quarantines" in dashboard.text
    assert "Authorize bounded burst" in dashboard.text
    assert 'value="firecrawl.search" checked' in dashboard.text
    assert "api_key" not in dashboard.text.casefold()

    quarantine = open_runaway_quarantine()
    form: dict[str, str] = {
        "csrf_token": csrf,
        "action_token": quarantine.action_token,
        "expected_generation": str(quarantine.generation),
        "reason": "Explicit bounded personal-use authorization",
        "duration_ms": "300000",
        "maximum_requests": "10",
        "maximum_credits": "25",
        "maximum_concurrency": "2",
        "operations": "firecrawl.search",
    }
    authorized = client.post(
        "/dashboard/runaway-quarantines/rqu_one/authorize",
        headers={"Origin": "http://testserver"},
        data=form,
        follow_redirects=False,
    )
    assert authorized.status_code == 303
    assert authorized.headers["location"] == "/dashboard"
    assert backend.runaway_actions == ["authorize"]

    current = backend.runaway_quarantine
    denied = client.post(
        "/dashboard/runaway-quarantines/rqu_one/deny",
        headers={"Origin": "http://testserver"},
        data={
            "csrf_token": csrf,
            "action_token": current.action_token,
            "expected_generation": str(current.generation),
            "reason": "Operator denied continued access",
        },
        follow_redirects=False,
    )
    assert denied.status_code == 303
    assert backend.runaway_actions == ["authorize", "deny"]


def test_origin_host_idle_expiry_and_read_surfaces_fail_closed() -> None:
    client, auth, _, clock = make_client()
    csrf = login(client, auth)
    wrong_host = client.get("/v1/admin/status", headers={"Host": "remote.example"})
    assert wrong_host.status_code == 400

    wrong_origin = client.post(
        "/v1/admin/approvals/approval-one/deny",
        headers={CSRF_HEADER_NAME: csrf, "Origin": "http://remote.example"},
        json=approval_body(),
    )
    assert wrong_origin.status_code == 401

    for route, key in (
        ("/v1/admin/pools", "pools"),
        ("/v1/admin/credentials", "credentials"),
        ("/v1/admin/incidents", "incidents"),
        ("/v1/admin/reconciliation", "reconciliation"),
    ):
        response = client.get(route)
        assert response.status_code == 200
        assert key in response.json()
    credential = client.get("/v1/admin/credentials").json()["credentials"][0]
    assert _SECRET_CANARY not in json.dumps(credential, sort_keys=True)
    assert set(credential) == {
        "credential_id",
        "service",
        "alias",
        "principal_id",
        "principal_alias",
        "quota_scope_id",
        "quota_scope_alias",
        "state",
        "generation",
        "expires_at_ms",
        "exclusive_usage",
        "pool_ids",
        "pool_aliases",
        "active_lease_count",
        "created_at_ms",
        "last_used_at_ms",
        "last_local_action",
    }

    clock.advance(201)
    expired = client.get("/v1/admin/status")
    assert expired.status_code == 401


def test_dashboard_is_accessible_bounded_and_secret_free() -> None:
    client, auth, _, _ = make_client()
    login(client, auth)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert '<html lang="en">' in dashboard.text
    assert "Skip to main content" in dashboard.text
    assert "Request-bound approvals" in dashboard.text
    assert "Approve once" in dashboard.text
    assert "api_key" not in dashboard.text.casefold()
    assert dashboard.headers["x-frame-options"] == "DENY"


def test_account_credential_and_emergency_models_are_strict_redacted_allowlists() -> None:
    with pytest.raises(ValidationError):
        AccountAddRequest.model_validate({**account_add_command(), "secret": _SECRET_CANARY})
    with pytest.raises(ValidationError):
        CredentialProvisionRequest.model_validate({**provision_command(), "secret": _SECRET_CANARY})
    for invalid_team_id in ("", "contains space", "non-ascii-\N{SNOWMAN}", "control\nvalue"):
        with pytest.raises(ValidationError):
            AccountAddRequest.model_validate(
                {**account_add_command(), "provider_team_id": invalid_team_id}
            )

    account = FakeAdminBackend._account_result(
        alias="primary",
        action="add",
        state="UNKNOWN",
        generation=1,
    ).model_dump(mode="json")
    account_status = FakeAdminBackend._account_status().model_dump(mode="json")
    account_observation = AccountObservationMutationResult(
        alias="primary",
        action="enable",
        enabled=True,
        acted_at_ms=1_500,
        audit_event_id="audit-observation-one",
    ).model_dump(mode="json")
    credential = FakeAdminBackend._credential_result(
        mutation_id="mut_provision",
        action="provision",
        state="HEALTHY",
        generation=1,
    ).model_dump(mode="json")
    emergency = FakeAdminBackend._emergency_view(
        action="unlock",
        state="ACTIVE",
    ).model_dump(mode="json")
    with pytest.raises(ValidationError):
        AccountMutationResult.model_validate({**account, "credential_id": "internal"})
    with pytest.raises(ValidationError):
        AccountStatus.model_validate({**account_status, "quota_scope_id": "internal"})
    with pytest.raises(ValidationError):
        AccountObservationMutationResult.model_validate(
            {**account_observation, "network_enabled": True}
        )
    with pytest.raises(ValidationError):
        CredentialMutationResult.model_validate({**credential, "secret_reference": _SECRET_CANARY})
    with pytest.raises(ValidationError):
        EmergencyUnlockView.model_validate({**emergency, "maximum_concurrency": 2})
    with pytest.raises(ValidationError):
        CredentialValidationRequest.model_validate(
            {"expected_generation": 3, "provider_url": _SECRET_CANARY}
        )
    validation = FakeAdminBackend._validation_result().model_dump(mode="json")
    with pytest.raises(ValidationError):
        CredentialValidationResult.model_validate(
            {**validation, "provider_response": _SECRET_CANARY}
        )
    forbidden = {
        "secret",
        "secret_reference",
        "ciphertext",
        "authorization",
        "provider_team_id",
        "provider_identity_fingerprint",
    }
    assert forbidden.isdisjoint(account)
    assert forbidden.isdisjoint(account_status)
    assert forbidden.isdisjoint(account_observation)
    assert forbidden.isdisjoint(credential)
    assert forbidden.isdisjoint(emergency)
    assert forbidden.isdisjoint(validation)
    assert _SECRET_CANARY not in json.dumps(
        {
            "account": account,
            "account_status": account_status,
            "account_observation": account_observation,
            "credential": credential,
            "emergency": emergency,
            "validation": validation,
        }
    )
    assert set(account) == {
        "alias",
        "action",
        "state",
        "pool_alias",
        "priority",
        "generation",
        "acted_at_ms",
        "audit_event_id",
    }
    assert set(account_status) == {
        "alias",
        "state",
        "remaining_decimal",
        "plan_decimal",
        "unit",
        "observed_at_ms",
        "staleness_ms",
        "stale",
        "source",
    }
    assert set(account_observation) == {
        "alias",
        "action",
        "enabled",
        "acted_at_ms",
        "audit_event_id",
    }
    assert set(credential) == {
        "mutation_id",
        "credential_id",
        "action",
        "state",
        "generation",
        "alias",
        "principal_id",
        "principal_alias",
        "quota_scope_id",
        "quota_scope_alias",
        "pool_id",
        "pool_alias",
        "expires_at_ms",
        "acted_at_ms",
        "audit_event_id",
    }
    assert set(emergency) == {
        "mutation_id",
        "unlock_id",
        "credential_id",
        "action",
        "state",
        "generation",
        "service",
        "alias",
        "principal_id",
        "principal_alias",
        "quota_scope_id",
        "quota_scope_alias",
        "pool_id",
        "pool_alias",
        "session_id",
        "root_run_id",
        "expires_at_ms",
        "remaining_requests",
        "remaining_credits",
        "remaining_concurrency",
        "acted_at_ms",
        "audit_event_id",
    }
    assert set(validation) == {
        "credential_id",
        "generation",
        "service",
        "principal_id",
        "quota_scope_id",
        "state",
        "snapshot_id",
        "unit",
        "remaining_units",
        "plan_total_units",
        "observed_remaining_units_decimal",
        "observed_plan_total_units_decimal",
        "captured_at_ms",
        "audit_event_id",
    }


@pytest.mark.parametrize(
    "path",
    [
        "/v1/admin/accounts",
        "/v1/admin/accounts/primary/rotate",
        "/v1/admin/accounts/primary/disable",
        "/v1/admin/accounts/primary/recover",
        "/v1/admin/accounts/primary/remove",
        "/v1/admin/accounts/primary/refresh",
        "/v1/admin/accounts/primary/observation",
        "/v1/admin/credentials",
        "/v1/admin/credentials/cred_one/rotate",
        "/v1/admin/credentials/cred_one/validate",
        "/v1/admin/credentials/cred_one/disable",
        "/v1/admin/credentials/cred_one/quarantine",
        "/v1/admin/credentials/cred_one/retire",
        "/v1/admin/emergency-unlocks",
        "/v1/admin/emergency-unlocks/unlock_one/cancel",
    ],
)
def test_every_admin_mutation_authenticates_cookie_origin_and_csrf_before_input(
    path: str,
) -> None:
    client, auth, backend, _ = make_client()
    invalid_input_headers = {
        COMMAND_HEADER_NAME: "not-json",
        "Content-Type": "text/plain",
    }
    unauthenticated = client.post(path, headers=invalid_input_headers, content=_SECRET_CANARY)
    assert unauthenticated.status_code == 401
    assert _SECRET_CANARY not in unauthenticated.text

    csrf = login(client, auth)

    missing_csrf = client.post(
        path,
        headers={**invalid_input_headers, "Origin": "http://testserver"},
        content=_SECRET_CANARY,
    )
    assert missing_csrf.status_code == 401

    missing_origin = client.post(
        path,
        headers={**invalid_input_headers, CSRF_HEADER_NAME: csrf},
        content=_SECRET_CANARY,
    )
    assert missing_origin.status_code == 401

    wrong_origin = client.post(
        path,
        headers={
            **invalid_input_headers,
            CSRF_HEADER_NAME: csrf,
            "Origin": "http://remote.example",
        },
        content=_SECRET_CANARY,
    )
    assert wrong_origin.status_code == 401

    agent_token = client.post(
        path,
        headers={
            **invalid_input_headers,
            CSRF_HEADER_NAME: csrf,
            "Origin": "http://testserver",
            "Authorization": "Bearer " + "agent-token-must-fail",
        },
        content=_SECRET_CANARY,
    )
    assert agent_token.status_code == 401
    assert backend.account_calls == []
    assert backend.credential_calls == []
    assert backend.emergency_calls == []
    assert backend.secret_buffers == []


def test_failed_lifecycle_auth_never_reads_body_for_exact_or_trailing_slash_paths() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    admin_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
    assert admin_cookie is not None
    app = client.app

    async def exercise() -> None:
        for base_path, _ in lifecycle_mutation_commands():
            for path in (base_path, f"{base_path}/"):
                valid_authority = {
                    "Cookie": f"{ADMIN_COOKIE_NAME}={admin_cookie}",
                    "Origin": "http://testserver",
                    CSRF_HEADER_NAME: csrf,
                    COMMAND_HEADER_NAME: "not-json",
                    "Content-Type": "application/octet-stream",
                }
                for missing in ("Cookie", "Origin", CSRF_HEADER_NAME):
                    headers = {
                        name: value for name, value in valid_authority.items() if name != missing
                    }
                    status, response_body, reads = await _asgi_post_following_normalization(
                        app,
                        path,
                        headers=headers,
                        chunks=(_SECRET_CANARY.encode(),),
                    )
                    assert status == 401
                    assert reads == 0
                    assert _SECRET_CANARY.encode() not in response_body

    asyncio.run(exercise())
    assert backend.credential_calls == []
    assert backend.emergency_calls == []
    assert backend.secret_buffers == []


@pytest.mark.parametrize(
    ("base_path", "csrf_header_required"),
    (
        ("/v1/admin/approvals/approval-one/approve", True),
        ("/v1/admin/approvals/approval-one/deny", True),
        ("/v1/admin/runaway-quarantines/rqu_one/authorize", True),
        ("/v1/admin/runaway-quarantines/rqu_one/deny", True),
        ("/dashboard/approvals/approval-one/approve", False),
        ("/dashboard/approvals/approval-one/deny", False),
        ("/dashboard/runaway-quarantines/rqu_one/authorize", False),
        ("/dashboard/runaway-quarantines/rqu_one/deny", False),
    ),
)
def test_failed_approval_auth_never_reads_json_or_form_body(
    base_path: str,
    csrf_header_required: bool,
) -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    admin_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
    assert admin_cookie is not None
    app = client.app
    valid_authority = {
        "Cookie": f"{ADMIN_COOKIE_NAME}={admin_cookie}",
        "Origin": "http://testserver",
        "Content-Type": (
            "application/json" if csrf_header_required else "application/x-www-form-urlencoded"
        ),
    }
    if csrf_header_required:
        valid_authority[CSRF_HEADER_NAME] = csrf

    async def exercise() -> None:
        for path in (base_path, f"{base_path}/"):
            failed_headers = [
                {name: value for name, value in valid_authority.items() if name != "Cookie"},
                {name: value for name, value in valid_authority.items() if name != "Origin"},
                {**valid_authority, "Authorization": "Bearer " + "agent-token-must-fail"},
            ]
            if csrf_header_required:
                failed_headers.append(
                    {
                        name: value
                        for name, value in valid_authority.items()
                        if name != CSRF_HEADER_NAME
                    }
                )
            for headers in failed_headers:
                status, response_body, reads = await _asgi_post_following_normalization(
                    app,
                    path,
                    headers=headers,
                    chunks=(_SECRET_CANARY.encode(),),
                )
                assert status == 401
                assert reads == 0
                assert _SECRET_CANARY.encode() not in response_body

    asyncio.run(exercise())
    assert backend.decisions == []
    assert backend.runaway_actions == []


def test_authenticated_dashboard_approval_parses_form_after_authority() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    response = client.post(
        "/dashboard/approvals/approval-one/approve",
        headers={"Origin": "http://testserver"},
        data={"csrf_token": csrf, **{key: str(value) for key, value in approval_body().items()}},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert backend.decisions == [ApprovalDecision.APPROVE]


def test_authenticated_empty_body_mutations_stream_bound_and_reject_chunked_bodies() -> None:
    client, auth, backend, _ = make_client(maximum_body_bytes=256)
    csrf = login(client, auth)
    admin_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
    assert admin_cookie is not None
    app = client.app
    empty_body_mutations = lifecycle_mutation_commands()[2:6] + (lifecycle_mutation_commands()[-1],)

    async def exercise() -> None:
        for base_path, command in empty_body_mutations:
            headers = {
                "Cookie": f"{ADMIN_COOKIE_NAME}={admin_cookie}",
                "Origin": "http://testserver",
                CSRF_HEADER_NAME: csrf,
                COMMAND_HEADER_NAME: command_header(command),
            }
            for path in (base_path, f"{base_path}/"):
                status, response_body, reads = await _asgi_post_following_normalization(
                    app,
                    path,
                    headers=headers,
                    chunks=(b"", _SECRET_CANARY.encode()),
                )
                assert status == 422
                assert reads == 2
                assert json.loads(response_body)["error"]["details"] == {
                    "fields": [{"field": "body", "type": "empty"}]
                }

        base_path, command = empty_body_mutations[0]
        status, response_body, reads = await _asgi_post_following_normalization(
            app,
            base_path,
            headers={
                "Cookie": f"{ADMIN_COOKIE_NAME}={admin_cookie}",
                "Origin": "http://testserver",
                CSRF_HEADER_NAME: csrf,
                COMMAND_HEADER_NAME: command_header(command),
            },
            chunks=(b"x" * 257,),
        )
        assert status == 422
        assert reads == 1
        assert json.loads(response_body)["error"]["details"] == {
            "fields": [{"field": "body", "type": "too_long"}]
        }

    asyncio.run(exercise())
    assert backend.credential_calls == []
    assert backend.emergency_calls == []


def test_admin_lifecycle_surface_adds_no_control_or_mcp_routes() -> None:
    client, _, _, _ = make_client()
    paths = {getattr(route, "path", "") for route in getattr(client.app, "routes", ())}
    assert "/v1/admin/credentials/{credential_id}/validate" in paths
    assert "/v1/admin/accounts" in paths
    assert "/v1/admin/accounts/{alias}/recover" in paths
    assert "/v1/admin/accounts/{alias}/refresh" in paths
    assert "/v1/admin/accounts/{alias}/observation" in paths
    assert not any(path.startswith("/v1/control") for path in paths)
    assert not any("mcp" in path.casefold() for path in paths)


def test_account_routes_use_aliases_raw_secrets_and_strict_redacted_results() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    added = client.post(
        "/v1/admin/accounts",
        headers=mutation_headers(
            csrf,
            account_add_command(),
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert added.status_code == 201
    assert added.json() == {
        "alias": "primary",
        "action": "add",
        "state": "UNKNOWN",
        "pool_alias": "interactive-default",
        "priority": 10,
        "generation": 1,
        "acted_at_ms": 1_500,
        "audit_event_id": "evt_account_01K32J0B80E4G7P6H9Q2R5T8VW",
    }
    assert _SECRET_CANARY not in added.text

    rotated = client.post(
        "/v1/admin/accounts/primary/rotate",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_account_rotate", "expires_at_ms": None},
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert rotated.status_code == 200
    assert rotated.json()["alias"] == "primary"
    assert rotated.json()["action"] == "rotate"

    expected_states = {
        "disable": "DISABLED",
        "recover": "UNKNOWN",
        "remove": "REMOVED",
    }
    for action, state in expected_states.items():
        response = client.post(
            f"/v1/admin/accounts/primary/{action}",
            headers=mutation_headers(
                csrf,
                {
                    "mutation_id": f"mut_account_{action}",
                    "action": action,
                    "reason": "operator request",
                },
            ),
            content=b"",
        )
        assert response.status_code == 200
        assert response.json()["action"] == action
        assert response.json()["state"] == state

    refreshed = client.post(
        "/v1/admin/accounts/primary/refresh",
        headers=mutation_headers(csrf, {"mutation_id": "mut_account_refresh"}),
        content=b"",
    )
    assert refreshed.status_code == 200

    observations = []
    for action in ("enable", "disable"):
        response = client.post(
            "/v1/admin/accounts/primary/observation",
            headers=mutation_headers(
                csrf,
                {
                    "mutation_id": f"mut_observation_{action}",
                    "action": action,
                    "reason": "operator request",
                },
            ),
            content=b"",
        )
        assert response.status_code == 200
        assert response.json() == {
            "alias": "primary",
            "action": action,
            "enabled": action == "enable",
            "acted_at_ms": 1_500,
            "audit_event_id": "evt_observation_01K32J0B80E4G7P6H9Q2R5T8VW",
        }
        observations.append(response)

    listed = client.get("/v1/admin/accounts?limit=5")
    status = client.get("/v1/admin/accounts/primary")
    assert listed.status_code == status.status_code == 200
    expected_status = {
        "alias": "primary",
        "state": "HEALTHY",
        "remaining_decimal": "750.25",
        "plan_decimal": "1000",
        "unit": "credits",
        "observed_at_ms": 1_400,
        "staleness_ms": 100,
        "stale": False,
        "source": "firecrawl-credit-usage",
    }
    assert status.json() == expected_status
    assert refreshed.json() == expected_status
    assert listed.json() == {"accounts": [expected_status]}
    assert all(buffer and set(buffer) == {0} for buffer in backend.secret_buffers[-2:])
    assert all(call[1] == "primary" for call in backend.account_calls if call[0] != "list")
    assert all(
        call[2] == LOCAL_ACCOUNT_OPERATOR_ACTOR_ID
        for call in backend.account_calls
        if call[0] not in {"list", "status"}
    )
    serialized = (
        added.text
        + rotated.text
        + refreshed.text
        + "".join(response.text for response in observations)
        + listed.text
        + status.text
    )
    assert _SECRET_CANARY not in serialized
    assert "credential_id" not in serialized
    assert "quota_scope_id" not in serialized
    assert "secret_reference" not in serialized


def test_account_mutation_replay_uses_stable_actor_across_admin_sessions() -> None:
    client, auth, backend, _ = make_client()
    first_csrf = login(client, auth)
    first_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
    headers = mutation_headers(
        first_csrf,
        account_add_command(),
        content_type="application/octet-stream",
    )
    first = client.post(
        "/v1/admin/accounts",
        headers=headers,
        content=_SECRET_CANARY.encode(),
    )

    second_csrf = login(client, auth)
    second_cookie = client.cookies.get(ADMIN_COOKIE_NAME)
    replay = client.post(
        "/v1/admin/accounts",
        headers=mutation_headers(
            second_csrf,
            account_add_command(),
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )

    assert first.status_code == replay.status_code == 201
    assert first.json() == replay.json()
    assert first_cookie != second_cookie
    assert backend.account_calls == [
        ("add", "primary", LOCAL_ACCOUNT_OPERATOR_ACTOR_ID),
        ("add", "primary", LOCAL_ACCOUNT_OPERATOR_ACTOR_ID),
    ]


def test_credential_mutation_routes_use_raw_secrets_and_redacted_results() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    provisioned = client.post(
        "/v1/admin/credentials",
        headers=mutation_headers(
            csrf,
            provision_command(),
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert provisioned.status_code == 201
    assert provisioned.json()["action"] == "provision"
    assert _SECRET_CANARY not in provisioned.text
    provision_buffer = backend.secret_buffers[-1]
    assert provision_buffer and set(provision_buffer) == {0}

    rotated = client.post(
        "/v1/admin/credentials/cred_one/rotate",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_rotate", "expires_at_ms": 60_000},
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert rotated.status_code == 200
    assert rotated.json()["action"] == "rotate"
    assert rotated.json()["generation"] == 2
    rotate_buffer = backend.secret_buffers[-1]
    assert rotate_buffer and set(rotate_buffer) == {0}

    for action, expected_state in (
        ("disable", "DISABLED"),
        ("quarantine", "QUARANTINED"),
        ("retire", "RETIRED"),
    ):
        changed = client.post(
            f"/v1/admin/credentials/cred_one/{action}",
            headers=mutation_headers(
                csrf,
                {
                    "mutation_id": f"mut_{action}",
                    "action": action,
                    "reason": "operator requested",
                },
            ),
            content=b"",
        )
        assert changed.status_code == 200
        assert changed.json()["action"] == action
        assert changed.json()["state"] == expected_state

    assert all(call[2].startswith("adm_") for call in backend.credential_calls)
    assert _SECRET_CANARY not in json.dumps(
        [provisioned.json(), rotated.json()],
        sort_keys=True,
    )


def test_credential_validation_is_exactly_bound_and_returns_a_strict_allowlist() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    response = client.post(
        "/v1/admin/credentials/cred_one/validate",
        headers=mutation_headers(csrf, {"expected_generation": 3}),
        content=b"",
    )

    assert response.status_code == 200
    assert response.json() == {
        "credential_id": "cred_one",
        "generation": 3,
        "service": "firecrawl",
        "principal_id": "prn_one",
        "quota_scope_id": "quota_one",
        "state": "authenticated",
        "snapshot_id": "snapshot_one",
        "unit": "credits",
        "remaining_units": 750,
        "plan_total_units": 1_000,
        "observed_remaining_units_decimal": "750",
        "observed_plan_total_units_decimal": "1000",
        "captured_at_ms": 1_500,
        "audit_event_id": "evt_validation_one",
    }
    assert len(backend.credential_calls) == 1
    assert backend.credential_calls[0][:2] == ("validate", "cred_one")
    assert backend.credential_calls[0][2].startswith("adm_")
    assert _SECRET_CANARY not in response.text


@pytest.mark.parametrize(
    "command",
    (
        {},
        {"expected_generation": 0},
        {"expected_generation": True},
        {"expected_generation": "3"},
        {"expected_generation": 3, "provider_url": _SECRET_CANARY},
    ),
)
def test_credential_validation_rejects_non_strict_command_headers(
    command: dict[str, object],
) -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    response = client.post(
        "/v1/admin/credentials/cred_one/validate",
        headers=mutation_headers(csrf, command),
        content=b"",
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "schema_validation_failed"
    assert _SECRET_CANARY not in response.text
    assert backend.credential_calls == []


@pytest.mark.parametrize(
    "result_update",
    (
        {"credential_id": "cred_other"},
        {"generation": 4},
        {"remaining_units": -1},
        {"observed_remaining_units_decimal": "750.0"},
        {"observed_remaining_units_decimal": "749.5"},
        {"observed_plan_total_units_decimal": None},
    ),
)
def test_credential_validation_fails_closed_on_unbound_or_invalid_backend_output(
    result_update: dict[str, object],
) -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    backend.validation_result_update = result_update

    response = client.post(
        "/v1/admin/credentials/cred_one/validate",
        headers=mutation_headers(csrf, {"expected_generation": 3}),
        content=b"",
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "daemon_degraded"
    assert response.json()["error"]["details"] == {}


@pytest.mark.parametrize(
    ("failure", "status", "code", "retry_after"),
    (
        (CredentialValidationUnavailable(_SECRET_CANARY), 503, "daemon_degraded", None),
        (CredentialValidationBusy(_SECRET_CANARY), 429, "capacity_exceeded", "1"),
        (
            CredentialValidationPersistenceError(_SECRET_CANARY),
            503,
            "daemon_degraded",
            None,
        ),
        (CredentialValidationError(_SECRET_CANARY), 503, "daemon_degraded", None),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.NONE),
            503,
            "daemon_degraded",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.INVALID_REQUEST),
            503,
            "provider_unavailable",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.UNAUTHORIZED),
            502,
            "provider_unauthorized",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.QUOTA_EXHAUSTED),
            429,
            "quota_exhausted",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.PERMISSION_DENIED),
            502,
            "provider_permission_denied",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.NOT_FOUND),
            503,
            "provider_unavailable",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.TIMEOUT),
            504,
            "provider_timeout",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.CONFLICT),
            503,
            "provider_unavailable",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.RATE_LIMITED, 2.1),
            429,
            "provider_rate_limited",
            "3",
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.TRANSIENT, 1.2),
            503,
            "provider_unavailable",
            "2",
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.MALFORMED_RESPONSE),
            503,
            "provider_unavailable",
            None,
        ),
        (
            CredentialValidationProviderFailure(ProviderErrorClass.UNKNOWN_OUTCOME),
            502,
            "uncertain_outcome",
            None,
        ),
    ),
)
def test_credential_validation_failures_map_to_sanitized_stable_errors(
    failure: CredentialValidationError,
    status: int,
    code: str,
    retry_after: str | None,
) -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    backend.validation_failure = failure

    response = client.post(
        "/v1/admin/credentials/cred_one/validate",
        headers=mutation_headers(csrf, {"expected_generation": 3}),
        content=b"",
    )

    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.json()["error"]["details"] == {}
    assert response.json()["error"]["retryable"] is (retry_after is not None)
    assert response.headers.get("retry-after") == retry_after
    assert _SECRET_CANARY not in response.text


def test_emergency_unlock_status_and_cancel_are_bounded_and_redacted() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    unlocked = client.post(
        "/v1/admin/emergency-unlocks",
        headers=mutation_headers(
            csrf,
            emergency_command(),
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert unlocked.status_code == 201
    assert unlocked.json()["state"] == "ACTIVE"
    assert unlocked.json()["remaining_concurrency"] == 1
    assert _SECRET_CANARY not in unlocked.text
    unlock_buffer = backend.secret_buffers[-1]
    assert unlock_buffer and set(unlock_buffer) == {0}

    status = client.get("/v1/admin/emergency-unlocks?limit=10")
    assert status.status_code == 200
    assert status.json() == {"emergency_unlocks": [unlocked.json()]}
    assert _SECRET_CANARY not in status.text

    cancelled = client.post(
        "/v1/admin/emergency-unlocks/unlock_one/cancel",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_cancel", "reason": "incident closed"},
        ),
        content=b"",
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["action"] == "cancel"
    assert cancelled.json()["state"] == "CANCELLED"
    assert cancelled.json()["remaining_concurrency"] == 0
    assert all(call[2].startswith("adm_") for call in backend.emergency_calls)


def test_sensitive_mutation_validation_never_reflects_input_and_enforces_raw_bounds() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    invalid_command = client.post(
        "/v1/admin/credentials",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_bad", "secret": _SECRET_CANARY},
            content_type="application/octet-stream",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert invalid_command.status_code == 422
    assert _SECRET_CANARY not in invalid_command.text
    assert all(
        set(item) == {"field", "type"}
        for item in invalid_command.json()["error"]["details"]["fields"]
    )

    oversized_command = client.post(
        "/v1/admin/credentials",
        headers={
            CSRF_HEADER_NAME: csrf,
            "Origin": "http://testserver",
            COMMAND_HEADER_NAME: "x" * (MAXIMUM_COMMAND_BYTES + 1),
            "Content-Type": "application/octet-stream",
        },
        content=_SECRET_CANARY.encode(),
    )
    assert oversized_command.status_code == 422
    assert oversized_command.json()["error"]["details"] == {
        "fields": [{"field": COMMAND_HEADER_NAME, "type": "too_long"}]
    }
    assert _SECRET_CANARY not in oversized_command.text

    wrong_type = client.post(
        "/v1/admin/credentials",
        headers=mutation_headers(
            csrf,
            provision_command(),
            content_type="text/plain",
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert wrong_type.status_code == 422
    assert _SECRET_CANARY not in wrong_type.text

    empty = client.post(
        "/v1/admin/credentials",
        headers=mutation_headers(
            csrf,
            provision_command(),
            content_type="application/octet-stream",
        ),
        content=b"",
    )
    assert empty.status_code == 422

    oversized = client.post(
        "/v1/admin/credentials",
        headers=mutation_headers(
            csrf,
            provision_command(),
            content_type="application/octet-stream",
        ),
        content=(_SECRET_CANARY.encode() + b"x" * MAXIMUM_SECRET_BYTES)[: MAXIMUM_SECRET_BYTES + 1],
    )
    assert oversized.status_code == 422
    assert _SECRET_CANARY not in oversized.text

    nonempty_state_body = client.post(
        "/v1/admin/credentials/cred_one/disable",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_disable", "action": "disable", "reason": "operator"},
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert nonempty_state_body.status_code == 422
    assert _SECRET_CANARY not in nonempty_state_body.text

    mismatched_state_action = client.post(
        "/v1/admin/credentials/cred_one/disable",
        headers=mutation_headers(
            csrf,
            {
                "mutation_id": "mut_mismatch",
                "action": "quarantine",
                "reason": "operator",
            },
        ),
        content=b"",
    )
    assert mismatched_state_action.status_code == 422

    nonempty_cancel_body = client.post(
        "/v1/admin/emergency-unlocks/unlock_one/cancel",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_cancel", "reason": "operator"},
        ),
        content=_SECRET_CANARY.encode(),
    )
    assert nonempty_cancel_body.status_code == 422
    assert _SECRET_CANARY not in nonempty_cancel_body.text
    assert backend.credential_calls == []
    assert backend.emergency_calls == []
    assert backend.secret_buffers == []


def test_secret_buffers_are_zeroed_when_backend_raises_and_surfaces_stay_sanitized(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    backend.fail_secret_mutation = True
    mutations: tuple[tuple[str, dict[str, object]], ...] = (
        ("/v1/admin/accounts", account_add_command()),
        (
            "/v1/admin/accounts/primary/rotate",
            {"mutation_id": "mut_account_rotate_failure", "expires_at_ms": None},
        ),
        ("/v1/admin/credentials", provision_command()),
        (
            "/v1/admin/credentials/cred_one/rotate",
            {"mutation_id": "mut_rotate_failure", "expires_at_ms": None},
        ),
        ("/v1/admin/emergency-unlocks", emergency_command()),
    )

    for path, command in mutations:
        response = client.post(
            path,
            headers=mutation_headers(
                csrf,
                command,
                content_type="application/octet-stream",
            ),
            content=_SECRET_CANARY.encode(),
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "daemon_degraded"
        assert response.headers["retry-after"] == "1"
        assert _SECRET_CANARY not in response.text

    assert len(backend.secret_buffers) == len(mutations)
    assert all(buffer == bytearray(len(_SECRET_CANARY)) for buffer in backend.secret_buffers)
    assert _SECRET_CANARY not in caplog.text


def test_schema_valid_backend_secret_reflection_fails_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    backend.reflect_secret_mutation = True
    mutations: tuple[tuple[str, dict[str, object]], ...] = (
        ("/v1/admin/accounts", account_add_command()),
        (
            "/v1/admin/accounts/primary/rotate",
            {"mutation_id": "mut_account_rotate_reflection", "expires_at_ms": None},
        ),
        ("/v1/admin/credentials", provision_command()),
        (
            "/v1/admin/credentials/cred_one/rotate",
            {"mutation_id": "mut_rotate_reflection", "expires_at_ms": None},
        ),
        ("/v1/admin/emergency-unlocks", emergency_command()),
    )

    for path, command in mutations:
        response = client.post(
            path,
            headers=mutation_headers(
                csrf,
                command,
                content_type="application/octet-stream",
            ),
            content=_SECRET_CANARY.encode(),
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "daemon_degraded"
        assert _SECRET_CANARY not in response.text

    assert len(backend.secret_buffers) == len(mutations)
    assert all(buffer == bytearray(len(_SECRET_CANARY)) for buffer in backend.secret_buffers)
    assert _SECRET_CANARY not in caplog.text


def test_non_namespaced_numeric_secret_is_rejected_before_backend() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    mutations: tuple[tuple[str, dict[str, object]], ...] = (
        ("/v1/admin/accounts", account_add_command()),
        (
            "/v1/admin/accounts/primary/rotate",
            {"mutation_id": "mut_account_rotate_numeric", "expires_at_ms": None},
        ),
        ("/v1/admin/credentials", provision_command()),
        (
            "/v1/admin/credentials/cred_one/rotate",
            {"mutation_id": "mut_rotate_numeric_reflection", "expires_at_ms": None},
        ),
        ("/v1/admin/emergency-unlocks", emergency_command()),
    )

    for path, command in mutations:
        response = client.post(
            path,
            headers=mutation_headers(
                csrf,
                command,
                content_type="application/octet-stream",
            ),
            content=b"12345",
        )
        assert response.status_code == 422
        assert response.json()["error"]["details"] == {
            "fields": [{"field": "body", "type": "credential_format"}]
        }
        assert "12345" not in response.text

    assert backend.secret_buffers == []
    assert backend.account_calls == []
    assert backend.credential_calls == []
    assert backend.emergency_calls == []


def test_secret_duplicated_into_command_metadata_is_rejected_before_backend() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)
    provision = provision_command()
    provision["alias"] = _SECRET_CANARY
    rotation: dict[str, object] = {
        "mutation_id": _SECRET_CANARY,
        "expires_at_ms": None,
    }
    emergency = emergency_command()
    emergency["alias"] = _SECRET_CANARY
    account_add = account_add_command()
    account_add["alias"] = _SECRET_CANARY
    account_rotation: dict[str, object] = {
        "mutation_id": _SECRET_CANARY,
        "expires_at_ms": None,
    }

    commands: tuple[tuple[str, dict[str, object]], ...] = (
        ("/v1/admin/accounts", account_add),
        ("/v1/admin/accounts/primary/rotate", account_rotation),
        ("/v1/admin/credentials", provision),
        ("/v1/admin/credentials/cred_one/rotate", rotation),
        ("/v1/admin/emergency-unlocks", emergency),
    )
    for path, command in commands:
        response = client.post(
            path,
            headers=mutation_headers(
                csrf,
                command,
                content_type="application/octet-stream",
            ),
            content=_SECRET_CANARY.encode(),
        )
        assert response.status_code == 422
        assert response.json()["error"]["details"] == {
            "fields": [{"field": "command", "type": "secret_overlap"}]
        }
        assert _SECRET_CANARY not in response.text

    assert backend.account_calls == []
    assert backend.credential_calls == []
    assert backend.emergency_calls == []
    assert backend.secret_buffers == []


def test_serialized_request_and_response_secret_overlap_fails_closed() -> None:
    client, auth, backend, _ = make_client()
    csrf = login(client, auth)

    command = provision_command()
    command_boundary_alias = "synthetic-command-boundary-seed"
    command["alias"] = command_boundary_alias
    command_overlap = f'{command_boundary_alias}","expires_at_ms":50000'.encode()
    response = client.post(
        "/v1/admin/credentials",
        headers=mutation_headers(
            csrf,
            command,
            content_type="application/octet-stream",
        ),
        content=command_overlap,
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"] == {
        "fields": [{"field": "command", "type": "secret_overlap"}]
    }

    path_credential_id = "synthetic-path-overlap-credential-000001"
    path_overlap = path_credential_id.encode()
    response = client.post(
        f"/v1/admin/credentials/{path_credential_id}/rotate",
        headers=mutation_headers(
            csrf,
            {"mutation_id": "mut_path_overlap", "expires_at_ms": None},
            content_type="application/octet-stream",
        ),
        content=path_overlap,
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"] == {
        "fields": [{"field": "command", "type": "secret_overlap"}]
    }
    assert backend.credential_calls == []
    assert backend.emergency_calls == []
    assert backend.secret_buffers == []

    backend.reflect_serialized_secret_mutation = True
    serialized_response_overlap = _SERIALIZED_RESPONSE_SECRET
    response_commands: tuple[tuple[str, dict[str, object]], ...] = (
        ("/v1/admin/credentials", provision_command()),
        (
            "/v1/admin/credentials/cred_one/rotate",
            {"mutation_id": "mut_rotate_serialized", "expires_at_ms": None},
        ),
        ("/v1/admin/emergency-unlocks", emergency_command()),
    )
    for path, response_command in response_commands:
        response = client.post(
            path,
            headers=mutation_headers(
                csrf,
                response_command,
                content_type="application/octet-stream",
            ),
            content=serialized_response_overlap,
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "daemon_degraded"
        assert serialized_response_overlap.decode() not in response.text

    assert len(backend.secret_buffers) == 3
    assert all(
        buffer == bytearray(len(serialized_response_overlap)) for buffer in backend.secret_buffers
    )
