from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import pytest

from gatehouse.admin import (
    AccountAddRequest,
    AccountLifecycleUnavailable,
    AccountMutationResult,
    AccountObservationChangeRequest,
    AccountObservationMutationResult,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    AccountStatus,
    SqliteApprovalAdminService,
    SqliteCredentialLifecycleService,
    StockAdminBackend,
)


class FakeAccountService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    @staticmethod
    def result(alias: str, action: str) -> AccountMutationResult:
        return AccountMutationResult.model_validate(
            {
                "alias": alias,
                "action": action,
                "state": "UNKNOWN",
                "pool_alias": "interactive-default",
                "priority": 10,
                "generation": 1,
                "acted_at_ms": 1_000,
                "audit_event_id": "audit-account-one",
            }
        )

    @staticmethod
    def status(alias: str) -> AccountStatus:
        return AccountStatus(
            alias=alias,
            state="UNKNOWN",
            remaining_decimal=None,
            plan_decimal=None,
            unit="credits",
            observed_at_ms=None,
            staleness_ms=None,
            stale=True,
            source=None,
        )

    async def add_account(
        self,
        request: AccountAddRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        self.calls.append(("add", request.alias, actor_id))
        assert secret
        return self.result(request.alias, "add")

    async def list_accounts(self, *, limit: int) -> Sequence[AccountStatus]:
        self.calls.append(("list", str(limit), "read"))
        return (self.status("primary"),)

    async def get_account_status(self, alias: str) -> AccountStatus | None:
        self.calls.append(("status", alias, "read"))
        return self.status(alias)

    async def rotate_account(
        self,
        alias: str,
        request: AccountRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        del request
        self.calls.append(("rotate", alias, actor_id))
        assert secret
        return self.result(alias, "rotate")

    async def change_account_state(
        self,
        alias: str,
        request: AccountStateChangeRequest,
        actor_id: str,
    ) -> AccountMutationResult:
        self.calls.append((request.action, alias, actor_id))
        return self.result(alias, request.action)

    async def refresh_account(
        self,
        alias: str,
        request: AccountRefreshRequest,
        actor_id: str,
    ) -> AccountStatus:
        del request
        self.calls.append(("refresh", alias, actor_id))
        return self.status(alias)

    async def change_account_observation(
        self,
        alias: str,
        request: AccountObservationChangeRequest,
        actor_id: str,
    ) -> AccountObservationMutationResult:
        self.calls.append((f"observe-{request.action}", alias, actor_id))
        return AccountObservationMutationResult(
            alias=alias,
            action=request.action,
            enabled=request.action == "enable",
            acted_at_ms=1_000,
            audit_event_id="audit-observation-one",
        )


def stock_backend(*, accounts: FakeAccountService | None) -> StockAdminBackend:
    return StockAdminBackend(
        approvals=cast(SqliteApprovalAdminService, object()),
        credentials=cast(SqliteCredentialLifecycleService, object()),
        accounts=accounts,
    )


async def test_stock_backend_delegates_alias_addressed_account_operations() -> None:
    service = FakeAccountService()
    backend = stock_backend(accounts=service)
    secret = bytearray(b"synthetic-secret")
    add = AccountAddRequest(
        mutation_id="mut-add",
        provider="firecrawl",
        provider_team_id="team-primary",
        alias="primary",
        pool_alias="interactive-default",
        priority=10,
    )

    assert (await backend.add_account(add, secret, "admin-one")).alias == "primary"
    assert len(await backend.list_accounts(limit=5)) == 1
    assert (await backend.get_account_status("primary")) is not None
    assert (
        await backend.rotate_account(
            "primary",
            AccountRotationRequest(mutation_id="mut-rotate"),
            secret,
            "admin-one",
        )
    ).action == "rotate"
    assert (
        await backend.change_account_state(
            "primary",
            AccountStateChangeRequest(
                mutation_id="mut-disable",
                action="disable",
                reason="operator request",
            ),
            "admin-one",
        )
    ).action == "disable"
    assert (
        await backend.refresh_account(
            "primary",
            AccountRefreshRequest(mutation_id="mut-refresh"),
            "admin-one",
        )
    ).alias == "primary"
    assert (
        await backend.change_account_observation(
            "primary",
            AccountObservationChangeRequest(
                mutation_id="mut-observe-enable",
                action="enable",
                reason="operator opt in",
            ),
            "admin-one",
        )
    ).enabled
    assert service.calls == [
        ("add", "primary", "admin-one"),
        ("list", "5", "read"),
        ("status", "primary", "read"),
        ("rotate", "primary", "admin-one"),
        ("disable", "primary", "admin-one"),
        ("refresh", "primary", "admin-one"),
        ("observe-enable", "primary", "admin-one"),
    ]


async def test_stock_backend_fails_closed_when_account_service_is_not_composed() -> None:
    backend = stock_backend(accounts=None)

    with pytest.raises(AccountLifecycleUnavailable, match="not configured"):
        await backend.list_accounts(limit=1)
