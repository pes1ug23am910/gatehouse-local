from __future__ import annotations

from typing import cast

import pytest

from gatehouse.api import PendingApprovalRecoveryResult
from gatehouse.core.ids import (
    ClientId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.daemon import composition
from gatehouse.fingerprint import RequestFingerprint
from gatehouse.invocations import (
    InvocationCoordinator,
    InvocationRequest,
    InvocationSession,
    VerifiedPendingApproval,
)
from gatehouse.policy import ClientClass

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


@pytest.mark.asyncio
async def test_pending_approval_recovery_adapter_preserves_exact_verified_facts() -> None:
    fingerprint = RequestFingerprint(b"f" * 32, 1, 1)
    verified = VerifiedPendingApproval(
        approval_id="approval-recovered",
        request_id=RequestId(f"req_{_A}"),
        root_run_id=RootRunId(f"run_{_B}"),
        fingerprint=fingerprint,
    )

    class Coordinator:
        async def recover_pending_approval(
            self,
            request: InvocationRequest,
            session: InvocationSession,
        ) -> VerifiedPendingApproval:
            assert request.request_id == verified.request_id
            assert session.session_id == f"ses_{_A}"
            return verified

    request = InvocationRequest(
        request_id=RequestId(f"req_{_A}"),
        access_token=None,
        root_run_id=RootRunId(f"run_{_A}"),
        service_id="firecrawl",
        operation="firecrawl.crawl.start",
        input_payload={
            "url": "https://example.com/careers",
            "maximum_pages": 5,
            "purpose": "multi_page_job_extraction",
            "data_classification": ["public_web"],
        },
        purpose="multi_page_job_extraction",
        data_classifications=frozenset({"public_web"}),
        queue_deadline_ms=10_000,
    )
    session = InvocationSession(
        session_id=SessionId(f"ses_{_A}"),
        client_id=ClientId(f"client_{_A}"),
        root_run_id=RootRunId(f"run_{_A}"),
        workspace_id=WorkspaceId(f"ws_{_A}"),
        client_class=ClientClass.INTERACTIVE,
        allowed_capabilities=frozenset({"firecrawl.crawl.start"}),
        pool_bindings={"firecrawl": "interactive-default"},
        request_count_remaining=10,
        credit_budget_remaining_units=100,
    )
    adapter = composition._PendingApprovalRecoveryAdapter(
        cast(InvocationCoordinator, Coordinator())
    )

    result = await adapter.recover_pending_approval(request, session)

    assert result == PendingApprovalRecoveryResult(
        approval_id=verified.approval_id,
        request_id=verified.request_id,
        root_run_id=verified.root_run_id,
        fingerprint=verified.fingerprint,
    )
