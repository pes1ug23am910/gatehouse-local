"""Production application bridge for the authenticated agent HTTP surface."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Literal, Protocol
from urllib.parse import urlsplit, urlunsplit

from gatehouse.config import ClientProfileConfig
from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock, require_utc_ms
from gatehouse.core.errors import ErrorCode, GatehouseError, JsonValue, make_error
from gatehouse.core.ids import (
    ClientId,
    JobId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import InvocationState
from gatehouse.credentials import ActiveSecretInspectionUnavailable
from gatehouse.credentials.redaction import SecretDetectedError
from gatehouse.documentation import DocumentationService
from gatehouse.feedback import FeedbackCapacityExceeded, FeedbackService
from gatehouse.fingerprint import RequestFingerprint
from gatehouse.invocations import InvocationRequest as CoordinatedInvocationRequest
from gatehouse.invocations import (
    InvocationResult,
    InvocationSession,
)
from gatehouse.jobs import JobAwaitResult, JobOwner, JobRecord, JobState
from gatehouse.notifier import ApprovalPendingSignal, ApprovalPendingSignalSink
from gatehouse.policy import ClientClass, Decision, WorkspacePolicy
from gatehouse.routing import ResourceAffinity, ResourceAffinityStore
from gatehouse.scheduler import PriorityClass
from gatehouse.sessions import AccessPrincipal, RootRunRecord, RootRunState

from .contracts import (
    ApiResponse,
    DocumentationSearchRequest,
    FeedbackSubmitRequest,
    InvocationRequest,
    JobAwaitRequest,
    JobContext,
    PolicyExplainAuthority,
    PolicyExplainConstraints,
    PolicyExplainRequest,
    PolicyExplainResponse,
    PolicyExplainRule,
)

_INVOCATION_CAPABILITIES = frozenset(
    {
        "firecrawl.search",
        "firecrawl.scrape",
        "firecrawl.map",
        "firecrawl.crawl.start",
        "firecrawl.crawl.status",
        "firecrawl.crawl.cancel",
    }
)
_JOB_CAPABILITIES = frozenset({"jobs.status", "jobs.await", "jobs.cancel"})
_DOCUMENTATION_CAPABILITIES = frozenset({"docs.search", "docs.get"})
_FEEDBACK_CAPABILITIES = frozenset({"feedback.submit"})
_RESOURCE_OPERATIONS = frozenset({"firecrawl.crawl.status", "firecrawl.crawl.cancel"})
_POLICY_OPERATION_CAPABILITIES = MappingProxyType(
    {
        "search": "firecrawl.search",
        "scrape": "firecrawl.scrape",
        "map": "firecrawl.map",
        "crawl": "firecrawl.crawl.start",
    }
)
_POLICY_DECISION_NAMES: Mapping[
    Decision,
    Literal["ALLOW", "ASK", "DENY"],
] = MappingProxyType(
    {
        Decision.ALLOW: "ALLOW",
        Decision.ASK: "ASK",
        Decision.DENY: "DENY",
    }
)
_MAXIMUM_JSON_DEPTH = 32
_MAXIMUM_JSON_NODES = 100_000


def _scrub_exception(error: BaseException) -> None:
    error.args = ()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None


class _AuthenticatedCoordinator(Protocol):
    async def invoke_authenticated(
        self,
        request: CoordinatedInvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult: ...


@dataclass(frozen=True, slots=True)
class PendingApprovalRecoveryResult:
    """Exact durable pending approval verified without replaying its coordinator path."""

    approval_id: str
    request_id: RequestId
    root_run_id: RootRunId
    fingerprint: RequestFingerprint

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.approval_id) <= 160
            or self.approval_id in {".", ".."}
            or not all(
                character.isascii() and (character.isalnum() or character in "_.:-")
                for character in self.approval_id
            )
        ):
            raise ValueError("recovered approval identifier is invalid")
        if not isinstance(self.request_id, RequestId):
            raise TypeError("recovered approval request identifier is invalid")
        if not isinstance(self.root_run_id, RootRunId):
            raise TypeError("recovered approval root-run identifier is invalid")
        if not isinstance(self.fingerprint, RequestFingerprint):
            raise TypeError("recovered approval fingerprint is invalid")


class PendingApprovalRecovery(Protocol):
    """Read-only exact verifier for a durable crawl approval continuation."""

    async def recover_pending_approval(
        self,
        request: CoordinatedInvocationRequest,
        session: InvocationSession,
    ) -> PendingApprovalRecoveryResult | None: ...


class _RootRunReader(Protocol):
    async def load_root_run(self, root_run_id: str) -> RootRunRecord | None: ...


class _FeedbackSecretInspector(Protocol):
    async def reject_overlap(self, value: object) -> None: ...


class _JobStore(Protocol):
    async def create_from_affinity(
        self,
        affinity: ResourceAffinity,
        *,
        maximum_runtime_at_ms: int,
        next_poll_at_ms: int | None = None,
        provider_status: str | None = None,
    ) -> JobRecord: ...

    async def load(self, job_id: JobId, *, owner: JobOwner) -> JobRecord | None: ...

    async def request_cancellation(
        self,
        job_id: JobId,
        *,
        owner: JobOwner,
        now_ms: int,
    ) -> JobRecord | None: ...

    async def await_update(
        self,
        job_id: JobId,
        *,
        owner: JobOwner,
        after_revision: int,
        maximum_wait_ms: int,
    ) -> JobAwaitResult: ...


@dataclass(frozen=True, slots=True)
class _ConfiguredPrincipal:
    session_id: SessionId
    client_id: ClientId
    workspace_id: WorkspaceId
    token_epoch: int
    revocation_epoch: int
    profile: ClientProfileConfig
    policy: WorkspacePolicy


def _daemon_degraded(*, request_id: RequestId | None = None) -> GatehouseError:
    return make_error(
        ErrorCode.DAEMON_DEGRADED,
        retryable=True,
        retry_after_seconds=1,
        request_id=request_id,
    )


def _invalid_session() -> GatehouseError:
    return make_error(ErrorCode.INVALID_SESSION, retryable=False)


def _invalid_job() -> GatehouseError:
    # Malformed, missing, and differently-owned identifiers are intentionally identical.
    return make_error(ErrorCode.INVALID_TARGET, retryable=False)


def _validated_approval_dashboard_url(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("approval dashboard URL is invalid") from error
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65_535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/dashboard"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("approval dashboard URL must be a fixed numeric loopback dashboard")
    return urlunsplit(("http", f"127.0.0.1:{port}", "/dashboard", "", ""))


def _safe_json(value: object) -> JsonValue:
    remaining = _MAXIMUM_JSON_NODES

    def copy(item: object, *, depth: int) -> JsonValue:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > _MAXIMUM_JSON_DEPTH:
            raise ValueError("result JSON exceeds its structural bound")
        if item is None or isinstance(item, (str, bool, int)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("result JSON contains a non-finite number")
            return item
        if isinstance(item, Mapping):
            result: dict[str, JsonValue] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("result JSON contains a non-string object key")
                result[key] = copy(child, depth=depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [copy(child, depth=depth + 1) for child in item]
        raise TypeError("result is not JSON-compatible")

    return copy(value, depth=0)


def _submit_approval_notification(
    sink: ApprovalPendingSignalSink,
    signal: ApprovalPendingSignal,
) -> None:
    """Keep best-effort notification failures outside the invocation result path."""

    try:
        sink.submit(signal)
    except Exception:
        return


class GatehouseAgentOperations:
    """Project authenticated durable authority into coordinator-safe operations."""

    def __init__(
        self,
        *,
        coordinator: _AuthenticatedCoordinator,
        root_runs: _RootRunReader,
        client_profiles: Mapping[str, ClientProfileConfig],
        workspace_policies: Mapping[str, WorkspacePolicy],
        jobs: _JobStore,
        affinities: ResourceAffinityStore,
        documentation: DocumentationService | None = None,
        feedback: FeedbackService | None = None,
        feedback_secret_inspector: _FeedbackSecretInspector | None = None,
        approval_notifications: ApprovalPendingSignalSink | None = None,
        pending_approval_recovery: PendingApprovalRecovery | None = None,
        approval_dashboard_url: str | None = None,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
        request_id_factory: Callable[[], RequestId] | None = None,
    ) -> None:
        self._coordinator = coordinator
        self._root_runs = root_runs
        self._client_profiles = MappingProxyType(dict(client_profiles))
        self._workspace_policies = MappingProxyType(dict(workspace_policies))
        self._jobs = jobs
        self._affinities = affinities
        self._documentation = documentation
        self._feedback = feedback
        self._feedback_secret_inspector = feedback_secret_inspector
        self._approval_notifications = approval_notifications
        self._pending_approval_recovery = pending_approval_recovery
        self._approval_dashboard_url = _validated_approval_dashboard_url(approval_dashboard_url)
        self._clock = clock
        self._request_id_factory = request_id_factory or (lambda: RequestId.new(clock=self._clock))

    async def capabilities(self, principal: AccessPrincipal) -> Sequence[str]:
        configured = self._configured_principal(principal)
        return tuple(sorted(self._available_capabilities(configured)))

    async def invoke(
        self,
        principal: AccessPrincipal,
        request: InvocationRequest,
    ) -> ApiResponse:
        configured, root_run = await self._invocation_authority(
            principal,
            request.context.root_run_id,
        )
        operation = f"{request.service}.{request.operation}"
        self._require_capability(configured, operation)
        if request.request_id is not None and operation != "firecrawl.crawl.start":
            raise make_error(
                ErrorCode.SCHEMA_VALIDATION_FAILED,
                retryable=False,
            )
        purpose, classifications = self._policy_inputs(operation, request.input)
        explicit_request_id = request.request_id is not None
        try:
            request_id = (
                RequestId(request.request_id)
                if request.request_id is not None
                else self._request_id_factory()
            )
        except (TypeError, ValueError) as error:
            raise make_error(
                ErrorCode.SCHEMA_VALIDATION_FAILED,
                retryable=False,
            ) from error
        if not isinstance(request_id, RequestId):
            raise _daemon_degraded()
        now_ms = self._clock.now_ms()
        queue_deadline_ms = require_utc_ms(now_ms + max(1, request.execution.wait_up_to_ms))
        session = self._invocation_session(configured, root_run)
        coordinated = CoordinatedInvocationRequest(
            request_id=request_id,
            access_token=None,
            root_run_id=session.root_run_id,
            service_id=request.service,
            operation=operation,
            input_payload=request.input,
            purpose=purpose,
            data_classifications=classifications,
            queue_deadline_ms=queue_deadline_ms,
            approval_id=request.approval_id,
        )
        if explicit_request_id and coordinated.operation == "firecrawl.crawl.start":
            recovered_job_id = await self._materialize_bound_crawl(
                configured=configured,
                request=coordinated,
            )
            if recovered_job_id is not None:
                return ApiResponse(
                    {
                        "request_id": str(request_id),
                        "state": InvocationState.SUCCEEDED.value,
                        "service": coordinated.service_id,
                        "operation": coordinated.operation.removeprefix(
                            f"{coordinated.service_id}."
                        ),
                        "attempts": 0,
                        "job_id": str(recovered_job_id),
                    }
                )
            if coordinated.approval_id is None and self._pending_approval_recovery is not None:
                recovered_approval = await self._pending_approval_recovery.recover_pending_approval(
                    coordinated,
                    session,
                )
                if recovered_approval is not None:
                    if recovered_approval.request_id != coordinated.request_id:
                        raise _daemon_degraded(request_id=request_id)
                    recovered_request = replace(
                        coordinated,
                        root_run_id=recovered_approval.root_run_id,
                    )
                    recovered_result = InvocationResult(
                        request_id=recovered_approval.request_id,
                        state=InvocationState.WAITING_APPROVAL,
                        attempts=0,
                        fingerprint=recovered_approval.fingerprint,
                        error=make_error(
                            ErrorCode.APPROVAL_PENDING,
                            retryable=True,
                            retry_after_seconds=1,
                            request_id=recovered_approval.request_id,
                        ).detail,
                        approval_id=recovered_approval.approval_id,
                    )
                    return await self._invocation_response(
                        configured=configured,
                        request=recovered_request,
                        result=recovered_result,
                    )
        result = await self._coordinator.invoke_authenticated(coordinated, session)
        if result.request_id != request_id:
            raise _daemon_degraded(request_id=request_id)
        return await self._invocation_response(
            configured=configured,
            request=coordinated,
            result=result,
        )

    async def explain_policy(
        self,
        principal: AccessPrincipal,
        request: PolicyExplainRequest,
    ) -> ApiResponse:
        """Explain configured policy for exact authenticated authority without execution."""

        configured, root_run = await self._invocation_authority(
            principal,
            request.context.root_run_id,
        )
        capability = _POLICY_OPERATION_CAPABILITIES[request.operation]
        if request.service != configured.policy.service:
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False)
        capability_allowed = capability in self._available_capabilities(configured)

        request_limit = root_run.budget.get(
            "requests",
            configured.policy.maximum_requests_per_root_run,
        )
        credit_limit = root_run.budget.get(
            "credits",
            math.floor(configured.policy.maximum_credits_per_root_run),
        )
        requests_remaining = max(
            0,
            request_limit - root_run.consumed.get("requests", 0),
        )
        credits_remaining = max(
            0,
            credit_limit - root_run.consumed.get("credits", 0),
        )
        client_class = (
            ClientClass.UNATTENDED
            if configured.profile.client.unattended
            else ClientClass.INTERACTIVE
        )
        if capability_allowed:
            default_decision, default_reason = self._explain_decision(
                configured.policy.default_decision,
                client_class=client_class,
            )
            default_rule_id = "default-decision"
        else:
            default_decision = Decision.DENY
            default_reason = "operation-not-authorized"
            default_rule_id = "capability-ceiling"
        default_denial = default_reason if default_decision is Decision.DENY else None
        purpose_rules: list[PolicyExplainRule] = []
        for purpose in sorted(configured.policy.purpose_rules):
            configured_rule = configured.policy.purpose_rules[purpose].get(request.operation)
            if not capability_allowed:
                decision = Decision.DENY
                reason = "operation-not-authorized"
                rule_id = "capability-ceiling"
                targeted_only = False
                maximum_cost = None
            elif configured_rule is None:
                decision, reason = self._explain_decision(
                    configured.policy.default_decision,
                    client_class=client_class,
                )
                rule_id = "default-decision"
                targeted_only = False
                maximum_cost = None
            else:
                decision, reason = self._explain_decision(
                    configured_rule.decision,
                    client_class=client_class,
                    targeted_only=configured_rule.targeted_only,
                )
                rule_id = f"purpose:{purpose}:{request.operation}"
                targeted_only = configured_rule.targeted_only
                maximum_cost = configured_rule.maximum_cost
            purpose_rules.append(
                PolicyExplainRule(
                    purpose=purpose,
                    decision=_POLICY_DECISION_NAMES[decision],
                    rule_id=rule_id,
                    reason_code=reason,
                    targeted_only=targeted_only,
                    maximum_cost_units=maximum_cost,
                    approval_required=decision is Decision.ASK,
                    denial_reason=reason if decision is Decision.DENY else None,
                )
            )

        response = PolicyExplainResponse(
            authority=PolicyExplainAuthority(
                session_id=str(configured.session_id),
                client_id=str(configured.client_id),
                client=configured.profile.client.id,
                workspace_id=str(configured.workspace_id),
                workspace=configured.policy.policy_id,
                root_run_id=root_run.root_run_id,
            ),
            service=request.service,
            operation=request.operation,
            decision=_POLICY_DECISION_NAMES[default_decision],
            rule_id=default_rule_id,
            reason_code=default_reason,
            policy_id=configured.policy.policy_id,
            policy_version=configured.policy.version,
            constraints=PolicyExplainConstraints(
                maximum_search_results=configured.policy.maximum_search_results,
                maximum_map_results=configured.policy.maximum_map_results,
                maximum_crawl_pages=configured.policy.maximum_crawl_pages,
                maximum_crawl_depth=configured.policy.maximum_crawl_depth,
                request_count_remaining=requests_remaining,
                credit_budget_remaining_units=credits_remaining,
            ),
            cost_ceiling_units=credits_remaining,
            approval_required=default_decision is Decision.ASK,
            denial_reason=default_denial,
            purpose_rules=purpose_rules,
        )
        return ApiResponse(response.model_dump(mode="json"))

    @staticmethod
    def _explain_decision(
        decision: Decision,
        *,
        client_class: ClientClass,
        targeted_only: bool = False,
    ) -> tuple[Decision, str]:
        if targeted_only and decision is Decision.ALLOW:
            decision = Decision.ASK
            reason = "target-context-required"
        else:
            reason = f"policy-{decision.value}"
        if decision is Decision.ASK and client_class is ClientClass.UNATTENDED:
            return Decision.DENY, "approval-unavailable-for-unattended-client"
        return decision, reason

    async def get_job(
        self,
        principal: AccessPrincipal,
        job_id: str,
        context: JobContext,
    ) -> ApiResponse:
        configured, owner = await self._job_authority(principal, context.root_run_id)
        self._require_capability(configured, "jobs.status")
        typed_job_id = self._job_id(job_id)
        record = await self._jobs.load(typed_job_id, owner=owner)
        if record is None:
            raise _invalid_job()
        return ApiResponse(self._job_body(record))

    async def await_job(
        self,
        principal: AccessPrincipal,
        job_id: str,
        request: JobAwaitRequest,
    ) -> ApiResponse:
        configured, owner = await self._job_authority(principal, request.root_run_id)
        self._require_capability(configured, "jobs.await")
        typed_job_id = self._job_id(job_id)
        initial = await self._jobs.load(typed_job_id, owner=owner)
        if initial is None:
            raise _invalid_job()
        if initial.terminal:
            return ApiResponse(
                {
                    **self._job_body(initial),
                    "changed": False,
                    "timed_out": False,
                }
            )
        awaited = await self._jobs.await_update(
            typed_job_id,
            owner=owner,
            after_revision=initial.revision,
            maximum_wait_ms=request.maximum_wait_ms,
        )
        if awaited.record is None:
            raise _invalid_job()
        body: dict[str, JsonValue] = {
            **self._job_body(awaited.record),
            "changed": awaited.changed,
            "timed_out": awaited.timed_out,
        }
        pending = not awaited.record.terminal and not awaited.changed
        return ApiResponse(
            body,
            status_code=202 if pending else 200,
            retry_after_seconds=1 if pending else None,
        )

    async def cancel_job(
        self,
        principal: AccessPrincipal,
        job_id: str,
        context: JobContext,
    ) -> ApiResponse:
        configured, owner = await self._job_authority(principal, context.root_run_id)
        self._require_capability(configured, "jobs.cancel")
        record = await self._jobs.request_cancellation(
            self._job_id(job_id),
            owner=owner,
            now_ms=self._clock.now_ms(),
        )
        if record is None:
            raise _invalid_job()
        pending = not record.terminal
        return ApiResponse(
            self._job_body(record),
            status_code=202 if pending else 200,
            retry_after_seconds=1 if pending else None,
        )

    async def search_documentation(
        self,
        principal: AccessPrincipal,
        request: DocumentationSearchRequest,
    ) -> ApiResponse:
        configured = self._configured_principal(principal)
        self._require_capability(configured, "docs.search")
        service = self._documentation
        if service is None:
            raise _daemon_degraded()
        results = service.search(
            service=request.service,
            query=request.query,
            limit=request.limit,
        )
        return ApiResponse(
            {
                "service": request.service,
                "results": [
                    {
                        "source_id": result.source_id,
                        "version_id": result.version_id,
                        "heading": result.heading,
                        "excerpt": result.excerpt,
                        "source_reference": result.source_reference,
                        "trust_level": result.trust_level,
                        "retrieved_at_ms": result.retrieved_at_ms,
                        "rank": result.rank,
                    }
                    for result in results
                ],
            }
        )

    async def get_documentation(
        self,
        principal: AccessPrincipal,
        service: str,
        document: str,
    ) -> ApiResponse | None:
        configured = self._configured_principal(principal)
        self._require_capability(configured, "docs.get")
        documentation = self._documentation
        if documentation is None:
            raise _daemon_degraded()
        content = documentation.get_document(service=service, source_id=document)
        if content is None:
            return None
        return ApiResponse(
            {
                "service": service,
                "document": document,
                "content": content,
            }
        )

    async def submit_feedback(
        self,
        principal: AccessPrincipal,
        request: FeedbackSubmitRequest,
    ) -> ApiResponse:
        configured = self._configured_principal(principal)
        self._require_capability(configured, "feedback.submit")
        feedback = self._feedback
        if feedback is None:
            raise _daemon_degraded()
        content: dict[str, object] = {
            "related_request_ids": list(request.related_request_ids),
        }
        for name in ("problem", "what_worked", "suggested_improvement"):
            value = getattr(request, name)
            if value is not None:
                content[name] = value
        try:
            if self._feedback_secret_inspector is not None:
                await self._feedback_secret_inspector.reject_overlap(
                    {
                        "category": request.category,
                        "severity": request.severity,
                        "component": request.component,
                        "summary": request.summary,
                        "content": content,
                    }
                )
            record = feedback.submit(
                session_id=principal.session_id,
                category=request.category,
                severity=request.severity,
                component=request.component,
                summary=request.summary,
                content=content,
                now_ms=self._clock.now_ms(),
            )
        except SecretDetectedError as exc:
            _scrub_exception(exc)
            raise make_error(
                ErrorCode.SENSITIVE_PAYLOAD_DENIED,
                retryable=False,
            ) from None
        except ActiveSecretInspectionUnavailable as exc:
            _scrub_exception(exc)
            raise _daemon_degraded() from None
        except FeedbackCapacityExceeded as exc:
            _scrub_exception(exc)
            raise make_error(
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=60,
            ) from None
        return ApiResponse(
            {
                "feedback_id": record.feedback_id,
                "state": record.state.value,
                "created_at_ms": record.created_at_ms,
            }
        )

    def _configured_principal(self, principal: AccessPrincipal) -> _ConfiguredPrincipal:
        now_ms = self._clock.now_ms()
        if now_ms >= principal.absolute_expires_at_ms:
            raise make_error(ErrorCode.SESSION_EXPIRED, retryable=False)
        if principal.workspace_id is None:
            raise make_error(ErrorCode.ATTRIBUTED_SESSION_REQUIRED, retryable=False)
        try:
            session_id = SessionId(principal.session_id)
            client_id = ClientId(principal.client_id)
            workspace_id = WorkspaceId(principal.workspace_id)
        except (TypeError, ValueError) as error:
            raise _invalid_session() from error
        profile = self._client_profiles.get(str(client_id))
        policy = self._workspace_policies.get(str(workspace_id))
        if profile is None or policy is None:
            raise _invalid_session()
        if policy.workspace_id != str(workspace_id) or policy.version != principal.policy_version:
            raise _invalid_session()
        return _ConfiguredPrincipal(
            session_id=session_id,
            client_id=client_id,
            workspace_id=workspace_id,
            token_epoch=principal.token_epoch,
            revocation_epoch=principal.revocation_epoch,
            profile=profile,
            policy=policy,
        )

    async def _invocation_authority(
        self,
        principal: AccessPrincipal,
        root_run_id: str,
    ) -> tuple[_ConfiguredPrincipal, RootRunRecord]:
        configured = self._configured_principal(principal)
        try:
            typed_root_run_id = RootRunId(root_run_id)
        except (TypeError, ValueError) as error:
            raise _invalid_session() from error
        root_run = await self._root_runs.load_root_run(str(typed_root_run_id))
        if (
            root_run is None
            or root_run.session_id != str(configured.session_id)
            or root_run.state is not RootRunState.ACTIVE
        ):
            raise _invalid_session()
        return configured, root_run

    async def _job_authority(
        self,
        principal: AccessPrincipal,
        root_run_id: str,
    ) -> tuple[_ConfiguredPrincipal, JobOwner]:
        configured = self._configured_principal(principal)
        try:
            typed_root_run_id = RootRunId(root_run_id)
        except (TypeError, ValueError) as error:
            raise _invalid_job() from error
        root_run = await self._root_runs.load_root_run(str(typed_root_run_id))
        if root_run is None or root_run.session_id != str(configured.session_id):
            raise _invalid_job()
        return configured, JobOwner(
            session_id=configured.session_id,
            workspace_id=configured.workspace_id,
            root_run_id=typed_root_run_id,
        )

    def _available_capabilities(
        self,
        configured: _ConfiguredPrincipal,
    ) -> frozenset[str]:
        routed = set(_JOB_CAPABILITIES)
        if (
            configured.policy.service == "firecrawl"
            and "firecrawl" in configured.profile.pools.bindings
        ):
            routed.update(_INVOCATION_CAPABILITIES)
        if self._documentation is not None:
            routed.update(_DOCUMENTATION_CAPABILITIES)
        if self._feedback is not None:
            routed.update(_FEEDBACK_CAPABILITIES)
        return frozenset(configured.profile.capabilities.allow) & frozenset(routed)

    def _require_capability(
        self,
        configured: _ConfiguredPrincipal,
        capability: str,
    ) -> None:
        if capability not in self._available_capabilities(configured):
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False)

    @staticmethod
    def _policy_inputs(
        operation: str,
        payload: Mapping[str, JsonValue],
    ) -> tuple[str, frozenset[str]]:
        if operation in _RESOURCE_OPERATIONS:
            return "active_job_verification", frozenset({"public_job_data"})
        purpose = payload.get("purpose")
        classifications = payload.get("data_classification")
        if not isinstance(purpose, str) or not purpose:
            raise make_error(ErrorCode.SCHEMA_VALIDATION_FAILED, retryable=False)
        if not isinstance(classifications, list) or not classifications:
            raise make_error(ErrorCode.SCHEMA_VALIDATION_FAILED, retryable=False)
        normalized_classifications: list[str] = []
        for item in classifications:
            if not isinstance(item, str) or not item:
                raise make_error(ErrorCode.SCHEMA_VALIDATION_FAILED, retryable=False)
            normalized_classifications.append(item)
        return purpose, frozenset(normalized_classifications)

    def _invocation_session(
        self,
        configured: _ConfiguredPrincipal,
        root_run: RootRunRecord,
    ) -> InvocationSession:
        try:
            priority = PriorityClass(configured.profile.client.default_priority.upper())
        except ValueError as error:
            raise _daemon_degraded() from error
        request_limit = root_run.budget.get(
            "requests",
            configured.policy.maximum_requests_per_root_run,
        )
        credit_limit = root_run.budget.get(
            "credits",
            math.floor(configured.policy.maximum_credits_per_root_run),
        )
        requests_remaining = max(
            0,
            request_limit - root_run.consumed.get("requests", 0),
        )
        credits_remaining = max(
            0,
            credit_limit - root_run.consumed.get("credits", 0),
        )
        return InvocationSession(
            session_id=configured.session_id,
            client_id=configured.client_id,
            root_run_id=RootRunId(root_run.root_run_id),
            workspace_id=configured.workspace_id,
            client_class=(
                ClientClass.UNATTENDED
                if configured.profile.client.unattended
                else ClientClass.INTERACTIVE
            ),
            allowed_capabilities=self._available_capabilities(configured),
            pool_bindings=configured.profile.pools.bindings,
            request_count_remaining=requests_remaining,
            credit_budget_remaining_units=credits_remaining,
            request_limit=request_limit,
            approval_mode=configured.profile.client.approval_mode,
            priority=priority,
            token_epoch=configured.token_epoch,
            revocation_epoch=configured.revocation_epoch,
        )

    async def _invocation_response(
        self,
        *,
        configured: _ConfiguredPrincipal,
        request: CoordinatedInvocationRequest,
        result: InvocationResult,
    ) -> ApiResponse:
        if result.error is not None:
            if result.error.code is not ErrorCode.APPROVAL_PENDING:
                error = result.error
                if (
                    error.code is ErrorCode.RUNAWAY_SUSPECTED
                    and error.details.get("authorization_required") is True
                    and self._approval_dashboard_url is not None
                ):
                    details = dict(error.details)
                    details["dashboard_url"] = self._approval_dashboard_url
                    error = replace(error, details=details)
                raise GatehouseError(error)
            if result.approval_id is None:
                raise _daemon_degraded()
            if request.approval_id is None and self._approval_notifications is not None:
                signal = ApprovalPendingSignal(
                    approval_id=result.approval_id,
                    request_id=str(result.request_id),
                    session_id=str(configured.session_id),
                    root_run_id=str(request.root_run_id),
                    client_id=str(configured.client_id),
                    workspace_id=str(configured.workspace_id),
                    requesting_client=configured.profile.client.id,
                    service=request.service_id,
                    operation=request.operation.removeprefix(f"{request.service_id}."),
                    request_fingerprint=(
                        None if result.fingerprint is None else str(result.fingerprint)
                    ),
                )
                _submit_approval_notification(self._approval_notifications, signal)
            approval_context: dict[str, JsonValue] = {
                "root_run_id": str(request.root_run_id),
                "required_action": "decide_locally_then_retry_exact_request",
            }
            if self._approval_dashboard_url is not None:
                approval_context["dashboard_url"] = self._approval_dashboard_url
            return ApiResponse(
                {
                    "request_id": str(result.request_id),
                    "state": result.state.value,
                    "approval_id": result.approval_id,
                    "approval_context": approval_context,
                    "error": result.error.to_dict(),
                },
                status_code=202,
                retry_after_seconds=result.error.retry_after_seconds,
            )

        body: dict[str, JsonValue] = {
            "request_id": str(result.request_id),
            "state": result.state.value,
            "service": request.service_id,
            "operation": request.operation.removeprefix(f"{request.service_id}."),
            "attempts": result.attempts,
        }
        if result.state is not InvocationState.SUCCEEDED:
            return ApiResponse(body)
        if request.operation == "firecrawl.crawl.start":
            body["job_id"] = str(
                await self._create_job(configured=configured, request=request, result=result)
            )
            return ApiResponse(body)
        if result.data is not None:
            try:
                safe_data = _safe_json(result.data)
            except (TypeError, ValueError) as error:
                raise _daemon_degraded() from error
            body["result"] = {
                "source_trust": "untrusted_web_content",
                "data": safe_data,
            }
        return ApiResponse(body)

    async def _create_job(
        self,
        *,
        configured: _ConfiguredPrincipal,
        request: CoordinatedInvocationRequest,
        result: InvocationResult,
    ) -> JobId:
        provider_resource_id = result.provider_resource_id
        if provider_resource_id is None:
            raise _daemon_degraded(request_id=request.request_id)
        affinity = await self._affinities.get(
            service_id=request.service_id,
            resource_type="crawl",
            provider_resource_id=provider_resource_id,
            owner_session_id=configured.session_id,
            owner_workspace_id=configured.workspace_id,
            owner_root_run_id=request.root_run_id,
        )
        if affinity is None or affinity.creating_request_id != request.request_id:
            raise _daemon_degraded(request_id=request.request_id)
        return await self._create_job_from_affinity(
            configured=configured,
            request_id=request.request_id,
            affinity=affinity,
        )

    async def _materialize_bound_crawl(
        self,
        *,
        configured: _ConfiguredPrincipal,
        request: CoordinatedInvocationRequest,
    ) -> JobId | None:
        try:
            affinity = await self._affinities.get_by_request(
                service_id=request.service_id,
                resource_type="crawl",
                creating_request_id=request.request_id,
                owner_session_id=configured.session_id,
                owner_workspace_id=configured.workspace_id,
                owner_root_run_id=request.root_run_id,
            )
        except (TypeError, ValueError, RuntimeError) as error:
            raise _daemon_degraded(request_id=request.request_id) from error
        if affinity is None:
            return None
        return await self._create_job_from_affinity(
            configured=configured,
            request_id=request.request_id,
            affinity=affinity,
        )

    async def _create_job_from_affinity(
        self,
        *,
        configured: _ConfiguredPrincipal,
        request_id: RequestId,
        affinity: ResourceAffinity,
    ) -> JobId:
        now_ms = self._clock.now_ms()
        try:
            maximum_runtime_at_ms = require_utc_ms(
                max(now_ms, affinity.bound_at_ms)
                + int(configured.profile.client.maximum_run_duration)
            )
            record = await self._jobs.create_from_affinity(
                affinity,
                maximum_runtime_at_ms=maximum_runtime_at_ms,
                next_poll_at_ms=max(now_ms, affinity.bound_at_ms),
            )
        except (TypeError, ValueError, RuntimeError) as error:
            raise _daemon_degraded(request_id=request_id) from error
        return record.job_id

    @staticmethod
    def _job_id(value: str) -> JobId:
        try:
            return JobId(value)
        except (TypeError, ValueError) as error:
            raise _invalid_job() from error

    @staticmethod
    def _job_body(record: JobRecord) -> dict[str, JsonValue]:
        body: dict[str, JsonValue] = {
            "job_id": str(record.job_id),
            "request_id": str(record.request_id),
            "service": record.service_id,
            "operation": record.operation,
            "state": record.state.value,
            "revision": record.revision,
            "terminal": record.terminal,
            "created_at_ms": record.created_at_ms,
            "maximum_runtime_at_ms": record.maximum_runtime_at_ms,
            "completed_at_ms": record.completed_at_ms,
            "provider_status": record.provider_status,
            "provider_status_observed_at_ms": record.provider_status_observed_at_ms,
            "cancel_requested_at_ms": record.cancel_requested_at_ms,
        }
        if record.state is JobState.UNKNOWN:
            body["warning"] = "provider_outcome_unknown"
        return body
