"""Adapters from the initial typed provider and fingerprint components."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import cast

from gatehouse.fingerprint.canonical import CanonicalValue, canonical_json_bytes
from gatehouse.fingerprint.hmac import FingerprintContext, FingerprintService, RequestFingerprint
from gatehouse.policy import InspectionResult, inspect_sensitive_content
from gatehouse.providers import ProviderErrorClass, ProviderRequest, ProviderResponse
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter
from gatehouse.providers.firecrawl.models import CrawlResourceInput, StrictInput

from .models import (
    AsyncResourceReference,
    CanonicalOperation,
    ClassifiedProviderOutcome,
    InvocationRequest,
    InvocationSession,
    ValidatedOperation,
)


class DefaultFingerprintGateway:
    """Build the authorization-scoped context required by ``FingerprintService``."""

    def __init__(self, service: FingerprintService) -> None:
        self._service = service

    def calculate(
        self,
        *,
        session: InvocationSession,
        request: InvocationRequest,
        canonical: CanonicalOperation,
    ) -> RequestFingerprint:
        classifications = ",".join(sorted(request.data_classifications)) or "unclassified"
        context = FingerprintContext(
            service=request.service_id,
            operation=request.operation,
            normalized_input=canonical.canonical_input,
            workspace_scope=str(session.workspace_id),
            data_scope=classifications,
            authorization_scope=str(session.session_id),
            result_format=request.result_format,
            additional_scope={"purpose": request.purpose},
        )
        return self._service.calculate(context)


class DefaultSensitiveInspector:
    def inspect(self, payload: object) -> InspectionResult:
        return inspect_sensitive_content(payload)


class FirecrawlOperationGateway:
    """Expose the existing typed adapter through the coordinator protocol."""

    service_id = "firecrawl"

    def __init__(self, adapter: FirecrawlAdapter | None = None) -> None:
        self._adapter = adapter or FirecrawlAdapter()

    def validate(
        self,
        service_id: str,
        operation: str,
        payload: object,
    ) -> ValidatedOperation:
        if service_id != self.service_id:
            raise ValueError("operation gateway does not serve the requested service")
        validation_payload = dict(payload) if isinstance(payload, Mapping) else payload
        model = self._adapter.validate(operation, validation_payload)
        return ValidatedOperation(
            service_id=service_id,
            operation=operation,
            spec=self._adapter.operation_spec(operation),
            provider_payload=model,
        )

    def canonicalize(self, validated: ValidatedOperation) -> CanonicalOperation:
        model = validated.provider_payload
        if not isinstance(model, StrictInput):
            raise TypeError("validated provider input must be a typed model")
        dumped = model.model_dump(mode="json", exclude_none=True)
        if not isinstance(dumped, Mapping):
            raise TypeError("validated provider input must serialize to an object")
        canonical_json_bytes(dumped)
        canonical_input = cast(Mapping[str, CanonicalValue], dumped)
        target = self._adapter.canonical_target(model)
        resource_reference: AsyncResourceReference | None = None
        if isinstance(model, CrawlResourceInput):
            resource_reference = AsyncResourceReference(
                resource_type="crawl",
                provider_resource_id=model.provider_job_id,
            )
        return CanonicalOperation(
            validated=validated,
            canonical_input=canonical_input,
            canonical_target=target,
            async_resource_type="crawl" if validated.spec.asynchronous else None,
            resource_reference=resource_reference,
        )

    def build_request(
        self,
        canonical: CanonicalOperation,
        *,
        credential_id: str,
    ) -> ProviderRequest:
        payload = canonical.validated.provider_payload
        if isinstance(payload, StrictInput):
            payload = payload.model_dump(mode="json", exclude_none=True)
        return self._adapter.build_request(
            canonical.validated.operation,
            payload,
            credential_id=credential_id,
        )

    def classify_response(
        self,
        operation: str,
        response: ProviderResponse,
    ) -> ClassifiedProviderOutcome:
        outcome = self._adapter.classify_response(operation, response)
        actual_units: int | None = None
        if (
            outcome.actual_credits is not None
            and math.isfinite(outcome.actual_credits)
            and outcome.actual_credits.is_integer()
            and 0 <= outcome.actual_credits < (1 << 63)
        ):
            actual_units = int(outcome.actual_credits)
        submission_may_have_occurred = outcome.submission_may_have_occurred or (
            outcome.error_class is ProviderErrorClass.MALFORMED_RESPONSE
            and response.status_code is not None
        )
        return ClassifiedProviderOutcome(
            error_class=outcome.error_class,
            data=outcome.data,
            retry_after_seconds=outcome.retry_after_seconds,
            provider_request_id=outcome.provider_request_id,
            actual_cost_units=actual_units,
            provider_resource_id=outcome.provider_job_id,
            submission_may_have_occurred=submission_may_have_occurred,
        )
