"""Separate local administrative API and accessible dashboard factory."""

from __future__ import annotations

import hmac
import json
import math
from collections.abc import Callable, Mapping
from html import escape
from typing import Annotated, Literal
from urllib.parse import parse_qs

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError

from gatehouse.admin import (
    AccountAddRequest,
    AccountMutationResult,
    AccountObservationChangeRequest,
    AccountObservationMutationResult,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    AccountStatus,
    AdminAuthCapacityExceeded,
    AdminAuthenticationError,
    AdminAuthManager,
    AdminBackend,
    AdminLoginSession,
    AdminPrincipal,
    ApprovalActionRequest,
    ApprovalActionResult,
    ApprovalDecision,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    CredentialValidationBusy,
    CredentialValidationError,
    CredentialValidationPersistenceError,
    CredentialValidationProviderFailure,
    CredentialValidationRequest,
    CredentialValidationResult,
    CredentialValidationUnavailable,
    EmergencyUnlockCancelRequest,
    EmergencyUnlockRequest,
    RunawayBurstAuthorizeRequest,
    RunawayQuarantineActionResult,
    RunawayQuarantineDenyRequest,
)
from gatehouse.admin.dashboard import render_dashboard
from gatehouse.core.errors import ErrorCode, JsonValue, make_error
from gatehouse.credentials.lease import zero_bytearray
from gatehouse.credentials.validation import is_admissible_firecrawl_secret
from gatehouse.database.runaway import (
    RunawayQuarantineConflict,
    RunawayQuarantinePersistenceError,
)
from gatehouse.providers import ProviderErrorClass

from .contracts import StrictApiModel
from .errors import error_response, install_error_handlers, schema_error
from .middleware import AdminSecurityHeadersMiddleware, LocalRequestBoundsMiddleware

ADMIN_COOKIE_NAME = "gatehouse_admin"
CSRF_COOKIE_NAME = "gatehouse_csrf"
CSRF_HEADER_NAME = "x-gatehouse-csrf"
COMMAND_HEADER_NAME = "x-gatehouse-command"
MAXIMUM_COMMAND_BYTES = 8 * 1_024
MAXIMUM_SECRET_BYTES = 16 * 1_024
LOCAL_ACCOUNT_OPERATOR_ACTOR_ID = "local-account-operator"

_CredentialStateAction = Literal["disable", "quarantine", "retire"]
_AccountStateAction = Literal["disable", "recover", "remove"]


class _AdminBodyTooLarge(Exception):
    """Internal signal preserving the ASGI body-bound response contract."""


_VALIDATION_PROVIDER_ERROR_CODES: Mapping[ProviderErrorClass, ErrorCode] = {
    ProviderErrorClass.NONE: ErrorCode.DAEMON_DEGRADED,
    ProviderErrorClass.INVALID_REQUEST: ErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorClass.UNAUTHORIZED: ErrorCode.PROVIDER_UNAUTHORIZED,
    ProviderErrorClass.QUOTA_EXHAUSTED: ErrorCode.QUOTA_EXHAUSTED,
    ProviderErrorClass.PERMISSION_DENIED: ErrorCode.PROVIDER_PERMISSION_DENIED,
    ProviderErrorClass.NOT_FOUND: ErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorClass.TIMEOUT: ErrorCode.PROVIDER_TIMEOUT,
    ProviderErrorClass.CONFLICT: ErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorClass.RATE_LIMITED: ErrorCode.PROVIDER_RATE_LIMITED,
    ProviderErrorClass.TRANSIENT: ErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorClass.MALFORMED_RESPONSE: ErrorCode.PROVIDER_UNAVAILABLE,
    ProviderErrorClass.UNKNOWN_OUTCOME: ErrorCode.UNCERTAIN_OUTCOME,
}


def _map_credential_validation_error(error: CredentialValidationError) -> Exception:
    """Replace internal validation failures with stable, body-free API errors."""

    if isinstance(error, CredentialValidationBusy):
        return make_error(
            ErrorCode.CAPACITY_EXCEEDED,
            retryable=True,
            retry_after_seconds=1,
        )
    if isinstance(error, CredentialValidationProviderFailure):
        code = _VALIDATION_PROVIDER_ERROR_CODES.get(
            error.error_class,
            ErrorCode.DAEMON_DEGRADED,
        )
        if error.error_class in {
            ProviderErrorClass.RATE_LIMITED,
            ProviderErrorClass.TRANSIENT,
        }:
            retry_after_seconds = max(
                1,
                math.ceil(error.retry_after_seconds or 1),
            )
            return make_error(
                code,
                retryable=True,
                retry_after_seconds=retry_after_seconds,
            )
        return make_error(code, retryable=False)
    if isinstance(
        error,
        (CredentialValidationUnavailable, CredentialValidationPersistenceError),
    ):
        return make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)
    return make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)


def _defer_sensitive_admin_body(scope: Mapping[str, object]) -> bool:
    if str(scope.get("method", "")).upper() != "POST":
        return False
    path = str(scope.get("path", "")).rstrip("/")
    if path in {
        "/v1/admin/accounts",
        "/v1/admin/credentials",
        "/v1/admin/emergency-unlocks",
    }:
        return True
    segments = path.split("/")
    if len(segments) == 6 and segments[4]:
        if segments[1:4] == ["v1", "admin", "credentials"]:
            return segments[5] in {
                "rotate",
                "validate",
                "disable",
                "quarantine",
                "retire",
            }
        if segments[1:4] == ["v1", "admin", "accounts"]:
            return segments[5] in {
                "rotate",
                "disable",
                "recover",
                "remove",
                "refresh",
                "observation",
            }
        if segments[1:4] == ["v1", "admin", "emergency-unlocks"]:
            return segments[5] == "cancel"
        if segments[1:4] == ["v1", "admin", "approvals"]:
            return segments[5] in {"approve", "deny"}
        if segments[1:4] == ["v1", "admin", "runaway-quarantines"]:
            return segments[5] in {"authorize", "deny"}
    return (
        len(segments) == 5
        and bool(segments[3])
        and (
            (segments[1:3] == ["dashboard", "approvals"] and segments[4] in {"approve", "deny"})
            or (
                segments[1:3] == ["dashboard", "runaway-quarantines"]
                and segments[4] in {"authorize", "deny"}
            )
        )
    )


class AdminLoginRequest(StrictApiModel):
    code: Annotated[str, Field(min_length=40, max_length=128)]


def _set_auth_cookies(response: JSONResponse | RedirectResponse, login: AdminLoginSession) -> None:
    response.set_cookie(
        ADMIN_COOKIE_NAME,
        login.cookie,
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        login.csrf_token,
        httponly=False,
        samesite="strict",
        secure=False,
        path="/",
    )


def _single_form_value(values: Mapping[str, list[str]], name: str) -> str:
    selected = values.get(name)
    if selected is None or len(selected) != 1 or not selected[0]:
        raise schema_error(fields=[{"field": name, "type": "required"}])
    return selected[0]


async def _read_bounded_body(request: Request, *, maximum_body_bytes: int) -> bytearray:
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > maximum_body_bytes:
                raise _AdminBodyTooLarge
            body.extend(chunk)
        return body
    except BaseException:
        zero_bytearray(body)
        raise


async def _form_values(
    request: Request,
    *,
    maximum_fields: int,
    maximum_body_bytes: int | None = None,
) -> dict[str, list[str]]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type != "application/x-www-form-urlencoded":
        raise schema_error(fields=[{"field": "content-type", "type": "unsupported"}])
    raw = (
        bytearray(await request.body())
        if maximum_body_bytes is None
        else await _read_bounded_body(request, maximum_body_bytes=maximum_body_bytes)
    )
    parsed: dict[str, list[str]] | None = None
    try:
        parsed = parse_qs(
            raw.decode("utf-8"),
            keep_blank_values=False,
            strict_parsing=True,
            max_num_fields=maximum_fields,
        )
    except (UnicodeDecodeError, ValueError):
        pass
    finally:
        zero_bytearray(raw)
    if parsed is None:
        raise schema_error(fields=[{"field": "body", "type": "form"}])
    return parsed


def _command_validation_fields(error: ValidationError) -> list[dict[str, JsonValue]]:
    fields: list[dict[str, JsonValue]] = []
    for item in error.errors(include_input=False, include_context=False, include_url=False):
        location = ".".join(str(part) for part in item.get("loc", ()))
        fields.append(
            {
                "field": f"command.{location}" if location else "command",
                "type": str(item.get("type", "validation_error")),
            }
        )
    return fields


def _body_validation_fields(error: ValidationError) -> list[dict[str, JsonValue]]:
    fields: list[dict[str, JsonValue]] = []
    for item in error.errors(include_input=False, include_context=False, include_url=False):
        location = ".".join(str(part) for part in item.get("loc", ()))
        fields.append(
            {
                "field": f"body.{location}" if location else "body",
                "type": str(item.get("type", "validation_error")),
            }
        )
    return fields


def _contains_active_secret(value: object, secret: bytearray) -> bool:
    """Fail closed if a result tries to reflect the currently supplied secret."""

    if not secret:
        return False
    if isinstance(value, str):
        encoded = bytearray(value.encode("utf-8", "surrogatepass"))
        try:
            return encoded.find(secret) >= 0
        finally:
            zero_bytearray(encoded)
    if value is None:
        encoded = bytearray(b"null")
        try:
            return encoded.find(secret) >= 0
        finally:
            zero_bytearray(encoded)
    if isinstance(value, (bool, int, float)):
        encoded = bytearray(json.dumps(value, separators=(",", ":")).encode("ascii"))
        try:
            return encoded.find(secret) >= 0
        finally:
            zero_bytearray(encoded)
    if isinstance(value, Mapping):
        return any(
            _contains_active_secret(key, secret) or _contains_active_secret(item, secret)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_active_secret(item, secret) for item in value)
    return False


def _request_metadata_contains_active_secret(request: Request, secret: bytearray) -> bool:
    """Check the actual non-body ASGI surfaces before handing off a secret."""

    if not secret:
        return False
    surfaces: list[bytes] = []
    method = str(request.scope.get("method", ""))
    surfaces.append(method.encode("ascii", "strict"))
    raw_path = request.scope.get("raw_path")
    if isinstance(raw_path, bytes):
        surfaces.append(raw_path)
    else:
        surfaces.append(str(request.scope.get("path", "")).encode("utf-8", "surrogatepass"))
    query_string = request.scope.get("query_string")
    if isinstance(query_string, bytes):
        surfaces.append(query_string)
    raw_headers = request.scope.get("headers")
    if isinstance(raw_headers, (list, tuple)):
        for item in raw_headers:
            if (
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], bytes)
                and isinstance(item[1], bytes)
            ):
                surfaces.extend(item)
    return any(surface.find(secret) >= 0 for surface in surfaces)


def _serialized_json_contains_active_secret(
    content: Mapping[str, object],
    secret: bytearray,
) -> bool:
    """Match Starlette's compact JSON encoding before constructing a response."""

    if not secret:
        return False
    encoded = bytearray(
        json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    try:
        return encoded.find(secret) >= 0
    finally:
        zero_bytearray(encoded)


def _validated_account_status(
    value: AccountStatus,
    *,
    expected_alias: str | None = None,
) -> dict[str, object]:
    raw: dict[str, object] | None = None
    try:
        raw = value.model_dump(mode="json")
        validated = AccountStatus.model_validate(raw)
    except (AttributeError, TypeError, ValidationError):
        if raw is not None:
            raw.clear()
        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from None
    if expected_alias is not None and validated.alias != expected_alias:
        raw.clear()
        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)
    content = validated.model_dump(mode="json")
    raw.clear()
    return content


def _validated_account_mutation(
    value: AccountMutationResult,
    *,
    expected_alias: str,
    expected_action: str,
    expected_pool_alias: str | None = None,
    expected_priority: int | None = None,
) -> dict[str, object]:
    raw: dict[str, object] | None = None
    try:
        raw = value.model_dump(mode="json")
        validated = AccountMutationResult.model_validate(raw)
    except (AttributeError, TypeError, ValidationError):
        if raw is not None:
            raw.clear()
        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from None
    if (
        validated.alias != expected_alias
        or validated.action != expected_action
        or (expected_pool_alias is not None and validated.pool_alias != expected_pool_alias)
        or (expected_priority is not None and validated.priority != expected_priority)
    ):
        raw.clear()
        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)
    content = validated.model_dump(mode="json")
    raw.clear()
    return content


def _validated_account_observation_mutation(
    value: AccountObservationMutationResult,
    *,
    expected_alias: str,
    expected_action: str,
) -> dict[str, object]:
    raw: dict[str, object] | None = None
    try:
        raw = value.model_dump(mode="json")
        validated = AccountObservationMutationResult.model_validate(raw)
    except (AttributeError, TypeError, ValidationError):
        if raw is not None:
            raw.clear()
        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from None
    if validated.alias != expected_alias or validated.action != expected_action:
        raw.clear()
        raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)
    content = validated.model_dump(mode="json")
    raw.clear()
    return content


async def _parse_json_body[BodyModel: BaseModel](
    request: Request,
    model: type[BodyModel],
    *,
    maximum_body_bytes: int,
) -> BodyModel:
    raw = await _read_bounded_body(request, maximum_body_bytes=maximum_body_bytes)
    content_type = request.headers.get("content-type")
    media_type = "" if content_type is None else content_type.partition(";")[0].strip().casefold()
    parse_as_json = (
        content_type is None or media_type == "application/json" or media_type.endswith("+json")
    )
    body: BodyModel | None = None
    validation_fields: list[dict[str, JsonValue]] | None = None
    try:
        if not raw:
            validation_fields = [{"field": "body", "type": "missing"}]
        else:
            try:
                body = (
                    model.model_validate_json(raw)
                    if parse_as_json
                    else model.model_validate(bytes(raw))
                )
            except ValidationError as exc:
                validation_fields = _body_validation_fields(exc)
    finally:
        zero_bytearray(raw)
    if body is None:
        raise schema_error(fields=validation_fields or [{"field": "body", "type": "invalid"}])
    return body


def _parse_command[CommandModel: BaseModel](
    request: Request,
    model: type[CommandModel],
) -> CommandModel:
    values = request.headers.getlist(COMMAND_HEADER_NAME)
    if len(values) != 1 or not values[0]:
        raise schema_error(fields=[{"field": COMMAND_HEADER_NAME, "type": "required"}])
    raw = values[0]
    if len(raw.encode("utf-8")) > MAXIMUM_COMMAND_BYTES:
        raise schema_error(fields=[{"field": COMMAND_HEADER_NAME, "type": "too_long"}])
    decoded: object | None = None
    json_valid = True
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        json_valid = False
    if not json_valid:
        raw = ""
        raise schema_error(fields=[{"field": "command", "type": "json"}])
    if not isinstance(decoded, dict):
        raise schema_error(fields=[{"field": "command", "type": "object"}])
    command: CommandModel | None = None
    validation_fields: list[dict[str, JsonValue]] | None = None
    try:
        command = model.model_validate(decoded)
    except ValidationError as exc:
        validation_fields = _command_validation_fields(exc)
        decoded.clear()
    if command is None:
        raise schema_error(fields=validation_fields or [{"field": "command", "type": "invalid"}])
    return command


async def _read_secret_body(request: Request) -> bytearray:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type.casefold() != "application/octet-stream":
        raise schema_error(fields=[{"field": "content-type", "type": "unsupported"}])
    secret = bytearray()
    try:
        async for chunk in request.stream():
            if len(secret) + len(chunk) > MAXIMUM_SECRET_BYTES:
                raise schema_error(fields=[{"field": "body", "type": "too_long"}])
            secret.extend(chunk)
        if not secret:
            raise schema_error(fields=[{"field": "body", "type": "required"}])
        if not is_admissible_firecrawl_secret(secret, maximum_bytes=MAXIMUM_SECRET_BYTES):
            raise schema_error(fields=[{"field": "body", "type": "credential_format"}])
        return secret
    except BaseException:
        zero_bytearray(secret)
        raise


async def _require_empty_body(request: Request, *, maximum_body_bytes: int) -> None:
    observed = 0
    async for chunk in request.stream():
        observed += len(chunk)
        if observed > maximum_body_bytes:
            raise schema_error(fields=[{"field": "body", "type": "too_long"}])
        if chunk:
            raise schema_error(fields=[{"field": "body", "type": "empty"}])


def create_admin_app(
    *,
    auth: AdminAuthManager,
    backend: AdminBackend,
    now_ms: Callable[[], int],
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:47622", "localhost:47622"),
    maximum_body_bytes: int = 32 * 1_024,
) -> FastAPI:
    allowed_origins = {
        f"{scheme}://{host.casefold().rstrip('.')}"
        for scheme in ("http", "https")
        for host in allowed_hosts
    }
    app = FastAPI(title="Gatehouse Admin API", docs_url=None, redoc_url=None)
    app.add_middleware(AdminSecurityHeadersMiddleware)
    app.add_middleware(
        LocalRequestBoundsMiddleware,
        allowed_hosts=allowed_hosts,
        maximum_body_bytes=maximum_body_bytes,
        defer_body_read=_defer_sensitive_admin_body,
    )
    install_error_handlers(app)

    @app.exception_handler(_AdminBodyTooLarge)
    async def admin_body_too_large(_: Request, __: Exception) -> JSONResponse:
        return error_response(schema_error(), status_code=413)

    def validate_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is None or origin.casefold().rstrip("/") not in allowed_origins:
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False)

    async def authenticate_admin(
        request: Request,
        *,
        require_csrf: bool = False,
        csrf_token: str | None = None,
    ) -> AdminPrincipal:
        if request.headers.get("authorization") is not None:
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False)
        cookie = request.cookies.get(ADMIN_COOKIE_NAME)
        if cookie is None:
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False)
        if require_csrf:
            validate_origin(request)
            csrf_token = csrf_token or request.headers.get(CSRF_HEADER_NAME)
        try:
            return await auth.authenticate(
                cookie,
                csrf_token=csrf_token,
                require_csrf=require_csrf,
            )
        except AdminAuthenticationError as exc:
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False) from exc

    async def exchange_code(code: str) -> AdminLoginSession:
        try:
            return await auth.exchange_login_code(code)
        except AdminAuthenticationError as exc:
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False) from exc
        except AdminAuthCapacityExceeded as exc:
            raise make_error(
                ErrorCode.CAPACITY_EXCEEDED,
                retryable=True,
                retry_after_seconds=5,
            ) from exc

    async def approval_action(
        approval_id: str,
        body: ApprovalActionRequest,
        decision: ApprovalDecision,
    ) -> ApprovalActionResult:
        approval = await backend.get_approval(approval_id)
        if approval is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        now = now_ms()
        if approval.expires_at_ms <= now or approval.state.casefold() != "pending":
            raise make_error(ErrorCode.APPROVAL_EXPIRED, retryable=False)
        matches = (
            hmac.compare_digest(body.action_token, approval.action_token)
            and hmac.compare_digest(
                body.request_fingerprint,
                approval.request_fingerprint,
            )
            and body.maximum_estimated_cost == approval.maximum_estimated_cost
            and body.maximum_uses == approval.maximum_uses == 1
        )
        if not matches:
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False)
        return await backend.decide_approval(
            approval=approval,
            decision=decision,
            now_ms=now,
        )

    async def authorize_runaway_action(
        quarantine_id: str,
        body: RunawayBurstAuthorizeRequest,
        actor_id: str,
    ) -> RunawayQuarantineActionResult:
        quarantine = await backend.get_runaway_quarantine(quarantine_id)
        if quarantine is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        if quarantine.generation != body.expected_generation or not hmac.compare_digest(
            quarantine.action_token, body.action_token
        ):
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False)
        try:
            return await backend.authorize_runaway_burst(
                quarantine_id,
                body,
                actor_id,
                now_ms(),
            )
        except RunawayQuarantineConflict as exc:
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False) from exc
        except RunawayQuarantinePersistenceError as exc:
            raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from exc
        except ValueError as exc:
            raise make_error(ErrorCode.SCHEMA_VALIDATION_FAILED, retryable=False) from exc

    async def deny_runaway_action(
        quarantine_id: str,
        body: RunawayQuarantineDenyRequest,
        actor_id: str,
    ) -> RunawayQuarantineActionResult:
        quarantine = await backend.get_runaway_quarantine(quarantine_id)
        if quarantine is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        if quarantine.generation != body.expected_generation or not hmac.compare_digest(
            quarantine.action_token, body.action_token
        ):
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False)
        try:
            return await backend.deny_runaway_quarantine(
                quarantine_id,
                body,
                actor_id,
                now_ms(),
            )
        except RunawayQuarantineConflict as exc:
            raise make_error(ErrorCode.POLICY_DENIED, retryable=False) from exc
        except RunawayQuarantinePersistenceError as exc:
            raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from exc
        except ValueError as exc:
            raise make_error(ErrorCode.SCHEMA_VALIDATION_FAILED, retryable=False) from exc

    @app.get("/login")
    async def login_page(
        code: Annotated[str, Query(min_length=40, max_length=128)],
    ) -> HTMLResponse:
        return HTMLResponse(
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>Gatehouse admin sign in</title><main><h1>Gatehouse admin sign in</h1>"
            "<p>Continue only if you requested this local administrative session.</p>"
            '<form method="post" action="/login">'
            f'<input type="hidden" name="code" value="{escape(code)}">'
            '<button type="submit">Continue to dashboard</button></form></main></html>'
        )

    @app.post("/login")
    async def browser_login(request: Request) -> RedirectResponse:
        values = await _form_values(request, maximum_fields=1)
        login = await exchange_code(_single_form_value(values, "code"))
        response = RedirectResponse("/dashboard", status_code=303)
        _set_auth_cookies(response, login)
        return response

    @app.post("/v1/admin/login/exchange")
    async def login_exchange(body: AdminLoginRequest) -> JSONResponse:
        login = await exchange_code(body.code)
        response = JSONResponse(
            content={
                "admin_session_id": login.admin_session_id,
                "csrf_token": login.csrf_token,
                "idle_expires_at_ms": login.idle_expires_at_ms,
                "absolute_expires_at_ms": login.absolute_expires_at_ms,
            }
        )
        _set_auth_cookies(response, login)
        return response

    @app.post("/v1/admin/logout")
    async def logout(request: Request) -> JSONResponse:
        await authenticate_admin(request, require_csrf=True)
        cookie = request.cookies.get(ADMIN_COOKIE_NAME, "")
        await auth.revoke(cookie)
        response = JSONResponse(content={"state": "logged_out"})
        response.delete_cookie(ADMIN_COOKIE_NAME, path="/")
        response.delete_cookie(CSRF_COOKIE_NAME, path="/")
        return response

    @app.get("/v1/admin/status")
    async def status(request: Request) -> JSONResponse:
        await authenticate_admin(request)
        return JSONResponse(content=(await backend.status()).model_dump(mode="json"))

    @app.get("/v1/admin/approvals")
    async def approvals(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> JSONResponse:
        await authenticate_admin(request)
        records = await backend.list_approvals(limit=limit)
        return JSONResponse(
            content={"approvals": [item.model_dump(mode="json") for item in records]}
        )

    @app.get("/v1/admin/approvals/{approval_id}")
    async def approval(request: Request, approval_id: str) -> JSONResponse:
        await authenticate_admin(request)
        record = await backend.get_approval(approval_id)
        if record is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        return JSONResponse(content=record.model_dump(mode="json"))

    async def json_decision(
        request: Request,
        approval_id: str,
        decision: ApprovalDecision,
    ) -> JSONResponse:
        await authenticate_admin(request, require_csrf=True)
        body = await _parse_json_body(
            request,
            ApprovalActionRequest,
            maximum_body_bytes=maximum_body_bytes,
        )
        result = await approval_action(approval_id, body, decision)
        return JSONResponse(content=result.model_dump(mode="json"))

    @app.post("/v1/admin/approvals/{approval_id}/approve")
    async def approve(
        request: Request,
        approval_id: str,
    ) -> JSONResponse:
        return await json_decision(request, approval_id, ApprovalDecision.APPROVE)

    @app.post("/v1/admin/approvals/{approval_id}/deny")
    async def deny(
        request: Request,
        approval_id: str,
    ) -> JSONResponse:
        return await json_decision(request, approval_id, ApprovalDecision.DENY)

    @app.get("/v1/admin/runaway-quarantines")
    async def runaway_quarantines(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> JSONResponse:
        await authenticate_admin(request)
        records = await backend.list_runaway_quarantines(limit=limit)
        return JSONResponse(
            content={"runaway_quarantines": [item.model_dump(mode="json") for item in records]}
        )

    @app.get("/v1/admin/runaway-quarantines/{quarantine_id}")
    async def runaway_quarantine(request: Request, quarantine_id: str) -> JSONResponse:
        await authenticate_admin(request)
        record = await backend.get_runaway_quarantine(quarantine_id)
        if record is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        return JSONResponse(content=record.model_dump(mode="json"))

    @app.post("/v1/admin/runaway-quarantines/{quarantine_id}/authorize")
    async def authorize_runaway_burst(
        request: Request,
        quarantine_id: str,
    ) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        body = await _parse_json_body(
            request,
            RunawayBurstAuthorizeRequest,
            maximum_body_bytes=maximum_body_bytes,
        )
        result = await authorize_runaway_action(
            quarantine_id,
            body,
            principal.admin_session_id,
        )
        return JSONResponse(content=result.model_dump(mode="json"))

    @app.post("/v1/admin/runaway-quarantines/{quarantine_id}/deny")
    async def deny_runaway_quarantine(
        request: Request,
        quarantine_id: str,
    ) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        body = await _parse_json_body(
            request,
            RunawayQuarantineDenyRequest,
            maximum_body_bytes=maximum_body_bytes,
        )
        result = await deny_runaway_action(
            quarantine_id,
            body,
            principal.admin_session_id,
        )
        return JSONResponse(content=result.model_dump(mode="json"))

    @app.get("/v1/admin/accounts")
    async def accounts(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> JSONResponse:
        await authenticate_admin(request)
        records = await backend.list_accounts(limit=limit)
        return JSONResponse(
            content={
                "accounts": [_validated_account_status(item) for item in records],
            }
        )

    @app.get("/v1/admin/accounts/{alias}")
    async def account_status(request: Request, alias: str) -> JSONResponse:
        await authenticate_admin(request)
        record = await backend.get_account_status(alias)
        if record is None:
            raise make_error(ErrorCode.INVALID_TARGET, retryable=False)
        return JSONResponse(content=_validated_account_status(record, expected_alias=alias))

    @app.post("/v1/admin/accounts")
    async def add_account(request: Request) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, AccountAddRequest)
        secret = await _read_secret_body(request)
        response_secret = bytearray()
        input_reflects_secret = False
        backend_failed = False
        response_content: dict[str, object] | None = None
        try:
            command_content = command.model_dump(mode="json")
            input_reflects_secret = _contains_active_secret(
                (command_content, principal.admin_session_id),
                secret,
            ) or _request_metadata_contains_active_secret(request, secret)
            command_content.clear()
            if not input_reflects_secret:
                response_secret.extend(secret)
                result = await backend.add_account(
                    command,
                    secret,
                    LOCAL_ACCOUNT_OPERATOR_ACTOR_ID,
                )
                dumped = _validated_account_mutation(
                    result,
                    expected_alias=command.alias,
                    expected_action="add",
                    expected_pool_alias=command.pool_alias,
                    expected_priority=command.priority,
                )
                if _contains_active_secret(
                    dumped, response_secret
                ) or _serialized_json_contains_active_secret(dumped, response_secret):
                    dumped.clear()
                    del result
                    backend_failed = True
                else:
                    response_content = dumped
        except Exception:
            backend_failed = True
        finally:
            zero_bytearray(secret)
            zero_bytearray(response_secret)
        if input_reflects_secret:
            del command
            raise schema_error(fields=[{"field": "command", "type": "secret_overlap"}])
        if backend_failed or response_content is None:
            raise make_error(
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=1,
            )
        return JSONResponse(status_code=201, content=response_content)

    @app.post("/v1/admin/accounts/{alias}/rotate")
    async def rotate_account(request: Request, alias: str) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, AccountRotationRequest)
        secret = await _read_secret_body(request)
        response_secret = bytearray()
        input_reflects_secret = False
        backend_failed = False
        response_content: dict[str, object] | None = None
        try:
            command_content = command.model_dump(mode="json")
            input_reflects_secret = _contains_active_secret(
                (command_content, alias, principal.admin_session_id),
                secret,
            ) or _request_metadata_contains_active_secret(request, secret)
            command_content.clear()
            if not input_reflects_secret:
                response_secret.extend(secret)
                result = await backend.rotate_account(
                    alias,
                    command,
                    secret,
                    LOCAL_ACCOUNT_OPERATOR_ACTOR_ID,
                )
                dumped = _validated_account_mutation(
                    result,
                    expected_alias=alias,
                    expected_action="rotate",
                )
                if _contains_active_secret(
                    dumped, response_secret
                ) or _serialized_json_contains_active_secret(dumped, response_secret):
                    dumped.clear()
                    del result
                    backend_failed = True
                else:
                    response_content = dumped
        except Exception:
            backend_failed = True
        finally:
            zero_bytearray(secret)
            zero_bytearray(response_secret)
        if input_reflects_secret:
            del command
            raise schema_error(fields=[{"field": "command", "type": "secret_overlap"}])
        if backend_failed or response_content is None:
            raise make_error(
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=1,
            )
        return JSONResponse(content=response_content)

    async def account_state_change(
        request: Request,
        alias: str,
        action: _AccountStateAction,
    ) -> JSONResponse:
        await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, AccountStateChangeRequest)
        if command.action != action:
            raise schema_error(fields=[{"field": "command.action", "type": "literal"}])
        await _require_empty_body(request, maximum_body_bytes=maximum_body_bytes)
        result = await backend.change_account_state(
            alias,
            command,
            LOCAL_ACCOUNT_OPERATOR_ACTOR_ID,
        )
        return JSONResponse(
            content=_validated_account_mutation(
                result,
                expected_alias=alias,
                expected_action=action,
            )
        )

    @app.post("/v1/admin/accounts/{alias}/disable")
    async def disable_account(request: Request, alias: str) -> JSONResponse:
        return await account_state_change(request, alias, "disable")

    @app.post("/v1/admin/accounts/{alias}/recover")
    async def recover_account(request: Request, alias: str) -> JSONResponse:
        return await account_state_change(request, alias, "recover")

    @app.post("/v1/admin/accounts/{alias}/remove")
    async def remove_account(request: Request, alias: str) -> JSONResponse:
        return await account_state_change(request, alias, "remove")

    @app.post("/v1/admin/accounts/{alias}/refresh")
    async def refresh_account(request: Request, alias: str) -> JSONResponse:
        await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, AccountRefreshRequest)
        await _require_empty_body(request, maximum_body_bytes=maximum_body_bytes)
        result = await backend.refresh_account(
            alias,
            command,
            LOCAL_ACCOUNT_OPERATOR_ACTOR_ID,
        )
        return JSONResponse(content=_validated_account_status(result, expected_alias=alias))

    @app.post("/v1/admin/accounts/{alias}/observation")
    async def change_account_observation(request: Request, alias: str) -> JSONResponse:
        await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, AccountObservationChangeRequest)
        await _require_empty_body(request, maximum_body_bytes=maximum_body_bytes)
        result = await backend.change_account_observation(
            alias,
            command,
            LOCAL_ACCOUNT_OPERATOR_ACTOR_ID,
        )
        return JSONResponse(
            content=_validated_account_observation_mutation(
                result,
                expected_alias=alias,
                expected_action=command.action,
            )
        )

    @app.get("/v1/admin/pools")
    async def pools(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> JSONResponse:
        await authenticate_admin(request)
        return JSONResponse(
            content={
                "pools": [
                    item.model_dump(mode="json") for item in await backend.list_pools(limit=limit)
                ]
            }
        )

    @app.get("/v1/admin/credentials")
    async def credentials(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> JSONResponse:
        await authenticate_admin(request)
        return JSONResponse(
            content={
                "credentials": [
                    item.model_dump(mode="json")
                    for item in await backend.list_credentials(limit=limit)
                ]
            }
        )

    @app.post("/v1/admin/credentials")
    async def provision_credential(request: Request) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, CredentialProvisionRequest)
        secret = await _read_secret_body(request)
        response_secret = bytearray()
        input_reflects_secret = False
        backend_failed = False
        response_content: dict[str, object] | None = None
        try:
            command_content = command.model_dump(mode="json")
            input_reflects_secret = _contains_active_secret(
                (command_content, principal.admin_session_id),
                secret,
            ) or _request_metadata_contains_active_secret(request, secret)
            command_content.clear()
            if not input_reflects_secret:
                response_secret.extend(secret)
                result = await backend.provision_credential(
                    command,
                    secret,
                    principal.admin_session_id,
                )
                dumped = result.model_dump(mode="json")
                if _contains_active_secret(
                    dumped, response_secret
                ) or _serialized_json_contains_active_secret(dumped, response_secret):
                    dumped.clear()
                    del result
                    backend_failed = True
                else:
                    response_content = dumped
        except Exception:
            backend_failed = True
        finally:
            zero_bytearray(secret)
            zero_bytearray(response_secret)
        if input_reflects_secret:
            del command
            raise schema_error(fields=[{"field": "command", "type": "secret_overlap"}])
        if backend_failed or response_content is None:
            raise make_error(
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=1,
            )
        return JSONResponse(
            status_code=201,
            content=response_content,
        )

    @app.post("/v1/admin/credentials/{credential_id}/rotate")
    async def rotate_credential(request: Request, credential_id: str) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, CredentialRotationRequest)
        secret = await _read_secret_body(request)
        response_secret = bytearray()
        input_reflects_secret = False
        backend_failed = False
        response_content: dict[str, object] | None = None
        try:
            command_content = command.model_dump(mode="json")
            input_reflects_secret = _contains_active_secret(
                (command_content, credential_id, principal.admin_session_id),
                secret,
            ) or _request_metadata_contains_active_secret(request, secret)
            command_content.clear()
            if not input_reflects_secret:
                response_secret.extend(secret)
                result = await backend.rotate_credential(
                    credential_id,
                    command,
                    secret,
                    principal.admin_session_id,
                )
                dumped = result.model_dump(mode="json")
                if _contains_active_secret(
                    dumped, response_secret
                ) or _serialized_json_contains_active_secret(dumped, response_secret):
                    dumped.clear()
                    del result
                    backend_failed = True
                else:
                    response_content = dumped
        except Exception:
            backend_failed = True
        finally:
            zero_bytearray(secret)
            zero_bytearray(response_secret)
        if input_reflects_secret:
            del command
            raise schema_error(fields=[{"field": "command", "type": "secret_overlap"}])
        if backend_failed or response_content is None:
            raise make_error(
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=1,
            )
        return JSONResponse(content=response_content)

    @app.post("/v1/admin/credentials/{credential_id}/validate")
    async def validate_credential(request: Request, credential_id: str) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, CredentialValidationRequest)
        await _require_empty_body(request, maximum_body_bytes=maximum_body_bytes)
        try:
            result = await backend.validate_credential(
                credential_id,
                command,
                principal.admin_session_id,
            )
        except CredentialValidationError as error:
            raise _map_credential_validation_error(error) from None
        try:
            validated = CredentialValidationResult.model_validate(result.model_dump(mode="json"))
        except (AttributeError, TypeError, ValidationError):
            raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from None
        if (
            validated.credential_id != credential_id
            or validated.generation != command.expected_generation
        ):
            raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False)
        content = validated.model_dump(mode="json")
        return JSONResponse(content=content)

    async def credential_state_change(
        request: Request,
        credential_id: str,
        action: _CredentialStateAction,
    ) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, CredentialStateChangeRequest)
        if command.action != action:
            raise schema_error(fields=[{"field": "command.action", "type": "literal"}])
        await _require_empty_body(request, maximum_body_bytes=maximum_body_bytes)
        result = await backend.change_credential_state(
            credential_id,
            command,
            principal.admin_session_id,
        )
        return JSONResponse(content=result.model_dump(mode="json"))

    @app.post("/v1/admin/credentials/{credential_id}/disable")
    async def disable_credential(request: Request, credential_id: str) -> JSONResponse:
        return await credential_state_change(
            request,
            credential_id,
            "disable",
        )

    @app.post("/v1/admin/credentials/{credential_id}/quarantine")
    async def quarantine_credential(request: Request, credential_id: str) -> JSONResponse:
        return await credential_state_change(
            request,
            credential_id,
            "quarantine",
        )

    @app.post("/v1/admin/credentials/{credential_id}/retire")
    async def retire_credential(request: Request, credential_id: str) -> JSONResponse:
        return await credential_state_change(
            request,
            credential_id,
            "retire",
        )

    @app.post("/v1/admin/emergency-unlocks")
    async def unlock_emergency(request: Request) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, EmergencyUnlockRequest)
        secret = await _read_secret_body(request)
        response_secret = bytearray()
        input_reflects_secret = False
        backend_failed = False
        response_content: dict[str, object] | None = None
        try:
            command_content = command.model_dump(mode="json")
            input_reflects_secret = _contains_active_secret(
                (command_content, principal.admin_session_id),
                secret,
            ) or _request_metadata_contains_active_secret(request, secret)
            command_content.clear()
            if not input_reflects_secret:
                response_secret.extend(secret)
                result = await backend.unlock_emergency(
                    command,
                    secret,
                    principal.admin_session_id,
                )
                dumped = result.model_dump(mode="json")
                if _contains_active_secret(
                    dumped, response_secret
                ) or _serialized_json_contains_active_secret(dumped, response_secret):
                    dumped.clear()
                    del result
                    backend_failed = True
                else:
                    response_content = dumped
        except Exception:
            backend_failed = True
        finally:
            zero_bytearray(secret)
            zero_bytearray(response_secret)
        if input_reflects_secret:
            del command
            raise schema_error(fields=[{"field": "command", "type": "secret_overlap"}])
        if backend_failed or response_content is None:
            raise make_error(
                ErrorCode.DAEMON_DEGRADED,
                retryable=True,
                retry_after_seconds=1,
            )
        return JSONResponse(
            status_code=201,
            content=response_content,
        )

    @app.get("/v1/admin/emergency-unlocks")
    async def emergency_unlocks(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> JSONResponse:
        await authenticate_admin(request)
        records = await backend.list_emergency_unlocks(limit=limit)
        return JSONResponse(
            content={"emergency_unlocks": [item.model_dump(mode="json") for item in records]}
        )

    @app.post("/v1/admin/emergency-unlocks/{unlock_id}/cancel")
    async def cancel_emergency_unlock(request: Request, unlock_id: str) -> JSONResponse:
        principal = await authenticate_admin(request, require_csrf=True)
        command = _parse_command(request, EmergencyUnlockCancelRequest)
        await _require_empty_body(request, maximum_body_bytes=maximum_body_bytes)
        result = await backend.cancel_emergency_unlock(
            unlock_id,
            command,
            principal.admin_session_id,
        )
        return JSONResponse(content=result.model_dump(mode="json"))

    @app.get("/v1/admin/incidents")
    async def incidents(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> JSONResponse:
        await authenticate_admin(request)
        return JSONResponse(
            content={
                "incidents": [
                    item.model_dump(mode="json")
                    for item in await backend.list_incidents(limit=limit)
                ]
            }
        )

    @app.get("/v1/admin/reconciliation")
    async def reconciliation(request: Request) -> JSONResponse:
        await authenticate_admin(request)
        return JSONResponse(
            content={
                "reconciliation": [
                    item.model_dump(mode="json") for item in await backend.reconciliation()
                ]
            }
        )

    @app.get("/dashboard")
    async def dashboard(request: Request) -> HTMLResponse:
        await authenticate_admin(request)
        csrf_token = request.cookies.get(CSRF_COOKIE_NAME)
        if csrf_token is None:
            raise make_error(ErrorCode.INVALID_SESSION, retryable=False)
        status_record = await backend.status()
        approval_records = await backend.list_approvals(limit=25)
        runaway_records = await backend.list_runaway_quarantines(limit=25)
        return HTMLResponse(
            render_dashboard(
                status=status_record,
                approvals=approval_records,
                csrf_token=csrf_token,
                runaway_quarantines=runaway_records,
            )
        )

    async def dashboard_decision(
        request: Request,
        approval_id: str,
        decision: ApprovalDecision,
    ) -> RedirectResponse:
        validate_origin(request)
        await authenticate_admin(request)
        values = await _form_values(
            request,
            maximum_fields=6,
            maximum_body_bytes=maximum_body_bytes,
        )
        csrf_token = _single_form_value(values, "csrf_token")
        await authenticate_admin(request, require_csrf=True, csrf_token=csrf_token)
        body: ApprovalActionRequest | None = None
        validation_fields: list[dict[str, JsonValue]] | None = None
        try:
            maximum_cost: int | None = None
            maximum_uses: int | None = None
            try:
                maximum_cost = int(_single_form_value(values, "maximum_estimated_cost"))
                maximum_uses = int(_single_form_value(values, "maximum_uses"))
            except ValueError:
                validation_fields = [{"field": "approval", "type": "integer"}]
            if validation_fields is None and maximum_uses != 1:
                validation_fields = [{"field": "maximum_uses", "type": "literal"}]
            if validation_fields is None:
                assert maximum_cost is not None
                try:
                    body = ApprovalActionRequest(
                        action_token=_single_form_value(values, "action_token"),
                        request_fingerprint=_single_form_value(values, "request_fingerprint"),
                        maximum_estimated_cost=maximum_cost,
                        maximum_uses=1,
                    )
                except ValidationError as exc:
                    validation_fields = _body_validation_fields(exc)
        finally:
            values.clear()
        if body is None:
            raise schema_error(
                fields=validation_fields or [{"field": "approval", "type": "invalid"}]
            )
        await approval_action(approval_id, body, decision)
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/dashboard/approvals/{approval_id}/approve")
    async def dashboard_approve(request: Request, approval_id: str) -> RedirectResponse:
        return await dashboard_decision(request, approval_id, ApprovalDecision.APPROVE)

    @app.post("/dashboard/approvals/{approval_id}/deny")
    async def dashboard_deny(request: Request, approval_id: str) -> RedirectResponse:
        return await dashboard_decision(request, approval_id, ApprovalDecision.DENY)

    async def dashboard_runaway_authorize(
        request: Request,
        quarantine_id: str,
    ) -> RedirectResponse:
        validate_origin(request)
        principal = await authenticate_admin(request)
        values = await _form_values(
            request,
            maximum_fields=16,
            maximum_body_bytes=maximum_body_bytes,
        )
        csrf_token = _single_form_value(values, "csrf_token")
        await authenticate_admin(request, require_csrf=True, csrf_token=csrf_token)
        body: RunawayBurstAuthorizeRequest | None = None
        validation_fields: list[dict[str, JsonValue]] | None = None
        try:
            try:
                body = RunawayBurstAuthorizeRequest(
                    action_token=_single_form_value(values, "action_token"),
                    expected_generation=int(_single_form_value(values, "expected_generation")),
                    reason=_single_form_value(values, "reason"),
                    duration_ms=int(_single_form_value(values, "duration_ms")),
                    maximum_requests=int(_single_form_value(values, "maximum_requests")),
                    maximum_credits=int(_single_form_value(values, "maximum_credits")),
                    maximum_concurrency=int(_single_form_value(values, "maximum_concurrency")),
                    operations=tuple(values.get("operations", ())),
                )
            except ValidationError as exc:
                validation_fields = _body_validation_fields(exc)
            except ValueError:
                validation_fields = [{"field": "runaway_authorization", "type": "integer"}]
        finally:
            values.clear()
        if body is None:
            raise schema_error(
                fields=validation_fields or [{"field": "runaway_authorization", "type": "invalid"}]
            )
        await authorize_runaway_action(
            quarantine_id,
            body,
            principal.admin_session_id,
        )
        return RedirectResponse("/dashboard", status_code=303)

    async def dashboard_runaway_deny_action(
        request: Request,
        quarantine_id: str,
    ) -> RedirectResponse:
        validate_origin(request)
        principal = await authenticate_admin(request)
        values = await _form_values(
            request,
            maximum_fields=4,
            maximum_body_bytes=maximum_body_bytes,
        )
        csrf_token = _single_form_value(values, "csrf_token")
        await authenticate_admin(request, require_csrf=True, csrf_token=csrf_token)
        body: RunawayQuarantineDenyRequest | None = None
        validation_fields: list[dict[str, JsonValue]] | None = None
        try:
            try:
                body = RunawayQuarantineDenyRequest(
                    action_token=_single_form_value(values, "action_token"),
                    expected_generation=int(_single_form_value(values, "expected_generation")),
                    reason=_single_form_value(values, "reason"),
                )
            except ValidationError as exc:
                validation_fields = _body_validation_fields(exc)
            except ValueError:
                validation_fields = [{"field": "runaway_denial", "type": "integer"}]
        finally:
            values.clear()
        if body is None:
            raise schema_error(
                fields=validation_fields or [{"field": "runaway_denial", "type": "invalid"}]
            )
        await deny_runaway_action(
            quarantine_id,
            body,
            principal.admin_session_id,
        )
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/dashboard/runaway-quarantines/{quarantine_id}/authorize")
    async def dashboard_authorize_runaway(
        request: Request,
        quarantine_id: str,
    ) -> RedirectResponse:
        return await dashboard_runaway_authorize(request, quarantine_id)

    @app.post("/dashboard/runaway-quarantines/{quarantine_id}/deny")
    async def dashboard_deny_runaway(
        request: Request,
        quarantine_id: str,
    ) -> RedirectResponse:
        return await dashboard_runaway_deny_action(request, quarantine_id)

    return app
