"""Stable public error-envelope handling for both HTTP realms."""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from gatehouse.core.errors import ErrorCode, GatehouseError, JsonValue, make_error

_ERROR_STATUS: Mapping[ErrorCode, int] = {
    ErrorCode.INVALID_SESSION: 401,
    ErrorCode.SESSION_EXPIRED: 401,
    ErrorCode.SESSION_REVOKED: 401,
    ErrorCode.ATTRIBUTED_SESSION_REQUIRED: 403,
    ErrorCode.SCHEMA_VALIDATION_FAILED: 422,
    ErrorCode.POLICY_DENIED: 403,
    ErrorCode.APPROVAL_PENDING: 202,
    ErrorCode.APPROVAL_EXPIRED: 409,
    ErrorCode.APPROVAL_UNAVAILABLE_FOR_UNATTENDED_CLIENT: 403,
    ErrorCode.CAPACITY_EXCEEDED: 429,
    ErrorCode.BUDGET_EXHAUSTED: 429,
    ErrorCode.RUNAWAY_SUSPECTED: 429,
    ErrorCode.DUPLICATE_IN_FLIGHT: 409,
    ErrorCode.INVALID_TARGET: 400,
    ErrorCode.SENSITIVE_PAYLOAD_DENIED: 403,
    ErrorCode.NO_ELIGIBLE_POOL: 503,
    ErrorCode.NO_ELIGIBLE_CREDENTIAL: 503,
    ErrorCode.QUOTA_EXHAUSTED: 429,
    ErrorCode.PROVIDER_RATE_LIMITED: 429,
    ErrorCode.PROVIDER_PERMISSION_DENIED: 502,
    ErrorCode.PROVIDER_UNAUTHORIZED: 502,
    ErrorCode.PROVIDER_TIMEOUT: 504,
    ErrorCode.PROVIDER_UNAVAILABLE: 503,
    ErrorCode.UNCERTAIN_OUTCOME: 502,
    ErrorCode.RESULT_UNAVAILABLE_AFTER_RESTART: 410,
    ErrorCode.DAEMON_DEGRADED: 503,
}


def error_response(error: GatehouseError, *, status_code: int | None = None) -> JSONResponse:
    headers: dict[str, str] = {}
    if error.detail.retry_after_seconds is not None:
        headers["Retry-After"] = str(error.detail.retry_after_seconds)
    return JSONResponse(
        status_code=status_code or _ERROR_STATUS[error.detail.code],
        content=error.to_dict(),
        headers=headers,
    )


def schema_error(*, fields: list[dict[str, JsonValue]] | None = None) -> GatehouseError:
    return make_error(
        ErrorCode.SCHEMA_VALIDATION_FAILED,
        retryable=False,
        details={"fields": fields or []},
    )


async def _gatehouse_error_handler(_: Request, exception: Exception) -> JSONResponse:
    if not isinstance(exception, GatehouseError):
        raise TypeError("gatehouse error handler received the wrong exception")
    return error_response(exception)


async def _validation_error_handler(_: Request, exception: Exception) -> JSONResponse:
    if not isinstance(exception, RequestValidationError):
        raise TypeError("validation handler received the wrong exception")
    fields: list[dict[str, JsonValue]] = []
    for item in exception.errors():
        location = ".".join(str(part) for part in item.get("loc", ()))
        fields.append(
            {
                "field": location,
                "type": str(item.get("type", "validation_error")),
            }
        )
    return error_response(schema_error(fields=fields))


async def _http_error_handler(_: Request, exception: Exception) -> JSONResponse:
    if not isinstance(exception, StarletteHTTPException):
        raise TypeError("HTTP error handler received the wrong exception")
    code = (
        ErrorCode.INVALID_TARGET
        if exception.status_code == 404
        else ErrorCode.SCHEMA_VALIDATION_FAILED
    )
    error = make_error(code, retryable=False)
    return error_response(error, status_code=exception.status_code)


async def _unexpected_error_handler(_: Request, exception: Exception) -> JSONResponse:
    del exception
    error = make_error(
        ErrorCode.DAEMON_DEGRADED,
        retryable=True,
        retry_after_seconds=1,
    )
    return error_response(error)


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(GatehouseError, _gatehouse_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(Exception, _unexpected_error_handler)
