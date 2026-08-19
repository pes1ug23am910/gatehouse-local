"""Separate local administrative API and accessible dashboard factory."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping
from html import escape
from typing import Annotated
from urllib.parse import parse_qs

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import Field

from gatehouse.admin import (
    AdminAuthCapacityExceeded,
    AdminAuthenticationError,
    AdminAuthManager,
    AdminBackend,
    AdminLoginSession,
    AdminPrincipal,
    ApprovalActionRequest,
    ApprovalActionResult,
    ApprovalDecision,
)
from gatehouse.admin.dashboard import render_dashboard
from gatehouse.core.errors import ErrorCode, make_error

from .contracts import StrictApiModel
from .errors import install_error_handlers, schema_error
from .middleware import AdminSecurityHeadersMiddleware, LocalRequestBoundsMiddleware

ADMIN_COOKIE_NAME = "gatehouse_admin"
CSRF_COOKIE_NAME = "gatehouse_csrf"
CSRF_HEADER_NAME = "x-gatehouse-csrf"


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


async def _form_values(request: Request, *, maximum_fields: int) -> dict[str, list[str]]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type != "application/x-www-form-urlencoded":
        raise schema_error(fields=[{"field": "content-type", "type": "unsupported"}])
    try:
        return parse_qs(
            (await request.body()).decode("utf-8"),
            keep_blank_values=False,
            strict_parsing=True,
            max_num_fields=maximum_fields,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise schema_error(fields=[{"field": "body", "type": "form"}]) from exc


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
    )
    install_error_handlers(app)

    def validate_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is not None and origin.casefold().rstrip("/") not in allowed_origins:
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
        body: ApprovalActionRequest,
        decision: ApprovalDecision,
    ) -> JSONResponse:
        await authenticate_admin(request, require_csrf=True)
        result = await approval_action(approval_id, body, decision)
        return JSONResponse(content=result.model_dump(mode="json"))

    @app.post("/v1/admin/approvals/{approval_id}/approve")
    async def approve(
        request: Request,
        approval_id: str,
        body: ApprovalActionRequest,
    ) -> JSONResponse:
        return await json_decision(request, approval_id, body, ApprovalDecision.APPROVE)

    @app.post("/v1/admin/approvals/{approval_id}/deny")
    async def deny(
        request: Request,
        approval_id: str,
        body: ApprovalActionRequest,
    ) -> JSONResponse:
        return await json_decision(request, approval_id, body, ApprovalDecision.DENY)

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
        return HTMLResponse(
            render_dashboard(
                status=status_record,
                approvals=approval_records,
                csrf_token=csrf_token,
            )
        )

    async def dashboard_decision(
        request: Request,
        approval_id: str,
        decision: ApprovalDecision,
    ) -> RedirectResponse:
        values = await _form_values(request, maximum_fields=6)
        csrf_token = _single_form_value(values, "csrf_token")
        await authenticate_admin(request, require_csrf=True, csrf_token=csrf_token)
        try:
            maximum_cost = int(_single_form_value(values, "maximum_estimated_cost"))
            maximum_uses = int(_single_form_value(values, "maximum_uses"))
        except ValueError as exc:
            raise schema_error(fields=[{"field": "approval", "type": "integer"}]) from exc
        if maximum_uses != 1:
            raise schema_error(fields=[{"field": "maximum_uses", "type": "literal"}])
        body = ApprovalActionRequest(
            action_token=_single_form_value(values, "action_token"),
            request_fingerprint=_single_form_value(values, "request_fingerprint"),
            maximum_estimated_cost=maximum_cost,
            maximum_uses=1,
        )
        await approval_action(approval_id, body, decision)
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/dashboard/approvals/{approval_id}/approve")
    async def dashboard_approve(request: Request, approval_id: str) -> RedirectResponse:
        return await dashboard_decision(request, approval_id, ApprovalDecision.APPROVE)

    @app.post("/dashboard/approvals/{approval_id}/deny")
    async def dashboard_deny(request: Request, approval_id: str) -> RedirectResponse:
        return await dashboard_decision(request, approval_id, ApprovalDecision.DENY)

    return app
