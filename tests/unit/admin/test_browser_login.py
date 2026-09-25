from __future__ import annotations

import base64
import hashlib
from itertools import count
from typing import cast

import pytest
from httpx import ASGITransport, AsyncClient

from gatehouse.admin import AdminAuthManager, AdminBackend
from gatehouse.admin.login import LOGIN_SCRIPT
from gatehouse.api.admin import ADMIN_COOKIE_NAME, create_admin_app


def make_login_client() -> tuple[AsyncClient, AdminAuthManager]:
    random_counter = count(1)
    auth = AdminAuthManager(
        verifier_key=b"k" * 32,
        now_ms=lambda: 1_000,
        random_bytes=lambda size: next(random_counter).to_bytes(size, "big"),
    )
    app = create_admin_app(
        auth=auth,
        backend=cast(AdminBackend, object()),
        now_ms=lambda: 1_000,
        allowed_hosts=("testserver",),
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver"), auth


async def test_login_get_never_reflects_or_consumes_a_code() -> None:
    client, auth = make_login_client()
    code = (await auth.mint_login_code()).code
    async with client:
        plain = await client.get("/login")
        legacy = await client.get("/login", params={"code": code})
    assert plain.status_code == legacy.status_code == 200
    assert plain.content == legacy.content
    assert code not in legacy.text
    assert "set-cookie" not in legacy.headers
    assert 'name="code" value=""' in plain.text
    assert "disabled" in plain.text
    assert "<script>" + LOGIN_SCRIPT + "</script>" in plain.text
    assert (await auth.exchange_login_code(code)).admin_session_id


async def test_login_csp_allows_only_the_exact_bootstrap_script() -> None:
    client, _ = make_login_client()
    async with client:
        response = await client.get("/login")
        other_response = await client.get("/not-a-route")
    digest = base64.b64encode(hashlib.sha256(LOGIN_SCRIPT.encode()).digest()).decode()
    policy = response.headers["content-security-policy"]
    assert f"script-src 'sha256-{digest}'" in policy
    assert "script-src 'self'" not in policy
    assert "script-src 'unsafe-inline'" not in policy
    assert "default-src 'none'" in policy
    assert "form-action 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "script-src" not in other_response.headers["content-security-policy"]


@pytest.mark.parametrize("origin", (None, "https://elsewhere.invalid", "null"))
async def test_browser_login_rejects_missing_or_foreign_origin_without_consuming_code(
    origin: str | None,
) -> None:
    client, auth = make_login_client()
    code = (await auth.mint_login_code()).code
    headers = {} if origin is None else {"Origin": origin}
    async with client:
        response = await client.post("/login", data={"code": code}, headers=headers)
    assert response.status_code == 401
    assert code not in response.text
    assert "set-cookie" not in response.headers
    assert (await auth.exchange_login_code(code)).admin_session_id


async def test_browser_login_posts_once_and_redirects_without_capability() -> None:
    client, auth = make_login_client()
    code = (await auth.mint_login_code()).code
    async with client:
        response = await client.post(
            "/login",
            data={"code": code},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        replay = await client.post(
            "/login",
            data={"code": code},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert code not in response.text
    assert code not in str(response.headers)
    cookie = response.cookies.get(ADMIN_COOKIE_NAME)
    assert cookie is not None
    assert (await auth.authenticate(cookie)).admin_session_id
    assert replay.status_code == 401


async def test_browser_login_rejects_duplicate_form_values() -> None:
    client, auth = make_login_client()
    code = (await auth.mint_login_code()).code
    async with client:
        response = await client.post(
            "/login",
            content=f"code={code}&code={code}",
            headers={
                "Origin": "http://testserver",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            follow_redirects=False,
        )
    assert response.status_code == 422
    assert "set-cookie" not in response.headers
    assert (await auth.exchange_login_code(code)).admin_session_id
