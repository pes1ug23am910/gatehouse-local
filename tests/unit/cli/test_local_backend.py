from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest

from gatehouse.admin.control import CONTROL_CAPABILITY_HEADER
from gatehouse.api.admin import ADMIN_COOKIE_NAME, CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from gatehouse.cli.contracts import CliUnavailable
from gatehouse.cli.local import DaemonChild, LocalCliBackend

CONTROL_CAPABILITY = "c" * 43
BOOTSTRAP = "b" * 43
ACCESS_TOKEN = "a" * 43
ADMIN_CODE = "l" * 43
ADMIN_COOKIE = "m" * 43
CSRF_TOKEN = "s" * 43


def _exception_graph_text(exception: BaseException) -> str:
    pending = [exception]
    seen: set[int] = set()
    rendered: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered.append(f"{type(current).__name__}: {current!s}")
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(rendered)


class FakeChild:
    def __init__(self) -> None:
        self.return_code: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True


class FakeDaemonProcesses:
    def __init__(self, *, on_start: Callable[[], None] | None = None) -> None:
        self.on_start = on_start
        self.run_arguments: list[tuple[str, ...]] = []
        self.start_arguments: list[tuple[str, ...]] = []
        self.child = FakeChild()

    def run(self, arguments: Sequence[str]) -> int:
        self.run_arguments.append(tuple(arguments))
        return 7

    def start(self, arguments: Sequence[str]) -> DaemonChild:
        self.start_arguments.append(tuple(arguments))
        if self.on_start is not None:
            self.on_start()
        return self.child


def _json(request: httpx.Request) -> dict[str, Any]:
    value = json.loads(request.content)
    assert isinstance(value, dict)
    return value


def _status(state: str = "READY") -> dict[str, object]:
    return {
        "ready": state == "READY",
        "status": state,
        "version": "0.0.1",
        "schema_version": 1,
        "policy_version": "policy-one",
        "uptime_seconds": 4,
        "degraded_components": [],
    }


def _write_config(tmp_path: Path, *, host: str = "127.0.0.1") -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = Path("config/config.example.yaml").read_text(encoding="utf-8")
    database = tmp_path / "state" / "gatehouse.db"
    source = source.replace(
        r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
        f"'{database.as_posix()}'",
    )
    source = source.replace("host: 127.0.0.1", f"host: {host}")
    config = tmp_path / "config.yaml"
    config.write_text(source, encoding="utf-8")
    return config, database


def _backend(
    tmp_path: Path,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    processes: FakeDaemonProcesses | None = None,
    host: str = "127.0.0.1",
    loaded_paths: list[Path] | None = None,
) -> tuple[LocalCliBackend, Path, Path]:
    config, database = _write_config(tmp_path, host=host)
    executable = tmp_path / "gatehoused.exe"
    executable.touch()

    def load(path: Path) -> str:
        if loaded_paths is not None:
            loaded_paths.append(path)
        return CONTROL_CAPABILITY

    backend = LocalCliBackend(
        config_path=config,
        environment={
            "APPDATA": str(tmp_path / "roaming"),
            "LOCALAPPDATA": str(tmp_path / "local"),
        },
        transport_factory=lambda: httpx.MockTransport(handler),
        capability_loader=load,
        daemon_processes=processes,
        daemon_executable=executable,
        sleep=lambda _: None,
    )
    return backend, config.resolve(), database


def _assert_control(request: httpx.Request) -> None:
    assert request.url.host == "127.0.0.1"
    assert request.url.port == 47622
    assert request.headers[CONTROL_CAPABILITY_HEADER] == CONTROL_CAPABILITY


def _launch_response(session_id: str = "ses_one") -> httpx.Response:
    return httpx.Response(
        201,
        json={
            "session_id": session_id,
            "bootstrap_capability": BOOTSTRAP,
            "client_id": "client-one",
            "workspace_id": "workspace-one",
            "identity_assurance": "configured",
            "policy_version": "policy-one",
            "absolute_expires_at_ms": 10_000,
        },
    )


def _exchange_response(
    session_id: str,
    capabilities: Sequence[str],
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in_seconds": 600,
            "session": {
                "session_id": session_id,
                "client_id": "client-one",
                "workspace_id": "workspace-one",
                "state": "ACTIVE",
                "absolute_expires_at_ms": 10_000,
            },
            "capabilities": list(capabilities),
        },
    )


def _policy_explain_response(
    *,
    session_id: str = "ses_policy",
    client: str = "editor-one",
    workspace: str = "workspace-one",
    root_run_id: str = "run_policy",
) -> dict[str, object]:
    return {
        "authority": {
            "session_id": session_id,
            "client_id": "client-one",
            "client": client,
            "workspace_id": "workspace-one",
            "workspace": workspace,
            "root_run_id": root_run_id,
        },
        "service": "firecrawl",
        "operation": "crawl",
        "decision": "ASK",
        "rule_id": "default-decision",
        "reason_code": "policy-ask",
        "policy_id": "workspace-one",
        "policy_version": "policy-one",
        "constraints": {
            "maximum_search_results": 20,
            "maximum_map_results": 100,
            "maximum_crawl_pages": 25,
            "maximum_crawl_depth": 2,
            "request_count_remaining": 30,
            "credit_budget_remaining_units": 200,
        },
        "cost_ceiling_units": 200,
        "approval_required": True,
        "denial_reason": None,
        "purpose_rules": [],
    }


def test_controlled_launch_has_exact_child_authority_and_explicit_cleanup(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []
    loaded_paths: list[Path] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        _assert_control(request)
        if request.url.path == "/v1/control/sessions":
            assert _json(request) == {
                "client": "editor-one",
                "workspace": "workspace-one",
                "non_interactive": False,
            }
            return _launch_response()
        assert request.url.path == "/v1/control/sessions/ses_one/disconnect"
        return httpx.Response(200, json={"session_id": "ses_one", "state": "DISCONNECTED"})

    backend, _, database = _backend(
        tmp_path,
        handler,
        loaded_paths=loaded_paths,
    )
    launch = backend.prepare_launch(
        client="editor-one",
        workspace="workspace-one",
        non_interactive=False,
        command=("worker.exe", "--bounded"),
    )
    assert launch.session_id == "ses_one"
    assert launch.argv == ("worker.exe", "--bounded")
    assert dict(launch.environment) == {
        "GATEHOUSE_AGENT_URL": "http://127.0.0.1:47621",
        "GATEHOUSE_SESSION_BOOTSTRAP": BOOTSTRAP,
        "GATEHOUSE_SESSION_ID": "ses_one",
    }
    assert CONTROL_CAPABILITY not in launch.environment.values()
    assert CONTROL_CAPABILITY not in repr(backend)

    backend.cleanup_launch(launch, revoke=False)
    assert loaded_paths == [database.parent / "control-capability.dpapi"]
    assert [request.url.path for request in requests] == [
        "/v1/control/sessions",
        "/v1/control/sessions/ses_one/disconnect",
    ]


def test_daemon_process_control_uses_configured_entrypoint_and_authenticated_readiness(
    tmp_path: Path,
) -> None:
    state = {"running": False}
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if not state["running"]:
            raise httpx.ConnectError("offline", request=request)
        if request.url.port == 47621:
            if request.url.path == "/health/live":
                return httpx.Response(200, json={"status": "live"})
            assert request.url.path == "/health/ready"
            return httpx.Response(200, json=_status())
        _assert_control(request)
        if request.url.path == "/v1/control/status":
            return httpx.Response(200, json=_status())
        assert request.url.path == "/v1/control/drain"
        state["running"] = False
        return httpx.Response(200, json={"state": "DRAINING", "requested": True})

    processes = FakeDaemonProcesses(on_start=lambda: state.update(running=True))
    backend, config, _ = _backend(tmp_path, handler, processes=processes)
    stopped = backend.daemon_status()
    assert stopped == {"ready": False, "status": "STOPPED"}

    started = backend.daemon_start()
    assert started["started"] is True
    assert started["status"] == "READY"
    assert processes.start_arguments == [
        (str(tmp_path / "gatehoused.exe"), "--config", str(config))
    ]
    assert backend.daemon_status()["ready"] is True

    stopped = backend.daemon_stop()
    assert stopped == {"action": "stop", "stopped": True, "status": "STOPPED"}
    assert "/v1/control/drain" in requests

    foreground = backend.daemon_run()
    assert foreground == {"action": "run", "exit_code": 7}
    assert processes.run_arguments == [(str(tmp_path / "gatehoused.exe"), "--config", str(config))]


def _admin_login_response() -> httpx.Response:
    return httpx.Response(
        200,
        headers=[
            (
                "set-cookie",
                f"{ADMIN_COOKIE_NAME}={ADMIN_COOKIE}; Path=/; HttpOnly; SameSite=strict",
            ),
            (
                "set-cookie",
                f"{CSRF_COOKIE_NAME}={CSRF_TOKEN}; Path=/; SameSite=strict",
            ),
        ],
        json={
            "admin_session_id": "admin-one",
            "csrf_token": CSRF_TOKEN,
            "idle_expires_at_ms": 2_000,
            "absolute_expires_at_ms": 4_000,
        },
    )


def _approval() -> dict[str, object]:
    return {
        "approval_id": "approval-one",
        "session_id": "ses-one",
        "client_id": "client-one",
        "workspace_id": "workspace-one",
        "service": "firecrawl",
        "operation": "search",
        "request_fingerprint": "f" * 32,
        "target_summary": "example.com",
        "pool": "interactive",
        "maximum_estimated_cost": 3,
        "maximum_uses": 1,
        "expires_at_ms": 10_000,
        "state": "PENDING",
        "action_token": "t" * 43,
    }


def test_admin_list_and_decision_use_one_use_login_cookie_csrf_and_redact_tokens(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    decisions: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        events.append(request.url.path)
        if request.url.path == "/v1/control/admin/login-code":
            _assert_control(request)
            return httpx.Response(
                200,
                json={"code": ADMIN_CODE, "expires_at_ms": 2_000},
            )
        if request.url.path == "/v1/admin/login/exchange":
            assert _json(request) == {"code": ADMIN_CODE}
            return _admin_login_response()
        assert request.headers.get("cookie") is not None
        assert f"{ADMIN_COOKIE_NAME}={ADMIN_COOKIE}" in request.headers["cookie"]
        if request.url.path == "/v1/admin/approvals":
            assert dict(request.url.params) == {"limit": "50"}
            return httpx.Response(200, json={"approvals": [_approval()]})
        if request.url.path == "/v1/admin/approvals/approval-one":
            return httpx.Response(200, json=_approval())
        if request.url.path == "/v1/admin/approvals/approval-one/approve":
            assert request.headers[CSRF_HEADER_NAME] == CSRF_TOKEN
            assert request.headers["origin"] == "http://127.0.0.1:47622"
            decisions.append(_json(request))
            return httpx.Response(
                200,
                json={
                    "approval_id": "approval-one",
                    "state": "APPROVED",
                    "acted_at_ms": 1_500,
                },
            )
        assert request.url.path == "/v1/admin/logout"
        assert request.headers[CSRF_HEADER_NAME] == CSRF_TOKEN
        assert request.headers["origin"] == "http://127.0.0.1:47622"
        return httpx.Response(200, json={"state": "logged_out"})

    backend, _, _ = _backend(tmp_path, handler)
    listed = backend.approval_list()
    assert listed[0]["approval_id"] == "approval-one"
    assert "action_token" not in listed[0]
    assert "t" * 43 not in json.dumps(listed)

    result = backend.approval_action("approval-one", "approve")
    assert result == {
        "approval_id": "approval-one",
        "state": "APPROVED",
        "acted_at_ms": 1_500,
    }
    assert decisions == [
        {
            "action_token": "t" * 43,
            "request_fingerprint": "f" * 32,
            "maximum_estimated_cost": 3,
            "maximum_uses": 1,
        }
    ]
    assert events.count("/v1/control/admin/login-code") == 2
    assert events.count("/v1/admin/login/exchange") == 2
    assert events.count("/v1/admin/logout") == 2


def test_dashboard_url_contains_only_the_new_one_use_code(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        _assert_control(request)
        assert request.url.path == "/v1/control/admin/login-code"
        return httpx.Response(200, json={"code": ADMIN_CODE, "expires_at_ms": 2_000})

    backend, _, _ = _backend(tmp_path, handler)
    assert backend.dashboard_login_url() == (f"http://127.0.0.1:47622/login?code={ADMIN_CODE}")


def test_docs_and_feedback_use_short_lived_capability_checked_sessions(
    tmp_path: Path,
) -> None:
    launches: list[dict[str, Any]] = []
    revocations: list[str] = []
    agent_calls: list[httpx.Request] = []
    sequence = iter(
        (
            ("ses_docs", "docs.search"),
            ("ses_get", "docs.get"),
            ("ses_feedback", "feedback.submit"),
        )
    )
    current: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/sessions":
            _assert_control(request)
            launches.append(_json(request))
            session_id, capability = next(sequence)
            current[session_id] = capability
            return _launch_response(session_id)
        if request.url.path.startswith("/v1/control/sessions/"):
            _assert_control(request)
            session_id = request.url.path.split("/")[4]
            assert request.url.path.endswith("/revoke")
            revocations.append(session_id)
            return httpx.Response(200, json={"session_id": session_id, "state": "REVOKED"})
        agent_calls.append(request)
        if request.url.path == "/v1/sessions/exchange":
            payload = _json(request)
            session_id = str(payload["session_id"])
            assert payload["bootstrap_capability"] == BOOTSTRAP
            assert isinstance(payload["client_nonce"], str)
            return _exchange_response(session_id, [current[session_id]])
        assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
        if request.url.path == "/v1/docs/search":
            assert _json(request) == {
                "service": "firecrawl",
                "query": "rate limit",
                "limit": 10,
            }
            return httpx.Response(
                200,
                json={
                    "service": "firecrawl",
                    "results": [{"source_id": "guide", "excerpt": "bounded"}],
                },
            )
        if request.url.path == "/v1/docs/firecrawl/guide":
            return httpx.Response(
                200,
                json={
                    "service": "firecrawl",
                    "document": "guide",
                    "content": "Official guidance.",
                },
            )
        assert request.url.path == "/v1/feedback"
        assert _json(request) == {
            "category": "contract",
            "severity": "medium",
            "component": "firecrawl.search",
            "summary": "Unexpected field",
        }
        return httpx.Response(
            200,
            json={
                "feedback_id": "feedback-one",
                "state": "NEW",
                "summary": "Unexpected field",
                "created_at_ms": 2_000,
            },
        )

    backend, _, _ = _backend(tmp_path, handler)
    searched = backend.docs_search(
        "firecrawl",
        "rate limit",
        client="editor-one",
        workspace="workspace-one",
        non_interactive=False,
    )
    assert searched == ({"source_id": "guide", "excerpt": "bounded"},)
    document = backend.docs_get(
        "firecrawl",
        "guide",
        client="editor-one",
        workspace="workspace-one",
        non_interactive=False,
    )
    assert document["content"] == "Official guidance."
    feedback = backend.feedback_submit(
        category="contract",
        severity="medium",
        component="firecrawl.search",
        summary="Unexpected field",
        client="editor-one",
        workspace="workspace-one",
        non_interactive=False,
    )
    assert feedback["feedback_id"] == "feedback-one"
    assert (
        launches
        == [
            {
                "client": "editor-one",
                "workspace": "workspace-one",
                "non_interactive": False,
            }
        ]
        * 3
    )
    assert revocations == ["ses_docs", "ses_get", "ses_feedback"]
    assert all(CONTROL_CAPABILITY not in request.headers.values() for request in agent_calls)


def test_missing_agent_capability_fails_closed_and_still_revokes(tmp_path: Path) -> None:
    revoked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/sessions":
            return _launch_response()
        if request.url.path == "/v1/sessions/exchange":
            return _exchange_response("ses_one", [])
        assert request.url.path == "/v1/control/sessions/ses_one/revoke"
        revoked.append("ses_one")
        return httpx.Response(200, json={"session_id": "ses_one", "state": "REVOKED"})

    backend, _, _ = _backend(tmp_path, handler)
    with pytest.raises(CliUnavailable, match="could not be adopted"):
        backend.docs_search(
            "firecrawl",
            "rate limit",
            client="editor-one",
            workspace="workspace-one",
            non_interactive=False,
        )
    assert revoked == ["ses_one"]


def test_policy_explain_uses_exact_controlled_authority_and_server_minted_root(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/control/sessions":
            _assert_control(request)
            assert _json(request) == {
                "client": "editor-one",
                "workspace": "workspace-one",
                "non_interactive": False,
            }
            return _launch_response("ses_policy")
        if request.url.path == "/v1/sessions/exchange":
            assert CONTROL_CAPABILITY not in request.headers.values()
            assert _json(request)["session_id"] == "ses_policy"
            return _exchange_response("ses_policy", [])
        if request.url.path == "/v1/root-runs":
            assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
            assert _json(request) == {}
            return httpx.Response(
                201,
                json={
                    "root_run_id": "run_policy",
                    "session_id": "ses_policy",
                    "state": "ACTIVE",
                    "started_at_ms": 1,
                    "budget": {"requests": 30, "credits": 200},
                },
            )
        if request.url.path == "/v1/policy/explain":
            assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
            assert _json(request) == {
                "service": "firecrawl",
                "operation": "crawl",
                "context": {"root_run_id": "run_policy"},
            }
            return httpx.Response(200, json=_policy_explain_response())
        assert request.url.path == "/v1/control/sessions/ses_policy/revoke"
        _assert_control(request)
        return httpx.Response(200, json={"session_id": "ses_policy", "state": "REVOKED"})

    backend, _, _ = _backend(tmp_path, handler)
    explained = backend.policy_explain(
        client="editor-one",
        workspace="workspace-one",
        service="firecrawl",
        operation="crawl",
    )

    assert explained["decision"] == "ASK"
    assert explained["cost_ceiling_units"] == 200
    assert [request.url.path for request in requests] == [
        "/v1/control/sessions",
        "/v1/sessions/exchange",
        "/v1/root-runs",
        "/v1/policy/explain",
        "/v1/control/sessions/ses_policy/revoke",
    ]


def test_policy_explain_rejects_mismatched_response_and_revokes_session(
    tmp_path: Path,
) -> None:
    revoked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/sessions":
            return _launch_response("ses_policy")
        if request.url.path == "/v1/sessions/exchange":
            return _exchange_response("ses_policy", ["firecrawl.search"])
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": "run_policy",
                    "session_id": "ses_policy",
                    "state": "ACTIVE",
                    "started_at_ms": 1,
                    "budget": {},
                },
            )
        if request.url.path == "/v1/policy/explain":
            body = _policy_explain_response(client="another-client")
            body["operation"] = "search"
            return httpx.Response(200, json=body)
        assert request.url.path == "/v1/control/sessions/ses_policy/revoke"
        revoked.append("ses_policy")
        return httpx.Response(200, json={"session_id": "ses_policy", "state": "REVOKED"})

    backend, _, _ = _backend(tmp_path, handler)
    with pytest.raises(CliUnavailable, match="policy explanation failed"):
        backend.policy_explain(
            client="editor-one",
            workspace="workspace-one",
            service="firecrawl",
            operation="search",
        )
    assert revoked == ["ses_policy"]


def test_remote_authority_is_rejected_without_http(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("no request expected")

    backend, _, _ = _backend(tmp_path, handler, host="localhost")
    with pytest.raises(CliUnavailable, match="configuration"):
        backend.status()
    assert requests == []


COMMAND_HEADER = "X-Gatehouse-Command"
SYNTHETIC_SECRET = b"synthetic-cli-credential-not-a-real-key"
ESCAPED_SYNTHETIC_SECRET = b'synthetic-cli-"reflected"-credential'


def _credential_result(
    *,
    mutation_id: str,
    action: str,
    state: str,
    credential_id: str = "cred_one",
    expires_at_ms: int | None = None,
) -> dict[str, object]:
    return {
        "mutation_id": mutation_id,
        "credential_id": credential_id,
        "action": action,
        "state": state,
        "generation": 1,
        "alias": "primary",
        "principal_id": "principal_one",
        "principal_alias": "Principal one",
        "quota_scope_id": "quota_one",
        "quota_scope_alias": "Quota one",
        "pool_id": "pool_one",
        "pool_alias": "Pool one",
        "expires_at_ms": expires_at_ms,
        "acted_at_ms": 1_500,
        "audit_event_id": "audit_one",
    }


def _emergency_result(
    *,
    mutation_id: str,
    action: str = "unlock",
    state: str = "ACTIVE",
) -> dict[str, object]:
    return {
        "mutation_id": mutation_id,
        "unlock_id": "unl_one",
        "credential_id": "cred_emergency",
        "action": action,
        "state": state,
        "generation": 1,
        "service": "firecrawl",
        "alias": "break-glass",
        "principal_id": "principal_emergency",
        "principal_alias": "Emergency principal",
        "quota_scope_id": "quota_emergency",
        "quota_scope_alias": "Emergency quota",
        "pool_id": "emergency-locked",
        "pool_alias": "Emergency locked",
        "session_id": "ses_one",
        "root_run_id": "run_one",
        "expires_at_ms": 90_000,
        "remaining_requests": 2,
        "remaining_credits": 5,
        "remaining_concurrency": 1,
        "acted_at_ms": 1_500,
        "audit_event_id": "audit_emergency",
    }


def _admin_handler(
    action: Callable[[httpx.Request], httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/admin/login-code":
            _assert_control(request)
            return httpx.Response(200, json={"code": ADMIN_CODE, "expires_at_ms": 2_000})
        if request.url.path == "/v1/admin/login/exchange":
            assert _json(request) == {"code": ADMIN_CODE}
            return _admin_login_response()
        assert request.headers.get("cookie") is not None
        assert f"{ADMIN_COOKIE_NAME}={ADMIN_COOKIE}" in request.headers["cookie"]
        if request.url.path == "/v1/admin/logout":
            assert request.headers[CSRF_HEADER_NAME] == CSRF_TOKEN
            assert request.headers["origin"] == "http://127.0.0.1:47622"
            return httpx.Response(200, json={"state": "logged_out"})
        return action(request)

    return handler


def _command(request: httpx.Request) -> dict[str, Any]:
    decoded = json.loads(request.headers[COMMAND_HEADER])
    assert isinstance(decoded, dict)
    return decoded


def _assert_admin_write(request: httpx.Request) -> None:
    assert request.headers[CSRF_HEADER_NAME] == CSRF_TOKEN
    assert request.headers["origin"] == "http://127.0.0.1:47622"
    assert request.headers.get("authorization") is None


def test_secret_admin_writes_use_bounded_octet_stream_metadata_header_and_zero_inputs(
    tmp_path: Path,
) -> None:
    writes: list[tuple[str, bytes, dict[str, Any], str]] = []
    retained_writes: list[httpx.Request] = []

    def action(request: httpx.Request) -> httpx.Response:
        _assert_admin_write(request)
        retained_writes.append(request)
        command = _command(request)
        writes.append(
            (
                request.url.path,
                request.content,
                command,
                request.headers["content-type"],
            )
        )
        if request.url.path == "/v1/admin/credentials":
            return httpx.Response(
                201,
                json=_credential_result(
                    mutation_id=str(command["mutation_id"]),
                    action="provision",
                    state="HEALTHY",
                ),
            )
        if request.url.path == "/v1/admin/credentials/cred_one/rotate":
            return httpx.Response(
                200,
                json=_credential_result(
                    mutation_id=str(command["mutation_id"]),
                    action="rotate",
                    state="HEALTHY",
                    credential_id="cred_two",
                    expires_at_ms=90_000,
                ),
            )
        assert request.url.path == "/v1/admin/emergency-unlocks"
        return httpx.Response(
            201,
            json=_emergency_result(mutation_id=str(command["mutation_id"])),
        )

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    provision_secret = bytearray(SYNTHETIC_SECRET)
    rotate_secret = bytearray(SYNTHETIC_SECRET)
    emergency_secret = bytearray(SYNTHETIC_SECRET)

    provisioned = backend.credential_provision(
        provision_secret,
        mutation_id="mut_provision",
        principal_id="principal_one",
        quota_scope_id="quota_one",
        pool_id="pool_one",
        alias="primary",
        expires_at_ms=None,
        exclusive_usage=True,
    )
    rotated = backend.credential_rotate(
        "cred_one",
        rotate_secret,
        mutation_id="mut_rotate",
        expires_at_ms=90_000,
    )
    unlocked = backend.emergency_unlock(
        emergency_secret,
        mutation_id="mut_unlock",
        service="firecrawl",
        pool_id="emergency-locked",
        session_id="ses_one",
        root_run_id="run_one",
        alias="break-glass",
        reason="manual incident recovery",
        duration_ms=60_000,
        maximum_requests=2,
        maximum_credits=5,
    )

    assert provisioned["action"] == "provision"
    assert rotated["action"] == "rotate"
    assert rotated["credential_id"] == "cred_two"
    assert unlocked["action"] == "unlock"
    assert SYNTHETIC_SECRET.decode() not in json.dumps(
        [provisioned, rotated, unlocked],
        sort_keys=True,
    )
    assert provision_secret == bytearray(len(SYNTHETIC_SECRET))
    assert rotate_secret == bytearray(len(SYNTHETIC_SECRET))
    assert emergency_secret == bytearray(len(SYNTHETIC_SECRET))
    assert [path for path, _, _, _ in writes] == [
        "/v1/admin/credentials",
        "/v1/admin/credentials/cred_one/rotate",
        "/v1/admin/emergency-unlocks",
    ]
    assert all(body == SYNTHETIC_SECRET for _, body, _, _ in writes)
    assert all(content_type == "application/octet-stream" for _, _, _, content_type in writes)
    assert all(request.method == "" for request in retained_writes)
    assert all(str(request.url) == "" for request in retained_writes)
    assert all(request.extensions == {} for request in retained_writes)
    assert writes[0][2] == {
        "mutation_id": "mut_provision",
        "principal_id": "principal_one",
        "quota_scope_id": "quota_one",
        "pool_id": "pool_one",
        "alias": "primary",
        "expires_at_ms": None,
        "exclusive_usage": True,
    }
    assert writes[1][2] == {"mutation_id": "mut_rotate", "expires_at_ms": 90_000}
    assert writes[2][2] == {
        "mutation_id": "mut_unlock",
        "service": "firecrawl",
        "pool_id": "emergency-locked",
        "session_id": "ses_one",
        "root_run_id": "run_one",
        "alias": "break-glass",
        "reason": "manual incident recovery",
        "duration_ms": 60_000,
        "maximum_requests": 2,
        "maximum_credits": 5,
        "maximum_concurrency": 1,
    }


@pytest.mark.parametrize(
    "overlap",
    ["metadata-leaf", "json-punctuation", "request-path"],
)
def test_secret_admin_write_rejects_nonbody_overlap_before_send(
    tmp_path: Path,
    overlap: str,
) -> None:
    observed_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_paths.append(request.url.path)
        if request.url.path == "/v1/control/admin/login-code":
            _assert_control(request)
            return httpx.Response(200, json={"code": ADMIN_CODE, "expires_at_ms": 2_000})
        if request.url.path == "/v1/admin/login/exchange":
            return _admin_login_response()
        if request.url.path == "/v1/admin/logout":
            return httpx.Response(200, json={"state": "logged_out"})
        raise AssertionError("credential mutation must not reach the transport")

    backend, _, _ = _backend(tmp_path, handler)
    metadata_secret = b"synthetic-metadata-leaf-overlap-000001"
    punctuation_alias = "synthetic-command-boundary-seed"
    punctuation_secret = f'{punctuation_alias}","expires_at_ms":null'.encode()
    path_secret = b"synthetic-request-path-overlap-000001"
    secret = bytearray(
        {
            "metadata-leaf": metadata_secret,
            "json-punctuation": punctuation_secret,
            "request-path": path_secret,
        }[overlap]
    )
    expected_size = len(secret)

    with pytest.raises(CliUnavailable, match="credential .* failed") as captured:
        if overlap == "request-path":
            backend.credential_rotate(
                path_secret.decode(),
                secret,
                mutation_id="mut_request_path_overlap",
                expires_at_ms=None,
            )
        else:
            backend.credential_provision(
                secret,
                mutation_id=f"mut_{overlap.replace('-', '_')}_overlap",
                principal_id="principal_one",
                quota_scope_id="quota_one",
                pool_id="pool_one",
                alias=(
                    metadata_secret.decode() if overlap == "metadata-leaf" else punctuation_alias
                ),
                expires_at_ms=None,
                exclusive_usage=True,
            )

    assert secret == bytearray(expected_size)
    assert observed_paths == [
        "/v1/control/admin/login-code",
        "/v1/admin/login/exchange",
        "/v1/admin/logout",
    ]
    overlap_text = {
        "metadata-leaf": metadata_secret.decode(),
        "json-punctuation": punctuation_secret.decode(),
        "request-path": path_secret.decode(),
    }[overlap]
    assert overlap_text not in _exception_graph_text(captured.value)


def test_state_list_and_cancel_use_empty_bodies_and_strict_safe_results(tmp_path: Path) -> None:
    writes: list[tuple[str, bytes, dict[str, Any]]] = []
    reads: list[str] = []

    def action(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            reads.append(request.url.path)
            assert request.content == b""
            if request.url.path == "/v1/admin/credentials":
                assert dict(request.url.params) == {"limit": "5"}
                return httpx.Response(
                    200,
                    json={
                        "credentials": [
                            {
                                "credential_id": "cred_one",
                                "service": "firecrawl",
                                "alias": "primary",
                                "principal_id": "principal_one",
                                "quota_scope_id": "quota_one",
                                "state": "HEALTHY",
                                "generation": 1,
                                "exclusive_usage": True,
                                "principal_alias": "principal-primary",
                                "quota_scope_alias": "quota-primary",
                                "pool_ids": ["pool_one"],
                                "pool_aliases": ["interactive-default"],
                                "active_lease_count": 0,
                                "created_at_ms": 1,
                                "expires_at_ms": None,
                                "last_used_at_ms": None,
                                "last_local_action": "provision",
                            }
                        ]
                    },
                )
            assert request.url.path == "/v1/admin/emergency-unlocks"
            assert dict(request.url.params) == {"limit": "7"}
            return httpx.Response(
                200,
                json={"emergency_unlocks": [_emergency_result(mutation_id="mut_unlock")]},
            )

        _assert_admin_write(request)
        command = _command(request)
        writes.append((request.url.path, request.content, command))
        if request.url.path.endswith("/cancel"):
            return httpx.Response(
                200,
                json=_emergency_result(
                    mutation_id=str(command["mutation_id"]),
                    action="cancel",
                    state="CANCELLED",
                ),
            )
        action_name = request.url.path.rsplit("/", 1)[-1]
        states = {"disable": "DISABLED", "quarantine": "QUARANTINED", "retire": "RETIRED"}
        return httpx.Response(
            200,
            json=_credential_result(
                mutation_id=str(command["mutation_id"]),
                action=action_name,
                state=states[action_name],
            ),
        )

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    for action_name in ("disable", "quarantine", "retire"):
        result = backend.credential_change_state(
            "cred_one",
            mutation_id=f"mut_{action_name}",
            action=action_name,
            reason="operator request",
        )
        assert result["action"] == action_name

    credentials = backend.credential_list(limit=5)
    listed = backend.emergency_list(limit=7)
    cancelled = backend.emergency_cancel(
        "unl_one",
        mutation_id="mut_cancel",
        reason="incident resolved",
    )
    assert len(listed) == 1
    assert len(credentials) == 1
    assert credentials[0]["credential_id"] == "cred_one"
    assert credentials[0]["state"] == "HEALTHY"
    assert listed[0]["unlock_id"] == "unl_one"
    assert cancelled["state"] == "CANCELLED"
    assert SYNTHETIC_SECRET.decode() not in json.dumps(
        [*credentials, *listed, cancelled],
        sort_keys=True,
    )
    assert reads == ["/v1/admin/credentials", "/v1/admin/emergency-unlocks"]
    assert all(body == b"" for _, body, _ in writes)
    assert [path for path, _, _ in writes] == [
        "/v1/admin/credentials/cred_one/disable",
        "/v1/admin/credentials/cred_one/quarantine",
        "/v1/admin/credentials/cred_one/retire",
        "/v1/admin/emergency-unlocks/unl_one/cancel",
    ]


@pytest.mark.parametrize(
    ("operation", "expected_error"),
    [
        ("provision", "credential provision failed"),
        ("rotate", "credential rotation failed"),
        ("emergency", "emergency unlock failed"),
    ],
)
def test_valid_secret_write_response_rejects_escaped_exact_secret_reflection(
    tmp_path: Path,
    operation: str,
    expected_error: str,
) -> None:
    retained: list[httpx.Request] = []
    reflected = ESCAPED_SYNTHETIC_SECRET.decode()

    def action(request: httpx.Request) -> httpx.Response:
        _assert_admin_write(request)
        assert request.content == ESCAPED_SYNTHETIC_SECRET
        retained.append(request)
        command = _command(request)
        if operation == "provision":
            assert request.url.path == "/v1/admin/credentials"
            body = _credential_result(
                mutation_id=str(command["mutation_id"]),
                action="provision",
                state="HEALTHY",
            )
            status = 201
        elif operation == "rotate":
            assert request.url.path == "/v1/admin/credentials/cred_one/rotate"
            body = _credential_result(
                mutation_id=str(command["mutation_id"]),
                action="rotate",
                state="HEALTHY",
            )
            status = 200
        else:
            assert request.url.path == "/v1/admin/emergency-unlocks"
            body = _emergency_result(mutation_id=str(command["mutation_id"]))
            status = 201
        body["principal_alias"] = reflected
        response = httpx.Response(status, json=body)
        assert ESCAPED_SYNTHETIC_SECRET not in response.content
        return response

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    secret = bytearray(ESCAPED_SYNTHETIC_SECRET)
    mutation_id = f"mut_reflected_{operation}"
    with pytest.raises(CliUnavailable, match=expected_error) as captured:
        if operation == "provision":
            backend.credential_provision(
                secret,
                mutation_id=mutation_id,
                principal_id="principal_one",
                quota_scope_id="quota_one",
                pool_id="pool_one",
                alias="primary",
                expires_at_ms=None,
                exclusive_usage=True,
            )
        elif operation == "rotate":
            backend.credential_rotate(
                "cred_one",
                secret,
                mutation_id=mutation_id,
                expires_at_ms=90_000,
            )
        else:
            backend.emergency_unlock(
                secret,
                mutation_id=mutation_id,
                service="firecrawl",
                pool_id="emergency-locked",
                session_id="ses_one",
                root_run_id="run_one",
                alias="break-glass",
                reason="manual incident recovery",
                duration_ms=60_000,
                maximum_requests=2,
                maximum_credits=5,
            )

    assert secret == bytearray(len(ESCAPED_SYNTHETIC_SECRET))
    assert reflected not in _exception_graph_text(captured.value)
    assert retained and retained[0].content == b""
    assert dict(retained[0].headers) == {}


def test_secret_write_rejects_set_cookie_reflection_before_logout(
    tmp_path: Path,
) -> None:
    reflected = SYNTHETIC_SECRET.decode()
    retained_write: list[httpx.Request] = []
    retained_response: list[httpx.Response] = []
    logout_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/admin/login-code":
            _assert_control(request)
            return httpx.Response(200, json={"code": ADMIN_CODE, "expires_at_ms": 2_000})
        if request.url.path == "/v1/admin/login/exchange":
            assert _json(request) == {"code": ADMIN_CODE}
            return _admin_login_response()
        if request.url.path == "/v1/admin/credentials":
            _assert_admin_write(request)
            assert request.content == SYNTHETIC_SECRET
            assert f"{ADMIN_COOKIE_NAME}={ADMIN_COOKIE}" in request.headers["cookie"]
            retained_write.append(request)
            command = _command(request)
            response = httpx.Response(
                201,
                headers={"Set-Cookie": f"reflected={reflected}; Path=/; HttpOnly; SameSite=strict"},
                json=_credential_result(
                    mutation_id=str(command["mutation_id"]),
                    action="provision",
                    state="HEALTHY",
                ),
            )
            retained_response.append(response)
            return response
        assert request.url.path == "/v1/admin/logout"
        logout_cookie_headers.append(request.headers.get("cookie"))
        assert request.headers[CSRF_HEADER_NAME] == CSRF_TOKEN
        assert request.headers["origin"] == "http://127.0.0.1:47622"
        return httpx.Response(200, json={"state": "logged_out"})

    backend, _, _ = _backend(tmp_path, handler)
    secret = bytearray(SYNTHETIC_SECRET)

    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_cookie_reflection",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert logout_cookie_headers == [None]
    assert reflected not in _exception_graph_text(captured.value)
    assert retained_write and retained_write[0].content == b""
    assert dict(retained_write[0].headers) == {}
    assert retained_response and dict(retained_response[0].headers) == {}


def test_non_json_response_rejects_raw_exact_secret_reflection(tmp_path: Path) -> None:
    retained: list[httpx.Request] = []
    retained_responses: list[httpx.Response] = []

    class TrackedReflectionStream(httpx.SyncByteStream):
        def __init__(self) -> None:
            self.body = bytearray(b"\x00binary-prefix:" + SYNTHETIC_SECRET + b":\xff")
            self.close_count = 0

        def __iter__(self) -> Iterator[bytes]:
            yield bytes(self.body)

        def close(self) -> None:
            self.close_count += 1

    stream = TrackedReflectionStream()

    def action(request: httpx.Request) -> httpx.Response:
        _assert_admin_write(request)
        assert request.content == SYNTHETIC_SECRET
        retained.append(request)
        response = httpx.Response(
            201,
            stream=stream,
            headers={"Content-Type": "application/octet-stream"},
        )
        retained_responses.append(response)
        return response

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    secret = bytearray(SYNTHETIC_SECRET)
    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_binary_reflection",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)
    assert retained and retained[0].content == b""
    assert dict(retained[0].headers) == {}
    assert retained_responses and retained_responses[0].content == b""
    assert dict(retained_responses[0].headers) == {}
    assert retained_responses[0].extensions == {}
    assert stream.close_count == 1
    assert stream.body == bytearray()


def test_binary_reason_phrase_reflection_is_not_logged_and_is_scrubbed(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    retained_response: list[httpx.Response] = []
    logout_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/admin/login-code":
            _assert_control(request)
            return httpx.Response(200, json={"code": ADMIN_CODE, "expires_at_ms": 2_000})
        if request.url.path == "/v1/admin/login/exchange":
            return _admin_login_response()
        if request.url.path == "/v1/admin/logout":
            logout_cookie_headers.append(request.headers.get("cookie"))
            return httpx.Response(200, json={"state": "logged_out"})
        _assert_admin_write(request)
        command = _command(request)
        response = httpx.Response(
            201,
            json=_credential_result(
                mutation_id=str(command["mutation_id"]),
                action="provision",
                state="HEALTHY",
            ),
            extensions={"reason_phrase": SYNTHETIC_SECRET},
        )
        retained_response.append(response)
        return response

    backend, _, _ = _backend(tmp_path, handler)
    secret = bytearray(SYNTHETIC_SECRET)
    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_reason_phrase_reflection",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert SYNTHETIC_SECRET.decode() not in caplog.text
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)
    assert "HTTP Request:" in caplog.text
    assert logout_cookie_headers == [None]
    assert retained_response and retained_response[0].content == b""
    assert dict(retained_response[0].headers) == {}
    assert retained_response[0].extensions == {}


@pytest.mark.parametrize("response_shape", ["extra-field", "invalid-allowed-field"])
def test_secret_is_zeroed_and_protocol_failure_detaches_response_canary(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    response_shape: str,
) -> None:
    caplog.set_level("DEBUG")

    def action(request: httpx.Request) -> httpx.Response:
        body = _credential_result(
            mutation_id="mut_bad",
            action="provision",
            state="HEALTHY",
        )
        if response_shape == "extra-field":
            body["api_key"] = SYNTHETIC_SECRET.decode()
        else:
            body["acted_at_ms"] = SYNTHETIC_SECRET.decode()
        return httpx.Response(201, json=body)

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    secret = bytearray(SYNTHETIC_SECRET)
    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_bad",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )
    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)
    assert SYNTHETIC_SECRET.decode() not in caplog.text


def test_invalid_command_detaches_pydantic_canary_and_zeroes_secret(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("no HTTP request expected")

    backend, _, _ = _backend(tmp_path, handler)
    secret = bytearray(SYNTHETIC_SECRET)
    invalid_mutation_id = SYNTHETIC_SECRET.decode() + "x" * 200
    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id=invalid_mutation_id,
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert requests == []
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)


def test_transport_failure_scrubs_secret_and_admin_request_authority(tmp_path: Path) -> None:
    retained: list[httpx.Request] = []

    def action(request: httpx.Request) -> httpx.Response:
        retained.append(request)
        raise httpx.RemoteProtocolError(SYNTHETIC_SECRET.decode(), request=request)

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    secret = bytearray(SYNTHETIC_SECRET)
    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_transport_failure",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)
    assert retained and retained[0].content == b""
    assert ADMIN_COOKIE not in "\n".join(retained[0].headers.values())
    assert CSRF_TOKEN not in "\n".join(retained[0].headers.values())


def test_success_scrubs_retained_secret_request_and_admin_authority(tmp_path: Path) -> None:
    retained: list[httpx.Request] = []

    def action(request: httpx.Request) -> httpx.Response:
        _assert_admin_write(request)
        command = _command(request)
        assert request.content == SYNTHETIC_SECRET
        retained.append(request)
        return httpx.Response(
            201,
            json=_credential_result(
                mutation_id=str(command["mutation_id"]),
                action="provision",
                state="HEALTHY",
            ),
        )

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    secret = bytearray(SYNTHETIC_SECRET)
    result = backend.credential_provision(
        secret,
        mutation_id="mut_retained_success",
        principal_id="principal_one",
        quota_scope_id="quota_one",
        pool_id="pool_one",
        alias="primary",
        expires_at_ms=None,
        exclusive_usage=True,
    )

    assert result["action"] == "provision"
    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert retained and retained[0].content == b""
    assert dict(retained[0].headers) == {}


def test_non_http_transport_failure_is_detached_and_scrubs_retained_request(
    tmp_path: Path,
) -> None:
    retained: list[httpx.Request] = []

    def action(request: httpx.Request) -> httpx.Response:
        _assert_admin_write(request)
        assert _command(request)["mutation_id"] == "mut_runtime_failure"
        assert request.content == SYNTHETIC_SECRET
        retained.append(request)
        raise RuntimeError(SYNTHETIC_SECRET.decode())

    backend, _, _ = _backend(tmp_path, _admin_handler(action))
    secret = bytearray(SYNTHETIC_SECRET)
    with pytest.raises(CliUnavailable, match="credential provision failed") as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_runtime_failure",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)
    assert retained and retained[0].content == b""
    assert dict(retained[0].headers) == {}


def test_keyboard_interrupt_scrubs_retained_request_and_zeroes_secret(tmp_path: Path) -> None:
    retained: list[httpx.Request] = []
    logout_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/control/admin/login-code":
            _assert_control(request)
            return httpx.Response(200, json={"code": ADMIN_CODE, "expires_at_ms": 2_000})
        if request.url.path == "/v1/admin/login/exchange":
            return _admin_login_response()
        if request.url.path == "/v1/admin/logout":
            logout_cookie_headers.append(request.headers.get("cookie"))
            return httpx.Response(200, json={"state": "logged_out"})
        _assert_admin_write(request)
        assert _command(request)["mutation_id"] == "mut_keyboard_interrupt"
        assert request.content == SYNTHETIC_SECRET
        retained.append(request)
        raise KeyboardInterrupt(SYNTHETIC_SECRET.decode())

    backend, _, _ = _backend(tmp_path, handler)
    secret = bytearray(SYNTHETIC_SECRET)
    with pytest.raises(
        KeyboardInterrupt,
        match="credential loopback request interrupted",
    ) as captured:
        backend.credential_provision(
            secret,
            mutation_id="mut_keyboard_interrupt",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )

    assert secret == bytearray(len(SYNTHETIC_SECRET))
    assert SYNTHETIC_SECRET.decode() not in _exception_graph_text(captured.value)
    assert logout_cookie_headers == [None]
    assert retained and retained[0].content == b""
    assert dict(retained[0].headers) == {}


def test_oversized_secret_is_rejected_and_zeroed_before_any_http(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise AssertionError("no HTTP request expected")

    backend, _, _ = _backend(tmp_path, handler)
    secret = bytearray(b"x" * (16 * 1_024 + 1))
    with pytest.raises(CliUnavailable, match="credential provision failed"):
        backend.credential_provision(
            secret,
            mutation_id="mut_large",
            principal_id="principal_one",
            quota_scope_id="quota_one",
            pool_id="pool_one",
            alias="primary",
            expires_at_ms=None,
            exclusive_usage=True,
        )
    assert secret == bytearray(16 * 1_024 + 1)
    assert requests == []
