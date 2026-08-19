from __future__ import annotations

import json
from collections.abc import Callable, Sequence
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
