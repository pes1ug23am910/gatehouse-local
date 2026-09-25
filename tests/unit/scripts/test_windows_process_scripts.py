from __future__ import annotations

from pathlib import Path

SCRIPTS = Path(__file__).parents[3] / "scripts"


def _script(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


def test_bootstrap_installs_the_repository_root_even_from_another_directory() -> None:
    bootstrap = _script("bootstrap.ps1")

    assert '"${repositoryRoot}[dev]"' in bootstrap
    assert "else { $repositoryRoot }" in bootstrap
    assert "-e $installTarget" in bootstrap
    assert 'else { "." }' not in bootstrap


def test_task_registration_has_only_a_fixed_refusal_after_parameter_binding() -> None:
    registration = _script("register-tasks.ps1")

    # An exact, inert parameter block plus one terminating statement is intentional.
    # This is source-contract evidence; native PowerShell behavior is a separate gate.
    statements = "\n".join(line.strip() for line in registration.splitlines() if line.strip())
    assert statements == "\n".join(
        (
            '[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]',
            "param(",
            '[string]$ConfigPath = "",',
            '[string]$DatabasePath = "",',
            "[int]$AgentPort = 0",
            ")",
            'throw "Task registration is unavailable: a reviewed native task adapter is required."',
        )
    )


def test_task_removal_has_no_name_lookup_or_deletion_path() -> None:
    removal = _script("unregister-tasks.ps1")

    statements = "\n".join(line.strip() for line in removal.splitlines() if line.strip())
    assert statements == "\n".join(
        (
            '[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]',
            "param()",
            'throw "Task removal is unavailable: a reviewed native task adapter is required."',
        )
    )


def test_health_check_uses_resolved_port_and_distinguishes_degraded_from_failure() -> None:
    health = _script("health-check.ps1")

    assert "--print-settings" in health
    assert '"http://127.0.0.1:$AgentPort"' in health
    assert '$readyState -eq "FAILED_CLOSED"' in health
    assert "$RequireReady" in health
    assert "127.0.0.1:47621" not in health
