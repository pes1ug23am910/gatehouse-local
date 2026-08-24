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


def test_registered_tasks_share_config_and_have_no_twenty_four_hour_limit() -> None:
    registration = _script("register-tasks.ps1")

    assert '".venv\\Scripts\\pythonw.exe"' in registration
    assert '"gatehouse.daemon.main"' in registration
    assert '"gatehouse.watchdog.main"' in registration
    assert registration.count('@("-I", "-B", "-m"') == 2
    assert registration.count("New-ScheduledTaskAction -Execute $windowlessPython") == 2
    assert "gatehoused.exe" not in registration
    assert "gatehouse-watchdog.exe" not in registration
    assert "$daemonArguments" in registration
    assert '"--config"' in registration
    assert '"--database"' in registration
    assert '"--agent-port"' in registration
    assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in registration
    assert "New-TimeSpan -Hours 24" not in registration
    assert "$WhatIfPreference" in registration
    assert "no tasks were changed" in registration


def test_registration_summary_only_names_tasks_registered_by_should_process() -> None:
    registration = _script("register-tasks.ps1")

    for task_name in ("Gatehouse Daemon", "Gatehouse Watchdog"):
        branch = registration.index(f'if ($PSCmdlet.ShouldProcess("{task_name}"')
        register = registration.index(f'Register-ScheduledTask -TaskName "{task_name}"', branch)
        record = registration.index(f'$registeredTaskNames.Add("{task_name}")', register)
        branch_end = registration.index("\n}", record)
        assert branch < register < record < branch_end

    assert "$registeredTaskNames.Count -eq 0" in registration
    assert "$registeredTaskNames -join ' and '" in registration
    assert "Registered Gatehouse Daemon and Gatehouse Watchdog for" not in registration


def test_health_check_uses_resolved_port_and_distinguishes_degraded_from_failure() -> None:
    health = _script("health-check.ps1")

    assert "--print-settings" in health
    assert '"http://127.0.0.1:$AgentPort"' in health
    assert '$readyState -eq "FAILED_CLOSED"' in health
    assert "$RequireReady" in health
    assert "127.0.0.1:47621" not in health
