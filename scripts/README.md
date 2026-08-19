# Scripts

Tracked scripts in this directory must be safe to publish and must not contain credentials, account-specific values, machine-specific paths, or private request content.

Included scripts:

- `bootstrap.ps1` creates the repository-local virtual environment, installs that repository by absolute path, and seeds configuration without overwriting existing files. Use `-ConfigPath` for a non-default main configuration.
- `register-tasks.ps1` registers the installed `gatehoused` and `gatehouse-watchdog` entry points for the current Windows user. Both receive the same `-ConfigPath`; optional `-DatabasePath` and `-AgentPort` values override only the watchdog. Registered tasks have no 24-hour execution limit.
- `unregister-tasks.ps1` removes only those two named tasks.
- `health-check.ps1` loads the agent port from the validated main configuration, or accepts `-AgentPort` directly. Live degraded states are reported successfully by default; use `-RequireReady` when any non-`READY` state must fail the check. `FAILED_CLOSED` always fails.
- `check_markdown_links.py` validates repository-relative Markdown links.

Machine-specific helpers belong under `.local/`.
