# Scripts

Tracked scripts in this directory must be safe to publish and must not contain credentials, account-specific values, machine-specific paths, or private request content.

Included scripts:

- `bootstrap.ps1` creates the repository-local virtual environment, installs that repository by absolute path, and seeds configuration without overwriting existing files. Use `-ConfigPath` for a non-default main configuration.
- `register-tasks.ps1` registers the installed `gatehoused` and `gatehouse-watchdog` entry points for the current Windows user. Both receive the same `-ConfigPath`; optional `-DatabasePath` and `-AgentPort` values override only the watchdog. Registered tasks have no 24-hour execution limit.
- `unregister-tasks.ps1` removes only those two named tasks.
- `health-check.ps1` loads the agent port from the validated main configuration, or accepts `-AgentPort` directly. Live degraded states are reported successfully by default; use `-RequireReady` when any non-`READY` state must fail the check. `FAILED_CLOSED` always fails.
- `build-wheel-offline.ps1` creates a dedicated build environment from an explicit local wheelhouse and the hash-locked `requirements/build-wheel.txt` manifest, then runs the standard no-isolation wheel build. It disables package indexes, accepts only wheels, refuses to reuse its build environment, rejects build/output paths inside the repository, and never overwrites an existing output wheel. The wheelhouse must contain the exact artifacts named by the lock file; the script never downloads missing packages.
- `check_markdown_links.py` validates repository-relative Markdown links.

Example offline build:

```powershell
$candidateRoot = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ("gatehouse-candidate-" + [Guid]::NewGuid().ToString("N"))

.\scripts\build-wheel-offline.ps1 `
    -PythonExecutable C:\Path\To\python.exe `
    -Wheelhouse C:\Path\To\verified-wheelhouse `
    -BuildEnvironment (Join-Path $candidateRoot "build-venv") `
    -OutputDirectory (Join-Path $candidateRoot "wheel")
```

Use a new `-BuildEnvironment` path for every run. When omitted, it defaults to a unique directory
under the operating-system temporary root. Audit and clean-install the resulting wheel before
treating it as candidate evidence. The verified wheelhouse, build environment, and output directory
must all be outside the repository checkout.

Machine-specific helpers belong under `.local/`.
