# Scripts

Tracked scripts in this directory must be safe to publish and must not contain credentials, account-specific values, machine-specific paths, or private request content.

Included scripts:

- `bootstrap.ps1` creates the repository-local virtual environment, installs that repository by absolute path, and seeds configuration without overwriting existing files. Use `-ConfigPath` for a non-default main configuration.
- `register-tasks.ps1` registers the daemon and watchdog modules for the current Windows user through
  the virtual environment's windowless `pythonw.exe`. Both receive the same `-ConfigPath`; optional
  `-DatabasePath` and `-AgentPort` values override only the watchdog. Registered tasks do not open a
  console window, run in isolated/no-bytecode mode, and have no 24-hour execution limit.
- `unregister-tasks.ps1` removes only those two named tasks.
- `health-check.ps1` loads the agent port from the validated main configuration, or accepts `-AgentPort` directly. Live degraded states are reported successfully by default; use `-RequireReady` when any non-`READY` state must fail the check. `FAILED_CLOSED` always fails.
- `build-wheel-offline.ps1` creates a dedicated build environment from an explicit local wheelhouse and the hash-locked `requirements/build-wheel.txt` manifest, then runs the standard no-isolation wheel build. It disables package indexes, accepts only wheels, refuses to reuse its build environment, rejects build/output paths inside the repository, and never overwrites an existing output wheel. The wheelhouse must contain the exact artifacts named by the lock file; the script never downloads missing packages.
- `check_markdown_links.py` validates repository-relative Markdown links.
- `check_publication_hygiene.py` scans the candidate tree and Git history for private process files,
  prohibited authorship/tool credits, unexpected author identities, and credential-shaped values.
- `audit_release_wheel.py` verifies archive safety, `RECORD`, metadata, console scripts, negative
  artifact scope, and exact byte parity for every package source/resource without installing the
  wheel.
- `audit_installed_release.py` runs from a clean environment and verifies installed metadata,
  console scripts, import location, and the exact package source/resource file set and bytes.
- `verify_release_supply_chain.py` validates one per-minor hash lock against the reviewed wheelhouse
  manifest and exact wheel bytes, proves the active transitive metadata closure, applies the
  short-lived offline OSV snapshot, and creates a deterministic CycloneDX 1.6 SBOM.
- `verify_gate_toolchain.py` independently validates the 42-package runtime scope and 21-package
  gate-only scope, including exact locks/manifests/wheel bytes, actual Python patch-level markers,
  archive bounds, gate-root reachability, their combined Windows dependency graph, and two separate
  fail-closed OSV snapshots before a quality or release tool executes.
- `refresh_release_vulnerability_snapshot.py` is the explicit network-backed maintenance path for a
  non-overwriting OSV snapshot review candidate. The release gate never invokes it implicitly.
- `verify-release-candidate.ps1` performs the offline supply-chain gate and an index-disabled,
  hash-required clean dependency install from an explicit runtime wheelhouse. It installs the
  separately audited candidate from a generated exact-hash requirement with dependencies disabled,
  runs `pip check` and the installed-process E2E, checks process/task residue, and writes the result
  manifest only below ignored
  `.local/release-evidence/`. It never publishes or uploads an artifact.

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

The tracked Windows workflows mirror these gates. Their checkout and Python setup actions are pinned
to reviewed full commit SHAs. `windows-ci.yml` acquires the single-artifact hash locks from official
PyPI, verifies both manifests and OSV scopes before installation, installs the combined environment
offline with hashes required, then runs the complete source, formatting, lint, strict typing, link,
and hygiene checks
on Python 3.12, 3.13, and 3.14. `release-evidence.yml` is manual and non-publishing. It adds the
hash-locked offline build, deterministic runtime SBOM, and clean installed-wheel exercise. Missing,
expired, incomplete, or vulnerable advisory data fails closed. Both workflows reject checkout dirt
and retain evidence only in runner-temporary or ignored private locations.
