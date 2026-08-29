# Release dependency inputs

Gatehouse keeps the release runtime inputs separate from the developer environment. These files
are reviewable release controls; none of them authorizes publication.

- `runtime-py312.txt`, `runtime-py313.txt`, and `runtime-py314.txt` pin the complete reachable
  runtime dependency closure. Every line selects one version and one exact wheel SHA-256.
- `runtime-wheelhouse.json` records each reviewed wheel filename, distribution identity, size,
  SHA-256, and compatible target. The Python 3.12, 3.13, and 3.14 targets are CPython on Windows
  x64. Minor-specific binary wheels are intentionally different, so a 3.14 wheelhouse is not
  evidence for 3.12 or 3.13.
- `osv-runtime-snapshot.json` is a short-lived, exact-version OSV advisory snapshot. It is mandatory
  offline input, not a permanent claim that dependencies are vulnerability-free.
- `gate-py312.txt`, `gate-py313.txt`, and `gate-py314.txt` pin the 21-package gate-only closure for
  source quality checks and release building. Runtime packages are deliberately not duplicated;
  active gate dependencies such as `build`'s Windows `colorama` edge resolve through the separately
  verified 42-package runtime closure.
- `gate-wheelhouse.json` is the independent reviewed manifest for those gate-only wheels.
- `osv-gate-tools-snapshot.json` is the short-lived OSV snapshot for code that executes in the
  quality and release trust path. The runtime snapshot does not cover or make claims about these
  tools; either missing, incomplete, vulnerable, future-dated, stale, or malformed scope fails the
  relevant workflow closed.
- `quality-roots.in` records the ten exact direct quality/build roots used only to maintain and
  verify reachability of the gate locks. Workflows never install this unhashed maintenance input.
- `build-wheel.txt` is the independent hash lock for the offline build environment.

On each matching Windows x64 Python minor, acquire an exact runtime wheelhouse with network access:

```powershell
$runtimeWheelhouse = Join-Path $env:TEMP "gatehouse-runtime-py312"
New-Item -ItemType Directory -Path $runtimeWheelhouse | Out-Null
py -3.12 -m pip download --disable-pip-version-check --no-cache-dir `
    --index-url https://pypi.org/simple --no-deps --only-binary=:all: --require-hashes `
    --requirement requirements\runtime-py312.txt `
    --dest $runtimeWheelhouse
```

Acquire the matching gate-only wheelhouse with the same trusted bootstrap interpreter:

```powershell
$gateWheelhouse = Join-Path $env:TEMP "gatehouse-gate-py312"
New-Item -ItemType Directory -Path $gateWheelhouse | Out-Null
py -3.12 -m pip download --disable-pip-version-check --no-cache-dir `
    --index-url https://pypi.org/simple --no-deps --only-binary=:all: --require-hashes `
    --requirement requirements\gate-py312.txt `
    --dest $gateWheelhouse
```

Repeat with the corresponding interpreter and locks for 3.13 and 3.14. Cross-target maintenance
can instead add `--platform win_amd64 --python-version 3.12 --implementation cp --abi cp312` and
change all four target values together for each minor. These reviewed acquisition commands contact
only the official PyPI simple index at `https://pypi.org/simple` and the artifact URLs it returns.
The tracked single-artifact hashes reject substitution; the offline verifier additionally rejects
filename, size, identity, metadata, compatibility-tag, dependency-graph, or archive-bound drift.

## Offline verification and SBOM

`scripts/verify_gate_toolchain.py` verifies the runtime and gate inputs as separate disjoint scopes,
then validates the gate roots and their active Windows dependency graph against the combined exact
environment. Both workflows acquire with hashes and run this verifier before installing any acquired
wheel. A pristine interpreter uses only pip's bundled `packaging` parser for this bootstrap check.
They then install from local wheelhouses with `--no-cache-dir`, `--no-index`, `--no-deps`,
`--only-binary=:all:`, and `--require-hashes` before any quality or build tool command. The pinned
setup action, selected CPython distribution, and its bundled pip remain reviewed bootstrap trust;
neither runtime nor gate-tool OSV data is represented as covering those bootstrap components.

`scripts/verify-release-candidate.ps1` separately invokes
`scripts/verify_release_supply_chain.py` before it creates the clean candidate installation. The
verifier rejects any extra, missing, renamed, resized, hash-different, metadata-incompatible, or
over-bound wheel. It emits canonical CycloneDX 1.6 JSON without a timestamp or random serial number,
reloads it, and records its SHA-256 in private release evidence. Runtime dependencies and the
separately audited candidate are installed from generated hash-locked requirement files with
`--require-hashes`; the candidate is also installed with `--no-deps`.

The verification step makes no advisory or package-index request. Missing, malformed, future-dated,
incomplete, vulnerable, or expired advisory data fails closed. The tracked snapshot expires no more
than seven days after its query time.

## Refreshing advisory data

A current scan requires separate network-backed operations against the fixed official OSV batch
endpoint. Produce non-overwriting review candidates under ignored `.local/`:

```powershell
.\.venv\Scripts\python.exe -I scripts\refresh_release_vulnerability_snapshot.py `
    --runtime-lock requirements\runtime-py312.txt `
    --runtime-lock requirements\runtime-py313.txt `
    --runtime-lock requirements\runtime-py314.txt `
    --output .local\osv-runtime-snapshot.candidate.json

.\.venv\Scripts\python.exe -I scripts\refresh_release_vulnerability_snapshot.py `
    --runtime-lock requirements\gate-py312.txt `
    --runtime-lock requirements\gate-py313.txt `
    --runtime-lock requirements\gate-py314.txt `
    --output .local\osv-gate-tools-snapshot.candidate.json
```

The only advisory endpoint is `https://api.osv.dev/v1/querybatch`; redirects are rejected. Review
each candidate's independent package coverage, query and expiry times, and advisory identifiers
before replacing its matching tracked snapshot. If OSV, DNS, TLS, Python, or required local tooling
is unavailable, refresh fails and no relevant gate can pass after the prior snapshot expires.

The workflows pin `actions/checkout` to commit
`3d3c42e5aac5ba805825da76410c181273ba90b1` and `actions/setup-python` to commit
`5fda3b95a4ea91299a34e894583c3862153e4b97`. Those immutable action inputs were reviewed from the
official `actions/checkout` and `actions/setup-python` GitHub repositories; tag names are retained
only as comments and are not execution references.

`pip-audit` is not installed in the repository environment and is not silently substituted for this
protocol. An independently provisioned, reviewed `pip-audit` tool environment can provide a second
online check with:

```powershell
python -m pip_audit --require-hashes --no-deps --disable-pip `
    --vulnerability-service osv --format json `
    --requirement requirements\runtime-py314.txt
```

That optional command requires its own trusted tool installation plus current OSV network access;
its output does not replace the canonical tracked snapshot or the per-minor wheel verification.
