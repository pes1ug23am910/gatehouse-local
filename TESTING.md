# Testing

## Test layers

```text
unit
contract
integration
concurrency
chaos and recovery
security and privacy
acceptance
```

Real provider credits must not be used for concurrency, retry, failover, or chaos testing.

The default and scripted suites make no provider network calls.
`providers.firecrawl.workload.mode: scripted` exercises
the same stock daemon composition, routing, API, CLI-backend, and MCP-backend paths with a bounded
local response manifest and synthetic credential-free authority.
That authority must be one deterministic, idempotent synthetic quota snapshot whose timestamp is
not refreshed on restart and whose settled usage is never replenished.

Source, artifact and installed checks use fresh synthetic fixtures and environments. They do not
migrate retained state or alter an existing installation. Live-workload validation is separate.
The observer's separately gated fixed credit-status request is outside the workload invocation ceiling.

New schema-17/18/19 tests cover exact durable observation-intent authority, irreversible session
request/cancellation bindings, and bounded lifecycle retention. Custody regressions exercise
identity-bound envelopes, create-only publication, replacement-preserving rollback and abandoned
worker cleanup. Native Windows cases use fresh synthetic files and current-user DPAPI canaries;
they never operate on retained installation state. File-symlink refusal tests use an explicit
metadata simulation when the account lacks link privilege; separate native junction cases exercise
real reparse ancestry. A simulated branch is not reported as native file-symlink proof.

## Current candidate verification

The `0.0.2.dev0` candidate has the following verification results as of 2026-09-13. Counts apply
independently to each runtime and are not added together as distinct tests.

| Check | Result |
| --- | --- |
| Python 3.12.10 source suite | 3,781 cases and 32 subtests passed; zero failures, warnings or skips |
| Python 3.13.15 source suite | 3,781 cases and 32 subtests passed; zero failures, warnings or skips |
| Python 3.14.4 source suite | 3,781 cases and 32 subtests passed; zero failures, warnings or skips |
| Strict mypy on all three versions | All 300 Python files pass |
| Ruff lint and formatting | Pass |
| Independent wheel builds | Two matching wheel hashes; wheel/source/RECORD and five entry-point definitions verified |
| Fresh installed runtime matrix | Python 3.12.10, 3.13.15 and 3.14.4 each passed all three installed-process cases and all five console scripts; zero failures, warnings or skips |

The source suite excludes only the three opt-in installed-process cases described below. Native
Windows source cases use new ACL/DPAPI fixtures. Configuration regressions cover stable agreement
across unrelated sibling-file creation while preserving ancestor identity, permissions and full
metadata checks during each capture. All 326 configuration-security cases are included in the
full source matrix.

Each installed run used a new hash-locked runtime and the same reproducible wheel, verified package
contents and import origins, passed dependency and SBOM audits, and rechecked integrity after the
workflows. All owned test processes exited and retained native scratch-root handles were released.
The checks used synthetic secrets and numeric-loopback scripted workloads. They did not register
scheduled tasks, inspect ambient task/process state, use existing installations or call a provider.

## Unit coverage

Long-lived environment tests cover exact and one-over UTF-8 budgets, bounded iteration, duplicate
case variants, invalid scalar/encoding input, coercion canaries, excluded values, empty bindings
and interruption propagation. Fake production subprocess adapters check both platform branches,
unchanged captured values and a fresh dictionary per call. Entrypoint cases require fixed exit-2
refusal before configuration discovery, environment replacement, secret prompts or process work.
These tests do not execute native processes or establish runtime/path ownership.

Daemon selection tests cover bounded literal paths and exact adjacent overrides, plus fake CLI and
watchdog consumers that assert one availability query, fixed refusal, no alternate lookup or spawn,
preserved configuration handoff, control-flow interruption and existing-responder bypass. These
source checks do not execute a launcher or establish native runtime/import ownership.

Policy precedence, provider-number parsing/canonicalization/projection boundaries, exact
reconciliation and tolerance arithmetic, scheduled cadence/baseline advancement, HMAC fingerprints,
duplicate eligibility, budget and quota arithmetic, state transitions, retry classification,
redaction, configuration validation, retention, and fixed-band database-footprint alert transitions.
Numeric coverage includes signed zero, fractions, exponent and significant-digit bounds,
precision beyond binary float, INT64 saturation, the 383-digit provider-delta and 384-digit derived
unexplained-delta envelopes, duplicate JSON keys, non-standard constants, numeric extensions,
discarded malformed/oversized error bodies, and HTTP-200-only credit-status success.

## Mock provider behavior

The scripted mock must support success, invalid input, invalid credential, exhausted credits, permission failure, timeout, conflict or ambiguity, rate limit with retry hint, transient failures, malformed JSON, connection resets before and after submission, delayed asynchronous jobs, and unexpected response fields.

## Concurrency target

```text
256 connected client contexts
200 simulated active identities
60 sustained producers
96 broker-level in-flight operations
300 queued operations
8 provider requests in flight
1 watcher-reserved provider slot
```

Pass conditions include no unbounded memory growth, no lost attribution, no starvation, responsive health, no duplicate provider call for coalescible work, no quota oversubscription, no SQLite corruption, and no credential in output.

## Crash and recovery tests

Terminate the daemon while queued, after quota reservation, after synchronous submission, after an
asynchronous provider-success checkpoint, and while a terminal job is `SETTLING`. Restart with
active sessions, watcher lease, and approvals. Simulate corrupt policy, migration mismatch,
semantically inconsistent job authority, SQLite busy behavior, and watchdog crash loops.

Migration coverage includes v8-to-v9 exact-text backfill, append-only v9-to-v10 provider-account
state, exact-dimension, provenance, freshness, schedule, and breaker backfill, append-only
v10-to-v11 durable runaway quarantine/burst authority, v11-to-v12 immutable provider/team
quota-scope identity reservations, and v12-to-v13 exact-generation fresh-run recovery evidence. It
also covers the v13-to-v14 bounded-retention query indexes and v14-to-v15 per-scope QUICK/FULL
reconciliation schedule state. Tests require unanchored cache clearing, valid anchor preservation,
corrupt-anchor atomic rollback, fixed checksums through migration 14, idempotence, populated-
v9/v10/v11/v12/v13/v14 compatibility, rollback to intact v12 on a broken v13 migration, rollback to
intact v13 on a broken v14 migration, rollback to intact v14 on a broken v15 migration followed by a
successful retry, owner/authority triggers, schedule scope/baseline/generation authority,
recovery-evidence truthfulness and authority triggers, and INSERT/UPDATE immutability triggers.
Durable-read and routing tests corrupt decimal grammar and snapshot scope, unit, capture time,
credential generation, freshness, or projection and require catalog, atomic reservation, and final
credential fences to fail closed while preserving eligible zero-cost exact-affinity cleanup.

Recovery coverage must prove that `READY` is not advertised before one bounded
retention/checkpoint/footprint batch, one bounded scheduled-reconciliation batch, and one complete
due-job pass. An attempt checkpoint reconstructs only its exact owner-bound resource; terminal usage
settles the
original quota and root-run budget once, and corrupt or conflicting authority fails closed without
provider I/O. It also proves that definitive exhaustion survives restart beyond the former timer,
terminal attempt and exhaustion state commit atomically, account onboarding/rotation custody sagas
recover idempotently, observation schedules rebind to the current generation after a crash, and
active burst permits restart as conservative orphans whose grant requires a new decision. Required-
task lifecycle tests cover maintenance and scheduled-reconciliation exits, persistence failures,
joined cancellation, and transition to `FAILED_CLOSED`.

One-send coverage requires a strict server ceiling of one, a durable claim before transport
handoff, repeated/cross-connection claim rejection, crash-window preservation, and no retry after
any transport invocation. Cases include HTTP 401/402/429, connect failure, malformed response,
retry-safe operations, cancellation, and ambiguity. Unknown HTTP billing must preserve both quota
and budget holds; proven unsubmitted connect failure settles zero, known actual cost settles
explicitly, and recovered holds cannot fall below known actual usage. Migration-16 coverage must
preserve prior checksums and reject inconsistent legacy authority atomically on fresh fixtures.

Resource-bound coverage fixes database-footprint observation to the main file plus three known
sidecars, verifies the exact 90%/cap bands and idempotent singleton alert, and exercises pressure
checkpoint remeasurement. Scheduled reconciliation tests enforce scope-count and wall-time batch
bounds, separate QUICK/FULL baselines, first-observation initialization, same-observation mismatch
deduplication, provider-I/O absence, and atomic result/alert/quarantine/baseline advancement under
independent SQLite connections.

## Security tests

- seed recognizable fake keys and scan every output surface;
- verify keys are absent from child environments;
- verify agent auth cannot access admin routes;
- verify no secret retrieval endpoint exists;
- reject arbitrary provider URL and headers;
- reject private and loopback targets;
- enforce watcher target and schedule restrictions;
- verify one-use approval binding;
- verify restart-safe exact approval consumption, crawl `WAITING_APPROVAL` rehydration by stable
  request handle, process-random keyed continuation indexes, concurrent continuation collapse, and
  cancellation-safe claim release without an MCP approve/deny surface; require same-session/
  client/workspace/root re-adoption, reject inheritance by a fresh controlled launch, and let a
  genuinely absent explicit crawl ID proceed normally under `ALLOW` or create a new row under
  `ASK`;
- verify the exact-number wrapper remains typed through clean scanning, is canary-scanned through
  its canonical representation, and cannot leak raw numeric tokens through exceptions or audits;
- race approve and deny from independent SQLite connections and require exactly one winner;
- verify that the operator-facing emergency unlock's memory-only state is lost and the pool relocks
  after restart;
- verify unimplemented-provider operations and non-default switches fail closed.
- verify account add/rotate secrets exist only in hidden-prompt memory and DPAPI custody, never in
  command arguments, environment variables, request/response JSON, SQLite rows, logs, errors, or
  child processes;
- verify account add requires a valid stable 1–160 character visible-ASCII provider team ID,
  immediately
  replaces it with an installation-keyed HMAC fingerprint, rejects duplicate declarations as a
  second balance, keeps one identity per scope across tombstone, and never exposes raw ID or
  fingerprint in status, results, audit, logs, errors, or child processes;
- verify management and observer credentials cannot enter workload routing, the emergency store is
  absent from the observer transport, and arbitrary provider origins/methods/headers/auth remain
  unrepresentable;
- verify unauthorized, permission, malformed, and ambiguous outcomes do not spray across unrelated
  account scopes.
- verify no HTTP 401/402/429 or transport failure can cause a second send under the sole supported
  per-invocation ceiling, including operations otherwise marked retry-safe;
- verify new/missing failover defaults false and non-Boolean values fail; authenticated ordinary
  pool toggles bind actor, alias, action, reason fingerprint, and mutation ID, persist audit and
  configuration atomically, reject conflicting replay, and cannot enable emergency pools;
- verify strict candidate bounds 1 and 32, overflow at 33, bounded SQL materialization of configured
  members and all workload generations, deterministic ranking without unranked truncation, and
  exact-affinity cleanup independent of unrelated pool overflow;
- verify equivalent and varied aggregate bursts quarantine the exact session/root-run/service,
  survive restart without timer healing, fence fresh same-client session/root admission across all
  unrecovered states, consume dashboard-authorized operation/time/request/credit/concurrency grants
  atomically, and reject fresh-run recovery while permits, ambiguous work, or affinity remain;
- verify an explicit `workspaces.allow` plus canonical current-directory containment is required for
  controlled launch, link escapes fail closed, legacy profiles have no implicit launch authority,
  and two client profiles can bind one workspace/pool with separate attribution;

## Documentation tests

Resolve Markdown links, validate examples, ensure public completed claims have evidence, require
schema version 19 and numeric-contract consistency, ensure local material is untracked, and
synchronize public documentation without publishing private ledgers.

## Local quality gates

```powershell
$qualityTemp = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ("gatehouse-quality-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $qualityTemp | Out-Null

.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider `
    --basetemp (Join-Path $qualityTemp "pytest")
.\.venv\Scripts\python.exe -B -m ruff check --no-cache .
.\.venv\Scripts\python.exe -B -m ruff format --check --no-cache .
.\.venv\Scripts\python.exe -B -m mypy --strict --no-incremental `
    src tests scripts
.\.venv\Scripts\python.exe -B scripts\check_markdown_links.py
.\.venv\Scripts\python.exe -B scripts\check_publication_hygiene.py
git diff --check
```

The tracked `Windows CI` workflow runs those gates independently on Python 3.12, 3.13, and 3.14.
It has read-only repository permission, fetches full history for the publication-hygiene scan, and
does not cache or publish build artifacts.

## Installed-process release gate

The final release path builds a wheel, installs it into a clean temporary virtual environment, and
runs `gatehoused`, `gatehouse`, `gatehouse-mcp`, `gatehouse-notifier`, and
`gatehouse-watchdog` from that installation. With a scripted provider and temporary database it
must exercise a controlled launch, MCP initialization and tool call, durable accounting, clean
shutdown, restart, and session re-adoption without test-only dependency injection. The v0.0.2
candidate gate additionally performs clean-install account onboarding through the supported
loopback CLI/API surface, idempotent add replay, redacted list/status, disabled-network refresh
rejection, observation-schedule toggling, restart restoration, rotation and replay, durable
disable/recover/remove operations, installed DPAPI custody checks, and secret-canary scans without a
provider request or raw-SQL route seeding. The installed process path also exercises its configured
workspace binding through controlled MCP launch. It uses a synthetic non-secret team ID, but does
test duplicate-ID rejection before and after tombstoning, query the identity-reservation table,
verify raw-ID/fingerprint redaction from result and audit surfaces, and prove that removal retains the
identity reservation. It does not exercise approval/runaway projections; those behaviors are covered
by source integration and unit tests. No installed test claims live provider pooling.

The v0.0.1 opt-in path passed on Windows from a separately installed wheel on 2026-08-19. It exercised all
five console scripts, one controlled long-lived MCP process, a clean daemon stop/restart, exact
session and root-run re-adoption at the new token epoch, synchronous accounting, and a nonterminal
asynchronous crawl that the restarted daemon settled before advertising `READY`. Real provider
networking remained disabled and only bounded scripted data was used.

Set `GATEHOUSE_E2E_BIN_DIR` to the clean environment's `Scripts` directory, choose a fresh
`--basetemp` directory outside the repository, and run:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider `
    --basetemp C:\Path\Outside\Repository\gatehouse-e2e-temp `
    tests\e2e\test_installed_process.py
```

In-process stock-composition coverage remains complementary rather than a substitute for this
artifact-level evidence.

`scripts/verify-release-candidate.ps1` automates the non-publishing artifact gate from an explicit
candidate wheel and runtime wheelhouse. It refuses a dirty checkout or reused clean environment,
audits wheel `RECORD` and exact package source/resource parity, verifies the per-minor runtime hash
lock and reviewed wheelhouse manifest, applies the current bounded OSV snapshot, and creates a
deterministic CycloneDX 1.6 SBOM. It installs the runtime closure with package-index access disabled
and hashes required, installs the separately audited candidate with dependency resolution disabled,
runs `pip check`, verifies all five entry-point definitions, runs this installed-process test, checks
for owned-process and scheduled-task residue, and writes a hashed JSON evidence set only under
ignored `.local/release-evidence/`.

The manual `Non-publishing release evidence` workflow runs that path independently on Python 3.12,
3.13, and 3.14 and intentionally uploads nothing. Minor-specific binary wheels prevent one target's
wheelhouse from serving as evidence for another. Missing or extra artifacts, an unavailable or stale
advisory snapshot, incomplete version coverage, or any reported advisory fails closed. Every
generated manifest keeps `publication_authorized` false.

## Manual live-provider validation evidence

A separately authorized manual release validation on 2026-08-22 issued exactly one fixed
credit-status request to the real provider. Authentication succeeded, exact integer observations
were preserved, and the provider balance remained unchanged through follow-up. It performed no
Firecrawl workload, fractional live case, retry, or revoked-key test. This historical v0.0.1
evidence is not part of
the automated suite, does not authorize a repeat provider request, and validates only that fixed
exact-integer path. Numeric edge cases remain local contract and scripted-test evidence.

## Release blockers

Any credential leak, unbounded queue or retry, watcher-reservation failure, unsafe ambiguous replay,
cross-scope coalescing, malformed durable exact observation, mismatched balance authority,
unsafe 429 spray, cross-offender runaway quarantine, prompt-derived approval, documentation
overclaim, unresolved high-severity incident, or database integrity/migration failure
blocks release.
