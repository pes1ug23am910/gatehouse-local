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

The default and scripted suites make no provider network calls. `provider.mode: scripted` exercises
the same stock daemon composition, routing, API, CLI-backend, and MCP-backend paths with a bounded
local response manifest and synthetic credential-free authority.
That authority must be one deterministic, idempotent synthetic quota snapshot whose timestamp is
not refreshed on restart and whose settled usage is never replenished.

## Unit coverage

Policy precedence, provider-number parsing/canonicalization/projection boundaries, exact
reconciliation and tolerance arithmetic, HMAC fingerprints, duplicate eligibility, budget and quota
arithmetic, state transitions, retry classification, redaction, configuration validation, and
retention. Numeric coverage includes signed zero, fractions, exponent and significant-digit bounds,
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

Migration coverage includes v8-to-v9 exact-text backfill, unanchored cache clearing, valid anchor
preservation, corrupt-anchor atomic rollback, checksum/idempotence, and INSERT/UPDATE trigger
defenses. Durable-read and routing tests corrupt decimal grammar and snapshot scope, unit, capture
time, or projection and require catalog and atomic reservation paths to fail closed while preserving
existing reservations and eligible zero-cost cleanup.

Recovery coverage must prove that `READY` is not advertised before one complete due-job pass, an
attempt checkpoint reconstructs only its exact owner-bound resource, terminal usage settles the
original quota and root-run budget once, and corrupt or conflicting authority fails closed without
provider I/O.

## Security tests

- seed recognizable fake keys and scan every output surface;
- verify keys are absent from child environments;
- verify agent auth cannot access admin routes;
- verify no secret retrieval endpoint exists;
- reject arbitrary provider URL and headers;
- reject private and loopback targets;
- enforce watcher target and schedule restrictions;
- verify one-use approval binding;
- verify the exact-number wrapper remains typed through clean scanning, is canary-scanned through
  its canonical representation, and cannot leak raw numeric tokens through exceptions or audits;
- race approve and deny from independent SQLite connections and require exactly one winner;
- once the operator-facing emergency-unlock workflow exists, verify that its memory-only state is
  lost and the pool relocks after restart;
- verify an unsupported-provider canary is absent from v1.

## Documentation tests

Resolve Markdown links, validate examples, ensure public completed claims have evidence, require
schema version 9 and numeric-contract consistency, ensure local material is untracked, and
synchronize public documentation without publishing private ledgers.

## Local quality gates

```powershell
.\.venv\Scripts\pytest.exe
.\.venv\Scripts\ruff.exe check --no-cache .
.\.venv\Scripts\ruff.exe format --check --no-cache .
.\.venv\Scripts\mypy.exe --strict src tests scripts\check_markdown_links.py
.\.venv\Scripts\python.exe scripts\check_markdown_links.py
git diff --check
```

## Installed-process release gate

The final release path builds a wheel, installs it into a clean temporary virtual environment, and
runs `gatehoused`, `gatehouse`, `gatehouse-mcp`, `gatehouse-notifier`, and
`gatehouse-watchdog` from that installation. With a scripted provider and temporary database it
must exercise a controlled launch, MCP initialization and tool call, durable accounting, clean
shutdown, restart, and session re-adoption without test-only dependency injection.

This opt-in path passed on Windows from a separately installed wheel on 2026-08-19. It exercised all
five console scripts, one controlled long-lived MCP process, a clean daemon stop/restart, exact
session and root-run re-adoption at the new token epoch, synchronous accounting, and a nonterminal
asynchronous crawl that the restarted daemon settled before advertising `READY`. Real provider
networking remained disabled and only bounded scripted data was used.

Set `GATEHOUSE_E2E_BIN_DIR` to the clean environment's `Scripts` directory and run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\e2e\test_installed_process.py
```

In-process stock-composition coverage remains complementary rather than a substitute for this
artifact-level evidence.

## Release blockers

Any credential leak, unbounded queue or retry, watcher-reservation failure, unsafe ambiguous replay,
cross-scope coalescing, malformed durable exact observation, mismatched balance authority,
documentation overclaim, unresolved high-severity incident, or database integrity/migration failure
blocks release.
