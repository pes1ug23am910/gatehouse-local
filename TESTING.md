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

## Unit coverage

Policy precedence, canonicalization, HMAC fingerprints, duplicate eligibility, budget and quota arithmetic, state transitions, retry classification, redaction, configuration validation, and retention.

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
- race approve and deny from independent SQLite connections and require exactly one winner;
- once the operator-facing emergency-unlock workflow exists, verify that its memory-only state is
  lost and the pool relocks after restart;
- verify an unsupported-provider canary is absent from v1.

## Documentation tests

Resolve Markdown links, validate examples, ensure public completed claims have evidence, ensure local material is untracked, and synchronize progress and changelog.

## Local quality gates

```powershell
.\.venv\Scripts\pytest.exe
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\mypy.exe src tests scripts\check_markdown_links.py
.\.venv\Scripts\python.exe scripts\check_markdown_links.py
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

Any credential leak, unbounded queue or retry, watcher-reservation failure, unsafe ambiguous replay, cross-scope coalescing, documentation overclaim, unresolved high-severity incident, or database integrity/migration failure blocks release.
