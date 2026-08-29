# Changelog

All notable user-visible changes are recorded here.

## [0.0.2] - Unreleased development candidate

### Added

- Added coherent `config init`, explained configuration validation, sanitized local diagnostics,
  Windows Python 3.12–3.14 CI, and a non-publishing offline wheel/install evidence workflow.
- Added reviewed, fully hashed Windows runtime locks for Python 3.12–3.14, an exact wheelhouse
  manifest, a time-bounded OSV snapshot, deterministic CycloneDX SBOM generation, and an offline
  release gate that verifies hashes, wheel compatibility, dependency closure, and advisory status.
- Added create-only sanitized JSON support bundles with bounded schema, size, alert summaries, and
  secret scanning; paths, identifiers, configuration text, database rows, and environment values
  remain outside the artifact.
- Added append-only migration 14 with indexes for every bounded periodic-retention query.
- Added supported clean-install Firecrawl account onboarding and alias-based `accounts` commands for
  add, list/status, rotate, disable, recover, remove, manual refresh, and observation scheduling.
  Add requires `--team-id` as non-secret quota-scope metadata; add and rotate accept the secret only
  through the existing hidden-prompt binary loopback path into DPAPI custody.
- Added append-only migration 10 for provider/account identity kinds, credential roles, exact native
  quota dimensions, authenticated observation provenance and freshness, durable quota-scope state
  events, breaker recovery policy, and default-disabled observation schedules.
- Added a bounded Firecrawl credit observer with an independent, default-disabled live/network
  switch. Each account schedule is separately disabled until an operator enables it.
- Added a code-owned provider registry for typed operations, fixed origins, methods, paths, headers,
  authentication strategies, response policies, credential roles, and provider implementation state.
  Future-provider identifiers are foundation-only and expose no workload or mutation operations.
- Added redacted account status containing only alias, effective state, exact provider-native
  remaining/plan values, observation time, staleness, unit, and code-owned source.
- Added append-only migration 11 for durable session/root-run/service runaway quarantines and
  request-bound bounded-burst permits, including restart orphan recovery and database owner/
  authority fences.
- Added append-only migration 12 and mandatory non-secret Firecrawl `provider_team_id` onboarding.
  Gatehouse immediately stores only an installation-HMAC identity reservation, preventing one
  declared team from becoming multiple quota scopes and retaining that guard after tombstone.
- Added repeated-equivalent and aggregate burst detection that blocks only the responsible client
  run. The local dashboard can deny it or authorize an operation-allowlisted burst with explicit
  time, request, credit, and concurrency ceilings; agent/MCP prompt text has no decision authority.
- Added explicit per-client `workspaces.allow` launch authority and canonical current-directory
  containment. Distinct MCP client profiles may share a workspace/pool while retaining separate
  session and root-run attribution.
- Added bounded MCP approval continuation and durable crawl-approval rehydration. The response links
  only to the fixed loopback dashboard; the MCP surface exposes no approval operation. Rehydration
  requires the same durable session/client/workspace/root-run authority, so a fresh controlled
  launch cannot inherit another session's approval.

### Changed

- Resolved relative database paths against the main configuration file's directory instead of the
  caller's working directory, and capped configured SQLite busy waits at five seconds. Existing
  configurations that relied on a different working directory or a larger `busy_timeout_ms` must be
  updated before startup.
- Made session revocation durably invalidate queued work, signal scheduler cancellation, revalidate
  authority immediately before provider handoff, and classify cancellation after a possible handoff
  as an uncertain outcome rather than replaying it.
- Bounded request-body time and size, raw and decoded provider responses, JSON structure, credential
  custody enumeration/files, and periodic database maintenance work.
- Made watchdog probes distinguish liveness from readiness, require exact readiness HTTP/state
  contracts after restart, reject incompatible databases without migrating them, and clean up an
  unsuccessful child it owns.
- Made the stock daemon run one bounded retention batch per configured maintenance interval, prune
  only eligible low-severity closed alerts, preserve watchdog and incident evidence, and request a
  passive WAL checkpoint outside the retention transaction.
- Made clean-install account graphs use canonical typed identifiers while retaining exact,
  class-scoped compatibility for UUIDv4-form identifiers created by earlier `0.0.2.dev0`
  onboarding, without rewriting database rows or DPAPI custody bindings.
- Made the supplied daemon and watchdog Task Scheduler actions use windowless `pythonw.exe` module
  launches in isolated/no-bytecode mode, with null-device standard-stream hardening when the GUI
  interpreter supplies no console streams.
- Made authenticated zero/negative Firecrawl balances and definitive quota-exhausted responses set a
  durable `EXHAUSTED` scope state. Elapsed timers and daemon restarts cannot restore eligibility;
  recovery requires a newer authenticated positive observation or an explicit audited operator
  action, and fresh quota authority is still required before positive-cost routing.
- Made deterministic fill-first routing share the leading healthy account while quota and dispatch
  headroom remain, spill only when capacity or a known-safe failure requires it, and traverse every
  later eligible pool scope once after definitive exhaustion, including pools larger than three.
- Restricted unauthorized retry to another equivalent credential in the same quota scope. Permission
  failures and ambiguous outcomes never spray across accounts; ambiguous side effects remain
  `UNKNOWN` and are never replayed.
- Kept automatic fallback inside the named Firecrawl pool. Emergency custody and other providers are
  never automatic fallback targets.
- Made retry-safe Firecrawl 429 handling stay on the current credential while its bounded retry can
  succeed, then traverse every later eligible distinct pool scope once only if missing guidance,
  exhausted attempts, or the deadline would otherwise fail. Side-effecting and ambiguously
  submitted operations never use this spill.
- Made `gatehoused` the long-lived central broker and `gatehouse-mcp` an on-demand controlled stdio
  shim that never receives a provider key. Project instruction prose guides the tool but does not
  replace configured client/workspace/session authority.

### Security

- Protected the dedicated Windows mutable-state root with a verified current-user-only DACL,
  re-secured known database/custody files and SQLite sidecars, and rejected reparse-point ancestry
  before daemon, watchdog, or DPAPI state access.
- Pinned fixed-provider TCP connections to a validated public DNS answer while retaining the
  configured hostname for HTTP `Host`, TLS SNI, and certificate verification. Poisoned provider
  DNS now fails as a sanitized retryable pre-handoff error.
- Rejected compressed provider responses, bounded pre-decode JSON structure and token sizes, and
  preserved uncertain-outcome handling whenever a malformed response follows possible submission.
- Rejects credential-shaped or active-secret-overlapping content across every feedback field,
  does not reflect free-form summaries in responses, escapes Markdown exports, and enforces
  per-session row/byte quotas plus footprint-aware admission and retention.
- Bounded reusable bootstrap exchange with configurable per-session access-token rotation and
  fixed-window rate limits. Token-capacity and exchange-rate exhaustion now return a sanitized,
  retryable `capacity_exceeded` response with HTTP 503 and bounded `Retry-After` guidance.
- Split workload and observer transports so observation cannot inherit the emergency credential or
  silently enable workload networking.
- Enforced current-generation authenticated snapshot freshness at catalog, atomic reservation, and
  final credential-handoff fences; missing, legacy, corrupt, stale, or unknown authority fails closed.
- Added secret-canary, restart, concurrency, rotation, stale-snapshot, no-spray, unknown-outcome, and
  installed-process coverage for the candidate paths.
- Bound approval recovery to original/current session, client, workspace, root run, fingerprint and
  canonicalization versions, pool, exact cost/unit, expiration, and one use. MCP continuation keys
  use a fresh process-random HMAC key and interrupted claims have a bounded cleanup lease.
- Kept the raw declared team identity and its HMAC fingerprint out of account status, lifecycle
  results, and audit. Firecrawl does not attest team identity in its credit response, so deliberately
  inconsistent operator declarations remain a documented offline limitation.

## [0.0.1] - 2026-08-23

### Added

- Added the concrete stock daemon composition, separate loopback agent/admin applications,
  production CLI backend, and controlled-session MCP stdio backend.
- Added explicit disabled, no-network scripted, and opt-in live provider modes; live startup verifies
  DPAPI custody metadata before listeners become operational.
- Added an installation-scoped operating-system daemon lock, `RECOVERING` readiness barrier, and
  bounded `DRAINING` lifecycle.
- Added owner-bound durable crawl jobs, migration-6 asynchronous attempt checkpoints, restart
  reconstruction, and semantic startup integrity validation.
- Added durable job `SETTLING` checkpoints so terminal provider usage reconciles the original quota
  and root-run budget exactly once across cancellation and restart races.
- Added optional stable `request_id` retry recovery for crawl start without coalescing intentionally
  distinct crawls.
- Added atomic file-backed administrative approval decisions with exactly one winner under
  concurrent approve/deny actions.
- Added a typed, authenticated policy-explanation route used by the production CLI without
  accepting caller-selected client or workspace authority.
- Added a clean-wheel Windows process gate covering all five installed entry points, controlled MCP
  re-adoption across daemon restart, and restart settlement of a scripted asynchronous crawl.
- Added server-directed MCP heartbeats and a stale-session authentication fence whose reconnect
  grace is anchored to the missed-heartbeat boundary.
- Project architecture and v1 implementation specification.
- Security and threat-model documentation.
- Concurrent session, fair scheduling, quota reservation, and watcher design.
- Firecrawl-first provider roadmap.
- Public development, testing, operations, and debugging guides.
- Added an immutable exact provider-number wrapper, bounded successful-credit-status JSON decoding,
  canonical decimal observations, and conservative whole-credit routing projections. Negative
  remaining credit is retained as provider overage, fractions remain exact, and only the projection
  floors or saturates.
- Restricted credit-status success to HTTP 200 and discard every non-200 body without decoding after
  transport security checks, preserving status classification and safe rate-limit retry hints while
  treating unexpected 2xx responses as non-retryable malformed data.
- Added exact reconciliation decision strings with separate 383-digit provider-delta and 384-digit
  derived unexplained-delta bounds, independently nullable signed-INT64 compatibility deltas,
  precision-512 tolerance arithmetic, and projection-collision detection.
- Added migration 9 with validated integer-to-canonical-text backfill, atomic corruption rollback,
  invalidation of unanchored legacy balance caches, anchored snapshot integrity, and defensive
  triggers.
- Added deterministic scripted availability backed by one idempotent synthetic no-network quota
  snapshot rather than an unauthoritative scope cache.
- Added operator-facing DPAPI credential provisioning and generation-fenced rotation, local
  disable/quarantine/terminal-retirement states, and one bounded memory-only emergency unlock.
- Recorded one separately authorized manual release validation on 2026-08-22: exactly one fixed
  real-provider credit-status request authenticated successfully, exact integer observations were
  preserved, and the provider balance remained unchanged through follow-up. No Firecrawl workload,
  fractional live case, retry, or revoked-key test was performed.

### Changed

- Made scheduler ticket cancellation and deadline expiry reclaim queue or permit capacity exactly once.
- Enforced configured per-quota-scope running limits and requeued work if reservation replacement
  changed its selected scope.
- Made invocation cleanup settle known pre-dispatch cancellations and retain ambiguous post-dispatch usage.
- Made eligible single-flight reads resolve every participant to a stable terminal outcome while mutations remain independent.
- Revalidate and replace quota reservations that expire while queued.
- Persist asynchronous resource affinity with exact session/workspace/root-run ownership,
  credential generation, and fail-closed legacy migration.
- Keep reconciled quota usage admission-visible across restarts until an authoritative balance
  snapshot with matching scope, unit, capture time, projection, and canonical observation advances
  the durable watermark.
- Align persisted invocation states with reserve-first acquisition, atomically replace expired
  reservations, and preserve ambiguous running outcomes during crash recovery.
- Share one bounded MCP bootstrap re-exchange across concurrent stale callers, cap its waiter set,
  and preserve precise expired or revoked session errors.

### Remaining implementation and rollout work

- A live-provider shadow workload and provider-ledger comparison beyond the fixed credit-status
  validation.
- Stock-daemon provider-counter and credit-status orchestration, periodic reconciliation, retention
  maintenance, and retention-pressure alert emission.
- Stock watcher execution through the daemon plus process-level reserved-capacity validation.
- Operator-facing Markdown audit generation.
- Real-workflow duplicate-decision and in-pool failover validation during shadow rollout.
