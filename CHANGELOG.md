# Changelog

All notable user-visible changes are recorded here.

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
