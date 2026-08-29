# Feature Roadmap

A feature is complete only when its acceptance tests pass and public documentation matches the
verified behavior. Checked items below describe repository implementation, not live-provider or
production-rollout validation.

## Phase 0 — Repository and contracts

- [x] Freeze v1 scope and threat posture.
- [x] Define session, request, attempt, and job state machines.
- [x] Define public documentation.
- [x] Define provider, policy, quota, and KeyStore boundaries.
- [x] Define Firecrawl-first rollout.
- [x] Scaffold package, migration, and test directories.
- [x] Add strict configuration-schema validation.
- [x] Add deterministic mock and scripted provider transports with synthetic snapshot-backed
  no-network quota authority.

## Phase 1 — Persistence and credential custody

- [x] Initialize SQLite in WAL mode with full synchronization and foreign keys.
- [x] Add append-only checksum-verified migrations through schema version 15. Version 10 adds
  canonical decimal observations, provider/account identity, credential roles, native quota
  dimensions, reset-window kinds and period bounds, durable health events, observation
  provenance/freshness, breaker recovery metadata, and default-disabled observation schedules;
  version 11 adds durable offender-scoped runaway quarantine and bounded burst authority; version
  12 adds immutable provider quota-scope identity reservations; version 13 adds exact-generation
  runaway fresh-run recovery evidence and the client-capacity lookup index; version 14 adds
  retention-query indexes for bounded cleanup transactions; version 15 adds per-scope QUICK/FULL
  reconciliation baselines, cadence state, and generation-fenced advancement.
- [x] Implement typed identifiers and UTC timestamp helpers.
- [x] Implement in-memory and Windows current-user DPAPI KeyStores.
- [x] Implement credential metadata, generations, leases, and state transitions.
- [x] Implement structured audit storage.
- [x] Implement secret-canary tests.
- [x] Implement bounded retention and WAL-maintenance primitives.
- [x] Schedule bounded periodic retention maintenance and passive WAL checkpointing in the stock
  daemon.
- [x] Add bounded startup/periodic global database-footprint observation, fixed-threshold singleton
  retention-pressure alerting, truncating-checkpoint remeasurement, and fail-closed cap enforcement
  beyond the feedback admission guard.
- [x] Add provider-mode-independent DPAPI credential provisioning through the local administrative CLI.

## Phase 2 — Sessions and scheduling

- [x] Implement controlled launch with child-environment secret scrubbing.
- [x] Implement bootstrap capability verifiers.
- [x] Implement short-lived access tokens.
- [x] Implement heartbeat and restart re-adoption.
- [x] Implement bounded weighted-deficit fair scheduling.
- [x] Implement global, per-session, per-service, and per-quota-scope limits.
- [x] Implement HMAC request fingerprints.
- [x] Implement bounded same-session duplicate coalescing.
- [x] Implement runaway circuit breakers.
- [x] Fence fresh same-client sessions/root runs across every unrecovered runaway state and provide
  a local-dashboard-only safe recovery that revokes the old authority without transferring a burst.
- [x] Restore generation-fenced service, operation, quota-scope, and credential breaker state from
  SQLite while keeping half-open probe ownership process-local.
- [x] Implement a durable watcher single-run lease.

## Phase 3 — Firecrawl vertical slice

- [x] Implement fixed-origin provider transport and a disabled-by-default network boundary.
- [x] Implement credential-free adapter requests.
- [x] Implement Search, Scrape, Map, Crawl start/status/cancel, and the internal credit-status
  adapter contract with bounded exact canonical numbers and conservative routing projections.
- [x] Implement named pools and selection strategies.
- [x] Implement atomic quota and root-run budget reservations with fail-closed snapshot-backed
  balance validation.
- [x] Implement error classification and circuit breakers.
- [x] Implement owner-bound, restart-persistent asynchronous resource affinity.
- [x] Implement migration-6 asynchronous attempt checkpoints and fail-closed reconstruction.
- [x] Implement durable job `SETTLING` and idempotent actual-usage accounting.
- [x] Implement optional stable crawl-start `request_id` recovery semantics.
- [x] Wire internal credit status into an authenticated, exact-generation, admin-only validation
  path with atomic canonical-observation, projected-counter, and audit persistence.
- [x] Implement bounded, per-account Firecrawl credit observation behind independent provider
  live/network switches and an explicit default-disabled account schedule.
- [x] Implement durable exhaustion, authenticated-positive recovery, operator recovery, restart
  restoration, freshness fencing, and full named-pool failover after definitive exhaustion.
- [x] Implement shared capacity-aware fill-first dispatch without sticky client/LLM account
  assignments and without automatic emergency or cross-provider fallback.
- [x] Schedule bounded provider-I/O-free QUICK/FULL reconciliation comparison and alerting over
  persisted exact observations.

## Phase 4 — Policy and watcher

- [x] Implement canonical workspace binding.
- [x] Implement rule precedence and `ALLOW`/`ASK`/`DENY`.
- [x] Implement unattended `ASK` to immediate denial.
- [x] Implement sensitive-data classification and heuristics.
- [x] Implement the example workspace policy.
- [x] Implement feed-set schemas, target rules, and schedule windows.
- [x] Implement watcher budgets, single-run leases, cursors, and previous summaries.
- [x] Implement watcher-reserved queue and provider capacity.
- [ ] Wire the watcher execution facade through the stock daemon end to end.

## Phase 5 — Administrative surface

- [x] Implement separate admin authentication, one-use login, cookies, and anti-forgery checks.
- [x] Implement dashboard status and approval views.
- [x] Implement one-use request-bound approvals and expiry.
- [x] Prove exactly one approval/denial winner under concurrent SQLite connections.
- [x] Implement the best-effort Windows notifier entry point and production CLI approval actions.
- [x] Implement redacted pool, credential, incident, and reconciliation views.
- [x] Implement credential provisioning, generation-fenced rotation, local state changes, and bounded emergency-unlock mutations.
- [x] Implement explicit live-only credential validation without exposing it to agent or MCP clients.
- [x] Implement clean-install Firecrawl account/pool onboarding, alias and priority management,
  rotation, disable/recover/remove, redacted status, manual refresh, and observation controls.

## Phase 6 — Stock runtime, recovery, and local tools

- [x] Implement the concrete stock daemon composition root.
- [x] Implement production loopback CLI and controlled-launch adapters.
- [x] Implement the controlled-session MCP stdio backend and capability-filtered tools.
- [x] Enforce one installation-scoped stock daemon with an operating-system lock.
- [x] Advertise `READY` only after recovery, one bounded retention/checkpoint/footprint batch, one
  initial job-supervisor pass, and one bounded scheduled-reconciliation batch.
- [x] Implement bounded `DRAINING` admission and shutdown.
- [x] Implement startup recovery classification and semantic job-integrity checks.
- [x] Implement asynchronous job re-adoption and settlement recovery.
- [x] Implement the Task Scheduler watchdog and Windows helper scripts.
- [x] Implement documentation storage/search and bounded feedback storage.
- [x] Implement bounded Markdown feedback export.
- [x] Implement reset-aware exact-observation reconciliation, including projected-balance collision
  detection, and exclusive-scope quarantine components.
- [x] Schedule bounded QUICK/FULL reconciliation comparison as a required stock-daemon task.
- [ ] Generate an operator-facing Markdown audit view.

## Phase 7 — Release evidence and rollout

- [x] Build a wheel, install it into a clean environment, and pass the subprocess entry-point E2E.
- [x] Pass installed scripted-provider restart, session re-adoption, job, and accounting E2E.
- [ ] Run one explicitly authorized real account in shadow mode.
- [ ] Compare the ledger with provider counters.
- [ ] Validate duplicate decisions against real workflows.
- [ ] Enable project policy and in-pool failover in the shadow deployment.
- [ ] Validate watcher capacity under process-level load.
- [ ] Keep the emergency pool locked during real-provider rollout except for an explicitly authorized bounded exercise.

## Future provider policy

Workload execution remains intentionally limited to Firecrawl. Schema, configuration, and a
code-owned fixed-operation registry reserve foundation identifiers for GitHub, OpenRouter, Gemini,
xAI, and JarvisLabs, but those providers expose no implemented operations. Any admission requires a
separate architecture decision, typed operation surface, threat review, provider-native quota model,
reconciliation design, and complete mock test suite. Automatic fallback remains within one provider.

## Deployment hardening

A later phase may use a separate credential-custody service identity, authenticated user-session
notifier, and migration/re-encryption tooling.
