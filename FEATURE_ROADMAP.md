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
- [x] Add deterministic mock and scripted provider transports.

## Phase 1 — Persistence and credential custody

- [x] Initialize SQLite in WAL mode with full synchronization and foreign keys.
- [x] Add append-only checksum-verified migrations through schema version 8.
- [x] Implement typed identifiers and UTC timestamp helpers.
- [x] Implement in-memory and Windows current-user DPAPI KeyStores.
- [x] Implement credential metadata, generations, leases, and state transitions.
- [x] Implement structured audit storage.
- [x] Implement secret-canary tests.
- [x] Implement bounded retention and WAL-maintenance primitives.
- [ ] Schedule periodic retention maintenance and retention-pressure alert emission in the stock daemon.
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
- [x] Implement a durable watcher single-run lease.

## Phase 3 — Firecrawl vertical slice

- [x] Implement fixed-origin provider transport and a disabled-by-default network boundary.
- [x] Implement credential-free adapter requests.
- [x] Implement Search, Scrape, Map, Crawl start/status/cancel, and the internal credit-status
  adapter contract.
- [x] Implement named pools and selection strategies.
- [x] Implement atomic quota and root-run budget reservations.
- [x] Implement error classification and circuit breakers.
- [x] Implement owner-bound, restart-persistent asynchronous resource affinity.
- [x] Implement migration-6 asynchronous attempt checkpoints and fail-closed reconstruction.
- [x] Implement durable job `SETTLING` and idempotent actual-usage accounting.
- [x] Implement optional stable crawl-start `request_id` recovery semantics.
- [ ] Wire internal credit status into authenticated stock provider-counter and reconciliation
  orchestration.

## Phase 4 — Policy and watcher

- [x] Implement canonical workspace binding.
- [x] Implement rule precedence and `ALLOW`/`ASK`/`DENY`.
- [x] Implement unattended `ASK` to immediate denial.
- [x] Implement sensitive-data classification and heuristics.
- [x] Implement the example Placement-Schedule policy.
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

## Phase 6 — Stock runtime, recovery, and local tools

- [x] Implement the concrete stock daemon composition root.
- [x] Implement production loopback CLI and controlled-launch adapters.
- [x] Implement the controlled-session MCP stdio backend and capability-filtered tools.
- [x] Enforce one installation-scoped stock daemon with an operating-system lock.
- [x] Advertise `READY` only after recovery and one initial job-supervisor pass.
- [x] Implement bounded `DRAINING` admission and shutdown.
- [x] Implement startup recovery classification and semantic job-integrity checks.
- [x] Implement asynchronous job re-adoption and settlement recovery.
- [x] Implement the Task Scheduler watchdog and Windows helper scripts.
- [x] Implement documentation storage/search and bounded feedback storage.
- [x] Implement bounded Markdown feedback export.
- [x] Implement reset-aware reconciliation and exclusive-scope quarantine components.
- [ ] Schedule quick/full reconciliation in the stock daemon.
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

V1 is intentionally limited to one provider. Any additional provider requires a separate
architecture decision, typed operation surface, threat review, quota model, reconciliation design,
and complete mock test suite before admission.

## Deployment hardening

A later phase may use a separate credential-custody service identity, authenticated user-session
notifier, and migration/re-encryption tooling.
