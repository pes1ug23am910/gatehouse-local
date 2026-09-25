# Changelog

All notable user-visible changes are recorded here.

## [0.0.2] - Unreleased development candidate

### Added

- Kept configuration agreement stable when unrelated sibling log or state files are created,
  while retaining ancestor identity and permission bindings and full capture-time drift checks.
- Added bounded read-only local route assessments for explicit ordinary workload pools, using
  actual operation costs and fixed eligible/ineligible/unverified results without reserving or
  dispatching. Authenticated control status now derives ordinary workload coverage from verified
  client/workspace/purpose and profile bindings; watcher-route coverage remains separate.
- Added migrations 17–19 for durable observation intents, controlled-session request bindings and
  cancellation tombstones, and a bounded lifecycle diagnostic ring. Unknown observations cannot
  replay; lost session creation responses can be cancelled by request ID.
- Added authenticated fixed-metadata Markdown audit and lifecycle endpoints.
- Moved browser login codes into history-cleared fragments with deliberate form exchange and a
  fixed script-hash policy. Hardened MCP HTTP cleanup for redirects, exception graphs and mutable
  bodies, preserving cancellation and sanitized errors across bounded closure.
- Bound persistent DPAPI ciphertext to credential/principal/scope identity, added create-only
  publication and ownership-checked rollback, and retained worker cleanup across cancellation.
- Preserved primary shutdown cancellation, attempted independent cleanup phases, and retained
  database/OS ownership until unfinished phases complete on an explicit retry.
- Added append-only migration 16 with a strict one-submission invocation ceiling, immutable
  request-bound transport claims, and conservative legacy exhaustion without fabricated send evidence.
- Added bounded ordinary catalog materialization (strict 1..32, default 32), overflow rejection
  without prefix truncation, and independent exact-resource-affinity lookup.
- Added typed administrative pool-fallback enable/disable commands with actor/pool/action/reason
  replay binding, pre-body authentication, and atomic preserved audit. Missing/new settings default
  false; explicit existing Boolean settings remain readable.
- Added coherent `config init`, explained configuration validation, sanitized local diagnostics,
  Windows Python 3.12–3.14 CI, and a non-publishing offline wheel/install evidence workflow.
- Added reviewed, fully hashed Windows runtime locks for Python 3.12–3.14, an exact wheelhouse
  manifest, a time-bounded OSV snapshot, deterministic CycloneDX SBOM generation, and an offline
  release gate that verifies hashes, wheel compatibility, dependency closure, and advisory status.
- Added create-only sanitized JSON support bundles with bounded schema, size, alert summaries, and
  secret scanning; paths, identifiers, configuration text, database rows, and environment values
  remain outside the artifact.
- Added append-only migration 14 with indexes for every bounded periodic-retention query.
- Added append-only migration 15 with same-scope, generation-fenced QUICK/FULL reconciliation
  baselines, due indexes, existing-scope compatibility, and first-snapshot initialization for new
  scopes.
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
- Added a stock, synchronous watcher facade for scripted no-network Firecrawl execution. MCP selects
  only a configured feed and optional cursor; Gatehouse owns the workspace-bound ordered scrape/map
  targets, manual watcher pool, policy projection, pending summary, and explicit fenced cursor commit.

### Changed

- Long-lived process environments now reject ambiguous, malformed or oversized inputs with a
  fixed diagnostic. The existing allowlist is preserved; accepted values, including empty
  configuration bindings, remain exact. CLI/watchdog snapshots are immutable and each subprocess
  receives a fresh explicit mapping. Invalid startup environments fail before configuration or
  process effects, while default CLI import remains safe.
- CLI and watchdog daemon launches now require the platform launcher beside the active interpreter.
  Removed PATH fallback and arbitrary executable overrides; explicit overrides must assert that
  exact adjacent spelling. Missing or invalid launchers fail before spawning. Native runtime trust
  and installed verification remain separate.
- Task registration/removal scripts now refuse before discovery or mutation pending a verified
  native adapter. Internal bounded disabled task plans bind explicit runtime, config/digest, owner
  and expansion-environment inputs without granting registration or ownership authority.
- Mutable-state admission now requires a fixed NTFS Windows volume and complete, strictly typed
  filesystem metadata before permission setup or creation. Trusted ancestor authority and atomic
  private creation use retained object handles, exact owner/DACL checks and bounded native
  descriptors. OWNER RIGHTS is bound to the descriptor's verified owner; private targets still
  require the exact execution-user ACL. Installed verification remains separate.
- Watchdog readiness now requires authenticated configuration agreement and coherent responses from
  both configured listeners. Missing/conflicting agreement and live degradation return nonzero;
  explicit fully disabled state has its own successful outcome. Only two explicit connection
  failures permit restart. Streamed control JSON, cooperative deadlines and late-result rejection
  are bounded; watchdog readiness timeout must be finite, positive and at most 60 seconds.
- Control mutations now use versioned v2 routes and require the captured configuration digest on
  each request, after capability authentication and before bounded body processing or effects.
  Legacy mutation routes have no fallback. Cleanup retains its original configuration authority;
  refusal after configuration drift leaves cleanup pending rather than silently rebinding it.
- CLI daemon startup now requires the capability-authenticated control status to report the exact
  captured configuration digest before accepting an existing daemon or owned child. Missing,
  malformed or mismatched digest fields fail without launch fallback; owned-child cleanup remains
  bounded. Older daemons without the field cannot satisfy this startup contract.
- Bound scripted response manifests into trusted configuration capture. Stock startup accepts one
  exact sibling manifest, verifies its immutable bytes against the retained configuration digest,
  and prepares scripted transport before mutable setup. External/nested paths, ambiguous spellings
  and path whitespace are rejected; startup no longer reopens the manifest pathname.
- Retained controlled-session request cleanup authority before dispatch. The daemon durably binds
  request IDs and cancellation tombstones; cleanup uses the original endpoint, capability and
  configuration digest even when the creation response is lost. The CLI's own cleanup authority
  remains local to one backend instance and cannot be reconstructed after it is lost.
- Resolved relative database paths against the main configuration file's directory instead of the
  caller's working directory, and capped configured SQLite busy waits at five seconds. Existing
  configurations that relied on a different working directory or a larger `busy_timeout_ms` must be
  updated before startup.
- Made feed configuration require an explicit workspace and 1–64 concrete scrape/map targets. Map
  targets require a 1–100 result limit, aggregate map limits cannot exceed the feed page cap, and all
  configured URLs are checked through the existing host/path/operation allowlist. Existing feed YAML
  must add the workspace and target list before the daemon can start.
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
  passive WAL checkpoint outside the retention transaction. Startup and periodic maintenance now
  observe the total main/WAL/shared-memory/rollback-journal footprint, maintain one fixed 90% HIGH
  pressure alert, attempt a truncating checkpoint before remeasurement, and fail closed on cap,
  unavailable observation, or alert-persistence failure. The feedback guard remains, and the sampled
  control is not represented as a hard race-free filesystem quota.
- Made the stock daemon supervise provider-I/O-free QUICK/FULL reconciliation over persisted exact
  observations with separate durable mode baselines/cadences, integer absolute tolerance, snapshot-
  age policy, bounded scope/time batches, current-observation deduplication, and atomic result,
  mismatch alert/quarantine, and baseline advancement. Valid indeterminate results remain durable;
  unexpected scheduler or persistence failure enters `FAILED_CLOSED`.
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
  headroom remain, with same-scope and cross-scope pre-dispatch fallback requiring explicit pool
  enablement. Ordinary catalog bounds conservatively include inactive credential generations.
- Limited every workload invocation to one durable transport claim, including emergency and
  exact-resource requests. Higher configured limits are unsupported. HTTP 401/402/429/5xx and even
  proven connection failure cannot trigger a same-request resend, retry sleep, or replacement lease.
- Separated failure billing from execution ambiguity: known actual usage settles once, unknown
  HTTP-failure cost remains held, and restart retains at least known actual-cost overruns. A known
  charge does not turn an ambiguous resource result into success or permit replay.
- Kept automatic fallback inside the named Firecrawl pool. Emergency custody and other providers are
  never automatic fallback targets.
- Retained bounded provider retry hints and durable exhaustion/cooldown for later independent
  admissions without automatic post-transport retries. Observer refreshes remain separately gated.
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
- Live-mode watcher execution, asynchronous crawl supervision, crash redispatch/resume, an internal
  periodic watcher scheduler, and process-level reserved-capacity validation.
- Operator-facing Markdown audit generation.
- Real-workflow duplicate-decision and in-pool failover validation during shadow rollout.
