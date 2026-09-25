# Uses and Limitations

The current source candidate adds ordinary workload status and bounded lifecycle diagnostics.
Workload status does not prove provider reachability, watcher coverage or future authorization;
the lifecycle ring can lose records and does not certify process exit. Durable session request
bindings prevent replay, but the CLI cannot reconstruct a lost request ID/capability pair. DPAPI
identity envelopes do not provide metadata rollback protection, and ownership checks can leave
replaced or unproven custody material pending rather than deleting it.

## Intended uses

Gatehouse v1 is designed for:

- controlling metered APIs from multiple simultaneous local clients;
- replacing per-project provider `.env` copies with one central opaque-custody broker whose typed
  clients never receive an API key;
- sharing and selecting among explicitly grouped quota scopes for one provider;
- preserving a reserved account and service lane for an unattended watcher;
- enforcing project-specific service policy;
- preventing equivalent in-flight requests from consuming duplicate credits;
- smoothing provider rate limits through bounded queues and cooldowns;
- attributing requests to controlled sessions and root runs;
- requiring human approval for selected interactive operations;
- quarantining one repeated-equivalent or aggregate runaway session/root run without blocking other
  client profiles, with a dashboard-authorized bounded old-root burst or safe fresh-run recovery;
- maintaining an auditable provider-usage ledger;
- detecting provider usage that did not pass through the broker;
- recovering sessions and asynchronous jobs after restart.

## Initial Firecrawl use cases

- current job and internship discovery;
- official company career and applicant-tracking-system research;
- difficult JavaScript-rendered page extraction;
- bounded multi-page career-site processing;
- checking whether known openings remain active;
- scheduled monitoring of allowlisted career feeds.

Gatehouse should prefer the smallest adequate operation and must not turn installation into automatic usage.

## Not intended for

- a general-purpose HTTP proxy;
- credential export to clients;
- arbitrary operating-system secret management;
- hostile same-user process isolation;
- Git repository or worktree management in v1;
- paid compute launch in v1;
- LAN or internet exposure;
- multiple human users;
- untrusted third-party adapters;
- complete provider-payload persistence;
- replacement of provider-side limits and scopes.

## Known limitations

### Same-user isolation

The normal-account deployment cannot guarantee that a deliberately hostile same-user process cannot eventually obtain protected material. Gatehouse reduces exposure and bounds loss; it does not create a process sandbox.

### Session identity

A valid bearer capability proves possession. The watcher identity is narrowed by policy but not tied cryptographically to Task Scheduler.

### Provider accounting delay

Usage may be delayed, rounded by the provider, or reported at team rather than credential level.
Gatehouse preserves the exact reported value as a canonical numeric string rather than adding
rounding or retaining the provider lexeme. Routing separately uses a conservative whole-credit
projection: negative or zero remaining credit projects to zero, positive fractions are floored, and
oversized valid values saturate at signed INT64. Reconciliation uses the exact observations even
when projections collide, applies tolerances, and may require manual review. Fractional production
counters are contract-permitted but remain operationally unproven.

Positive-cost routing also requires the observation head to remain fresh and bound to the current
credential generation. A last-known number is not spendable merely because it was once valid:
missing, stale, legacy, or contradictory authority is treated as unknown and skipped.

### Multi-account routing boundary

Supported onboarding requires a stable, non-secret operator-declared Firecrawl team ID. Gatehouse
stores only its installation-keyed HMAC fingerprint and reserves it immutably to one quota scope, so
two keys with the same declaration cannot become two balances. Tombstoning retains the reservation;
rotation is key replacement within the same scope. Raw declarations and fingerprints are absent
from account status, mutation results, and audit.

`fill_first` is capacity-aware sharing, not a sticky account per session, root run, project, or LLM.
Concurrent callers remain on the leading eligible account/team quota scope while atomic quota and
scheduler/lease headroom permit. A later scope is considered only before provider handoff, when
within-pool failover is explicitly enabled and the leader cannot safely accept dispatch. If every
eligible scope is only temporarily at its in-flight ceiling, the request waits under the normal
queue deadline on the deterministic leader rather than distributing identities across accounts.

The source candidate accepts only `routing.maximum_total_provider_attempts: 1`. The durable send
claim is consumed before transport handoff and cannot be restored by a failure or restart. No
transport result allows another credential, account, or retry for that invocation, including a
proven connection failure and HTTP 401/402/429. This intentionally trades automatic retry
availability for a strict one-send boundary. It is not a global per-user/request-burst limit:
separate invocations still require ordinary admission controls. The independently gated observer
channel is outside the workload ceiling.

New pools and missing failover fields default to false. Explicit existing Boolean settings remain
readable. The metadata-only `pools failover enable|disable` administrative command requires a
mutation ID and nonblank reason, binds replay to actor and exact safe metadata, and atomically
records its setting and audit. It grants neither network authority nor another send. Automatic
fallback never leaves the named pool/provider and never uses emergency custody.

`routing.maximum_route_candidates` is a strict integer from 1 through 32, default 32. The catalog
conservatively applies it to configured members and all workload credential generations, including
inactive history, before materialization. Oversized catalogs are rejected, not truncated; a long
rotation history can therefore block normal routing until separately authorized administration
resolves that catalog. Exact-affinity cleanup queries only its bound scope/credential/generation.
No automatic deletion, migration of existing state, or cleanup is implied.

Unknown HTTP billing retains estimated quota and budget holds for reconciliation rather than
assuming a rejected read was free. Proven unsubmitted connection failure settles zero; explicit
actual usage settles the known charge. Recovery retains at least known actual usage when it exceeds
the estimate. [TESTING.md](TESTING.md) records candidate validation separately from live-workload
evidence. Fresh verification does not alter any existing installed runtime.

`EXHAUSTED` is durable across requests, timer expiry, and daemon restart. It can return to `HEALTHY`
only through a newer authenticated positive observation or explicit audited operator recovery, and
ordinary freshness and reservation checks still apply afterward. A stale positive snapshot does not
recover the scope.

This identity is operator-declared, not remotely attested. The Firecrawl credit endpoint reports
team-scoped counters but no authoritative team identifier. Offline Gatehouse can reject identical
declarations, but it cannot discover a deliberately inconsistent pair of IDs for keys that actually
share one provider team. Correct stable declaration and later reconciliation remain operator
responsibilities.

### Local scheduling and database latency

Scheduling weights distribute request dispatch opportunities. The stock coordinator charges one
unit for each request; requests can have different provider costs and durations. Separate policy,
budget and quota checks enforce financial limits, and concurrency limits bound simultaneous work.

SQLite calls on the daemon's event loop are synchronous. The configured busy timeout is at most
5 seconds per busy handler, but it is not an end-to-end request deadline: multiple statements,
checkpoints and filesystem delays can block the loop for longer. Cancellation and shutdown cannot
preempt those calls. Gatehouse does not currently promise a latency SLA or measured maximum loop lag.

### Crash recovery of synchronous results

A completed synchronous response that was returned but not persisted may be unavailable after restart. Gatehouse records the outcome but not the response body.

### Workspace and agent authority

Gatehouse does not interpret project instruction files or natural-language prompts as cryptographic
or administrative authority. Those files may guide an MCP client to request a tool. The broker
still requires an explicitly allowed client/workspace pair, an existing absolute working directory
inside the configured canonical root, a controlled session/root run, operation capability, and
workspace policy. A legacy client profile without `workspaces.allow` remains parseable but cannot
launch.

The expected agent topology requires the one central `gatehoused` process to be running; a
per-session `gatehouse-mcp` stdio shim starts on demand and contains no provider secret. If the
daemon is unavailable, the shim fails retryably instead of falling back to an environment key or
waking an ambient credential process. The supplied registration/removal scripts refuse native task
management pending a verified adapter and runtime binding. Internal disabled review plans do not
configure the host, attest ownership or establish an enforced child environment.

CLI and watchdog can select only the daemon launcher beside their active interpreter. A missing
launcher or an explicit override with a different spelling is refused; PATH is not searched.
Layouts that place scripts in another directory are unsupported by this launch path. The selector
requires bounded absolute literal spelling, including an uppercase Windows drive letter, and
rejects ambiguous components before the consumer's single availability check. This does not attest native
identity, link resistance, interpreter/import ownership or atomic execution; filesystem latency
and any normalization already performed by a caller's Path object remain outside this check.

### Long-lived process environment

Long-lived daemon/watchdog environment capture is bounded and rejects ambiguous retained names or
malformed values. Frozen mappings and fresh subprocess dictionaries preserve configuration-expansion
bindings across launches. This does not attest allowlisted path/trust-store ownership, prevent a
custom mapping method from blocking, sanitize Python before interpreter startup, enforce a native
scheduled task's environment or change controlled-client inheritance. Those remain separate limits.

### Runaway authorization boundary

Repeated-equivalent and aggregate thresholds create a durable quarantine for the exact
session/root-run/service offender. A cooldown or restart does not unblock it. Every new session or
root run for the same client profile is also fenced, including while the old root is `AUTHORIZED`;
unrelated client profiles remain independent. The MCP result can link to the fixed local dashboard,
but neither an agent tool nor text such as "I authorize this" can approve a burst or recover a fresh
run. The authenticated human dashboard decision must select typed operations and explicit limits no
greater than 15 minutes, 25 requests, 100 credits, concurrency eight, and 16 operations.

Every admitted burst request consumes durable request/credit authority and a concurrency slot.
Unknown actual cost consumes the remaining credit grant. Expiry, exhaustion, or daemon restart
closes rather than broadens the grant; active permits at restart are conservatively orphaned and
require another human decision. These controls do not override quota freshness, account state,
same-provider routing, side-effect safety, or asynchronous affinity.

Fresh-run recovery is a distinct local dashboard action, not a broader burst. It requires an exact
generation/action token, explicit confirmation, no active permit, no nonterminal or unknown work,
no unreconciled quota or budget, and no live/missing asynchronous affinity. Success revokes the old
session, closes the root, and releases only that current quarantine generation. It does not carry
request, credit, concurrency, operation, credential, or account authority into the new run.

### Sensitive-data detection

Heuristics can catch obvious credential patterns, but explicit classification and strict operation schemas remain necessary.

### Local-only deployment

V1 does not include remote authentication, network transport security, or multi-host coordination.

### No automatic emergency pooling

The emergency workflow always requires a manual interactive unlock even when automatic fallback
would improve availability. It permits exactly one memory-only authority bound to one session,
root run, and pool, with hard maxima of 15 minutes, 25 requests, 100 credits, and concurrency one.
It is synchronous-only and cannot become a default, automatic selection, or failover route.

### Provider-specific behavior

Every adapter must encode provider-specific quota, ownership, exact-number envelope, projection,
retry, and resource-affinity rules. A generic retry strategy is insufficient. Named-pool fallback is
same-provider only because switching providers may change behavior, privacy exposure, pricing, and
output semantics.

### Live-provider rollout

The repository includes a live fixed-origin transport and strict DPAPI route-metadata validation,
but it does not claim a completed real-provider shadow workload. Normal tests use disabled or
scripted no-network mode. Local DPAPI provisioning and bounded emergency-unlock surfaces exist
without enabling networking. One separately authorized manual release validation on 2026-08-22
issued exactly one fixed credit-status request to the real provider: authentication succeeded,
exact integer observations were preserved, and the provider balance remained unchanged through
follow-up. It did not perform a Firecrawl workload, a fractional live case, a retry, or a
revoked-key test. Any further real credential use, provider-counter comparison, or live shadow
workload remains an explicitly operator-controlled rollout action.
Negative, fractional, exponent-form, and above-INT64 credit observations are covered by the local
contract and tests only; none is a claim about Firecrawl production behavior.

### Installed release evidence

Stock daemon, CLI, MCP, notifier, and watchdog entry points are implemented. The clean-wheel,
subprocess-level scripted restart gate covers all five entry points, long-lived MCP session/root
re-adoption, deterministic synthetic snapshot-backed routing authority, synchronous accounting, and
asynchronous job settlement before readiness. That gate
does not authorize or substitute for a live-provider shadow run.

### Periodic maintenance

The stock daemon supervises two independent required tasks. One runs a bounded
retention/checkpoint/footprint batch at the configured retention maintenance interval. The other
polls on its own scheduler interval for a bounded, provider-I/O-free QUICK/FULL reconciliation
batch and processes only scopes due under their durable reconciliation cadences. Both tasks also
run one batch before readiness. Scheduled reconciliation reads persisted snapshots and ledger
state only and remains under fail-closed supervision; it neither enables nor invokes provider
observation.
A separate bounded Firecrawl credit-observation loop is wired but disabled by default; it exists
only when the independent observer mode and network switch are both explicitly live, and it caps
accounts per cycle, concurrency, request duration, and observation freshness. The admin validation
command remains the on-demand equivalent. Both observation paths retain exact canonical values;
scheduled reconciliation compares those persisted observations rather than only their projected
integer balances.

### Manual validation evidence

A successful manual validation atomically records its sanitized canonical observations, projected
integer counters, and attributable
audit event. A provider rejection, timeout, transport failure, or malformed counter result after the
service invokes live transport records a separate `credential.provider_validation_failed` event.
Its payload contains
only `actor_id`, the local `credential_id`, `credential_generation`, a stable `error_class`, and
`outcome: failed`; it excludes provider bodies, headers, reason text, request identifiers,
retry-after values, and exception data. The event does not prove HTTP submission or provider receipt.
Disabled or scripted mode, service-local rejection before transport invocation, and cancellation
remain zero-event paths for this failure audit. Cancellation or an ambiguous send can still retain
an unresolved durable observation intent, which cannot authorize automatic replay.
Failure to persist the failure event is returned only as
a generic persistence or daemon-degraded error. The operator-facing API error is otherwise
unchanged and does not return the audit-event identifier.
Raw numeric lexemes and provider bodies are excluded. A malformed successful response creates no
success snapshot. Non-200 credit-status bodies are discarded without decoding after transport
security and size checks; ordinary error status remains authoritative, while every unexpected 2xx
is a non-retryable malformed response.

Migration 9 deliberately clears any v8 scope balance that lacks a matching snapshot anchor. That
cache was not an authoritative provider observation; live positive-cost routing requires fresh
authenticated evidence afterward. Valid anchored balances are preserved only when their snapshot
identity, scope, unit, time, projection, and canonical observation all agree.

The successful manual release validation exercised only the exact-integer happy path described
above. It does not establish production behavior for fractional, negative, exponent-form,
above-INT64, retry, workload, failover, or revoked-key cases, and it does not authorize another
provider request.

The stock DPAPI metadata enumerator sends its local filesystem work through the shared
capacity-bounded offload boundary instead of blocking the event loop. Cancellation is joined: the
bounded slot remains owned until the non-preemptible filesystem call finishes, and the
post-enumeration durable heartbeat still prevents provider dispatch after an expired fence. A
severely slow or hostile local filesystem can therefore delay completion, but it cannot orphan the
worker, exceed the configured offload concurrency, or permit an unfenced provider dispatch.

## Operational boundaries

Every implemented queue, provider request, retry, approval, and debug capture has an explicit
maximum. The stock watcher adds a maximum-64 configured target sequence, explicit map-result
ceilings, a 30-second synchronous execution deadline, a two-MiB aggregate result ceiling, per-run
budgets, and a fenced explicit cursor commit, but it is available only with the scripted no-network
workload. It does not provide live
watcher use, asynchronous crawl, crash redispatch/resume, or an internal periodic trigger.
Emergency unlock is constrained to 15 minutes, 25 requests, 100 credits, and one concurrent
synchronous request. Ambiguous side-effecting provider handoff is `UNKNOWN` and requires
reconciliation; it is never replayed on another account or provider to improve availability.
