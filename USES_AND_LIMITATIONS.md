# Uses and Limitations

## Intended uses

Gatehouse v1 is designed for:

- controlling metered APIs from multiple simultaneous local clients;
- selecting among explicitly grouped provider accounts;
- preserving a reserved account and service lane for an unattended watcher;
- enforcing project-specific service policy;
- preventing equivalent in-flight requests from consuming duplicate credits;
- smoothing provider rate limits through bounded queues and cooldowns;
- attributing requests to controlled sessions and root runs;
- requiring human approval for selected interactive operations;
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

### Crash recovery of synchronous results

A completed synchronous response that was returned but not persisted may be unavailable after restart. Gatehouse records the outcome but not the response body.

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
retry, and resource-affinity rules. A generic retry strategy is insufficient.

### Live-provider rollout

The repository includes a live fixed-origin transport and strict DPAPI route-metadata validation,
but it does not claim a completed real-provider shadow run. Normal tests use disabled or scripted
no-network mode. Local DPAPI provisioning and bounded emergency-unlock surfaces exist without
enabling networking. The manual validation command is rejected in disabled and scripted modes;
entering any real credential, comparing provider counters, and performing a live shadow validation
remain explicitly operator-controlled rollout actions.
Negative, fractional, exponent-form, and above-INT64 credit observations are covered by the local
contract and tests only; none is a claim about Firecrawl production behavior.

### Installed release evidence

Stock daemon, CLI, MCP, notifier, and watchdog entry points are implemented. The clean-wheel,
subprocess-level scripted restart gate covers all five entry points, long-lived MCP session/root
re-adoption, deterministic synthetic snapshot-backed routing authority, synchronous accounting, and
asynchronous job settlement before readiness. That gate
does not authorize or substitute for a live-provider shadow run.

### Periodic maintenance

Retention, reconciliation, quarantine, and WAL-maintenance primitives are implemented, but the
stock daemon does not yet schedule periodic retention or quick/full reconciliation loops. The
documented cadences are operational rollout targets until that wiring is complete. The separate
admin-only validation command captures one on-demand counter snapshot; it is not a scheduler.
Those snapshots carry exact canonical observations; periodic reconciliation must not compare only
their projected integer balances.

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
remain zero-event paths. Failure to persist the failure event is returned only as
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

This evidence surface has not been exercised against a real provider credential. Gate B remains
NOT RUN and requires separate operator authorization for live mode, provider networking, the real
credential, and provider-side counter observation.

The stock DPAPI metadata enumerator performs synchronous local filesystem reads inside its async
method. The post-enumeration durable heartbeat prevents provider dispatch after an expired fence,
but a severely slow or hostile local filesystem can make the pre-dispatch metadata phase exceed its
nominal coroutine timeout. Moving that enumeration behind an interruptible worker boundary remains
availability hardening; it does not permit an unfenced provider dispatch.

## Operational boundaries

Every implemented queue, provider request, retry, approval, and debug capture has an explicit
maximum. The not-yet-wired watcher execution workflow remains required to retain its explicit
bounds. Emergency unlock is already constrained to 15 minutes, 25 requests, 100 credits, and one
concurrent synchronous request.
