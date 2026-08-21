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

Usage may be delayed, rounded, or reported at team rather than credential level. Reconciliation uses tolerances and may require manual review.

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

Every adapter must encode provider-specific quota, ownership, retry, and resource-affinity rules. A generic retry strategy is insufficient.

### Live-provider rollout

The repository includes a live fixed-origin transport and strict DPAPI route-metadata validation,
but it does not claim a completed real-provider shadow run. Normal tests use disabled or scripted
no-network mode. Local DPAPI provisioning and bounded emergency-unlock surfaces exist without
enabling networking. The manual validation command is rejected in disabled and scripted modes;
entering any real credential, comparing provider counters, and performing a live shadow validation
remain explicitly operator-controlled rollout actions.

### Installed release evidence

Stock daemon, CLI, MCP, notifier, and watchdog entry points are implemented. The clean-wheel,
subprocess-level scripted restart gate covers all five entry points, long-lived MCP session/root
re-adoption, synchronous accounting, and asynchronous job settlement before readiness. That gate
does not authorize or substitute for a live-provider shadow run.

### Periodic maintenance

Retention, reconciliation, quarantine, and WAL-maintenance primitives are implemented, but the
stock daemon does not yet schedule periodic retention or quick/full reconciliation loops. The
documented cadences are operational rollout targets until that wiring is complete. The separate
admin-only validation command captures one on-demand counter snapshot; it is not a scheduler.

### Manual validation evidence

A successful manual validation atomically records its sanitized counter snapshot and attributable
audit event. Provider rejection, timeout, transport failure, or malformed counters currently return
a sanitized error and release the durable lease without adding a validation-outcome audit event;
retain the operator command result during a live canary. Add bounded failure-outcome auditing before
any future unattended validation or scheduled counter collection.

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
