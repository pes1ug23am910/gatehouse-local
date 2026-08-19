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

The intended emergency workflow requires a manual bounded unlock even when automatic fallback would
improve availability. The stock administrative surface does not yet expose that workflow, so the
emergency pool remains disabled and locked.

### Provider-specific behavior

Every adapter must encode provider-specific quota, ownership, retry, and resource-affinity rules. A generic retry strategy is insufficient.

### Live-provider rollout

The repository includes a live fixed-origin transport and strict DPAPI route-metadata validation,
but it does not claim a completed real-provider shadow run. Normal tests use disabled or scripted
no-network mode. Credential provisioning, bounded emergency unlock, provider-counter comparison,
and live shadow validation remain operator-controlled rollout work.

### Installed release evidence

Stock daemon, CLI, MCP, notifier, and watchdog entry points are implemented. A clean-wheel,
subprocess-level scripted restart test passes from a fresh virtual environment. It covers all five
entry points, long-lived MCP session/root re-adoption, synchronous accounting, and asynchronous job
settlement before readiness. This evidence does not authorize or substitute for a live-provider
shadow run.

### Periodic maintenance

Retention, reconciliation, quarantine, and WAL-maintenance primitives are implemented, but the
stock daemon does not yet schedule periodic retention or quick/full reconciliation loops. The
documented cadences are operational rollout targets until that wiring is complete.

## Operational boundaries

Every implemented queue, provider request, retry, approval, and debug capture has an explicit
maximum. The not-yet-wired watcher execution and emergency-unlock workflows are required to retain
explicit duration, request, credit, and concurrency bounds when implemented.
