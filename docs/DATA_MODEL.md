# Data Model

## Entity graph

```text
Client ──< Session ──< RootRun ──< Invocation ──< Attempt
  │           │                          │             │
  │           └──< ReportedContext       │             └── Credential
  │                                      │
  └── policy profile                     ├── Approval
                                         ├── Job
                                         └── QuotaReservation

ProviderPrincipal ──< QuotaScope ──< Credential
                           │
                           └──< PoolMembership >── Pool

Invocation ──< ExternalResource >── ProviderPrincipal
QuotaScope ──< QuotaSnapshot ──< ReconciliationItem
```

## Key invariants

### Session

- plaintext bootstrap capability is never persisted;
- one session belongs to one client profile;
- workspace binding is immutable after launch;
- revocation invalidates tokens and queued invocations;
- absolute expiry cannot be extended by the client.

### Invocation

- one logical operation independent of provider retry count;
- immutable fingerprint and canonicalization version;
- request body not persisted;
- terminal state recorded once;
- coalesced reads persist the original request link before resolving to a stable terminal state;
- actual cost may remain pending reconciliation.

### Attempt

- one provider execution attempt;
- ordered within an invocation;
- records credential, principal, quota scope, status, latency, and error class;
- a successful asynchronous creation atomically records resource type, provider resource identifier,
  credential generation, and pool as an all-or-none handoff checkpoint;
- never records authorization material.

### Quota reservation

- belongs to one invocation and quota scope;
- created atomically before dispatch;
- released, reconciled, expired safely, or retained pending reconciliation;
- reconciled actual usage remains an admission-visible charge until an authoritative provider
  remaining-balance snapshot advances that scope's balance watermark;
- cannot disappear solely because the daemon restarted.

### Approval

- one use by default;
- request-bound;
- expires to denial;
- cannot be consumed by another session;
- approval or denial changes `PENDING` exactly once through an immediate compare-and-set
  transaction, and consumption is separately exactly once;
- unattended clients never create one.

### External resource

- stores provider resource identifier;
- remains immutably bound to the creating session, workspace, root run, principal, quota scope,
  credential generation, pool, and request;
- requires the exact execution owner for lookup; guessed identifiers from another owner fail
  closed before policy or admission;
- supports asynchronous recovery and safe cancellation.

### Job

- is materialized exactly once from a successful invocation and its external-resource affinity;
- is looked up only with the exact session, workspace, and root-run owner fence;
- repeats the immutable provider principal, quota scope, credential generation, and pool authority
  needed for restart-safe status and cancellation;
- has a bounded maximum runtime, bounded poll scheduling, and compare-and-set revision;
- records cancellation intent durably before provider cancellation so a restart does not replay the
  destructive call blindly;
- enters `SETTLING` with a complete terminal target, actual usage, and observation timestamp before
  changing the original quota and root-run budget ledgers;
- resumes `SETTLING` without provider I/O and becomes terminal only after idempotent accounting.

## Recommended tables

```text
clients
workspaces
sessions
reported_contexts
root_runs
principals
quota_scopes
credentials
pools
pool_members
invocations
attempts
quota_reservations
approvals
jobs
external_resources
leases
circuit_breakers
quota_snapshots
reconciliation_runs
reconciliation_items
alerts
feedback
audit_events
```

## Identifier strategy

Use opaque sortable identifiers such as:

```text
ses_...
run_...
req_...
att_...
job_...
apr_...
cred_...
quota_...
pool_...
alert_...
```

Identifiers must not embed account names, credentials, paths, or personal data.

## Time and JSON

Persist UTC Unix milliseconds as integers. Convert to local time only in presentation.

Flexible JSON metadata is allowed only when schema-validated, secret-free, body-free, and not a substitute for query-critical stable columns.

## State values

### Session

```text
CREATED
ACTIVE
DISCONNECTED
SUSPENDED
EXPIRED
REVOKED
```

### Invocation

```text
RECEIVED
VALIDATING
POLICY_CHECK
WAITING_APPROVAL
DEDUPLICATION
QUOTA_RESERVED
QUEUED
DISPATCHING
RUNNING
RETRY_WAIT
RECONCILING
SUCCEEDED
FAILED
DENIED
CANCELLED
UNKNOWN
DUPLICATE_IN_FLIGHT
CAPACITY_EXCEEDED
QUOTA_EXHAUSTED
```

`DUPLICATE_IN_FLIGHT` is a bounded nonterminal coalescing state. Startup recovery converts an
unresolved coalesced participant to `FAILED` with `result_unavailable_after_restart` rather than
leaving a terminal-looking duplicate record.

### Credential

```text
HEALTHY
DRAINING
COOLDOWN
EXPIRED
REVOKED
INSUFFICIENT_SCOPE
DISABLED
QUARANTINED
UNKNOWN
```

### Job

```text
CREATED
RUNNING
POLLING
CANCELLING
RECOVERING
SETTLING
SUCCEEDED
FAILED
CANCELLED
UNKNOWN
```

Only the final four values are terminal. `SETTLING` is deliberately nonterminal because the
provider outcome is known but durable quota and budget accounting has not yet been confirmed.

### Daemon health

```text
RECOVERING
READY
DEGRADED_READ_ONLY
DEGRADED_NO_PROVIDER
DRAINING
FAILED_CLOSED
STOPPED
```

Only `READY` produces a successful readiness response. `RECOVERING` includes the first due-job
supervisor pass; `DRAINING` closes new provider admission while bounded cleanup continues.

### Circuit breaker

```text
CLOSED
OPEN
HALF_OPEN
```

## Database writer design

SQLite supports one active writer. Use a dedicated low-priority audit writer for batchable events, direct short transactions for security state, no network waits inside transactions, bounded busy retries, and startup integrity checks.

Schema migration 6 adds the four asynchronous attempt-checkpoint columns, database triggers that
forbid partial or non-success checkpoints, and an index used by startup reconstruction. Applied
migration names and checksums are verified before new migrations run.

Schema migration 7 adds a trigger that makes a completed asynchronous checkpoint's attempt
identifier, request, ordinal, credential, principal, quota scope, completion time, resource type and
identifier, generation, and pool authority immutable. This prevents a later direct database update
from clearing, reparenting, or mutating the authority that startup reconstruction trusts.
