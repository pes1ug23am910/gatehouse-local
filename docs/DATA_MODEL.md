# Data Model

## Entity graph

```text
Client ──< Session ──< RootRun ──< Invocation ──< Attempt
  │           │                          │             ├── Credential
  │           └──< ReportedContext       │             └── EmergencyUnlockRecord
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
- an ordinary attempt records credential, principal, quota scope, status, latency, and error class;
- its initial write freezes the exact dispatch credential generation and pool alongside that
  authority, before any provider handoff;
- an emergency attempt leaves those ordinary foreign-key columns null and records dedicated
  redacted unlock, credential, principal, quota-scope, pool, and generation authority;
- a successful asynchronous creation atomically records resource type, provider resource identifier,
  credential generation, and pool as an all-or-none handoff checkpoint validated against the frozen
  dispatch authority, not later mutable credential state;
- emergency authority is synchronous-only and cannot carry an asynchronous checkpoint;
- never records authorization material.

### Credential mutation

- is idempotently keyed by mutation identifier and operation;
- records the target and optional replacement credential identifiers plus a redacted phase journal;
- persists a high-entropy `custody_intent_alias` and the expected principal, quota scope, generation,
  state, and expiry before provision or rotation enters persistent custody;
- advances from prepared authority to custody-created authority only after the KeyStore create
  returns, allowing restart recovery to distinguish exact staged ownership from an unrelated
  identifier collision;
- never stores the submitted secret in `metadata_json`, `result_json`, identifiers, aliases,
  timestamps, or other scalar fields;
- permits recovery to delete staged custody only through the exact journal alias; mismatched or
  unprovable material remains intact and the mutation remains cleanup-required.

### Emergency unlock record

- stores opaque credential, principal, and quota-scope identifiers and aliases directly, without
  creating rows in the persistent credential/principal/quota graph;
- binds one unlock to one exact service, pool, session, and root run;
- records only redacted mutation, state, expiry, and ceiling evidence;
- never stores a secret, ciphertext, secret reference, or automatic pool membership;
- remains as audit authority after cancellation, expiry, shutdown, or restart relock.

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
- begins `ACTIVE` and changes to the matching `COMPLETED`, `FAILED`, or `CANCELLED` evidence state
  atomically with a known terminal job transition; an `UNKNOWN` job deliberately leaves it
  `ACTIVE`;
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
- resumes `SETTLING` without provider I/O and becomes terminal only after idempotent accounting;
- commits its terminal state and the exact affinity's matching terminal evidence state in one
  immediate transaction.

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
credential_mutations
emergency_unlock_records
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

Flexible JSON metadata is allowed only when schema-validated, secret-free, body-free, and not a
substitute for query-critical stable columns. For secret-bearing lifecycle operations, the final
serialized column values—including JSON keys and scalar spellings—must be exact-checked against the
live secret before commit; checking only the decoded string leaves is insufficient.

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
RETIRED
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

Schema migration 8 adds credential-mutation records, redacted emergency-unlock authority, dedicated
nullable emergency-attempt columns, and the frozen dispatch credential-generation/pool pair for
ordinary attempts. Emergency credential, principal, and quota-scope IDs are deliberately not
foreign keys into the persistent credential graph. Database triggers require every new ordinary
attempt to carry complete dispatch authority, permit only migrated legacy rows to retain a null
pair, freeze the complete ordinary authority tuple, and require an all-or-none emergency authority
shape, exact active pre-expiry admission, null ordinary credential/checkpoint columns, and immutable
emergency references. The same migration advances a pre-existing `ACTIVE` resource to matching
terminal evidence only when its terminal job, invocation, owner, and generation/pool authority all
agree; ambiguous or incomplete rows remain active and fail closed.
