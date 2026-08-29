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

RootRun ──< RunawayQuarantine ──< RunawayBurstPermit >── Invocation

Provider ──< ProviderPrincipal ──< QuotaScope ──< Credential
                                      │              └── credential role/generation
                                      ├─── ProviderQuotaScopeIdentity
                                      ├──< QuotaDimension ──< QuotaSnapshot
                                      ├──< QuotaScopeStateEvent
                                      ├─── QuotaObservationSchedule
                                      ├─── ReconciliationScopeSchedule
                                      └──< PoolMembership >── Pool

Invocation ──< ExternalResource >── ProviderPrincipal
QuotaSnapshot ──< ReconciliationItem
```

## Key invariants

### Session

- plaintext bootstrap capability is never persisted;
- one session belongs to one client profile;
- workspace binding is immutable after launch;
- controlled launch exists only for a client profile's explicit `workspaces.allow` member and an
  actual working directory that resolves to the workspace's canonical root or a descendant;
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

### Provider identity, credentials, and quota scopes

- a principal records the provider-facing identity kind independently from its local alias:
  account, team, project, user, or organization; legacy rows retain `LEGACY`;
- a quota scope records the actual billing/rate scope independently from a credential. Supported
  scope kinds include account, team, project, per-key budget, and rate bucket;
- multiple credentials may bind to one quota scope, so multiple keys never imply multiple balances;
- supported Firecrawl onboarding requires a stable operator-declared provider team identity. Its
  raw 1–160 character visible ASCII (`!` through `~`) value is HMACed immediately with an
  installation key and is never
  persisted;
- `provider_quota_scope_identities` stores provider ID, `TEAM` identity kind, keyed fingerprint,
  owning principal/scope, creation time, and tombstone-retained metadata. Provider/kind/fingerprint
  is unique and each quota scope has at most one identity. A principal may own multiple
  independently identified scopes, but an equal declaration cannot create a second balance;
- each credential has one role: `WORKLOAD`, `INFERENCE`, `MANAGEMENT`, or `OBSERVER`;
- current Firecrawl workload dispatch accepts only `WORKLOAD`; its fixed credit observer accepts a
  `WORKLOAD` or isolated `OBSERVER` credential. The other roles are provider-neutral foundation,
  not implemented Firecrawl workload authority;
- one account onboarding mutation stages DPAPI custody and then atomically creates the Firecrawl
  account principal, team scope, workload credential, fill-first pool membership, native quota
  dimension, disabled observation schedule, initial state event, result, and audit evidence;
- account aliases are operator-facing identifiers. Opaque principal, scope, credential, pool, and
  schedule identifiers remain internal;
- removal retires custody and tombstones/disables the graph; it does not delete its provider/team
  identity reservation, audit, or state history and does not claim provider-side credential
  revocation. Rotation remains a credential-generation change inside that identity/scope;
- the raw provider team ID and stored HMAC fingerprint are excluded from status, lifecycle result,
  and audit schemas. Because Firecrawl's team credit response supplies no attested identity, the
  model cannot prove that deliberately different operator declarations do not name one real team.

### Quota dimensions and durable scope state

- a scope has one primary dimension and may have multiple independently named provider-native
  dimensions;
- dimension rows retain the native unit, counter kind, and reset-window kind. They do not convert
  request buckets, tokens, money, or provider credits into one generic unit;
- each snapshot attached to a dimension can retain the provider-native `period_start_ms` and
  `period_end_ms`; the scope also retains its latest known billing-period bounds. Null bounds mean
  the typed provider observation supplied no authoritative reset instant, not that Gatehouse
  invented a timer;
- `quota_scope_state_events` is append-only and generation-ordered. The current scope state and
  generation are a queryable projection of that history;
- a definitive authenticated quota-exhausted response and an authenticated nonpositive balance
  durably transition the whole quota scope to `EXHAUSTED` in the same attempt/observation
  transaction;
- elapsed time alone never heals exhaustion. Only an authenticated positive observation or an
  explicit operator recovery may transition it out of `EXHAUSTED`;
- operator recovery does not manufacture a balance observation. Without a fresh authoritative
  snapshot the effective routing/status state remains `UNKNOWN`;
- `DISABLED` and `QUARANTINED` are durable operator/security exclusions. `COOLDOWN` is persisted for
  bounded provider conditions but is presented as `UNKNOWN` on the account status surface;
- circuit breakers carry a generation, update time, and explicit `TIMER`,
  `AUTHENTICATED_POSITIVE`, or `OPERATOR` recovery policy instead of relying only on process memory.

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
- routing estimates and floors, reservation amounts, settlement usage, and approval-consumption cost
  inputs are strict non-Boolean nonnegative signed-INT64 integers; rejection occurs at the public
  boundary before a mutating transaction or SQLite parameter binding;
- released, reconciled, expired safely, or retained pending reconciliation;
- reconciled actual usage remains an admission-visible charge until an authoritative provider
  remaining-balance snapshot advances that scope's balance watermark;
- cannot disappear solely because the daemon restarted.

### Quota snapshot and scope balance

- exact remaining and optional plan observations are bounded canonical decimal `TEXT`, not raw
  provider lexemes; projected counters remain signed-INT64-compatible nonnegative integers;
- every authenticated snapshot names its quota dimension, exact credential and generation,
  observation kind, fixed code-owned source, capture time, and `stale_at_ms`; an optional exact used
  counter has the same text-plus-projection representation;
- nullable period start/end values preserve the exact provider window associated with that
  dimension and observation. Either bound may be independently absent; when both are present, end
  follows start;
- remaining projected/observed fields are paired, as are plan projected/observed fields, and every
  projection exactly matches the canonical observation;
- a known scope balance is a three-field watermark: projected remaining, capture time, and snapshot
  ID are either all null or all non-null;
- the named snapshot must match the scope, unit, capture time, projected balance, canonical
  observation, and recomputed projection; reads never normalize or repair a mismatch;
- validation has four outcomes: `VALID` retains proven fresh authority, `ABSENT` means the complete
  watermark triplet is null, `STALE` means the provenance is sound but no longer admissible, and
  `CORRUPT` covers every partial or inconsistent non-null authority;
- `ABSENT` and `STALE` remain unavailable for positive-cost admission. `CORRUPT` is ineligible for
  every route, including the existing zero-cost exact-affinity cleanup path, and none of those
  outcomes can create or replace a positive reservation;
- zero and negative exact remaining values validly project to zero, and snapshot observations are
  immutable after insertion.

### Quota observation schedule

- one schedule belongs to one quota scope and optionally binds one exact observer credential
  generation;
- state is `DISABLED`, `ENABLED`, or `PAUSED`; onboarding always starts `DISABLED`;
- interval, freshness TTL, next-due time, last start/completion, last snapshot, consecutive failure,
  last error class, and generation are durable;
- a compare-and-set generation fences concurrent claim, completion, rotation, disable, and restart;
- a schedule being enabled is not network authority. Collection additionally requires the
  provider's default-off observer channel to be live with its separate network switch enabled;
- provider I/O occurs outside SQLite transactions and is bounded by the configured accounts per
  cycle and observer concurrency.

### Reconciliation scope schedule

- one durable row belongs to one quota scope and stores separate QUICK/FULL baseline snapshot IDs
  and last-checked timestamps;
- every non-null baseline must name a persisted snapshot owned by that scope; no provider counter is
  synthesized for initialization;
- a new scope starts with null baselines and its first real snapshot initializes both. Migration of
  an existing scope uses the latest valid current snapshot from durable reconciliation when
  available, otherwise the actual latest retained snapshot;
- FULL comparison advances both cadence baselines at the same current observation, while QUICK
  advances only QUICK and MANUAL advances neither;
- one shared generation and exact last-reconciliation pointer fence selection, result/alert/
  quarantine persistence, current-observation mismatch deduplication, and baseline advancement in
  one short transaction;
- scheduled comparison reads persisted snapshots and ledger rows only. Provider observation is a
  separate, default-disabled network authority.

### Approval

- one use by default;
- request-bound;
- expires to denial;
- cannot be consumed by another session;
- approval or denial changes `PENDING` exactly once through an immediate compare-and-set
  transaction, and consumption is separately exactly once;
- restart rehydration remains bound to the same durable session, client, workspace, and root run. A
  new controlled-launch session cannot inherit the row; pending crawl recovery also requires the
  original stable request handle;
- unattended clients never create one.

### Runaway quarantine and burst permit

- one quarantine is uniquely owned by an exact session, root run, and service; database triggers
  prove the root run belongs to that session;
- trigger reason is `REPEATED_EQUIVALENT`, `AGGREGATE_BURST`, or bounded detector-capacity failure;
- state is `OPEN`, `AUTHORIZED`, `DENIED`, `EXPIRED`, or `EXHAUSTED`, with a monotonic generation;
- `OPEN` and `DENIED` have no grant. An authorized/expired/exhausted grant retains its human actor,
  reason fingerprint/supplied flag, expiration, request/credit/concurrency ceilings and remaining
  values, plus a bounded code-owned operation allowlist;
- the dashboard action token is derived with an installation key from current immutable action
  facts; it is not stored as a reusable plaintext database secret. The current generation and token
  fence concurrent or stale decisions;
- one burst permit belongs to one quarantine generation and one unique invocation/request. Its
  insert trigger proves the invocation owner/service/operation and the live request, credit,
  concurrency, expiry, and allowlist authority;
- reservation atomically decrements remaining requests/estimated credits and increments active
  concurrency. Settlement is exactly once; known actual overrun consumes more credits and unknown
  actual cost exhausts the grant;
- restart converts every active permit to `ORPHANED`/unknown cost, retains its conservative
  consumption, releases the counted concurrency slot, and expires the authorization. No timer
  transitions an offender back to ordinary unrestricted admission;
- every unrecovered quarantine generation fences fresh session/root admission for the owning client
  profile, including `AUTHORIZED`; unrelated client profiles remain independent;
- one immutable fresh-run recovery row binds the exact current quarantine generation and its
  client/session/root owner. It is valid only after the old session is revoked/expired, the root is
  completed/cancelled, active concurrency is zero, and no active permit remains;
- the service additionally rejects nonterminal/unknown work, usable approval or unreconciled
  accounting authority, and nonterminal or unreconstructed asynchronous affinity before it closes
  the old authority and appends recovery. Recovery transfers no burst grant;
- no request body, provider content, key, or human decision reason is stored in these rows or audit
  payloads.

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
provider_quota_scope_identities
quota_dimensions
quota_scope_state_events
quota_observation_schedules
credentials
credential_mutations
emergency_unlock_records
pools
pool_members
invocations
attempts
quota_reservations
approvals
runaway_quarantines
runaway_burst_permits
runaway_quarantine_recoveries
jobs
external_resources
leases
circuit_breakers
quota_snapshots
reconciliation_runs
reconciliation_items
reconciliation_scope_schedules
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
rqu_...
rbp_...
```

Identifiers must not embed account names, credentials, paths, or personal data.

## Time and JSON

Persist UTC Unix milliseconds as integers. Convert to local time only in presentation.

Flexible JSON metadata is allowed only when schema-validated, secret-free, body-free, and not a
substitute for query-critical stable columns. For secret-bearing lifecycle operations, the final
serialized column values—including JSON keys and scalar spellings—must be exact-checked against the
live secret before commit; checking only the decoded string leaves is insufficient.
Exact reconciliation values are stable canonical `TEXT` columns and canonical strings in
`details_json`; oversized or fractional values are never emitted as JSON numeric tokens or routed
through SQLite `REAL`.

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

Credential state is distinct from the quota-scope state and the credential role. For example, two
healthy keys may still share one exhausted team scope, and an observer credential is never eligible
for a Firecrawl workload merely because it is healthy.

### Quota scope

```text
HEALTHY
EXHAUSTED
UNKNOWN
DISABLED
QUARANTINED
COOLDOWN
```

The public account status allowlist exposes only `HEALTHY`, `EXHAUSTED`, `UNKNOWN`, `DISABLED`, and
`QUARANTINED`; internal cooldown is conservatively rendered as unknown.

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

Only `READY` produces a successful readiness response. `RECOVERING` includes the first bounded
retention/checkpoint/footprint batch, scheduled-reconciliation batch, and due-job supervisor pass;
`DRAINING` closes new provider admission while bounded cleanup continues.

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

Schema migration 9 appends `observed_remaining_units_decimal` and
`observed_plan_total_units_decimal` to `quota_snapshots`, plus
`provider_delta_units_decimal`, `unexplained_delta_units_decimal`, and
`allowed_tolerance_units_decimal` to `reconciliation_items`. Before backfill it atomically validates
the SQLite type and range of v8 snapshot/scope/reconciliation integers, proves the legacy
`details_json` tolerance is an exact SQLite integer, and validates every non-null scope snapshot
anchor. Any malformed row rolls the entire migration back, leaving version 8 unchanged.

Backfill uses canonical integer `CAST(... AS TEXT)` values, including conversion of the legacy
allowed-tolerance JSON member to a JSON string without SQLite `REAL`. A scope balance with no
snapshot ID is an unauthoritative cache and is cleared along with its timestamp; existing
reservations and unrelated state are preserved. Valid anchors remain. INSERT and UPDATE triggers
defend integer types and ranges, paired text shapes and ASCII/length bounds, exact-string length
bounds, the all-null/all-non-null scope triplet, snapshot identity consistency, and observation
immutability. Application parsing remains authoritative for full canonical grammar, exact
round-trip equality, and projection equality. No decimal column is added to `quota_scopes`.

Schema migration 10 is append-only and leaves migrations 1–9 and their checksums unchanged. It adds
principal identity kind, credential role, quota-scope kind and durable state-generation metadata;
native `quota_dimensions`; authenticated snapshot provenance, freshness, and optional exact used
counters; append-only quota-scope state events; breaker generation/recovery policy; and durable
observation schedules. Existing scopes receive one primary legacy dimension and a generation-zero
migration event. Only the exact built-in scripted no-network snapshot is grandfathered as
non-expiring scripted authority; every other pre-v10 live snapshot remains `LEGACY` and fails the
freshness fence until re-observed. Migration guards reject malformed legacy state, identifiers, or
generations atomically before any v10 schema change survives.

Schema migration 11 is append-only and leaves migrations 1–10 and their checksums unchanged. It
adds `runaway_quarantines` with a unique session/root-run/service owner, generation-fenced human
decision and bounded-grant shape checks, plus `runaway_burst_permits` with unique invocation
ownership, authorization-generation, estimated/actual credit, concurrency, and settlement state.
Owner and permit-authority triggers reject cross-session/root/service/operation attachment. There is
no backfill that fabricates a quarantine or grant for earlier data; existing rows and release
history remain unchanged.

Schema migration 12 is append-only and leaves migrations 1–11 and their checksums unchanged. It
adds immutable `provider_quota_scope_identities` with bounded provider and identity kind, a fixed
installation-HMAC fingerprint shape, one provider/kind/fingerprint reservation globally, and one
identity per quota scope. The row records the owning principal, which may own multiple independently
identified scopes. It persists no raw provider identity and does not fabricate one for a legacy
scope. Tombstoning does not delete the row, preserving duplicate-balance prevention across local
account retirement and re-onboarding.

Schema migration 13 is append-only and leaves migrations 1–12 and their checksums unchanged. It
adds immutable `runaway_quarantine_recoveries`, uniquely keyed by quarantine and exact generation,
with client/session/root owner, prior state, local admin actor, recovery time, literal confirmation,
and a reason fingerprint. Insert authority requires the current generation, terminal old
session/root, zero active concurrency, and no active permit; update and delete are prohibited. The
same migration adds the client session-capacity lookup index. It performs no recovery backfill and
does not rewrite an earlier quarantine, provider identity, or release-history row.

Schema migration 14 is append-only and leaves migrations 1–13 and their checksums unchanged. It adds
only the indexes required for each bounded periodic-retention query.

Schema migration 15 is append-only and leaves migrations 1–14 and their checksums unchanged. It adds
`reconciliation_scope_schedules`, due-order indexes, same-scope pointer/generation triggers, automatic
schedule creation for new scopes, and first-snapshot baseline initialization. Populated upgrades
preserve existing reconciliation rows and derive baselines only from real scope-owned snapshots.
