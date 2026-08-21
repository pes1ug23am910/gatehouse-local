# Architecture

## 1. System purpose

Gatehouse is a local capability broker. It mediates access from concurrent interactive clients and scheduled jobs to credentialed external services. Clients receive typed capabilities, not credentials.

The v1 architecture is a modular monolith. One daemon owns authorization, scheduling, credential selection, provider transport, persistence, and audit. This avoids premature distributed-system complexity while retaining clear internal boundaries for future adapters and deployment hardening.

## 2. Process topology

```text
┌─────────────────────────────────────────────────────────────┐
│ Windows user session                                        │
│                                                             │
│  Controlled launcher                                        │
│      ├── Interactive client session                         │
│      ├── Interactive client session                         │
│      └── Scheduled watcher                                  │
│              │                                              │
│              ▼                                              │
│       CLI / MCP local client shim                           │
│              │  short-lived access token                    │
└──────────────┼──────────────────────────────────────────────┘
               ▼
       127.0.0.1 Agent API
               │
┌──────────────▼──────────────────────────────────────────────┐
│ gatehoused (one installation-scoped process lease)          │
│                                                             │
│ Session registry ─ Policy engine ─ Approval manager         │
│         │               │               │                   │
│         └──────────── Fair scheduler ────┘                   │
│                         │                                   │
│                 Deduplication layer                         │
│                         │                                   │
│             Quota router and reservations                   │
│                         │                                   │
│            KeyStore lease and provider transport            │
│                         │                                   │
│                       Firecrawl                             │
│                                                             │
│ SQLite WAL: sessions, requests, attempts, jobs, audit        │
└─────────────────────────────────────────────────────────────┘
               ▲
               │
       127.0.0.1 Admin API
               │
       Dashboard and administrative CLI
```

## 3. Trust boundaries

### Client boundary

Client input is untrusted. A valid session capability proves that the request belongs to a configured Gatehouse session; it does not prove that every instruction inside that client is benign.

The client cannot choose a provider credential, authorization header, arbitrary provider base URL, unrestricted HTTP method, emergency pool, administrative action, or a higher budget than the session received at launch.

### Administrative boundary

The admin API uses a separate authentication realm. An agent access token cannot approve a request, unlock an emergency pool, add a credential, change policy, or view administrative details.

Credential mutations use an authenticated admin cookie plus exact loopback `Origin` and CSRF
validation before command or body parsing. The CLI collects provision, rotation, and emergency
secrets through an interactive hidden prompt and sends bounded metadata in
`X-Gatehouse-Command` with the raw secret as `application/octet-stream`. It never accepts the
secret from arguments, environment, files, or stdin, and no secret-export operation exists.
The loopback client keeps cookies only for the lifetime of that bounded admin session. A binary
secret-mutation response may not set a cookie; any such response or exact active-secret reflection
fails the request and clears the cookie jar before best-effort logout.

Manual credential validation uses the same admin cookie, exact loopback `Origin`, and CSRF boundary,
but accepts only an opaque credential identifier and expected generation with an empty body. It is
live-only, bypasses ordinary agent routing, permits one in-process request with no queue or retry,
and constructs only the fixed Firecrawl credit-status read. The result allowlist contains no
provider response body or credential material.

### Secret boundary

The KeyStore returns a time-bounded secret lease only to the provider transport. Policy, scheduling,
dashboard, audit, and adapter layers operate on opaque credential identifiers and metadata. Each
provider request carries an explicit `PERSISTENT` or `EMERGENCY` custody selector derived from its
admitted authority. The composite store opens only the selected backend; a missing emergency lease
never falls back to a same-named persistent credential.

### Same-user residual risk

The v1 deployment runs under the normal Windows account. It is an operational authorization and
damage-bounding boundary, not hostile same-user process isolation. Provider-side caps and narrow
scopes are mandatory compensating controls. Reset-aware reconciliation and local-quarantine
components are implemented. The stock admin surface can capture one explicit, exact-generation
credit-status snapshot in live mode, but periodic provider-counter collection and reconciliation
orchestration remain unwired. Local provisioning, rotation, disable, quarantine, and retirement are
stock administrative mutations; provider-side revocation remains a separate operator
responsibility.

## 4. Session identity

A controlled launch creates a session record and a high-entropy bootstrap capability. The plaintext bootstrap value is not persisted. The client shim exchanges it for a short-lived access token.

```text
Controlled launch
→ persist session and bootstrap verifier
→ inject bootstrap capability into client shim
→ exchange for 10-minute access token
→ heartbeat and refresh
```

After daemon restart, access tokens are invalidated, but a non-expired bootstrap capability can re-adopt the persisted session. Process identifiers may be logged for diagnostics but never establish attribution or liveness.

## 5. Concurrency hierarchy

```text
Human user
└── Session
    └── Root run
        └── Reported client context
            └── Invocation
                └── Attempt
```

Authorization and hard budgets are session-scoped. Reported child-context identifiers may improve attribution and fairness, but they cannot bypass the session ceiling.

Initial design target:

- up to 256 connected client contexts;
- 40–60 sustained active callers;
- approximately 96 broker-level operations in flight;
- strict provider-specific concurrency below the global ceiling;
- bounded queues for remaining work.

## 6. Request flow

```text
1. Authenticate short-lived access token.
2. Validate operation-specific schema.
3. Build canonical context.
4. Evaluate policy.
5. Create or consume approval when required.
6. Compute keyed request fingerprint.
7. Coalesce or reject duplicate work when safe.
8. Check runaway and budget circuits.
9. Select an eligible named pool and atomically reserve estimated quota and root-run budget.
10. Enter the bounded fair queue carrying the selected quota-scope identity.
11. Revalidate the reservation after queueing; atomically replace it and requeue if its scope changes.
12. Open a credential lease and apply the final quota-validity fence.
13. Execute the provider request.
14. Classify success, retry, rate limit, denial, or ambiguity.
15. Reconcile actual usage.
16. Persist attempt and invocation outcome.
17. Return a redacted structured result or durable asynchronous job handle.
```

## 7. Scheduler

The scheduler enforces global, per-service, per-quota-scope, and per-session limits plus a soft per-reported-context fairness limit and reserved watcher capacity.

A weighted deficit round-robin policy rotates between sessions within each priority class. One session cannot fill the entire service queue and starve another session. Every queue entry has a deadline.

The quota-scope identity is part of each queued work item and dispatch permit. If an expired
reservation is replaced onto another scope, the old permit is released and the invocation queues
again under the new scope; a scope cannot evade its running limit by switching credentials.

## 8. Duplicate control

Gatehouse computes an HMAC-SHA-256 fingerprint over the canonical semantic request. This supports equality checks without storing plaintext bodies or a public plain digest.

Eligible public reads may use single-flight coalescing:

```text
first equivalent request → provider call
subsequent equivalent request → original request/job handle
```

Mutations, private-scope results, and account-specific results are not coalesced across security boundaries.

## 9. Account and quota model

```text
Provider
└── Principal or team
    └── Quota scope
        ├── Credential A
        └── Credential B
```

Pools reference quota scopes rather than raw keys. This prevents multiple keys belonging to one shared balance from being mistaken for independent credit pools.

Named pools:

- `interactive-default` — automatic selection within the pool;
- `watcher-reserved` — guaranteed watcher capacity;
- `emergency-locked` — no persistent credential and no automatic selection.

Persistent provisioning seals the supplied secret into current-user DPAPI custody even when the
provider is disabled; it does not enable networking. Rotation creates a generation-fenced
successor and moves the prior credential to `DRAINING`. New routing uses the successor while an
existing asynchronous resource retains its exact original credential generation and pool affinity.
Disable and quarantine are local routing states. `RETIRED` is terminal and remains distinct from a
provider-side revocation; none of these mutations contacts the provider.

The emergency path is a separate explicit projection, never a pool member or automatic failover.
One interactive unlock may bind one credential to one exact service, pool, session, and root run.
It is synchronous-only and capped at 15 minutes, 25 requests, 100 credits, and concurrency one.
The secret exists only in the process-local in-memory KeyStore. SQLite retains redacted authority
and attempt evidence, not the emergency secret or persistent credential/principal/quota rows.

## 10. Atomic quota reservations

```text
BEGIN short transaction
committed = active/pending/disputed estimates
          + reconciled actual usage newer than the balance watermark
available = provider-reported remaining - committed - configured floor
if available is sufficient:
    create reservation and credential lease metadata
COMMIT
perform network request outside transaction
reconcile actual usage in a new short transaction
```

Settlement atomically replaces an estimate with actual usage. An authoritative remaining-balance
snapshot advances the durable watermark and absorbs older settled usage; stale or used-only
snapshots cannot resurrect capacity. Unconfirmed reservations remain pending until provider status
or reconciliation resolves them.

## 11. Provider transport

The adapter builds a credential-free request. The coordinator attaches the exact persistent or
emergency custody kind, and the transport opens only that store, decrypts the secret, injects
authorization, sends the request, removes authentication metadata from diagnostics, and closes the
lease.

Provider HTTP state is per-request: the transport clears its cookie jar before and after handoff,
removes any inherited `Cookie` header, and rejects every `Set-Cookie` response. While the lease is
live it exact-checks raw response header names and values and the bounded response bytes against the
active credential before JSON parsing. A match fails closed as a malformed response with no data;
request, response, cookie, and mutable response-buffer surfaces are scrubbed on every exit.

No generic authenticated proxy is exposed.

## 12. Watcher architecture

The following is the implemented component model and intended stock topology. Feed-set, policy,
lease, budget, cursor, and reservation components exist, but the stock watcher execution facade is
not yet wired end to end. The company watcher model is a named unattended system client with:

- one active-run lease;
- a narrow feed-set capability;
- allowlisted hosts and path patterns;
- scheduled execution windows;
- a reserved queue lane;
- a reserved provider slot;
- a dedicated account pool;
- per-run request, credit, and duration budgets;
- immediate denial for any decision that would otherwise require approval.

A stolen watcher session can therefore consume only the watcher’s narrow envelope.

## 13. Persistence and recovery

SQLite in WAL mode stores clients, workspaces, sessions, root runs, invocations, attempts, pools,
principals, credentials, quota scopes, credential mutations, redacted emergency-unlock authority,
reservations, approvals, asynchronous jobs, resources, incidents, and audit events. Emergency
attempts use dedicated redacted authority columns while their ordinary credential, principal, and
quota-scope foreign-key columns remain null.

Network calls never occur while a database write transaction is open.

Provision and rotation first persist a high-entropy, non-secret custody-intent alias in the mutation
journal. DPAPI custody derives deterministic staging filenames from a hash of that alias, publishes
an exact `{credential_id, staged_alias}` intent marker before the ciphertext blob and metadata, and
removes the marker after a complete commit. Startup cleanup calls the ownership-aware
`discard_staged` contract: absence or fully removed exact-owned material succeeds, while a
mismatched marker, token, or unrelated collision is preserved and leaves cleanup unresolved.

For asynchronous provider creation, the successful attempt durably checkpoints resource type,
provider resource identifier, credential generation, and pool before the separate affinity bind.
Migration 6 adds those columns and all-or-none database triggers. If the process stops between the
provider response and affinity binding, startup validates the checkpoint against the invocation and
routing authorities, reconstructs the exact owner-bound resource, and promotes the invocation and
queue state. Incomplete, contradictory, or conflicting checkpoint authority fails startup closed.

Jobs use an explicit `SETTLING` checkpoint before their terminal transition. Provider-reported
actual usage is first persisted on the job, then applied idempotently to the original quota and
root-run budget reservations, and only then is the job made terminal. Startup resumes `SETTLING`
without another provider call.

The stock daemon acquires an installation-scoped operating-system file lock before opening or
recovering the database. It begins in `RECOVERING`, validates migrations and semantic job
authority, expires stale sessions and approvals, moves formerly active sessions to
`DISCONNECTED`, classifies interrupted attempts, reconstructs asynchronous resources, retains
unresolved reservations, and runs one initial job-supervisor pass before advertising `READY`.
Shutdown changes admission to `DRAINING`, rejects new provider work, allows bounded status and
cancellation cleanup, and stops no later than the configured lifecycle deadline.

## 14. Asynchronous ownership

Every durable external resource and job is fenced by its creating session, workspace, and root run,
as well as its provider principal, quota scope, credential generation, pool, and request. Status,
await, cancellation, recovery, and reconciliation rebuild that exact authority from SQLite;
caller-supplied provider identifiers cannot transfer ownership.

An optional stable `request_id` exists only for `firecrawl.crawl.start`. Reusing it under the same
authority recovers the already-created resource or job after a local materialization failure;
omitting it creates a distinct crawl. It is not a general deduplication key for other operations.

## 15. Administrative decisions

Approvals are request-bound and one-use. Approval and denial use one immediate SQLite transaction
with a `PENDING` compare-and-set predicate, so concurrent dashboard or CLI contenders have exactly
one winner. Later contenders observe the winning terminal decision instead of overwriting it.

Credential lifecycle mutations are idempotently keyed, redacted, and local. Provision and rotation
commit DPAPI custody metadata without requiring provider mode or networking. Rotation preserves
old-generation asynchronous affinity through `DRAINING`; retirement is the irreversible local
terminal state. Emergency cancel, expiry, clean shutdown, and startup recovery close admission and
relock the memory-only authority. A restart can retain only redacted SQLite evidence, never a usable
emergency credential.

While a submitted secret remains live, lifecycle code exact-checks the final serialized journal,
credential metadata, mutation result, audit payload, generated identifiers, and returned custody
reference. DPAPI also checks every cleartext filename, marker, reference, and metadata serialization
before publishing. Any overlap aborts the mutation and invokes the same ownership-fenced cleanup;
the active secret is never accepted as non-secret durable authority.

## 16. Reconciliation

When supplied with provider-usage snapshots, the reset-aware engine compares them with the local
ledger and the durable store can create a high-severity incident and locally quarantine a credential
for a large unexplained exclusive-use delta. An authenticated admin can explicitly capture one
sanitized counter snapshot for an exact persistent credential generation in live mode. The stock
daemon does not schedule quick/full reconciliation or collect counters periodically.

## 17. Deployment evolution

The KeyStore is an interface from the first commit. A future hardened deployment may move credential custody into a separate Windows service identity without changing the policy, scheduler, adapter, or audit models.

The trigger is an unattended client that both ingests untrusted content and receives either external mutation capability or a continuing financial-commitment capability.
