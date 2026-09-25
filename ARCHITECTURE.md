# Architecture

## 1. System purpose

Gatehouse is a local capability broker. It mediates access from concurrent interactive clients and scheduled jobs to credentialed external services. Clients receive typed capabilities, not credentials.

The v1 architecture is a modular monolith. One daemon owns authorization, scheduling, credential selection, provider transport, persistence, and audit. This avoids premature distributed-system complexity while retaining clear internal boundaries for future adapters and deployment hardening.

The daemon is the long-lived central broker. Each controlled MCP client process starts an MCP
stdio shim on demand; that shim carries only session/bootstrap authority and makes bounded loopback
calls. It never receives provider custody, and there is no per-project credential process or `.env`
copy. User-logon availability remains a deployment gate; the supplied task wrappers currently refuse
native registration and removal.

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
provider response body or credential material. It contains conservative projected integers and
validated canonical observation strings only; the strings represent exact numeric values rather
than provider lexemes and never flow to the agent API, MCP, dashboard, or audit payloads.

### Secret boundary

The KeyStore returns a time-bounded secret lease only to the provider transport. Policy, scheduling,
dashboard, audit, and adapter layers operate on opaque credential identifiers and metadata. Each
provider request carries an explicit `PERSISTENT` or `EMERGENCY` custody selector derived from its
admitted authority. The composite store opens only the selected backend; a missing emergency lease
never falls back to a same-named persistent credential.

Persistent DPAPI payloads bind credential, principal, quota scope and secret reference in a
versioned envelope. Opening a lease checks that identity and current generation/eligibility.
Publication uses exclusive stages and create-only destinations; in-flight rollback verifies file
identity and preserves replacements. Mutable metadata remains subject to validation and provides
no rollback protection. Queued abandoned work refuses effects, while running workers own buffer
scrubbing and closure of late abandoned leases.

The provider key is never projected to an agent, MCP tool, client environment, or typed result.
Gatehouse chooses a credential internally and returns only the provider operation's redacted typed
result and permitted routing metadata.

### Same-user residual risk

The v1 deployment runs under the normal Windows account. It is an operational authorization and
damage-bounding boundary, not hostile same-user process isolation. Provider-side caps and narrow
scopes are mandatory compensating controls. Reset-aware reconciliation and local-quarantine
components are implemented. The stock admin surface can capture one explicit, exact-generation
credit-status snapshot in live mode. A separate bounded Firecrawl observation loop is wired but
default-disabled behind its own live/network switches. Scheduled QUICK/FULL reconciliation is a
provider-I/O-free stock task over persisted snapshots; it does not enable that observer. Local
provisioning, rotation, disable, quarantine, and retirement are stock administrative mutations;
provider-side revocation remains a separate operator responsibility.

## 4. Session identity

Controlled creation carries a request ID retained by the client before dispatch. SQLite atomically
binds it and the validated launch-authority digest to the session. Reuse cannot mint a second
session or recover a raw bootstrap capability. Request cancellation commits a permanent tombstone
before revoking any bound session, so cleanup can target a lost creation response. The daemon
binding survives restart; the CLI does not durably store lost request IDs or capabilities.

A controlled launch creates a session record and a high-entropy bootstrap capability. The plaintext bootstrap value is not persisted. The client shim exchanges it for a short-lived access token.

```text
Controlled launch
→ persist session and bootstrap verifier
→ inject bootstrap capability into client shim
→ exchange for 10-minute access token
→ heartbeat and refresh
```

After daemon restart, access tokens are invalidated, but a non-expired bootstrap capability can re-adopt the persisted session. Process identifiers may be logged for diagnostics but never establish attribution or liveness.

Launch authority is the explicit `(client, workspace)` binding in the client profile plus the
workspace's configured canonical root. The CLI submits its real current directory, and the daemon
resolves links and permits only an existing absolute root or descendant before pinning that exact
directory as the child `cwd`. Project prose may guide an agent to request a tool, but Gatehouse does
not parse instruction files or prompt text as authorization. Multiple client profiles may bind the
same workspace and pool while receiving distinct sessions and root runs.

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
9. Build one immutable, deterministic plan for the explicitly named pool after validating durable
   scope state and fresh snapshot-backed balance authority, rejecting configured catalog overflow.
10. Atomically reserve estimated quota and root-run budget against the leading eligible scope.
11. Enter the bounded fair queue carrying that quota-scope identity. If the scope cannot accept
    dispatch because its scheduler capacity is full and pool failover is explicitly enabled,
    replace the unused reservation with the next
    eligible distinct scope from the same plan; if all are full, wait on the deterministic leader.
12. Revalidate the reservation after queueing; atomically replace it and requeue if its scope changes.
13. Open a credential lease and apply the final quota-validity fence.
14. Durably claim the invocation's sole provider send, then execute the provider request.
15. Classify success, rate limit, denial, quota exhaustion, or ambiguity without another send.
16. Persist the attempt checkpoint. A definitive quota-exhausted attempt and its durable scope-state
    transition commit atomically before any later invocation can select that scope.
17. Retain uncertain usage for reconciliation; never retry or fail over after transport handoff.
18. Reconcile actual usage and persist the invocation outcome.
19. Return a redacted structured result or durable asynchronous job handle.
```

## 7. Scheduler

The scheduler enforces global, per-service, per-quota-scope, and per-session limits plus a soft per-reported-context fairness limit and reserved watcher capacity.

A weighted deficit round-robin policy rotates between sessions within each priority class. One session cannot fill the entire service queue and starve another session. Every queue entry has a deadline.

The quota-scope identity is part of each queued work item and dispatch permit. If an expired
reservation is replaced onto another scope, the old permit is released and the invocation queues
again under the new scope; a scope cannot evade its running limit by switching credentials.

`fill_first` is a shared capacity policy, not a sticky account assignment for a session, root run,
or LLM. Concurrent callers continue to use the leading eligible scope while its fresh quota
authority, atomic reservation capacity, and scheduler/lease headroom permit. Gatehouse considers a
later scope only when failover is explicitly enabled and the leading scope cannot safely admit
that dispatch within the bounded policy;
it does not spread work merely to distribute callers. If every eligible scope is temporarily at its
in-flight ceiling, the request queues against the deterministic leading scope until its deadline
rather than acquiring a per-caller account affinity.

The source candidate supports only `routing.maximum_total_provider_attempts: 1`. A durable,
request-bound claim precedes transport handoff and survives restart. No provider response or
transport failure permits a second send, including proven connection failure, HTTP 401/402/429,
or an operation otherwise marked retry-safe. Pre-dispatch capacity selection consumes no provider
send. Administrative and scheduled observation remain independently gated, outside this workload
ceiling.

`maximum_route_candidates` is a strict integer from 1 through 32, default 32. SQLite reads bound
configured pool members and the total of all workload credential generations to that ceiling,
including inactive history, before materialization. Overflow rejects the selected pool rather
than truncating its unranked rows. Exact-affinity selection queries the bound scope, credential,
and generation independently of unrelated members. Candidate materialization in the in-memory
router is also bounded before ranking.

## 8. Duplicate control

Gatehouse computes an HMAC-SHA-256 fingerprint over the canonical semantic request. This supports equality checks without storing plaintext bodies or a public plain digest.

Eligible public reads may use single-flight coalescing:

```text
first equivalent request → provider call
subsequent equivalent request → original request/job handle
```

Mutations, private-scope results, and account-specific results are not coalesced across security boundaries.

Runaway control is separate from single-flight. A bounded detector counts equivalent fingerprints
and aggregate arrivals in one exact session/root-run/service scope. Crossing either threshold opens
a durable offender-scoped quarantine; unrelated client profiles remain independent, while new
sessions and root runs for the same client profile are fenced by every unrecovered quarantine
generation. Ordinary time-based detector cleanup never heals that database state. The local
dashboard can deny it or grant the exact old root a generation-fenced typed-operation burst capped
by duration, requests, credits, and concurrency. Every authorized admission creates a one-use
durable permit and settles or conservatively orphans it. A separate dashboard recovery may revoke
the old session, close its root, and release one exact generation only after all permits, ambiguous
work, unreconciled authority, and nonterminal resource affinity are absent. It transfers no burst
authority. Agent/MCP/CLI calls and prompt text have no decision or recovery authority.

## 9. Account and quota model

```text
Provider
└── Principal or team
    └── Quota scope
        ├── Credential A
        └── Credential B
```

Pools reference quota scopes rather than raw keys. This prevents multiple keys belonging to one shared balance from being mistaken for independent credit pools.

Supported Firecrawl onboarding also requires a stable operator-declared team identifier. Gatehouse
immediately HMACs that non-secret value with an installation key and persists only the fingerprint
as internal mutation authority and an immutable provider/`TEAM` identity reservation; one
fingerprint cannot attach to two scopes, and one scope
cannot acquire a second identity. Tombstoning retains the reservation, while rotation replaces a
key inside the same scope. Neither the raw value nor its fingerprint appears in status, mutation
results, or audit.

This is a declaration-consistency guard, not provider attestation. Firecrawl's credit observation is
team-scoped but supplies no authoritative team identifier, so an offline broker cannot detect an
operator deliberately assigning different declared IDs to two keys that actually share one team.

Normal positive-cost routing admits only a `HEALTHY` quota scope with valid current balance
authority. Durable scope states are `HEALTHY`, `EXHAUSTED`, `UNKNOWN`, `DISABLED`, `QUARANTINED`,
and `COOLDOWN`; all but `HEALTHY` are excluded from ordinary automatic dispatch. Status expiry or a
missing, stale, or contradictory snapshot is fail-closed, not a reason to assume capacity.

Every named pool belongs to exactly one service/provider and every member must belong to that same
service. Automatic fallback is therefore same-provider and remains inside the immutable named-pool
plan. Gatehouse never silently substitutes a different provider, model, privacy boundary, price, or
output contract.

The local route-assessment helper evaluates at most 32 explicit ordinary new-work requirements
at one supplied UTC time. It derives each operation's positive credit estimate from its code-owned
specification, asks the existing planner for that exact automatic pool and validates the represented
plan facts. Immutable results distinguish eligible, ineligible and unverified observations; empty
requirements remain unverified. Assessment does not reserve quota, take permits, refresh or dispatch.
The planner still supplies authority and breaker facts absent from its returned plan. The standalone
helper does not own a transaction or reserve joint capacity. `SqliteWorkloadHealth` derives verified
client/workspace/purpose and profile-pool coverage and owns a bounded read transaction for each
authenticated control-status assessment. The watcher's manual-pool routing remains separate.

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

New pools and missing within-pool failover settings default to false; explicit legacy Boolean
settings remain readable. Changing ordinary pool failover requires a typed admin-cookie,
origin/CSRF-protected mutation with actor, nonblank reason, and caller-chosen mutation ID. A single
immediate transaction updates the setting and commits its exact replay binding, redacted result,
and preserved audit; reasons are fingerprinted, not retained as text. The corresponding CLI is
`pools failover enable|disable`. This control neither enables networking nor overrides the one-send
ceiling. Emergency authority is outside the ordinary plan and cannot be enabled by this mutation.

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

The `provider-reported remaining` term in that routing calculation is a conservative signed-INT64
whole-credit projection of the exact canonical observation: negative values and zero project to
zero, positive fractions are floored, and larger valid values saturate. A known balance is eligible
only when its scope watermark names a snapshot with the same scope, unit, capture time, projected
balance, canonical observation, and recomputed projection. Catalog reads and the positive-reservation
transaction both validate that authority. A mismatch makes the balance unknown without repairing it.
Zero or negative observations therefore block new positive-cost ordinary reservations while leaving
existing reservation and affinity authority intact and allowing eligible zero-cost exact-affinity
status, reconciliation, and cancellation cleanup.

For live positive-cost work, the anchored head must be an unexpired authenticated observation from
the credential generation bound to that scope. The only no-network exception is the exact
code-owned `SCRIPTED` authority created by scripted synchronization. Legacy, stale, absent, or
corrupt authority is ineligible at both catalog selection and atomic reservation, so a race cannot
turn an expired status view into a provider dispatch.

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

Only an HTTP 200 response for `firecrawl.account.credit_status` uses exact JSON numeric hooks.
Those hooks bound every numeric token in that successful body, reject duplicate object keys and
non-standard constants, and retain only a normalized exact-number wrapper. The adapter applies the
stricter credit-observation envelope to `remainingCredits` and present `planCredits`. Syntax,
duplicate-key, and numeric failures are cleared of token-bearing exception context and become a
sanitized malformed response. Other operations retain ordinary JSON decoding. A non-200
credit-status body is discarded without decoding after transport security and size checks; its HTTP
status remains authoritative, except that every unexpected 2xx is a non-retryable malformed
response.

No generic authenticated proxy is exposed.

## 12. Watcher architecture

The stock watcher topology is implemented for bounded synchronous scrape/map execution with the
credential-free scripted transport. The company watcher is a named unattended system client with:

- one active-run lease;
- a narrow feed-ID capability with no caller-selected URL or provider payload;
- a configuration-owned workspace, ordered target sequence, and allowlisted hosts and paths;
- scheduled execution windows;
- a reserved queue lane;
- a reserved provider slot;
- an isolated manual-only scripted pool;
- per-run request, credit, and duration budgets;
- a server-owned pending summary and explicit versioned cursor commit;
- immediate denial for any decision that would otherwise require approval.

A stolen watcher session can therefore consume only the watcher’s narrow envelope. The ordinary
invocation scheduler handles admitted provider steps, but Gatehouse does not yet schedule scans
periodically. Live credentials, asynchronous crawl, and crash redispatch or step-level resume remain
outside this topology.

## 13. Persistence and recovery

Observer validation, refresh and scheduled reads commit request-bound intents before provider
handoff, outside the eventual network call. Exact scope, generation, actor and source authority
bind terminal snapshots and audits. Ambiguous sends or failed evidence commits retain `UNKNOWN`
and cannot be replayed. A fresh authorized observation may reconcile earlier uncertainty without
proving that an earlier provider request arrived.

Lifecycle diagnostics retain at most 256 fixed-field records across daemon runs. Diagnostic loss
does not fabricate successful shutdown; a poisoned connection fences admission and durable writes.
Shutdown attempts independent resource cleanup, preserves primary cancellation, and retains the
database and installation lease while an owned task or cleanup phase remains unresolved. An
explicit retry resumes unfinished phases. A finalization record is not proof of process exit.

SQLite in WAL mode stores clients, workspaces, sessions, root runs, invocations, attempts, pools,
principals, credentials, quota scopes, credential mutations, redacted emergency-unlock authority,
reservations, approvals, asynchronous jobs, resources, incidents, and audit events. Emergency
attempts use dedicated redacted authority columns while their ordinary credential, principal, and
quota-scope foreign-key columns remain null.

Migration 10 appends provider/account identity kinds, credential roles, quota-scope kinds, native
quota dimensions, authenticated observation provenance and freshness, generation-fenced durable
scope state, immutable scope-state events, and bounded observation schedules. Existing identifiers
and migration history are preserved.

Migration 11 appends durable `runaway_quarantines` and `runaway_burst_permits` without modifying
versions 1–10. The quarantine owner is one session/root-run/service tuple. State generations,
action-token verification, request/credit balances, operation allowlists, permit concurrency, and
actual/unknown cost settlement are durable. Startup marks any active pre-restart permit orphaned,
retains its conservative consumption, closes the grant, and requires a fresh dashboard decision.

Migration 12 appends `provider_quota_scope_identities` without modifying versions 1–11. It binds one
provider identity kind plus installation-keyed HMAC fingerprint to one quota scope with immutable
owner fields and uniqueness in both directions. No raw provider team ID is stored and no legacy
identity is fabricated. A tombstoned account retains this reservation so the same declared billing
scope cannot later be reintroduced as independent capacity.

Migration 13 appends immutable `runaway_quarantine_recoveries` without modifying versions 1–12. A
recovery row binds one current quarantine generation to its client/session/root owner and records
only the local admin actor, confirmation, timestamp, and reason fingerprint. Its insert trigger
requires a revoked/expired session, completed/cancelled root, zero active concurrency, and no active
burst permit. A client-capacity index supports atomic profile-wide launch admission. Exact-current-
generation recovery evidence is the only exception to that launch fence; stale evidence and a
recovery for one of several quarantines remain blocking.

Migration 14 appends only the indexes needed by every bounded periodic-retention query. Migration 15
then adds one `reconciliation_scope_schedules` row per quota scope. QUICK and FULL each retain a
snapshot baseline and last-checked time, while a shared generation and exact last-reconciliation
pointer fence transactional advancement. Triggers require every baseline and result pointer to
belong to the same scope. New scopes start without invented history, and their first persisted
snapshot initializes both baselines. Existing scopes resume from a real current snapshot in the
last durable reconciliation when available, otherwise from the actual latest retained snapshot;
no synthetic provider counter is backfilled.

When a non-emergency attempt receives a definitive quota-exhausted response, its terminal attempt
update and the `EXHAUSTED` compare-and-set plus immutable event share one SQLite transaction. The
event binds scope, credential generation, request, attempt, reason, source, and time. A missing or
conflicting authority rolls the transaction back and fails closed. `EXHAUSTED` survives restart
and does not heal when an in-memory breaker or timer
expires. Only a newer authenticated positive balance or an explicit audited operator recovery may
transition it back to `HEALTHY`; routing still independently requires valid positive capacity.

Network calls never occur while a database write transaction is open.

The stock database-maintenance worker owns a separate compatible connection. Before readiness and
at each maintenance interval it applies one bounded retention policy, commits, requests a `PASSIVE`
WAL checkpoint, and observes only the main database plus the fixed WAL, shared-memory, and rollback-
journal sidecars. A trusted footprint from 90% to below the cap transitions one preserved HIGH
retention-pressure alert. Pressure requests one bounded `TRUNCATE` checkpoint and a fresh complete
observation. Falling below 90% resolves the singleton; a still-at/above-cap observation, unavailable
measurement, or alert-persistence failure propagates through required-task supervision to
`FAILED_CLOSED`. The existing per-feedback projection guard remains in front of low-priority
feedback. These observations do not serialize all file growth, so they are not a hard race-free
filesystem quota and mandatory evidence may grow between samples.

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
unresolved reservations, and runs one bounded maintenance/footprint batch plus one initial job-
supervisor pass and one bounded scheduled-reconciliation batch before advertising `READY`.
Shutdown changes admission to `DRAINING`, rejects new provider work, allows bounded status and
cancellation cleanup, and applies a finite cooperative lifecycle deadline. Synchronous SQLite and
native calls are not preemptible. Unfinished owned work or cleanup retains shared resources and
installation ownership rather than reporting a completed stop.

Schema migration 9 appends canonical decimal observation columns to quota snapshots and exact
decision columns to reconciliation items. It validates all relevant v8 integer rows and every
anchored scope watermark before backfill, converts proven integer values to canonical text without
SQLite `REAL`, and rolls back completely on malformed or contradictory state. An unanchored legacy
balance cache is deliberately cleared because it is not provider evidence. After migration the scope
balance triplet is either wholly null or names an internally consistent snapshot; triggers defend
the integer/text shapes, anchor consistency, and snapshot-observation immutability. Full canonical
grammar and projection equality remain application-enforced and every durable read fails closed.

Scripted synchronization establishes the same invariant locally: it creates a new scope with a null
triplet, inserts one deterministic synthetic no-network snapshot for 1,000,000 credits, then anchors
the scope to it in one immediate transaction. Restart validates and reuses that snapshot without
refreshing its timestamp or replenishing settled usage; a collision rolls the transaction back.

## 14. Asynchronous ownership

Every durable external resource and job is fenced by its creating session, workspace, and root run,
as well as its provider principal, quota scope, credential generation, pool, and request. Status,
await, cancellation, recovery, and reconciliation rebuild that exact authority from SQLite;
caller-supplied provider identifiers cannot transfer ownership.

An optional stable `request_id` exists only for `firecrawl.crawl.start`. Reusing it under the same
authority recovers the already-created resource or job after a local materialization failure;
omitting it creates a distinct crawl. It is not a general deduplication key for other operations.

Once provider handoff may have occurred, an ambiguous side-effecting attempt becomes `UNKNOWN`,
retains accounting and exact resource authority for reconciliation, and is never replayed or sent to
another credential, account, pool, emergency authority, or provider. Within-pool failover is a
pre-dispatch mechanism only; it never overrides asynchronous resource affinity. Unknown HTTP
billing retains quota and budget holds. Proven unsubmitted connection failure settles unused
usage at zero; known actual usage settles at that amount. Crash recovery retains a conservative
hold of at least the known actual amount and cannot reclaim the sole durable send.

## 15. Administrative decisions

Approvals are request-bound and one-use. Approval and denial use one immediate SQLite transaction
with a `PENDING` compare-and-set predicate, so concurrent dashboard or CLI contenders have exactly
one winner. Later contenders observe the winning terminal decision instead of overwriting it.

An approval-pending agent response carries only redacted binding context and a fixed
numeric-loopback dashboard URL. The MCP surface has no approve/deny operation and maintains only a
bounded process-random-HMAC index for an exact retry. Durable lookup rechecks session, client,
workspace, root run, service, operation, fingerprint/canonicalization versions, pool, exact cost and
unit, expiration, and one-use state. After an MCP restart, a pending crawl can be rehydrated only by
reusing its returned stable `request_id`; the original `WAITING_APPROVAL` invocation is not
re-executed. That continuation is available only after the same durable session/client/workspace/
root-run authority is re-adopted. A fresh controlled launch creates a different session and cannot
inherit the approval.

Runaway decisions are a distinct local-admin/dashboard-only human boundary. Both bounded burst and
fresh-run recovery post through the admin cookie/origin/CSRF realm with the current quarantine
generation and keyed action token. A bounded burst may allow multiple same-provider pool accounts
to handle otherwise failing safe work, but it remains attached to the old root and cannot be escaped
through a fresh launch. Recovery is a separate destructive fence: it succeeds only after old work is
safe, revokes the old session, closes the root, and grants no request or account authority. Neither
action weakens quota, policy, retry-safety, affinity, or no-emergency-fallback checks.

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

When supplied with provider-usage snapshots, the reset-aware engine subtracts exact canonical
remaining observations and compares that decimal result with integral ledger values. An increase is
a reset, not negative usage; an exact within-period plan change is indeterminate even if projections
match. Exact provider and unexplained deltas remain authoritative, while legacy signed-INT64 integer
fields are independently null when a value is fractional or out of range. Relative tolerance uses a
local precision-512 decimal context, exact multiplication, and one final ceiling; absolute tolerance
is a strict non-Boolean nonnegative signed-INT64 integer.

The stock daemon supervises scheduled QUICK and FULL reconciliation as a required local task. A
worker-owned compatible database connection processes at most the configured scope count and wall-
time per batch, with one short transaction per scope. It performs no provider I/O. QUICK and FULL
use separate durable baselines and cadences; FULL advances both modes at the same observation, while
QUICK leaves the FULL baseline unchanged. One scope transaction selects the due mode, reads the
persisted baseline/current snapshots and ledger window, records the exact result and any mismatch
alert/quarantine, deduplicates consecutive-mismatch progression for an already-seen current
snapshot, and generation-fences baseline advancement. A first observation is baseline evidence, not
an invented prior counter.

An authenticated admin can explicitly capture one sanitized counter snapshot for an exact
persistent credential generation in live mode. The separately gated, default-disabled bounded
Firecrawl observation schedule can add later snapshots, but scheduled reconciliation neither
enables that observer nor makes a network call. `UNKNOWN`, `STALE`, and reset decisions are valid
durable outcomes; an unexpected loop exit, persistence failure, or corrupt schedule authority fails
the required stock lifecycle closed.

## 17. Deployment evolution

The internal disabled-task planner produces bounded canonical review data for an explicit runtime,
configuration origin/digest, account SID and configuration-expansion environment. Both daemon and
watchdog intents are disabled, use limited interactive principals and carry the same supplied
configuration digest. Immutable manifest bytes and a digest permit exact consistency checks; they
do not attest runtime trust or establish task ownership. The planner performs no discovery, command
rendering or native operation, and its outputs explicitly retain unavailable registration and
unconfirmed ownership. Native definition normalization, create-only registration, full environment
enforcement, native executable binding and safe removal remain separate contracts.

CLI and watchdog daemon selection now derives only the platform launcher name beside the active
interpreter. The pure selector accepts bounded absolute literal paths; an explicit launcher is an
exact spelling assertion of that same adjacent path. Consumers perform one availability check on
that path and refuse missing or invalid results without PATH fallback. An already accepted existing
daemon needs no new executable selection. This is pathname selection only: a following filesystem
check does not attest executable identity, trusted ancestry, import closure or atomic execution.
See [the launcher-selection decision](docs/adr/0013-adjacent-daemon-selection.md).

The shared long-lived environment builder validates bounded exact inputs before configuration
capture. It retains the existing allowlist, rejects duplicate canonical names, preserves values
including empty expansion bindings, and produces sorted uppercase keys. Native CLI runners and
watchdog settings freeze accepted mappings; each process call receives a fresh dictionary. Typed
refusals stop entrypoints before discovery or execution, and the default CLI factory routes invalid
environment startup through its normal command-error path. The bounds and limits are specified in
[the environment decision](docs/adr/0014-bounded-long-lived-environment.md).

The KeyStore is an interface from the first commit. A future hardened deployment may move credential custody into a separate Windows service identity without changing the policy, scheduler, adapter, or audit models.

The trigger is an unattended client that both ingests untrusted content and receives either external mutation capability or a continuing financial-commitment capability.
