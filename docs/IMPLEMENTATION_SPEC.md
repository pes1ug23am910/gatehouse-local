# Gatehouse v1 Implementation Specification

**Status:** Normative draft for the unreleased local v0.0.2 development candidate  
**Target:** Native Windows 11, PowerShell 7 and Git Bash  
**Deployment:** Normal Windows user account  
**Initial provider:** Firecrawl

The public v0.0.1 tag, release artifacts, history, and evidence remain historical, immutable release
surfaces. This draft specifies additive candidate work; it does not redefine v0.0.1.

## 1. Normative terms

- **MUST / MUST NOT:** required for v1 acceptance.
- **SHOULD / SHOULD NOT:** strong recommendation; deviation requires an architecture decision record.
- **MAY:** optional implementation choice.

## 2. v1 objectives

Gatehouse v1 MUST:

1. support multiple simultaneous controlled client sessions;
2. tolerate large child-context fan-outs while retaining hard session limits;
3. hold provider credentials outside ordinary client environments;
4. expose typed provider operations only;
5. enforce workspace, client, operation, target, purpose, data, pool, and budget policy;
6. provide bounded queues, approvals, retries, leases, and timeouts;
7. reserve service capacity and credits for the unattended watcher;
8. prevent duplicate credit burn for eligible equivalent reads;
9. persist crash-safe metadata without request or response bodies;
10. reconcile provider counters with the local ledger;
11. recover valid sessions and asynchronous jobs after restart;
12. centrally manage multiple provider accounts without placing a key in each client project;
13. preserve provider-native quota dimensions and credential roles for future providers; and
14. fail closed when policy, schema, integrity, or redaction safety cannot be established.

## 3. Required processes

- `gatehoused` — daemon and control plane;
- `gatehouse` — administrative and launch CLI;
- local client shim — typed client interface and token refresh;
- notifier — user-session approval and incident signal;
- watchdog — health-aware bounded restart helper.

The installed stock daemon MUST compose these authorities without test-only dependency injection.
Before database migration, recovery, provider setup, or listener binding it MUST acquire one
installation-scoped, process-crash-safe operating-system lock. A competing stock daemon MUST make
no durable or listener-visible change.

`gatehoused` MUST be the only long-lived custody/routing authority. A controlled MCP client
session MAY start one `gatehouse-mcp` stdio shim on demand, but that shim MUST contain only bounded
session/bootstrap authority, MUST use loopback typed operations, and MUST NOT receive or return a
provider key. User-logon registration MAY keep the daemon available; an unavailable daemon MUST NOT
cause the shim to read ambient or per-project credentials.

## 4. Listener separation

- Agent API: loopback-only, default port `47621`.
- Admin API: loopback-only, default port `47622`.
- Agent access tokens MUST NOT authenticate administrative routes.
- The dashboard MUST use one-use login exchange, an `HttpOnly` cookie, strict same-site policy, host validation, and anti-forgery protection for state changes.
- Secret-bearing credential mutations MUST authenticate the admin cookie and validate exact
  loopback `Origin` and CSRF authority before parsing metadata or body. Safe metadata MUST be
  separate from the bounded raw secret body. No argument, environment, file, stdin, echo, export,
  or retrieval path may exist in the stock CLI.
- The loopback client MUST scope cookies to one bounded administrative session. A binary
  secret-mutation response MUST NOT set cookies; response header names and values plus the
  resulting cookie jar MUST be exact-checked against the active secret. Any request failure MUST
  clear the jar before best-effort logout and scrub retained request and body handles.

## 5. Session authentication

### Bootstrap capability

- minimum 256 bits of cryptographic randomness;
- one session only;
- persisted only as a keyed verifier;
- absolute expiry;
- revocable;
- never reused as a provider credential.

### Access token

- opaque and memory-only;
- approximately 10-minute default lifetime;
- renewed through the bootstrap capability;
- invalidated by daemon restart;
- rejected after session revocation.

### Re-adoption

After restart, a valid non-expired bootstrap capability may re-adopt a persisted session. Process identifiers MUST NOT be used as the authority for identity or liveness.

### Controlled workspace launch

Every launchable client profile MUST explicitly list the requested workspace in
`workspaces.allow`. Missing v0.0.1 fields MAY remain parse-compatible but MUST create no launch
authority. The launch request MUST carry the caller's actual existing absolute working directory.
The daemon MUST resolve links in that directory and the configured canonical workspace root, admit
only the root or a descendant, return the exact resolved directory, and require the launcher to use
it as the child `cwd`. Project instruction files, process names, prompts, and caller-selected opaque
identifiers MUST NOT establish authority. Multiple explicitly configured client profiles MAY bind
one workspace/pool while retaining separate sessions and root runs.

## 6. Session states

```text
CREATED → ACTIVE → DISCONNECTED → EXPIRED
             │            └──────→ ACTIVE
             ├────────────→ SUSPENDED → ACTIVE
             └────────────→ REVOKED
```

Session revocation MUST invalidate access tokens and queued work. External asynchronous resources remain subject to provider reconciliation.

## 7. Client classes

- `interactive` — may create dashboard approvals.
- `system` — unattended; converts `ASK` to immediate denial.
- `unattributed` — local status and documentation only; no metered or mutating operations.

## 8. Request envelope

Every invocation MUST include service, operation, operation-specific input, root-run identifier, optional reported child-context metadata, and a wait preference bounded by the server maximum.

`firecrawl.crawl.start` MAY additionally carry a caller-retained stable `request_id` in the strict
Gatehouse request-identifier format. It MUST be accepted only as a same-owner recovery handle for
that exact crawl request. Once that identifier is bound, a retry payload MUST NOT mutate or launch
a replacement for the durable resource; omission MUST create a distinct crawl. Other operations
MUST reject this field.

The caller MUST NOT provide provider authorization, raw credential or credential alias, arbitrary provider base URL, arbitrary HTTP method, emergency-pool selection, or local filesystem target.

## 9. Request state machine

```text
RECEIVED
→ VALIDATING
→ POLICY_CHECK
→ WAITING_APPROVAL | DEDUPLICATION
→ DUPLICATE_IN_FLIGHT → stable leader terminal outcome
→ QUOTA_RESERVED
→ QUEUED
→ DISPATCHING
→ RUNNING
→ RETRY_WAIT | RECONCILING
→ SUCCEEDED | FAILED | DENIED | CANCELLED | UNKNOWN
```

Every nonterminal state MUST have a deadline or an owning durable lease.

## 10. Scheduling

The scheduler MUST enforce global in-flight and queue limits, per-service limits, per-quota-scope limits, per-session limits, reserved watcher capacity, and fair rotation between sessions.

The default fairness algorithm SHOULD be weighted deficit round-robin. Queue expiration returns `capacity_exceeded` and a retry hint.

Every queued item and dispatch permit MUST retain the selected quota-scope identity. If atomic
reservation replacement selects a different scope while the invocation holds a permit, Gatehouse
MUST release that permit and queue again under the replacement scope before dispatch.

Firecrawl pool selection MUST be deterministic fill-first by configured priority. Independent LLM
sessions MAY share the highest-priority healthy account while its fresh quota authority and atomic
per-scope dispatch capacity permit. Gatehouse MUST move a new request to the next eligible member
only when admitting it to the preferred scope would exhaust quota or exceed that scope's dispatch
capacity. It MUST scan every eligible member of the named pool rather than imposing a three-account
ceiling. The scheduler MUST make the saturation check and enqueue decision atomically so concurrent
clients cannot all select an already-full scope. This is central capacity sharing, not per-LLM
credential assignment or sticky affinity.

Once an operation has provider-side handoff, capacity alone MUST NOT move it to another account.
Exact asynchronous resource affinity remains authoritative, and an ambiguous side-effecting
operation MUST become `UNKNOWN` rather than be replayed elsewhere.

## 11. Fingerprints and duplicate handling

Fingerprints MUST use HMAC-SHA-256 over canonical semantic request bytes. Plain request bodies MUST NOT be stored merely to support deduplication.

Same-session equivalent in-flight reads return the original request or job handle. Cross-session coalescing is permitted only for public read-only operations with equivalent authorization scope.

Only operations explicitly marked coalescible may join a single-flight group. A coalesced
participant MUST have a bounded wait, persist its link to the original request, and resolve to the
same stable terminal outcome. Participant cancellation detaches only that participant; the shared
execution is cancelled only after its last participant detaches.

## 12. Runaway control

A bounded detector MUST count both equivalent fingerprints and aggregate arrivals within one exact
session/root-run/service scope. Crossing either configured threshold or exhausting detector
capacity MUST atomically create or reuse a durable offender-scoped quarantine and return
`runaway_suspected`. Another session/root run MUST remain independent. A detector cooldown or
daemon restart MUST NOT heal the durable quarantine.

Only the authenticated local dashboard MAY authorize the offender to continue. Agent, MCP, prompt
text, and the stock CLI MUST expose no burst-decision capability. The dashboard decision MUST be
fenced by admin cookie, exact loopback origin, CSRF, current quarantine generation, and a keyed
action token. It MUST require a human reason, a nonempty code-owned typed-operation allowlist, and
explicit duration/request/credit/concurrency ceilings no greater than 15 minutes, 25 requests, 100
credits, concurrency eight, and 16 operations.

Every authorized admission MUST atomically create one request-bound permit, decrement one request
and estimated credits, and increment active concurrency. Settlement MUST be exactly once. Known
actual overrun MUST consume additional credits; unknown cost MUST exhaust remaining credit
authority. Expiry or exhaustion MUST remain blocked. Startup MUST mark active permits orphaned with
unknown cost, preserve their conservative consumption, close the authorization generation, and
require a fresh human decision.

## 13. Policy

Decisions are `ALLOW`, `ASK`, and `DENY`. For unattended clients, `ASK` becomes immediate `DENY`.

Required policy inputs include client class, session, workspace, operation, canonical target, purpose, data classification, estimated cost, pool, current schedule window, budget state, and circuit breakers.

An interactive approval MUST bind the complete canonical request authority, expire to denial, and
default to one use. Concurrent approve and deny actions MUST use a single immediate durable
compare-and-set from `PENDING`, so exactly one action wins and later actions cannot overwrite it.
Approval consumption MUST also be exactly once.

An approval-pending agent/MCP response MAY expose only its redacted identifier, stable request
handle, exact root run, fixed retry instruction, and validated numeric-loopback dashboard URL. The
MCP process MAY retain only a bounded, process-random keyed-HMAC continuation index and MUST release
cancelled/interrupted claims. Durable exact retry MUST revalidate session, client, workspace, root
run, service, operation, fingerprint/canonicalization versions, pool, cost/unit, expiration, and
one-use state. After MCP restart, pending crawl recovery MUST require its returned stable
`request_id`, MUST require the same re-adopted durable session/client/workspace/root-run authority,
and MUST NOT execute the original `WAITING_APPROVAL` invocation. A new controlled-launch
session MUST NOT inherit another session's approval; under `ASK` it MUST create a fresh approval.
A fresh valid crawl `request_id` with no durable parent MUST proceed normally under `ALLOW` and MUST
create a new pending approval under `ASK`; absence MUST NOT be confused with a mismatched recovery
handle.

## 14. Credentials, principals, quota scopes, and pools

The persistent model MUST distinguish provider identifier; account, team, project, user, or
organization principal identity; quota or billing scope; provider-native quota dimension;
credential role; credential generation; and pool membership. Multiple credentials MAY share one
quota scope. Gatehouse MUST NOT infer independent balances merely because two keys exist.
Provider-created asynchronous resources MUST also retain their creating session, workspace, root
run, and request authority across daemon restarts.

Credential roles are `WORKLOAD`, `INFERENCE`, `MANAGEMENT`, and `OBSERVER`. A typed operation MUST
declare its allowed roles in code. Firecrawl workload operations permit only `WORKLOAD`; the account
credit observer permits `WORKLOAD` or `OBSERVER`. An observer or management credential MUST NOT be
selected as Firecrawl workload authority.

Each quota dimension MUST retain its exact provider-native unit, counter kind, and reset-window
semantics. Money, tokens, request-rate buckets, and provider credits MUST NOT be collapsed into a
generic credit value. Fixed-point observations MUST remain canonical decimal text; integer
projections are admission aids, not replacements for the exact provider value. Existing snapshot
`period_start_ms` and `period_end_ms` columns MUST preserve authoritative provider window bounds for
the attached dimension. A typed collector MUST leave them null when its provider exposes no exact
reset instant rather than manufacture one.

The first durable ordinary-attempt write MUST freeze the exact credential, principal, quota scope,
credential generation, and pool used for dispatch. Before a successful asynchronous provider
creation can be exposed as complete, its terminal attempt MUST durably checkpoint resource type,
provider resource identifier, credential generation, and pool together and validate the checkpoint
against that frozen dispatch authority. A later local disable, quarantine, or generation fence MUST
NOT rewrite or invalidate the known dispatch fact. Startup MUST reconstruct a missing affinity only
after validating that checkpoint against the invocation, session/workspace/root owner and frozen
authority. Partial, contradictory, duplicate, or conflicting authority MUST fail startup closed.

Persistent provisioning MUST seal current-user DPAPI custody without depending on provider mode or
enabling provider networking. Rotation MUST create a generation-fenced successor, move its
predecessor to `DRAINING`, and preserve exact predecessor generation/pool authority for existing
asynchronous resources. Disable, quarantine, and terminal `RETIRED` MUST be local-only states and
MUST NOT claim or perform provider-side revocation.

Supported Firecrawl account onboarding MUST accept an explicit account alias, mandatory non-secret
`provider_team_id`, fill-first pool alias, priority, idempotent mutation identifier, optional expiry,
and one hidden-prompt secret. The team ID MUST contain 1–160 visible ASCII characters, each from
`!` through `~`. It
MUST use a crash-recoverable custody saga whose final immediate transaction creates the principal,
team quota scope, workload credential binding, immutable provider/`TEAM` identity reservation,
pool/member, native credit dimension, disabled observation schedule, generation-zero state event,
mutation result, and audit event as one graph.
Restart recovery MUST remove only custody proven to belong to an incomplete onboarding intent.

Gatehouse MUST HMAC `provider_team_id` immediately with an installation-derived key and MUST NOT
persist the raw value. Provider + `TEAM` + fingerprint MUST be unique, and one quota scope MUST have
at most one identity reservation. Duplicate declaration MUST fail before another scope is routable.
Removal/tombstoning MUST retain the reservation, and rotation MUST replace a credential only inside
the existing scope. Raw declared identity and fingerprint MUST NOT appear in account status,
mutation results, or audit. Because Firecrawl's team-scoped credit response supplies no attested
team identifier, the implementation MUST document that offline controls cannot detect deliberately
different declared IDs for keys sharing one real team.

No provider secret may be accepted through a command argument, environment variable, YAML,
ordinary file, standard input, log, error, child process, or serialized response. The administrative
client MUST send bounded non-secret command metadata separately from the hidden-prompt
`application/octet-stream` body and MUST zero mutable secret buffers after use.

Before any backend or custody handoff, stock Firecrawl secret ingress MUST enforce a namespace that
cannot equal Gatehouse's durable state, counter, identifier, or HTTP-literal vocabulary. Production
tokens MUST be lowercase `fc-` followed by at least 20 ASCII letters, digits, `_`, or `-`;
`FAKE-` and `synthetic-` namespaces are reserved solely for no-network verification. Input outside
these namespaces MUST NOT create custody, a mutation journal, or provider work.

Before a persistent create enters the KeyStore, the mutation journal MUST durably record a
high-entropy non-secret staging alias and the expected custody authority. DPAPI MUST derive its
exclusive staging filenames from a one-way token of that alias, publish an exact non-secret intent
marker before the ciphertext blob and metadata, and remove the marker after commit or complete
deletion. Ownership-aware staged cleanup MUST report success only when no custody material exists
or every exact-owned marker, partial, and token-derived stage was removed. It MUST preserve and
report failure for mismatched, colliding, or otherwise unproven material.

Automatic failover may occur only within an explicitly configured pool. Emergency authority MUST
be created only by an explicit interactive administrative action, held only in memory, and bound to
one exact service, pool, session, and root run. It MUST be synchronous-only, permit no default,
automatic, or failover selection, and cap one unlock at 15 minutes, 25 requests, 100 credits, and
concurrency one. Cancel, expiry, shutdown, and restart MUST relock it. Durable records MAY retain
only redacted authority and attempt evidence, not a secret or persistent emergency
credential/principal/quota row.

An authenticated nonpositive Firecrawl balance or definitive quota-exhausted workload response MUST
atomically and durably transition the account's team quota scope to `EXHAUSTED`. Every later request
and restart MUST exclude that scope. A short timer MUST NOT heal it. Only an authenticated positive
observation or explicit operator recovery MAY transition it out of exhaustion, and operator
recovery MUST NOT fabricate fresh balance authority. `DISABLED`, `QUARANTINED`, `UNKNOWN`, and
stale-balance scopes MUST remain ineligible for positive-cost workload routing.

An unauthorized response MAY try another healthy workload credential bound to the same quota scope
but MUST NOT spray the request across unrelated accounts. Permission denial MUST fail without
account failover. Definitive quota exhaustion MAY fail over across each later eligible member of the
same named provider pool. The emergency credential MUST never be an automatic fallback.

Every provider request MUST carry the exact `PERSISTENT` or `EMERGENCY` custody class selected by
admission. Persistent dispatch MUST open only persistent custody; emergency dispatch MUST require
the composite store's emergency-only lease path. Missing, expired, cancelled, or colliding custody
MUST fail before handoff and MUST NOT trigger cross-store fallback.

## 15. Quota reservations

Quota reservation MUST be atomic. A short transaction creates the reservation before network dispatch. Network I/O MUST occur outside the transaction. Actual usage is reconciled afterward.

A reservation that expires while its invocation is queued MUST be settled without usage and
atomically replaced before credential acquisition or provider dispatch.

The persisted state order MUST match that reserve-first acquisition order. Replacement of an
expired pre-dispatch reservation MUST commit old settlement and new reservation in one short
transaction. Quota validity MUST be checked again immediately before transport handoff.

Unconfirmed usage remains pending rather than being silently released.

Known settlement MUST replace the held estimate with actual usage atomically and idempotently.
Reconciled actual usage remains chargeable on later admissions until a newer authoritative
remaining-balance snapshot advances the durable scope watermark. Stale and used-only snapshots
MUST NOT restore capacity.

Routing MUST use the conservative whole-unit projection of an exact canonical remaining
observation. Negative and zero values project to zero, positive fractions floor, and values above
signed SQLite INT64 saturate. A known scope balance MUST name a snapshot with matching scope, unit,
capture time, projected integer, canonical observation, and recomputed projection. Catalog reads,
repository quota reads, and the atomic positive-reservation check MUST fail closed on any mismatch
without repair. Existing reservation and affinity authority MUST survive a zero or negative
observation; eligible zero-cost exact-affinity cleanup MAY continue. `quota_scopes` MUST NOT acquire
decimal columns.

## 16. Provider transport and provider-neutral boundary

The provider adapter constructs a credential-free typed request. An immutable, code-owned provider
descriptor MUST fix the provider ID, HTTPS origin and host, authentication strategy, operation name,
HTTP method, relative path pattern, request-body policy, allowed query names, target URL fields,
allowed credential roles, response-number policy, and error-body policy. Configuration and callers
MUST NOT supply or override origins, authorization/header strategies, arbitrary methods, paths, or
query fields. The transport opens only the explicitly selected KeyStore lease, injects the
code-owned headers and authentication, sends the request, redacts diagnostics, and closes the lease.

Provider HTTP handling MUST be stateless: clear the cookie jar before and after every handoff,
remove an inherited `Cookie` header, and reject every `Set-Cookie` response. While the exact lease
is live, raw response header names and values and the bounded response-byte buffer MUST be checked
for the active credential before JSON parsing. A match MUST yield a malformed response with no
data. The mutable response buffer MUST be overwritten on normal return, size rejection, ordinary
failure, cancellation, and arbitrary `BaseException`, before response close; retained request,
response, cookie, and exception surfaces MUST be scrubbed as far as the runtime permits.

Exact JSON numeric hooks MUST run only for `firecrawl.account.credit_status` at HTTP 200. They MUST
bound every numeric token in that successful body, reject duplicate keys and non-standard constants,
and retain only the dedicated normalized exact-number wrapper. Complete 128-significant-digit,
adjusted-exponent, and fixed-point observation checks MUST run only on `remainingCredits` and present
`planCredits` in the adapter. JSON syntax, duplicate-key, or numeric exceptions MUST have traceback,
cause, and context cleared, MUST NOT echo a token, and MUST become sanitized malformed responses.
All other operations retain ordinary decoding. Every non-200 credit-status body MUST be discarded
without decoding after credential-overlap, unsafe-header, response-size, and transport checks. Its
HTTP status and safe `Retry-After` MUST remain authoritative; every unexpected 2xx MUST be a
non-retryable `MALFORMED_RESPONSE`. Retained provider data MUST be null. Secret scanning MAY
preserve only the validated wrapper, MUST scan its canonical representation, and MUST NOT preserve
arbitrary decimal objects. The wrapper is transport-internal and MUST be consumed before generic
JSON serialization.

No secret-getting or generic authenticated proxy operation may exist. An unregistered provider,
foundation-only provider, unknown operation, role mismatch, method/path mismatch, absolute URL,
path traversal, unexpected query parameter, or invalid body shape MUST fail before credential
custody or network handoff.

The provider-neutral foundation reserves these IDs:

| Provider ID | Candidate status | Native quota model retained for later design |
|---|---|---|
| `firecrawl` | active typed vertical slice | team/account `credits` balance |
| `github` | foundation only; no operations | user-shared request-rate buckets and reset windows |
| `openrouter` | foundation only; no operations | per-key budget separately from account credits observed by a management key |
| `gemini` | foundation only; no operations | project RPM, TPM, RPD, and token use; no invented authoritative prepaid balance |
| `xai` | foundation only; no operations | inference authority separately from management/billing observation |
| `jarvislabs` | foundation only; no operations | account balance and grants, without broad infrastructure authority |

Foundation-only means schema/configuration identity, not a transport, validator, credential format,
or callable operation. Non-default runtime configuration for one of those providers MUST fail until
its typed implementation exists. Automatic fallback MUST remain within one provider. Gatehouse MUST
NOT silently switch an OpenRouter, Gemini, or xAI workload to another provider because model
semantics, privacy exposure, and cost differ.

## 17. Firecrawl operations

V1 exposes search, scrape, map, crawl start, crawl status, and crawl cancellation through typed
agent capabilities. Account credit status MUST remain an internal reconciliation and authenticated
administrative operation, not an ordinary agent or MCP capability. Its typed adapter contract is
implemented, and the stock authenticated path permits explicit manual refresh plus bounded
scheduled observation of exact generations through the separately gated observer transport.

Workload and observer networking MUST be independent default-off switches. A schedule MUST also be
enabled for each account; schedule enablement alone MUST NOT grant network permission. The collector
MUST bound request timeout, accounts per cycle, and concurrency, claim schedules with a durable
generation fence, perform provider I/O outside transactions, and persist exact observation,
credential/generation provenance, source, capture time, freshness deadline, state transition, and
audit atomically. Provider failures MAY update bounded schedule error metadata but MUST NOT expose a
provider body or credential.

The credit-status counters MUST be bounded RFC 8259 numbers. Canonical observations are normalized
values rather than provider lexemes: no exponent, plus, redundant leading zero, trailing fractional
zero, or signed zero remains. Missing/null remaining and present-null plan are malformed; missing
plan produces paired null fields. Negative and fractional remaining/plan values and valid exponent
notation are accepted, no plan-versus-remaining ordering is imposed, Python floats are rejected, and
injected exact non-Boolean integers pass the same bounds. The lower-level validation response
exposes exact observation strings and derived projections. The account-status allowlist exposes
alias, effective state, exact remaining/plan strings, native unit, observation time, staleness,
stale flag, and code-owned source. Agent, MCP, dashboard, configuration, and audit payloads MUST NOT
add those counters.

Paired v2 `billingPeriodStart` and `billingPeriodEnd` values MUST be bounded RFC 3339 timestamps,
exactly representable in milliseconds, and strictly ordered. Authenticated observations persist
them on the Firecrawl credit dimension. A partial, invalid, reversed, or sub-millisecond pair is a
malformed response; an absent pair remains null and MUST NOT be replaced by a synthetic reset time.

The adapter MUST set narrow explicit limits for crawl operations. Whole-domain crawling, external-link traversal, robot-policy bypass, and arbitrary browser interaction are excluded from v1.

## 18. Error classification

Provider outcomes MUST distinguish invalid credential, exhausted quota, permission or plan mismatch, rate limit, transient server failure, invalid request, and ambiguous side effect.

Permission failures MUST NOT trigger indiscriminate account spraying. Ambiguous side effects become `UNKNOWN` and are reconciled before replay.

For an operation marked retry-safe, a Firecrawl rate limit with a valid retry hint MUST retry the
same credential while its finite attempt budget and request deadline permit. Gatehouse MAY move to
the next eligible distinct scope only when retry guidance is absent, the same-credential attempts
are exhausted, or the delay would consume the remaining deadline. It MUST be able to visit every
later eligible distinct scope in the immutable same-provider pool plan once. A reconcile-first or
side-effecting operation, or any outcome for which submission may have occurred, MUST NOT use this
spill. Emergency and cross-provider authority MUST remain excluded.

## 19. Watcher

The watcher receives a feed-set capability rather than arbitrary provider tools. It MUST have one active-run lease, schedule enforcement, host/path allowlists, per-run request/credit/duration budgets, reserved queue/provider capacity, a dedicated pool, no emergency-pool access, and immediate denial for approval-requiring requests.

## 20. Persistence

SQLite MUST run with:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

Transactions remain short. Audit writes may be batched; approval consumption, local credential
state, quota reservation, runaway quarantine/permit state, and redacted emergency-unlock state
require immediate durable commits.

Migration 9 MUST append canonical exact-observation columns to quota snapshots and exact decision
columns to reconciliation items without changing migrations 1–8. Before backfill it MUST atomically
validate relevant v8 SQLite integer types/ranges, exact legacy allowed-tolerance sources, and every
anchored balance identity. Failure MUST leave schema/user version 8 with no version-9 row, columns,
or triggers. Backfill MUST use canonical integer text, convert tolerance JSON to a string without
SQLite `REAL`, clear unanchored scope balance caches, and preserve valid anchors and all reservations.
Post-migration triggers MUST defend integer/text shapes, paired nullability, bounds, complete scope
triplets, snapshot identity consistency, and observation immutability. Full canonical grammar,
round-trip, and projection equality remain application-authoritative. Every durable exact-text read
MUST require a real `str`, bounded canonical parse, and exact round trip; corruption MUST NOT be
normalized.

Migration 10 MUST append provider-account and durable quota-state support without changing
migrations 1–9. It MUST add identity/scope kinds, credential roles, multiple native quota
dimensions, authenticated snapshot credential/generation/freshness provenance, immutable
generation-ordered scope-state events, durable breaker recovery policy, and bounded observation
schedules. It MUST backfill one primary legacy dimension and generation-zero migration event per
existing scope. Only the exact built-in scripted no-network snapshot MAY be grandfathered as
non-expiring `SCRIPTED` authority; other legacy live snapshots MUST become stale/unavailable until
authenticated re-observation. Malformed legacy identifiers, generations, or states MUST roll the
whole migration back.

Migration 11 MUST append durable offender-scoped runaway quarantine and bounded burst authority
without changing migrations 1–10. It MUST add one unique session/root-run/service quarantine with
generation-fenced states and bounded grant fields, plus request-unique burst permits with
authorization generation, operation, estimated/actual credit, concurrency, and settlement state.
Database triggers MUST reject a root/session mismatch and a permit whose invocation owner, service,
operation, generation, expiry, remaining capacity, or concurrency lacks exact authority. Migration
MUST create no synthetic quarantine or grant for legacy rows.

Migration 12 MUST append immutable provider/quota-scope identity reservations without changing
migrations 1–11. It MUST store provider, identity kind, installation-HMAC fingerprint, owning
principal, quota scope, creation time, and bounded non-secret metadata, with uniqueness for
provider/kind/fingerprint and quota scope. A principal MAY own multiple independently identified
scopes. It MUST NOT persist raw declared identity, fabricate an identity for legacy scopes, or
delete the reservation when an account is tombstoned. Owner identity and fingerprint MUST be
immutable after insert.

Scripted synchronization MUST create a new scope unanchored, insert one deterministic idempotent
synthetic no-network snapshot for 1,000,000 credits, then anchor the scope inside one immediate
transaction. Restart MUST validate and reuse it without refreshing the timestamp or replenishing
settled usage. A collision or conflict MUST roll back and fail closed.

While a lifecycle secret remains live, every final serialized non-secret persistence surface MUST
be exact-checked against it before commit, including JSON keys and scalar spellings, generated
identifiers, mutation journals and results, audit payloads, custody references, DPAPI markers,
filenames, and metadata. An overlap MUST fail closed and use only ownership-proven cleanup; schema
validation or encryption alone MUST NOT authorize the overlapping value.

## 21. Logging and retention

Persist metadata and keyed fingerprints. Do not persist request or response bodies by default.

Default retention:

- detailed metadata: 60 days and a database-size cap;
- debug excerpts: opt-in, maximum 72 hours;
- daily aggregates: one year.

## 22. Reconciliation

Every Gatehouse credential SHOULD be exclusive to Gatehouse. Reconciliation MUST subtract exact
canonical remaining observations (`previous - current`) and compare the result with exact decimal
conversions of integral ledger, pending, and adjustment values. Remaining increase is reset
detection. Exact plan change within a period is indeterminate even when projections match. Missing
plan in either snapshot remains non-comparable.

Relative tolerance MUST be finite, within `[0, 1]`, and at most 128 significant digits; existing
configuration floats MUST convert through `Decimal(str(value))`. Absolute tolerance MUST be a
strict non-Boolean nonnegative signed-INT64 integer. Arithmetic MUST use a local precision-512
context with `Inexact` and `Rounded` traps, with only the final ceiling intentional after exact
multiplication. Provider deltas MUST support at most 383 significant digits. Derived unexplained
reconciliation deltas MUST support at most 384 significant digits after subtraction of a signed
INT64 ledger bound. Both exact delta strings MUST remain bounded to 385 signed fixed-point
characters without changing the global context.

Determinate decisions MUST retain canonical exact provider/unexplained deltas. Each legacy integer
field is independently populated only for an integral signed-INT64 exact value. Indeterminate,
reset, and plan-change decisions clear both exact and compatibility deltas. Exact integral allowed
tolerance is always retained as a canonical nonnegative string, including above INT64, with an
independently derived limit of 129 significant digits and 129 fixed-point characters. Decision
construction MUST enforce the role-specific bounds, exact/compatibility equality, and indeterminate
paired-null invariants. Durable reads MUST enforce role-specific bounds and exact/compatibility
equality. Details JSON MUST use strings rather than oversized numeric tokens.

A repeated significant mismatch on an exclusive credential creates a high-severity incident and local quarantine.

## 23. Recovery

On startup, Gatehouse remains `RECOVERING` while it validates the database, migration checksums, and
semantic job authority; loads policy and KeyStore metadata; expires stale approvals and sessions;
converts active sessions to disconnected; classifies interrupted attempts; reconstructs valid
asynchronous handoff checkpoints; re-adopts jobs; retains unresolved reservations; and restores
watcher lease state. It MUST run one complete bounded due-job supervisor pass before reporting
`READY` or an operational degraded state.

Startup MUST retain durable scope states and state-event generations, repair observation schedules
to the current healthy workload generation without silently enabling them, and recover incomplete
account mutations without provider I/O. `EXHAUSTED`, `DISABLED`, and `QUARANTINED` exclusions MUST
survive restart. If the separately authorized observer loop is configured, it begins only after
startup recovery and remains a required bounded runtime task.

Startup MUST also recover every active runaway burst permit as an `ORPHANED` unknown-cost permit,
retain its request and reserved-credit consumption, release durable active concurrency, close the
authorization generation, and require a fresh dashboard decision. Open/denied/exhausted durable
offender quarantines MUST NOT be timer-healed.

A terminal asynchronous observation MUST first move its job to durable `SETTLING` with the target
terminal state and actual usage. Gatehouse MUST then reconcile the original quota and root-run
budget reservations idempotently before the final job transition. Restart recovery MUST resume this
checkpoint without repeating provider I/O.

Shutdown MUST change provider admission to `DRAINING`, reject new provider work, preserve bounded
status and cancellation cleanup, and release remaining tasks and local leases within a finite drain
deadline. A required listener, scheduler, or supervisor failure MUST fail the process closed.

## 24. Release acceptance

V1 is not complete until:

- provider keys are absent from client environments and outputs;
- secret-canary tests have zero findings;
- concurrent quota oversubscription is prevented;
- watcher reserved capacity survives saturation;
- duplicate eligible requests create one provider call;
- error classes route differently and correctly;
- exact provider-number boundaries, duplicate-key handling, canonicalization, and projection pass;
- migration 9 backfill, rollback, checksum, trigger, and durable-authority tests pass;
- migration 10 append-only backfill, rollback, checksum, provenance, immutable-state-event, and
  restart tests pass;
- migration 11 append-only compatibility, owner/authority-trigger, generation-race, permit
  settlement, orphan-restart, and no-timer-heal tests pass;
- migration 12 append-only compatibility, checksum, raw-ID absence, fingerprint uniqueness,
  one-identity-per-scope, immutability, tombstone retention, and rollback tests pass;
- clean-install account onboarding, idempotency, rotation, disable/recover/tombstone, and redacted
  status tests pass;
- account onboarding requires a valid declared provider team identity, rejects duplicate declared
  teams as independent balances, never serializes raw identity/fingerprint, and keeps rotation on
  the original scope;
- durable exhaustion, fresh-positive recovery, stale/unknown exclusion, full-pool failover,
  permission no-spray, and capacity share-then-spill concurrency tests pass;
- safe 429 retry-then-full-pool behavior, no-guidance/deadline spill, and side-effect/ambiguous
  no-spray tests pass;
- equivalent and aggregate offender-scoped quarantine, bounded dashboard burst, restart recovery,
  and cross-session isolation tests pass;
- explicit workspace allowlist, canonical directory containment/link escape, legacy fail-closed,
  and separate-client shared-workspace attribution tests pass;
- approval retry binding, cancellation-safe MCP continuation, process-random HMAC index, and
  crawl-pending restart rehydration tests pass;
- default-off manual/scheduled observation and bounded collector tests pass with mock/no-network
  transports;
- scripted no-network availability is backed by one deterministic restart-stable snapshot;
- exact reconciliation detects fractional changes and plan changes hidden by projection ties;
- ambiguous side effects are not blindly retried;
- sessions re-adopt after restart;
- asynchronous jobs preserve principal affinity;
- asynchronous jobs preserve exact session/workspace/root ownership and resume settlement once;
- concurrent administrative approval decisions have exactly one winner;
- off-ledger usage simulation quarantines the credential;
- a clean wheel installation runs the stock daemon, CLI, MCP, notifier, and watchdog entry points
  through a scripted no-network process and restart test;
- public documentation matches passing tests.
