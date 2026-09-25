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

### Long-lived environment capture

Long-lived environment capture MUST use the existing allowlist without coercing names or retained
values. It MUST bound iteration to 512 accepted source entries plus one overflow observation, names
to 256 characters and 65,536 aggregate UTF-8 bytes, retained values to 8,192 UTF-8 bytes each, and
the defined output block to 32,768 bytes. That block counts one final NUL and two bytes per entry
beside its name/value bytes. These are application data limits, not native ABI guarantees.

Names and retained values MUST be exact strings, encode strictly and contain no NUL/CR/LF.
Non-ASCII names MUST be excluded before case normalization; excluded values MUST NOT be inspected.
Duplicate canonical retained names MUST fail even when values agree. Accepted values, including
empty configuration-expansion bindings, MUST remain exact. Canonical output keys MUST be sorted.
Ordinary failures MUST produce the fixed typed environment error without rejected text; control-flow
interruptions MUST propagate. Mapping callbacks have no preemptive deadline guarantee.

Native CLI runners and watchdog settings MUST freeze validated mappings, and actual subprocess
calls MUST receive fresh explicit dictionaries without ambient merging. Invalid entry environments
MUST refuse before configuration discovery or process effects. The default CLI factory MUST remain
import-safe and refuse affected commands before configuration mutation or secret prompts. These
controls MUST NOT be presented as native path/runtime ownership, interpreter-startup isolation,
scheduled-task environment enforcement or controlled-client environment policy.

### Scheduled-task deployment boundary

CLI/watchdog daemon selection MUST derive only `gatehoused.exe` on Windows or `gatehoused` on POSIX
beside one captured active-interpreter pathname. The pure selector MUST validate exact string types,
absolute literal spelling, at most 4,096 characters per input and result, at most 128 components,
and at most 255 characters per component. It MUST reject ambiguous platform-specific components.
An explicit executable MUST assert the exact selected spelling, never select an alternative.
Consumers MUST perform at most one availability check on that path and MUST NOT search PATH or
spawn after refusal. Ordinary failures MUST retain fixed unavailable outcomes; control-flow
interruptions MUST propagate. Accepting an existing matching daemon requires no launch selection.
These checks MUST NOT be represented as native identity, ancestry, alias-resistance, runtime/import
ownership, atomic execution or preemptive filesystem-deadline guarantees.

Task deployment MUST use explicit reviewed runtime and configuration bindings. The source planner
MAY construct a data-only disabled daemon/watchdog pair with canonical manifest bytes and digest,
but MUST NOT treat supplied review references, SID syntax or digest equality as native trust or
creation evidence. Its bounded configuration-expansion environment MUST remain distinct from a
complete enforced child environment. Task intent arguments MUST carry the exact same explicit
configuration origin and expected digest, without database or port overrides.

Until a native adapter proves disabled-at-creation, create-only behavior, complete definition
readback and owned runtime execution, the supplied task-management entrypoints MUST refuse. Task
name equality or a read-then-delete comparison MUST NOT manufacture conditional deletion authority.
Partial or uncertain native outcomes MUST remain unresolved; no automatic replacement or blind
cleanup fallback is permitted. Native deployment and activation remain separate from plan validation.

## 4. Listener separation

- Agent API: loopback-only, default port `47621`.
- Admin API: loopback-only, default port `47622`.
- Agent access tokens MUST NOT authenticate administrative routes.
- The dashboard MUST use one-use login exchange, an `HttpOnly` cookie, strict same-site policy, host validation, and anti-forgery protection for state changes.
- Browser login codes MUST use a bounded URL fragment rather than a query parameter. The fixed
  hash-authorized script MUST clear the fragment before retaining the code in the explicit exchange
  form; GET MUST NOT consume it. Origin validation MUST precede exchange-body processing.
- MCP loopback HTTP MUST use explicit numeric IPv4 loopback and a bounded port. Cleanup MUST retain
  ownership of actual request, response and redirect-request objects through separately bounded
  close attempts; mutable bodies and bounded retained exception/HTTP references MUST be scrubbed.
  Primary cancellation/control interruption MUST survive cleanup, with sanitized ordinary errors
  and no retained diagnostic chains. This MUST NOT be described as erasure of immutable copies.
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

The stock invocation coordinator charges one scheduling unit per admitted request. Priority weights
and session rotation therefore allocate request dispatch opportunities; they do not equalize provider
credits, response size, CPU time or request duration. Native provider costs remain independently
enforced by quota reservations, policy ceilings and session budgets. A future cost-normalized
scheduler requires a separate bounded cost definition before changing this accounting unit.

Every queued item and dispatch permit MUST retain the selected quota-scope identity. If atomic
reservation replacement selects a different scope while the invocation holds a permit, Gatehouse
MUST release that permit and queue again under the replacement scope before dispatch.

Firecrawl pool selection MUST be deterministic fill-first by configured priority. Independent
sessions MAY share the leading healthy scope while fresh quota and atomic dispatch capacity permit.
Automatic pre-dispatch fallback MUST default false and require an explicit audited pool action.
It MUST remain inside the selected same-provider pool and preserve the request deadline.

The server-owned `routing.maximum_route_candidates` MUST be a strict integer in 1..32 (default 32).
Ordinary catalog reads MUST bound configured pool members and total WORKLOAD credential generations
before materialization, reject overflow rather than truncate an unranked prefix, and preserve
deterministic ranking. Historical/ineligible generations MAY conservatively exhaust the bound.
Exact resource-affinity queries MUST select the original scope/credential/generation independently
of unrelated ordinary candidate overflow. Overflow implies no cleanup or migration. The scheduler
MUST make saturation checking and enqueueing atomic.

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
`runaway_suspected`. Detection and request admission MUST remain exact to that offender and MUST NOT
block an unrelated client profile. Every fresh session or root-run admission for the same client
profile MUST fail closed while any quarantine lacks exact-current-generation recovery evidence,
including `AUTHORIZED`, `DENIED`, `EXPIRED`, and `EXHAUSTED`. A detector cooldown or daemon restart
MUST NOT heal the durable quarantine.

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

Only the authenticated local admin/dashboard MAY recover one quarantine generation for a future
fresh run. Agent, MCP, prompt text, and stock CLI MUST expose no recovery capability. Recovery MUST
be fenced by admin cookie, exact loopback origin, CSRF, current generation, keyed action token,
explicit `RECOVER_FRESH_RUN` confirmation, actor, and reason fingerprint. Within one immediate
transaction it MUST reject active permits/concurrency, nonterminal or `UNKNOWN` invocations,
attempts, queues, or jobs, usable approval authority, unreconciled quota/budget authority, and any
nonterminal or unreconstructed asynchronous resource affinity. Only then MAY it revoke the old
session, terminalize its root, advance the quarantine generation, and append immutable recovery
evidence. Recovery MUST grant no burst, credential, account, operation, request, credit, or
concurrency authority. Stale/partial evidence or recovery of only one among multiple client
quarantines MUST remain blocking.

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

Local workload-route assessment MUST consume an explicit bounded immutable set of canonical
pool/operation requirements and one supplied UTC time. It MUST use the code-owned positive
estimated cost and unit for each supported new-work operation, rather than an arbitrary pool or
zero-cost probe. Empty requirements MUST remain unverified. The assessment MUST call only read-only
planning, validate represented output facts, and return fixed eligible/ineligible/unverified
results without retaining credential identifiers or raw exceptions. It MUST NOT reserve quota,
take breaker permits or leases, refresh observations or dispatch work. Legitimate zero-cost
resource reconciliation remains separate and unchanged.

Authenticated control status MUST derive workload coverage from verified client/workspace/purpose
policy and profile pool bindings, separate control availability from workload eligibility, and
reassess expiry or state changes. Each assessment MUST use a bounded read transaction without
committing a caller-owned transaction. Empty coverage MUST remain unconfigured and rejected
coverage unverified. Public health MUST remain lifecycle-only; the watcher's reserved route is
outside ordinary new-work coverage. A local observation MUST NOT imply provider reachability,
future request authorization, simultaneous capacity or reservation success. Facts absent from the
returned plan remain the planner's responsibility rather than independently proved by output
validation.

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

Persistent DPAPI payloads MUST contain a versioned envelope binding credential, principal, quota
scope and derived secret reference. Lease opening MUST validate that identity and recheck current
eligibility and generation. Legacy unbound ciphertext MUST refuse. Mutable alias, state, expiry
and generation metadata MUST NOT be described as rollback-protected. Publication MUST be
create-only; in-flight rollback MUST verify captured file identity and preserve replacements.
Mutable secret input MUST be copied before asynchronous work can outlive the caller. An abandoned
queued worker MUST refuse effects; a running worker MUST scrub its owned buffers and close a late
abandoned lease while preserving primary cancellation or control interruption.

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

Every admitted workload invocation MUST persist a server-owned
`maximum_total_provider_attempts` of exactly integer 1. Higher limits, booleans, strings, and
fractional values MUST be rejected. One short transaction MUST irrevocably claim the matching
RUNNING invocation/attempt before transport handoff; duplicate or exhausted claims MUST fail closed.
Transport I/O MUST begin only after that transaction commits. Cancellation, restart, connection
failure, error classification, same-scope failover, and emergency routing MUST NOT reopen the claim.

No workload response, including 401, 402, 429, or 5xx, MAY cause a second transport submission,
retry sleep, or replacement credential lease for that invocation. Durable exhaustion and cooldown
still affect later independently admitted requests. This is at-most-one local transport invocation,
not exactly-once provider effects or cross-request deduplication. Observer refreshes are separately
gated requests and MUST NOT inherit workload authorization.

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

Manual validation, refresh and scheduled observation MUST commit a bounded request-bound intent
before their only provider transport handoff. The intent MUST bind exact generation, scope, source
and actor authority without secret or provider payload. Provider I/O MUST remain outside database
transactions. Ambiguous dispatch or failed terminal evidence commit MUST retain `UNKNOWN`; restart
or replay of the same mutation MUST NOT send again. Terminal snapshot and audit evidence MUST match
the exact intent. A separately authorized new observation MAY resolve older uncertainty without
claiming whether an earlier request reached the provider.

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

Permission failures MUST NOT trigger indiscriminate account spraying. Ambiguous side effects MUST
remain `UNKNOWN` for reconciliation. A consumed invocation claim or observation intent MUST NOT be
replayed; any later work requires a distinct authorized request and its own admission.

Retry-safety classification MUST NOT override the total submission ceiling. Return the classified
provider failure and bounded retry hint without an automatic same-request resend. Ambiguous
execution remains UNKNOWN/reconciliation-only. Failure billing MUST be evaluated independently:
an HTTP failure with no explicit actual cost is not zero-cost evidence. Retain quota and root-run
budget reservations when billing is unknown; settle explicitly known actual costs once. Only
proven pre-submission transport failure permits zero settlement without reported actual usage.
Restart MUST retain claimed unresolved billing and keep at least the persisted actual-cost amount
admission-visible, even if it exceeds the original estimate.

## 19. Watcher

The watcher receives a feed-set capability rather than arbitrary provider tools. It MUST have one
active-run lease, schedule enforcement, host/path allowlists, per-run request/credit/duration budgets,
reserved queue/provider capacity, a dedicated pool, no emergency-pool access, and immediate denial
for approval-requiring requests. A stock scan MUST derive its workspace, ordered operation targets,
and provider payload from server configuration; MCP MUST NOT supply arbitrary target authority.

The current bounded implementation executes synchronous scrape/map sequences only with the
scripted no-network transport. Completion creates a server-owned pending summary and requires a
separate run-fenced, versioned cursor commit. Live execution, asynchronous crawl, crash redispatch or
step resume, and daemon-owned periodic triggering remain future extensions rather than implicit
behavior.

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

Migrations 16–19 MUST append to the checksum-verified history without rewriting earlier migrations.
Version 16 adds the irreversible invocation submission ceiling; version 17 adds request-bound
observation intents; version 18 adds durable controlled-session request bindings and cancellation
tombstones; version 19 adds bounded lifecycle diagnostics. Each migration MUST advance the schema
version only within its successful transaction and preserve prior authority on rollback.

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

Migration 14 MUST append only the indexes required by the bounded retention queries without
changing migrations 1–13. Migration 15 MUST append one reconciliation schedule row per quota scope
without changing migrations 1–14. That row MUST retain separate QUICK/FULL baseline snapshots and
last-checked times, one generation, and an exact last-reconciliation pointer. Database authority
MUST require each pointer to name the same scope and every update to advance its generation exactly
once. A newly created scope MUST start without fabricated history; its first persisted snapshot
initializes both baselines. A populated upgrade MAY resume from a valid current snapshot recorded by
the latest durable reconciliation or an actual retained scope snapshot, but MUST NOT synthesize a
provider observation or rewrite an earlier result.

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

Before reporting `READY`, and at each configured maintenance interval, the stock daemon MUST use a
worker-owned compatible connection to apply one bounded retention batch, commit, request a `PASSIVE`
WAL checkpoint, and observe the total regular-file footprint of exactly the main database, WAL,
shared-memory, and rollback-journal paths without following links. Each observation MUST use at most
four stat calls. A trusted result from exactly 90% to below the cap MUST maintain one preserved HIGH
retention-pressure alert. Pressure MUST request one bounded `TRUNCATE` checkpoint and a fresh
complete observation. A result below 90% MUST resolve the singleton alert. A result at/above the cap
MUST preserve critical pressure evidence and fail the required task closed. Observation or alert-
persistence failure MUST also fail closed without exposing a path or byte count.

The existing feedback-admission guard MUST continue to reject a projected low-priority feedback
write when its logical record bytes would exceed the same observed cap or measurement is
untrustworthy. It MUST NOT shed mandatory audit, quarantine, cancellation, reconciliation, or
cleanup writes. Neither sampled observation is a hard race-free filesystem quota; mandatory writes
and SQLite page/WAL allocation MAY grow the files between samples.

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

The stock daemon MUST supervise scheduled QUICK and FULL reconciliation as a required provider-I/O-
free task. It MUST read only persisted snapshots and ledger state through a worker-owned compatible
connection. Each batch MUST stop admitting new scope work when either
`maximum_scopes_per_batch` or `maximum_batch_duration` is reached, and cancellation MUST join any
non-preemptible bounded database worker. `maximum_snapshot_age` MUST classify a future-dated or old
current snapshot as `STALE`; it MUST NOT refresh evidence. `absolute_credit_tolerance` MUST remain a
strict non-Boolean nonnegative signed-INT64 integer.

QUICK and FULL MUST retain separate durable baselines and last-checked times. FULL MUST advance both
cadences at the same current observation; QUICK MUST NOT advance FULL, and MANUAL comparison MUST
advance neither. A scope transaction MUST atomically select the due mode, validate its baseline and
last-result authority, compute the exact decision and ledger window, persist the result and any
alert/quarantine, suppress consecutive-mismatch progression for an already-processed current
snapshot, and generation-fence baseline advancement. A first real observation MUST establish a
baseline rather than invent a prior counter. `UNKNOWN`, `STALE`, and reset decisions are valid
durable outcomes. Corrupt authority, persistence failure, or unexpected task exit MUST propagate to
stock lifecycle supervision and `FAILED_CLOSED`.

## 23. Recovery

CLI `daemon start` MUST require an exact configuration-bundle digest match in each successful
decoded installation-capability control-status response before accepting readiness or waiting on
`RECOVERING`. This applies to both existing responders and owned children. The daemon MUST freeze
that value from its verified capture before mutable composition; explicit snapshot-less in-memory
composition MUST report null. Missing, null, malformed or mismatched digest fields MUST fail
without transport-unavailable fallback, and cleanup MUST remain confined to an owned child.
This comparison MUST NOT be described as process identity, watchdog attestation or a fence for
subsequent control mutations.

Each control mutation MUST use its distinct `/v2/control` route and require exactly
one `x-gatehouse-expected-config-digest` header matching the daemon's frozen configuration digest.
The value MUST be an exact 64-character lowercase hexadecimal string; missing/null server
attestation, missing/duplicate/malformed headers and mismatch MUST refuse before body ingestion or
service effects. Capability authentication MUST precede digest validation. Legacy v1 mutation paths
MUST NOT dispatch effects, and the CLI MUST NOT fall back to them. GET v1 control status remains
separate and does not require an expected-digest header.

Control mutation admission MUST retain the existing request byte and total/inter-chunk time bounds.
The deferred middleware path MUST bind its exact receive callback to the request scope; the control
route MUST reject a missing or replaced callback before reading. Body-bound exceptions MUST retain
their existing HTTP classification outside the typed body parser. Bodyless mutation routes MUST
reject nonempty or disconnected bodies before effects. Session creation retains its strict typed
schema. `/v2/control/session-requests/cancel` MUST accept a strict request-ID body under the same
capability, digest and deferred-ingestion bounds. Creation MUST atomically bind a client-retained
request ID and validated launch-authority digest to its session, without persisting or reissuing
the raw bootstrap capability. Cancellation MUST commit a tombstone before revoking a bound session;
acknowledgement MUST require confirmed revocation. Bounded request bindings MUST survive restart
and MUST NOT be discarded to permit replay. Owned cleanup MUST use its original captured settings,
capability and digest, preserving
pending authority after refusal rather than rebinding or retrying automatically. These requirements
do not establish process identity or bind later admin-cookie/agent requests or watchdog probes.

The watchdog MUST derive its admin endpoint from the same verified configuration as its expected
digest. It MUST obtain readiness through capability-authenticated control status, require exact
digest agreement and coherent typed status, and preserve actual agent/control HTTP status evidence.
Both listeners MUST return HTTP 200 before agreement is accepted; public readiness is not the
attestation channel. The control response MUST be identity-encoded JSON, bounded to 64 KiB and
validated without duplicate keys, nonfinite numbers, coercion or state/digest normalization.
One asynchronous deadline MUST cover both probe requests and asynchronous client closure.

Probe agreement MUST default to unverified. Received responses MUST remain live evidence across
subsequent failures. Only explicit connection failures on both configured listeners before any
response may classify absence and permit a leased restart. Capability, timeout, parse, stream or
closure failures MUST NOT imply absence. Mismatch, unverified and live-degraded outcomes MUST be
nonzero and MUST NOT restart an unowned responder. Successful providers-disabled outcome requires
matched DEGRADED_NO_PROVIDER/ready=false and both provider channels configured disabled. Controller
and owned-restart admission MUST independently enforce these conditions, including for injected
probe results. Unsuccessful owned startup retains bounded cleanup of only its owned child.
Synchronous protected-capability reads and noncooperative native code are outside the asynchronous
deadline guarantee; authenticated digest agreement still does not establish server/process identity.

Windows mutable-state entrypoints MUST admit only exact fixed-drive and NTFS facts before ACL
backend construction, metadata traversal or creation. Missing, malformed or coerced volume facts
MUST fail closed. Native drive classification MUST precede filesystem querying, so non-fixed
drives do not receive a filesystem query. Only function bindings may be cached; volume facts MUST
be fresh. An explicit injected probe MUST propagate through nested database-state operations.

State-kind checking MUST require valid mode, Windows file attributes and positive link-count
metadata without permissive defaults. Reparse/symlink objects and multiply linked regular files
remain forbidden. Native creation and permission changes MUST retain ancestor/target identity and
admit trusted owner/DACL authority before effects. OWNER RIGHTS MAY be interpreted only through
that same descriptor's verified owner; owner drift MUST refuse. Private targets MUST retain the
exact execution-user owner and supported protected DACL. ACL changes MUST use the retained target
handle and validate the complete bounded descriptor afterward, without rewriting descendant ACLs.

Lifecycle diagnostics MUST retain at most 256 fixed records of sequence, run ID, UTC time and phase.
Admin reads MUST authenticate and enforce a 1–256 limit, default 100. Exception text, secrets,
configuration paths and provider payloads MUST be excluded. Failed diagnostic writes MAY be lost;
an unusable connection MUST fence admission and durable writes. Shutdown MUST preserve primary
control interruption, attempt independent resource cleanup and retain database/OS ownership while
owned work or cleanup remains unfinished. Explicit retries MUST resume only unfinished phases.
A diagnostic finalization record MUST NOT certify database closure or process exit.

On startup, Gatehouse remains `RECOVERING` while it validates the database, migration checksums, and
semantic job authority; loads policy and KeyStore metadata; expires stale approvals and sessions;
converts active sessions to disconnected; classifies interrupted attempts; reconstructs valid
asynchronous handoff checkpoints; re-adopts jobs; retains unresolved reservations; and restores
watcher lease state. It MUST run one complete bounded due-job supervisor pass before reporting
`READY` or an operational degraded state. It MUST first complete the bounded
retention/checkpoint/footprint batch defined above; an unavailable or at-cap observation MUST NOT
reach readiness. It MUST also complete one bounded scheduled-reconciliation batch before readiness;
remaining due scopes MAY continue through the required periodic task.

Startup MUST retain durable scope states and state-event generations, repair observation schedules
to the current healthy workload generation without silently enabling them, and recover incomplete
account mutations without provider I/O. `EXHAUSTED`, `DISABLED`, and `QUARANTINED` exclusions MUST
survive restart. If the separately authorized observer loop is configured, it begins only after
startup recovery and remains a required bounded runtime task.

Scheduled QUICK/FULL reconciliation MUST remain a required runtime task whether or not the provider
observer is enabled. It MUST NOT infer network authority from its cadence. Shutdown MUST stop
admitting new comparison batches and join the bounded active worker; an unexpected exit or
persistence failure MUST follow the same `FAILED_CLOSED` supervision as maintenance.

Startup MUST also recover every active runaway burst permit as an `ORPHANED` unknown-cost permit,
retain its request and reserved-credit consumption, release durable active concurrency, close the
authorization generation, and require a fresh dashboard decision. Open/denied/exhausted durable
offender quarantines MUST NOT be timer-healed. Every unrecovered state, including authorized and
expired generations, MUST continue fencing fresh same-client session/root admission across restart.

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
- migration 13 append-only compatibility, checksum freeze through v12, exact-generation authority,
  immutability, rollback, capacity-index, restart, stale-evidence, and multi-quarantine tests pass;
- migration 14 retention-index compatibility and migration 15 append-only compatibility, checksum
  freeze through v14, populated-upgrade, rollback, scope-pointer, baseline, generation, and new-scope
  initialization tests pass;
- clean-install account onboarding, idempotency, rotation, disable/recover/tombstone, and redacted
  status tests pass;
- account onboarding requires a valid declared provider team identity, rejects duplicate declared
  teams as independent balances, never serializes raw identity/fingerprint, and keeps rotation on
  the original scope;
- durable exhaustion, fresh-positive recovery, stale/unknown exclusion, bounded explicit
  pre-dispatch fallback, and capacity share-then-spill concurrency tests pass;
- one total durable workload submission across all response classes, claim replay/restart
  rejection, unknown-cost holds, known-cost settlement, and candidate-overflow tests pass;
- equivalent and aggregate offender-scoped quarantine, bounded dashboard burst, same-client fresh-
  run fence, safe dashboard recovery, active-permit/unknown/affinity rejection, restart recovery, and
  unrelated-client isolation tests pass;
- explicit workspace allowlist, canonical directory containment/link escape, legacy fail-closed,
  and separate-client shared-workspace attribution tests pass;
- approval retry binding, cancellation-safe MCP continuation, process-random HMAC index, and
  crawl-pending restart rehydration tests pass;
- default-off manual/scheduled observation and bounded collector tests pass with mock/no-network
  transports;
- scripted no-network availability is backed by one deterministic restart-stable snapshot;
- exact reconciliation detects fractional changes and plan changes hidden by projection ties;
- scheduled reconciliation proves separate QUICK/FULL cadence baselines, first-observation
  initialization, same-observation mismatch deduplication, bounded scope/time work, no provider I/O,
  atomic incident advancement, joined cancellation, and required-task fail-closed behavior;
- startup/periodic footprint tests prove fixed sidecar/stat bounds, exact 90% pressure alerting,
  truncating-checkpoint remeasurement, cap/unavailable/persistence failure, feedback-guard
  preservation, and the documented non-quota limitation;
- ambiguous side effects are not blindly retried;
- sessions re-adopt after restart;
- asynchronous jobs preserve principal affinity;
- asynchronous jobs preserve exact session/workspace/root ownership and resume settlement once;
- concurrent administrative approval decisions have exactly one winner;
- off-ledger usage simulation quarantines the credential;
- a clean wheel installation runs the stock daemon, CLI, MCP, notifier, and watchdog entry points
  through a scripted no-network process and restart test;
- public documentation matches passing tests.
