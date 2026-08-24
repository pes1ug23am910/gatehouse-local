# Failure Modes

## Daemon unavailable

Return `provider_unavailable` or `daemon_degraded` with a retry hint. Do not fall back to ambient credentials. The watchdog performs bounded restart and the client re-adopts its session.

The on-demand MCP shim does not start an alternate credential broker or read a project `.env` when
the central daemon is absent. User-logon registration may keep the daemon available, but failure to
start it remains a local availability failure, not authority to bypass Gatehouse.

## Database busy

Use bounded busy retry. Never wait indefinitely or make a network call inside an open transaction. Enter degraded mode if critical state cannot commit.

## Policy load failure

Fail closed for provider operations. Keep local diagnostics and status available where safe.

## Credential decryption failure

Mark the credential unavailable without exposing ciphertext or platform error details. Try another
eligible persistent credential only when the configured pool and policy permit. An explicitly
emergency dispatch never falls back to persistent custody, and a persistent dispatch never opens
the emergency store.

## Administrative credential validation failure

Disabled or scripted provider mode, network disablement, stale generation, ineligible custody,
lease contention, malformed counters, provider rejection, timeout, and persistence failure all fail
closed with a sanitized error. Validation performs no pool selection, credential fallback, retry,
or emergency-store access. A service-level deadline bounds the whole transport dispatch so the
durable generation lease cannot expire while a trickling response remains in flight. A successful
provider response is not reported as authenticated unless its sanitized counter snapshot and audit
event commit atomically; a release failure is surfaced for operator review rather than silently
hidden.

Provider rejection, timeout, transport failure, and malformed counters after live transport invocation record
`credential.provider_validation_failed`. Its exact payload allowlist is `actor_id`, local
`credential_id`, `credential_generation`, stable `error_class`, and `outcome: failed`. It excludes provider
bodies, headers, reason text, request identifiers, retry-after values, and exception data. Disabled
or scripted mode, network disablement, stale generation, ineligible custody, lease contention, and
other service-local failures before transport invocation record no such event; cancellation also
records none. The event does not prove HTTP submission or provider receipt. If the audit write
fails, return a generic persistence or daemon-degraded error and do not disclose the original
provider detail. When it succeeds, the existing sanitized provider-failure API response is unchanged
and contains no audit-event identifier. Success snapshot-and-audit atomicity is unaffected.

For an HTTP 200 credit-status body, invalid JSON syntax, duplicate object keys, non-standard
constants, overlong or out-of-envelope numbers, missing or null remaining credit, explicit-null
plan credit, non-numeric counters, malformed canonical observations, paired-nullability violations,
or projection mismatch all become `MALFORMED_RESPONSE`. Decode exceptions are stripped of numeric
token-bearing traceback and context. Exactly one failure audit is written after transport invocation
and no success snapshot is written. Bodies from every non-200 credit-status response are discarded
without decoding after transport security and size checks. A 401, 429, or 5xx therefore retains its
ordinary status classification even when its body is malformed or contains an oversized integer;
every unexpected 2xx is a non-retryable `MALFORMED_RESPONSE`.

## Credential custody creation interrupted

Provision and rotation persist an exact non-secret staging alias before entering DPAPI custody.
DPAPI publishes the matching intent marker before ciphertext and metadata. On restart,
`discard_staged` treats completely absent material as clean and may remove only the marker and
token-derived staging or partial files proven to belong to that journal alias. A malformed or
mismatched marker, a different staging token, or an unrelated temporary-file collision is not
deleted; the mutation remains `CLEANUP_REQUIRED` and the candidate is not admitted.

## Duplicate or inconsistent Firecrawl team declaration

Account add requires one stable non-secret `provider_team_id`. HMAC it immediately with the
installation key and perform the provider/`TEAM` fingerprint uniqueness check in the same final
transaction that creates the quota scope. If the fingerprint is already reserved to any existing or
tombstoned scope, reject onboarding before a second balance becomes routable. Do not return the raw
ID or fingerprint in the error, mutation result, status, or audit. Rotation has no identity selector
and remains bound to the existing scope.

Firecrawl credit observations are team-scoped but contain no attested team identifier. Gatehouse
therefore cannot detect an operator deliberately using different declared IDs for two keys that
actually share one real team. Treat this as a configuration-integrity failure requiring operator
correction and reconciliation; an authenticated positive balance does not prove independent quota.

## Exhausted quota

For a definitive non-emergency Firecrawl 402, update the terminal attempt and append the
generation-fenced quota-scope transition to durable `EXHAUSTED` in the same transaction. Include the
request, actual attempt, scope, credential generation, source, reason, and time. If that authority is
missing or conflicts, roll back the terminal checkpoint and fail closed; do not dispatch a backup
before the transition commits.

After the commit, stop new positive-cost ordinary reservations selecting that scope and traverse
later eligible **distinct quota scopes** from the request's immutable named-pool plan in deterministic
order. Every eligible member may be considered even when the pool contains more than three scopes,
but each scope is visited at most once. The same-credential transient retry cap is independent.
Traversal never leaves the named same-provider pool and never considers emergency custody.

A newer authenticated zero or negative exact remaining observation also makes the scope durably
`EXHAUSTED` and projects to zero. Exhaustion survives later requests, daemon restart, and timer or
in-memory-breaker expiry. Only a newer authenticated positive head observation or explicit audited
operator recovery may transition the stored state to `HEALTHY`; positive-cost routing still requires
fresh valid capacity afterward. A stale positive observation never recovers the scope.

These transitions do not release active, pending, disputed, replacement, or handed-off authority.
Eligible zero-cost exact-affinity status, reconciliation, and cancellation cleanup remains available.

## Quota-scope capacity saturation

`fill_first` shares the deterministic leading eligible quota scope among concurrent sessions. When
that scope is saturated before provider handoff, settle the unused reservation and try the next
eligible distinct scope from the same immutable plan. This is bounded capacity admission, not sticky
per-session/LLM assignment and not load spreading. If every eligible scope is temporarily full,
queue against the deterministic leader under the normal request deadline; never escape the pool,
provider, or emergency boundary.

## Durable balance authority or migration corruption

A known balance whose snapshot ID, scope, unit, capture time, projected value, canonical
observation, or recomputed projection disagrees is unknown and ineligible. Catalog, repository, and
atomic reservation reads fail closed without repair. Malformed durable decimal text is never
normalized silently.

Migration 9 validates relevant v8 integer rows, exact legacy tolerance sources, and every anchored
balance before backfill. Any failure rolls the entire migration back with schema/user version 8 and
no migration-9 row, column, or trigger. Unanchored legacy caches are intentionally cleared; they are
not converted into fabricated provider observations. A scripted synthetic snapshot collision also
rolls its immediate synchronization transaction back.

Migration 11 is append-only over versions 1–10 and creates no grant during backfill. Owner or
authority trigger failure, malformed quarantine/grant shape, or a checksum mismatch fails migration
closed. Do not delete or rewrite pre-v11 evidence, quarantine generations, or permit settlement to
force recovery.

Migration 12 adds only immutable provider/quota-scope identity reservations. It never persists a raw
provider team ID or fabricates identity for legacy scopes. Fingerprint shape, duplicate provider/
kind/fingerprint, multiple identities for one scope, checksum mismatch, or attempted owner mutation
fails closed without rewriting versions 1–11. Tombstoned reservations remain authoritative.

## Permission failure

An HTTP 403 or classified permission denial is terminal for automatic routing. Fail the attempt and
do not try another credential, account, pool, emergency authority, or provider. Permission failures
may indicate a target, scope, or plan mismatch rather than account capacity.

## Unauthorized credential

For HTTP 401, Gatehouse may try a later eligible credential only when it belongs to the **same quota
scope**. This supports generation or key replacement without treating credentials sharing one team
balance as separate capacity. Once 401 selects this no-spray path, later lease contention or another
credential failure cannot cross to a distinct account. If no same-scope credential is eligible,
fail the attempt.

## Rate limit

For a retry-safe Firecrawl operation, honor a valid provider retry hint on the same credential while
the same-credential attempt count and request deadline can still succeed. If guidance is absent,
those attempts are exhausted, or the required wait would consume the remaining deadline, treat the
current route as otherwise failing and select the next eligible distinct quota scope from the same
immutable named-pool plan. Continue in deterministic order through every later eligible scope, each
at most once. If there is no later scope, return `provider_rate_limited`.

Do not use this spill for a reconcile-first/side-effecting operation or whenever submission may have
occurred. Such an ambiguous attempt becomes `UNKNOWN`; a known safe but ineligible operation fails on
the current account. Never cross the pool/provider boundary or inspect emergency custody. An
expired queue entry still returns a retryable capacity error.

## Controlled launch outside workspace

Reject a missing client/workspace allow binding, a legacy client profile with no
`workspaces.allow`, a relative/missing/non-directory working path, or a resolved directory outside
the configured canonical workspace. Resolve links before containment comparison and pin the exact
validated directory for the child. Do not infer authority from project instruction files, the
process name, or a prompt assertion.

## Connection loss before submission

Retry only when transport evidence shows the provider did not receive the request.

## Connection loss after submission

The outcome may be ambiguous. Mark `UNKNOWN`, preserve the reservation and exact dispatch/resource
authority, and reconcile. Do not replay automatically and do not move the operation to another
credential, quota scope, named pool, emergency unlock, or provider. A timer, restart, or available
capacity elsewhere does not turn an unknown side effect into a safe retry.

## Active-secret reflection

If a secret-bearing lifecycle value would overlap a serialized identifier, journal, result, audit,
custody reference, filename, marker, or metadata value, abort or roll back through exact-owned
cleanup. Do not persist the overlap or include it in an error graph.

Provider transport rejects `Set-Cookie` and any exact leased credential found in response header
names, header values, or the bounded response bytes before decoding. It returns no response data,
clears provider cookies, and scrubs retained HTTP request/response handles; retry and `UNKNOWN`
handling still follow the operation's existing handoff evidence. The admin CLI likewise rejects
`Set-Cookie` or an exact active-secret reflection on a binary mutation response, clears the whole
session cookie jar before best-effort logout, scrubs request/body handles, and reports only the
generic mutation failure. The same mutation identifier may be used only through its normal
idempotent recovery path.

## Asynchronous job creation response lost

If Gatehouse received a successful typed response, the terminal attempt checkpoints the provider
resource and exact routing authority before affinity binding. Startup validates that checkpoint,
reconstructs the owner-bound affinity, and materializes the job. A caller that supplied a stable
crawl-start `request_id` may retry the same request and receive that same job.

If no complete checkpoint exists, Gatehouse does not guess a provider resource or replay the crawl
start. It preserves an ambiguous submitted outcome as `UNKNOWN` for reconciliation. Partial,
contradictory, or conflicting checkpoints fail startup closed.

## Runaway request burst

Equivalent repetition, varied aggregate traffic, or bounded detector capacity can open one durable
quarantine for the exact session/root-run/service offender. Return `runaway_suspected` with only the
allowlisted quarantine projection and fixed numeric-loopback dashboard URL. Do not block another
session/root run, try another account merely to evade detection, or treat prompt text as human
authority.

The authenticated local dashboard may deny the burst or authorize a typed-operation allowlist with
explicit time, request, credit, and concurrency ceilings. A stale generation/action token loses the
decision race and cannot overwrite the winner. Each admitted request owns one durable permit and
atomically consumes its estimate. Known overrun consumes additional remaining credits; unknown cost
exhausts the grant. Duration/request/credit exhaustion remains blocked, and no detector cooldown
heals the quarantine.

If the daemon stops with an active permit, restart marks it orphaned with unknown cost, retains its
request/credit consumption, releases the durable concurrency count, expires the authorization, and
requires a fresh dashboard decision. Do not resume the old grant or replay its operation merely
because the process returned.

## Client disconnect

Queued work may be cancelled by policy. Short work may continue or cancel based on operation class. Asynchronous jobs remain tracked. The session becomes disconnected after heartbeat expiry.

Cancellation of one coalesced participant detaches only that participant. Shared execution remains
owned by the remaining participants; the last participant cancellation triggers conservative
execution cleanup. Cancellation after provider handoff retains quota and budget for reconciliation.

## Daemon restart

Access tokens become invalid. The bootstrap capability may re-adopt a valid session. The daemon
stays `RECOVERING` while active attempts are classified, asynchronous handoff checkpoints and jobs
are re-adopted, `SETTLING` usage is resumed without provider I/O, and unresolved reservations are
preserved. It does not advertise `READY` before one complete due-job supervisor pass.

Durable `EXHAUSTED`, `UNKNOWN`, `DISABLED`, `QUARANTINED`, and `COOLDOWN` quota-scope states are read
from SQLite during routing reconstruction. Restart does not replace them with a healthy in-memory
breaker or heal them because wall-clock time passed. Ordinary positive-cost work remains closed
until the documented state and fresh-authority recovery conditions are satisfied.

Durable runaway quarantines also survive restart. Active burst permits become conservative orphans
and close their grant before readiness. This is independent from any process-local detector timer.

## Watcher overlap

At component level, the second run returns a successful no-op and does not queue. The stock watcher
execution facade is not yet wired end to end.

## Approval expiry

Expired approval becomes denial and cannot be consumed later.

Concurrent approve and deny actions use a `PENDING` compare-and-set. Exactly one action commits;
later contenders observe a non-pending state and cannot replace the winner.

An MCP restart may discard only its bounded process-local continuation index, not the durable
approval. An exact retry revalidates the full binding and can consume the winner once. A pending
crawl must reuse the returned stable `request_id`; Gatehouse rehydrates the original
`WAITING_APPROVAL` projection without executing that parent invocation, but only under the same
re-adopted durable session/client/workspace/root run. A different or newly launched session,
request ID,
root run, workspace, client, fingerprint, pool, cost/unit, or expired session fails closed.

An otherwise valid fresh crawl `request_id` with no durable parent is not a conflict. It proceeds
normally under `ALLOW`, or creates a fresh pending row under `ASK`; only an existing ambiguous or
mismatched handle is a rehydration failure.

## Emergency unlock restart

All usable emergency state is process-local. Cancel, timer expiry, and clean shutdown immediately
close admission, close any lease, and zero/remove the in-memory secret. After an unclean restart,
startup marks formerly active redacted authority `RELOCKED`; it cannot reconstruct a credential
from SQLite. Existing exact attempts may record a terminal settlement after relock, but no new or
nonterminal admission is accepted.

## Retention pressure

Bounded deletion and WAL-checkpoint primitives are implemented, but the stock daemon does not yet
schedule retention or emit a retention-pressure event. The future pressure handler must purge
expired debug data and then expired detailed metadata in bounded batches, retain unexpired daily
aggregates, checkpoint WAL, and emit the event.

## Reconciliation mismatch

When the implemented engine and durable store are invoked with provider snapshots, a repeated
significant unexplained delta on an exclusive credential produces local quarantine and a
high-severity incident. Explicit admin-only counter capture and a separately gated, default-disabled
bounded Firecrawl observation loop exist; automated quick/full reconciliation remains pending.

The engine compares exact canonical remaining observations and exact plan totals, not only integer
projections. A remaining increase is `RESET_DETECTED`; an exact within-period plan change is
`UNKNOWN`/`HOLD_ROUTING`, including when projections tie. Determinate fractional results retain
canonical provider and unexplained deltas, while each legacy signed-INT64 field is populated only
when its own value is integral and in range. Indeterminate/reset/plan-change results clear both
exact and compatibility deltas. Allowed tolerance is always retained as an integral canonical
string even above INT64.
