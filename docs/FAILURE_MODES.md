# Failure Modes

## Daemon unavailable

Return `provider_unavailable` or `daemon_degraded` with a retry hint. Do not fall back to ambient credentials. The watchdog performs bounded restart and the client re-adopts its session.

The on-demand MCP shim does not start an alternate credential broker or read a project `.env` when
the central daemon is absent. User-logon registration may keep the daemon available, but failure to
start it remains a local availability failure, not authority to bypass Gatehouse.

## Background task failure or incomplete shutdown

Job-supervisor and credit-observer batches retain ownership of every selected child. A child fault
or cancellation cancels its siblings and waits for their cleanup within a bounded interval.
Overlapping batches are refused. If a child resists cancellation past the deadline, new batch
admission remains closed and the drain failure exposes the remaining ownership. Durable claims are
not released or replayed merely because the caller failed.

The daemon tracks startup, periodic loops and final passes through teardown. It reserves part of
the shutdown interval for cancellation and joining. Resource closure drains those callers and their
batch children before closing transports, SQLite or the installation lease. Unresolved work or a
failed asynchronous resource close retains the remaining resources and prevents a clean `STOPPED`
checkpoint. A later close attempt can finish only after the owned work has actually ended.

Listener shutdown is cooperative: the wrapper requests exit and stays owned until both listener
tasks finish. It does not cancel those tasks because cancellation can interrupt the server library
before its connection cleanup. A listener that ignores the exit request keeps the wrapper pending;
composition's drain deadline then retains the shared resources. Fake-listener tests cannot certify
native socket cleanup after partial server startup or a failure inside the server library.

Cleanup records completed phases so a retry skips already-closed resources. Database-close failure
retains the installation lease. A late lease-release or admission-stop failure retains the in-memory
`FAILED_CLOSED` outcome, even if database finalization already recorded a durable clean marker.
That marker certifies drained database finalization; it does not certify atomic completion of
database closure, lease release and admission shutdown.

The serve-drain and resource-close intervals are sequential and can consume up to twice the
configured `drain_timeout_ms`. These are cooperative asyncio bounds. Synchronous event-loop
blocking, a blocked worker thread, Python's final `asyncio.run` cleanup and native process
termination are separate boundaries; this mechanism cannot kill cancellation-resistant work.

## Controlled session preparation or cleanup failure

The local backend records its random creation request ID before dispatch and owns a valid minted
session ID before later response validation, response
closure or launch construction can fail. For session-mint responses only, it defers the underlying
stream close until bounded decoding can record that ID; actual close is attempted once. It retains
the original cleanup endpoint and capability without retaining bootstrap material in the ownership
record. No controlled process is returned after failed preparation.

A known-ID failure permits at most one automatic revoke attempt. An unsuccessful, mismatched,
late or interrupted revoke leaves cleanup pending and blocks further minting. The backend's explicit no-target
`retry_pending_session_cleanup()` retries only that retained provisional session with its original
authority. A returned launch still requires its identical owned handle for cleanup. The reservation
also covers short-lived typed sessions through their final cleanup.

Each cleanup invocation has a fresh deadline of at most one second, pre/post checks and bounded
HTTPX I/O phases. Synchronous transport or close work is not preempted at that wall-clock deadline.
An outcome without a valid session ID after possible dispatch is cleaned up by its original
creation request ID, without guessing a session or retrying creation. The durable request digest
binds at most one session; cancellation also creates a tombstone when it wins before creation.
These records survive daemon restart. The backend's retained endpoint, capability, configuration
digest and plaintext request handle remain process-local: recreating the backend loses those
cleanup inputs, and the durable digest does not reconstruct them.

## Database busy

Use bounded busy retry. Never wait indefinitely or make a network call inside an open transaction. Enter degraded mode if critical state cannot commit.

## Policy load failure

Fail closed for provider operations. Keep local diagnostics and status available where safe.

## Credential decryption failure

Mark the credential unavailable without exposing ciphertext or platform error details. Once the
transport claim is consumed, do not try another credential for that invocation. An explicitly
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
DPAPI publishes the matching intent marker before canonical ciphertext and metadata. On restart,
`discard_staged` treats completely absent material as clean and may remove only the marker and
token-derived staging or partial files proven to belong to that journal alias. A malformed or
mismatched marker, a different staging token, or an unrelated temporary-file collision is not
deleted; the mutation remains `CLEANUP_REQUIRED` and the candidate is not admitted.

The versioned DPAPI envelope binds the immutable credential, principal, quota scope and reference;
mutable metadata checks do not provide rollback protection. In-flight cleanup retains captured
file identities, while a published intent persists blob/metadata identities for restart cleanup.
Before intent publication, token-derived stages have no persisted identity proof. Do not interpret
restart cleanup as universal protection against replacement of every pre-marker stage.

## Observer response or process lost

A retained `SEND_INTENT` commits before the exact fixed credit-status transport call. Reusing its
request cannot submit again. Startup classifies unfinished intents as `UNKNOWN`; scheduled
observation remains blocked for that generation until a new explicitly authorized successful
manual observation records resolution. Neither timer expiry nor daemon restart replays the old
request. Snapshot/audit persistence failure cannot turn an observed response into accepted success.

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

After the commit, stop new positive-cost ordinary reservations selecting that scope and return the
quota failure. The exhausted invocation cannot submit through a backup: its one durable transport
claim has been consumed. Later independently admitted requests may select another eligible scope
inside the bounded same-provider pool. Neither path considers emergency custody automatically.

A newer authenticated zero or negative exact remaining observation also makes the scope durably
`EXHAUSTED` and projects to zero. Exhaustion survives later requests, daemon restart, and timer or
in-memory-breaker expiry. Only a newer authenticated positive head observation or explicit audited
operator recovery may transition the stored state to `HEALTHY`; positive-cost routing still requires
fresh valid capacity afterward. A stale positive observation never recovers the scope.

These transitions do not release active, pending, disputed, replacement, or handed-off authority.
Eligible zero-cost exact-affinity status, reconciliation, and cancellation cleanup remains available.

## Quota-scope capacity saturation

`fill_first` shares the deterministic leading eligible quota scope among concurrent sessions. When
that scope is saturated before provider handoff and pool fallback was explicitly enabled, settle
the unused reservation and try the next
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

Migration 13 adds only immutable exact-generation runaway fresh-run recovery evidence and the
client-capacity lookup index. Malformed ownership, nonterminal session/root authority, an active
permit, checksum drift, or attempted evidence mutation/deletion fails closed without rewriting
versions 1–12. It creates no recovery during backfill.

Migrations 17 and 18 retain observer send intents and controlled-session creation/tombstone
authority with 100,000-record ordinal ceilings. Exhaustion refuses new authority; it does not
delete evidence to make room. Migration 19 bounds lifecycle diagnostics to a 256-record ring
across runs. A journal's failed-write counter is local to that instance and normal ring eviction
does not increase it. Missing or finalizing diagnostics are not proof of clean process exit.

## Permission failure

An HTTP 403 or classified permission denial is terminal for automatic routing. Fail the attempt and
do not try another credential, account, pool, emergency authority, or provider. Permission failures
may indicate a target, scope, or plan mismatch rather than account capacity.

## Unauthorized credential

For HTTP 401, fail the invocation without trying another credential or account. Its durable
submission claim remains consumed. Permission denial, 402, 429, 5xx, and connection failure likewise
cannot authorize a second same-request transport submission.

## Rate limit

Return `provider_rate_limited` and a bounded retry hint. Cooldown still affects later independent
admissions, but the current invocation neither sleeps for a retry nor spills to another credential
or scope. An ambiguous execution becomes `UNKNOWN` and is never replayed automatically.

HTTP status and execution ambiguity do not establish billing. An HTTP failure without explicit
actual usage retains quota and root-run budget for reconciliation. Known actual usage is settled
once; only proven pre-submission connection failure permits zero settlement without reported usage.
Claimed unresolved reservations survive restart, and any larger persisted actual usage raises their
admission-visible hold conservatively.

## Controlled launch outside workspace

Reject a missing client/workspace allow binding, a legacy client profile with no
`workspaces.allow`, a relative/missing/non-directory working path, or a resolved directory outside
the configured canonical workspace. Resolve links before containment comparison and pin the exact
validated directory for the child. Do not infer authority from project instruction files, the
process name, or a prompt assertion.

## Connection loss before submission

Proven connection failure before submission permits zero-cost settlement, but still consumes the
one local transport claim. Do not retry the same invocation, even when it was not received.

The fixed provider hostname is resolved and every answer must be globally routable before
credential custody opens. Gatehouse then connects to one validated literal address while retaining
the configured hostname for HTTP `Host`, TLS SNI, and certificate verification; HTTPX does not
perform a second independent provider-host lookup. A resolution or TLS failure therefore fails at
the provider boundary without weakening hostname authentication. URLs passed to an external
provider for provider-side fetching remain subject to that provider's own DNS resolution and
redirect policy; local connection pinning cannot govern the provider's remote fetcher.

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
clears provider cookies, and scrubs retained HTTP request/response handles. No resend is permitted;
terminal execution classification follows handoff evidence while unknown billing remains held.
The admin CLI likewise rejects
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
client profile, try another account merely to evade detection, or treat prompt text as human
authority. Fresh session/root admission for the same client profile remains blocked by every
unrecovered state, including `AUTHORIZED`; exiting the old shim cannot turn a bounded grant into
ordinary authority.

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

Fresh-run recovery is a separate local-dashboard action. It fails closed if an active permit,
nonterminal/`UNKNOWN` work, usable approval, unreconciled quota/budget record, or nonterminal or
missing asynchronous affinity belongs to the old root. On success one immediate transaction revokes
the old session, closes the root, advances the quarantine generation, and records immutable
recovery evidence. Stale evidence or another unrecovered quarantine for the client remains blocking;
no old burst authority is copied to the new run.

## Client disconnect

Queued work may be cancelled by policy. Short work may continue or cancel based on operation class. Asynchronous jobs remain tracked. The session becomes disconnected after heartbeat expiry.

Cancellation of one coalesced participant detaches only that participant. Shared execution remains
owned by the remaining participants; the last participant cancellation triggers conservative
execution cleanup. Cancellation after provider handoff retains quota and budget for reconciliation.

## Daemon restart

Access tokens become invalid. The bootstrap capability may re-adopt a valid session. The daemon
stays `RECOVERING` while active attempts are classified, asynchronous handoff checkpoints and jobs
are re-adopted, `SETTLING` usage is resumed without provider I/O, and unresolved reservations are
preserved. It does not advertise `READY` before one bounded retention/checkpoint/footprint batch and
one bounded scheduled-reconciliation batch plus one complete due-job supervisor pass.

Durable `EXHAUSTED`, `UNKNOWN`, `DISABLED`, `QUARANTINED`, and `COOLDOWN` quota-scope states are read
from SQLite during routing reconstruction. Restart does not replace them with a healthy in-memory
breaker or heal them because wall-clock time passed. Ordinary positive-cost work remains closed
until the documented state and fresh-authority recovery conditions are satisfied.

Durable runaway quarantines also survive restart. Active burst permits become conservative orphans
and close their grant before readiness. Exact-current-generation recovery evidence also survives;
stale or partial evidence does not release same-client launch admission. This is independent from
any process-local detector timer.

## Watcher overlap

The stock scripted watcher returns a successful no-op with the active run identifier and does not
queue a second scan. A process interruption does not redispatch provider steps or resume from an
ordinal. Its durable lease continues to fence overlap until expiry, and incomplete or uncertain work
cannot perform the explicit cursor commit.

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

Before readiness and at each configured maintenance interval, the stock daemon runs one bounded
retention batch, requests a passive WAL checkpoint outside the deletion transaction, and observes
the main database, WAL, shared-memory, and rollback-journal files with a fixed maximum of four non-
following stat calls per observation. Retention removes only eligible aged data; open, high-severity,
explicitly preserved, and watchdog alerts remain durable.

A trusted total from exactly 90% to below `retention.database_size_cap` opens or maintains one
preserved HIGH `DATABASE_RETENTION_PRESSURE` alert. The alert contains a fixed status band, not the
database path or byte totals. Pressure requests one bounded `TRUNCATE` checkpoint and a fresh full
observation. A result below 90% resolves the singleton. A result still at/above the cap retains
critical pressure evidence and raises a sanitized capacity failure. An unavailable observation or
alert-persistence failure also propagates as a required maintenance failure. During startup this
prevents `READY`; after startup required-task supervision transitions the daemon to `FAILED_CLOSED`.

New feedback remains the one low-priority write class shed earlier by the same configured cap.
Inside its existing `IMMEDIATE` admission transaction, Gatehouse observes the fixed files and adds
the logical candidate-record bytes. Cap projection or untrustworthy measurement returns the ordinary
typed capacity error without path, size, or submitted text. Mandatory audit, quarantine,
cancellation, reconciliation, and cleanup writes are not shed. SQLite file allocation is page/frame
granular and those mandatory writes can occur between samples, so neither control promises a race-
free global disk limit or guaranteed reclamation once storage is exhausted.

## Reconciliation mismatch

The required stock-daemon scheduler runs bounded QUICK/FULL comparison over persisted snapshots
without provider I/O. A repeated significant unexplained delta on an exclusive scope atomically
records the exact result, high-severity incident, local scope/credential quarantine, and durable
mode-baseline advancement. The current snapshot advances the consecutive mismatch count at most
once even when both modes or repeated cycles see it. An initial observation establishes a real
baseline; Gatehouse does not invent a previous provider counter.

Explicit admin-only counter capture and a separately gated, default-disabled bounded Firecrawl
observation loop can supply later live observations only when separately enabled. The comparison
cadence itself neither enables that channel nor turns stale evidence into a fresh observation.
`UNKNOWN`, `STALE`, and reset decisions are recorded domain outcomes. Corrupt schedule authority,
persistence failure, or unexpected scheduler exit is a required-task failure and transitions the
daemon to `FAILED_CLOSED`.

The engine compares exact canonical remaining observations and exact plan totals, not only integer
projections. A remaining increase is `RESET_DETECTED`; an exact within-period plan change is
`UNKNOWN`/`HOLD_ROUTING`, including when projections tie. Determinate fractional results retain
canonical provider and unexplained deltas, while each legacy signed-INT64 field is populated only
when its own value is integral and in range. Indeterminate/reset/plan-change results clear both
exact and compatibility deltas. Allowed tolerance is always retained as an integral canonical
string even above INT64.
