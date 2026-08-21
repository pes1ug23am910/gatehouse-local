# Failure Modes

## Daemon unavailable

Return `provider_unavailable` or `daemon_degraded` with a retry hint. Do not fall back to ambient credentials. The watchdog performs bounded restart and the client re-adopts its session.

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

## Credential custody creation interrupted

Provision and rotation persist an exact non-secret staging alias before entering DPAPI custody.
DPAPI publishes the matching intent marker before ciphertext and metadata. On restart,
`discard_staged` treats completely absent material as clean and may remove only the marker and
token-derived staging or partial files proven to belong to that journal alias. A malformed or
mismatched marker, a different staging token, or an unrelated temporary-file collision is not
deleted; the mutation remains `CLEANUP_REQUIRED` and the candidate is not admitted.

## Exhausted quota

Open the quota-scope breaker, stop queued work selecting that scope, and fail over only within the configured pool.

## Permission failure

Fail the attempt and do not try every account automatically. Permission failures may indicate target, scope, or plan mismatch.

## Rate limit

Honor the provider retry hint, open cooldown, and return or queue within the request deadline. Expired queue entries return a retryable capacity error.

## Connection loss before submission

Retry only when transport evidence shows the provider did not receive the request.

## Connection loss after submission

The outcome may be ambiguous. Mark `UNKNOWN`, preserve the reservation, and reconcile before replay.

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

## Watcher overlap

At component level, the second run returns a successful no-op and does not queue. The stock watcher
execution facade is not yet wired end to end.

## Approval expiry

Expired approval becomes denial and cannot be consumed later.

Concurrent approve and deny actions use a `PENDING` compare-and-set. Exactly one action commits;
later contenders observe a non-pending state and cannot replace the winner.

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
high-severity incident. Explicit admin-only counter capture exists; periodic provider-counter
collection and invocation remain pending.
