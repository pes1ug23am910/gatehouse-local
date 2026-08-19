# Failure Modes

## Daemon unavailable

Return `provider_unavailable` or `daemon_degraded` with a retry hint. Do not fall back to ambient credentials. The watchdog performs bounded restart and the client re-adopts its session.

## Database busy

Use bounded busy retry. Never wait indefinitely or make a network call inside an open transaction. Enter degraded mode if critical state cannot commit.

## Policy load failure

Fail closed for provider operations. Keep local diagnostics and status available where safe.

## Credential decryption failure

Mark the credential unavailable without exposing ciphertext or platform error details. Try another eligible credential only when policy permits.

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

This is a requirement for the future operator-facing unlock workflow: all memory-only unlock state
must be lost and the pool must return to locked. The stock administrative surface does not yet expose
an unlock mutation, so the emergency pool currently remains disabled and locked.

## Retention pressure

Bounded deletion and WAL-checkpoint primitives are implemented, but the stock daemon does not yet
schedule retention or emit a retention-pressure event. The future pressure handler must purge
expired debug data and then expired detailed metadata in bounded batches, retain unexpired daily
aggregates, checkpoint WAL, and emit the event.

## Reconciliation mismatch

When the implemented engine and durable store are invoked with provider snapshots, a repeated
significant unexplained delta on an exclusive credential produces local quarantine and a
high-severity incident. Stock provider-counter collection and periodic invocation remain pending.
