# Debugging and Incident Notes

This file is for durable, sanitized debugging knowledge. Runtime logs remain structured in the database; temporary machine-specific artifacts belong under `.local/`.

## Safety rules

Never place provider credentials, access or bootstrap tokens, authorization headers, raw request or response bodies, private documents, database copies containing encrypted secrets, or revealing screenshots in this file. Use internal aliases and opaque identifiers.

## Investigation workflow

1. Reproduce with the mock provider whenever possible.
2. Record the request state, attempt state, and error class.
3. Identify whether the issue is policy, scheduling, quota, transport, provider, persistence, or recovery.
4. Determine whether the provider outcome is known or ambiguous.
5. Preserve ambiguous-effect evidence for reconciliation; never replay a consumed submission claim.
6. Add a failing test.
7. Implement the smallest fix.
8. Run focused, regression, concurrency, and secret-canary tests as applicable.
9. Update this file and `CHANGELOG.md` when appropriate.

## Open issues

### Native scheduled-task and runtime ownership

The legacy force-registration and name-only removal bodies have been replaced by fixed refusals.
The internal planner supplies disabled canonical review data with matching config/digest arguments,
but no native adapter exists. Runtime interpreter/launcher/import closure and ownership, complete
environment enforcement, task definition normalization and disabled create-only behavior still
need verification. CLI/watchdog selection now permits only the exact interpreter-adjacent pathname;
its following availability check does not establish native identity or alias resistance. Native task
deletion takes a name; readback followed by deletion cannot establish atomic conditional ownership.
Matching plan hashes or supplied SIDs do not resolve these boundaries. No task activation follows
from source plan validation.

### Workload eligibility and health coverage

Authenticated control status now includes a separate workload projection derived from verified
client/workspace/purpose bindings, profile pools and real operation costs. Each bounded read-only
assessment uses current route, quota and credential facts without reserving capacity or calling a
provider. Empty coverage remains unconfigured; rejected coverage remains unverified. Lifecycle states
outside `READY` and `DEGRADED_NO_PROVIDER` report workload coverage as unavailable.
Public lifecycle health is separate. The watcher's manual reserved route is outside this ordinary
new-work projection, which does not prove joint capacity, future request authorization, provider
reachability or a synchronous wall-clock deadline.

### Continuity beyond configuration-bound control requests

Startup status and each v2 control mutation check configuration agreement separately. Later
admin-cookie and agent API requests still need their own continuity analysis across daemon
replacement; a successful control request does not bind every later request to that process.
Watchdog probing now requires authenticated configuration agreement with explicit failure outcomes.
Digest equality does not establish hostile same-user server identity.
If replacement prevents an owned cleanup request from matching its original digest, cleanup stays
pending; there is no authority to substitute a new digest or report completion.

### Controlled session creation without recoverable identity

The source candidate retains a request ID before dispatch and durably binds it to validated launch
authority and any created session. Authenticated request cancellation commits a tombstone before
revoking a bound session, so an absent creation response no longer prevents targeted cleanup.
Replaying a bound or cancelled request cannot mint another session. The CLI still has no durable
storage of its request ID, capability and original configuration authority; a new backend instance
cannot reconstruct authority it was never given. Losing that client-side record remains unresolved.
No automatic replay or inferred cleanup success is permitted.

## Resolved issues

### GH-DBG-0009 — Long-lived environment capture silently changed ambiguous inputs

Status: Resolved in selected source checks; native runtime ownership unverified  
Detected: 2026-09-13  
Resolved: 2026-09-13  
Component: process environment / CLI / daemon / watchdog

Symptom: Arbitrary objects were string-coerced, case-colliding names overwrote each other, invalid
retained values disappeared and input/output size was unbounded. A native CLI runner also exposed
the same mutable environment dictionary to successive subprocess calls.

Fix: Reject malformed, ambiguous or oversized retained inputs with one fixed typed error, preserve
accepted values exactly and freeze snapshots. Each child receives a fresh dictionary. Explicit
entrypoint handling keeps invalid environments from reaching discovery, configuration or spawning;
the default CLI remains import-safe and refuses before command effects.

Tests: Pure boundary/encoding/coercion cases and fake actual subprocess adapters cover rejection,
snapshot preservation, repeated launch isolation, configuration continuity and safe startup exits.
Native path/import ownership, interpreter-startup effects and task environment enforcement remain
separate. Controlled-client environment handling is unchanged.

### GH-DBG-0008 — Secondary daemon selection could leave the interpreter directory

Status: Resolved in selected source checks; native deployment unverified  
Detected: 2026-09-10  
Resolved: 2026-09-13  
Component: CLI / watchdog / daemon selection

Symptom: PATH fallback and arbitrary executable overrides could select a daemon outside the
active interpreter's directory.

Fix: Derive only the adjacent platform launcher with bounded literal-path validation, require an
explicit override to match it exactly, and check only that path once before spawning. Preserve
configuration handoff, owned-child handling and the existing-responder bypass.

Tests: 38 new pure-selector and fake-consumer cases passed with the 1,159-case selected regression
set. Native runtime ownership, alias resistance, import closure and installed execution remain open.

### GH-DBG-0007 — Mutable-state admission accepted incomplete volume and object facts

Status: Resolved in selected source checks; native deployment unverified  
Detected: 2026-09-10  
Resolved: 2026-09-10  
Component: mutable state / filesystem admission

Symptom: Removable and RAM drives were admitted without a filesystem check, and missing reparse
attributes or link counts received safe-looking defaults. These were insufficient preconditions
for the Windows state policy.

Fix: Require fresh exact typed fixed-NTFS facts before backend setup or filesystem effects; require
complete bounded mode, Windows attributes and positive link-count facts without coercion/defaults.
Preserve reparse and multiply linked regular-file refusal. Native bindings are statically reviewed.

Tests: 86 new in-memory admission cases and 57 screened legacy/fixture cases passed within the
974-case selected successor. The preceding attempt recorded legacy metadata refusals. Static
review identified ancestry traversal beyond permitted scratch metadata; the exact refused target
was not captured. The successor models only exact lexical ancestors
in memory and preserves guarded descendant metadata and later replacement simulations; no guard
exemption or production weakening was added. The later schema-19 candidate adds retained-handle
owner/DACL admission, private creation and identity-bound native ACL mutation. Fresh native cases
exercise stored-descriptor preservation and exact private postconditions; final installed matrix
acceptance remains separate from those synthetic checks.

### GH-DBG-0006 — Watchdog accepted unverified readiness and hid live degradation

Status: Resolved in selected source checks; native deployment unverified  
Detected: 2026-09-10  
Resolved: 2026-09-10  
Component: watchdog / configuration / readiness

Symptom: Public readiness could report healthy without authenticated configuration agreement.
Other live degraded responses produced successful task exits, and later transport failure could
discard earlier response evidence. An injected probe could return coherent status after its
deadline and still be accepted during owned restart.

Fix: Require strict authenticated control status and exact configuration agreement alongside agent
liveness, classify uncertainty explicitly, and permit restart accounting only after two explicit
connection failures. Bound accepted raw JSON and cooperative asynchronous work, retain response
presence across later failures, and recheck the owned-startup deadline before acceptance.

Tests: Synthetic streamed responses, malformed/coercible/oversized status, digest conflict, body
and close failures, external cancellation, fabricated probe facts, disabled-state exit policy,
original handoff authority and late-result owned cleanup. Protected capability/native filesystem
enforcement and confirmed termination after cleanup failure remain outside this result.

### GH-DBG-0005 — Per-credential retries multiplied unaccounted workload submissions

Status: Resolved in source; deployment unverified  
Detected: 2026-09-05  
Resolved: 2026-09-05  
Component: routing / invocation / accounting / recovery  
Severity: high

Symptom: A finite retry allowance per credential could multiply across a pool while quota and
root-run budget were reserved only once. Failure handling could settle an HTTP rejection as free
without explicit billing evidence.

Fix: Support only one durable workload submission per invocation, refuse duplicate claims after
restart, reject ordinary catalog overflow, and require explicit pre-dispatch fallback enablement.
Settle known actual cost independently of execution ambiguity; hold unknown billing and preserve
known-cost overrun floors during recovery. Cancellation observed before transport entry makes no
send even when its durable claim has already committed.

Tests: Focused synthetic coordinator, claim/migration/recovery, routing, transport, and admin/CLI
checks, including cancellation around claim commit, malformed resource identifiers with known
usage, fallback opt-in, and authentication before any pool-mutation body read. No existing runtime
database or installed artifact was exercised by this fix.

### GH-DBG-0001 — Cancellation could strand admission resources

Status: Resolved  
Detected: 2026-08-19  
Resolved: 2026-08-19  
Component: scheduler / quota / provider / persistence  
Severity: high

Symptom: Cancellation or a post-response exception could leave queue entries, permits, quota,
budgets, credential leases, single-flight participants, or half-open breaker probes active.

Root cause: Cleanup was distributed across success and error branches instead of following exact
resource ownership, and the provider handoff boundary did not distinguish known-not-submitted from
possibly-submitted failures.

Fix: Added exact ticket and breaker permits, group-owned single-flight execution, a centralized
coordinator finalizer, dispatch-time quota revalidation, and conservative outcome classification.

Tests: Scheduler race tests plus coordinator cancellation/fault injection at queue, persistence,
provider send, classification, and post-response settlement boundaries.

### GH-DBG-0002 — Resource identifiers were not owner-fenced or restart-persistent

Status: Resolved  
Detected: 2026-08-19  
Resolved: 2026-08-19  
Component: policy / routing / persistence  
Severity: high

Symptom: A session sharing a pool could reference another session's guessed provider job identifier,
and all bindings disappeared on daemon restart.

Root cause: The only affinity adapter was in-memory and lookup verified existence without the
creating session, workspace, and root-run authority.

Fix: Added owner-scoped lookups, durable immutable binding with normalized creation-graph checks,
and a migration that quarantines unverifiable legacy rows.

Tests: File-database reopen, authority conflict, stale credential generation, legacy quarantine,
and cross-session pre-admission denial.

### GH-DBG-0003 — Settled quota usage disappeared from later admission math

Status: Resolved  
Detected: 2026-08-19  
Resolved: 2026-08-19  
Component: quota / reconciliation / persistence  
Severity: high

Symptom: Sequential successful calls could reserve repeatedly against the same provider balance
after each reservation moved from `ACTIVE` to `RECONCILED`.

Root cause: Admission subtracted held estimates but not reconciled actual usage, while settlement
did not advance an effective balance.

Fix: Admission now charges settled actual usage newer than a durable provider-balance watermark.
Authoritative remaining snapshots advance that watermark; stale and used-only snapshots do not.
Settlement is idempotent and pending reservations can be resolved through the manager.

Tests: Restart persistence, exact/over/under-estimate settlement, replay, authoritative snapshot,
stale snapshot, and used-only snapshot regressions.

### GH-DBG-0004 — Persisted admission order and recovery contradicted resource ownership

Status: Resolved  
Detected: 2026-08-19  
Resolved: 2026-08-19  
Component: invocation / quota / persistence / recovery  
Severity: critical

Symptom: Durable history showed queueing before quota despite reserve-first acquisition, expired
replacement used two transactions, and an expired queue row could relabel ambiguous running work as
`CAPACITY_EXCEEDED` after restart.

Root cause: The state graph encoded a documentation order rather than operational checkpoints, and
recovery applied queue expiry to every nonterminal invocation before classifying provider handoff.

Fix: Canonicalized reserve-first states, added atomic replacement and a final pre-handoff expiry
fence, and split restart handling into known-unused pre-dispatch failure versus ambiguous running
`UNKNOWN` outcomes.

Tests: Exact success/exhaustion histories, replacement rollback and concurrency, expiry during
durable `RUNNING` persistence, and crash checkpoints from deduplication through running.

## Issue template

```text
### GH-DBG-0001 — Title

Status: Open | Resolved
Detected: YYYY-MM-DD
Resolved: —
Component: scheduler | policy | quota | provider | persistence | recovery | dashboard
Severity: low | medium | high | critical

Symptom:
Sanitized description.

Reproduction:
1. Step.
2. Step.

Expected:
Expected state transition or result.

Observed:
Observed state transition or result.

Root cause:
Technical explanation.

Fix:
Implementation summary.

Tests:
- Test name or path.
```
