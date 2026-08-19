# Debugging and Incident Notes

This file is for durable, sanitized debugging knowledge. Runtime logs remain structured in the database; temporary machine-specific artifacts belong under `.local/`.

## Safety rules

Never place provider credentials, access or bootstrap tokens, authorization headers, raw request or response bodies, private documents, database copies containing encrypted secrets, or revealing screenshots in this file. Use internal aliases and opaque identifiers.

## Investigation workflow

1. Reproduce with the mock provider whenever possible.
2. Record the request state, attempt state, and error class.
3. Identify whether the issue is policy, scheduling, quota, transport, provider, persistence, or recovery.
4. Determine whether the provider outcome is known or ambiguous.
5. Preserve metadata before retrying an ambiguous side effect.
6. Add a failing test.
7. Implement the smallest fix.
8. Run focused, regression, concurrency, and secret-canary tests as applicable.
9. Update this file and `CHANGELOG.md` when appropriate.

## Open issues

_No open issues recorded._

## Resolved issues

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
