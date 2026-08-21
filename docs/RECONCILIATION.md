# Reconciliation

## Purpose

When supplied with provider-usage snapshots, reconciliation compares them with Gatehouse's local
ledger to identify possible direct provider use, stolen credentials, accounting bugs, and
reservations that were never resolved.

Current implementation status: the reset-aware comparison engine, durable recording, incident, and
local-quarantine components are implemented and tested with supplied snapshots. The stock daemon
does not yet fetch provider counters, invoke internal credit status, or schedule quick/full runs.

## Credential ownership mode

Each credential is marked:

```text
GATEHOUSE_EXCLUSIVE
SHARED_EXTERNAL_USE
```

An unexplained delta on an exclusive credential is a strong compromise or bypass indicator. A shared credential can produce legitimate external usage and requires manual interpretation.

## Schedules

Recommended rollout targets, not current automatic stock-daemon schedules:

```yaml
quick: every 6 hours
full: every 7 days
opportunistic: after 100 requests or 250 estimated credits
on_demand: before and after rotation or incident response
```

## Calculation

```text
provider_delta = provider_usage_end - provider_usage_start
ledger_delta = sum(actual provider usage from Gatehouse attempts)
unexplained_delta = provider_delta - ledger_delta - approved adjustments
```

Use absolute and relative tolerances because provider accounting may be delayed or rounded.

Suggested initial values:

```yaml
absolute_credit_tolerance: 5
relative_tolerance: 0.02
consecutive_mismatches: 2
```

## Reservation reconciliation

Reservations may end in:

```text
RELEASED
RECONCILED
PENDING_RECONCILIATION
EXPIRED_SAFE
DISPUTED
```

A daemon restart does not release a reservation automatically. The system determines whether a provider call occurred and may have been billed.

For an asynchronous terminal observation, the job first enters durable `SETTLING` with its target
state and actual usage. The settlement transaction applies that usage idempotently to the original
quota and root-run budget reservations. Only after both ledgers are reconciled does the job become
terminal; restart resumes the checkpoint without another provider call.

Status, cancellation, and settlement route through the exact persisted resource affinity. This
internal reconciliation path may operate while a quota scope is cooled down, exhausted, or unknown,
but it still requires a healthy non-expired credential under the original principal and never uses
a disabled, quarantined, or retired route.

## Incident flow

Once provider-counter orchestration is wired, the target incident flow for a repeated significant
unexplained delta on an exclusive credential is:

1. create a high-severity alert;
2. quarantine the credential locally;
3. stop new leases from the affected scope;
4. record provider counter snapshots;
5. notify the user;
6. rotate or revoke the provider key;
7. run full reconciliation;
8. restore the pool only after a clean result.

Automatic provider-side revocation is optional and must not require storing a more powerful management credential.

## Failure handling

The component workflow is bounded and does not silently mark provider failure as clean. A future
stock orchestration loop must mark snapshots stale after repeated failures, reduce or stop automatic
routing according to policy, alert the user, and preserve reservations conservatively.
