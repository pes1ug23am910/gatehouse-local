# Reconciliation

## Purpose

When supplied with provider-usage snapshots, reconciliation compares them with Gatehouse's local
ledger to identify possible direct provider use, stolen credentials, accounting bugs, and
reservations that were never resolved.

Current implementation status: the reset-aware comparison engine, durable recording, incident, and
local-quarantine components are implemented and tested with supplied snapshots. An authenticated
admin can explicitly invoke one exact-generation credit-status read in live mode and atomically
record its sanitized counters and audit event. The stock daemon does not collect counters
periodically or schedule quick/full runs.

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
provider_delta = previous.observed_remaining - current.observed_remaining
expected_low = settled_ledger_units + manual_adjustment_units
expected_high = expected_low + pending_reserved_units
unexplained_delta = provider_delta - the applicable expected bound
allowed_tolerance = max(
    absolute_tolerance_units,
    ceil(max(abs(provider_delta), abs(expected_high)) * relative_tolerance)
)
```

Remaining-counter and plan-total comparisons use exact canonical decimals, not the routing
projections. Thus `0.25 -> -0.75` consumes exactly `1`, `-1.25 -> -3.75` consumes `2.5`, and
`1.9 -> 1.1` consumes `0.8`. A remaining-balance increase is `RESET_DETECTED`, never negative
usage. An exact within-period plan change is `UNKNOWN` with routing held even when both projected
integers match. If either snapshot lacks a plan observation, the plan is not comparable.

Settled ledger values, pending reservations, and manual adjustments remain integers and enter exact
arithmetic through exact decimal conversion. The relative tolerance is finite, within `[0, 1]`, and
has at most 128 significant digits; a configuration float is converted with `Decimal(str(value))`.
Absolute tolerance is a strict non-Boolean, nonnegative signed-INT64 integer. Arithmetic uses a local
precision-512 context with traps for unintended inexact or rounded work. The only intentional
rounding is the final ceiling after exact tolerance multiplication. Accepted observations can
produce a provider delta with 383 significant digits. Subtracting a signed-INT64 ledger bound can
then produce an unexplained reconciliation delta with 384 significant digits. Both exact delta
strings remain bounded to 385 signed fixed-point characters; neither the global decimal context nor
SQLite `REAL` participates.

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
Valid zero or negative observations project to zero and block new positive-cost ordinary
reservations. They do not release existing authority. Eligible zero-cost exact-affinity status,
reconciliation, and cancellation cleanup remains available.

## Decision representation

Determinate decisions persist canonical `provider_delta_units_decimal` and
`unexplained_delta_units_decimal` strings. Their legacy integer compatibility fields are populated
independently only when each exact value is integral and fits signed SQLite INT64. A fractional
match therefore has an exact provider delta, a null integer provider delta, exact unexplained
`"0"`, and integer unexplained `0`. Fractional mismatches retain both exact values with independent
integer nullability. Indeterminate, reset, and plan-change results set both exact and compatibility
provider/unexplained deltas to null. `allowed_tolerance_units_decimal` is always an integral
canonical nonnegative string and may exceed INT64; its independent observation-and-policy envelope
permits at most 129 significant digits and 129 fixed-point characters. Decision construction
enforces these role-specific bounds, exact/compatibility equality, and paired nulls for indeterminate
states. Durable reads enforce role-specific bounds and exact/compatibility equality. Reconciliation
details store exact values as JSON strings, never oversized JSON numeric tokens.

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
