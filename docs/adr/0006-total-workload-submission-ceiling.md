# ADR 0006: One total workload submission and bounded explicit fallback

Date: 2026-09-05

Status: Accepted for source implementation; deployment validation remains separate.

## Context

A per-credential retry limit multiplied by an uncapped pool permits more transport submissions than
one logical request's quota and budget reservation account for. Execution ambiguity and billing
ambiguity are different: a definitive HTTP failure need not be free.

## Decision

Support only strict integer `maximum_total_provider_attempts=1`. Persist one irrevocable request
claim immediately before transport entry, outside network I/O. A successful claim cannot be reused
after cancellation, connection failure, retry classification, failover, or restart. All workload
paths, including emergency and exact-resource operations, use the same gate. New requests and
separately authorized observer requests are distinct admissions; this is not exactly-once provider
execution or proof of delivery.

Do not support higher limits until every potentially billable submission has independent atomic
accounting. Settle explicit known usage, retain unknown billing, and keep known overruns visible
during recovery even if they exceed the original estimate.

Bound ordinary catalog materialization by a strict 1..32 member/WORKLOAD-generation ceiling,
default 32. Reject overflow instead of truncating before ranking. Exact-affinity lookup remains
independent of unrelated ordinary overflow. Inactive history may conservatively block new routing;
it does not authorize cleanup.

Default pre-dispatch fallback to false. Enablement is a typed authenticated operator mutation with
actor/pool/action/reason replay binding and an atomic preserved audit. It cannot override the
submission ceiling, provider boundary, emergency exclusion, or exact resource affinity.

## Consequences

Automatic post-transport retries are removed, including safe reads after 401/402/429/5xx or a proven
connection failure. This intentionally trades availability for a defensible single-submission cost
boundary. Durable exhaustion and cooldown still affect later independent requests. Migration 16
preserves earlier migration checksums and treats legacy attempted invocations as conservatively
exhausted without inventing transport evidence. No existing database is migrated by a source edit.
