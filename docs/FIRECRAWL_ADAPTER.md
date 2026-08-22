# Firecrawl Adapter

## Scope

The Firecrawl adapter is the first provider vertical slice. It validates typed requests, constructs credential-free provider requests, classifies provider outcomes, and reports usage metadata.

It does not select accounts, decrypt credentials, change policy, or hold provider keys.

## Implemented adapter operations

```text
firecrawl.search
firecrawl.scrape
firecrawl.map
firecrawl.crawl.start
firecrawl.crawl.status
firecrawl.crawl.cancel
firecrawl.account.credit_status
```

Account credit status has a typed internal adapter contract and is intentionally absent from the
ordinary agent and MCP capability surfaces. The stock daemon exposes it only through an explicit
authenticated administrative credential-validation route in `live` plus network-enabled mode.
Credential provisioning, rotation, local state, and emergency-unlock routes remain custody/control
operations only and make no Firecrawl request.

Excluded from v1 are arbitrary browser interaction, arbitrary extraction scripts, whole-domain crawl defaults, unbounded batch operations, and generic provider endpoint access.

## Runtime modes

The stock daemon defaults to `disabled`, which has no Firecrawl route. `scripted` reads a bounded
local response manifest, creates one deterministic idempotent synthetic no-network quota snapshot,
anchors its scope to that snapshot, and never enables networking. Restart validates and reuses the
same snapshot without refreshing its timestamp or replenishing settled usage.
`live` requires the separate `network_enabled: true` setting and exact current-user DPAPI custody
metadata for every active route. Those settings make the transport available; an actual call still
passes ordinary session, policy, quota, and any applicable approval admission. There is no third
global operator-authorization switch in the runtime. Automated and release-simulation tests use
scripted data, and project operating procedure requires explicit human authorization before live
validation.

## Search schema

```yaml
query: string, 1..500
limit: integer, 1..20
include_content: boolean
purpose: enum
data_classification: list
```

By default, request discovery metadata only. Content retrieval is explicit and policy-compatible.

## Scrape schema

```yaml
url: absolute HTTPS URL
formats: subset of [markdown, summary, links]
only_main_content: true by default
timeout_ms: bounded
purpose: enum
data_classification: list
```

## Map schema

```yaml
url: absolute base URL
search: optional relevance query
limit: 1..100
purpose: career_site_research
```

Map is for locating relevant careers or job paths, not enumerating an entire site without need.

## Crawl schema

```yaml
url: absolute HTTPS URL
include_paths: bounded list
exclude_paths: bounded list
maximum_pages: policy-capped
maximum_depth: policy-capped
sitemap: skip | include | only
ignore_query_parameters: boolean
allow_subdomains: false by default
allow_external_links: false
purpose: multi_page_job_extraction
```

Gatehouse always sends explicit narrow limits. Whole-domain traversal and external-link following are denied in v1.

### Stable crawl-start retry

The agent invocation envelope and `firecrawl_crawl_start` MCP tool accept an optional Gatehouse
`request_id`. A caller may reuse it only to recover the same prior crawl start under the same
session and root-run authority—for example, after Gatehouse received the provider resource but
failed before returning its local job. Omit it for a distinct crawl. The provider payload never
receives this local identifier, and other operations reject it.

## URL safety

Before dispatch:

- normalize scheme and host;
- reject embedded credentials;
- reject local file and network-share targets;
- reject localhost, loopback, private, link-local, multicast, and unsupported schemes;
- enforce feed-set host and path rules;
- cap URL length;
- reject control characters;
- canonicalize before fingerprinting.

## Error classification

| Outcome | Classification | Routing action |
|---|---|---|
| invalid credential | `UNAUTHORIZED` | disable or refresh credential; no same-credential loop |
| exhausted credits | `QUOTA_EXHAUSTED` | open quota-scope breaker; try next eligible scope within pool |
| permission or plan mismatch | `PERMISSION_DENIED` | do not spray across unrelated accounts |
| rate limit | `RATE_LIMITED` | honor retry hint; cooldown scope |
| transient server error | `TRANSIENT` | bounded retry when safe |
| invalid input | `INVALID_REQUEST` | fail without retry |
| ambiguous timeout after submission | `UNKNOWN_OUTCOME` | reconcile before replay |

Bodies from non-200 credit-status responses are discarded without decoding after transport security
and size checks. A 401, 429, or 5xx therefore retains its provider error classification even when
the body is malformed or contains an oversized integer. Exact numeric hooks are reserved for HTTP
200, and every unexpected 2xx is a non-retryable malformed response.

## Crawl resource affinity

Persist provider job identifier, creating session/workspace/root-run owner, principal, quota scope,
credential generation, pool, and creating request. Status and cancellation require the exact
execution owner and use the same provider principal or an equivalent credential under that
principal. Owner or authority facts missing from a legacy row fail closed.

The successful crawl-start attempt checkpoints resource type, provider job identifier, credential
generation, and pool in the same durable attempt update before affinity binding. On restart,
migration-6 rules allow reconstruction only when the complete checkpoint agrees with the durable
invocation, credential, principal, quota scope, pool, and owner graph. Conflicts or corruption stop
startup; they never cause a guessed bind or a replayed crawl start.

Migration 7 additionally freezes the complete checkpoint and its request, attempt, credential,
principal, quota-scope, completion-time, generation, and pool authority after creation.

Local job creation is idempotent over that exact affinity and creating request. A repeated stable
request returns the same job; a different request cannot claim the same provider resource.

## Provider transport request

```python
ProviderRequest(
    method="POST",
    path="/v2/search",
    credential_id="cred_...",
    json_body=validated_payload,
    timeout_ms=30000,
    maximum_response_bytes=20000000,
    operation="firecrawl.search",
)
```

The path is a fixed provider-relative `/v2/` path; arbitrary absolute URLs and traversal are
rejected. The adapter never receives a raw provider key.

## Usage reconciliation

Synchronous operations record provider-reported usage when available. Crawl quota and root-run
budget reservations remain pending until status reports terminal actual usage. The supervisor first
persists a complete `SETTLING` checkpoint, reconciles both original reservations idempotently, and
then makes the job terminal. Restart resumes settlement without another provider observation.
The credit-status adapter constructs only `GET /v2/team/credit-usage`, with a 10-second
provider-request timeout and 64 KiB response ceiling. The admin service also enforces a 15-second
end-to-end dispatch deadline inside a longer durable credential lease. Only this operation at HTTP
200 uses JSON `parse_int`/`parse_float` hooks that retain normalized exact numbers. Every numeric
token in that successful body receives transport-level ASCII token-length and exponent resource
checks; duplicate object keys and `NaN`, `Infinity`, and `-Infinity` are rejected. Decode exceptions
are stripped of traceback, cause, and context without echoing the token, and the response becomes
sanitized malformed data. All other operations use ordinary decoding. Non-200 credit-status bodies
are discarded without decoding after credential-overlap, unsafe-header, response-size, and transport
checks. Safe `Retry-After` survives for a 429, but no response-body data is retained.

The adapter then applies the complete observation envelope only to `data.remainingCredits` and a
present `data.planCredits`: an RFC 8259 JSON number no longer than 256 ASCII characters, explicit
exponent in `[-256, 256]`, finite normalized value, at most 128 significant digits after removing
leading and insignificant trailing coefficient zeros, nonzero adjusted exponent in `[-128, 127]`,
and canonical fixed-point text no longer than 258 characters. Injected tests may supply an exact
non-Boolean Python integer through the same checks; an already-rounded Python float is rejected.
Unrelated bounded numeric extensions remain extensions and cannot become a credit counter.

Canonical observations have no exponent, leading plus, redundant leading integer zeros, trailing
fractional zeros, or signed zero: `1`, `1.0`, and `1e0` all become `"1"`. Insignificant lexical
scale and raw provider lexemes are not retained. Remaining credit is required and non-null. Missing
plan credit produces null plan observation and projection, while present null plan credit is
malformed. Boolean, string, object, array, non-standard constant, and out-of-envelope counters reject
the whole response, write no success snapshot, and produce the bounded failure audit.

The adapter preserves negative remaining as provider overage and accepts negative or fractional
plan values. Routing projects each present observation as
`min(9223372036854775807, floor(max(0, value)))`: positive fractions remain exact but only the
projection floors, negative and signed zero project to zero, and values above INT64 remain exact but
only the projection saturates. No `planCredits >= remainingCredits` relation is required. Exact
remaining and plan observations plus their projections commit atomically with the sanitized audit.
The path is bound to one exact healthy persistent generation and has no pool selection, retry,
failover, or emergency custody. Scheduled counter collection and quick/full reconciliation
orchestration remain pending. Failures that may still be billable remain conservative until
reconciliation.

The principal and quota-scope identifiers returned by validation are local Gatehouse bindings, not
Firecrawl account attestations. A live rollout must cross-check the accepted credential and counters
against the intended provider-side team/account view.
