# Firecrawl Adapter

## Scope

The Firecrawl adapter is the first active provider vertical slice. It validates typed requests,
constructs credential-free provider requests, classifies provider outcomes, and reports usage
metadata. The shared provider registry fixes its origin, operation contracts, credential roles,
authentication strategy, and native quota model in code.

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
ordinary agent and MCP capability surfaces. The stock daemon exposes it only through lower-level
credential validation, explicit account refresh, and bounded per-account scheduled observation when
the separate observer channel is `live` plus network-enabled. Credential/account provisioning,
rotation, local state, observation-schedule changes, and emergency-unlock routes remain
custody/control operations only and make no Firecrawl request.

Excluded from v1 are arbitrary browser interaction, arbitrary extraction scripts, whole-domain crawl defaults, unbounded batch operations, and generic provider endpoint access.

## Runtime channels

`providers.firecrawl.workload` and `providers.firecrawl.observer` are independent and default to
`disabled` with `network_enabled: false`. The workload channel accepts `disabled`, `scripted`, or
`live`. Stock scripted mode consumes the bounded response manifest captured beside the main
configuration, with its origin, identity and content bound into the configuration digest. It
validates captured bytes before mutable setup and has no pathname reopen fallback. It creates one deterministic idempotent
synthetic no-network quota snapshot, anchors its scope to that snapshot, and never enables
networking. Restart validates and reuses the same snapshot without refreshing its timestamp or
replenishing settled usage. Live workload requires its own `network_enabled: true` and exact
current-user DPAPI custody metadata for every active route. Workload calls still pass session,
policy, quota, capacity, and any applicable approval admission.

The observer channel accepts only `disabled` or `live` and has a distinct transport backed only by
persistent custody—never emergency custody. Live observation requires its own explicit
`network_enabled: true`, bounded timeout, accounts-per-cycle ceiling, and concurrency ceiling. Each
account schedule is also default-disabled. `accounts observe enable` changes only that durable
schedule; it cannot turn on the observer transport. Automated and release-simulation tests use
scripted or mock/no-network data, and operating procedure still requires explicit human
authorization before any live validation or observation.

## Account scopes, selection, and failover

Firecrawl account onboarding models the independently billed team/account as one `TEAM` quota
scope. A second key bound to the same team is another credential, not another balance. Each normal
workload credential has role `WORKLOAD`; the credit-status operation also permits a separately
isolated `OBSERVER` role.

Named account pools use deterministic fill-first ordering by explicit priority. Concurrent LLM
sessions share the highest-priority healthy account while fresh balance and its atomic per-scope
dispatch limit permit. With pool fallback explicitly enabled, an invocation may select the next
eligible account before transport when the preferred scope cannot safely admit the combined load.
This avoids unnecessary
per-client key assignment while preventing a saturated account from causing avoidable failure.

Ordinary plans are bounded by `routing.maximum_route_candidates` (strict integer 1..32,
default 32), conservatively counting configured members and all WORKLOAD credential generations.
Overflow fails closed rather than selecting a truncated prefix. Exact resource affinity is queried
independently. Pre-dispatch fallback defaults false and requires an explicit audited pool action.

Every workload invocation owns one durable, irrevocable submission claim. HTTP 401, 402, 429, 5xx,
and even proven connection failure cannot cause a second same-request send. Exhaustion/cooldown
still exclude routes for later independently admitted requests. Emergency requests obey the same
one-submission ceiling, and emergency custody is never an automatic fallback.

Capacity does not break provider-handoff affinity. Crawl status/cancel remain bound to their exact
resource authority, and an ambiguous side-effecting outcome becomes `UNKNOWN`; it is not replayed
through another account.

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
| invalid credential | `UNAUTHORIZED` | fail without another same-request send |
| exhausted credits | `QUOTA_EXHAUSTED` | durably exhaust the quota scope; no same-request backup |
| permission or plan mismatch | `PERMISSION_DENIED` | do not spray across unrelated accounts |
| rate limit | `RATE_LIMITED` | return bounded retry hint; cooldown scope; no resend |
| transient server error | `TRANSIENT` | fail without another same-request send |
| invalid input | `INVALID_REQUEST` | fail without retry |
| ambiguous timeout after submission | `UNKNOWN_OUTCOME` | retain accounting; reconcile without automatic replay |

Bodies from non-200 credit-status responses are discarded without decoding after transport security
and size checks. A 401, 429, or 5xx therefore retains its provider error classification even when
the body is malformed or contains an oversized integer. Exact numeric hooks are reserved for HTTP
200, and every unexpected 2xx is a non-retryable malformed response.

The attempt record and definitive exhaustion transition commit together. `EXHAUSTED` therefore
survives later requests and daemon restarts; expiration of the in-memory quota breaker cannot
re-enable the account. Only an authenticated positive credit observation or explicit operator
recovery can change the durable scope state. Explicit recovery does not refresh the stored balance,
so stale or absent authority remains conservatively unavailable.

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
    provider_id="firecrawl",
    method="POST",
    path="/v2/search",
    credential_id="cred_...",
    credential_generation=1,
    credential_role=CredentialRole.WORKLOAD,
    json_body=validated_payload,
    timeout_ms=30000,
    maximum_response_bytes=20000000,
    operation="firecrawl.search",
)
```

The active descriptor fixes the origin to `https://api.firecrawl.dev`, host to
`api.firecrawl.dev`, and authentication to a bearer `Authorization` header injected only while the
DPAPI lease is open. It also owns `Accept: application/json`, the Gatehouse `User-Agent`, and
`Content-Type: application/json` when a JSON body is required. Callers cannot add headers or
choose another authentication strategy.

The code-owned method/path contracts are:

| Typed operation | Method | Exact path contract | Credential roles |
|---|---|---|---|
| `firecrawl.search` | `POST` | `/v2/search` | `WORKLOAD` |
| `firecrawl.scrape` | `POST` | `/v2/scrape` | `WORKLOAD` |
| `firecrawl.map` | `POST` | `/v2/map` | `WORKLOAD` |
| `firecrawl.crawl.start` | `POST` | `/v2/crawl` | `WORKLOAD` |
| `firecrawl.crawl.status` | `GET` | `/v2/crawl/{validated_resource_id}` | `WORKLOAD` |
| `firecrawl.crawl.cancel` | `DELETE` | `/v2/crawl/{validated_resource_id}` | `WORKLOAD` |
| `firecrawl.account.credit_status` | `GET` | `/v2/team/credit-usage` | `WORKLOAD`, `OBSERVER` |

All paths are provider-relative and accept no caller-defined query parameters. Absolute URLs,
userinfo, fragments, query strings embedded in paths, backslashes, and traversal are rejected before
custody. The transport re-validates the operation, method, path, body policy, and credential role
against the immutable registry; it is not a generic authenticated HTTP proxy. The adapter never
receives a raw provider key.

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

The Firecrawl dimension records provider-defined reset semantics. The typed v2 credit endpoint's
paired `billingPeriodStart` and `billingPeriodEnd` RFC 3339 values are allowlisted, converted exactly
to millisecond instants, and stored as `period_start_ms` and `period_end_ms` on the authenticated
snapshot. Missing pairs remain null for backward-compatible scripted responses; partial, reversed,
invalid, or sub-millisecond values fail closed as malformed. Gatehouse never synthesizes a reset
timer when the provider supplies no authoritative period.

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
failover, or emergency custody. Manual account refresh and scheduled collection reuse that same
typed operation through the observer channel; each call still names one exact credential generation.
The schedule claim is bounded and generation-fenced, provider I/O occurs outside the database
transaction, and completion stores source, capture time, `stale_at_ms`, exact credential provenance,
and schedule outcome durably. Failures that may still be billable remain conservative until
reconciliation.

An authenticated zero or negative remaining balance persists both the immutable snapshot and a
durable `EXHAUSTED` transition. A positive authenticated refresh may recover an exhausted,
unknown, or cooldown scope to `HEALTHY`; it never overrides an operator-disabled or quarantined
scope. Legacy or expired live observations are stale and cannot authorize positive-cost routing.

Account status is a separate strict redacted view. It returns only `alias`, `state`, exact
`remaining_decimal`, optional exact `plan_decimal`, native `unit`, `observed_at_ms`, computed
`staleness_ms`, `stale`, and the code-owned observation `source`. The only accepted sources are
`admin-credential-validation`, `account-manual-refresh`, and
`scheduled-firecrawl-credit-observation`. Incomplete or unrecognized provenance suppresses the
observation fields together. A complete code-owned observation may remain visible as stale for
operator diagnosis, but cannot authorize positive-cost routing and yields `UNKNOWN` unless a
stronger durable disabled, quarantined, or exhausted state applies. Credential, local opaque IDs,
custody reference, headers, and provider body are absent.

The principal and quota-scope identifiers returned by lower-level validation are local Gatehouse
bindings, not Firecrawl account attestations. Supported account onboarding deliberately treats the
provider team/account as the quota scope, but a separately authorized live rollout must still
cross-check the accepted credential and counters against the intended provider-side team/account
view.
