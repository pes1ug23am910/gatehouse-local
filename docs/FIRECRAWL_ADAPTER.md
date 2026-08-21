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
ordinary agent and MCP capability surfaces. The stock daemon does not yet invoke it or expose an
authenticated administrative execution route. Credential provisioning, rotation, local state, and
emergency-unlock admin routes are custody/control operations only: they neither invoke credit status
nor make any other Firecrawl request.

Excluded from v1 are arbitrary browser interaction, arbitrary extraction scripts, whole-domain crawl defaults, unbounded batch operations, and generic provider endpoint access.

## Runtime modes

The stock daemon defaults to `disabled`, which has no Firecrawl route. `scripted` reads a bounded
local response manifest, synthesizes credential-free route metadata, and never enables networking.
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
The credit-status adapter contract can construct the fixed provider request and classify its
outcome, but no stock execution path converts a response into a quota snapshot. Failures that may
still be billable remain conservative until reconciliation.
