# API Contract

## Principles

- loopback-only in v1;
- JSON request and response bodies;
- stable machine-readable error codes;
- operation-specific validation;
- no raw credential, header, or provider-base-url fields;
- agent and admin authentication are separate;
- request-size and wait-time bounds are enforced server-side.

## Agent API

Default base URL:

```text
http://127.0.0.1:47621
```

### MCP session adoption

`gatehouse-mcp` must be started through a controlled Gatehouse launch with
`GATEHOUSE_SESSION_ID` and `GATEHOUSE_SESSION_BOOTSTRAP` in its child environment. The MCP
process consumes and removes both values from the environment, retains the bootstrap only in process
memory, performs the initial exchange, and creates one server-minted root run. The exchange returns
the configured bounded heartbeat cadence. The MCP server lifespan heartbeats that exact root at the
returned cadence even while no tool is running. After a daemon token-epoch change, a stale-token
`401` from either heartbeat or tool traffic triggers one shared re-exchange and at most one replay
per request; the original root remains authoritative, transient exchange failures stay retryable,
and a capability removed by the new exchange is not replayed. At most 64 concurrent stale callers
may wait on the one bounded exchange; overflow fails retryably instead of forming an unbounded
queue. An optional `GATEHOUSE_AGENT_URL` may select another explicit numeric loopback HTTP address
and port; remote, credential-bearing, redirected, and path-prefixed URLs are rejected.

Only public capabilities returned by the exchange are registered as MCP tools. Every provider
invocation and job operation is internally bound to the server-minted root run; callers cannot
supply or replace that authority through tool arguments.

The installed MCP backend is a bounded loopback client, not a test-only injection. It removes the
bootstrap values from its own environment before exchange, rejects non-loopback or credentialed
agent URLs, disables redirects and ambient proxy use, and keeps the bearer token only in memory.

### Session exchange

```http
POST /v1/sessions/exchange
```

```json
{
  "session_id": "ses_...",
  "bootstrap_capability": "opaque",
  "client_nonce": "opaque"
}
```

Response includes a short-lived bearer token, session metadata, capability names, and
`heartbeat_interval_ms`. The interval is server authority and may change after re-adoption.

### Heartbeat

```http
POST /v1/sessions/heartbeat
Authorization: Bearer <token>
```

```json
{
  "active_root_runs": ["run_..."],
  "reported_agent_count": 1
}
```

An `ACTIVE` session whose last heartbeat exceeds the configured `stale_after` fence is moved to
`DISCONNECTED`. Its reconnect deadline is anchored to the instant it became stale, not to a later
detection attempt, so a retained bootstrap cannot manufacture a fresh grace window.

### Invoke

```http
POST /v1/invocations
Authorization: Bearer <token>
```

```json
{
  "service": "firecrawl",
  "operation": "search",
  "input": {
    "query": "graduate software roles Bengaluru",
    "limit": 10,
    "include_content": false,
    "purpose": "career_discovery",
    "data_classification": ["public_web_query"]
  },
  "context": {
    "root_run_id": "run_...",
    "reported_context_id": "worker-research-3",
    "tool_call_id": "tool_..."
  },
  "execution": {
    "wait_up_to_ms": 15000,
    "allow_cached_result": true
  }
}
```

### Policy explanation

```http
POST /v1/policy/explain
Authorization: Bearer <token>
```

```json
{
  "service": "firecrawl",
  "operation": "crawl",
  "context": { "root_run_id": "run_..." }
}
```

The request deliberately contains no client or workspace selector. Both are taken from the
authenticated controlled session, and the supplied root run must be active and owned by that
session. The route accepts only the four configured Firecrawl policy operation families: `search`,
`scrape`, `map`, and `crawl`.

The response gives the applicable capability ceiling, default decision, purpose-specific rules,
bounded policy constraints, remaining root-run request and credit ceilings, approval requirement,
denial reason, and policy version. Because the CLI form does not supply a target, purpose, payload,
or estimated cost, targeted rules are reported as requiring target context and the top-level
decision is the configured default. A missing operation capability is returned as a
`capability-ceiling` denial rather than executed or escalated. Explanation never queues work,
reserves quota, opens a credential, or calls a provider.

### Jobs

```text
GET  /v1/jobs/{job_id}
POST /v1/jobs/{job_id}/await
POST /v1/jobs/{job_id}/cancel
```

`await` requires a bounded wait value.
Job status carries `root_run_id` as a query parameter. Job await and cancellation carry the same
field in their JSON request body. The server rejects a job outside that exact session/root owner.

Every lookup also verifies the durable workspace, provider principal, quota scope, credential
generation, pool, creating request, and external resource binding. A malformed, absent, or
differently owned job identifier produces the same public invalid-target response.

The response may expose nonterminal `RECOVERING`, `CANCELLING`, or `SETTLING` states. `SETTLING`
means the terminal provider outcome and actual usage are durably checkpointed while the original
quota and root-run budget reservations are being reconciled. Clients may poll or use bounded
`await`; they must not infer a terminal outcome before the terminal state is returned.

### Crawl-start retry handle

`POST /v1/invocations` accepts an optional top-level `request_id` only when the operation is
`firecrawl.crawl.start`:

```json
{
  "request_id": "req_01J00000000000000000000000",
  "service": "firecrawl",
  "operation": "crawl.start",
  "input": {
    "url": "https://example.com/careers",
    "include_paths": ["/careers/**"],
    "exclude_paths": [],
    "maximum_pages": 5,
    "maximum_depth": 1,
    "maximum_concurrency": 1,
    "sitemap": "include",
    "ignore_query_parameters": true,
    "allow_subdomains": false,
    "allow_external_links": false,
    "purpose": "multi_page_job_extraction",
    "data_classification": ["public_web_page"]
  },
  "context": {"root_run_id": "run_..."}
}
```

The identifier is a stable recovery handle, not a caller-selected authority. Reuse it only under
the same authenticated session and root run to recover the same crawl after a local response or
job-materialization failure. A matching durable affinity returns the same job, and the retry
payload cannot mutate or launch a replacement for that already-bound resource. Omit `request_id`
for every intentionally distinct crawl. The API rejects this field for all other operations. The
MCP `firecrawl_crawl_start` tool exposes the same optional field and semantics.

### Documentation and feedback

```text
POST /v1/docs/search
GET  /v1/docs/{service}/{document}
POST /v1/feedback
```

## Result envelope

```json
{
  "request_id": "req_...",
  "state": "SUCCEEDED",
  "service": "firecrawl",
  "operation": "search",
  "result": {
    "source_trust": "untrusted_web_content",
    "data": []
  },
  "usage": {
    "credits_used": 2,
    "estimated": false
  },
  "routing": {
    "pool": "interactive-default",
    "account_alias": "firecrawl-primary"
  },
  "warnings": []
}
```

## Queued result

```http
202 Accepted
Retry-After: 4
```

```json
{
  "request_id": "req_...",
  "job_id": "job_...",
  "state": "QUEUED",
  "queue_position": 3,
  "retry_after_seconds": 4
}
```

## Coalesced result

Eligible equivalent reads may transiently enter `DUPLICATE_IN_FLIGHT`. When the caller elects to
wait, that wait is bounded and the response uses the caller's request identifier with the shared
execution's stable terminal state and typed result. The durable state history records the original
request link; non-coalescible operations never use this path.

```json
{
  "request_id": "req_duplicate_...",
  "state": "SUCCEEDED",
  "service": "firecrawl",
  "operation": "search",
  "result": {
    "source_trust": "untrusted_web_content",
    "data": []
  }
}
```

## Error envelope

```json
{
  "error": {
    "code": "capacity_exceeded",
    "message": "The service queue reached its configured capacity.",
    "retryable": true,
    "retry_after_seconds": 20,
    "request_id": "req_...",
    "policy_rule_id": null,
    "details": {}
  }
}
```

Required codes:

```text
invalid_session
session_expired
session_revoked
attributed_session_required
schema_validation_failed
policy_denied
approval_pending
approval_expired
approval_unavailable_for_unattended_client
capacity_exceeded
budget_exhausted
runaway_suspected
duplicate_in_flight
invalid_target
sensitive_payload_denied
no_eligible_pool
no_eligible_credential
quota_exhausted
provider_rate_limited
provider_permission_denied
provider_unauthorized
provider_timeout
provider_unavailable
uncertain_outcome
result_unavailable_after_restart
daemon_degraded
```

Every retryable error includes a retry delay or reset timestamp.

## Admin API

Default base URL:

```text
http://127.0.0.1:47622
```

The authenticated admin API exposes status, pending approvals, redacted pool and credential
summaries, incidents, reconciliation summaries, and the local dashboard. Installation-capability
control routes separately provide daemon status/stop, configured controlled-session launch and
cleanup, and one-use dashboard login minting.

Credential lifecycle routes are:

| Method and path | Purpose |
|---|---|
| `GET /v1/admin/credentials` | list redacted credential metadata |
| `POST /v1/admin/credentials` | provision into current-user DPAPI custody |
| `POST /v1/admin/credentials/{credential_id}/rotate` | create a generation-fenced successor |
| `POST /v1/admin/credentials/{credential_id}/validate` | validate one exact persistent generation and capture canonical observations plus projections |
| `POST /v1/admin/credentials/{credential_id}/disable` | disable local routing |
| `POST /v1/admin/credentials/{credential_id}/quarantine` | quarantine local routing |
| `POST /v1/admin/credentials/{credential_id}/retire` | enter terminal local `RETIRED` state |
| `POST /v1/admin/emergency-unlocks` | create the sole bounded memory-only unlock |
| `GET /v1/admin/emergency-unlocks` | list redacted unlock status |
| `POST /v1/admin/emergency-unlocks/{unlock_id}/cancel` | cancel and relock an unlock |

Every state-changing route authenticates the admin cookie and validates exact loopback `Origin`
and CSRF authority before parsing command metadata or a body. An `Authorization` bearer header is
not accepted. Safe bounded JSON metadata is carried in `X-Gatehouse-Command`. Provision, rotation,
and emergency unlock alone carry a bounded `application/octet-stream` secret body; validation,
local state changes, and emergency cancellation require an empty body. Responses use explicit
redacted allowlists and never contain secret material.

An accepted stock Firecrawl secret is namespace-separated: `fc-` plus at least 20 ASCII letters,
digits, `_`, or `-`. `FAKE-` and `synthetic-` values with at least 20 printable suffix bytes are
reserved for no-network tests only. Other body values fail before backend invocation or custody.
This format boundary prevents a credential from being identical to ordinary status, counter, or
HTTP response literals.

The stock CLI obtains those three secret bodies only from an interactive hidden prompt. There is no
secret/API-key argument, environment, file, stdin, echo, retrieval, or export path. DPAPI
provisioning works while provider mode is disabled and does not enable networking. Rotation moves
the predecessor to `DRAINING` while preserving exact old-generation asynchronous affinity;
disable, quarantine, and terminal retirement are local actions and do not revoke a provider key.

`gatehouse credentials list --limit N` uses `GET /v1/admin/credentials` through one bounded admin
session and validates each response against the strict `CredentialSummary` allowlist. Its output is
redacted metadata only and never opens credential custody.

Credential validation carries only `{"expected_generation": N}` in `X-Gatehouse-Command`. It is
unavailable unless the daemon is configured with both `mode: live` and `network_enabled: true`.
The backend acquires one exact persistent-generation lease, makes one fixed credit-status read, and
atomically records a sanitized quota snapshot and audit event. The strict response contains only
credential/generation, service, principal and quota-scope identifiers, authenticated state,
`remaining_units` and optional `plan_total_units` routing projections,
`observed_remaining_units_decimal` and optional `observed_plan_total_units_decimal` exact canonical
values, capture time, and snapshot/audit identifiers. The two plan fields have paired nullability.
Canonical strings are numeric values, not provider lexemes: they omit exponent and insignificant
scale, all signed zeros are `"0"`, negative values are permitted, and the integer projections floor
only positive fractions, clamp negative values to zero, and saturate at signed INT64. It does
not return the provider body, headers, cookies, credential, ciphertext, or custody reference. The
route has one in-process slot and no queue, retry, failover, emergency fallback, agent capability,
or MCP tool. It also rejects before dispatch if the active SQLite `busy_timeout` exceeds five
seconds, preserving the durable lease deadline.

The exact observation fields are administrative-only. They are deliberately absent from agent API,
MCP, dashboard, configuration, and audit schemas.

The returned `principal_id` and `quota_scope_id` are Gatehouse's local bindings for the selected
credential; they are not provider-issued account identifiers. A successful typed credit response
proves that the provider accepted that credential for the fixed endpoint. Confirming the intended
provider team/account remains a separate provider-side observation during live rollout.

A provider rejection, timeout, transport failure, or malformed counter result after the service
invokes live transport records `credential.provider_validation_failed`. The event payload is exactly
`actor_id`, the local
`credential_id`, `credential_generation`, stable `error_class`, and `outcome` with the value `failed`. It never
contains provider bodies, headers, reason text, provider request identifiers, retry-after values, or
exception data. The event does not prove HTTP submission or provider receipt. Disabled or scripted
mode, service-local rejection before transport invocation, and cancellation create no failure event.
A successful failure-event write does not change the existing sanitized API error
mapping and its identifier is not returned. If the event cannot be persisted, the route returns only
a generic persistence or daemon-degraded error. Successful validation still commits the sanitized
counter snapshot and success audit atomically.
Invalid syntax, duplicate object keys, non-standard constants, null or non-numeric counters, numeric
bounds violations, and projection inconsistencies are all sanitized malformed responses. They write
no success snapshot. Credit-status bodies from 401, 429, 5xx, and every other non-200 response are
discarded without decoding after transport security and size checks. Their HTTP status remains
authoritative even when the body is malformed or contains an oversized integer. Every unexpected
2xx is instead a non-retryable malformed response.

Emergency unlock is explicit, interactive, synchronous-only, and bound to one exact service, pool,
session, and root run. Hard maxima are 15 minutes, 25 requests, 100 credits, and concurrency one.
It is never a default, automatic selection, or failover route. Cancel, expiry, shutdown, and restart
relock it; SQLite retains only redacted authority evidence.

Policy explanation uses the authenticated agent route above so the hypothetical request is bound
to exact configured session authority.

An agent bearer token must always fail against these routes.

## Approval binding

An approval binds session, service, operation, canonical request fingerprint, target summary, pool,
maximum estimated cost, exactly one use, and expiration. Changing a semantic field creates a new
approval requirement. Approval and denial are immediate SQLite compare-and-set transactions over
the `PENDING` state; concurrent actors can produce exactly one committed winner, and a later actor
cannot overwrite that decision. Consumption is separately exactly once and rechecks the full
request binding.
