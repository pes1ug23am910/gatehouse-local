# API Contract

## Principles

- loopback-only in v1;
- JSON request and response bodies;
- stable machine-readable error codes;
- operation-specific validation;
- no raw credential, header, or provider-base-url fields;
- code-owned provider origins, methods, paths, headers, authentication strategies, and credential
  roles—never a generic authenticated HTTP proxy;
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

Firecrawl is the only dispatch-capable provider in this candidate. `github`, `openrouter`, `gemini`,
`xai`, and `jarvislabs` are provider-neutral foundation identifiers with no API operation or
transport. No agent request can ask Gatehouse to switch providers automatically.

The installed MCP backend is a bounded loopback client, not a test-only injection. It removes the
bootstrap values from its own environment before exchange, rejects non-loopback or credentialed
agent URLs, disables redirects and ambient proxy use, and keeps the bearer token only in memory.

The deployment topology keeps one `gatehoused` process available in the user session and starts one
MCP stdio shim on demand per controlled client. The shim is a typed loopback client, not a
credential holder or provider proxy; no provider key is placed in its environment or returned from
a tool.

Before the MCP process starts, the installation-capability control client posts `request_id`, `client`,
`workspace`, `non_interactive`, and `working_directory` to `POST /v2/control/sessions`. The working
directory must be the caller's actual existing absolute current directory. The daemon resolves it
and the configured canonical workspace root, requires the requested client profile to list the
workspace in `workspaces.allow`, admits only the root or a descendant, and returns the exact pinned
child directory. The request cannot select opaque client/workspace identifiers or regain the old
implicit cross-product. Project instruction files are not an input to this API.

The creation `request_id` is exactly 32 lowercase hexadecimal characters generated before dispatch.
Its durable digest binds at most one session; repeated creation is refused and never reissues a
bootstrap capability. `POST /v2/control/session-requests/cancel` accepts only that `request_id` and
returns it with `state: CANCELLED` and the nullable bound `session_id`. Cancellation revokes an
existing binding or creates a retained tombstone before creation, so a delayed create cannot mint
authority afterward. Both operations require the same installation-capability and configuration
digest checks as other control mutations. Losing the client's original request handle does not
provide a way to reconstruct it from a durable digest.

If a Firecrawl tool returns `approval_pending`, the response includes `approval_id`, `request_id`,
and an `approval_context` containing the exact root run, the fixed action
`decide_locally_then_retry_exact_request`, and (when composed) an exact numeric-loopback
`http://127.0.0.1:<port>/dashboard` URL. The MCP tool surface cannot approve or deny and explicitly
treats prompt text as non-authoritative. It remembers only a bounded keyed-HMAC continuation and
collapses concurrent exact retries. After MCP restart, a pending crawl retry must reuse the returned
stable `request_id`; the agent API revalidates and rehydrates the original durable
`WAITING_APPROVAL` binding without executing that parent invocation. The process must re-adopt the
same durable session/client/workspace/root run. A fresh controlled launch creates another session,
cannot inherit the approval, and proceeds through a new policy/approval decision.

A fresh explicit crawl `request_id` with no matching durable invocation is not mistaken for failed
rehydration: under `ALLOW` it follows normal crawl admission, and under `ASK` it creates a new
pending approval. Only an existing but mismatched/ambiguous durable handle fails closed.

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

The response additionally requires a closed, typed `effective_policy` descriptor. It contains:

- `compiler_revision: 1`, `policy_id`, `service`, `default_decision`, and `default_pool`;
- `workspace_binding`, a 64-character lowercase hexadecimal digest that binds the workspace
  without returning its canonical root;
- `hard_denies`, with `profile: fixed-v1`, the seven sorted fixed sensitive-data classifications,
  `crawl_requires_include_paths: true`, `crawl_external_links: false`, and `crawl_subdomains: false`;
- `credit_discipline`, with `duplicate_in_flight: return_original`,
  `cross_session_public_coalescing: false`, `cache_completed_public_reads: disabled`,
  `broad_crawl_without_narrow_attempt: deny`, and `prior_narrow_attempt_tracking: false`;
- `enforce_limits: true` and `limits` containing `search_results`, `map_results`, `crawl_pages`,
  `crawl_depth`, `requests_per_root_run`, and `credits_per_root_run`;
- at most 64 sorted `purposes`, each containing `purpose` and at most four sorted `operations`.
  An operation contains `operation` (`search`, `scrape`, `map`, or `crawl`), uppercase `decision`,
  strict Boolean `targeted_only`, and required nullable finite nonnegative `maximum_cost`.

All descriptor fields are required; unknown fields and invalid nested types are rejected. Limits
are positive, except that crawl depth may be zero; the credit limit is finite. Sensitive-data
classifications are exactly `api_key`, `credential`, `identity_document`, `private_document`,
`private_key`, `resume`, and `sensitive_personal_information`. Fixed Boolean and revision fields do
not accept numeric or string coercion. Purpose and operation names are unique within their arrays.
The descriptor states configured policy; the selected-operation decision and purpose-rule
projection remain filtered by authenticated capabilities and unattended approval behavior.

For compiled and built-in default policies, `policy_version` is the first 16 hexadecimal characters
of SHA-256 over the canonical JSON descriptor. Equivalent shorthand/explicit rule representations
have the same version. The descriptor is provided through this existing route and grants no new
operation or authority.

The candidate rejects unsupported hard-deny profiles, `enforce_limits: false`, enabled
cross-session coalescing, and the old `cache_completed_public_reads: policy_controlled` setting.
Completed-result caching is disabled. Crawl include-path presence does not establish regex
narrowness, and prior narrow-attempt history is not tracked. These are candidate API contracts;
[testing evidence](../TESTING.md) separately records source, artifact and installed validation.
Reading this contract does not migrate configuration or retained state or authorize live use.

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

### Watcher

```text
POST /v1/watcher/feed-sets/{feed_set_id}/scan
GET  /v1/watcher/feed-sets/{feed_set_id}/cursor
POST /v1/watcher/feed-sets/{feed_set_id}/cursor/commit
GET  /v1/watcher/feed-sets/{feed_set_id}/previous-summary
```

Every route requires the authenticated controlled watcher session and its active `root_run_id`.
Scan accepts only that root run plus an optional expected cursor. Cursor commit accepts the watcher
run ID, expected cursor version, new bounded cursor value, and increasing cursor sequence. No route
accepts a target URL, operation, provider payload, pool, workspace selector, or previous-summary
body.

Cursor sequences are non-negative JSON-safe integers. In addition to strict monotonicity, one commit
cannot advance the stored sequence by more than 10,000,000,000,000.

The MCP backend supplies the adopted root run automatically. `watcher_scan_feed_set` therefore
exposes only `feed_set_id` and optional cursor; the read tools expose only `feed_set_id`; and commit
adds only the run and cursor-fencing fields. Gatehouse resolves workspace-bound ordered scrape/map
targets from server configuration.

A completely successful scripted scan returns `READY_TO_COMMIT`, its step results (subject to a
two-MiB aggregate serialized ceiling), the current cursor, and watcher run ID. Gatehouse stores only
a bounded pending summary for that run. A separate commit reconstructs the session-bound fence and
atomically publishes the pending summary with the new cursor. Live execution, crawl, crash
redispatch/resume, and daemon-owned periodic triggering are not exposed by these routes.

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

Feedback accepts this closed request shape:

```json
{
  "category": "reliability",
  "severity": "medium",
  "component": "firecrawl.search",
  "summary": "A concise description",
  "problem": null,
  "what_worked": null,
  "suggested_improvement": null,
  "related_request_ids": []
}
```

Allowed classification values are:

- `category`: `contract`, `documentation`, `performance`, `reliability`, `security`, `usability`,
  or `other`;
- `severity`: `low`, `medium`, `high`, or `critical`;
- `component`: `agent-api`, `cli`, `client`, `configuration`, `credentials`, `database`,
  `documentation`, `feedback`, `firecrawl.crawl`, `firecrawl.map`, `firecrawl.scrape`,
  `firecrawl.search`, `mcp`, `policy`, `routing`, `runtime`, `scheduler`, `sessions`, `transport`,
  `watchdog`, `watcher`, or `other`.

The summary is required and limited to 1,000 characters. Each optional narrative field is limited
to 4,000 characters, and `related_request_ids` accepts at most 64 identifiers. A successful response
contains only `feedback_id`, `state`, and `created_at_ms`; submitted free-form text is not reflected.

## Result envelope

```json
{
  "request_id": "req_...",
  "state": "SUCCEEDED",
  "service": "firecrawl",
  "operation": "search",
  "attempts": 1,
  "result": {
    "source_trust": "untrusted_web_content",
    "data": []
  }
}
```

Every invocation result contains exactly `request_id`, `state`, `service`, `operation`, and
`attempts`. A successful non-crawl operation may additionally contain the redacted typed `result`
shown above. A successful crawl start contains `job_id` instead; a non-success state contains
neither optional field. Usage, pool, credential, and account-selection metadata are not projected to
the agent result.

## Bounded queue wait

The coordinator may durably transition an invocation through `QUEUED`, but the HTTP route does not
return a queue position or create a job at that point. The request waits for a scheduler permit only
within `execution.wait_up_to_ms` and the server's configured maximum. Permit acquisition continues
to the normal invocation result; queue capacity or deadline exhaustion returns the standard
retryable `capacity_exceeded` error and `Retry-After` header. A `job_id` is created only after a
successful `firecrawl.crawl.start` provider result.

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
  "attempts": 1,
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
    "message": "The configured capacity is currently exhausted.",
    "retryable": true,
    "retry_after_seconds": 20,
    "provider_reset_at_ms": null,
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

A workload invocation makes at most one local transport submission. Its server-owned strict
`maximum_total_provider_attempts=1` cannot be changed by an API payload. `provider_rate_limited`
returns the provider failure and bounded retry hint without same-request sleep, retry, or fallback.
Other HTTP failures and proven connection failure also consume the durable claim. Unknown execution
remains `UNKNOWN`; known billing is settled independently and unknown billing retains reservations.
The claim is not proof of provider receipt or exactly-once effects; distinct new request IDs are
separate admissions. Observer refreshes are separate explicitly gated requests.

`runaway_suspected` details are an allowlisted projection: `authorization_required`,
`quarantine_id`, `reason_code`, `scope: session_root_run_service`, durable state, trigger, and—only
when authorization is required—the validated numeric-loopback `dashboard_url`. They contain no
request payload, fingerprint, key, provider response, action token, or decision capability. A human
dashboard decision must precede an exact retry.

## Admin API

Default base URL:

```text
http://127.0.0.1:47622
```

The authenticated admin API exposes status, pending approvals, redacted pool and credential
summaries, incidents, reconciliation summaries, and the local dashboard. Installation-capability
control routes separately provide daemon status/stop, configured controlled-session launch and
cleanup, and one-use dashboard login minting.

`GET /v1/control/status` includes `config_digest`, the daemon's captured configuration-bundle
digest, through the existing installation-capability authentication. A non-null value is exactly
64 lowercase hexadecimal characters. Stock file-backed composition freezes the verified value
before mutable setup; explicit snapshot-less in-memory composition reports null. No configuration
document text or origin is returned by this field, and public health routes do not expose it.

This authenticated status also includes the bounded `workload` projection, forwarded by
`gatehouse daemon status`. Its statuses are `DISABLED`, `UNAVAILABLE`, `UNVERIFIED`, `UNCONFIGURED`,
`DEGRADED`, and `READY`. It evaluates at most 32 configured interactive routes
and 256 bindings under a fresh owned read transaction, including ordinary policy/capability,
custody and capacity checks. It does not reserve capacity or promise that multiple routes can run
together. Public `gatehouse status` and health routes remain lifecycle-only.

CLI `daemon start` requires this value to equal its freshly captured expected digest before
accepting either an existing daemon or an owned child, including intermediate `RECOVERING`
responses. A missing, null, malformed or mismatched value in a successful decoded response causes
a fixed failure. It neither starts a replacement for an existing responder nor stops that
responder; unsuccessful owned startup retains its bounded child cleanup. This checks agreement
with the responding endpoint, not cryptographic server/process identity or continuity of later
control requests. See [the startup digest decision](adr/0007-startup-configuration-digest.md).

The watchdog also uses capability-authenticated `GET /v1/control/status`, with the admin endpoint
from its verified configuration. Public `/health/live` is presence evidence only; `/health/ready`
does not establish its configuration agreement. Acceptance requires agent HTTP 200 and control
HTTP 200, an exact matching digest and a coherent typed daemon state. Control status uses HTTP 200
for every reported state, including degraded states.

The watchdog accepts at most 64 KiB of identity-encoded JSON under one asynchronous deadline covering
both probes and client closure. Any response remains evidence of a live endpoint after later
failure. Only explicit connection failures on both configured listeners, before any response, can
permit the existing leased restart. Missing capability, timeout, malformed responses or conflicting
configuration produce a nonzero outcome without restarting another responder. Other live degraded
states also produce a nonzero outcome; `providers_disabled` is successful only for a matching,
coherent disabled state when both configured provider channels are disabled. Owned startup uses
the same agreement requirements and retains bounded cleanup of only its child. See
[the watchdog decision](adr/0009-authenticated-watchdog-configuration.md).

Control mutations use these distinct routes; the former v1 mutation paths are not dispatched:

| Method and path | Purpose |
|---|---|
| `POST /v2/control/drain` | request bounded daemon shutdown |
| `POST /v2/control/sessions` | create a configured controlled session |
| `POST /v2/control/session-requests/cancel` | cancel the exact creation request or tombstone it before arrival |
| `POST /v2/control/sessions/{session_id}/disconnect` | disconnect the exact session |
| `POST /v2/control/sessions/{session_id}/revoke` | revoke the exact session |
| `POST /v2/control/admin/login-code` | mint a one-use administrative login code |

Each mutation requires the installation capability and exactly one
`x-gatehouse-expected-config-digest` header equal to the server's frozen captured digest. The value
must be exactly 64 lowercase hexadecimal characters without whitespace or coercion. A null server
digest refuses mutations. Capability validation precedes digest validation, body ingestion and
service effects. `GET /v1/control/status` stays available without an expected-digest header.

The stock bounds middleware defers recognized v2 control bodies until authorization and binds the
request to its bounded receive callback. A bare or incorrectly wrapped control router fails closed
before reading. Authorized bodies retain the existing byte and total/inter-chunk deadline limits;
the four bodyless routes reject nonempty bodies before effects. Session creation retains its strict
typed JSON schema. No generic proxy is introduced.

The static browser `GET /login` page accepts a one-use code only from a URL fragment, clears the
fragment with `history.replaceState`, and submits after a deliberate form action to `POST /login`.
Only that GET page receives its exact script-hash CSP allowance. The browser POST requires the
exact admin Origin; the separate typed CLI exchange endpoint retains its own contract.

The CLI uses only v2 mutation paths and sends the digest from its operation's captured settings.
Owned cleanup retains its original endpoint, capability and digest after configuration changes. A
replacement daemon with a different digest refuses cleanup; the pending record remains until that
original authority can be used successfully. There is no automatic rebinding or v1 fallback. Old
daemons do not expose the new paths and cannot ignore the header on an existing mutation handler.
This fences one control request. Subsequent admin-cookie and agent API requests still need their
own continuity contract; no control or watchdog comparison establishes hostile same-user server
identity. See
[the control request decision](adr/0008-configuration-bound-control-mutations.md).

Durable runaway quarantine routes back the local human dashboard:

| Method and path | Purpose |
|---|---|
| `GET /v1/admin/runaway-quarantines?limit=N` | list redacted offender-scoped quarantine status |
| `GET /v1/admin/runaway-quarantines/{quarantine_id}` | read one current generation and action token |
| `POST /v1/admin/runaway-quarantines/{quarantine_id}/authorize` | grant one bounded typed-operation burst |
| `POST /v1/admin/runaway-quarantines/{quarantine_id}/deny` | deny the burst and keep the offender blocked |
| `POST /v1/admin/runaway-quarantines/{quarantine_id}/recover` | safely close old authority and release one exact generation for a future fresh run |

These admin-cookie routes are not agent or MCP capabilities and have no stock CLI command; the
supported human workflow is the CSRF-protected local dashboard. Authorize requires the current
`action_token`, `expected_generation`, a nonempty reason, `duration_ms`, `maximum_requests`,
`maximum_credits`, `maximum_concurrency`, and a nonempty tuple of code-owned typed operations. Hard
maxima are 900,000 ms, 25 requests, 100 credits, concurrency eight, and 16 operations. Deny requires
the same generation/action fences and a reason. Recover additionally requires literal
`RECOVER_FRESH_RUN` confirmation. It rejects active burst permits, nonterminal/ambiguous work,
unreconciled quota/budget authority, and live or unreconstructed asynchronous affinity before it
revokes the old session, closes the root, and appends exact-generation evidence. It transfers no
burst grant. The decision reason is retained only as a fingerprint plus supplied flag; it is not
returned or written into an audit payload.

The view includes the quarantine ID, session/client/workspace/root-run/service scope, state,
trigger, trigger operation, generation/times, remaining grant counters, concurrency, operation
allowlist, optional recovery ID/time, and keyed action token. It contains no provider key, request
body, request fingerprint, provider body, or page content. Every authorized request owns a durable
one-use permit. Known
actual-cost overrun consumes additional remaining credits; unknown cost exhausts the grant. Startup
marks active permits `ORPHANED`, closes the authorization generation, and requires a new dashboard
decision.

Supported Firecrawl account and pool routes are:

| Method and path | Purpose |
|---|---|
| `GET /v1/admin/accounts?limit=N` | list redacted account status |
| `GET /v1/admin/accounts/{alias}` | read one redacted account status |
| `POST /v1/admin/accounts` | atomically onboard an account and fill-first pool membership after DPAPI staging |
| `POST /v1/admin/accounts/{alias}/rotate` | rotate the current workload generation from a hidden-prompt secret |
| `POST /v1/admin/accounts/{alias}/disable` | durably exclude the account locally |
| `POST /v1/admin/accounts/{alias}/recover` | explicitly recover local state without fabricating a balance refresh |
| `POST /v1/admin/accounts/{alias}/remove` | retire custody and tombstone the local account graph |
| `POST /v1/admin/accounts/{alias}/refresh` | perform one bounded authenticated balance observation |
| `POST /v1/admin/accounts/{alias}/observation` | enable or disable the durable per-account schedule |
| `POST /v1/admin/pools/{alias}/failover` | explicitly enable or disable pre-dispatch fallback in an ordinary pool |

Pool failover changes carry only `mutation_id`, `action` (`enable` or `disable`), and a bounded
nonblank `reason` in `X-Gatehouse-Command`, with an empty body. Admin cookie, exact Origin, and CSRF
checks precede parsing. The service atomically commits the Boolean pool setting, a preserved audit,
and a replay-bound metadata journal result. The reason is retained only as a fingerprint. Results
contain exactly `pool_alias`, `action`, `enabled`, `acted_at_ms`, and `audit_event_id`. This route
never creates a credential, contacts a provider, or permits a second workload submission. The CLI
is `gatehouse pools failover enable|disable ALIAS --mutation-id ID --reason REASON`.

`POST /v1/admin/accounts` accepts `mutation_id`, literal provider `firecrawl`, `alias`, mandatory
non-secret `provider_team_id`, `pool_alias`, integer `priority`, and optional `expires_at_ms` in
`X-Gatehouse-Command`. `provider_team_id` is a stable 1–160 character visible ASCII identifier using
only characters `!` through `~`. The secret is the bounded `application/octet-stream` body. The
final SQLite transaction creates the account
principal, team quota scope, workload credential binding, immutable provider/`TEAM` identity
reservation, native credit dimension, fill-first pool and member, disabled observation schedule,
immutable initial state event, mutation result, and audit event. Gatehouse HMACs the declared ID
immediately with an installation key; only the fingerprint is persisted. Provider/kind/fingerprint
uniqueness plus one identity per quota scope prevent duplicate declarations from becoming two
balances. One principal may own multiple independently identified scopes.
The DPAPI staging intent makes the cross-store workflow idempotent and restart-recoverable.
An existing pool must be an active Firecrawl fill-first pool. A newly onboarded account starts
`UNKNOWN` pending fresh authenticated balance authority.

Rotation metadata contains `mutation_id` and optional `expires_at_ms`; its secret is also a bounded
octet-stream body. Disable, recover, and remove contain `mutation_id`, matching `action`, and a
bounded non-secret `reason`, with an empty body. Refresh contains only `mutation_id`, with an empty
body. Observation control contains `mutation_id`, `action` (`enable` or `disable`), and a reason,
also with an empty body. Every mutation identifier is bound to its actor and exact safe metadata;
conflicting reuse fails closed.

Account add/rotate/disable/recover/remove responses contain exactly `alias`, `action`, local
`state`, `pool_alias`, `priority`, current workload `generation`, `acted_at_ms`, and
`audit_event_id`. Observation-toggle responses contain exactly `alias`, `action`, `enabled`,
`acted_at_ms`, and `audit_event_id`. Refresh returns the account-status shape below. These are
redacted operator results; none includes a provider or custody secret.

Account status is an exact allowlist:

```json
{
  "alias": "personal-firecrawl-a",
  "state": "HEALTHY",
  "remaining_decimal": "123.5",
  "plan_decimal": "500",
  "unit": "credits",
  "observed_at_ms": 1787548800000,
  "staleness_ms": 1200,
  "stale": false,
  "source": "account-manual-refresh"
}
```

Visible states are `HEALTHY`, `EXHAUSTED`, `UNKNOWN`, `DISABLED`, and `QUARANTINED`. The three
code-owned sources are `admin-credential-validation`, `account-manual-refresh`, and
`scheduled-firecrawl-credit-observation`. Exact values are canonical provider-native decimals, not
floating-point values or converted generic credits. Missing or unrecognized observation provenance
suppresses the observation fields together. A complete code-owned observation may remain visible
with `stale: true` for operator diagnosis, but its effective state becomes `UNKNOWN` unless a
stronger durable disabled, quarantined, or exhausted state applies, and it cannot authorize
positive-cost routing. The view never returns a credential identifier, generation,
principal/scope/pool identifier, custody reference, secret, provider body, or header.

The corresponding CLI surface is `gatehouse accounts add`, `list`, `status`, `rotate`, `disable`,
`recover`, `remove`, `refresh`, and `observe enable|disable`. `add` and `rotate` are the only account
commands that open a hidden prompt. CLI removal additionally requires the human to confirm the
account alias. None accepts a secret argument, environment variable, file, redirected standard
input, retrieval, or export option.

The CLI add form requires `--team-id ID`; rotation has no team-ID field because it replaces a key
inside the existing quota scope. Account tombstoning retains the identity reservation. Neither raw
`provider_team_id` nor its HMAC fingerprint appears in the mutation response, status view, or audit
payload. Firecrawl's team-scoped credit response contains no attested team identifier, so the
offline API cannot detect an operator deliberately assigning different declared IDs to two keys
that actually share one team.

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
not accepted. Safe bounded JSON metadata is carried in `X-Gatehouse-Command`. Only account add,
account rotation, lower-level credential provision/rotation, and emergency unlock carry a bounded
`application/octet-stream` secret body; validation, refresh, observation controls, local state
changes, and emergency cancellation require an empty body. Responses use explicit redacted
allowlists and never contain secret material.

An accepted stock Firecrawl secret is namespace-separated: `fc-` plus at least 20 ASCII letters,
digits, `_`, or `-`. `FAKE-` and `synthetic-` values with at least 20 printable suffix bytes are
reserved for no-network tests only. Other body values fail before backend invocation or custody.
This format boundary prevents a credential from being identical to ordinary status, counter, or
HTTP response literals.

The stock CLI obtains every secret body only from an interactive hidden prompt. There is no
secret/API-key argument, environment, file, redirected standard-input, echo, retrieval, or export
path. DPAPI provisioning works while provider channels are disabled and does not enable networking.
Rotation moves the predecessor to `DRAINING` while preserving exact old-generation asynchronous
affinity; disable, quarantine, tombstone, and terminal retirement are local actions and do not
revoke a provider key.

`gatehouse credentials list --limit N` uses `GET /v1/admin/credentials` through one bounded admin
session and validates each response against the strict `CredentialSummary` allowlist. Its output is
redacted metadata only and never opens credential custody.

Credential validation carries only `{"expected_generation": N}` in `X-Gatehouse-Command`. It is
unavailable unless `providers.firecrawl.observer` is configured with both `mode: live` and
`network_enabled: true`.
The backend acquires one exact persistent-generation lease, makes one fixed credit-status read, and
atomically records a sanitized quota snapshot, any resulting durable scope-state transition, and an
audit event. The strict response contains only
credential/generation, service, principal and quota-scope identifiers, authenticated state,
`remaining_units` and optional `plan_total_units` routing projections,
`observed_remaining_units_decimal` and optional `observed_plan_total_units_decimal` exact canonical
values, capture time, and snapshot/audit identifiers. The two plan fields have paired nullability.
Canonical strings are numeric values, not provider lexemes: they omit exponent and insignificant
scale, all signed zeros are `"0"`, negative values are permitted, and the integer projections floor
only positive fractions, clamp negative values to zero, and saturate at signed INT64. It does
not return the provider body, headers, cookies, credential, ciphertext, or custody reference. The
route uses the configured bounded observer slots (one by default, at most eight) with no queue,
retry, failover, emergency fallback, agent capability, or MCP tool. It also rejects before dispatch
if the active SQLite `busy_timeout` exceeds five seconds, preserving the durable lease deadline.

The exact observation fields are administrative-only. They are deliberately absent from agent API,
MCP, dashboard, configuration, and audit schemas.

`accounts refresh` invokes the same typed fixed-endpoint observer for the alias's exact current
workload generation and persists source `account-manual-refresh`. It is disabled unless the separate
observer channel is live and network-enabled. Scheduled observation additionally requires a durable
per-account `ENABLED` schedule. Claims are bounded by `maximum_accounts_per_cycle` and
`maximum_concurrency`; a schedule generation fences concurrent rotation/disable/completion. A
schedule toggle never grants network permission, and neither manual nor scheduled observation can
use emergency custody.

Before entering observer transport, Gatehouse commits one retained `SEND_INTENT` for the exact
request and credential generation. A duplicate request cannot authorize another send. Startup
converts unfinished intents to `UNKNOWN`; unresolved evidence blocks scheduled observation for
that generation. A new explicitly authorized manual observation can resolve earlier uncertainty
only after its successful snapshot and audit commit. It does not replay the old request.

A confirmed zero or negative authenticated balance durably marks the team quota scope
`EXHAUSTED`. A confirmed positive observation may heal `EXHAUSTED`, `UNKNOWN`, or `COOLDOWN`, but
never silently overrides `DISABLED` or `QUARANTINED`. No elapsed timer re-enables an exhausted
scope. Stale, legacy, absent, or corrupt balance authority is unavailable for positive-cost
routing.

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
request binding, including original/current session and root run, client, workspace, fingerprint and
canonicalization versions, pool service/alias, and exact cost unit/value.

An exact approved retry may locate and consume its durable one-use approval even if an MCP process
lost its process-local continuation index during restart. For `firecrawl.crawl.start`, the caller
must reuse the returned stable `request_id`; the API performs a read-only probe of the original
`WAITING_APPROVAL` invocation and emits the pending projection again. The next retry uses a fresh
continuation request with the same approval. It never attempts to restart the waiting parent or
replays an already handed-off crawl.
