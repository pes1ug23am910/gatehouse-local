# Security

## Security objective

Gatehouse reduces accidental credential exposure, centralizes authorization, bounds provider usage,
and records attributable metadata for concurrent local workflows. Reset-aware comparison and local
quarantine components can evaluate supplied provider-usage snapshots. The stock admin surface can
capture one explicit, sanitized credit-status snapshot for an exact credential generation only in
live mode. The retained observations are validated canonical numeric values, never provider
lexemes or arbitrary decimal objects, and their conservative whole-credit projections are stored
separately. Scheduled Firecrawl credit observation is a distinct, bounded channel that is disabled
by default and requires both its own `live` mode and its own network switch; enabling workload
networking does not enable observation networking.
The stock QUICK/FULL reconciliation task is a separate provider-I/O-free consumer of persisted
snapshots. Its cadence does not grant provider-network authority or make stale evidence fresh.

It does not claim to isolate secrets from a deliberately hostile process running under the same ordinary Windows account in v1.

## Mandatory controls

- Provider credentials are encrypted at rest with a Windows user-scoped KeyStore implementation.
- Credentials are never written to tracked files, ordinary configuration, command arguments, persistent logs, dashboard HTML, agent/MCP responses, or client results. LLMs receive typed operation
  results, never keys to dispatch themselves.
- Provider credentials are never injected into client environments.
- Provider-side limits and least-privilege scopes are mandatory.
- Persistent emergency credentials are forbidden. A manual unlock stores its secret only in the
  process-local in-memory KeyStore and never makes the emergency pool eligible for automatic use.
- Every provider dispatch names exactly one custody class. `PERSISTENT` dispatches may open only
  persistent custody and `EMERGENCY` dispatches may open only the process-local emergency store;
  neither class may fall back to the other, including when identifiers collide.
- Credentials for services outside the v1 provider allowlist are not admitted.
- Agent and administrative authentication are separate.
- One installation-scoped operating-system lock prevents concurrent stock daemons from recovering
  or serving the same database.
- Every wait, approval, retry, queue, lock, lease, and job has a time or count bound.
- Before readiness and periodically thereafter, a required worker bounds retention work, checkpoints
  WAL, and observes only the main database plus three fixed SQLite sidecars. The exact 90% pressure
  band uses one path-free HIGH alert and one truncating-checkpoint remeasurement; an unavailable
  observation, still-at-cap result, or alert-persistence failure enters `FAILED_CLOSED`.
- Scheduled QUICK/FULL comparison uses persisted snapshots only, bounded scope/time batches, exact-
  decimal policy, current-observation deduplication, and atomic result/alert/quarantine/baseline
  advancement. Unexpected task or persistence failure enters `FAILED_CLOSED`.
- Every automatic route stays inside one explicitly named same-service pool. No fallback crosses a
  provider boundary, and emergency authority is never a default or automatic fallback candidate.
- `fill_first` shares the deterministic leading eligible quota scope among concurrent callers while
  its reservation and dispatch headroom remain available. Session, root-run, or LLM identity does
  not receive an implicit exclusive account; spill occurs only after bounded capacity admission says
  the leading scope cannot safely accept that dispatch.
- A retry-safe Firecrawl 429 advances to later distinct pool scopes only when bounded same-account
  retry would otherwise fail because reset guidance is absent, attempts are exhausted, or the delay
  cannot fit the request deadline. Reconcile-first/side-effecting or ambiguously submitted work never
  sprays, and each later scope is visited at most once.
- Repeated-equivalent and aggregate bursts open a durable quarantine for the exact
  session/root-run/service offender and fence fresh session/root admission for the same client
  profile. Timer expiry cannot heal it. Only the authenticated local dashboard may issue a
  generation-fenced, operation-allowlisted burst for the old root or recover one exact generation
  after safely terminating the old authority; prompt text and MCP/agent/CLI calls have no decision
  or recovery authority.
- Controlled launch requires an explicit `workspaces.allow` client binding and an existing absolute
  working directory that resolves to the configured canonical workspace root or a descendant.
  Project instruction files are agent guidance, not Gatehouse authorization.
- Unattended clients cannot wait for approval.
- Request and response bodies are not persisted by default.
- A generic authenticated HTTP proxy is prohibited.
- A secret export or retrieval operation is prohibited.
- Administrative credential validation is unavailable outside explicit `live` plus
  `network_enabled` mode. It is bound to one healthy persistent generation, one fixed read-only
  provider endpoint, one in-process slot, a 10-second provider-request timeout, a 15-second
  end-to-end dispatch deadline, a 64 KiB response ceiling, and no queue, retry, redirect, ambient
  proxy, emergency credential, pool selection, or failover. Validation also fails closed when the
  active SQLite `busy_timeout` exceeds five seconds so acquisition, heartbeat, evidence commit, and
  release cannot outlive the durable generation fence.
- A live validation transport attempt that fails records `credential.provider_validation_failed`
  with only `actor_id`, the local `credential_id`, `credential_generation`, a stable `error_class`, and
  `outcome: failed`. Provider bodies, headers, reason text, request identifiers, retry-after values,
  and exception data are prohibited. The event proves that the validation service invoked its live
  transport, not that HTTP submission occurred or the provider received the request. Disabled,
  scripted, service-local rejection before transport invocation, and cancellation record no such
  event. Failure to persist the event fails closed as a generic
  persistence or daemon-degraded error without disclosing provider details.
- Invalid numeric content in an otherwise successful credit-status response—including duplicate
  keys, non-standard constants, out-of-envelope counters, explicit nulls where a counter is present,
  or projection inconsistency—is a sanitized `MALFORMED_RESPONSE`. It creates the one bounded
  failure audit above and no success snapshot. Non-200 credit-status bodies are discarded without
  decoding after transport security and size checks. Their status classification remains
  authoritative; an unexpected 2xx is always a non-retryable `MALFORMED_RESPONSE`.
- A known quota balance must be anchored to an immutable snapshot with matching scope, unit,
  capture time, projected integer, canonical observation, and recomputed projection. Catalog reads
  and the atomic positive-reservation transaction require fresh authenticated authority and fail
  closed to unknown/ineligible on expiry or any mismatch; the exact code-owned scripted authority is
  the only no-network exception. Reads never repair or refresh authority.
- Supported Firecrawl account onboarding requires a stable operator-declared team ID and immediately
  replaces it with an installation-keyed HMAC fingerprint. The raw ID is never persisted or
  returned; provider/`TEAM` fingerprint uniqueness and one-identity-per-scope invariants prevent the
  same declared billing scope from becoming two balances, including after tombstone/re-onboarding.
- A definitive non-emergency quota failure atomically commits the terminal attempt and a
  generation-fenced `EXHAUSTED` event before failover. Exhaustion survives restart and timer expiry;
  only a newer authenticated positive observation or an explicit audited operator recovery can
  restore `HEALTHY`, after which ordinary freshness and available-capacity checks still apply.
- Firecrawl 402 failover visits each later eligible distinct quota scope in the immutable named-pool
  plan at most once. A 401 can advance only to another eligible credential in the same quota scope.
Permission denial and unknown outcome never spray across accounts, and transient same-credential
  retries retain their independent finite bound.
- Asynchronous resource and job access is fenced by the creating session, workspace, root run,
  request, provider principal, quota scope, credential generation, and pool.

## Same-user residual risk

The daemon and clients run under the same Windows account. A process with unrestricted execution under that account may be able to access user-scoped protected data or inspect another ordinary process, depending on operating-system controls.

Gatehouse therefore focuses on making compromise bounded and visible:

- low provider balances and hard provider-side limits;
- per-session and per-run budgets;
- narrow operation schemas;
- explicit account pools;
- restricted watcher target and schedule policy;
- reset-aware scheduled QUICK/FULL off-ledger reconciliation and local quarantine over persisted
  snapshots, with an explicit admin-only counter capture and a separately gated, default-disabled
  bounded Firecrawl observer for obtaining new live observations;
- generation-fenced local rotation plus separate operator-run provider validation and
  provider-side revocation procedures;
- no high-spend compute credential in v1.

The filesystem-footprint control is sampled, not an operating-system disk quota. SQLite page/WAL
allocation and mandatory audit, quarantine, cancellation, reconciliation, and cleanup writes can
grow state between observations. Failing closed limits further stock operation but cannot guarantee
that the configured byte count was never crossed or reclaim space needed to preserve incident
evidence.

The provider-team identity guard depends on truthful, consistent operator declaration. Firecrawl's
team-scoped credit response does not attest a team identifier, so a deliberately different pair of
declared IDs for keys sharing one real team cannot be detected offline. This is a residual
configuration-integrity risk; authenticated counter refresh does not prove identity equality.

## Credential classes

Persistent active credentials must be dedicated to Gatehouse where practical, minimally scoped, bounded provider-side, revocable without unrelated impact, and identified in logs only by an internal alias.

The emergency workflow keeps credentials offline while locked and accepts one secret only through
an explicit interactive hidden CLI prompt. One active unlock is bound to an exact service, pool,
session, and root run; permits are synchronous-only and limited to at most 15 minutes, 25 requests,
100 credits, and one concurrent request. It is never selected as a default or failover route.
Cancel, expiry, clean shutdown, and restart immediately close admission and relock it. SQLite stores
only redacted identifiers, aliases, limits, state, and attempt authority—not the secret or a
persistent emergency credential/principal/quota graph.

Persistent custody creation is crash-owned rather than name-owned. The durable mutation journal
records a high-entropy non-secret staging alias before custody creation; DPAPI derives exact staging
paths from that token and publishes a matching non-secret intent marker before ciphertext and
metadata. Recovery deletes only absent material or artifacts proven to belong to that exact alias.
Mismatched markers and unrelated filesystem collisions are preserved and cleanup remains unresolved.

## Watcher security

The watcher security model is implemented in feed-set, policy, scheduler, and persistence
components, but the stock watcher execution facade is not yet wired end to end. Under that model,
the watcher receives a purpose-built feed-set operation rather than arbitrary provider access. Its
policy binds the client identity, schedule window, feed-set identifier, target host and path
patterns, provider pool, operation sequence, request and credit budgets, maximum runtime, and one
active run.

Exact in-envelope impersonation may be indistinguishable in v1, but it remains bounded by this policy.

## Sensitive-data handling

The policy engine hard-denies known sensitive classifications, including credentials and private keys, private documents, identity documents, résumés unless a separate explicit policy exists, and sensitive personal information.

Heuristic secret detection is supplementary, not the sole enforcement mechanism.

While an active credential buffer is available, its exact bytes must not overlap any serialized
non-secret mutation, audit, result, custody-reference, marker, filename, or metadata surface.
Checks include mapping keys and JSON scalar spellings, not only string leaves. An overlap aborts
before publication where possible and otherwise invokes ownership-fenced cleanup; it is never
accepted merely because schema validation succeeded.

The secret scanner may preserve the dedicated validated exact-provider-number wrapper so exact
credit parsing survives sanitization, but it still scans that wrapper's canonical representation
for registered canaries. Arbitrary `Decimal` instances receive no such privilege. Active-credential
redaction likewise keeps a clean wrapper typed instead of converting it to an ordinary string.

Provider HTTP is stateless. The transport strips inherited cookies, clears its jar around each
handoff, rejects `Set-Cookie`, and exact-checks response header names, values, and bounded body bytes
against the leased credential before parsing. A reflected credential yields no response data and
all retained request, response, cookie, and mutable body handles are scrubbed. The admin CLI scopes
its required login cookies to one bounded session, forbids `Set-Cookie` on binary secret-mutation
responses, and clears the jar on any request failure before attempting logout.

## Administrative decisions

Dashboard and CLI approvals bind the request fingerprint, session, service, operation, target,
pool, cost ceiling, one-use ceiling, and expiration. Approval and denial use one immediate
file-backed compare-and-set transaction, so concurrent actors have exactly one winner. An agent
bearer token cannot authenticate the admin realm.

The agent response may include only a fixed numeric-loopback `/dashboard` URL and redacted
decision context. The MCP shim has no approval tool. It retains at most a bounded process-local
continuation index keyed with a fresh random HMAC key, releases interrupted claims through a bounded
lease, and never treats prompt text as authority. A durable exact retry rechecks session, client,
workspace, root run, operation, fingerprint versions, pool, cost/unit, expiry, and one-use state.
Pending crawl approval recovery after an MCP restart additionally requires the caller to reuse the
returned stable crawl `request_id`; recovery does not execute the original waiting invocation.
It also requires the same re-adopted durable session/client/workspace/root run; a new controlled-
launch session cannot inherit that approval.

Runaway administration is deliberately narrower than ordinary approval administration: the human
uses the local dashboard form, which supplies the authenticated admin cookie, exact loopback
`Origin`, CSRF token, current quarantine generation, and keyed action token. Neither the CLI nor any
agent/MCP capability exposes burst authorization or fresh-run recovery. The resulting burst permit
remains subject to all ordinary policy, quota, retry-safety, same-provider, and affinity controls. A
restart conservatively orphans active permits, consumes their reserved authority, and closes the
grant for a fresh human decision. The same-client fresh-launch fence includes `AUTHORIZED`, so an
old bounded grant cannot be converted into ordinary authority by exiting its shim and launching a
new root.

Fresh-run recovery is separately confirmed and audited. Within one immediate transaction it
requires no active permit or concurrency, no nonterminal/`UNKNOWN` invocation, attempt, queue, or
job, no usable approval or unreconciled quota/budget authority, and no nonterminal or missing
asynchronous resource affinity. It then revokes the old session, cancels an active old root, advances
the quarantine generation, and writes immutable exact-generation recovery evidence. A stale or
partial recovery record cannot release admission, and no burst counters or operation allowlist are
transferred to the new run.

Provision, rotation, and emergency-unlock requests require an authenticated admin cookie, exact
loopback `Origin`, and CSRF token before their metadata or body is parsed. The CLI has no secret or
API-key option and no environment, file, stdin, or echo fallback: it reads an interactive hidden
secret into a mutable buffer, sends it as bounded `application/octet-stream` beside safe JSON in
`X-Gatehouse-Command`, and zeroes the buffer on every path. DPAPI provisioning remains available
while provider mode is disabled because custody mutation does not enable or contact the provider.
No route exports or retrieves secret material.

The stock Firecrawl boundary accepts only a namespace-separated token shape: lowercase `fc-`
followed by at least 20 ASCII letters, digits, `_`, or `-`. Reserved `FAKE-` and `synthetic-`
namespaces exist only for no-network verification. This makes accepted credential material
disjoint from durable state names, numeric counters, HTTP media types, and Gatehouse identifiers;
out-of-namespace input is rejected before custody or mutation and is never live-provider evidence.

Rotation creates a successor with a fenced generation and makes the predecessor `DRAINING`; exact
asynchronous affinity remains on the predecessor generation. Disable, quarantine, and terminal
`RETIRED` are local states only. They neither revoke a provider credential nor make a network call.

## Crash authority

A successful asynchronous provider creation is not represented by a provider identifier alone. The
initial attempt freezes the exact credential, principal, quota scope, generation, and pool before
handoff; its terminal update checkpoints resource type, provider identifier, generation, and pool
against that immutable dispatch fact. A later local state or generation fence cannot rewrite a
known send. Startup reconstructs affinity only when the checkpoint agrees with every durable owner
and the frozen authority; partial or conflicting authority fails closed. Terminal job usage is
likewise checkpointed in `SETTLING` before quota and budget ledgers change, preventing a restart from
dropping or duplicating known cost. Its final commit atomically moves the exact resource affinity to
matching terminal evidence; ambiguous `UNKNOWN` work remains active and continues to fence local
credential retirement.

An ambiguous provider handoff is never treated as a capacity or availability signal. Gatehouse does
not replay the operation or move it to another credential, account, emergency unlock, or provider;
it retains the reservation and exact affinity until reconciliation establishes a known outcome.

## Logging

Persisted metadata may include timestamp, session and root-run identifiers, service and operation, normalized target summary, request fingerprint, request and response sizes, status, latency, retry and error class, estimated and actual usage, pool/principal/credential aliases, and policy or approval identifiers. A quota snapshot may additionally retain canonical exact observations and their projected integers; it never retains the provider numeric lexeme or body. The credential-validation failure event is narrower: its payload is limited to `actor_id`, local `credential_id`, `credential_generation`, stable `error_class`, and the failed outcome. The singleton database-retention-pressure alert retains only its fixed status band; database paths and byte counts are excluded.

Persisted records must not include provider credentials, session bootstrap capabilities, access tokens, authorization headers, full request or response bodies, page content, or private document content.

They also must not include the raw operator-declared provider team ID. Only its installation-keyed
HMAC fingerprint may be persisted as internal mutation-binding and immutable identity-reservation
authority, and neither the raw ID nor fingerprint is permitted in account status, mutation results,
or audit payloads.

## Incident response

For suspected credential compromise:

1. disable or quarantine the credential locally;
2. stop new leases from the affected quota scope;
3. capture canonical provider-counter values, their projections, and relevant audit metadata;
4. separately revoke or rotate the provider credential through the provider;
5. inspect off-ledger usage and affected operations;
6. confirm provider-side limits and account state;
7. run full reconciliation;
8. restore service only after a clean result;
9. record the incident and corrective action.

## Vulnerability handling

Report security findings privately to Yash Verma at
[`pes1ug23am910@pesu.pes.edu`](mailto:pes1ug23am910@pesu.pes.edu). Include the affected version,
impact, and minimal reproduction steps, but do not email provider credentials, Gatehouse bearer
material, private response bodies, or other secrets. Do not disclose exploit details through a
public issue before the maintainer has had an opportunity to assess the report.
