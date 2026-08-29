# Operations

## Startup model

Gatehouse v1 runs under the normal Windows account. The supplied scripts can register the daemon at
user logon and a one-shot watchdog with Task Scheduler. The same validated configuration path is
passed to both processes. Registration launches both modules through the installed environment's
`pythonw.exe` in isolated/no-bytecode mode, so the recurring tasks do not create interactive console
windows or source-tree bytecode caches. The entry points replace the GUI interpreter's absent
standard streams with the null device before runtime startup.

For agent-facing use, keep the single `gatehoused` process running as the central custody,
authorization, accounting, and routing service. An MCP client starts a controlled
`gatehouse-mcp` stdio shim only when that client session needs Gatehouse tools. The shim talks to the
daemon over loopback and never owns or returns a provider key; it is not a second credential daemon.
This is the supported background topology, not a claim that a particular machine has already
registered or enabled the supplied Task Scheduler entries.

The stock daemon acquires an operating-system file lock derived from the configured database path
before migration, recovery, provider setup, or listener startup. A competing daemon exits without
mutating database state or binding a second listener. The lock is released on clean shutdown and by
the operating system after process failure.

### Private mutable state on Windows

The configured database parent is Gatehouse's dedicated mutable-state root. This applies equally to
the default `%LOCALAPPDATA%\Gatehouse\state` location and to an operator-relocated database. Startup
refuses to change its DACL when the directory contains an unmanaged top-level object, so a profile,
configuration, workspace, or other shared/multipurpose directory fails closed before its permissions
change. An absent or empty dedicated root is accepted, as is an established root containing only the
exactly spelled configured SQLite files and canonical Gatehouse lease, installation-key, control-capability, and
`credentials` objects. After that preflight, startup removes inherited access from the root, makes
the current Windows account its only DACL trustee with full control, protects the DACL from later
parent inheritance, and lets new database sidecars and custody files inherit that owner-only rule.

Configuration loading rejects a symlink, junction, or other reparse point in any existing database
path component before canonicalization. UNC/network-share paths, device namespaces, and mapped
remote drives are also rejected because mutable WAL state must remain on a local Windows drive.
Win32-aliased components (trailing dots/spaces, alternate-data-stream colons, 8.3 short-name tildes,
reserved device names,
and other forbidden filename characters) are rejected before filesystem mutation so they cannot
alias a fixed Gatehouse state object.
Before creating the daemon
lease or opening SQLite, startup then verifies the root owner and resulting DACL. The watchdog
performs the same root/database/sidecar check before its writable restart-accounting open. Startup
also re-secures an existing database and its WAL/journal sidecars, lease, installation key,
control-capability files, and every bounded regular object in the credential-custody subtree. A
reparse point at a managed object, a non-regular filesystem object, an owner other than the current
account, an over-bound entry-count or aggregate path-text custody tree, or an unavailable Windows ACL
API fails closed. Tree structure, types, and bounds are preflighted before its first ACL write. A
custody-specific failure is surfaced only as the sanitized typed credential permissions error;
Gatehouse does not continue on the assumption that `chmod(0o600)` created a private Windows DACL.

For a relocation, create or copy the dedicated directory and managed files as the same Windows
account that runs Gatehouse, remove unrelated notes/backups from its top level, use a path with no
junction or symlink component, and then start the daemon once to apply and verify the policy. Do not
grant another user access afterward. Non-Windows source
development keeps the host permission model and does not attempt Windows DACL calls; production
DPAPI custody remains Windows-only. Windows does not provide a transaction spanning DACL changes on
multiple filesystem objects: a later owner/API failure can leave an already-visited prefix tightened,
and a filesystem replacement between preflight and use has the same limitation. Correct the fault
and rerun startup. This policy separates ordinary Windows accounts, but it is not an isolation
boundary against the same account modifying its own files after verification or against a privileged
administrator taking ownership.

During `RECOVERING`, incomplete provision and rotation journals are reconciled against their exact
custody-intent alias. The DPAPI store may remove an absent or exactly owned marker, partial, or
token-derived staging file; it deliberately preserves mismatched markers and unrelated collisions.
An unresolved mutation remains cleanup-required and its candidate must not be routed. Do not delete
unknown custody artifacts manually or reuse their identifiers as a shortcut around this fence.

Migration 9 validates v8 quota integers, reconciliation tolerance sources, and every anchored
balance watermark before adding canonical decimal observation columns. A malformed anchor or
unprovable tolerance aborts the whole migration at schema version 8. Valid anchors are preserved;
unanchored legacy balance caches are cleared because they are not provider evidence and require a
fresh authenticated snapshot before live positive-cost routing can be re-armed. Do not restore or
hand-edit those caches.

Migration 10 is append-only and preserves the v0.0.1 identifiers and migration history. It validates
existing principal, credential, scope, state, and generation rows before adding provider-neutral
identity kinds, credential roles, native quota dimensions, authenticated snapshot provenance and
freshness, immutable generation-fenced quota-state events, and bounded observation schedules. Any
invalid legacy row aborts the migration as one transaction. Do not delete dimension or state-event
rows, hand-edit generations, or downgrade the database to bypass an ineligible scope.

Migration 11 is append-only over versions 1–10. It adds durable offender-scoped
`runaway_quarantines` and one-use `runaway_burst_permits`, with database owner and authority
triggers. Existing sessions, invocations, accounts, quota history, approvals, and release evidence
are not rewritten. On restart, any formerly active burst permit becomes orphaned with unknown cost,
the request/credit reservation remains consumed conservatively, and its authorization closes until
a fresh human decision; do not edit permit or quarantine generations manually.

Migration 12 is append-only over versions 1–11. It adds immutable
`provider_quota_scope_identities`: one installation-HMAC fingerprint for each declared
provider/identity-kind combination and one identity reservation per quota scope. Existing v0.0.1
and candidate history is not rewritten. The migration does not invent identities for legacy
scopes; new supported account onboarding requires one. Tombstoning keeps the reservation. Do not
delete an identity row or copy its fingerprint to manufacture another spendable balance.

Migration 13 is append-only over versions 1–12. It adds immutable
`runaway_quarantine_recoveries` and a client session-capacity lookup index. It performs no recovery
backfill and does not rewrite v0.0.1, provider identity, account, quota, or release evidence. Do not
edit quarantine generations or insert/delete recovery rows manually; only the authenticated local
dashboard action may establish the transactionally checked recovery evidence.

Migration 14 is append-only over versions 1–13. It adds only the composite and partial indexes used
by bounded periodic retention. The configured row limit applies independently to each retained data
class during one maintenance wake. Within the debug-excerpt class, explicit expiry runs first;
maximum-age cleanup then uses only the remainder of that same budget. Both branches use separate,
deterministically ordered range scans. Migration 14 rewrites no retained row or prior migration
evidence. Do not remove or replace these indexes: the stock maintenance loop requires the exact
current migration ledger and fails closed rather than running unindexed cleanup.

Migration 15 is append-only over versions 1–14. It adds per-scope QUICK/FULL reconciliation
baselines and last-checked times, one generation and exact last-result pointer, due-order indexes,
and triggers that require every pointer to remain within its scope. Existing reconciliation and
snapshot rows are not rewritten. New scopes initialize both baselines from their first real
snapshot; populated upgrades use only existing scope-owned snapshot evidence. Do not edit baseline
pointers or schedule generations manually.

## Health states

- `RECOVERING` — migration, integrity, authority recovery, the initial bounded
  retention/checkpoint/footprint and scheduled-reconciliation batches, and the initial due-job pass
  are in progress.
- `READY` — mandatory components and the first recovery pass are available.
- `DEGRADED_READ_ONLY` — status, docs, audit, and diagnostics available; provider calls denied.
- `DEGRADED_NO_PROVIDER` — policy and persistence healthy; no eligible provider credential.
- `DRAINING` — no new provider work during shutdown.
- `FAILED_CLOSED` — policy, migration, integrity, or redaction safety failure.

The process can be live while it is not ready. Provider admission remains closed throughout
`RECOVERING` and `DRAINING`; the readiness endpoint returns success only for `READY`. If composition
fails before normal control is available, the health-only `FAILED_CLOSED` fallback expires after the
configured watchdog readiness window (capped at five minutes) so it cannot retain the ports
indefinitely.

## Health endpoints

```text
GET http://127.0.0.1:47621/health/live
GET http://127.0.0.1:47621/health/ready
```

Suggested watchdog defaults:

```yaml
interval: 2m
readiness_timeout: 30s
maximum_restarts: 5
restart_window: 10m
crash_loop_cooldown: 15m
```

The watchdog uses a restart lease to prevent simultaneous restart attempts.

## Installed control

```powershell
gatehouse --config C:\path\to\config.yaml config init
gatehouse --config C:\path\to\config.yaml config validate --explain
gatehouse --config C:\path\to\config.yaml diagnose
gatehouse --config C:\path\to\config.yaml diagnose --support-bundle C:\path\to\new-support.json
gatehouse --config C:\path\to\config.yaml daemon start
gatehouse --config C:\path\to\config.yaml status
gatehouse --config C:\path\to\config.yaml dashboard
gatehouse --config C:\path\to\config.yaml credentials list --limit 50
gatehouse --config C:\path\to\config.yaml credentials validate CREDENTIAL_ID --generation 1
gatehouse --config C:\path\to\config.yaml daemon stop
gatehouse-watchdog --once --config C:\path\to\config.yaml
```

`config init` is offline and non-overwriting. `config validate --explain` loads the complete runtime
configuration without starting the daemon. `diagnose` also stays offline: it opens an existing
database read-only, never creates or migrates one, applies a bounded SQLite step budget, and reports
only fixed configuration/schema/integrity/alert categories, counts, paths, and degraded component
names.
It also reports configured numeric-loopback ports, lease-file presence without disclosing an owner
identity, and at most 20 recent stable alert-category summaries. It exits with status 1 when the
sanitized report has a degraded component. `--support-bundle` writes a create-only JSON artifact of
at most 64 KiB. The bundle omits paths, configuration text, database rows, alert titles/summaries,
identifiers, environment values, and secret-shaped material; the CLI reports its size and SHA-256.
These commands do not contact a provider or probe a listener. Review even a sanitized bundle before
sharing it, and never overwrite an earlier incident artifact in place.

`daemon start` launches the installed `gatehoused` without a shell and waits only for bounded local
liveness/readiness evidence. `status`, approval actions, dashboard login, policy explanation,
documentation, and feedback use bounded loopback clients with redirects and ambient proxy settings
disabled. Daemon and watchdog children inherit only an allowlisted set of operating-system paths,
temporary directories, locale values, and trust-store locations; arbitrary shell variables and
Python injection controls are not retained. Controlled client launch separately scrubs
provider-secret environment variables before adding the one-session Gatehouse bootstrap authority.

Each client profile must explicitly bind the requested workspace in `workspaces.allow`. Run the
controlled launch from the actual project root or a descendant:

```powershell
Set-Location C:\path\to\configured-workspace
gatehouse --config C:\path\to\config.yaml run editor-one --workspace example-project -- gatehouse-mcp
```

The CLI and daemon both resolve the working directory; the daemon admits only an existing absolute
directory inside the configured canonical workspace and returns that exact directory for the child
process. A project instruction file may guide the agent to call Gatehouse, but it does not grant
access. Unconfigured client/workspace pairs, legacy profiles missing `workspaces.allow`, or launches
from another directory fail closed. Separate MCP client profiles may bind the same
workspace/pool and remain separately attributable.

### Register the MCP shim with a client

Register Gatehouse as a stdio MCP server in each client's per-user configuration, not in the
project. The command is `<GATEHOUSE_EXE> --config <GATEHOUSE_CONFIG_YAML> run <CLIENT_PROFILE>
--workspace <WORKSPACE_ID> -- <GATEHOUSE_MCP_EXE>`, with absolute paths from the installed
candidate. These paths and the profile/workspace names are non-secret; never add a provider key to a
registration. Do not pin a working directory on a globally visible entry: the wrapper must inherit
the directory the client was actually launched from, and `--workspace` fails closed outside the
configured root. Give each client its own Gatehouse profile; profiles may bind the same workspace
and pool while remaining separately attributable.

## Graceful shutdown

```text
state → DRAINING
reject new provider invocations
continue status and cancellation
wait up to drain deadline
cancel queued work
run one final bounded due-job/cancellation pass
checkpoint the SQLite WAL
release local leases
exit
```

The stock lifecycle currently uses a five-second drain deadline. Queued or in-flight work cannot
extend shutdown indefinitely. A required listener, scheduler pump, job-supervisor,
database-maintenance, or enabled observation task failure changes the daemon to `FAILED_CLOSED` and
returns a failing process status.

## Provider modes

Keep `providers.firecrawl.workload.mode: disabled` for configuration and control-plane operation
without a provider. The legacy `provider` block remains accepted for v0.0.1 configuration
compatibility; do not configure both surfaces. Use `scripted` only with a local response manifest
when deterministic, no-network behavior is required. Scripted synchronization creates or reuses one
deterministic synthetic 1,000,000-credit quota snapshot, anchors the scope to it atomically, and never
refreshes its timestamp or replenishes settled usage on restart. `live` additionally requires the
workload channel's `network_enabled: true` and validated DPAPI-backed routing metadata. Those
settings make the workload transport available; an actual call still requires ordinary session,
policy, fresh quota, and any applicable approval admission. Gatehouse has no separate global
"operator authorized" runtime switch. Project operating procedure therefore requires explicit
human authorization before live use. Live mode is not part of routine tests.

The Firecrawl observer is a separate network channel. It remains off unless both
`providers.firecrawl.observer.mode: live` and its own `network_enabled: true` are set. Workload live
mode does not enable it. Its interval, freshness TTL, request timeout, maximum accounts per cycle,
and concurrency are bounded; default configuration is disabled with concurrency one. Other provider
channels are registered but reject non-default configuration until their typed operations exist.

## Multi-account routing and durable recovery

Use `gatehouse accounts add --team-id TEAM_ID` to create the provider principal/account, quota
scope, workload credential binding, and named-pool membership as one idempotent lifecycle operation.
The secret is
accepted only by the hidden prompt and goes directly into DPAPI custody; do not put it in arguments,
environment variables, YAML, files, or scripted stdin. `gatehouse accounts rotate` uses the same
custody boundary. Use `accounts list` or `accounts status ALIAS` for the redacted view: alias, durable
state, exact remaining and plan values, observation and staleness times, stale flag, and source.

`TEAM_ID` is required non-secret metadata: a stable 1–160 character visible ASCII value using only
characters `!` through `~`. Choose one stable operator label and reuse it in this installation for
every key billed to the same Firecrawl team. Gatehouse immediately stores an installation-keyed HMAC
fingerprint, never the raw ID, and omits both raw ID and fingerprint from mutation results, status,
and audit. A duplicate declaration cannot create a second balance; removal retains the reservation,
and rotation remains a same-scope key replacement.

Firecrawl's credit response is team-scoped but contains no attested team identifier. The offline
guard can detect equal declarations, not a deliberately inconsistent pair of labels for two keys
that actually share a team. Before onboarding, the operator must establish and consistently reuse
the label; authenticated balance refresh cannot repair a false declaration automatically.

Account priority is deterministic `fill_first`. It is shared capacity, not a sticky account per
session, root run, project, or LLM: concurrent work remains on the leading eligible scope while
fresh balance, atomic reservation capacity, and scheduler/lease headroom allow. A saturated leading
scope may spill to the next eligible member; when all eligible scopes are only temporarily full, the
request queues against the deterministic leader under its normal deadline. Do not change priorities
merely to distribute callers unless that change is the intended billing policy.

Positive-cost routing requires `HEALTHY` plus a fresh authenticated snapshot from the bound current
generation; the exact built-in scripted snapshot is the sole no-network exception. Stale, missing,
legacy, corrupt, `UNKNOWN`, `EXHAUSTED`, `DISABLED`, `QUARANTINED`, or `COOLDOWN` authority is skipped
conservatively at catalog and reservation time.

A definitive Firecrawl 402 atomically marks the current non-emergency scope `EXHAUSTED` with request,
attempt, credential, generation, source, reason, and time before selecting the next scope. Failover
then traverses every later eligible distinct member of that immutable same-provider named-pool plan,
each at most once. A 401 may try only another eligible credential sharing the same quota scope. A
403, permission denial, or ambiguous outcome does not spray. Emergency custody is never examined by
automatic routing or failover, and no fallback crosses providers.

For an operation classified as retry-safe, a Firecrawl 429 first honors a valid retry hint on the
same credential while the per-credential attempt bound and request deadline allow it. Gatehouse
spills to the next eligible distinct scope only if the hint is absent, the bounded same-account
attempts are exhausted, or waiting would consume the remaining deadline. It may then visit every
later eligible scope in the immutable same-provider plan once, including pools larger than three.
A side-effecting/reconcile-first operation, evidence that submission may have occurred, permission
failure, or unknown outcome never takes this 429 spill path. This is failure avoidance, not routine
load distribution.

`EXHAUSTED` survives subsequent requests, daemon restart, and expiry of any short in-memory breaker.
Use `gatehouse accounts refresh ALIAS --mutation-id ID` for one authenticated refresh only when the
separate observer channel is explicitly live. A newer authenticated positive observation may recover
the scope automatically. Otherwise `gatehouse accounts recover ALIAS --mutation-id ID --reason TEXT`
is the explicit audited override. Recovery changes durable state but does not fabricate a fresh or
positive balance, so ordinary authority and reservation checks may still reject dispatch. Use
`accounts disable` to close local routing; removal and provider-side revocation remain separate
operator decisions.

## Runaway quarantine and human burst authorization

Repeated-equivalent requests and varied aggregate request bursts are measured separately for each
exact session/root-run/service authority. Once either threshold is reached, Gatehouse durably blocks
that offender and returns `runaway_suspected` with a redacted quarantine identifier, reason code,
scope, state, trigger, and fixed numeric-loopback dashboard URL. Existing request detection remains
exact to that offender and unrelated client profiles remain eligible. Every fresh session or root
run for the offender's client profile is fenced until each quarantine has exact-current-generation
recovery evidence, including while an old root is `AUTHORIZED`.

This isolation unit is Gatehouse authority, not a client-side label. Native subagents multiplexed
through the same `gatehouse-mcp` process and root run share one session/root/service offender unit
and can quarantine one another. A separate controlled launch under the same client profile cannot
escape the fence; independent isolation requires a separately configured client profile.

Open the local dashboard and either deny the request or authorize only the required typed
operations. The form requires a reason and explicit duration, request, credit, concurrency, and
operation bounds; hard maxima are 15 minutes, 25 requests, 100 credits, concurrency eight, and 16
operations. The dashboard action is protected by the normal admin cookie, exact loopback origin,
CSRF token, a quarantine-generation fence, and a keyed one-use action token. The CLI, agent API, and
MCP tool surface expose no burst-approval command. Telling an LLM "I authorize this" is not a
decision until the human uses the dashboard.

After authorization, retry the exact tool request. Each admitted request atomically consumes one
request and its estimated credits and holds one concurrency slot; settlement accounts for known
actual overrun, while unknown cost exhausts the remaining credit grant. Expiry or exhausted bounds
leave the offender blocked. A daemon restart or orphaned in-flight permit expires the grant and
requires a fresh dashboard decision; no short timer automatically removes the quarantine.

To abandon the old root and permit a future fresh run, use the separate **Close old run and allow a
fresh run** dashboard action. Confirm the displayed exact quarantine generation and supply the
reason. Gatehouse rejects recovery while a burst permit, nonterminal/unknown request, attempt,
queue, or job, usable approval, unreconciled quota/budget record, or nonterminal/unreconstructed
external resource remains. On success it revokes the old session, cancels an active old root, and
records one immutable recovery generation. It does not transfer the old operation, request, credit,
concurrency, account, or credential authority. There is no CLI, MCP, agent, or prompt-text recovery
route.

For an ordinary `approval_pending` result, use the linked local dashboard and then retry the exact
arguments. Gatehouse can consume the exact durable approval once after daemon restart. The MCP shim
keeps only a bounded, process-random-HMAC continuation index and never exposes an approve/deny tool.
After an MCP process restart, reuse the pending crawl's returned `request_id`; Gatehouse verifies and
rehydrates the original `WAITING_APPROVAL` binding without executing that parent request or replaying
an ambiguous crawl. Rehydration requires re-adoption of the same durable
session/client/workspace/root run. A fresh controlled launch has a new session ID, cannot inherit
the prior approval, and creates a new requirement when policy still returns `ASK`. When configured,
the stock notifier adds only a best-effort Windows attention sound; it does not open the dashboard
or make the decision.

## Backup and restore

A backup includes the SQLite database and schema version plus configuration and policy. V1 does not
export credential material. The stock administrative surface exposes redacted credential state and
can provision or rotate secrets into current-user DPAPI custody, but it has no secret retrieval or
export path. A database backup contains custody references and redacted metadata, not a portable
plaintext credential bundle.

Restore metadata to a temporary location, run offline diagnostics and integrity checks, start
degraded with every pool disabled, provision replacement credentials only through a separately
reviewed local custody procedure, reconcile provider balances, and enable pools manually.
Treat a restored balance as known only when its complete scope watermark still matches the named
snapshot's scope, unit, capture time, projected integer, canonical observation, and recomputed
projection. An unanchored cache is not provider evidence.

## Credential rotation

The CLI provision and rotate commands use a hidden interactive prompt. They do not accept a secret
argument, environment variable, file, stdin, or echo fallback. After the admin session, exact
loopback `Origin`, and CSRF checks succeed, the CLI sends safe metadata separately from a bounded
raw secret body and zeroes its mutable buffer. Provisioning can seal DPAPI custody while provider
mode is disabled and does not contact the provider.

The stock command accepts only a lowercase `fc-` token with at least 20 ASCII letters, digits, `_`,
or `-` after the prefix. `FAKE-` and `synthetic-` namespaces are test-only and do not constitute a
usable or verified provider credential. A format rejection occurs before custody or durable
mutation; do not work around it with arguments, environment variables, files, or direct database
writes.

`gatehouse credentials list` opens one bounded administrative session and returns only the strict
redacted credential summary: opaque identifiers, aliases, local state, generation, pool membership,
lease count, and timestamps. It does not open DPAPI custody and has no secret, ciphertext,
authorization-header, retrieval, or export field.

`gatehouse credentials validate CREDENTIAL_ID --generation N` is a distinct live-only operator
action. It takes no secret and is rejected before provider transport in disabled or scripted mode.
With `mode: live` and `network_enabled: true`, it leases that exact healthy persistent generation,
makes one fixed `GET /v2/team/credit-usage` request with a 10-second request timeout, 15-second
end-to-end dispatch deadline, and 64 KiB response ceiling, and records a sanitized quota snapshot
plus audit event atomically. It has no pool choice, emergency fallback, queue, retry, redirect
following, ambient proxy inheritance, or agent/MCP capability. Provider-side observation and
revocation remain separate operator checks. The validation action requires the active SQLite
`busy_timeout` to be at most five seconds; a larger configured wait disables this action rather than
weakening its lease-expiry calculation.

The validation result contains the canonical exact remaining observation and optional plan
observation alongside their conservative integer projections. These strings are normalized numeric
values, not original JSON lexemes: insignificant scale is discarded, negative remaining credit is
provider overage with projection zero, positive fractions are retained exactly and floored only for
routing, and large valid observations saturate only the projection. A missing plan counter remains
absent; an explicit null plan counter is malformed.

After the validation service invokes live transport, provider rejection, timeout, transport failure, or malformed
counters record `credential.provider_validation_failed`. Inspect only its allowlisted `actor_id`,
local `credential_id`, `credential_generation`, stable `error_class`, and `outcome: failed`; the event never
contains provider bodies, headers, reason text, request identifiers, retry-after values, or
exception data. This event does not prove HTTP submission or provider receipt. Disabled or scripted
mode, service-local rejection before transport invocation, and cancellation do not create this
event. If the audit write fails, treat the generic persistence or daemon-degraded result
as a failed validation and investigate local persistence; Gatehouse does not return an event
identifier or replace the original sanitized provider-failure API mapping when the audit succeeds.
The successful counter snapshot and success audit remain one atomic commit.
Duplicate JSON keys, non-standard constants, invalid numeric syntax or bounds, and null or
non-numeric required counters follow this same malformed-counter failure path: one failure audit
after transport invocation and no success snapshot. A non-200 credit-status body is discarded
without decoding after transport security and size checks, so malformed or oversized numeric
content cannot override the HTTP status. An unexpected 2xx is a non-retryable malformed response.

The mutation journal records a fresh non-secret staging alias before DPAPI creation. If the process
stops mid-create, restart recovery removes only artifacts proved to belong to that alias. Preserve
the original mutation identifier for idempotent inspection or retry; a `CLEANUP_REQUIRED` record or
mismatched custody marker requires review rather than broad filesystem cleanup.

Rotation creates a generation-fenced successor under the established principal and quota scope and
makes the predecessor `DRAINING`. New routing moves to the successor. Existing asynchronous
resources remain bound to the exact predecessor credential generation and pool for status,
cancellation, and settlement; rotation does not rewrite that affinity. A known terminal job moves
its exact affinity from `ACTIVE` to matching terminal evidence in the same transaction, while an
`UNKNOWN` result remains `ACTIVE` and blocks retirement until reconciled. After those resources and
leases are resolved, the operator may retire the predecessor locally and separately revoke the old
provider credential. Gatehouse does not perform provider-side validation or revocation as part of
the local mutation.

Disable and quarantine immediately close local routing. `RETIRED` is the irreversible local
terminal state. These state changes are audited and local-only; none implies that the provider has
revoked the corresponding key.

## Emergency unlock

Use `gatehouse emergency unlock` only from an interactive terminal. It requires a reason and exact
service, `emergency-locked` pool, session, and root-run authority; the secret is collected by a
hidden prompt and held only in the process-local in-memory KeyStore. Requested ceilings cannot
exceed 15 minutes, 25 requests, 100 credits, or one concurrent request. Only synchronous manual
work under the exact authority is eligible: crawl creation, client defaults, automatic selection,
and failover are denied.

`gatehouse emergency list` returns redacted status and remaining ceilings. `gatehouse emergency
cancel` immediately closes admission and zeroes/removes the in-memory secret. Expiry does the same.
Clean shutdown and startup recovery relock any formerly active record; restart retains redacted
SQLite authority and attempt evidence but no usable emergency credential.

## Reconciliation

- QUICK cadence: `reconciliation.quick_interval`, six hours by default;
- FULL cadence: `reconciliation.full_interval`, seven days by default;
- on demand: an operator-requested comparison does not advance either scheduled cadence.

The stock daemon runs QUICK and FULL comparisons as one required, provider-I/O-free lifecycle task.
It reads only persisted snapshots and ledger rows through a worker-owned compatible database
connection; it does not enable the separately gated Firecrawl observer or make a provider request.
Each batch is bounded by `maximum_scopes_per_batch` and `maximum_batch_duration`, and the worker is
joined during cancellation so its connection is not orphaned. QUICK and FULL keep separate durable
snapshot baselines and last-checked times. FULL subsumes QUICK at the same current observation;
QUICK does not advance the FULL baseline. The first real observation establishes a baseline rather
than creating an invented historical counter comparison.

Selection, result persistence, mismatch alert/quarantine changes, current-observation deduplication,
and baseline advancement occur atomically for one scope. Reusing a current snapshot can record the
domain result but cannot increment the consecutive-mismatch threshold again. `UNKNOWN`, `STALE`,
and reset results are retained domain outcomes. An unexpected scheduler exit, database/persistence
failure, or invalid durable authority propagates through required-task supervision to
`FAILED_CLOSED`.

The explicit credential-validation command can add one authenticated counter snapshot. The
separately gated Firecrawl observer can schedule bounded counter collection only when its provider
channel and individual account schedule are enabled. When that observer is disabled, scheduled
reconciliation continues over existing persisted evidence but does not manufacture a fresh provider
observation.
Remaining-counter subtraction and within-period plan comparison use exact canonical decimals, even
when projected integers tie. A balance increase is reset detection, not negative usage. Persisted
exact provider and unexplained deltas are authoritative; their legacy signed-INT64 fields are
independently null for fractional or oversized results, while exact integral tolerance is always
retained as a canonical string.

## Watcher operations

Watcher lease, budget, cursor, feed-set, policy, and reservation components are implemented. The
stock watcher execution facade is not yet wired end to end, so the following describes component
behavior rather than an available stock-process workflow: one active-run lease, a successful no-op
for a second launch, and immediate denial rather than an approval wait when policy returns `ASK`.

## Maintenance

Current stock maintenance includes health and status review, database backup and integrity checks,
clean-shutdown WAL checkpointing, incident inspection, and confirmation that emergency unlocks are
either absent or explicitly bounded and that restart recovery relocked prior authority.

Before `READY`, and again at each configured maintenance interval, the daemon performs one bounded
retention batch and requests a `PASSIVE` WAL checkpoint outside the deletion transaction. Each
complete-footprint observation makes at most four non-following stat calls covering the main
database, WAL, shared-memory, and rollback-journal files. A trusted footprint from 90% up to the
configured cap opens or maintains one
preserved HIGH `DATABASE_RETENTION_PRESSURE` alert. Pressure requests one bounded `TRUNCATE`
checkpoint and a fresh complete-footprint observation. Returning below 90% resolves the singleton
alert; reaching the cap keeps critical evidence and fails the required maintenance task closed.
Observation unavailability or pressure-alert persistence failure also produces `FAILED_CLOSED`
rather than silently continuing without storage evidence.

New feedback is still rejected with the ordinary sanitized capacity response when its logical write
projection exceeds the configured observed footprint. That guard sheds one low-priority write class;
it does not shed mandatory state, audit, quarantine, cancellation, reconciliation, or cleanup writes.
The periodic observation is sampled and SQLite allocation is page/frame based, so this is not a
race-free hard filesystem quota. Mandatory evidence can grow the files between observations and may
leave an operator with storage recovery work after the daemon fails closed.

Bounded Firecrawl counter observation is available only through its default-disabled independent
observer switch. Stock scheduled reconciliation does not change that network boundary. Watcher-
success review still awaits the end-to-end stock watcher facade.
