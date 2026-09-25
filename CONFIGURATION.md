# Configuration

## Principles

Configuration is declarative and schema-validated. It contains identifiers, limits, policies, paths, and provider metadata—not plaintext credentials. Unknown fields are rejected unless explicitly forward-compatible.

## Workload submission and routing bounds

```yaml
routing:
  maximum_total_provider_attempts: 1
  maximum_route_candidates: 32
```

Only strict integer `1` is supported for the total workload submission limit. Higher values,
booleans, strings, and floats fail validation. Each invocation durably claims that single allowance
before transport entry. No response or connection error permits another same-request send, even
when retry classification would otherwise permit it. This does not guarantee provider receipt or
exactly-once effects, and distinct request IDs remain separate admissions.

The candidate bound is a strict integer from 1 through 32, default 32. Ordinary routing rejects
overflow before materializing an unbounded catalog; it does not truncate an unranked prefix. The
bound conservatively includes configured pool members and all WORKLOAD credential generations,
including inactive history. Exact resource-affinity lookup is independent of unrelated overflow.
Exceeding the bound grants no authority to clean, migrate, or discard existing state.

Missing pool `automatic_failover_within_pool` defaults false, and new pools store explicit false.
Existing explicit Boolean values remain readable. A local authenticated, audited operator action
can enable or disable pre-dispatch fallback:

```text
gatehouse pools failover enable POOL --mutation-id UNIQUE_ID --reason "operator selection"
gatehouse pools failover disable POOL --mutation-id ANOTHER_ID --reason "operator selection"
```

These commands change only the selected ordinary pool's metadata. They do not enable networking,
open a credential, increase the submission limit, or override exact affinity. The mutation ID is
bound to actor, pool, action, and reason fingerprint; conflicting reuse fails closed. No command in
this example is an instruction to run it against existing state.

Workload and observer network switches remain independent. Manual/scheduled observer refreshes are
separate requests and are not included in a workload invocation's one-submission ceiling.

## Main configuration

See [`config/config.example.yaml`](config/config.example.yaml). Major sections cover installation and timezone, loopback listeners, database durability, session and approval TTLs, concurrency and queue limits, runaway detection, retention, reconciliation, watchdog behavior, and provider-scoped workload and observer channels. Before readiness and at `retention.maintenance_interval`, stock maintenance performs one bounded deletion batch, a passive WAL checkpoint, and one bounded complete-footprint observation.

`retention.database_size_cap` governs the stock maintenance observation of the main database plus
its fixed `-wal`, `-shm`, and `-journal` sidecars. A trusted total at 90% of the cap opens one
preserved HIGH retention-pressure alert. Pressure requests one `TRUNCATE` checkpoint and a fresh
measurement. A still-at-cap result, an unavailable observation, or failure to persist the alert
fails the required daemon task closed. The threshold is fixed; there is no separate pressure-ratio
setting.

The same cap remains an earlier guard on untrusted feedback admission. Each candidate is checked
inside its SQLite `IMMEDIATE` admission transaction against a bounded stat-only observation, with
its logical candidate-record bytes projected onto that total. Measurement failure denies the
feedback write with the same sanitized capacity response. SQLite allocates pages and WAL frames,
and mandatory writes or unrelated filesystem changes can occur between observations, so neither
path is a hard or race-free filesystem quota.

Scheduled comparison has separate local bounds and no provider-network authority:

```yaml
reconciliation:
  quick_interval: 6h
  full_interval: 7d
  maximum_snapshot_age: 30m
  maximum_batch_duration: 30s
  maximum_scopes_per_batch: 20
  absolute_credit_tolerance: 5
  relative_tolerance: 0.02
  consecutive_mismatches: 2
```

`quick_interval` is bounded from one minute through 30 days. `full_interval` cannot be shorter than
QUICK and cannot exceed 365 days. `maximum_snapshot_age` is one minute through 30 days;
`maximum_batch_duration` is 100 milliseconds through 60 seconds; and
`maximum_scopes_per_batch` is 1–1,000. `absolute_credit_tolerance` is a strict non-Boolean
nonnegative signed-INT64 integer, `relative_tolerance` is within `[0, 1]`, and
`consecutive_mismatches` is 1–1,000. The scheduler consumes only persisted snapshots. Configuring
these cadences does not enable the independent provider observer.

Before feedback can enter SQLite, the stock daemon also enumerates a bounded set of active
persistent and emergency credentials and compares every submitted string with one short-lived
secret lease at a time. Exact overlap, known credential/capability shapes, or an unavailable
inspection rejects the write without echoing the submitted value; plaintext is never registered as
a long-lived scanner canary.

Gatehouse v1 accepts only the literal listener address `127.0.0.1`. The main loader resolves only a
plain, drive-unqualified relative database path against the directory containing the main
configuration file and then passes that canonical absolute path to every runtime surface.
Drive-relative or root-relative forms are rejected as ambiguous. Database state must use a fixed
local Windows NTFS volume; removable, RAM, unknown and non-NTFS volumes are refused. Unavailable or
malformed volume facts fail before ACL backend construction or creation. UNC/network-share paths,
device namespaces, and mapped remote drives are rejected
before canonicalization. Win32-aliased filename components, including trailing dots/spaces,
alternate-data-stream colons, short-name tildes, and reserved device names, are also rejected.
Missing or malformed file-kind, Windows reparse-attribute or positive link-count metadata is
rejected without safe defaults. Multiply linked mutable-state files are rejected. On Windows, the database
parent must be an absent, empty, or established dedicated Gatehouse state root; managed object names
must have their exact configured or canonical spelling, and an unmanaged or case-variant top-level
object causes startup to fail before any DACL change. SQLite `busy_timeout_ms` is bounded
to `5000` milliseconds per busy handler. Synchronous SQLite and filesystem calls are not
preemptible, so this setting is not an end-to-end request or shutdown deadline.

The stock loader also reads sibling `clients/*.yaml`, `policies/*.yaml`, and `feeds/*.yaml` files.
Configured human-readable client and workspace names are synchronized to stable opaque SQLite
identifiers at startup. Each feed is then synchronized to its resolved opaque workspace and current
compiled policy version; a persisted feed identifier cannot be rebound to another workspace.
Removing a feed file retires its durable row on the next successful startup. Restoring the same feed
ID under the same workspace reactivates it; moving a feed to another workspace requires a new feed
ID so historical cursors and summaries cannot cross the binding.

Initialize that complete topology from the installed, provider-disabled templates with:

```powershell
gatehouse --config C:\path\to\Gatehouse\config.yaml config init
gatehouse --config C:\path\to\Gatehouse\config.yaml config validate --explain
```

Initialization creates the main file plus `clients`, `policies`, `feeds`, and `state` siblings. It
refuses to overwrite any existing target file; review and edit the generated workspace policy before
starting the daemon. Initialization checks document content and topology; it does not establish or
repair filesystem trust. Explicit `config validate` and file-backed stock startup additionally
require the trusted configuration snapshot described below. Validation's JSON explanation is limited
to resolved configuration/state paths, document counts, schema version, database/provider modes,
and the fixed snapshot profile and digest; it never prints configuration document values or
credentials. The digest describes that capture; it is not a capability or permission to launch.
After reviewing the bundle, supply its exact `snapshot.digest` as `--expected-config-digest` to
`gatehoused`, `gatehouse daemon run`, `gatehouse daemon start`, or the watchdog. These consumers
require a fresh matching capture before runtime state, control requests or process creation.
Missing, repeated or malformed expectations fail closed. A mismatch does not mint a replacement.

### Trusted configuration snapshot

The source candidate captures the main YAML, participating client, policy and feed YAML, and the
selected scripted-response manifest as one bounded, immutable in-memory configuration snapshot.
Parsing consumes captured bytes and the captured allowlisted expansion environment. The snapshot
binds the lexical origin, directory membership, file identity, security metadata and content. It
retains bounded canonical manifest bytes so consumers can check each document and scripted
attachment against the captured digest. A conflicting origin or attachment is rejected before
mutable runtime state is opened.

The digest retains ancestor identity and security metadata, but omits sizes and write timestamps
for directories above the private configuration root. Creating an unrelated sibling log or state
file therefore does not invalidate a later startup or control request. Every retained object's
full metadata is still rechecked during capture; configuration-root and captured-file timestamps,
directory membership and content remain bound.

In scripted workload mode, `scripted_responses_path` must name one direct sibling of the main YAML:
either a single filename or an absolute local path with the exact parent spelling and filename
case. Nested or external paths, main-file reuse, aliases, repeated separators, and outer whitespace
are rejected. The scripted file receives the same ownership, ACL, identity and link checks as YAML.
Its bytes are validated before state-path parsing; composition constructs a fresh response queue
from those captured bytes before mutable setup. Stock startup does not reopen the manifest path.
Existing scripted configurations using other locations need a new supported bundle and fresh
validation; the loader does not move files, repair permissions or reuse an earlier manifest.

The supported native admission contract is Windows on a fixed local NTFS volume. The configuration
root, participating directories, and captured files must already be owned by the current user and have
the supported protected, current-user-only DACL. Ancestors use a distinct policy: their ownership
may belong to the current user, SYSTEM, Administrators, or TrustedInstaller, but untrusted grants
that can modify, replace, delete, or change permissions on the configuration path are rejected.
An ancestor's `OWNER RIGHTS` grant is interpreted only through that descriptor's already-trusted
owner. It grants no exception to `CREATOR OWNER` or unrelated identities; retained owner drift
refuses even between two otherwise trusted identities. Private configuration targets still require
the exact current-user owner and supported protected DACL with the user's explicit SID.
Unsupported or unavailable security metadata fails closed. UNC/device paths, ambiguous or aliased
Win32 components, reparse points, nonregular captured files, and multiply linked files are rejected
without resolving them into an apparently trusted path.

The code-owned bounds are not configuration switches:

| Capture limit | Maximum |
|---|---:|
| Captured files, including the main YAML and optional scripted manifest | 64 |
| Enumerated directory entries, including non-YAML names | 128 |
| Bytes per captured file | 1 MiB |
| Aggregate captured file bytes | 4 MiB |
| Retained canonical manifest bytes | 4 MiB |
| Ancestor traversal | 64 |
| Aggregate path text | 64 KiB |

Read-only, non-following handles retain the inspected objects during capture. Identity, volume,
type, security metadata, and file metadata are checked around bounded reads, and directory
membership is checked again. An unavailable check, overflow, or detected change rejects the whole
capture; no partial topology is admitted. These checks are not an atomic filesystem snapshot or a
hostile same-user isolation boundary.

The verifier does not create configuration, repair ACLs, migrate state, or enable a provider.
Standalone `load_*` content readers, configuration initialization and diagnostics do not establish
this trust contract. CLI control operations capture a fresh complete bundle and keep their settings
and capability cache within that operation. CLI and watchdog launch handoffs preserve raw path
spelling until capture and forward the supplied digest with the same frozen, allowlisted expansion
environment. Watchdog database and port overrides must match the captured configuration.
An owned creation request retains its request ID, original private cleanup endpoint, capability
and configuration digest until cleanup succeeds, including when no usable creation response was
received. Durable daemon bindings and cancellation tombstones prevent a late or repeated create
from minting another session. Later configuration changes do not redirect cleanup;
unrelated operations still capture their own bundle. The backend permits one owned session at a
time across controlled launches and short-lived typed operations, and refuses further minting while
cleanup or an indeterminate creation outcome is pending.
The CLI does not persist its cleanup authority across loss of the backend instance.

The long-lived environment is captured before configuration discovery with a bounded allowlist.
Duplicate case-insensitive retained names, non-string or invalid retained values and size overflow
fail with a fixed error; rejected bindings are never silently dropped or coerced. Empty APPDATA/
LOCALAPPDATA values remain distinct from missing names and are forwarded unchanged. Names are
canonical uppercase, but accepted values are neither trimmed nor normalized. Native CLI and watchdog
consumers retain immutable mappings and pass a fresh dictionary to each child. See
[the environment contract](docs/adr/0014-bounded-long-lived-environment.md) for exact limits.

CLI `daemon start` requires the capability-authenticated control status to report `config_digest`
equal to the operation's freshly verified expectation, for both an existing daemon and an owned
child. Missing, null, malformed or mismatched digests fail before readiness acceptance. A decoded
successful response with a bad digest never triggers another launch; an unsuccessful owned startup
retains bounded cleanup of only its child. Older daemons without this field cannot satisfy the
startup contract. Public health responses do not establish this agreement.
The digest identifies the captured bundle reported by the endpoint, not its process identity.
Subsequent control mutations separately require the operation's expected digest on distinct v2
routes, checked before body ingestion and effects. The CLI never falls back to v1 mutation paths.
Owned cleanup sends its original digest even after configuration changes; rejection preserves its
pending record. Subsequent admin-cookie/agent requests remain separate continuity contracts.

The watchdog requires a finite positive readiness timeout of at most 60 seconds; a larger value
may parse as main configuration but cannot start this watchdog. It captures the admin port with
the same expected digest and environment, then verifies
capability-authenticated control status. It accepts only coherent matching status alongside agent
liveness HTTP 200. Missing or mismatched agreement produces a nonzero outcome without restarting
the responder. Only explicit connection failure on both configured listeners permits a restart;
timeouts and malformed or interrupted responses are not absence. `live_degraded` is nonzero;
`providers_disabled` succeeds only when both channels are configured disabled and matching control
status is `DEGRADED_NO_PROVIDER` with `ready=false`. This requires an existing readable installation
capability, which is neither created nor included in printed settings. Synchronous protected-file
reads remain outside the asynchronous probe deadline's preemptive guarantees.
Request-ID cancellation handles a missing or invalid session ID without guessing one. The daemon's
binding survives restart, but recreating the CLI backend or exiting its process loses client-held
cleanup authority; it cannot be reconstructed from the current configuration alone.

Mutable state has its own native admission contract, separate from the read-only configuration
snapshot. It checks fixed-NTFS volume and object facts, retains ancestor and target handles, verifies
owner/DACL authority before effects, and checks private creation and handle-bound ACL updates.
These checks are not a transaction over the whole tree: a later failure can leave an already-visited
prefix tightened. The standalone scripted pathname reader remains a content utility without this
trust contract. Neither source checks nor configuration capture establish installed-candidate
acceptance, executable/import ownership, or hostile same-user isolation.

CLI startup accepts a coherent `READY`/`ready=true` status or `DEGRADED_NO_PROVIDER`/`ready=false`
when both workload and observer channels are fully disabled. Other degraded, inconsistent or
failed-closed states are unsuccessful starts. Fully disabled startup is not live readiness, and
local `READY` does not establish authenticated provider reachability or a successful live workload.

`gatehouse daemon status` also returns the authenticated ordinary-workload projection. It derives
up to 32 distinct pool/operation requirements and 256 effective interactive client/workspace/purpose
bindings. Only configured `ALLOW` work is covered; `ASK` decisions, unattended watcher work and
resource-bound continuations remain separate. Each assessment uses a bounded read transaction and
refuses to adopt or commit an existing caller transaction. It neither reserves capacity nor opens
secret leases, refreshes counters or contacts a provider. Empty verified coverage is `UNCONFIGURED`,
unprovable coverage is `UNVERIFIED`, and lifecycle states that cannot assess work report
`UNAVAILABLE`. The other statuses are `DISABLED`, `DEGRADED` and `READY`; see
[the operational status definitions](OPERATIONS.md#health-endpoints). Public `gatehouse status`
and health endpoints remain lifecycle-only.

## Client profiles

Client profiles define interactive or unattended behavior, approval mode, priority, session and queue ceilings, capability families, explicit workspace bindings, and default provider pool. An interactive
profile uses `approval_mode: dashboard` to allow an `ASK` decision to create a durable dashboard
approval. `deny_on_ask` and `denied` fail closed instead; unattended profiles must use
`deny_on_ask`.

The CLI uses configured client and workspace names for controlled launch. The daemon remains the
authority for the resulting opaque session, workspace, and root-run identifiers. Every profile must
name each permitted workspace explicitly:

```yaml
workspaces:
  allow:
    - example-project
```

The missing v0.0.1 `workspaces` field remains parse-compatible, but it creates no controlled-launch
authority; there is no implicit client/workspace cross-product. The allowlist is unique and
fail-closed. Multiple client profiles may explicitly bind the same workspace and Firecrawl pool so
different tools retain distinct session/root-run attribution without receiving sticky accounts.

## Workspace policy

Workspace policy binds a canonical workspace to allowed services and operations, purposes, target constraints, data classifications, cost ceilings, approval rules, and a default pool. At launch, the
CLI sends its actual existing absolute current directory. The daemon resolves the configured root
and requested directory through links and admits only the root or a descendant, then pins the exact
resolved directory as the child process working directory. Missing, relative, nonexistent,
different-drive, or outside-root directories fail closed.

Project instruction files can tell an MCP client when to request a tool, but they are not parsed as
Gatehouse authorization. Access is enforced by the client profile's `workspaces.allow`, the
canonical working-directory check, the controlled session, and the workspace policy. A project
whose prose says "authorized" still fails if any of those authorities is absent.

For a project that should have automatic typed Firecrawl access, explicitly bind each intended
MCP client profile to that workspace and configure the applicable workspace-policy rule as
`ALLOW`, with its pool and budgets. For a project that should ask each time, it must still be a
configured workspace/client binding, the client must use `approval_mode: dashboard`, and the rule is
`ASK`. An unconfigured directory cannot be elevated by a prompt-time claim; add and review its
policy first. This separates agent guidance (whether to call) from Gatehouse enforcement (whether
the call is allowed, asks, or is denied).

## Runaway detection and bounded burst authority

`runaway_detection.identical_requests` detects repeated equivalent requests and
`aggregate_requests` detects varied high-volume requests within the same configured `window`. The
aggregate threshold cannot be below the identical threshold. Detection is scoped to the exact
session, root run, and service, so another concurrently connected LLM/client is not quarantined.
That boundary follows Gatehouse authority rather than an LLM's internal subagent label: distinct
controlled MCP client launches isolate one another, while native subagents sharing one
`gatehouse-mcp` process/root share the offender unit and require separate controlled launches for
independent quarantine.

The `cooldown` remains a bounded detector-memory parameter; it does not heal a durable quarantine.
An opened quarantine remains blocked across subsequent requests and daemon restarts. There is no
configuration switch that turns prompt text into authority. An authenticated human uses the local
dashboard to deny the burst or grant an explicit operation allowlist and ceilings of at most 15
minutes, 25 requests, 100 credits, and concurrency eight. Expiry, request/credit exhaustion,
unknown usage, or restart closes that bounded authority rather than restoring unrestricted access.

`approvals.windows_notification: true` enables a bounded, best-effort off-request-path signal when a
new durable approval is pending. The stock notifier emits a Windows attention sound; it does not
open a browser, approve, deny, or affect the invocation if its queue/delivery fails. The agent/MCP
response independently carries the validated numeric-loopback dashboard URL so the human can open
the decision surface explicitly. `terminal_prompt` remains fixed `false`.

## Feed sets

Feed sets replace arbitrary watcher URLs with a server-owned named policy object. Each feed must name
one configured workspace and provide an ordered list of concrete synchronous targets:

```yaml
schema_version: 1
feed_set:
  id: research-feeds-primary
  display_name: Primary research feeds
  workspace: example-project
allowed_targets:
  - host: careers.example.com
    path_regex: '^/jobs(/.*)?$'
    operations: [scrape]
  - host: jobs.example-ats.com
    path_regex: '^/company-name/.*$'
    operations: [map]
targets:
  - operation: scrape
    url: https://careers.example.com/jobs
  - operation: map
    url: https://jobs.example-ats.com/company-name/jobs
    limit: 25
```

`targets` contains 1–64 entries and preserves configuration order. The only executable target kinds
in this tranche are `scrape` and `map`. A scrape target owns only its HTTPS URL; Gatehouse fixes its
provider formats, main-content behavior, timeout, purpose, and data classification. A map target must
also declare `limit` from 1 through 100. All targets are validated through `allowed_targets`, target
count cannot exceed `budgets.maximum_requests_per_run`, and total map limits cannot exceed
`crawl.maximum_pages`.

Schedule windows, crawl/page ceilings, and per-run request, credit, and duration budgets remain
required elsewhere in the same feed document. An allowlist entry mentioning `crawl` does not make a
crawl executable: asynchronous crawl targets are explicitly deferred. Missing workspace or concrete
targets fail validation; no implicit workspace or URL is inferred from a client profile.

The stock watcher facade is composed only when Firecrawl workload mode is `scripted`, networking is
false, at least one feed is configured, and the isolated manual-only `watcher-reserved` pool exists.
Disabled and live workload modes do not advertise watcher execution capabilities in this tranche.
MCP selects a scan by feed ID and optional expected cursor; target URLs and provider payload fields
remain configuration-owned.

## Provider runtime channels

Every named provider has independent workload and quota-observer switches. Both default off. The
current Firecrawl shape is:

```yaml
providers:
  firecrawl:
    workload:
      mode: disabled
      network_enabled: false
    observer:
      mode: disabled
      network_enabled: false
      interval: 15m
      freshness_ttl: 30m
      request_timeout: 10s
      maximum_accounts_per_cycle: 20
      maximum_concurrency: 1
```

The workload channel is an explicit three-way switch:

- `disabled` is the default and creates no provider workload route;
- `scripted` requires `network_enabled: false` and a bounded
  `scripted_responses_path`; it creates synthetic, credential-free routing authority for
  no-network verification;
- `live` requires `network_enabled: true`, no scripted manifest, and complete active routes whose
  credential references match current-user Windows DPAPI custody metadata exactly.

The observer channel accepts only `disabled` or `live`. Live observation requires its own explicit
`network_enabled: true`; enabling Firecrawl workloads does not enable observation, and enabling the
observer does not enable workloads. `request_timeout` cannot exceed 60 seconds,
`maximum_concurrency` is bounded to 1–8, and `freshness_ttl` must cover at least one configured
interval. The collector also limits the number of accounts claimed in one cycle. Each account's
schedule remains disabled until an operator separately runs `accounts observe enable`; that
per-account action does not grant network permission.

The v0.0.1 top-level `provider:` workload block remains accepted for configuration compatibility.
New configurations use `providers.firecrawl.workload`; setting both forms to non-default values is
rejected as ambiguous.

The fixed configuration schema also reserves `github`, `openrouter`, `gemini`, `xai`, and
`jarvislabs`. They are provider-neutral foundation identifiers only in this candidate. Any
non-default channel configuration for one of them fails validation because no operation,
credential validator, or network transport is implemented for it yet.

No mode transition retrieves, prints, or sends a credential during configuration validation.
Automated tests use only disabled, scripted, and mock/no-network transports. Live provider use
remains a separately authorized operator action.

## Firecrawl account and pool onboarding

The supported clean-install workflow creates a provider principal, team quota scope, workload
credential binding, immutable provider/team identity reservation, fill-first pool membership,
primary native `credits` dimension, disabled observation schedule, immutable state event, mutation
result, and audit event. It is an idempotent, crash-recoverable custody saga: the secret is first
staged into DPAPI under durable intent, and the
complete routing graph is then committed in one short SQLite transaction. A new account begins in
`UNKNOWN` until an authenticated positive observation establishes fresh balance authority.

Representative commands are:

```powershell
gatehouse accounts add --provider firecrawl --alias personal-a --team-id TEAM_ID --pool personal-firecrawl --priority 10 --mutation-id add-personal-a-001
gatehouse accounts list --limit 50
gatehouse accounts status personal-a
gatehouse accounts rotate personal-a --mutation-id rotate-personal-a-001
gatehouse accounts disable personal-a --mutation-id disable-personal-a-001 --reason "operator maintenance"
gatehouse accounts recover personal-a --mutation-id recover-personal-a-001 --reason "operator reviewed"
gatehouse accounts refresh personal-a --mutation-id refresh-personal-a-001
gatehouse accounts observe enable personal-a --mutation-id observe-personal-a-001 --reason "periodic balance checks approved"
gatehouse accounts observe disable personal-a --mutation-id observe-off-personal-a-001 --reason "periodic checks paused"
gatehouse accounts remove personal-a --mutation-id remove-personal-a-001 --reason "account retired" --confirm-human personal-a
```

`add` requires a non-secret `--team-id`: a stable 1–160 character visible ASCII identifier using
only characters `!` through `~`. It is safe command metadata, not a key. Gatehouse immediately
derives an installation-keyed HMAC fingerprint and persists only that fingerprint as internal
mutation/identity authority, including the immutable provider/team reservation; it never returns or
persists the raw ID. A duplicate declared
Firecrawl team cannot create a second quota scope, and account removal/tombstoning retains the
reservation so re-onboarding cannot resurrect duplicate balance authority. Rotation replaces the
key within the existing scope and does not accept another team identity.

`add` and `rotate` obtain the secret from a hidden interactive prompt. There is no API-key option,
environment variable, YAML field, ordinary-file input, standard-input mode, echo, retrieval, or
export path. All other account commands are secret-free. Every mutation identifier is an
idempotency binding; reusing it with different metadata or another actor fails closed. `remove` is
a local tombstone/retirement workflow, refuses while the account owns active work, and does not
claim to revoke the provider-side key.

For an authorized live rollout, add every independently billed Firecrawl team/account to the same
named pool with explicit priorities, then enable the observer channel separately and run one
`accounts refresh` per alias before workload admission. Enable periodic observation per account only
if desired. Rotation keeps the same account/team quota scope and pool priority while fencing the old
generation and rebinding its schedule. Disable removes the account from routing and disables its
schedule. Recover re-enables pool membership but does not fabricate fresh balance or silently
re-enable the schedule; inspect `accounts status` and refresh explicitly when required.

Firecrawl credit observations are team-scoped, but the response does not contain an attested team
identifier. Gatehouse can therefore prevent duplicate scopes only for equal operator declarations;
offline onboarding cannot prove that deliberately different `--team-id` values do not refer to the
same real Firecrawl team. Operators must use one stable ID consistently for every key sharing that
team balance.

## Credential custody

The current candidate requires a versioned identity-bound DPAPI envelope. Legacy unbound ciphertext
refuses lease opening. Alias, expiry, state and generation remain mutable validated metadata, not
rollback-protected fields. New publication is create-only and cleanup preserves any replacement
detected by its applicable ownership checks. In-flight rollback checks captured file identities.
Once the intent marker is published, restart cleanup also checks its recorded ciphertext and
metadata identities, including their token-derived stages. Before marker publication, restart
cleanup has only the exact token-derived staging names, not a durable identity for every stage;
this is not a universal replacement-resistance guarantee. These operations do not revoke provider
credentials.

Configuration and administrative read models contain only aliases, local state, pool membership,
priority, expiry metadata, credential roles and generations, quota dimensions, exact redacted
observations, and exclusive/shared usage mode. The stock administrative CLI exposes purpose-built
account onboarding, provisioning, rotation, local state changes, observation controls, and bounded
emergency commands, but no secret export or retrieval route. Provisioning writes current-user
DPAPI custody and is available while every provider channel is disabled; it neither changes a
provider mode nor enables networking. Secret-bearing values never belong in configuration.

Account add, account rotation, lower-level credential provision/rotation, and emergency unlock read
the secret only from an interactive hidden prompt. Safe command metadata is sent separately from
the bounded raw secret body after admin-cookie, `Origin`, and CSRF validation. Emergency limits are
request values constrained by hard maxima, not configuration settings: 15 minutes, 25 requests,
100 credits, and concurrency one.

Installation-local control material, the DPAPI installation key, credential ciphertext, the
SQLite database, and the daemon lock live beside the configured database or in its derived state
paths. None belongs in source control.

## Environment expansion

Paths may support a narrow set of Windows environment substitutions such as `%APPDATA%` and `%LOCALAPPDATA%`. Expansion occurs before canonicalization. Arbitrary shell evaluation is prohibited.

## Validation failures

Startup fails closed when configuration is invalid, a pool references a missing scope, an
unattended client uses interactive approval, the watcher lacks reserved capacity, an emergency
pool is selected as a client binding or workspace default, a listener binds outside loopback, a
per-quota-scope limit exceeds its service limit, a sensitive operation lacks a cost/time ceiling,
live workload routing cannot prove exact DPAPI custody, an observer mode/network pair disagrees, an
observer freshness window is shorter than its interval, reconciliation cadence/batch/tolerance
bounds conflict, or a foundation-only provider is configured for use. Policy separately denies
automatic use of the emergency pool. The manual workflow must
name the stock emergency pool and exact interactive session/root authority; it cannot make that pool
a client default or failover target.

Session heartbeat intervals must be between one and 300 seconds. Both `stale_after` and
`reconnect_grace` must exceed the heartbeat interval. The daemon returns the validated cadence to
controlled MCP clients; stale reconnect grace is measured from the missed-heartbeat boundary.

Bootstrap re-exchange is bounded per session. `maximum_active_access_tokens_per_session` accepts
one through four and defaults to one, so a successful exchange rotates out the oldest token before
it can consume another global client slot. When global capacity is greater than one, the per-session
cap must also be strictly lower so one session cannot occupy every token slot.
`maximum_bootstrap_exchanges_per_window` accepts one through 120, while
`bootstrap_exchange_window` is bounded from one to 300 seconds. The in-memory
rate tracker is itself bounded, and exchange-capacity failures return a typed HTTP 503 response with
bounded `Retry-After` guidance.
