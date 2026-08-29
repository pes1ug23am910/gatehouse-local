# Configuration

## Principles

Configuration is declarative and schema-validated. It contains identifiers, limits, policies, paths, and provider metadata—not plaintext credentials. Unknown fields are rejected unless explicitly forward-compatible.

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
Drive-relative or root-relative forms are rejected as ambiguous. Database state must use a local
Windows drive; UNC/network-share paths, device namespaces, and mapped remote drives are rejected
before canonicalization. Win32-aliased filename components, including trailing dots/spaces,
alternate-data-stream colons, short-name tildes, and reserved device names, are also rejected.
Multiply linked mutable-state files are rejected. On Windows, the database
parent must be an absent, empty, or established dedicated Gatehouse state root; managed object names
must have their exact configured or canonical spelling, and an unmanaged or case-variant top-level
object causes startup to fail before any DACL change. SQLite `busy_timeout_ms` is bounded
to `5000` milliseconds to preserve the frozen responsiveness contract.

The stock loader also reads sibling `clients/*.yaml`, `policies/*.yaml`, and `feeds/*.yaml` files.
Configured human-readable names are synchronized to stable opaque SQLite identifiers at startup.

Initialize that complete topology from the installed, provider-disabled templates with:

```powershell
gatehouse --config C:\path\to\Gatehouse\config.yaml config init
gatehouse --config C:\path\to\Gatehouse\config.yaml config validate --explain
```

Initialization creates the main file plus `clients`, `policies`, `feeds`, and `state` siblings. It
refuses to overwrite any existing target file; review and edit the generated workspace policy before
starting the daemon. Validation uses the same strict main/profile/policy/feed loaders as startup.
Its JSON explanation is limited to resolved configuration/state paths, document counts, schema
version, and database/provider modes; it never prints configuration document values or credentials.

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

Feed sets replace arbitrary watcher URLs with a named policy object containing allowed hosts, path expressions, operation sequence, crawl limits, schedule windows, per-run budgets, and cursor behavior.

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
