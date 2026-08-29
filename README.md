# Gatehouse

Gatehouse is a Windows-local capability broker for credentialed developer services. It gives interactive tools and scheduled jobs a narrow, policy-controlled interface while keeping provider credentials out of prompts, command arguments, ordinary configuration files, persistent logs, and client/LLM responses. Clients receive typed results; they never receive an API key to use themselves.

The first release is centered on Firecrawl because it combines metered usage, multiple accounts, asynchronous jobs, rate limits, and project-specific authorization. The architecture is modular so additional providers can be added without redesigning session identity, policy, quota routing, audit, or recovery.

## Why Gatehouse exists

Local workflows often accumulate API keys across providers and accounts. Directly placing those keys in environment files or terminal processes creates several problems:

- credentials spread across shells, scripts, and configuration files;
- one runaway workflow can exhaust every account;
- account switching is manual and error-prone;
- scheduled jobs can be starved by interactive work;
- usage is difficult to attribute to a session or project;
- retries, approvals, and long-running jobs are not centrally bounded;
- provider-reported usage cannot be reconciled against a local ledger.

Gatehouse addresses these problems with session-scoped capabilities, named credential pools, bounded fair scheduling, atomic quota reservations, request deduplication, policy-only unattended identities, and metadata-only audit records.

## Core capabilities

- **Session-scoped access:** controlled launches mint revocable session capabilities and short-lived access tokens.
- **Typed operations:** clients call provider-specific operations instead of a generic authenticated proxy.
- **Named account pools:** independently billed Firecrawl accounts are centrally onboarded, ordered
  by explicit priority, and shared until fresh quota or dispatch headroom requires bounded spillover.
  Onboarding requires an operator-declared Firecrawl team identity so two keys declared for the same
  quota scope cannot be counted as two balances.
- **Concurrent workload control:** per-session, per-service, per-quota-scope, and global limits prevent one workflow or shared provider balance from monopolizing the broker.
- **Duplicate-burn protection:** equivalent in-flight reads can be coalesced without issuing another provider request.
- **Offender-scoped runaway control:** repeated-equivalent and aggregate bursts durably quarantine
  the responsible session/root run and fence fresh runs for that client profile. The local dashboard
  can authorize a short exact-root burst or, only after all old work is safely terminal, revoke the
  old session and release the exact quarantine generation for a fresh run.
- **Watcher reservation components:** feed-set policy, durable run leases, budgets, and reserved
  scheduler capacity are implemented; the stock watcher execution facade remains pending.
- **Human approvals:** interactive approvals expire to deny and are completed only through the local dashboard or administrative CLI.
- **Crash-safe state:** SQLite in WAL mode records sessions, requests, attempts, jobs, reservations, and incidents.
- **Durable asynchronous ownership:** crawl jobs remain bound to their creating session, workspace, root run, provider principal, quota scope, credential generation, and pool across restarts.
- **Reconciliation components:** reset-aware exact-decimal comparison and quarantine logic can
  evaluate provider-usage snapshots even when conservative whole-credit projections collide. A
  separately gated, bounded Firecrawl observer can collect authenticated exact balances on enabled
  account schedules; full periodic ledger-comparison orchestration remains pending.
- **Provider isolation:** credentials are decrypted only inside the provider transport boundary.
  The fixed provider hostname is resolved before custody, and the local TCP connection is pinned to
  one validated public address while TLS SNI, certificate verification, and HTTP `Host` retain the
  configured hostname. URLs delegated to an external provider remain governed by that provider's
  own remote DNS and redirect policy.
- **Local account and credential lifecycle:** the administrative CLI can transactionally onboard and
  rotate aliased Firecrawl accounts into DPAPI custody, manage pool membership and durable account
  state, and create one bounded memory-only emergency unlock without exporting a secret.
- **Installed local surfaces:** the stock daemon composes the loopback APIs, while the CLI and MCP stdio server adopt controlled sessions through production loopback clients.

## High-level architecture

```text
Interactive clients ─┐
Scheduled watcher ───┼──> Agent API on 127.0.0.1
Local tools ─────────┘              │
                                    ▼
                          Session and policy layer
                                    │
                   ┌────────────────┼────────────────┐
                   ▼                ▼                ▼
              Fair scheduler   Quota router      Audit ledger
                   │                │                │
                   └─────────────── ▼ ──────────────┘
                              Provider transport
                                    │
                                    ▼
                                 Firecrawl

Browser dashboard ─────> Separate admin API on 127.0.0.1
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component and request-flow design.

## Current status

The repository contains a local-first v1 implementation with a concrete stock daemon, CLI, MCP
stdio server, SQLite persistence, and deterministic scripted-provider test mode. The daemon starts
in `RECOVERING`, completes durable job recovery before advertising `READY`, and enters a bounded
`DRAINING` phase on shutdown. One installation-scoped operating-system lock prevents two stock
daemons from recovering or serving the same database concurrently.

Every workload and observer provider channel defaults to `disabled`. Firecrawl workload `scripted`
mode is deterministic, makes no network calls, and backs its routing availability with one
idempotent synthetic no-network quota snapshot. Workload `live` mode requires both explicit network
enablement and valid Windows DPAPI custody metadata. The separate observer channel requires its own
explicit live/network opt-in, and every account observation schedule starts disabled. Real-provider
calls are not part of normal installation or automated testing. The clean-wheel
Windows process gate covers the five installed entry points, controlled MCP launch, daemon restart,
session/root re-adoption, and asynchronous job settlement using the no-network scripted provider;
it does not cover live-provider rollout. Credential lifecycle and bounded emergency administration
remain local-only and do not authorize a provider call. Manual account refresh and credential
validation are available only when the observer channel is explicitly live and network-enabled;
each makes one fixed, generation-bound credit-status request and persists only validated canonical
numeric values, conservative projected integers, and body-free audit evidence. Canonical values are
not provider lexemes: insignificant scale is discarded, negative remaining credit represents
provider overage and projects to zero, positive fractions are preserved exactly but floored only for
routing, and oversized valid observations saturate only the projection. Exact observations remain
authoritative for reconciliation when projections collide. A confirmed zero/negative authenticated
balance or definitive quota-exhausted response durably excludes that account across requests and
restarts; a timer cannot heal exhaustion. Fill-first routing shares the leading account while its
fresh quota and dispatch capacity are sufficient, then spills deterministically only when needed.
For retry-safe reads, a Firecrawl 429 stays on the current account while its bounded retry and
deadline permit; only when that path would otherwise fail does Gatehouse visit later eligible pool
scopes, each at most once. Unsafe or ambiguously submitted operations never use this spill path. It
does not create sticky account assignments for clients or LLMs. Repeated-equivalent or aggregate
request bursts instead quarantine the exact session/root-run offender. Every fresh session/root
launch for the same client profile remains blocked across restart, including while the old root has
a bounded `AUTHORIZED` grant. The authenticated local dashboard can either grant that old root a
bounded burst or perform a distinct fresh-run recovery after no permit, nonterminal/unknown work,
or live external-resource affinity remains. Recovery revokes the old session, closes its root, and
releases only the exact quarantine generation; it transfers no burst grant. Prompt text is never
either decision. One native client process may multiplex several internal subagents through that
same Gatehouse session/root, so those subagents share its quarantine boundary; a separate client
profile is required for independent isolation. One
separately authorized manual release validation on 2026-08-22 exercised the fixed credit-status
path exactly once against the
real provider: authentication succeeded, exact integer observations were preserved, and the
provider balance remained unchanged through follow-up. It did not perform a Firecrawl workload, a
fractional live case, a retry, or a revoked-key test. The exact-integer validation path therefore has
real-provider evidence, while fractional and other numeric edge cases remain supported by contract
and local tests only. Other provider IDs currently supply schema and fixed-operation foundation only;
no cross-provider inference fallback or non-Firecrawl workload is implemented. Stock watcher
execution, full periodic ledger comparison, and the Markdown audit view remain open. The daemon now
performs bounded periodic retention and passive WAL checkpointing at the configured maintenance
interval. The configured database cap also sheds new untrusted feedback before its logical insert
projection exceeds the observed main-database, WAL, shared-memory, and rollback-journal footprint;
it is an admission signal rather than a race-free filesystem quota.
See [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) for capability status and
[TESTING.md](TESTING.md) for the exact evidence path.

## Prerequisites and installation

The public Gatehouse 0.0.1 release remains finalized and unchanged. This checkout reports
`0.0.2.dev0` while the next candidate is developed offline and has no published artifact. Gatehouse
is Windows-only pre-alpha software and requires PowerShell and Python 3.12 or newer within Python
3.x (`>=3.12,<4`) with `venv` and `pip`. Tracked Windows CI is configured for Python 3.12, 3.13,
and 3.14. The completed release evidence currently covers CPython 3.14.4 on Windows x64; Python
3.12 and 3.13 have not yet received the same installed-process verification.

From a source checkout, the bootstrap script creates `.venv`, installs Gatehouse in editable mode,
and seeds `%APPDATA%\Gatehouse\config.yaml` without overwriting an existing configuration:

```powershell
.\scripts\bootstrap.ps1 -PythonExecutable C:\Path\To\python.exe
```

Use `-IncludeDevelopmentTools` only for a development environment. To install a built release wheel
instead, create a clean virtual environment and install the audited artifact directly:

```powershell
& C:\Path\To\python.exe -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\dist\gatehouse_local-0.0.1-py3-none-any.whl
```

Review [CONFIGURATION.md](CONFIGURATION.md) before first startup. Provider channels default to
`disabled`; installation and configuration do not require a provider credential or provider network
access.

## Local entry points

After installation, the stock surfaces are:

```powershell
gatehoused --config C:\path\to\config.yaml
gatehouse --config C:\path\to\config.yaml config init
gatehouse --config C:\path\to\config.yaml config validate --explain
gatehouse --config C:\path\to\config.yaml diagnose
gatehouse --config C:\path\to\config.yaml diagnose --support-bundle C:\path\to\new-support.json
gatehouse --config C:\path\to\config.yaml status
gatehouse --config C:\path\to\config.yaml dashboard
gatehouse --config C:\path\to\config.yaml credentials --help
gatehouse --config C:\path\to\config.yaml credentials list --limit 50
gatehouse --config C:\path\to\config.yaml credentials validate CREDENTIAL_ID --generation 1
gatehouse --config C:\path\to\config.yaml accounts --help
gatehouse --config C:\path\to\config.yaml accounts add --provider firecrawl --alias primary --team-id TEAM_ID --pool default --priority 10 --mutation-id MUTATION_ID
gatehouse --config C:\path\to\config.yaml accounts list
gatehouse --config C:\path\to\config.yaml accounts status primary
gatehouse --config C:\path\to\config.yaml accounts rotate primary --mutation-id MUTATION_ID
gatehouse --config C:\path\to\config.yaml accounts disable primary --mutation-id MUTATION_ID --reason REASON
gatehouse --config C:\path\to\config.yaml accounts recover primary --mutation-id MUTATION_ID --reason REASON
gatehouse --config C:\path\to\config.yaml accounts remove primary --mutation-id MUTATION_ID --reason REASON --confirm-human primary
gatehouse --config C:\path\to\config.yaml accounts observe enable primary --mutation-id MUTATION_ID --reason REASON
gatehouse --config C:\path\to\config.yaml accounts refresh primary --mutation-id MUTATION_ID
gatehouse --config C:\path\to\config.yaml emergency --help
gatehouse --config C:\path\to\config.yaml run editor-one --workspace example-project -- gatehouse-mcp
```

The last command launches `gatehouse-mcp` with a one-session bootstrap capability. The MCP process
consumes that capability, exchanges it over loopback, creates a server-authoritative root run, and
registers only the tools allowed by the adopted session. Provider credentials are never added to
the child environment or returned by an MCP tool. The intended agent topology keeps `gatehoused`
running as the central broker (for example through the supplied user-logon registration) and starts
one small `gatehouse-mcp` stdio shim on demand for each controlled MCP client session. The shim
does not hold provider keys and does not need a second background credential service.

Each client profile must explicitly list launchable workspace names under `workspaces.allow`. A
controlled launch submits its actual existing absolute working directory; the daemon resolves links
and admits it only when it is the configured canonical workspace root or a descendant. The exact
resolved directory is pinned as the child process working directory. Project instruction files may
tell an agent when it should request a Firecrawl tool, but Gatehouse does not parse prose as access
authority: the configured client/workspace pair, canonical directory, session capability, and
workspace policy remain the enforcement boundary. Different MCP client profiles may bind the same
workspace and pool while retaining distinct session/root-run attribution.

If an MCP call returns `approval_pending`, the agent directs the human to the fixed numeric-loopback
dashboard URL in the response and retries the exact same arguments after the decision. The MCP
surface cannot approve or deny, and words in a prompt do not count as approval. Pending authority is
durable: an exact retry can consume it once after daemon restart; after an MCP restart, a pending
crawl retry must reuse the returned crawl `request_id` so Gatehouse can rehydrate the exact binding
without replaying the side effect. This works only when the shim re-adopts the same durable
session/client/workspace/root-run authority. A newly launched controlled MCP session has a
different session ID, cannot inherit the old approval, and must create a fresh one if policy still
asks.

Account add/rotate, credential provisioning/rotation, and emergency unlock read a secret only from
an interactive hidden prompt. There is no secret command-line option, environment/file/stdin
fallback, or export command. Account metadata such as alias, pool, priority, reason, and the
caller-chosen idempotency key is safe to pass as arguments; the required team ID is also explicitly
non-secret command metadata. Provider secrets are not.

`--team-id` is mandatory, non-secret operator-declared quota-scope identity containing 1–160
visible ASCII characters (`!` through `~`). Gatehouse persists only an installation-keyed
fingerprint as internal mutation/identity authority and never returns the raw value or fingerprint
in status, mutation results, or audit. Reusing the same declared Firecrawl team ID cannot create a
second spendable scope; account tombstoning retains that reservation, and rotation replaces a key
inside the same scope. Firecrawl's credit endpoint reports team-scoped counters but does not attest a
team identifier, so offline onboarding cannot detect a user deliberately supplying inconsistent IDs
for keys that actually share one team.

## Documentation

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, flows, concurrency, and recovery |
| [SECURITY.md](SECURITY.md) | Security posture, secret handling, and incident response |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, adversaries, and residual risk |
| [USES_AND_LIMITATIONS.md](USES_AND_LIMITATIONS.md) | Intended uses, non-goals, and known constraints |
| [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) | Milestones and future provider phases |
| [DEBUG.md](DEBUG.md) | Debugging and incident-note conventions |
| [OPERATIONS.md](OPERATIONS.md) | Startup, health, backup, recovery, and reconciliation |
| [TESTING.md](TESTING.md) | Test strategy and release gates |
| [CONFIGURATION.md](CONFIGURATION.md) | Configuration model and examples |
| [docs/IMPLEMENTATION_SPEC.md](docs/IMPLEMENTATION_SPEC.md) | Normative v1 implementation contract |
| [docs/API.md](docs/API.md) | Agent and administrative API contract |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Persistent entities and invariants |
| [docs/POLICY_ENGINE.md](docs/POLICY_ENGINE.md) | Policy inputs, precedence, and decisions |
| [docs/FIRECRAWL_ADAPTER.md](docs/FIRECRAWL_ADAPTER.md) | Initial provider adapter contract |
| [docs/WATCHER.md](docs/WATCHER.md) | Unattended watcher identity and reservations |
| [docs/RECONCILIATION.md](docs/RECONCILIATION.md) | Provider-ledger comparison and quarantine |
| [docs/FAILURE_MODES.md](docs/FAILURE_MODES.md) | Expected failures and safe responses |
| [docs/DEMO.md](docs/DEMO.md) | Technical demonstration plan |

## Design principles

1. Every queue, wait, lease, retry, approval, and external operation is bounded.
2. No provider key is placed in an ordinary client environment.
3. A child context cannot gain capabilities absent from its parent session.
4. Account pools are explicit; emergency accounts are never consumed automatically.
5. Provider side effects are retried only when the outcome is known to be safe.
6. Request and response bodies are not persisted by default.
7. The unattended watcher never blocks on interactive approval.
8. The database is authoritative; Markdown logs are generated views or concise human summaries.
9. The v1 deployment is a policy and damage-bounding boundary, not hostile same-user process isolation.
10. Documentation must distinguish implemented behavior from planned behavior.

## Ownership

Gatehouse is designed and maintained by **Yash Verma**. See [AUTHORS.md](AUTHORS.md).

## License

This repository is a portfolio project. No license for copying, modification, redistribution, or commercial use is granted. See [LICENSE](LICENSE).
