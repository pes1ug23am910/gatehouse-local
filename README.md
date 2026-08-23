# Gatehouse

Gatehouse is a Windows-local capability broker for credentialed developer services. It gives interactive tools and scheduled jobs a narrow, policy-controlled interface while keeping provider credentials out of prompts, command arguments, ordinary configuration files, and persistent logs.

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
- **Named account pools:** interactive, reserved, and emergency accounts remain separate by policy.
- **Concurrent workload control:** per-session, per-service, per-quota-scope, and global limits prevent one workflow or shared provider balance from monopolizing the broker.
- **Duplicate-burn protection:** equivalent in-flight reads can be coalesced without issuing another provider request.
- **Watcher reservation components:** feed-set policy, durable run leases, budgets, and reserved
  scheduler capacity are implemented; the stock watcher execution facade remains pending.
- **Human approvals:** interactive approvals expire to deny and are completed only through the local dashboard or administrative CLI.
- **Crash-safe state:** SQLite in WAL mode records sessions, requests, attempts, jobs, reservations, and incidents.
- **Durable asynchronous ownership:** crawl jobs remain bound to their creating session, workspace, root run, provider principal, quota scope, credential generation, and pool across restarts.
- **Reconciliation components:** reset-aware exact-decimal comparison and quarantine logic can
  evaluate supplied provider-usage snapshots even when conservative whole-credit projections
  collide; stock provider-counter collection and periodic orchestration remain pending.
- **Provider isolation:** credentials are decrypted only inside the provider transport boundary.
- **Local credential lifecycle:** the administrative CLI can provision and rotate DPAPI-backed
  credentials, apply local disable/quarantine/terminal-retirement states, and create one bounded
  memory-only emergency unlock without exporting a secret or enabling provider networking.
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

Provider mode defaults to `disabled`. `scripted` mode is deterministic, makes no network calls, and
backs its routing availability with one idempotent synthetic no-network quota snapshot.
`live` mode requires both explicit network enablement and valid Windows DPAPI custody metadata;
real-provider calls are not part of normal installation or automated testing. The clean-wheel
Windows process gate covers the five installed entry points, controlled MCP launch, daemon restart,
session/root re-adoption, and asynchronous job settlement using the no-network scripted provider;
it does not cover live-provider rollout. Credential lifecycle and bounded emergency administration
remain local-only and do not authorize a provider call. A separate manual credential-validation
command is available only when both `live` mode and provider networking are explicitly enabled; it
makes one fixed, generation-bound credit-status request and persists only validated canonical
numeric values, conservative projected integers, and body-free audit evidence. Canonical values are
not provider lexemes: insignificant scale is discarded, negative remaining credit represents
provider overage and projects to zero, positive fractions are preserved exactly but floored only for
routing, and oversized valid observations saturate only the projection. Exact observations remain
authoritative for reconciliation when projections collide. One separately authorized manual
release validation on 2026-08-22 exercised the fixed credit-status path exactly once against the
real provider: authentication succeeded, exact integer observations were preserved, and the
provider balance remained unchanged through follow-up. It did not perform a Firecrawl workload, a
fractional live case, a retry, or a revoked-key test. The exact-integer validation path therefore has
real-provider evidence, while fractional and other numeric edge cases remain supported by
contract and local tests only. Stock watcher execution, scheduled provider-counter reconciliation,
periodic retention, and the Markdown audit view remain open.
See [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) for capability status and
[TESTING.md](TESTING.md) for the exact evidence path.

## Prerequisites and installation

Gatehouse 0.0.1 is a Windows-only pre-alpha candidate. It requires PowerShell and Python 3.12 or
newer with `venv` and `pip`. The release evidence currently covers CPython 3.14.4 on Windows x64;
Python 3.12 and 3.13 satisfy the package metadata but have not received the same installed-process
verification.

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

Review [CONFIGURATION.md](CONFIGURATION.md) before first startup. Provider mode defaults to
`disabled`; installation and configuration do not require a provider credential or provider
network access.

## Local entry points

After installation, the stock surfaces are:

```powershell
gatehoused --config C:\path\to\config.yaml
gatehouse --config C:\path\to\config.yaml status
gatehouse --config C:\path\to\config.yaml dashboard
gatehouse --config C:\path\to\config.yaml credentials --help
gatehouse --config C:\path\to\config.yaml credentials list --limit 50
gatehouse --config C:\path\to\config.yaml credentials validate CREDENTIAL_ID --generation 1
gatehouse --config C:\path\to\config.yaml emergency --help
gatehouse --config C:\path\to\config.yaml run editor-one --workspace placement-schedule -- gatehouse-mcp
```

The last command launches `gatehouse-mcp` with a one-session bootstrap capability. The MCP process
consumes that capability, exchanges it over loopback, creates a server-authoritative root run, and
registers only the tools allowed by the adopted session. Provider credentials are never added to
the child environment.

Credential provisioning, rotation, and emergency unlock read a secret only from an interactive
hidden prompt. There is no secret command-line option, environment/file/stdin fallback, or export
command.

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
