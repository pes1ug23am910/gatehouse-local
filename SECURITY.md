# Security

## Security objective

Gatehouse reduces accidental credential exposure, centralizes authorization, bounds provider usage,
and records attributable metadata for concurrent local workflows. Reset-aware comparison and local
quarantine components can evaluate supplied provider-usage snapshots, but the stock daemon does not
yet collect provider counters or schedule reconciliation.

It does not claim to isolate secrets from a deliberately hostile process running under the same ordinary Windows account in v1.

## Mandatory controls

- Provider credentials are encrypted at rest with a Windows user-scoped KeyStore implementation.
- Credentials are never written to tracked files, ordinary configuration, command arguments, persistent logs, dashboard HTML, or client results.
- Provider credentials are never injected into client environments.
- Provider-side limits and least-privilege scopes are mandatory.
- The design forbids persistent emergency credentials. The stock administrative surface does not
  yet implement an unlock workflow, so emergency pools remain disabled and locked.
- Credentials for services outside the v1 provider allowlist are not admitted.
- Agent and administrative authentication are separate.
- One installation-scoped operating-system lock prevents concurrent stock daemons from recovering
  or serving the same database.
- Every wait, approval, retry, queue, lock, lease, and job has a time or count bound.
- Unattended clients cannot wait for approval.
- Request and response bodies are not persisted by default.
- A generic authenticated HTTP proxy is prohibited.
- A secret export or retrieval operation is prohibited.
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
- reset-aware off-ledger reconciliation and local-quarantine components, which become active
  operational controls only after provider-counter collection and orchestration are wired;
- an operator-run provider rotation procedure; the stock administrative surface does not yet
  implement rotation mutations;
- no high-spend compute credential in v1.

## Credential classes

Persistent active credentials must be dedicated to Gatehouse where practical, minimally scoped, bounded provider-side, revocable without unrelated impact, and identified in logs only by an internal alias.

The intended emergency workflow requires credentials to remain offline while locked, enter daemon
memory only for a bounded manual unlock, stay restricted to one session or root run, and carry
request, credit, and time ceilings. The stock administrative surface does not yet expose that
workflow; until it does, the emergency pool remains disabled and locked.

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

## Administrative decisions

Dashboard and CLI approvals bind the request fingerprint, session, service, operation, target,
pool, cost ceiling, one-use ceiling, and expiration. Approval and denial use one immediate
file-backed compare-and-set transaction, so concurrent actors have exactly one winner. An agent
bearer token cannot authenticate the admin realm, and the stock admin API has no credential-export
or generic secret-onboarding route.

## Crash authority

A successful asynchronous provider creation is not represented by a provider identifier alone.
The terminal attempt first checkpoints its resource type, credential generation, and pool. Startup
reconstructs affinity only when that checkpoint agrees with every durable owner and routing fact;
partial or conflicting authority fails closed. Terminal job usage is likewise checkpointed in
`SETTLING` before quota and budget ledgers change, preventing a restart from dropping or duplicating
known cost.

## Logging

Persisted metadata may include timestamp, session and root-run identifiers, service and operation, normalized target summary, request fingerprint, request and response sizes, status, latency, retry and error class, estimated and actual usage, pool/principal/credential aliases, and policy or approval identifiers.

Persisted records must not include provider credentials, session bootstrap capabilities, access tokens, authorization headers, full request or response bodies, page content, or private document content.

## Incident response

For suspected credential compromise:

1. disable or quarantine the credential locally;
2. stop new leases from the affected quota scope;
3. capture provider counters and relevant audit metadata;
4. revoke or rotate the provider credential;
5. inspect off-ledger usage and affected operations;
6. confirm provider-side limits and account state;
7. run full reconciliation;
8. restore service only after a clean result;
9. record the incident and corrective action.

## Vulnerability handling

Security findings should be reported privately to the maintainer rather than disclosed through public issue content containing exploit details or secrets.
