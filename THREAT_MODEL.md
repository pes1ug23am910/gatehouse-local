# Threat Model

## Assets

Gatehouse protects or governs provider credentials, credits and spending capacity, workspace authorization context, watcher availability, session attribution and budgets, provider job ownership, audit and reconciliation integrity, administrative approvals, and local policy.

## Trust boundaries

1. Client to agent API: all input is untrusted.
2. Agent API to administrative API: separate authentication and authorization.
3. Policy and scheduler to KeyStore: opaque credential identifiers only.
4. KeyStore to provider transport: temporary secret lease.
5. Gatehouse to provider: external network and billing boundary.
6. Daemon to SQLite: local durability boundary.
7. Watcher to interactive clients: bearer identity with narrow policy, not an operating-system identity boundary.

## Adversary classes

### Accidental misuse

Wrong account selection, duplicate requests, unbounded fan-out, broad crawling, provider key leakage, and scheduled-job starvation are in scope for prevention.

### Workflow-driven abuse through Gatehouse

Requests outside workspace policy, watcher target abuse, repeated calls, budget bypass, or approval avoidance are in scope for prevention, damage bounding, and detection.

### Direct provider bypass using a stolen key

Extraction prevention is out of scope for same-user v1. Provider-side damage bounding and off-ledger detection are in scope.

### Watcher session impersonation

Perfect origin proof is out of scope for v1. Operation, URL, schedule, capacity, and budget bounding are in scope. Anomalous use is detected where distinguishable.

### Remote attacker

The service is loopback-only. Loopback binding, host validation, admin anti-forgery protection, and no remote listener are in scope.

### Malicious third-party adapter

Third-party adapters are excluded from v1.

## Primary abuse cases and controls

| Abuse case | Primary controls |
|---|---|
| Credential appears in client environment | launcher strips provider secrets; controlled transport injects authentication internally |
| Client asks for raw secret | no such operation exists |
| Client uses arbitrary authenticated URL | no generic proxy; operation schemas and host validation |
| One session starves others | bounded per-session queue; fair scheduler |
| Concurrent requests oversubscribe credits | atomic quota reservation |
| Exhausted account is retried repeatedly | quota-scope circuit breaker |
| Permission error sprays across accounts | error classification; no cross-principal spray |
| Duplicate public read burns credits twice | keyed fingerprint and single-flight coalescing |
| Emergency account is consumed automatically | emergency default/binding denial and a disabled, locked stock pool; a future unlock must be manual and bounded |
| Watcher runs twice | durable single-holder run-lease component; stock watcher execution remains unwired |
| Watcher accesses arbitrary target | feed-set identifier, host/path policy, schedule window |
| Approval waits forever | approval TTL with default denial |
| Ambiguous side effect is replayed | `UNKNOWN` state and reconciliation |
| Off-ledger usage occurs | supplied-snapshot comparison and quarantine components; stock counter collection and scheduling remain unwired |
| Logs expose private content | metadata-only persistence and debug TTL |
| Restart orphans sessions | persisted bootstrap verifier and re-adoption |

## Security assumptions

- The host is not fully compromised by a higher-privilege attacker.
- Provider accounts support sufficiently narrow credentials or provider-side limits.
- The user protects the administrative dashboard session.
- Gatehouse-exclusive credentials are not used manually outside Gatehouse.
- Provider usage counters may be delayed or rounded.

## Explicit non-goals

- hostile same-user secret isolation;
- proof that Task Scheduler originated a watcher request;
- protection of unrelated host credentials;
- protection against an administrator or kernel-level attacker;
- remote multi-user deployment;
- high-availability clustering.

## Hardening trigger

A separate credential-custody service identity becomes required when an unattended client both ingests untrusted external content and receives external mutation or continuing financial-commitment capability.
