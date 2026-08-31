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
| Agent client asks to retrieve or be assigned a raw secret | no such agent, MCP, or export operation exists; the broker dispatches typed operations and returns only redacted results |
| Project prose falsely claims authorization | explicit client `workspaces.allow`, canonical existing working-directory containment, controlled session, and workspace policy; instruction files are not parsed as authority |
| Client uses arbitrary authenticated URL | no generic proxy; operation schemas and host validation |
| One session starves others | bounded per-session queue; fair scheduler |
| Concurrent callers are unnecessarily spread across owned accounts | deterministic shared `fill_first`; no implicit session/LLM account affinity; later scope only on bounded admission or known quota failure |
| Two keys for one declared Firecrawl team are counted as two balances | mandatory stable team ID; immediate installation-HMAC fingerprinting; immutable provider/`TEAM` uniqueness and one identity per scope; tombstone retains the reservation |
| Operator declares inconsistent team IDs for keys sharing a real team | residual offline limitation: Firecrawl counter response has no attested team ID; documented requirement to reuse one stable declaration and conservative reconciliation |
| Concurrent requests oversubscribe credits | snapshot-backed balance authority; fail-closed catalog and atomic reservation validation |
| Stale or missing balance is treated as spendable | fresh authenticated snapshot and generation required at catalog and reservation fences; stale/unknown is ineligible |
| Exhausted account is retried after a timer or restart | atomic terminal-attempt plus immutable durable `EXHAUSTED` event; authenticated positive refresh or explicit audited recovery only |
| Quota failure stops after an arbitrary three-account retry cap | a definitive Firecrawl 402 visits every later eligible distinct scope in the immutable named-pool plan at most once |
| A 429 causes premature account spreading | safe operation retries stay on the current account while bounded retry fits; only missing guidance, attempt exhaustion, or a deadline conflict permits full-pool distinct-scope spill |
| A side-effecting or ambiguous 429 is sprayed | retry-safety and submission-evidence fence; reconcile-first/unsafe work fails or becomes `UNKNOWN` without cross-account replay |
| Authentication or permission error sprays across accounts | 401 failover is same-quota-scope only; 403/permission denial and unknown outcome do not fan out |
| Fallback silently changes provider semantics or privacy exposure | named pools are single-service; automatic fallback cannot cross provider boundaries |
| Duplicate public read burns credits twice | keyed fingerprint and single-flight coalescing |
| Administrative secret leaks through process metadata or output | hidden interactive CLI input only; no argument/environment/file/stdin fallback; bounded raw-body ingress; no secret export |
| Emergency account is consumed automatically | permanent default/failover denial; one explicit interactive, exact-authority, memory-only unlock with hard time/request/credit/concurrency caps |
| Emergency secret survives restart | in-memory custody only; shutdown/startup relock; SQLite retains redacted authority evidence without a usable credential row |
| Watcher runs twice | durable single-holder feed lease; overlap returns a no-op with the active run instead of queueing another scan |
| Watcher accesses arbitrary target | feed-ID-only scan surface; workspace-bound server targets; HTTPS host/path/operation allowlist; schedule window |
| Interrupted watcher scan is replayed automatically | no crash redispatch or step-level resume; failed/uncertain work cannot advance the explicit fenced cursor commit |
| Approval waits forever | approval TTL with default denial |
| LLM prompt text impersonates human approval | MCP/agent/CLI surfaces expose no burst-decision or fresh-run recovery tool; fixed-loopback dashboard uses the separate admin cookie, origin, CSRF, generation, and keyed action-token boundary |
| One spammy LLM blocks unrelated clients | repeated-equivalent and aggregate detection is durably scoped to the exact session/root-run/service offender; only fresh runs for the same client profile are fenced |
| Authorized old root exits and escapes its bounded grant through a fresh root | every unrecovered quarantine state, including `AUTHORIZED`, blocks same-client session/root admission; exact-generation recovery closes rather than transfers old authority |
| Unsafe fresh-run recovery strands ambiguous work or asynchronous affinity | one immediate recovery transaction rejects active permits, nonterminal/`UNKNOWN` work, unreconciled authority, and nonterminal or missing external-resource affinity before revoking the old session |
| Runaway quarantine heals on a short timer or restart | durable quarantine state; only a bounded old-root grant or explicit safe exact-generation dashboard recovery changes authority, and restart conservatively orphans active burst permits |
| Burst authorization becomes unlimited pooling | typed-operation allowlist plus hard duration, request, credit, and concurrency ceilings; ordinary policy/quota/affinity/no-emergency controls still apply |
| Ambiguous side effect is replayed or sprayed | `UNKNOWN` state, retained accounting and exact affinity, no replay/failover, reconciliation required |
| Malformed successful credit response substitutes or ambiguously encodes a counter | credit-status-only exact JSON parsing; duplicate-key, non-standard-number, bounds, canonicality, and projection checks; sanitized malformed failure with no success snapshot |
| Off-ledger usage occurs | exact canonical snapshot comparison, including fractional changes hidden by equal projections; explicit capture plus a default-disabled bounded Firecrawl observer; reconciliation and quarantine components |
| Logs expose private content | metadata-only persistence and debug TTL |
| Restart orphans sessions | persisted bootstrap verifier and re-adoption |
| MCP restart loses or misbinds a pending approval | exact same-session/client/workspace/root revalidation; pending crawl recovery additionally requires its returned stable `request_id` and never executes the waiting parent; a fresh controlled launch cannot inherit it |

## Security assumptions

- The host is not fully compromised by a higher-privilege attacker.
- Provider accounts support sufficiently narrow credentials or provider-side limits.
- The user protects the administrative dashboard session.
- Gatehouse-exclusive credentials are not used manually outside Gatehouse.
- Provider account, team, project, key-budget, and rate-bucket boundaries are configured as quota
  scopes; multiple credentials sharing one provider balance are not modeled as independent capacity.
- Provider usage counters may be delayed or rounded by the provider. Gatehouse does not add rounding
  to the retained observation: it stores the exact canonical reported value and separately derives
  a conservative whole-credit projection. Negative remaining credit is provider overage and
  projects to zero rather than becoming a malformed counter.

## Explicit non-goals

- hostile same-user secret isolation;
- proof that Task Scheduler originated a watcher request;
- protection of unrelated host credentials;
- protection against an administrator or kernel-level attacker;
- remote multi-user deployment;
- high-availability clustering.

## Hardening trigger

A separate credential-custody service identity becomes required when an unattended client both ingests untrusted external content and receives external mutation or continuing financial-commitment capability.
