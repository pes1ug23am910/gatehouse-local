# Policy Engine

## Purpose

The policy engine decides whether a validated typed operation may proceed. It does not select credentials or execute provider calls.

## Decisions

```text
ALLOW
ASK
DENY
```

Configuration shorthands such as `allow_targeted` and `allow_with_limits` compile to `ALLOW` plus explicit constraints; they are not additional runtime decisions.

The source candidate accepts only the implemented policy profile. `enforce_limits` must be the
strict Boolean `true`; false, numeric, string, or otherwise unsupported values are rejected.
Configured purpose rules compile to a decision and a targeted-only constraint; per-rule cost
customization is not accepted in YAML. The internal rule type can also represent a cost ceiling.
`targeted_only: true` is supported only for `ALLOW` rules on `scrape`, `map`, and `crawl`;
it is rejected for `ASK`, `DENY`, and targetless `search`. Explicit decision strings normalize
case and compile identically to the corresponding shorthand.
Configuration is limited to 64 purposes and the four operation families `search`,
`scrape`, `map`, and `crawl` per purpose. Unknown rule fields and operation families fail validation.

For unattended clients:

```text
ALLOW → execute
ASK   → deny immediately
DENY  → deny immediately
```

## Inputs

Every decision can inspect:

- client profile and unattended flag;
- session and root run;
- workspace identifier and canonical root;
- service and operation;
- purpose;
- canonical target;
- data classification;
- estimated request and cost ceilings;
- proposed pool;
- current time and configured schedule window;
- remaining session and root-run budgets;
- service and account circuit breakers;
- exact external resource session/workspace/root-run ownership.

The client cannot override verified workspace, pool eligibility, or budget ceilings.

## Precedence

1. non-overridable hard deny;
2. service emergency kill switch;
3. client capability ceiling;
4. resource ownership constraint;
5. explicit workspace deny;
6. valid one-use approval;
7. explicit workspace allow;
8. explicit client allow;
9. global allow;
10. default ask or deny.

## Hard denies

V1 hard denies include raw credential retrieval, arbitrary authenticated HTTP, private/loopback targets, emergency-pool automatic selection, prohibited sensitive data, watcher arbitrary target, watcher outside its schedule, watcher operation requiring approval, unsupported-provider admission, and listener binding outside loopback.

Emergency admission is not an agent or MCP policy override. It requires a separate interactive
administrative unlock and the exact service/pool/session/root authority; automatic/default/failover
selection and asynchronous creation remain hard denied.

Configuration must retain the three baseline declarations (`no-sensitive-payloads`,
`no-broad-domain-crawl`, and `no-external-link-crawl`) exactly, allowing rule and classification
ordering differences. Their effective `fixed-v1` profile covers
`api_key`, `credential`, `identity_document`, `private_document`, `private_key`, `resume`, and
`sensitive_personal_information`; crawl requires include paths and forbids external links.
The code also unconditionally forbids subdomain crawling. Unsupported hard-deny predicates,
weakened alternatives, or missing profile members
are rejected rather than accepted as configurable enforcement.

The supported credit-discipline settings are `duplicate_in_flight: return_original`,
`cross_session_public_coalescing: false`, `cache_completed_public_reads: disabled`, and
`broad_crawl_without_narrow_attempt: deny`. Cross-session coalescing cannot be enabled. The old
`policy_controlled` cache value is rejected because completed-result caching is not implemented.
The crawl check requires include paths; it does not prove that an include-path regular expression
is narrow, and it does not track or require a previously completed narrower operation. Effective
policy explicitly reports `prior_narrow_attempt_tracking: false`.

## Purpose model

Initial Firecrawl purposes:

```text
career_discovery
career_site_research
active_job_verification
js_heavy_extraction
multi_page_job_extraction
opening_monitoring
```

A purpose narrows operations and cost ceilings. It is not a free-text justification.

## Approval model

An approval binds session, service, operation, request fingerprint, target summary, account pool,
maximum estimated cost, maximum uses, and expiration. Approvals default to one use and
approximately five minutes. Expiration is denial. Approval and denial race through one immediate
SQLite compare-and-set from `PENDING`, so exactly one actor wins; consumption is separately
exactly once and revalidates the complete request binding.

## Example workspace policy

The policy allows Firecrawl only for material placement or career-research benefit, prefers local information and direct official sources before broader extraction, permits targeted search and scrape more readily than map or crawl, denies broad whole-domain crawling, prevents duplicate burn, and prohibits credentials, private documents, and other sensitive content.

See `config/policies/placement-schedule.example.yaml`.

## Explainability

Every decision records final decision, highest-precedence matching rule, constraints, cost ceiling,
approval requirement, denial reason, and policy version.

`gatehouse policy explain` uses a fresh configured interactive session and server-minted root run.
The daemon derives client and workspace identity from that authenticated authority; they are never
accepted in the explain request body. The command reports the capability ceiling, configured
default, and a bounded matrix of purpose rules for `search`, `scrape`, `map`, or `crawl`. With no
purpose or target in the command, the top-level decision is the configured default and targeted
rules explicitly require target context. Runtime-only inputs such as the concrete target, payload,
estimated cost, circuit state, and resource ownership are still evaluated when a real typed
invocation is submitted.

Explanation is side-effect free with respect to provider execution: it does not enqueue work,
reserve quota or budget, open a credential lease, or contact the provider.

The required `effective_policy` response field describes the compiled configuration: compiler
revision, policy and service identifiers, default decision and pool, a workspace-binding digest,
the fixed hard-deny and credit-discipline profile, enforced limits, and sorted purpose/operation
rules. It never exposes the canonical workspace root. For compiled and built-in default policies,
`policy_version` is the first 16 hexadecimal characters of SHA-256 over this canonical descriptor
JSON. Purpose and operation order is normalized; shorthand and explicit rules that enforce the
same behavior receive the same version. Accepted inputs that change effective enforcement change
the descriptor used for versioning.

The descriptor states configured policy; it does not grant capabilities. The explanation's
selected-operation decision and purpose projection continue to apply the authenticated client's
capability ceiling and unattended approval rules. The complete descriptor is the same whether
that client may use the selected operation or receives a capability denial.

These stricter compilation and explanation contracts are source-only candidate changes. Existing
configuration with unsupported values must be revised under separate authorization before using
this candidate. No configuration or retained state is migrated automatically, and source/offline
evidence does not establish installed-runtime, live-workload, normal-use, or release readiness.
