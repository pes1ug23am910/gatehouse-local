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

## Placement-Schedule policy

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
