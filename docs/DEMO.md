# Technical Demonstration Plan

Show implemented behavior only. Use `providers.firecrawl.workload.mode: scripted`; never use real
provider credentials or enable networking for this demonstration. Use synthetic secrets for local
lifecycle examples; stock watcher execution remains a separate integration gate.

## 1. Overview

Explain that multiple local clients need credentialed provider access, direct keys create leakage/attribution/quota problems, and Gatehouse exposes typed operations with policy, quotas, audit, and recovery.

## 2. Controlled sessions

Start the clean-installed stock daemon, launch two independent sessions, show separate session
identifiers/workspaces/budgets, and show that an unattributed metered request is denied.

## 3. Concurrent scheduling

Generate a burst from session A, issue one request from session B, and show fair service, bounded queue depth, and deadlines.

## 4. Duplicate-burn protection

Submit the same eligible read twice. Show one provider attempt and the second invocation linked to the original job.

## 5. Account routing

Using the scripted provider, make account A report exhausted credits, show the quota breaker, show
account B selected within the same pool, and show that the emergency pool is never selected as a
default or failover. If demonstrating emergency administration, use a synthetic secret entered at
the hidden prompt, bind it to one exact interactive session/root/pool, show the hard remaining
ceilings, then cancel or restart and show relock. Do not use crawl creation or real networking.

## 6. Watcher reservation

At component-test level, saturate interactive capacity, show the watcher-reserved slot and pool,
deny a target outside the feed set, and show a second durable run lease as a successful no-op. Defer
the stock-process watcher demonstration until its execution facade is wired end to end.

## 7. Approval

Submit an approval-requiring request, open the dashboard or use the CLI, approve once, modify the
request to invalidate approval, and demonstrate expiry to denial. Race approve and deny from
independent connections to show exactly one durable winner. The notifier entry point is
best-effort; do not claim automatic daemon notification emission unless that wiring is present.

## 8. Crash recovery

Start an asynchronous scripted crawl, terminate and restart the stock composition, re-adopt the
session, and show the same job, owner, provider principal, quota scope, credential generation, and
pool. Also show a `SETTLING` checkpoint resuming original quota and budget accounting without a
second provider call. The installed-process release test demonstrates the same restart boundary.

## 9. Reconciliation

Seed two persisted exact snapshots with provider usage absent from the ledger, make the scope due,
and show the stock daemon's provider-I/O-free QUICK/FULL result, high-severity incident, and local
quarantine. Show that QUICK and FULL retain separate durable baselines, a first observation does not
invent historical usage, and reusing the same current snapshot cannot increment the consecutive-
mismatch count twice. Keep the scope/time batch limits small for the demonstration and leave the
independent live observer disabled.

## 10. Security summary

Show no provider key in client environment, logs, or dashboard; no request body in persistent audit; the same-user residual-risk statement; and provider-side plus Gatehouse-side loss bounds.
