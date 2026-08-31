# Company Watcher

## Purpose

The watcher is an unattended client that monitors configured career and applicant-tracking-system
feeds without receiving broad provider access. The stock daemon now exposes a bounded synchronous
execution facade for the credential-free, no-network scripted Firecrawl workload only. This is a
deterministic local execution and verification surface, not a live-provider rollout.

Feed-set validation, workspace binding, schedules, durable single-run leases, budgets, cursors,
previous summaries, and reserved invocation-scheduler capacity remain server-owned. Gatehouse does
not yet start watcher scans on an internal periodic schedule; an external controlled client must
invoke the watcher during an allowed window.

## Identity

The controlled launcher creates a configured unattended session with
`CONTROLLED_UNATTENDED_LAUNCH` assurance. This proves possession of the watcher capability, not
origin from a particular process or Task Scheduler instance.

## Capabilities

Allowed:

```text
watcher.scan_feed_set
watcher.get_cursor
watcher.commit_cursor
watcher.get_previous_summary
```

Not allowed:

```text
arbitrary provider search
arbitrary URL scrape
arbitrary crawl
interactive approval
emergency pool
administrative API
```

## Feed-set resolution

Each feed configuration names its workspace and owns an ordered list of concrete targets. A target is
either a fixed `scrape` request or a `map` request with an explicit result limit from 1 through 100.
The list contains at most 64 entries, cannot exceed the per-run request budget, and the aggregate of
all map limits cannot exceed `crawl.maximum_pages`. Scrape payload options are fixed by Gatehouse.

At configuration load, every concrete URL and operation is checked against the same HTTPS host/path/
operation allowlist used at execution. The human workspace name is resolved to the durable opaque
workspace and current policy version before the feed is persisted. An existing feed identifier cannot
be silently rebound to another workspace.

The scan tool accepts a feed-set identifier and an optional expected cursor only. It never accepts a
URL, operation, provider payload, workspace, pool, or credential from MCP. Gatehouse resolves the
ordered targets, schedule, budgets, workspace, and cursor state from server configuration and durable
state. This prevents a stolen watcher capability from becoming general provider access.

## Synchronous scripted execution

For a configured scan, the stock facade:

1. verifies the caller's controlled unattended session, root run, configured workspace, watcher
   profile, and feed binding;
2. compares an optional expected cursor with the durable current cursor;
3. evaluates the feed schedule and acquires its single-run lease;
4. executes the configured scrape/map targets in order through the ordinary invocation coordinator,
   with `opening_monitoring`, public-job-data classification, `SYSTEM_RESERVED` priority, and the
   manual-only `watcher-reserved` pool;
5. returns the bounded step results and marks the run `READY_TO_COMMIT` only after every target
   succeeds.

The synchronous execution deadline is at most 30 seconds. Provider request and response bodies are
not written to watcher state, and returned step data has a two-MiB aggregate serialized ceiling. A
failed, timed-out, cancelled, budget-exhausted, oversized, or uncertain scan does not advance the
cursor.

## Reserved capacity

Admitted watcher target work uses the scheduler's `SYSTEM_RESERVED` queue and
provider-capacity reservations. The stock scripted route is additionally bound
to the watcher-reserved, manual-only pool configured for its feed set. Scripted
synthetic execution does not establish a live provider account or rate-limit
quota guarantee. Process-level capacity validation remains future work.

## Single-run lease

```yaml
lease_type: WATCHER_FEED_SET
lease_key: <feed_set_id>
maximum_holders: 1
maximum_runtime: feed_sets[].budgets.maximum_duration
```

A second launch does not queue. It returns a successful no-op with the existing run identifier.

## Schedule policy

Each feed set declares timezone, windows, and grace periods. A call outside the configured window
returns `OUTSIDE_SCHEDULE` without provider execution. The watcher never waits for approval; `ASK`
becomes immediate denial. This tranche does not add a separate stock anomaly-alert dispatcher for
outside-window calls.

## Budgets

Each run has explicit request, credit, page, and lease-duration ceilings. The synchronous executor
conservatively charges one watcher request, one credit, and one page per configured target before
dispatch; the ordinary coordinator independently retains its root-run and quota accounting. The
configured target count and aggregate map limits are also checked before startup. No per-period
watcher budget is added by this tranche.

## Cursor safety

Cursor commits are monotonic, versioned, run-fenced, and transactional. A successful scan stores a
small server-owned pending summary containing completed-target count and operation names. The MCP
caller cannot supply or replace that summary.

`watcher.scan_feed_set` does not commit a cursor. After processing the returned results, the caller
must explicitly invoke `watcher.commit_cursor` with the feed ID, watcher run ID, expected cursor
version, new cursor value, and increasing sequence. Gatehouse reconstructs the active session-bound
run fence, commits the server-owned summary with the cursor, and completes the run atomically.
Sequences are restricted to JSON-safe integers and a single commit cannot jump forward by more than
10,000,000,000,000, preventing one malformed watermark from permanently eclipsing ordinary values.
`watcher.get_previous_summary` returns only the summary attached to the last committed cursor. A
failed or incomplete scan does not advance past unprocessed results.

```text
read previous cursor
scan configured feed set
process returned results
explicitly commit the new cursor
publish the server-owned summary atomically
```

## Explicit deferrals

The following are not implemented by this bounded tranche:

- live-mode watcher execution or use of a real provider credential;
- asynchronous crawl targets or watcher-owned crawl job supervision;
- automatic redispatch, step-level resume, or continuation of an interrupted scan after a process
  crash;
- a daemon-owned periodic watcher scheduler or Task Scheduler installation workflow.

The existing invocation scheduler still supplies reserved queue and provider capacity after an
external controlled watcher call is admitted. Future process-level load and live-provider validation
remain separate, explicitly authorized rollout work.
