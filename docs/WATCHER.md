# Company Watcher

## Purpose

The watcher is an unattended scheduled client that monitors configured career and applicant-tracking-system feeds. It is placement-critical and must continue during heavy interactive use without receiving broad provider access.

Feed-set validation, schedules, durable single-run leases, budgets, cursors, previous summaries, and
reserved scheduler capacity are implemented as bounded components. End-to-end watcher execution is
not yet wired through the stock daemon, so this document remains the contract for that final runtime
integration rather than a live-rollout claim.

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

The client submits a feed-set identifier. Gatehouse resolves it into hosts and paths, operation sequence, crawl limits, schedule windows, request and credit budgets, result schema, and cursor storage.

This prevents a stolen watcher capability from becoming general provider access.

## Reserved capacity

The watcher receives reservations at four layers:

1. queue slots;
2. provider execution slot;
3. rate-limit capacity or priority;
4. dedicated account pool or guaranteed quota floor.

A reserved credential without reserved queue and execution capacity is insufficient.

## Single-run lease

```yaml
lease_key: system-client/company-watcher
maximum_holders: 1
heartbeat_interval: 30s
stale_after: 120s
maximum_runtime: 30m
```

A second launch does not queue. It returns a successful no-op with the existing run identifier.

## Schedule policy

Each feed set declares timezone, windows, and grace periods. Calls outside the configured window are denied and alerted. The watcher never waits for approval; `ASK` becomes immediate denial.

## Budgets

Per run: maximum requests, provider credits, pages, duration, and concurrent provider operations.

Per period: maximum runs, minimum account floor, and optional daily or monthly ceiling.

## Cursor safety

Cursor commits should be monotonic and transactional. A failed scan must not advance past unprocessed results.

```text
read previous cursor
scan feed set
persist candidate results
validate completion
commit new cursor atomically
```

## Anomaly detection

Alert on requests outside schedule, unknown feed sets, unusual request or credit volume, repeated denied targets, overlap attempts, missing success beyond the expected interval, and provider usage without a matching watcher ledger entry.
