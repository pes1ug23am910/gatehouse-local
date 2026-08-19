# Operations

## Startup model

Gatehouse v1 runs under the normal Windows account. The supplied scripts can register the daemon at
user logon and a one-shot watchdog with Task Scheduler. The same validated configuration path is
passed to both processes.

The stock daemon acquires an operating-system file lock derived from the configured database path
before migration, recovery, provider setup, or listener startup. A competing daemon exits without
mutating database state or binding a second listener. The lock is released on clean shutdown and by
the operating system after process failure.

## Health states

- `RECOVERING` — migration, integrity, authority recovery, and the initial due-job pass are in progress.
- `READY` — mandatory components and the first recovery pass are available.
- `DEGRADED_READ_ONLY` — status, docs, audit, and diagnostics available; provider calls denied.
- `DEGRADED_NO_PROVIDER` — policy and persistence healthy; no eligible provider credential.
- `DRAINING` — no new provider work during shutdown.
- `FAILED_CLOSED` — policy, migration, integrity, or redaction safety failure.

The process can be live while it is not ready. Provider admission remains closed throughout
`RECOVERING` and `DRAINING`; the readiness endpoint returns success only for `READY`.

## Health endpoints

```text
GET http://127.0.0.1:47621/health/live
GET http://127.0.0.1:47621/health/ready
```

Suggested watchdog defaults:

```yaml
interval: 2m
readiness_timeout: 30s
maximum_restarts: 5
restart_window: 10m
crash_loop_cooldown: 15m
```

The watchdog uses a restart lease to prevent simultaneous restart attempts.

## Installed control

```powershell
gatehouse --config C:\path\to\config.yaml daemon start
gatehouse --config C:\path\to\config.yaml status
gatehouse --config C:\path\to\config.yaml dashboard
gatehouse --config C:\path\to\config.yaml daemon stop
gatehouse-watchdog --once --config C:\path\to\config.yaml
```

`daemon start` launches the installed `gatehoused` without a shell and waits only for bounded local
liveness/readiness evidence. `status`, approval actions, dashboard login, policy explanation,
documentation, and feedback use bounded loopback clients with redirects and ambient proxy settings
disabled. Controlled client launch scrubs provider-secret environment variables before adding the
one-session Gatehouse bootstrap authority.

## Graceful shutdown

```text
state → DRAINING
reject new provider invocations
continue status and cancellation
wait up to drain deadline
cancel queued work
run one final bounded due-job/cancellation pass
checkpoint the SQLite WAL
release local leases
exit
```

The stock lifecycle currently uses a five-second drain deadline. Queued or in-flight work cannot
extend shutdown indefinitely. A required listener, scheduler pump, or job-supervisor failure
changes the daemon to `FAILED_CLOSED` and returns a failing process status.

## Provider modes

Keep `provider.mode: disabled` for configuration and control-plane operation without a provider.
Use `scripted` only with a local response manifest when deterministic, no-network behavior is
required. `live` additionally requires `network_enabled: true` and validated DPAPI-backed routing
metadata. Those settings make the live transport available; an actual call still requires ordinary
session, policy, quota, and any applicable approval admission. Gatehouse has no separate global
"operator authorized" runtime switch. Project operating procedure therefore requires explicit
human authorization before live validation. Live mode is not part of routine tests.

## Backup and restore

A backup includes the SQLite database and schema version plus configuration and policy. V1 does not
export credential material. The current stock administrative surface exposes redacted credential
state but does not implement credential import or secret export.

Restore metadata to a temporary location, run offline diagnostics and integrity checks, start
degraded with every pool disabled, provision replacement credentials only through a separately
reviewed local custody procedure, reconcile provider balances, and enable pools manually.

## Credential rotation

1. provision the replacement credential through the reviewed local custody procedure;
2. validate provider identity without a billable request where possible;
3. place it in the correct quota scope;
4. mark the old credential draining;
5. wait for active leases to close;
6. disable and revoke the old credential;
7. reconcile;
8. remove the old encrypted record.

## Emergency unlock

The architecture requires emergency credentials to be entered manually and held in memory only,
with reason, session/root-run scope, duration, request, and credit bounds. The stock admin surface
does not yet expose this unlock workflow, so an emergency pool must remain disabled and locked.

## Reconciliation

- target quick cadence: every 6 hours;
- target full cadence: weekly;
- opportunistic: after configured thresholds;
- on demand: before and after rotation or an incident.

The reconciliation engine and durable store implement reset-aware mismatch handling and local
quarantine decisions. Periodic quick/full orchestration is not yet part of the stock daemon loop;
until it is, these cadences are operator-run rollout targets rather than an automatic-service claim.

## Watcher operations

Watcher lease, budget, cursor, feed-set, policy, and reservation components are implemented. The
stock watcher execution facade is not yet wired end to end, so the following describes component
behavior rather than an available stock-process workflow: one active-run lease, a successful no-op
for a second launch, and immediate denial rather than an approval wait when policy returns `ASK`.

## Maintenance

Current stock maintenance includes health and status review, database backup and integrity checks,
clean-shutdown WAL checkpointing, incident inspection, and confirmation that emergency pools remain
locked. Watcher-success review, provider-counter reconciliation, periodic retention, and
retention-pressure alerting require separately reviewed operator tooling until their stock-daemon
roadmap wiring is complete.
