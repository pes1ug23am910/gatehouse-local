# Operations

## Startup model

Gatehouse v1 runs under the normal Windows account. The supplied scripts can register the daemon at
user logon and a one-shot watchdog with Task Scheduler. The same validated configuration path is
passed to both processes.

The stock daemon acquires an operating-system file lock derived from the configured database path
before migration, recovery, provider setup, or listener startup. A competing daemon exits without
mutating database state or binding a second listener. The lock is released on clean shutdown and by
the operating system after process failure.

During `RECOVERING`, incomplete provision and rotation journals are reconciled against their exact
custody-intent alias. The DPAPI store may remove an absent or exactly owned marker, partial, or
token-derived staging file; it deliberately preserves mismatched markers and unrelated collisions.
An unresolved mutation remains cleanup-required and its candidate must not be routed. Do not delete
unknown custody artifacts manually or reuse their identifiers as a shortcut around this fence.

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
gatehouse --config C:\path\to\config.yaml credentials list --limit 50
gatehouse --config C:\path\to\config.yaml daemon stop
gatehouse-watchdog --once --config C:\path\to\config.yaml
```

`daemon start` launches the installed `gatehoused` without a shell and waits only for bounded local
liveness/readiness evidence. `status`, approval actions, dashboard login, policy explanation,
documentation, and feedback use bounded loopback clients with redirects and ambient proxy settings
disabled. Controlled client launch scrubs provider-secret environment variables before adding the
one-session Gatehouse bootstrap authority.

Administrative cookies live only inside one bounded CLI admin session and are cleared on any
loopback request failure before best-effort logout. Binary provision, rotation, and emergency
responses are not allowed to set cookies; a `Set-Cookie` header or exact active-secret reflection is
reported as the generic mutation failure. Provider HTTP is separately stateless and neither accepts
nor replays cookies between calls.

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
export credential material. The stock administrative surface exposes redacted credential state and
can provision or rotate secrets into current-user DPAPI custody, but it has no secret retrieval or
export path. A database backup contains custody references and redacted metadata, not a portable
plaintext credential bundle.

Restore metadata to a temporary location, run offline diagnostics and integrity checks, start
degraded with every pool disabled, provision replacement credentials only through a separately
reviewed local custody procedure, reconcile provider balances, and enable pools manually.

## Credential rotation

The CLI provision and rotate commands use a hidden interactive prompt. They do not accept a secret
argument, environment variable, file, stdin, or echo fallback. After the admin session, exact
loopback `Origin`, and CSRF checks succeed, the CLI sends safe metadata separately from a bounded
raw secret body and zeroes its mutable buffer. Provisioning can seal DPAPI custody while provider
mode is disabled and does not contact the provider.

The stock command accepts only a lowercase `fc-` token with at least 20 ASCII letters, digits, `_`,
or `-` after the prefix. `FAKE-` and `synthetic-` namespaces are test-only and do not constitute a
usable or verified provider credential. A format rejection occurs before custody or durable
mutation; do not work around it with arguments, environment variables, files, or direct database
writes.

`gatehouse credentials list` opens one bounded administrative session and returns only the strict
redacted credential summary: opaque identifiers, aliases, local state, generation, pool membership,
lease count, and timestamps. It does not open DPAPI custody and has no secret, ciphertext,
authorization-header, retrieval, or export field.

The mutation journal records a fresh non-secret staging alias before DPAPI creation. If the process
stops mid-create, restart recovery removes only artifacts proved to belong to that alias. Preserve
the original mutation identifier for idempotent inspection or retry; a `CLEANUP_REQUIRED` record or
mismatched custody marker requires review rather than broad filesystem cleanup.

Rotation creates a generation-fenced successor under the established principal and quota scope and
makes the predecessor `DRAINING`. New routing moves to the successor. Existing asynchronous
resources remain bound to the exact predecessor credential generation and pool for status,
cancellation, and settlement; rotation does not rewrite that affinity. A known terminal job moves
its exact affinity from `ACTIVE` to matching terminal evidence in the same transaction, while an
`UNKNOWN` result remains `ACTIVE` and blocks retirement until reconciled. After those resources and
leases are resolved, the operator may retire the predecessor locally and separately revoke the old
provider credential. Gatehouse does not perform provider-side validation or revocation as part of
the local mutation.

Disable and quarantine immediately close local routing. `RETIRED` is the irreversible local
terminal state. These state changes are audited and local-only; none implies that the provider has
revoked the corresponding key.

## Emergency unlock

Use `gatehouse emergency unlock` only from an interactive terminal. It requires a reason and exact
service, `emergency-locked` pool, session, and root-run authority; the secret is collected by a
hidden prompt and held only in the process-local in-memory KeyStore. Requested ceilings cannot
exceed 15 minutes, 25 requests, 100 credits, or one concurrent request. Only synchronous manual
work under the exact authority is eligible: crawl creation, client defaults, automatic selection,
and failover are denied.

`gatehouse emergency list` returns redacted status and remaining ceilings. `gatehouse emergency
cancel` immediately closes admission and zeroes/removes the in-memory secret. Expiry does the same.
Clean shutdown and startup recovery relock any formerly active record; restart retains redacted
SQLite authority and attempt evidence but no usable emergency credential.

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
clean-shutdown WAL checkpointing, incident inspection, and confirmation that emergency unlocks are
either absent or explicitly bounded and that restart recovery relocked prior authority.
Watcher-success review, provider-counter reconciliation, periodic retention, and
retention-pressure alerting require separately reviewed operator tooling until their stock-daemon
roadmap wiring is complete.
