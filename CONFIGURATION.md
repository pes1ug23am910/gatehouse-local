# Configuration

## Principles

Configuration is declarative and schema-validated. It contains identifiers, limits, policies, paths, and provider metadata—not plaintext credentials. Unknown fields are rejected unless explicitly forward-compatible.

## Main configuration

See [`config/config.example.yaml`](config/config.example.yaml). Major sections cover installation and timezone, loopback listeners, database durability, session and approval TTLs, concurrency and queue limits, runaway detection, retention, reconciliation, watchdog behavior, and the provider runtime mode.

The stock loader also reads sibling `clients/*.yaml`, `policies/*.yaml`, and `feeds/*.yaml` files.
Configured human-readable names are synchronized to stable opaque SQLite identifiers at startup.

## Client profiles

Client profiles define interactive or unattended behavior, approval mode, priority, session and queue ceilings, capability families, and default provider pool.

The CLI uses configured client and workspace names for controlled launch. The daemon remains the
authority for the resulting opaque session, workspace, and root-run identifiers.

## Workspace policy

Workspace policy binds a canonical workspace to allowed services and operations, purposes, target constraints, data classifications, cost ceilings, approval rules, and a default pool.

## Feed sets

Feed sets replace arbitrary watcher URLs with a named policy object containing allowed hosts, path expressions, operation sequence, crawl limits, schedule windows, per-run budgets, and cursor behavior.

## Provider runtime mode

Provider transport is an explicit three-way switch:

```yaml
provider:
  mode: disabled
  network_enabled: false
```

- `disabled` is the default and creates no provider route.
- `scripted` requires `network_enabled: false` and a bounded
  `scripted_responses_path`. It creates synthetic, credential-free routing authority and is the
  production-composition test mode.
- `live` requires `network_enabled: true`, no scripted manifest, and a complete active route whose
  credential references match Windows DPAPI custody metadata exactly.

No mode transition retrieves, prints, or sends a credential during configuration validation.
Normal automated tests use only `disabled` or `scripted`; live-provider validation and shadow
rollout remain separate operator-controlled work.

## Credential custody

Configuration and administrative read models contain only principal aliases, quota-scope aliases,
pool membership, expiry metadata, scopes, generations, and exclusive/shared usage mode. The stock
admin API currently lists redacted credential metadata; it does not provide a secret export route
or a general credential-onboarding endpoint. Operational live credential provisioning and the
memory-only emergency-unlock workflow remain rollout work, not a configuration-file shortcut.

Installation-local control material, the DPAPI installation key, credential ciphertext, the
SQLite database, and the daemon lock live beside the configured database or in its derived state
paths. None belongs in source control.

## Environment expansion

Paths may support a narrow set of Windows environment substitutions such as `%APPDATA%` and `%LOCALAPPDATA%`. Expansion occurs before canonicalization. Arbitrary shell evaluation is prohibited.

## Validation failures

Startup fails closed when configuration is invalid, a pool references a missing scope, an
unattended client uses interactive approval, the watcher lacks reserved capacity, an emergency
pool is selected as a client binding or workspace default, a listener binds outside loopback, a
per-quota-scope limit exceeds its service limit, a sensitive operation lacks a cost/time ceiling,
or live routing cannot prove exact DPAPI custody. Policy separately denies automatic use of the
emergency pool; its future manual lease workflow is not part of the stock surface.

Session heartbeat intervals must be between one and 300 seconds. Both `stale_after` and
`reconnect_grace` must exceed the heartbeat interval. The daemon returns the validated cadence to
controlled MCP clients; stale reconnect grace is measured from the missed-heartbeat boundary.
