# ADR 0007: Configuration Agreement During Daemon Startup

**Status:** Accepted  
**Date:** 2026-09-10

## Context

A consumer can verify a new configuration bundle while an older daemon remains available on the
configured loopback endpoint. Readiness and policy version alone do not identify the complete
bundle loaded by that daemon.

## Decision

Freeze the verified bundle digest before mutable stock composition and report it as `config_digest`
through the existing installation-capability control-status route. Require exactly 64 lowercase
hexadecimal characters when present; explicit snapshot-less in-memory composition reports null.

Before accepting startup or waiting on a recovering owned child, CLI `daemon start` compares each
successful decoded control response to its operation's verified expectation. A missing, null,
malformed or mismatched field causes a fixed refusal outside unavailable-transport fallback.
Refusing an existing responder does not start or stop a process. Failed owned startup keeps the
existing bounded cleanup of only its child.

## Consequences

Older daemons without the field cannot satisfy this startup contract. Public health endpoints and
watchdog behavior remain unchanged. Matching digests establish configuration agreement reported by
the control endpoint; they do not identify its process or executable, prove that it is the owned
child, isolate hostile same-user code, or prevent replacement before a later request. Same-request
configuration fencing for control mutations and authenticated watchdog probing remain separate
designs. Native and installed-runtime verification remain necessary before deployment claims.
