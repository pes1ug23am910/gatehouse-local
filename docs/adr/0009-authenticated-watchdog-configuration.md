# Authenticated watchdog configuration agreement

Date: 2026-09-10

Status: Accepted

The watchdog's public readiness probe could accept a responder without proving agreement with the
configuration captured by its launcher. It also treated all live degradation as a successful task
run, and some later transport failures could discard earlier response evidence.

The watchdog now uses the configured admin endpoint and existing installation capability to read
control status. Exact digest, strict typed state/readiness and actual HTTP 200 responses from both
configured listeners are required for acceptance. The public liveness probe supplies presence
evidence; it does not attest configuration. Control status remains HTTP 200 across daemon states.

Probe classification defaults to unverified. Mismatch and unverified outcomes are nonzero and do
not trigger restart. Received responses remain live evidence after body or close failure. Only
explicit connection failures on both listeners before any response permit the existing leased
restart. Other live-degraded outcomes are nonzero; a separate providers-disabled success requires
matched coherent disabled status and both provider channels configured disabled.

A private reader bounds raw identity-encoded JSON to 64 KiB and rejects malformed, duplicated or
nonfinite content. One asynchronous deadline covers requests and client closure. Controller and
owned-startup admission independently validate probe facts; a fake ready flag alone cannot admit
success. Owned startup retains its original digest/environment and cleans only its own child.

Older daemons without the digest and installations without a usable capability fail closed.
Capability content is not included in settings output, diagnostics or child environments. Tests use
explicit fake readers, transports and children; synchronous capability reads and noncooperative
native code are not made preemptively bounded by the asynchronous timeout.

This extends [startup configuration agreement](0007-startup-configuration-digest.md) while preserving
the separate [mutation fence](0008-configuration-bound-control-mutations.md). It does not authenticate
a hostile same-user server, prove executable/PID identity, bind later admin-cookie/agent traffic,
or establish native, installed, provider, normal-use or release readiness.
