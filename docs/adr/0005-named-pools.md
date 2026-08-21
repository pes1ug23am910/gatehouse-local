# ADR 0005: Named Account Pools

**Status:** Accepted  
**Date:** 2026-08-19

## Context

Treating every provider key as one transparent pool would merge blast radius, blur attribution, and let interactive work consume emergency or watcher capacity.

## Decision

Use explicitly named interactive-default, watcher-reserved, and emergency-locked pools. Automatic
selection occurs only inside the selected pool. `emergency-locked` has no persistent member and is
never eligible as a default or failover. Its administrative workflow admits at most one credential
manually into process memory, binds it to an exact interactive session/root/pool, permits
synchronous use only, and enforces hard time, request, credit, and concurrency ceilings.

## Consequences

Predictable account use, reserved watcher availability, clear accounting, no automatic emergency
fallback, and additional configuration discipline. Emergency availability always requires an
explicit operator action and disappears on cancellation, expiry, shutdown, or restart.
