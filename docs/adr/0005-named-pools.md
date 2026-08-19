# ADR 0005: Named Account Pools

**Status:** Accepted  
**Date:** 2026-08-19

## Context

Treating every provider key as one transparent pool would merge blast radius, blur attribution, and let interactive work consume emergency or watcher capacity.

## Decision

Use explicitly named interactive-default, watcher-reserved, and emergency-locked pools. Automatic
selection occurs only inside the selected pool. The emergency pool remains disabled and locked
until an operator-facing workflow exists; that future workflow must admit a credential manually
for a bounded memory-only lease.

## Consequences

Predictable account use, reserved watcher availability, clear accounting, no automatic emergency
fallback, and additional configuration discipline. Manual emergency intervention remains a
separate implementation milestone.
