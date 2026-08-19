# ADR 0003: Session Capability Attribution

**Status:** Accepted  
**Date:** 2026-08-19

## Context

Windows process identifiers recycle, and suspended or orphaned processes make process-tree inspection unreliable for durable attribution.

## Decision

Controlled launches mint a session bootstrap capability. Clients exchange it for short-lived access tokens. Persisted session state supports re-adoption after daemon restart.

## Consequences

Attribution survives process changes and restart; revocation and budgets are session-scoped; bearer theft remains possible under the accepted residual risk; child identifiers remain metadata, not a hard boundary.
