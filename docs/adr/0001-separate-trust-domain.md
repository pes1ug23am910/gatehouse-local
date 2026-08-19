# ADR 0001: Keep Gatehouse in a Separate Trust Domain

**Status:** Accepted  
**Date:** 2026-08-19

## Context

The project stores live credential metadata, authorization policy, audit state, and provider usage. Combining it with unrelated registries would widen the trust boundary and complicate backup, access, and failure analysis.

## Decision

Gatehouse uses a separate repository, state directory, configuration directory, database, and backup policy.

## Consequences

Clearer secret and state ownership, independent migration and recovery, no accidental coupling, and additional repository/deployment setup.
