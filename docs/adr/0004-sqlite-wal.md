# ADR 0004: SQLite WAL Persistence

**Status:** Accepted  
**Date:** 2026-08-19

## Context

Gatehouse is a single-user local daemon that needs crash-safe state, concurrent reads, simple backup, and no external database service.

## Decision

Use SQLite in WAL mode with full synchronization, foreign keys, bounded busy timeout, short security-critical transactions, and a dedicated audit writer.

## Consequences

Simple local deployment and durable state, one active writer at a time, no network I/O inside transactions, and deferred migration to a server database until multi-host or multi-user requirements exist.
