# ADR 0004: SQLite WAL Persistence

**Status:** Accepted  
**Date:** 2026-08-19

## Context

Gatehouse is a single-user local daemon that needs crash-safe state, concurrent reads, simple backup, and no external database service.

## Decision

Use SQLite in WAL mode with full synchronization, foreign keys, bounded busy timeout, short security-critical transactions, and a dedicated audit writer.

## Consequences

Simple local deployment and durable state, one active writer at a time, no network I/O inside transactions, and deferred migration to a server database until multi-host or multi-user requirements exist.

The stock daemon uses synchronous SQLite calls on the event-loop thread. Its configured busy wait
is bounded to at most 5,000 ms per SQLite busy handler, but a request may perform multiple calls.
Query execution, checkpoints and filesystem I/O can also block that thread. Async cancellation,
health polling and drain deadlines cannot preempt such a call. WAL and short transactions preserve
the intended concurrency and durability rules; they do not establish a latency SLA. No event-loop
latency measurement or dedicated serialized database worker is claimed for this implementation.
