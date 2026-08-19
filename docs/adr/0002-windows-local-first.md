# ADR 0002: Windows-Local First Deployment

**Status:** Accepted  
**Date:** 2026-08-19

## Context

Primary workflows use native Windows, PowerShell 7, Git Bash, and Task Scheduler. Reliability of scheduled jobs is more important than introducing a cross-account service boundary in v1.

## Decision

Run v1 under the normal Windows account with loopback HTTP APIs, a user-scoped KeyStore, and a Task Scheduler watchdog.

## Consequences

Simple launch and notifications, direct workspace access, no hostile same-user credential isolation, mandatory provider caps and reconciliation, and a KeyStore interface reserved for later hardening.
