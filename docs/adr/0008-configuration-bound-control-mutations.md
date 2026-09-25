# ADR 0008: Configuration-Bound Control Mutations

**Status:** Accepted  
**Date:** 2026-09-10

## Context

A successful startup status check cannot prevent daemon replacement before a later control
mutation. An unfamiliar header on an old mutation path is also insufficient: an older daemon may
ignore that header and execute the request. Typed request handling can read a body before router
dependencies, so a dependency-only guard does not establish authorization before body ingestion.

## Decision

Move the five control mutations to `/v2/control` paths, remove v1 mutation dispatch, and provide no
CLI fallback. Keep `GET /v1/control/status`. Each mutation requires the existing installation
capability followed by exactly one expected-configuration-digest header matching the daemon's
frozen captured digest. A null server digest refuses mutations.

Place checks before the typed route handler. Defer recognized v2 mutation bodies through the
existing bounds middleware, and require the request to retain that exact bounded receive callback.
Missing or substituted bounds fail closed. Read authorized bodies outside the typed parser's
generic body-error translation, retaining byte/deadline responses. Keep the existing session DTO;
require empty bodies for the other four mutations before effects.

Send the digest from the CLI operation's retained settings. Owned cleanup retains its original
endpoint, capability and digest even after configuration changes. Refused cleanup remains pending;
do not rebind it to a replacement daemon or retry automatically.

## Consequences

Old clients and old daemons cannot silently use unbound mutation paths. A bare router or unsupported
middleware that replaces the receive callback cannot mutate. This is an application-level request
contract, not hostile-Python isolation. Each accepted control mutation has configuration agreement
with its serving endpoint; later admin-cookie/agent requests, authenticated watchdog probing,
native identity and installed-runtime verification remain separate contracts.

This extends [ADR 0007](0007-startup-configuration-digest.md) from startup status to individual
control mutations without claiming that the endpoint's digest identifies its process or executable.
