# Fixed-NTFS admission for mutable state

Date: 2026-09-10

Status: Accepted

Mutable-state path admission allowed removable and RAM drives without checking the filesystem.
Kind checks substituted safe-looking defaults when reparse attributes or link counts were absent.
Those checks could not establish the intended Windows state-path preconditions.

State entrypoints now require immutable, strictly typed volume facts identifying a fixed NTFS
volume before permission backend construction, metadata traversal or creation. A private injected
probe supports explicit synthetic tests and is forwarded through nested database-state operations.
The default adapter checks drive classification before querying the filesystem, uses bounded
native outputs and caches only native bindings. Volume facts are never cached as durable authority.

Kind checking requires valid mode, Windows attributes and positive link counts without coercion or
defaults. Reparse/symlink objects and multiply linked regular files remain forbidden. Non-Windows
development behavior remains explicit and does not invoke Windows volume APIs.

This is an initial admission check. It leaves owner/DACL/delete-child trust across ancestry,
identity-bound permission updates and atomic private creation unresolved. A future mutable-state
backend must retain trusted parent identities and create each child relative to an owned parent
with its private ACL at creation; replacing recursive mkdir alone is insufficient. Later SQLite
and custody opens also need integration review.

Tests use injected volume, metadata and ACL facts, in-memory adapters and screened fresh scratch.
Native bindings and actual drive/token/ACL behavior are not executed by that selection. Fixed NTFS
does not establish native isolation, race-free provenance, installed proof or normal-use readiness.
