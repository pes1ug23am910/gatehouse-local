# Disabled task review plans before native deployment

Date: 2026-09-10

Status: Accepted

The former task helpers used mutable repository Python, omitted configuration digest agreement,
overwrote fixed names and removed tasks by name. Disable these mutation paths with a fixed
terminating refusal before discovery, including WhatIf. Preserve compatible parameter binding
only to provide a clear error; do not infer permission from an existing task or a matching name.

Introduce a pure bounded planner with explicit runtime root/executable, opaque runtime-review
digest, installation/creation IDs, configuration origin/digest, account SID and frozen APPDATA/
LOCALAPPDATA expansion bindings. Validate raw lexical paths before normalization using a documented
ASCII subset. No filesystem access, user/environment lookup, clock or randomness is involved.

Return immutable canonical ASCII JSON bytes and SHA256. The two ordered intents are disabled,
deny demand start, use limited interactive principals and isolated/no-bytecode module argv with
the same config origin/digest. Both logon triggers are disabled. The watchdog intent repeats every
120 seconds with a 300-second outer execution cap; the daemon has no scheduler lifetime cap. These
are review settings, not native definitions certified against Task Scheduler defaults or XML.
Validation requires exact reconstruction of every field and byte under a 32-KiB bound. Unknown,
noncanonical, duplicated, malformed or rehashed definitions inconsistent with their bound inputs
or the fixed schema are refused with fixed errors.

No ownership receipt, native executor, command-line renderer or activation switch is introduced.
Plans explicitly retain unverified runtime/environment, unavailable registration and unconfirmed
ownership. A review digest is a supplied reference, not immutable runtime proof. The two supplied
configuration environment names do not constrain the full task environment.

Microsoft distinguishes creation from update in
[RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertaskdefinition).
A future adapter must still prove disabled creation and complete normalized readback. The
[DeleteTask interface](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask)
accepts a name without an expected-identity predicate; read-then-delete therefore cannot be treated
as atomic conditional removal. The documented
[ExecAction environment caching](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction)
also prevents treating current environment values as proof of future task execution values.

Native runtime ownership, interpreter/import closure, full environment enforcement, secondary
executable binding, pair-wide creation admission, uncertain outcomes and safe removal require
separate implementation and native verification. Pure tests and source refusal checks cannot
establish installed, host-task, live-provider or normal-use readiness.
