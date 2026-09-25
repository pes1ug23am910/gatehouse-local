# Adjacent daemon executable selection

Date: 2026-09-13

Status: Accepted

CLI and watchdog startup previously accepted arbitrary supplied daemon paths and searched PATH
when an adjacent executable was unavailable. That allowed secondary executable selection to leave
the active interpreter's directory.

The selector now derives only the platform daemon name beside one captured interpreter pathname.
It validates exact strings and bounded absolute literal spelling without filesystem, environment,
PATH or current-directory discovery. An explicit executable is an exact spelling assertion of that
same result. Inputs and output are limited to 4,096 characters, 128 components and 255 characters
per component. Ambiguous components and unsupported platform values are rejected.

CLI and watchdog wrappers accept only a concrete native Path override or None. They perform one
availability check for the selected pathname. Ordinary failures return fixed unavailable outcomes
before spawning; control-flow interruptions propagate. Configuration digest/environment forwarding,
owned-child cleanup and authenticated existing-responder acceptance retain their prior contracts.

Installations with script launchers in a separate directory do not satisfy this layout. Literal
comparison is deliberately strict, including case and an uppercase Windows drive letter. A Path
provided by a caller may already have normalized its original spelling.

This establishes pathname selection only. The following availability query neither rejects every
native alias nor attests file identity, trusted ancestry, immutable interpreter/import closure or
atomic execution. It also does not impose a preemptive filesystem deadline. Native task/runtime
ownership and installed verification remain separate requirements.

The selected source tests use pure strings and fake metadata/process adapters. Passing them is not
native, installed, provider or normal-use readiness evidence.
