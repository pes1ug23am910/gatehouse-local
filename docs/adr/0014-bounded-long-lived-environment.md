# Bounded long-lived process environment

Date: 2026-09-13

Status: Accepted

The daemon/watchdog environment allowlist previously string-coerced arbitrary objects, silently
resolved case-insensitive duplicates, dropped invalid retained values and accepted unbounded data.
Those transformations could obscure the APPDATA/LOCALAPPDATA context used for configuration capture.
The native CLI runner also reused a mutable mapping across subprocess calls.

Keep the existing allowlist and validate before configuration discovery or child effects. Names
and retained values must be exact strings with strict UTF-8 encoding and no NUL, CR or LF. Excluded
values are not converted or inspected. Non-ASCII names are excluded before case normalization, so
Unicode case mappings cannot alias an ASCII allowlisted name. Every duplicate canonical retained
name is rejected, including duplicates with equal or empty values. Accepted values, including empty
strings, remain exact; output keys are sorted uppercase names.

| Bound | Limit |
| --- | ---: |
| Source entries | 512, with at most one extra observation to detect overflow |
| Characters per source name | 256 |
| Aggregate source-name UTF-8 bytes | 65,536 |
| UTF-8 bytes per retained value | 8,192 |
| Defined output block UTF-8 bytes | 32,768 |

Check retained character length before encoding. The output budget includes one final NUL and,
for each entry, name/value byte lengths plus two bytes for '=' and its terminator. This is an
application data budget, not a claim about a native operating-system environment-block ABI.

Ordinary input and iterator failures produce only EnvironmentValidationError(ValueError) with
`long-lived process environment is invalid`. Its construction uses no rejected text or object
coercion, and the builder raises outside its exception handler. Control-flow interruptions propagate.
A bounded number of iterations cannot preempt a blocking custom mapping callback.

Native CLI runners and watchdog settings freeze validated mappings. Each subprocess API receives
a fresh explicit dictionary without ambient merging or rereading. Configuration capture and child
creation retain the same expansion values. Daemon/watchdog entrypoints handle invalid environments
before normal parser/default-path discovery or execution. The default CLI app factory handles typed
capture failure and refuses commands through its root callback before configuration changes or
secret prompts; help may remain available. Watchdog restart keeps its fixed refusal outcome.

The allowlist still includes PATH, profile, temporary-directory and trust-store values. Their
contents are not native ownership or provenance evidence. Python startup already precedes this
validation, and controlled-client inheritance is a separate contract. Native runtime/import closure,
scheduled-task enforcement and hostile same-user isolation are not established by fake-backed source
tests. Installed and live readiness remain separate gates.
