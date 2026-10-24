# A27 syscall publication: interpretation limits

These are complete sanitized copies of the original plan, report and review.
All 114 observation rows remain: six preflight checks, 96 instrumented calls,
and twelve final checks. Their result/error/retry flags, metric values, times,
resource counters and retained sampling-error entries remain unchanged.
Identity or opaque payload fields use the frozen A26 sanitizer policy and
hash receipts; the publication receipt binds both original and public bytes.

Two original flags remain true in the report:
`instrumented_cell.sampled_tree_cpu_seconds_delta_is_lower_bound` and
`shutdown_wrapper.resources.sampled_peaks_and_tree_cpu_are_lower_bounds`.
They are historical producer assertions, not valid guarantees endorsed here.
Cross-process samples are incomplete and not simultaneous. Differences of
sampled lifetime CPU counters are estimates and need not be rigorous lower
bounds for the corresponding cell interval. This publication records the
limitation separately rather than rewriting those original evidence flags.

The inherited helper tracked the strace wrapper as its root process. Its
`controller_cpu_seconds`, `controller_cpu_ms_per_call`, controller RSS/FD
fields and same-PID CPU-source text must not be read as isolated runtime CPU
or resource measurements. The plan's wrapper warning and review's explicit
interpretation flags remain present. Descendant aggregates and syscall
counts cover instrumented activity; they do not repair this attribution.

The syscall trace covers the complete traced controller lifetime including
local descendants. Instrumentation changes timing. Syscall error counts
are not RPC failures, and a futex syscall-time percentage is not a runtime
CPU fraction. This is neither a throughput comparison nor a user-space CPU
profile. There is one retained resource-sampling error in the original
report; its complete sanitized text remains present. Retaining that array
does not prove that all unsampled processes or unavailable fields were seen.

The six original job IDs are discovered from the source plan and bound to
full canonical hash receipts. The unchanged sanitizer replaces their string
occurrences with its existing private-identity markers. The original
`trace_commands` list keeps its order and row count, while each complete argv
row becomes the existing opaque argv receipt. No base64 or command payload
is decoded, no observation is replayed, and no raw evidence is modified.
