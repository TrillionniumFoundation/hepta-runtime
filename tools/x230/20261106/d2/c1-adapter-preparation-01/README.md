# D2 C1 adapter preparation

This is new, unsealed D2 source preparation. It does not run a benchmark,
qualify a build, adopt an optimization or change the failed D1 campaign.
The accepted runtime remains R24. The original D1 parent and adapter remain
failed, and their original missing summary paths remain absent.

## Why this source exists

The completed D1 offline interpretation uniquely matched all 468 diagnostic-ON
requests, including 384 measured requests, to their original RPC intervals.
Validation accounted for 14.01373 ms/call, 86.43% of recorded synchronous CPU
and 61.08% of the measured controller CPU. D2 adds narrower validation phases
to distinguish the initial fresh open/check, the complete original content
loop, the final fresh check, and the existing identity/shell/policy checks.
The runtime source and trace-capacity changes are prepared independently.

D1's first adapter incorrectly required a public native request ID in
`process_status` and `process_read` responses. The existing runtime interface
does not expose it for those tools. D2 uses the correlation already established
by the completed D1 offline interpretation. It does not expose a new wire field
or change the original controller, resource sampler or workload.

## Reused code and exact changes

`correlate_trace.py` contains ten function bodies copied exactly from the
completed D1 interpreter, whose SHA256 is
`7857a1f8960e82cbb1ba7700c1e805b87f7363cf5d8c3fecf32c5ebbf0dfa870`:

- Strict JSON/canonical-byte and unsigned-integer helpers.
- Full original transport/index/RPC request and response verification.
- Bidirectional unique trace-span-to-original-RPC correlation.
- Phase arithmetic reconciled with every parser distribution and request total.
- Measured-only aggregation and signed controller-CPU residual calculation.

The new module supplies only a D2 root constant and the same six hosts and two
observation operations. It has no process launcher, host client, native auditor,
archive extraction or runtime mutation. Its caller provides only the exact
already-closed controller's raw transport and index byte streams.

The new adapter is constructed from the frozen unsealed D1 parent-template-05
adapter. The main changes are the D2 namespace, new helper-module loading,
`select_trace`, and the final matrix-level identity/coverage checks. The original
environment hook, original wrapper/cell/controller/Popen identity checks, close
validation, input readers and create-only output behavior are retained.
`source-construction.json` records each copied function hash and the changed
function set. `build_adapter.py` parses source only; it never imports or executes
the target programs.

## Correlation and failure behavior

No trace is read until the unchanged original matrix has returned and all eight
original controllers have normal close evidence. Each transport/index is read
through the original bounded reader and matched to the original shutdown
capture hash. Every raw frame, index range, sequence, JSON-RPC ID, original
request byte hash and response byte hash is checked. Original RPC timestamps
must be ordered and remain inside their original call and cell intervals.

Each trace is bound to the same original controller PID, birth ticks, boot,
qualified feature ELF and lifetime interval. For an ON controller, a complete
trace request span must lie inside exactly one original RPC interval with the
same host and operation, and every original call must have exactly one such
trace request. Unmatched, reused or ambiguous bindings fail. Across the complete
matrix, all 468 trace native IDs must be unique and 384 must be measured.
The observed wire native ID remains null; the internal trace identity is not
presented as an on-wire field. The original reader's `read_start` timestamp is
not used as the RPC's lower bound.

The D2 parser first validates the whole raw trace. The reused selective arithmetic
must reproduce every parser phase distribution, per-request CPU total and
whole-trace CPU total before selecting measured requests. OFF contains no phase
data and is not a zero-CPU observation. Preflight, warmup, measured and restart
categories remain separate.

With D2's additional nested spans, `validation_worker` and `validation_owner`
inclusive CPU represent their complete scope. Their exclusive CPU is the
remaining portion after subtracting their direct synchronous children. The
reference/hash loop labels include the original reads and cancellation checks
as well as comparison or hashing; neither label is pure read or pure hashing
cost. No nested wall intervals are added together. Controller-minus-recorded
CPU residuals retain their sign and are not assigned to SSH or networking.

The adapter still accepts no command-line workload changes and retains the
fixed six-host OFF/ON/ON/OFF C1 plan: 192 measured and 24 warmup calls per round,
two Tokio workers, six preflight and twelve restart calls per round. This is a
new D2 diagnostic campaign, not a replay that changes the D1 outcome. The
original native auditor remains a separate required parent stage.

## Sealing still required

`SPEC` is intentionally null. The retained old parser pin is explicitly an
unsealed placeholder and cannot qualify or launch this preparation. Before
execution, bind the exact reviewed D2 parser, D2 qualified source map and feature
ELF, original qualification/CI/ordinary receipts, and the reviewed D2 parent
input. The original held-agent lifetime, quiet period, compiler monitor,
source/ELF checks and stage ownership remain required by that parent.

No D2 workload, build, test, trace, performance result or new optimized release
is claimed by these files.
