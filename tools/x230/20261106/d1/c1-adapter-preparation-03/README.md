# D1 C1 environment and sidecar adapter — unsealed preparation

This package prepares one diagnostic C1 comparison on accepted R24 plus the
diagnostic feature. It contains no qualification result, actual feature ELF pin,
future job ID, measurement output, or performance conclusion. The executable
template has SPEC = None and rejects before importing the original benchmark or
creating output. No runtime, benchmark, parser, Cargo command, or host request
was executed to prepare this package.

The same retained feature-enabled ELF will run in A = OFF and B = ON. The fixed
order is A, B, B, A. This compares diagnostic overhead and exposes recorded
phases. It does not compare a new production optimization with R24, and passing
this adapter does not adopt a production version.

## Frozen protocol

The four original R16 files are copied as exact bytes under reference/. They
were read as unique regular members from the verified R35 observation archive,
without extracting paths. The fifth reference is the reviewed diagnostic
summarize_trace.py; its source is also unchanged.

The original wrapper owns every controller, initializes its native stdio MCP
session, runs balanced warmup, calls the original cell, captures resources and
raw responses, closes stdin, waits, and performs its normal restart checks.
The adapter keeps Controller, its constructor/call/close methods, cell, benchmark
main, and wrapper main unchanged. There is no subprocess.Popen replacement, new
signal handler, extra child owner, fd-based ELF launcher, or second reaper.

| Item | Fixed plan |
| --- | --- |
| Controller ELF | One actual qualified feature-enabled ELF, identical path and SHA for A and B |
| Mode order | OFF / ON / ON / OFF |
| Concurrency | C1 only |
| Measured calls | 192 per round, balanced status/read across the same six original jobs |
| Warmup | 24 before each measured cell, outside its performance denominator |
| First controller preflight | Six original complete-output reads per round |
| Restart controller | Twelve checks, status and read for each same original job |
| Workers / allocator | Two Tokio workers / MALLOC_ARENA_MAX=1 for both arms |
| Repeats | Four rounds, eight original controller launches, no automatic retries |

The planned matrix has 768 measured, 96 warmup, 24 preflight and 48 restart
calls, totaling 936 native calls. These numbers describe the intended original
protocol; they are not future receipts. C8 is not authorized and the adapter has
no option to add it. Its command line cannot override the sealed dimensions.

## The single environment hook

The only new observation hook is bench.allocator.child_environment. It calls the
original allocator function and adds exactly:

- HEPTA_RUNTIME_PHASE_COST_MODE, OFF for A and ON for B.
- HEPTA_RUNTIME_PHASE_COST_OUTPUT, an absolute new phase-cost.trace.jsonl inside
  the original round directory's first/ or restart/ directory.
- HEPTA_RUNTIME_PHASE_COST_ELF_SHA256, the actual retained qualified ELF SHA.

No ambient diagnostic variable is accepted. Parent os.environ is unchanged.
The original base environment, SSH agent, allocator filtering and configured
allocator values are preserved. Only these three additions are recorded;
credentials or the full environment are not serialized.

A constructor context is accepted only when the immediate caller code object is
the exact original Controller.__init__ and its parent code object is the
original benchmark main. The hook checks the main thread, original self class,
binary, configuration, profile, directory, round index, arm, worker count,
optional flags and allocator arguments. Eight slots are preregistered in ABBA
first/restart order. Each slot is consumed exactly once before the original
Popen. The hook rejects duplicates, unknown paths and out-of-order calls.

The hook does not create the trace, retain a frame or controller object, alter
launch arguments, or acquire a child owner. It checks that the existing original
controller directory is owned, direct and mode 0700, and that the new trace
name is absent. The diagnostic runtime itself creates the sidecar with its
original exclusive/no-follow rules. Frame references and the hook are restored
in finally paths.

The short planned socket directory is /home/qian/hd1c01. The future outer parent
must create this exact fresh private directory once before the adapter starts.
The adapter only checks it. A directory under the long D1 root cannot satisfy
the original conservative Unix/OpenSSH temporary-socket path budget. Original
profile creation still performs that budget check; no symlink shortcut is used.

## Owner and failure boundaries

The existing original benchmark owns all Popen/wait/close behavior. Consuming a
slot or observing a trace path does not prove that a controller started, stopped,
or was reaped. The adapter requires the original report to contain the complete
four-round matrix and eight normal stdin-EOF closes, including reader EOF,
zero unmatched responses, no original reader/sampler error and no observed
surviving descendants, before opening any trace.

The original constructor still has its original operations between Popen and
its initialization try block. This adapter does not add a reaper around them.
If construction or original cleanup fails and complete original closure proof
is missing, the adapter records failure and leaves raw files untouched. It
does not interpret a partial trace as a complete CPU measurement, start an
extra round, retry a request, or invent a terminal. Any incomplete native/owned
agent closure remains an outer workflow blocker.

The original driver's error behavior is preserved. In particular, an individual
call recorded as unsuccessful can remain in the original matrix under the
driver's existing logic. This adapter neither filters those calls nor changes
the original continuation policy; it only refuses a complete diagnostic result
unless the original complete report succeeds.

The environment hook is restored immediately when original wrapper.main returns
or raises. The original raw report is read and hashed, never rewritten by the
adapter. New evidence is written separately, create-only, as attempt-input.json
and adapter-report.json in the sealed evidence directory. Raw original stdout,
native process receipts and all benchmark files remain available to the outer
collector.

## Timing and request selection

No sidecar is opened, hashed, parsed or formatted during any measured round.
The complete original wrapper returns first. The adapter checks all eight
original closes, unchanged source identities and the retained ELF, then loads
the exact original trace parser and starts offline analysis.

The first controller's ON trace includes six preflight calls, 24 warmup calls
and 192 measured calls. Its restarted controller has a separate trace with
twelve original checks. A whole first-controller trace is therefore not the
measured C1 interval.

For every original call, the adapter reads the exact frame referenced by the
original report, checks the original raw transport and index SHA/length, frame
offset/length/SHA, JSON-RPC ID and response hash, and obtains the native identity
from result._meta["io.hepta.runtime/request-v8"].request_id. This field is the
unchanged R24 request_results identity attached by native server audit; it is
not an adapter-generated ID. The diagnostic server binds the same audit ticket
ID into each trace request.

The join requires exact native ID sets on ON controllers and the same operation
and host. Categories come from the original report's actual arrays:

- initial_complete_outputs: preflight;
- cells[0].warmup.rows: warmup;
- cells[0].rows: measured;
- restart_checks: restart.

Warmup and measured calls both use the original purpose C1, so purpose alone is
never used for this distinction. Each selected request must fall inside its
original call interval and, when applicable, its original cell/warmup
raw_timing interval. Its native request scope must fall within the original RPC
call bounds. A boundary mismatch is retained as an adapter error; it is not
silently reassigned or removed.

The adapter binds each trace PID, start ticks and boot ID to the original
controller startup. Python's monotonic implementation must be Linux
CLOCK_MONOTONIC, the same explicit wall clock used in the trace. A trace begins
between original Popen timing and initialization readiness, and its footer must
precede the next original controller start or the original wrapper return.
Raw bytes and all non-measured groups remain retained.

The original trace parser validates its own bounded rows, footer, nesting,
thread identity and counters. Only explicit synchronous spans carry thread CPU;
async spans remain wall time. Selected requests expose the parser's recorded
synchronous exclusive CPU, with the original per-request selection category.
The adapter does not turn this partial instrumented CPU into whole-controller
CPU, SSH-child CPU, remote CPU or pure network delay. Those unavailable values
remain unavailable. Original controller CPU remains the original synchronous
same-PID/start-ticks counter delta in the untouched benchmark report.

OFF traces must have no request/event records. The adapter retains the OFF
original native request mapping but does not synthesize per-request CPU from it.
Nested phase wall totals remain non-additive. Startup/header/footer and final
serialization happen outside the 192-call interval; ON request bookkeeping
inside that interval remains real diagnostic overhead.

## Binding still required before any execution

input.unsealed.json lists the exact input shape. Actual values remain null.
The future sealed outer parent must bind the real first qualification terminal,
original eight-stage report and final 222-file source map, and prove that the
retained ELF was built with the diagnostic feature. The original qualifier's
all-features artifact supplies that feature-enabled binary. Any ordinary
empty-feature supplemental binary is a different artifact and cannot be
substituted.

The adapter checks these actual file pins and their basic map/report identity
when sealed. Its outer_input_manifest pin names the immutable original outer
input binding, not a live parent report, quiet result or continuously written
monitor ledger. Hashing that input is not verification of successful quiescence,
complete monitor evidence, held-agent ownership or native terminal streams.

The original held-agent workflow, original 90-second quiet stage, compiler
monitor, original native read-only auditor, exact source/binary identities,
native stdout/stderr and terminal completion, and final owned-agent reap remain
required outer evidence. This package does not implement or replace those
owners or gates. A future outer package must be independently reviewed and
sealed before use. No standalone adoption verdict is produced.

## Bounds and preparation checks

The original runtime trace bound remains 32 MiB per controller, at most eight
planned traces. Inputs and generated adapter evidence have explicit limits;
individual source files are at most 256 KiB, original report/transport/index and
new JSON evidence at most 16 MiB, and the retained ELF is hashed with a 128 MiB
bound. Files are read as owned single-link regular files with no-follow and
stable before/open/after metadata. Trace reads occur one controller at a time.

Preparation performs Python AST parsing and exact byte/hash/protocol comparisons
only. It does not import or execute the adapter, original benchmark, parser,
runtime or diagnostic helper. The unchanged source bodies and independent
review can be rechecked from the package's Git blob catalog.

The earlier draft-01 was retained as a source object and never executed. Static
inspection found its unsuitable long/fresh socket-parent assumption. The
replacement uses the original pre-existing short socket-parent contract.
