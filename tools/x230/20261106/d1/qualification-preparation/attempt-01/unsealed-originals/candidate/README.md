# R24 phase-cost diagnostic preparation — recovery-02

## Status and purpose

This is a separately opted-in diagnostic candidate, based only on accepted R24 commit
**baab4def80be7af015b2e7a594cb302f66c4130e**. It is not an optimization, an adopted
runtime, or evidence of improved throughput, CPU, concurrency, or RSS.

The preparation has **not been formatted, compiled, Rust-tested, or executed on any
host**. No Cargo, rustfmt, SSH, x230/Mac API, fixture, or benchmark was run for this
revision. Future qualification, binary, native job, and measurement identities are
null in input.json. Existing acceptance thresholds and experiment controls are
unchanged.

The prior local preparation became inaccessible while its last edit was awaiting
an acknowledgement. Its final bytes and SHA are unknown. This recovery-02 was
reconstructed from independently hash-checked R24 Git objects in pure JavaScript,
and has its own patch and source identities. It does not claim to recover or
overwrite that unconfirmed draft.

The purpose is to locate material absolute costs behind the approximate
20 ms of **controller-process CPU per observation** discussed in the prior review.
That estimate excludes local SSH children and remote helpers. The preceding
R27-scale allocation evidence was at the microsecond level; this package does not
justify another optimization qualification on that basis. R35 remains a separate
frozen experiment; none of its command ownership or deferred JSON changes are
present here.

## Exact source boundary

The original 220-input map is retained byte-for-byte as baseline-source-map.json:

- SHA256: c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd.
- Git blob: 0d39eba02f860a1824f19313bb31f7011995eb54.
- Accepted Git root tree: b74e40052e275abe99c51df460e94622d516af34.

The candidate has 222 compile inputs: eleven existing paths change and two files
are added. The other 209 inputs retain their original bytes. source-index.json
lists every candidate path, byte count, SHA256, Git blob, and its relationship to
R24. source/ contains the thirteen complete changed/added files, not fragments.
candidate.patch independently reproduces those same files from the original map.

| Area | Change |
| --- | --- |
| Cargo.toml | Adds only the empty, nondefault phase-cost-diagnostics feature. |
| src/main.rs | Initializes an explicit diagnostic sink before transport startup and closes it after both original owners join. |
| runtime/mod.rs | Defines the Linux feature module and macros whose default branches retain the original expressions. |
| server.rs | Numeric status/read context, router CPU span, native audit wall spans, and original native request-ID binding. |
| jobs.rs | Status/read reference/encoding and original observation audit spans. |
| ssh.rs | Original preparation and JSON decoding CPU spans. |
| ssh_observation_pool.rs | Context handoff, original queue/admission markers, validation/SSH spans, and existing child identity annotations. |
| ssh_observation_validation.rs | Context crosses the same original blocking closure while retaining its existing ticket and permit. |
| Three existing pool test files | Nine constructors receive only a feature-gated default context; assertions and behavior are unchanged. |
| New phase_cost.rs | Bounded collector and private create-only sidecar output. |
| New phase_cost_tests.rs | Six diagnostic custody/context contract tests, written but not run. |

Cargo.lock, dependency versions, all six release-profile settings, ssh_direct.rs,
ssh_observation_profile.rs, the post-spawn proof implementation, original embedded
Python, and original remote helper protocols are unchanged. There is no reserve
lane, router cache, pidfd cancellation wait, path cache, JSON deferral, or command
ownership move.

## Opt-in and ordinary release behavior

Both a Cargo feature and an explicit runtime mode are required to record data.

| Build / invocation | Behavior |
| --- | --- |
| Ordinary build, feature absent | No diagnostic module, clocks, environment checks, collector fields, or sidecar output. |
| Linux feature build, mode absent | No collector or output. Diagnostic output/hash variables without a mode are refused. |
| Linux feature build, mode=off | Same fixed slot allocations and durable header/footer, no request events. |
| Linux feature build, mode=on | Fixed slots and request-scoped records. |
| Feature selected on non-Linux | Explicit compilation refusal. Ordinary non-Linux builds keep their old path. |

The explicit variables are HEPTA_RUNTIME_PHASE_COST_MODE=on or off,
HEPTA_RUNTIME_PHASE_COST_OUTPUT, and HEPTA_RUNTIME_PHASE_COST_ELF_SHA256.
Only stdio with an explicit runtime configuration and observation profile is
accepted in diagnostic mode. A tool request cannot enable the diagnostic mode or
choose its output path.

diagnostic-entry.py verifies the exact supplied ELF SHA256 through one retained
descriptor and uses fd-exec. It retains PID, session, stdio, and all original mcp
arguments, adding only the three diagnostic variables. It does not spawn a helper,
compile, change a profile, start an agent, or retry. The descriptor/hash check does
not prove a Cargo feature, nor prevent an authorized concurrent same-inode writer;
the independently frozen build manifest and external binary custody are still
required. The Rust header calls its ELF identity declared, not self-verified.

A future invocation has this shape, with actual pins supplied only after a real
build and review:

    python3 -B diagnostic-entry.py \
      --binary /absolute/frozen/diagnostic-elf \
      --expected-elf-sha256 ACTUAL_LOWERCASE_SHA256 \
      --mode on \
      --output /absolute/new-private-cell/trace.jsonl \
      -- mcp ORIGINAL_EXPLICIT_ARGUMENTS

This is an entry example, not a sealed campaign command. No actual ELF, directory,
job, or future success has been invented in this preparation.

## What each record means

Only the exact process_status and process_read routes create request contexts.
The internal slot is allocated before router construction; the actual native
request ID is attached only after the original native audit admission returns.
The context crosses the original pool Request as a feature-gated Copy field.
It is restored on the sole actor and explicitly carried into the original
validation/audit blocking closures. Unrelated spawned tasks and maintenance do
not inherit it.

Each row contains fixed enums and numeric identities/timestamps. No arguments,
stdin payload, output content, environment values, key material, or credentials
are logged. The bounded startup table contains configured host aliases; requests
store only an index into that table.

| Record family | Timing and exact scope |
| --- | --- |
| Request | Whole request wall interval, not success or per-request process CPU. |
| RouterBuild | Synchronous controller thread CPU and wall for the original router constructor. |
| NativeAuditBegin / NativeAuditFinish | Original future wall only. Their separate worker CPU is not attributed. |
| CheckJobReference | Original reference-check future wall. Its worker CPU remains unattributed. |
| PrepareObservation / DecodeObservation / EncodeObservation | Synchronous CPU and wall around the original preparation/serialization expressions. |
| LogicalAdmission | Original immediate admission16 try-acquire and error mapping; there is no new wait. |
| QueueReservation | Original channel reserve select wall including its existing deadline/stop outcomes. |
| QueueSubmitted / QueueReceived / InitialCapacityGranted / OwnerExecute | Markers at original handoffs; their differences contain scheduling/fairness as well as waiting. |
| AdmissionProfile / PreCaptureProfile / PostCaptureProfile | The three original full profile futures, wall only. |
| ValidationPermit / ValidationBlockingQueue | Original semaphore and submitted-to-started blocking-closure wall. |
| ValidationWorker / ValidationOwner | Each original whole six-file validation loop; synchronous CPU and wall, including the original current-owner checks. |
| AgentSnapshot | The original bounded agent-frame future, no added frame or probe. |
| MasterEntry / HostCapacity / MasterReady / GlobalCapacity | Original futures/selects; wall intervals overlap and do not isolate a pure lock cost. |
| Arguments / ExpectedArgv / ProcessIdentity | Existing synchronous argument and original identity preparation. |
| ChildRegistry | Original child-ledger lock select wall. |
| Spawn | The synchronous parent-side Command::spawn call, not pure fork/exec or child CPU. |
| PostExecProof | Only the existing wait_empty_argv future; other proof work is outside this named wall span. |
| SocketConnect / SocketAndBoundary | Original local Unix socket connect wall / peer lookup synchronous CPU and wall. The latter does not time all boundary checks. |
| Capture / StdinWrite / StdoutDrain / StderrDrain / ChildWait | Original capture and four joined I/O/wait futures. Their intervals overlap. |
| AuditPrepare / AuditMutex / AuditCritical / AuditWrite / AuditSync | Original observation-audit preparation, mutex, critical section, write, and mandatory fdatasync. |
| Binding | Markers with the existing deadline budget, master generation, OwnedChild id/PID/birth ticks, or captured byte lengths. |

The queue-derived intervals are explicitly channel wall, pending-until-initial-
global-grant wall, and dispatch scheduling wall. A capacity permit has already
been granted at the corresponding marker. They are not separately measured CPU,
not a new queue, and not proof that every elapsed nanosecond was semaphore wait.

All twelve original complete file-set validation passes remain on the normal
warm successful observation path: three request profile checks, two verify_files
calls in each, worker plus owner full reads in each call. Each set contains six
fixed files. That is a static count of 72 fixed-file verification calls, not a
physical disk-I/O count or measured CPU cost. Cold renewal, lifecycle/background,
and failed paths can differ. No metadata-only substitution, cached FD, inode,
content, authority, skipped hash, or weakened permission check was introduced.

## CPU and wall accounting

CLOCK_MONOTONIC records phase wall spans. CLOCK_THREAD_CPUTIME_ID is read only in
synchronous lexical spans that contain no await. SyncSpan contains an Rc phantom
and is not Send. Its start/end TID must agree. A thread-local parent span records
synchronous nesting; the raw rows retain both inclusive CPU endpoints.

The static source check finds eighteen synchronous wrappers, each with no await
token in its measured body. This is a bounded source check and review aid, not a
Rust compiler result or proof about arbitrary hidden call graphs. The selected
bodies call the same original synchronous operations.

An async span has no CPU endpoints, even on the current-thread owner runtime.
Another request can run while it awaits. Process CPU deltas at phase boundaries
are never assigned to individual concurrent requests.

summarize_trace.py validates complete slots, native IDs, clocks, parent IDs and
nesting before calculating CPU. Direct synchronous children must share the
request/TID and fit within both parent intervals. Exclusive CPU subtracts only
those direct children. Phase wall distributions are explicitly nonadditive.
Raw rows and raw SHA remain the primary evidence.

The instrumentation itself costs atomic operations, clocks, cache traffic, and
some parent-span CPU. Event bookkeeping occurs after its own endpoint and can be
charged to a surrounding parent's exclusive remainder. These are instrumented
costs, not exact uninstrumented costs. OFF/ON using the same diagnostic ELF is
needed to quantify perturbation. Feature-off source equivalence is not a claim
of binary-byte equality.

## Bounded storage and output custody

The fixed limits are 32,768 events, 2,048 request slots, 128 ASCII bytes per native
request ID, 64 host aliases of at most 128 bytes each, and a 32 MiB output file.
Slots are allocated once as boxed OnceLock arrays. Each atomic index has one
writer; there is no collector mutex, per-event string allocation, or hot-path
file write. Atomic contention and the memory cost are still real overhead.

The header records architecture-specific logical slot sizes. Those sizes exclude
allocator overhead, host strings, buffers, thread stacks, and RSS. Mode off uses
the same fixed storage. The package makes no memory-reduction claim.

The output must be a new file under an owned mode-0700 parent. The helper starts
from a fresh root directory, opens every ancestor with no-follow directory
semantics, and creates the final mode-0600 regular file exclusively. It retains
only its own diagnostic sink/parent descriptors. Fresh path checks must still
match those descriptors before and after explicit flush/sync.

A durable header is written before transport startup. During requests, evidence
stays in bounded memory. After both original transport owners return, the
collector freezes admission, emits original rows and a footer, explicitly
flushes/synchronizes, and rechecks its own output binding. Overflow, missing
native IDs, abandoned spans, clock/stack errors, active work at freeze, or
incomplete owner shutdown prevent a complete recording window.

BufWriter is stored in an Option and consumed with into_parts on Drop. A failed
or unrequested flush is not implicitly retried by destructor cleanup. Partial
bytes remain; no trace is deleted, truncated, renamed over another original, or
silently restarted. The byte bound is not an I/O wall deadline: a stalled
filesystem can delay diagnostic shutdown; an external timeout remains incomplete
evidence. A hard kill or panic-abort may leave only a header; the raw parser
refuses it as complete.

Main still joins both original owners before propagating either original error.
The error order remains direct cleanup, pool cleanup, transport, then diagnostic
result. Early diagnostic Drop preserves the original error and can only attempt
an explicitly incomplete footer. No diagnostic path signals, reaps, replaces, or
retries a runtime child, and no data-completeness flag proves business success.

## What this preparation cannot determine

The first-stage implementation deliberately leaves these quantities unavailable:

- Total controller CPU must still come from the same original controller
  PID/start-ticks counter interval. The trace does not measure that counter.
- Local SSH child CPU is not exported by the original wait API. There is no
  second reaper, new rusage consumer, or inference from 100 ms sampled trees.
- Remote helper CPU and Python interpreter startup are not instrumented.
- Network-only latency cannot be obtained by subtracting remote time or comparing
  monotonic clocks on different hosts.
- Native audit/reference worker CPU, uninstrumented synchronous work, unrelated
  requests, maintenance, cold/master initialization work, and background work can
  remain outside the named synchronous buckets.
- Queue, capture, agent and master spans combine multiple causes. A large span
  alone does not identify CPU, network, disk, scheduler, or a specific lock.
- The aggregate six-file validation spans do not identify an individual file's
  read/hash cost.

Unmatched controller CPU must stay unattributed, including negative residuals
that expose incompatible intervals/measurement overhead. No residual is rounded
away or relabeled network. The parent/child process ledger, source/binary
identities, native status/read evidence, and original harness results remain
necessary outside this raw-trace parser.

Header/output setup and final JSON/sync have their own costs outside the recorded
request spans. A future campaign must state whether its actual controller CPU
endpoints include them. It must not subtract an assumed flush cost or compare
different OFF/ON intervals.

## Static evidence and future validation

static-review.json records the pure-JavaScript checks actually performed:
all 220 original SHA256 values; reversible edit ledger; exact applied-patch
roundtrip; balanced Rust token groups; unchanged lock/dependencies/release
settings; and normalized default tokens. The macro normalizer removes only the
declared diagnostic cfg/items/wrappers plus one redundant Live break block.
All ten modified original Rust paths normalize to R24 tokens, and the mod.rs
original module tail is byte-identical.

That result does not replace compiler/type/borrow checks, rustfmt, Clippy,
original correctness gates, or feature-enabled regression tests. The new tests
cover concurrent immutable slot retention, overflow without overwrite,
create-only/nofollow output, byte-limit partial retention, no Drop flush, and
explicit task/blocking context propagation without unrelated-task inheritance.

materialize_static.py can independently verify the pinned package and original
R24 directory, apply the unified patch, compare every full source file and map,
check TOML/lock identity, parse Python tools with ast.parse, and optionally create
a new complete source tree. It never runs runtime code, Cargo, rustfmt, fixtures,
or tests. The full materializer entry point has not run. The local executor later
recovered; the separately retained static execution receipt records the Python
AST/source/TOML and helper patch-replay checks actually performed. It does not
represent Rust execution or a materialized, qualified runtime.

Any future source formatting changes require a new exact final source map and
binary binding. Both ordinary builds and the explicit Linux feature build need
real correctness/CI verification before any diagnostic run. Existing R24 release
settings and locked dependency versions remain; future commands must be offline
and locked against the established cache, with actual toolchain/environment pins.

The already-published diagnostic-plan-01 remains the scheduling boundary:
initial C1, six hosts, original status/read mix, 192 calls per cell, fixed
OFF1/ON1/ON2/OFF2. An optional C8 stage requires a decision sealed before execution;
C16 is outside the initial scope. There is no automatic retry or best-run
selection. Reuse the original held-agent, 90-second quiet, compiler monitor and
owner-closing controls when the parent schedules it. This package supplies an
entry and parser, not a newly executed or sealed outer campaign. Actual control,
cell and binary pins remain null.

Existing optimization acceptance ABBA thresholds are not modified by diagnostic
findings. A useful result identifies a material absolute cost and supports a
separately scoped optimization hypothesis; it does not itself authorize adopting
a new runtime.
