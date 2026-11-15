# Shell foreground controller: private HIA ABI v1

This Linux x86-64 owner composes the existing HIA process owner, log IO owner and
outcome formatter. It accepts an already-owned capture pair. Request/MCP admission,
background prepare/registry, spawn-error discard/text, promotion registry/text and
background callbacks remain separate. Other process events remain observations.
Production activation, whole-runtime replacement and old-stack removal are false.

## Entry and input

f0(readbuf request, mutbuf descriptor, mutbuf private_work) -> u32.

The exact request is HSHFGQ01 followed by four little-endian Q words: operation,
capture token, command byte length, raw cwd byte length; then command and cwd.
Operation 1 starts; 2 advances; 3 cancels the foreground caller; 4 shuts down the
tracked child. Operations 2/3/4 have both lengths zero and exactly 40 bytes.
Command is strict UTF-8. Cwd is arbitrary Unix bytes. NUL keeps the process owner's
original spawn-error semantics. Token is nonzero and remains bound. Repeated op1
must have byte-identical admitted command/cwd. No caller supplies a PID, FD,
pointer, completion or syscall.

A fresh workspace is zeroed and at least 8192 bytes. The copied process start
frame at 4096 must fit in advertised capacity. Descriptor capacity is at least64.
Private capacity is transport, not a new command/log semantic quota.

Return 0xfffffff0 is pending; 0xffffffff malformed input; 0xfffffffe private buffer
capacity; 0xfffffff9 private state/completion contract; 0xfffffff8 infrastructure
allocation/bridge failure. All preserve the complete output. Return0 retires
without output. Infrastructure failures never become command/read Results.

## Published borrowed output

Success is fixed64 and eight Q words:
HSHFGD01, sequence, capture token, source token, offset, length, event kind, zero.
Extents are u64. Source1 is controller workspace; source2 its owned outcome output.

| Event kind | Complete loan |
|---:|---|
| 1 | HSHOUR01 foreground response including all text |
| 2 | Exact96B HSHPRR01 non-foreground process observation |
| 3 | HSHFGC01, token, 1, 0: four Q words acknowledging IO-stage cancellation |

The controller consumes process kind2 itself. The native bridge maps only owned
source spans, copies/queues the complete descriptor and loan, and then may
advance f0. Next entry acknowledges consumption and permits storage reuse.
No host branch interprets event kind or decides an outcome. Backpressure must
not leave borrowed pointers live after advance or stop child/IO custody.

## Lifecycle owned by HIA

After actual process kind2, HIA maps raw wait status or raw errno into HSHOIQ01
and starts IO before requesting process quiet retirement. It continues process
orphan custody independently. Wait errors never skip either stream/discard;
the unchanged outcome owner selects all error priority and text.

IO first ADMIT is seeded from controller statx capability state0/1/2 before
dispatch, then completion/cancellation snapshots it back. The bridge only
copies this field at the admitted phase. Fresh controller state is Unknown.
Cross-controller process-global cache sharing requires an enclosing HIA owner
and is not claimed by the one-invocation fixture.

Cancel before foreground completion queues op3 for process. The unchanged process
entry consumes only completed private effects: HIA waits for POLL to commit ready1
before forwarding op3/op4. IO separately supports cancellation while ready0.
WAIT_WAKEUP observes control readiness; an exec handshake remains synchronous.
After kind2 the controller
forwards op3 to IO; its acknowledgment need not wait for an already-started File
task to finish/close. The transition through submission of the first stdout
OPEN is committed before delivering a latched IO cancellation, matching the
original poll starting that blocking task. IO then finishes the current read
and skips later awaits. A successful final IO loan commits the synchronous
outcome tail; cancellation cannot preempt that CPU-only tail. Cancel after
promotion cannot cancel the moved child. Shutdown separately forwards op4 while
process custody remains. Reaped numeric PIDs are never reused as capabilities.

The process and IO policies run unchanged in separate flat HIA arenas. The
controller decides calls, effect submission, polling, growth and publication.
Blocking READ/WAIT_WAKEUP use independent jobs; they never occupy its sole
capability slot. Outcome is the unchanged owned-buffer HIA object, called with
a borrowed IO span. No Python or assembly owns these decisions.

## Private capability slot

Workspace+256 is96B / twelve Q words:
HSHFGFX1, sequence, action, arg0, arg1, arg2, zero,
result, errno, auxiliary, ready, zero.

Emission zeros completion fields. The bridge validates issued sequence,
arguments, tokens and spans, then writes ready1. HIA checks all immutable fields
against its private shadow. All auxiliary fields are zero. A capability errno
is positive1..4095 with zero result/aux and means infrastructure failure.
Actual syscall errors instead belong to the process/IO owner mailbox.
CALL_IO additionally copies its current complete arena capacity to controller
workspace648 on every call, independent of return or descriptor kind. HIA uses
that actual capacity to bound the returned loan before CALL_OUTCOME.

| Action | Arguments | Completion |
|---:|---|---|
| 1 INIT_ARENAS | token, process capacity, IO capacity | result0; four actual capacities at640..671 |
| 2 CALL_PROCESS | request offset, length, result offset | actual f0 u64 return; fixed96B output |
| 3 DISPATCH_PROCESS | 0,0,0 | positive job token |
| 4 POLL_PROCESS | process job token,0,0 | readiness0/1; on1 commit owner completion |
| 5 CALL_IO | request offset,40,result offset | actual f0 u64 return; fixed64B descriptor |
| 6 SEED_IO_CACHE | cache0/1/2,0,0 | zero |
| 7 DISPATCH_IO | 0,0,0 | positive job token |
| 8 POLL_IO | IO job token,0,0 | readiness0/1; on1 commit owner completion |
| 9 SNAPSHOT_IO_CACHE | 0,0,0 | actual IO workspace240 value0/1/2 |
| 10 CALL_OUTCOME | IO loan offset,loan length,header destination | actual f0 u64 return; fixed first40 output bytes copied |
| 11 GROW_OUTCOME | minimum capacity,0,0 | actual new output capacity |
| 12 WAIT_ACTIVITY | process job or0,IO job or0,0 | zero after readiness/control wake |
| 13 CONTEXT_EXTENT | 0,0,0 | full raw ENV_SNAPSHOT encoded byte count |

SEED is admitted only at IO ADMIT phase1/seq1/ready0. It copies HIA's value to
IO workspace240. SNAPSHOT only copies it back. CALL does not re-dispatch an
already-issued effect. POLL validates the precise live job and retires it once.

CONTEXT_EXTENT counts the already-held inherited environment snapshot without
parsing keys, deduplication or PATH policy. Fixture environment stays stable.
HIA chooses checked process capacity65536+4*(command+cwd)+16*encoded_env_bytes.
INIT uses this request, IO8192, initial outcome output4096 and work128. Its four
actual capacity Q words are process, IO, outcome output, outcome work. Outcome
CAPACITY makes HIA request checked doubling; there is no raw8MiB input rejection.
Real allocation failure is infrastructure, not a semantic read Err.

Workers retain separate private completions. They may write only an admitted
IO data range while main latches cancellation in disjoint owner state. POLL on
main publishes completion into owner mailbox; workers do not race f0's ready
field. Owner GROW executes on main with no in-flight borrower and preserves old
bytes. FORK executes its fixed primitive on main and supplies a completed job in
each branch; child setup remains in the original HIA process owner. WAIT_ACTIVITY
only waits on owned readiness/control surfaces and never chooses business work.

## Workspace

0..255 plus352..511: controller state. 256..351: capability slot.
512..551: IO request. 576..615: process control/resume request.
640..671: capacities. 704..743: outcome header copy.
896..959: capability shadow and consumed completion scratch.
1024..1119: actual process output. 1152..1215: actual IO descriptor.
2048..2143: published process observation. 2176..2207: cancellation acknowledgment.
4096 onward: admitted process start frame, with HSHPRQ01 magic.

Public descriptor bytes are written only after the complete source span is
validated. Pending/refusal never alters output. Qualification retains actual
entries, full input/output/workspace buffers, bilateral guards and emitted effects.

## Evidence and remaining scope

This ABI is a contract, not an execution receipt. Qualification must bind the
actual controller image, unchanged process/IO images, allocator/outcome object,
compiler/linker/bridge sources and full raw OS traces. Required cases include
foreground success/errors, both streams, cancellation with a blocked read,
same-child promotion observations and immediate IO before process quiet retirement.
Original Rust comparisons cover only the declared foreground domain.
