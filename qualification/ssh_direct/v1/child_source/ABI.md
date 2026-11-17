# Original direct-SSH child custody, source candidate v1

This is a private HIA policy boundary derived from the complete target
`src/mcp/runtime/ssh_direct.rs` at d3d75c30719db966b004756f610007a7c723729e.
It is not yet an independent native actor, an SSH command builder, or a public route.
The actual target source and both unchanged original test modules are retained.

## Fixed bytes

Every request is 128 bytes. The prefix is HSDCCQ01; u64 fields at offsets
8/16/24/32/40/48/56/64/72 are operation, original registry id, original
opaque child capability, generation, effect sequence, argument A, argument B,
monotonic nanoseconds low word, and monotonic nanoseconds high word.
Offsets 80..127 must be zero. Identity, capability and generation are nonzero.
The capability is an actor-owned original-child handle, never a public PID.
It may be issued only by the original physical spawn and its registry insertion.

The workspace is at least 512 bytes and output at least 576 bytes. INIT requires
the whole first 512 bytes zero. Bytes beyond these extents are not touched.
Output HSDCCR01 has extent 576, operation, status, effect, sequence, reason and
errno at successive u64 offsets 8..56; bytes 64..575 copy the complete state.
Return 576 is success or a complete business result; 0xffffffff is a refused
private frame and 0xfffffffe is insufficient fixed capacity. Both refusals leave
all workspace and output bytes unchanged. No output prefix implies an OS action.

Status 0 is completed, 1 is an actual effect request, 3 is a retained-custody
error. The actor must check the complete result before acting. All effects are
bound to the original id/capability/generation and a fresh monotonic effect
sequence. ACK consumes that exact sequence once. No ACK is inferred from timeout.

## Calls and effects

| Op | Meaning | Inputs |
|---|---|---|
| 0 | Initialize one already registered original child | A=entry guard present, B=0 |
| 1 / 2 | Borrow / finish all pipe futures | A=B=0, no pending wait |
| 3 | Await original Child.wait | Returns effect 1, or cached reap |
| 4 | Cancel only the pending wait future | Exact sequence, no signal or reap claim |
| 5 | Stop and reconcile after all pipe futures ended | Effect 2=original try_wait |
| 6 | try_wait ACK | A=0 alive,1 reaped,2 error; B=status or errno |
| 7 | original start_kill ACK | A=errno or zero; effect 4 always follows |
| 8 | original timed wait ACK | A=0 reaped,1 wait error,2 timeout |
| 9 | original wait ACK | A=0 reaped,1 wait error |
| 10 | Release registry entry | Requires actual reap; effect 5 |
| 11 | Registry identity/removal ACK | A=0 exact removal,1 identity mismatch |
| 12 | Inspect complete state | No new effect |
| 13 | Original last-owner/guard release ACK | Effect 6 only; marks retired |
| 14 | Clear retired storage | Requires no registry, guard or pipe borrow |

All unused arguments are zero. Exit status is the complete OS u32 wait status;
errno is 1..4095 for actual errors. A try_wait-alive ACK carries the actual
monotonic observation. A timed-wait timeout ACK carries an observation at or
after the cached deadline; other ACK clocks are zero. Clocks cannot go backwards.

The first confirmed-alive try_wait stores now+3 seconds using a 128-bit
nanosecond representation. It is never extended. Later stop calls still perform
try_wait first: a completed original child can be reconciled after that deadline.
A still-live child at/after it is not signalled again. An uncertain wait sets a
sticky wait_failed flag and refuses future signal attempts. A failed signal does
not skip the actual timed wait. A timed-out reap retains the original capability.

Effect 5 must compare the actual registry object identity, not only its id.
Effect 6 occurs only after registry removal and release of the last actual
original-child owner. Its optional Send guard is not required to be Sync.
Reply publication belongs after this boundary; caller Drop never frees it.
The native adapter must preserve an original capability on any uncertain return.

## Workspace

The first words are magic, id, capability, generation, pending phase and effect
sequence. Offsets 48/56 record reap/wait uncertainty; 64/72/80 the cached cleanup
deadline; 88/96/104 guard/registry/pipe ownership; 112/120 actual status;
128 the last signal errno; 136/144 last result reason/errno; 152/160/168 the
observed clock; 176 actual reap marker; 184/192/200/208 wait/signal/try/remove
counts; 216 consumed sequence; 224 abandoned wait count. 232..511 stay zero.
Pending phases 1..6 correspond to the six actual effects above; 7 is retired.

Reasons: 1 original wait uncertain; 2 refusing uncertain signal; 3 cached reap
deadline exhausted; 4 original wait/try_wait failed; 5 cleanup wait failed;
6 incomplete timed reap; 7 not reaped; 8 registry identity mismatch. Exact
user diagnostics remain a later target formatter boundary.

The future independent actor must also preserve queued cancellation vs commit,
entry immediately before spawn, unlimited per-host tasks, original capture
deadline, biased cancellation/stop selection, both 8 MiB streams, controller
PDEATHSIG, sticky process-global initialization/freeze and one shared join receipt.
These are explicitly not claimed by this child-only source/build package.
