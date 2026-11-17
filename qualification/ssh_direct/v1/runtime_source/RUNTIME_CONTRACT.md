# Target SSH runtime policy source v1

These three HIA owners retain policy; an independently owned native thread and
its real syscall adapter are the next required boundary. This source/build
candidate does not claim actual SSH, native concurrency, or public registration.
The complete d3d75 direct owner and both original test modules remain unchanged.

## Request admission

HSDARQ01 is a private 128-byte frame: op/capability/generation at 8/16/24,
A/B/C at 32/40/48, monotonic low/high at 56/64, effect sequence at 72, all
remaining words zero. The state is 256 bytes. HSDARR01 output is 320 bytes:
extent/op/status/pending/sequence/reason/error at 8..56 and the entire state.

- 0 initializes an unsubmitted request; A says whether an Entry exists, the
  clock words are the original absolute deadline.
- 1 performs the actual prequeue/postcapture active check. A is the actual
  core stop token; B/C zero; the clock is the current observation.
- 2 performs only cancellation's QUEUED-to-CANCELLED compare transition.
- 3 performs the following cancellation-token publication. The two calls
  remain distinct so a commit can observe the real original intermediate state.
- 4 runs the submission transition while holding the real short admission
  gate. A is stop, B is accepting (0/1) or actual poisoned gate (2), C the id
  issued under the original child-registry lock. The original current clock is
  checked before the QUEUED-to-COMMITTED transition. No child exists yet.
- 5 consumes final Entry and requests its invocation, then physical spawn.
  Once COMMITTED, cancellation or freeze does not turn this original attempt
  into a no-spawn attempt.
- 6 ACKs Entry (A=success0/error1, B opaque owned error on failure).
- 7 ACKs physical spawn (A=success0 with B child capability/C registry id, or
  failure1 with B errno/C0). A successful entry guard follows the new original
  child. A failed spawn requests its guard release before returning the error.
- 8 ACKs that failed-spawn guard release; 9 observes; 10 retires final state.

Effect 1 is final Entry on the independent actor, 2 is actual physical spawn,
3 is failed-spawn guard release. Effects have an exact generation/sequence.
No request JSON selects any executable or capability. Physical argv, pipe
configuration and callback are trusted installed capabilities.

The native caller cancellation boundary must not hold either the registry or
admission gate while blocking on OS spawn, I/O, wait, kill, or reap. The short
HIA calls themselves are serialized at the same logical transition. The
independent actor owns the request once queued, even if its caller runtime dies.

## Shared owner

HSDCPQ01 is 128 bytes: op/core capability/core generation at 8/16/24,
id/request-or-child capability/generation at 32/40/48, A/B/C at 56/64/72,
effect sequence at 80; 88..127 are zero. State begins with a 320-byte header
followed by 64-byte actual task and original-child registry rows.
HSDCPR01 returns 384 bytes including the entire header. Complete registry bytes
stay in the retained workspace, which all observers must capture in full.

| Op | Actual boundary |
|---|---|
| 0 | Initialize process-global storage once |
| 1/2 | Shared owner lookup/start and original initialization receipt |
| 3 | Process-wide permanent freeze |
| 4 | Core freeze without resetting the process-wide OnceLock |
| 5/6 | Reserve original child id / abort reservation or register actual child |
| 7 | Remove exact reaped original child identity |
| 8/9 | Register actual received task / retire that exact task |
| 10 | Actual owner thread exit with cleanup outcome |
| 11/12/13 | Take unique original join / persist actual join receipt / observe it |
| 14 | Bind an actual poisoned child-registry or admission mutex observation |
| 15 | Observe without changing ownership |

The original sequence is consumed before accepting/active/commit checks.
A reservation allocates required HIA registry space before physical spawn.
A GROW response does not consume an id or change state. Reservations prevent
other registry additions from taking the physical slot. The native child
registry remains exclusively owned through entry/spawn/registration, while
freeze and caller cancellation use only their separate short transitions.

Rows have id/capability/generation/kind at 0/8/16/24; all other row bytes zero.
Kind1 is original child; kind2 is task (id0). Id and actual capability collisions
are rejected. Completed task removal does not delete quarantined children.
There is no host count or per-target admission limit.

Failed initialization is sticky. A stopped owner is never replaced. Freeze
does not abort tasks or forget original children. The native actor must stop
receiving, let all received tasks finish their original cleanup, then drain the
original registry. Uncertain original waits keep their original capabilities.

Only one actual join worker takes the original thread handle. All shutdown
waiters read one persisted outcome; cancellation of one waiter cannot replace
or reset it. Successful join requires actual owner exit, no tasks, no child
rows and no pending spawn reservation. Error join retains quarantined objects.
The native original thread and join worker must be actual independently owned
OS execution contexts, not a synchronous caller wrapper.

## Composition boundary

The original-child owner in ABI.md remains byte-exact from its first successful
source/build. Reaped child identity is removed by the shared owner before the
child owner's final guard-release ACK. Complete result publication follows both.
Each actual callback must validate all returned status and extent fields.

Production still has no SSH slot. The current installed SDK124 graph is not
modified by this candidate. Original-test reference, HIA source build, native
actor execution and eventual public configured-host qualification stay separate.
