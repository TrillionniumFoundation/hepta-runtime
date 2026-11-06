# R34: bounded direct SSH capacity for existing-job cancellation

**Status: first complete x230 qualification passed: 1653 passed, 0 failed,
34 ignored, 1687 selected, 0 retries. Exact native CI is running.
R34 is not adopted; accepted runtime remains R24.**

The initial source commit is `5d0b180b832e7f2a8120078231e97ef9e702608a`,
independently based on accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`.
The original 22-file candidate package remains under ../r34-candidate/ with its
original pre-execution statement and hashes. This directory records subsequent
preparation and actual execution without rewriting that frozen snapshot.

## Runtime change and bounds

Only four of the same 220 compiler inputs change. An existing-job cancellation
first tries the ordinary admitted, target and global permits immediately.
If capacity is unavailable, all partial ordinary permits are dropped before
waiting in a separate reserve with eight admitted identities and one executing
request. The original absolute deadline, stop fence, ownership state machine,
confirmed reap and uncertain-wait custody remain. The nine-entry owner channel
can accept eight ordinary ready requests and the one reserved ready request.

Ordinary direct limits remain 16 admitted identities, eight executing requests
globally and two per configured SSH target. Combined ordinary plus reserve
bounds are 24 admitted identities, nine executing globally and three on one
configured target, within this controller's direct transport. These are not
a cross-controller or physical-host alias quota. The existing upstream cancel
publication limit remains eight. ACK and final job completion remain distinct.

The change affects only the two validated existing-job cancellation dispatches.
Original remote helper bytes and job identity/intent checks are unchanged.
A reserve waiter does not switch back to subsequently freed ordinary capacity.
The latency/resource tradeoff still requires original measurement.

## First complete qualification

Original native job: **`1a1aef7882f-fc05-6499`**, started once with a two-hour
outer timeout and no automatic retry. The 19 original qualification tools,
eight stages and `jobs=2` remain unchanged.

All eight original stages closed with exit code 0. The unfiltered isolated
inventory reports **1653 passed, 0 failed, 34 ignored, 1687 selected and 0 retries**;
the original independent auditor reports success with no errors and 1653 executed
cases. The native terminal is succeeded/0 with complete, durable, synced and
untruncated 1108-byte stdout and empty stderr. This was the first qualification
execution, with no automatic retry.

The actual final source map contains the same 220 paths. Exactly the original four
candidate paths differ from R24; 216 are unchanged. Formatting changed only the
candidate test file, which is now published at src/mcp/runtime/ssh_direct_tests.rs
with SHA256 `b3ad50032291f32eb4492ca09d3198937b0dcda4eb9abc228d91d2f5b0b847c6`.
The three production source files remain identical to the initial R34 candidate.
Postflight re-read the complete 220-file map, 19 original harness files and all
three retained release binaries and confirmed their qualified identities.

| Retained program | Bytes | SHA256 |
|---|---:|---|
| hepta-runtime | 14,379,112 | `85211f3d60844554c778fbe460d455320425aa43b5525bf8786b3cc51a992c30` |
| hepta-runtime-jobctl | 739,016 | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| native_process_driver | 2,903,568 | `d6f7ca735830a17fd7d243fd6bb0b3b2b70e94bd931c19ecce1e706a0d1926b4` |

Original report, map, summary, complete native streams and postflight are under
qualification-01/. The earlier interim read remains historical evidence.
The full bounded qualification archive was created once by native job
`1a1af1c9f22-fc05-65e1`: 3,307,677 bytes, SHA256
`488f38422ffca19dc28ecc986fda5218cff090fe8a906053a217eee8e741cb1b`.
Its immutable transfer and local zero-extraction verification are still in progress;
this source milestone does not claim that the archive has already been published.

The sealed 30-file installation package is 265,304 bytes, SHA256
`16d21b200f3e871f58ad30d6ea130d342c467963d432a93bf362fed4748998e4`.
The actual install readback confirms all 30 files before qualification. Candidate
files live under candidate/; the preparer creates a fresh runtime source from
R24 and applies the frozen four-file patch. R33 contributes only its closed
build cache. R33's C8 rejection and lifecycle refusal remain mandatory owner
closure inputs and are not composed into this source.

## Recorded capacity preparation

The original 3 GiB free-space requirement was preserved. Actual capacity was
initially 2,652,098,560 bytes. Only these two rebuildable project artifacts were
eligible for removal from the inactive R33 cache:

- debug/deps/hepta_runtime-1b8b761b89392e3b
- debug/deps/libhepta_runtime-564505b54e9d81cd.rlib

The retained test executable is an independently stored, single-link inode
with the original audited SHA256
`e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1`.
The cleanup tool checks owner closure, all retained program hashes, process
references, fixed object identity, stable complete hashes, and full before/after
cache metadata. It deletes no directory and does not run a compiler or test.

The original cleanup job `1a1aeeea99f-fc05-6440` failed before deletion because
root had passed nanosecond timestamps through JavaScript Number. The two pins
differed from original integers by +35 ns and −124 ns. Its original native
streams and report are preserved with zero deletions; both cache inventories
and both owner reports were byte-identical.

An independent read of the original text, failed inventory and live file metadata
confirmed the exact integers. Separately reviewed cleanup version 02 uses decimal
strings and strict equality, with no tolerance or relaxed condition. Its original
job `1a1aef5957d-fc05-6486` passed, deleted exactly the two authorized artifacts,
kept retained programs and all unselected cache entries unchanged, and reported
**3,566,792,704 free bytes**. The original failure was not overwritten or restarted.
This maintenance correction is separate from the first runtime qualification.

The actual cleanup report is 4,426 bytes, SHA256
`51fae444ad2ec1a11ba371a26f5e4ed5d12df3e2d2ca36187a9f60159b1b9b87`.
Its unchanged helper, original source/closure bindings, exact native originals,
static reviews and execution catalog are retained under cache-prune-01/ and
cache-prune-02/.

## Remaining acceptance work

The original exact native CI is running as job `1a1af1ebf1d-fc05-65f2`, bound to
the final qualified source and original all-target/all-feature commands, pinned
nextest 0.9.137, full inventory reconciliation, one test thread and zero retries.
Its result is pending. This is a native x230 reproduction, not a hosted GitHub
Actions result. The
original six-host observation, boundary, recovery and normal lifecycle gates
remain separate from compilation and static review.

Saturated direct cancellation requires a distinct same-process component using
the actual shared production DIRECT owner: eight ordinary requests held across
six hosts before dispatching the existing-job cancellation. Existing-job
cancellations alone cannot establish global-eight saturation because the
upstream publication limit is eight. The component's implementation-01 source package and independent static review
are now published under capacity-component/. It is explicitly unformatted,
uncompiled and unexecuted. A new formatted revision, actual offline A/B builds,
retained ELF identities and the complete outer eight-cell campaign remain required. No saturated result is claimed
by this preparation or by a normal six-host recovery canary.

The experimental branch is published for review. Adoption awaits successful
exact CI, unchanged original performance gates and appropriately
scoped cancellation-capacity evidence.
