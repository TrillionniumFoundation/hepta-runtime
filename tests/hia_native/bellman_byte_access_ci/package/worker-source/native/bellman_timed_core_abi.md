# Resumable Bellman numerical checkpoints

This private new source retains the qualified `bellman_core.hepta` as its
unchanged reference. The author proves an exact inverse for the original f0
and retains f1 through f18 byte-for-byte as function graphs. No floating point
operation, validation, branch, selection, consistency check, or output byte is
recomputed by Python or the mechanical clock adapter.

The current target is d3d75c30719db966b004756f610007a7c723729e. Its complete
`src/mcp/weight_bellman.rs` still has Git blob
7cf126f97d0cdc38a605b3ea894846b3842600c4 and SHA-256
254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7.

## Worker-private initialization

The actual admitted worker obtains CLOCK_MONOTONIC when `solve` starts, after
any blocking-pool queue wait. A separate 64-byte private initialization frame
contains eight little-endian u64 words:

`HBTMIN01`, nonzero job generation, start nanoseconds, clock domain 1, and four
zeros. This frame is never accepted from ordinary tool JSON. The workspace is
private, disjoint from input/output, and initially zero. It needs at least
`128 + 72 * state_count + 512` bytes and its length is a multiple of eight.
The final 512 bytes are continuation metadata. Initialized timers cannot be
reset through this interface.

Initialization returns 64 and `HBTMIR01`, extent 64, generation, start,
`start + 30,000,000,000`, and three zeros. It leaves the numerical scratch area
unchanged. The monotonic nanosecond representation refuses addition overflow;
it does not shorten or make the 30-second deadline caller-configurable.

Subsequent calls borrow the exact same immutable `HIABELL1` frame and output
capacity used for the current operation. This is a private caller lifetime
contract, not an admission API for caller-supplied clock acknowledgements or
mutated continuations. The existing numerical output and semantic refusal
codes retain their meaning. New deadline refusal is `0xfffffdf0`.

## Source-owned continuation edges

The original state-loop edges now yield at the following exact points:

| PC | Original target block | Required action |
| --- | --- | --- |
| 1 | b14 | CLOCK before each state in validation |
| 2 | b71 | Actual typed canonical commitment after full validation/work admission |
| 3 | b73 | CLOCK before each state in the forward pass |
| 4 | b112 | CLOCK before each state in the repeated consistency pass |
| 5 | b113 | Final CLOCK before constructing/publishing the successful numerical frame |

Yield returns `0xffffffe0` and leaves the entire output array unchanged. With
`T = workspace_length - 512`, the complete 128-byte descriptor at `T + 256`
contains: magic `HBTMEF01`, sequence, kind (1 CLOCK, 2 commitment), generation,
PC, state index (zero for PC 2/5), start, deadline, immutable input length,
output capacity, numerical result extent, and five zero words. Sequence is
nonzero and increases once per yielded effect. The suspended loop scalars
are owned by this same HIA instance.

The fixed caller writes a 64-byte acknowledgement at `T + 384`: magic
`HBTMAK01`, the exact sequence, kind, generation, observed monotonic
nanoseconds (zero for commitment), child status (zero for successful CLOCK or
commitment), and two zeros. CLOCK observations must be monotonic and come
from the actual worker's clock. HIA performs `now >= deadline`; the adapter
does not choose whether the deadline has expired. A successful acknowledgement
resumes the original target block directly, without replaying its checkpoint
or any completed numerical state.

The commitment caller must retain the actual successful `HBCMTRES` frame for
the result renderer. Its failures propagate before any forward state runs.
Qualifying only the clock edges does not qualify the separate original
`Commitment::write` per-write deadline checks; a resumable writer and its
exact actual Serde write boundaries are required for the complete solver.

The final renderer input is the separately agreed `HBLMRQ01`: complete
`HIABPLN1`, complete `HBCMTRES`, and worker-observed elapsed binary64 bits.
No identity or elapsed-time field is taken from public parameters.

## Present scope

The source proof is an authoring check. Native compilation, full old/new
numerical comparisons, actual CLOCK/worker qualification, and fresh original
Rust replay are recorded separately. Until those pass, this source makes no
runtime qualification claim. Public handler replacement, HTTP activation,
the joined two-permit scheduler, and old-stack removal remain false.
