# Private resumable Bellman canonical writer

This owner serializes the same admitted typed frame as `bellman_commitment`,
retains its exact binary64 formatter and SHA helper graphs, and pauses before
every write made by the target Serde serializer. It is a private child of the
fixed Bellman worker. It does not accept an external clock or installation
identity from public tool arguments.

The source author retains the old `f1` through `f48` graphs byte for byte at
the HIA AST level. The new entry and continuation helpers replace only the
old synchronous entry. The typed writer grammar uses separate Serde writes
for object/array punctuation, string quotes, raw ASCII field/tag fragments,
null, unsigned successors and finite binary64 numbers. An actual unchanged
target writer trace is retained from CI run `43820406101`; successful native
comparison and physical-clock qualification are separate gates.

## Borrow and storage

The fixed worker owns an immutable complete `HBCMT001` input for the whole
invocation. Its first 40 bytes contain the trusted installation digest; its
remaining bytes are the unchanged `HIABELL1` frame. The normal output remains
the complete `HBCMTRES` frame. No successful output is published until all
writes, budget checks and both hashes complete.

Workspace length is a multiple of eight and at least 16,896 bytes. Let `T`
be `workspace_length - 512`. The original formatter, numeric text cache and
SHA scratch retain their original offsets below 16,384. Canonical bytes
occupy `[16384, 16384 + cursor)`, strictly below `T`. The final 512 bytes hold
the continuation. Input, output capacity and workspace capacity remain
fixed after the first typed invocation. After a CLOCK yield the caller may
write only the acknowledgement at `[T+384,T+448)`. Arbitrarily replacing the
input, stored progress or prepared fragment is outside this private loan.

All 512 continuation bytes must initially be zero. A completed invocation
cannot be restarted without a new workspace. A bad input or acknowledgement
is rejected with `0xffffffff` without changing output or workspace; repairing
the acknowledgement permits continuation from the same pending write.

## Initialization

The 64-byte initialization input has eight little-endian words:

| Offset | Meaning |
|---|---|
| 0 | `HBTCIN01` |
| 8 | Nonzero job generation |
| 16 | Actual worker start time in monotonic nanoseconds |
| 24 | Clock domain 1 |
| 32–63 | Zero |

The start must allow an exact addition of 30,000,000,000 nanoseconds. The
64-byte `HBTCIR01` response contains its extent, job, start, exact deadline,
then three zero words. Initialization may use a separate output loan; the
normal result capacity is bound only by the first typed invocation.

## CLOCK continuation

The entry returns `0xffffffe0` and leaves the output loan unchanged. The
128-byte descriptor at `T+256` contains:

| Offset within descriptor | Meaning |
|---|---|
| 0 | `HBTCEF01` |
| 8 | Strictly increasing nonzero write sequence |
| 16 | Kind 1, actual monotonic CLOCK |
| 24 | Job generation |
| 32 | Next grammar program counter |
| 40 | State index |
| 48, 56 | Worker start and its exact deadline |
| 64 | Number of already accepted canonical bytes |
| 72 | Prepared write length, 1–32 |
| 80, 88, 96 | Action, branch and next token indices |
| 104–127 | Zero |

The complete prepared write is at `T+224`, with the rest of that 32-byte
slot zero. A formatter runs before its corresponding CLOCK edge, matching
Serde's preparation of the bytes passed to `Write::write`.

The 64-byte acknowledgement contains `HBTCAK01`, the same sequence, kind 1,
the same job, actual monotonic time, and three zero words. Time may not move
backward. Time **at or after** the deadline returns `0xfffffde1`; that write
is not appended. Otherwise the owner applies the original inclusive 8 MiB
budget and then the private workspace capacity check before appending the
prepared bytes. Budget failure is `0xffffff00`, capacity is `0xfffffffd`,
and formatting refusal is `0xfffffffc`.

The SHA helpers hash the completed canonical span after all writes pass;
hash-state internals are private and no partially computed digest is a
published response. The accepted canonical prefix and every clock boundary
are retained for refusal evidence. No check is invented after the final
write: the numerical core supplies the original next state/final checks.

## Qualification boundary

This interface alone does not establish a real worker, cancellation,
semaphore, operating-system clock, public routing, or error-text adapter.
The eventual fixed caller must make the actual CLOCK syscall for each
descriptor and retain its owned-worker lifecycle through completion even
after the caller is dropped. Synthetic acknowledgements are only typed ABI
controls. The unchanged synchronous commitment remains separately qualified.
