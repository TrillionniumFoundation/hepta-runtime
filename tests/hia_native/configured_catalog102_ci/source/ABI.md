# Configured catalog and installed capability projection

This private successor targets `d3d75c30719db966b004756f610007a7c723729e`.
It keeps the qualified fixed eleven-tool entry and all its helpers. Its new
operation selects whole Tool values produced by the actual HIA policy, Value,
and SDK serializers. Original Rust replies are comparison evidence only.

## Private catalog operation 7

The input is exactly 40 bytes, five little-endian 64-bit words:

| Offset | Value |
| --- | --- |
| 0 | `HRMCD002` |
| 8 | operation `7` |
| 16 | modern output mode, `0` or `1` |
| 24 | installed runtime configuration flags |
| 32 | fixed installed tool capability mask |

The nine valid flag values are `0, 1, 3, 5, 7, 9, 11, 13, 15`.
Bit 0 means a runtime configuration is installed. Bits 1, 2, and 3 mean an HIA
worker, REA static profiles, and weight workers respectively. The target's
classification excludes all eleven selected tools from those latter three
groups. Therefore their values cannot change this selected directory. The
configuration query in the public frontend supplies only the equivalent
runtime-presence bit; it does not claim to decode the other settings.

Capability masks `0..3` select the original nine tools plus Batch at bit 0 and
Bellman at bit 1. These are private build capabilities, never fields accepted
from an MCP request. The actual 102-image successor fixes this mask to `1`:
ten tools with runtime configuration and seven without it. Mask `3` is the
eleven-tool component domain; advertising it publicly requires the real Bellman
route, worker, and SDK task pump to be installed and jointly qualified.

The response retains `HRCATR02`: entry return `32`, success header 32 bytes,
then the complete exact JSON result fragment. Modern mode preserves the
current target's `resultType=complete`, `ttlMs=0`, `cacheScope=public`.
The complete fragment size is word 16. Reserved/status words are zero.

Invalid requests return `0xffffffff` without changing either mutable buffer.
Output shorter than 32 returns `0xfffffffe` without writes. Workspace needs
22,152 bytes. Growth returns `0xffffffd0` and writes only a complete 32-byte
`HGRWS002` request (kind 1 workspace or kind 2 output, exact required size,
reserved zero). All workspace growth precedes output growth. Success writes
only the admitted result extent. The remaining output and workspace tails are
retained. No state or decompression cache survives as a semantic dependency.

The compressed constant occupies workspace `[0,6956)`, with four constant
alignment bytes. Its decoded common catalog occupies `[6960,22151)`.
Every backreference reads a previously written byte. The author checks every
access and the entire decoded value. The old two-buffer decoder is retained
unchanged; the new single-workspace decoder has its own disjoint-region proof.

## Frontend successor

The exact 102 frontend preserves Batch child 13 and Authority child 12. New
phase 18 / growth phase 118 queries config child 6 with the existing exact
24-byte `HRCFGQ01`, operation 3, zero payload. A success is admitted only with
`HRCFGM01`, status 0, reason 0 and exactly 32 digest bytes. Absence is admitted
only with status 1, reason 9 and the exact existing disabled-runtime message.
Every other result is rejected; it is never reclassified as absence.

After that actual query, phase 4 asks catalog child 2 for operation 7, the
resolved protocol mode, the presence bit and fixed capability mask 1. The
public input cannot choose these values. Existing request identity, child
continuation, workspace relocation and delivery checks stay in the old entry.
The former catalog, prepare and Authority continuation functions are retained
as exact relocated graphs. The former entry is restored by reversing two
phase-bound constants; all other original function graphs are preserved.

This document specifies the source candidate. Component, packed graph,
original-reference and public qualifications are distinct evidence. The whole
runtime and all-configuration public handler flags remain false until the
corresponding complete execution gates pass.
