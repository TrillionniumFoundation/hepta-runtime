# ELF Zstandard destination error ordering

This is a parser differential checkpoint against the frozen REA 6.8.0 package
and Node v22.23.4. It does not close a public operation gate, replacement
qualification, arbitrary Zstandard parity, or another machine's resource profile.
Public gates and capability remain zero.

## Fixed observations

The existing 5,244 inputs were reused without regeneration, filtering or a relaxed
comparison. Their SHA-256 is
`4ee44f2adbb29c5ea185282d0e58e228c7dee310fdd4cd8cd7d2905ac9dd0ec1`.
The actual original parser and the pre-change production Rust parser were rerun:
84 complete JSON responses differed. The conservative checkpoint parser reports
34 differences, all from those original 84; there are no new differences. An
intermediate prototype had 26 differences, but eight were restored when the
proof stopped depending on zero-padded missing input bits. The checkpoint closes
50 original differences, without treating that intermediate 58 count as final. These
numbers concern the standalone adapters invoking the real parsers, not a shipping
Runtime/MCP operation or mock engine.

Reference identities:

| Input | SHA-256 |
| --- | --- |
| Original `rea-agents-6.8.0.tgz` | `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb` |
| Actual `/usr/bin/node` v22.23.4 | `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90` |
| Unchanged reference parser adapter | `07a64848d56a3533faeb0d3a6066af2073469618cea0ad30e9fc768adb6240dd` |
| Root Cargo.lock used to select the harness dependency graph | `7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43` |

Every registry dependency in the resulting small-harness lock has the same
name, version and checksum as an entry in that root lock. The harness compiles
the production ELF parser by absolute source path and the production vendored
ruzstd patch. The old independent lock and the root-aligned lock are both retained.
Rust 1.95.0, edition 2021, offline/locked Cargo, debug information disabled, four
build jobs, the designated private Cargo home and an independent small target
were used. The final integrated binary still requires its own complete build and
public operation validation.

## What changed

The fixed Node producer starts with a 16 KiB output chunk. A complete first frame
with a known size that fits that chunk can use libzstd's single-pass path. Other
frames use its streaming output allocation, bounded by the declared frame size
and the window plus two block regions and 64 bytes of copy padding. The adapter
tracks the destination position across blocks and streaming buffer reuse.

A single-pass decoder may place copied literals after the maximum block plus
32 bytes inside that output region. Consequently its actual sequence boundary
can be smaller than the nominal 16 KiB chunk. This checkpoint only infers that
placement for raw/RLE literal sections of at most 64 bytes, which fit the minimum
supported literal scratch. Larger, split and Huffman literal layouts retain their
existing validation. It does not replace every window/format error with a
destination error.

The optional vendor hook validates a decoded sequence's output length while
decoding that sequence, before the later bitstream exhaustion check. The proof
checks output capacity before literal and offset validity, following the original
decoder's execution order. A prior invalid literal/offset prefix disables further
capacity inference, so a later sequence cannot replace that earlier data error.
An incomplete sequence is not inferred from the backend's zero-padded missing
bits: only a lower bound from an already complete FSE state may prove exhaustion.
If that lower bound does not exceed the destination, the original short-bitstream
error is preserved. Only a distinct typed `OutputCapacityExceeded` result selects
the destination message. Ordinary decoder consumers default to no additional capacity inference;
the frame/window bounds remain enforced. The hook persists until explicitly
updated and is only used here without an external dictionary. It is not a general
output-budget API for raw blocks or zero-sequence literal copies.

For RLE blocks, the encoded payload is one byte. The header must not compare the
regenerated RLE length against the encoded-size admission bound. Once the byte is
available, actual destination exhaustion precedes the regenerated block/window
format check, matching the original decoder's ordering.

## Implementation evidence and remaining cases

The ordering was checked against the official fixed-tag
[libzstd v1.5.7 source](https://github.com/facebook/zstd/tree/v1.5.7/lib/decompress),
including `ZSTD_allocateLiteralsBuffer`, `ZSTD_execSequenceEnd`,
`ZSTD_decompressSequences_body`, `ZSTD_decodingBufferSize_internal`, and the
streaming block/flush loop. The downloaded source is retained separately and was
read as evidence; it was not substituted as the Rust implementation.

The 34 remaining cases are explicitly unresolved at this checkpoint: twelve
exhaust the sequence bitstream after filling the destination, fourteen use larger
literal sections outside this initial placement proof, and eight require a more
precise proof for partially present sequence extra bits. Their exact original and
native errors remain in the differential file. They are not normalized away.

All paths below are on the authorized desktop host under
`/home/qian-qi/work/hepta-rea-static-elf-ca464-20261105/`:

| Evidence directory | Contents |
| --- | --- |
| `capacity-baseline-r1` | Fresh actual original and pre-change native runs, 84 differences, source identities |
| `capacity-prototype-r1` | Retained offline build failure before dependency alignment; no semantic result |
| `capacity-prototype-r2` | Root-aligned lock and intermediate prototype, 26 differences; superseded by the stricter proof guard |
| `capacity-checkpoint-r4` | Conservative proof, 32 real parser tests and strict Clippy passed, exact 5,244 comparisons with 34 differences and zero new differences |
| `capacity-checkpoint-r5` | Source/driver identities, retained comparison and commit receipt for this checkpoint |
| `reference-libzstd-1.5.7-r2` | Fixed-tag official source bytes and identities |

Three regression payloads in `rea_elf_notes_parser_tests.rs` are copied unchanged
from the existing corpus (`zstd-bit-8-37`, `zstd-bit-9-145`,
`zstd-bit-10-48`). The full unchanged corpus also retains its adjacent valid and
malformed controls. No new fuzz corpus was introduced for this work.
