# Native text budget and line rendering

`native/text_budget.hepta` owns the deterministic behavior of
`src/utils/truncation.rs` at runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`. It uses the same content-only
FNV-1a 32-bit hash folded to eight bits as `src/utils/line_hash.rs`.
The compiler target is Linux x86-64 and the component uses the common
`hepta.runtime.borrowed-bytes.linux-x86_64.v1` ABI.

## Frame

The input is a 64-byte header followed by an ordered line array. Header words
are unsigned 64-bit little-endian integers. An `i64` endpoint uses its exact
two's-complement bits in the corresponding word.

| Byte offset | Meaning |
|---|---|
| 0 | Eight literal bytes `HRTEXT01` |
| 8 | Operation, 1 through 5 |
| 16 | Argument a |
| 24 | Argument b |
| 32 | Argument c |
| 40 | Argument d |
| 48 | Number of supplied lines |
| 56 | Reserved; must be zero |

Each line consists of an eight-byte byte length followed by exactly that many
UTF-8 bytes. Empty lines, NUL, carriage returns, and embedded newlines are
preserved. There is no implicit line splitting or trimming. Invalid UTF-8,
missing bytes, trailing bytes, invalid flags, and nonzero unused fields are
rejected before any output is written. The input ceiling is 8 MiB, including
framing. Workspace must contain at least `128 + 16 * line_count` bytes.

| Operation | Original owner | Arguments | Return bytes |
|---|---|---|---|
| 1 | `estimate_tokens` | a = byte length; b/c/d/count = 0 | Eight-byte unsigned token estimate |
| 2 | `format_megabytes` | a = byte length; b/c/d/count = 0 | Exact UTF-8 decimal text, e.g. `0.2 MB` |
| 3 | `format_content_with_line_numbers` | a = source position of line 0; b = range-present flag; c = start; d = signed end | Exact rendered UTF-8 text |
| 4 | `format_extracted_content_smart` | a = source position of line 0; b = maximum-present flag; c = maximum; d = 0 | Exact rendered UTF-8 text |
| 5 | Original constants | a/b/c/d/count = 0 | `MAX_RESULT_BYTES` as u64, then the exact binary64 bits of `CHARS_PER_TOKEN` |

Operations 1, 2, and 5 accept no line records. Flags are zero or one. With flag
zero, c and d must be zero. Operation 3 with flag one uses the existing range
semantics, including `start == 0`, the `end == -1` sentinel, and the original
cast-and-clamp behavior for other negative end values. Operation 4 with flag
zero uses the original default of 50 displayed lines.

The native return value is the number of output bytes. `0xffffffff` means an
invalid frame and `0xfffffffe` means insufficient declared capacity. Empty
successful results return zero. Line rendering and decimal formatting count
output in a first pass and write only after the entire output fits, so capacity
refusal leaves output bytes unchanged. Mutable workspace is private scratch.

## Numeric and release semantics

The original token estimate uses byte length, not Unicode scalar count. The
HIA implementation preserves `ceil((bytes as f64) / 3.5)` throughout the full
u64 domain, including integer-to-binary64 rounding above 2^53 and quotient
rounding before the ceiling. It implements that arithmetic with explicit
integer bit operations. It does not substitute exact rational ceiling where
that would differ from the original binary64 behavior.

MiB formatting preserves the original binary64 conversion and one-decimal
round-to-nearest, ties-to-even rendering. The exact input `262144` therefore
renders as `0.2 MB`; `u64::MAX` renders as `17592186044416.0 MB`.

`Cargo.toml` explicitly sets `overflow-checks = false` in the production
release profile. The HIA owner preserves this behavior. Source line positions
wrap as unsigned 64-bit values. For a nonempty line array and an explicit zero
smart-display maximum, the original release function emits its existing
`[...n+1 lines more]` marker. This case is retained in differential tests.
Development Rust builds with overflow checks enabled can panic on those same
arithmetic edges; they are not the reference profile for this component.

## Verification

`tests/hia_native/test_text_budget.py` accepts `HIA_TEXT_MANIFEST`. It validates
26,869 complete valid requests, 84 invalid frames, exact and insufficient
buffer capacities, and the standalone ELF without Python or a system PATH.
`--vm-only` with `HIA_HEPTA_DIR` runs independent HIA VM checks.

`HIA_TEXT_CORPUS_DIR` exports actual native `requests.hex`, `native-output.txt`,
and `native-corpus.json`. The metadata binds source, image, oracle, input and
output identities. Corpus output is captured from actual native invocations;
reference expectations are compared separately.

`tests/hia_native/oracle_text_budget.rs` contains the original truncation module
and the exact original line-hash function bodies. Compile it with:

```sh
rustc --edition=2021 -O -C overflow-checks=off \
  tests/hia_native/oracle_text_budget.rs -o "$HIA_BUILD_ROOT/text-oracle"
"$HIA_BUILD_ROOT/text-oracle" < requests.hex > rust-output.txt
cmp rust-output.txt native-output.txt
```

The observed original-Rust run used Rust 1.95.0, completed with exit zero,
returned all 26,869 expected results, and matched all 1,531,374 output bytes.
Source, oracle, input and retained native output hashes were unchanged across
the run. This qualifies the component's tested domain; replacing existing
production callers and the rest of the runtime remains a separate integration
step.
