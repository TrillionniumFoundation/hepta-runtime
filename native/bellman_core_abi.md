# HIA finite-DAG Bellman numerical owner

This private numerical component implements the mathematical behavior of
`src/mcp/weight_bellman.rs` at runtime commit
`737acf6f901e46c57b0b4374e323e0d1132e0d49`. The public MCP handler is not yet
replaced. JSON decoding, canonical serde commitment and plan identity, public
rendering, async ownership, and the 30-second deadline require integration.

The implementation uses HIA integer and byte-buffer operations. There is no
host floating-point routine or dependence on host rounding mode. Its static
Linux x86-64 executable requires no Python, Rust, libc or dynamic loader.
Python is an explicit build/qualification tool. Hepta is pinned at
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, compiler image SHA256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.

## Borrowed-buffer entry

`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`

The buffers must be disjoint. Input is immutable. Workspace is private scratch
and may change on a semantic refusal. Output is written only after validation,
the forward pass and repeated consistency pass all succeed. Every refusal
leaves output unchanged. Capacity refusal also leaves workspace unchanged.

All integer fields are little-endian u64. Floating fields contain exact
IEEE-754 binary64 bits, including signed zero. This is an internal typed frame,
not JSON or a replacement for public schema admission.

| Region | Layout |
|---|---|
| Input header, 16 bytes | ASCII `HIABELL1`; state count |
| Per state, 720 bytes | Six ordered 120-byte action records |
| Per action header, 24 bytes | Kind; terminal-value bits; branch count |
| Three branch slots, 32 bytes each | Probability bits; successor; reward bits; fee bits |

Kind 0 means illegal; the remaining 112 bytes must be zero. Kind 1 means
terminal; value bits occupy offset 8 and bytes 16..119 must be zero. Kind 2
means continue; offset 8 is zero, count is 1..3, and unused branch slots are
zero. Unknown kinds and noncanonical padding are refused.

Count is 1..4096. Input length is exactly `16 + 720 * count` (maximum 2,949,136
bytes). Each state has at least one legal action and at most two continuing
actions. Every successor precedes its parent, including zero-probability
branches. The original 24,576-branch and 8,000,000-work budgets remain.
Both output and workspace need `128 + 72 * count` bytes (maximum 295,040).
Bytes beyond the returned output extent are unchanged.

## Result

Success returns the complete output extent. The header contains sixteen words:
magic `HIABPLN1`, states, legal actions, continuing actions, branches,
zero-probability branches, maximum probability-error bits, charged work,
exact-tie states, near-tie states, minimum-gap-present flag, minimum-gap bits,
maximum consistency-residual bits, and three reserved zeros.

Each 72-byte state record contains a six-bit legal mask, selected index,
selected-value bits and six Q-value bit patterns. Illegal Q slots are zero;
the mask distinguishes them from legal zero. Slots preserve STOP, WAIT, READ,
REPAIR, SUBMIT_0, SUBMIT_1 order.

## Arithmetic and ordering

Finite values, subnormals and signed zeros are supported. Every operation
rounds independently to nearest, ties to even. Addition orders magnitudes and
retains guard/round/sticky bits. Multiplication retains the exact two-word
53-by-53-bit product before one rounding. Division uses integer restoring
division and a sticky remainder. Comparisons treat signed zeros as equal.

In supplied order, nonzero branches perform exactly
`total += probability * ((child_value + reward) - fee)` with four separate
operations. Fees stay inside multiplication. Probabilities are not normalized.
Zero branches are validated and charged before being skipped. Overflow refuses
at its original operation boundary. Strict greater-than selects the first
legal maximum; near-tie diagnostics do not change selection.

Sequential probability sums retain `1e-12` tolerance. Scaled gap diagnostics
retain `2e-12`. Finite min/max ties retain the first operand, matching the
observed Rust 1.95 reference including signed zeros. A second complete pass
recomputes all Q values and selection from each solved prefix.

## Refusal codes

| Code | Meaning |
|---|---|
| `0xffffffff` | Malformed frame/kind/size/reserved bytes |
| `0xfffffffd` | Output or workspace capacity |
| `0xfffffe01` | State count |
| `0xfffffe02` | Nonfinite terminal |
| `0xfffffe03` | Branch count |
| `0xfffffe04` | Branch budget |
| `0xfffffe05`, `06`, `07` | Nonfinite probability, reward, fee |
| `0xfffffe08` | Negative probability or fee |
| `0xfffffe09` | Invalid successor |
| `0xfffffe0a` | Nonfinite probability sum |
| `0xfffffe0b` | Sum tolerance |
| `0xfffffe0c` | Legal/continuing action count |
| `0xfffffe0d` | Work budget |
| `0xfffffe0e`, `10` | Nonfinite Q/value residual |
| `0xfffffe0f` | Repeated selection mismatch |
| `0xffffff01`..`04` | Nonfinite reward addition, fee subtraction, multiplication, ordered sum |

## Arithmetic probe and evidence scope

`finite_binary64.hepta` accepts 24 bytes: operation, left bits, right bits.
Operations 0..4 are add, subtract, multiply, divide and compare. Output is one
u64; compare returns 0 equal, 1 less, 2 greater. Nonfinite inputs are refused.
Finite operations may return infinity; zero/zero returns canonical quiet NaN.
General NaN-payload propagation is outside this component. Bellman refuses all
nonfinite intermediates.

The actual-machine corpus covers 165,810 arithmetic calls and seven refusal
controls, comparing complete bits with independent hardware arithmetic. The
Bellman corpus covers 299 graphs and ten transport/capacity refusals, including
original numerical cases, randomized DAGs and the full 4096-state domain.
Three separate static-executable calls cover known, tie and maximum cases.
These finite observations are not exhaustive binary64 correctness proofs.

The Rust replay driver copies `finite`, `deadline`, `validate`, `action_value`,
`choose` and both numerical passes byte-for-byte from the pinned original.
Its separate frame decoder/encoder excludes serde JSON, request hashing,
public rendering and async admission. Deadline calls remain in the reference;
they do not qualify a timeout implementation in this pure native component.
