# Bellman typed canonical commitment owner

This component owns typed-frame serialization, the canonical request byte
count, SHA-256 of that serialization, and the domain-separated plan identity.
Its executable path is HIA integer and buffer operations. Python and Rust are
build or qualification tools, and do not implement a runtime fallback.

The public `weight_bellman_plan` handler is **not yet qualified** by this
component. Public JSON decoding, numerical admission before commitment,
trusted installed-source binding, response rendering, the compute deadline,
semaphore ownership, cancellation, and routing remain separate obligations.
The existing numerical Bellman owner must validate a request before this
commitment owner is called in the eventual public composition.

## Source and reference identities

The reference is `src/mcp/weight_bellman.rs` at runtime commit
`737acf6f901e46c57b0b4374e323e0d1132e0d49`. Its SHA-256 is
`254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7`.
The extraction retains the original four serde-annotated types, `Commitment`
writer, hexadecimal function, canonical serialization and plan-ID block,
semantics constant, and byte-budget constant without changing their bytes.
The reference release build retains the original Cargo release profile.
The portable gate verifies every resolved registry package version and
checksum against that commit's exact Cargo lockfile before frozen builds.

The compiler is Hepta commit
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. The native source imports the
existing integer binary64 formatter from `native/serde_json.hepta` and SHA-256
functions from `native/binary_codec.hepta`. The composition receipt pins their
source bytes and individual function graphs. The formatter and six SHA
functions only change function names and direct call targets. The SHA update
function additionally contracts its read-source loan into its existing
exclusive workspace loan. No operation is added or removed in that graph;
the corresponding block parameters and edge arguments are removed and source
references use the workspace parameter. The source spans and SHA scratch are
disjoint as specified below.

## Input frame

All integers are unsigned little-endian words. Binary64 values are their exact
64-bit IEEE 754 representations, including the sign of zero.

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII `HBCMT001` |
| 8 | 32 | Private trusted implementation-source SHA-256 bytes |
| 40 | 8 | ASCII `HIABELL1`, the numerical owner's frame magic |
| 48 | 8 | State count, 0 through 4096 |
| 56 | `720 * count` | Six 120-byte actions per state |

The input length must be exactly `56 + 720 * count`. This layer permits an
empty typed state list, empty branch lists, and mathematically invalid graphs
because it is a serializer. Those cases must be rejected by public numerical
admission when the original rejects them. Its fixed frame represents at most
three branches per action.

Each action starts with a 64-bit kind: zero for null, one for terminal, two
for continue. For null, the remaining 112 bytes must be zero. A terminal's
value bits occupy offset 8 and its remaining 104 bytes must be zero. A
continuation has zero at offset 8, branch count at offset 16, and up to three
32-byte branches at offset 24. Unused branch slots must be zero. Each branch
contains probability bits, a successor word whose value fits `u32`, reward
bits, and fee bits, in that order. All supplied floating-point fields must be
finite. Unknown kinds, noncanonical padding, excess counts, and trailing bytes
are rejected before changing the workspace.

The implementation-source digest is an installation-layer input. **It is not
a public request field or an authorization decision.** Original comparison
uses the digest of the exact Rust reference file. A deployed HIA composition
must bind the digest of its actual installed implementation through a trusted
owner; this private component alone does not establish that binding.

## Canonical JSON and identity

Serialization uses the original type declaration order:

```json
{"states":[{"actions":[{"kind":"terminal","value":-0.0},null,null,null,null,null]}]}
```

A continuation begins with `kind`, then `branches`. Each branch emits
`probability`, `successor`, `reward`, and `fee`, in that exact order. No
whitespace is added. Finite binary64 text follows the already qualified
serde-json formatter, including `-0.0`, shortest round-tripping digits, and
the original fixed/exponent cutoffs. Successors use unsigned decimal integers.
The bounded `u32` division by ten uses `(value * 3435973837) >> 35`; the
product cannot overflow a `u64` in this admitted domain.

The request byte count covers these canonical JSON bytes. Up to and including
8,388,608 bytes are admitted. The request digest is SHA-256 of the exact bytes.
The plan digest is SHA-256 of the concatenation:

1. ASCII `hepta.weight.bellman-plan.v1` and one NUL byte.
2. ASCII `finite_dag_ordered_f64_v1` and one NUL byte.
3. The implementation-source digest as 64 lowercase hexadecimal bytes and
   one NUL byte.
4. The request digest as 64 lowercase hexadecimal bytes.

The public textual plan ID is `wb1_` followed by the plan digest in lowercase
hexadecimal. This private ABI returns the raw digest to its future renderer.

## Successful output

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII `HBCMTRES` |
| 8 | 8 | Canonical JSON byte count |
| 16 | 32 | Raw request SHA-256 |
| 48 | 32 | Raw implementation-source SHA-256 |
| 80 | 32 | Raw plan SHA-256 |
| 112 | 16 | Zero reserved bytes |
| 128 | byte count | Exact canonical JSON |

The returned `u32` is `128 + byte_count`. Every output byte within that result
is assigned. No output is published until serialization, budget checks,
capacity checks, and both hashes have completed. Refusal preserves the entire
output buffer, including when a previous successful result occupies it.

| Return code | Private meaning |
|---|---|
| `0xffffffff` | Malformed frame or nonfinite typed scalar |
| `0xfffffffd` | Insufficient output or workspace capacity |
| `0xfffffffc` | Imported formatter could not produce a finite scalar |
| `0xffffff00` | Canonical request exceeds 8 MiB |

The budget error corresponds to the original writer's text, `Bellman canonical
request exceeds 8 MiB`. Other codes are private transport failures and must
not be presented as claims of equivalent public JSON-RPC errors.

## Workspace ownership

At least 16,384 bytes of workspace and 128 bytes of output capacity are needed
for initial admission. Successful serialization additionally needs
`16,384 + canonical_byte_count` workspace bytes and
`128 + canonical_byte_count` output bytes. The build uses the existing
`serde-json.v1` capacity profile so the inclusive 8 MiB payload plus its
header fits the declared transport.

| Workspace span | Owner |
|---|---|
| 0–8191 | Formatter scratch, then SHA state and schedule |
| 8192–8375 | Complete 184-byte plan-identity preimage |
| 10000–10009 | Reversed `u32` decimal digits |
| 12000–12031 | Preserved request digest |
| 12032–12063 | Plan digest |
| 12288–12303 | Canonical cursor and latched failure code |
| 16384 onward | Canonical JSON bytes |

The SHA update adapter reads only the canonical span or the identity span,
while its state and schedule remain below 8192. The formatter finishes before
hashing begins. Every invocation resets the cursor and error latch after frame
admission; qualification checks reuse after a budget refusal. Workspace bytes
are private and may change on a serialization or capacity refusal.

## Qualification and remaining public work

`scripts/hia_native_bellman_commitment_build.py` runs the registered native
suite and original recipe. The suite regenerates the source and composition
receipt, checks the declared source closure, builds a fresh native image and
standalone ELF, builds the unchanged extracted Rust owner in debug and the
original release profile, and compares complete binary result streams.
The corpus covers existing successful Bellman graphs, every finite normal
binary exponent, randomized finite bit patterns, signed-zero field
permutations, exponent notation transitions, `u32` decimal boundaries, and
exact request-budget boundaries. Separate controls check transport refusals,
capacity failures, unchanged output, and trusted-digest domain separation.

This gate is a component qualification. It does not execute a 30-second
deadline, enforce the two-planner semaphore, hold a permit after caller
cancellation, decode arbitrary JSON-RPC parameters, or render the full public
response. Those obligations remain explicit before public activation or old
stack removal can be qualified.

## Qualification scheduling

The ordinary aggregate retains its 180-second deadline. Its typed commitment
suite runs two owned worker processes: all 1,139 ordinary rows and their 23
refusal/33 trusted-digest controls occupy one native arena; the three exact
8 MiB boundary rows and the subsequent refusal recovery remain in one other
session. Every original native call still executes. The collector joins the
complete input/output streams in their original 1,142-row order and checks the
unchanged fixed SHA256 values before unchanged Rust debug/release replay.

Both workers inherit the actual outer process group. Receipts bind their PID,
parent PID, command, source inputs, native manifest, complete streams and reaped
exit state; the strict reader cross-checks the parent against the aggregate's
actual Popen record. Eleven owned-copy mutation controls exercise those
bindings. A timeout or failure retains partial receipts and retires the owned
group. This scheduling change does not change the HIA source, capacity or
public-handler qualification.
