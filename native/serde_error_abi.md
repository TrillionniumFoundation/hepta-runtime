# Native serde_json Value diagnostics

This component runs the raw `serde_json::from_slice::<Value>` admission and
error-display contract for the original locked serde_json 1.0.151 build with
`float_roundtrip` and `raw_value`. The exact serde/serde_core version is
1.0.229; number display uses the locked zmij 1.0.23 behavior.

The implementation is compiled HIA, with no Python, Rust, libc, host JSON
parser, or host floating-point callback at runtime. It returns a diagnostic
record. A successful validation does **not** return or serialize a Value.
Typed `Deserialize` errors, such as a user struct's missing field, are a
separate contract and are not supplied by this entry.

## Entry and input

`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`

All integer words are little-endian u64. The input is:

| Offset | Field |
|---:|---|
| 0 | Eight bytes `HSJERQ01` |
| 8 | Operation 1 |
| 16 | Raw JSON byte length, from 0 through 8,388,608 |
| 24 | Exactly that many raw bytes |

Input is a byte slice, not a prevalidated UTF-8 string. There is no global
strict-UTF-8 or lexer preflight that can change which parser error wins.

## Result

A normal return is the complete output byte length. The output begins with
64 bytes:

| Offset | Field |
|---:|---|
| 0 | Eight bytes `HSJERR01` |
| 8 | 0 for a valid Value; 1 for an original parser error |
| 16 | Category: 0 on success, 1 Syntax, 2 Eof, or 3 Data |
| 24 | Original one-based line, or zero on success |
| 32 | Original byte column, including a possible zero at a line boundary |
| 40 | Complete UTF-8 `Error::Display` byte length |
| 48, 56 | Reserved zero words |
| 64 | Exactly that many display bytes; no trailing NUL |

Successful validation returns exactly 64 bytes with every word after the
magic equal to zero. Slice parsing performs no IO and therefore does not
produce the original Error category Io. The display includes the original
` at line N column M` suffix; consumers must not append another suffix.

`0xffffffff` refuses an invalid adapter frame. `0xfffffffe` reports actual
output/workspace capacity shortage. Both leave the whole public output
unchanged. Workspace mutation on either refusal is private and may be
discarded. Calls are independent: the next invocation initializes its parser
state before using the workspace. The ABI supplies no session authority.

## Parser order and enabled RawValue behavior

The state machine follows the original consumed-byte versus peeked-byte
error positions, integer/float classification and exponent-overflow order.
It allows 127 nested containers per Deserializer instance. An invalid UTF-8
string is reported at its closing quote; an earlier escape, control-byte or
EOF error retains priority.

With the original `raw_value` feature, the first decoded object key
`$serde_json::private::RawValue` selects a string that is parsed again as a
Value. That inner parser has its own source positions and container budget.
An inner failure retains its inner line/column and is converted to category
Data by the original `Error::custom` path. A later occurrence of this key in
an ordinary object is not special. Extra fields after a successful special
first field follow the original `end_map` error order. The diagnostic entry
implements this behavior even though the separately frozen generic Value
serializer still needs a derived success-path update for this special key.

## Memory and native composition

The existing `serde-json.v1` build profile supplies a 16 MiB framed input
buffer, 64 MiB output buffer, and 256 MiB workspace. The diagnostic's own
raw-input limit remains 8 MiB. A 1 KiB output span is sufficient for its
original fixed messages and numeric displays, but smaller exact-capacity
spans are accepted when the actual result fits.

The workspace contains numeric scratch below byte 8192, parser words at
16384, a 4096-record stack at 32768 (64 bytes per record), and the immutable
input copy/decoded inner strings at byte 1048576 and above. Each capture
checks its remaining arena capacity before writing. A nested RawValue keeps
its enclosing source and stack frame until its inner result is known.
Therefore a caller must use the declared 256 MiB workspace for the whole
bounded input domain, rather than extrapolating from a smaller workspace
used by ordinary inputs.

The integer decimal-to-binary64 and shortest-number-display closures are
imported from the pinned HIA Value source. Two numeric functions coalesce
their source and scratch resource arguments into the private workspace;
their arithmetic, constants, calls and branch graph are otherwise retained.
Token reads are above 1 MiB and the existing numeric writes remain below
8192. The standalone UTF-8 helper is imported unchanged. The accompanying
composition record binds every original and derived function before call
relocation. This is an explicit resource-ABI adaptation, not a host semantic
fallback.

## Qualification and current integration boundary

The unchanged d3 HIA compiler built the real source and static ELF. The
base suite contains 98,699 retained semantic rows, 41 actual capacity/frame
controls, and four empty-PATH static-ELF processes. A fresh explicit Rust
1.95 release build of all eleven locked registry dependencies and the actual
`from_slice::<Value>` observer replayed the complete corpus, producing
8,597,741 identical bytes. Full source, process, corpus and binary records
are retained. The separate combined RawValue arena/stack suite adds two 8 MiB semantic
rows, two exact-minus-one capacity refusals, and one static ELF execution.
The most demanding retained cases use 142,600,689 and 142,557,939 bytes of
workspace, with 38 and 2,288 live stack records respectively. Both exact
capacities succeed; one byte less refuses atomically. The same actual Rust
binary replayed both additional rows with all 230 output bytes identical.

Across the two semantic suites there are 98,701 retained reference rows,
98,753 direct native calls, 43 controls, and five actual static ELF processes.
The portable reference recipe builds the original observer with explicit
Rust 1.95 and a checked-in locked dependency graph, then replays both complete
streams. Retained historical captures are not fresh executions.

This component run reuses and rechecks the pinned HIA compiler fixed point;
it is not a new full compiler cold replay. Public SSH/MCP call-site adoption,
typed-derive diagnostics and whole-runtime replacement remain separately
tracked. No original production owner is removed by this private component.
