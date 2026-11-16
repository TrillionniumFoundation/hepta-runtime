# Bellman typed parameter and diagnostic ABI

All words are unsigned little-endian u64. Components use the unchanged
`batch-plan.v1` private buffer profile. No HIA image contains Rust or Python.

## Typed projection: bellman_params

Input is a 64-byte `HBLPAR01` header, operation 1, canonical JSON byte length,
five zero words, followed by that complete JSON. The canonical input comes from
the qualified serde_json Value owner: object keys are unique and ascending.
The projection verifies ordering and full syntax with a dynamically sized
explicit stack. Its classifier preserves the imported serde numeric graphs.

Output is a 128-byte `HBLPAT01` header:

| Offset | Field |
| --- | --- |
| 0 | Magic |
| 8 | Status: 0 typed success, 1 typed error, 2 workspace growth, 3 output growth |
| 16 | Appended graph length, otherwise zero |
| 24 | Required capacity for growth, otherwise zero |
| 32 | Successful state count, otherwise zero |
| 40 | Error class: 1 type, 2 value, 3 length, 4 missing field, 5 unknown field, 6 unknown variant |
| 48 | Unexpected node kind: null 0, false 1, true 2, number 3, string 4, array 5, map 6 |
| 56 | Expected-type or declared-field identifier |
| 64 | Invalid sequence length |
| 72, 80 | Complete quoted string's begin/end offsets in the original HBLPAR01 input |
| 88, 96 | Numeric tag (3 u64, 4 i64, 5 f64) and exact bits |
| 104–127 | Zero |

Success appends HIABELL1. Counts 1..4096 have six 120-byte records per state.
Other counts have only the 16-byte header with the real count. Each continuation
retains the true branch count and first three branch records. All tail states
and branches are still typed before publication. Numerical limits are checked
later by the actual Bellman core, after worker admission.

Return is the complete output length; typed errors and growth return 128.
Malformed header returns `0xffffffff`; output shorter than 128 returns
`0xfffffffe`. These two paths leave both buffers untouched. Invalid canonical
content returns `0xfffffffd`, with output unchanged and private workspace
allowed to change. A workspace growth identified before arena initialization
also preserves workspace; a later graph growth can retain parser scratch.
No partial graph or diagnostic is exposed. Growth publishes only its header.

## Diagnostic renderer: bellman_params_diagnostic

Input is the complete 128-byte typed-error response followed by the exact
original HBLPAR01 request. It validates descriptor classes, reserved words,
source extents and the quoted span before decoding it. The caller must retain
the same source borrow and response; this renderer does not authenticate them.

Output is 64 bytes `HBLPDR01`, status 0/2/3, complete UTF-8 error length,
required growth capacity and four zero words. Success appends the entire
original Serde error text and returns its full extent. Growth returns 64.
The invalid-header, short-output and invalid-content return codes have the same
meanings as above, with a 64-byte minimum output. Minimum private workspace is
65536 bytes. Complete text is rendered into private workspace before public
publication; the required workspace is 65536 plus its full byte length.

Diagnostic rendering preserves the qualified Rust Debug Unicode escape table
and exact serde_json finite float formatting. All Unicode scalar values are
tested in unexpected strings, unknown variants and unknown field names.

## Ownership boundary

These modules qualify the original typed Deserialize behavior and complete
errors only. They neither acquire a Bellman permit nor enforce its deadline,
authenticate a caller, serialize a successful plan, or activate a public route.
The typed graph must enter the real blocking worker; the successful plan must
use the timed commitment and separately qualified result owner.
