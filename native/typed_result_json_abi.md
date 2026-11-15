# SDK typed result serialization

`typed_result_json.hepta` emits the actual locked rmcp 3.4.1
`serde_json::to_vec(CallToolResult)` or `serde_json::to_vec(ErrorData)` bytes.
The input is the canonical `serde_json::to_value` projection of that same typed
value. A generic caller-supplied JSON object is not sufficient provenance.
This owner does not implement SDK deserialization or non-Complete responses.

## Input and execution

The 24-byte little-endian header contains `HRTYP001`, a u64 tag (1 Complete,
2 ErrorData), and a u64 body length. The body follows immediately with no
trailing bytes. It is UTF-8, canonical compact Value JSON, at most 8 MiB.
The `serde-json.v1` image profile admits the frame; the owner needs 96 MiB of
workspace. Output capacity may be any sufficient size within the profile.
There are no host effects or child calls. Success returns the exact output
byte length, without a terminating NUL or header. INVALID is `0xffffffff`;
CAPACITY is `0xfffffffe`. Refusal leaves the output payload unchanged.

The Complete owner covers Text, Image, Audio, embedded text/blob Resource and
ResourceLink, their typed annotations/icons, optional resultType, structured
content, isError and metadata. ErrorData covers code, message and optional
arbitrary data. Typed declaration field order and absent/present-null choices
are preserved. Arbitrary JSON values retain Value formatting and key order.
An annotation priority is decoded from its exact binary64 widening of binary32
and formatted as binary32; it is not formatted as a generic JSON f64. The
canonical null projection of a non-finite priority stays null. Other numbers
are not narrowed. Unknown typed fields and unsupported variants are refused.

## Independent binary32 owner

`binary32_json.hepta` accepts `HJF32001` plus a little-endian u64 containing
32 raw float bits; upper bits must be zero. It requires 8192 workspace bytes.
It returns exact JSON float bytes, including signed zero and null for
non-finite input. No host floating-point formatter is used at runtime.

## Actual qualification and limits

On ai395 with Rust 1.95, job `1a1de0aac30-392-2296` freshly compiled both HIA
and the locked original SDK oracle. All 5,249 Complete/ErrorData cases matched
complete bytes; two additional actual original probes selected exact 8 MiB
body boundaries. Fourteen rejection/capacity controls passed. All 100 locked
registry packages, all 175 SDK files and all selected serde_json/zmij sources
were checked. Deep arbitrary metadata/structured values include depth 256.
Task and InputRequired serialization remains outside this contract.

The independent binary32 job `1a1dded457c-392-223b` compared 541,693 bit
patterns and all 7,170,383 output bytes, spanning every exponent/sign,
subnormal edges and deterministic random samples. This is not an exhaustive
enumeration of all 2^32 inputs. It made 1,045 production-owner entries and
one exact-import bulk fixture entry, with six controls.

The earlier typed qualification failed at the Rust fixture format check and
is preserved as failure. Local retained-oracle replays are identified
separately from the fresh original builds. This component does not qualify
request persistence, transport admission or production activation.
