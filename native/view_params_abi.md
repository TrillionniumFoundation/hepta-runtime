# Typed ViewParams projection

The HIA source entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. The trusted
JSON-RPC frontend must first
run the existing actual `serde_json` Value owner, operation 1, over arguments.
This private interface accepts that complete canonical Value serialization;
it is not a substitute JSON parser accepting public unvalidated bytes.

Input is `HVPRQ001`, `u64 canonical_json_length`, `u64 zero`, then the exact
canonical JSON object. The projection performs all original ViewParams type
checks before the frontend may touch its first-tool workdir latch, path policy,
or request scope. Unknown fields are ignored. Optional null is absent.
`start`/`end` admit any non-null JSON Value at this stage; endpoint parsing stays
after the original filesystem existence/directory dispatch.

The output header is 96 bytes, twelve little-endian words including magic:

| Offset | Field |
| ---: | --- |
| 0 | `HVPRR001` |
| 8 | Status: 0 typed success, 1 exact serde typed diagnostic |
| 16 | Boolean values: bit 2 full, bit 3 regex, bit 4 include_hidden |
| 24 | Decoded path byte length |
| 32 | Complete start HIAEP001 frame byte length, 0 when absent |
| 40 | Complete end HIAEP001 frame byte length, 0 when absent |
| 48 | Decoded pattern byte length |
| 56 | Decoded content byte length |
| 64 | Context usize value, zero when absent |
| 72 | Max_depth usize value, zero when absent |
| 80 | Optional presence bits described below |
| 88 | Diagnostic byte length, zero on success |

Success payload order is decoded UTF-8 path, start frame, end frame, decoded
pattern, decoded content. Presence bits are context=1, max_depth=2, pattern=4,
content=8, full=16, regex=32, include_hidden=64. These distinguish Some(false),
Some(0), and Some("") from None without inventing a public context selector.
The flags passed to the ordinary `HVCLQ001` branch are `flags & 4` only.

On a typed error, words 16 through 80 are zero and the payload is only the exact
serde diagnostic. It omits the router's `failed to deserialize parameters: `
prefix, which remains the real frontend's responsibility. No filesystem,
session, cache, scope, or publication effect has occurred.

A successful projection retains every valid directory/search field; it does
not label those routes as implemented. The frontend must preserve their
existing dispatch order and cannot replace an unsupported branch with an
ordinary-file success. In particular, content search follows the is_dir check.

`0xffffffff` is an invalid private frame or violation of the canonical-Value
contract; `0xfffffffe` is insufficient actual borrowed output/workspace.
Neither is an original typed diagnostic. Output is admitted in full before
writing. Exact UTF-8 bytes, u64 usize limits and optional-value presence are
owned by HIA; the host adapter performs no JSON or parameter interpretation.

## Storage and diagnostics

The owner scans the complete canonical object in its actual serialized key
order. It reports the first wrongly typed known field before checking for a
missing `path`, matching deserialization from the original sorted Value map.
String decoding and nested-value cursors use independent u64 offsets. The
scratch requirement is 32 KiB plus two bytes for each simultaneous nested
container; there is no separate fixed node-count or nesting quota. The caller
may grow actual scratch and retry a capacity refusal. A 64 KiB scratch buffer
covers the existing Value owner's admitted nesting domain.

`view_params_composition.json` binds the unchanged Unicode 17 Rust Debug
classification and scalar-emission helpers from `execution_json.hepta`.
Diagnostics preserve Rust string Debug escaping, including `\0`, `\u{8}` and
`\u{c}`, and use the actual canonical floating-point spelling produced by
`serde_json.hepta`. They do not substitute JSON string escaping for Debug.
The complete result byte count must fit the borrowed ABI's u32 success return
domain and the actual output allocation. A short output is unchanged; scratch
is disposable and can be overwritten on either success or refusal.

This projection does not independently claim the public router, capability
resolver, session latch, filesystem policy, or the later `view` branch. Those
owners must be connected to this same source image by the production frontend.
