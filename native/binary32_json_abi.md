# Native binary32 JSON byte owner

`f0(readbuf, mutbuf, mutbuf) -> u32` accepts exactly sixteen bytes:
`HJF32001`, followed by a little-endian `u64` containing one raw binary32 bit
pattern. The upper thirty-two bits must be zero. Workspace is 8,192 bytes.

Success returns the byte count of the compact JSON serialization used by the
locked `serde_json 1.0.151` and `zmij 1.0.23` implementation. The HIA algorithm
uses integer interval arithmetic, including negative zero, subnormals, all
finite exponents and JSON `null` for nonfinite values. It does not call a host
floating-point formatter. Invalid framing returns `0xffffffff`; insufficient
output or workspace returns `0xfffffffe`. Refusals preserve output bytes.

The independent qualification includes 541,693 original Rust bit patterns,
one native bulk invocation importing all fifteen production helper functions
without changes, 1,045 direct production entries, and six refusal controls.
This is not an exhaustive test of all 2^32 patterns. The standalone transport
is not activated: the owner is an image-only private byte dependency under
the existing `serde-json.v1` capacity profile.
