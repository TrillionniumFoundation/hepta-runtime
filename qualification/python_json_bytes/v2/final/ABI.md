# Native Python JSON byte decoding ABI

Entry f0 is a pure HIA function using the standard three-span ABI
(input pointer/length, output pointer/capacity, workspace pointer/capacity).
The input is an unframed byte sequence of at most 6,291,456 bytes. The caller
provides distinct, valid spans; the input remains unchanged. No interpreter,
libc codec, host semantic fallback, or syscall is required by this owner.

The owner implements the byte-processing part of CPython 3.12.3 json.loads:
json.detect_encoding(input), followed by decoding with surrogatepass.
UTF-8, UTF-8 with BOM, UTF-16 and UTF-32 with both byte orders and BOM or
zero-byte autodetection are included. Lone surrogate code points remain
representable. The JSON grammar and Python value operations belong to the
separate python_json_value owner.

Workspace capacity is at least 1,024 bytes. Bytes after offset 1,023 and all
borrowed-buffer guards remain unchanged. A conservative output allocation is
max(512, 64 + 4 * input_length). Qualification also covers smaller capacities.

The native return is the complete output extent, or one of these private u32
refusals: 0xffffffff for input over the bound, 0xfffffffd for workspace below
1,024 bytes, and 0xfffffffe for insufficient output capacity. Refusals leave
the entire output unchanged. Input and workspace admission precede decoding;
those two refusals also leave the entire workspace unchanged. Output-capacity
refusal may leave the admitted diagnostic workspace populated.

Successful return starts with eight little-endian u64 words, then one complete
payload. The first word is the eight bytes HPYDER01. Word 1 is the kind.

For kind 0 (decoded text), words 2..7 are: encoding ID, code point count,
BOM bytes skipped, zero, zero, payload byte count. The payload is UTF-32LE,
including unpaired surrogates, with exactly four bytes per code point.

For kind 1 (UnicodeDecodeError), words 2..7 are: encoding ID, actual error
start, exclusive error end, reason ID, first erroneous byte, payload byte
count. The payload is the complete UTF-8 class-prefixed original diagnostic.
UTF-8-with-BOM error positions refer to the post-BOM error object, exactly
as CPython does; UTF-16/32 positions include consumed BOM bytes.

Encoding IDs: 1 UTF-8, 2 UTF-16LE, 3 UTF-16BE, 4 UTF-32LE, 5 UTF-32BE.
Reason IDs: 1 invalid start byte, 2 invalid continuation byte, 3 unexpected
end of data, 4 truncated data, 5 code point outside the Unicode range.

Publication is atomic: a complete admission/decode pass determines the
output extent before any output is written. A second pure pass emits decoded
text. The complete output tail remains unchanged. Caller code must preserve
kind 1 diagnostics and must not reinterpret lone surrogates as invalid input
to this owner.

## Qualified production identity

The sole final HIA source has 28 functions, 2,008 instructions and 178 blocks.
Source SHA-256:
f21190231ca5ae4c2e466f39b4cfae049acba4416fc813e485ce88028e25cd09

The 108,673-byte native image SHA-256 is:
78f300c74e6340fa5225e1b6b66e58903924656282bee4614f5e341333775e85

Compilation uses pinned Hepta d3e2c90173cf733e42b299d0c4274df4b593a12f and
retained fixed-point B3. The build manifest uses serde-json.v1 transport
ceilings of 16 MiB input, 64 MiB output and 256 MiB workspace; the stricter
owner bounds above apply to every caller.

Actual qualification retained 100,640 original calls and 100,670 HIA calls,
including 30 private admission/capacity controls. All 65,536 two-byte inputs,
all single bytes, every Unicode code point across ten encoding/BOM variants,
surrogate and truncation boundaries, exact six-MiB inputs, and complete error
texts were compared. All four independently recovered uploaded archives
passed, including full process records, input/output/workspace bytes and
guard spans. Eight physically resealed corruptions were refused and two
complete directory relocations were accepted. No completed application or
physical control was replayed by independent reading.

This closes this private decoder owner. Upload/inode bodies, value parsing,
caller lifetimes and public route integration have separate qualifications.
