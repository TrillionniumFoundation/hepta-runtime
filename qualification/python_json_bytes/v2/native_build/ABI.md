# Python JSON byte decoder source contract

The entry accepts every byte string of length 0..6,291,456. It implements the
encoding selection in CPython 3.12.3 json.detect_encoding followed by the actual
surrogatepass byte decoder. It does not parse JSON syntax or execute IO.

Input is the complete unframed byte string. Workspace is at least 1,024 bytes.
The result starts with HPYDER01 and eight little-endian u64 words. Success kind 0
has encoding ID at 16, code point count at 24, skipped BOM bytes at 32, zero 40
and 48, payload bytes at 56, and complete UTF-32LE code points at 64. Surrogates
are preserved where surrogatepass preserves them. Encoding IDs 1..5 are UTF-8,
UTF-16LE, UTF-16BE, UTF-32LE and UTF-32BE; encoding byte order follows detection.

Unicode failure kind 1 has encoding ID at 16, original exception start/end at
24/32, reason at 40, first failing byte at 48, text length at 56 and complete
UTF-8 formatted UnicodeDecodeError, including its class prefix, at 64. Reasons
1..5 are invalid start, invalid continuation, unexpected end, truncated data,
and out-of-range code point. UTF-8 signature decoding reports positions relative
to the post-signature byte substring, matching its codec boundary.

Private returns 0xffffffff/0xfffffffd/0xfffffffe mean input resource bound,
workspace capacity, and output capacity. Output is unchanged on all private
refusals. Input is always unchanged. Decode admission precedes any output write;
accepted success emits exactly 64 + 4*codepoints bytes. Scratch is not persistent.
This source author has made zero application calls; no semantic qualification
is claimed until actual fixed runtime and native comparisons complete.
