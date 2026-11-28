# Durable audit Record, private ABI 1

This component owns the complete original `request_audit::Record` JSON type and the
additional filename/identity checks of `read_record`. It does not authorize an
owner, open files, select an archive, or implement a public Runtime handler.

All integers are unsigned little-endian. The six-argument flat HIA ABI uses an
immutable input, output, and private workspace. The return is the output length,
`0xffffffff` for a malformed private frame, or `0xfffffffe` for insufficient
capacity. A private-frame failure produces no output.

Input starts with `HRAJQ001`: operation at 8, JSON byte length at 16, filename
length at 24, then filename and JSON. Operation 1 is the exact typed Record
domain; operation 2 additionally requires a 69-byte lowercase hexadecimal ID
plus `.json` filename, matching request ID/owner/tool identity. Both operations retain the original
2,048-byte JSON bound. The filename is checked before the JSON.

Output starts with `HRAJR001`. Error results are 32 bytes: diagnostic at 8
(1 JSON type, 2 identity, 3 size, 4 filename), remaining words zero.
A successful result contains a 128-byte header followed by decoded UTF-8 request
ID, owner, and tool name. Header words: diagnostic 0; state at 16
(0 unknown, 1 completed, 2 failed); accepted timestamp low/high words at 24/32;
elapsed-present and elapsed milliseconds at 40/48; total length at 56; three
offset/length pairs at 64/72, 80/88, 96/104; reserved zero at 112/120.

The JSON owner retains the original six-field map and sequence forms, optional
elapsed field, externally tagged unit-state form, decoded-key duplicate and
unknown-field rejection, full Unicode decoding, and unsigned 128-bit timestamp
range. Its qualification compares complete output bytes to independently
compiled original Rust/Serde sources; it does not replace the public storage
and source-custody gates.
