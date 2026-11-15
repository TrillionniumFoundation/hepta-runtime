# Native batch Planner input bridge

This HIA owner translates the complete successful native `BatchEditParams`
projection and, after reading, the complete native `EditableContent` normalized
response into the existing Planner's `HBPLAN01` frame. It performs no I/O and
does not replace the public batch handler.

The 64-byte request is `HBPIQ002` followed by seven little-endian u64 words:
mode, complete parameter-frame length, complete Editable-frame length, and
four zero reserved words. The payload contains those two complete frames.
Mode 0 is preflight and requires the Editable frame to be absent. Mode 1
requires a successful, zero-operation, normalized `HEDRES01` response.

The successful parameter input is `HBPRR002`; decoded path and canonical
normalized object must agree byte for byte. The owner validates the complete
JSON grammar, scalar UTF-8, exact frame extents, operation count and private
field layout. A private producer contract violation returns `0xffffffff`
without publishing output. An output shorter than 64 bytes returns
`0xfffffffe` and preserves both output and workspace.

For ordinary outcomes the entry returns 64. The output begins with `HBPIR002`
and seven little-endian u64 words: status, complete Planner-frame length,
line count, operation count, required capacity, and two zero reserved words.

| Status | Meaning |
| --- | --- |
| 0 | Complete `HBPLAN01` frame follows the 64-byte response header |
| 2 | Workspace must grow to the exact required capacity |
| 3 | Output must grow to the exact required capacity |
| 4 | The required extent cannot be represented by u64 |

Growth responses publish only the fixed header and have zero body/count
fields. The minimum workspace is 32768 bytes; nested JSON uses a checked
two-byte stack entry per depth above that area. Callers continue only while
the requested capacity strictly increases and remains within their admitted
carrier profile. A private allocation boundary is not a batch semantic error.

The output preserves Rust `str::lines()` behavior over the already normalized
text: split on LF, remove one CR immediately preceding LF, keep a final bare
CR, and omit the empty segment after a trailing LF. Line lengths use canonical
ULEB128. Typed operations preserve their order, decoded content and exact
endpoint kinds. Null endpoints become absent fields. Integer endpoints use
the original JSON number's `as_i64()` range; other numbers have no scalar
payload. Strings are decoded UTF-8, and other Values retain compact canonical
JSON. Empty and over-50 operation lists remain intact for the Planner's
existing admission order. There is no independent 8-MiB gate in this owner.

Qualification invokes actual native Value, typed projection, Editable, this
bridge, Planner, endpoint and verifier images before compiling the independent
Rust reference. Complete native borrowed spans and complete original results
are retained. Full handler fencing, Session, policy, locking, read/write,
history, cache, diff, hints and public routing are separate unfinished callers.
