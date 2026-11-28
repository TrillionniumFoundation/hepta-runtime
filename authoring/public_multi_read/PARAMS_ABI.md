# Public multi-file typed parameter owner

This pure HIA owner projects the unchanged MultiReadParams declaration after the
actual installed serde_json Map admission. It does not look up hosts, authorize
paths, apply the 16-path business limit, or execute any remote operation.

The request is a 24-byte HMRPQ001 header followed by canonical Map JSON:
JSON length at 8 and kind 1 at 16. Return 0xffffffff refuses private framing;
0xfffffffe refuses output shorter than 256 before mutating either buffer.

An admitted return is always 256. The HMRPR001 result has status at 8
(0 success, 1 typed error, 2 workspace growth, 3 output growth, 4 extent refusal),
kind 1 at 16, optional-present bits at 24 (bit 0 file, bit 1 response),
full u64 file value at 32, full u64 response value at 40, path count at 48,
host byte length at 56, dynamic record bytes at 64, error length at 72 and
required capacity at 80. Bytes 88 through 255 are reserved zero.
Non-success headers contain no successful parameter fields.

Success payload begins at 256 with complete host UTF-8, followed by exactly
path-count records in original order. Each record is u64 byte length then the
complete path UTF-8. Arbitrarily many fully typed paths can be represented:
a wrong-typed seventeenth or later element must fail typed admission before
the handler's original path-count validation. Missing/null optional values
remain distinct from Some(0), and all unsigned 64-bit values remain exact.

Error payload is the complete original typed diagnostic. Workspace demand is
max(request length, 512) + 65536, with the original helper scratch layout and
a 512-byte field table at 65536. Growth preserves existing workspace and
appends zero bytes. Publication modifies no output bytes beyond its extent.
Current public gateway integration and complete remote execution remain separate.
