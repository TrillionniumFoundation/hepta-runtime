# Native background-job output and resource text

## Ownership and original boundary

`shell_background_text.hepta` implements the deterministic output and text
projection in `src/mcp/fs/background.rs` from runtime commit
`93f320a8e02b522e4bafd4a2cf346d68069ec74b`. The complete original file has
SHA256 `826394f843a0891dfbe8b0b6986dad40d85b53e20a497cb4ddb04838a185f065`.
Its owners are `read` after the two `read_tail` results,
`resource_text`, `resource_uri`, and `job_id_from_uri`.
The successful, stable-file tail selection in `read_tail` is also available
as a separate input operation.

The module has no filesystem, registry, locking, process, or MCP effects. Its
caller supplies the registry lookup result and the status observed at the
original point after both log reads and output conversion. Unknown jobs return
the original `None`. Supplying a known record does not independently prove
registry membership. Production resource dispatch and background-job registry
ownership remain separate integration work.

The compiler is pinned to Hepta
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, using HIA program v8 and the common
`hepta.runtime.borrowed-bytes.linux-x86_64.v1` ABI. The entry is
`f0(readbuf input, mutbuf output, mutbuf private_work) -> u32`.

## Input frame

All header integers are little-endian u64 words. The frame has exactly 88
header bytes followed by the four contiguous byte strings.

| Offset | Field |
| --- | --- |
| 0 | Eight literal bytes `HSHBGT01` |
| 8 | Operation: 1 stable full logs, 2 observed tail results, 3 make URI, 4 parse URI |
| 16 | Known-job flag, exactly 0 or 1 |
| 24 | Status: 0 Running, 1 Exited |
| 32 | Exit code: the i32 value sign-extended to its exact two's-complement u64 bits |
| 40 | Original stdout `read_tail` truncated flag, exactly 0 or 1 |
| 48 | Original stderr `read_tail` truncated flag, exactly 0 or 1 |
| 56 | ID/URI argument byte length |
| 64 | Command byte length |
| 72 | Raw stdout byte length |
| 80 | Raw stderr byte length |
| 88 | ID/URI bytes, command bytes, stdout bytes, stderr bytes, in this order |

The ID/URI and command are valid UTF-8, including NUL and embedded newlines.
Log bytes may contain any bytes. Every length is checked by subtracting from
the actual remaining frame extent, so overflowing lengths cannot wrap into
valid spans. Extra or missing bytes, invalid UTF-8 in string fields, invalid
flags/status/code, and noncanonical unused fields are refused.

Running requires exit-code bits zero. Exited accepts all i32 values, including
`-2147483648`, `-1`, `0`, and `2147483647`; values outside this signed
32-bit domain are not silently truncated.

### Operations 1 and 2

Known-job flag 1 supplies a job projection. With flag 0, only the ID may be
nonempty: command/log lengths, status, code, and both truncated flags must all
be zero. The result is `None`; no workspace is needed.

Operation 1 takes complete, stable raw log snapshots. Both input truncated
flags must be zero. Each stream longer than 30,000 bytes is independently
replaced by its last 30,000 raw bytes, and its truncated flag becomes true.
Exactly 30,000 bytes does not set that flag.

Operation 2 takes the exact `(Vec<u8>, bool)` results already observed from
the original log-read boundary. It preserves every supplied raw byte and both
flags; it does not apply another per-stream limit. This is necessary because
the original ignores metadata, seek, and read errors: a failed seek, a partial
read, or concurrent growth can produce a result that is not a stable
30,000-byte suffix. Opening failure is represented by empty bytes and false.
This operation represents all such observed results; it does not claim that
this pure renderer performed or qualified those filesystem operations.

Both operations then execute the same deterministic projection:

1. Convert stdout and stderr separately using Rust's UTF-8 lossy replacement
   boundaries, including incomplete multibyte sequences and invalid
   continuation bytes.
2. If stderr is empty, select stdout. If stdout is empty, select stderr.
   If both are nonempty, join them with exactly `\n\nstderr:\n`.
3. Test the combined UTF-8 **byte** length against 30,000. If larger, take its
   last 30,000 bytes and apply UTF-8 lossy conversion a second time.
4. Set the final truncated flag to the OR of the two stream flags and the
   combined-output truncation flag.

A cut through a multibyte character can therefore make the final output
slightly longer than 30,000 bytes. There is no final character-boundary
adjustment or third truncation. ANSI escapes, CR, whitespace, empty lines and
repeated lines are retained; foreground terminal cleaning is not part of this
owner.

The exact resource text is:

```text
job {id}
command: {command}
status: running

{output}
```

Exited status uses `exited with code {signed_decimal_code}`. If truncated,
the following exact line is inserted immediately after the status text:

```text
[earlier output dropped — showing the last 30000 bytes]
```

There is one preceding newline before that marker and two newline bytes
between the status/marker and output. No trailing newline is added.

### Operations 3 and 4

The first string holds the sole argument. Known-job, status, code, truncated
flags, command length and both log lengths must be zero.

Operation 3 returns `octofs://jobs/` followed by the exact ID bytes.
Operation 4 implements the case-sensitive `strip_prefix("octofs://jobs/")`
operation. It returns the remaining ID for a match and `None` otherwise.
An exact prefix with an empty remaining ID is `Some("")`, not `None`.
There is no URL decoding, escaping, path normalization, or nonempty-ID rule.

## Output and refusal contract

A successful return is the exact number of published output bytes. The
48-byte output header is followed by three contiguous payloads.

| Offset | Field |
| --- | --- |
| 0 | Eight literal bytes `HSHBGR01` |
| 8 | Present flag: 0 None, 1 Some |
| 16 | Final output truncated flag |
| 24 | JobView output byte length |
| 32 | Complete resource-text byte length |
| 40 | URI/ID result byte length |
| 48 | JobView output, resource text, URI/ID bytes, in this order |

Operations 1 and 2 with a known record return all three payloads, with the
third equal to `resource_uri(id)`. Operation 3 returns only the third payload,
containing the constructed URI. Operation 4 returns only the third payload,
containing the parsed ID. None returns a 48-byte header with all five numeric
fields zero. An empty parsed ID has present 1 and all three lengths zero.

Return `0xffffffff` means invalid typed framing. Return `0xfffffffe` means
insufficient transport or workspace capacity. These are distinct from the
original `None` result. Both refusals leave every output byte unchanged.
Success modifies only the returned prefix; every trailing output byte remains
unchanged. The input buffer is immutable.

The two rendering operations first count the complete first-round lossy
combined output. Workspace must hold exactly that many bytes; no initialization
is required. The renderer writes that private combination, counts the final
second-round output and all metadata, and checks the complete output capacity
before publishing any output. URI helpers and unknown-job results require
zero workspace.

The selected NativeBuild manifest carries the byte transport capacities.
The packed imported decoder uses a 32-bit byte-offset field: input length and
the first-round combined workspace extent must each fit u32. Successful output
lengths must be below `0xfffffff0`, which reserves the shared error-code range.
Exceeding any of these explicit byte-transport bounds returns capacity refusal;
the original command, ID or observed-log result has no new semantic length
restriction.

## Reused HIA functions

The strict UTF-8 validator and little-endian input/output helpers are retained
from `native/shell_gate.hepta`, whose SHA256 is
`52682cdf9e13a3eaf3ad8f168112531b2f918ed6139f06b769665a2ddaec05d1`.
Their original functions `f62`, `f63`, `f65` become `f19`, `f20`,
`f21`.

The complete Rust-compatible lossy decoder from `native/policy.hepta::f18`
becomes `f22`. The source SHA256 is
`57d64450b81a46b92687a3efec056e2491e4c4a4ffde57a0999124d6bb0736d0`;
the canonical function SHA256 is
`24e4b678399d88114aa161b9a6ac50dbfc9dbd8a49a61528a4983d673bd09c4f`.
Function `f23` is the same decoder with only its function name and buffer
parameter/block types changed from readbuf to private mutbuf, allowing the
second conversion to read the already-owned combination. Its instructions and
control flow are unchanged. All functions are in the compiled native image;
there is no host-language rendering fallback.
