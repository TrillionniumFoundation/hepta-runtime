# Native `view` range, rendering and cache-action owner

`view_render.hepta` closes the deterministic local-file range and rendering
decisions used by the original `view` tool. It preserves two independent read
snapshots, original line-endpoint resolution, whole-file normalization, exact
line IDs, the unchanged/empty messages, Myers delta ordering and fallback,
the 5 MiB metadata limit, and the 8 MiB result-body limit.

This is an independent component, not an installed `view` handler. It does not
own path admission, file reads, directory enumeration, content search, remote
execution, request/session identity, cache storage, locks or write-history
invalidation. No additional MCP tool is advertised by this change. Legacy
owners remain retained and removal remains disallowed.

## Original source and reuse

The comparison baseline is runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`.
The exact source SHA-256 and Git blob identities are recorded in
`view_render_composition.json` for these original owners:

| Source | Decisions exercised |
| --- | --- |
| `src/mcp/fs/core.rs` | `resolve_endpoint_to_line`, `resolve_view_range`, result-size gate in `execute_view` |
| `src/mcp/fs/file_ops.rs` | Successful text-read branch of `view_file_spec`, ranged result error |
| `src/mcp/fs/delta.rs` | `ViewCache::set` action, `render_whole_file`, normalization, exact Myers rendering/fallback |
| `src/utils/line_hash.rs` | Signed clamped resolution and composite line IDs |
| `src/utils/truncation.rs` | Exact line renderer and megabyte formatting |
| `src/mcp/server.rs` | `append_hints` after the result-size gate |

The complete native source has 61 functions. Forty-nine are taken from the
existing `runtime_bytes.hepta`, `text_budget.hepta`, and `delta.hepta` owners.
Composition changes only their function identifiers and call targets. Tests
reverse this relocation and compare every imported function, block and
operation to its original admitted HIA document. No second implementation of
line hashing, clamped signed indexing, formatting, normalization or Myers is
used by the native runtime.

JSON endpoint parsing remains the existing `line_endpoint.hepta` owner. The
new component begins after that parser has produced typed endpoints. A parsed
line ID contributes its positional `usize as i64` bits; its hash does not
constrain viewing, exactly as in the original range resolver.

## Native and transport profile

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`, using the existing six-argument
Linux x86-64 borrowed-byte ABI. Input, output and workspace must be disjoint
live buffers. The module has no system-call effects and calls no interpreter.

| Limit | `view-render.v1` profile |
| --- | --- |
| Input frame | 16 MiB |
| Output buffer | 16 MiB |
| Workspace | 256 MiB |
| Original actual-file metadata threshold | 5 MiB, unchanged |
| Original result-body threshold | 8 MiB, unchanged |
| Original per-entry normalized cache threshold | 1 MiB, unchanged |

The larger profile is explicit in the builder and loader. The existing
`standard` profile remains 8 MiB input, 8 MiB output and 32 MiB workspace.
The new profile has a separate source-owned `view_filter_packer.hepta`; the
builder refuses a wide-profile stdio request because that transport is not
implemented. The filter reads one opaque frame through stdin, invokes the
actual HIA image and writes its result through stdout. It is a static ELF with
no dynamic loader, libc, Python or Rust runtime requirement.

Two independent 5 MiB reads and an optional 1 MiB previous cache entry fit the
input profile. A file containing 5 MiB of LF bytes can produce 5,242,880 lines;
with a 1 MiB previous all-LF snapshot the exact existing delta helper requires
more than the old 32 MiB workspace. Its line table, operation reserve and lazy
Myers snapshots fit the explicit 256 MiB profile. An insufficient workspace
returns a capacity refusal; it never becomes a semantic Myers `None`.

A metadata check is not a file lock. A file can grow after the check, and the
two original reads can differ. The input permits independently supplied
snapshots and accepts a complete frame up to 16 MiB, including a tested growth
case at exactly that bound. Larger races or insufficient caller buffers are
explicit native-capacity/transport refusals; the component does not pretend
they are an original 5 MiB file rejection.

Return values are a complete output byte count, `0xffffffff` for malformed
ABI input, or `0xfffffffe` for insufficient output/workspace. Refusals leave
the output unchanged. Workspace is scratch and can be reused. No output bytes
are written until the entire result and any cache payload fit.

## Input frame

Every integer is a little-endian `u64`. Signed endpoints carry their exact
two's-complement `i64` bits. The fixed header is 96 bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HVIEW001` |
| 8 | Operation: 1 prepare, 2 render |
| 16 | Flags below |
| 24 | Start endpoint bits, zero if absent |
| 32 | End endpoint bits, zero if absent |
| 40 | First read snapshot byte length |
| 48 | Actual body snapshot byte length |
| 56 | Previous cache snapshot byte length |
| 64 | First metadata size, zero if no successful first metadata observation |
| 72 | Actual successful metadata size |
| 80, 88 | Reserved zero |

Payload order is first snapshot, actual body, previous cache snapshot. Each
span must be valid UTF-8 and the frame must have no trailing bytes.

| Flag | Meaning |
| --- | --- |
| 1 | Start endpoint present |
| 2 | End endpoint present |
| 4 | `full: true` |
| 8 | Request context with a cache/hint scope exists |
| 16 | Previous cached snapshot exists, including an empty string |
| 32 | First text read failed; its byte length must be zero |
| 64 | First metadata observation succeeded |

No other flag is accepted. Previous data requires flag 16, and flag 16 requires
flag 8. Its byte length cannot exceed 1 MiB. A previous cached string is used
as supplied: it is not normalized again. In particular, a once-normalized
string can still contain CRLF when the original had `CR CR LF`.

If both endpoints are absent, first-read bytes, first metadata size and flags
32/64 must be absent or zero. Otherwise an unavailable first metadata
observation is represented by flag 64 clear and size zero; this does not imply
a first text-read failure. The latter is separate flag 32. Both distinctions
preserve the original `resolve_view_range` ordering.

The frame represents an actual body which was successfully read as UTF-8,
together with its preceding successful metadata observation. Actual
existence/type/metadata/read errors belong to the later IO caller; they are
not encoded as successful empty strings. An initial range read failure is
encoded because the original intentionally converts that failure into a
zero-line count before trying the actual file read.

## Result frame

The fixed result header is 128 bytes. Its payload is the complete result or
diagnostic text, followed by normalized cache bytes when action 1 is present.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HVIEWR01` |
| 8 | Status: 0 success, 1 original semantic error |
| 16 | Result/diagnostic text byte length |
| 24 | Cache action: 0 no action, 1 set, 2 forget |
| 32 | Cache payload byte length; zero for an empty-string set is valid |
| 40 | Resolved range present |
| 48, 56 | Resolved inclusive start/end lines, zero when absent |
| 64 | First snapshot line count |
| 72 | Actual snapshot line count |
| 80 | Hint mask: 1 transposed range, 2 clamped endpoint |
| 88 | Render kind below |
| 96 | Actual body's once-normalized UTF-8 byte length |
| 104 | Result/diagnostic body byte length before appended hints |
| 112, 120 | Reserved zero |

| Kind | Meaning |
| --- | --- |
| 0 | Full first view or `full: true` view |
| 1 | Unchanged cached contents |
| 2 | Delta, or a delta candidate in prepare mode |
| 3 | Exact Myers ceiling produced `None`; full-content fallback |
| 4 | Ranged formatting, including its original out-of-range diagnostic |
| 5 | Original `File is too large (>5MB)` rejection |
| 6 | Original zero-line-index error |
| 7 | Original result body exceeded 8 MiB |

An original semantic error is a successful native ABI response with status 1.
The caller must keep it distinct from malformed frames and native capacity.
For kind 7, cache action can still be set/forget: this is required by the
original side-effect order, not an error in the response.

## Range and whole-file behavior

When endpoints exist, the successful first metadata observation is checked
before counting first-read lines. A failed first metadata observation is
ignored. A failed/empty first read produces no range, even for a typed zero
endpoint; a malformed endpoint would already have failed in the parser.
For a nonempty first snapshot, missing start defaults to 1 and missing end to
−1. Start resolves first, then end. Both clamp, and transposed endpoints are
swapped. The swap hint precedes the clamp hint.

The actual body is independent. It can have fewer or more lines than the
first snapshot. The existing formatter clamps the resolved end to the actual
line count and can report `Start line ... exceeds content length`. That
diagnostic is an original tool error, and its hints are not appended.
Ranged reads leave the whole-file cache alone and ignore `full`.

Whole-file views normalize CRLF once, request cache set or forget before
rendering, and then use the prior snapshot unless `full` was true. Exact
string equality gives the unchanged message. Otherwise exact original
Myers distance 500, context 2, tie ordering and fallback determine the result.
No request context produces full views without hints or cache actions.

Rust `str::lines()` is preserved: LF ends a line, a preceding CR is removed,
a final LF adds no trailing empty line, and a final lone CR remains. Whole-file
normalization happens before that splitting; ranged splitting has no prior
normalization. Thus raw `a CR CR LF` is rendered as `a` for whole-file views
but as `a CR` for ranges. The cache payload remains `a CR LF` in that example.

The exact 8 MiB comparison applies to the rendered body before hints. Hints
are appended only after successful execution, as in the original server.
The tests include an exact-8-MiB ranged body whose appended hints take the
final text above 8 MiB; this is preserved rather than silently trimmed.

The publication path retains the first exact body measurement while the body
kind and range remain unchanged. It then measures only the appended hints
before admitting the complete output capacity. If the first body exceeds
8 MiB, its kind changes to the original oversized-result error and that new
body is measured separately. Prepare mode, early errors, cache actions and the
final render-after-capacity-check order remain unchanged. This removes a
repeated traversal of identical body bytes; it adds no output truncation or
new admission rule.

## Required caller sequence for cache effects

1. Keep the first snapshot, actual body, typed endpoints and previous cache
   snapshot immutable for this operation.
2. Invoke operation 1. Apply its requested set/forget action to the exact
   session/file cache identity before rendering. Action 1 with a zero-length
   payload means set an empty entry, not no action.
3. Invoke operation 2 using the same immutable input snapshots and prior
   cache entry. Do not replace `previous` with the just-committed current text.
4. Return the rendered text or semantic error. Do not undo the earlier cache
   update for an oversized body or a later native rendering-capacity refusal.

Prepare mode returns an empty text on a valid plan, plus cache payload and
resolved range facts. Known metadata/index errors still return their
diagnostic. A prepare delta candidate can become kind 3 after rendering, so a
caller must not require that provisional kind to equal the final kind.

This is a requested cache mutation, not proof that a real cache committed it.
The current component owns neither cache identity nor storage, locking,
allocation failure, poisoning, eviction or invalidation. The original cache
has a per-entry 1 MiB cap and no total-entry LRU. A future session-cache owner
must preserve or explicitly bound that domain; a small fixed replacement
cannot be presented as complete original cache parity.

## Executed verification

`test_view_render.py` supports `HIA_VIEW_MANIFEST`, `HIA_HEPTA_DIR`,
`HIA_VIEW_CORPUS_DIR` and explicit portable source/repository/loader arguments.
The supplied manifest must have been built with
`buffer_profile="view-render.v1"`. `HIA_BUILD_ROOT` is consumed by the normal
build/qualification driver, not by a fallback implementation in the test.
The test exports actual native inputs and outputs as `requests.hex.gz`,
`native-output.txt.gz`, and `native-corpus.json`. Their recorded hashes and
sizes describe the decompressed bytes.

The complete native run passed 3,125 corpus cases: 2,721 render cases and 404
prepare cases. It also passed 135 malformed-frame refusals, exact/insufficient
buffer controls, a 32-MiB workspace refusal distinct from Myers `None`, and
three real static-ELF cases. A separate transport suite passed six HIA VM /
native / independent-reference samples, explicit profile admission controls,
exact fixed transport-prefix and embedded-image binding, and actual output-IO
failure. The current measurement-reuse source completed the unchanged full
suite in 145.32 seconds (145.48 seconds including process startup and exit),
under the existing 180-second suite limit. The loader, all 3,125 corpus rows,
assertions and named buffer profiles were unchanged. These local observations
do not establish a CI speedup or a future timing guarantee.

`oracle_view_render.rs` contains the unchanged original function bodies and
the original Apache-2.0 notices. The test recreates it from the pinned original
files before accepting a corpus. Its adapters provide typed endpoints,
independent IO snapshots and an isolated original `ViewCache`; the original
functions still perform their original call sequence and cache methods.
The Rust binary takes no arguments, reads hexadecimal requests on stdin and
writes `OK <hex>` results on stdout.

The retained corpus was actually compared byte-for-byte against Rust 1.95.0
compiled with `--edition=2021 -O -C overflow-checks=off`. All 3,125 outputs
matched, including 139,202,296 uncompressed output bytes. The observed durable
job finished with exit code 0, complete stdout/stderr and confirmed terminal
publication. Input source and compressed corpus identities were checked
before and after. Detailed evidence is retained in
`view_original_rust_comparison.json` and `view_render_native_proof.json`.

The current native source reran the same full corpus and reproduced both
complete decompressed hashes exactly. The original Rust process receipt is
retained unchanged and is bound through those matching bytes; this
optimization does not claim another Rust compilation or execution.

| Artifact | SHA-256 |
| --- | --- |
| HIA source | `fe21cd3aa04cf81fd8a59480dcbf614de7ffddd8c9f25157007c2869bc7f0968` |
| Actual HIA image | `089f3b64ad7df1e0cec496fa5f0b2f9be34b96c83aacb1ad2e314295526e49ee` |
| Static ELF | `6de6d2d3d0d20fd2b70f9a13dc5bb40ae71b031a0de0a9105ebc12d08173a965` |
| Rust source | `36efacf6a1d418c10251afed788f52b20127c62fa39a3f2534882461cce8d585` |
| Decompressed requests | `25ee9795db24913b4d2bb717711f613242b51b629203a1588e79bc7dba71a8db` |
| Native and Rust output | `3d432e0350eb351df875bcc8fa7d195fbefe2e64460a117a6e3c92c601417c17` |

## Remaining production owners

Actual local file admission and reads must preserve existence/type/metadata/
UTF-8 error ordering and the two-read behavior. Existing IO operation 2 has a
64 KiB, single-link full-read contract and cannot be relabelled as the original
5 MiB `view` reader. The root capability, pathname identity and path-policy
authority need their own integration.

The production caller also needs session cache custody and an output path
large enough for JSON escaping of an accepted 8 MiB result. The raw-text
component's 16 MiB output profile does not establish that an existing 8 MiB
MCP serializer can emit every such result. Directory, content search,
remote paths, endpoint JSON parsing/routing, cache write invalidation and
local-file IO are still retained owners. Until they are connected, the
complete `view` handler remains unmigrated.
