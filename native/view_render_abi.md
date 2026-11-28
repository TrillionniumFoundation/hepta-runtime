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

The complete native source has 72 functions. Forty-nine are taken from the
existing `runtime_bytes.hepta`, `text_budget.hepta`, and `delta.hepta` owners.
Composition changes only their function identifiers and call targets. Tests
reverse this relocation and compare every imported function, block and
operation to its original admitted HIA document. All 49 imported functions
remain unchanged. Native bulk helpers copy complete text spans, normalize CRLF
by contiguous spans, and measure line prefixes without rendering unused hash
bytes. Publication still uses the original line hash; signed indexing, range
errors, Myers order, capacity admission and appended hints remain unchanged.
The growth revision replaces functions `f0` through `f3` and adds two
helpers. The other 66 previously admitted functions, including all 49 imported
functions, remain identical. The exact differences and their hashes are bound
by `growth_revision` in the composition record.

JSON endpoint parsing remains the existing `line_endpoint.hepta` owner. The
new component begins after that parser has produced typed endpoints. A parsed
line ID contributes its positional `usize as i64` bits; its hash does not
constrain viewing, exactly as in the original range resolver.

## Native and transport profile

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`, using the existing six-argument
Linux x86-64 borrowed-byte ABI. Input, output and workspace must be disjoint
live buffers. The module has no system-call effects and calls no interpreter.

| Resource or rule | Retained `view-render.v1` filter | Actual `view_call` composition |
| --- | --- | --- |
| Input frame | 16 MiB transport window | Complete growing caller-owned frame |
| Output buffer | 16 MiB | 16 MiB, sufficient for the semantic output bound below |
| Workspace | 256 MiB allocation | Grows from 128 KiB according to actual line tables |
| Original actual-file metadata threshold | 5 MiB | 5 MiB, unchanged |
| Original result-body threshold | 8 MiB | 8 MiB, unchanged |
| Original per-entry normalized cache threshold | 1 MiB | 1 MiB, unchanged |

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
two original reads can differ. The source admits complete independently
supplied snapshots without a fixed cumulative input window. The retained
filter still refuses frames exceeding its transport allocation; the actual
ordinary-file composition uses the growing reader and caller allocations.
Actual allocation failure remains a resource failure and is never recast as
the original 5 MiB metadata rejection.

Resolved start/end, first-read line count and actual-read line count occupy
independent u64 fields. They are not truncated to 32 bits. Line-table sizes
are checked against available scratch before multiplication. When previous
and current line counts differ by more than 500, the exact original Myers
distance ceiling already implies `None`; the source uses that lower bound
before attempting its bounded frontier. It does not change the original
distance, ordering, fallback or cache mutation decisions.

A successful result has at most 8 MiB of base text, two bounded range hints,
1 MiB of normalized cache payload and a 128-byte header. Error diagnostics
produced by this renderer are bounded messages with at most u64 decimal
fields. Thus its 16 MiB output allocation admits every semantic result;
workspace growth cannot conceal an insufficient renderer output. Larger
endpoint or path errors belong to the caller and use its separate growing
result allocation. All extents remain subject to the LP64 address space,
representable ABI lengths and real memory resources.

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

## Executable qualification

The same 72-function HIA source is compiled in two independently registered
borrowed-buffer profiles. The 16 MiB `view-render.v1` carrier retains its full
original test domain; the `history.v1` image-only carrier independently tests
larger complete snapshots. Neither carrier capacity is a semantic read limit.
The source and every compiled image are bound to the actual completed process,
current composition, unchanged original owners and complete captured bytes.

`test_view_render.py` requires 3,125 captured requests: 2,721 render requests
and 404 preparation requests. Its separate controls retain 135 malformed-frame
refusals, exact and insufficient buffers, an explicit workspace refusal and
actual static ELF requests. `test_view_transport.py` verifies the fixed filter
prefix and embedded image, six VM/native/reference samples, profile admission
and actual output-I/O failure. A failed or killed suite cannot qualify this
profile, even if its ordinary render samples passed elsewhere.

`test_view_render_growth.py` executes 2,707 actual HIA calls: 2,703 retained
ordinary semantic cases, two independent double-snapshot cases exceeding
33 MiB, and two short-output refusal controls. The semantic corpus therefore
has 2,705 rows; the overlapping retained cases are not additional original
behavior. The in-process native execution does not claim an ELF subprocess or
an original Rust execution. `test_view_render_growth_evidence.py` independently
admits the complete capture and rejects 30 changed invocation, artifact,
accounting and physical-stream controls.

The separate original recipes each freshly compile the unchanged
`oracle_view_render.rs` with Rust release overflow behavior and compare every
complete row. The source is reconstructed from the pinned original functions
before a corpus is accepted. The adapters supply typed endpoints, independent
read snapshots and an isolated original `ViewCache`; they do not replace the
original range, rendering, cache or result-gate decisions. Original replay adds
no native case. Source changes require new completed native evidence and a
fresh original comparison in the repository aggregate.

| Complete captured domain | Bytes | SHA-256 |
| --- | ---: | --- |
| Original-profile requests | 237,318,931 | `25ee9795db24913b4d2bb717711f613242b51b629203a1588e79bc7dba71a8db` |
| Original-profile responses | 139,202,296 | `3d432e0350eb351df875bcc8fa7d195fbefe2e64460a117a6e3c92c601417c17` |
| Growth-profile requests | 139,170,251 | `b9185e085ece0a3abc1271ba50979cba00d438051bd6a603413e07b5dbb57ac3` |
| Growth-profile responses | 1,173,696 | `6770742d493aa09accb8e3ec9e9696cc6d68e8e0ed02240120ec2b49b7d094b8` |

## Remaining production owners

The local-file caller now provides separate ordinary metadata/read observations,
growing snapshots, canonical cache-key derivation, the session cache lease and
request hints through fixed native children. Its independent read, parameter,
caller and wide-endpoint suites are required in addition to this renderer.
Their static fixture is not the complete production `view` handler.

The renderer returns raw text and a cache plan. The public JSON-RPC frontend
must transfer every accepted result into the growable publisher before it
retires or reuses the caller. Its profile must also account for JSON escaping
and complete error text. A bounded transport demonstration does not qualify
unconstrained production ingress or output. Directory traversal, content search,
remote paths, background resources and all production dispatch/installation
joins remain separate required owners.
