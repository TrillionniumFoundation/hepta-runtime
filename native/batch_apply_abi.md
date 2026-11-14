# Batch conflict and application owner

`batch_apply.hepta` owns the pure state transition after successful endpoint
planning: conflict detection, duplicate-context guards and ordered application
through the native `EditableContent` child. It does not read or write files,
acquire path locks, create history, update view caches, render a final diff or
activate a production MCP handler.

The reference is `src/mcp/fs/text_editing.rs` at runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`, together with original line-ID
formatting in `src/utils/line_hash.rs`. The composition document pins both complete
Rust files by SHA256 and Git blob. Operation indices are zero based. The Rust
adapter contains the original operation types, Editable methods, incoming-line
conversion, duplicate guards, `apply_batch_operations` and conflict loop without
changing their bodies. Test-only error carriers and a poll-once executor supply
transport for those private owners.

## Entry and ownership

The Linux x86-64 entry is `f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.
The caller owns three nonoverlapping buffers and keeps them stable through the
complete continuation. Workspace is private to one serial request. The caller
must not resume an unrelated request using a live continuation's workspace.

| Return | Meaning |
| --- | --- |
| `0xffffffe0` | Submit the fixed native Editable child call described by the footer |
| `0xffffffff` | Malformed typed request, invalid UTF-8 or invalid resolved range |
| `0xfffffffe` | Insufficient admitted output or workspace capacity |
| `0xfffffff8` | Child, continuation, identity or result contract failure |
| Other successful value | Complete response length below the reserved-code domain |

Refusals leave every caller output byte unchanged. Original conflict and duplicate
errors are normal structured responses with status 1 and their complete original
UTF-8 text. They are not truncated or converted to capacity-independent semantic
errors. Complete response capacity is checked before any caller output is written.

## Request

All words are unsigned 64-bit little endian. The fixed header is 64 bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HBACT001` |
| 8 | Mode: 0 rendered, 1 normalized, 2 normalized followed by rendered |
| 16 | Original raw UTF-8 byte length |
| 24 | Successful plan byte length |
| 32, 40, 48, 56 | Reserved, zero |
| 64 | Original raw bytes, then the complete plan |

The plan is the unchanged `HBPLR001` success response from `batch_plan.hepta`.
Its 48-byte header carries status 0, 1 through 50 operations, exact body length
and two zero reserved words. Each operation has six words followed by UTF-8
content: zero-based ordinal, kind, resolved-range kind, start, end and content
length. Kinds are 1 insert and 2 replace. Range kind must equal operation kind;
insert end is zero. All records and the frame end at their declared boundaries.
No padding or ignored suffix is permitted.

The component checks typed structure and resolved ranges against the original
logical lines. Possessing a typed plan is not authentication, path authorization
or proof that a file is unchanged. The later filesystem transaction owner must
keep planning and application bound to the same locked file version.

## Response

The 80-byte header is followed by selected text and then error text.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HBAPLR01` |
| 8 | Status: 0 success, 1 original conflict or duplicate error |
| 16 | Original operation count on success, zero on error |
| 24 | Original dominant ending length: 1 LF, 2 CRLF |
| 32 | Original trailing-newline bit |
| 40 | Final line count, or original line count on error |
| 48 | Final normalized length, or original normalized length on error |
| 56 | Final rendered length, or original raw length on error |
| 64 | Selected text length |
| 72 | Error text length |
| 80 | Selected text followed by error text |

Mode 2 concatenates normalized bytes before rendered bytes. A semantic error
has no selected text. Failure never exposes a partially applied result. Unused
output tail bytes retain their caller-provided contents.

## Original decisions and order

Conflicts use the original input-order `(i, j)` nested loop and report its first
conflict. Replacement ranges overlap inclusively. Equal insert anchors conflict.
An insert conflicts with a replacement when its anchor is at or after the
replacement start and strictly before its end.

Duplicate guards then run in original operation order. Replacement compares its
incoming first line with the preceding line before checking its last line against
the following line. Single-line insertion checks the next original line and
retains the original structural-noise exemption. Multi-line insertion checks the
available block prefix when at least two lines can be compared, without that
single-line exemption. Noise uses original Unicode trim, removes trailing comma
and semicolon characters and recognizes the original closing delimiters. Error
line IDs and Rust Debug string escaping match the original.

Application sorts replacements by descending original start, preserving input
order for ties, then inserts by descending original anchor. Each insert anchor
is adjusted by original replacement deltas whose ends are at or before it.
HIA translates the operations into an ordered `HEDIT001` program and executes
the native Editable child. Mixed LF/CRLF, literal CR text, empty unterminated
lines and original trailing-newline policy are preserved. A final empty line
remains distinct from an empty line vector. Internal state is never reconstructed
by reparsing rendered CRLF, which could discard literal CR text.

## Continuation and cleanup

Fixed image IDs are apply 4 and Editable 5. Apply has call mask 32 and can call
only Editable. Every call uses the existing `HIACAL01` 256-byte footer, workspace
regions, increasing sequence and fixed identity. Controller entry requires event
3 and caller 4. Results are consumed only after checking the complete footer,
acknowledgment, capacities, status, result length, metadata and UTF-8.

The first child call returns original normalized text and metadata. A success
then makes one selected-output call, or two for mode 2. At most three child calls
occur; original conflict/duplicate errors stop after the first. Final children
must report the exact translated operation count, original dominant/trailing
metadata and consistent lengths. Mode 2 compares both final metadata sets before
copying either result to the caller.

Every terminal path clears the complete controller-workspace prefix that could
have held original text, translated content, child output or diagnostics. The
high-water mark includes a prepared request before sequence exhaustion is tested.
Qualification checks every byte of that prefix and untouched tail, including a
known-secret child-result fault. The retained 256-byte completion footer is
separate. This is a controller-scratch claim: the independent Editable workspace
and caller's successful output are not claimed to be erased.

## Capacity domains

Direct-image qualification uses the existing `batch-plan.v1` borrowed-buffer
profile: 512 MiB input, 1 GiB output and 1152 MiB workspace ceilings. The caller
allocates actual buffers for each request. These are adapter capacity bounds,
not new original handler limits. The owner never replaces capacity refusal with
semantic errors, reduces the original 50-operation domain or imposes a new
5 MiB ceiling on each internal content value.

Qualification includes complete 5 MiB files and 5,242,880 empty lines. One case
combines a 5 MiB file with all 50 operations, each carrying 5 MiB of content:
request 267,389,392 bytes; response 267,387,010 bytes. Another retains a complete
26,214,696-byte duplicate diagnostic. Full input and output are retained and
compared as streams.

The separate static ELF is a bounded test composition, not proof that its hex
transport accepts every wide borrowed-image request. Its fixed table is:

| ID | Owner | Flags | Call mask | Input / output / workspace |
| --- | --- | --- | --- | --- |
| 0 | Hex test transport | 1 | 16 | 8 / 8 / 16 MiB |
| 1 | Batch plan | 1 | 12 | 8 / 2 / 16 MiB |
| 2 | Line endpoint | 0 | 0 | 8 / 8 MiB / 8 bytes |
| 3 | Line verification | 0 | 0 | 8 / 8 MiB / 192 bytes |
| 4 | Batch apply | 1 | 32 | 8 / 4 / 32 MiB |
| 5 | Editable content | 0 | 0 | 8 / 8 / 32 MiB |

The hex root has a 2 MiB child-result region and admits no file or entropy
effects. Eight actual static-ELF requests include all result modes, literal CR,
exact semantic errors, invalid framing and an explicit large-result capacity
refusal. Separately, eight actual native planner outputs pass unchanged to the
actual apply image and match the same original-replayed corpus entries. Joined
calls add no new original-reference cases.

## Required qualification

The strict builder verifies actual B3 compile receipts, the actual HIA packer
receipt, exact image/source identities, the complete static ELF prefix and table,
every embedded image, private offsets and padding. Development cache reuse is
not a fresh full compiler cold gate.

Four suites are required: full semantic/capacity corpus, child-contract faults
and cleanup, actual native/ELF composition, and physical evidence/image corruption
controls. All retain the existing 180-second suite deadline. The semantic corpus
has 14,412 original-reference cases, 140 malformed frames and six capacity
refusals. Actual calls are 36,210 controller entries and 21,652 Editable entries.
The fault suite has 103 requests, 304 controller entries and 201 Editable entries.
Evidence controls add zero native or Rust calls.

The mandatory original recipe freshly compiles and executes the unchanged owner
on all captured requests and retains all 301,354,944 response bytes. It also
freshly compiles and runs the Rust 1.95 Unicode Debug probe: all 1,112,064 valid
scalars in four prefix contexts, with all 1,114,112 native code-point flags
compared including surrogate refusals. Archived comparisons and a successful
helper readback do not replace a completed qualification process. The aggregate
must bind the helper to current completed stdout/stderr, timeout, source map and
exact suite commands.

The existing independent Editable 8,749-case native suite and locked original
Rust recipe remain required. Its only changed functions are f3, f5 and f8:
f3 unrolls the LF-count loop in blocks of 32 while retaining the original
last-byte and explicit empty-final-line additions; f5/f8 copy admitted byte spans
in bulk. The other 20 function graphs remain unchanged. The unprofitable f5
word-search experiment is retained only as development evidence and is not part
of the delivered owner. No semantic, capacity, CRLF or trailing-newline check is
removed by these implementation changes.
