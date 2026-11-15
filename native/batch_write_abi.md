# Native Local batch-edit body

## Owner and boundary

`native/batch_write.hepta` implements the Local body of
`src/mcp/fs/text_editing.rs::batch_edit_spec`, pinned to runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`. It calls fixed HIA owners for
canonical file locks, the fresh history snapshot, atomic replacement, the
session view cache, editable text, endpoint verification, conflict/apply, and
the final annotated result. `native/batch_render.hepta` owns the original
result layout. `native/batch_write_packer.hepta` emits the fixed Linux x86-64
static executable containing those owners and its syscall/thread boundary.

The packet below is a trusted internal projection. It is not an MCP tool,
session authorization mechanism, public parameter decoder, or replacement for
the common policy, effect-permit, audit, durable-result, and SDK layers. The
resolved raw Local path and original display string are separate values.
Remote/SFTP execution is outside this composition.

## Request

The borrowed entry has the existing three-buffer HIA calling convention and
returns a `u32`. Integers in packets are unsigned little-endian 64-bit words
unless a field below says otherwise. `HFBWT001` requests have a 64-byte header.

| Offset | Value |
| --- | --- |
| 0 | Eight bytes `HFBWT001` |
| 8 | Request context: `1` has the private view cache; `2` has no request context |
| 16 | Raw Unix Local path length |
| 24 | UTF-8 display path length |
| 32 | Operation count |
| 40 | Complete encoded operation-record length |
| 48 | `1` if the original `path` parameter is present; `0` if absent |
| 56 | Zero |
| 64 | Raw path, display path, then the complete `HBPLAN` operation records |

Operation records use the published batch-plan typed record representation;
their entire original input domain and byte lengths remain available to the
fixed planner. There is no JSON interpreter in the production boundary.
Undefined enum values, malformed spans, invalid required UTF-8, trailing frame
bytes, and child-contract violations are transport refusals. An admitted
semantic request retains the original missing-path, empty-operation, and
over-50-operation ordering before filesystem activity.

## Result and continuation

An ordinary result is `HFBWR001`, followed by a result kind at offset 8
(`0` success, `1` original error), complete UTF-8 body length at offset 16,
zero at offset 24, and all body bytes starting at offset 32. Original errors
are preserved without truncation or substitution by capacity errors.

| Return code | Meaning |
| --- | --- |
| Below `0xffff0000` | Exact number of initialized output bytes |
| `0xffffffe0` | Fixed child call is pending |
| `0xffffffe1` | Wait for the already-issued lock operation |
| `0xffffffef` | Grow the private workspace to the declared checked extent |
| `0xffffffee` | Grow the caller's output buffer |
| `0xfffffff7` | Original asynchronous cancellation completed |
| `0xfffffff9` | Invalid private continuation or child contract |
| `0xfffffffe` | Insufficient caller capacity |
| `0xffffffff` | Invalid outer transport frame |

The fixed boundary owns completion words and private buffers. A caller may
not fabricate a child result, choose a module number, supply a file descriptor,
or redirect a syscall pointer. Complete expected child result lengths and
source/reply spans are checked before use. `batch_write_layout.json` records
the fixed private offsets; they are implementation custody, not public input.

## Fixed graph

| Image | HIA owner |
| --- | --- |
| 0 | Batch body continuation |
| 1 | Canonical lock service |
| 2 | Local canonical-key traversal |
| 3 | Shared history state |
| 4 | Shared atomic-write policy |
| 5 | Private session view cache |
| 6 | Local read policy |
| 7 | Shared file-lock state |
| 8 | Editable content |
| 9 | Batch plan |
| 10 | Line endpoint |
| 11 | Line verification |
| 12 | Batch conflict/apply |
| 13 | Annotated result renderer |

The actual ELF contains exactly this table and all fourteen compiled images.
The builder separately compiles two small qualification-only UTF-8 probes;
they are not embedded production children. They execute the exact relocated
new and original HIA UTF-8 closures. The complete compiler dependency, source
functions, emitted images, pack input/output, normalized fixed ELF prefix,
embedded bytes, and native compile/pack receipts are rechecked on cache use.

## State, effects, and cancellation

Four actual native request threads have private controller, key-traversal,
read, and write state. Lock/history/cache arenas are shared under native
serialization. Dynamic arena growth, pointer replacement, and retirement
occur while the corresponding state lock is held. EOF drains worker state
and reaps children before releasing its storage.

The call order retains existence admission, canonical guard acquisition,
the first strict UTF-8 read, complete validation and conflict checks, reverse
application, a separate fresh history read and key, atomic replacement,
a fresh cache key and separate cache get/set or invalidation, then rendering.
The canonical file guard remains held through the final render. Untouched
CRLF/LF terminators and trailing-newline behavior belong to the existing
editable owner. The atomic owner retains the original deterministic temporary
path, followed metadata, permission bits, write-error residue, and cleanup
ordering.

Cancellation does not invent completion of a held syscall. At an original
asynchronous boundary it releases the logical guard and acknowledges the
cancelled task, while the fixed supervisor separately waits for the real
blocking worker to drain before reusing its buffers. Synchronous original
sections finish before observing cancellation. Tests distinguish these causal
orders from an impossible total ordering across independently scheduled
threads. Independent paths may progress while one path is held. Identical
concurrent edits retain the original duplicate-line errors after the first
successful queued edit.

## Capacity and qualified scopes

Only image 0 and renderer 13 use the private `batch-write.v1` declaration:
512 MiB input, 2 GiB output, and 3 GiB workspace. Other images and all previous
profiles retain their existing declarations. See `batch_write_capacity.md`
for the live-buffer analysis and the complete 50×5 MiB case. Its normalized
transport response is 1,279,265,842 bytes and its final CRLF file is
262,144,100 bytes. Captures retain and compare every byte. This finite `u32`
return interface does not claim every size representable by Rust `usize`.

The direct-image suite exercises a positive existing-cache match using real
HIA state owners and explicitly synthetic filesystem/canonical completions.
The static executable tests real filesystem, history, cancellation, aliases,
permissions, and shared lock behavior. Its cache begins empty and the
qualification transport has no public view-seeding operation. Therefore
`shared_cache_positive_branch_actual_elf` remains false until the public view
and batch callers share that state through the real session controller.

Public parameter conversion, public result wrapping, shared admission/audit/
result durability, remote execution, and complete production-handler coverage
remain outside this body qualification. All production/whole-runtime/old-stack
removal flags remain false. Design-time `PENDING` fields in source-composition
records are not edited into passes; actual invocations live in separate,
source-bound qualification receipts.
