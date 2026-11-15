# Batch edit result owner

`batch_diff.hepta` owns the unchanged post-write annotated diff and trailing
`shift: lines` note from `batch_edit_spec`. It consumes the successful original
plan, original normalized text and final normalized text. It performs no I/O,
history push, locking, authorization, duplicate detection or cache mutation.
The future filesystem caller must bind all three inputs to the same actual
planning/application transaction, then invoke this owner after the original
history → atomic write → cache update order. A plan is not an authorization token.

## Private input

The Linux x86-64 entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. The three spans
are disjoint and stable during one call. Every word below is little-endian u64.

The 64-byte input header is `HBDFQ002`, zero, original normalized length, final
normalized length, plan length, and three zero words. It is followed by original
normalized UTF-8, final normalized UTF-8, and the complete successful `HBPLR001`
plan from the existing batch planner, with its original 1–50 operation domain.
There is no ignored suffix. Operation ordinals, kinds, range kinds, exact lengths,
UTF-8 and resolved original line bounds are validated before workspace mutation.

The original and final strings use Rust `str::lines` semantics, including CRLF
and a final unterminated CR. Operation strings use the original
`incoming_content_lines`: `str::lines` followed by removal of all trailing CRs
from each incoming line. The planner's empty-insert conversion is retained;
this owner does not silently repeat or substitute it.

## Fixed result header and dynamic extents

A normal return is always 64, independent of body length. The header is
`HBDIFR02`, status, body length, operation count, original line count, final line
count, required extent, zero. On status 0 the exact UTF-8 body follows at 64 and
required extent is `64 + body length`.

Status 2 requests the exact required workspace extent. Status 3 requests the
exact complete output extent. These are private allocation continuations; they
are not original tool errors. Status 4 is an unrepresentable u64 allocation or
output extent. A trusted caller may allocate or relocate the indicated private
span and repeat the unchanged pure request. No view 8 MiB gate, cumulative
window quota or u32 body-length truncation is introduced. Real address-space,
allocation and publication failures remain resource failures, including after
an already completed file write.

`0xffffffff` rejects malformed input. `0xfffffffe` means the output cannot hold
the fixed 64-byte header. Both leave every output and workspace byte unchanged.
Workspace-growth status leaves workspace unchanged. Once admitted, metadata
workspace is scratch: all used bytes are cleared before output-growth or normal
return, and unowned tail bytes remain unchanged. Result writes preserve unused
output tail. No file or state effects occur during either count/write pass.

## Original result semantics

The owner stable-sorts operations by original start, renders context from the
final file with two surrounding lines, hashes removed IDs from the original
file, and hashes added IDs from the incoming content itself. It retains complete
short blocks and the original first/range/last collapse for blocks longer than
three lines. Operation fragments join with `\n---\n`.

The shift note aggregates changes by original region end, including zero-sum
groups and end-of-file exclusions, before applying signed cumulative deltas.
FNV-1a folding and all decimal, sign, punctuation and UTF-8 output are native HIA.
This component does not by itself replace a public batch-edit route or establish
the lifetime of a write permit, history snapshot, file lock or request scope.

