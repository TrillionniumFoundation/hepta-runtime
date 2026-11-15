# Local batch body capacity

This is the capacity of the internal typed Local body and its fixed native
composition. It is not a new application-level file-size rule. The original
`batch_edit_spec` admits at most 50 operations, but does not impose a 5 MiB
limit on either a file or an individual content string. The 5 MiB cases below
are required complete qualification domains; larger original inputs remain
subject to the explicitly declared borrowed-buffer capacity.

The private `batch-write.v1` declaration is 512 MiB input, 2 GiB output, and
3 GiB workspace. Only root image 0 and result renderer 13 use this declaration.
The existing plan, apply, canonical key, history, cache, read, and atomic-write
images keep their original declarations. The shared repository's profiles
have not been changed. The proposed common-file changes are confined to
`private-common/scripts` and have exact before/after hashes in
`private-common/profile-change.json`.

## Why one GiB is insufficient

Let B be the original normalized file bytes, M the maximum content bytes in
one operation, C the sum of all operation content bytes, and N the operation
count. For the complete B <= 5 MiB, M <= 5 MiB, N <= 50 domain, C <= 250 MiB.
Each successful operation's original diff may copy two preceding and two
following context lines, as well as its added content. A line is no longer
than max(B, M). The content part of an operation's output is therefore bounded
by `4 * max(B, M) + M`; prefixes, numbered hashes, separators, removed markers,
and shift notes add a small bounded amount. A conservative 512 bytes per
operation suffices for those decimal fields over this domain. This gives
`50 * (25 MiB + 512)` bytes, below 2 GiB but above 1 GiB.

The retained full boundary case replaces 50 small original lines with 50
distinct uniform lines, each exactly 5,242,880 bytes. Every operation emits
one added line and up to four adjacent context lines. The edge operations
remove six context appearances from the maximum of 250: 244 complete big
lines appear in the actual expected result. The exact body length is
1,279,265,798 bytes, and the internal `HFBWR001` result length is
1,279,265,830 bytes. Every output byte is retained and compared, including
the prefixes and all repeated context content. The final file uses the
original CRLF convention and is exactly 262,144,100 bytes.

## Live workspace and child capacity

After successful atomic replacement, the first raw read, the fresh history
snapshot, and the already-written rendered content are dead. The root moves
the still-live old normalized content, validated plan, and final normalized
content downward using overlap-safe HIA moves, then clears the retired tail.
This keeps about `2 * B + 2 * C` bytes live at final rendering (plus records
and small headers). Both that retained state and the complete render request
remain present while the complete child result is copied back. The
conservative result bound above brings this phase below 3 GiB.

Before replacement, final normalized content can be at most `B + C + N`
bytes, and a CRLF rendering at most twice that. Keeping the complete apply
result and a complete atomic-write request remains below 3 GiB for the same
domain. The existing 512 MiB I/O input covers the corresponding CRLF
rendering, including the fixed frame and ordinary qualified Local paths.
This arithmetic is not used to silently truncate or split a semantic
request. Actual child capacities and all spans are checked by both the HIA
continuation and its fixed native boundary.

The original I/O mapping offsets and all I/O limits stay unchanged. Larger
root workspace/output mappings are independent native allocations. Values
at or above 2 GiB are loaded into zero-extending registers before 64-bit
comparison; no sign-extended 32-bit immediate supplies an enlarged bound.
Only renderer 13 may return more than the old 1 GiB child bound. Other child
images retain the old exact result-capacity admission.

## Return-value boundary

The three-buffer entry returns a `u32`. Successful result lengths must be
strictly below `0xffff0000`, because the upper range contains reserved
capacity, cancellation, continuation, and contract codes. The 2 GiB output
ceiling is below that range. Capacity refusal remains a transport/capacity
result; it is never converted into an original business error, truncated
text, or a reduced operation count. This internal capacity-bounded owner
does not claim arbitrary Rust `usize`/`String` result sizes, public SDK
admission, remote execution, or complete production-handler closure.

## Evidence interpretation

The complete wide test generates and retains the full request, response and
final file as compressed streams, with independent raw lengths and SHA-256.
Its expected output uses a streamed copy of the original layout. Uniform-line
FNV-1a hashes use an independent affine jump over the low-byte cycle, checked
against straightforward byte iteration for all 256 byte values and nine
lengths. A native capture is not an original Rust pass: the separate full
original owner replay must compare every retained byte before original
parity is claimed. Earlier failures and older-capacity observations remain
separate historical evidence.
