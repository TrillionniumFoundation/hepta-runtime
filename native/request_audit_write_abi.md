# HIA audit record publication

This component implements the Unix `save_raw_with_sync` operation from
`src/mcp/runtime/request_audit.rs`, including its replacement read and staging
recovery. The authoritative implementation is `request_audit_write.hepta`.
`request_audit_write_composition.json` identifies its borrowed function, exact
scalar imports, immutable source digest, workspace layout and read child.

The static Linux x86-64 qualification executable contains the write owner,
the already qualified audit read owner and the typed audit JSON decoder.
`request_audit_write_packer.hepta` assembles those images using the checked
descriptor boundary recorded in `request_audit_write_layout.json`. Execution
requires no Rust, Python, dynamic loader or libc. The carrier opens one root
directory and retains it across framed operations; operation-owned files are
closed before a response. The caller must supply the authoritative directory
and serialize concurrent mutations as required by the original store lock.

## Request and response

All integers are little-endian. The transport frames each request with an
eight-byte byte count and each response with a four-byte return code. Requests
are bounded by one MiB. The internal function accepts ordinary UTF-8 strings;
it does not add the public admission API's identifier restrictions.

| Request offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 8 | `HRAWQ001` |
| 8 | 8 | Operation: `1` creates, `2` replaces |
| 16 | 8 | Directory synchronization flag, exactly `0` or `1` |
| 24 | 8 | Length of the following record projection |
| 32 | variable | Complete `HRAJJ001` audit record projection |

The projection follows `request_audit_json`'s record format. It has a 256-byte
header, kind `1`, the optional elapsed-time flag, two words containing the
full unsigned 128-bit acceptance time, a state code (`0` unknown, `1`
completed, `2` failed), and the unsigned 64-bit elapsed time. The request ID,
owner and tool are three contiguous offset/length pairs followed by UTF-8
bytes. Reserved bytes must be zero. An absent elapsed time has both flag and
value zero. Empty strings, Unicode, quotes, control characters and embedded
NUL are representable; the original operation's later serialization,
filename conversion and replacement validation determine their outcome.

Successful or classified operation results contain exactly 32 bytes:

| Response offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 8 | `HRAWR001` |
| 8 | 8 | Diagnostic, zero on success |
| 16 | 8 | Positive errno only for diagnostic `23` |
| 24 | 8 | Reserved zero |

Malformed request/projection or inconsistent suspended receipts return
`0xffffffff`. Insufficient borrowed workspace/output returns `0xfffffffe`.
These raw return codes do not write a response body. The borrowed owner
requires four MiB of workspace and at least 32 output bytes; the composed
executable gives its read child a separate four MiB workspace and its JSON
child a separate one MiB workspace. A final inaccessible guard page follows
the mapped workspaces.

| Diagnostic | Meaning |
| ---: | --- |
| 0 | Publication completed |
| 8 | Existing record exceeded the read limit |
| 16 | Directory failed the original private-directory check |
| 17 | Published or newly created file failed the private-file check |
| 18 | Staging inode refused during replacement recovery |
| 19 | Staging hard-link binding refused |
| 20 | Existing immutable owner/tool/acceptance binding differs |
| 22 | Serialized new record exceeds 2,048 bytes |
| 23 | Operating-system error; errno is retained |
| 24 | Existing record JSON rejected |
| 25 | Existing record identity rejected |
| 26 | Existing record filename rejected |
| 27 | Staging filename/identity rejected |
| 28 | Directory entry UTF-8 rejected during recovery |
| 29 | Filename contains an embedded NUL |
| 30 | A nonempty write returned zero bytes |

These diagnostics classify the original operation's errors for composition.
They are not the exact public error strings or a replacement for the full
public request dispatcher.

## Operation order and failure behavior

Both operations first validate the held directory as a directory owned by the
effective user with exactly mode `0700`, including rejection of extra mode
bits. Replacement then invokes the complete audit read graph on the derived
record filename. That graph performs deterministic and legacy random staging
recovery and validates the read record. Its initial deterministic probe stays
open until its cleanup branch finishes, preserving the original Rust match
scrutinee's lifetime.

Replacement compares the old owner's string, tool string and complete
128-bit acceptance time. State and elapsed time may change. A binding error
precedes serialization and size checking, as in the original function.

The new record is serialized in the original six-field order: request ID,
owner, tool, state, acceptance time, elapsed time. String escaping uses JSON
control escapes and raw valid UTF-8; integer formatting preserves all bits.
Serialization size is checked before filename conversion or temporary-file
creation. The deterministic temporary name is derived by repeating the
request ID: a leading dot, the ID, a hyphen, the ID, and `.tmp`.

Creation opens that name exclusively with mode `0600`. It does not remove an
existing staging file first. The new descriptor must refer to a regular file
owned by the effective user, exactly mode `0600`, exactly one link, and at
most 2,048 bytes. A failure at this validation step closes the descriptor and
leaves the temporary entry, matching the original pre-persistence failure.

Persistence writes all bytes, handles real short writes and interrupted
writes, synchronizes the file, and closes it **before** publication. Creation
links the temporary inode to the published filename, then unlinks the
temporary name. Replacement renames the temporary name to the published
filename. A requested directory barrier follows publication. File and
directory synchronization retry interruption; operations that the original
does not retry retain their original error behavior.

Once persistence begins, a failure closes any held temporary descriptor and
attempts best-effort temporary-name removal. Cleanup failure cannot replace
the first error. Publication may already have taken effect when a later
unlink or directory barrier fails, and the resulting namespace remains
observable. The original create and replacement operations determine
subsequent recovery; no implicit replay or rollback is introduced.

## Borrowed effects and graph ownership

An effect returns `0xfffffff0`. Its 96-byte descriptor starts at workspace
offset 256. It records action magic, a monotonically increasing sequence,
action kind, slot, span, length, argument, child capacity, acknowledgement,
result, errno and a reserved word. The owner retains an independent copy of
the six action words and the suspended request. Resume verifies the complete
request, buffer lengths, action binding, acknowledgement and bounded error
fields before advancing. A child call additionally verifies that its input
span was not modified.

| Action | Meaning |
| ---: | --- |
| 1 | Obtain actual directory/file metadata and effective user ID |
| 2 | Exclusive temporary-file creation |
| 4 | Write the remaining serialized byte span |
| 5 | File or directory synchronization |
| 6 | Link temporary name to published name |
| 7 | Rename temporary name over published name |
| 8 | Unlink temporary name |
| 9 | Close the owned temporary descriptor |
| 100 | Invoke the complete audit record read child |

The owner uses one temporary slot. The read child has its own six slots and
may use the same retained directory authority while the write slot is empty.
The boundary independently checks derived filename bytes, pointer spans,
descriptor ownership and close-before-response invariants. Zero-length
request IDs are accepted by the internal create operation and receive the
original later read refusal; an empty byte comparison must not depend on
stale processor flags.

## Qualification and limits

The actual ai395 Rust 1.95.0 comparison builds 21 unchanged original source
blocks, including the complete original diagnostic module, against 19 exact
registry packages pinned by the runtime's lock file. The diagnostic
environment is explicitly `HEPTA_REQUEST_AUDIT_TRACE=0`; enabled diagnostic
buffering and logging are outside this component's qualification.

The final fresh run passes 215 baseline cases / 709 requests per side,
61 kernel-fault and namespace-race cases / 179 requests per side, and 15
publication edge cases / 43 requests per side. The last group includes seven
actual owned-child deaths before selected kernel effects and eight actual
kernel short-write cases. Comparisons include complete response bytes,
contents, modes, ownership, hard-link relationships, inode changes, retained
initial inodes and selected live descriptors. The nonfatal request groups
also check descriptor release before each response. Source, dependency and
executable byte pins are rechecked after execution.

Separate borrowed-buffer controls exercise 24 rejections and one synthetic
completion. They do not execute Rust or filesystem effects and are not
counted as storage equivalence. Prior lock-file, zero-length boundary and
reference-framing failures remain in the qualification evidence.

This component does not establish the audit store lock, active-request and
read-pin registries, archive anchoring/indexing, hot-cache retention,
admission/cohort coordination, enabled tracing, public dispatch, async
cancellation, non-Linux platforms, or whole-runtime replacement. Production
activation and legacy-stack removal remain unqualified until the complete
composed runtime closes those dependencies.
