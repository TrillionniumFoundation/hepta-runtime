# Native shell foreground and promotion outcomes

## Scope and source boundary

This HIA owner projects the original foreground result tail and promotion
result in `src/mcp/fs/shell.rs`. It accepts already observed, typed wait and
log-read results. It does not perform either log read or either discard,
prove that they occurred, register a job, perform promotion, send a
notification, or replace a production Shell handler.

The original complete source SHA-256 is
`9a8a1d3a5f93807fadbf16fe67126bd531ec4e03acef381ceed3e31d88673d2d`.
The exact original spans are:

| Span | Byte start | Byte end, exclusive | SHA-256 |
| --- | --- | --- | --- |
| Foreground result tail | 28553 | 30328 | `f5608eec1f952590d672044a69f0fa1b68d61952f8b64688091bb4f3e6902b19` |
| Promotion result | 27497 | 28278 | `e0bfe3b8092296fa141fd7fa17137f142d9e75d0d8a8d31c7aa55633c82710ba` |

Compilation uses pinned Hepta
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, HIA v8 and its explicit
`selfhost_elf` owned-buffer object profile. The callable entry retains the
three disjoint borrowed buffers:
`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.

## Input frame

All integers are little-endian u64 words. A signed i32 value is represented by
its exact sign extension to a two's-complement u64. Values in the gap between
`0x7fffffff` and `0xffffffff80000000` are invalid, never truncated.

The header contains exactly 112 bytes, followed by five contiguous payloads.

| Offset | Field |
| --- | --- |
| 0 | Eight literal bytes `HSHOUT01` |
| 8 | Operation: 1 foreground projection, 2 promotion projection, 3 OS-error display |
| 16 | Wait result kind |
| 24 | Wait raw status or OS errno |
| 32 | Stdout read result kind |
| 40 | Stdout OS errno |
| 48 | Stderr read result kind |
| 56 | Stderr OS errno |
| 64 | Job PID |
| 72 | Wait-error text byte length |
| 80 | Stdout result payload byte length |
| 88 | Stderr result payload byte length |
| 96 | Original command byte length |
| 104 | Job ID byte length |
| 112 | Wait text, stdout payload, stderr payload, command, ID, in that order |

Every length is admitted by subtraction from the actual remaining input
extent. Missing or trailing bytes and arithmetic wraparound are invalid.
Text fields allow empty strings, embedded NUL and newlines. No input text is
implicitly trimmed or normalized.

### Result kinds

| Kind | Value word | Payload |
| --- | --- | --- |
| 0 | Wait: raw signed-i32 Unix `ExitStatusExt::from_raw` status; stream: exactly zero | Wait: empty; stream: complete arbitrary bytes from a successful read |
| 1 | Exactly zero | Complete valid UTF-8 `io::Error` Display text, supplied as a pure result projection |
| 2 | Signed-i32 raw OS errno, including zero and negative values | Empty |
| 3 | Exactly zero | Empty; original `ErrorKind::OutOfMemory` display |
| 4 | Exactly zero | Empty; `Error::other("background task failed")` display |

All result kinds are validated, including results which lose to an earlier
error. Kind 1 describes the supplied Display string directly; no extra OS
suffix is added. Kind 2 is formatted by this HIA owner in the fixed Linux GNU
C-locale domain described below. Kind 3 is the original non-OS allocation
error projection, distinct from this component refusing its private storage.
Kind 4 projects the Tokio asyncify join-error string; accepting that value
does not claim that an actual worker failed.

### Operation 1: foreground

The three typed Results are supplied. PID, command length and ID length must
be zero. All three kinds are in 0 through 4 and obey the preceding table.

The completed IO controller must reach this boundary only after original
child-drop/unregister, stdout read, stderr read, stdout discard and stderr
discard, in that order. Both reads and both discard attempts happen even
when wait or stdout already contains an error. This pure owner cannot attest
to those effects and must not short-circuit them in its caller.

The exact choice is:

1. Wait error: `Error: Command execution failed: {display}`.
2. Stdout read error: `Failed to read command stdout: {display}`.
3. Stderr read error: `Failed to read command stderr: {display}`.
4. Independently convert each successful stream with Rust-compatible UTF-8
   lossy replacement, then call the original HIA terminal cleaner separately.
5. If cleaned stderr is empty, select stdout. If cleaned stdout is empty,
   select stderr without a label. Otherwise combine stdout,
   `\n\nstderr:\n` (ten bytes), then stderr.
6. Read the original maximum from `text_budget` operation 5. Only a combined
   UTF-8 byte count strictly greater than that maximum produces the original
   oversized-output error, including status code and two exact operation-2
   MiB formats.
7. Successful status returns the cleaned combination. Otherwise return
   `Command failed with exit code {code}\n\n{combination}`.

A non-exited status has code -1. The raw status domain is not narrowed to
naturally occurring exited or signaled values. The original success and code
predicates apply separately. Exactly 8 MiB is admitted; the unsuccessful-exit
prefix is added afterwards and is not subjected to a second limit check.
Raw logs are never truncated to the foreground limit before lossy conversion
or cleaning.

### Operation 2: promotion

Only PID, command and ID may be nonzero/nonempty. All wait/read kinds, value
words and their three payload lengths are zero. PID accepts the full u32
domain, including zero in this typed projection; higher values are invalid.
Command and ID must be valid UTF-8.

The owner applies the original syntactic `stashes_changes` helper to the
complete untrimmed command. Its full original stash note appears only when
that helper returns true, including when the stash is behind a shell branch
that did not execute. Actual execution of a stash is not inferred.

It returns the complete original promotion message with ID once, PID twice,
and `Some("octofs://jobs/" + id)`. No URI escaping, ID validation, terminal
cleaning or foreground result limit is added. Request-context hints are a
separate channel and are not appended to this outcome.

### Operation 3: raw OS-error display

Wait kind must be 2 and wait value is the signed-i32 errno. Every other
numeric field and every payload length must be zero.

This formats the complete original OS-error Display string:
`{GNU description} (os error {signed decimal errno})`.
The description table comes from GNU glibc 2.43
`sysdeps/gnu/errlist.h`, combined with the Linux asm-generic errno numbers
used by x86-64. Unknown numbers use `Unknown error {signed decimal errno}`.
The decimal algorithm covers the full i32 domain, including -2147483648.
Zero is `Success (os error 0)`.

This is explicitly Linux GNU C-locale behavior. It does not claim equivalent
messages for another libc, architecture errno map, translated locale, or
allocator failure inside libc's own display machinery.

## Complete output and native return

The wire result has a 40-byte header and contiguous complete text and URI.

| Offset | Field |
| --- | --- |
| 0 | Eight literal bytes `HSHOUR01` |
| 8 | Result kind: 0 successful ShellOutcome, 1 complete error, 2 operation-3 display |
| 16 | Text byte length, u64 |
| 24 | URI present: 0 or 1 |
| 32 | URI byte length, u64 |
| 40 | Text bytes followed immediately by URI bytes |

Operation 1 always has URI present zero and URI length zero. Operation 2 has
URI present one. Operation 3 has result kind two and no URI. There is no
implicit terminator or trailing newline.

**A successful native call returns the fixed value 40**, not the response
extent. The complete published extent is `40 + text_length + uri_length`,
computed and checked in the u64/usize buffer domain. The caller retains the
output borrow and reads that entire extent. The wire lengths, not a u32
return cast, carry large error and promotion strings.

| Native return | Meaning |
| --- | --- |
| 40 | Complete header and body published |
| `0xffffffff` | Invalid typed frame |
| `0xfffffffe` | Private output/workspace/allocation or imported-leaf capacity refusal |
| `0xfffffff9` | An imported qualified helper violated the expected internal contract |

Every refusal leaves the entire output buffer unchanged. Success changes
only its complete published extent; the tail is unchanged. Input is immutable.
Workspace is private scratch and need not be initialized; at least 128 bytes
are required after full frame validation. It may change on a later refusal.

## Native memory and retained limits

The HIA control graph decides every allocation, conversion, helper call,
error priority, size check and publication. The formal compiler object
profile imports only `calloc` and `free` for owned buffers. Allocation sizes,
zero-initialized storage, failed allocation and matching releases follow the
compiler's checked owned-buffer contract. A failed private allocation returns
capacity refusal; it never manufactures an original log-read error.

The pinned compiler implements an empty allocation as a null pointer with
length zero and success, without calling libc. For nonempty storage it rejects
sizes with the signed usize bit set, then calls `calloc(1, size)`. A nonnull
result carries the requested length and fully zero-initialized bytes. NULL
returns an empty owner with failure; this owner uses `buffer.try_new`, so that
condition does not enter a trap or Rust error path. `owner.drop` calls `free`
once only for a nonnull owned pointer after all loans end. Every success and
refusal path releases its temporary owners. The build records and retains the
actual linker and loaded libc ELF bytes before and after linking; its pure
reader permits only the two allocator imports, not a host outcome formatter.

The ordinary flat profile rejects these owned operations. Its observed E64
probe remains development evidence, followed by the explicit ELF profile;
neither the compiler nor the existing flat builder is patched to bypass that
boundary.

No new fixed total input, error-text, command, ID or promotion-result quota is
a Shell decision. Actual buffers, allocation success and representable usize
arithmetic bound this private invocation. The outcome calls a HIA u64 wrapper
over the original terminal-clean
helpers. It preserves the original entry's validation, scratch-capacity
check, ANSI removal, line cleanup, repeated-line join, leading-LF removal,
Unicode trim, output-capacity check and complete copy, in that order. Only
the final u32 extent restriction and return cast are removed. Invalid and
capacity conditions use distinct private u64 sentinels before the outcome
maps them to its refusal codes. The original terminal-clean f0 and every
imported function remain present with their bodies unchanged except for
function and call-target IDs.

The retained step map in `shell_outcome_reuse.json` binds the original f0
body and the new wrapper body. Offsets, lengths and helper returns remain
u64 through that path. The lossy decoder's packed low-32-bit next cursor is
used only to derive its one-to-four-byte consumed width by modular
subtraction; the owning cursor stays u64. Full responses likewise use the
40-byte descriptor's u64 lengths. These changes remove a fixed 4 GiB public
quota. The ordinary corpus does not by itself qualify a physical allocation
above 4 GiB; any such pressure evidence is reported separately.

The existing terminal-clean and text-budget function bodies remain unchanged.
Static composition may rename function IDs and their call targets only;
per-function provenance and reconstruction are retained separately. No
Python/ASM path implements a cleaner, rounding, stash decision or outcome
choice. Production invocation order, actual filesystem IO, registry
membership, MCP envelopes and old-stack removal remain separate work.
