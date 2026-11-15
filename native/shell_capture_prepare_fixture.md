# Capture preparation native fixture

This is the Linux x86-64 fixture for `shell_capture_prepare`, after duplicate
admission and before construction of a production `Job`. HIA selects directory
creation, sequence observation, path construction, file creation, ownership
transfer and cleanup. The adapter forwards fixed capabilities. It never chooses
a path, retry, cleanup branch, subsequent owner phase or public error.

The executable contains four independent flat HIA images, in the order
prepare, path, mkdir, file. The latter three images are unchanged. Five child
contexts use these entries: path role 1, mkdir role 2, and independent file
roles 3, 4 and 5. File roles 3 and 4 create stdout and stderr; role 5 is the
fresh unlink arena selected by HIA. No Rust, Python, libc, interpreter or dynamic
loader executes a semantic operation in the executable.

## Scope

The public private-owner contract is `native/shell_capture_prepare_abi.md`.
This fixture supplies real mkdir/statx/newfstatat/openat/unlink/close operations
and a private serial `AtomicU64`-equivalent fetch-add. It records the actual
owned descriptor ledger and complete native calls. TMPDIR presence/bytes, PID
and initial statx cache remain typed input observations. The sequence service
belongs to this single fixture process; it is not production `JOB_SEQ`.

Registry locking and duplicate admission, ambient environment/PID/time lookup,
global concurrent sequence identity, Tokio await cancellation/into_std
scheduling, Job/Arc/Mutex construction, error Display and any public handler
remain separate. There is no asynchronous-abandonment claim. EOF is a fixture
receiver lifetime boundary: Linux releases any still-owned descriptors on
process exit. That is recorded separately from a HIA-requested close.

## Invocation and admission

Invoke the static executable as:

```
shell-capture-prepare.elf --capture-prepare-fixture CASE_DIRECTORY
```

The caller supplies an explicitly owned current directory, umask and environment.
The fixture creates exclusive, no-follow, close-on-exec ordinary files
`effects.bin` and `entries.bin` inside `CASE_DIRECTORY`. Only these audit
descriptors are normalized above 2. A descriptor returned by capture openat is
retained unchanged. The directory descriptor is closed before the ready record.

Standard output first contains 64 bytes, eight little-endian Q words:

```
HSPRRDY1, pid, tid, effects_fd, entries_fd, 1, 0, 0
```

Each external request on standard input has a 32-byte transport header:

```
u64 request_bytes, u64 output_capacity, u64 workspace_capacity,
u64 private_sequence_seed, followed by the exact HSHPPQ01 request
```

The first transport header initializes the private sequence storage. It is not
a HIA request field or an externally supplied effect completion. Later transport
headers must repeat the same capacities and seed; the sequence is never reset.
The main workspace persists across requests and initially contains zero bytes.
The main output starts at A7 for each external request. Input is remapped to its
exact current extent. The fixture mechanically changes only outer request
operation offset 8 to RESUME after a completed effect. All other original
request fields and bytes remain unchanged.

The output for an external request is `u64 return_value`, `u64 extent`, followed
by exactly `extent` bytes. A return of 128 obtains its complete extent from the
HIA response word at offset 8, checked against the owned output allocation.
INVALID and CAPACITY have extent zero. PENDING is handled through the fixed
private capability slot and is never published as an external result.

## Observation gates

After each private effect completes, and before HIA consumes its ready-one
completion, the fixture emits a 96-byte record. This permits the controller to
retain the actual descriptor/inode/tree observation while the native process
still owns the files, including immediately before stderr-error cleanup.

The twelve Q words are:

```
HSPRGT01, effect_sequence, action, external_request, native_entries,
kernel_completed, minted, closed, adopted, physically_live,
receiver_owned, current_private_sequence
```

The only accepted gate input is the 16-byte acknowledgement `HSPRACK1` followed
by the matching effect sequence. It cannot contain an errno, FD, path, phase or
completion result, and it cannot alter any HIA workspace. A gate merely pauses
and resumes execution. Full actual stdin, including every acknowledgement,
and full stdout, including every gate, are retained. Gates and audit writes are
fixture instrumentation, not original filesystem effects.

At an external-frame boundary, EOF writes the same 256-byte footer to stdout
and both audit files, then exits zero. Partial frames, failed audit transport or
mapping failures outside INIT are infrastructure failures. Exit codes are 64
for invocation, 74 for infrastructure and 78 for a capability contract failure.
Semantic filesystem errors still produce a complete HIA result and exit zero.

## Fixed capabilities and custody

The only parent dispatch input is the current HIA `HSHPPFX1` slot at workspace
offset 128. The adapter writes only its four completion words at +56..87,
publishing ready last. It dispatches no next owner action by itself. Parent
sequence zero after u64 wrap is valid. A leaf mailbox must be issued and not yet
completed before a kernel operation is admitted.

INIT uses one checked anonymous RW mmap for all five child contexts and their
guards, plus three fixed file-arena descriptor nodes. Thus mmap failure has no
partial allocation to roll back. The aggregate size is:

```
5 * input_capacity + path_output_capacity + mkdir_workspace_capacity
    + 3 * file_workspace_capacity + 976
```

Each file arena can create at most one file under its unchanged lifetime ABI;
the node is reused across interrupted failed open attempts and is minted only
after actual successful openat. This is a fixed ownership representation for
the three arenas, not a public path, retry or file-count quota. Tokens are
nonzero sequential private identities, never incoming raw descriptors.

CALLs copy exactly the parent-selected input span to the child input allocation,
initialize child output from the complete destination span, invoke the actual
unchanged native entry, and copy the whole output allocation back regardless of
the scalar result. MKDIR copies 32 bytes and clears the following 16 bytes;
FILE copies 48 bytes; PATH copies its entire admitted output capacity. The
adapter does not parse a child result to choose an owner phase. Child workspaces
persist independently. All native entries use the six-pointer/length System V
calling convention and proper stack alignment.

The leaf syscall capabilities are exactly mkdir 83, statx 332, newfstatat 262,
openat 257, unlink 87 and close 3. Kernel calls each occur once. Only the HIA file
leaf retries an interrupted open. Transport reads/writes independently retry
EINTR. The adapter validates owned C-string bounds and their exact NUL endpoint;
it does not synthesize, normalize, decode or concatenate path bytes.

ADOPT validates a completed successful TAKE, empty leaf held custody, matching
actual output token, and a live ledger node owned by the specified file arena.
It then transfers that node to the receiver. CLOSE_OWNED accepts only a live
receiver token and issues one actual close. Every close return retires the
ledger node, including errno; it cannot restore a possibly reused descriptor.
The HIA owner alone chooses whether to ignore that errno and then invoke unlink.

OBSERVE_SEQUENCE executes one aligned `lock xadd` on the private u64 storage.
The effect records retain its actual before/after values and returned old value,
including wrapping from u64 maximum. The bridge never looks at a mkdir or file
outcome to decide whether to increment it.

## Complete entry records

`entries.bin` consists of paired before/after records, followed by the footer.
Every record has a 192-byte, 24-Q header:

| Q index | Meaning |
| --- | --- |
| 0 | HSPREN01 |
| 1..6 | External request, global entry number, role, phase 0/1, PID, TID |
| 7..9 | Borrowed input length, output capacity, workspace capacity |
| 10 | Actual scalar return; zero in a before record |
| 11 | Actual CLOCK_MONOTONIC nanoseconds |
| 12 | Parent effect sequence for a child call; zero for the main owner |
| 13..16 | Parent issued/completed, kernel issued/completed counters |
| 17..21 | Minted, closed, adopted, physically live, receiver-owned counters |
| 22 | Complete input allocation capacity |
| 23 | Per-role entry counter |

Three complete allocations follow, in input/output/workspace order, each with
16-byte left and right guards. Guard pairs are C1/C2, A5/A6 and 5A/5B.
The main input allocation equals the borrowed input length. Child input staging
has fixed admitted capacity; bytes beyond the borrowed length are initialized
to D1 and retained completely. The child call receives only the exact borrowed
length. This allows the reader to verify both immutable input and unused input
capacity, not only a hash or a truncated prefix. All work and output tails are
retained, including pending/refusal calls and completed-result replays.

## Parent and kernel effect records

`effects.bin` interleaves paired parent effects and any actual leaf/direct-close
kernel effects nested inside them. Every header is 192 bytes.

A parent header contains Q words:

```
HSPREF01, external_request, effect_sequence, pid, tid, phase,
parent_issued, parent_completed, kernel_issued, kernel_completed,
minted, closed, adopted, physically_live, receiver_owned,
private_sequence_seed, current_private_sequence, last_main_return,
arenas_initialized, child_mapping_bytes, 0, 0, 0, 0
```

The complete actual 96-byte parent slot follows. The issued slot is taken from
the owner workspace; the completed slot is taken after the admitted completion
and any precisely specified child-result copies.

A kernel header contains:

```
HSPRSC01, external_request, parent_sequence, role, leaf_sequence,
pid, tid, phase, syscall_number, fd_argument, flags, mode_or_mask,
raw_result_bits, errno, minted_result_token, returned_mode,
path_bytes, slot_bytes, stat_buffer_bytes, close_target_token,
minted_count, closed_count, physically_live, receiver_owned
```

The header is followed by the complete leaf slot if slot_bytes=96, then exact
raw borrowed path bytes, then the actual stat buffer if present. Direct receiver
close uses role/leaf-sequence/slot-bytes zero and binds its token to the parent
slot. A statx path call retains 256 bytes; newfstatat retains 144. Buffers start
at zero, and both before and after bytes are retained. Returned mode is copied
from stx_mode at offset 28 or st_mode at offset 24 only on actual success.
The NULL availability probe has no path or stat buffer. Raw negative syscall
results and positive errno are both retained; raw success is never inferred
from a final message. Non-open result tokens are zero.

## Footer

The identical 32-Q footer in all three streams contains:

```
HSPRAUD1, pid, external_requests, all_native_entries,
parent_issued, parent_completed, kernel_issued, kernel_completed,
minted, closed, adopted, physically_live, receiver_owned,
private_sequence_seed, current_private_sequence,
infrastructure_error, contract_error, last_main_return,
main_output_capacity, main_workspace_capacity, child_mapping_bytes,
arenas_initialized, effects_fd, entries_fd,
role0_entries, role1_entries, role2_entries, role3_entries,
role4_entries, role5_entries, first_transport_initialized, 0
```

Successful process evidence requires zero infrastructure/contract errors, exact
paired counts, complete stream consumption and equal footer bytes. A successful
capture tuple retains two live adopted descriptors until receiver process exit;
a completed stderr-error cleanup retains none. No footer itself proves semantic
ordering: the reader must replay the full parent/child/effect chain and the
actual gate observations.

## HIA executable packing

The packer accepts `HSCPPK01`, four u64 nonzero image lengths, then exact prepare,
path, mkdir and file bytes. It constructs the ELF entirely in HIA. There is a
176-byte fixed ELF64 header with one RX LOAD and one RW GNU_STACK, base address
0x400000 and entry 0x4000b0. The fixed adapter `.text` follows.

The adapter has a four-Q zero `module_offset_table`. The HIA packer replaces
only these 32 bytes with offsets relative to the first image. Each subsequent
image starts at a 16-byte boundary; intervening padding is explicitly zero.
The first offset is zero. The final file image has no trailing padding. The
adapter's terminal int3 sentinel labels the first image location and is removed
before packing. The source-owned layout pins the actual adapter bytes, zero
relocations, unique _start offset zero, table offset and first image offset.

The pure build reader must reconstruct the whole ELF, including the table,
all padding and all four original images. Tool receipts and packer before/after
guarded arrays supplement that byte reconstruction. No host packer is used to
create the executable and no reader loads an image or executes a subprocess.
