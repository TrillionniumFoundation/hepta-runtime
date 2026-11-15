# Blocking mkdir capability fixture

This is a private qualification executable for the HIA implementation of the
Linux Rust 1.95 `std::fs::create_dir_all` leaf. The HIA owner determines paths,
ancestor order, directory mode, metadata availability, error preservation and
the complete returned Result. The adapter performs fixed kernel operations and
records their actual results. It contains no directory-creation algorithm.

This fixture does not establish Tokio cancellation, global atomic metadata
cache behaviour, capture filename allocation, capture preparation, registry
publication, production activation or whole-runtime replacement.

## Build and ownership

The fixed compiler is Hepta commit
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. The packer input is
`HSCMPK01`, a little-endian u64 nonzero image length and that many unchanged
flat-owner bytes. The HIA packer emits a canonical ELF64 Linux x86-64 ET_EXEC:
176 bytes of ELF and two program headers, the source-owned adapter, then the
unchanged owner image. The entry is `0x4000b0`; the sole load segment is RX and
the GNU stack is RW. There is no interpreter, libc, external symbol or runtime
Python dependency. Writable buffers come from anonymous private `mmap`.

The assembler `.text` starts with the unique global function `_start` at offset
zero. All branches are resolved within that section. Its trailing local owner
label has a single zero-byte sentinel after alignment to 16 with zero padding.
The sentinel is excluded from the adapter image and replaced with the owner
image. The layout pins the complete adapter source and actual text bytes, entry
offset and empty relocation list. The qualification builder retains actual
assembler/objcopy input, output and process receipts, and full guarded packer
arrays. The packer changes neither input nor workspace; every refusal leaves
the output unchanged, and success leaves the output tail unchanged.

## Invocation and transport

```
shell-capture-mkdir.elf --mkdir-fixture TRACE_DIRECTORY
```

The controller starts in the caller's explicitly owned working directory and
inherits the caller-selected umask. The trace directory must already exist.
The fixture creates exactly `effects.bin` and `entries.bin` using exclusive,
no-follow, close-on-exec opens with mode 0600. Their descriptors are normalized
above 2. No request accepts a raw descriptor or process identifier. This is a
trusted qualification transport, not a filesystem sandbox.

Before reading the request, stdout receives a 64-byte ready record: eight
little-endian u64 fields, magic `HSHMKRD1`, actual PID, actual TID, effect-trace
descriptor, entry-trace descriptor, version 1, zero, zero. The qualification
driver binds the actual subprocess, executable, cwd and descriptor identities
before sending the request.

Stdin then contains one transport envelope: u64 wire length, u64 workspace
capacity, and the complete owner input. The adapter allocates precisely those
borrowed lengths plus guards, and a 64-byte output. A transport allocation
failure is an independent fixture failure, not an `io::Error` returned by the
owner. There is no maximum-path policy or truncation. All additions are checked.

The owner input and 32-byte tagged result follow `shell_capture_mkdir_abi.md`.
On pending return `0xfffffffd`, the fixture performs the one issued effect,
publishes its complete result, changes only input opcode at offset 8 to RESUME
(2) and cache seed at offset 16 to zero, and re-enters the same owner. It never
inspects a semantic result kind. A final return 32 sends u64 32, u64 32 and the
unchanged 32-byte result. INVALID/CAPACITY send their u64 return, u64 zero and
no body. The final 32 bytes of the 64-byte borrowed output remain a guardable
tail. There is one blocking owner and no background worker or cancellation API.

## Fixed effect operations

The 96-byte private effect slot is at workspace offset 96. It contains magic
`HSHMKFX1`, sequence, action, path offset, path length, third argument, ready,
raw signed syscall result, positive errno, original mode, zero and zero.
Sequence begins at 1 and advances exactly once per issued effect. On issue the
six completion/reserved fields are zero. The adapter checks all borrowed bounds
and the complete terminating C string before using the HIA-selected path.

| Action | Actual syscall and fixed arguments | Successful metadata |
| --- | --- | --- |
| 1 | `mkdir(path, 0777)`; x86-64 syscall 83 | none |
| 2 | `statx(AT_FDCWD, path, 0, 0xFFF, buffer)`; syscall 332 | original `stx_mode` at byte 28 |
| 3 | `statx(0, NULL, 0, 0xFFF, NULL)`; syscall 332 | none |
| 4 | `newfstatat(AT_FDCWD, path, buffer, 0)`; syscall 262 | original `st_mode` at byte 24 |

No leaf syscall is retried, including EINTR. The adapter does not implement
EEXIST, ENOENT, `is_dir`, path components or statx availability. It copies the
kernel result and mode to the slot. A negative result in `[-4095,-1]` gives
its positive errno; failed metadata gives mode zero. The whole 256-byte statx
or 144-byte stat buffer, zero-initialized before the actual syscall, is retained
even on failure. The HIA owner alone chooses whether a metadata operation is
needed and whether its error preserves the preceding mkdir error.

The action-4 syscall follows GNU glibc 2.43's Linux x86-64 implementation:
`stat64.c` delegates to `__fstatat64_time64` with `AT_FDCWD` and flags zero;
`fstatat64.c` selects `newfstatat` for this ABI. The same release's
`internal-stat.h`, `kernel_stat.h` and x86-64 `arch-syscall.h` establish the
64-bit branch and syscall number 262. The original sources were retrieved from
the Android GNU mirror at `refs/tags/upstream/glibc-2.43`:

- [stat64.c](https://android.googlesource.com/toolchain/glibc/+/refs/tags/upstream/glibc-2.43/sysdeps/unix/sysv/linux/stat64.c),
  SHA256 `5dd6837562836e6c633f2efc48956f10b66cbdcf3c9c91987dd7a411f72f9624`.
- [fstatat64.c](https://android.googlesource.com/toolchain/glibc/+/refs/tags/upstream/glibc-2.43/sysdeps/unix/sysv/linux/fstatat64.c),
  SHA256 `69fbd971e9d8bf29bf5282997169d86d87794115679d35cb184b2dee18b85e8f`.

The unavailable-cache case remains an explicitly supplied serial-cache state.
The source review does not claim that a fresh Rust process on a statx-capable
kernel naturally entered its global unavailable state.

## Complete syscall trace

Each issue and completion record in `effects.bin` has a 192-byte header followed
by the actual raw path bytes (excluding the terminating NUL), then the complete
metadata buffer when present. Its first 12 u64 fields are magic `HSHMKTR1`,
sequence, phase (0 issue / 1 completion), PID, TID, actual syscall number, raw
signed result bits, errno, mode, path-byte length, metadata-byte length, zero.
Bytes 96..191 are the complete actual private effect slot. The path and metadata
lengths determine the record boundary; trailing or incomplete data is invalid.
The issue slot and completion slot are compared byte for byte except for the
four admitted completion fields. Both records carry the same path.

## Complete native entry arrays

For every real owner call, `entries.bin` retains a before and after record. Each
has a 96-byte header of twelve u64 fields: magic `HSHMKEN1`, entry index, phase
(0 before / 1 after), actual PID, actual TID, input length, output capacity 64,
workspace capacity, raw entry return (zero before), actual monotonic time in
nanoseconds, zero, zero. It is followed by full input, output and workspace
allocations, each including its two 16-byte guards. Guard bytes are C1/C2 for
input, A5/A6 for output and 5A/5B for workspace. Output initially contains A7;
workspace initially contains 5C. Input initially equals the actual transport
payload. The reader checks every before/after array, every guard, successful
tail, refusal output and complete bridge transition between successive calls.

## Footer and failure domain

Both binary files end with the same 128-byte footer. Its sixteen u64 fields are
magic `HSHMKAU1`, PID, entry count, last effect sequence, issue count, completion
count, fixture I/O error, fixture contract flag, final return, final body extent,
input length, workspace capacity, output capacity 64, trace descriptor, entry
descriptor, zero. A qualified run requires zero I/O error and contract flag,
equal issue/completion/sequence counts, exact entry arrays and a matching final
stdout frame. For no-syscall inputs the effect count is zero, not fabricated.

Exit 0 means the fixture delivered a complete tagged owner Result, including a
semantic error. Exit 2 is input INVALID, 64 is invocation usage, 74 is fixture
transport/trace failure, 75 is memory/capacity refusal and 78 is private ABI
contract failure. No infrastructure error is relabelled as a mkdir errno.
Interrupted transport reads/writes may resume; this does not retry a leaf
filesystem syscall. The driver preserves every failed run and deadline receipt.

## Filesystem evidence and retirement

The OS suite uses explicitly owned case working directories. It retains initial
and final lstat trees with raw relative path bytes, modes, device/inode identities,
regular-file payloads and symbolic-link targets, together with actual subprocess
stdin/stdout/stderr, command/cwd/environment/umask, executable identity and both
binary traces. Symlinks are never followed during inventory or retirement.
Every deletion is preceded by an exact identity/type comparison against the
sealed tree. No recursive deletion of an unverified root is permitted. The
case's transient working directory is removed only after the complete result is
read back and the exact registered tree is sealed; ordinary evidence remains.

Read-only verification reconstructs the registered cases and complete binary
streams. It does not execute the native image, run a compiler, read live procfs
as historical proof, write files or execute evidence-bundle code. Recorded-path
and current-source binding is explicit; artifact relocation is not silently
called a strong-path verification. No inferred or synthetic errno is labelled a
real kernel observation. EINTR and unavailable-statx-probe branches that cannot
be triggered naturally remain separate typed state tests.
