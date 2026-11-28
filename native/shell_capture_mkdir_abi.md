# Shell capture mkdir: blocking Linux leaf ABI

This module owns the blocking algorithm of Rust 1.95.0
`std::fs::DirBuilder::create_dir_all` for raw Unix paths. It does not implement
Tokio scheduling or cancellation, capture-file preparation, a registry, or a
global atomic statx cache. The private bridge executes fixed syscalls; HIA
chooses every ancestor, order, metadata check, fallback, and semantic result.

The target is the pinned d3 HIA compiler, version 8, Linux x86_64. All lengths,
indices, private capacities, and effect sequence values are u64. There is no
public path-size quota. Native address-space and caller workspace limits remain
explicit transport/capacity limitations.

## Three-buffer entry

f0(readbuf request, mutbuf output, mutbuf workspace) -> u32

The three complete buffers are disjoint, initialized, and owned by the caller
for the duration of the entry. A live workspace is private to one invocation.
The caller may publish only the documented completion fields between entries.
The input and the unused output/workspace tails are retained byte for byte.

Return values:

| Scalar | Meaning |
|---|---|
| 32 | A complete fixed-size semantic result is published, including errors |
| 0xfffffffd | An effect is pending; no output bytes are published |
| 0xfffffffe | Private workspace/output capacity is insufficient |
| 0xffffffff | Invalid request, state, or effect completion |

Every non-32 return preserves the complete output buffer, including its first
byte. A successful return modifies exactly its first 32 bytes. Request bytes
are always unchanged. A capacity/invalid refusal does not advance the workspace.
A valid ready-zero poll is likewise unchanged. Issuing or consuming an effect
changes the private workspace even when the return is PENDING.

## Request

The request consists of a 64-byte header followed by the complete raw path.
All integer fields are little-endian.

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII HSHMKQ01 |
| 8 | 8 | Operation: 1 START, 2 RESUME |
| 16 | 8 | START: observed statx cache 0, 1, or 2; RESUME: zero |
| 24 | 8 | Raw path length N |
| 32 | 32 | Four zero reserved words |
| 64 | N | Complete raw path bytes |

The frame must have exactly 64 + N bytes. Paths are not decoded as UTF-8,
normalized, or converted lossily. A START can use a fresh dirty workspace whose
word at offset 64 is not HSHMKW01. A workspace already carrying that magic
cannot be restarted; use another fresh workspace for a new operation.

Every RESUME carries the same complete path bytes as its START. HIA compares
them with the retained original. The fixture's mechanical continuation changes
operation to 2 and resets header offset 16 to zero. A completed invocation
accepts the same RESUME and republishes the same result without another effect.

The statx cache input is a typed observation of a serial cache: 0 Unknown,
1 Present, 2 Unavailable. It is neither a syscall result nor proof of a
global atomic load. HIA returns the final value. Integrating shared atomic
state and concurrent updates is a separate owner/composition task.

## Result

The result is always exactly 32 bytes. Transport may frame it as
u64(return=32), u64(extent=32), body.

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII HSHMKR01 |
| 8 | 8 | Kind: 0 Ok, 1 raw OS error, 2 local NUL InvalidInput |
| 16 | 8 | Kind 1: original positive Linux errno; otherwise zero |
| 24 | 8 | Final serial statx cache, 0..2 |

Kind 2 represents Rust's non-OS error
InvalidInput("file name contained an unexpected NUL byte").
It has no raw errno. It must not be rendered as EINVAL or another fabricated
OS error. Error-message formatting is not performed in the syscall bridge.

A raw syscall error has errno 1..4095; successful syscalls have errno zero.
Synthetic state tests can supply this typed completion domain. Such tests are
not claims that a particular kernel, permission setup, or race produced it.

## Workspace and ownership

Required capacity is 512 + 10 * (N + 1) bytes.

The owner checks the u64 multiplication/addition before using the formula.
This reserves two raw-path regions and an upper bound on the missing-ancestor
length stack. It is private capacity, not a semantic limit. The bridge can
allocate the requested capacity or report infrastructure failure. It must not
turn an mmap/allocation failure into a successful mkdir result or a fabricated
OS error.

| Offset | Meaning |
|---:|---|
| 0..63 | Scratch used by the retained path helpers |
| 64 | State magic HSHMKW01 |
| 72 | Pending flag, zero or one |
| 80 | Current effect sequence |
| 88 | Expected action |
| 96..191 | 96-byte effect slot |
| 192 | Algorithm stage: 1 ancestor ascent, 2 reverse rebuild, 3 completed |
| 200 | Current ancestor's raw prefix length |
| 208 | Its parent length during ascent; zero during rebuild |
| 216 | Count of collected missing ancestor lengths |
| 224 | Remaining reverse-rebuild entries |
| 232 | Serial statx cache |
| 240 | Saved mkdir errno for a metadata check |
| 248 | Saved first statx errno while probing/falling back |
| 256 | Completed result kind |
| 264 | Completed result value |
| 272 | Original raw path length |
| 280 | Initial typed cache value |
| 288 | Required workspace capacity |
| 296..511 | Reserved zero bytes |
| 512 | Original path N bytes, followed by one NUL |
| 513 + N | Effect C string region, up to N bytes plus one NUL |
| 514 + 2*N | Missing-ancestor stack, little-endian u64 prefix lengths |

Stack storage reserves N + 1 words. Entries are appended only after an actual
typed mkdir completion with ENOENT in the ascent stage. No top-down syscall
plan is precomputed. The original bytes and current effect C string are
separate, so terminating an ancestor prefix cannot corrupt later paths.

Only bytes before the required capacity may change. Extra workspace capacity
is retained byte for byte. The bridge reads the path span and its owner-written
NUL from the owned workspace; it does not create a different path.

## Fixed private effect slot

The 96-byte slot starts at workspace offset 96.

| Relative offset | Width | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII HSHMKFX1 |
| 8 | 8 | Current nonzero sequence |
| 16 | 8 | Action 1..4 |
| 24 | 8 | Owned workspace path offset, or zero for action 3 |
| 32 | 8 | Raw path length, or zero for action 3 |
| 40 | 8 | Action argument: mode/mask/zero as below |
| 48 | 8 | Ready flag: 0 issued, 1 complete |
| 56 | 8 | Exact signed 64-bit raw syscall result bits |
| 64 | 8 | Zero or positive Linux errno 1..4095 |
| 72 | 8 | Original file mode on successful action 2 or 4; otherwise zero |
| 80 | 16 | Two reserved zero words |

On issue, the four completion words at offsets 48..72 are all zero. Only those
four words may be published by the bridge, as one complete observation.
A success has raw result zero and errno zero. A failure has raw result -errno
and mode zero. The bridge does not manufacture an io::Error or directory bool.

| Action | Fixed syscall operation | Argument at +40 |
|---:|---|---:|
| 1 | mkdir(owner C string, mode), no EINTR retry | 511 (0777) |
| 2 | statx(AT_FDCWD, owner C string, flags 0, mask, owned stat buffer) | 4095 (BASIC_STATS \| BTIME) |
| 3 | statx(fd 0, NULL path, flags 0, mask, NULL result buffer) | 4095 |
| 4 | newfstatat(AT_FDCWD = -100, owner C string, owned stat buffer, flags 0), no EINTR retry | 0 |

For action 2 the copied mode is the unsigned 16-bit stx_mode; for action 4
it is unsigned 32-bit st_mode. Action 4 uses Linux x86_64 syscall 262
(newfstatat), with AT_FDCWD and flags zero, matching the GNU libc stat64 path.
It does not substitute legacy syscall 4 (stat). The owned metadata buffer has
144 bytes and is cleared before the syscall, as in the original Rust stat64
fallback. The complete buffer is retained by the adapter/OS evidence; HIA
consumes its mode through the typed completion.

The owner checks magic, sequence, action, every issued argument, reserved
words, C-string prefix/terminator, readiness, result/errno consistency, and
mode domain before consuming completion. A ready-zero poll returns PENDING
without issuing a second job. A duplicated/stale/altered completion must not
be treated as a new syscall. The surrounding controller owns exactly-once
dispatch and may not publish arbitrary caller completions.

## Algorithm and error precedence

1. HIA tests the empty path and parent=None before issuing any effect.
   Such paths return Ok with the incoming cache unchanged.
2. The complete original path is attempted first. NUL validation is local
   and yields kind 2 before any mkdir/syscall. Raw non-UTF-8 remains intact.
3. A successful mkdir ends the ancestor search. ENOENT alone records that
   exact raw prefix and moves to its parent. Every other non-EEXIST error,
   including EINTR, terminates immediately without metadata.
4. EEXIST alone performs is_dir. A directory ends the ancestor search.
   A non-directory or any metadata error returns the saved **mkdir EEXIST**,
   never the metadata errno.
5. After the search stops, HIA attempts only the recorded missing ancestors
   in reverse order. During this rebuild, ENOENT is an immediate error; it
   does not restart ancestor search. EEXIST is accepted only by the same
   successful directory check. There is no rollback.
6. Successful completion is emitted only after every required rebuild has
   completed. No host code decides success, errors, ancestors, or reversal.

Statx policy is serial and stays in HIA:

- Unavailable skips statx and uses stat64.
- Present uses statx, retaining the mkdir error if it fails.
- Unknown uses statx. Success changes the cache to Present.
- On an Unknown failure, HIA records the statx errno and issues the null probe.
  EFAULT establishes Present and retains the original mkdir EEXIST. Any other
  probe result establishes Unavailable and invokes stat64.
- A successful metadata result is a directory precisely when
  mode & 0170000 equals 0040000. The syscall bridge does not perform this test.

This preserves the pinned algorithm's observable syscall order. It does not
claim equivalence for the global atomic race in which another thread updates
statx availability between the original Rust loads. It also does not reproduce
Rust allocator-abort boundaries for temporary CString/Vec allocations. Private
native capacity refusal is explicitly separate from semantic io::Result.

## Path reuse and derivation

Six complete helper bodies are copied from frozen shell_capture_path.hepta,
changing only function declaration IDs and call target IDs:

- f2: root/current-directory prefix classification.
- f4: one backward component cut.
- f5: trailing ignored-component trimming.
- f16: little-endian request u64 read.
- f17: little-endian workspace u64 read.
- f18: little-endian mutable-buffer u64 write.

The original capture-path parent function f6 takes a whole read buffer. Pinned
d3 HIA has no slice capability, so this module adds a separate parent_prefix
HIA function taking an explicit prefix length. Its two whole-buffer length
expressions become 64 + size; the path algorithm and complete copied helper
bodies remain the same. This wrapper is **not** described as an unchanged
original body. The reuse JSON retains the original and new bodies, precise
function maps, hashes, and the wrapper's explicit authoring definition.

The private authoring generator is not required to build or execute this
module. Production semantics are in the checked HIA source. The builder
checks the complete retained-helper relocation closure and source identities.

## Pinned original sources

- Rust 1.95.0 library/std/src/fs.rs,
  Git blob cf6f9594c0027af9755a4518b1460a7db92a36ff,
  SHA256 bac06d50380e9bc8e7a95a89d209cd9aabe0970e4ec589e5d265ccc44a70f9c4:
  DirBuilder::create_dir_all and its two iteration phases.
- Rust 1.95.0 library/std/src/sys/fs/unix.rs,
  Git blob 7db474544f04abc75e2d66ec007ebe4799a491d3,
  SHA256 77c6419ee048c348d9ed4bef226ce6ceb735d6077d0eb9f6bcac0ef46fa7b86d:
  mkdir mode/cvt, stat, try_statx, and file-mode tests.
- Rust 1.95.0 library/std/src/path.rs,
  Git blob bf27df7b0428169a4308ebf413e732f3479754fe,
  SHA256 2c41294523392663a73fa3da08864427a05bdd8ff0fff0bd157c0236680593bf:
  parent, backward Components traversal, as_path, and is_dir.
- Rust 1.95.0 library/std/src/sys/helpers/small_c_string.rs,
  Git blob f54505a856e05cca952669988b47a88663607507:
  local NUL_ERR and run_path_with_cstr.
- Rust 1.95.0 library/std/src/sys/io/error/unix.rs,
  Git blob b10343b2752c2a1fe32db232002a6393b8f1caf9:
  ENOENT -> NotFound and EEXIST -> AlreadyExists.

Sources are available under
https://github.com/rust-lang/rust/blob/1.95.0/ with the paths above.
Tests distinguish typed state completions, real kernel effects, and original
Rust comparison. None of these alone activates production, replaces Shell,
or qualifies removal of the old runtime.

GNU libc source for the fixed x86_64 stat64 primitive was separately read:
- glibc 2.39 sysdeps/unix/sysv/linux/stat64.c, Git blob
  4c8e175b7a6d262dff765f9eac312928604a9b36, and fstatat64.c, Git blob
  da496177c9a2ad1e149b01f54ebf1340440b101d, at
  https://github.com/bminor/glibc/tree/glibc-2.39/sysdeps/unix/sysv/linux.
- glibc 2.43 stat64.c, 1503 bytes, SHA256
  5dd6837562836e6c633f2efc48956f10b66cbdcf3c9c91987dd7a411f72f9624;
  fstatat64.c, 5762 bytes, SHA256
  69fbd971e9d8bf29bf5282997169d86d87794115679d35cb184b2dee18b85e8f.
  Exact upstream snapshots were retrieved from
  https://android.googlesource.com/toolchain/glibc/+/refs/tags/upstream/glibc-2.43/sysdeps/unix/sysv/linux/
  with the named files and format=TEXT. Both versions forward stat64 to
  fstatat64 with AT_FDCWD/flags zero; the x86_64 branch uses newfstatat.
These are source observations. Actual host/kernel compatibility and primitive
execution are reported by the separate original/native OS qualification.
