# Local atomic-write owner

## Ownership

`atomic_write.hepta` owns the Linux Local branch of
`src/mcp/fs/text_editing.rs::atomic_write`, together with the exact temporary-path
calculation and the associated Rust 1.95 / GNU Linux metadata transitions. The
reference is the complete original function, including its unexecuted Remote
branch, from commit `a0dcdda1991ec536d5e2d252c006a778993fa566`. Its 1,647 bytes
have SHA256 `78f128e5938311d9248df09e94fa340a37bea4c759538e93b8d342feee046dfa`;
the enclosing source has SHA256
`e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590`.

The companion HIA packer emits a static Linux x86-64 ELF containing the HIA image
and a fixed syscall adapter. Its runtime needs neither Python, Rust, libc nor a
dynamic loader. The Python builder and suites are build and qualification tools.
This is an internal owner: caller authorization, canonical file locking,
history/cache updates, public MCP dispatch and the Remote/SSH branch remain
outside this component. A caller must already have authority to write the
supplied path. No production handler or whole-runtime replacement is claimed.

The pinned compiler is Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`,
tree `8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49`; the B3 image SHA256 is
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
The composition proof checks five complete imported HIA functions against the
retained text-budget and policy sources, including UTF-8 admission and Rust
lossy-string behavior.

## Borrowed-byte ABI

The entry point is `f0(readbuf input, mutbuf output, mutbuf private_work) -> u32`.
All integers below are little endian. No pointer appears in the request.

| Byte offset | Field |
| --- | --- |
| 0 | Eight bytes `HRAWI001` |
| 8 | u64 operation: 1 = local atomic write; 2 = temporary-path calculation |
| 16 | u64 raw Unix path byte count |
| 24 | u64 UTF-8 content byte count |
| 32–63 | Four reserved u64 words, all zero |
| 64 | Raw path bytes, followed immediately by content bytes |

The total length must be exact. Operation 2 requires empty content. A raw path
can contain invalid UTF-8 or NUL; those bytes are not silently normalized.
Operation 1 requires valid UTF-8 content, as the original parameter is `&str`;
NUL is valid inside the content. Invalid framing is distinct from an original
filesystem error.

A successful return value is the number of output bytes. The output begins with
the following 32-byte header, followed by the exact payload:

| Byte offset | Field |
| --- | --- |
| 0 | Eight bytes `HRAWR001` |
| 8 | u64 tag: 0 = original unit success; 1 = original error; 2 = temporary path |
| 16 | u64 stage: 0 for success/path, otherwise 1 metadata, 2 write, 3 chmod, 4 rename |
| 24 | u64 payload byte count |
| 32 | Payload bytes |

Tag 0 has no payload. Tag 1 contains the complete original error text without a
new prefix or truncation. Tag 2 contains the raw Unix bytes of the temporary
path, including any raw parent bytes.

| Return code | Meaning |
| --- | --- |
| `0xffffffff` | Invalid typed request |
| `0xfffffffe` | Supplied input/output/workspace capacity is insufficient |
| `0xfffffff9` | Invalid private state or fixed child/effect contract |
| `0xfffffff7` | Canceled request |
| `0xfffffff0` | Private effect pending; only the trusted adapter consumes this |

Refusals, cancellation and pending effects publish no output-buffer payload.
Completed responses modify only their returned prefix. Tests check the
immutable input, output tail and all three buffer guards on every native entry.
Capacity refusal is never translated into an original semantic error.

The existing `batch-plan.v1` build profile is reused: 512 MiB input, 1 GiB output
and 1,152 MiB private workspace. These are transport capacities, not an added
file-size rule inside the original function. The static adapter maps these
regions lazily. A real 505 MiB content write is qualified: fifty maximum 5 MiB
insertions can each expand LF to CRLF, plus the maximum 5 MiB starting file.
The scalar policy tests also exercise large raw-path and lossy-name domains.

## Path and filesystem behavior

The temporary name is exactly
`parent.join(format!(".octofs_tmp_{}.tmp", file_name.to_string_lossy()))`.
Rust `Path::parent` and `file_name` semantics are retained for repeated
separators, leading/trailing dot components, parent components and raw bytes.
Only the filename is converted lossily; the parent retains its original Unix
bytes. This is not a lexical path normalization.

The state machine preserves the original ordering:

1. Construct the temporary path, then obtain metadata for the target, following
   symlinks. NotFound permits a new target. Other metadata errors return the
   original metadata error.
2. Create or truncate the fixed temporary path with mode 0666 under the inherited
   umask and write all bytes. Open and write retry EINTR; partial writes advance
   the content offset. A zero write produces the original write-all error.
3. If target metadata existed, apply the original mode, including its 07777
   permission bits, to the temporary path. Chmod retries EINTR.
4. Rename the temporary path over the target.

A write/open failure leaves the temporary path as the original does. Chmod or
rename failure attempts unlink once; cleanup failure does not replace the
original error. Rename and unlink do not acquire extra EINTR retries. File-drop
close errors are ignored and never cause a second close of a retired slot.
Existing temporary symlinks/hardlinks and target symlinks retain the original
observable behavior. There is no added exclusive-open, nofollow, randomized
temporary name, fsync or durability policy.

The metadata owner includes both layers observed in the unchanged reference:
Rust's unknown/present/unavailable statx cache, and GNU libc's statx ENOSYS
fallback to newfstatat. In particular, the NULL availability probe can itself
take that GNU fallback and return EFAULT. That result changes Rust's cache
decision and must not be replaced with the physical statx ENOSYS. The cache
persists across serial requests, including a completed blocking stage after
cancellation.

## Private effects and descriptor authority

The 96-byte effect slot starts at private-work offset 256. It contains twelve
u64 words: `HIAATFX1`, per-request sequence, action, three arguments, reserved,
completion value, completion errno, completion auxiliary value, completion
ready (exactly 1), and reserved. All completion/reserved fields are zero when
the effect is emitted. The adapter supplies the completion and reenters HIA.
This memory is never writable through the public request frame.

| Action | Fixed operation |
| --- | --- |
| 1 | Target statx |
| 2 | Rust's NULL statx availability probe |
| 3 | Rust's stat/newfstatat fallback |
| 4 | Open the fixed temporary path |
| 5 | Write the admitted input span to the private temporary FD |
| 6 | Close and retire the private temporary FD |
| 7 | Chmod the fixed temporary path |
| 8 | Rename that temporary path to the admitted target |
| 9 | Unlink that temporary path |
| 10 | GNU statx path fallback through newfstatat |
| 11 | GNU NULL-probe fallback through newfstatat |

The adapter verifies action, phase, sequence, path/span bounds, reserved words,
fixed flags and descriptor state. A request cannot choose a syscall number,
borrow an unrelated FD or submit an effect completion. A terminal contract
error independently retires/closes the actual FD before exit. Nineteen real
malformed-child controls prove this with the emitted ELF.

## Static transport and cancellation

The executable accepts no arguments. Stdin consists of u64 frame length plus
the request bytes. Each response is a u32 return code followed by the returned
output prefix for an ordinary length result. EOF between frames exits normally.
Partial framing exits 74; an input length over 512 MiB is refused before reading
its body and exits 3; extra arguments exit 64. Invalid complete frames can be
followed by a valid request.

Each request uses one owned worker process; the parent retains the private
workspace and serializes subsequent requests. The input mapping is read-only
while borrowed. SIGUSR1 is the trusted envelope's cancellation signal. The
parent installs its handler and unblocks only that signal; inherited unrelated
mask bits are preserved. The worker ignores SIGUSR1.

Cancellation can be reported while an already-started filesystem syscall is
still blocked. That blocking stage is allowed to finish; its FD cleanup and
private metadata cache update are drained before admitting the next request.
This mirrors cancellation of the original Tokio task without pretending that
`spawn_blocking` work stopped. Both native and original envelopes are tested
with SIGUSR1 initially blocked and with a subsequent request.

The worker installs SIGKILL as its parent-death signal and checks parent
identity after installation. An actual held-write parent-death test verifies
that the worker dies and is reaped without releasing the held effect. These
tests do not claim public server shutdown integration or concurrent canonical
lock ownership.

## Qualification domains

| Domain | Actual completed coverage |
| --- | --- |
| Direct native policy | 170,947 HIA entries; 88,807 path requests; 16,414 synthetic effect sequences; 19 framing/capacity refusals |
| Errno formatting | 16,377 synthetic projections using 4,095 actual Rust error strings; NUL and generic WriteZero properties retained separately |
| Native kernel suite | 151 cases / 171 requests: 77 ordinary cases, 48 injected-error cases, 2 real RLIMIT partial-write cases, 24 cancellation/recovery cases |
| Fixed boundary | 28 ELF processes: 19 effect-contract refusals, 8 transport controls, 1 real parent/worker death |
| Evidence admission | Four groups; 34 changed-artifact, missing-corpus and false-completion refusals; no new semantic invocations |
| Original replay | A fresh locked Rust build; 88,807 exact Path responses; 171 actual original atomic_write calls in 151 state/owned-syscall comparisons |

The complete kernel request stream is 535,921,251 bytes per side. The complete
response stream is 23,326 bytes, SHA256
`aff118164acbc46e16fd244bdd6eabbc2f02a53d952d0b7d27bd5a9916215f66`.
Both full streams, complete file payloads in lossless gzip snapshots, raw stat
observations, owned syscall traces and actual process stdout/stderr are retained.
Clock values and opaque device/inode/FD numbers are recorded before normalization;
the comparison preserves modes, ownership relation, hardlink groups, identity
retention, byte content, operation order, flags, errors and cancellation order.

The observer's domain is fixed by the owned fixture paths/FDs and the two exact
availability-probe signatures. Dynamic-loader activity outside that domain is
not an atomic-write operation. An observer may read such a path before
classification; this does not make a NUL-path refusal a filesystem syscall.

The original recipe locks Rust 1.95.0 on x86_64-unknown-linux-gnu, Tokio 1.53.1,
anyhow 1.0.104, libc 0.2.189 and pin-project-lite 0.2.17. Its build script copies
the complete original function byte for byte. Actual compiler/package logs,
compiled owner bytes and the executed reference binary are checked. All four
native suites and the original driver retain the existing 180-second outer
budget; individual held-syscall and transport controls retain their shorter
deadlines. Captured comparison evidence is labeled as a retained completed
execution. Integration CI must build and execute its own source-matched recipe.
