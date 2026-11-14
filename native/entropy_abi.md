# Bounded Linux entropy owner

`entropy_policy.hepta` owns backend selection, initialization, retries, partial
fills, output admission and state cleanup. `entropy_packer.hepta` constructs the
complete static Linux x86-64 executable, including its fixed syscall adapter.
The resulting program requires no Python, Rust, libc or dynamic loader.

This internal component supplies up to 128 bytes per fill. The original crypto
scope uses four ordered 32-byte fills for stdio keys and 12-byte fills for seal
nonces. This component is not a registered MCP tool and does not authorize
caller scopes, admit replay, reserve nonces or replace their owners. The
original process-wide concurrent cache and scope locking are separate work.

## Request and result

The entry receives input, output and mutable workspace buffers through the
ordinary HIA native ABI. Its input must be exactly 24 bytes:

| Offset | Width | Value |
|---|---:|---|
| 0 | 8 | `HRENT001` |
| 8 | 8 | Requested byte count, unsigned little endian, 0 through 128 |
| 16 | 8 | Zero, reserved |

The workspace must contain at least 1,024 bytes. Bytes outside the used workspace
and output spans are preserved. A successful result is the requested count and
publishes exactly that many bytes. A zero-byte request succeeds without an OS
effect, including before backend selection.

| Result | Meaning |
|---|---|
| `0` through `128` | Complete successful fill |
| `0xfffffff0` | One declared effect is pending; resume after its exact acknowledgement |
| `0xffffffff` | Invalid request at idle admission |
| `0xfffffffe` | Insufficient output or workspace capacity at admission |
| `0xfffffffd` | Entropy backend failed; no partial output is published |
| `0xfffffffc` | Invalid private state, continuation or acknowledgement; permanently poisoned instance |

Invalid idle requests and admission capacity refusals leave both buffers
unchanged. A continuation must retain its original request, admitted output
capacity and exact effect identity. Withdrawing capacity during a fill poisons
the instance. Too little workspace is refused without reading or writing it.
An instance poisoned by a contract failure cannot be reused; the adapter must
also close any private descriptors that the rejected operation had acquired.

The policy accumulates bytes in its private workspace. It copies them to the
output only after the complete fill succeeds. Every terminal success or
backend error wipes transient state and entropy bytes while retaining the
backend choice, cached-descriptor flag and monotonic effect sequence. The
permanent poisoned-state marker is retained after a contract failure.

## Original Linux backend behavior

The reference is the complete original `operation_crypto.rs` SystemEntropy,
actually compiled with ring 0.17.14 and getrandom 0.2.17. The actual getrandom
build has an empty enabled-feature set, so `linux_disable_fallback` is absent.
The isolated oracle locks libc 0.2.191; the retained runtime lock selects
0.2.189. This is an executed comparison against the exact original owner source
and the recorded backend, not a claim of rebuilding the complete runtime with
its identical dependency lock or production toolchain.

On the first nonempty fill, HIA declares a zero-length `getrandom` probe with
flags zero. It caches the selected backend:

- Probe `ENOSYS` or `EPERM` selects the file fallback.
- Every other probe outcome selects direct `getrandom`, including interruption
  and other errors. A later direct data error does not switch backends.
- Fallback initialization opens `/dev/random` with `O_RDONLY | O_CLOEXEC`,
  waits indefinitely for `POLLIN`, closes that temporary descriptor once, then
  opens and caches `/dev/urandom` with the same flags.
- Opens retry `EINTR`. The readiness poll retries `EINTR` and `EAGAIN`.
  A temporary close error is ignored, with no retry or duplicate close.
- Failed initialization is retried by the next fill without repeating the
  availability probe. A cached urandom descriptor survives an ordinary read
  error and is reused by the next request.
- Direct `getrandom` and fallback reads advance on partial success and retry
  `EINTR`. Zero-byte or oversized success is refused. The oversized case is a
  native adapter contract control, outside valid kernel behavior and the
  original Rust comparison domain.

Readiness and entropy blocking follow the original backend. This component
does not add or claim a wall-clock timeout for those operations.

## Persistent state and effect envelope

All words below are unsigned 64-bit little endian. The initialized workspace
starts zeroed. Only the three words at offsets 24, 32 and 40 survive ordinary
terminal cleanup.

| Offset | Meaning |
|---|---|
| 0 | Phase: 0 idle; 1 probe; 2 direct fill; 3 open random; 4 poll; 5 close random; 6 open urandom; 7 fallback read; 8 poisoned |
| 8 | Original requested byte count |
| 16 | Completed bytes in the current fill |
| 24 | Persistent monotonic effect sequence |
| 32 | Backend: 0 unknown, 1 direct, 2 fallback |
| 40 | Cached urandom ownership flag, 0 or 1 |
| 48 | Temporary random descriptor ownership flag |
| 56 | Deferred readiness failure, reported after closing the temporary descriptor |
| 512–639 | Private temporary entropy bytes |

The effect record starts at offset 256:

| Offset | Meaning |
|---|---|
| 256 | Magic `HIAENT02` |
| 264 | Next sequence number; zero and wraparound are forbidden |
| 272 | Workspace destination: 512 for the empty probe; a span within 512–639 for data; zero for other effects |
| 280 | Requested data bytes; zero for probe and descriptor operations |
| 288 | Flags, exactly zero |
| 296 | Action, matching one of phases 1 through 7 |
| 304 | Result count; successful opens are normalized to zero |
| 312 | Positive errno on failure; zero on success |
| 320 | Acknowledged sequence, initially zero |
| 328 | Completion flag, initially zero and acknowledged as exactly one |

The pending result/errno/acknowledgement fields must all be zero before the
adapter performs an effect. A completion must match the original action,
sequence, destination and width. The policy checks combinations of result and
errno before consuming any bytes. A sequence that cannot advance poisons the
instance instead of wrapping.

## Fixed executable boundary

The executable accepts no command-line arguments and processes a stream of
24-byte frames. Each reply is a four-byte little-endian result code, followed
by payload bytes only for codes 0 through 128. Valid empty fills have a
four-byte zero reply. EOF between frames is successful; EOF within a frame
terminates with exit 2 and does not publish that partial request.

The adapter maps disjoint input, output, workspace and private descriptor
regions, with guard pages. Input is read-only during HIA execution. It rejects
dirty upper return bits and malformed effect spans before any requested
entropy syscall. HIA cannot select device paths, flags or arbitrary file
descriptors. Raw descriptors remain in the adapter's private slots.

Its entropy syscalls are fixed: Linux `getrandom(318)`, `openat(257)` for the
two literal device paths, `poll(7)`, `read(0)` and `close(3)`. The temporary
descriptor slot is cleared before its one close attempt. Normal backend
errors keep a cached urandom descriptor; EOF, fatal state or transport failure
closes tracked descriptors, wipes buffers and unmaps the owned mapping. SIGPIPE
is ignored so a broken output pipe follows the declared transport error path.

| Process exit | Meaning |
|---|---|
| 0 | Clean stream EOF |
| 2 | Truncated framing or invalid native/effect contract |
| 64 | Unexpected command-line arguments |
| 71 | Permanently poisoned HIA state |
| 74 | Setup or stream transport failure |

Frame-level invalid, capacity and entropy errors are returned as result codes
and allow the same process to continue. An original getrandom process-wide
urandom cache is normally released by process exit. The native executable also
closes its cached descriptor explicitly at EOF; this cleanup difference is
recorded rather than hidden in the syscall comparison.

## Qualification domains

`test_entropy_backend.py` executes the actual HIA image with explicitly
synthetic effect completions. It checks every bounded size, both backends,
cache/retry transitions, partial output refusal, capacity, cleanup and poisoned
state. These completions are not counted as real kernel observations.

`test_entropy_kernel_backend.py` runs the actual native executable and the
actually compiled original Rust SystemEntropy under the same directly owned
child controls. Its eight groups cover 25 processes and 56 request frames per
owner. Normal random bytes are checked for successful length and publication,
never compared for equality. Deterministic partial completions are compared
exactly. The supervisor accepts no external PID and writes synthetic bytes
only into its directly forked child's currently notified, bounded RNG buffer.

`test_entropy_packer.py` executes the HIA packer and malformed test-only images,
checking exact output capacities, ELF structure and effect refusal.
`test_entropy_transport.py` separately checks framing, CLI refusal, broken
output and impossible kernel result counts. Neither suite is mislabelled as an
original SystemEntropy comparison.

The retained real comparison has identical normalized effect sequences and
results for both owners. Raw descriptor numbers and the native explicit EOF
close are the documented normalization differences. Full runtime activation,
caller authority, concurrent cache coordination and scope lifetime are not
established by this component's result.
