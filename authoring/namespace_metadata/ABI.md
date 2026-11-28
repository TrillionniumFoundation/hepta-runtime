# Native namespace metadata

This Linux x86-64 component implements the Rust 1.95 GNU metadata behavior used by the private namespace and append owners. HIA owns the Rust statx cache protocol, the GNU statx ENOSYS fallback, both complete structure conversions and typed responses. The fixed assembly captures the complete request privately, executes selected syscalls and accesses the caller's shared byte. There is no runtime libc, host interpreter, TLS replacement or second cache.

## Six-argument ABI

`entry(request, length, output, capacity, shared_cache, shared_cache_capacity)` has flat entry offset 0. Output capacity is at least 176; cache capacity is at least 1. The caller supplies live, disjoint ranges and retains the shared byte across all metadata consumers. Initialize that byte to 0 once for the process; this entry never resets it.

| Request offset | Field |
|---|---|
| 0 | `HNSMQ001` |
| 8 | Command: 1 borrowed FD, 2 raw path |
| 16 | FD for command 1; zero for command 2 |
| 24 | Path length |
| 32–95 | All zero |

The request is exactly 96 plus path length. FD is a nonnegative signed 32-bit descriptor, including 0, and has no payload. The FD remains borrowed. Paths can be relative or non-UTF-8. NUL returns the original typed NUL error before any syscall or cache read. The full path is privately captured and terminated, without PATH_MAX truncation.

Every normal terminal returns scalar **32**, the header length. The complete initialized response extent is **32 + payload_length**: **176** on success and **32** on error. Output bytes beyond that extent remain unchanged.

| Response offset | Field |
|---|---|
| 0 | `HNSMR001` |
| 8 | Kind: 0 success, 1 OS error, 2 NUL |
| 16 | Positive original errno for kind 1; otherwise zero |
| 24 | Payload length: 144 success, zero error |
| 32 | Complete Linux x86-64 stat64 for success |

Stat64 includes device, inode, nlink, mode, UID, GID, rdev, size, block size, blocks, all three second/nanosecond pairs and every zero padding/reserved field. Rust `FileAttr.extra` birth-time fields are outside this interface.

Transport returns are `0xffffffff` (invalid request/ranges/cache), `0xfffffffe` (capacity/private capture allocation), and `0xfffffffc` (unexpected closed-effect or continuation). These are separate from original OS/NUL errors. Rejection does not publish partial output.

## Exact cache and GNU behavior

The shared AtomicU8 meanings remain 0 unknown, 1 present, 2 unavailable. Statx failure reloads the real shared byte before probing. The real NULL-argument probe preserves the original operation errno. Relaxed byte loads/stores use single native x86-64 operations.

GNU libc statx first handles raw ENOSYS using newfstatat and a complete stat64-to-statx conversion. HIA implements this wrapper for ordinary requests and the probe before applying the outer Rust cache logic. Direct File/path fallback is separate. This private request ABI admits only flags 0 and AT_EMPTY_PATH, both supported by the GNU wrapper.

A real kernel cannot succeed on the fallback probe's NULL path with flags 0. A fabricated successful ACK for that probe is transport corruption. Actual qualification uses real kernel results and seccomp errno injection, without fabricated successful stat payloads.

The full Rust reference is blob `7db474544f04abc75e2d66ec007ebe4799a491d3`, 88,655 bytes, SHA256 `77c6419ee048c348d9ed4bef226ce6ceb735d6077d0eb9f6bcac0ef46fa7b86d`, from [Rust 1.95 unix.rs](https://github.com/rust-lang/rust/blob/1.95.0/library/std/src/sys/fs/unix.rs). The complete [GNU statx wrapper](https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/statx.c) and [GNU fallback](https://github.com/bminor/glibc/blob/master/io/statx_generic.c) are independently pinned by complete bytes and Git blobs in the composition report, with their upstream license retained. The gate captures the actual host libc; it does not infer a release identity from the upstream branch.

## Reproduction and actual qualification

`scripts/hia_native_namespace_metadata.py` reproduces authored HIA, compiles it with the pinned native compiler, assembles the closed boundary and invokes the original native HIA ELF linker. It checks the complete text, padding, symbols and zero unresolved relocations. The flat image is exactly the linked ELF bytes starting at offset 256.

`authoring/namespace_metadata/run.py` binds actual Rust 1.95, all standard-library rlibs and host libc. It compares 24 separate reference/native process groups containing 122 requests, including full 256-byte output buffers, input/output/cache guards, and actual ptrace metadata syscall sequences. Ten seccomp profiles run cold and warm, covering GNU fallback, probe fallback, EPERM, EINVAL, EFAULT, EBADF and fallback failure. Another 21 controls reject malformed, aliased and undersized inputs.

The first direct-raw-statx candidate failed ENOSYS syscall comparison. Both actual traces and the failure are retained; the GNU wrapper correction passes the same comparison. Component qualification does not qualify the complete namespace or the entire runtime.
