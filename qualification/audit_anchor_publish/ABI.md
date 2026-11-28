# Private audit archive-anchor publisher

## Scope and identity

This new version implements the unchanged target `request_audit::publish_archive_anchor` and its unchanged `new_id`, `name`, `open_at`, and `open_at_component` dependencies from d3d75c30719db966b004756f610007a7c723729e. Exact whole source and byte-range extracts are in reference/ORIGINAL_SPANS.json. It consumes the already qualified four-u64 ArchiveAnchor serializer from audit JSON handoff 7e7d6ea01e792b142f38eb13d2c8e087d2172047.

This preparation contains source authoring and fresh HIA compilation only. Runtime semantic comparison, native lifecycle controls, independent complete readers, archive open/namespace_version, HOT_CACHE, public callers, and the whole runtime are not qualified by preparation.

## Initial request

All words are unsigned little endian. HAPURQ01 has exactly 128 bytes:
magic at 0; operation 1 at 8; nonzero generation at 16; nonzero borrowed root capability at 24; root_device, root_inode, archive_device, archive_inode at 32,40,48,56; all bytes64..127 zero. The native adapter installs the caller-owned directory FD as capability1. HIA itself permits a nonzero opaque root identity; it never receives an ambient root pathname.

A fresh owner workspace may be initialized. Reuse requires a completed valid state, strictly increasing generation, and the same root capability. One active generation is exclusively owned. One native context is 98304 bytes. Owner input/output/workspace are separate borrowed regions. The native entry uses a 128-byte initial input, output capacity at least8192, and context capacity at least98304. Direct HIA uses output8192 and workspace16384 minimum. Native reserves32768 owner-work bytes and retains both full tails and canaries.

## Result and effect frames

HAPURS01 has a128-byte header. kind8 is0success,1error,2filesystem effect,3JSON effect. Sequence16 and generation24 identify the outstanding operation. operation32 and arguments40/48/56 are private. First payload offset/length64/72, second80/88; error family96/code104; complete extent112; reserved120zero. Payloads are contiguous after the header and complete extent is exact.

Terminal success/error has extent128 and operation1, without payload. Error family1 is a real OS errno; family2/code1 is the original fixed entropy-unavailable error; family4/code1 is write_all WriteZero. Full original display/debug/chain must be retained during semantic comparison. No private transport failure may be relabeled as a target business error.

HAPUACK1 completion is128-byte header plus complete returned bytes: generation8,sequence16,kind24,operation32,status40,errno48,value56,payload length64,complete extent72,reserved80..127zero. Status0 is success and1 is a real OS error. An unsuccessful ACK requires errno1..4095 and no value/payload. JSON op4 must return actual nonempty successful encoded bytes, value==payload length<=4096. Every pending phase, effect identity, argument, token, reserved word, payload extent and output/workspace capacity is admitted before owner mutation.

## Actual filesystem and entropy boundaries

The HIA owner alone selects effects, retry decisions and cleanup. Native code resolves an opaque capability and performs exactly the selected libc boundary:

| Effect | Meaning |
|---|---|
|1|openat borrowed root, requested flags193 (WRONLY/CREAT/EXCL) and mode0600; native adds NOFOLLOW/CLOEXEC|
|4|read owned entropy FD, exact requested remaining length|
|5|write owned temporary FD, complete remaining serialized bytes|
|6|fsync owned file or borrowed root|
|7|close owned FD, forget capability exactly once|
|8|linkat between two names under the same borrowed root|
|9|unlinkat under borrowed root|
|17|libc syscall with fixed SYS_getrandom318, flags0 and requested length0..32|
|18|libc open of the exact HIA-owned /dev/random or /dev/urandom name, RDONLY/CLOEXEC|
|19|libc poll one owned random FD, POLLIN and infinite timeout|

The initialized native table has20 real function pointers followed by one zero word: errno_location,openat,fstat,geteuid,read,write,fsync,close,linkat,unlinkat,renameat,fcntl,fdopendir,readdir,closedir,fstatat,pread,syscall,open,poll,zero. The preserved older helpers are unreachable from this owner; admission allows only the listed effect operations. Caller supplies actual libc addresses, never fixture functions.

The locked ring0.17.14/getrandom0.2.17 source is part of the forthcoming fresh reference dependency closure. Upstream source snippets in this preparation must be compared to complete locked crate members before qualification; tag provenance alone is not a crate check.

The empty getrandom probe selects fallback only on ENOSYS or Linux EPERM. Getrandom/read loops preserve partial progress, retry EINTR and reject zero/other errors with the target fixed entropy error. File fallback opens /dev/random, polls with EINTR/EAGAIN retries, closes it on both paths, then opens and retains /dev/urandom. It reads32 real entropy bytes. HIA encodes64 lowercase hexadecimal characters into the84-byte temporary component.

Fallback descriptor and availability selection live in one private service context and persist across its completed operations; context disposal closes its last owned descriptor. This private lifetime does not claim processwide atomic entropy-cache synchronization or equivalence between multiple separately initialized service contexts. No entropy bytes are supplied by an initial request.

## Publication and cleanup

The exact sequence is entropy → exclusive temp open → actual JSON child op4 → write_all → temp fsync → hard link to .request-archive-v11-anchor.json → temp unlink → borrowed root fsync → owned temp close. Serialize is after successful open, matching the original. Existing targets are never overwritten. A failure after open attempts temp unlink and then closes the temp, preserving the first actual error. File Drop ignores close errors. A failure before open does not invent cleanup.

On a malformed borrowed request/effect the private transport fails closed and disposes its owned descriptors; that is not an original target result. Optional observation only copies complete borrowed buffers and syscall data. The observer never decides a policy, selects a call, returns an effect, or performs a filesystem action. The production callable must work with observer absent.

## Outstanding composition

This owner does not yet implement archive creation/open, v12 shards, namespace_version/inotify/fingerprint, HOT_CACHE, begin_with_read, begin_reserved_record, finish_sync, retention effects, or public routing. Those remain explicit successor work; the completed PinnedAnchor source and evidence remain unchanged.
