# Pinned request-archive anchor: private source-stage contract

This new version is not qualified yet. It does not modify the closed audit record-I/O pump.
Target d3d75c30719db966b004756f610007a7c723729e supplies the exact AnchorStamp,
PinnedAnchor, open_at and named_stat_with_component bodies retained in reference/.
All implementation policy remains in HIA. The adapter only performs actual descriptor calls,
copies complete buffers, owns descriptors, and invokes the unchanged audit JSON op 2.

## HIA entry and retained state

f0(readbuf input, mutbuf output, mutbuf workspace) returns u32. It requires 8192 output
bytes and 16384 workspace bytes. All frame words are little-endian u64, never host pointers.
HAPNRQ01 is exactly 128 bytes: magic at 0, operation at 8, nonzero generation at 16,
nonzero borrowed root capability at 24, and zero bytes 32 through 127.
Operations 1/2/3 are open/fence/drop. One workspace owns at most one anchor. Open requires
an empty workspace; fence/drop require a pinned anchor. Each new operation strictly
increases generation and keeps the same root capability. Drop permits later open.
Invalid input/ACK returns 0xffffffff; insufficient buffers returns 0xfffffffe.
Direct HIA admission refusals leave the entire output and workspace unchanged.

The original constant component is .request-archive-v11-anchor.json. Open performs actual
no-follow open, held metadata, source-ordered validation, named metadata, complete bounded
read, held/named rechecks, then the qualified four-field Anchor decoder. It retains the
actual descriptor, all original bytes, the full stamp and the typed four-u64 projection.
The stamp covers mode, uid, nlink, length, device, inode, gid and both signed seconds and
nanoseconds of mtime/ctime. These are compared in full, without a timestamp-only shortcut.
The original 2048-byte read bound remains; read-to-end is limited to 2049 actual bytes.

Fence validates the pinned stamp against current euid, compares actual held and named
stamps, positionally reads exactly the pinned number of bytes, compares all bytes, then
rechecks held and named stamps. Each actual pread offset comes from HIA progress. EINTR and
partial progress are handled in HIA. A fence failure retains the anchor and does not close
it. Drop performs the actual owned close, ignores its error as File::drop does, then retires
the pinned state. Open failure closes any descriptor already opened.

Workspace words: magic 0 HAPNWS01, life 8 (1 pending, 2 pinned idle, 3 empty idle),
generation 16, borrowed root 24, command 32, pinned flag 40, phase 48, effect sequence 56,
pending kind/op 64/72, pending a/b/c 80/88/96, error family/code 104/112,
owned file capability 120, pinned byte length 128, current read progress 136.
The full initial request is copied at 256; stamp is 512..607; constant component at 768;
pinned bytes at 1024, independent reread bytes at 4096, typed projection at 7168,
complete current ACK data at 8192. No field is supplied through public JSON.

## Complete effects and replies

HAPNRS01 uses a 128-byte header: kind 8 (0 success, 1 error, 2 filesystem, 3 JSON);
sequence 16; generation 24; operation 32; arguments a/b/c 40/48/56;
payload0 offset/length 64/72; payload1 80/88 is absent; family/code 96/104;
complete extent 112; zero 120. Payload is contiguous from 128.
Successful open returns the full 128-byte HAJPR001 kind-2 Anchor. Fence and drop return no
payload. No native or observer code fabricates a typed record.

Filesystem effects preserve the established numbers OPEN=1, METADATA=2, EUID=3, READ=4,
CLOSE=7 and add NAMED_METADATA=15, PREAD=16. NAMED_METADATA is actual fstatat with
AT_SYMLINK_NOFOLLOW. PREAD arguments are owned capability, requested count, absolute offset.
OPEN flags are O_RDONLY|O_NONBLOCK, plus the unchanged adapter O_NOFOLLOW|O_CLOEXEC.
Metadata payload is exactly 96 bytes: mode/uid/nlink/size/device/inode/gid/mtime-sec/
mtime-nsec/ctime-sec/ctime-nsec/zero, in that order. Mode/uid/gid are zero-extended u32;
all other fields retain their complete bits. Negative named size is rejected by HIA using
the exact original error, not normalized away by the adapter.

HAPNACK1 has the same 128-byte structural layout as the qualified record-I/O ACK:
generation 8, sequence 16, kind 24, op 32, status 40, errno 48, value 56, data bytes 64,
complete extent 72, reserved zero 80..127. It must match the current pending effect and
the immutable copied request. The entire payload and all bounds are admitted before any
workspace mutation. Status 1 preserves OS errno; JSON status 2 preserves invalid return.
The JSON effect is the complete HAJRQ001 op-2 frame; no new JSON implementation is added.

Private errors retain OS errno (family 1), fixed source errors (family 2), serde rejection
(family 3), and UnexpectedEof (family 4). Fixed source codes:
1 private request archive legacy anchor refused
2 request archive legacy anchor disappeared
3 request archive legacy anchor size refused
4 request archive legacy anchor binding changed
5 request archive legacy anchor changed while reading
6 request archive legacy anchor bytes changed.
The original reference will retain full original error display and chain. This projection
does not substitute for exact serde diagnostic display in a later public caller.

## Actual callable

The source template derives from the exact closed record-I/O assembly, with the complete
ordered delta retained. New exports entry/initialize/dispose use the same SysV argument
shapes. Context remains 98304 aligned bytes. The 18-word libc table contains the existing
15 addresses, actual fstatat, actual pread, and a zero terminator. Explicit libc.so.6 and
whole-library identity admission remain required in the later loader.
The root descriptor is borrowed and never closed. Exactly one additional file descriptor
may be retained between calls, matching the HIA-owned capability. Native dispose closes
that descriptor before clearing the context. Mechanical fault cleanup owns all closes.
Both observed and observer-off execution must use the same packed bytes. Observers only
copy evidence and do not supply policy or syscall results.

## Remaining qualification and composition

This checkpoint authors sources, compiles the HIA owner, and assembles the native prefix
without calling the new owner. A later frozen recipe must compare the complete ordinary
and failure corpus with the unmodified original functions, retain full before/after
buffers, verify actual descriptor custody, execute observer-off cases and physical
reader controls, and independently read the uploaded archive without executing code.
Rust is CI only. Existing 60/180/900-second process budgets and 15-minute job budget apply.
No public handler, full archive store, HOT_CACHE, retention caller, begin/finish caller,
async lifecycle or whole-runtime qualification is asserted.
