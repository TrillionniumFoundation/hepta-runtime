# Fixed native file_info capability

Build-only source; no actual file_info application or original comparison has
run at this freeze. Six runtime HIA images are info, unchanged fingerprint,
unchanged metadata, binary codec, stat version and the qualified dual-frame
path_error. The actual HIA linker and packer produce one syscall-only
ELF with a private qualification carrier. The source author is reproduced.

## Native exports and graph ownership

file_info_at_create(callback, callback_context, process_orphans_pool) returns
a guarded context, or a negative errno. The graph supplies the same existing
c811 process pool to every info/writer context in this OS process. The pool
creator PID must match. Neither release nor destroy disposes that pool.

file_info_at_invoke(ctx, borrowed_parent_fd, packet, length) validates an idle
context, a nonnegative Linux int FD and an external HINFQ001 packet with zero
FD field. It copies the complete packet and injects the trusted register FD.
Only actual child results and requested native effects resume the HIA owner.
On return 64, context+104 points at the complete HINFR001 response and
context+168 gives its full extent. State 2 holds this output loan.
file_info_at_release consumes only the loan; destroy rejects states 1 and 2.

The parent is not in the owned ledger. One actual openat-owned file can be in
the ledger. The HIA owner closes it or issues ORPHAN_OWNED in the exact original
initial-regular-fstat error branch. Native code validates that real token,
calls hia_process_orphans_append, and removes the token only after zero.
No orphan FD is closed by context teardown. Failed private resource/protocol
operations retain operable tokens for teardown; allocation exhaustion is not
qualified as original Python memory-failure behavior.

The unchanged fingerprint child receives binary_read_body_invoke_at with the
same borrowed parent and no dup. The unchanged metadata child receives the
actual info-owned file on capture, then zero FDs with the captured snapshot on
summary. Child output bytes are copied completely before explicit release.
The stat child uses 128 output and 256 work bytes. No native code chooses
regular status, version equality, snapshot ordering, errors or JSON fields.

## Context layout

The 4096-byte RW context is followed by a guard page. Common fields retain the
qualified native pump layout: magic0/capacity8, body entry16/stat entry24,
callback40/context48, state56; input pointer64/capacity72/extent80;
workspace88/96; output104/112; resume120/128; stat output136/work144;
borrow extent168/last return176/owned count184/generation192;
current input200/208, request seq216/op224, actual result232/payload240,
HIA call count248; eight owned slots256..319; direct stat entry320 and
output/work spans328/336. Owned slots initialize to -1.

Info fields are borrowed parent344 and active flag352, current nested child
pointer360/type368, shared orphan pool376, fingerprint context384, metadata
context392, and cumulative successful orphan transfers400. The completed
call clears parent/active/nested fields. Parent FD zero is distinguished by
the active bit. Per-context generations are nonzero and monotonic. Orphan
records bind the actual FD, this context pointer and that generation; the
pointer is an immutable identity and must not be dereferenced after destroy.

## Exact effects and complete journals

The fixed capability set is openat read-only (257), fstat (5), close (3), and
the shared orphan-memory primitive. Only openat can use the borrowed parent;
only the actually opened owned token can reach fstat/close/orphan. Open flags
are exactly O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC. Metadata and fingerprint
native pumps retain their own qualified syscall capabilities.

Context buffers use guarded RW mappings, never WX. Every application HIA call
has full input, workspace-before, filled output-before, output-after and
workspace-after spans. Work growth captures complete old and new arenas.
Stat child calls include full 128/256 buffers. Nested opaque callables produce
their own complete journals and the outer owner records full returned bytes
plus the entire child context before release. The observer cannot substitute
a syscall or HIA result. The three journals use HINFJR01, HBRDJR01 and HMDTJR01
with the original 128-byte common header; event15 is the outer complete nested
context. Every event8 fixed capability notification receives only zero ACK.

## Private binary carrier

HIFXFQ01: little-endian u64 length prefix, then 64-byte header with operation8,
context slot16 (0 or1), payload length24 and zero32..56. Response HIFXFR01 has
return8, payload extent16, state24, generation32, owned count40, output cap48,
work cap56, followed by every payload byte. Parent slots store FD+1, so FD0
is represented without an absence collision.

| Operation | Behavior |
| --- | --- |
| 1 | Invoke the fixed HIA info graph with HINFQ001 |
| 2 / 3 | Release / destroy selected context |
| 4 / 5 / 6 / 7 | Entire context / work / output / input mapping |
| 8 / 9 | Create with full observer / null observer |
| 10 | Fixture opens a parent directory from a NUL-terminated fixture path |
| 11 | Full process orphan pool and every complete record page |
| 12 | Fixture closes its held parent |
| 13 | Actual qualified path_error on the current nested exception |
| 14 | Actual fstat of the still-held parent |
| 15 | Complete fingerprint and metadata child contexts |
| 16 | Actually close parent but retain its numeric input for refusal cases |
| 17 | Move only the control pipe away from FD0, then close stdin's old slot |
| 18 | Arm one real kernel fstat failure at info regular's first stat |
| 19 | Actual native ORPHAN_OWNED refusal for a non-owned fixed token |
| 20 | Actual forked-PID refusal of the same process orphan pool |

Operation17 duplicates only the carrier pipe, never a borrowed directory or
file. Calling it before or after opening the parent makes real parent-FD0 or
info-file-FD0 cases possible with the same production capability.

Operation18 is a fixture effect, not a replacement response. Once the actual
info owner requests its initial regular fstat, the observed fixture installs
PR_SET_NO_NEW_PRIVS and a real seccomp BPF filter. The filter makes actual
fstat/newfstatat of that just-opened FD fail with kernel EIO, and leaves all
other calls allowed. The original reference must install the same actual
kernel restriction at the corresponding original fstat. No fake stat bytes
or errno may resume the owner. The filter remains until OS process exit.

Orphan snapshot HOPSN001 contains a 32-byte header (pool address, record count,
page count), all 4096 pool bytes and every full 4096 record page in link order.
Reads occur only while the producer is quiescent. The shared primitive retains
its guard pages, PID admission and futex; no reset/close API exists.

Operation13 keeps the info output loan alive, passes its unchanged nested
HBRDS001/HMDSR001 frame to path_error f0 with 12288 work bytes, and
returns the entire UTF-8 diagnostic with no newline. HIFER001 records all
formatter input, work/output before, work/output after and actual byte count.
No nested format field is reconstructed by the fixture. This composition
must still compare actual diagnostic text against the original interpreter.

The full runtime, Remote/SSH, path policy, public route, Scope/cache effects
and async lifecycle remain outside this private build qualification.

Owned lookup rejects negative/u64-out-of-int-range FD words and an empty ledger before comparing any slot, so the -1 empty-slot sentinel cannot be selected as an owned token. FD 0 remains an admissible live token.

## Qualified dependency successor

This candidate links read67 from final 8bb4e020 / production 6ba1cbe2, and the single final formatter34 from 96a3eccc / production 2464624e. The original info40 controller, its complete HIA source and private request/response ABI are unchanged. Info supports its existing info operation only; no mode4 is added. Fingerprint remains read67 HBRDFD01 mode2.

The sole production info-boundary edit passes its already validated shared pool at context+376 in rdx to binary_read_body_create. Thus the outer info owner and every fingerprint child use the same process-wide HPORP001 pool. The child's own initial-regular-fstat failure transfers its actual owned file FD to that same pool; no context release/destroy or ordinary EOF closes an orphan. Baseline read source remains solely the original source-author helper provenance and is not a packed production image.

Private fixture command21, with no payload, arms a real seccomp EIO at the fingerprint child's first regular fstat (HBRDCI01, operation2, workspace phase25). Existing command18 continues to select the outer info first regular fstat (HINFCI01, phase13). Both wait for the same zero ACK and execute the original syscall against the installed kernel filter. All prior commands, full journals and output fields remain unchanged. Only the final formatter34 is packed; its generated module text remains literal_error and its production filename is native/path_error.hepta. This source/build checkpoint makes no new actual composed-application claim.
