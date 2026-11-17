# Two actual public sessions in one native process

This is a private fixture, absent from the installed production boundary.
Production source is f8857cbd18b3dedb38718f68822c072053b03233: 530 exact files.
Its actual HIA graph remains 124 runtime images / 69 fixed descriptor slots.

The process owns one configuration, filesystem hub, text hub, publication pool
at hub+216, and Bellman port. Each of two sessions owns its real extra engine,
PM page, request registry58, view cache, workdir, input buffer, descriptor table
and continuation storage. Session0 pipes are inherited7(read)/8(write);
session1 pipes are9(read)/10(write). The fixture duplicates only the selected
session's pipe endpoints onto descriptors0/1 before calling the ordinary pump.
The peer owns the other pipe ends. A dropped reader therefore produces a real
EPIPE, EOF is a real read0, and SEND_ACK follows only actual writes.

FD3, FD4 and FD6 retain complete existing port/host/publication observations.
Fixed blocking Unix stream socketFD5 carries 64-byte HAPFQ001 requests:
sequence@8, operation@16, session0/1@24, payloadLength@32, argument0@40,
argument1@48, reserved0@56. Operations1 drive both sessions for0..1000 actual
milliseconds;2 invokes the actual fixed cache fixture32 with a full HVCACH01
frame;3 observes full state;4 drains the selected already-closed input;5 retires
the one process runtime only after both services have actually detached.
These operations do not choose public methods, child slots, output bytes,
cancellation identities or worker completion.

A HAPFR001 response is128 bytes followed by the actual borrowed cache output,
then the complete4096-byte coordinator and both4096-byte PM pages. Header fields:
sequence8, operation16, session24, zero status32, resultLength40, snapshotBytes48,
observed-job-count56, actual PM phases64/72, pending counts80/88, bytes truly
read96/104, process-runtime-retired112, fixed mappingBytes12288 at120.
Operations3/5 append both complete unchanged27-mapping HXLTR001 snapshots.
All extents come from real descriptors; no pointer fromFD5 is dereferenced.

The complete ordinary line framing loop is retained mechanically, including
16MiB inclusive-LF limit, BOM, CRLF, discarded tail and recovery. EAGAIN returns
to the coordinator instead of blocking the other session. Actual EOF calls the
same registry6 transition. Once the real registry permits close, the unchanged
service teardown executes; its original fixed pipe duplicates are then closed
to expose real peer EOF. The process runtime is closed/reaped once, after both
services retire. State remains observable until the final reply, then actual
owner releases and the original configuration finalizer execute.

An append-only fixture observation at the existing post-HIA frontend boundary
reads the actual PA context's pool/job/engine/tag/stage and trace sequence.
It neither resumes a future nor updates any production owner. At most32 fixture
records are admitted; this is only the frozen input-domain observer bound.
A new source/read gate and actual execution are still required. This private
entry does not qualify public multi-session Bellman READY routing, arbitrary
HTTP sessions, completeSDK or136 handlers.
