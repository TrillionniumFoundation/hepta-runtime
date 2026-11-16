# Private task pump and observation boundary

This candidate keeps the standard public stdin/stdout interface and one actual
connection per process. It is a development graph. Full public, asynchronous,
HTTP and all-handler qualification remain false. The merged frontend has a
Batch branch, but this graph does not install slots 47–52 or advertise Batch.

## Ownership and pending storage

The fixed extra table has 59 entries, at engine offset 8192 in a 16384-byte
engine. Authority is 56, the verified packed Bellman capability is 57, and the
current SDK request-task registry is 58. Existing slots and +400/+408 Text,
+416/+424 reserved Batch, +432 authority and +440/+448 worker fields retain
their meanings. No public JSON selects these slots or addresses.

A pending request retains its original input, the entire slot 18 descriptor,
its entire continuation, actual workspace/output mappings, private SDK
generation and fixed engine identity. Detach clears slot 18's mapping words,
continuation and ownership bits. Restore requires the original fixed entry,
empty target storage and the same engine before transferring all ownership.

The frontend returns exactly 64 bytes of `HRCMFR02` kind 4. It retains phase 97,
record 1280 `[HBLFRS01,tag,job,0,0,sequence,0,0]` and the initially empty control
at 1344. The host supplies only `[HBLFRQ01,2/3,tag,job,sequence,0,0,0]` from its
owned current CALL. Worker READY borrows are copied in full and actually
released before any later port call or frontend resumption.

## Cancellation and transport closure

Normal `notifications/cancelled` goes through G1 and the HIA registry. It removes
the SDK ID map entry and marks the context cancelled. It does not drop the
Bellman handler future. The retained handler resumes with command 2 and its
eventual wire is accepted or discarded by the actual SDK map rule.

Command 3 is limited to destruction of the retained handler future after actual
stdout closure. EOF first drains previously started sends and then queued
responses, retaining the actual five-second deadline. A timed-out drain does
not abort older main-loop send futures: the writer lock queue must settle before
close. A send owned by the inline drain has its own cancellation lifetime.
Positive OS writes alone advance publisher acknowledgements; an EAGAIN retains
the current publisher mappings and borrowed output. The final SDK SEND_ACK is
given only after the whole response plus newline settles, or actual failure.

Registry 58 owns this asynchronous close policy. Historical shutdown owner 53
is retained exactly for its original profile; the pump does not feed it invented
empty counts. SDK private storage generations are not a stronger ID map policy:
the current SDK removes by typed ID. The qualifier does not exercise overlapping
duplicate IDs as a separate risk scenario.

## Fixed fixture descriptors

Production opens `/dev/null` for the worker journal and owns that descriptor.
It does not select descriptor 3 or 4. The independently built
`--private-pump-fixture` entry instead takes a caller-owned, already open,
writable journal on **FD3**, checked with the actual `fcntl` operations. It
keeps FD3 valid through worker drain and port destruction, and never closes it.

The separately built `--private-pump-fixture --private-pump-trace` entry also
requires a caller-owned, already open, writable **FD4** for the host observations
below. The journal-only fixture never probes FD4. Required fixture descriptors
are checked at raw process entry before any configuration/owner file opens,
then checked again before installation. Missing descriptors cannot accidentally
select a later owner file. Neither descriptor is selected by JSON, environment
variables or an input command. The fixture parent supplies ordinary owned files;
production requests cannot acquire this capability. No observer result selects
an SDK decision or acknowledges a worker/write action.

The stdio O_NONBLOCK changes are restored on ordinary closure. The failure path
also attempts restoration for every descriptor whose flags were actually set.
This does not claim complete abnormal-process or arbitrary shared-FD semantics.

## FD4 records

Each record has a 128-byte little-endian u64 header, then exact spans A, B and C:

| Offset | Value |
| --- | --- |
| 0 | `HPTREV01` |
| 8 | Entire record extent: 128 + A + B + C |
| 16 | Monotonic observation sequence |
| 24 | Event number |
| 32, 40 | Host node generation and SDK request generation, or zero |
| 48, 56 | Actual private node and engine addresses |
| 64 | Actual monotonic nanoseconds |
| 72, 80, 88 | Exact A, B and C byte lengths |
| 96 | Host phase: running 0, draining 1, closing 2, transport closed 3, worker reap 4 |
| 104 | Node's last send-turn result, or zero |
| 112 | Observed registry/publisher arena capacity when relevant, otherwise zero |
| 120 | Reserved zero |

| Event | A | B | C |
| --- | --- | --- | --- |
| 1 accepted input | Entire original input | First 512 bytes of owned node | Empty |
| 2 registry turn | Entire `HRTKRQ02` input | Entire 192-byte `HRTKRS02` | Entire committed registry extent |
| 3 detached frontend | Node prefix 512 | Frontend workspace prefix 1408 | Entire returned frontend frame |
| 4 restored frontend | Node prefix 512 | Frontend workspace prefix 1408, including actual control | Entire retained frontend frame |
| 5 released READY | Entire copied READY frame | Original complete 32-byte borrow descriptor | Empty |
| 6 send turn | Node prefix 512 | Suspended publisher transport prefix 256, otherwise empty | Suspended publisher workspace prefix 640, otherwise empty |
| 7 retiring node | Node prefix 512 | Frontend workspace prefix 1408 | Entire returned frontend frame |
| 8 actual stdout close | Current registry reply 192 | Empty | Empty |

Event 2 captures the complete initialized registry extent returned at reply
offset 96, checked against its actual capacity and workspace header offset 72.
It does not describe unused allocation capacity as captured bytes. Events 3,
4, 6 and 7 deliberately identify bounded diagnostic prefixes, not entire large
frontend or publisher arenas. The complete private slot descriptor and
continuation are in the 512-byte node prefix, at offsets 88 and 152. Node offset
456 stores the observed result; 464 identifies publisher return (1), direct
write syscall (2), or newline syscall (3). Publisher return codes are not
misreported as byte counts. Full public wire and worker journals are separate
artifacts, and all three must be admitted together for a public graph claim.

All these source contracts precede the new observation tests. The two old
production engineering smokes did not record FD3/FD4 and remain separate.
