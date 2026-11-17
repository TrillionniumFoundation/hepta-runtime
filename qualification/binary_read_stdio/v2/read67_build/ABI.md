# Fixed HIA binary read stdio helper

This package builds one production ELF and one observed qualification ELF. It executes no
application request. Four final qualified HIA images implement read67, binary codec,
stat version and formatter34. The final orphan-aware borrowed-directory body library
owns native memory, descriptors and raw OS acknowledgements. The new mechanical entry
owns stdin/stdout/stderr and process exit. Every image is freshly compiled by pinned B3,
then linked and packed by the actual HIA linker/packer.

The input is exactly one HBRDQ001 read start packet through stdin, terminated by EOF:
at least 96 bytes, command 1 at +8, sequence 0 at +16, mode 1 at +24. The existing HIA
body validates every remaining reserved field, payload extent, UTF-8 and read request.
No JSON input, argv value or packet can select a descriptor, code pointer, callback,
fingerprint mode, private-read mode, or borrowed-parent entry. The fixed internal wire
is for an owning controller, after named-host operator and configured-root admission.
This build does not implement or qualify that controller or an SSH transport.

For a completed HIA read success, stdout receives the entire returned JSON payload and
one newline, then exit 0. For a completed HIA error, the complete HBRDS001 error packet
is borrowed by the qualified HIA formatter. Stderr receives its entire UTF-8 diagnostic
and one newline, then exit 1. A malformed private wire or an internal native transport
failure exits 111. Successful JSON is an internal compact serialization; the original
public binary caller subsequently parses JSON and serializes the Value. This build
does not claim a comparison of raw Python helper JSON whitespace or public RPC results.

The body borrow stays live throughout formatter calls and output publication. Only the
formatter output buffer grows on its capacity result; no file read is repeated. Its
workspace has exactly 12,288 bytes plus an inaccessible guard page. All native mappings
have guard pages. The read body context is released and destroyed after publication,
and helper input/formatter/control mappings are explicitly retired before ordinary exit.

The observed image is selected only at build time. It requires inherited FD 3, FD 4 and the fixed lifecycle ACK pipe FD 5.
FD 3 receives the unchanged complete HBRDJR01 body/codec/stat/OS journal. FD 4 receives
HBRFJR01 records with a 64-byte header: magic, event, formatter call ordinal, actual
u64 return (zero before the call), full span size, exact input length, full output
capacity and full workspace capacity. Events 1/2/3/4/5 are input, workspace before,
output before, output after and workspace after. All owned bytes follow each header.
The production image excludes both journal routines and always creates an observer-free
body context. An input request cannot enable observation.

The fixed build records both complete assembler sources and relocatable objects,
requires no relocations, retains all compiler/linker/packer buffers, and verifies each
packed instruction and image displacement under a reader that rejects execution.
Original/native helper requests, output/error equivalence, FIFO interruption, SSH
direct/observation-pool custody, asynchronous cancel/Drop and public SDK routing remain
unqualified until their separately frozen actual domains complete.

## Explicit read67 shared-pool successor

This source binds read67 final 8bb4e020 (production 6ba1cbe2) and formatter34 final
96a3eccc (production 2464624e). Exactly one HPORP001 pool is created by the process
owner after the fixed outer header admission. The driver stores it at +112 and
passes it as the mandatory rdx third argument to binary_read_body_create.
All original stdout/stderr/exit framing, body loan and formatter growth rules remain.
The pool and every orphan record survive body release, body destruction and helper
arena retirement. Whole OS process exit is their only final reclamation.

The sole diagnostic source is native/path_error.hepta (generated module name
literal_error). HBRDS001 named0/1 remains the existing private error wire.
No expanded metadata/error input is newly admitted by this stdio entry.

## Observed lifecycle records, absent from production

The observed image additionally writes HBRLJR01 records to FD3, after all output
publication. Each 64-byte header is magic0, event8, full span length16, actual span
pointer24, shared pool pointer32, auxiliary40, and two zero words48/56.
Event1 carries all 4096 bytes of the completed body context before release;
event2 carries all 4096 bytes after release. After body destroy and retirement of
input, formatter-output and formatter-work arenas, event3 carries the full
4096-byte shared pool with auxiliary=record count; each event4 carries the next
complete 4096-byte record page with auxiliary=zero-based page ordinal.
The entire page list and final null link are checked. Event5 has an empty span,
zero span pointer, auxiliary=record count and denotes the live pre-exit boundary.
Only then does the observed helper read exactly eight zero bytes from FD5.
The observer cannot replace any effect or HIA result. The production conditional
contains no lifecycle routine, no FD5 requirement and no final ACK wait.

The harness may inspect live /proc FD and mapping custody at event5, including
orphan descriptors after all application contexts and helper arenas have retired.
The driver mapping itself and process-pool mappings remain until the ACK; the driver
then retires and exits with the original success/error status. These records
establish a new private observation surface that still requires actual runtime
qualification. They do not make an EIO injection or a public transport command.
