# Fixed HIA binary read stdio helper

This package builds one production ELF and one observed qualification ELF. It executes no
application request. Four unchanged HIA images implement the read body, binary codec,
stat version and exact error renderer. The unchanged borrowed-directory body library
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

The observed image is selected only at build time. It requires inherited FD 3 and FD 4.
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
