# Shell process native fixture

This fixture executes the HIA process owner through a private Linux x86-64
syscall boundary. It is development qualification, not production MCP dispatch.
The HIA owner chooses environment construction, PATH candidates, child setup
order, the foreground deadline, promotion, cancellation and shutdown. The native
boundary validates owned handles and executes the requested fixed kernel
operation. The complete effect contract is in shell_process_abi.md.

## Build and evidence

Run the existing pinned Hepta compiler through:

    python3 scripts/hia_native_shell_process_build.py \
      --hepta /absolute/Hepta \
      --build /absolute/new-build-directory

The successful top manifest is new-build-directory/shell-process/manifest.json.
Both owner_manifest and packer_manifest are relative to new-build-directory,
which is the top manifest's parent directory's parent. They are not relative
to the shell-process directory.

The build seals all four compiled or assembled inputs: shell_process.hepta,
shell_process_packer.hepta, shell_process_layout.json and shell_process_adapter.S.
It also seals the ABI, this document and the Python build/admission producers.
NativeBuild retains the compiler provenance and native component inputs.
The final ELF contains the actual admitted HIA owner image after the fixed
adapter; there is no libc interpreter, Python runtime or Rust fallback.

build-evidence.json pins the retained inputs, adapter object and machine bytes,
the actual as and objcopy executions and seven actual HIA packer entries.
Tool receipts contain resolved executable path and before/after binary SHA256,
argv, cwd, environment, PID, monotonic start/end, duration, deadline, exit status
and complete stdout and stderr. A failed tool execution retains its receipt.

Each packer entry retains the full before/after input, output and workspace and
both sixteen-byte guards around each span. The success entry additionally checks
37 output tail bytes. Five malformed-input cases must return INVALID without
writing output; one undersized-output case must return CAPACITY without writing
output. All cases must preserve the input, workspace and all guard bytes.
Qualification invokes the sealed NativeModule entry using private ctypes arrays;
this development FFI is not included in the emitted executable.

Read existing build evidence without executing the ELF or toolchain:

    python3 scripts/hia_native_shell_process_build.py \
      --verify /absolute/new-build-directory/shell-process/manifest.json

This verifies portable bytes and retained process receipts. It does not claim
to rerun the original process paths or authenticate an external system clock.

## Prepared capture and transport

Start the actual ELF with exactly:

    shell-process.elf --process-fixture OWNED_EMPTY_CAPTURE_DIRECTORY

The fixture creates stdout.log and stderr.log as the semantic capture pair.
effects.bin is a third, fixture-only audit file. Its failures make qualification
fail; this audit IO is not part of the original shell API semantics.

The fixture owns the capture token, fixed to 1. It accepts no arbitrary raw FD
or caller-selected PID. Every private directory, capture, audit, null and exec
channel FD is above 2 and close-on-exec. Only dup2 targets 0, 1 and 2 survive the
child exec. Unrelated inherited descriptors are not silently closed.

Input is a little-endian u64 byte length followed by exactly one HSHPRQ01 frame.
The initial frame is:

| Byte offset | Value |
| --- | --- |
| 0 | Eight bytes HSHPRQ01 |
| 8 | u64 operation 1 |
| 16 | u64 prepared capture token 1 |
| 24 | u64 command length |
| 32 | u64 cwd length |
| 40 | UTF-8 command bytes, then raw Unix cwd bytes |

Operations 2 (continue), 3 (cancel) and 4 (shutdown) have exactly the forty-byte
header with both lengths zero. HIA copies the initial command and cwd before
later controls can replace input. An EOF requests shutdown once.

A reply is u64 returned value, u64 byte extent, then exactly that many body
bytes. An event reply has value and extent 96 and a HSHPRR01 event body. A final
retirement reply has both fields zero. Typed refusals have extent zero.
Events are defined by the ABI, including foreground completion, promotion,
background completion, cancellation acknowledgement and shutdown acknowledgement.

The fixture continues the same HIA arena after events. It does not block child
wait/reap on a partial later input frame or on stdout backpressure. Replies are
queued privately. After child custody has ended, it may wait for the output sink
to drain. The optional pidfd is only a readiness optimization; the fallback is
bounded polling. Neither path changes the HIA deadline or wait-before-timeout
ordering. The inherited child signal mask and SIGCHLD disposition are not reset.

## Audit records

effects.bin consists of 128-byte records and exactly one final 128-byte footer.
Each normal record is sixteen little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | Eight-byte magic HSHPRTR1 |
| 1 | Role: 0 before fork, 1 parent, 2 child |
| 2 | Recording process PID |
| 3 | Owned child token |
| 4 | HIA effect sequence in that process |
| 5 | Effect action |
| 6, 7, 8 | Effect arguments 0, 1, 2 |
| 9 | Completion result |
| 10 | Completion errno |
| 11 | Completion auxiliary result |
| 12 | Owned child PID, zero before fork |
| 13 | Ownership flags |
| 14 | Phase: 0 issued, 1 completed |
| 15 | Primary raw syscall result, or zero when no syscall occurred |

Ownership flags are bit 0 for child custody, bit 1 for tracker membership,
bit 2 for closed setup descriptors, and bits 3..4 for handshake observation:
zero unobserved, one exec-channel EOF, two NOEX.

Parent and child append independently. Their records do not establish a total
cross-process action order. The fork has one issued record and two role-specific
completion records. A successful exec has no child completion record; a NOEX
failure is established by the parent's handshake and actual wait.

The footer begins with HSHPAUD1 and then fifteen little-endian u64 values:

| Index after magic | Meaning |
| --- | --- |
| 0, 1 | Parent and child record attempts |
| 2, 3 | Parent and child trace error flags |
| 4, 5 | Parent and child last trace-write raw result |
| 6, 7 | Parent and child contract failure flags |
| 8 | Private child PID still owned |
| 9 | Tracker membership |
| 10 | Cached wait: 0 absent, 1 reaped, 2 ECHILD custody loss |
| 11 | Child PID |
| 12 | EOF observed |
| 13 | Transport IO error raw result |
| 14 | Reserved zero |

Successful qualification checks counts against the actual role records, complete
128-byte writes, zero error/contract/transport flags and zero remaining custody.
A real fork completion must be paired with an actual wait/reap record when the
test claims reaping. ECHILD is custody loss, not proof of reaping.
Original foreground cancellation can retain tracker membership; the native
boundary still refuses to signal a retired or lost PID.

## Failure and scope

Exit 0 means the fixture completed its recorded owner protocol; a command's
nonzero exit or an ordinary spawn error is still a semantic result. Exit 2 is a
typed owner refusal. Other fixture exits are 64 for CLI misuse, 74 for transport
or audit IO failure, 75 for allocation or declared capacity, and 78 for a private
contract violation or emergency containment.

Failure containment may kill and reap only the fixture's still-owned direct
child, and marks the run failed. It cannot create successful qualification.
The external transport driver also binds a child observation to its actual
controller PPID and starttime before failure cleanup. It never adopts a bare
trace PID as authority to signal.

The all-PATH-components-too-long case can return a NOEX payload with errno zero.
NOEX result 1 is distinct from successful channel EOF result 0. The native owner
currently has no libc ambient errno state; exact equivalence with the original
Rust/glibc ambient errno in this no-attempt corner remains an explicit open
contract. Do not promote this fixture to a whole-shell or production closure
claim based on its successful selected tests.
