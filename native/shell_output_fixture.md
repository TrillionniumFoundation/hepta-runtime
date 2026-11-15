# Prepared foreground-output fixture

This executable qualifies the HIA foreground file-IO owner. It does not activate
production Shell, create the original job registry, or replace the whole runtime.
The fixed Linux adapter performs only HIA-issued primitives. HIA chooses the
operation order, EINTR retries, read-to-EOF policy, capacity growth, cancellation
continuation, and tagged Results. The separate shell_outcome owner chooses text
and error precedence.

## Invocation and trusted ownership

`shell-output.elf --output-fixture CAPTURE_DIRECTORY [--step-effects] [--interruptible]`

The directory must already exist. The fixture opens it with
O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, creates stdout.log, stderr.log and effects.bin
with O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode0600, and holds both actual writer FDs.
All private FDs are normalized above2 and remain CLOEXEC. Inputs contain only
the minted token1, never paths, arbitrary rawFDs, or PIDs. Semantic open/unlink
operations use the exact prepared full path, preserving ordinary path-following
and path replacement behavior. The held writer is not substituted for a read FD.

The first stdout record is exactly64 bytes, eight little-endian Q words:
HSHOIRD1, token1, actualPID, stdoutWriterFD, stderrWriterFD,
stdoutInode, stderrInode, flags.
flags bit0 is step-effects; bit1 is interruptible.
The fixture has completed two actual fstat custody observations before READY.
Tests must bind its actual /proc identity and writer links before injecting a
fixture-local path change; new inode contents and held old writer contents are
distinct evidence.

The controller writes exactly the40-byte HSHOIQ01 request described in
shell_output_io_abi.md. The normal fixture executes to completion without further
stdin. It is a one-transaction IO fixture; the process-global statx capability
cache and asynchronous multi-arena scheduling belong to the subsequent combined
HIA controller. This synchronous standalone transport does not prove that a
blocked syscall permits another arena to advance.

## Explicit effect scheduling control

With --step-effects, before each primitive the fixture emits64 bytes:
HSHOIGT1, sequence, action, arg0, arg1, arg2,0,0.
It then accepts one40-byte resume/cancel request with the same token/wait fields.
The native HIA entry validates and latches that request while the effect remains
pending; the adapter rechecks the issued sequence/immutable arguments and performs
the primitive exactly once. This enables actual path growth/truncation, rename,
unlink and cancellation at observed boundaries. It does not inject syscall
results. Tests must account for the entire exact stdin and stdout stream.

--interruptible installs an empty SIGUSR1 handler without SA_RESTART. A test may
interrupt an observed blocking read with SIGUSR1 and later release its FIFO peer.
EINTR is the actual Linux return, not a replacement completion. Transport reads
and writes retry EINTR; semantic open/read/close/unlink policy belongs to HIA.

## Completion stream and status

After READY and any gates, the final wire has two Q words:
return_value, extent, followed by extent bytes.
For completed IO return_value=64. The extent is64 plus the complete workspace
loan length. The first64 bytes are HSHOID01, followed by exactly the complete
HSHOUT01 loan when descriptor kind1; quiet cancellation kind2 has no loan.
All lengths are u64; a u32 return does not impose a4GiB raw-log policy.
Read errors remain tagged results and do not make the fixture process fail.

A refusal has its actual owner return and extent0. Exit codes:
0 completed typed IO;2 invalid request;64 usage;74 transport/audit/setup failure;
75 initial capacity/allocation infrastructure refusal;78 private contract failure.
Fatal probe-allocation OOM has actual SIGABRT termination, complete raw stderr,
and a final issued action11 instead of a return frame/footer. It is never a
published Read OutOfMemory result. Complete raw stdout/stderr and the actual exit
code must be retained. A footer
alone does not prove the transport completed. All live owned read/writer FDs are
closed before publishing the potentially large final frame.

## Raw effect audit

effects.bin is fixture-only instrumentation and is not part of original Shell
semantics. No audit failure is converted into a read Result; it makes qualification
fail through exit74. Every ordinary record has128 bytes /16Q followed by payload:
HSHOITR1, sequence, action, phase, actualPID, actualTID, token1, actualFD,
arg0,arg1,arg2, rawSignedSyscallReturnBits, errno, payloadKind, payloadLength,0.

phase0 is issued; phase1 is completed. Each HIA action has one same-sequence
issue/completion pair, in order. Capture ownership observations use sequence0,
action0, phase1, arg0 stream0/1 and actual fstat bytes. Actual HIA result tokens
are reconstructed from action semantics; raw return preserves the true syscall
number or address even when the completion returns an opaque handle/capacity.
A failed syscall has raw bits of -errno and no payload. An open's raw FD may be
normalized above2; the recorded actualFD is the owned resulting FD.

payloadKind1 contains the exact NUL-terminated prepared pathname on open/unlink
issue; kind2 contains every actual successful read byte including a zero-length
EOF record; kind3 is the complete256-byte statx or144-byte x86-64 stat structure.
payloadKind4 contains the complete HIA diagnostic write span on action10 issue.
Other records have payloadKind0 and no payload. Original read and inode evidence
must be derived from these actual bytes, not only from an expected final message.

Final footer is128 bytes /16Q:
HSHOIAU1, actualPID, recordCount, issuedCount, completedCount,
traceError, transportError, readFD, stdoutWriterFD, stderrWriterFD,
exitCode, flags,0,0,0,0.
A normally returned completion requires complete paired records, counters that equal the
parsed records, zero errors/exit code, and all three FD fields equal u64(-1).
Read/unlink errors are still visible in the records. Unlink failure leaves the
fixture-local path intact, exactly as the ignored original discard error does.

## Build and evidence

build_shell_output(hepta, build_root, source_root=ROOT) returns the top manifest.
The actual pinned HIA compiler creates the IO image and the HIA packer image.
Native HIA packer writes the ELF header, exact source-owned adapter bytes and
the owner image; Python does not supply an alternative runtime packer.
GNU as and objcopy run independently against sealed adapter source, and their
complete process receipts plus resulting bytes must match the HIA-packed ELF.
Seven real native packer invocations retain all input/output/workspace bytes,
guards, tail/refusal checks and return values. Ten named input/producer sources
are sealed. The pure reader verifies these arrays and actual source/tool bindings
without invoking any compiler, subprocess, or native image.

## Allocation-failure qualification

The Rust release profile uses panic=abort. The initial Vec try_with_capacity and
main-loop try_reserve failures produce an IO OutOfMemory Result. The32-byte probe
uses infallible extend_from_slice: ENOMEM invokes the fatal allocation hook;
capacity overflow is a fatal release panic. HIA distinguishes these paths.
The adapter's new action10 writes only the admitted HIA span to fixed stderr2;
action11 is the fixed self-abort intrinsic, including the default-signal fallback.
No raw signal target or arbitraryFD is admitted.

The allocation probes apply RLIMIT_AS only to the actually owned fixture PID at
an observed growth gate, using its current VmSize and stable /proc starttime.
They preserve the actual limit before/after, raw ENOMEM, diagnosis, exit signal
and complete still-owned captures before exact retirement. They do not change
an original syscall return. Core dumps are disabled for that fixture alone.
Backtrace-enabled/custom-hook/full Rust panic-location diagnostics remain outside
this standalone fixture's claim; see the IO ABI's explicit diagnostic boundary.
