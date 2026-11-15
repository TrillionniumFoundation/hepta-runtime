# Native recorded-core worker

This increment adds a Rust decoder for the selected Linux ELF core payload used
by the frozen `rea-agents@6.8.0` recorded-crash helper. It is an internal worker
and a related implementation facility. It does not expose the public
`inspect_recorded_crash` MCP operation or grant complete REA replacement
qualification.

## Reference and source boundary

The behavior reference is the actual published package, not an inferred Git
rebuild. Its `bridge/pwntools/recorded_crash_impl.py` has SHA-256
`8dd89f64d7fa1a218b7def48c02a1e3bddfe8d2a47a2816e2e06441b9d394bb8`.
Its pinned dependencies are pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2.
The reference Python installation used for differential testing is separate from
the original reference install. The actual package source, dependency versions,
installation report and individual input/output bytes are retained in the
qualification evidence.

The Rust branch starts at `f165624f968e6a65f8575c5dddb1d6519d537cfc`. Results
reported for that earlier candidate do not qualify this increment. The new
binary must have its own build, source identity and differential evidence.

## Content semantics

The decoder accepts an immutable captured byte sequence. It interprets ELF64
little-endian `ET_CORE` recordings for x86-64 and AArch64 under the selected
System V/GNU Linux ABI profile. It preserves segment and note ordering,
original source ranges, note owner/descriptor bytes, zero padding and all
recorded threads. Only the exact owner byte sequence `CORE\0` admits the
selected Linux `NT_PRSTATUS` and `NT_SIGINFO` meanings.

Register names, order and source offsets follow the pinned helper dependencies.
`pr_cursig` is signed 16-bit. The selected pwntools `elf_siginfo_64` structure is
32 bytes, with its address member at byte 16; treating it as a generic 128-byte
signal object would change the frozen helper's accepted input domain.

Two pyelftools constructor paths are explicit native admission differences:
noncanonical `PN_XNUM` section-zero types that invoke specialized symbol, hash,
version or dynamic constructors, and `PT_DYNAMIC` segment construction when a
section table is declared. Known specialized-constructor preconditions retain
the reference's early malformed-input errors; remaining constructor paths
return `unsupported-target` rather than silently skipping additional checks.
These inputs remain in the
full differential corpus and count as differences when the reference result
differs; they are not removed from the denominator.

Historical PIDs and addresses remain recorded metadata. The decoder performs no
process lookup, attach, target execution, host pathname resolution, executable
pairing or unwinding. Signal-to-thread association and unrecognized note
semantics remain unknown. A missing field does not establish that it was absent
at the original crash.

## Native frame

The hidden CLI entry is `hepta-runtime rea-recorded-core-worker`. One request is:

1. A four-byte little-endian unsigned JSON-header length, from 1 through 16 KiB.
2. A strict UTF-8 JSON header containing only `schema`, `sha256`, `bytes`,
   `max_file_bytes`, and `max_output_bytes`.
3. Exactly `bytes` captured bytes, followed by EOF.

The frame schema is `hepta.rea.recorded-core-frame.v1`. SHA-256 is lowercase
hexadecimal and is recomputed from the captured input before decoding. No path
is accepted. Input admission is capped at 256 MiB; complete JSON reply admission
is capped at 64 MiB. Both are explicit native bounds, not claims about every
input accepted by the original Python provider.

Successful replies use the native profile and include the complete decoded
`value`, verified snapshot identity and observed resource limits. Format and
unsupported-target failures retain their typed reason and message. Native
protocol, integrity, allocation and budget failures are distinguished. No
partial array is returned as a successful complete result.

The final envelope and newline count toward the reply budget. When a complete
failure reply itself cannot fit, stdout stays empty, a bounded typed diagnostic
is emitted on stderr and the process exits 76. A malformed header has not
admitted any caller budget; its diagnostic uses the fixed bounded error policy.

The worker starts before Tokio initialization, lowers process resource limits,
and applies the existing post-read isolation policy before decoding. CPU limits
do not bound idle reads from an open pipe. The original caller must own the
child, enforce a wall deadline, signal only that owned child/group, reap it and
finish both output pipes. Direct worker tests keep this ownership boundary
explicit.

Linux applies the existing post-read seccomp policy. On macOS the existing
post-read hook is a no-op, so resource limits alone do not establish the Linux
isolation claim. This increment's executed native qualification is identified
by its actual host and binary; it does not establish a cross-platform result.

## Validation and remaining work

The differential corpus invokes the unchanged reference helper and this actual
Runtime worker. Raw fixtures, input frames, stdout/stderr, typed failures,
process exits, source/binary identities and every difference are retained.
Native transport admission and original payload equivalence are reported
separately. Results are populated only from completed runs.

This does not complete the original `recorded_crash.py` request/reply-file and
resource-marker protocol, `PwntoolsRecordedCrashProvider` integration, Evidence
retention and pagination, optional GDB/pwndbg enrichment, session recovery or the
public 229-tool qualification matrix. The historical Python-helper inventory
remains an identity-bound historical observation. The new Rust payload decoder
is a partial migration of that helper until the remaining integration and
behavior boundaries are implemented and independently qualified.

All test inputs in this increment are generated core-format fixtures. No live
target or user crash recording is executed or attached.
