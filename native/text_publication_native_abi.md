# Text publication native Linux boundary

This boundary invokes the unchanged HIA text publication owner, binary codec,
and errno renderer. It contains no host implementation of publication policy,
path interpretation, identity checks, checksum semantics, or response rendering.
The complete runtime graph has three fixed entries. The standalone executable
is statically packed by HIA and needs neither Rust, Python, nor libc at runtime.
The public MCP route is not replaced by this private boundary.

## Callable entry points

`text_publication_create(rdi = table[3])` returns an owned engine address or a
negative Linux errno in `rax`. Entries are text publication, binary codec, and
view error, in that order. The caller must retain these executable images until
engine destruction. Partial initialization failure unmaps all successful prior
allocations and preserves the original errno.

`text_publication_call(rdi = engine, rsi = borrowed input, rdx = input extent)`
returns the original unsigned HIA code in `eax`, an engine-owned output pointer
in `rdx`, and its complete extent in `rcx`. The input is copied before invoking
HIA. The output borrow ends at the next call or destruction. One execution chain
may use an engine at a time; callers must not race calls with destruction. A
reentrant call is rejected without clearing the active invocation's busy flag.
The four callable assembly sources exclude the standalone fixture entry point.

`text_publication_destroy(rdi = engine)` consumes the engine and returns zero or
the first negative cleanup errno. Active calls return `-EBUSY`. Every owned FD
is consumed once before Linux `close`; EINTR does not cause a second close.
All four owned mappings and the engine mapping are unmapped. The callable entry
does not change process signal dispositions or external FD flags.

Workspace and output grow only on the corresponding original HIA return and
required extent. Growth preserves all prior bytes. Allocation failure preserves
the previous mapping and completed HIA effects for a later retry. In particular,
output allocation after publication cannot repeat the completed filesystem work.
There is no adapter-level cumulative byte or chunk-count quota. The original HIA
operation limits, LP64 representation, and real memory/IO resources still apply.

## Standalone stream

Input consists of repeated little-endian `u64(frame_extent)` followed by the
complete original `HTXTQ001` frame. Its original header is magic plus seven u64
values: operation, mode, path length, text length, expected length, generation,
and zero; the payload is path, expected value, and text. Operation 1 uses zero
generation. Operation 2 is the original explicit terminal DROP and supplies its
generation with all other fields zero. EOF is transport shutdown, not public
request cancellation.

Output consists of `u64(record_extent)`, then `HTXTER01` and seven u64 values:
original HIA code, generation, effect sequence, HIA payload length, live FD count,
HIA phase, and zero. The complete HIA payload follows. Error codes at or above
`0xffff0000` have no payload. Explicit DROP preserves the original owner rules.

A clean boundary EOF exits zero. A partial length header or partial frame exits
74. A malformed command line exits 64; a violated boundary contract exits 70;
an unrecoverable transport allocation exits 71. The standalone entry ignores
SIGPIPE so it can retire private resources after EPIPE. It does not change
stdin/stdout open-file-description flags. Stream EINTR retries and EAGAIN polling
are mechanical; filesystem errors remain owned by the HIA state machine.

## Effect observations and deterministic filesystem races

Default execution writes no diagnostic bytes. `--trace` emits one complete
256-byte record to stderr after each real effect and before HIA consumes its
completion. The header is `HTXTEF01` plus seven u64 values: generation, sequence,
kind, phase, raw Linux return, workspace capacity, zero. The next 128 bytes are
the exact HIA `HTXTFX01` effect/completion. The final 64 bytes contain four pairs
of signed FD and opening sequence. An unowned slot is exactly `(-1, 0)`.

The raw return is a two's-complement signed Linux result: a failed syscall is
`-errno`, and a successful open preserves the actual FD. HIA's normalized open
completion is separate. Internal child effects 11 and 19 report the actual
native child helper result, not a fabricated syscall.

`--sync` adds an unframed 24-byte acknowledgment on stdin after each receipt:
`HTXTACK1` plus the observed generation and sequence. Only those exact values
permit continuation. An observer can perform a real filesystem mutation before
acknowledging; it cannot replace the syscall return, select a child, or inject
business output. Malformed acknowledgment or EOF poisons this engine and closes
its owned descriptors. The standalone process then reports failure and exits.
This observation channel is a qualification facility, not an MCP protocol.

The fixed kinds are: 1 root open; 2 parent openat; 3 serial close; 4 flock;
5 lstat via newfstatat; 6 source open; 7 fstat; 8 geteuid; 9 flistxattr;
10 read; 11 native streaming SHA-256; 12 getrandom; 13 exclusive stage open;
14 fchmod; 15 write; 16 fsync; 17 renameat2; 18 unlinkat; 19 native errno text.
Only four private FD slots exist. Every syscall frame is checked against the
fixed kind, current generation/sequence, actual owned spans, and FD opening
serial. The HIA owner decides retries, partial I/O, cleanup, and final results.

## Qualification scope

Build evidence includes all source and image bytes, real assembler commands and
complete streams, the zero-relocation check, HIA packer input/output, and the
actual ELF. Native qualification precedes an independent original comparison.
Private resource and corrupted-state controls are counted separately from real
filesystem cases; they are never new original semantics or public-route proof.
