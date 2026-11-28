# Complete audit hot collection, private ABI 1

This actor consumes an already admitted, retained hot-directory lease under
the real global audit store guard. It owns complete member enumeration,
staging cleanup before any Record reads, Record-limit enforcement, and
ordering by full unsigned 128-bit timestamp then request ID. It delegates
actual Record and staging policy to the fixed Record I/O HIA actor.

Input is 24 bytes: `HRAHOT01`, u64 512, u64 zero. Output is `HRAHOTR1`,
a 64-byte header plus 256-byte rows. Diagnostic/errno/count/total are at
8/16/24/32; remaining header words are zero. Row layout is exactly the
qualified Page ABI: ID 0, owner 64, zero-padded tool at 128, tool length 192,
state 200, timestamp low/high 208/216, elapsed-present/value 224/232,
active 240 (zero here), reserved 248 (zero).
Workspace is 532,480 bytes; output is 131,136 bytes. Terminal replay is
refused. Malformed input and short capacity produce the usual flat ABI codes.

The original 544-member directory bound is checked during full enumeration
before cleanup; the original 512-record bound is checked before each read.
Every directory name is decoded as UTF-8 before filtering. All leading-dot
members are then processed as staging names before any non-dot Record.
A directory scan uses its own newly opened description and duplicated
fdopendir-equivalent handle, so the caller's current seek position is irrelevant.
Both scan handles close before the first child call.

Private actions use `HRAHAS01` at workspace 256 with the same twelve-word
sequence/shadow/ack format as the I/O actor. Kinds 1/2/6/7/8/9/10 are the
closed scan operations described there; kind 100 invokes the exact fixed
Record I/O image with input at 524288 and output at 525312. Only logical
slots 4 and 5 are owned by this actor; directory slot 0 is borrowed.
Child results are typed and bounded before consumption. Errors do not yield
partial successful rows. Diagnostics retain I/O codes, with 28 for excessive
directory members and 29 for unexpected non-staging entries or excess records.

Forty actual original-versus-native filesystem scenarios passed, including
ascending/descending sets through 512/513, all original refusal categories,
staging-before-bad-record behavior, a pre-seeked input directory, full u128
ordering, and 512+32/512+33/544/545 member boundaries. All output fields and
full post-operation directory snapshots are compared. The exact original
seventeen-function/type blocks and locked dependency graph remain an independent
Rust oracle. Python supplies only qualification effects and calls actual
HIA Hot, I/O and Record images; public history/archive routing and the final
native syscall engine are separately qualified.
