# Audit History composition, private ABI 1

The HIA owner preserves the complete original history_at order from fixed
Runtime commit abc9ecb95ee9538518ec3f36c47b881974107021. It composes the actual
Root, Hot, Record I/O, Page, FIFO and Activity owners. It does not substitute the
result-store archive or JobRecord protocols for the audit Record domain.

## Request and response

HRAHIS01 is a 192-byte header followed by the actual installed configuration
root's raw bytes. At offsets 8, 16 and 24 are the limit, cursor-present flag and
path length. Bytes 32..63 are zero. Owner and optional cursor occupy 64..127
and 128..191. The mechanical public parameter layer must preserve the original
typed JSON validation before supplying this private frame.

Output HRAHYR01 has a 32-byte header: diagnostic at 8, JSON length at 16,
whole length at 24, then the exact original JSON bytes when successful.

| Diagnostic | Outcome |
| --- | --- |
| 0 | Exact successful history JSON |
| 1 | Ordinary private metadata unavailable/refused |
| 2 | Original expired or other-session cursor error |
| 3 | Original release-profile numeric JSON conversion panic; fatal, no public JSON response |

Diagnostic 3 is deliberately not an ordinary redacted error. The complete
original dependency graph uses panic=abort and serde_json without arbitrary
precision. Actual selected accepted_unix_ms values above u64::MAX cause
SIGABRT at original request_audit.rs:2221. The same record is harmless when not
selected for this session/page. Final runtime dispatch must preserve that
fatal distinction; this component does not claim the public termination path
is already installed.

The actor requires 65568 output bytes and workspace of at least
1048608 + twice the input length. These are declared mechanical buffers; the
original retained-record limit remains 512 and the page limit remains 32.

## Closed private actions

Every yield is 0xffffffe0 with a twelve-word HRAHYA01 action at workspace 256.
The first eight words are magic, sequence, kind, zero slot, input span, input
length, output span and output capacity. The last four words are acknowledgment
sequence, result, errno and zero. A separate snapshot of all original action
arguments and the complete public input is checked on every resumption.

| Kind | Required capability or child |
| --- | --- |
| 110 | Acquire the one runtime-global FIFO writer lease |
| 101 | Root operation 2, returning an actually held hot-directory capability |
| 102 | Complete Hot capture using that same descriptor |
| 103 | Activity query for one selected unknown request |
| 104 | Fixed Page child with the complete validated rows |
| 105 | Close the actual held directory exactly once |
| 111 | Release the writer after directory close |

Owner and parameter checks precede the store lock. The complete hot scan and
record validation precede owner filtering and cursor lookup. Only selected
unknown rows query ACTIVE; their original order is preserved. A selected high
u128 timestamp fails after that row's activity query and before any later row.
All cleanup paths close the held directory before releasing the writer lease.
A completed actor refuses replay.

## Actual evidence and remaining integration

The exact complete original Cargo.toml, Cargo.lock, default features and release
profile were built with Rust 1.95.0, --release --locked --offline and two jobs.
All 360 locked crate archives were hashed; all 11389 source members of the
309 actually compiled registry packages were checked against those archives.
The original 5394-file project, 356 compiler-artifact messages and 653 output
artifacts were bound before and after. The initial collector's missing registry
check is retained as a failed provenance boundary and corrected by the separate
complete source comparison.

The first actual 70-case filesystem comparison had 63 matches and seven fatal
classification differences. After the two explicit HIA terminal changes, all
same 70 cases matched, including full filesystem state and descriptor counts.
Twenty-two additional controls exercised retained-directory path replacement,
two actual threads sharing one HIA FIFO state, seven known synchronous
cancellation points, twelve malformed ACK fields and late input mutation.

The qualification uses real Python Condition/Lock only as its kernel
synchronization harness, and fixed native calls through a sealed engine emitted
by HIA. The original public asynchronous transport, installed native
synchronization and full ten-handler Durable Requests routing remain separate
integration gates. No unknown external operation is replayed.
