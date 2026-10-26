# A49 phase diagnostic: fixed warmup failed; measurement never started

**A49 returned a terminal failed report before its measurement phase.** Its
one fixed `request_archive` warmup exceeded the product deadline. The frozen
policy required that warmup to succeed and allowed no readiness retry, so all
20 planned measured calls and all eight waves remain explicitly unexecuted.
`complete=false`, `diagnostic_complete=false` and `controller_completed=false`
are preserved. There is no measured throughput or C1/C4 regression result.

The run used the already qualified A48 ELF, SHA-256
`252cb58e08559d6cc68a5db19008c20ec858f7693a44ae353e60bbda81a2b386`,
with the existing opt-in `HEPTA_ARCHIVE_INDEX_TRACE=1`. It selected the original
controller 1 / arm B plan, without starting another arm. This instrumentation
changes timing conditions; this is a separate diagnostic, not a replacement
for the completed failed A48 comparison.

## Complete result inventory

The run spans `2026-10-26T05:27:28.464752+00:00` to
`2026-10-26T05:29:47.345414+00:00` (138.891436 seconds). All setup calls below
were written once and received their original response; none was retried.

| Call | Result | Response elapsed ms |
|---|---|---:|
| Native `host_list` seed | Success | 23.016906 |
| `usage_stats` index kickoff | Product total deadline | 3003.540215 |
| Fixed `request_archive(limit=1)` warmup | Product total deadline | 3007.982044 |

After the kickoff, the prescribed 60-second idle lasted 60.000268 seconds,
with zero readiness polls or queries. The one warmup failure then stopped
admission to measurement. C1 has **0 attempted, 4 unexecuted**; C4 has
**0 attempted, 16 unexecuted**. These are not 20 measured product failures,
and zero successful measurements cannot be converted into a throughput rate.
The exact error for both failed setup calls is retained in the original report
and [summary.json](summary.json), along with all 20 slot rows and eight waves.

## What the retained trace actually shows

Two existing `SteadyTrace` rows were captured after original child reap. The
independent review matched their raw line hashes (including the original LF),
line numbers, byte offsets and all parsed fields against the unchanged
631-byte stderr. Parsing produced no errors.

| Existing stage | Elapsed µs | Snapshot read µs | Store lock wait µs | Outcome |
|---|---:|---:|---:|---|
| `quiet_seal` | 145,848 | 0 | 0 | sealed |
| `metadata_drain` | 2,998,812 | 2,998,759 | 0 | error_or_unwind |

The metadata event spent almost all its recorded elapsed time in the snapshot
read stage. That identifies the recorded stage to investigate. It does not
identify the channel implementation as the sole cause of the warmup failure.
The existing tracer emits only durations above 100 ms, spans setup, idle and
background work as well as shutdown, and carries no RPC or cohort identifier.
No C1/C4 wave ran. A missing trace is not proof of zero work, and the zero lock
wait in this one row is not proof that all work was free of lock contention.
The rows cannot be summed into disjoint workload time or assigned to individual
RPCs from these fields.

## I/O conditions limit causal interpretation

| Original whole-life wait4 observation | Input blocks | Major faults |
|---|---:|---:|
| A49 diagnostic, A48 ELF | 563,976 | 91 |
| A48 formal comparison, candidate controller 1 | 16 | 0 |
| A48 formal comparison, candidate controller 2 | 24 | 1 |

These actual counters show materially different observed I/O conditions. They
cover the original process's whole lifetime and do not locate the I/O within
the warmup, prove a particular cache state, or isolate channel overhead.
The A49 warmup failure therefore cannot by itself establish that batching the
channel will solve the deadline. A50's bounded batching is a separate candidate
that still requires its own qualification and unchanged formal correctness and
resource gates.

A49's original wait4 reports 6.643218 s user CPU plus 10.492502 s system CPU
(17.135720 s total), peak RSS 46,640 KiB, and 93,217 voluntary context switches.
These include initialization, seed, synthetic fixture exposure, kickoff, idle,
warmup, final verification, remaining work and shutdown. They are not pure
query CPU or steady-state memory measurements. The diagnostic retains the
original mixed fixture: 65,536 archive records, 512 hot records, one real
native seed and synthetic remaining archive entries; it makes no native
admission-throughput or power-loss durability claim.

## Cleanup, integrity and publication scope

The original owned controller was reaped with exit code 0 after stdin EOF;
raw stdout EOF was captured and shutdown/protocol error lists are empty.
The report records unchanged original fixture and qualified inputs, clear
before/after host gates and a clear disk gate. These cleanup and integrity
records do not convert the failed diagnostic into a completed measurement.
The review checks the locally captured report bodies; it does not claim a new
independent remote read of wire files, the entire fixture, source or ELF.

All four raw bodies were reviewed for private keys, tokens, credentials and
unrelated host inventories. No publication blocker was found. The only
captured environment is the owned controller's six nonsecret settings;
fixture-native hex decodes to its own nonsecret seed record. Owned-task,
original custody and synthetic identifiers can remain. Raw files were not
edited, and no remote action or workload was performed by this review.

| Original artifact | Bytes | SHA-256 |
|---|---:|---|
| report.json | 53,651 | `a50e218f891bb39f5dc1b4aada44d64d4781215ff0d0901399d9247c54fb3b9a` |
| steady-trace.json | 1,992 | `7d6c5a7b1a5a18af348562467b064340d4ff9b341cf78031ab801b75abf1eb28` |
| stderr.log | 631 | `57c33a6c773148cb1dcf78296a3d4c8b7feed3b6cf70463e232ef6500cff35f1` |
| protocol.original.json | 12,631 | `542a5ff01d2a580d1fd50b369fae39e79fd6ac2d8d76e4bcf1e18ff4ddcae52d` |

The prior A48 large report remains separate and unchanged at SHA-256
`8c0377e52d930d93597f7b4e551d68101a29bffe6dd9aaa3d9bcdf22a036215f`.
A49 establishes neither performance adoption nor an exhausted optimization
limit, and none of its observations are pooled into that failed comparison.
