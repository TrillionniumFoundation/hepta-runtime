# Complete Local Create composition

This private component runs the Local `create_file_spec` body through the same
ordering as the selected original source: source existence, parent selection and
existence, one complete directory-creation worker, exclusive segmented creation,
inline close, canonical cache key, `note_create`, and the original success or
error message. Its HIA caller invokes the existing read, path, mkdir, segmented
write, canonical-key, and ViewCache owners. It does not duplicate those owners.

The standalone transport accepts an eight-byte little-endian frame length and
the following request. All integers are unsigned little-endian 64-bit values.

| Request offset | Meaning |
| --- | --- |
| 0 | `HLCSPQ01` magic |
| 8 | Operation 1 |
| 16 | Context 1 (ViewCache present) or 2 (no cache context) |
| 24 | Raw path byte length |
| 32 | UTF-8 content byte length |
| 40 | Nonzero generation |
| 48, 56 | Zero reserved fields |
| 64 | Complete raw path followed by complete content |

The response has a 32-byte header: `HLCSPR01`, operation 1, result kind
(0 success or 1 original error), and UTF-8 message byte length, followed by the
complete message. Cancellation is reported through the independent observer;
it is not presented as a completed success or original error.

The private continuation frame carries the actual child result back to the
caller. Prepared, queued, running, ready, consumed, closed and reaped states
remain distinct. Cancellation is admitted only at the existing poll boundaries.
Directory creation remains one worker lifetime. The no-context path still
canonicalizes before the original cache helper returns without mutation.

See [the retained protocol and observations](../tests/hia_native/local_create/spec/PROTOCOL.md)
for exact continuation, fixture, cache and owned-trace layouts. The source
component and build helper bind the complete seven-member graph, HIA packer,
mechanical bridge, compiler identity, full packed output and final executable.

## Qualification domain

The five native suites are `test_local_create_spec_build.py`,
`test_local_create_spec_state.py`, `test_local_create_spec_semantics.py`,
`test_local_create_spec_held.py`, and `test_local_create_spec_evidence.py`.
They preserve 20,207 typed calls, 111 caller cases, 266 continuation refusals,
37 actual packer calls, four actual assembler processes, 38 ordinary body cases,
and 15 held-boundary cases. Full response bytes, resulting file bytes, complete
cache observations and the owned syscall/poll records are retained and reread.

The ordinary original recipe owns six real processes: Rust and Cargo version
checks, locked Cargo metadata, a fresh original build, and ordinary and held
replays. Rust 1.95.0 and the target lock's Tokio 1.53.3 are required. Original
functions are extracted unchanged, and complete selected source files are
checked against the current migration-target inventory. Their immutable
extraction provenance remains commit `737acf6f901e46c57b0b4374e323e0d1132e0d49`;
an equal selected-file binding does not relabel that provenance.

The focused five-suite/six-process gate passed with 53 native and 53 fresh
original roots and 25,273,048 compared bytes. Its strict readers also admitted
the original and relocated captures and rejected 53 native evidence mutations
and 32 original evidence mutations. Every runtime child retained its 60-second
limit; each suite and original process retained its 180-second limit. The gate
reused the separately verified frozen HIA build and did not claim a new cold
compiler qualification.

These are private Local-body and owned-adapter results. Public MCP routing,
full runtime concurrency and shutdown, arbitrary resource budgets, global
activation, and removal of the existing implementation remain unqualified.
The separately developed callable export and joined TextEditor gateway are not
included by this component's standalone evidence.
