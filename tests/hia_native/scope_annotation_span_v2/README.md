# Native span annotation qualification

This source package replaces the private fixed 8 MiB annotation request and
fixed workspace with HIA-owned span layout and explicit buffer growth. It
implements `OwnerScope::annotate` and `OwnerScope::annotate_search_effect`,
including complete SDK wire budgeting, parse errors, retained search identity,
UTF-8 byte limits, retained Boolean flags, and the exact tracing warning text.

The original comparison uses target commit
`d3d75c30719db966b004756f610007a7c723729e`. Both methods are extracted byte for
byte. A separate observer copies the original serialization prefix to retain
the entire rejected wire. The fixture resolves an exact subset of the target
lock, compiles actual rmcp 3.9.0, and records the real tracing event. Rust is
executed only by a fresh CI or explicitly authorized reference-host gate.

## Frozen domain and admission

`DOMAIN.json` contains 842 inputs: all 444 qualified old cases, all 222 old
search-mode cases through the actual effect method, 172 identity/field/budget
cases, and four inputs larger than 8 MiB. Python generates inputs and transports
bytes; original Rust supplies the complete semantic comparison. There is no
Python implementation of annotation, serialization, or fallback output.

`CONTROL_DOMAIN.json` declares 60 atomic owner refusals, three actual child
capacity refusals, and six complete recoveries. The mapping of all 39 old
controls is in `BASELINE_CONTROL_COVERAGE.json`. Fixed-capacity rejections are
replaced by actual growth/recovery; malformed input and continuation custody
remain refusals. Constructor workspace and output growth are actual child
events. Acknowledging growth or capacity as a completed constructor result is
rejected.

The native reader preserves all 25 prior admission controls and adds four
physical rehash controls. The original reader preserves all 12 prior controls.
Each runs two complete physical relocations. Native relocation readers also
exercise twelve write, metadata, process, mapping, foreign-path and descriptor
refusals. Readers are preloaded before activating their guard.

## Physical custody

All four HIA owners are compiled by the pinned B3. Local development must copy
the verified B3; CI builds the pinned B1=B2=B3 fixed point. This fixture does not
rename fixed-point evidence as the separate complete compiler cold gate.
Compiler sources, full inputs and outputs, receipts and all images are retained.

Every actual call reads and hashes the complete declared output and workspace
before and after execution, with independent guard bytes. Content-addressed
128 KiB chunks deduplicate storage after physical reads. No sparse regions or
implicit zero reconstruction substitute for captured bytes. The independent
reader checks every retained chunk and reconstructs full buffers, exact host
copies, acknowledgment fields, growth prefixes and zero-initialized extensions.
Repeated concatenation proofs may reuse identities only after every physical
chunk is checked again in the current copy.

The request has a 48-byte `HSCANS02` header. Operation 1 annotates; operation 2
applies the search-effect policy. The 64-byte `HSCAR002` response records full
payload, annotation, wire and warning extents. `HGRWS002` requests allocation;
`HSCAA002` requests an actual Value, error, or SDK constructor child. Workspace
layout follows the input span rather than the old fixed ceiling. The HIA module
allocation profile still applies physical resource limits. This is not a claim
of unlimited memory or a completed public runtime.

## Execution and scope

`run_gate.py` preserves process stdin/stdout/stderr, owned process-group reaping,
every failure, and unchanged deadlines. Native corpus, native controls,
original replay, and each reader/control process retain their 180-second
limits. The original compile retains its existing 900-second inner limit; the
fresh CI job retains a fifteen-minute outer limit. Source, domains, and readers
must be committed before qualification execution.

The package is a private component qualification recipe. Public-handler
integration, all configured catalogs, full SDK concurrency, and removal of the
legacy runtime are separate gates. Neither a source package nor a development
capture establishes those gates. `export.py` archives complete successful or
failed evidence and reads every archive member back without semantic replay.
