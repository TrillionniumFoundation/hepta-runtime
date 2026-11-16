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
short-output boundaries, and six complete recoveries. Capacities 0 and 31 refuse
without writes; capacity 63 retains the actual 32-byte workspace-growth frame
and unchanged output tail. These are the constructor's existing HIA semantics. The mapping of all 39 old
controls is in `BASELINE_CONTROL_COVERAGE.json`. Fixed-capacity rejections are
replaced by actual growth/recovery; malformed input and continuation custody
remain refusals. Constructor workspace and output growth are actual child
events. Acknowledging growth or capacity as a completed constructor result is
rejected.

The native reader preserves all 25 prior admission controls, the four physical
rehash controls, and adds two allocation-admission refusals. The original reader preserves all 12 prior controls.
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

## Allocation revision

The Value child's workspace allocation doubles the actual HIA-requested minimum,
bounded by the existing module profile. Every growth still records that minimum,
the complete old and new buffers, and the actual addresses. The reader checks
the exact policy, preserved prefix, and zero extension. Other owners and output
growth continue to allocate the exact requested minimum.

For semantic cases, the first actual owner action supplies the Value child's
initial output capacity. The reader binds it to that case's HIA action and four
owned sessions. Private controls retain their small outputs and actual growth.
The reused Value source changes only three byte-access helpers; the remaining
77 functions are byte identical. Provenance indices retain the earlier symbolic
and paired evidence. They do not qualify this component in place of its full
domain. The original copied-input inventory remains historical provenance;
SOURCE_MANIFEST.json binds the current source bytes.

REVISION.json records the two prior failures and unchanged budgets. The first
CI failed before Rust compilation because a target-filtered dependency fetch
omitted an Android package needed by offline metadata. Fetch now covers every
platform in the unchanged target lock. The native development attempt timed out
during repeated minimum-sized Value workspace growth. Neither failure is a pass.

The short-output boundary correction retains all three inputs and the complete
captured buffers. An independent byte-only CI read of the prior failure verified
its whole archive and observed CAPACITY at 0/31 and GROW(resource 1, 16582) at 63.
That read also compared all 842 native and original outputs byte for byte under
twelve guards. The old control gate remains failed; this revision still requires
a new complete gate, including every refusal, recovery, and reader control.
