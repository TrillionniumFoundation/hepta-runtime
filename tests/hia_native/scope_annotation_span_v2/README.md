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

The native reader preserves the 31 pre-allocation controls, including all four physical
rehash controls, and the two added
allocation-admission refusals, for 33 controls. The original reader preserves
all 12 prior controls.
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

## Complete-request output reservation

Semantic sessions reserve `max(65600, 64 + len(complete_request))` output
bytes before their first HIA call. This policy uses only the complete incoming
byte span. It does not parse JSON, predict a result, reuse a semantic result, or
increase the workspace. The session ledger records the exact input length,
SHA-256 and allocation. The physical reader reopens the first actual input;
the semantic reader separately binds the same declaration to the frozen input
frame. Explicit small-capacity controls retain their original allocations.
All complete buffers, actual addresses, growth and child handoffs remain read
and checked. The prior 31 reader controls remain; two additional mutations
reject forged owner capacity and input identity.

The retained wide-array call sequence shows why this matters. After the
required Value, constructor, and second Value calls, the old 65,600-byte output
needed to grow to 155,725 bytes. The owner's documented restart then repeated
both Value calls and the constructor. Reserving 155,773 bytes from the complete
155,709-byte input avoids this replay. The required two Value calls remain
actual executions. The full independent archive read and exact old call
sequence are pinned in `provenance/owner-allocation-observation.json`.

This revision also reuses the exact HIA constructor qualified in the joint
102-image Authority/Batch graph. Fifteen existing functions, including the
entry, UTF-8 validator and growth behavior, remain byte identical. Only the
quoting loop gains a bounded eight-byte ordinary-ASCII path; all other bytes
retain the scalar path. The authoring source, proof and prior qualification
index are retained as provenance. That earlier scope does not replace the
fresh 842-case original comparison and complete private controls here.

The preceding boundary-corrected revision timed out after 665 complete cases
and 5,911 complete native calls. Its complete failed archive remains retained.
Neither this source revision nor a successful read of earlier evidence is a
qualification pass. The 180-second process and fifteen-minute CI limits remain
unchanged.


## Complete evidence reader scheduling

Revision 5 completed all 842 native cases in 135.12 seconds, all private
refusals and recoveries, and the complete guarded original comparison. The
33-control native evidence process then reached its unchanged 180-second limit
after both full relocations and seven refusals. Its full failed archive is
retained and independently byte-checked; the overall gate remains failed.

This revision consumes and hashes each complete decompressed input and
observation stream through EOF before expensive physical reconstruction. It
checks structural call, session, allocation and growth declarations earlier,
then still reads every actual input and verifies all four complete buffer
descriptors for every call. Each physical buffer store freshly reads and
validates its entire retained chunk domain before any content identity is used.
The original per-case semantic, handoff and lifecycle checks remain mandatory.

Only two pure content proofs may be reused: a constant-byte digest keyed by the
exact byte and size, and an already established prefix-plus-zero equation keyed
by both complete descriptors, including their lengths, digests and ordered
chunk identities. Both growth descriptors must first pass full verification;
failed equations never enter the cache. Growth minima, policies, actual actions,
addresses, sessions and following calls are still checked for every event.
No physical observation, semantic result, refusal, recovery or deadline is
removed. All HIA and original source bytes remain identical to revision 5.
The new source and readers still require the complete fresh qualification gate.

## Complete read-only guard traversal

Revision 6 again completed all 842 native cases, all private controls and the
complete guarded original comparison. The evidence-control process completed
both physical relocations and twenty of its thirty-three refusals before the
unchanged 180-second limit. Its full failed archive contains 63,657 files and
3,442,057,179 logical bytes; every member and mode was independently read. The
failure remains a failure, and all remaining controls are still required.

Revision 7 removes repeated whole-ancestor path construction from snapshots.
It traverses ordinary directories through held descriptors, opens each ordinary
file with O_NOFOLLOW, reads every byte through EOF, and checks the opened and
final metadata against the original stat. Each before/after record retains
mode, inode, device, byte count, mtime, ctime and SHA-256. No file, directory,
physical byte or hash is skipped or cached. The audit dispatcher retains only
active guards, and nested cleanup always restores original descriptor methods.
All twelve refusal probes and every existing audit refusal branch are retained.

A frozen paired diagnostic over 29,195 entries produced exactly equal complete
before/after records and probe records. Guard time changed from 44.13 seconds
to 10.08 seconds. This diagnostic read existing captured bytes without native
or Rust execution; it is not a qualification pass. The current source still
requires a fresh 842-case gate, all thirty-three native and twelve original
reader controls, both relocations, and the unchanged 180-second process and
fifteen-minute CI limits.

## Parallel custody of the complete reader controls

Revision 7 completed all 842 native cases, all private controls, the full
original comparison and both physical relocations. Thirty of the thirty-three
native evidence refusals completed before the same 180-second parent limit.
The remaining controls and the later original controls were not qualified.
The complete failed ZIP and every member's byte and mode identity are retained.

Revision 8 keeps both complete physical copies and assigns each to one owned
Python reader process. The frozen control names are partitioned by alternating
indices; their exact disjoint union remains all thirty-three names. Every
selected mutation runs the same complete source/copy before-and-after guard
and twelve refusal probes. No physical byte or metadata field is excluded.
Both copies receive a complete guarded admission before mutations and another
after exact restoration. The original mutation helpers and complete native,
private-control, build and process-custody readers are unchanged.

The parent owns both actual Popen handles in its existing process group and
retains complete commands, PID/parent/group identities, monotonic lifetimes,
stdout/stderr and exit/reap observations. Both complete worker reports and
all four full guarded proofs are independently read and joined to the current
native baseline and recovery bytes. Cleanup attempts every kill and every wait
before final receipt writes, including on failure. The single existing
180-second parent deadline includes preparation, copies, both workers, joining
and cleanup. No native or Rust implementation executes in these readers.
A fresh complete gate is still required; this scheduling change is not a pass.

## Revision 9: isolated entry-point import order

Revision 8 run `43925950485` completed all 842 native/original cases and all 69 private control/recovery cases, then failed before starting the native reader controls: `python -I` does not add the script directory to its import path. The sibling import preceded the existing explicit source-root admission. Revision 9 moves that single import after `sys.path.insert(0, str(ROOT))`. All function bodies, the complete parallel reader and qualifier, every HIA/original source and domain, and the original deadlines remain unchanged. The failed run and complete archive are retained. A fresh complete gate is required; the import repair is not a passing qualification.
