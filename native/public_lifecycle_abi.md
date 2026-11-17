# Selected public lifecycle graph

The selected stdio graph exposes nine original tool names: `host_list`,
`effective_config`, `execution_shadow_admit`, `host_health`, `request_status`,
`request_result`, `request_history`, `request_start`, and `request_cancel`.
Its finite public qualification includes actual SDK parsing, authority, audit,
retention, asynchronous producer work, ordinary effect-fence waits, public
cancellation and EOF. It does not activate the production registry. All 125
production handlers and all 10 owner categories remain `not_ported`;
production activation, whole-runtime replacement and old-stack removal are
false. Module and case counts are not production migration counts.

## Canonical source and build boundary

`public_lifecycle_graph.json` selects 111 distinct HIA images for 128 fixed
roles and 135 address/size patches. Each selected image has one source path in
`native/`. Sixty-eight selected source files are byte-identical to existing
canonical sources. The former public mapper and packer are replaced, rather
than retained as alternate versions. Private stage directories, duplicated
dependency trees, compiled images and historical captures remain outside this
repository in the verified archive identified by `public_lifecycle_evidence.json`.

The fixed boundary is `scripts/public_lifecycle_adapter.S` with one include,
`scripts/public_lifecycle_metadata.S`. Expanding that include must produce the
exact qualified assembly SHA. HIA makes business and lifecycle decisions;
fixed assembly provides allocation, actual syscalls, descriptor and reference
custody, fixed child invocation, and transport.

Two HIA prefix packers produce four complete, checked fragments. Every input
starts with `HRISEG03`, little-endian u64 part and stage, and the complete 111
image-size table. Part 0 emits prefix bytes `[0, 94208)` without images. Part 1
emits the remainder of the 190,282-byte prefix followed by image ranges
`[0, 43)`, `[43, 90)`, and `[90, 111)`. The full prefix size determines every
image address, including addresses stored in the first fragment. No fixed
patch crosses a fragment boundary. Each call retains the original 8 MiB input
and output limit; compiler operation and function limits are unchanged.
The builder verifies every input, output and workspace, then compares the
concatenated ELF against an independent reconstruction of every prefix patch
and all 111 images. A successful build does not itself claim runtime qualification.

Installed configuration comes from trusted startup arguments. Session identity,
owner authority, root capabilities, policy binding and private handles cannot
be supplied through tool arguments. Canonical JSON-RPC ID and protocol version
remain owned by the SDK dispatcher. The internal typed result seams preserve
`HRPCTYP1` and `HRPCRES1`; a Complete result with `isError=true` remains Complete.
Top-level arguments are a JSON object, so a `$serde_json::private::RawValue` key
there remains an ordinary map key. Nested SDK Values retain the locked Value
parser's behavior.

## Shared ownership and request order

The original outer `call_tool` ordering remains intact: resolve authority,
perform any early Async target observation, begin the actual audit Ticket,
admit an Intent when eligible, invoke the handler, attach request identity,
reserve final wire space, inspect cancellation, finish the Ticket and attach
the acknowledgement. Read handlers retain their separate inner authority
resolution and Async observation. The two observations are not interchangeable.
History is a metadata observer and does not create its own outer Ticket.

`request_start` and `request_cancel` use private mapper routes 10 and 11,
dispatcher child 6 and mapper child 14. Both remain ineligible for an outer
ResultIntent while retaining their own outer request identity. Start performs
the original second authority resolution and effect-owner admission before
calling the shared start engine. A started producer has its own Binding,
Registry Slot, Ticket and private Intent. Its request ID is distinct from the
outer Start/Read/Cancel request IDs. Reusing an idempotency key returns the
original producer identity without dispatching another producer.

Pool callback role 16 owns the fence acquisition's persistent permit escrow.
The caller and worker hold separate references; successful take transfers the
permit only after the worker reference has retired. Dropping the caller
releases only its own reference. The final reference performs the actual
permit drop and resource destruction. Existing pool callback roles 11–15 keep
their original Ticket/Intent/start resource duties.

Public SDK cancellation sets the public token and suppresses its response; it
does not impersonate a producer Registry cancellation or immediately destroy
the pending handler. EOF has its own five-second grace and actual runtime-drop
path. Runtime teardown releases Read and Metadata caller guards, joins the
shared blocking pool, checks the Ticket service gate, then retires Intent and
Ticket globals. This ordering allows detached ResultComplete callbacks to
finish before their resource owners disappear.

The metadata allocation repair remains an explicit
`mov edi, OFFSET FLAT:tk_CV_BYTES`. Ordinary early ResultIntent errors can
return their original response and allow a following request. The direct
bridge unit exercises the selected allocation/drop body with an explicit
synthetic child, separately from actual public service qualification.

## Executable qualification gates

The portable native gate retains the earlier 64-process, 359-request normal
corpus for the original three routes, including two ordinary file-conflict
recovery cases. A separate finite nine-tool suite contains 22 service processes
and 348 SDK requests: two complete preflight/protocol cases, fourteen ordinary
producer and business-refusal cases, and six Pending/cancel/EOF cases. Together
these gates run 86 native processes and 707 requests. These are test-domain
sizes; results are reported only after the current source has actually run.

The Rust-only consumer freshly builds the selected 42-file original reference
with Rust 1.95, verifies 315 unchanged original blocks and all 140 locked
packages, then executes the same 86 original processes against the current
invocation's native captures. It starts **zero new native processes**. The
retained native build, source, cases, complete process captures and external
workflow seal are bound before replay and rechecked afterward. Shard,
aggregate-pipeline and explicitly owned local invocations remain separate
validated contexts. Conflicting workflow ownership is rejected.

The nine-tool checks reconstruct every request/reply byte, filesystem snapshot,
audit copy, Binding, Outcome and retained typed result. Inner producer identity
and outer request identities are independently joined before normalization.
Key/request/policy hashes, directory and shard identities, anchor hashes,
complete Base64 payloads, page offsets and payload hashes are checked. Dynamic
timestamps are normalized only after single-side identity equality and observed
time bounds succeed. This is not independent entropy-source qualification.

After each owned service has exited, the checker compares every remaining
fixture entry and byte with its complete EOF/fence capture and finishes semantic
reconstruction before removing the temporary fixture. The retirement receipt
binds the checker source, actual PID, complete streams and snapshot hashes.
Later admission requires both this exact receipt and absence of the retired
trees. Captured device/inode identities still participate in all original
identity and anchor checks; restored artifact files may have new inodes.
Twenty-seven data-only controls cover copied captures and rejection of changed
live bytes, snapshots, streams, ownership, source pins and retirement state.

The Pending cases hold an ordinary lock belonging to their own fixture and
observe the owned child's PID/TID, wait channel and matching lock inode. They
retain unrelated replies while Start waits, distinguish cancelled response
suppression from EOF, and keep the lock held beyond the actual EOF grace. No
syscall interception, injected kernel failure or third-party host operation is
used. Seventeen data-only projection controls reject damaged Pending evidence.
Sixteen admission controls reject changed provenance and both complete stream
domains, restore all bytes, and repeat admission. Process deadlines remain
180 seconds and workflow job deadlines remain 15 minutes.

## Frozen evidence and remaining work

The external nine-tool handoff records 22 actual Original/native process pairs,
348 SDK requests per side and 11 producer starts per side. Its independent
340,999,033-byte archive contains 14,041 regular files with 1,309,334,272 raw
bytes and a full byte/metadata/link verification. It retains failed attempts,
including the corrected Pending checker failure. Unobserved duplicate Cargo
intermediates are explicitly excluded; all selected source, compiler, binary,
actual stream and process evidence is retained. This historical evidence does
not replace the current portable gates.

Unrestricted parallel handlers, the full Tokio executor and blocking pool,
active Archive Index publication, HTTP sockets/sessions, all other production
handlers and complete startup/shutdown ownership remain unqualified. New
scheduler, database or HTTP components must be integrated and qualified against
this graph before its closure flags change. Older independent repository
profiles still have separate source-bound gates; removing them requires a
selected production owner graph and complete replacement evidence. They are
not counted as completed migrations and must not be imported again as stage
trees during final consolidation.
