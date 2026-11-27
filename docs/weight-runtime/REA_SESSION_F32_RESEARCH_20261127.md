# REA session-bound F32 research

This increment adds one typed MCP route, `rea_model_session_weight`, inside the
existing REA model-session authority. It supports preparation, one research
roundtrip and explicit recovery of the original intent. It does not introduce
a model worker, a deployment pointer, a result replay service or another journal.

The source baseline is commit `1c0a512bce5d4d44ae8d5794c35f2e04866885ae`, tree
`8d04938a2142f4c7f49652a35519f96bc4cca9f0`, together with the separately reviewed
original-intent F32 recovery increment. The integration manifest identifies each
published-base and recovery-base file independently. A source preparation check
is not a Rust 1.95 compilation or native qualification result.

The current integration target is `7b4352e169fd4dce33418d606c017c4b870a469d`, tree
`1f86b26e57ce87c72cbec2b967f9fdeed154fc8c`. Its only change from the baseline is
the existing stored-bias test fixture's private state directory; this overlay
does not include or replace that test file.

## Authority and scope

The server obtains `OwnerScope` from its existing authenticated request context.
The JSON request cannot contain an owner, path, state directory, executable or
authority object. The adapter loads an existing REA session under that owner and
the exact current Runtime policy, checks its complete parent SHA, and verifies
the two selected tensor entries against the retained index.

`SessionAuthority` has private fields and no `Deserialize` implementation. Only
successful session admission constructs it. It binds the session, owner, policy,
original source path, parent SHA and a single selected F32 matrix plus its separate
stored F32 bias. Only the matrix may be edited; the bias is read-only. Names and
shapes alone do not establish graph roles or feature provenance.

The internal source path comes from the retained session manifest. New preparation
and a new roundtrip require that current workspace source to exist and still have
the exact complete parent SHA. They do not turn a private snapshot path into a
general file-writing capability. Recovery loads the retained session metadata and
the original intent; it does not open the original workspace source or replay its
forward. Removing all retained session authority also prevents session recovery.

The existing credential model remains unchanged. Verified HTTP operator credentials
can resume the same owner under the same policy. Anonymous stdio has a random
native-session owner and cannot impersonate that owner after a process restart.
The response reports `credential_metadata_resume`; it never claims authenticated
ChatGPT user or conversation isolation. A direct library control using a fixed
owner is not evidence of HTTP authentication or cross-process credential resume.

This route's scope checks do not migrate the existing generic artifact tools to
per-caller ACLs. The canonical artifact store remains the existing private Runtime
owner. Identical immutable artifact bytes may be reused by that owner; session
authority distinguishes the original journal intents. No global multi-tenant
isolation claim is made by this increment.

## Protocol

The request contains `session_id`, `parent_sha256`, `readout`, and `operation`.
`readout` contains the exact weight and bias tensor names, their complete payload
SHA-256 values, and the output and input dimensions. Dtype is fixed to F32.

The closed operations are:

| Operation | Required data | Result and effect |
| --- | --- | --- |
| `f32_prepare` | Fixed edits, input rows, stored bias, original guard objective and constraints, finite exact update radius | Authenticates the source and old edit bytes, computes the complete candidate SHA and original journal ID; no forward, journal creation or publication. |
| `f32_roundtrip` | Identical fixed request and `expected_journal_id` from preparation | Re-authenticates the source, runs one original guard transaction, inverses passing and failing candidates, and makes a fresh source-bound head request on the actual restored artifact. |
| `f32_recover` | Original journal ID, complete candidate SHA, optional exact candidate artifact ID | Requires the same session authority in the original intent, restores via the canonical owner, and verifies one fresh restored-head request. No parent/candidate replay or new candidate. |

The `request` field of prepare and roundtrip is the same typed `F32GuardInput`:

```json
{
  "edits": [{"index": 0, "expected_hex": "0000803f", "replacement_hex": "00000040"}],
  "inputs": [[1.0, 2.0]],
  "bias": [0.5, -0.5],
  "objective": {"kind": "squared_error", "targets": [[2.5, 1.5]]},
  "minimum_gain": 0.0,
  "constraints": [],
  "maximum_update_l2_norm": 1.0
}
```

This small example describes the synthetic test fixture; the session and tensor
hashes must come from the real source being inspected. Targets are explicit
guard data. They are not model inputs, verified holdout data or complete-task
targets unless a separate producer and evaluation contract establish that fact.

Preparation returns a deterministic ID so a lost roundtrip response does not
erase the recovery identity. An already existing session-bound intent refuses
another roundtrip before any parent forward; use `f32_recover` for that ID.
Changing the request, tensor scope, session, owner, policy or named implementation
source changes the prepared identity or causes rejection. Preparation is evidence,
not an authorization token. The operation always authenticates current authority
again before it can publish.

## Bytes, budgets and lifecycle

Preparation and roundtrip preflight use one admitted source descriptor. The
proposal stream checks every exact old byte and computes the source, candidate
and selected-weight payload hashes without allocating a checkpoint-sized copy.
The stored-bias verifier performs its existing second complete-source pass on that
same descriptor and compares F32 bits, including signed zero. Descriptor metadata
is checked across both passes. A four-byte edit spanning a stream boundary is
handled byte by byte.

The existing limits remain: source at most 2 GiB, 1..1024 exact edits to one F32
matrix, at most 1,048,576 weights, dimensions 1..4096, at most 64 rows, 16,777,216
multiply-add pairs and 16,384 output values per existing head forward, and a 1 MiB
canonical request. The radius is mandatory and uses the existing exact integer
F32 difference check. It excludes bias, other tensors and cumulative drift.

Preflight has a shared 60-second read-only timeout. The original guard retains its
existing forward/publication/restoration phase limits. The roundtrip has a
420-second response deadline around an existing retained owner task, and the fresh
restored request has a 60-second read-only deadline. The response deadline does not
cancel or kill an admitted write, and arbitrary filesystem blocking is not a hard
wall-clock guarantee. Full-file hashing and immutable artifact publication costs
must be counted separately from the small number of edited elements.

The same cohort concurrency permit and effect-owner admission are held by the
retained transaction through inverse publication and verification. The source
authority is owned by that task rather than borrowed from the RPC stack. Checks
occur during preflight, immediately before candidate publication, before candidate
evaluation, and before/after roundtrip inverse verification. If session metadata
becomes invalid after publication, the already admitted task still attempts its
exact compensating inverse and reports the authority failure. It cannot promote
the candidate. The current policy is immutable in a running Runtime; these checks
are not a new external credential revocation service.

The internal guard may report `accepted_on_supplied_rows`. The outer research
operation always reports `accepted_for_activation=false` and restores the candidate.
`research_roundtrip_verified` additionally requires successful authority revalidation.
A malformed receipt, inverse failure or fresh-read failure is explicit and retains
the prepared journal identity. No failed or interrupted result triggers an automatic
new candidate or another parent forward.

Response JSON is checked as an actual MCP text-content wire object. When detailed
guard data would exceed the 60 KiB envelope, the response preserves the original
journal and canonical candidate/restoration identities in a compact receipt. It
does not create a result store or claim that request audit retained the body.

## Original journal compatibility

The existing `weight-guard-journal-v1` remains the sole guard journal. Session-bound
intents add server-derived `session_authority` and named session-adapter source
digests to the canonical original intent. The unbound `None` path omits both fields
entirely and keeps the original request serialization and identity algorithm.

The original named-source map includes `weight_guard_journal.rs` itself. Editing
that source legitimately changes the fingerprint, and therefore the ID of a newly
generated intent, even for legacy requests. This implementation does not freeze a
false old source hash to manufacture unchanged IDs. A request replay under new
source is distinct from recovery of an old on-disk intent by its original ID.

Recovery authenticates the old raw intent bytes and original ID. Named source
digests in that old intent bind its historical implementation; they are not
replaced with the current binary's hashes. The existing incomplete-source-closure
flag remains false. Complete source/tree/toolchain/binary identity belongs to the
qualified CI package and its execution receipt.

Legacy unbound recovery rejects a session-bound intent, including an explicit null
authority field. Session recovery rejects an unbound intent or any different
owner, policy, parent, session or tensor scope. The authority equality check occurs
while the original journal lock is held, before canonical inverse publication.
The old unbound recovery controls remain relevant and are not relabeled as scoped
transport or crash-recovery evidence.

## Reuse and deliberate integration limits

The published baseline already provides native REA model sessions, artifact and
cohort owners, linear forward, proximal ridge, finite-DAG Bellman planning,
continuation certificates, and semantic replay/certificate tools. The new route
does not duplicate those algorithms. The qualification program's
`AuthenticatedSnapshot`, `ReadoutEquation` and finite planner describe their
specific F64 research profile; they are not arbitrary F32/F16 graph authorization.

Affine F32 proposals, exact F16 proposals, coupled F16 evaluation, and binary-choice
contrast are existing library/CLI modules. They have not been silently added to
this F32 MCP enum. A subsequent adapter can reuse session admission while retaining
their dtype, data-pairing, budget and source contracts. The full SmallHCSN example
also remains separate: its explicit file paths and executable are not exposed by
this route. A future complete-model route needs a typed admitted producer/profile,
not a generic executable or path passthrough.

The HIA catalog and configured resident `weight_open`/`weight_call` provider protocol
are unchanged. The global `request_result` replay whitelist still contains only
host-list/health/config reads. Neither audit records nor a serialized proposal are
treated as a capability or a model execution receipt.

## Qualification

Eleven authored sibling controls cover real synthetic safetensors and the canonical
owner: positive roundtrip and source deletion recovery; wrong-owner session and
legacy recovery refusal; failed-candidate inverse; exact no-op at zero radius;
parent/tensor/bias/radius/request tampering; source replacement/deletion after
preparation; revoked manifest; post-publication revocation and caller cancellation with a retained
compensating inverse; legacy unbound intent compatibility; typed schema
rejection of caller authority/path fields; and an F32 edit spanning a stream block.
The positive control also rejects a second roundtrip on the same original intent.

These are authored controls until native CI executes them. Local formatting and
static source checks do not count as typechecking, native tests or model results.
Use the existing Rust 1.95 locked all-target check, Clippy and nextest gates in both
feature configurations, followed by the existing release bins/examples build.
Nextest provides process isolation for controls that initialize immutable Runtime
configuration. No dependency or CI budget change is required.

Formal end-to-end admission evidence additionally needs the qualified binary's MCP
route under a real server-resolved scope. Cross-process scoped recovery must retain
the same verified operator credential; anonymous stdio cannot supply that evidence.
The authored cancellation control acts after candidate publication and revokes
retained session metadata. Abrupt process death, real credential revocation and
mid-publication revocation remain separate lifecycle qualifications. This increment claims no background recovery,
full-model execution, independent feature provenance, NDU optimum or production
adoption from its F32 head controls.
