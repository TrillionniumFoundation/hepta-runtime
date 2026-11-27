# Read-only exact-byte F16 proposals

This isolated source candidate fills a proposal-binding gap. It does not repair
or evaluate a model. `weight_f16_proposal::compile_from_admitted` borrows one
already-admitted `tokio::fs::File`, validates caller-supplied exact F16 element
bytes, and returns evidence plus an optional existing `cohort::PatchParams`.
It performs no write, path open, owner invocation, training, selection,
registration, publication, rollback or activation. No MCP route is added.

The fixed base is Runtime `84c7f9f1c6a32cfaeab1e56688be9fa0e32eef73`.
The independently frozen F32 affine candidate a640 is unchanged. This module
does not depend on it, reproduce its affine arithmetic, or change any existing
parser, owner, gain/retention guard, admission rule, feature or dependency.

## Interface and authority

The caller supplies the complete source-file SHA-256; a stable request ID;
bounded tensor names, F16 dtype, exact shapes and complete payload SHA-256s;
exact little-endian expected/replacement bytes; member and global norm bounds;
and explicit data, objective and dependency commitments. Each member is either
an edit target with at least one requested element or an observed dependency
with no edits. The read set retains both roles even when a member has no changed
bytes in the eventual owner request.

The `path` field labels a possible future owner request. It is syntactically
checked but never opened or authenticated as the borrowed descriptor's path.
The caller must obtain that descriptor through the existing authorized source
admission. The independently invoked owner must later admit its own path under
configured roots and revalidate the complete digest, old bytes, effects and
budgets. This Rust function and its output are not a replacement for that
admission. No new path-resolution or authorization API is introduced.

The result has no deserialization constructor. Its optional cohort request is
data, not an authorization token or a registered operation. It always uses the
existing inference-only training contract. Its behavior-evaluated and
production-eligible fields remain false.

## Bounds and source binding

The file cap is the existing owner's 2 GiB, with a narrower initial header cap
of 256 KiB, at most 256 verified tensor declarations and 64 bounded metadata
entries. At most 32 distinct F16 read-set members and 1,024 requested element
edits are admitted. The total is checked before identity edits are removed;
no-op edits cannot bypass it. Both the typed input serialization and the eventual
cohort request stay within the existing 256 KiB request cap. These are byte and
count bounds, not wall-clock guarantees, and typed validation is not a bound
on an as-yet-unprovided wire decoder.

The function checks regular-file length, the initial safetensors prefix and the
existing Unix descriptor observation token. It then calls the existing
`rea_model::inspect_snapshot_directory` on the same descriptor. Outside tests,
that API uses the existing isolated inherited-descriptor worker; this is not
a process-free parser. Inside existing unit-test configuration it uses the
same parser through its established blocking-task path. Neither was run for
this source preparation. The descriptor is sought and read only after that
inspection returns; no concurrent cloned-descriptor seeks are introduced.

The existing parser rejects duplicate JSON keys, inconsistent dtype/shape
products, gaps, overlaps and unindexed trailing data. This narrow profile also
rejects unknown storage and requires selected tensors to be nonempty F16 with
the exact declared shapes. File offsets originate in the checked directory,
never caller-supplied raw offsets. Nonempty edit lists are prepared by the
unchanged `weight_tensor::prepare`, including its finite-value, width, index
and duplicate checks.

One complete streaming pass with a 1 MiB buffer then computes all of:

* the full source SHA-256;
* the raw-prefix SHA-256, including the eight-byte safetensors length;
* the JSON-header SHA-256, excluding those eight bytes and including the exact
  header whitespace;
* every selected member's complete payload SHA-256;
* the full hypothetical candidate SHA-256 with only the sorted exact two-byte
  replacements substituted.

Every expected element byte is compared against this same stream, including a
two-byte element split across buffer boundaries. The candidate is hashed without
writing it or allocating a full source, candidate or tensor copy. Only the
bounded edits, directory, hash states and stream buffer are retained. The
existing parser's own allocation/response limits remain separate: the new
precheck is not an atomic promise that a hostile concurrent writer cannot make
that existing parser encounter its larger original cap before rejection.

The streamed prefix must match the parser-bound prefix; the full source and
all selected payloads must match their explicit commitments. The descriptor
observation must remain unchanged, and every requested byte must have been
observed. These checks bind the returned proposal to the exact observed stream.
They do not create a filesystem snapshot or a namespace lease against hostile
writers. No guarantee is made about future path contents or final use.

The read-set commitment includes the full source SHA, both named header domains,
roles, exact names, dtype, shape, payload commitments and verified extents.
It is not interchangeable with the historical pretty-printed JSON-header SHA
or with a640's narrower tensor-map schema. The selected-source hash includes
the compiler/capture, model/parser, exact-tensor, norm, cohort, config and Cargo
manifest source bytes. It is explicitly not a compiled-binary or complete
transitive-build attestation. Caller data/objective/dependency hashes bind
claims without proving their correctness.

## Exact representation and KEEP

Only exact lowercase two-byte binary16 values are accepted. There is no F64,
F32, adapter, affine-matrix or numeric coefficient encoder. Finite binary16
values are decoded exactly into binary32 solely for the existing exact integer
norm checker; no decoded value is used to replace an element's supplied bytes.
There is no F64-to-F32-to-F16 rounding path.

Both expected and replacement edited values must be finite. Negative zero and
finite subnormals retain their actual bytes. A negative-zero to positive-zero
edit has zero numeric norm but is still a byte change. All-no-op input becomes
KEEP only after request, budget, directory, full source, read-set and expected
byte validation; no empty owner request is constructed. Unedited values are not
interpreted as finite, and the result explicitly does not claim the entire
checkpoint is finite. Hashing a read-only dependency is not evaluation of it.

The existing global and per-member norm machinery operates on at most 1,024
exactly represented binary32 pairs. A passing norm is feasibility of represented
bytes, not semantic equivalence, retention, improvement or repair evidence.

## Relation to actual research inputs

The historical 643,835,514-byte checkpoint is mostly F16 and cannot fit a640's
F32/32 MiB/width-32 profile. Its restored metadata is compatible with this
candidate's outer size/directory bounds; actual admission requires future live
source bytes and the supplied full digest, which were not read here.

The complete ACT final W/b pair has 514 coefficients and the PRICE final pair
has 769. Editing all 1,283 coefficients in one request exceeds 1,024; a sparse
joint proposal with at most 1,024 supplied elements can remain admissible.
Historical F32 adapter deltas are not F16 encoded-change counts and cannot be
silently merged. No over-budget request may be split into transactions to evade
the joint cap. The separate 85-to-48-to-4 F64 research readout has a different
model, layout and contract; it is not reinterpreted here.

This candidate is the arithmetic-free part of the earlier F16 design. Dense
affine input budgets, direct correctly specified F16 lowering, coupled F16 W/b
evaluation, source-to-graph semantics and model-quality qualification are still
missing. The current guard's F32 weights and fixed external bias cannot verify
such a coupled F16 migration. Existing gain, retention and NDU gates stay open;
an exact-byte proposal or a zero-gain equivalence claim cannot promote them.

## Prepared validation and limits

The sibling Unix controls are authored, not executed. They use owned synthetic
files and the real compile interface, including existing directory parsing.
They cover independent candidate/inverse byte oracles, both header hash domains,
negative zero/subnormals/nonfinite values, changed and unchanged read-set members,
wrong bytes/shapes/dtypes/indices, malformed directories, the joint 1,024 cap,
member/global norms, a split element at 1 MiB, a synthetic sparse source above
32 MiB, and rejection above the original 2 GiB cap. These are not an artifact
owner crash/rollback test or a model run. They do not deterministically exercise
a hostile mutation concurrent with the complete scan.

Source formatting uses the available 1.96 formatter only as explicitly labeled
preparation. Runtime's pinned Rust 1.95/dev compile, lint and native-test gates
remain unexecuted until the authorized dev mapping and tooling are established.
No source is staged or committed by this preparation. No checkpoint, image,
model, training, old compiler control, REA worker replay or CI run is executed.
