# Native weight recovery coordination

This library journals research intent around the existing canonical weight
artifact owner. It does not implement another artifact store or change a live
model pointer. The root test bridge includes the same `engine.rs` directly,
using existing root dependencies without modifying Cargo.toml or its persistent
guard identity.

## Contract

An `Intent` binds complete original/candidate content hashes, law, task,
evaluator identity, and the canonical owner's exact request. The transaction ID
is the hash of this complete intent. A private per-transaction directory is
locked with a kernel flock. Records have a bounded sequence, exact predecessor
hash, fixed intent, and restricted state transitions. Each record is written
create-only, synced, atomically renamed with `RENAME_NOREPLACE`, and followed by
directory sync. Staging names have unique bounded-attempt suffixes; a complete
pending record is reused only when its bytes exactly equal the currently
requested transition. Incomplete or different records are retained and bounded.
The quota is an explicit refusal boundary, not a promise of unlimited crashes.

The caller provides `ArtifactOwner` (`publish`, `inspect`, `restore`,
`verify_original`) and `Evaluator`. The actual owner must reconcile repeated
publication/restoration requests to the same immutable artifact. Restart never
repeats evaluation or invents a fresh acceptance. It reconciles a possibly
published candidate and creates the canonical inverse artifact. A completed
transaction can be read repeatedly without additional model artifacts or
journal records.

The canonical owner also reconciles complete `.pending-*` stages left before
rename. This occurs under its existing store lock and requires the same exact
source, patch, kind and parent; manifest identity, model bytes, current source
bytes, computed target, and changed-byte count are independently checked before
publication or duplicate-stage removal. Partial/unrelated stages are retained;
the existing bounded store quota still applies. Such files are never blindly
deleted to make recovery succeed.

## Validation

Nine fast library tests cover normal acceptance/rejection, return-path errors at
eleven boundaries, idempotent replay, incorrect evaluation identity, changed
original bytes, missing journal records, a missing/corrupt durable restore before
completion, and same-process partial journal stages. These use an explicitly named mock
owner and do not establish canonical storage behavior.

`run_canonical.py` instead invokes the complete root library test executable's
ignored `mcp::weight_artifact::recovery_tests::canonical_f64_crash_recovery_worker`.
That bridge calls the real `apply_with_roots`, `open_pinned_artifact` and
`restore_with_state`. The supervisor sends real SIGKILL to a waiting worker at
14 predeclared boundaries, including inside the owner's publish and restore
before rename. Each case starts a fresh process for recovery and a second
process for idempotent readback. Independent Python checks recompute canonical
artifact IDs and file hashes, require byte-exact restoration, no matching
pending stages, and no writes on the second recovery. Normal accept/reject
controls also run. Four negative process controls corrupt pending model/manifest
bytes or remove/corrupt an already durable restoration; recovery must refuse
without writing Complete. Another killed-process case checks that unrelated and
partial pending stages survive unchanged. Each feature mode therefore includes
19 actual SIGKILL cases and two normal controls when all gates complete.

The fixture is four F64 values and a deterministic linear score. It is a
transaction-recovery qualification, not a Hepta model-quality comparison. There
is no production adoption, power-loss emulation, network filesystem claim, or
implicit qualification transfer from earlier D3 binaries.

The workflow checks the coordination crate, checks/lints the complete root
library and bridge, builds an exact-source root test binary, and runs the
process campaign in both feature modes. Full-project release gates are separate.
