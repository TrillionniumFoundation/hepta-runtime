# X230 compiler experiment — preparation only

This preparation update adds a bounded source/public-registry inventory template
alongside the existing qualification driver, preparation designs, and exact
metadata staging/execution requests. For this
compiler experiment, native metadata runs, builds, training, qualifications and
performance measurements all remain **0**. No candidate is selected or adopted.
The current native-work owner's reservation 25 supersedes the earlier reservations and
remains unreleased. No handoff or compiler preflight execution is claimed here.
References to earlier reservations inside the frozen packages remain historical
preparation records; current coordination follows reservation 25.

## Why this direction is being checked

Accepted R24 already declares release optimization level 3, fat LTO, one codegen
unit, aborting panics and symbol stripping. The bounded [local history review](reviews/compiler-optimization-history-01.md)
found no recorded CPU-specialized, PGO or BOLT experiment in the inspected
R5–R24 files. This is a search result within those files, not proof that no such
experiment has ever happened.

The accepted qualifier removes `RUSTFLAGS` and several wrappers, but does not
clear every Cargo profile/target/build override. Its actual report does not
capture every rustc argument. Consequently, the historical effective CPU target
and all profile overrides are not established merely by reading Cargo.toml.
Any future candidate will have a separately recorded, clean build recipe and
will be compared with the actual accepted binary bound when that recipe is
frozen. R24 below is the historical and last verified accepted reference for
this checkpoint. A later R28 adoption requires a new binding. A product difference
will not automatically be attributed to a single compiler flag.

The first proposed action is a bounded [metadata preflight](preflight-plan.json). It checks the actual
compiler and host CPU, compatible profiling-tool availability, available disk,
and the accepted source/binary identities. It performs no compilation or
installation. Missing prerequisites are recorded, never filled by an implicit
download or by substituting another toolchain.

## Candidate sequence, not execution approval

1. Review the preflight and [exact request protocol](native-requests-01/protocol.md)
   with the current native-work owner. That owner may execute the exact kit within
   its own window, or explicitly hand the window over before we execute it. Use
   its one original job, reconcile that exact identity if transport becomes
   uncertain, and read back the complete report and command outputs. The request
   files themselves are still unexecuted; owner execution needs no ownership transfer.
2. Select an exact compiler-only recipe only after that evidence exists. The
   first possible variant is the then-accepted source with an explicit verified
   X230 CPU target and a clean, fully recorded environment. Generic release settings,
   source trust checks, concurrency limits and runtime semantics remain bound
   to the chosen source, not inferred from the recipe name.
3. Freeze the source map, flags, output directory, toolchain, environment,
   qualification launcher and unchanged acceptance gates before any build or
   measurement. Use the [guarded driver design](candidate-qualification-design-01.md)
   and [private preparation design](preparation-design-01.md) to bind fresh candidate
   inputs and outputs; retain original failures. The source/cache preparer is not
   implemented by this checkpoint.
4. Complete native formatting, Clippy, the full selected all-features tests,
   release build, artifact identity and cleanup checks. Any change in required
   tools or environment receives a new explicit preparation record.
5. Run one fixed six-host acceptance campaign for that distinct qualified
   candidate, with the original observation, resource, correctness and
   lifecycle gates. Retain a failed result; do not rerun an unchanged candidate
   until it passes.
6. Publish the exact recipe, relevant source/build changes, measured results
   and decision on a separate experiment branch. Update the accepted version
   only with complete passing evidence and coordinated shared-branch ownership.

PGO is a separate conditional possibility, not bundled into the first CPU
experiment. The [official Rust workflow](https://doc.rust-lang.org/rustc/profile-guided-optimization.html)
uses an instrumented build, representative execution, `llvm-profdata` merging,
then a profile-use build with matching other flags. It recommends explicit
Cargo `--target`, absolute profile paths and missing-function diagnostics.
The [codegen reference](https://doc.rust-lang.org/rustc/codegen-options/index.html#target-cpu)
describes `target-cpu` and its `native` selection. These documents do not prove
tool availability, compatibility, performance or training coverage on X230.
No PGO training or final build is currently selected. BOLT is not selected.

## Fixed evaluation boundaries

The historical and last verified accepted reference is R24 source commit
`baab4def80be7af015b2e7a594cb302f66c4130e`, source tree
`b71cac25e2c2138837f27f3c74f6a2dc5c56b565`, runtime SHA-256
`bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`.
R25/R26 and the rejected phase-diagnostic result are not substituted as the
accepted baseline. The prepared R27 serializer is not included.

This checkpoint does not choose a future candidate baseline. If R28 or another
version is adopted before selection, a new fixed recipe must bind its actual
accepted source, ELF, tests and matching native metadata. Do not relabel the
historical R24 preflight or fill the template from stale R24 assumptions.

Controller own CPU, waited local-child CPU, sampled RSS and remote-host costs
remain distinct. Child-CPU improvement cannot replace a failing own-CPU gate.
CPU-specialized artifacts are evaluated for the verified target host; their
portability to the other machines is not presumed. Training executions, if
later selected, are never counted as independent validation samples.

The complete lifecycle and observation gate specifications are recorded in
[compiler-screen-plan.json](compiler-screen-plan.json); actual measured binaries, frozen launch inputs
and qualification still need to be created. This is a bounded next experiment,
not a claim that the current product is globally optimal or that another
compiler setting will improve it.

## Guarded driver and local checks

The [external driver package](qualification-template-01/README.md) preserves the
original eight qualification stages, original 19 Python tools, copyright, full
test inventory and no-retry behavior. It builds a clean allowlist environment,
uses separately bound target-directory and target-triple fields, and requires
actual source/toolchain/config/metadata/driver/artifact identities. Explicit Cargo
`--target`, `-vv` and release JSON provide evidence; missing or ambiguous actual
compiler commands fail closure. No wrapper or old compiled-target cache is added.

The [input template](qualification-template-01/input-template.json) remains
`selected=false`, with every future binding null. The preserved
[local negative check](qualification-template-01/local-validation.json) returned
**exit 2 with 0 mutation/subprocess calls**. That result only establishes refusal
of the unbound template; it is not a native metadata result or a successful
qualification. This publication copy did not rerun the check. The
[admission review](qualification-template-01/root-review-admission-01.md) and
[Cargo review](qualification-template-01/root-review-cargo-01.md) found no definite
blocker within their static scope; selected execution and actual compiler-log
compatibility remain unverified.

Actual coordination, accepted-version selection, native metadata, independent
source and sparse-registry preparation, a measured fresh-build space budget,
complete qualification and the unchanged full acceptance campaign remain future
work. These materials are a preparation checkpoint, not an optimized runtime
version or a change to the accepted candidate.

## Read-only source and public-cache inventory

The [inventory template](inventory/README.md) records identities for a selected
accepted source, its original harness, and bounded public crates.io registry
inputs. It performs no Cargo/Rust execution, subprocess, network, copying,
unpacking or cache cleanup. Its [input template](inventory/input.template.json)
remains `selected=false`, with all future bindings null. The preserved
[manifest](inventory/manifest.json) records one actual local unbound rejection:
**exit 2**, without reading selected source/cache paths or creating an evidence
directory. The selected/native branch has never run; this publication copy did
not rerun the check.

Sparse-index file identities and archive-to-lock checksums do not establish the
index checksum for an exact package version: that parser is not implemented and
the value remains unknown. Cargo.lock entries are not the resolved
target/features/host-build dependency closure. The observed registry map can
include checksum mismatches; it is not a copy allowlist or a prepared private
registry manifest. `inventory_complete` would only mean that bounded observation
finished, not preparation, offline resolution, qualification or build success.

Actual source/cache inventory, current free space and a fresh-build space budget
remain unknown. The 16 MiB evidence-output cap is not a build-space budget.
This template cannot serve directly as a preparation receipt; a later preparer
must independently bind and verify the actual inputs and copies. The existing
preflight, coordination routes, qualification stages and acceptance gates remain
unchanged.

## Checkpoint files

- [中文 prepared-only checkpoint](../../../../docs/X230_COMPILER_EXPERIMENT_20261105.md)
- [Preflight script](preflight.py), [frozen plan](preflight-plan.json), and [original local manifest](preflight-manifest.json)
- [History review JSON](reviews/compiler-optimization-history-01.json)
- [Accepted R24 report](../../../../docs/X230_OPTIMIZATION_20261105_R24.md)
- [Qualification design](candidate-qualification-design-01.md) and [JSON](candidate-qualification-design-01.json)
- [Private preparation design](preparation-design-01.md) and [JSON](preparation-design-01.json)
- [Read-only inventory script](inventory/inventory.py), [input template](inventory/input.template.json),
  [scope README](inventory/README.md), and [frozen manifest](inventory/manifest.json)
- [External driver](qualification-template-01/qualify_cpu.py), [exact diff](qualification-template-01/qualify_cpu.py.diff),
  [original tools map](qualification-template-01/original-harness-map.json), and [package manifest](qualification-template-01/manifest.json)
- [Admission review JSON](qualification-template-01/root-review-admission-01.json) and [Cargo review JSON](qualification-template-01/root-review-cargo-01.json)
- [Create-only parent request](native-requests-01/01-setup-tools-parent.process_start.request.json),
  [exact script write](native-requests-01/02-stage-preflight.binary_write.request.json),
  [file identity request](native-requests-01/03-verify-preflight.file_info.request.json),
  [single-key execution request](native-requests-01/04-run-preflight.process_start.request.json), and [request manifest](native-requests-01/manifest.json)

The preserved JSON and history files retain their original local/remote provenance
paths verbatim; the links above are the repository navigation for this checkpoint.
All frozen package source, JSON, diffs, local checks and reviews are byte-identical
copies. This update adds only the four frozen inventory files; the previous 27
non-entry files retain their exact bytes. Only this entry README and the Chinese
checkpoint document are edited. This is a tools preparation checkpoint, not a
new measured optimization version.
