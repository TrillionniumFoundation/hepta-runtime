# X230 compiler experiment — native metadata verified

One original metadata preflight completed on X230: job
`1a1acae0548-fc05-5655`, strong succeeded / exit0 at
2026-11-05 17:08:05.345 UTC, complete durable115 B stdout /0 B stderr.
The first MCP start response timed out; the unchanged full request and key
reconciled to that same job, reused=true and retried_launch=false. All five
rustc metadata commands returned0; their ten original output files are verified.

The native-work owner executed the frozen kit inside reservation26; no ownership
handoff occurred. Source/cache inventory, compiler builds, training, qualifications
and performance measurements remain **0**. Both future input templates remain
selected=false. This update adds the [actual result and original evidence](actual-metadata-01/README.md)
without changing runtime source, frozen tools, qualification or performance gates.
No compiler variant is selected, qualified or adopted.

## Actual metadata

| Item | Observed result |
|---|---|
| CPU | Intel Core i5-3230M @2.60GHz;4logical CPUs, affinity0–3 |
| rustc / LLVM | 1.95.0 (59807616e) /22.1.2 |
| native CPU identification | ivybridge, explicitly stated in original target-cpus output |
| Toolchain default CPU | x86-64 for the current x86_64-unknown-linux-gnu target |
| Selected llvm-profdata path | unavailable; no alternate search or installation |
| Available-space snapshot | 3,267,739,648 B, approximately3.04 GiB; not a clean-build budget |

The [report](actual-metadata-01/report.json) is15772 B, SHA256
`93d2c3acc11247b86cb9d016a9df2facc6f06c1a01eab0a7fecb175058a85754`.
The [closure](actual-metadata-01/closure-01.json) and [independent review](actual-metadata-01/actual-review-02.md)
bind original requests, terminal state, report and ten command streams. Reads
are independent file snapshots, not a ten-file atomic snapshot. Native cfg adds
13 features and removes none: aes,avx,cmpxchg16b,f16c,pclmulqdq,popcnt,rdrand,sse3,
sse4.1,sse4.2,ssse3,xsave,xsaveopt. This was independently recomputed from original
default/native stdout and matches the report. No named ivybridge cfg or build ran.

The metadata cfg's debug_assertions and panic=unwind describe only those commands.
They do not reconstruct historical release settings. The absent selected
llvm-profdata path does not establish absence elsewhere. The220-input binding is
not a full source inventory; available space does not establish build feasibility.

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

The completed first action was the bounded [metadata preflight](preflight-plan.json). It checked the actual
compiler and host CPU, compatible profiling-tool availability, available disk,
and the accepted source/binary identities. It performed no compilation or
installation. Missing prerequisites were recorded, never filled by an implicit
download or by substituting another toolchain.

## Candidate sequence, not execution approval

1. Completed: the owner executed the unchanged [exact request protocol](native-requests-01/protocol.md)
   in its own window. Original timeout, same-key reconciliation, full terminal
   output, report and command streams are preserved in [actual metadata](actual-metadata-01/README.md).
   Frozen request packages retain their historical preparation wording; this
   result does not transfer ownership or authorize an overlapping native workload.
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

Further coordination, current accepted-version binding, independent
source and sparse-registry preparation, a measured fresh-build space budget,
complete qualification and the unchanged full acceptance campaign remain future
work. The completed metadata is not an optimized runtime
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

Actual source/cache inventory and a fresh-build space budget
remain unknown. The metadata gives only one3.04 GiB available-space snapshot. The 16 MiB evidence-output cap is not a build-space budget.
This template cannot serve directly as a preparation receipt; a later preparer
must independently bind and verify the actual inputs and copies. The existing
preflight, coordination routes, qualification stages and acceptance gates remain
unchanged.

## Checkpoint files

- [Actual metadata report and evidence](actual-metadata-01/README.md), [closure](actual-metadata-01/closure-01.json), and [independent review](actual-metadata-01/actual-review-02.json)
- [中文实际metadata检查点](../../../../docs/X230_COMPILER_EXPERIMENT_20261105.md)
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
All31 non-entry files from the previous33-file checkpoint retain their exact bytes.
Only this entry README and the Chinese checkpoint are edited; original native
metadata, tool wrappers, command streams and independent review are added.
No runtime source or frozen tool is modified, and no new measured optimization
version is claimed.
