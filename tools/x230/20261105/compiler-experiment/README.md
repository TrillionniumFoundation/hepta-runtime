# X230 compiler experiment — preparation only

No compiler experiment has been launched. No tool has been installed, no Rust
binary built, and no performance result or adoption decision exists here. The
other native-work owner retains the archive I/O window. The preflight must not
be uploaded or executed until that window is explicitly handed over.

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
will be compared with the actual accepted R24 binary. A product difference will
not automatically be attributed to a single compiler flag.

The first proposed action is a bounded [metadata preflight](preflight-plan.json). It checks the actual
compiler and host CPU, compatible profiling-tool availability, available disk,
and the accepted source/binary identities. It performs no compilation or
installation. Missing prerequisites are recorded, never filled by an implicit
download or by substituting another toolchain.

## Candidate sequence, not execution approval

1. Review the preflight and obtain the native-work handoff. Execute its one
   original job, reconcile that exact identity if transport becomes uncertain,
   and read back the complete report and command outputs.
2. Select an exact compiler-only recipe only after that evidence exists. The
   first possible variant is accepted R24 source with an explicit X230 CPU
   target and a clean, fully recorded environment. Generic release settings,
   source trust checks, concurrency limits and runtime semantics remain bound
   to the chosen source, not inferred from the recipe name.
3. Freeze the source map, flags, output directory, toolchain, environment,
   qualification launcher and unchanged acceptance gates before any build or
   measurement. Use fresh candidate outputs and retain original failures.
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

The baseline is accepted R24 source commit
`baab4def80be7af015b2e7a594cb302f66c4130e`, source tree
`b71cac25e2c2138837f27f3c74f6a2dc5c56b565`, runtime SHA-256
`bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`.
R25/R26 and the rejected phase-diagnostic result are not substituted as the
accepted baseline. The prepared R27 serializer is not included.

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

## Checkpoint files

- [中文 prepared-only checkpoint](../../../../docs/X230_COMPILER_EXPERIMENT_20261105.md)
- [Preflight script](preflight.py), [frozen plan](preflight-plan.json), and [original local manifest](preflight-manifest.json)
- [History review JSON](reviews/compiler-optimization-history-01.json)
- [Accepted R24 report](../../../../docs/X230_OPTIMIZATION_20261105_R24.md)

The preserved JSON and history files retain their original local/remote provenance
paths verbatim; the links above are the repository navigation for this checkpoint.
