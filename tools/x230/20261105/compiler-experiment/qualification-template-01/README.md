# Compiler qualification driver template 01

**Prepared locally, unselected, and unexecuted.** This directory contains an external derivative of the original X230 qualifier. It contains no candidate source, compiled artifact, successful future receipt, selected CPU, selected target triple, or selected accepted version. Every future binding in `input-template.json` is `null`; `selected` is `false`.

The original qualifier is `r24-tested-source/tools/x230/20261028/qualify.py`, 7,661 bytes, SHA256 `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d`. Its TrillionniumFoundation copyright and Apache-2.0 SPDX header are retained. `qualify_cpu.py.diff` is the exact unified diff, with stable labels `original/qualify.py` and `external/qualify_cpu.py`. The original source and its 19 Python harness files were not edited. The separate 19-file map is an immutable historical input, not a claim that the new executed driver is the original driver.

This implements the local driver portion of `candidate-qualification-design-01.md/json`. The source/cache preparation described in `preparation-design-01.md/json` remains external and unimplemented here. Existing published plans and the metadata preflight were not changed.

## Execution boundary

There is no native request or native handoff in this directory. Reservation 23 remains the other root's coordination scope at this preparation point. R28 attempt 01 failed its preparation space check before source copying, compilation, or tests; that failure neither adopts R28 nor releases execution ownership. A later actual accepted version must be checked when a new recipe is frozen. Do not fill this template from assumptions that R24 is still the newest accepted source.

The eventual interface, shown only as an unexecuted shape, is:

```text
/usr/bin/python3 -I -B /absolute/external/qualify_cpu.py \
  --input /absolute/frozen-build-recipe.json \
  --input-sha256 ACTUAL_SHA256_OF_THAT_EXACT_INPUT
```

`--target` in the original driver meant a directory. In this version `paths.target` still means that directory, and the separate `target_triple` plan field supplies Cargo's compile target. No executable wrapper is introduced. Direct `cargo`, `rustc`, `rustdoc`, `cargo-fmt`, `rustfmt`, `cargo-clippy`, and `clippy-driver` must all be bound to regular executable files under one selected toolchain's `bin` directory. There is no rustup shim, tool discovery, install, cache population, download, or fallback target path.

The input's SHA is passed outside the JSON to avoid a self-referential input hash. The driver and exact diff have their own mandatory file references. A reference always means `{path, bytes, sha256}` for the actual file available at execution time. The driver reconstructs its diff from the unchanged original qualifier and checks exact equality.

## Read-only admission before any write or child

`admit()` first checks input SHA, schema, `selected is True`, and absence of every `null`/placeholder. An unselected or incompletely bound input returns exit 2 with a short refusal on stdout. It does not create output/target directories, change umask/configuration, copy files, or call a subprocess. The local check in `local-validation.json` covers the real unselected template with mutation and subprocess functions replaced by failing sentinels; no Rust was invoked.

A selected input must additionally establish these concrete conditions:

- **Current accepted source:** an actual adopted/verified publication readback, its qualified eight-stage report, compiler source map, complete source map, retained runtime, and successful full test audit/summary/tests rows. Publication commit/tree/runtime/report hashes must agree. Both the accepted source and private copy must match the full manifest; the private copy must use owned independent regular files. The historical 220-input map is not a complete source-copy recipe.
- **Private preparation:** fresh owned `0700` run root, source, and Cargo home; target and output must not exist. Source, target, Cargo home, and output are four distinct immediate children of the new root. The account's actual passwd home is used for `HOME`. The external preparation receipt must bind the run root, full source map, registry manifest, Cargo.lock, sparse registry checksum completion, and a real fresh-build space budget. This driver only checks that receipt and actual manifests; it does not implement archive/index checksum validation or calculate a space budget.
- **Cache scope:** the initial private Cargo home must exactly match its supplied manifest and contain only `registry/cache/<namespace>/*.crate`, `registry/index/<namespace>/config.json`, and `registry/index/<namespace>/.cache/**`. No expanded `registry/src`, compiled target cache, credential/config file, symlink, or hardlinked input is accepted. The external preparer must establish the actual sparse namespace and lock/index/archive checksum relationships; a path prefix alone does not prove them. Cargo may unpack sources into its own private home during the actual run.
- **Cargo configuration:** only metadata is inspected for `.cargo/config` and `.cargo/config.toml` from source cwd through every ancestor to `/`, and `config`/`config.toml` in the selected Cargo home. Only definite absence passes. Present files, symlinks, permission errors, and indeterminate ancestors stop admission. No config body is read or printed, and no config is modified. There is no exception for a reviewed config in this first template.
- **Actual native metadata:** mandatory pins cover the successful native preflight start receipt, terminal/read receipt, job ID/key, exact runner, report/schema, full compiler version stdout/text, and exact CPU/triple cfg command/output. The preflight's accepted commit and runtime must match the selected accepted source. Historical R24 metadata cannot establish an R28 binding. A named CPU requires an actual metadata command for that exact name; the existing `native` cfg is not silently relabeled.
- **Existing coordination:** `native_handoff` binds the frozen run/CPU/triple/driver/accepted commit/metadata and the hash of `coordination_evidence`. These are records of the actual owner's coordination decision, not a new user approval flow. A self-authored `authorized: true` without actual owner evidence does not grant a slot. The driver verifies recorded identities; the coordinator must still establish current exclusive ownership immediately before the real launch.

### Minimal external receipt fields

The future preparer may supply a larger receipt; this template reads `passed`, `run_root`, `full_source_map_sha256`, `registry_manifest_sha256`, `cargo_lock_sha256`, `sparse_registry_checksums_verified`, and `fresh_build_space_budget_passed`. The latter two may only be true after actual preparation checks. No such receipt is fabricated here.

The coordination decision reads `authorized`, `run_id`, `target_cpu`, `target_triple`, `accepted_commit`, `driver_sha256`, `metadata_report_sha256`, and `coordination_evidence_sha256`. Its evidence must be the actual owner handoff or frozen coordinator decision after real coordination; the driver does not acquire a live reservation itself.

The native start receipt uses the existing `{request, response}` capture convention. Its one MCP text JSON or structured DTO must show the same pinned job ID/key, host `x230`, executable `/usr/bin/python3`, and exactly `[preflight_runner_path]`, plus a successful launch and no pending local record. The terminal file uses the existing `{status, read}` decoded capture convention. It must show `state=succeeded`, integer exit 0, terminal protocol 1 confirmed, complete/durable/audited output, no automatic retry/cancel/timeout, and no log errors/truncation. Complete byte ranges must agree with original log byte counts, and the real preflight footer must name the pinned report and say `passed=true`. This is a consistency check of preserved actual DTOs, not remote status polling. Unknown receipt layouts require review; do not manufacture a normalized successful result.

## Preserved eight-stage qualification

| Stage | Preserved scope | Deliberate change |
|---|---|---|
| `format` | `cargo fmt --all` | Fail the compiler-only claim if formatting changes any copied source byte. |
| `fmt-check` | `cargo fmt --all -- --check` | None. |
| `harness-tests` | Original `python3 -B -m unittest discover`, original directory and `*_tests.py` pattern | None. |
| `clippy` | Offline, locked, all targets, all features, warnings denied | Explicit selected `--target`, `-vv`. |
| `test-build` | Offline, locked, all targets, all features, `--no-run`, full JSON stdout | Explicit selected `--target`, `-vv`; all original events retained. |
| `isolated-tests` | Original runner, full inventory, 180-second per-case/enumeration timeout | None. |
| `audit-isolated-tests` | Original independent auditor and original evidence layout | Additionally compare the audited logical inventory with the selected accepted version. |
| `release` | Offline, locked, all features, release bins and examples | Explicit selected `--target`, `-vv`, release JSON stdout. |

The stage timeout remains 3,600 seconds and no stage or test retries are added. Jobs must be frozen as 1 or 2; the template chooses neither. Failure stops and preserves that original attempt. The driver does not perform benchmarks, deployment, publication, service changes, or automatic adoption.

Test executable retention still filters `compiler-artifact` with `profile.test` and an executable, copies bytes, verifies SHA, and changes only the event's executable path. It does not filter on `target.test`. Zero-inventory targets are retained. Logical comparison normalizes only the source-root portion of Cargo target `src_path`, then compares all target identities, exact test names, and ignored status. Counts are derived from the selected accepted inventory; R24's 1,645/34/1,679 historical totals are not built-in requirements. Test ELF hashes may legitimately differ between compiler recipes; each variant's original runner/auditor verifies its own bytes.

## Environment and actual compiler evidence

The child environment is constructed from explicit entries rather than copied from `os.environ`. It sets the pinned toolchain/system `PATH`, actual account `HOME`, `LANG=C`, `LC_ALL=C`, private `CARGO_HOME` and `CARGO_TARGET_DIR`, frozen jobs, incremental=0, one test thread, two Tokio workers, Python isolation, no Cargo color, and direct `RUSTC`/`RUSTDOC` paths. After construction it sets only `CARGO_ENCODED_RUSTFLAGS` to `[-C, target-cpu=<selected>]` joined by ASCII 0x1f. No ambient Cargo profile/target/build override, Rust flag/wrapper, SSH/Hepta variable, Python path, or compiler/preload variable is inherited. Cargo/Clippy may generate their own internal compiler variables as part of their normal operation.

Release artifacts must come from `<fresh-target>/<selected-triple>/release/`. Exactly one actual Cargo event must identify each original runtime, jobctl, and native process driver, with the expected source target, profile, and frozen feature list. There is no fallback to `<target>/release` or a historical artifact. The driver preserves test/release JSON and raw `-vv` stdout/stderr and records binary hashes.

For each final bin/example the actual verbose rustc command must be unique, use the selected target/CPU, and show the unchanged release opt-level, codegen units, panic, LTO, and strip settings; Cargo profile data must show release/no overflow checks. Duplicate contradictory codegen fields fail. The root library command's actual target/CPU is also checked. Missing, ambiguous, or differently formatted command evidence fails closure; intended recipe flags are not substituted for observed argv. The first template does not add a compiler wrapper or a fingerprint-file discovery framework. Cargo fingerprints may be preserved separately as corroboration, but are not needed to reinterpret missing command evidence as success.

The original report/stage keys are retained, with a separate `compiler_recipe` block and `compiler-build-evidence.json`. `qualified=true` can only be written after the real eight stages, source/harness/config/toolchain checks, inventory comparison, and actual command/artifact checks all pass. `performance_accepted` remains false: successful qualification does not pass the frozen observation/capacity/recovery/lifecycle gates or prove a CPU-only causal improvement over a historical build with incompletely known flags.

## Remaining work and limits

No selected-path execution has been exercised. The strict verbose-command reader must be assessed against actual retained output when a real future run is authorized; an unsupported shape is a failed evidence closure, not permission to invent flags. No future manifest/job/version/source/runtime hash is supplied in this template. Input paths must refer to preserved actual evidence accessible on the execution host; archive copies with moved original paths do not justify pretending the original auditor was rerun.

The driver preserves the original stage subprocess behavior. It does not add a process-group containment framework or claim that a stage timeout proves descendant absence; the native owner must retain the applicable outer job/cleanup supervision. It does not calculate future debug+release/LTO space, reserve native resources, change shared caches, or guarantee portability of CPU-specific jobctl/driver outputs to other hosts. Those preparation, ownership, deployment-scope, and full acceptance decisions remain explicit future work.
