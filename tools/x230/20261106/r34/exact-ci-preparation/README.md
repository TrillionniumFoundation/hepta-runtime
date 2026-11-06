# R34 exact native Rust CI: unsealed preparation

This package is **unsealed and cannot run CI**. `JOB_ID`, all final qualification receipt/source pins, `FROZEN_COUNTS`, and the launcher `SPEC` are null. The separately started first R34 qualification job `1a1aef7882f-fc05-6499` supplies no success claim here. A completed qualification with its original reports and terminal evidence is required before sealing a new output directory.

## Original CI contract

The three templates are byte-identical to the R33 unsealed templates after changing only R33 to R34 and the runtime root to `/home/qian/hepta-runtime-optimization-20261106-r34`. The source baseline remains accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`. Attempt 01 remains a first attempt; no earlier R31 planning failure chain or R33 actual receipt is copied into R34 expectations.

The unchanged commands are:

```text
cargo check --locked --all-targets --all-features
cargo nextest list --locked --all-targets --all-features --message-format json
cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
```

The actual original nextest 0.9.137 installation and its receipt/binary SHA pins are unchanged. The independent nextest output auditor (8,563 bytes, SHA256 `03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2`) and canonical workflow (7,631 bytes, SHA256 `b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51`) are copied byte-for-byte. The private source workflow is checked separately and is never overwritten to look canonical. Native execution does not claim a hosted GitHub Actions run.

The original 19-file Python qualification harness and all eight qualification stages remain required. R34 retains 220 compilation inputs. The new test count is not predicted: the seal tool derives it from the actual complete isolated summary and reconciles it with the original independent audit. `FROZEN_COUNTS` is filled only with that measured inventory. The old R33 cache-owner count remains solely in the R34 observation binder's old-owner evidence.

## Binding and sealing

`seal_package.py` is the original R33 sealer with version/root changes, new template identities, and two exact input path changes: `qualification-input.json` and `candidate/candidate.patch`. It reads stable, bounded actual local original bytes, requires a fully successful original terminal and eight-stage qualification, checks the actual final source map, summary and audit, then creates a new local sealed directory. It does not import the parent binder, run CI, run an auditor, access a host, or update Git.

The ten entries of `actual-pins.example.json` require actual local source locations and exact remote paths, byte counts and SHA256 values. They identify the original qualification report, native terminal, preparation, launcher, input, patch, final source map, isolated summary, isolated audit, and reviewed `ROOT/tools-01/r34_campaign.py` parent binder. Fill them only from exact original files; use an integer-preserving parser when handling raw native/stat receipts.

The sealed materializer uses the independently bound R34 parent qualification binder. That binder checks accepted R24 plus the frozen four-file R34 candidate, the current tested source and 19 harness inputs, the complete original isolated test evidence, and the actual rejected-but-closed R33 cache owner before any CI command. It does not start the observation campaign. The evidence binder interface remains six keys: qualification launcher, input, patch, preparation, original terminal with job ID, and original qualification report list.

When original qualification evidence is available, the local sealing command is:

```text
python3 -B seal_package.py --pins /absolute/path/actual-pins.json --out /absolute/new/sealed-01
```

This is a future operator step, not something performed by this template delivery. The resulting six tool files belong under `ROOT/rust-ci-tools-01/`; the separate `rust-ci-qualification-bindings-01.json` belongs directly under ROOT, and the exact reviewed parent binder must already exist at `ROOT/tools-01/r34_campaign.py`. Review the final seal manifest and hashes before the root coordinator starts the one original native CI job. Preserve any materialization or execution failure as the real first attempt.

## Static verification and limits

`build_templates.py` verifies the published R33 reference hashes and the two fixed original CI files, parses all generated Python, compares the three complete template texts under ROOT/version normalization, compares the sealer AST after only its declared path/pin changes, and checks the unchanged command/toolchain constants. It confirms the materializer's unsealed guard precedes writes, the runner's guard precedes output-directory creation and `Popen`, and the launcher's guard precedes its subprocess call. `LOCAL_STATIC_CHECKS.json` records that scope.

The local builder initially rejected its own sealer AST comparison because `pprint(sort_dicts=True)` changed only the `TEMPLATE_PINS` dictionary key order. No output file had yet been created and no target code had executed. The static comparator now canonicalizes that same declared pin dictionary on both sides; all other sealer AST nodes must remain equal. This changes no generated CI command or validation rule.

No generated CI template, original auditor, parent binder, Cargo command, Rust test or benchmark was imported or executed while preparing this package. No Mac/x230 API call or Git tree/commit/ref mutation was made. A passed static check is not a completed qualification, CI run, observation result or performance adoption.
