# D1 ordinary feature-off supplement — preparation revision 02

This is a separate ordinary-build supplement to the original successful D1 qualification and exact Rust CI. It does not change the diagnostic source, the original eight-stage qualification, the nineteen qualification tools, or the acceptance benchmark.

The input templates are deliberately unsealed. No ordinary compiler, test, formatter, verifier entry or workload has been executed by the package author. A later actual-input seal and its original native result are separate evidence.

## Five stages and the source boundary

The final pre-execution decision is to run exactly these corresponding original stages, in order:

1. clippy
2. test-build
3. isolated-tests
4. audit-isolated-tests
5. release

The original Q already completed format, format-check and harness self-tests. Revision 02 omits those three calls, so ordinary compilation does not invoke a formatter. It removes exactly three `--all-features` arguments. The original command runner, copying, isolated-test execution, auditor, output preservation, environment and error handling are unchanged.

The derived qualifier still uses the original report schema. Its output is independently identified as `ROOT/ordinary-01/`, with a separate `ordinary-plan-01.json`. Its source_input, source_tested and source_after must all equal the already qualified 222-input map. Counts are observed from the actual ordinary inventory; no predicted count is used.

The accepted R24 Cargo manifest has no package features. D1 adds only the empty opt-in `phase-cost-diagnostics` feature. Removing the three selectors restores that original package feature selection without `--no-default-features`, without changing dependency defaults and without changing the original release profile. The references and static review verify those TOML facts.

The earlier eight-stage source draft was never sealed or executed. Its five exact files remain under `superseded-unexecuted-01/`. The explicit pre-execution change is recorded in `revision-02-decision.json`; no result was reinterpreted after execution.

## Launch preparation

The root is `/home/qian/hepta-runtime-phase-cost-20261106-d1`. The reviewed Q/CI foundation remains `ROOT/rust-ci-prerequisites-01/d1_prerequisites.py`, SHA-256 `11875566eefa5532495d4411974faa2232a4339d3fd4ee1acae230c7394daba7`.

The actual full Q/CI JSON is installed independently as `ROOT/ordinary-prerequisites-01.json`. This avoids occupying the outer campaign's separate first-use `c1-prerequisites-01.json`. Both can later use the same original full prerequisite bytes.

Fill only real identities in `launch-seal-request.unsealed.json`, then run `seal_ordinary.py --input <actual-request> --output <new-local-seal>`. This local operation binds bytes and emits four tools, the actual prerequisite, the launch command and the seal manifest. It does not import the foundation or start a process.

Before exec, the sealed launcher performs the full reviewed Q/CI prerequisite validation, binds the qualified source and three preserved feature executables, checks the original three-GiB build-space condition, and retains a create-only plan. It then execs the five-stage qualifier in the same PID, using the existing independent D1 target, original Cargo home and jobs=2. The original qualifier strips diagnostic and other uncontrolled runtime environment variables. The launcher itself also requires all three diagnostic variables absent.

The existing `qualification-01/` executables are preserved separate copies, not target-build aliases. Ordinary release executables are separately copied into `ordinary-01/`. No target cache is copied, cleared or concurrently built by this package.

## Actual result closure

Retain the original ordinary native terminal and every original read page, unchanged. Fixed locations are `ROOT/ordinary-native-01.json` and `ROOT/ordinary-native-read-000.json`, followed by 001, etc. Page content is never reconstructed into a fabricated single-page response.

Fill `result-seal-request.unsealed.json` with the actual launch seal and original plan/report/map/summary/audit/native/page identities. The result sealer emits `ordinary-verification-input-01.json` and a read-only verification command. Byte sealing alone is not proof of success: the verifier still validates all original semantics and current source/release files.

The verifier reconciles the complete original native stdout/stderr with the launch plan and all five stage receipts. Every stage must be successful with its exact corresponding Q command, minus the feature selector and with only output paths changed. It binds the actual raw stage logs, source map, full test summary, actual original auditor and all five auditor input files. Test counts must reconcile with zero failure and zero retry.

Retained debug test-ELF custody is established by the original auditor's actual before/after SHA records, as in the original Q binder. The postflight does not read those large test ELFs again and explicitly says so. It re-reads all six release executables: the three qualified feature copies must equal the pre-launch identities, and the three ordinary copies must match their original release report.

The new report is `ROOT/ordinary-postflight-01.json`, schema `hepta-d1-ordinary-supplement-postflight/v2`. It records the actual native job/pages, five stages, dynamic counts, source-map equality, feature-program identities before and after, and ordinary-program identities. It is create-only. Failures retain original evidence and cannot be converted into success by the input templates.

The import-safe API `verify_ordinary(inputs, bind, foundation, prerequisite_proof)` returns `hepta-d1-ordinary-supplement-validation/v2`. The caller must first obtain a fresh full Q/CI proof from the reviewed foundation. The outer C1 preparation must bind the actual ordinary originals, verifier/postflight and native receipt, and the two executable categories before it can seal. Q/CI success alone does not authorize measurement.

## Scope

This package adds no performance samples, thresholds, production hooks, persistent helpers or security exceptions. It claims neither an ordinary result nor a performance gain. Actual compiler and native process execution remain separately scheduled and controlled by the experiment owner.
