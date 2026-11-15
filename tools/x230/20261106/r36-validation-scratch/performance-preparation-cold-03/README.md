# R36 validation-scratch: full acceptance preparation, cold-02

This package prepares the original full R35 observation and normal lifecycle protocol for the two-file R36 validation-scratch candidate (PR108), based on accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`. It is distinct from the rejected, three-file R36 audit-cache candidate in PR106. No performance result or adoption decision is established by this package.

The sole runtime root is `/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02`. The earlier scratch preparation at `/home/qian/hepta-runtime-validation-scratch-20261106-r36` and its original failed job `1a1b1bedd38-fc05-7a99` remain separate. The cold preparer creates a new empty target; its D2 documents are historical evidence and do not assert cache reuse, rename, or ownership transfer. Its original eight stages, nineteen harness files, jobs=2, offline/locked behavior and source checks are unchanged.

## Original measurement protocol

The observation parent retains all seven original stages: native observation, independent native audit, native boundary, boundary audit, six-host cancel/recovery, recovery audit, and observation summary. The original controller, direct ELF launch, resource collection, shutdown, stage ownership, failure handling, compiler monitor and 90-second quiet interval are retained.

The fixed matrix remains six hosts, ABBA, C1/C8/C16, 192 measured calls and 24 warmups per concurrency per round, two workers and arena maximum one. Its planned totals are 2,304 measured, 288 warmup and 72 preflight/restart calls, or 2,664 calls. These are protocol counts, not observed results. C32 remains two original boundary bursts. The six-host recovery canary retains its original interruption and evidence rules.

The observation thresholds remain throughput B/A at least 0.95, p95 at most 1.10, controller CPU at most 1.10, and peak RSS at most both A+512 KiB and A×1.05. C8 remains the primary concurrency. The original SSH input-size/cache-budget checks remain unchanged.

Only an actually closed and passing observation gate permits the original normal lifecycle materializer. Normal lifecycle retains the original 14 tool tests, four-round six-host ABBA, original resource/auditor evidence, and required `all_operations`, `launch` and `concurrent_cancel` comparisons. The original lifecycle tool bundle, including its CPU tick tolerance, remains authoritative. No reserve/capacity gate is added. A completed experiment that rejects performance is preserved; no favorable subset or selective rerun replaces it.

## Recovered fixtures and protected profile

The seven public fixture inputs are the exact reviewed recovery originals: six frozen job JSON files and the 796-byte topology with SHA-256 `c131f12bd145d53bd2c26d0917411a41e6e85d19a6273fc19d0ef3744d23658e`. The installer copies them create-only from `tools-01/frozen-fixture-inputs` to `measurement-fixtures-01`. All three observation workload consumers and the normal lifecycle parent obtain the same paths from the parent constants.

The existing private seed is `/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01/profile/profile.json`, 792 bytes, SHA-256 `ed680dc1613e4aea4de99336d21009c73e71554694edbe23f9dc3a433b586e89`. Its body is neither read during preparation nor included in this package. The reviewed relocation proof is preserved under `provenance/`. The original worker's bounded stable reads, configuration identities, private fresh-profile construction, held-agent binding and socket-length checks are unchanged. No descriptor, private configuration or prior controller is reused.

Fresh socket namespaces are `/home/qian/hs36n01`, `/home/qian/hs36b01`, `/home/qian/hs36c01` and lifecycle prefix `/home/qian/s36lc1`. The unchanged canary retains its original R16 parent-directory guard and writes the new sibling `/home/qian/hepta-runtime-optimization-20261104-r16/s36-cancel-recovery-01`. No blanket cleanup is performed. Their live absence is checked by the original runtime protocol, not assumed by this offline preparation.

## Binding and sealing

The unsealed observation parent has `R36_PREPARATION_SEAL = None` and refuses execution before output creation. The same guard protects the public `bind_r36_candidate_preparation(inputs, bind)` interface used by exact CI. Its six-input and proof ABI is the original R35 interface. Actual source/report/count/ELF facts come from completed qualification, not from a predicted test count.

The binder checks the two-file patch, including the original four-field patch identity and Git blob, the formatted 220-input source map, original eight stages and complete isolated audit. The D2 historical owner functions are copied from the reviewed cold preparer and applied to bound original documents. They do not call the pre-build process scanner or access the missing old target. Only the six actual retained D2 release copies remain read-bound.

`seal_parent_bundle.py` is a local artifact producer. Populate `seal-request.unsealed.json` with ten actual local original paths and exact bytes/SHA-256 values after the cold qualification succeeds. Invoke:

```text
/usr/bin/python3 -I -B seal_parent_bundle.py --request /absolute/actual-request.json --output /absolute/new-sealed-directory
```

The sealer uses stable readers and pure JSON/AST checks. It copies seven original helper functions, imports no parent or binder, and changes only the parent's `R36_PREPARATION_SEAL` assignment. It creates a new output directory containing the five tools, bundle manifest and seven fixtures under `x230/tools-01`, the original holder and identical parent copies under `mac`, and a sealing receipt. No compiler, installer, auditor, SSH connection or workload is started.

Upload the sealed thirteen `x230/tools-01` files into the new runtime `tools-01` directory, then run the original adapted `install_measurement_tools.py --bundle-sha256 <actual sealed manifest SHA>`. The installer copies pinned shared monitor/summary tools and the original 27-file lifecycle harness from the completed R35 root. Only the two lifecycle output-root constants are derived anew; their actual installation hashes and rebuilt lifecycle manifest must be used by later evidence collection. The installer also creates the actual observation/lifecycle example JSON files. The examples in this source package are review copies and must not be uploaded over those outputs.

After the original exact Rust CI closes, use the original observation materializer with actual example, preparation, native-terminal and job identities. The unchanged Mac holder then invokes the sealed observation parent. Its concrete fixed argv and the conditional lifecycle argv are in `operator-plan.unsealed.json`. The Mac source directory is `/Users/qianqi/work/hepta-runtime-r36-validation-scratch-cold-02-parent-01`; the two holder output directories are separate fresh observation/lifecycle paths. Root owns deployment and all host calls.

There is no CI/parent dependency cycle: the parent is sealed from actual qualification; exact CI imports that sealed parent binder; observation runs only after exact CI; lifecycle follows the original passing observation gate. Future CI, observation, lifecycle and adoption results remain null.

## Verification scope and history

`build_sources.py` and `build_metadata.py` perform source derivation, JSON/AST parsing and exact byte comparisons only. The full nonbinder parent prefix/suffix is equal to the original R35 source after the enumerated root/fixture/socket changes and removal of the added unsealed guard. Nineteen general parent helpers are byte-identical; the twentieth changes only its R35/R36 error label. Both materializers are namespace-only derivations. The normal lifecycle source changes only namespaces and its unsealed guard. The original holder is byte-identical.

The first redundant metadata check demanded all twenty helper texts be byte-identical without normalizing the existing versioned error label. It failed before generating outputs. Its builder and explanation are preserved in `preparation-history/`; the corrected check uses the precise nineteen-plus-one boundary. This was a local preparation assertion, not a target execution failure.

The earlier unexecuted warm-cache parent draft is preserved by its Git objects; it is superseded by this cold-only root and evidence contract. No Rust build, runtime test, target helper, benchmark, host operation or Git ref change was performed while preparing this package.

## Preparation revision 03

Independent review found that the identifier-prefix transformation had also rewritten the ordinary postflight JSON key `native_terminal`. This revision restores that one literal key in the owner helper and embedded parent. The prefixed Python function name is unchanged. The prior 52-file revision and catalog `d2a2927560e8d08acc545a65e36ebaccfafe21b0` remain preserved and unexecuted. The amended source was checked for literal equality with all six copied pure helper bodies; no measurement or qualification result is changed.
