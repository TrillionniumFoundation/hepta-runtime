# Real-checkpoint lifecycle qualification evidence

These records qualify the native worker at source commit **`65ae015f0ccee9366f29d4477ce9a9015682b6c0`**, built by [CI run 45006849470](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45006849470). The implementation remains in the sibling [weight_lifecycle_runtime_20261122](../weight_lifecycle_runtime_20261122/) crate. This evidence-only directory is based directly on that qualified commit. Adding evidence does not rebuild, re-identify or qualify another binary.

## Entry points

- [SUMMARY.json](evidence/20261122/SUMMARY.json) retains observed counts, acceptance and preservation outcomes, the independent read-only audit checks, measured costs, and hashes of complete raw records.
- [LIFECYCLE_RESULT_20261122.md](evidence/20261122/LIFECYCLE_RESULT_20261122.md) is the exact original local report. Workspace-relative references in that retained report keep their original meaning; complete data is delivered separately.
- [EXECUTION_PLAN_FROZEN.json](evidence/20261122/EXECUTION_PLAN_FROZEN.json) is the exact plan frozen before attempt004. Its absolute paths are historical identity, not evidence that a new run occurred at those paths.
- [HISTORY.json](evidence/20261122/HISTORY.json) binds older source commits and original failed attempts. The [history directory](evidence/20261122/history/) retains their small original plans, failure summaries, stderr and measurements. Earlier failures are not overwritten by later success.
- [PRIVATE_INPUT_MANIFEST.json](evidence/20261122/PRIVATE_INPUT_MANIFEST.json) and [PORTABLE_INPUT_MANIFEST.json](evidence/20261122/PORTABLE_INPUT_MANIFEST.json) contain pins and paths, not checkpoint bytes. Relocated request records have distinct identities while scientific input bytes remain unchanged.
- [REMOTE_CLI_PLAN_65ae015f.json](evidence/20261122/REMOTE_CLI_PLAN_65ae015f.json) contains planned public-entry argv and expected results. It is not a remote execution receipt.

The retained `evidence/20261122/*.measurement.json` files are original outer process-tree measurements. They include successfully reaped parser children and failed work. Inner process or phase CPU must not be added to these totals again.

## Exact script snapshots

The following complete files are copied without content changes:

| Script | Purpose |
|---|---|
| [run_private_campaign.py](scripts/run_private_campaign.py) | The actual frozen 39-case campaign, per-process limits, process-tree monitoring, owned process-group cleanup, failure retention and final aggregate budget gate. |
| [measure_campaign.py](scripts/measure_campaign.py) | The actual outer process-tree measurement and partial-result-safe cost receipt. |
| [materialize_portable_inputs.py](scripts/materialize_portable_inputs.py) | The used input relocation builder, preserving scientific bytes while emitting newly identified request paths. |

No helper extraction, refactoring, formatting or source rewriting was performed when adding the scripts to Git. The script hashes in the original plan still match file bytes, while Git destination paths are new.

## Path and invocation assumptions

The scripts do not require a fixed repository working directory. They resolve top-level command-line paths from the current working directory, so future invocations should provide explicit absolute paths. Paths embedded in input pins and execution plans are read as supplied; they are not automatically rebased relative to the manifest or to this README. The retained original plans intentionally keep their historical workspace paths.

`measure_campaign.py` accepts `--plan`, `--mode` and `--output-base`. It launches the script and binary paths recorded in that plan with the current Python interpreter; it does not discover these new sibling script paths automatically. The output base must already exist, and per-mode log/result paths must be new. A fresh plan must pin actual script, input and binary bytes and use a separate output base. The existing completed execution directory must not be reused.

`run_private_campaign.py` accepts explicit `--binary`, `--binary-sha`, `--input-manifest`, `--input-sha`, `--output`, `--features` and `--source`. Its supervisor-death case re-enters the same complete script via its resolved `__file__` path. Moving the intact script preserves its byte hash but changes the path recorded by a future run. Its output directory is create-only. The binary source argument must identify the source that actually built that binary; this evidence commit is not that identity.

`materialize_portable_inputs.py` accepts `--manifest`, `--manifest-sha`, `--remote-prefix` and `--output`. Every source pin must resolve to separately retained bytes available locally. The remote prefix must be an absolute path. It creates a new output directory and adjacent archive, preserves the referenced scientific bytes, and emits separately hashed requests with relocated paths. It does not fetch checkpoints or perform a model evaluation.

These snapshots use normal Python 3 execution with assertions enabled and Linux process facilities (`/proc`, `prctl`, process groups and resource limits). They are the historical tested implementation, not a cross-platform runner claim. New source locations, request paths, output roots and binary identity belong in a newly frozen plan for any future execution. Merely relocating or rebuilding files does not transfer the recorded result.

## Qualification scope

Each mode actually completed 105 lifecycle CLI calls, 39 cases and 93 full policy DPs. CLI counts exclude internal canonical parser processes. The 67 successful owner operations per mode imply 67 parser launches from the exact reviewed implementation; parser PIDs were not independently enumerated. The acceptance/preservation cases reuse previously exposed tasks and teacher programs and are engineering qualification, not a new generalization result.

Checkpoint data, edited models, inverse models, full task outputs, full per-case records, complete audit material-pin lists and CI binary archives stay outside Git. These summaries retain their hashes. `HISTORY.json` references Git-backed source by exact commit/blob; separate final data packaging need not duplicate that source. No active pointer, service adoption, arbitrary power-loss or cross-version journal migration claim is made.

## Evidence publication

All added files are under `qualification/weight_lifecycle_evidence_20261122/`, outside the compiled runtime crate. No compiled source, Cargo manifest/lock or workflow changes are part of this publication. JSON syntax, copied bytes and Git blob identities can be checked without running a model or rebuilding the worker. All existing mandatory repository gates remain in effect; none is cancelled or bypassed by this evidence directory. The original CI and both native campaigns remain the execution qualification authority.
