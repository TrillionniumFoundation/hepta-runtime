# Preserve the native evidence producer across partial workflow retries

The failed-only retry of runtime PR #136 exposed an artifact identity defect.
The successful cold/native producer came from workflow run `44688261179`,
attempt 1. The retried original-system consumer used the same source head
`5e0fb6d5c88290db6581490bf5bd08e18776343f`, but reconstructed its invocation
from attempt 2. It requested an artifact ending in `44688261179-2`, while
the admitted complete artifact belonged to `44688261179-1`. Download failed
before any original Rust recipe was executed.

The [attempt-2 system job](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/44688261179/job/136212266257)
and its complete log are retained here. The first attempt remains a separate
failure: GitHub reported that the original-system job exceeded its unchanged
45-minute maximum. That first timeout has no established root cause, and this
artifact-routing fix does not claim to resolve it. The old run is not relabeled
as a complete CI pass.

## Changed behavior

The fresh `prepare` job publishes its actual run/attempt as a job output beside
its existing sealed-build hash. Native partitions and their collector consume
that fixed output. The collector forwards the same value beside its existing
complete-native hash. All eight original groups and the final aggregate consume
the forwarded value. Artifact names, `--invocation` arguments and admission
contexts therefore identify the same producer even if a consumer is retried.

A full rerun executes `prepare` again and receives a distinct producer identity.
No fallback searches other attempts, sources or runs. Existing exact source,
location, compiler, hash, full-corpus and full-recipe admission remains unchanged.
Failed original-job diagnostics include their actual execution attempt so a
later failure cannot overwrite the first diagnostic artifact. Upload overwrite
is not enabled; conflicting immutable uploads remain failures.

GitHub documents that jobs omitted from a partial rerun retain the outputs of
their previous attempt, which the newly run jobs can consume:
[Re-running workflows and jobs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs).

## Exact source scope

Four existing files change: the two workflow YAML files, three invocation/name
assertions plus three added controls in `test_native_pipeline.py`, and the two
workflow pins in the current historical-view profile. The profile's 544 current
graph rows, 120 original restored files, six authority rows, four workflow rows,
all public-route ownership and all completion flags retain their other values.

The complete old four files and precise forward/inverse records are preserved.
The reader proves each inverse returns the exact original bytes. The normal
pipeline implementations, original Rust recipe registry, original 70-control
reader and fixed compiler pin are unchanged. The old 15/45/60-minute job bounds
and each underlying application/observer deadline remain in force.

## Actual validation

The current profile was checked and a fresh historical58 source was materialized
from the isolated candidate. Its 2,202 source identities were reread after both
reporting suites. All 61 existing native reporting controls plus the three new
invocation controls passed: 64 tests, 10.783 seconds inside the unchanged
180-second outer bound. All 70 existing original-recipe reporting controls
passed: 27.387 seconds inside the same 180-second bound. Both process groups
were confirmed gone; complete stdout/stderr and controller receipts are retained.

The added controls evaluate the actual artifact-name and command templates for
fresh runs, failed-only retries, later retries, and fresh producers. They reject
consumer-local attempt substitution at native download, native execution,
collector output, original-system input and final collection. Separate controls
ensure failure diagnostics from two actual attempts have different names.
These controls are source/data and small Python process-reporting fixtures;
they do not run HIA products or Rust recipes and do not replace normal CI.

Run the independent retained-source reader from the repository root:

```sh
python3 -I -B qualification/workflow_invocation/v1/read_source.py
```

The new branch is published through normal Draft CI. Its eventual CI outcome
must be reported separately from these local controls and from both preserved
attempts of PR #136. No additional manual retry is included in this change.
The runtime still has 13 public routes out of the declared 136-handler target.
The full native rewrite and removal of the old runtime remain unqualified.
